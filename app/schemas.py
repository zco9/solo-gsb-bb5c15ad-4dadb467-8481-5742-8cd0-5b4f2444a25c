"""Pydantic models for the HTTP API (pydantic v2)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from .analyzer import ValidationError, normalize_action
from .change_guard import GUARD_ACTIONS


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cidr: str = Field(..., description="IPv4/IPv6 network in CIDR notation; host bits must be zero")
    action: str = Field(..., description="permit/allow or deny/block/drop/reject")
    priority: int = Field(
        default=100, ge=0, description="Smaller number = higher priority; only breaks same-CIDR ties"
    )
    source_tag: str = Field(default="default", description="Label of the rule's origin")
    rule_id: str | None = Field(default=None, description="Optional unique id; auto-generated as r1, r2...")

    @field_validator("action")
    @classmethod
    def _normalize_action(cls, v: str) -> str:
        try:
            return normalize_action(v)
        except ValidationError as exc:
            # Pydantic turns ValueError into a 422 validation error response.
            raise ValueError(str(exc)) from exc

    @field_validator("cidr", "source_tag")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        return v


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[RuleIn] = Field(..., min_length=1, description="Ordered rule set")
    name: str | None = Field(default=None, description="Optional human-readable version name")
    save: bool = Field(default=True, description="Persist this analysis as an immutable version")


class RuleAdd(RuleIn):
    """A brand-new rule for a simulation batch; the id must not exist yet."""

    rule_id: str = Field(..., description="Unique id of the new rule; must not exist in the base version")


class RuleReplace(RuleIn):
    """Full replacement record of an existing rule (id must hit the base version)."""

    rule_id: str = Field(..., description="rule_id of the base-version rule to replace")


class RuleRemove(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., description="rule_id of the base-version rule to remove")

    @field_validator("rule_id")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        return v


class SimulateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    add: list[RuleAdd] = Field(
        default_factory=list,
        description="Rules to append; rule_ids must be new (no overlap with the base version)",
    )
    replace: list[RuleReplace] = Field(
        default_factory=list,
        description="Existing rules to rewrite in place; rule_ids must hit the base version",
    )
    remove: list[RuleRemove] = Field(
        default_factory=list,
        description="Existing rules to delete; rule_ids must hit the base version",
    )

    @field_validator("add", "replace", "remove", mode="before")
    @classmethod
    def _must_be_list(cls, v: Any) -> Any:
        if not isinstance(v, list):
            raise ValueError("must be a list of operations")
        return v


class ChangeBatch(SimulateRequest):
    """One side (``a`` or ``b``) of a two-batch merge precheck.

    Same add/replace/remove contract as a single-batch simulation, evaluated
    independently against the common base version: at least one operation and
    the normal all-or-nothing patch validation.
    """


class MergePrecheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    a: ChangeBatch = Field(
        ...,
        description="First change batch (applied first when composing the merge)",
    )
    b: ChangeBatch = Field(
        ...,
        description="Second change batch (applied on top of batch A)",
    )


class GuardEntryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cidr: str = Field(
        ..., description="Strict IPv4/IPv6 CIDR: explicit prefix length, host bits must be zero"
    )
    from_action: str = Field(..., description="permit / deny / none")
    to_action: str = Field(..., description="permit / deny / none; must differ from from_action")

    @field_validator("cidr")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        return v

    @field_validator("from_action", "to_action")
    @classmethod
    def _normalize_guard_action(cls, v: str) -> str:
        key = v.strip().lower()
        if key not in GUARD_ACTIONS:
            raise ValueError("must be one of permit, deny, none")
        return key

    @model_validator(mode="after")
    def _transition_must_differ(self) -> "GuardEntryIn":
        if self.from_action == self.to_action:
            raise ValueError("from_action and to_action must differ")
        return self


class ChangeGuardRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authorizations: list[GuardEntryIn] = Field(
        ...,
        min_length=1,
        description="Granted action transitions; same-transition CIDRs are unioned, "
        "overlapping CIDRs of different transitions are rejected",
    )


class QuarantinePlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cidr: str = Field(
        ..., description="Strict IPv4/IPv6 target CIDR: explicit prefix length, host bits must be zero"
    )
    rule_id_prefix: str = Field(
        ...,
        min_length=1,
        description="Prefix of the generated deny rule ids; ids are '<prefix>1', '<prefix>2', ...",
    )

    @field_validator("cidr", "rule_id_prefix")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        return v


class TrafficRecordIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str = Field(
        ..., description="IPv4/IPv6 address of the observed access (a plain address, no prefix length)"
    )
    action: str = Field(..., description="Observed action: permit/allow or deny/block/drop/reject")
    count: StrictInt = Field(
        default=1,
        ge=1,
        description="Optional positive integer weight: how many observations this record stands for",
    )

    @field_validator("action")
    @classmethod
    def _normalize_action(cls, v: str) -> str:
        try:
            return normalize_action(v)
        except ValidationError as exc:
            # Pydantic turns ValueError into a 422 validation error response.
            raise ValueError(str(exc)) from exc

    @field_validator("ip")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        return v


class TrafficAuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records: list[TrafficRecordIn] = Field(
        ..., min_length=1, description="Non-empty list of observed access records"
    )


class ObservationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str = Field(
        ..., description="Observed IPv4/IPv6 address (a plain address, no prefix length)"
    )
    action: str = Field(..., description="Expected action: permit/allow or deny/block/drop/reject")

    @field_validator("action")
    @classmethod
    def _normalize_action(cls, v: str) -> str:
        try:
            return normalize_action(v)
        except ValidationError as exc:
            # Pydantic turns ValueError into a 422 validation error response.
            raise ValueError(str(exc)) from exc

    @field_validator("ip")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        return v


class ObservationCorrectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observations: list[ObservationIn] = Field(
        ...,
        min_length=1,
        max_length=20,
        description="1-20 traffic observations (IP + the action it should resolve to)",
    )
    candidate_rule_ids: list[str] = Field(
        ...,
        min_length=1,
        max_length=8,
        description="1-8 distinct, existing rule_ids that may be kept, disabled or flipped",
    )

    @field_validator("candidate_rule_ids")
    @classmethod
    def _strip_candidate_ids(cls, v: list[str]) -> list[str]:
        stripped = [item.strip() for item in v]
        if any(not item for item in stripped):
            raise ValueError("candidate rule_id must not be empty")
        return stripped


class ActivateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(
        ..., description="Id of the saved analysis version to publish (an_ + 16 hex chars)"
    )
    expected_revision: int = Field(
        ...,
        ge=0,
        description="Pointer revision the caller saw; activation proceeds only when it "
        "still matches (optimistic concurrency control)",
    )

    @field_validator("analysis_id")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        return v


class ListAnalysesResponse(BaseModel):
    total: int
    analyses: list[dict[str, Any]]


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
