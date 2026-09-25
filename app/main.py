"""FastAPI application: network prefix policy analysis.

Endpoints
---------
POST   /api/analyze                          analyze a rule set (optionally persist)
POST   /api/analyses/{id}/simulate           preview add/replace/remove changes without saving
POST   /api/analyses/{id}/merge-precheck     precheck merging two change batches on one base version
POST   /api/analyses/{id}/quarantine-plan    deterministic deny-rule plan that quarantines one CIDR (preview only)
POST   /api/analyses/{id}/traffic-audit      attribute observed access records to winning rules (read-only)
POST   /api/analyses/{id}/observation-correction minimum keep/disable/flip plan making observations hit expected actions (read-only)
GET    /api/analyses                         list saved analysis versions
GET    /api/analyses/{id}                    fetch one version with the full result
GET    /api/analyses/{id}/rules              query rules (filters: status/action/ip_version)
GET    /api/analyses/{id}/findings           query findings (filters: severity/behavioral_only)
GET    /api/analyses/{id}/decision-map       CIDR decision map of this version (query: cidr)
GET    /api/analyses/{id}/redundant-rules    per-rule removability inventory (recomputed LPM diff)
GET    /api/analyses/{id}/source-retirement  per-source-tag whole-group withdrawal preview (recomputed LPM diff)
GET    /api/analyses/{id}/export.json        download the result as a JSON file
GET    /api/analyses/{id}/diff/{oid}         effective-action semantic diff of two versions
POST   /api/analyses/{id}/change-guard/{oid} authorize the semantic diff against caller-supplied grants
GET    /api/active                           current published-version pointer (revision + active_id)
POST   /api/active/activate                  publish a saved version, checked against expected_revision
GET    /api/active/history                   read-only audit log of successful pointer switches
GET    /health                               liveness probe
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from hashlib import sha256
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.responses import JSONResponse

from . import __version__
from .analyzer import ANALYZER_VERSION, ValidationError, analyze_rules
from . import db
from .change_guard import ChangeGuardError, guard_changes, parse_guard_entries
from .decision_map import DecisionMapError, build_decision_map, parse_query_cidr
from .diff import ANALYSIS_ID_RE, diff_analyses
from .merge_precheck import build_batch, merge_precheck
from .observation_correction import ObservationCorrectionError, correct_observations
from .quarantine_plan import QuarantinePlanError, plan_quarantine
from .redundant import redundant_rule_inventory
from .source_retirement import source_retirement_report
from .schemas import (
    ActivateRequest,
    AnalyzeRequest,
    ChangeGuardRequest,
    MergePrecheckRequest,
    ObservationCorrectionRequest,
    QuarantinePlanRequest,
    SimulateRequest,
    TrafficAuditRequest,
)
from .simulate import PatchError, apply_patch, rebuild_input_rules
from .traffic_audit import TrafficAuditError, audit_traffic


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield


app = FastAPI(
    title="Network Prefix Policy Analyzer",
    version=__version__,
    description=(
        "Submit IPv4/IPv6 CIDR rules with priority, action and source tags. "
        "The service computes each rule's effective coverage under longest-prefix "
        "match, identifies fully shadowed / partially overlapping / action-conflicting "
        "rules, and returns reproducible minimal conflict pairs."
    ),
    lifespan=lifespan,
)


@app.exception_handler(ValidationError)
async def _validation_error_handler(_request, exc: ValidationError):
    return JSONResponse(status_code=400, content={"error": "invalid_ruleset", "detail": str(exc)})


@app.exception_handler(PatchError)
async def _patch_error_handler(_request, exc: PatchError):
    # The whole batch is rejected; every offending target is reported at once.
    return JSONResponse(
        status_code=400,
        content={"error": "invalid_simulation", "detail": str(exc), "issues": exc.issues},
    )


@app.exception_handler(DecisionMapError)
async def _decision_map_error_handler(_request, exc: DecisionMapError):
    return JSONResponse(status_code=400, content={"error": "invalid_cidr", "detail": str(exc)})


@app.exception_handler(QuarantinePlanError)
async def _quarantine_plan_error_handler(_request, exc: QuarantinePlanError):
    return JSONResponse(
        status_code=400, content={"error": "invalid_quarantine_plan", "detail": str(exc)}
    )


@app.exception_handler(ChangeGuardError)
async def _change_guard_error_handler(_request, exc: ChangeGuardError):
    # The whole authorization set is rejected; every problem is reported at once.
    return JSONResponse(
        status_code=400,
        content={"error": "invalid_change_guard", "detail": str(exc), "issues": exc.issues},
    )


@app.exception_handler(TrafficAuditError)
async def _traffic_audit_error_handler(_request, exc: TrafficAuditError):
    # The whole record batch is rejected; every offending record is reported at once.
    return JSONResponse(
        status_code=400,
        content={"error": "invalid_traffic_audit", "detail": str(exc), "issues": exc.issues},
    )


@app.exception_handler(ObservationCorrectionError)
async def _observation_correction_error_handler(_request, exc: ObservationCorrectionError):
    # The whole request is rejected; every offending candidate/observation is
    # reported at once.
    return JSONResponse(
        status_code=400,
        content={
            "error": "invalid_observation_correction",
            "detail": str(exc),
            "issues": exc.issues,
        },
    )


@app.exception_handler(db.RevisionConflict)
async def _revision_conflict_handler(_request, exc: db.RevisionConflict):
    # Another publish landed first: report the pointer state that won the race.
    return JSONResponse(
        status_code=409,
        content={
            "error": "revision_conflict",
            "detail": "expected_revision does not match the current pointer revision; "
            "refetch GET /api/active and retry",
            "current": exc.current,
        },
    )


def _make_id(ruleset_hash: str) -> str:
    return "an_" + ruleset_hash[:16]


@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": "prefix-policy-analyzer",
        "version": __version__,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__, "analyzer_version": ANALYZER_VERSION}


@app.post("/api/analyze", status_code=200)
def analyze(req: AnalyzeRequest) -> dict[str, Any]:
    """Analyze a rule set.

    The analysis is deterministic: identical inputs always produce the same
    ``ruleset_hash`` and the same ``id``. Saving is idempotent, even under
    concurrent submission: the first successful save of a given ruleset hash
    creates the immutable version (and its rules/findings) and every later
    save — including requests racing the first one — is reused as-is. The
    response metadata of every successful request is therefore the stored
    version's ``id``/``name``/``created_at`` (a duplicate's own ``name`` is
    ignored), matching GET /api/analyses/{id} and the version list.
    """
    raw_rules = [r.model_dump(exclude_defaults=False) for r in req.rules]
    # model_dump turns unset rule_id into None; the analyzer assigns r1, r2...
    result = analyze_rules(raw_rules)

    analysis_id = _make_id(result["ruleset_hash"])
    if req.save:
        saved = db.save_analysis(analysis_id, req.name, result)
        result["id"] = saved["id"]
        result["name"] = saved["name"]
        result["created_at"] = saved["created_at"]
        result["persisted"] = True
    else:
        # Analysis only: nothing is written, so the response carries the
        # request-supplied name and a fresh timestamp rather than stored metadata.
        result["id"] = analysis_id
        result["name"] = req.name
        result["created_at"] = db.utc_now_iso()
        result["persisted"] = False
    return result


@app.get("/api/analyses")
def list_analyses(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    total, analyses = db.list_analyses(limit=limit, offset=offset)
    return {"total": total, "analyses": analyses}


@app.get("/api/analyses/{analysis_id}")
def get_analysis(analysis_id: str) -> dict[str, Any]:
    result = db.get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")
    return result


@app.post("/api/analyses/{analysis_id}/simulate", status_code=200)
def simulate_changes(analysis_id: str, req: SimulateRequest) -> dict[str, Any]:
    """Preview a batch of ``add`` / ``replace`` / ``remove`` rule changes.

    The analyzer input is rebuilt from the saved version, the validated patch
    is applied, and the LPM analysis is re-run.  Nothing is persisted: the
    response carries the unsaved preview plus its final effective-action
    semantic diff against the base version.
    """
    base = db.get_analysis(analysis_id)
    if base is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")

    add_rules = [r.model_dump() for r in req.add]
    replace_rules = [r.model_dump() for r in req.replace]
    remove_rules = [r.model_dump() for r in req.remove]

    base_input = rebuild_input_rules(base)
    patched_input = apply_patch(base_input, add_rules, replace_rules, remove_rules)

    # Invalid CIDRs/actions inside replacement or added rules surface as the
    # same 400 invalid_ruleset error as POST /api/analyze.
    simulated = analyze_rules(patched_input)
    simulated["id"] = None
    simulated["name"] = None
    simulated["created_at"] = db.utc_now_iso()
    simulated["persisted"] = False

    diff = diff_analyses(base, simulated)
    return {
        "base": {
            "id": analysis_id,
            "ruleset_hash": base.get("ruleset_hash"),
            "analyzer_version": base.get("analyzer_version"),
        },
        "simulated": simulated,
        "diff": diff,
    }


@app.post("/api/analyses/{analysis_id}/merge-precheck", status_code=200)
def merge_precheck_changes(analysis_id: str, req: MergePrecheckRequest) -> dict[str, Any]:
    """Precheck merging two batches of rule changes on one saved version.

    Batches ``a`` and ``b`` each carry the ordinary add/replace/remove
    operations of a simulation batch.  Both are replayed independently from
    the rebuilt base input and re-analyzed; a ``rule_id`` targeted by both
    batches is a *structural conflict*.  The address ranges each side changes
    relative to the base are overlaid per IPv4/IPv6 family, and intersections
    whose final action differs come back as minimal-CIDR *action conflicts*
    carrying the base and both sides' actions.  Otherwise batch A is applied
    first and B on top, the merge is re-analyzed, and any range a side had
    changed but the merge does not keep at that side's action is reported as a
    *merge conflict*; a clean response carries the full merged analysis plus
    its diff against the base.  Nothing is persisted: no analysis version is
    created and the base version is never modified.
    """
    base = db.get_analysis(analysis_id)
    if base is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")

    def _build_batch(batch: SimulateRequest):
        return build_batch(
            add=[r.model_dump() for r in batch.add],
            replace=[r.model_dump() for r in batch.replace],
            remove=[r.model_dump() for r in batch.remove],
        )

    result = merge_precheck(base, _build_batch(req.a), _build_batch(req.b))

    merged = result["merged"]
    if merged is not None:
        # Present the merged candidate exactly like a simulated (unsaved)
        # analysis: it has no identity of its own and is never persisted.
        merged["id"] = None
        merged["name"] = None
        merged["created_at"] = db.utc_now_iso()
        merged["persisted"] = False
    return result


@app.post("/api/analyses/{analysis_id}/quarantine-plan", status_code=200)
def quarantine_plan(analysis_id: str, req: QuarantinePlanRequest) -> dict[str, Any]:
    """Plan deterministic ``priority=0`` deny rules quarantining one CIDR.

    The target CIDR is partitioned by the saved version's decision map.
    Addresses that already resolve to ``deny`` produce no rule; permit and
    unmatched blocks get one new deny rule each, except that a block held by
    an existing same-CIDR priority-0 rule is subdivided (down to single
    addresses, where an unbeatable block is reported instead).  Generated ids
    are ``<rule_id_prefix>1, <rule_id_prefix>2, ...`` and must not collide
    with an existing rule id.  The candidate ruleset is re-analyzed and
    diffed against the base, proving the whole target becomes deny while
    actions outside the target stay unchanged.  Preview only: nothing is
    persisted.
    """
    # Validate the strict target CIDR before looking the version up, mirroring
    # the decision-map endpoint's format-before-existence ordering.
    target = parse_query_cidr(req.cidr)

    base = db.get_analysis(analysis_id)
    if base is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")

    return plan_quarantine(base, target, req.rule_id_prefix)


@app.post("/api/analyses/{analysis_id}/traffic-audit", status_code=200)
def traffic_audit_records(analysis_id: str, req: TrafficAuditRequest) -> dict[str, Any]:
    """Attribute observed access records to the rules of a saved version.

    Each record carries an IPv4/IPv6 address, the observed action
    (``permit``/``deny``) and an optional positive integer ``count`` weight
    (default 1).  Every address is attributed to the rule that would decide
    it under the version's longest-prefix + same-CIDR-priority semantics —
    never by record order or first match — and the observed action is
    compared with the expected one.  An address no rule covers is reported
    as ``uncovered`` (``expected_action: null``); no action is inferred for
    it.  Weighted counts are aggregated per winning rule, per action
    mismatch and for the uncovered surface.  Any invalid IP rejects the
    whole batch.  Read-only: nothing is persisted and the saved version is
    never modified.
    """
    base = db.get_analysis(analysis_id)
    if base is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")

    return audit_traffic(base, [r.model_dump() for r in req.records])


@app.post("/api/analyses/{analysis_id}/observation-correction", status_code=200)
def correct_observation_policy(
    analysis_id: str, req: ObservationCorrectionRequest
) -> dict[str, Any]:
    """Find the minimum rule-change plan aligning a saved version with observations.

    Each observation (1–20 of them) pairs an IPv4/IPv6 address with the action
    (``permit``/``deny``) the policy should take on it.  Each of 1–8 distinct,
    existing candidate ``rule_id`` values may be kept, disabled (removed from
    the recomputed ruleset) or flipped (its action inverted).  The endpoint
    enumerates the combinations under the version's longest-prefix +
    same-prefix-priority semantics and returns the plan changing the fewest
    rules (then the fewest disables, then the lexicographically smallest
    ``(rule_id, operation)`` sequence) that makes every observation resolve to
    its expected action.  An observation no surviving rule covers is a miss —
    never an implicit permit.  When nothing works, ``plan`` is ``null``; when
    the version already agrees with every observation, the plan is empty.
    Read-only: nothing is persisted and the saved version is never modified.
    """
    base = db.get_analysis(analysis_id)
    if base is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")

    return correct_observations(
        base,
        [r.model_dump() for r in req.observations],
        list(req.candidate_rule_ids),
    )


@app.get("/api/analyses/{analysis_id}/rules")
def get_rules(
    analysis_id: str,
    status: str | None = Query(default=None, pattern="^(active|partial|shadowed)$"),
    action: str | None = Query(default=None, pattern="^(permit|deny)$"),
    ip_version: int | None = Query(default=None, alias="ip", ge=4, le=6),
) -> dict[str, Any]:
    rows = db.query_rules(
        analysis_id, status=status, action=action, ip_version=ip_version
    )
    if rows is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")
    return {"analysis_id": analysis_id, "count": len(rows), "rules": rows}


@app.get("/api/analyses/{analysis_id}/findings")
def get_findings(
    analysis_id: str,
    severity: str | None = Query(default=None, pattern="^(conflict|warning|info)$"),
    behavioral_only: bool = Query(default=False),
) -> dict[str, Any]:
    rows = db.query_findings(
        analysis_id, severity=severity, behavioral_only=behavioral_only
    )
    if rows is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")
    return {"analysis_id": analysis_id, "count": len(rows), "findings": rows}


@app.get("/api/analyses/{analysis_id}/decision-map")
def get_decision_map(
    analysis_id: str,
    cidr: str = Query(..., description="Strict IPv4/IPv6 CIDR query range"),
) -> dict[str, Any]:
    """Decision map of a *saved* version over one CIDR query.

    Read-only: the version's stored rules and their winning effective
    coverage are partitioned into disjoint, exhaustive minimal CIDR blocks.
    Each block reports its address count, final action (``none`` when nothing
    matches), winning rule/source tag, and the full longest-prefix-first
    match chain (losing duplicates included). No analysis is created.
    """
    # The query is validated before looking the version up, mirroring the
    # diff endpoint's format-before-existence ordering.
    query = parse_query_cidr(cidr)

    result = db.get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")

    return build_decision_map(result, query)


@app.get("/api/analyses/{analysis_id}/redundant-rules")
def get_redundant_rules(analysis_id: str) -> dict[str, Any]:
    """Inventory the rules that can be individually deleted without effect.

    Every rule of the saved version is removed in turn, the longest-prefix
    analysis is recomputed on the remainder, and the final effective actions
    (``permit``/``deny``/``none``) are compared against the original version
    for both address families.  A rule is ``safe_to_remove`` only when no
    address changes action; ``changed_addresses`` is the exact number of
    addresses whose action would change.  Read-only: nothing is persisted.
    """
    result = db.get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")
    return redundant_rule_inventory(result)


@app.get("/api/analyses/{analysis_id}/source-retirement")
def get_source_retirement(analysis_id: str) -> dict[str, Any]:
    """Preview withdrawing every rule of each source tag as one group.

    For every distinct ``source_tag`` of the saved version, all of its rules
    are removed together in their original order, the longest-prefix +
    same-CIDR-priority analysis is recomputed on the remainder, and the final
    effective actions (``permit``/``deny``/``none``) are compared against the
    original version for both address families.  A source is
    ``safe_to_retire`` only when no address changes action; per-source
    ``changes`` carry the minimal CIDR ranges grouped by the six action
    transitions, with exact address counts.  Removing the source's rules one
    by one without effect does not imply group safety: the group removal is
    always re-adjudicated as a whole.  Deleting the version's last rules is
    compared against an empty rule set (everything unmatched).  Read-only:
    nothing is persisted.
    """
    result = db.get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")
    return source_retirement_report(result)


@app.get("/api/analyses/{analysis_id}/export.json")
def export_analysis(analysis_id: str) -> Response:
    result = db.get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{analysis_id}.json"'},
    )


def _validate_analysis_id_pair(base_id: str, target_id: str) -> None:
    """Format/identity checks shared by the diff and change-guard endpoints."""
    bad = [i for i in (base_id, target_id) if not ANALYSIS_ID_RE.match(i)]
    if bad:
        raise HTTPException(
            status_code=400,
            detail=f"invalid analysis id format: {', '.join(sorted(set(bad)))}; "
            "expected 'an_' followed by 16 lowercase hexadecimal characters",
        )
    if base_id == target_id:
        raise HTTPException(status_code=400, detail="base and target ids must differ")


@app.get("/api/analyses/{base_id}/diff/{target_id}")
def diff_versions(base_id: str, target_id: str) -> dict[str, Any]:
    """Compare final effective actions of two saved versions.

    Every address covered by either version is classified by its effective
    action in each version (``permit``/``deny``, ``none`` when no rule
    matches).  Only addresses whose action changed are returned, as minimal
    CIDR ranges grouped by the six change types; adjacent ranges of the same
    type are merged.
    """
    _validate_analysis_id_pair(base_id, target_id)

    base = db.get_analysis(base_id)
    if base is None:
        raise HTTPException(status_code=404, detail=f"analysis '{base_id}' not found")
    target = db.get_analysis(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail=f"analysis '{target_id}' not found")

    return diff_analyses(base, target)


@app.post("/api/analyses/{base_id}/change-guard/{target_id}", status_code=200)
def change_guard_versions(base_id: str, target_id: str, req: ChangeGuardRequest) -> dict[str, Any]:
    """Authorize the base→target semantic diff against caller-supplied grants.

    Each authorization entry grants one action transition
    (``permit``/``deny``/``none`` → a *different* one) on one strict CIDR.
    A changed address is authorized only when covered by a grant of the same
    IP family and the same transition; grants of one transition are unioned
    (nesting/duplicates allowed), while overlapping grants of different
    transitions are rejected with ``400``.  The response reports ``passed``
    and, per transition, the unauthorized surface as minimal CIDRs with exact
    address counts.  Nothing is persisted.
    """
    _validate_analysis_id_pair(base_id, target_id)

    # The authorization set is validated before the versions are looked up,
    # mirroring the decision-map endpoint's format-before-existence ordering.
    grants = parse_guard_entries([e.model_dump() for e in req.authorizations])

    base = db.get_analysis(base_id)
    if base is None:
        raise HTTPException(status_code=404, detail=f"analysis '{base_id}' not found")
    target = db.get_analysis(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail=f"analysis '{target_id}' not found")

    return guard_changes(base, target, grants)


@app.get("/api/active")
def get_active_pointer() -> dict[str, Any]:
    """Current publication pointer.

    Starts at ``{"active_id": null, "revision": 0}`` and only ever points at
    saved analysis versions.
    """
    return db.get_active()


@app.post("/api/active/activate", status_code=200)
def activate_pointer(req: ActivateRequest) -> dict[str, Any]:
    """Publish a saved analysis version as the active one.

    The request carries the ``revision`` the caller last saw on
    ``GET /api/active``. Inside one SQLite transaction the stored revision is
    compared with ``expected_revision``; on a match the pointer moves to the
    target version, the revision increments and an audit row (previous/new
    versions, revision, timestamp) is appended. A stale ``expected_revision``
    means another publish won the race and yields ``409`` with the current
    state. Only saved versions may be published; unknown targets are ``404``.
    """
    if not ANALYSIS_ID_RE.match(req.analysis_id):
        raise HTTPException(
            status_code=400,
            detail=f"invalid analysis id format: '{req.analysis_id}'; "
            "expected 'an_' followed by 16 lowercase hexadecimal characters",
        )

    # Existence is checked before opening the write transaction, so requests
    # for unsaved/unknown versions never take the publication write lock.
    if db.get_analysis(req.analysis_id) is None:
        raise HTTPException(status_code=404, detail=f"analysis '{req.analysis_id}' not found")

    result = db.activate_pointer(req.analysis_id, req.expected_revision)
    return {
        "active": {
            "active_id": result["active_id"],
            "revision": result["revision"],
            "activated_at": result["activated_at"],
            "history_seq": result["history_seq"],
        },
        "previous": result["previous"],
    }


@app.get("/api/active/history")
def get_active_history(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Read-only audit log of successful pointer switches, newest first."""
    total, entries = db.list_active_history(limit=limit, offset=offset)
    return {"total": total, "history": entries}
