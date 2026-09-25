"""Observation-based policy correction ("observability rectification").

Given 1–20 traffic observations — each an IPv4/IPv6 address plus the action
(``permit``/``deny``) the policy *should* take on it — and 1–8 distinct,
existing candidate ``rule_id`` values, this module searches for the smallest
set of rule changes that makes **every** observation resolve to its expected
action when the saved ruleset is recomputed under the ordinary
longest-prefix + same-prefix-priority semantics.

Each candidate rule may be operated on in exactly one of three ways:

* ``keep``   : leave the rule untouched;
* ``disable``: remove the rule from the ruleset (its range may fall back to an
  ancestor or to a same-CIDR duplicate);
* ``flip``   : invert the rule's action in place (``permit`` ↔ ``deny``),
  keeping its CIDR, priority, source tag and submission position.

Optimization is lexicographic over the whole candidate sequence (candidates
sorted by ``rule_id``):

1. **fewest changed rules** — the number of ``keep``-less entries is minimum;
2. on a tie, **fewest ``disable`` operations**;
3. on a still-remaining tie, the **lexicographically smallest sequence of
   ``(rule_id, operation)`` pairs** — operations order alphabetically
   (``disable`` < ``flip`` < ``keep``), so the first differing candidate takes
   the alphabetically smallest operation.

There are at most eight candidates, so the whole space of
``3 ** len(candidates) <= 6561`` combinations is enumerated directly; the
winner of each combination is computed with the same LPM tie-break the engine
uses (longest prefix wins; same-CIDR ties go to the smallest ``priority``
number, then the original submission order).

An observation an active ruleset does not cover stays **uncovered**
(``matched_rule_id: null``, ``action: null``) — a miss is never treated as an
implicit ``permit``.  When no combination satisfies every observation the plan
is ``null``; when the unchanged ruleset already satisfies all observations the
plan is an empty plan (no operations).  Nothing is persisted: no analysis
version is created and the saved version is never modified.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from itertools import product
from typing import Any, Iterable

from .simulate import rebuild_input_rules

Address = ipaddress._BaseAddress
Network = ipaddress._BaseNetwork

#: The three operations a candidate rule may receive.  Their order is the
#: alphabetical order used by the final lexicographic tie-break
#: (``disable`` < ``flip`` < ``keep``).
OPERATIONS: tuple[str, ...] = ("disable", "flip", "keep")
KEEP = "keep"
DISABLE = "disable"
FLIP = "flip"

_FLIPPED_ACTION = {"permit": "deny", "deny": "permit"}


class ObservationCorrectionError(Exception):
    """The request is invalid as a whole (unknown/duplicate candidates, ...).

    ``issues`` lists every problem found, so a client can correct all of them
    at once.
    """

    def __init__(self, issues: list[str]):
        self.issues = issues
        super().__init__("; ".join(issues))


@dataclass(frozen=True)
class _Rule:
    """One rebuilt base rule with its parsed network (input order = index)."""

    index: int
    rule_id: str
    network: Network
    action: str
    priority: int


@dataclass(frozen=True)
class _Observation:
    address: Address
    expected_action: str


def _load_rules(base_rules: list[dict[str, Any]]) -> list[_Rule]:
    return [
        _Rule(
            index=index,
            rule_id=raw["rule_id"],
            network=ipaddress.ip_network(raw["cidr"]),
            action=raw["action"],
            priority=raw["priority"],
        )
        for index, raw in enumerate(base_rules)
    ]


def _parse_observations(
    records: list[dict[str, Any]], issues: list[str]
) -> list[_Observation]:
    """Parse every observation's IP, appending one issue per bad address."""
    observations: list[_Observation] = []
    for seq, rec in enumerate(records):
        try:
            address = ipaddress.ip_address(rec["ip"])
        except ValueError:
            issues.append(
                f"observation #{seq + 1}: invalid IP address {rec['ip']!r}; "
                "expected a plain IPv4 or IPv6 address (no prefix length)"
            )
            continue
        observations.append(_Observation(address=address, expected_action=rec["action"]))
    return observations


def _validate_candidate_ids(
    candidate_ids: list[str], rules: list[_Rule], issues: list[str]
) -> list[str]:
    """Validate the candidate list and return it sorted by rule_id.

    Duplicates (in request order) and unknown ids (alphabetical) are appended
    to ``issues``, mirroring the all-issues-at-once convention of other
    endpoints; on success the candidates come back sorted by rule_id.
    """
    seen: set[str] = set()
    duplicates: list[str] = []
    for rule_id in candidate_ids:
        if rule_id in seen and rule_id not in duplicates:
            duplicates.append(rule_id)
            issues.append(
                f"candidate rule_id {rule_id!r} appears more than once; "
                "candidates must be distinct"
            )
        seen.add(rule_id)

    existing = {rule.rule_id for rule in rules}
    for rule_id in sorted(seen - existing):
        issues.append(
            f"candidate rule_id {rule_id!r} does not exist in this analysis version"
        )

    return sorted(set(candidate_ids))


def _covering_groups(
    address: Address, rules: Iterable[_Rule]
) -> list[list[_Rule]]:
    """Rules covering ``address`` grouped by prefix length, longest first.

    Rules sharing one prefix length necessarily share the CIDR (equal-length
    networks containing one address are identical), so each group is one
    same-CIDR set whose members are ordered exactly like the engine's
    priority tie-break ``(priority, index)``.
    """
    by_prefix: dict[int, list[_Rule]] = {}
    for rule in rules:
        if rule.network.version != address.version:
            continue
        if address in rule.network:
            by_prefix.setdefault(rule.network.prefixlen, []).append(rule)
    groups = [
        sorted(members, key=lambda r: (r.priority, r.index))
        for members in by_prefix.values()
    ]
    groups.sort(key=lambda group: -group[0].network.prefixlen)
    return groups


def _winner(
    groups: list[list[_Rule]],
    disabled: frozenset[str],
    flipped: frozenset[str],
) -> tuple[str | None, str | None]:
    """Winning rule/action for one address under one operation combination.

    The longest prefix group with a non-disabled member decides; within it the
    highest-priority surviving member wins, with a flipped action applied when
    that member is flipped.  Returns ``(None, None)`` when nothing survives —
    a miss, never an implicit permit.
    """
    for group in groups:
        survivors = [rule for rule in group if rule.rule_id not in disabled]
        if survivors:
            winner = survivors[0]
            action = (
                _FLIPPED_ACTION[winner.action]
                if winner.rule_id in flipped
                else winner.action
            )
            return winner.rule_id, action
    return None, None


def _operation_entry(rule: _Rule, operation: str) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "rule_id": rule.rule_id,
        "operation": operation,
        "from_action": rule.action,
    }
    if operation == FLIP:
        entry["to_action"] = _FLIPPED_ACTION[rule.action]
    else:
        # Disabling does not assign the rule a new action.
        entry["to_action"] = None
    return entry


def correct_observations(
    base: dict[str, Any],
    records: list[dict[str, Any]],
    candidate_ids: list[str],
) -> dict[str, Any]:
    """Find the minimum change plan satisfying all observations.

    ``records`` carry already-normalized ``ip`` / ``action`` pairs and
    ``candidate_ids`` are 1–8 distinct rule ids of the saved version ``base``.
    Returns a response-shaped dict (see module docstring); raises
    :class:`ObservationCorrectionError` for duplicate/unknown candidates or
    invalid IPs.  The saved version is only read.
    """
    rules = _load_rules(rebuild_input_rules(base))

    # Validate the whole request in one pass: observation issues (in record
    # order) are reported before candidate issues, and every problem is listed.
    issues: list[str] = []
    observations = _parse_observations(records, issues)
    candidates_sorted = _validate_candidate_ids(candidate_ids, rules, issues)
    if issues:
        raise ObservationCorrectionError(issues)

    rules_by_id = {rule.rule_id: rule for rule in rules}
    candidate_rules = [rules_by_id[rule_id] for rule_id in candidates_sorted]

    # Per-observation covering groups are fixed by the base ruleset: only the
    # enabled/flipped state of candidates changes between combinations.
    cover = [_covering_groups(obs.address, rules) for obs in observations]

    best_key: tuple[int, int, tuple[str, ...]] | None = None
    best_ops: tuple[str, ...] | None = None

    for operations in product(OPERATIONS, repeat=len(candidate_rules)):
        disabled = frozenset(
            rule_id
            for rule_id, op in zip(candidates_sorted, operations)
            if op == DISABLE
        )
        flipped = frozenset(
            rule_id
            for rule_id, op in zip(candidates_sorted, operations)
            if op == FLIP
        )

        for groups, observation in zip(cover, observations):
            _winner_id, action = _winner(groups, disabled, flipped)
            if action != observation.expected_action:
                break
        else:
            changed = sum(1 for op in operations if op != KEEP)
            disabled_count = sum(1 for op in operations if op == DISABLE)
            # The alphabetical OPERATIONS ordering makes plain tuple
            # comparison exactly the prescribed (rule_id, operation) sequence
            # order (candidates are already sorted by rule_id).
            key = (changed, disabled_count, operations)
            if best_key is None or key < best_key:
                best_key = key
                best_ops = operations

    common = {
        "analysis_id": base.get("id"),
        "ruleset_hash": base.get("ruleset_hash"),
        "analyzer_version": base.get("analyzer_version"),
        "observation_count": len(observations),
        "candidate_rule_ids": candidates_sorted,
    }

    if best_ops is None:
        # No combination makes every observation hit its expected action.
        return {**common, "solvable": False, "plan": None, "observations": None}

    disabled_final = frozenset(
        rule_id
        for rule_id, op in zip(candidates_sorted, best_ops)
        if op == DISABLE
    )
    flipped_final = frozenset(
        rule_id
        for rule_id, op in zip(candidates_sorted, best_ops)
        if op == FLIP
    )

    observation_results: list[dict[str, Any]] = []
    for seq, (observation, groups) in enumerate(zip(observations, cover)):
        winner_id, action = _winner(groups, disabled_final, flipped_final)
        observation_results.append(
            {
                "seq": seq,
                "ip": str(observation.address),
                "ip_version": observation.address.version,
                "expected_action": observation.expected_action,
                "matched_rule_id": winner_id,
                "action": action,
                "satisfied": action == observation.expected_action,
            }
        )

    chosen_ops = [
        _operation_entry(rule, op)
        for rule, op in zip(candidate_rules, best_ops)
        if op != KEEP
    ]
    disabled_count = sum(1 for op in best_ops if op == DISABLE)
    flipped_count = sum(1 for op in best_ops if op == FLIP)
    kept_count = len(best_ops) - disabled_count - flipped_count

    plan = {
        "operations": chosen_ops,
        "changed_rule_count": disabled_count + flipped_count,
        "disabled_count": disabled_count,
        "flipped_count": flipped_count,
        "kept_count": kept_count,
    }

    return {**common, "solvable": True, "plan": plan, "observations": observation_results}
