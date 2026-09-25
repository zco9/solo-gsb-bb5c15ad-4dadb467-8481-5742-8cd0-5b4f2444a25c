"""Rule-change simulation ("what-if" preview) on top of a saved version.

A simulation rebuilds the exact analyzer input of a stored analysis version,
applies a batch of ``add`` / ``replace`` / ``remove`` operations located by
``rule_id``, and re-runs the LPM analysis **without persisting** anything.

Patch contract
--------------
* Each ``rule_id`` is the target of **at most one** operation in the whole
  batch (duplicates inside one list or across lists are rejected).
* ``add``     may only introduce rule ids that do not exist in the base
  version; the new rules are appended after the surviving base rules, in the
  request order (order still breaks same-CIDR priority ties).
* ``replace`` must hit a base rule id.  The whole rule record is replaced in
  place (the rule keeps its position); the ``rule_id`` cannot be renamed.
* ``remove``  must hit a base rule id.
* The batch is all-or-nothing: every problem is collected and the patch is
  rejected as one unit (:class:`PatchError`), so callers never see a partially
  applied preview.

Removing or rewriting a more-specific subnet rule naturally lets ancestor
rules forward that address range again — that effect is visible both in the
recomputed analysis (the ancestor's ``status``/``effective_cidrs``) and in the
effective-action diff against the base version.
"""

from __future__ import annotations

from typing import Any

#: Canonical traversal/reporting order of the three operation kinds.
OP_ORDER: tuple[str, ...] = ("add", "replace", "remove")

#: Input fields needed to re-run the analyzer, in the persisted record's
#: vocabulary (``cidr`` rather than the derived ``ip_version``).
_RULE_FIELDS = ("rule_id", "cidr", "action", "priority", "source_tag")


class PatchError(Exception):
    """The requested operation batch is invalid as a whole.

    ``issues`` lists every rejected target (deterministic order), so a client
    can correct all problems at once.
    """

    def __init__(self, issues: list[str]):
        self.issues = issues
        super().__init__("; ".join(issues))


def rebuild_input_rules(base_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Reconstruct the analyzer input (``analyze_rules`` payload) of a saved
    version from its persisted per-rule records, in original submission order.
    """
    records = sorted(base_result.get("rules", []), key=lambda r: r["index"])
    return [{field: r[field] for field in _RULE_FIELDS} for r in records]


def validate_patch(
    base_rules: list[dict[str, Any]],
    add: list[dict[str, Any]],
    replace: list[dict[str, Any]],
    remove: list[dict[str, Any]],
) -> None:
    """Validate an operation batch against the rebuilt base input.

    Raises :class:`PatchError` collecting every problem found.
    """
    groups = {"add": add, "replace": replace, "remove": remove}
    base_ids = {r["rule_id"] for r in base_rules}

    if not (add or replace or remove):
        raise PatchError(["at least one operation (add/replace/remove) is required"])

    # Every target id -> the operations naming it, in canonical op order and
    # then request order.  A target may appear at most once in the whole batch.
    targeting: dict[str, list[str]] = {}
    for op in OP_ORDER:
        for item in groups[op]:
            targeting.setdefault(item["rule_id"], []).append(op)

    issues: list[str] = []
    for rule_id in sorted(targeting):
        ops = targeting[rule_id]
        if len(ops) > 1:
            issues.append(
                f"rule_id {rule_id!r} is targeted {len(ops)} times "
                f"({', '.join(ops)}); each rule may be the target of at most one operation"
            )

    for rule_id in sorted(target_for_op(targeting, "add")):
        if rule_id in base_ids:
            issues.append(
                f"add targets existing rule_id {rule_id!r}; add may only introduce a new rule_id"
            )
    for op in ("replace", "remove"):
        for rule_id in sorted(target_for_op(targeting, op)):
            if rule_id not in base_ids:
                issues.append(
                    f"{op} targets unknown rule_id {rule_id!r}; it must match a rule of the "
                    "base version"
                )

    if issues:
        raise PatchError(issues)


def target_for_op(targeting: dict[str, list[str]], op: str) -> set[str]:
    return {rule_id for rule_id, ops in targeting.items() if op in ops}


def apply_patch(
    base_rules: list[dict[str, Any]],
    add: list[dict[str, Any]],
    replace: list[dict[str, Any]],
    remove: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Validate then apply a patch; returns the new (un-persisted) analyzer
    input.  Replaced rules keep their position, removed rules drop out, added
    rules are appended in request order.
    """
    validate_patch(base_rules, add, replace, remove)

    replacements = {r["rule_id"]: r for r in replace}
    removed = {r["rule_id"] for r in remove}

    patched = [
        replacements.get(rule["rule_id"], rule)
        for rule in base_rules
        if rule["rule_id"] not in removed
    ]
    patched.extend(add)

    if not patched:
        raise PatchError(
            ["the patch removes every rule; a simulated ruleset must contain at least one rule"]
        )
    return patched
