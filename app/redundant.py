"""Redundant-rule inventory for a saved analysis version.

For every rule of the version, in original submission order, this module
removes exactly that rule, re-runs the longest-prefix-match analysis on the
remaining rules, and compares the resulting *final effective actions*
(``permit`` / ``deny`` / ``none``) against the original version over both
address families — the same geometric semantic diff as
``GET /api/analyses/{base}/diff/{target}``.

A rule is reported ``safe_to_remove`` only when **no address at all** changes
its final action.  The flag is never inferred from the rule's ``shadowed``
status or from same-action overlaps alone: a fully shadowed rule is indeed
always safe, but so is an active rule whose entire range falls back to a
same-action ancestor, while removing a *winner* flips its range when a
same-CIDR duplicate or a different-action ancestor takes over.  Only the
recomputed verdict decides, and the per-rule ``changed_addresses`` count is
the exact number of addresses (IPv4 + IPv6) whose action would change.

The inventory is read-only: the analyzer is re-run in memory only, nothing
is persisted and no new analysis version is created.
"""

from __future__ import annotations

from typing import Any

from .analyzer import analyze_rules
from .diff import diff_analyses
from .simulate import rebuild_input_rules


def _empty_analysis() -> dict[str, Any]:
    """Effective-action surface of an empty rule set (everything is ``none``).

    ``analyze_rules`` requires at least one rule, so deleting the last
    remaining rule of a single-rule version is compared against this
    synthetic empty result instead.
    """
    return {"id": None, "ruleset_hash": None, "analyzer_version": None, "rules": []}


def redundant_rule_inventory(base: dict[str, Any]) -> dict[str, Any]:
    """Check every rule of a saved version for individual removability.

    ``base`` is the stored analysis result (as returned by
    ``db.get_analysis``).  The returned entries follow the original rule
    order and carry ``rule_id``, ``safe_to_remove`` and the exact number of
    addresses whose final action would change if that rule were deleted.
    """
    base_input = rebuild_input_rules(base)

    entries: list[dict[str, Any]] = []
    for rule in base_input:
        remaining = [r for r in base_input if r["rule_id"] != rule["rule_id"]]
        # Recompute the longest-prefix verdict without this one rule...
        reduced = analyze_rules(remaining) if remaining else _empty_analysis()
        # ...then compare final permit/deny/none actions on every address.
        diff = diff_analyses(base, reduced)
        changed = diff["summary"]["total_changed_addresses"]
        entries.append(
            {
                "rule_id": rule["rule_id"],
                "safe_to_remove": changed == 0,
                "changed_addresses": changed,
            }
        )

    return {
        "analysis_id": base.get("id"),
        "ruleset_hash": base.get("ruleset_hash"),
        "analyzer_version": base.get("analyzer_version"),
        "summary": {
            "rule_count": len(entries),
            "safe_to_remove_count": sum(1 for e in entries if e["safe_to_remove"]),
        },
        "rules": entries,
    }
