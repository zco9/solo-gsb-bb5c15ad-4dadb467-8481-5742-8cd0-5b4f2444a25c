"""Source-tag retirement preview for a saved analysis version.

For every distinct ``source_tag`` of the version, in original first-seen
order, this module removes **all** rules carrying that tag in one batch,
re-runs the longest-prefix-match + same-CIDR-priority analysis on the
remaining rules, and compares the resulting *final effective actions*
(``permit`` / ``deny`` / ``none``) against the original version over both
address families — the same geometric semantic diff as
``GET /api/analyses/{base}/diff/{target}``.

A source is reported ``safe_to_retire`` (can be withdrawn as a whole group)
only when **no address at all** changes its final action after the group
removal.  The group verdict is never inferred from per-rule removability:
even when deleting each of the source's rules *individually* leaves the
forwarding surface unchanged, deleting them *together* can still change
actions — for example several same-action rules that redundantly back one
another up, or the same-CIDR winner together with its duplicate.  Only the
recomputed whole-group verdict decides.

Deleting every rule of the version (the only source tag present) is legal:
the remainder is the empty rule set, compared as "every address unmatched"
so the source's full coverage is reported as ``*_to_none`` changes.

The report is read-only: the analyzer is re-run in memory only, nothing is
persisted and no new analysis version is created.
"""

from __future__ import annotations

from typing import Any

from .analyzer import analyze_rules
from .diff import diff_analyses
from .simulate import rebuild_input_rules


def _empty_analysis() -> dict[str, Any]:
    """Effective-action surface of an empty rule set (everything is ``none``).

    ``analyze_rules`` requires at least one rule, so removing the last
    remaining rules (retiring the only source tag of a version) is compared
    against this synthetic empty result instead.
    """
    return {"id": None, "ruleset_hash": None, "analyzer_version": None, "rules": []}


def source_retirement_report(base: dict[str, Any]) -> dict[str, Any]:
    """Preview whole-group withdrawal of every source tag of a saved version.

    ``base`` is the stored analysis result (as returned by
    ``db.get_analysis``).  The returned source entries follow the original
    first-seen order of the tags; inside each entry the removed ``rule_ids``
    follow the original submission order.
    """
    base_input = rebuild_input_rules(base)

    # First-seen order of the tags, matching the original rule sequence.
    source_order: list[str] = []
    for rule in base_input:
        tag = rule["source_tag"]
        if tag not in source_order:
            source_order.append(tag)

    sources: list[dict[str, Any]] = []
    for tag in source_order:
        tagged = [r for r in base_input if r["source_tag"] == tag]
        removed_ids = [r["rule_id"] for r in tagged]
        remaining = [r for r in base_input if r["source_tag"] != tag]

        # Recompute the longest-prefix + same-CIDR-priority verdict with the
        # whole group gone at once — never as the union of single-rule deletes.
        retired = analyze_rules(remaining) if remaining else _empty_analysis()
        diff = diff_analyses(base, retired)

        changed_addresses = diff["summary"]["total_changed_addresses"]
        sources.append(
            {
                "source_tag": tag,
                "rule_ids": removed_ids,
                "rule_count": len(removed_ids),
                "safe_to_retire": changed_addresses == 0,
                "changed_addresses": changed_addresses,
                "changes": diff["changes"],
                "summary": {
                    "changed_addresses": changed_addresses,
                    "change_groups": diff["summary"]["total_change_groups"],
                    "ipv4": diff["summary"]["ipv4"],
                    "ipv6": diff["summary"]["ipv6"],
                },
            }
        )

    return {
        "analysis_id": base.get("id"),
        "ruleset_hash": base.get("ruleset_hash"),
        "analyzer_version": base.get("analyzer_version"),
        "summary": {
            "source_count": len(sources),
            "rule_count": len(base_input),
            "safe_to_retire_count": sum(1 for s in sources if s["safe_to_retire"]),
        },
        "sources": sources,
    }
