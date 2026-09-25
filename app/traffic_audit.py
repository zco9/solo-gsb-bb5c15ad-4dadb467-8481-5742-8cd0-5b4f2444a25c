"""Traffic observation audit ("attribution") against a saved analysis version.

Given a batch of observed access records — each an IPv4/IPv6 address, the
*observed* action (``permit``/``deny``) and an optional positive integer
weight — this module attributes every observation to the rule of the saved
version that *would* decide it, and checks whether the observed action agrees
with the expected one.

Attribution semantics
---------------------
Attribution replays the engine's forwarding decision for a single address:

* **longest prefix wins**: among the rules whose CIDR contains the address
  (same IP family only), the rule with the longest prefix decides — never
  the first matching rule in submission order, and never the record order;
* **same-CIDR ties** go to the smallest ``priority`` number, then to the
  original submission order (the stored ``index``) — exactly the engine's
  tie-break, so losing duplicates never win an attribution;
* an address no rule covers is reported as **uncovered**: ``expected_action``
  is ``null`` and no action is inferred for it (it is neither counted as
  consistent nor as a mismatch).

The batch is all-or-nothing: any invalid IP address rejects the whole
request (:class:`TrafficAuditError`) with every offending record listed at
once.  Nothing is persisted and the analyzer is never re-run: the audit only
reads the version's stored rules.

Aggregation
-----------
Every record carries a weight (``count``, default 1).  The response
aggregates the weighted counts three ways: per winning rule (``by_rule``),
per action mismatch (``mismatches``, grouped by
rule/expected/observed action), and for the uncovered surface
(``uncovered``, grouped by IP family and observed action).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from .simulate import rebuild_input_rules

Address = ipaddress._BaseAddress
Network = ipaddress._BaseNetwork


class TrafficAuditError(Exception):
    """The record batch is invalid as a whole.

    ``issues`` lists every offending record (in record order), so a client
    can correct all problems at once.
    """

    def __init__(self, issues: list[str]):
        self.issues = issues
        super().__init__("; ".join(issues))


@dataclass(frozen=True)
class _Rule:
    """One stored rule with its parsed network (submission order = index)."""

    index: int
    rule_id: str
    network: Network
    action: str
    priority: int


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


def _winner_for(address: Address, rules: list[_Rule]) -> _Rule | None:
    """Winning rule for one address under LPM + same-CIDR priority.

    The longest matching prefix decides; rules sharing that prefix (they
    necessarily share the CIDR — equal-length networks containing one
    address are identical) are ordered by ``(priority, index)`` exactly like
    the engine.  ``None`` means no rule covers the address.
    """
    longest = -1
    candidates: list[_Rule] = []
    for rule in rules:
        if rule.network.version != address.version:
            continue
        if address not in rule.network:
            continue
        if rule.network.prefixlen > longest:
            longest = rule.network.prefixlen
            candidates = [rule]
        elif rule.network.prefixlen == longest:
            candidates.append(rule)
    if not candidates:
        return None
    candidates.sort(key=lambda r: (r.priority, r.index))
    return candidates[0]


def _parse_addresses(records: list[dict[str, Any]]) -> list[Address]:
    """Parse every record's IP; any failure rejects the whole batch."""
    issues: list[str] = []
    addresses: list[Address | None] = []
    for seq, rec in enumerate(records):
        try:
            addresses.append(ipaddress.ip_address(rec["ip"]))
        except ValueError:
            issues.append(
                f"record #{seq + 1}: invalid IP address {rec['ip']!r}; "
                "expected a plain IPv4 or IPv6 address (no prefix length)"
            )
            addresses.append(None)
    if issues:
        raise TrafficAuditError(issues)
    return [a for a in addresses if a is not None]


def audit_traffic(base: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    """Attribute ``records`` to the winning rules of the saved version ``base``.

    ``records`` carry ``ip`` / ``action`` (already normalized) / ``count``
    (positive integer weight).  Returns a response-shaped dict (see module
    docstring).  Raises :class:`TrafficAuditError` when any record's IP is
    invalid; the batch is all-or-nothing.
    """
    rules = _load_rules(rebuild_input_rules(base))
    addresses = _parse_addresses(records)

    results: list[dict[str, Any]] = []
    by_rule: dict[str, dict[str, Any]] = {}
    mismatches: dict[tuple[str, str, str], dict[str, Any]] = {}
    uncovered: dict[tuple[int, str], dict[str, Any]] = {}

    covered_records = covered_count = 0
    consistent_records = consistent_count = 0
    mismatch_records = mismatch_count = 0
    family: dict[int, list[int]] = {4: [0, 0], 6: [0, 0]}  # version -> [records, count]

    for seq, (rec, address) in enumerate(zip(records, addresses)):
        weight = rec["count"]
        observed = rec["action"]
        winner = _winner_for(address, rules)

        if winner is None:
            verdict = "uncovered"
            consistent: bool | None = None
            matched_rule_id = None
            expected_action = None
        else:
            matched_rule_id = winner.rule_id
            expected_action = winner.action
            consistent = observed == expected_action
            verdict = "consistent" if consistent else "mismatch"

        results.append(
            {
                "seq": seq,
                "ip": str(address),
                "ip_version": address.version,
                "observed_action": observed,
                "count": weight,
                "verdict": verdict,
                "matched_rule_id": matched_rule_id,
                "expected_action": expected_action,
                "consistent": consistent,
            }
        )

        fam = family[address.version]
        fam[0] += 1
        fam[1] += weight

        if winner is None:
            bucket = uncovered.setdefault(
                (address.version, observed),
                {
                    "ip_version": address.version,
                    "observed_action": observed,
                    "records": 0,
                    "count": 0,
                },
            )
            bucket["records"] += 1
            bucket["count"] += weight
            continue

        covered_records += 1
        covered_count += weight
        rule_bucket = by_rule.setdefault(
            winner.rule_id,
            {
                "rule_id": winner.rule_id,
                "action": winner.action,
                "records": 0,
                "count": 0,
                "consistent_count": 0,
                "mismatch_count": 0,
            },
        )
        rule_bucket["records"] += 1
        rule_bucket["count"] += weight
        if consistent:
            consistent_records += 1
            consistent_count += weight
            rule_bucket["consistent_count"] += weight
        else:
            mismatch_records += 1
            mismatch_count += weight
            rule_bucket["mismatch_count"] += weight
            mismatch_bucket = mismatches.setdefault(
                (winner.rule_id, winner.action, observed),
                {
                    "rule_id": winner.rule_id,
                    "expected_action": winner.action,
                    "observed_action": observed,
                    "records": 0,
                    "count": 0,
                },
            )
            mismatch_bucket["records"] += 1
            mismatch_bucket["count"] += weight

    by_rule_list = sorted(by_rule.values(), key=lambda b: (-b["count"], b["rule_id"]))
    mismatch_list = sorted(
        mismatches.values(),
        key=lambda b: (-b["count"], b["rule_id"], b["expected_action"], b["observed_action"]),
    )
    uncovered_list = sorted(
        uncovered.values(), key=lambda b: (b["ip_version"], b["observed_action"])
    )

    total_count = covered_count + sum(b["count"] for b in uncovered_list)
    summary = {
        "record_count": len(records),
        "total_count": total_count,
        "covered": {"records": covered_records, "count": covered_count},
        "uncovered": {
            "records": len(records) - covered_records,
            "count": total_count - covered_count,
        },
        "consistent": {"records": consistent_records, "count": consistent_count},
        "mismatch": {"records": mismatch_records, "count": mismatch_count},
        "ipv4": {"records": family[4][0], "count": family[4][1]},
        "ipv6": {"records": family[6][0], "count": family[6][1]},
    }

    return {
        "analysis_id": base.get("id"),
        "ruleset_hash": base.get("ruleset_hash"),
        "analyzer_version": base.get("analyzer_version"),
        "record_count": len(records),
        "results": results,
        "by_rule": by_rule_list,
        "mismatches": mismatch_list,
        "uncovered": uncovered_list,
        "summary": summary,
    }
