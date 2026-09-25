"""Temporary quarantine ("deny") rule plan on top of a saved analysis version.

Given a *strict* target CIDR and a caller-chosen ``rule_id_prefix``, this
module deterministically derives a set of **new deny rules** (all with
``priority = 0``) whose addition to the saved ruleset would make *every*
address inside the target resolve to ``deny`` under the ordinary
longest-prefix + same-prefix-priority semantics, while leaving the final
action of every address outside the target untouched.

How candidate CIDRs are chosen
------------------------------
The target is walked recursively with the base version's *rebuilt input
rules* and the engine's own tie-break (longest prefix wins; same-CIDR ties
go to the smallest priority number, then submission order):

* a network whose current winner already forwards **deny** needs no rule
  ("already-deny addresses never generate a rule");
* an **unmatched** network (no rule covers it, ``none``) gets one new
  ``priority=0`` deny rule;
* a network won by a rule whose CIDR is a *strict supernet* also gets one
  new deny rule — a strictly longer prefix wins by LPM regardless of the
  ancestor's priority;
* a network whose CIDR coincides with an existing winner gets a new deny
  rule only when that winner's priority is numerically greater than ``0``
  (the fresh ``priority=0`` rule then wins the same-CIDR tie);
* when the coinciding winner already sits at **priority 0**, a same-CIDR
  deny rule cannot win, so the network is **subdivided** one prefix length
  at a time and each half is re-evaluated against the real ruleset — the
  halves are strictly longer than the bypassed priority-0 rule, so they
  resolve via their own (enclosing) decision, and deny rules placed on them
  win outright;
* subdivision reaching a single host (``/32`` for IPv4, ``/128`` for IPv6)
  that is still held by a priority-0 non-deny winner cannot be outranked by
  any CIDR rule — that host is reported as **not generatable**, together
  with the blocking original rule's CIDR.

Generated rule ids are ``<rule_id_prefix><n>`` with a continuous sequence
starting at 1, assigned in deterministic address-traversal order; a
collision with any rule id of the base version rejects the whole request
with :class:`QuarantinePlanError`.

The candidate ruleset is always re-analyzed with the real engine and
re-compared against the base version with the semantic diff, so the reported
converted surface is a recomputed verdict, not an assumption.  Nothing is
persisted: no analysis version is created and the base is never modified.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, NamedTuple

from .analyzer import _sort_networks, _subtract, analyze_rules
from .decision_map import build_decision_map
from .diff import diff_analyses
from .simulate import rebuild_input_rules

Network = ipaddress._BaseNetwork

#: Every quarantine rule is a deny rule at the numerically highest priority.
QUARANTINE_ACTION = "deny"
QUARANTINE_PRIORITY = 0

#: Provenance label stamped on every generated rule (visible in the candidate).
QUARANTINE_SOURCE_TAG = "quarantine-plan"


class QuarantinePlanError(Exception):
    """The request cannot produce a plan as stated (e.g. rule id collision)."""


@dataclass(frozen=True)
class _Rule:
    """One rebuilt base rule with its parsed network (input order = index)."""

    index: int
    rule_id: str
    network: Network
    action: str
    priority: int


class _Placement(NamedTuple):
    """One new deny rule to add."""

    network: Network
    from_action: str | None  # the base decision converted: "permit" or None (none)
    supersedes_rule_id: str | None  # base winner the new rule outranks, if any
    bypassed_rule_id: str | None  # p0 same-CIDR winner that forced subdivision, if any


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


def _winner_on(
    network: Network, rules: list[_Rule]
) -> tuple[_Rule | None, bool]:
    """Return ``(winner, exact)`` for ``network`` under the base ruleset.

    ``winner`` is the longest-prefix matching rule's same-CIDR priority
    winner (smallest number, then input order); ``exact`` says whether that
    winner's CIDR coincides with ``network``.  ``(None, False)`` means no
    rule covers the network (``none``).
    """
    longest = -1
    candidates: list[_Rule] = []
    for rule in rules:
        if rule.network.version != network.version:
            continue
        if not network.subnet_of(rule.network):
            continue
        if rule.network.prefixlen > longest:
            longest = rule.network.prefixlen
            candidates = [rule]
        elif rule.network.prefixlen == longest:
            candidates.append(rule)
    if not candidates:
        return None, False
    candidates.sort(key=lambda r: (r.priority, r.index))
    winner = candidates[0]
    return winner, winner.network == network


def _distinct_inner_networks(network: Network, rules: list[_Rule]) -> list[Network]:
    """Distinct rule CIDRs that are *strict subnets* of ``network``.

    Only the roots of the inner containment forest are returned (an inner
    CIDR strictly contained in another inner CIDR is visited by recursing
    into that ancestor instead); networks are returned in deterministic
    address order.
    """
    inner = [
        rule.network
        for rule in rules
        if rule.network.version == network.version
        and rule.network.prefixlen > network.prefixlen
        and rule.network.subnet_of(network)
    ]
    roots: list[Network] = []
    for net in _sort_networks(set(inner)):
        if not any(net != other and net.subnet_of(other) for other in inner):
            roots.append(net)
    return _sort_networks(roots)


def _plan_network(
    network: Network,
    rules: list[_Rule],
    placements: list[_Placement],
    blocking: list[dict[str, Any]],
    bypassed: _Rule | None = None,
) -> None:
    """Recursively derive deny placements for one network of the target.

    The network is split between its *background* decision (its own exact
    winner, or the nearest enclosing one / ``none``) and the distinct rule
    CIDRs strictly inside it; each of those inner roots is handled by
    recursion while the background surface is covered directly.  Splitting
    on actual inner CIDRs — rather than always halving — guarantees a
    background fragment never hides a deeper rule.
    """
    winner, exact = _winner_on(network, rules)
    inner_roots = _distinct_inner_networks(network, rules)
    background = _subtract(network, inner_roots) if inner_roots else [network]

    # ---- Background surface of this network ------------------------------
    if winner is None or winner.action != QUARANTINE_ACTION:
        if (
            exact
            and winner is not None
            and winner.priority == QUARANTINE_PRIORITY
            and not inner_roots
        ):
            # The whole network is one active priority-0 non-deny winner: a
            # same-CIDR deny rule cannot win and there is no background
            # fragment to cover — subdivide and re-decide each half against
            # the real ruleset (the halves are strictly longer CIDRs).
            if network.prefixlen >= network.max_prefixlen:
                blocking.append(
                    {
                        "cidr": str(network),
                        "ip_version": network.version,
                        "address_count": network.num_addresses,
                        "blocking_cidr": str(winner.network),
                        "blocking_rule_id": winner.rule_id,
                        "blocking_action": winner.action,
                        "blocking_priority": winner.priority,
                        "reason": (
                            f"single-address block {network} is held by priority-0 rule "
                            f"'{winner.rule_id}' ({winner.action}) on {winner.network}; "
                            "a deny rule cannot outrank it at the same prefix and no "
                            "longer prefix exists"
                        ),
                    }
                )
            else:
                for half in network.subnets(new_prefix=network.prefixlen + 1):
                    _plan_network(half, rules, placements, blocking, bypassed=winner)
        else:
            # Either no exact rule blocks the same-CIDR tie (unmatched, an
            # enclosing winner, or an exact winner with priority > 0), or a
            # priority-0 exact winner coexists with inner rules: the
            # background *fragments* are then strict subnets of it, so one
            # deny rule per fragment wins by LPM even at priority 0.
            if exact and winner is not None and winner.priority == QUARANTINE_PRIORITY:
                # Fragments only exist when inner roots do; they are the
                # surface the exact priority-0 winner keeps for itself.
                fragment_bypassed = winner
            else:
                fragment_bypassed = bypassed
            for fragment in _sort_networks(background):
                placements.append(
                    _Placement(
                        network=fragment,
                        from_action=None if winner is None else winner.action,
                        supersedes_rule_id=None if winner is None else winner.rule_id,
                        bypassed_rule_id=(
                            None if fragment_bypassed is None else fragment_bypassed.rule_id
                        ),
                    )
                )

    # ---- Strictly inner rule CIDRs carry their own decisions -------------
    # An inner root is a fresh context: it is never itself a subdivision
    # half, so the outer ``bypassed`` marker must not leak into its subtree.
    for inner in inner_roots:
        _plan_network(inner, rules, placements, blocking, bypassed=None)


def plan_quarantine(
    base: dict[str, Any],
    target: Network,
    rule_id_prefix: str,
) -> dict[str, Any]:
    """Derive the deterministic quarantine plan for ``target`` on ``base``.

    Returns a response-shaped dict (see module docstring).  Raises
    :class:`QuarantinePlanError` when the generated rule ids collide with ids
    already present in the base version, or when the recomputed candidate
    violates the plan's own contract.
    """
    base_rules_raw = rebuild_input_rules(base)
    rules = _load_rules(base_rules_raw)
    base_ids = {r.rule_id for r in rules}

    # ---- Baseline decision summary of the target (read-only) -------------
    before = build_decision_map(base, target)["summary"]

    placements: list[_Placement] = []
    blocking: list[dict[str, Any]] = []
    _plan_network(target, rules, placements, blocking)

    # Background fragments and inner-root fragments are discovered in
    # traversal order (background first); normalize to the canonical network
    # order so generated ids are deterministic address-order sequence numbers.
    placements.sort(
        key=lambda p: (
            p.network.version,
            int(p.network.network_address),
            p.network.prefixlen,
        )
    )
    blocking.sort(
        key=lambda b: (int(ipaddress.ip_network(b["cidr"]).network_address),
                       ipaddress.ip_network(b["cidr"]).prefixlen)
    )

    # ---- Assign deterministic ids: prefix + continuous 1-based sequence ---
    generated_rules: list[dict[str, Any]] = []
    collisions: list[str] = []
    for seq, placement in enumerate(placements, start=1):
        rule_id = f"{rule_id_prefix}{seq}"
        if rule_id in base_ids:
            collisions.append(rule_id)
        generated_rules.append(
            {
                "rule_id": rule_id,
                "cidr": str(placement.network),
                "action": QUARANTINE_ACTION,
                "priority": QUARANTINE_PRIORITY,
                "source_tag": QUARANTINE_SOURCE_TAG,
                "address_count": placement.network.num_addresses,
                "from_action": placement.from_action,
                "supersedes_rule_id": placement.supersedes_rule_id,
                "subdivision_of_rule_id": placement.bypassed_rule_id,
            }
        )
    if collisions:
        raise QuarantinePlanError(
            "generated rule_id(s) collide with existing rules of the base version: "
            f"{', '.join(collisions)}; choose a different rule_id_prefix"
        )

    base_meta = {
        "id": base.get("id"),
        "ruleset_hash": base.get("ruleset_hash"),
        "analyzer_version": base.get("analyzer_version"),
    }

    def _result(generated: bool) -> dict[str, Any]:
        return {
            "analysis_id": base.get("id"),
            "ruleset_hash": base.get("ruleset_hash"),
            "analyzer_version": base.get("analyzer_version"),
            "base": base_meta,
            "target_cidr": str(target),
            "ip_version": target.version,
            "rule_id_prefix": rule_id_prefix,
            "generated": generated,
            "new_rules": [] if not generated else generated_rules,
            "new_rule_count": len(generated_rules) if generated else 0,
            "blocking": [] if generated else blocking,
            "candidate": None,
            "diff": None,
            "quarantined_cidrs": [],
            "quarantined_range_count": 0,
            "quarantined_addresses": 0,
            "already_deny_addresses": before["deny_addresses"],
            "summary": None,
        }

    if blocking:
        # All-or-nothing: a partial plan is never returned.  Counts describe
        # the full target so callers can see how much of it stays exposed.
        blocked_addr = sum(item["address_count"] for item in blocking)
        result = _result(False)
        result["summary"] = {
            "target_addresses": target.num_addresses,
            "already_deny_addresses": before["deny_addresses"],
            "before_permit_addresses": before["permit_addresses"],
            "before_none_addresses": before["unmatched_addresses"],
            "planned_new_rules": 0,
            "blocking_range_count": len(blocking),
            "blocking_addresses": blocked_addr,
            "quarantined_addresses": 0,
        }
        return result

    # ---- Recompute: add the rules and re-run the real LPM analysis --------
    candidate_input = list(base_rules_raw)
    candidate_input.extend(
        {
            "rule_id": rule["rule_id"],
            "cidr": rule["cidr"],
            "action": rule["action"],
            "priority": rule["priority"],
            "source_tag": rule["source_tag"],
        }
        for rule in generated_rules
    )
    candidate = analyze_rules(candidate_input)
    candidate["id"] = None
    candidate["name"] = None
    candidate["persisted"] = False

    # ---- Recompute the semantic verdict against the base version ---------
    semantic_diff = diff_analyses(base, candidate)

    # The changed surface must be entirely deny-converting and contained in
    # the target; any other change means the plan violated its own contract.
    converted_nets: list[Network] = []
    for change in semantic_diff["changes"]:
        if change["ip_version"] != target.version:
            raise QuarantinePlanError(
                f"internal: quarantine plan changes IPv{change['ip_version']} addresses "
                "outside the target family"
            )
        if change["to_action"] != QUARANTINE_ACTION:
            raise QuarantinePlanError(
                "internal: quarantine plan produced a non-deny conversion "
                f"({change['change_type']}); this must never happen"
            )
        for cidr in change["cidrs"]:
            net = ipaddress.ip_network(cidr)
            if not net.subnet_of(target):
                raise QuarantinePlanError(
                    f"internal: quarantine plan changes {cidr} outside the target {target}"
                )
            converted_nets.append(net)

    quarantined = list(ipaddress.collapse_addresses(_sort_networks(converted_nets)))
    quarantined_addresses = sum(net.num_addresses for net in quarantined)

    # Final verification against the candidate's own decision map: every
    # address of the target must now resolve to deny.
    candidate_map = build_decision_map(candidate, target)
    final_permit = candidate_map["summary"]["permit_addresses"]
    final_unmatched = candidate_map["summary"]["unmatched_addresses"]
    final_deny = candidate_map["summary"]["deny_addresses"]
    if final_permit != 0 or final_unmatched != 0 or final_deny != target.num_addresses:
        raise QuarantinePlanError(
            "internal: quarantine candidate does not deny the whole target "
            f"(deny={final_deny}, permit={final_permit}, none={final_unmatched})"
        )

    result = _result(True)
    result["candidate"] = candidate
    result["diff"] = semantic_diff
    result["quarantined_cidrs"] = [str(net) for net in quarantined]
    result["quarantined_range_count"] = len(quarantined)
    result["quarantined_addresses"] = quarantined_addresses
    result["summary"] = {
        "target_addresses": target.num_addresses,
        "already_deny_addresses": before["deny_addresses"],
        "before_permit_addresses": before["permit_addresses"],
        "before_none_addresses": before["unmatched_addresses"],
        "planned_new_rules": len(generated_rules),
        "quarantined_addresses": quarantined_addresses,
        "quarantined_ranges": len(quarantined),
        "final_deny_addresses": final_deny,
        "final_permit_addresses": final_permit,
        "final_none_addresses": final_unmatched,
        "total_changed_addresses": semantic_diff["summary"]["total_changed_addresses"],
    }
    return result
