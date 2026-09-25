"""Core engine: longest-prefix + priority coverage and conflict analysis.

Semantics
---------
Each input rule has:

* ``cidr``      : an IPv4/IPv6 network in CIDR notation (host bits must be zero)
* ``action``    : ``permit`` (allow) or ``deny`` (block); aliases accepted
* ``priority``  : integer, **smaller value = higher priority**
* ``source_tag``: free-form label identifying where the rule came from

Forwarding follows classical *longest prefix match* (LPM): the rule with the
longest matching prefix decides the packet.  Priority only breaks ties between
rules that carry the *exact same* CIDR.  This means a long-prefix rule wins
inside its network even when its numeric priority is lower — such a case is
flagged as a ``priority_inversion`` observation.

Coverage of a rule R is
``cidr(R) minus the union of cidr(D) for every winning rule D in R's subtree``.
Winning rules with the same CIDR are grouped into one trie node; among them the
highest-priority rule (smallest number, ties broken by input order) is the
*winner*, the others are *duplicates* and never cover any address space.

A *minimal conflict pair* is generated from every rule N that effectively
forwards at least one address (``effective`` is non-empty): walk up N's
ancestor chain, **skip ancestors whose winning action equals N's action**
(they agree with N, so N changes nothing relative to them), and pair N with
the first ancestor carrying a different action.  The pair's ``override_range``
is exactly N's effective coverage.  Skipping same-action ancestors keeps the
set minimal while never losing a behavioural conflict: a fully shadowed
deny-parent between a deny-child and a permit-grandparent is transparently
jumped over.  The result is deterministic for identical input.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Iterable

ANALYZER_VERSION = "1.0.0"

# Accepted action spellings.
ACTION_ALIASES: dict[str, str] = {
    "permit": "permit",
    "allow": "permit",
    "accept": "permit",
    "pass": "permit",
    "deny": "deny",
    "block": "deny",
    "drop": "deny",
    "reject": "deny",
}


class ValidationError(Exception):
    """Raised when a submitted rule set is structurally invalid."""


def normalize_action(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"action must be a string, got {value!r}")
    key = value.strip().lower()
    if key not in ACTION_ALIASES:
        raise ValidationError(
            f"invalid action {value!r}; expected permit/allow or deny/block/drop"
        )
    return ACTION_ALIASES[key]


def _as_int(value: Any, field_name: str) -> int:
    # Reject booleans (bool is a subclass of int) and floats.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field_name} must be an integer, got {value!r}")
    return value


@dataclass
class InputRule:
    index: int
    rule_id: str
    network: ipaddress._BaseNetwork
    action: str
    priority: int
    source_tag: str


@dataclass
class Node:
    """A trie node: one distinct CIDR, containing same-CIDR duplicates."""

    network: ipaddress._BaseNetwork
    members: list[InputRule] = field(default_factory=list)
    winner: InputRule | None = None
    children: list["Node"] = field(default_factory=list)
    parent: "Node | None" = None
    effective: list[ipaddress._BaseNetwork] = field(default_factory=list)
    status: str = "active"  # active | partial | shadowed


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------
def _parse_rule(raw: Any, index: int) -> InputRule:
    if not isinstance(raw, dict):
        raise ValidationError(f"rule #{index + 1} must be an object")

    missing = [k for k in ("cidr", "action") if k not in raw]
    if missing:
        raise ValidationError(
            f"rule #{index + 1} is missing required field(s): {', '.join(missing)}"
        )

    cidr = raw["cidr"]
    if not isinstance(cidr, str):
        raise ValidationError(f"rule #{index + 1}: cidr must be a string")
    try:
        # strict=True rejects inputs with host bits set, e.g. 10.0.0.5/24.
        network = ipaddress.ip_network(cidr.strip(), strict=True)
    except ValueError as exc:
        raise ValidationError(f"rule #{index + 1}: invalid CIDR {cidr!r} ({exc})")

    action = normalize_action(raw.get("action"))
    priority = _as_int(raw.get("priority", 100), "priority")
    source_tag = raw.get("source_tag")
    if source_tag is None:
        source_tag = "default"
    elif not isinstance(source_tag, str) or not source_tag.strip():
        raise ValidationError(f"rule #{index + 1}: source_tag must be a non-empty string")

    given_id = raw.get("rule_id")
    if given_id is None:
        rule_id = f"r{index + 1}"
    elif isinstance(given_id, str) and given_id.strip():
        rule_id = given_id
    else:
        raise ValidationError(f"rule #{index + 1}: rule_id must be a non-empty string")

    return InputRule(
        index=index,
        rule_id=rule_id,
        network=network,
        action=action,
        priority=priority,
        source_tag=source_tag,
    )


def _parse_rules(raw_rules: Any) -> list[InputRule]:
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ValidationError("rules must be a non-empty list")
    parsed = [_parse_rule(r, i) for i, r in enumerate(raw_rules)]
    seen: set[str] = set()
    for r in parsed:
        if r.rule_id in seen:
            raise ValidationError(f"duplicate rule_id {r.rule_id!r}; rule_id must be unique")
        seen.add(r.rule_id)
    return parsed


# ---------------------------------------------------------------------------
# Geometry helpers
# ---------------------------------------------------------------------------
def _subtract(
    network: ipaddress._BaseNetwork,
    cutters: Iterable[ipaddress._BaseNetwork],
) -> list[ipaddress._BaseNetwork]:
    """Return CIDRs covering ``network`` minus the union of ``cutters``.

    The caller guarantees every cutter is a strict subnet of ``network`` and
    that cutters are pairwise disjoint (true for distinct children of one trie
    node), so ``ipaddress.address_exclude`` can be applied in sequence.
    """
    remaining = [network]
    for cutter in cutters:
        next_remaining: list[ipaddress._BaseNetwork] = []
        for piece in remaining:
            if cutter.version != piece.version:
                raise ValidationError("internal: cannot mix IPv4 and IPv6 networks")
            if cutter == piece:
                # Fully removed.
                continue
            if cutter.subnet_of(piece):
                next_remaining.extend(piece.address_exclude(cutter))
            else:
                next_remaining.append(piece)
        remaining = next_remaining
    return remaining


def _sort_networks(
    networks: Iterable[ipaddress._BaseNetwork],
) -> list[ipaddress._BaseNetwork]:
    return sorted(networks, key=lambda n: (n.version, int(n.network_address), n.prefixlen))


def _addr_count(networks: Iterable[ipaddress._BaseNetwork]) -> int:
    return sum(n.num_addresses for n in networks)


# ---------------------------------------------------------------------------
# Canonicalization / idempotency hash
# ---------------------------------------------------------------------------
def canonical_input(rules: list[InputRule]) -> str:
    payload = [
        {
            "rule_id": r.rule_id,
            "cidr": str(r.network),
            "action": r.action,
            "priority": r.priority,
            "source_tag": r.source_tag,
        }
        for r in rules
    ]
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------
def analyze_rules(raw_rules: Any) -> dict[str, Any]:
    rules = _parse_rules(raw_rules)

    # ---- Group same-CIDR rules; choose a winner per group ----------------
    groups: dict[str, list[InputRule]] = {}
    for r in rules:
        groups.setdefault(str(r.network), []).append(r)

    nodes: list[Node] = []
    for cidr, members in groups.items():
        # Higher priority = smaller number; input order is the final tie-break.
        ordered = sorted(members, key=lambda r: (r.priority, r.index))
        node = Node(network=ipaddress.ip_network(cidr), members=ordered, winner=ordered[0])
        nodes.append(node)

    nodes_by_version: dict[int, list[Node]] = {4: [], 6: []}
    for node in nodes:
        nodes_by_version[node.network.version].append(node)
    for version_nodes in nodes_by_version.values():
        version_nodes.sort(key=lambda n: (int(n.network.network_address), n.network.prefixlen))

    # ---- Build containment trie (nearest enclosing winning node) --------
    for version, version_nodes in nodes_by_version.items():
        for node in version_nodes:
            net = node.network
            best: Node | None = None
            best_prefix = -1
            for candidate in version_nodes:
                if candidate is node:
                    continue
                cnet = candidate.network
                if cnet.prefixlen < net.prefixlen and net.subnet_of(cnet):
                    if cnet.prefixlen > best_prefix:
                        best = candidate
                        best_prefix = cnet.prefixlen
            node.parent = best
            if best is not None:
                best.children.append(node)

    for version_nodes in nodes_by_version.values():
        for node in version_nodes:
            node.children.sort(
                key=lambda n: (int(n.network.network_address), n.network.prefixlen)
            )

    # ---- Effective coverage per node -------------------------------------
    for version_nodes in nodes_by_version.values():
        for node in version_nodes:
            node.effective = _subtract(
                node.network, (child.network for child in node.children)
            )
            if not node.effective:
                node.status = "shadowed"
            elif node.children:
                node.status = "partial"
            else:
                node.status = "active"

    node_by_network: dict[str, Node] = {str(n.network): n for n in nodes}
    node_by_rule: dict[str, Node] = {}
    for node in nodes:
        for member in node.members:
            node_by_rule[member.rule_id] = node

    out_rules: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    minimal_pairs: list[dict[str, Any]] = []

    # ---- Duplicates inside a node ----------------------------------------
    for node in _sort_nodes(nodes):
        winner = node.winner
        assert winner is not None
        for loser in node.members[1:]:
            node_by_rule[loser.rule_id] = node
            same_action = loser.action == winner.action
            findings.append(
                {
                    "type": "duplicate",
                    "severity": "info" if same_action else "conflict",
                    "rule_id": loser.rule_id,
                    "other_rule_id": winner.rule_id,
                    "cidr": str(node.network),
                    "loser_action": loser.action,
                    "winner_action": winner.action,
                    "action_conflict": not same_action,
                    "behavioral": not same_action and bool(node.effective),
                    "reason": (
                        f"rule '{loser.rule_id}' shares CIDR {node.network} with higher-priority "
                        f"rule '{winner.rule_id}'; exact-prefix ties are resolved by priority "
                        f"({loser.priority} >= {winner.priority})"
                    ),
                }
            )
            if not same_action and node.effective:
                minimal_pairs.append(
                    {
                        "kind": "duplicate",
                        "rule_id": loser.rule_id,
                        "other_rule_id": winner.rule_id,
                        "action": loser.action,
                        "other_action": winner.action,
                        "winner_rule_id": winner.rule_id,
                        "cidr": str(node.network),
                        "override_range": [str(n) for n in _sort_networks(node.effective)],
                        "reason": f"exact-prefix duplicate; '{winner.rule_id}' wins by priority",
                    }
                )

    # ---- Parent/child edges (partial overlap, conflicts, inversions) ----
    # The cover finding describes every *direct* edge in the containment trie.
    # Behavioural status for an edge is decided below from the minimal pairs.
    for parent in _sort_nodes(nodes):
        for child in parent.children:
            p_rule = parent.winner
            c_rule = child.winner
            assert p_rule is not None and c_rule is not None
            action_conflict = c_rule.action != p_rule.action
            if action_conflict:
                severity = "conflict" if child.effective else "info"
                reason = (
                    f"rule '{c_rule.rule_id}' ({c_rule.action}) overrides '{p_rule.rule_id}' "
                    f"({p_rule.action}) on {child.network} via longer prefix"
                )
            else:
                severity = "info"
                reason = (
                    f"rule '{c_rule.rule_id}' shadows part of '{p_rule.rule_id}' on {child.network}; "
                    f"actions agree ({c_rule.action})"
                )
            findings.append(
                {
                    "type": "cover",
                    "severity": severity,
                    "rule_id": c_rule.rule_id,
                    "other_rule_id": p_rule.rule_id,
                    "cidr": str(child.network),
                    "parent_cidr": str(parent.network),
                    "child_action": c_rule.action,
                    "parent_action": p_rule.action,
                    "action_conflict": action_conflict,
                    "behavioral": False,  # refined after minimal-pair computation
                    # An inversion only matters when the longer prefix also
                    # changes the action; same-action inversions are no-ops.
                    "priority_inversion": c_rule.priority > p_rule.priority and action_conflict,
                    "child_effective": [str(n) for n in _sort_networks(child.effective)],
                    "reason": reason,
                }
            )

    # ---- Shadow findings for the winning rule of each node ---------------
    for node in _sort_nodes(nodes):
        winner = node.winner
        assert winner is not None
        if node.status == "partial":
            covered = _sort_networks(
                n for child in node.children for n in [child.network]
            )
            findings.append(
                {
                    "type": "partial_shadow",
                    "severity": "info",
                    "rule_id": winner.rule_id,
                    "cidr": str(node.network),
                    "overlapped_by": [child.winner.rule_id for child in node.children],
                    "overlapped_cidrs": [str(n) for n in covered],
                    "reason": (
                        f"rule '{winner.rule_id}' ({str(node.network)}) is partially overlapped "
                        f"by {len(node.children)} longer-prefix rule(s)"
                    ),
                }
            )
        elif node.status == "shadowed":
            findings.append(
                {
                    "type": "fully_shadow",
                    "severity": "warning",
                    "rule_id": winner.rule_id,
                    "cidr": str(node.network),
                    "covered_by": [child.winner.rule_id for child in node.children],
                    "reason": (
                        f"rule '{winner.rule_id}' ({str(node.network)}) covers no addresses: "
                        f"its whole range is taken by longer-prefix rule(s)"
                    ),
                }
            )

    # ---- Minimal cover conflict pairs ------------------------------------
    # For every node that actually forwards traffic, walk up the ancestor
    # chain skipping same-action ancestors, and pair it with the first
    # different-action ancestor.  Pairs are keyed by the unordered set of
    # (child, ancestor) rule ids; if a pair ever repeats (it cannot with a
    # tree and per-node walk, but keep the guard explicit) we keep one entry.
    cover_pair_edge_index: set[tuple[str, str]] = set()
    for node in _sort_nodes(nodes):
        winner = node.winner
        assert winner is not None
        if not node.effective:
            continue
        # Walk up through same-action ancestors; ``top`` ends up as the
        # topmost node of the same-action run, so (top, ancestor) is the
        # direct trie edge where the action boundary lies.
        top = node
        ancestor = node.parent
        while ancestor is not None and ancestor.winner is not None and ancestor.winner.action == winner.action:
            top = ancestor
            ancestor = ancestor.parent
        if ancestor is None or ancestor.winner is None:
            continue
        a_rule = ancestor.winner
        minimal_pairs.append(
            {
                "kind": "cover",
                "rule_id": winner.rule_id,
                "other_rule_id": a_rule.rule_id,
                "action": winner.action,
                "other_action": a_rule.action,
                "winner_rule_id": winner.rule_id,
                "cidr": str(node.network),
                "override_range": [str(n) for n in _sort_networks(node.effective)],
                "reason": (
                    f"longest-prefix match: '{winner.rule_id}' ({winner.action}) wins over "
                    f"'{a_rule.rule_id}' ({a_rule.action}) on this range"
                ),
            }
        )
        cover_pair_edge_index.add((top.winner.rule_id, a_rule.rule_id))

    # Refine behavioural flags on direct-edge findings: an edge is behavioural
    # when it is the action-boundary edge of at least one minimal conflict pair.
    for f in findings:
        if f["type"] != "cover":
            continue
        is_boundary = (f["rule_id"], f["other_rule_id"]) in cover_pair_edge_index
        f["behavioral"] = bool(f["action_conflict"] and is_boundary)
        if f["action_conflict"] and is_boundary:
            f["severity"] = "conflict"

    # Rule ids that participate in any behavioural conflict pair.
    conflicting_rule_ids: set[str] = set()
    for p in minimal_pairs:
        conflicting_rule_ids.add(p["rule_id"])
        conflicting_rule_ids.add(p["other_rule_id"])

    # ---- Per-rule result objects -----------------------------------------
    for r in sorted(rules, key=lambda x: x.index):
        node = node_by_rule[r.rule_id]
        is_winner = node.winner is r
        if is_winner:
            effective = node.effective
            status = node.status
            covered_by = [c.winner.rule_id for c in node.children]
        else:
            effective = []
            status = "shadowed"
            covered_by = [node.winner.rule_id]
        effective_sorted = _sort_networks(effective)
        out_rules.append(
            {
                "rule_id": r.rule_id,
                "index": r.index,
                "cidr": str(r.network),
                "ip_version": r.network.version,
                "action": r.action,
                "priority": r.priority,
                "source_tag": r.source_tag,
                "role": "winner" if is_winner else "duplicate",
                "status": status,
                "covered": _addr_count(effective_sorted),
                "total_addresses": r.network.num_addresses,
                "effective_cidrs": [str(n) for n in effective_sorted],
                "covered_by": covered_by,
                "has_conflict": r.rule_id in conflicting_rule_ids,
            }
        )

    def _pair_key(p: dict[str, Any]) -> tuple:
        a, b = sorted((p["rule_id"], p["other_rule_id"]))
        return (p["kind"], a, b)

    minimal_pairs.sort(key=_pair_key)
    findings.sort(key=lambda f: (f["type"], f.get("rule_id", ""), f.get("other_rule_id", "")))

    summary = {
        "rule_count": len(rules),
        "distinct_cidrs": len(nodes),
        "ipv4_rules": sum(1 for r in rules if r.network.version == 4),
        "ipv6_rules": sum(1 for r in rules if r.network.version == 6),
        "active_rules": sum(1 for r in out_rules if r["status"] == "active"),
        "partial_rules": sum(1 for r in out_rules if r["status"] == "partial"),
        "shadowed_rules": sum(1 for r in out_rules if r["status"] == "shadowed"),
        "duplicate_rules": sum(1 for r in out_rules if r["role"] == "duplicate"),
        "conflict_findings": sum(1 for f in findings if f["severity"] == "conflict"),
        "warning_findings": sum(1 for f in findings if f["severity"] == "warning"),
        "info_findings": sum(1 for f in findings if f["severity"] == "info"),
        "behavioral_conflicts": len(minimal_pairs),
        "priority_inversions": sum(1 for f in findings if f.get("priority_inversion")),
    }

    canonical = canonical_input(rules)
    ruleset_hash = sha256(canonical.encode("utf-8")).hexdigest()

    return {
        "analyzer_version": ANALYZER_VERSION,
        "ruleset_hash": ruleset_hash,
        "rules": out_rules,
        "findings": findings,
        "minimal_conflict_pairs": minimal_pairs,
        "summary": summary,
    }


def _sort_nodes(nodes: Iterable[Node]) -> list[Node]:
    return sorted(nodes, key=lambda n: (n.network.version, int(n.network.network_address), n.network.prefixlen))
