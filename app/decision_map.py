"""CIDR decision map for a saved analysis version.

Given a *strict* IPv4/IPv6 CIDR query and one already-stored analysis result,
this module answers, for every address in the query:

* the final effective action (``permit`` / ``deny``, or ``None`` when no rule
  matches);
* the winning rule (``rule_id`` / ``source_tag``), i.e. the longest-prefix
  winner node covering the address;
* the full **match chain**: every rule whose CIDR contains the address,
  including losing exact-prefix duplicates and fully shadowed ancestor nodes.

The query range is carved geometrically into pairwise disjoint, jointly
exhaustive *minimal* CIDR blocks of constant decision.  Adjacent blocks with
the same winning rule are collapsed with
``ipaddress.collapse_addresses``; unmatched blocks (``none``) are collapsed
the same way.  Nothing is ever written and the analyzer is never re-run: the
map is derived purely from the version's stored rules and their winning
``effective_cidrs``.

Chain ordering
--------------
Longest prefix first; rules sharing the exact same CIDR are ordered by
priority (smaller number first) and then by original submission order.  When
a block matches at least one rule, the first chain entry is therefore the
winning rule; an unmatched block carries an empty chain.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any

# Reuse the engine's canonical network sorting / subtraction helpers so the
# geometry behaves exactly like in analysis and diff.
from .analyzer import _sort_networks, _subtract

Network = ipaddress._BaseNetwork


class DecisionMapError(ValueError):
    """The query CIDR is not a strict IPv4/IPv6 CIDR."""


# ---------------------------------------------------------------------------
# Query parsing
# ---------------------------------------------------------------------------
def parse_query_cidr(raw: Any) -> Network:
    """Parse a strict IPv4/IPv6 CIDR query parameter.

    A prefix length is mandatory (a bare address is not a CIDR query) and host
    bits must be zero; anything else raises :class:`DecisionMapError`.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise DecisionMapError("cidr query parameter is required")
    text = raw.strip()
    if "/" not in text:
        raise DecisionMapError(
            f"invalid CIDR {raw!r}; an explicit prefix length is required (e.g. '10.0.0.0/8')"
        )
    try:
        # strict=True rejects host bits, e.g. 10.0.0.5/24 and 2001:db8::1/32.
        return ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise DecisionMapError(f"invalid CIDR {raw!r} ({exc})") from None


# ---------------------------------------------------------------------------
# Rule grouping (from the stored version, read-only)
# ---------------------------------------------------------------------------
def _chain_entry(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_id": rule["rule_id"],
        "index": rule["index"],
        "cidr": rule["cidr"],
        "action": rule["action"],
        "priority": rule["priority"],
        "source_tag": rule["source_tag"],
        "role": rule["role"],
    }


def _match_chain(
    node_network: Network,
    groups: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """All rules covering ``node_network``, longest prefix first.

    Every rule whose CIDR is a supernet of (or equal to) the node matches all
    of its effective pieces; same-CIDR duplicates come right after their node
    mates, ordered by (priority, original submission index).
    """
    covering: list[dict[str, Any]] = []
    for cidr, members in groups.items():
        if not node_network.subnet_of(ipaddress.ip_network(cidr)):
            continue
        # ``members`` are already (priority, index) ordered; the first one is
        # the node winner.
        covering.extend(members)
    covering.sort(
        key=lambda r: (
            -ipaddress.ip_network(r["cidr"]).prefixlen,
            r["priority"],
            r["index"],
        )
    )
    return [_chain_entry(r) for r in covering]


def _clip(piece: Network, query: Network) -> Network | None:
    """Intersect one effective piece with the query (CIDRs never half-overlap)."""
    if piece == query or piece.subnet_of(query):
        return piece
    if query.subnet_of(piece):
        return query
    return None


# ---------------------------------------------------------------------------
# Decision map
# ---------------------------------------------------------------------------
def build_decision_map(result: dict[str, Any], query: Network) -> dict[str, Any]:
    """Partition ``query`` into constant-decision blocks for ``result``.

    The matched surface is the union of the winner rules' stored
    ``effective_cidrs`` (clipped to the query); every address outside it
    matches no rule.  See module docstring for the output semantics.
    """
    rules = result.get("rules", [])

    # Same-CIDR groups, members ordered exactly like the engine's tie-break:
    # highest priority (smallest number), then original submission order.
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rule in rules:
        if rule.get("ip_version") != query.version:
            continue
        groups[rule["cidr"]].append(rule)
    for members in groups.values():
        members.sort(key=lambda r: (r["priority"], r["index"]))

    # Chains are constant over every effective piece of one winner node, so
    # compute each winner's chain exactly once.
    chains: dict[str, list[dict[str, Any]]] = {}
    winner_by_id: dict[str, dict[str, Any]] = {}
    for cidr, members in groups.items():
        winner = next((m for m in members if m.get("role") == "winner"), None)
        if winner is None:
            # Should never happen for an analyzer-produced version, but stay
            # robust: treat the priority winner as the node winner.
            winner = members[0]
        winner_by_id[winner["rule_id"]] = winner
        chains[winner["rule_id"]] = _match_chain(ipaddress.ip_network(cidr), groups)

    # Carve matched cells: each winner's effective pieces, clipped to query.
    # Effective pieces of distinct winners are pairwise disjoint.
    matched_by_winner: dict[str, list[Network]] = defaultdict(list)
    matched_all: list[Network] = []
    for rule in rules:
        if rule.get("role") != "winner" or rule.get("ip_version") != query.version:
            continue
        for piece_cidr in rule.get("effective_cidrs", []):
            piece = ipaddress.ip_network(piece_cidr)
            clipped = _clip(piece, query)
            if clipped is not None:
                matched_by_winner[rule["rule_id"]].append(clipped)
                matched_all.append(clipped)

    # Unmatched surface = query minus the (pairwise disjoint) matched pieces.
    unmatched = _subtract(query, matched_all) if matched_all else [query]

    blocks: list[dict[str, Any]] = []

    def _emit(networks: list[Network], winner: dict[str, Any] | None) -> None:
        chain = chains[winner["rule_id"]] if winner is not None else []
        for net in networks:
            blocks.append(
                {
                    "cidr": str(net),
                    "ip_version": net.version,
                    "address_count": net.num_addresses,
                    "action": winner["action"] if winner is not None else None,
                    "winner_rule_id": winner["rule_id"] if winner is not None else None,
                    "winner_source_tag": winner["source_tag"] if winner is not None else None,
                    "match_chain": [dict(entry) for entry in chain],
                }
            )

    # Merge only adjacent blocks sharing the same winning rule; cells of
    # different winners (or none) separated by a gap never join.
    for winner_id, pieces in matched_by_winner.items():
        _emit(list(ipaddress.collapse_addresses(_sort_networks(pieces))), winner_by_id[winner_id])
    _emit(list(ipaddress.collapse_addresses(_sort_networks(unmatched))), None)

    # Stable order: address ascending, then shorter prefix first.
    blocks.sort(key=lambda b: (int(ipaddress.ip_network(b["cidr"]).network_address),
                               ipaddress.ip_network(b["cidr"]).prefixlen))

    matched_addresses = sum(
        n.num_addresses for nets in matched_by_winner.values() for n in nets
    )
    unmatched_addresses = sum(n.num_addresses for n in unmatched)
    permit_addresses = sum(
        n.num_addresses
        for winner_id, nets in matched_by_winner.items()
        for n in nets
        if winner_by_id[winner_id]["action"] == "permit"
    )
    deny_addresses = matched_addresses - permit_addresses

    return {
        "analysis_id": result.get("id"),
        "ruleset_hash": result.get("ruleset_hash"),
        "query_cidr": str(query),
        "ip_version": query.version,
        "summary": {
            "block_count": len(blocks),
            "matched_blocks": sum(1 for b in blocks if b["winner_rule_id"] is not None),
            "unmatched_blocks": sum(1 for b in blocks if b["winner_rule_id"] is None),
            "matched_addresses": matched_addresses,
            "unmatched_addresses": unmatched_addresses,
            "permit_addresses": permit_addresses,
            "deny_addresses": deny_addresses,
            "total_addresses": query.num_addresses,
        },
        "blocks": blocks,
    }
