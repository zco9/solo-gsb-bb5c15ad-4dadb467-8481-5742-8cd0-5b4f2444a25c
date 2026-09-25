"""Semantic diff between two saved analysis versions.

Given two analysis results, this module compares the *final effective action*
at every address covered by either version's rules:

* an address inside some winning rule's ``effective_cidrs`` gets that rule's
  action (``permit`` / ``deny``);
* an address matching no rule is recorded as ``none``.

The diff is computed geometrically — CIDRs are carved into disjoint cells,
never enumerated address by address — so IPv6 ranges (up to 2**128 addresses)
are handled exactly.

For every cell whose action differs between the two versions we record one of
the six change types: ``permit_to_deny``, ``permit_to_none``, ``deny_to_permit``,
``deny_to_none``, ``none_to_permit``, ``none_to_deny``.  Cells of the same
(IP version, change type) are then collapsed with
``ipaddress.collapse_addresses``, which merges **adjacent, equal-prefix**
blocks only; ranges of different change types, or ranges separated by a gap
(including unchanged / ``none``-to-``none`` gaps), are never joined.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import Any

# Reuse the geometry helpers of the core engine rather than re-implementing
# network subtraction / canonical sorting here.
from .analyzer import _sort_networks, _subtract

#: Saved analysis ids look like ``an_`` followed by 16 lowercase hex chars
#: (see ``main._make_id``).
ANALYSIS_ID_RE = re.compile(r"^an_[0-9a-f]{16}$")

#: ``None`` stands for "no matching rule" (implicit ``none`` action).
Action = str | None

Network = ipaddress._BaseNetwork
Partition = list[tuple[Network, str]]
Cell = tuple[Network, Action, Action]

#: All six possible transitions, in the canonical reporting order.
CHANGE_TYPE_ORDER: tuple[tuple[Action, Action], ...] = (
    ("permit", "deny"),
    ("permit", None),
    ("deny", "permit"),
    ("deny", None),
    (None, "permit"),
    (None, "deny"),
)


def change_type_name(from_action: Action, to_action: Action) -> str:
    return f"{from_action or 'none'}_to_{to_action or 'none'}"


# ---------------------------------------------------------------------------
# Effective-action partition of one version
# ---------------------------------------------------------------------------
def _effective_partition(result: dict[str, Any]) -> Partition:
    """Return the disjoint ``(network, action)`` pieces a version forwards on.

    The effective surface is exactly the union of the winning rules'
    ``effective_cidrs``: fully shadowed winners and same-CIDR duplicates have
    no effective coverage, and the pieces of distinct winners are pairwise
    disjoint (they are the leaves of the containment-trie subtraction).
    Everything outside this union matches no rule and is implicitly ``none``.
    """
    pieces: Partition = []
    for rule in result.get("rules", []):
        if rule.get("role") != "winner":
            continue
        for cidr in rule.get("effective_cidrs", []):
            pieces.append((ipaddress.ip_network(cidr), str(rule["action"])))
    # (version, address, prefixlen) — also a deterministic tie-break order.
    pieces.sort(key=lambda p: (p[0].version, int(p[0].network_address), p[0].prefixlen))
    return pieces


def _split_by_version(partition: Partition) -> dict[int, Partition]:
    by_version: dict[int, Partition] = defaultdict(list)
    for piece in partition:
        by_version[piece[0].version].append(piece)
    return by_version


# ---------------------------------------------------------------------------
# Overlay of two partitions -> disjoint cells tagged (base, target)
# ---------------------------------------------------------------------------
def _overlay(a_pieces: Partition, b_pieces: Partition) -> list[Cell]:
    """Carve two disjoint piece-sets into disjoint ``(cell, action_a, action_b)``.

    For any two CIDRs either one contains the other or they are disjoint, so
    the overlay is built from three kinds of output cells:

    * the exact intersection of an A piece and a B piece (equal CIDRs, or one
      carved out as a strict subnet of the other);
    * the remainder of an A piece after its strict B subnets are removed
      (B-action inherited from the enclosing B piece, or ``none``);
    * the remainder of a B piece after its strict A subnets are removed.
    """
    cells: list[Cell] = []

    for a_net, a_action in a_pieces:
        equal = next((b for b, _ in b_pieces if b == a_net), None)
        if equal is not None:
            # The pieces coincide exactly; the winner actions decide the cell.
            b_action = next(act for b, act in b_pieces if b == equal)
            cells.append((a_net, a_action, b_action))
            continue

        b_inside = [b for b, _ in b_pieces if b.subnet_of(a_net)]
        if b_inside:
            # Strict B subnets carve A up.  Because B pieces are pairwise
            # disjoint, any B piece enclosing such a strict subnet would also
            # contain A itself, which is impossible; hence A's holes match no
            # B piece and carry action ``none``.
            for b_net in b_inside:
                cells.append((b_net, a_action, _action_of(b_pieces, b_net)))
            for rem in _subtract(a_net, b_inside):
                cells.append((rem, a_action, None))
            continue

        # Either A is a strict subnet of some B piece, or A/B are disjoint.
        enclosing = next((b for b, _ in b_pieces if a_net.subnet_of(b)), None)
        cells.append((a_net, a_action, None if enclosing is None else _action_of(b_pieces, enclosing)))

    for b_net, b_action in b_pieces:
        equal = next((a for a, _ in a_pieces if a == b_net), None)
        if equal is not None:
            continue  # emitted on the A pass
        a_inside = [a for a, _ in a_pieces if a.subnet_of(b_net)]
        if a_inside:
            # Strict A subnets (with their enclosing B action) were emitted on
            # the A pass; B's holes match no A piece -> action ``none``.
            for rem in _subtract(b_net, a_inside):
                cells.append((rem, None, b_action))
        elif not any(b_net.subnet_of(a) for a, _ in a_pieces):
            # B is disjoint from A (a strict subnet of A was already emitted
            # on the A pass, together with its enclosing A's holes).
            cells.append((b_net, None, b_action))

    return cells


def _action_of(pieces: Partition, network: Network) -> str:
    return next(act for net, act in pieces if net == network)


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------
def diff_analyses(base: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    """Compute the effective-action diff of two stored analysis results.

    Output contract::

        {
          "base": {...}, "target": {...},
          "changes": [
            {"ip_version": 4, "change_type": "permit_to_deny",
             "from_action": "permit", "to_action": "deny",
             "address_count": 256, "range_count": 1,
             "cidrs": ["10.1.0.0/24"]}, ...
          ],
          "summary": {"total_changed_addresses": ...,
                      "ipv4": {"changed_addresses": ..., "change_groups": ...,
                               "by_type": {...}},
                       "ipv6": {...}}
        }
    """
    a_by_version = _split_by_version(_effective_partition(base))
    b_by_version = _split_by_version(_effective_partition(target))

    changes: list[dict[str, Any]] = []
    summary: dict[str, Any] = {
        "total_changed_addresses": 0,
        "total_change_groups": 0,
    }

    # IPv4 and IPv6 are always reported, even when a family has no rules.
    for version in (4, 6):
        cells = _overlay(a_by_version.get(version, []), b_by_version.get(version, []))

        # Group the changed cells by transition, then collapse each group's
        # adjacent sibling blocks into the minimum CIDR representation.
        by_type: dict[tuple[Action, Action], list[Network]] = defaultdict(list)
        for net, a_action, b_action in cells:
            if a_action != b_action:
                by_type[(a_action, b_action)].append(net)

        family_total = 0
        family_groups = 0
        type_counts: dict[str, int] = {
            change_type_name(frm, to): 0 for frm, to in CHANGE_TYPE_ORDER
        }
        for frm, to in CHANGE_TYPE_ORDER:
            nets = by_type.get((frm, to))
            if not nets:
                continue
            collapsed = list(ipaddress.collapse_addresses(_sort_networks(nets)))
            count = sum(n.num_addresses for n in collapsed)
            changes.append(
                {
                    "ip_version": version,
                    "change_type": change_type_name(frm, to),
                    "from_action": frm,
                    "to_action": to,
                    "address_count": count,
                    "range_count": len(collapsed),
                    "cidrs": [str(n) for n in collapsed],
                }
            )
            type_counts[change_type_name(frm, to)] = count
            family_total += count
            family_groups += 1

        summary[f"ipv{version}"] = {
            "changed_addresses": family_total,
            "change_groups": family_groups,
            "by_type": type_counts,
        }
        summary["total_changed_addresses"] += family_total
        summary["total_change_groups"] += family_groups

    return {
        "base": {
            "id": base.get("id"),
            "ruleset_hash": base.get("ruleset_hash"),
            "analyzer_version": base.get("analyzer_version"),
        },
        "target": {
            "id": target.get("id"),
            "ruleset_hash": target.get("ruleset_hash"),
            "analyzer_version": target.get("analyzer_version"),
        },
        "changes": changes,
        "summary": summary,
    }
