"""Two-batch change-merge precheck on top of one saved analysis version.

Two change batches (``A`` and ``B``), each an ordinary add/replace/remove
patch of the kind accepted by ``POST /api/analyses/{id}/simulate``, are
reviewed as if they were to land together on the **same base version**.  The
precheck is purely computational — the analyzer is re-run in memory and
nothing is persisted, no analysis version is created.

The review runs in strict order and reports four kinds of output:

1. **Structural conflicts** — a ``rule_id`` is the target of an operation in
   *both* batches (two removes included).  The two patches both want to
   decide that rule's fate on the same base version, so they cannot be
   composed; the conflict record names the rule and the operation chosen by
   each side.

2. **Action conflicts** — the address ranges each side *changes relative to
   the base* are overlaid per IP family (IPv4 and IPv6 handled independently
   and exactly, never enumerating addresses).  Every address changed by both
   sides whose resulting action differs between the sides is reported as a
   minimal-CIDR conflict carrying the base action and the two sides' actions.

3. **Merge conflicts** — when neither structural nor action conflicts exist,
   batch A is applied to the base first and batch B on top of the result
   (``add`` rules of A precede those of B for same-CIDR priority ties), and
   the merged ruleset is re-analyzed.  Each side's changed surface is then
   checked against the merged final action: addresses that side had changed
   but the sequential merge does not keep at that side's action are reported
   as minimal-CIDR conflicts (with the base and merged actions).  This catches
   interactions the direct overlay cannot see — e.g. an added rule of one
   side shadowing a replacement made by the other.

4. **Success** — with no conflicts at all the full merged analysis and its
   effective-action diff against the base version are returned.

When a stage fails, later stages that presuppose it are skipped (``null``):
structural conflicts stop the merge entirely; action conflicts stop at the
overlay, as every composition order would be an arbitrary tie-break on the
already-flagged disputed surface.
"""

from __future__ import annotations

import ipaddress
from typing import Any, NamedTuple

from .analyzer import _sort_networks, _subtract, analyze_rules
from .diff import Action, diff_analyses
from .simulate import OP_ORDER, apply_patch, rebuild_input_rules, validate_patch

Network = Any  # ipaddress._BaseNetwork

#: Reporting order of an action value, ``none`` last.
_ACTION_RANK: dict[Action, int] = {"permit": 0, "deny": 1, None: 2}

#: Field names persisted in an analysis result (vocabulary shared with diff).
_PIECE_ROLE = "winner"


class _ChangedPiece(NamedTuple):
    """One disjoint CIDR whose action one side changed relative to base.

    ``action`` is the side's resulting action (``None`` == ``none``: no rule
    forwards there after the patch) and ``base_action`` is what the base
    version forwarded on the same CIDR.
    """

    network: Network
    action: Action
    base_action: Action


class _BatchPatch(NamedTuple):
    """The three operation lists of one validated batch."""

    add: list[dict[str, Any]]
    replace: list[dict[str, Any]]
    remove: list[dict[str, Any]]

    def targets(self) -> dict[str, str]:
        """Map every targeted rule_id -> operation kind (single target each)."""
        targeted: dict[str, str] = {}
        for op in OP_ORDER:
            for item in getattr(self, op):
                targeted[item["rule_id"]] = op
        return targeted


def build_batch(
    add: list[dict[str, Any]],
    replace: list[dict[str, Any]],
    remove: list[dict[str, Any]],
) -> _BatchPatch:
    """Assemble a validated batch from dumped schema operation lists."""
    return _BatchPatch(add=add, replace=replace, remove=remove)


# ---------------------------------------------------------------------------
# Empty results (the merge may legitimately delete every rule)
# ---------------------------------------------------------------------------
def _empty_result() -> dict[str, Any]:
    """Analysis-shaped record of the empty ruleset: every address is ``none``.

    ``analyze_rules`` requires at least one rule, so a merge removing the last
    rule is compared against this synthetic result, mirroring
    ``app.redundant._empty_analysis``.
    """
    return {
        "analyzer_version": None,
        "ruleset_hash": None,
        "rules": [],
        "findings": [],
        "minimal_conflict_pairs": [],
        "summary": {
            "rule_count": 0,
            "distinct_cidrs": 0,
            "ipv4_rules": 0,
            "ipv6_rules": 0,
            "active_rules": 0,
            "partial_rules": 0,
            "shadowed_rules": 0,
            "duplicate_rules": 0,
            "conflict_findings": 0,
            "warning_findings": 0,
            "info_findings": 0,
            "behavioral_conflicts": 0,
            "priority_inversions": 0,
        },
    }


# ---------------------------------------------------------------------------
# Changed-surface extraction
# ---------------------------------------------------------------------------
def _tag_of(tagged: list[tuple[Network, Any]], network: Network) -> Any:
    return next(tag for net, tag in tagged if net == network)


def _overlay_tagged(
    a_pieces: list[tuple[Network, Any]],
    b_pieces: list[tuple[Network, Any]],
) -> list[tuple[Network, Any, Any]]:
    """Carve two disjoint piece-sets into disjoint ``(cell, tag_a, tag_b)``.

    This is the geometry of :func:`app.diff._overlay` generalized from plain
    actions to arbitrary opaque tags (``None`` means "this side forwards
    nothing on the cell").  For any two CIDRs either one contains the other
    or they are disjoint, so cells come from exact equal-CIDR matches, strict
    subnets carved out of an enclosing piece, and the resulting remainders.
    """
    cells: list[tuple[Network, Any, Any]] = []

    for a_net, a_tag in a_pieces:
        if any(b == a_net for b, _ in b_pieces):
            cells.append((a_net, a_tag, _tag_of(b_pieces, a_net)))
            continue

        b_inside = [b for b, _ in b_pieces if b.subnet_of(a_net)]
        if b_inside:
            for b_net in b_inside:
                cells.append((b_net, a_tag, _tag_of(b_pieces, b_net)))
            for rem in _subtract(a_net, b_inside):
                cells.append((rem, a_tag, None))
            continue

        enclosing = next((b for b, _ in b_pieces if a_net.subnet_of(b)), None)
        cells.append((a_net, a_tag, None if enclosing is None else _tag_of(b_pieces, enclosing)))

    for b_net, b_tag in b_pieces:
        if any(a == b_net for a, _ in a_pieces):
            continue  # emitted on the A pass
        a_inside = [a for a, _ in a_pieces if a.subnet_of(b_net)]
        if a_inside:
            for rem in _subtract(b_net, a_inside):
                cells.append((rem, None, b_tag))
        elif not any(b_net.subnet_of(a) for a, _ in a_pieces):
            cells.append((b_net, None, b_tag))

    return cells


def _effective_tagged(result: dict[str, Any]) -> list[tuple[Network, tuple[Action, Action]]]:
    """Disjoint effective pieces of one analysis as ``(cidr, (action, action))``.

    The duplicated slot later holds ``(own_action, base_action)``; on freshly
    extracted version surfaces both slots are the version's own action
    (``None`` is never produced here — uncovered addresses simply have no
    piece).
    """
    tagged: list[tuple[Network, tuple[Action, Action]]] = []
    for rule in result.get("rules", []):
        if rule.get("role") != _PIECE_ROLE:
            continue
        action = str(rule["action"])
        for cidr in rule.get("effective_cidrs", []):
            net = ipaddress.ip_network(cidr)
            tagged.append((net, (action, action)))
    tagged.sort(key=lambda t: (t[0].version, int(t[0].network_address), t[0].prefixlen))
    return tagged


def _changed_pieces(base: dict[str, Any], side: dict[str, Any]) -> list[_ChangedPiece]:
    """Disjoint CIDRs where ``side`` forwards differently from ``base``.

    IPv4 and IPv6 are overlaid independently (mixing families is impossible
    under LPM).  Each family's base/side overlay yields cells
    ``(cell, base_tag, side_tag)`` where a ``None`` tag means that version
    forwards nothing on the cell (``none``); each present tag is the
    ``(own_action, own_action)`` placeholder produced by
    :func:`_effective_tagged`.  A cell changed relative to base iff the two
    effective actions differ, and on that cell the base action is inherited
    from the enclosing base piece (or ``None`` for uncovered space).
    """
    base_by_version = _split_by_version(_effective_tagged(base))
    side_by_version = _split_by_version(_effective_tagged(side))

    pieces: list[_ChangedPiece] = []
    for version in (4, 6):
        cells = _overlay_tagged(
            base_by_version.get(version, []),
            side_by_version.get(version, []),
        )
        for net, base_tag, side_tag in cells:
            side_action = None if side_tag is None else side_tag[0]
            base_action = None if base_tag is None else base_tag[0]
            if side_action != base_action:
                pieces.append(_ChangedPiece(net, side_action, base_action))
    pieces.sort(key=lambda p: (p.network.version, int(p.network.network_address), p.network.prefixlen))
    return pieces


def _split_by_version(
    tagged: list[tuple[Network, Any]],
) -> dict[int, list[tuple[Network, Any]]]:
    by_version: dict[int, list[tuple[Network, Any]]] = {}
    for net, tag in tagged:
        by_version.setdefault(net.version, []).append((net, tag))
    return by_version


def _changed_tagged(pieces: list[_ChangedPiece]) -> list[tuple[Network, tuple[Action, Action]]]:
    """Tag the changed surface as ``(cidr, (side_action, base_action))``."""
    return [
        (p.network, (p.action, p.base_action))
        for p in sorted(
            pieces,
            key=lambda x: (x.network.version, int(x.network.network_address), x.network.prefixlen),
        )
    ]


# ---------------------------------------------------------------------------
# Conflict grouping into minimal CIDRs
# ---------------------------------------------------------------------------
def _conflict_group_key(actions: tuple[Action, ...]) -> tuple:
    return tuple(_ACTION_RANK[a] for a in actions)


def _collapse_conflicts(
    cells: list[tuple[Network, tuple[Action, ...]]],
) -> list[dict[str, Any]]:
    """Collapse cells with identical action tuples into minimal-CIDR groups.

    Cells arrive already disjoint (an overlay output); per identical tuple the
    CIDRs are collapsed with ``ipaddress.collapse_addresses``, so adjacent
    equal-prefix sibling blocks merge while differently-tagged ranges never
    join.  Groups are ordered deterministically by (family, action tuple,
    first CIDR) and each carries the exact (IPv6-safe) address count.
    """
    grouped: dict[tuple[int, tuple[Action, ...]], list[Network]] = {}
    for net, actions in cells:
        grouped.setdefault((net.version, actions), []).append(net)

    groups: list[dict[str, Any]] = []
    for version, actions in sorted(
        grouped, key=lambda k: (k[0], _conflict_group_key(k[1]))
    ):
        collapsed = list(ipaddress.collapse_addresses(_sort_networks(grouped[(version, actions)])))
        groups.append(
            {
                "ip_version": version,
                "actions": list(actions),
                "address_count": sum(n.num_addresses for n in collapsed),
                "range_count": len(collapsed),
                "cidrs": [str(n) for n in collapsed],
            }
        )
    return groups


def _action_conflicts(changed_a: list[_ChangedPiece], changed_b: list[_ChangedPiece]) -> list[dict[str, Any]]:
    """Intersection of the two changed surfaces where the sides end differently.

    Both inputs are disjoint piece sets, so the per-family overlay splits the
    exact intersection into cells tagged ``(a_action, base_action)`` and
    ``(b_action, base_action)`` for the two sides.  The base action carried by
    the two sides must agree on every shared cell; a cell conflicts only when
    the two sides' own actions differ.
    """
    a_by_version = _split_by_version(_changed_tagged(changed_a))
    b_by_version = _split_by_version(_changed_tagged(changed_b))

    disputed: list[tuple[Network, tuple[Action, ...]]] = []
    for version in (4, 6):
        cells = _overlay_tagged(a_by_version.get(version, []), b_by_version.get(version, []))
        for net, tag_a, tag_b in cells:
            if tag_a is None or tag_b is None:
                continue  # changed by one side only -> nothing to dispute
            a_action, a_base = tag_a
            b_action, b_base = tag_b
            if a_action == b_action:
                continue  # both sides change it to the same final action
            assert a_base == b_base, f"base action disagreement on {net}"
            disputed.append((net, (a_base, a_action, b_action)))

    groups = _collapse_conflicts(disputed)
    return [
        {
            "ip_version": g["ip_version"],
            "base_action": g["actions"][0],
            "side_a_action": g["actions"][1],
            "side_b_action": g["actions"][2],
            "address_count": g["address_count"],
            "range_count": g["range_count"],
            "cidrs": g["cidrs"],
        }
        for g in groups
    ]


def _merge_conflicts(
    changed: list[_ChangedPiece],
    side_name: str,
    merged: dict[str, Any],
) -> list[dict[str, Any]]:
    """Where the sequential merge fails to preserve one side's changed surface.

    The merged version's effective surface is overlaid (per IP family) as the
    *first* partition with the side's changed pieces (tagged with the side's
    own and the base action): output cells carry ``(merged_tag, changed_tag)``
    where either tag is ``None`` when that partition forwards nothing
    (``none``).  A cell covered by a changed piece whose merged action differs
    from the side's action is a merge conflict.
    """
    merged_by_version = _split_by_version(_effective_tagged(merged))
    changed_by_version = _split_by_version(_changed_tagged(changed))

    violated: list[tuple[Network, tuple[Action, ...]]] = []
    for version in (4, 6):
        cells = _overlay_tagged(
            merged_by_version.get(version, []),
            changed_by_version.get(version, []),
        )
        for net, tag_merged, tag_changed in cells:
            if tag_changed is None:
                continue  # the merge is free on addresses this side did not touch
            side_action, base_action = tag_changed
            merged_action = None if tag_merged is None else tag_merged[0]
            if merged_action == side_action:
                continue
            violated.append((net, (base_action, side_action, merged_action)))

    groups = _collapse_conflicts(violated)
    return [
        {
            "side": side_name,
            "ip_version": g["ip_version"],
            "base_action": g["actions"][0],
            "side_action": g["actions"][1],
            "merged_action": g["actions"][2],
            "address_count": g["address_count"],
            "range_count": g["range_count"],
            "cidrs": g["cidrs"],
        }
        for g in groups
    ]


def _compose_on_top(
    rules_a: list[dict[str, Any]],
    add: list[dict[str, Any]],
    replace: list[dict[str, Any]],
    remove: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Validate batch B against A's result and apply it.

    Unlike :func:`app.simulate.apply_patch`, the composed ruleset may end up
    empty (the two batches can collectively delete every rule); the merged
    result then becomes the synthetic all-``none`` surface instead of being
    rejected.  Every other patch-contract check (unknown targets, duplicate
    targets, add collisions) still applies and raises :class:`PatchError`.
    """
    validate_patch(rules_a, add, replace, remove)
    replacements = {r["rule_id"]: r for r in replace}
    removed = {r["rule_id"] for r in remove}
    composed = [
        replacements.get(rule["rule_id"], rule)
        for rule in rules_a
        if rule["rule_id"] not in removed
    ]
    composed.extend(add)
    return composed


# ---------------------------------------------------------------------------
# Main precheck
# ---------------------------------------------------------------------------
def merge_precheck(
    base: dict[str, Any],
    batch_a: _BatchPatch,
    batch_b: _BatchPatch,
) -> dict[str, Any]:
    """Run the two-batch merge precheck against a stored base analysis.

    Both batches are validated and analyzed independently from the rebuilt
    base input (the same validation contract as the single-batch simulation,
    including at-least-one-operation and the all-or-nothing rejection of an
    empty resulting ruleset).
    """
    base_input = rebuild_input_rules(base)

    # ---- Stage 0: independently replay each batch on the base ------------
    input_a = apply_patch(base_input, batch_a.add, batch_a.replace, batch_a.remove)
    input_b = apply_patch(base_input, batch_b.add, batch_b.replace, batch_b.remove)
    side_a = analyze_rules(input_a)
    side_b = analyze_rules(input_b)

    def _side_meta(result: dict[str, Any]) -> dict[str, Any]:
        return {
            "ruleset_hash": result.get("ruleset_hash"),
            "rule_count": result.get("summary", {}).get("rule_count"),
        }

    # ---- Stage 1: structural conflicts (same rule_id targeted twice) -----
    targets_a = batch_a.targets()
    targets_b = batch_b.targets()
    structural_conflicts = [
        {
            "rule_id": rule_id,
            "side_a_operation": targets_a[rule_id],
            "side_b_operation": targets_b[rule_id],
        }
        for rule_id in sorted(set(targets_a) & set(targets_b))
    ]

    # ---- Stage 2: direct action overlay of the two changed surfaces ------
    changed_a = _changed_pieces(base, side_a)
    changed_b = _changed_pieces(base, side_b)
    action_conflicts = _action_conflicts(changed_a, changed_b)

    merged_result: dict[str, Any] | None = None
    diff: dict[str, Any] | None = None
    merge_conflicts: list[dict[str, Any]] | None = None

    if not structural_conflicts and not action_conflicts:
        # ---- Stage 3: apply A then B on top, and re-analyze --------------
        # Batch B's adds come after every surviving A rule (including A's
        # adds), which is the "A then B" order used to break same-CIDR ties.
        # The composed set may be empty (both batches deleting everything);
        # that is a valid merge result (every address reverts to ``none``).
        merged_input = _compose_on_top(
            input_a, batch_b.add, batch_b.replace, batch_b.remove
        )
        merged_result = analyze_rules(merged_input) if merged_input else _empty_result()

        merge_conflicts = _merge_conflicts(changed_a, "a", merged_result)
        merge_conflicts += _merge_conflicts(changed_b, "b", merged_result)

        if not merge_conflicts:
            # ---- Stage 4: clean merge — diff against the base ------------
            diff = diff_analyses(base, merged_result)

    passed = not structural_conflicts and not action_conflicts and not (merge_conflicts or [])

    summary = {
        "structural_conflicts": len(structural_conflicts),
        "action_conflict_ranges": sum(g["range_count"] for g in action_conflicts),
        "action_conflict_addresses": sum(g["address_count"] for g in action_conflicts),
        "merge_conflict_ranges": (
            sum(g["range_count"] for g in merge_conflicts) if merge_conflicts is not None else None
        ),
        "merge_conflict_addresses": (
            sum(g["address_count"] for g in merge_conflicts) if merge_conflicts is not None else None
        ),
    }

    return {
        "base": {
            "id": base.get("id"),
            "ruleset_hash": base.get("ruleset_hash"),
            "analyzer_version": base.get("analyzer_version"),
        },
        "sides": {"a": _side_meta(side_a), "b": _side_meta(side_b)},
        "passed": passed,
        "structural_conflicts": structural_conflicts,
        "action_conflicts": action_conflicts,
        "merge_conflicts": merge_conflicts,
        "merged": merged_result,
        "diff": diff,
        "summary": summary,
    }
