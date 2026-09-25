"""Change-guard: authorize the semantic diff between two saved versions.

A *change guard* replays the effective-action semantic diff of two versions
(:func:`app.diff.diff_analyses`) against a caller-supplied set of
**authorization entries**.  Each entry grants exactly one action transition
on one strict CIDR::

    {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny"}

``from_action`` / ``to_action`` take the values ``permit`` / ``deny`` /
``none`` (``none`` = no matching rule) and must differ — a grant describes a
*change*, so a transition from an action to itself is meaningless.

An address whose effective action changes between the two versions is
**authorized** only when it falls inside at least one grant of the **same IP
family and the same action transition**; anything else is a violation.  The
grant set itself is normalized geometrically:

* grants of the same (family, transition) may nest or repeat freely — their
  CIDRs are merged into one union (``ipaddress.collapse_addresses``);
* grants of **different** transitions whose CIDRs overlap (one contains the
  other, or they coincide) are rejected as a whole with
  :class:`ChangeGuardError` — the guard never guesses which transition the
  caller meant for the shared range.

Only addresses whose action actually changed need a grant: unchanged space
covered by a grant is not a violation, and grants that match no change are
simply unused.  The response reports ``passed`` plus, per transition, the
**unauthorized** surface as minimal CIDRs with exact address counts.  Like
the diff itself, everything is CIDR geometry — addresses are never
enumerated, so IPv6 ranges (up to 2**128) are handled exactly.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

# Reuse the engine's canonical sorting / subtraction helpers and the diff's
# transition vocabulary rather than re-implementing them here.
from .analyzer import _sort_networks, _subtract
from .diff import CHANGE_TYPE_ORDER, Action, change_type_name, diff_analyses

Network = ipaddress._BaseNetwork

#: Legal spellings of a grant's ``from_action`` / ``to_action``.
GUARD_ACTIONS: tuple[str, str, str] = ("permit", "deny", "none")

#: Sentinel for "action failed to parse" (``None`` is a valid action).
_INVALID = object()


class ChangeGuardError(Exception):
    """The authorization set is invalid as a whole.

    ``issues`` lists every problem found (bad CIDRs, bad actions, same-action
    transitions, cross-transition overlaps) in deterministic order, so a
    client can fix everything at once.
    """

    def __init__(self, issues: list[str]):
        self.issues = issues
        super().__init__("; ".join(issues))


@dataclass(frozen=True)
class GuardGrant:
    """One parsed authorization entry: a transition granted on a network."""

    network: Network
    from_action: Action  # None == "none" (no matching rule)
    to_action: Action

    @property
    def transition(self) -> str:
        return change_type_name(self.from_action, self.to_action)


# ---------------------------------------------------------------------------
# Authorization entry parsing / validation
# ---------------------------------------------------------------------------
def _parse_guard_action(value: Any, field: str, label: str, issues: list[str]) -> Any:
    if not isinstance(value, str):
        issues.append(f"{label}: {field} must be one of permit, deny, none")
        return _INVALID
    key = value.strip().lower()
    if key not in GUARD_ACTIONS:
        issues.append(
            f"{label}: invalid {field} {value!r}; expected permit, deny or none"
        )
        return _INVALID
    return None if key == "none" else key


def _grant_sort_key(grant: GuardGrant) -> tuple:
    net = grant.network
    return (net.version, int(net.network_address), net.prefixlen, grant.transition)


def parse_guard_entries(raw_entries: Any) -> list[GuardGrant]:
    """Validate raw authorization entries and return deduplicated grants.

    Every entry must carry a *strict* CIDR (explicit prefix length, host bits
    zero) and two different actions out of ``permit`` / ``deny`` / ``none``.
    Entries of the same (family, transition) may nest or repeat (they are
    unioned later); entries of **different** transitions must not overlap.
    All problems are collected and raised as one :class:`ChangeGuardError`.
    """
    if not isinstance(raw_entries, list) or not raw_entries:
        raise ChangeGuardError(["authorizations must be a non-empty list"])

    issues: list[str] = []
    grants: list[GuardGrant] = []
    for index, raw in enumerate(raw_entries):
        label = f"authorization #{index + 1}"
        if not isinstance(raw, dict):
            issues.append(f"{label} must be an object")
            continue

        frm = _parse_guard_action(raw.get("from_action"), "from_action", label, issues)
        to = _parse_guard_action(raw.get("to_action"), "to_action", label, issues)
        if frm is not _INVALID and to is not _INVALID and frm == to:
            issues.append(f"{label}: from_action and to_action must differ")

        network: Network | None = None
        cidr = raw.get("cidr")
        if not isinstance(cidr, str) or not cidr.strip():
            issues.append(f"{label}: cidr must be a non-empty string")
        else:
            text = cidr.strip()
            if "/" not in text:
                issues.append(
                    f"{label}: invalid CIDR {cidr!r}; an explicit prefix length is "
                    "required (e.g. '10.0.0.0/8')"
                )
            else:
                try:
                    # strict=True rejects host bits, e.g. 10.0.0.5/24.
                    network = ipaddress.ip_network(text, strict=True)
                except ValueError as exc:
                    issues.append(f"{label}: invalid CIDR {cidr!r} ({exc})")

        if network is not None and frm is not _INVALID and to is not _INVALID and frm != to:
            grants.append(GuardGrant(network, frm, to))

    # Nested / duplicate grants of one transition are fine (unioned below);
    # overlapping grants of *different* transitions are ambiguous -> reject.
    unique = sorted(set(grants), key=_grant_sort_key)
    for version in (4, 6):
        family = [g for g in unique if g.network.version == version]
        for i, a in enumerate(family):
            for b in family[i + 1:]:
                if a.transition == b.transition:
                    continue
                # Two CIDRs of one family overlap only by containment.
                if a.network.overlaps(b.network):
                    issues.append(
                        f"authorizations {a.network} ({a.transition}) and "
                        f"{b.network} ({b.transition}) overlap but grant different "
                        "transitions; overlapping entries must share the same "
                        "from_action/to_action"
                    )

    if issues:
        raise ChangeGuardError(issues)
    return unique


# ---------------------------------------------------------------------------
# Guard evaluation
# ---------------------------------------------------------------------------
def _union_by_transition(
    grants: Iterable[GuardGrant],
) -> dict[tuple[int, Action, Action], list[Network]]:
    """Merge each (family, transition)'s grant CIDRs into a disjoint union."""
    grouped: dict[tuple[int, Action, Action], list[Network]] = defaultdict(list)
    for grant in grants:
        key = (grant.network.version, grant.from_action, grant.to_action)
        grouped[key].append(grant.network)
    return {
        key: list(ipaddress.collapse_addresses(_sort_networks(nets)))
        for key, nets in grouped.items()
    }


def _unauthorized_surface(network: Network, union: list[Network]) -> list[Network]:
    """Part of ``network`` not covered by the pairwise-disjoint ``union``.

    ``union`` elements are post-collapse, hence pairwise disjoint with no
    containment; a changed CIDR is therefore either swallowed whole by one
    grant or carved by strict subnets of it.
    """
    for u in union:
        if network.subnet_of(u):  # includes equality
            return []
    cutters = [u for u in union if u.subnet_of(network)]
    if not cutters:
        return [network]
    return _subtract(network, cutters)


def guard_changes(
    base: dict[str, Any],
    target: dict[str, Any],
    grants: list[GuardGrant],
) -> dict[str, Any]:
    """Check the base→target semantic diff against the parsed grants.

    Output contract::

        {
          "base": {...}, "target": {...},
          "passed": bool,
          "violations": [
            {"ip_version": 4, "change_type": "permit_to_deny",
             "from_action": "permit", "to_action": "deny",
             "unauthorized_address_count": 256, "unauthorized_range_count": 1,
             "unauthorized_cidrs": ["10.1.0.0/24"]}, ...
          ],
          "summary": {"total_changed_addresses": ...,
                      "total_authorized_addresses": ...,
                      "total_unauthorized_addresses": ...,
                      "ipv4": {...}, "ipv6": {...}}
        }
    """
    diff = diff_analyses(base, target)
    unions = _union_by_transition(grants)

    violations: list[dict[str, Any]] = []
    by_family: dict[int, dict[str, Any]] = {
        version: {
            "changed_addresses": diff["summary"][f"ipv{version}"]["changed_addresses"],
            "unauthorized_addresses": 0,
            "violation_groups": 0,
            "by_type": {
                change_type_name(frm, to): 0 for frm, to in CHANGE_TYPE_ORDER
            },
        }
        for version in (4, 6)
    }

    # ``diff.changes`` is already ordered by (family, CHANGE_TYPE_ORDER) and
    # carries each transition's changed surface as minimal CIDRs.
    for change in diff["changes"]:
        version = change["ip_version"]
        frm, to = change["from_action"], change["to_action"]
        union = unions.get((version, frm, to), [])

        unauthorized: list[Network] = []
        for cidr in change["cidrs"]:
            unauthorized.extend(_unauthorized_surface(ipaddress.ip_network(cidr), union))
        if not unauthorized:
            continue

        collapsed = list(ipaddress.collapse_addresses(_sort_networks(unauthorized)))
        count = sum(n.num_addresses for n in collapsed)
        violations.append(
            {
                "ip_version": version,
                "change_type": change["change_type"],
                "from_action": frm,
                "to_action": to,
                "unauthorized_address_count": count,
                "unauthorized_range_count": len(collapsed),
                "unauthorized_cidrs": [str(n) for n in collapsed],
            }
        )
        family = by_family[version]
        family["unauthorized_addresses"] += count
        family["violation_groups"] += 1
        family["by_type"][change["change_type"]] = count

    total_changed = diff["summary"]["total_changed_addresses"]
    total_unauthorized = sum(f["unauthorized_addresses"] for f in by_family.values())

    return {
        "base": diff["base"],
        "target": diff["target"],
        "passed": not violations,
        "violations": violations,
        "summary": {
            "authorization_entries": len(grants),
            "total_changed_addresses": total_changed,
            "total_authorized_addresses": total_changed - total_unauthorized,
            "total_unauthorized_addresses": total_unauthorized,
            "total_violation_groups": sum(f["violation_groups"] for f in by_family.values()),
            "ipv4": by_family[4],
            "ipv6": by_family[6],
        },
    }
