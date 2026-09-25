"""End-to-end tests for POST /api/analyses/{id}/merge-precheck."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-merge-")
    os.close(fd)
    os.remove(path)  # let sqlite create it
    db.reset_db(path)
    from app.main import app

    with TestClient(app) as c:
        yield c
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


def _save(client: TestClient, rules: list[dict], name: str | None = None) -> str:
    body: dict = {"rules": rules}
    if name is not None:
        body["name"] = name
    r = client.post("/api/analyze", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["persisted"] is True
    return r.json()["id"]


def _precheck(client: TestClient, aid: str, side_a: dict, side_b: dict):
    return client.post(f"/api/analyses/{aid}/merge-precheck", json={"a": side_a, "b": side_b})


NESTED = [
    {"rule_id": "p", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100, "source_tag": "hq"},
    {"rule_id": "d", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200, "source_tag": "edge"},
    {"rule_id": "l", "cidr": "10.1.1.0/24", "action": "permit", "priority": 50, "source_tag": "lab"},
]


# ---------------------------------------------------------------------------
# Structural conflicts
# ---------------------------------------------------------------------------
def test_same_rule_targeted_by_both_batches_is_structural_conflict(client: TestClient) -> None:
    aid = _save(client, NESTED)
    r = _precheck(
        client,
        aid,
        {"replace": [{"rule_id": "d", "cidr": "10.1.0.0/16", "action": "permit"}]},
        {"remove": [{"rule_id": "d"}]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["passed"] is False
    assert body["structural_conflicts"] == [
        {"rule_id": "d", "side_a_operation": "replace", "side_b_operation": "remove"}
    ]
    # A structural conflict stops the merge: no merged analysis, no diff.
    assert body["merged"] is None
    assert body["diff"] is None
    assert body["merge_conflicts"] is None
    assert body["summary"]["structural_conflicts"] == 1
    # But the independent action overlay is still computed for visibility.
    assert isinstance(body["action_conflicts"], list)


def test_two_removes_of_same_rule_are_structural_conflict(client: TestClient) -> None:
    aid = _save(client, NESTED)
    r = _precheck(client, aid, {"remove": [{"rule_id": "p"}]}, {"remove": [{"rule_id": "p"}]})
    assert r.status_code == 200
    assert r.json()["structural_conflicts"] == [
        {"rule_id": "p", "side_a_operation": "remove", "side_b_operation": "remove"}
    ]


def test_structural_conflicts_sorted_by_rule_id(client: TestClient) -> None:
    aid = _save(client, NESTED)
    r = _precheck(
        client,
        aid,
        {"remove": [{"rule_id": "l"}, {"rule_id": "d"}]},
        {"remove": [{"rule_id": "d"}, {"rule_id": "l"}]},
    )
    assert r.status_code == 200
    ids = [c["rule_id"] for c in r.json()["structural_conflicts"]]
    assert ids == ["d", "l"]


# ---------------------------------------------------------------------------
# Action conflicts (direct overlay of the two changed surfaces)
# ---------------------------------------------------------------------------
def test_action_conflict_on_remove_versus_deny_add(client: TestClient) -> None:
    # Base permit /8 (plus an unrelated permit /24 so neither batch empties
    # its own side).  A removes the /8 permit -> its range becomes none;
    # B adds a deny /16 inside it.  On /16 the sides disagree:
    # base permit, side A none, side B deny.
    aid = _save(client, [
        {"rule_id": "p", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "q", "cidr": "192.168.1.0/24", "action": "permit"},
    ])
    r = _precheck(
        client,
        aid,
        {"remove": [{"rule_id": "p"}]},
        {"add": [{"rule_id": "z", "cidr": "10.1.0.0/16", "action": "deny"}]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["passed"] is False
    assert body["action_conflicts"] == [
        {
            "ip_version": 4,
            "base_action": "permit",
            "side_a_action": None,
            "side_b_action": "deny",
            "address_count": 2 ** 16,
            "range_count": 1,
            "cidrs": ["10.1.0.0/16"],
        }
    ]
    # Action conflicts stop at the overlay: the sequential merge is skipped.
    assert body["merged"] is None
    assert body["merge_conflicts"] is None
    assert body["diff"] is None
    assert body["summary"]["action_conflict_addresses"] == 2 ** 16
    assert body["summary"]["action_conflict_ranges"] == 1


def test_action_conflict_returns_minimal_cidr(client: TestClient) -> None:
    # B denies the two adjacent /25 halves; the disputed intersection
    # (A removes the permit /8, so A's action is none) collapses to /24.
    aid = _save(client, [
        {"rule_id": "p", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "q", "cidr": "192.168.1.0/24", "action": "permit"},
    ])
    r = _precheck(
        client,
        aid,
        {"remove": [{"rule_id": "p"}]},
        {"add": [
            {"rule_id": "y1", "cidr": "10.0.0.0/25", "action": "deny"},
            {"rule_id": "y2", "cidr": "10.0.0.128/25", "action": "deny"},
        ]},
    )
    assert r.status_code == 200
    conflicts = r.json()["action_conflicts"]
    assert [c["cidrs"] for c in conflicts] == [["10.0.0.0/24"]]
    assert conflicts[0]["address_count"] == 2 ** 8
    assert conflicts[0]["base_action"] == "permit"
    assert conflicts[0]["side_a_action"] is None
    assert conflicts[0]["side_b_action"] == "deny"


def test_same_final_action_on_intersection_is_not_conflict(client: TestClient) -> None:
    # A denies the whole /16; B denies the inner /24.  The intersection is
    # deny on both sides -> no action conflict; the merged ruleset keeps the
    # /16 deny (B's rule is a same-action duplicate shadowed by LPM).
    aid = _save(client, [{"rule_id": "p", "cidr": "10.0.0.0/8", "action": "permit"}])
    r = _precheck(
        client,
        aid,
        {"add": [{"rule_id": "x", "cidr": "10.1.0.0/16", "action": "deny"}]},
        {"add": [{"rule_id": "y", "cidr": "10.1.1.0/24", "action": "deny"}]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["passed"] is True
    assert body["action_conflicts"] == []
    assert body["merge_conflicts"] == []
    assert [c["cidrs"] for c in body["diff"]["changes"]] == [["10.1.0.0/16"]]


def test_disjoint_changes_are_not_action_conflicts(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "p", "cidr": "10.0.0.0/8", "action": "permit"}])
    r = _precheck(
        client,
        aid,
        {"add": [{"rule_id": "x", "cidr": "10.2.0.0/16", "action": "deny"}]},
        {"add": [{"rule_id": "y", "cidr": "10.3.0.0/16", "action": "deny"}]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["passed"] is True
    # Adjacent sibling /16s of the same transition collapse to a /15.
    assert [c["cidrs"] for c in body["diff"]["changes"]] == [["10.2.0.0/15"]]


def test_ipv4_and_ipv6_conflicts_are_grouped_separately(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "p", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "v", "cidr": "2001:db8::/32", "action": "permit"},
        {"rule_id": "q", "cidr": "192.168.1.0/24", "action": "permit"},
    ])
    # A removes both covering rules (permit -> none on both families);
    # B denies one IPv4 /16 and one IPv6 /48 inside the removed surfaces.
    r = _precheck(
        client,
        aid,
        {"remove": [{"rule_id": "p"}, {"rule_id": "v"}]},
        {"add": [
            {"rule_id": "x4", "cidr": "10.1.0.0/16", "action": "deny"},
            {"rule_id": "x6", "cidr": "2001:db8:1::/48", "action": "deny"},
        ]},
    )
    assert r.status_code == 200
    conflicts = r.json()["action_conflicts"]
    by_version = {c["ip_version"]: c for c in conflicts}
    assert set(by_version) == {4, 6}
    assert by_version[4]["cidrs"] == ["10.1.0.0/16"]
    assert by_version[6]["cidrs"] == ["2001:db8:1::/48"]
    assert by_version[6]["address_count"] == 2 ** (128 - 48)


# ---------------------------------------------------------------------------
# Merge conflicts (A applied first, B on top; recomputed LPM)
# ---------------------------------------------------------------------------
def test_merge_conflict_when_b_undoes_as_change(client: TestClient) -> None:
    # Base permit /8.  A adds deny /16 (permit -> deny on /16); B adds a
    # permit /24 inside it.  B's permit /24 is a no-op relative to the
    # permit /8 baseline, so the direct overlay sees nothing; but after A
    # then B is applied, B's longer prefix wins the /24 back to permit,
    # undoing A's deny there -> merge conflict on side A only.
    aid = _save(client, [{"rule_id": "p", "cidr": "10.0.0.0/8", "action": "permit"}])
    r = _precheck(
        client,
        aid,
        {"add": [{"rule_id": "x", "cidr": "10.1.0.0/16", "action": "deny"}]},
        {"add": [{"rule_id": "y", "cidr": "10.1.1.0/24", "action": "permit"}]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["passed"] is False
    assert body["action_conflicts"] == []
    assert body["merge_conflicts"] == [
        {
            "side": "a",
            "ip_version": 4,
            "base_action": "permit",
            "side_action": "deny",
            "merged_action": "permit",
            "address_count": 2 ** 8,
            "range_count": 1,
            "cidrs": ["10.1.1.0/24"],
        }
    ]
    # The merged candidate is still returned for inspection; the diff is not.
    assert body["merged"] is not None
    assert body["merged"]["id"] is None
    assert body["merged"]["persisted"] is False
    assert {rule["rule_id"] for rule in body["merged"]["rules"]} == {"p", "x", "y"}
    assert body["diff"] is None
    assert body["summary"]["merge_conflict_addresses"] == 2 ** 8


def test_both_sides_can_have_merge_conflicts(client: TestClient) -> None:
    # Base permit /8.  A adds deny 10.1.0.0/16, B adds deny 10.2.0.0/16, and
    # then (still in B) a permit /24 inside each: two permit /24s undo both
    # of the deny /16s at their subnets.
    aid = _save(client, [{"rule_id": "p", "cidr": "10.0.0.0/8", "action": "permit"}])
    r = _precheck(
        client,
        aid,
        {"add": [{"rule_id": "x", "cidr": "10.1.0.0/16", "action": "deny"}]},
        {"add": [
            {"rule_id": "y1", "cidr": "10.1.1.0/24", "action": "permit"},
            {"rule_id": "y2", "cidr": "10.2.1.0/24", "action": "permit"},
        ]},
    )
    assert r.status_code == 200
    body = r.json()
    # y2's permit /24 is inside the untouched permit /8 surface -> no change
    # relative to base, hence only A's /16 contains an undone range.
    assert [c["side"] for c in body["merge_conflicts"]] == ["a"]
    assert body["merge_conflicts"][0]["cidrs"] == ["10.1.1.0/24"]


def test_merge_conflict_through_interaction_only(client: TestClient) -> None:
    # The direct changed-surface overlay agrees, but the sequential merge
    # undoes one side through an LPM interaction with an ancestor replacement.
    #
    # Base: deny /8 (p) -> permit /16 (d).  A rewrites d to deny /16, so A
    # changes the /16 surface from permit to deny.  B adds a permit /24 inside
    # the /16: relative to the *base* that is a no-op (the base /16 already
    # forwards permit), so the two changed surfaces do not intersect.  Applied
    # as A then B, however, B's longer permit /24 wins over A's deny /16 on
    # the /24, undoing A's change there -> merge conflict on side A only.
    aid = _save(client, [
        {"rule_id": "p", "cidr": "10.0.0.0/8", "action": "deny"},
        {"rule_id": "d", "cidr": "10.1.0.0/16", "action": "permit"},
    ])
    r = _precheck(
        client,
        aid,
        {"replace": [{"rule_id": "d", "cidr": "10.1.0.0/16", "action": "deny"}]},
        {"add": [{"rule_id": "z", "cidr": "10.1.1.0/24", "action": "permit"}]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["action_conflicts"] == []
    assert body["merge_conflicts"] == [
        {
            "side": "a",
            "ip_version": 4,
            "base_action": "permit",
            "side_action": "deny",
            "merged_action": "permit",
            "address_count": 2 ** 8,
            "range_count": 1,
            "cidrs": ["10.1.1.0/24"],
        }
    ]


# ---------------------------------------------------------------------------
# Clean merges
# ---------------------------------------------------------------------------
def test_clean_merge_returns_merged_analysis_and_base_diff(client: TestClient) -> None:
    aid = _save(client, NESTED)
    r = _precheck(
        client,
        aid,
        {"add": [{"rule_id": "x", "cidr": "10.9.0.0/16", "action": "deny"}]},
        {"remove": [{"rule_id": "l"}]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["passed"] is True
    assert body["structural_conflicts"] == []
    assert body["action_conflicts"] == []
    assert body["merge_conflicts"] == []

    merged = body["merged"]
    assert merged["persisted"] is False
    assert merged["id"] is None
    assert merged["name"] is None
    assert "created_at" in merged
    ids = [rule["rule_id"] for rule in merged["rules"]]
    # Surviving base rules first (d), then A's add, B only removed l.
    assert ids == ["p", "d", "x"]

    # The diff is the merged analysis vs the base version:
    # * the new deny /16 (permit -> deny),
    # * deleting the permit /24 l reveals the deny /16 (permit -> deny /24).
    changed = {
        (ch["change_type"], cidr)
        for ch in body["diff"]["changes"]
        for cidr in ch["cidrs"]
    }
    assert ("permit_to_deny", "10.1.1.0/24") in changed
    assert ("permit_to_deny", "10.9.0.0/16") in changed
    assert body["diff"]["base"]["id"] == aid


def test_clean_merge_deleting_every_rule_is_all_none(client: TestClient) -> None:
    # The two batches collectively delete all rules; neither batch alone is
    # empty, so each side is a legal simulation and the merge is valid.
    aid = _save(client, [
        {"rule_id": "x", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "y", "cidr": "2001:db8::/32", "action": "deny"},
    ])
    r = _precheck(
        client,
        aid,
        {"remove": [{"rule_id": "x"}]},
        {"remove": [{"rule_id": "y"}]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["passed"] is True
    assert body["merged"]["summary"]["rule_count"] == 0
    by_type = {(ch["ip_version"], ch["change_type"]): ch for ch in body["diff"]["changes"]}
    assert by_type[(4, "permit_to_none")]["cidrs"] == ["10.0.0.0/8"]
    assert by_type[(6, "deny_to_none")]["cidrs"] == ["2001:db8::/32"]


def test_sides_metadata_reports_independent_hashes(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "p", "cidr": "10.0.0.0/8", "action": "permit"}])
    r = _precheck(
        client,
        aid,
        {"add": [{"rule_id": "x", "cidr": "10.9.0.0/16", "action": "deny"}]},
        {"add": [{"rule_id": "y", "cidr": "10.8.0.0/16", "action": "deny"}]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["sides"]["a"]["rule_count"] == 2
    assert body["sides"]["b"]["rule_count"] == 2
    assert body["sides"]["a"]["ruleset_hash"] != body["sides"]["b"]["ruleset_hash"]
    assert body["base"]["id"] == aid


# ---------------------------------------------------------------------------
# Read-only / validation / error contract
# ---------------------------------------------------------------------------
def test_precheck_is_never_persisted(client: TestClient) -> None:
    aid = _save(client, NESTED)
    r = _precheck(
        client,
        aid,
        {"add": [{"rule_id": "x", "cidr": "10.9.0.0/16", "action": "deny"}]},
        {"add": [{"rule_id": "y", "cidr": "10.8.0.0/16", "action": "deny"}]},
    )
    assert r.status_code == 200
    merged_hash = r.json()["merged"]["ruleset_hash"]
    # Only the base version exists.
    assert client.get("/api/analyses").json()["total"] == 1
    assert client.get(f"/api/analyses/an_{merged_hash[:16]}").status_code == 404
    # The base version is untouched.
    assert {x["rule_id"] for x in client.get(f"/api/analyses/{aid}").json()["rules"]} == {
        "p",
        "d",
        "l",
    }


def test_invalid_batch_returns_invalid_simulation_with_issues(client: TestClient) -> None:
    aid = _save(client, NESTED)
    r = _precheck(
        client,
        aid,
        {"remove": [{"rule_id": "ghost"}]},
        {"add": [{"rule_id": "z", "cidr": "10.9.0.0/16", "action": "deny"}]},
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_simulation"
    assert any("ghost" in issue for issue in body["issues"])


def test_batch_referencing_other_sides_add_is_rejected(client: TestClient) -> None:
    # Each batch is validated independently against the *base* version: B
    # cannot replace an id that only exists because A adds it.
    aid = _save(client, NESTED)
    r = _precheck(
        client,
        aid,
        {"add": [{"rule_id": "z", "cidr": "10.9.0.0/16", "action": "deny"}]},
        {"replace": [{"rule_id": "z", "cidr": "10.9.0.0/16", "action": "permit"}]},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_simulation"
    assert "'z'" in r.json()["detail"]


def test_batch_emptying_its_own_side_is_rejected(client: TestClient) -> None:
    # The single-batch contract applies to each side: A alone may not delete
    # the only rule (collectively empty via both batches is still allowed).
    aid = _save(client, [
        {"rule_id": "x", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "y", "cidr": "2001:db8::/32", "action": "deny"},
    ])
    r = _precheck(
        client,
        aid,
        {"remove": [{"rule_id": "x"}, {"rule_id": "y"}]},
        {"remove": [{"rule_id": "x"}]},  # also structural, but stage 0 fires first
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_simulation"
    assert "at least one rule" in r.json()["detail"]


def test_invalid_rule_payload_returns_invalid_ruleset(client: TestClient) -> None:
    aid = _save(client, NESTED)
    r = _precheck(
        client,
        aid,
        {"remove": [{"rule_id": "l"}]},
        {"add": [{"rule_id": "z", "cidr": "10.0.0.5/24", "action": "deny"}]},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_ruleset"


def test_schema_level_errors_return_422(client: TestClient) -> None:
    aid = _save(client, NESTED)

    # Missing one of the two batches.
    r = client.post(
        f"/api/analyses/{aid}/merge-precheck",
        json={"a": {"remove": [{"rule_id": "l"}]}},
    )
    assert r.status_code == 422

    # Unknown top-level field.
    r = client.post(
        f"/api/analyses/{aid}/merge-precheck",
        json={
            "a": {"remove": [{"rule_id": "l"}]},
            "b": {"remove": [{"rule_id": "d"}]},
            "c": {},
        },
    )
    assert r.status_code == 422

    # Empty batch (no operations) passes the schema but is rejected as 400;
    # a malformed operation object is a schema error.
    r = client.post(
        f"/api/analyses/{aid}/merge-precheck",
        json={
            "a": {"remove": [{"rule_id": "l"}]},
            "b": {"add": [{"cidr": "10.9.0.0/16", "action": "deny"}]},
        },
    )
    assert r.status_code == 422


def test_empty_batches_are_rejected_like_simulation(client: TestClient) -> None:
    aid = _save(client, NESTED)
    r = client.post(
        f"/api/analyses/{aid}/merge-precheck",
        json={"a": {}, "b": {"remove": [{"rule_id": "l"}]}},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_simulation"
    assert "at least one operation" in r.json()["detail"]


def test_unknown_analysis_returns_404(client: TestClient) -> None:
    r = client.post(
        "/api/analyses/an_0000000000000000/merge-precheck",
        json={
            "a": {"remove": [{"rule_id": "p"}]},
            "b": {"add": [{"rule_id": "z", "cidr": "10.9.0.0/16", "action": "deny"}]},
        },
    )
    assert r.status_code == 404
    assert "an_0000000000000000" in r.json()["detail"]
