"""End-to-end tests for the saved-version semantic diff endpoint."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-diff-")
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


def _by_type(payload: dict) -> dict[str, dict]:
    return {
        (c["ip_version"], c["change_type"]): c
        for c in payload["changes"]
    }


# ---------------------------------------------------------------------------
def test_action_flip_and_none_transitions(client: TestClient) -> None:
    # base: permit /8 with a permit /24 hole (same action -> flat permit);
    # target: deny /16 with a permit /24 inside it.
    base_id = _save(client, [
        {"cidr": "10.0.0.0/8", "action": "permit"},
        {"cidr": "10.1.1.0/24", "action": "permit"},
    ], name="v1")
    target_id = _save(client, [
        {"cidr": "10.1.0.0/16", "action": "deny"},
        {"cidr": "10.1.1.0/24", "action": "permit"},
    ], name="v2")

    r = client.get(f"/api/analyses/{base_id}/diff/{target_id}")
    assert r.status_code == 200, r.text
    payload = r.json()

    assert payload["base"]["id"] == base_id
    assert payload["target"]["id"] == target_id

    by_type = _by_type(payload)
    # /16 minus /24: permit -> deny (65536 - 256 = 65280)
    permit_deny = by_type[(4, "permit_to_deny")]
    assert permit_deny["address_count"] == 2 ** 16 - 2 ** 8
    assert permit_deny["from_action"] == "permit"
    assert permit_deny["to_action"] == "deny"
    assert permit_deny["range_count"] == len(permit_deny["cidrs"])

    # /8 minus /16: permit -> none (16777216 - 65536 = 16711680)
    permit_none = by_type[(4, "permit_to_none")]
    assert permit_none["address_count"] == 2 ** 24 - 2 ** 16
    # The diff surface stays inside the /8; ranges are minimal CIDRs.
    assert all(c.startswith("10.") for c in permit_none["cidrs"])

    # The /24 keeps permit on both sides -> no change entry for it.
    assert all(c["change_type"] != "permit_to_permit" for c in payload["changes"])
    assert (4, "deny_to_permit") not in by_type

    summary = payload["summary"]
    assert summary["ipv4"]["changed_addresses"] == 2 ** 24 - 2 ** 8
    assert summary["ipv4"]["change_groups"] == 2
    assert summary["total_changed_addresses"] == 2 ** 24 - 2 ** 8
    assert summary["ipv6"]["changed_addresses"] == 0
    assert summary["ipv6"]["change_groups"] == 0
    # All six types appear in by_type counters.
    assert set(summary["ipv4"]["by_type"]) == {
        "permit_to_deny", "permit_to_none", "deny_to_permit",
        "deny_to_none", "none_to_permit", "none_to_deny",
    }
    assert summary["ipv4"]["by_type"]["permit_to_deny"] == 2 ** 16 - 2 ** 8


def test_reverse_direction_inverts_transitions(client: TestClient) -> None:
    base_id = _save(client, [{"cidr": "10.1.0.0/16", "action": "deny"}])
    target_id = _save(client, [{"cidr": "10.1.0.0/16", "action": "permit"}])

    forward = client.get(f"/api/analyses/{base_id}/diff/{target_id}").json()
    backward = client.get(f"/api/analyses/{target_id}/diff/{base_id}").json()

    fwd = _by_type(forward)
    bwd = _by_type(backward)
    assert (4, "deny_to_permit") in fwd
    assert fwd[(4, "deny_to_permit")]["cidrs"] == ["10.1.0.0/16"]
    assert (4, "permit_to_deny") in bwd
    assert bwd[(4, "permit_to_deny")]["address_count"] == 2 ** 16
    assert forward["summary"]["total_changed_addresses"] == backward["summary"]["total_changed_addresses"]


def test_removing_all_rules_is_none_transitions_per_family(client: TestClient) -> None:
    base_id = _save(client, [
        {"cidr": "192.0.2.0/24", "action": "permit"},
        {"cidr": "2001:db8::/48", "action": "deny"},
    ])
    # An empty ruleset cannot be analyzed; instead save a disjoint v4 rule so
    # both original surfaces disappear and one new surface appears.
    target_id = _save(client, [
        {"cidr": "198.51.100.0/24", "action": "deny"},
    ])

    payload = client.get(f"/api/analyses/{base_id}/diff/{target_id}").json()
    by_type = _by_type(payload)

    assert by_type[(4, "permit_to_none")]["cidrs"] == ["192.0.2.0/24"]
    assert by_type[(4, "none_to_deny")]["cidrs"] == ["198.51.100.0/24"]
    assert by_type[(6, "deny_to_none")]["cidrs"] == ["2001:db8::/48"]

    assert payload["summary"]["ipv4"]["changed_addresses"] == 2 * 2 ** 8
    assert payload["summary"]["ipv6"]["changed_addresses"] == 2 ** 80


def test_adjacent_same_type_ranges_are_merged(client: TestClient) -> None:
    # Two new permit /24s that are siblings of 10.0.0.0/23 -> one /23 in output.
    target_id = _save(client, [
        {"cidr": "10.0.0.0/24", "action": "permit"},
        {"cidr": "10.0.1.0/24", "action": "permit"},
    ])
    # Need two distinct saved versions; create a base with an unrelated rule.
    base_id = _save(client, [{"cidr": "172.16.0.0/12", "action": "deny"}])

    payload = client.get(f"/api/analyses/{base_id}/diff/{target_id}").json()
    by_type = _by_type(payload)

    assert by_type[(4, "none_to_permit")]["cidrs"] == ["10.0.0.0/23"]
    assert by_type[(4, "none_to_permit")]["address_count"] == 2 ** 9
    assert by_type[(4, "deny_to_none")]["cidrs"] == ["172.16.0.0/12"]


def test_non_adjacent_and_different_type_ranges_are_not_merged(client: TestClient) -> None:
    # /24s separated by a gap stay separate even though the type is the same...
    target_gap = _save(client, [
        {"cidr": "10.0.0.0/24", "action": "permit"},
        {"cidr": "10.0.2.0/24", "action": "permit"},
    ])
    base = _save(client, [{"cidr": "172.16.0.0/12", "action": "deny"}])
    gap_payload = client.get(f"/api/analyses/{base}/diff/{target_gap}").json()
    none_permit = _by_type(gap_payload)[(4, "none_to_permit")]
    assert sorted(none_permit["cidrs"]) == ["10.0.0.0/24", "10.0.2.0/24"]
    assert none_permit["range_count"] == 2

    # ...and adjacent ranges with different change types stay separate too.
    target_mixed = _save(client, [
        {"cidr": "10.0.0.0/24", "action": "permit"},
        {"cidr": "10.0.1.0/24", "action": "deny"},
    ])
    mixed_payload = client.get(f"/api/analyses/{base}/diff/{target_mixed}").json()
    mixed = _by_type(mixed_payload)
    assert mixed[(4, "none_to_permit")]["cidrs"] == ["10.0.0.0/24"]
    assert mixed[(4, "none_to_deny")]["cidrs"] == ["10.0.1.0/24"]
    # The sibling /24s must not have been collapsed across change types.
    assert "10.0.0.0/23" not in {
        cidr for c in mixed_payload["changes"] for cidr in c["cidrs"]
    }


def test_semantically_equal_rule_sets_have_no_changes(client: TestClient) -> None:
    # Different rule shapes that yield the same effective action everywhere:
    # base permit /8 with permit /16 inside (flat permit); target flat permit /8.
    base_id = _save(client, [
        {"cidr": "10.0.0.0/8", "action": "permit"},
        {"cidr": "10.1.0.0/16", "action": "permit"},
    ])
    target_id = _save(client, [{"cidr": "10.0.0.0/8", "action": "permit"}])

    payload = client.get(f"/api/analyses/{base_id}/diff/{target_id}").json()
    assert payload["changes"] == []
    assert payload["summary"]["total_changed_addresses"] == 0
    assert payload["summary"]["total_change_groups"] == 0


def test_ipv6_counts_are_exact(client: TestClient) -> None:
    base_id = _save(client, [{"cidr": "2001:db8::/32", "action": "deny"}])
    target_id = _save(client, [{"cidr": "2001:db8::/32", "action": "permit"}])

    payload = client.get(f"/api/analyses/{base_id}/diff/{target_id}").json()
    entry = _by_type(payload)[(6, "deny_to_permit")]
    assert entry["cidrs"] == ["2001:db8::/32"]
    # 2**96 addresses — far beyond 64-bit range, must remain an exact integer.
    assert entry["address_count"] == 2 ** 96
    assert isinstance(entry["address_count"], int)
    assert payload["summary"]["ipv6"]["changed_addresses"] == 2 ** 96


def test_nested_partitions_overlay_without_double_count(client: TestClient) -> None:
    # base: permit /8 ; target: deny /16 with permit /24 nested inside.
    base_id = _save(client, [{"cidr": "10.0.0.0/8", "action": "permit"}])
    target_id = _save(client, [
        {"cidr": "10.1.0.0/16", "action": "deny"},
        {"cidr": "10.1.1.0/24", "action": "permit"},
    ])
    payload = client.get(f"/api/analyses/{base_id}/diff/{target_id}").json()
    by_type = _by_type(payload)

    assert by_type[(4, "permit_to_deny")]["address_count"] == 2 ** 16 - 2 ** 8
    assert by_type[(4, "permit_to_none")]["address_count"] == 2 ** 24 - 2 ** 16
    # The /24 agrees (permit on both sides) -> nothing reported for it.
    assert sum(c["address_count"] for c in payload["changes"]) == 2 ** 24 - 2 ** 8


def test_deep_nesting_inherits_enclosing_piece_action(client: TestClient) -> None:
    # A's /16 is fragmented by its own deny /24; B additionally has an outer
    # permit /8.  A's fragmented remainder (permit) falls inside B pieces that
    # sit at different nesting depths — the overlay must inherit the right one.
    base_id = _save(client, [
        {"cidr": "10.1.0.0/16", "action": "permit"},
        {"cidr": "10.1.1.0/24", "action": "deny"},
    ])
    target_id = _save(client, [
        {"cidr": "10.0.0.0/8", "action": "permit"},
        {"cidr": "10.1.0.0/16", "action": "deny"},
        {"cidr": "10.1.1.0/24", "action": "permit"},
    ])
    by_type = _by_type(client.get(f"/api/analyses/{base_id}/diff/{target_id}").json())

    # /16 minus .1/24: permit -> deny (65280)
    assert by_type[(4, "permit_to_deny")]["address_count"] == 2 ** 16 - 2 ** 8
    # .1/24: deny -> permit (256)
    assert by_type[(4, "deny_to_permit")]["address_count"] == 2 ** 8
    # /8 minus /16: none -> permit (the outer B piece)
    assert by_type[(4, "none_to_permit")]["address_count"] == 2 ** 24 - 2 ** 16
    # .1/24 is the only deny->permit surface; nothing else leaked.
    assert by_type[(4, "deny_to_permit")]["cidrs"] == ["10.1.1.0/24"]

    # Reverse direction inverts every transition.
    rev = _by_type(client.get(f"/api/analyses/{target_id}/diff/{base_id}").json())
    assert rev[(4, "deny_to_permit")]["address_count"] == 2 ** 16 - 2 ** 8
    assert rev[(4, "permit_to_deny")]["address_count"] == 2 ** 8
    assert rev[(4, "permit_to_none")]["address_count"] == 2 ** 24 - 2 ** 16


def test_diff_error_codes(client: TestClient) -> None:
    aid = _save(client, [{"cidr": "10.0.0.0/8", "action": "permit"}])

    # Malformed ids -> 400
    r = client.get("/api/analyses/not-an-id/diff/an_0123456789abcdef")
    assert r.status_code == 400
    assert "invalid analysis id format" in r.json()["detail"]

    r = client.get(f"/api/analyses/{aid}/diff/zz_0123456789abcdef")
    assert r.status_code == 400

    # Same id -> 400 even though it exists
    r = client.get(f"/api/analyses/{aid}/diff/{aid}")
    assert r.status_code == 400
    assert "must differ" in r.json()["detail"]

    # Same id but nonexistent: still 400 (format/identity checked first)
    r = client.get("/api/analyses/an_0000000000000000/diff/an_0000000000000000")
    assert r.status_code == 400

    # Well-formed but missing -> 404 (either side)
    r = client.get(f"/api/analyses/{aid}/diff/an_0000000000000000")
    assert r.status_code == 404
    assert "an_0000000000000000" in r.json()["detail"]

    r = client.get(f"/api/analyses/an_0000000000000000/diff/{aid}")
    assert r.status_code == 404

    # Two different well-formed nonexistent ids -> 404 on the base first
    r = client.get("/api/analyses/an_aaaaaaaaaaaaaaaa/diff/an_bbbbbbbbbbbbbbbb")
    assert r.status_code == 404
