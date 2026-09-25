"""End-to-end tests for POST /api/analyses/{id}/quarantine-plan."""

from __future__ import annotations

import ipaddress
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-q-")
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


def _partition_covers_target(payload: dict, target: str) -> None:
    """The quarantined CIDRs plus already-deny surface exhaust the target."""
    target_net = ipaddress.ip_network(target)
    covered = 0
    for cidr in payload["quarantined_cidrs"]:
        net = ipaddress.ip_network(cidr)
        assert net.subnet_of(target_net)
        covered += net.num_addresses
    covered += payload["already_deny_addresses"]
    assert covered == target_net.num_addresses


NESTED_RULES = [
    {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100, "source_tag": "core"},
    {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200, "source_tag": "edge"},
    {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit", "priority": 50, "source_tag": "lab"},
]


# ---------------------------------------------------------------------------
def test_generated_rules_flip_permit_hole_inside_deny_surface(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES, name="nested")

    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "10.1.0.0/16", "rule_id_prefix": "tmp"},
    )
    assert r.status_code == 200, r.text
    payload = r.json()

    assert payload["generated"] is True
    assert payload["target_cidr"] == "10.1.0.0/16"
    assert payload["ip_version"] == 4
    assert payload["rule_id_prefix"] == "tmp"
    assert payload["blocking"] == []

    # Only the permit /24 hole needs a rule; the deny remainder generates none.
    assert payload["new_rule_count"] == 1
    rule = payload["new_rules"][0]
    assert rule == {
        "rule_id": "tmp1",
        "cidr": "10.1.1.0/24",
        "action": "deny",
        "priority": 0,
        "source_tag": "quarantine-plan",
        "address_count": 2 ** 8,
        "from_action": "permit",
        "supersedes_rule_id": "c",
        "subdivision_of_rule_id": None,
    }

    assert payload["quarantined_cidrs"] == ["10.1.1.0/24"]
    assert payload["quarantined_addresses"] == 2 ** 8
    assert payload["quarantined_range_count"] == 1
    assert payload["already_deny_addresses"] == 2 ** 16 - 2 ** 8
    _partition_covers_target(payload, "10.1.0.0/16")

    summary = payload["summary"]
    assert summary["target_addresses"] == 2 ** 16
    assert summary["already_deny_addresses"] == 2 ** 16 - 2 ** 8
    assert summary["before_permit_addresses"] == 2 ** 8
    assert summary["before_none_addresses"] == 0
    assert summary["planned_new_rules"] == 1
    assert summary["final_deny_addresses"] == 2 ** 16
    assert summary["final_permit_addresses"] == 0
    assert summary["final_none_addresses"] == 0

    # The recomputed semantic diff contains exactly permit_to_deny on the hole.
    changes = {(c["change_type"]): c for c in payload["diff"]["changes"]}
    assert set(changes) == {"permit_to_deny"}
    assert changes["permit_to_deny"]["cidrs"] == ["10.1.1.0/24"]
    assert changes["permit_to_deny"]["address_count"] == 2 ** 8


def test_unmatched_target_generates_one_rule_from_none(client: TestClient) -> None:
    aid = _save(client, [{"cidr": "10.0.0.0/8", "action": "permit", "source_tag": "hq"}])

    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "192.168.10.0/24", "rule_id_prefix": "q"},
    )
    payload = r.json()
    assert payload["generated"] is True
    assert len(payload["new_rules"]) == 1
    rule = payload["new_rules"][0]
    assert rule["rule_id"] == "q1"
    assert rule["cidr"] == "192.168.10.0/24"
    assert rule["from_action"] is None
    assert rule["supersedes_rule_id"] is None
    changes = {c["change_type"]: c for c in payload["diff"]["changes"]}
    assert set(changes) == {"none_to_deny"}
    assert payload["summary"]["before_none_addresses"] == 2 ** 8


def test_straddling_target_fragments_into_minimal_cidrs(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "r1", "cidr": "10.0.0.0/8", "action": "permit"}])

    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "8.0.0.0/6", "rule_id_prefix": "blk"},
    )
    payload = r.json()
    assert payload["generated"] is True
    # 8.0.0.0/7 (none), 10.0.0.0/8 (permit), 11.0.0.0/8 (none)
    assert [rule["cidr"] for rule in payload["new_rules"]] == [
        "8.0.0.0/7",
        "10.0.0.0/8",
        "11.0.0.0/8",
    ]
    assert [rule["rule_id"] for rule in payload["new_rules"]] == [
        "blk1",
        "blk2",
        "blk3",
    ]
    assert payload["quarantined_cidrs"] == ["8.0.0.0/6"]
    assert payload["quarantined_addresses"] == 2 ** 26
    _partition_covers_target(payload, "8.0.0.0/6")


def test_already_deny_target_generates_no_rules_and_is_success(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "r1", "cidr": "10.0.0.0/24", "action": "deny"}])

    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "10.0.0.0/24", "rule_id_prefix": "q"},
    )
    payload = r.json()
    assert payload["generated"] is True
    assert payload["new_rules"] == []
    assert payload["new_rule_count"] == 0
    assert payload["quarantined_addresses"] == 0
    assert payload["quarantined_cidrs"] == []
    assert payload["already_deny_addresses"] == 2 ** 8
    assert payload["summary"]["final_deny_addresses"] == 2 ** 8
    assert payload["diff"]["changes"] == []


def test_priority_zero_same_cidr_permit_is_subdivided(client: TestClient) -> None:
    # An active priority-0 permit /24 cannot be out-tied at the same CIDR;
    # the plan subdivides into two /25 halves (they fall back to "none") and
    # places deny rules on the strictly longer prefixes.
    aid = _save(client, [
        {"rule_id": "p", "cidr": "10.0.0.0/24", "action": "permit", "priority": 0},
    ])

    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "10.0.0.0/24", "rule_id_prefix": "q"},
    )
    payload = r.json()
    assert payload["generated"] is True
    assert [rule["cidr"] for rule in payload["new_rules"]] == [
        "10.0.0.0/25",
        "10.0.0.128/25",
    ]
    for rule in payload["new_rules"]:
        assert rule["priority"] == 0
        assert rule["from_action"] == "permit"
        assert rule["subdivision_of_rule_id"] == "p"
    assert payload["quarantined_cidrs"] == ["10.0.0.0/24"]


def test_subdivision_goes_deep_around_inner_rules(client: TestClient) -> None:
    # priority-0 permit /25 nested in a priority-0 permit /25 with an inner
    # priority-0 permit /26: both levels must be subdivided, and the whole
    # target still ends up deny.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/24", "action": "permit", "priority": 100},
        {"rule_id": "b", "cidr": "10.0.0.0/25", "action": "permit", "priority": 0},
        {"rule_id": "c", "cidr": "10.0.0.0/26", "action": "permit", "priority": 0},
    ])

    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "10.0.0.0/24", "rule_id_prefix": "q"},
    )
    payload = r.json()
    assert payload["generated"] is True
    cidrs = {rule["cidr"] for rule in payload["new_rules"]}
    # Outer half not covered by the p0 /25; inner structure around the p0 /26.
    assert "10.0.0.128/25" in cidrs
    assert "10.0.0.64/26" in cidrs
    # Generated CIDRs are pairwise disjoint and exhaust the target.
    nets = [ipaddress.ip_network(c) for c in cidrs]
    for i, x in enumerate(nets):
        for y in nets[i + 1:]:
            assert not x.overlaps(y), (x, y)
    assert sum(n.num_addresses for n in nets) == 2 ** 8
    _partition_covers_target(payload, "10.0.0.0/24")
    # The outer half is won by LPM over the permit /24 (no p0 bypass there);
    # fragments around the p0 /26 report the rule their subdivision beats.
    markers = {rule["cidr"]: rule["subdivision_of_rule_id"] for rule in payload["new_rules"]}
    assert markers["10.0.0.128/25"] is None
    assert markers["10.0.0.64/26"] == "b"
    assert markers["10.0.0.0/27"] == "c"


def test_single_address_blocked_by_priority_zero_is_not_generatable(
    client: TestClient,
) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/24", "action": "permit", "priority": 100},
        {"rule_id": "b", "cidr": "10.0.0.5/32", "action": "permit", "priority": 0},
    ])

    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "10.0.0.0/24", "rule_id_prefix": "q"},
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["generated"] is False
    assert payload["new_rules"] == []
    assert payload["new_rule_count"] == 0
    assert payload["candidate"] is None
    assert payload["diff"] is None
    assert payload["quarantined_addresses"] == 0

    blocking = payload["blocking"]
    assert len(blocking) == 1
    item = blocking[0]
    assert item["cidr"] == "10.0.0.5/32"
    assert item["ip_version"] == 4
    assert item["address_count"] == 1
    assert item["blocking_cidr"] == "10.0.0.5/32"
    assert item["blocking_rule_id"] == "b"
    assert item["blocking_action"] == "permit"
    assert item["blocking_priority"] == 0
    assert "priority-0" in item["reason"]

    summary = payload["summary"]
    assert summary["blocking_range_count"] == 1
    assert summary["blocking_addresses"] == 1
    assert summary["planned_new_rules"] == 0
    assert summary["quarantined_addresses"] == 0


def test_blocking_report_is_all_or_nothing(client: TestClient) -> None:
    # One p0 /32 blocker inside an otherwise trivially-quarantinable /24: no
    # partial rule list is returned.
    aid = _save(client, [
        {"rule_id": "h", "cidr": "10.0.0.7/32", "action": "deny", "priority": 0},
        {"rule_id": "p", "cidr": "10.0.0.9/32", "action": "permit", "priority": 0},
    ])
    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "10.0.0.0/28", "rule_id_prefix": "q"},
    )
    payload = r.json()
    assert payload["generated"] is False
    # The already-deny /32 host is not blocking; only the permit host is.
    assert [b["cidr"] for b in payload["blocking"]] == ["10.0.0.9/32"]


def test_existing_priority_above_zero_loses_the_same_cidr_tie(
    client: TestClient,
) -> None:
    aid = _save(client, [
        {"rule_id": "p", "cidr": "10.0.0.0/24", "action": "permit", "priority": 5},
    ])
    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "10.0.0.0/24", "rule_id_prefix": "q"},
    )
    payload = r.json()
    assert payload["generated"] is True
    assert [rule["cidr"] for rule in payload["new_rules"]] == ["10.0.0.0/24"]
    assert payload["new_rules"][0]["supersedes_rule_id"] == "p"
    assert payload["new_rules"][0]["subdivision_of_rule_id"] is None


def test_rule_id_collision_is_400_and_reports_ids(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "q1", "cidr": "10.0.0.0/24", "action": "permit"},
    ])
    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "10.0.0.0/24", "rule_id_prefix": "q"},
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_quarantine_plan"
    assert "q1" in body["detail"]
    # A different prefix works.
    ok = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "10.0.0.0/24", "rule_id_prefix": "deny-"},
    )
    assert ok.status_code == 200
    assert ok.json()["new_rules"][0]["rule_id"] == "deny-1"


def test_invalid_target_cidr_is_400_before_lookup(client: TestClient) -> None:
    aid = _save(client, [{"cidr": "10.0.0.0/8", "action": "permit"}])
    for bad in ("10.0.0.5/24", "10.0.0.0", "nonsense", "10.0.0.0/33"):
        r = client.post(
            f"/api/analyses/{aid}/quarantine-plan",
            json={"cidr": bad, "rule_id_prefix": "q"},
        )
        assert r.status_code == 400, (bad, r.status_code)
        assert r.json()["error"] == "invalid_cidr"

    # Invalid CIDR is rejected even when the version does not exist: query
    # validation precedes the version lookup.
    r = client.post(
        "/api/analyses/an_0000000000000000/quarantine-plan",
        json={"cidr": "10.0.0.5/24", "rule_id_prefix": "q"},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_cidr"


def test_missing_version_is_404(client: TestClient) -> None:
    r = client.post(
        "/api/analyses/an_0000000000000000/quarantine-plan",
        json={"cidr": "10.0.0.0/24", "rule_id_prefix": "q"},
    )
    assert r.status_code == 404


def test_body_validation_is_422(client: TestClient) -> None:
    aid = _save(client, [{"cidr": "10.0.0.0/24", "action": "permit"}])
    # Empty / missing / whitespace prefix.
    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "10.0.0.0/24", "rule_id_prefix": "   "},
    )
    assert r.status_code == 422
    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan", json={"cidr": "10.0.0.0/24"}
    )
    assert r.status_code == 422
    # Unknown field.
    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "10.0.0.0/24", "rule_id_prefix": "q", "priority": 0},
    )
    assert r.status_code == 422


def test_ipv6_target_and_single_host_blocking(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "v6", "cidr": "2001:db8::/32", "action": "deny", "source_tag": "v6"},
        {"rule_id": "hole", "cidr": "2001:db8:1::/48", "action": "permit", "priority": 10},
    ])
    r = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "2001:db8:1::/48", "rule_id_prefix": "v6q"},
    )
    payload = r.json()
    assert payload["generated"] is True
    assert payload["ip_version"] == 6
    assert payload["new_rules"][0]["cidr"] == "2001:db8:1::/48"
    assert payload["quarantined_addresses"] == 2 ** 80

    # priority-0 permit /128 is a single-address blocker for IPv6 too.
    aid2 = _save(client, [
        {"rule_id": "x", "cidr": "2001:db8::/120", "action": "permit", "priority": 100},
        {"rule_id": "y", "cidr": "2001:db8::1/128", "action": "permit", "priority": 0},
    ])
    blocked = client.post(
        f"/api/analyses/{aid2}/quarantine-plan",
        json={"cidr": "2001:db8::/120", "rule_id_prefix": "q"},
    ).json()
    assert blocked["generated"] is False
    assert blocked["blocking"][0]["cidr"] == "2001:db8::1/128"
    assert blocked["blocking"][0]["address_count"] == 1


def test_preview_is_not_persisted_and_outside_target_unchanged(
    client: TestClient,
) -> None:
    before = client.get("/api/analyses").json()["total"]
    aid = _save(client, NESTED_RULES)
    assert client.get("/api/analyses").json()["total"] == before + 1

    payload = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "10.1.0.0/16", "rule_id_prefix": "q"},
    ).json()

    # The candidate is presented exactly like an unsaved simulation.
    candidate = payload["candidate"]
    assert candidate["id"] is None
    assert candidate["persisted"] is False
    # It contains the original rules plus the generated deny rule.
    candidate_ids = {rule["rule_id"] for rule in candidate["rules"]}
    assert candidate_ids == {"a", "b", "c", "q1"}

    # No new version, no pointer movement.
    assert client.get("/api/analyses").json()["total"] == before + 1
    assert client.get("/api/active").json() == {"active_id": None, "revision": 0}

    # Only deny-converting changes exist and all stay inside the target.
    target_net = ipaddress.ip_network("10.1.0.0/16")
    for change in payload["diff"]["changes"]:
        assert change["to_action"] == "deny"
        for cidr in change["cidrs"]:
            assert ipaddress.ip_network(cidr).subnet_of(target_net)


def test_repeated_calls_are_deterministic(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    body = {"cidr": "10.1.0.0/16", "rule_id_prefix": "q"}
    first = client.post(f"/api/analyses/{aid}/quarantine-plan", json=body).json()
    second = client.post(f"/api/analyses/{aid}/quarantine-plan", json=body).json()
    assert first["new_rules"] == second["new_rules"]
    assert first["quarantined_cidrs"] == second["quarantined_cidrs"]
    assert first["candidate"]["ruleset_hash"] == second["candidate"]["ruleset_hash"]


def test_partial_target_with_mixed_inner_actions(client: TestClient) -> None:
    # permit /24 (p100); deny /25 covers the top half; p0 permit /32 lives in
    # the permit half and blocks the whole plan.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/24", "action": "permit", "priority": 100},
        {"rule_id": "b", "cidr": "10.0.0.128/25", "action": "deny"},
        {"rule_id": "c", "cidr": "10.0.0.5/32", "action": "permit", "priority": 0},
    ])
    payload = client.post(
        f"/api/analyses/{aid}/quarantine-plan",
        json={"cidr": "10.0.0.0/24", "rule_id_prefix": "q"},
    ).json()
    assert payload["generated"] is False
    assert [b["cidr"] for b in payload["blocking"]] == ["10.0.0.5/32"]
    assert payload["summary"]["already_deny_addresses"] == 128
