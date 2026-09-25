"""End-to-end tests for the GET /api/analyses/{id}/source-retirement endpoint."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-retirement-")
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


def _report(client: TestClient, aid: str) -> dict:
    r = client.get(f"/api/analyses/{aid}/source-retirement")
    assert r.status_code == 200, r.text
    return r.json()


def _by_tag(payload: dict) -> dict[str, dict]:
    return {entry["source_tag"]: entry for entry in payload["sources"]}


# ---------------------------------------------------------------------------
def test_entries_follow_first_seen_order_and_rule_ids_submission_order(
    client: TestClient,
) -> None:
    aid = _save(client, [
        {"rule_id": "z", "cidr": "10.0.0.0/8", "action": "permit", "source_tag": "zeta"},
        {"rule_id": "a1", "cidr": "2001:db8::/32", "action": "deny", "source_tag": "alpha"},
        {"rule_id": "a2", "cidr": "10.1.0.0/16", "action": "deny", "source_tag": "alpha"},
        {"rule_id": "m", "cidr": "192.168.0.0/24", "action": "deny", "source_tag": "zeta"},
    ])
    payload = _report(client, aid)

    assert [s["source_tag"] for s in payload["sources"]] == ["zeta", "alpha"]
    assert payload["sources"][0]["rule_ids"] == ["z", "m"]
    assert payload["sources"][1]["rule_ids"] == ["a1", "a2"]
    assert payload["summary"] == {
        "source_count": 2,
        "rule_count": 4,
        "safe_to_retire_count": 0,
    }
    assert payload["analysis_id"] == aid
    saved = client.get(f"/api/analyses/{aid}").json()
    assert payload["ruleset_hash"] == saved["ruleset_hash"]
    assert payload["analyzer_version"] == saved["analyzer_version"]


def test_safe_source_whole_range_falls_back_to_same_action_ancestor(
    client: TestClient,
) -> None:
    # The `edge` permit /16 lives inside the `core` permit /8: removing the
    # whole edge group only hands its range back to the same-action ancestor,
    # so the source can be withdrawn as a group.
    aid = _save(client, [
        {"rule_id": "r1", "cidr": "10.0.0.0/8", "action": "permit", "source_tag": "core"},
        {"rule_id": "r2", "cidr": "10.1.0.0/16", "action": "permit", "source_tag": "edge"},
    ])
    sources = _by_tag(_report(client, aid))

    edge = sources["edge"]
    assert edge["safe_to_retire"] is True
    assert edge["changed_addresses"] == 0
    assert edge["changes"] == []
    assert edge["summary"]["changed_addresses"] == 0
    assert edge["summary"]["ipv4"]["by_type"] == {
        "permit_to_deny": 0,
        "permit_to_none": 0,
        "deny_to_permit": 0,
        "deny_to_none": 0,
        "none_to_permit": 0,
        "none_to_deny": 0,
    }

    core = sources["core"]
    assert core["safe_to_retire"] is False
    assert core["changed_addresses"] == 2 ** 24 - 2 ** 16
    assert len(core["changes"]) == 1
    change = core["changes"][0]
    # The surviving edge /16 keeps permitting; only /8 minus /16 drops to none.
    assert change["change_type"] == "permit_to_none"
    assert change["address_count"] == 2 ** 24 - 2 ** 16
    assert "10.1.0.0/16" not in change["cidrs"]


def test_group_unsafe_even_when_each_rule_is_individually_safe_same_cidr(
    client: TestClient,
) -> None:
    # permit (priority 10) and deny (priority 20) share one CIDR.  The deny
    # duplicate deletes cleanly on its own; deleting the permit winner alone
    # also looks safe *only if the duplicate stays* — here both rules carry
    # the same tag, so each single deletion is a no-op but the whole group
    # withdrawal drops the entire /12 to none.
    aid = _save(client, [
        {"rule_id": "win", "cidr": "172.16.0.0/12", "action": "permit",
         "priority": 10, "source_tag": "hq"},
        {"rule_id": "dup", "cidr": "172.16.0.0/12", "action": "deny",
         "priority": 20, "source_tag": "hq"},
    ])

    redundant = client.get(f"/api/analyses/{aid}/redundant-rules").json()
    by_id = {e["rule_id"]: e for e in redundant["rules"]}
    # Only the losing duplicate is individually safe; the point of the test
    # is that the group verdict comes from its own recomputation regardless.
    assert by_id["dup"]["safe_to_remove"] is True

    sources = _by_tag(_report(client, aid))
    hq = sources["hq"]
    assert hq["rule_ids"] == ["win", "dup"]
    assert hq["safe_to_retire"] is False
    assert hq["changed_addresses"] == 2 ** 20
    assert len(hq["changes"]) == 1
    change = hq["changes"][0]
    assert change["change_type"] == "permit_to_none"
    assert change["from_action"] == "permit"
    assert change["to_action"] is None
    assert change["address_count"] == 2 ** 20
    assert change["cidrs"] == ["172.16.0.0/12"]


def test_group_unsafe_when_mutually_backing_same_action_rules_leave(
    client: TestClient,
) -> None:
    # A shadowed deny /16 plus the two deny /17 halves that cover it, all from
    # `dc1`, inside a permit /8 from `core`.  Each /17 is individually safe
    # (the /16 denies its half) and the /16 is individually safe (the /17s
    # cover it); removing the whole dc1 group exposes the full /16 to permit.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "source_tag": "core"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "source_tag": "dc1"},
        {"rule_id": "c", "cidr": "10.1.0.0/17", "action": "deny", "source_tag": "dc1"},
        {"rule_id": "d", "cidr": "10.1.128.0/17", "action": "deny", "source_tag": "dc1"},
    ])

    redundant = client.get(f"/api/analyses/{aid}/redundant-rules").json()
    by_id = {e["rule_id"]: e for e in redundant["rules"]}
    assert all(by_id[r]["safe_to_remove"] for r in ("b", "c", "d"))

    sources = _by_tag(_report(client, aid))
    dc1 = sources["dc1"]
    assert dc1["safe_to_retire"] is False
    assert dc1["changed_addresses"] == 2 ** 16
    assert len(dc1["changes"]) == 1
    change = dc1["changes"][0]
    assert change["change_type"] == "deny_to_permit"
    assert change["address_count"] == 2 ** 16
    # The /16 is the minimum CIDR covering both changed sibling halves.
    assert change["cidrs"] == ["10.1.0.0/16"]

    # Withdrawing core drops /8 minus /16 (still denied by dc1) to none.
    core = sources["core"]
    assert core["safe_to_retire"] is False
    assert core["changed_addresses"] == 2 ** 24 - 2 ** 16
    assert [c["change_type"] for c in core["changes"]] == ["permit_to_none"]


def test_nested_conflict_source_reports_each_transition_as_minimal_cidrs(
    client: TestClient,
) -> None:
    # permit /8 (core) -> deny /16 (edge) -> permit /24 (lab): withdrawing
    # edge hands /16 minus /24 back to the permit ancestor and leaves the
    # permit /24 standing, so only deny_to_permit fragments change.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "source_tag": "core"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "source_tag": "edge"},
        {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit", "source_tag": "lab"},
    ])
    edge = _by_tag(_report(client, aid))["edge"]

    assert edge["safe_to_retire"] is False
    assert edge["changed_addresses"] == 2 ** 16 - 2 ** 8
    change = edge["changes"][0]
    assert change["change_type"] == "deny_to_permit"
    assert change["ip_version"] == 4
    assert change["range_count"] == len(change["cidrs"])
    assert sum(_cidr_size(c) for c in change["cidrs"]) == 2 ** 16 - 2 ** 8
    # Fragments are strict subnets of /16 and never include the /24 hole.
    assert "10.1.1.0/24" not in change["cidrs"]


def test_retiring_the_only_source_compares_against_empty_ruleset(
    client: TestClient,
) -> None:
    aid = _save(client, [
        {"rule_id": "only", "cidr": "192.168.0.0/24", "action": "deny",
         "source_tag": "solo"},
    ])
    payload = _report(client, aid)
    assert payload["summary"] == {
        "source_count": 1,
        "rule_count": 1,
        "safe_to_retire_count": 0,
    }
    solo = payload["sources"][0]
    assert solo["rule_ids"] == ["only"]
    assert solo["safe_to_retire"] is False
    assert solo["changed_addresses"] == 2 ** 8
    assert solo["changes"] == [
        {
            "ip_version": 4,
            "change_type": "deny_to_none",
            "from_action": "deny",
            "to_action": None,
            "address_count": 2 ** 8,
            "range_count": 1,
            "cidrs": ["192.168.0.0/24"],
        }
    ]


def test_ipv6_and_ipv4_sources_are_counted_independently(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "v6a", "cidr": "2001:db8::/32", "action": "deny", "source_tag": "v6"},
        {"rule_id": "v6b", "cidr": "2001:db8:1::/48", "action": "permit", "source_tag": "v6"},
        {"rule_id": "v4", "cidr": "10.0.0.0/8", "action": "permit", "source_tag": "v4"},
    ])
    sources = _by_tag(_report(client, aid))

    v6 = sources["v6"]
    assert v6["rule_ids"] == ["v6a", "v6b"]
    assert v6["safe_to_retire"] is False
    # Removing both v6 rules drops the whole /32 (2**96) to none.
    assert v6["changed_addresses"] == 2 ** 96
    assert v6["summary"]["ipv6"]["changed_addresses"] == 2 ** 96
    assert v6["summary"]["ipv4"]["changed_addresses"] == 0
    types = {c["change_type"]: c["address_count"] for c in v6["changes"]}
    assert types == {"deny_to_none": 2 ** 96 - 2 ** 80, "permit_to_none": 2 ** 80}

    v4 = sources["v4"]
    assert v4["changed_addresses"] == 2 ** 24
    assert v4["summary"]["ipv4"]["changed_addresses"] == 2 ** 24
    assert v4["summary"]["ipv6"]["changed_addresses"] == 0


def test_default_source_tag_is_used_when_absent(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "r1", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "r2", "cidr": "10.1.0.0/16", "action": "deny"},
    ])
    sources = _by_tag(_report(client, aid))
    assert set(sources) == {"default"}
    assert sources["default"]["rule_ids"] == ["r1", "r2"]


def test_report_never_persists_anything(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "r1", "cidr": "10.0.0.0/8", "action": "permit", "source_tag": "a"},
        {"rule_id": "r2", "cidr": "10.1.0.0/16", "action": "deny", "source_tag": "b"},
    ])
    _report(client, aid)
    _report(client, aid)
    listing = client.get("/api/analyses").json()
    assert listing["total"] == 1
    assert listing["analyses"][0]["id"] == aid
    # The stored version is untouched.
    assert len(client.get(f"/api/analyses/{aid}").json()["rules"]) == 2
    # The publication pointer is unaffected as well.
    assert client.get("/api/active").json() == {"active_id": None, "revision": 0}


def test_unknown_analysis_returns_404(client: TestClient) -> None:
    r = client.get("/api/analyses/an_0000000000000000/source-retirement")
    assert r.status_code == 404
    assert "an_0000000000000000" in r.json()["detail"]


def _cidr_size(cidr: str) -> int:
    import ipaddress

    return ipaddress.ip_network(cidr).num_addresses
