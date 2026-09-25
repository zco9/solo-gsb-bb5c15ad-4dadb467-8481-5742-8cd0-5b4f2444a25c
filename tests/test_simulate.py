"""End-to-end tests for the POST /api/analyses/{id}/simulate endpoint."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-sim-")
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


def _changes_by_type(payload: dict) -> dict[tuple, dict]:
    return {(c["ip_version"], c["change_type"]): c for c in payload["diff"]["changes"]}


NESTED_RULES = [
    {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100, "source_tag": "core"},
    {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200, "source_tag": "edge"},
    {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit", "priority": 50, "source_tag": "edge"},
]


# ---------------------------------------------------------------------------
def test_remove_subnet_rule_reveals_ancestor_scope(client: TestClient) -> None:
    # Base: permit /8 -> deny /16 -> permit /24.  Deleting the deny /16 must
    # make the permit /8 ancestor forward /16 minus /24 again; the permit /24
    # grandchild stays permit and is unchanged.
    aid = _save(client, NESTED_RULES, name="nested")

    r = client.post(f"/api/analyses/{aid}/simulate", json={"remove": [{"rule_id": "b"}]})
    assert r.status_code == 200, r.text
    payload = r.json()

    # Base reference block.
    assert payload["base"]["id"] == aid

    sim = payload["simulated"]
    by_id = {rule["rule_id"]: rule for rule in sim["rules"]}
    assert set(by_id) == {"a", "c"}
    # /8 now has the /24 as its only child -> partial, coverage /8 minus /24.
    a = by_id["a"]
    assert a["status"] == "partial"
    assert a["covered"] == 2 ** 24 - 2 ** 8
    assert "10.1.1.0/24" not in a["effective_cidrs"]
    assert "10.1.0.0/24" in a["effective_cidrs"]
    # c remains the active winner of its /24.
    assert by_id["c"]["status"] == "active"
    assert by_id["c"]["effective_cidrs"] == ["10.1.1.0/24"]

    # Semantic diff: exactly the deleted deny surface flips back to permit.
    by_type = _changes_by_type(payload)
    revert = by_type[(4, "deny_to_permit")]
    assert revert["address_count"] == 2 ** 16 - 2 ** 8
    assert all(cidr.startswith("10.1.") for cidr in revert["cidrs"])
    assert "10.1.1.0/24" not in revert["cidrs"]
    # Nothing outside the /16 changes; the /24 and the rest of the /8 agree.
    assert (4, "permit_to_deny") not in by_type
    assert (4, "deny_to_none") not in by_type
    assert (4, "permit_to_none") not in by_type
    assert payload["diff"]["summary"]["ipv4"]["changed_addresses"] == 2 ** 16 - 2 ** 8


def test_removing_leaf_restores_ancestor_to_active(client: TestClient) -> None:
    # permit /24 covered entirely by one deny /25 leaf... plus a disjoint /25:
    # deleting both deny halves makes the permit /24 active again.
    aid = _save(client, [
        {"rule_id": "p", "cidr": "192.168.0.0/24", "action": "permit"},
        {"rule_id": "d1", "cidr": "192.168.0.0/25", "action": "deny"},
        {"rule_id": "d2", "cidr": "192.168.0.128/25", "action": "deny"},
    ])
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"remove": [{"rule_id": "d1"}, {"rule_id": "d2"}]},
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    p = next(rule for rule in payload["simulated"]["rules"] if rule["rule_id"] == "p")
    assert p["status"] == "active"
    assert p["effective_cidrs"] == ["192.168.0.0/24"]

    by_type = _changes_by_type(payload)
    # Adjacent sibling halves are collapsed back into the enclosing /24.
    assert by_type[(4, "deny_to_permit")]["cidrs"] == ["192.168.0.0/24"]
    assert by_type[(4, "deny_to_permit")]["address_count"] == 2 ** 8


def test_replace_subnet_action_flips_effective_surface(client: TestClient) -> None:
    # Rewriting the deny /16 into a permit /16 makes the whole /16 follow the
    # permit /8 ancestor again (/16 minus the permit /24 was previously deny).
    aid = _save(client, NESTED_RULES)
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"replace": [{
            "rule_id": "b", "cidr": "10.1.0.0/16", "action": "permit",
            "priority": 200, "source_tag": "edge",
        }]},
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    by_type = _changes_by_type(payload)
    assert by_type[(4, "deny_to_permit")]["address_count"] == 2 ** 16 - 2 ** 8
    assert "10.1.1.0/24" not in by_type[(4, "deny_to_permit")]["cidrs"]
    assert (4, "permit_to_deny") not in by_type
    b = next(x for x in payload["simulated"]["rules"] if x["rule_id"] == "b")
    assert b["action"] == "permit"
    # Same-action child: b is partial (its /24 child), but no conflict remains.
    assert not any(
        f["severity"] == "conflict" for f in payload["simulated"]["findings"]
    )


def test_replace_cidr_reattaches_rule_in_trie(client: TestClient) -> None:
    # Move the deny rule onto a disjoint /16: the original /16 reverts to the
    # permit ancestor while the new /16 flips permit -> deny.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny"},
    ])
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"replace": [{"rule_id": "b", "cidr": "10.2.0.0/16", "action": "deny"}]},
    )
    assert r.status_code == 200, r.text
    by_type = _changes_by_type(r.json())
    assert by_type[(4, "deny_to_permit")]["cidrs"] == ["10.1.0.0/16"]
    assert by_type[(4, "permit_to_deny")]["cidrs"] == ["10.2.0.0/16"]


def test_add_new_longer_prefix_denies_inside_ancestor(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"}])
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"add": [{"rule_id": "new", "cidr": "10.9.9.0/24", "action": "deny"}]},
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    sim_ids = [rule["rule_id"] for rule in payload["simulated"]["rules"]]
    assert sim_ids == ["a", "new"]  # appended after the surviving base rules
    new_rule = next(rule for rule in payload["simulated"]["rules"] if rule["rule_id"] == "new")
    assert new_rule["status"] == "active"
    assert new_rule["effective_cidrs"] == ["10.9.9.0/24"]
    by_type = _changes_by_type(payload)
    assert by_type[(4, "permit_to_deny")]["cidrs"] == ["10.9.9.0/24"]
    assert by_type[(4, "permit_to_deny")]["address_count"] == 2 ** 8


def test_add_appended_order_breaks_same_cidr_tie(client: TestClient) -> None:
    # An added rule on an existing CIDR with worse priority loses the tie but
    # is still a valid *new* rule_id.
    aid = _save(client, [{"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "priority": 10}])
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"add": [{"rule_id": "z", "cidr": "10.0.0.0/8", "action": "deny", "priority": 99}]},
    )
    assert r.status_code == 200, r.text
    rules = {x["rule_id"]: x for x in r.json()["simulated"]["rules"]}
    assert rules["z"]["role"] == "duplicate"
    assert rules["a"]["role"] == "winner"
    # The loser never forwards -> final effective actions are unchanged.
    assert r.json()["diff"]["changes"] == []


def test_action_aliases_and_defaults_accepted_in_patch(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={
            "add": [{"rule_id": "x", "cidr": "2001:db8:9::/48", "action": "BLOCK"}],
            "replace": [{"rule_id": "c", "cidr": "10.1.1.0/24", "action": "allow"}],
        },
    )
    assert r.status_code == 200, r.text
    rules = {x["rule_id"]: x for x in r.json()["simulated"]["rules"]}
    assert rules["x"]["action"] == "deny"
    assert rules["x"]["priority"] == 100
    assert rules["x"]["source_tag"] == "default"
    assert rules["c"]["action"] == "permit"


def test_simulation_is_never_persisted(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"add": [{"rule_id": "x", "cidr": "10.9.9.0/24", "action": "deny"}]},
    )
    assert r.status_code == 200
    sim = r.json()["simulated"]
    assert sim["persisted"] is False
    assert sim["id"] is None
    # Only the base version exists; no new row, no new rules/findings rows.
    assert client.get("/api/analyses").json()["total"] == 1
    assert client.get("/api/analyses").json()["analyses"][0]["id"] == aid
    # The simulated hash must not resolve to a stored analysis.
    assert client.get(f"/api/analyses/an_{sim['ruleset_hash'][:16]}").status_code == 404


def test_no_op_patch_matches_base_semantics(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    base = client.get(f"/api/analyses/{aid}").json()
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"replace": [{
            "rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny",
            "priority": 200, "source_tag": "edge",
        }]},
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["simulated"]["ruleset_hash"] == base["ruleset_hash"]
    assert payload["diff"]["changes"] == []
    assert payload["simulated"]["summary"] == base["summary"]


def test_unknown_analysis_returns_404(client: TestClient) -> None:
    r = client.post(
        "/api/analyses/an_0000000000000000/simulate",
        json={"remove": [{"rule_id": "a"}]},
    )
    assert r.status_code == 404
    assert "an_0000000000000000" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Batch validation: any illegal operation rejects the whole batch.
# ---------------------------------------------------------------------------
def test_invalid_batch_reports_every_issue_and_applies_nothing(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={
            "add": [{"rule_id": "a", "cidr": "10.2.0.0/16", "action": "deny"}],
            "replace": [{"rule_id": "ghost", "cidr": "10.3.0.0/16", "action": "permit"}],
            "remove": [{"rule_id": "phantom"}],
        },
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_simulation"
    joined = " ".join(body["issues"])
    assert len(body["issues"]) == 3
    assert "add" in joined and "'a'" in joined
    assert "'ghost'" in joined
    assert "'phantom'" in joined
    # Nothing was persisted and the base is untouched.
    assert client.get("/api/analyses").json()["total"] == 1
    after = client.get(f"/api/analyses/{aid}").json()
    assert {x["rule_id"] for x in after["rules"]} == {"a", "b", "c"}


def test_target_may_appear_at_most_once_per_batch(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    # Same id listed twice within one operation list.
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"remove": [{"rule_id": "b"}, {"rule_id": "b"}]},
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_simulation"
    assert "'b'" in body["detail"]
    assert "at most one operation" in body["detail"]

    # Same id spanning two different lists.
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={
            "replace": [{"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny"}],
            "remove": [{"rule_id": "b"}],
        },
    )
    assert r.status_code == 400
    assert "replace, remove" in r.json()["detail"]

    # A new add id may not be reused by a second add in the same batch.
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={
            "add": [
                {"rule_id": "x", "cidr": "10.4.0.0/16", "action": "deny"},
                {"rule_id": "x", "cidr": "10.5.0.0/16", "action": "deny"},
            ]
        },
    )
    assert r.status_code == 400
    assert "targeted 2 times (add, add)" in r.json()["detail"]


def test_removing_every_rule_is_rejected(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"remove": [{"rule_id": "a"}, {"rule_id": "b"}, {"rule_id": "c"}]},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_simulation"
    assert "at least one rule" in r.json()["detail"]
    # The base version still has all three rules.
    assert len(client.get(f"/api/analyses/{aid}").json()["rules"]) == 3


def test_invalid_rule_payload_in_patch_returns_invalid_ruleset(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    # Host bits set on an added rule -> same 400 contract as /api/analyze.
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"add": [{"rule_id": "x", "cidr": "10.0.0.5/24", "action": "deny"}]},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_ruleset"
    assert "invalid CIDR" in r.json()["detail"]

    # Duplicate id produced by the whole patched set is impossible via the
    # batch contract, but a malformed replacement CIDR is still surfaced.
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"replace": [{"rule_id": "b", "cidr": "nonsense", "action": "deny"}]},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_ruleset"


def test_schema_level_errors_return_422(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    # Unknown operation section.
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"delete": [{"rule_id": "b"}]},
    )
    assert r.status_code == 422

    # Extra field inside an operation object.
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"remove": [{"rule_id": "b", "force": True}]},
    )
    assert r.status_code == 422

    # add/replace rule_id missing.
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"add": [{"cidr": "10.9.0.0/16", "action": "deny"}]},
    )
    assert r.status_code == 422

    # Bad action.
    r = client.post(
        f"/api/analyses/{aid}/simulate",
        json={"add": [{"rule_id": "x", "cidr": "10.9.0.0/16", "action": "maybe"}]},
    )
    assert r.status_code == 422


def test_empty_batch_is_rejected(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    r = client.post(f"/api/analyses/{aid}/simulate", json={})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_simulation"
    assert "at least one operation" in r.json()["detail"]
