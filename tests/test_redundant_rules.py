"""End-to-end tests for the GET /api/analyses/{id}/redundant-rules endpoint."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-redundant-")
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


def _inventory(client: TestClient, aid: str) -> dict:
    r = client.get(f"/api/analyses/{aid}/redundant-rules")
    assert r.status_code == 200, r.text
    return r.json()


def _by_id(payload: dict) -> dict[str, dict]:
    return {entry["rule_id"]: entry for entry in payload["rules"]}


# ---------------------------------------------------------------------------
def test_same_action_fallback_is_safe_even_when_not_shadowed(client: TestClient) -> None:
    # permit /16 inside permit /8: the child forwards traffic (status active,
    # not shadowed), yet deleting it only hands its range back to the
    # same-action ancestor -> no address changes its final action.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "permit"},
    ])
    payload = _inventory(client, aid)
    entries = _by_id(payload)

    assert entries["b"]["safe_to_remove"] is True
    assert entries["b"]["changed_addresses"] == 0
    # Deleting the ancestor instead orphans /8 minus /16 to `none`.
    assert entries["a"]["safe_to_remove"] is False
    assert entries["a"]["changed_addresses"] == 2 ** 24 - 2 ** 16
    assert payload["summary"] == {"rule_count": 2, "safe_to_remove_count": 1}


def test_shadowed_rule_and_same_action_chain_are_safe(client: TestClient) -> None:
    # deny /16 is fully shadowed by two deny /17s.  Deleting the shadowed /16
    # changes nothing; deleting either /17 is *also* safe because the /16
    # ancestor still denies that half.  Only the permit /8 is load-bearing.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny"},
        {"rule_id": "c", "cidr": "10.1.0.0/17", "action": "deny"},
        {"rule_id": "d", "cidr": "10.1.128.0/17", "action": "deny"},
    ])
    payload = _inventory(client, aid)
    entries = _by_id(payload)

    for rid in ("b", "c", "d"):
        assert entries[rid]["safe_to_remove"] is True, rid
        assert entries[rid]["changed_addresses"] == 0, rid
    assert entries["a"]["safe_to_remove"] is False
    assert entries["a"]["changed_addresses"] == 2 ** 24 - 2 ** 16
    assert payload["summary"]["safe_to_remove_count"] == 3


def test_nested_conflicting_rules_report_exact_change_counts(client: TestClient) -> None:
    # permit /8 -> deny /16 -> permit /24: every rule changes some addresses.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny"},
        {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit"},
    ])
    entries = _by_id(_inventory(client, aid))

    # Removing the deny /16 lets the permit /8 ancestor forward /16 minus /24.
    assert entries["b"]["safe_to_remove"] is False
    assert entries["b"]["changed_addresses"] == 2 ** 16 - 2 ** 8
    # Removing the permit /24 exposes it to the deny /16.
    assert entries["c"]["safe_to_remove"] is False
    assert entries["c"]["changed_addresses"] == 2 ** 8
    # Removing the /8 drops everything outside the /16 to none.
    assert entries["a"]["safe_to_remove"] is False
    assert entries["a"]["changed_addresses"] == 2 ** 24 - 2 ** 16


def test_removing_winner_with_same_cidr_duplicate_flips_action(client: TestClient) -> None:
    # The deny duplicate never forwards, but deleting the permit *winner*
    # hands the whole /8 to it — shadowed/duplicate status alone cannot
    # decide this; the recomputation must.
    aid = _save(client, [
        {"rule_id": "win", "cidr": "172.16.0.0/12", "action": "permit", "priority": 10},
        {"rule_id": "dup", "cidr": "172.16.0.0/12", "action": "deny", "priority": 20},
    ])
    entries = _by_id(_inventory(client, aid))

    assert entries["dup"]["safe_to_remove"] is True
    assert entries["dup"]["changed_addresses"] == 0
    assert entries["win"]["safe_to_remove"] is False
    assert entries["win"]["changed_addresses"] == 2 ** 20


def test_single_rule_version_gives_correct_result(client: TestClient) -> None:
    # Deleting the only rule leaves an empty set: its whole range -> none.
    aid = _save(client, [{"rule_id": "only", "cidr": "192.168.0.0/24", "action": "deny"}])
    payload = _inventory(client, aid)

    assert payload["rules"] == [
        {"rule_id": "only", "safe_to_remove": False, "changed_addresses": 2 ** 8}
    ]
    assert payload["summary"] == {"rule_count": 1, "safe_to_remove_count": 0}


def test_single_shadowed_rule_would_be_safe(client: TestClient) -> None:
    # A rule that forwards nothing at all (here: a duplicate loser is the
    # only same-CIDR loser, and the permit /24 is fully covered by a deny
    # /25 pair) — the fully shadowed permit /24 deletes cleanly.
    aid = _save(client, [
        {"rule_id": "p", "cidr": "192.168.0.0/24", "action": "permit"},
        {"rule_id": "d1", "cidr": "192.168.0.0/25", "action": "deny"},
        {"rule_id": "d2", "cidr": "192.168.0.128/25", "action": "deny"},
    ])
    entries = _by_id(_inventory(client, aid))

    assert entries["p"]["safe_to_remove"] is True
    assert entries["p"]["changed_addresses"] == 0
    # Each deny half is load-bearing (its half would fall back to permit).
    assert entries["d1"]["changed_addresses"] == 2 ** 7
    assert entries["d2"]["changed_addresses"] == 2 ** 7


def test_ipv6_family_is_compared_independently(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "v6a", "cidr": "2001:db8::/32", "action": "deny"},
        {"rule_id": "v6b", "cidr": "2001:db8:1::/48", "action": "permit"},
        {"rule_id": "v4", "cidr": "10.0.0.0/8", "action": "permit"},
    ])
    payload = _inventory(client, aid)
    entries = _by_id(payload)

    # Removing the v6 permit /48 exposes exactly 2**80 addresses to the deny.
    assert entries["v6b"]["safe_to_remove"] is False
    assert entries["v6b"]["changed_addresses"] == 2 ** 80
    # Removing the v6 deny /32 drops /32 minus /48 to none (IPv6 counted exactly).
    assert entries["v6a"]["changed_addresses"] == 2 ** 96 - 2 ** 80
    # The disjoint IPv4 rule stands alone.
    assert entries["v4"]["safe_to_remove"] is False
    assert entries["v4"]["changed_addresses"] == 2 ** 24


def test_entries_follow_original_rule_order(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "z-first", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "m-second", "cidr": "2001:db8::/32", "action": "deny"},
        {"rule_id": "a-third", "cidr": "10.1.0.0/16", "action": "deny"},
    ])
    payload = _inventory(client, aid)
    assert [e["rule_id"] for e in payload["rules"]] == ["z-first", "m-second", "a-third"]
    assert payload["analysis_id"] == aid
    saved = client.get(f"/api/analyses/{aid}").json()
    assert payload["ruleset_hash"] == saved["ruleset_hash"]
    assert payload["analyzer_version"] == saved["analyzer_version"]


def test_inventory_never_persists_anything(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "permit"},
    ])
    _inventory(client, aid)
    _inventory(client, aid)
    listing = client.get("/api/analyses").json()
    assert listing["total"] == 1
    assert listing["analyses"][0]["id"] == aid
    # The stored version is untouched.
    assert len(client.get(f"/api/analyses/{aid}").json()["rules"]) == 2


def test_unknown_analysis_returns_404(client: TestClient) -> None:
    r = client.get("/api/analyses/an_0000000000000000/redundant-rules")
    assert r.status_code == 404
    assert "an_0000000000000000" in r.json()["detail"]
