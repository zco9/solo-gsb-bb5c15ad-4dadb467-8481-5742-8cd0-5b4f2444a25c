"""End-to-end tests for GET /api/analyses/{id}/decision-map."""

from __future__ import annotations

import ipaddress
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-map-")
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


NESTED_RULES = [
    {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100, "source_tag": "core"},
    {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200, "source_tag": "edge"},
    {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit", "priority": 50, "source_tag": "lab"},
    {"rule_id": "d", "cidr": "10.1.0.0/16", "action": "deny", "priority": 300, "source_tag": "dup"},
]


def _blocks(payload: dict) -> list[dict]:
    return payload["blocks"]


def _assert_partition(payload: dict, cidr: str) -> None:
    query = ipaddress.ip_network(cidr)
    nets = [ipaddress.ip_network(b["cidr"]) for b in _blocks(payload)]
    # Pairwise disjoint, jointly exhaustive, same family.
    for i, x in enumerate(nets):
        for y in nets[i + 1:]:
            assert not x.overlaps(y), (x, y)
    assert sum(n.num_addresses for n in nets) == query.num_addresses
    # Stable sort: network address, then prefix length.
    order = [(int(n.network_address), n.prefixlen) for n in nets]
    assert order == sorted(order)
    for b in _blocks(payload):
        assert b["address_count"] == ipaddress.ip_network(b["cidr"]).num_addresses


# ---------------------------------------------------------------------------
def test_decision_map_basic_partition_and_chains(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES, name="nested")

    r = client.get(f"/api/analyses/{aid}/decision-map", params={"cidr": "10.1.0.0/16"})
    assert r.status_code == 200, r.text
    payload = r.json()

    assert payload["analysis_id"] == aid
    assert payload["query_cidr"] == "10.1.0.0/16"
    assert payload["ip_version"] == 4
    _assert_partition(payload, "10.1.0.0/16")

    by_cidr = {b["cidr"]: b for b in _blocks(payload)}

    # The lab /24 keeps its own permit winner.
    lab = by_cidr["10.1.1.0/24"]
    assert lab["action"] == "permit"
    assert lab["winner_rule_id"] == "c"
    assert lab["winner_source_tag"] == "lab"
    assert [e["rule_id"] for e in lab["match_chain"]] == ["c", "b", "d", "a"]
    # First chain entry is always the winner.
    assert lab["match_chain"][0]["rule_id"] == lab["winner_rule_id"]
    # Losing duplicate d is included, after winner b of the same /16.
    roles = {e["rule_id"]: e["role"] for e in lab["match_chain"]}
    assert roles["d"] == "duplicate"

    # The remainder of the /16 is won by b (deny); b's fragments are merged.
    deny_blocks = [b for b in _blocks(payload) if b["winner_rule_id"] == "b"]
    assert "10.1.0.0/24" in {b["cidr"] for b in deny_blocks}
    assert all(b["action"] == "deny" and b["winner_source_tag"] == "edge" for b in deny_blocks)
    example = deny_blocks[0]
    assert [e["rule_id"] for e in example["match_chain"]] == ["b", "d", "a"]

    summary = payload["summary"]
    assert summary["matched_addresses"] == 2 ** 16
    assert summary["unmatched_addresses"] == 0
    assert summary["permit_addresses"] == 2 ** 8
    assert summary["deny_addresses"] == 2 ** 16 - 2 ** 8
    assert summary["total_addresses"] == 2 ** 16
    assert summary["matched_blocks"] == len(deny_blocks) + 1
    assert summary["unmatched_blocks"] == 0


def test_unmatched_blocks_have_empty_chain_and_none_action(client: TestClient) -> None:
    aid = _save(client, [{"cidr": "10.0.0.0/8", "action": "permit", "source_tag": "hq"}])

    # Query wholly outside any rule.
    r = client.get(f"/api/analyses/{aid}/decision-map", params={"cidr": "192.168.0.0/24"})
    payload = r.json()
    assert len(_blocks(payload)) == 1
    block = _blocks(payload)[0]
    assert block["cidr"] == "192.168.0.0/24"
    assert block["action"] is None
    assert block["winner_rule_id"] is None
    assert block["winner_source_tag"] is None
    assert block["match_chain"] == []
    assert block["address_count"] == 2 ** 8
    assert payload["summary"]["unmatched_addresses"] == 2 ** 8
    assert payload["summary"]["matched_addresses"] == 0

    # Query straddling the rule: adjacent unmatched sides merge separately and
    # never join across the matched middle.
    r = client.get(f"/api/analyses/{aid}/decision-map", params={"cidr": "8.0.0.0/6"})
    payload = r.json()
    _assert_partition(payload, "8.0.0.0/6")
    by_cidr = {b["cidr"]: b for b in _blocks(payload)}
    assert by_cidr["10.0.0.0/8"]["action"] == "permit"
    assert by_cidr["8.0.0.0/7"]["action"] is None
    assert by_cidr["11.0.0.0/8"]["action"] is None
    assert all(b["match_chain"] == [] for b in _blocks(payload) if b["action"] is None)


def test_adjacent_same_winner_blocks_merge_but_not_different_winners(client: TestClient) -> None:
    # Two distinct winners on sibling /24s: no /23 merge between winners.
    aid = _save(client, [
        {"rule_id": "x", "cidr": "10.0.0.0/24", "action": "deny"},
        {"rule_id": "y", "cidr": "10.0.1.0/24", "action": "deny"},
    ])
    payload = client.get(
        f"/api/analyses/{aid}/decision-map", params={"cidr": "10.0.0.0/23"}
    ).json()
    cidrs = [b["cidr"] for b in _blocks(payload)]
    assert cidrs == ["10.0.0.0/24", "10.0.1.0/24"]
    assert "10.0.0.0/23" not in cidrs

    # One winner fragmented by a child: the winner's adjacent fragments around
    # the child merge (10.0.0.0/25 permit + 10.0.0.128/25 deny).
    aid2 = _save(client, [
        {"rule_id": "p", "cidr": "10.0.0.0/24", "action": "permit"},
        {"rule_id": "q", "cidr": "10.0.0.128/25", "action": "deny"},
    ])
    payload2 = client.get(
        f"/api/analyses/{aid2}/decision-map", params={"cidr": "10.0.0.0/24"}
    ).json()
    blocks2 = _blocks(payload2)
    assert [b["cidr"] for b in blocks2] == ["10.0.0.0/25", "10.0.0.128/25"]
    assert blocks2[0]["winner_rule_id"] == "p"
    assert blocks2[1]["winner_rule_id"] == "q"
    # The child's chain contains the fully covering ancestor.
    assert [e["rule_id"] for e in blocks2[1]["match_chain"]] == ["q", "p"]


def test_shadowed_ancestor_still_appears_in_chain(client: TestClient) -> None:
    # The /24 winner is fully shadowed by its two /25 children but every
    # address still matches it along the LPM chain.
    aid = _save(client, [
        {"rule_id": "r1", "cidr": "192.168.0.0/24", "action": "permit"},
        {"rule_id": "r2", "cidr": "192.168.0.0/25", "action": "deny"},
        {"rule_id": "r3", "cidr": "192.168.0.128/25", "action": "deny"},
    ])
    payload = client.get(
        f"/api/analyses/{aid}/decision-map", params={"cidr": "192.168.0.0/24"}
    ).json()
    assert [b["cidr"] for b in _blocks(payload)] == ["192.168.0.0/25", "192.168.0.128/25"]
    for block in _blocks(payload):
        chain_ids = [e["rule_id"] for e in block["match_chain"]]
        assert chain_ids[0] == block["winner_rule_id"]
        assert chain_ids[-1] == "r1"


def test_same_cidr_chain_ordered_by_priority_then_submission(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "x", "cidr": "10.0.0.0/16", "action": "permit", "priority": 50},
        {"rule_id": "y", "cidr": "10.0.0.0/16", "action": "deny", "priority": 20},
        {"rule_id": "z", "cidr": "10.0.0.0/16", "action": "deny", "priority": 50},
    ])
    payload = client.get(
        f"/api/analyses/{aid}/decision-map", params={"cidr": "10.0.0.0/16"}
    ).json()
    block = _blocks(payload)[0]
    assert block["winner_rule_id"] == "y"
    assert [e["rule_id"] for e in block["match_chain"]] == ["y", "x", "z"]


def test_query_smaller_than_winning_network_is_clipped(client: TestClient) -> None:
    aid = _save(client, [{"cidr": "10.0.0.0/8", "action": "deny", "source_tag": "core"}])
    payload = client.get(
        f"/api/analyses/{aid}/decision-map", params={"cidr": "10.1.2.0/24"}
    ).json()
    blocks = _blocks(payload)
    assert len(blocks) == 1
    assert blocks[0]["cidr"] == "10.1.2.0/24"
    assert blocks[0]["winner_rule_id"] == "r1"
    assert blocks[0]["address_count"] == 2 ** 8


def test_ipv6_query(client: TestClient) -> None:
    aid = _save(client, [{"cidr": "2001:db8::/32", "action": "deny", "source_tag": "v6"}])

    r = client.get(f"/api/analyses/{aid}/decision-map", params={"cidr": "2001:db8:1::/48"})
    block = _blocks(r.json())[0]
    assert block["cidr"] == "2001:db8:1::/48"
    assert block["action"] == "deny"
    assert block["winner_source_tag"] == "v6"
    assert block["address_count"] == 2 ** 80

    # Full v6 space: exact big integers, geometric (never enumerated).
    r = client.get(f"/api/analyses/{aid}/decision-map", params={"cidr": "::/0"})
    payload = r.json()
    assert payload["summary"]["matched_addresses"] == 2 ** 96
    assert payload["summary"]["unmatched_addresses"] == 2 ** 128 - 2 ** 96
    _assert_partition(payload, "::/0")

    # Neighbor /32 is unmatched.
    r = client.get(f"/api/analyses/{aid}/decision-map", params={"cidr": "2001:db9::/32"})
    assert _blocks(r.json())[0]["action"] is None


def test_invalid_cidr_returns_400(client: TestClient) -> None:
    aid = _save(client, [{"cidr": "10.0.0.0/8", "action": "permit"}])
    for bad in ("10.0.0.5/24", "10.0.0.0", "not-a-cidr", "2001:db8::1/32", "10.0.0.0/33"):
        r = client.get(f"/api/analyses/{aid}/decision-map", params={"cidr": bad})
        assert r.status_code == 400, (bad, r.status_code)
        assert r.json()["error"] == "invalid_cidr"
        assert "invalid CIDR" in r.json()["detail"] or "prefix length" in r.json()["detail"]

    # Missing parameter -> 422 (framework validation).
    r = client.get(f"/api/analyses/{aid}/decision-map")
    assert r.status_code == 422


def test_missing_version_returns_404(client: TestClient) -> None:
    r = client.get(
        "/api/analyses/an_0000000000000000/decision-map", params={"cidr": "10.0.0.0/8"}
    )
    assert r.status_code == 404

    # A malformed CIDR is rejected even when the version does not exist:
    # query validation runs before the version lookup.
    r = client.get(
        "/api/analyses/an_0000000000000000/decision-map", params={"cidr": "10.0.0.5/24"}
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_cidr"


def test_endpoint_is_read_only(client: TestClient) -> None:
    before = client.get("/api/analyses").json()["total"]
    aid = _save(client, NESTED_RULES)
    assert client.get("/api/analyses").json()["total"] == before + 1

    for cidr in ("10.1.0.0/16", "192.168.0.0/24", "2001:db8::/32"):
        r = client.get(f"/api/analyses/{aid}/decision-map", params={"cidr": cidr})
        assert r.status_code == 200
    # No new analysis rows were created by queries.
    assert client.get("/api/analyses").json()["total"] == before + 1
