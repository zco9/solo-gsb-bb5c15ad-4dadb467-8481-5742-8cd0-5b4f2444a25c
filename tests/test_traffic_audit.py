"""End-to-end tests for POST /api/analyses/{id}/traffic-audit."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-ta-")
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


def _audit(client: TestClient, aid: str, records: list[dict]) -> dict:
    r = client.post(f"/api/analyses/{aid}/traffic-audit", json={"records": records})
    assert r.status_code == 200, r.text
    return r.json()


# permit /8 first in submission order: a naive first-match attribution would
# pin every 10.x record on "a"; LPM must attribute to the longer prefixes.
NESTED_RULES = [
    {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100, "source_tag": "core"},
    {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200, "source_tag": "edge"},
    {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit", "priority": 50, "source_tag": "lab"},
]


# ---------------------------------------------------------------------------
# Attribution semantics
# ---------------------------------------------------------------------------
def test_lpm_attribution_not_first_match(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES, name="nested")

    payload = _audit(
        client,
        aid,
        [
            {"ip": "10.1.1.7", "action": "permit"},   # inside the /24
            {"ip": "10.1.2.9", "action": "deny"},     # /16 but not /24
            {"ip": "10.2.3.4", "action": "permit"},   # only the /8
        ],
    )

    assert payload["analysis_id"] == aid
    assert payload["record_count"] == 3
    results = payload["results"]
    assert [r["seq"] for r in results] == [0, 1, 2]

    assert results[0]["matched_rule_id"] == "c"
    assert results[0]["expected_action"] == "permit"
    assert results[0]["verdict"] == "consistent"
    assert results[0]["consistent"] is True

    # Longest prefix wins even though rule "a" was submitted first.
    assert results[1]["matched_rule_id"] == "b"
    assert results[1]["expected_action"] == "deny"
    assert results[1]["verdict"] == "consistent"

    assert results[2]["matched_rule_id"] == "a"
    assert results[2]["expected_action"] == "permit"

    by_rule = {b["rule_id"]: b for b in payload["by_rule"]}
    assert set(by_rule) == {"a", "b", "c"}
    assert by_rule["c"]["count"] == 1
    assert payload["mismatches"] == []
    assert payload["uncovered"] == []
    assert payload["summary"]["covered"] == {"records": 3, "count": 3}


def test_same_cidr_tie_break_by_priority_then_submission_order(client: TestClient) -> None:
    # Same CIDR twice: the smaller priority wins even when submitted later.
    aid = _save(
        client,
        [
            {"rule_id": "hi", "cidr": "10.0.0.0/24", "action": "permit", "priority": 200},
            {"rule_id": "lo", "cidr": "10.0.0.0/24", "action": "deny", "priority": 100},
        ],
    )
    payload = _audit(client, aid, [{"ip": "10.0.0.7", "action": "deny"}])
    result = payload["results"][0]
    assert result["matched_rule_id"] == "lo"
    assert result["expected_action"] == "deny"
    assert result["verdict"] == "consistent"

    # Equal priorities: the originally first-submitted rule wins.
    aid2 = _save(
        client,
        [
            {"rule_id": "first", "cidr": "192.168.0.0/24", "action": "deny", "priority": 100},
            {"rule_id": "second", "cidr": "192.168.0.0/24", "action": "permit", "priority": 100},
        ],
    )
    payload2 = _audit(client, aid2, [{"ip": "192.168.0.7", "action": "deny"}])
    result2 = payload2["results"][0]
    assert result2["matched_rule_id"] == "first"
    assert result2["expected_action"] == "deny"


def test_uncovered_is_explicit_not_inferred(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    payload = _audit(
        client,
        aid,
        [
            {"ip": "192.0.2.8", "action": "deny", "count": 4},
            {"ip": "10.1.1.7", "action": "permit"},
        ],
    )

    uncovered = payload["results"][0]
    assert uncovered["verdict"] == "uncovered"
    assert uncovered["matched_rule_id"] is None
    assert uncovered["expected_action"] is None
    assert uncovered["consistent"] is None

    # Uncovered weight is aggregated on its own, never as permit or deny.
    assert payload["uncovered"] == [
        {"ip_version": 4, "observed_action": "deny", "records": 1, "count": 4}
    ]
    summary = payload["summary"]
    assert summary["uncovered"] == {"records": 1, "count": 4}
    assert summary["covered"] == {"records": 1, "count": 1}
    assert summary["consistent"] == {"records": 1, "count": 1}
    assert summary["mismatch"] == {"records": 0, "count": 0}
    assert summary["total_count"] == 5


def test_mismatch_aggregation_by_rule_and_transition(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    payload = _audit(
        client,
        aid,
        [
            {"ip": "10.1.1.7", "action": "deny", "count": 2},    # expected permit
            {"ip": "10.1.1.8", "action": "deny"},                # same mismatch again
            {"ip": "10.1.2.9", "action": "permit", "count": 5},  # expected deny
            {"ip": "10.1.2.10", "action": "deny"},               # consistent
        ],
    )

    results = payload["results"]
    assert [r["verdict"] for r in results] == ["mismatch", "mismatch", "mismatch", "consistent"]
    assert results[0]["matched_rule_id"] == "c"
    assert results[0]["expected_action"] == "permit"
    assert results[0]["consistent"] is False

    # Mismatches grouped by (rule, expected, observed), weighted by count.
    assert payload["mismatches"] == [
        {"rule_id": "b", "expected_action": "deny", "observed_action": "permit",
         "records": 1, "count": 5},
        {"rule_id": "c", "expected_action": "permit", "observed_action": "deny",
         "records": 2, "count": 3},
    ]

    by_rule = {b["rule_id"]: b for b in payload["by_rule"]}
    assert by_rule["c"] == {"rule_id": "c", "action": "permit", "records": 2,
                            "count": 3, "consistent_count": 0, "mismatch_count": 3}
    assert by_rule["b"] == {"rule_id": "b", "action": "deny", "records": 2,
                            "count": 6, "consistent_count": 1, "mismatch_count": 5}

    summary = payload["summary"]
    assert summary["record_count"] == 4
    assert summary["total_count"] == 9
    assert summary["consistent"] == {"records": 1, "count": 1}
    assert summary["mismatch"] == {"records": 3, "count": 8}


def test_by_rule_sorted_by_weighted_count_desc(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    payload = _audit(
        client,
        aid,
        [
            {"ip": "10.2.0.1", "action": "permit"},               # a, weight 1
            {"ip": "10.1.2.1", "action": "deny", "count": 3},     # b, weight 3
            {"ip": "10.1.1.1", "action": "permit", "count": 2},   # c, weight 2
        ],
    )
    assert [b["rule_id"] for b in payload["by_rule"]] == ["b", "c", "a"]


def test_record_order_does_not_change_attribution(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    records = [
        {"ip": "10.1.1.7", "action": "deny"},
        {"ip": "10.1.2.9", "action": "permit"},
        {"ip": "192.0.2.8", "action": "deny"},
    ]
    forward = _audit(client, aid, records)
    backward = _audit(client, aid, list(reversed(records)))

    # Aggregations are identical; per-record results follow input order (seq).
    assert forward["by_rule"] == backward["by_rule"]
    assert forward["mismatches"] == backward["mismatches"]
    assert forward["uncovered"] == backward["uncovered"]
    assert forward["summary"] == backward["summary"]
    assert [r["ip"] for r in backward["results"]] == ["192.0.2.8", "10.1.2.9", "10.1.1.7"]
    assert backward["results"][0]["seq"] == 0
    assert backward["results"][0]["verdict"] == "uncovered"


def test_ipv6_records_and_mixed_families(client: TestClient) -> None:
    aid = _save(
        client,
        [
            {"rule_id": "v6", "cidr": "2001:db8::/32", "action": "deny", "priority": 100},
            {"rule_id": "v6h", "cidr": "2001:db8:1::/48", "action": "permit", "priority": 900},
            {"rule_id": "v4", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100},
        ],
    )

    payload = _audit(
        client,
        aid,
        [
            {"ip": "2001:db8:1::7", "action": "permit", "count": 2},  # /48 hole
            {"ip": "2001:db8:2::7", "action": "deny"},                # /32 only
            {"ip": "2001:db9::1", "action": "permit"},                # no v6 rule covers it
            {"ip": "10.1.2.3", "action": "permit"},
        ],
    )

    results = payload["results"]
    assert results[0]["matched_rule_id"] == "v6h"
    assert results[0]["ip_version"] == 6
    assert results[0]["ip"] == "2001:db8:1::7"
    assert results[1]["matched_rule_id"] == "v6"
    assert results[2]["verdict"] == "uncovered"
    assert results[2]["matched_rule_id"] is None
    assert results[3]["matched_rule_id"] == "v4"

    summary = payload["summary"]
    assert summary["ipv6"] == {"records": 3, "count": 4}
    assert summary["ipv4"] == {"records": 1, "count": 1}
    assert payload["uncovered"] == [
        {"ip_version": 6, "observed_action": "permit", "records": 1, "count": 1}
    ]


def test_action_aliases_are_normalized(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    payload = _audit(client, aid, [{"ip": "10.1.1.7", "action": "DROP"}])
    result = payload["results"][0]
    assert result["observed_action"] == "deny"
    assert result["expected_action"] == "permit"
    assert result["verdict"] == "mismatch"


# ---------------------------------------------------------------------------
# Validation: the batch is all-or-nothing
# ---------------------------------------------------------------------------
def test_invalid_ips_reject_whole_batch_with_all_issues(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    r = client.post(
        f"/api/analyses/{aid}/traffic-audit",
        json={
            "records": [
                {"ip": "10.1.1.7", "action": "permit"},
                {"ip": "10.0.0.5/24", "action": "permit"},   # CIDR, not an address
                {"ip": "not-an-ip", "action": "deny"},
                {"ip": "10.1.2.9", "action": "deny"},
            ]
        },
    )
    assert r.status_code == 400, r.text
    body = r.json()
    assert body["error"] == "invalid_traffic_audit"
    assert len(body["issues"]) == 2
    assert "record #2" in body["issues"][0]
    assert "10.0.0.5/24" in body["issues"][0]
    assert "record #3" in body["issues"][1]
    assert "not-an-ip" in body["issues"][1]


def test_invalid_action_and_count_rejected(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    url = f"/api/analyses/{aid}/traffic-audit"

    # Unknown action -> 422 (field-level, same convention as rule actions).
    r = client.post(url, json={"records": [{"ip": "10.1.1.7", "action": "maybe"}]})
    assert r.status_code == 422

    # count must be a positive integer: 0, negative, bool, float, str all rejected.
    for bad_count in (0, -2, True, 1.5, "3"):
        r = client.post(
            url, json={"records": [{"ip": "10.1.1.7", "action": "permit", "count": bad_count}]}
        )
        assert r.status_code == 422, f"count={bad_count!r} must be rejected"

    # Empty batch, missing fields, unknown fields -> 422.
    assert client.post(url, json={"records": []}).status_code == 422
    assert client.post(url, json={"records": [{"action": "permit"}]}).status_code == 422
    assert client.post(url, json={"records": [{"ip": "10.1.1.7"}]}).status_code == 422
    assert client.post(
        url, json={"records": [{"ip": "10.1.1.7", "action": "permit", "note": "x"}]}
    ).status_code == 422
    assert client.post(url, json={}).status_code == 422


def test_unknown_analysis_returns_404(client: TestClient) -> None:
    r = client.post(
        "/api/analyses/an_0000000000000000/traffic-audit",
        json={"records": [{"ip": "10.1.1.7", "action": "permit"}]},
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Read-only contract
# ---------------------------------------------------------------------------
def test_audit_is_read_only_and_deterministic(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    records = [
        {"ip": "10.1.1.7", "action": "deny", "count": 2},
        {"ip": "192.0.2.8", "action": "permit"},
    ]

    before = client.get("/api/analyses").json()
    first = _audit(client, aid, records)
    second = _audit(client, aid, records)
    after = client.get("/api/analyses").json()

    assert first == second
    assert after["total"] == before["total"] == 1
    assert [a["id"] for a in after["analyses"]] == [aid]

    # The saved version itself is untouched.
    assert client.get(f"/api/analyses/{aid}").json()["summary"]["rule_count"] == 3
