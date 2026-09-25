"""End-to-end tests against the FastAPI app with a temp SQLite database."""

from __future__ import annotations

import os
import tempfile
import threading

import pytest
from fastapi.testclient import TestClient

from app import db
from app.analyzer import analyze_rules


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-")
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


# ---------------------------------------------------------------------------
def test_root_and_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert client.get("/").status_code == 200


def test_full_scenario_conflicts_and_shadowing(client: TestClient) -> None:
    body = {
        "name": "scenario-1",
        "rules": [
            {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100, "source_tag": "core"},
            {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200, "source_tag": "edge"},
            {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit", "priority": 50, "source_tag": "edge"},
            {"rule_id": "d", "cidr": "10.1.0.0/16", "action": "deny", "priority": 300, "source_tag": "dup"},
        ],
    }
    r = client.post("/api/analyze", json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["persisted"] is True
    by_id = {rule["rule_id"]: rule for rule in data["rules"]}

    # a: /8 minus b's /16 (d is only a same-CIDR duplicate of b, not a separate child)
    a = by_id["a"]
    assert a["status"] == "partial"
    assert a["covered"] == 2 ** 24 - 2 ** 16

    # b deny vs a permit: effective except c's /24 -> partial, conflict
    b = by_id["b"]
    assert b["status"] == "partial"
    assert b["covered"] == 2 ** 16 - 2 ** 8
    assert b["has_conflict"] is True

    # c wins its own /24, conflicts with b
    c = by_id["c"]
    assert c["status"] == "active"
    assert c["effective_cidrs"] == ["10.1.1.0/24"]

    # d is an exact-prefix duplicate of b and same action -> shadowed, no conflict
    d = by_id["d"]
    assert d["role"] == "duplicate"
    assert d["status"] == "shadowed"
    assert d["covered"] == 0
    assert d["has_conflict"] is False

    # Minimal pairs: (b,a) and (c,b); transitive (c,a) is suppressed.
    pairs = {(p["rule_id"], p["other_rule_id"]) for p in data["minimal_conflict_pairs"]}
    assert pairs == {("b", "a"), ("c", "b")}
    ba = next(p for p in data["minimal_conflict_pairs"] if p["rule_id"] == "b")
    assert ba["winner_rule_id"] == "b"
    assert ba["kind"] == "cover"

    # Priority inversion: b (priority 200) overrides a (priority 100) by prefix length.
    inversions = [f for f in data["findings"] if f.get("priority_inversion")]
    assert {(f["rule_id"], f["other_rule_id"]) for f in inversions} == {("b", "a")}

    summary = data["summary"]
    assert summary["rule_count"] == 4
    assert summary["partial_rules"] == 2
    assert summary["shadowed_rules"] == 1
    assert summary["behavioral_conflicts"] == 2


def test_fully_shadowed_warning(client: TestClient) -> None:
    body = {
        "rules": [
            {"cidr": "192.168.0.0/24", "action": "permit"},
            {"cidr": "192.168.0.0/25", "action": "deny"},
            {"cidr": "192.168.0.128/25", "action": "deny"},
        ]
    }
    r = client.post("/api/analyze", json=body)
    assert r.status_code == 200
    data = r.json()
    root = next(rule for rule in data["rules"] if rule["cidr"] == "192.168.0.0/24")
    assert root["status"] == "shadowed"
    assert root["covered"] == 0
    assert any(f["type"] == "fully_shadow" and f["severity"] == "warning" for f in data["findings"])
    # Both halves agree with... root permit vs deny children -> two conflict pairs,
    # even though the parent itself covers nothing, the children are behavioural.
    assert len(data["minimal_conflict_pairs"]) == 2


def test_shadowed_child_same_action_produces_no_conflict_pair(client: TestClient) -> None:
    # r2 (deny /16) is fully shadowed by two deny /17s.  No conflict exists
    # *inside* the /16, but the /16 as a whole still denies against the
    # permit /8: the same-action run (r3/r4 -> r2) is jumped over and each
    # effective leaf pairs with r1; the fully shadowed r2 generates no pair.
    body = {
        "rules": [
            {"cidr": "10.0.0.0/8", "action": "permit", "priority": 100},
            {"cidr": "10.0.0.0/16", "action": "deny", "priority": 100},
            {"cidr": "10.0.0.0/17", "action": "deny", "priority": 100},
            {"cidr": "10.0.128.0/17", "action": "deny", "priority": 100},
        ]
    }
    data = client.post("/api/analyze", json=body).json()
    pairs = {(p["rule_id"], p["other_rule_id"]) for p in data["minimal_conflict_pairs"]}
    assert pairs == {("r3", "r1"), ("r4", "r1")}
    # Override ranges of the two leaves partition the whole /16.
    ranges = sorted(
        cidr for p in data["minimal_conflict_pairs"] for cidr in p["override_range"]
    )
    assert ranges == ["10.0.0.0/17", "10.0.128.0/17"]

    # The direct boundary edge r2 -> r1 is flagged behavioural even though r2
    # itself covers nothing; inner same-action edges are not.
    by_edge = {(f["rule_id"], f["other_rule_id"]): f for f in data["findings"] if f["type"] == "cover"}
    assert by_edge[("r2", "r1")]["behavioral"] is True
    assert by_edge[("r3", "r2")]["behavioral"] is False
    assert by_edge[("r4", "r2")]["behavioral"] is False

    # No same-action pair is ever reported.
    assert not any(p["action"] == p["other_action"] for p in data["minimal_conflict_pairs"])


def test_duplicate_cidr_action_conflict_pair(client: TestClient) -> None:
    body = {
        "rules": [
            {"cidr": "172.16.0.0/12", "action": "permit", "priority": 10},
            {"cidr": "172.16.0.0/12", "action": "deny", "priority": 20},
        ]
    }
    data = client.post("/api/analyze", json=body).json()
    assert len(data["minimal_conflict_pairs"]) == 1
    pair = data["minimal_conflict_pairs"][0]
    assert pair["kind"] == "duplicate"
    assert pair["rule_id"] == "r2"
    assert pair["winner_rule_id"] == "r1"
    assert pair["override_range"] == ["172.16.0.0/12"]


def test_ipv6_is_handled_independently(client: TestClient) -> None:
    body = {
        "rules": [
            {"cidr": "2001:db8::/32", "action": "deny"},
            {"cidr": "2001:db8:1::/48", "action": "permit"},
            {"cidr": "::1/128", "action": "permit"},
        ]
    }
    data = client.post("/api/analyze", json=body).json()
    assert data["summary"]["ipv6_rules"] == 3
    by_id = {r["rule_id"]: r for r in data["rules"]}
    assert by_id["r1"]["status"] == "partial"
    assert by_id["r2"]["status"] == "active"
    assert by_id["r3"]["status"] == "active"
    assert len(data["minimal_conflict_pairs"]) == 1


def test_invalid_inputs_return_400(client: TestClient) -> None:
    # Host bits set
    r = client.post("/api/analyze", json={"rules": [{"cidr": "10.0.0.5/24", "action": "permit"}]})
    assert r.status_code == 400
    assert "invalid CIDR" in r.json()["detail"]

    # Duplicate rule_id
    r = client.post(
        "/api/analyze",
        json={
            "rules": [
                {"rule_id": "x", "cidr": "10.0.0.0/24", "action": "permit"},
                {"rule_id": "x", "cidr": "10.1.0.0/24", "action": "permit"},
            ]
        },
    )
    assert r.status_code == 400
    assert "duplicate rule_id" in r.json()["detail"]

    # Empty rule list
    r = client.post("/api/analyze", json={"rules": []})
    assert r.status_code == 422

    # Bad action -> schema error
    r = client.post("/api/analyze", json={"rules": [{"cidr": "10.0.0.0/24", "action": "maybe"}]})
    assert r.status_code == 422


def test_idempotent_submission_and_versions(client: TestClient) -> None:
    body = {"rules": [{"cidr": "10.0.0.0/8", "action": "permit"}]}
    first = client.post("/api/analyze", json=body).json()
    second = client.post("/api/analyze", json=body).json()
    assert first["id"] == second["id"]
    assert first["ruleset_hash"] == second["ruleset_hash"]

    listing = client.get("/api/analyses").json()
    assert listing["total"] == 1

    fetched = client.get(f"/api/analyses/{first['id']}").json()
    assert fetched["ruleset_hash"] == first["ruleset_hash"]

    assert client.get("/api/analyses/does-not-exist").status_code == 404


def test_rules_and_findings_query_filters(client: TestClient) -> None:
    body = {
        "rules": [
            {"cidr": "10.0.0.0/8", "action": "permit"},
            {"cidr": "10.1.0.0/16", "action": "deny"},
            {"cidr": "2001:db8::/32", "action": "permit"},
        ]
    }
    aid = client.post("/api/analyze", json=body).json()["id"]

    partial = client.get(f"/api/analyses/{aid}/rules", params={"status": "partial"}).json()
    assert {r["rule_id"] for r in partial["rules"]} == {"r1"}

    deny = client.get(f"/api/analyses/{aid}/rules", params={"action": "deny"}).json()
    assert {r["rule_id"] for r in deny["rules"]} == {"r2"}

    v6 = client.get(f"/api/analyses/{aid}/rules", params={"ip": 6}).json()
    assert {r["rule_id"] for r in v6["rules"]} == {"r3"}

    conflicts = client.get(f"/api/analyses/{aid}/findings", params={"severity": "conflict"}).json()
    assert conflicts["count"] >= 1

    behavioral = client.get(f"/api/analyses/{aid}/findings", params={"behavioral_only": True}).json()
    assert all(f["behavioral"] for f in behavioral["findings"])


def test_export_json(client: TestClient) -> None:
    aid = client.post(
        "/api/analyze", json={"rules": [{"cidr": "10.0.0.0/8", "action": "permit"}]}
    ).json()["id"]
    r = client.get(f"/api/analyses/{aid}/export.json")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/json"
    assert f'attachment; filename="{aid}.json"' in r.headers["content-disposition"]
    payload = r.json()
    assert payload["id"] == aid
    assert "minimal_conflict_pairs" in payload


def test_save_false_is_not_persisted(client: TestClient) -> None:
    r = client.post(
        "/api/analyze",
        json={"rules": [{"cidr": "10.0.0.0/8", "action": "permit"}], "save": False},
    )
    assert r.json()["persisted"] is False
    assert client.get("/api/analyses").json()["total"] == 0


def test_duplicate_submit_keeps_first_version_metadata(client: TestClient) -> None:
    # A resubmit with a *different* name reuses the stored version: its name
    # and created_at come from the first save and match GET / list responses.
    body = {"name": "first-name", "rules": [{"cidr": "10.0.0.0/8", "action": "permit"}]}
    first = client.post("/api/analyze", json=body).json()
    second = client.post("/api/analyze", json={**body, "name": "later-name"}).json()

    assert second["id"] == first["id"]
    assert second["name"] == "first-name"
    assert second["created_at"] == first["created_at"]
    assert second["persisted"] is True

    assert client.get("/api/analyses").json()["total"] == 1

    fetched = client.get(f"/api/analyses/{first['id']}").json()
    assert fetched["name"] == "first-name"
    assert fetched["created_at"] == first["created_at"]

    listing = client.get("/api/analyses").json()["analyses"][0]
    assert listing["name"] == "first-name"
    assert listing["created_at"] == first["created_at"]


def test_concurrent_identical_saves_share_one_version(client: TestClient) -> None:
    # N racing requests with the same ruleset must all succeed, share one id,
    # and leave exactly one stored version with one set of rules/findings.
    body = {"rules": [{"cidr": "10.0.0.0/8", "action": "permit"}]}
    n = 12
    barrier = threading.Barrier(n)
    responses: list[dict] = []
    errors: list[Exception] = []

    def submit() -> None:
        try:
            barrier.wait()
            r = client.post("/api/analyze", json=body)
            assert r.status_code == 200, r.text
            responses.append(r.json())
        except Exception as exc:  # pragma: no defensive - surfaced by assertions
            errors.append(exc)

    threads = [threading.Thread(target=submit) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(responses) == n
    assert len({r["id"] for r in responses}) == 1
    assert all(r["persisted"] is True for r in responses)

    listing = client.get("/api/analyses").json()
    assert listing["total"] == 1
    aid = listing["analyses"][0]["id"]
    with db._connect() as conn:  # type: ignore[attr-defined]
        assert conn.execute("SELECT COUNT(*) AS c FROM analyses").fetchone()["c"] == 1
        assert conn.execute("SELECT COUNT(*) AS c FROM rules").fetchone()["c"] == 1
        assert conn.execute("SELECT COUNT(*) AS c FROM findings").fetchone()["c"] == 0


def test_concurrent_save_analysis_calls_are_atomic() -> None:
    # Direct persistence-layer race: concurrent saves of the same ruleset hash
    # reuse one stored row even when each caller passes a different name.
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-")
    os.close(fd)
    os.remove(path)
    db.reset_db(path)
    try:
        result = analyze_rules([{"cidr": "10.0.0.0/8", "action": "permit"}])
        analysis_id = "an_" + result["ruleset_hash"][:16]
        n = 8
        barrier = threading.Barrier(n)
        outcomes: list[dict] = []
        errors: list[Exception] = []

        def save(slot: int) -> None:
            try:
                barrier.wait()
                outcomes.append(
                    db.save_analysis(analysis_id, f"name-{slot}", result)
                )
            except Exception as exc:  # pragma: no defensive
                errors.append(exc)

        threads = [threading.Thread(target=save, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len({o["id"] for o in outcomes}) == 1
        assert len({o["name"] for o in outcomes}) == 1
        assert sum(1 for o in outcomes if not o["reused"]) == 1
        assert len({o["created_at"] for o in outcomes}) == 1
        with db._connect() as conn:  # type: ignore[attr-defined]
            assert conn.execute("SELECT COUNT(*) AS c FROM analyses").fetchone()["c"] == 1
            assert conn.execute("SELECT COUNT(*) AS c FROM rules").fetchone()["c"] == 1
    finally:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(path + suffix)
            except OSError:
                pass


def test_save_false_name_is_reflected_without_persisting(client: TestClient) -> None:
    r = client.post(
        "/api/analyze",
        json={
            "name": "draft-only",
            "rules": [{"cidr": "10.0.0.0/8", "action": "permit"}],
            "save": False,
        },
    )
    data = r.json()
    assert data["name"] == "draft-only"
    assert data["persisted"] is False
    assert client.get("/api/analyses").json()["total"] == 0
