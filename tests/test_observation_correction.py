"""End-to-end tests for POST /api/analyses/{id}/observation-correction."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-oc-")
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


def _correct(
    client: TestClient, aid: str, observations: list[dict], candidates: list[str]
) -> dict:
    r = client.post(
        f"/api/analyses/{aid}/observation-correction",
        json={"observations": observations, "candidate_rule_ids": candidates},
    )
    assert r.status_code == 200, r.text
    return r.json()


# permit /8 -> deny /16 -> permit /24 (LPM decides; submission order does not).
NESTED_RULES = [
    {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100, "source_tag": "core"},
    {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200, "source_tag": "edge"},
    {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit", "priority": 50, "source_tag": "lab"},
]


# ---------------------------------------------------------------------------
# Plan search
# ---------------------------------------------------------------------------
def test_flip_winner_to_meet_expected_action(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES, name="nested")

    payload = _correct(
        client,
        aid,
        [{"ip": "10.1.1.7", "action": "deny"}],
        ["c", "b"],
    )

    assert payload["solvable"] is True
    plan = payload["plan"]
    assert plan["operations"] == [
        {"rule_id": "c", "operation": "flip", "from_action": "permit", "to_action": "deny"}
    ]
    assert plan["changed_rule_count"] == 1
    assert plan["flipped_count"] == 1
    assert plan["disabled_count"] == 0
    assert plan["kept_count"] == 1

    obs = payload["observations"][0]
    assert obs["seq"] == 0
    assert obs["ip"] == "10.1.1.7"
    assert obs["expected_action"] == "deny"
    assert obs["matched_rule_id"] == "c"
    assert obs["action"] == "deny"
    assert obs["satisfied"] is True


def test_already_aligned_observations_return_empty_plan(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    payload = _correct(
        client,
        aid,
        [
            {"ip": "10.1.1.7", "action": "permit"},  # c
            {"ip": "10.1.2.9", "action": "deny"},    # b
            {"ip": "10.2.3.4", "action": "permit"},  # a
        ],
        ["a", "b", "c"],
    )

    assert payload["solvable"] is True
    assert payload["plan"] == {
        "operations": [],
        "changed_rule_count": 0,
        "disabled_count": 0,
        "flipped_count": 0,
        "kept_count": 3,
    }
    assert [o["satisfied"] for o in payload["observations"]] == [True, True, True]
    assert [o["matched_rule_id"] for o in payload["observations"]] == ["c", "b", "a"]


def test_minimum_changed_rules_one_flip_fixes_two_observations(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    payload = _correct(
        client,
        aid,
        [
            {"ip": "10.1.1.7", "action": "deny"},
            {"ip": "10.1.1.9", "action": "deny"},
        ],
        ["a", "b", "c"],
    )

    # Both observations are decided by the same /24 winner c: one flip fixes both.
    assert payload["plan"]["changed_rule_count"] == 1
    assert payload["plan"]["operations"] == [
        {"rule_id": "c", "operation": "flip", "from_action": "permit", "to_action": "deny"}
    ]
    assert [o["matched_rule_id"] for o in payload["observations"]] == ["c", "c"]
    assert all(o["action"] == "deny" for o in payload["observations"])


def test_flip_of_ancestor_leaves_longer_prefix_decision_intact(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    # o1 is already permit via c (/24); o2 under a (/8) wants deny. Flipping a
    # must not change the /24 verdict (LPM keeps c in charge).
    payload = _correct(
        client,
        aid,
        [
            {"ip": "10.1.1.7", "action": "permit"},
            {"ip": "10.2.3.4", "action": "deny"},
        ],
        ["a", "b", "c"],
    )

    assert [op["rule_id"] for op in payload["plan"]["operations"]] == ["a"]
    assert payload["plan"]["operations"][0]["operation"] == "flip"
    assert [o["matched_rule_id"] for o in payload["observations"]] == ["c", "a"]
    assert [o["action"] for o in payload["observations"]] == ["permit", "deny"]


def test_uncovered_observation_can_never_become_permit(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    # 192.0.2.9 has no covering rule; keep/disable/flip only ever *remove*
    # coverage, so no combination can make it hit anything.
    payload = _correct(
        client,
        aid,
        [{"ip": "192.0.2.9", "action": "permit"}],
        ["a", "b", "c"],
    )
    assert payload["solvable"] is False
    assert payload["plan"] is None
    assert payload["observations"] is None

    # Expecting deny on an uncovered address cannot be satisfied either:
    # a miss is not an implicit deny.
    payload = _correct(
        client,
        aid,
        [{"ip": "192.0.2.9", "action": "deny"}],
        ["a", "b", "c"],
    )
    assert payload["solvable"] is False
    assert payload["plan"] is None


def test_mismatch_on_non_candidate_winner_is_unsolvable(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    # 10.1.2.9 is decided by b, which is not among the candidates; candidate
    # ancestors cannot reach the address while b stays in the ruleset.
    payload = _correct(
        client,
        aid,
        [{"ip": "10.1.2.9", "action": "permit"}],
        ["a", "c"],
    )
    assert payload["solvable"] is False
    assert payload["plan"] is None


def test_conflicting_demands_under_one_winner_are_unsolvable(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    # Both addresses are decided by c (permit). One wants deny, one permit:
    # flipping c satisfies one and breaks the other; disabling c falls back to
    # b (deny), which also cannot satisfy the permit demand.
    payload = _correct(
        client,
        aid,
        [
            {"ip": "10.1.1.7", "action": "deny"},
            {"ip": "10.1.1.8", "action": "permit"},
        ],
        ["a", "b", "c"],
    )
    assert payload["solvable"] is False
    assert payload["plan"] is None


def test_same_cidr_tie_flip_prefers_fewer_disables_over_disabling_winner(
    client: TestClient,
) -> None:
    # Two rules on one CIDR: smaller priority "lo" (deny) wins; "hi" (permit)
    # is the losing duplicate. The observation wants permit.
    aid = _save(
        client,
        [
            {"rule_id": "hi", "cidr": "10.0.0.0/24", "action": "permit", "priority": 200},
            {"rule_id": "lo", "cidr": "10.0.0.0/24", "action": "deny", "priority": 100},
        ],
    )

    # Two one-change solutions exist: flip "lo" (it stays winner, now permit)
    # or disable "lo" (duplicate "hi" takes over). Both change one rule; the
    # fewest-disables tie-break selects the flip.
    payload = _correct(
        client,
        aid,
        [{"ip": "10.0.0.7", "action": "permit"}],
        ["hi", "lo"],
    )

    assert payload["plan"]["changed_rule_count"] == 1
    assert payload["plan"]["disabled_count"] == 0
    assert payload["plan"]["operations"] == [
        {"rule_id": "lo", "operation": "flip", "from_action": "deny", "to_action": "permit"}
    ]
    obs = payload["observations"][0]
    assert obs["matched_rule_id"] == "lo"
    assert obs["action"] == "permit"


def test_disabling_winner_exposes_same_cidr_duplicate_is_enumerated(
    client: TestClient,
) -> None:
    # Flip is impossible because the winner itself is not a candidate; when
    # the winner cannot be touched at all the demand must be unsolvable
    # (disable only applies to candidates), proving keeps/disables are honored.
    aid = _save(
        client,
        [
            {"rule_id": "hi", "cidr": "10.0.0.0/24", "action": "permit", "priority": 200},
            {"rule_id": "lo", "cidr": "10.0.0.0/24", "action": "deny", "priority": 100},
        ],
    )
    # Only the losing duplicate is offered: nothing can unseat "lo".
    payload = _correct(
        client, aid, [{"ip": "10.0.0.7", "action": "permit"}], ["hi"]
    )
    assert payload["solvable"] is False


def test_flip_beats_disable_on_fewer_disables_tie_break(client: TestClient) -> None:
    # 10.1.2.9 is decided by b (deny /16, ancestor a is permit /8). Demanding
    # permit admits two one-change plans: flip b (it stays the winner, now
    # permit) and disable b (a takes over). Same changed-rule count; the
    # fewest-disables rule picks the flip.
    aid = _save(client, NESTED_RULES)
    payload = _correct(
        client, aid, [{"ip": "10.1.2.9", "action": "permit"}], ["a", "b"]
    )
    assert payload["plan"]["changed_rule_count"] == 1
    assert payload["plan"]["disabled_count"] == 0
    assert payload["plan"]["operations"] == [
        {"rule_id": "b", "operation": "flip", "from_action": "deny", "to_action": "permit"}
    ]
    assert payload["observations"][0]["matched_rule_id"] == "b"
    assert payload["observations"][0]["action"] == "permit"


def test_disabled_winner_falls_back_to_ancestor_in_recomputed_verdict() -> None:
    # Unit-level: with binary actions a disable can never beat the equivalent
    # flip in the optimum, but the enumeration must still recompute verdicts
    # correctly when rules are disabled (the LPM winner drops out and the
    # ancestor chain decides). Exercise the covering/winner helpers directly.
    from app.observation_correction import (
        _covering_groups,
        _load_rules,
        _winner,
    )
    from app.simulate import rebuild_input_rules
    from app.analyzer import analyze_rules

    raw = [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100,
         "source_tag": "t"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200,
         "source_tag": "t"},
        {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit", "priority": 50,
         "source_tag": "t"},
    ]
    saved = analyze_rules(raw)
    saved["id"] = "an_0000000000000000"
    rules = _load_rules(rebuild_input_rules(saved))
    import ipaddress

    addr = ipaddress.ip_address("10.1.2.9")
    groups = _covering_groups(addr, rules)

    # Baseline: b (deny /16) wins.
    assert _winner(groups, frozenset(), frozenset()) == ("b", "deny")
    # Disabling b lets the permit /8 ancestor a take over.
    assert _winner(groups, frozenset({"b"}), frozenset()) == ("a", "permit")
    # Disabling everything covering the address is a miss (None), not permit.
    assert _winner(groups, frozenset({"a", "b", "c"}), frozenset()) == (None, None)
    # Flipping b keeps it as winner with inverted action.
    assert _winner(groups, frozenset(), frozenset({"b"})) == ("b", "permit")


def test_ipv6_observations(client: TestClient) -> None:
    aid = _save(
        client,
        [
            {"rule_id": "v6", "cidr": "2001:db8::/32", "action": "deny", "priority": 100},
            {"rule_id": "v6h", "cidr": "2001:db8:1::/48", "action": "permit", "priority": 900},
        ],
    )

    # /48 currently permit; demand deny -> flip v6h. The /32-only address
    # already agrees (deny) and must stay on v6.
    payload = _correct(
        client,
        aid,
        [
            {"ip": "2001:db8:1::7", "action": "deny"},
            {"ip": "2001:db8:2::7", "action": "deny"},
        ],
        ["v6", "v6h"],
    )

    assert payload["plan"]["operations"] == [
        {"rule_id": "v6h", "operation": "flip", "from_action": "permit", "to_action": "deny"}
    ]
    assert [o["matched_rule_id"] for o in payload["observations"]] == ["v6h", "v6"]
    assert [o["ip_version"] for o in payload["observations"]] == [6, 6]


def test_action_aliases_are_normalized(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    payload = _correct(
        client, aid, [{"ip": "10.1.1.7", "action": "BLOCK"}], ["c"]
    )
    assert payload["observations"][0]["expected_action"] == "deny"
    assert payload["plan"]["operations"][0]["to_action"] == "deny"


def test_candidate_order_in_response_is_sorted_and_input_order_independent(
    client: TestClient,
) -> None:
    aid = _save(client, NESTED_RULES)
    observations = [{"ip": "10.1.1.7", "action": "deny"}]

    one = _correct(client, aid, observations, ["a", "c", "b"])
    two = _correct(client, aid, observations, ["b", "a", "c"])
    assert one["candidate_rule_ids"] == ["a", "b", "c"]
    assert two["candidate_rule_ids"] == ["a", "b", "c"]
    assert one["plan"] == two["plan"]
    assert one["observations"] == two["observations"]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _post(client: TestClient, aid: str, body: dict):
    return client.post(f"/api/analyses/{aid}/observation-correction", json=body)


def test_invalid_ips_reject_whole_batch_with_all_issues(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    r = _post(
        client,
        aid,
        {
            "observations": [
                {"ip": "10.1.1.7", "action": "permit"},
                {"ip": "10.0.0.5/24", "action": "permit"},
                {"ip": "not-an-ip", "action": "deny"},
            ],
            "candidate_rule_ids": ["a"],
        },
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_observation_correction"
    assert len(body["issues"]) == 2
    assert "observation #2" in body["issues"][0]
    assert "10.0.0.5/24" in body["issues"][0]
    assert "observation #3" in body["issues"][1]
    assert "not-an-ip" in body["issues"][1]


def test_duplicate_and_unknown_candidates_reported_together(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    r = _post(
        client,
        aid,
        {
            "observations": [{"ip": "10.1.1.7", "action": "deny"}],
            "candidate_rule_ids": ["c", "c", "a", "zz"],
        },
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_observation_correction"
    assert len(body["issues"]) == 2
    assert "'c'" in body["issues"][0] and "distinct" in body["issues"][0]
    assert "'zz'" in body["issues"][1] and "does not exist" in body["issues"][1]


def test_invalid_candidates_and_ips_are_all_reported(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    r = _post(
        client,
        aid,
        {
            "observations": [{"ip": "nope", "action": "deny"}],
            "candidate_rule_ids": ["c", "c"],
        },
    )
    assert r.status_code == 400
    assert len(r.json()["issues"]) == 2


def test_field_level_constraints_return_422(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    url = f"/api/analyses/{aid}/observation-correction"

    # Unknown action -> 422.
    assert _post(
        client, aid,
        {"observations": [{"ip": "10.1.1.7", "action": "maybe"}],
         "candidate_rule_ids": ["c"]},
    ).status_code == 422

    # Candidate count bounds: 0 and 9 are rejected; 1..8 accepted.
    assert _post(
        client, aid,
        {"observations": [{"ip": "10.1.1.7", "action": "deny"}], "candidate_rule_ids": []},
    ).status_code == 422
    assert _post(
        client, aid,
        {"observations": [{"ip": "10.1.1.7", "action": "deny"}],
         "candidate_rule_ids": ["a", "b", "c", "d", "e", "f", "g", "h", "i"]},
    ).status_code == 422

    # Observation count bounds: 0 and 21 are rejected.
    assert _post(
        client, aid, {"observations": [], "candidate_rule_ids": ["a"]}
    ).status_code == 422
    assert _post(
        client,
        aid,
        {
            "observations": [{"ip": "10.1.1.7", "action": "deny"}] * 21,
            "candidate_rule_ids": ["a"],
        },
    ).status_code == 422

    # Missing / extra fields, blank candidate id -> 422.
    assert client.post(url, json={"observations": []}).status_code == 422
    assert client.post(url, json={"candidate_rule_ids": ["a"]}).status_code == 422
    assert _post(
        client, aid,
        {"observations": [{"ip": "10.1.1.7", "action": "deny"}],
         "candidate_rule_ids": ["a"], "note": "x"},
    ).status_code == 422
    assert _post(
        client, aid,
        {"observations": [{"ip": "10.1.1.7", "action": "deny", "note": "x"}],
         "candidate_rule_ids": ["a"]},
    ).status_code == 422
    assert _post(
        client, aid,
        {"observations": [{"ip": "10.1.1.7", "action": "deny"}],
         "candidate_rule_ids": ["  "]},
    ).status_code == 422


def test_unknown_analysis_returns_404(client: TestClient) -> None:
    r = _post(
        client,
        "an_0000000000000000",
        {
            "observations": [{"ip": "10.1.1.7", "action": "deny"}],
            "candidate_rule_ids": ["a"],
        },
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Read-only contract
# ---------------------------------------------------------------------------
def test_correction_is_read_only_and_deterministic(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    body = {
        "observations": [
            {"ip": "10.1.1.7", "action": "deny"},
            {"ip": "192.0.2.8", "action": "permit"},
        ],
        "candidate_rule_ids": ["a", "b", "c"],
    }

    before = client.get("/api/analyses").json()
    first = client.post(f"/api/analyses/{aid}/observation-correction", json=body).json()
    second = client.post(f"/api/analyses/{aid}/observation-correction", json=body).json()
    after = client.get("/api/analyses").json()

    # The unsolvable request is deterministic too, and creates nothing.
    assert first == second
    assert first["solvable"] is False
    assert after["total"] == before["total"] == 1
    assert [a["id"] for a in after["analyses"]] == [aid]

    # The saved version itself is untouched.
    saved = client.get(f"/api/analyses/{aid}").json()
    assert saved["summary"]["rule_count"] == 3
    assert [r["action"] for r in saved["rules"] if r["rule_id"] == "c"] == ["permit"]
