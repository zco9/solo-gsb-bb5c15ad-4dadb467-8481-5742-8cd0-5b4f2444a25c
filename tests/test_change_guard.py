"""End-to-end tests for the change-guard endpoint."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-guard-")
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


def _guard(client: TestClient, base_id: str, target_id: str, authorizations: list[dict]):
    return client.post(
        f"/api/analyses/{base_id}/change-guard/{target_id}",
        json={"authorizations": authorizations},
    )


def _flip_pair(client: TestClient) -> tuple[str, str]:
    """base: permit /16 ; target: deny /16 -> one permit_to_deny change."""
    base_id = _save(client, [{"cidr": "10.1.0.0/16", "action": "permit"}], name="v1")
    target_id = _save(client, [{"cidr": "10.1.0.0/16", "action": "deny"}], name="v2")
    return base_id, target_id


# ---------------------------------------------------------------------------
def test_fully_authorized_change_passes(client: TestClient) -> None:
    base_id, target_id = _flip_pair(client)
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny"},
    ])
    assert r.status_code == 200, r.text
    payload = r.json()

    assert payload["passed"] is True
    assert payload["violations"] == []
    assert payload["base"]["id"] == base_id
    assert payload["target"]["id"] == target_id

    summary = payload["summary"]
    assert summary["total_changed_addresses"] == 2 ** 16
    assert summary["total_authorized_addresses"] == 2 ** 16
    assert summary["total_unauthorized_addresses"] == 0
    assert summary["total_violation_groups"] == 0
    assert summary["authorization_entries"] == 1
    assert summary["ipv4"]["changed_addresses"] == 2 ** 16
    assert summary["ipv4"]["unauthorized_addresses"] == 0
    assert summary["ipv6"]["changed_addresses"] == 0
    # All six transitions are reported per family, even when zero.
    assert set(summary["ipv4"]["by_type"]) == {
        "permit_to_deny", "permit_to_none", "deny_to_permit",
        "deny_to_none", "none_to_permit", "none_to_deny",
    }


def test_no_grant_is_a_full_violation(client: TestClient) -> None:
    base_id, target_id = _flip_pair(client)
    r = _guard(client, base_id, target_id, [
        # A grant of a different transition does not authorize anything.
        {"cidr": "10.1.0.0/16", "from_action": "deny", "to_action": "permit"},
    ])
    assert r.status_code == 200, r.text
    payload = r.json()

    assert payload["passed"] is False
    assert len(payload["violations"]) == 1
    violation = payload["violations"][0]
    assert violation["ip_version"] == 4
    assert violation["change_type"] == "permit_to_deny"
    assert violation["from_action"] == "permit"
    assert violation["to_action"] == "deny"
    assert violation["unauthorized_cidrs"] == ["10.1.0.0/16"]
    assert violation["unauthorized_address_count"] == 2 ** 16
    assert violation["unauthorized_range_count"] == 1
    assert payload["summary"]["total_unauthorized_addresses"] == 2 ** 16
    assert payload["summary"]["total_authorized_addresses"] == 0
    assert payload["summary"]["ipv4"]["by_type"]["permit_to_deny"] == 2 ** 16


def test_wrong_ip_family_does_not_authorize(client: TestClient) -> None:
    base_id, target_id = _flip_pair(client)
    r = _guard(client, base_id, target_id, [
        {"cidr": "2001:db8::/32", "from_action": "permit", "to_action": "deny"},
    ])
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["passed"] is False
    assert payload["violations"][0]["unauthorized_cidrs"] == ["10.1.0.0/16"]
    assert payload["summary"]["ipv6"]["unauthorized_addresses"] == 0


def test_partial_grant_carves_minimal_unauthorized_cidrs(client: TestClient) -> None:
    base_id, target_id = _flip_pair(client)
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/24", "from_action": "permit", "to_action": "deny"},
    ])
    assert r.status_code == 200, r.text
    payload = r.json()

    assert payload["passed"] is False
    violation = payload["violations"][0]
    # /16 minus the granted /24, as minimal CIDRs (sorted, collapsed).
    assert violation["unauthorized_cidrs"] == [
        "10.1.1.0/24", "10.1.2.0/23", "10.1.4.0/22", "10.1.8.0/21",
        "10.1.16.0/20", "10.1.32.0/19", "10.1.64.0/18", "10.1.128.0/17",
    ]
    assert violation["unauthorized_address_count"] == 2 ** 16 - 2 ** 8
    assert violation["unauthorized_range_count"] == 8
    summary = payload["summary"]
    assert summary["total_authorized_addresses"] == 2 ** 8
    assert summary["total_unauthorized_addresses"] == 2 ** 16 - 2 ** 8


def test_nested_and_duplicate_same_transition_grants_are_unioned(client: TestClient) -> None:
    base_id, target_id = _flip_pair(client)
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/24", "from_action": "permit", "to_action": "deny"},
        {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny"},  # nests the /24
        {"cidr": "10.1.0.0/24", "from_action": "permit", "to_action": "deny"},  # exact duplicate
    ])
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["passed"] is True
    assert payload["summary"]["total_unauthorized_addresses"] == 0


def test_adjacent_sibling_grants_merge_into_union(client: TestClient) -> None:
    base_id = _save(client, [{"cidr": "10.1.0.0/23", "action": "permit"}])
    target_id = _save(client, [{"cidr": "10.1.0.0/23", "action": "deny"}])
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/24", "from_action": "permit", "to_action": "deny"},
        {"cidr": "10.1.1.0/24", "from_action": "permit", "to_action": "deny"},
    ])
    assert r.status_code == 200, r.text
    assert r.json()["passed"] is True


def test_overlapping_different_transitions_are_rejected(client: TestClient) -> None:
    base_id, target_id = _flip_pair(client)

    # Nested CIDRs, different transitions -> 400.
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny"},
        {"cidr": "10.1.0.0/24", "from_action": "none", "to_action": "permit"},
    ])
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_change_guard"
    assert len(body["issues"]) == 1
    assert "10.1.0.0/16" in body["issues"][0]
    assert "10.1.0.0/24" in body["issues"][0]

    # Identical CIDR, different transitions -> also an overlap -> 400.
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny"},
        {"cidr": "10.1.0.0/16", "from_action": "deny", "to_action": "permit"},
    ])
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_change_guard"

    # Same CIDR, same transition (exact duplicate) -> fine.
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny"},
        {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny"},
    ])
    assert r.status_code == 200
    assert r.json()["passed"] is True

    # Disjoint CIDRs, different transitions -> fine.
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny"},
        {"cidr": "192.0.2.0/24", "from_action": "none", "to_action": "permit"},
    ])
    assert r.status_code == 200


def test_multiple_transitions_are_authorized_independently(client: TestClient) -> None:
    # base: permit /8 ; target: deny /16 with a permit /24 hole inside.
    base_id = _save(client, [{"cidr": "10.0.0.0/8", "action": "permit"}], name="v1")
    target_id = _save(client, [
        {"cidr": "10.1.0.0/16", "action": "deny"},
        {"cidr": "10.1.1.0/24", "action": "permit"},
    ], name="v2")

    # Grant only the permit->deny transition; permit->none stays unauthorized.
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny"},
    ])
    assert r.status_code == 200, r.text
    payload = r.json()

    assert payload["passed"] is False
    assert len(payload["violations"]) == 1
    violation = payload["violations"][0]
    assert violation["change_type"] == "permit_to_none"
    # /8 minus the /16, as minimal CIDRs.
    assert violation["unauthorized_cidrs"] == [
        "10.0.0.0/16", "10.2.0.0/15", "10.4.0.0/14", "10.8.0.0/13",
        "10.16.0.0/12", "10.32.0.0/11", "10.64.0.0/10", "10.128.0.0/9",
    ]
    assert violation["unauthorized_address_count"] == 2 ** 24 - 2 ** 16

    summary = payload["summary"]
    # The granted /16 covers the whole permit->deny surface (65536 - 256).
    assert summary["total_authorized_addresses"] == 2 ** 16 - 2 ** 8
    assert summary["total_unauthorized_addresses"] == 2 ** 24 - 2 ** 16
    assert summary["total_changed_addresses"] == 2 ** 24 - 2 ** 8
    assert summary["ipv4"]["by_type"]["permit_to_deny"] == 0
    assert summary["ipv4"]["by_type"]["permit_to_none"] == 2 ** 24 - 2 ** 16


def test_none_transitions_require_none_grants(client: TestClient) -> None:
    # base: permit 10.1.0.0/16 ; target: a disjoint deny rule, so the /16
    # surface becomes none and a new none->deny surface appears.
    base_id = _save(client, [{"cidr": "10.1.0.0/16", "action": "permit"}])
    target_id = _save(client, [{"cidr": "192.0.2.0/24", "action": "deny"}])

    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "none"},
        {"cidr": "192.0.2.0/24", "from_action": "none", "to_action": "deny"},
    ])
    assert r.status_code == 200, r.text
    assert r.json()["passed"] is True

    # Dropping the none->deny grant surfaces exactly that violation.
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "none"},
    ])
    payload = r.json()
    assert payload["passed"] is False
    assert len(payload["violations"]) == 1
    violation = payload["violations"][0]
    assert violation["change_type"] == "none_to_deny"
    assert violation["from_action"] is None
    assert violation["to_action"] == "deny"
    assert violation["unauthorized_cidrs"] == ["192.0.2.0/24"]
    assert violation["unauthorized_address_count"] == 2 ** 8


def test_authorized_region_without_change_is_not_a_violation(client: TestClient) -> None:
    # Semantically equal versions: nothing changes, so any grant is unused.
    base_id = _save(client, [
        {"cidr": "10.0.0.0/8", "action": "permit"},
        {"cidr": "10.1.0.0/16", "action": "permit"},
    ])
    target_id = _save(client, [{"cidr": "10.0.0.0/8", "action": "permit"}])

    r = _guard(client, base_id, target_id, [
        {"cidr": "10.0.0.0/8", "from_action": "none", "to_action": "permit"},
    ])
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["passed"] is True
    assert payload["violations"] == []
    assert payload["summary"]["total_changed_addresses"] == 0
    assert payload["summary"]["total_unauthorized_addresses"] == 0


def test_ipv6_guard_counts_are_exact(client: TestClient) -> None:
    base_id = _save(client, [{"cidr": "2001:db8::/32", "action": "deny"}])
    target_id = _save(client, [{"cidr": "2001:db8::/32", "action": "permit"}])

    # Grant only the lower half; the upper /33 remains unauthorized.
    r = _guard(client, base_id, target_id, [
        {"cidr": "2001:db8::/33", "from_action": "deny", "to_action": "permit"},
    ])
    assert r.status_code == 200, r.text
    payload = r.json()

    assert payload["passed"] is False
    violation = payload["violations"][0]
    assert violation["ip_version"] == 6
    assert violation["change_type"] == "deny_to_permit"
    assert violation["unauthorized_cidrs"] == ["2001:db8:8000::/33"]
    # 2**95 addresses — exact big integer, computed geometrically.
    assert violation["unauthorized_address_count"] == 2 ** 95
    assert isinstance(violation["unauthorized_address_count"], int)
    assert payload["summary"]["ipv6"]["unauthorized_addresses"] == 2 ** 95
    assert payload["summary"]["total_authorized_addresses"] == 2 ** 95

    # Granting the whole /32 passes.
    r = _guard(client, base_id, target_id, [
        {"cidr": "2001:db8::/32", "from_action": "deny", "to_action": "permit"},
    ])
    assert r.status_code == 200, r.text
    assert r.json()["passed"] is True


def test_change_guard_error_codes(client: TestClient) -> None:
    base_id, target_id = _flip_pair(client)
    grant = [{"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny"}]

    # Malformed ids -> 400 (checked before the authorization set).
    r = _guard(client, "not-an-id", target_id, [{"cidr": "nonsense", "from_action": "permit", "to_action": "deny"}])
    assert r.status_code == 400
    assert "invalid analysis id format" in r.json()["detail"]

    # Same id -> 400 even though it exists.
    r = _guard(client, base_id, base_id, grant)
    assert r.status_code == 400
    assert "must differ" in r.json()["detail"]

    # Well-formed but missing -> 404 (either side).
    r = _guard(client, base_id, "an_0000000000000000", grant)
    assert r.status_code == 404
    r = _guard(client, "an_0000000000000000", target_id, grant)
    assert r.status_code == 404

    # Invalid authorization CIDRs -> 400 invalid_change_guard, all issues listed.
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.0.0.5/24", "from_action": "permit", "to_action": "deny"},  # host bits
        {"cidr": "10.0.0.0", "from_action": "permit", "to_action": "deny"},     # no prefix length
    ])
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_change_guard"
    assert len(body["issues"]) == 2
    assert "authorization #1" in body["issues"][0]
    assert "authorization #2" in body["issues"][1]

    # Entry validation happens before version existence: bad entries win over 404.
    r = _guard(client, base_id, "an_0000000000000000", [
        {"cidr": "10.0.0.5/24", "from_action": "permit", "to_action": "deny"},
    ])
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_change_guard"


def test_change_guard_schema_validation(client: TestClient) -> None:
    base_id, target_id = _flip_pair(client)

    # from_action == to_action -> 422.
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "permit"},
    ])
    assert r.status_code == 422

    # Unknown action -> 422.
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/16", "from_action": "allow", "to_action": "deny"},
    ])
    assert r.status_code == 422

    # Empty authorization list -> 422.
    r = _guard(client, base_id, target_id, [])
    assert r.status_code == 422

    # Extra field -> 422.
    r = client.post(
        f"/api/analyses/{base_id}/change-guard/{target_id}",
        json={"authorizations": [
            {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny", "note": "x"},
        ]},
    )
    assert r.status_code == 422

    # Missing body -> 422.
    r = client.post(f"/api/analyses/{base_id}/change-guard/{target_id}")
    assert r.status_code == 422


def test_action_values_are_case_insensitive(client: TestClient) -> None:
    base_id, target_id = _flip_pair(client)
    r = _guard(client, base_id, target_id, [
        {"cidr": "10.1.0.0/16", "from_action": "Permit", "to_action": "DENY"},
    ])
    assert r.status_code == 200, r.text
    assert r.json()["passed"] is True
