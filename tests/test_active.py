"""Tests for the saved-version publication pointer (/api/active)."""

from __future__ import annotations

import os
import tempfile
import threading

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-active-")
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


def _save(client: TestClient, cidr: str, action: str = "permit") -> str:
    r = client.post(
        "/api/analyze",
        json={"rules": [{"cidr": cidr, "action": action}]},
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ---------------------------------------------------------------------------
def test_initial_pointer_state(client: TestClient) -> None:
    r = client.get("/api/active")
    assert r.status_code == 200
    assert r.json() == {"active_id": None, "revision": 0}

    r = client.get("/api/active/history")
    assert r.status_code == 200
    assert r.json() == {"total": 0, "history": []}


def test_activate_publishes_and_bumps_revision(client: TestClient) -> None:
    a = _save(client, "10.0.0.0/8")
    r = client.post("/api/active/activate", json={"analysis_id": a, "expected_revision": 0})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["active"]["active_id"] == a
    assert data["active"]["revision"] == 1
    assert data["active"]["history_seq"] == 1
    assert data["active"]["activated_at"]
    assert data["previous"] == {"active_id": None, "revision": 0}

    assert client.get("/api/active").json() == {"active_id": a, "revision": 1}

    history = client.get("/api/active/history").json()
    assert history["total"] == 1
    entry = history["history"][0]
    assert entry == {
        "seq": 1,
        "revision": 1,
        "previous_id": None,
        "active_id": a,
        "activated_at": data["active"]["activated_at"],
    }


def test_switching_versions_records_before_and_after(client: TestClient) -> None:
    a = _save(client, "10.0.0.0/8")
    b = _save(client, "10.1.0.0/16", action="deny")

    assert client.post(
        "/api/active/activate", json={"analysis_id": a, "expected_revision": 0}
    ).status_code == 200
    r = client.post("/api/active/activate", json={"analysis_id": b, "expected_revision": 1})
    assert r.status_code == 200
    data = r.json()
    assert data["active"]["active_id"] == b
    assert data["active"]["revision"] == 2
    assert data["previous"] == {"active_id": a, "revision": 1}

    history = client.get("/api/active/history").json()["history"]
    assert [(h["revision"], h["previous_id"], h["active_id"]) for h in history] == [
        (2, a, b),
        (1, None, a),
    ]


def test_repointing_same_version_still_bumps_revision(client: TestClient) -> None:
    a = _save(client, "10.0.0.0/8")
    client.post("/api/active/activate", json={"analysis_id": a, "expected_revision": 0})
    r = client.post("/api/active/activate", json={"analysis_id": a, "expected_revision": 1})
    assert r.status_code == 200
    assert r.json()["active"]["revision"] == 2
    assert r.json()["previous"]["active_id"] == a

    assert client.get("/api/active/history").json()["total"] == 2


def test_stale_expected_revision_returns_409_with_current_state(client: TestClient) -> None:
    a = _save(client, "10.0.0.0/8")
    b = _save(client, "10.1.0.0/16", action="deny")
    client.post("/api/active/activate", json={"analysis_id": a, "expected_revision": 0})

    # A first publisher wins; a second one still holding revision 0 conflicts.
    won = client.post("/api/active/activate", json={"analysis_id": b, "expected_revision": 1})
    assert won.status_code == 200
    r = client.post("/api/active/activate", json={"analysis_id": b, "expected_revision": 0})
    assert r.status_code == 409
    body = r.json()
    assert body["error"] == "revision_conflict"
    assert body["current"] == {"active_id": b, "revision": 2}

    # Pointer and history reflect exactly the winning activation.
    assert client.get("/api/active").json() == {"active_id": b, "revision": 2}
    assert client.get("/api/active/history").json()["total"] == 2

    # The caller refetches, retries with the fresh revision, and succeeds.
    retry = client.post("/api/active/activate", json={"analysis_id": b, "expected_revision": 2})
    assert retry.status_code == 200
    assert retry.json()["active"]["revision"] == 3


def test_activate_unknown_version_returns_404(client: TestClient) -> None:
    r = client.post(
        "/api/active/activate",
        json={"analysis_id": "an_0000000000000000", "expected_revision": 0},
    )
    assert r.status_code == 404
    # A 404 must not advance the pointer.
    assert client.get("/api/active").json() == {"active_id": None, "revision": 0}
    assert client.get("/api/active/history").json()["total"] == 0


def test_activate_bad_id_format_returns_400(client: TestClient) -> None:
    r = client.post(
        "/api/active/activate", json={"analysis_id": "nope", "expected_revision": 0}
    )
    assert r.status_code == 400
    assert "invalid analysis id format" in r.json()["detail"]
    assert client.get("/api/active").json()["revision"] == 0


def test_activate_validation_errors(client: TestClient) -> None:
    a = _save(client, "10.0.0.0/8")

    # Missing fields / extra fields / negative expected_revision -> 422.
    assert client.post("/api/active/activate", json={"analysis_id": a}).status_code == 422
    assert client.post(
        "/api/active/activate", json={"analysis_id": a, "expected_revision": -1}
    ).status_code == 422
    assert client.post(
        "/api/active/activate",
        json={"analysis_id": a, "expected_revision": 0, "extra": 1},
    ).status_code == 422


def test_history_pagination(client: TestClient) -> None:
    a = _save(client, "10.0.0.0/8")
    for rev in range(3):
        r = client.post(
            "/api/active/activate", json={"analysis_id": a, "expected_revision": rev}
        )
        assert r.status_code == 200

    page = client.get("/api/active/history", params={"limit": 2, "offset": 0}).json()
    assert page["total"] == 3
    assert [h["seq"] for h in page["history"]] == [3, 2]

    page = client.get("/api/active/history", params={"limit": 2, "offset": 2}).json()
    assert [h["seq"] for h in page["history"]] == [1]


def test_concurrent_activations_do_not_overwrite_each_other(client: TestClient) -> None:
    # Two distinct saved versions raced by two threads, both believing the
    # pointer is at revision 0. Exactly one must win; the loser gets 409.
    a = _save(client, "10.0.0.0/8")
    b = _save(client, "10.1.0.0/16", action="deny")
    barrier = threading.Barrier(2)
    statuses: list[int] = []
    pointers: list[str | None] = []
    lock = threading.Lock()

    def publish(target: str) -> None:
        barrier.wait()
        r = client.post(
            "/api/active/activate", json={"analysis_id": target, "expected_revision": 0}
        )
        with lock:
            statuses.append(r.status_code)
            pointers.append(client.get("/api/active").json()["active_id"])

    t1 = threading.Thread(target=publish, args=(a,))
    t2 = threading.Thread(target=publish, args=(b,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert sorted(statuses) == [200, 409]
    # The loser never overwrote the winner: the pointer ended on exactly one.
    assert set(pointers) <= {a, b}
    assert client.get("/api/active").json()["revision"] == 1
    assert client.get("/api/active/history").json()["total"] == 1
