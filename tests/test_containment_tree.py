"""Tests for the prefix-index containment-tree builder.

The containment trie used to be built by comparing every node against every
other node of the same IP family (O(n^2)).  These tests pin the replacement
(builder per family, prefix index, level-by-level nearest-strict-parent
lookup) to the *same* results as the exhaustive search, cover sparse and
deeply nested inputs (functionally and for performance), and confirm the
HTTP preview surfaces stay consistent with ``POST /api/analyze``.
"""

from __future__ import annotations

import ipaddress
import os
import random
import tempfile
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import db
from app.analyzer import (
    ANALYZER_VERSION,
    Node,
    _link_containment_parents,
    _parse_rules,
    analyze_rules,
)


# ---------------------------------------------------------------------------
# Construction helpers
# ---------------------------------------------------------------------------
def _nodes_from_rules(raw_rules: list[dict[str, Any]]) -> tuple[dict[int, list[Node]], list[Node]]:
    """Replicate the analyzer's group/winner phase without linking parents."""
    rules = _parse_rules(raw_rules)
    groups: dict[str, list] = {}
    for rule in rules:
        groups.setdefault(str(rule.network), []).append(rule)

    nodes: list[Node] = []
    for cidr, members in groups.items():
        ordered = sorted(members, key=lambda r: (r.priority, r.index))
        nodes.append(
            Node(network=ipaddress.ip_network(cidr), members=ordered, winner=ordered[0])
        )

    nodes_by_version: dict[int, list[Node]] = {4: [], 6: []}
    for node in nodes:
        nodes_by_version[node.network.version].append(node)
    for version_nodes in nodes_by_version.values():
        version_nodes.sort(
            key=lambda n: (int(n.network.network_address), n.network.prefixlen)
        )
    return nodes_by_version, nodes


def _brute_force_parents(nodes_by_version: dict[int, list[Node]]) -> dict[int, int | None]:
    """Reference O(n^2) parent selection: nearest enclosing strict subnet."""
    parent_of: dict[int, int | None] = {}
    for version_nodes in nodes_by_version.values():
        for node in version_nodes:
            net = node.network
            best: Node | None = None
            best_prefix = -1
            for candidate in version_nodes:
                if candidate is node:
                    continue
                cnet = candidate.network
                if (
                    cnet.prefixlen < net.prefixlen
                    and net.subnet_of(cnet)
                    and cnet.prefixlen > best_prefix
                ):
                    best = candidate
                    best_prefix = cnet.prefixlen
            parent_of[id(node)] = id(best) if best is not None else None
    return parent_of


def _indexed_parents(nodes_by_version: dict[int, list[Node]]) -> dict[int, int | None]:
    # Reset any pre-existing links before (re)building the tree.
    for version_nodes in nodes_by_version.values():
        for node in version_nodes:
            node.parent = None
            node.children = []
    _link_containment_parents(nodes_by_version)
    return {
        id(node): id(node.parent) if node.parent is not None else None
        for version_nodes in nodes_by_version.values()
        for node in version_nodes
    }


def _random_cidr(rng: random.Random) -> str:
    use_v6 = rng.random() < 0.5
    bits = 128 if use_v6 else 32
    value = rng.getrandbits(bits)
    if use_v6:
        max_len = rng.choice([0, 8, 32, 48, 64, 64, 96, 127, 128])
        cls = ipaddress.IPv6Address
    else:
        max_len = rng.choice([0, 8, 16, 24, 24, 30, 31, 32])
        cls = ipaddress.IPv4Address
    prefix_len = rng.randint(0, max_len)
    if prefix_len:
        masked = (value >> (bits - prefix_len)) << (bits - prefix_len)
    else:
        masked = 0
    return f"{cls(masked)}/{prefix_len}"


# ---------------------------------------------------------------------------
# Functional equivalence with the exhaustive builder
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("seed", range(20))
def test_indexed_builder_matches_brute_force_on_random_mixes(seed: int) -> None:
    rng = random.Random(1000 + seed)
    raw_rules = [
        {
            "rule_id": f"r{i}",
            "cidr": _random_cidr(rng),
            "action": rng.choice(["permit", "deny", "allow", "block"]),
            "priority": rng.randint(0, 5),
        }
        for i in range(rng.randint(1, 60))
    ]

    nodes_by_version, _ = _nodes_from_rules(raw_rules)
    expected = _brute_force_parents(nodes_by_version)
    assert _indexed_parents(nodes_by_version) == expected


def test_nearest_parent_is_the_longest_enclosing_prefix_not_any_ancestor() -> None:
    # /8 and /16 both enclose /24; the immediate parent must be the /16.
    raw = [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny"},
        {"rule_id": "c", "cidr": "10.1.2.0/24", "action": "permit"},
    ]
    nodes_by_version, nodes = _nodes_from_rules(raw)
    _indexed_parents(nodes_by_version)
    by_cidr = {str(n.network): n for n in nodes}

    assert by_cidr["10.0.0.0/8"].parent is None
    assert by_cidr["10.1.0.0/16"].parent is by_cidr["10.0.0.0/8"]
    assert by_cidr["10.1.2.0/24"].parent is by_cidr["10.1.0.0/16"]
    assert by_cidr["10.0.0.0/8"].children == [by_cidr["10.1.0.0/16"]]
    assert by_cidr["10.1.0.0/16"].children == [by_cidr["10.1.2.0/24"]]


def test_disjoint_sparse_prefixes_have_no_parent_links() -> None:
    # Many mutually-disjoint /24s plus a v6 counterpart: nothing nests.
    raw = [
        {"rule_id": f"s{third}_{fourth}", "cidr": f"10.{third}.{fourth}.0/24",
         "action": "permit" if (third + fourth) % 2 else "deny"}
        for third in range(6)
        for fourth in range(256)
    ]
    raw += [
        {"rule_id": f"v6_{i}", "cidr": f"2001:db8:{i:x}::/48",
         "action": "permit" if i % 2 else "deny"}
        for i in range(64)
    ]
    nodes_by_version, nodes = _nodes_from_rules(raw)
    _indexed_parents(nodes_by_version)

    assert len(nodes) == 6 * 256 + 64
    assert all(node.parent is None for node in nodes)
    assert all(node.children == [] for node in nodes)


def test_default_routes_anchor_both_families() -> None:
    raw = [
        {"rule_id": "v4root", "cidr": "0.0.0.0/0", "action": "deny"},
        {"rule_id": "v4leaf", "cidr": "192.0.2.1/32", "action": "permit"},
        {"rule_id": "v6root", "cidr": "::/0", "action": "deny"},
        {"rule_id": "v6leaf", "cidr": "2001:db8::1/128", "action": "permit"},
    ]
    nodes_by_version, nodes = _nodes_from_rules(raw)
    _indexed_parents(nodes_by_version)
    by_cidr = {str(n.network): n for n in nodes}

    assert by_cidr["192.0.2.1/32"].parent is by_cidr["0.0.0.0/0"]
    assert by_cidr["2001:db8::1/128"].parent is by_cidr["::/0"]
    # Families stay independent: an IPv4 node never links under an IPv6 node.
    assert by_cidr["0.0.0.0/0"].parent is None
    assert by_cidr["::/0"].parent is None


def test_full_ipv4_and_ipv6_nesting_chains() -> None:
    raw = [
        {"rule_id": "v4_0", "cidr": "0.0.0.0/0", "action": "permit"},
        {"rule_id": "v4_8", "cidr": "10.0.0.0/8", "action": "deny"},
        {"rule_id": "v4_16", "cidr": "10.1.0.0/16", "action": "permit"},
        {"rule_id": "v4_24", "cidr": "10.1.2.0/24", "action": "deny"},
        {"rule_id": "v4_28", "cidr": "10.1.2.0/28", "action": "permit"},
        {"rule_id": "v4_32", "cidr": "10.1.2.3/32", "action": "deny"},
    ]
    v6_seed = int(ipaddress.IPv6Address("2001:db8::"))
    for prefix_len in range(0, 129):
        if prefix_len:
            masked = (v6_seed >> (128 - prefix_len)) << (128 - prefix_len)
        else:
            masked = 0
        raw.append(
            {
                "rule_id": f"v6_{prefix_len}",
                "cidr": f"{ipaddress.IPv6Address(masked)}/{prefix_len}",
                "action": "permit" if prefix_len % 2 == 0 else "deny",
            }
        )

    nodes_by_version, nodes = _nodes_from_rules(raw)
    _indexed_parents(nodes_by_version)
    by_id = {n.winner.rule_id: n for n in nodes}

    # Each chain node links to the immediately shorter prefix (32 v4 + 129 v6).
    v4_levels = [0, 8, 16, 24, 28, 32]
    for shorter, longer in zip(v4_levels, v4_levels[1:]):
        assert by_id[f"v4_{longer}"].parent is by_id[f"v4_{shorter}"]
    for prefix_len in range(1, 129):
        assert by_id[f"v6_{prefix_len}"].parent is by_id[f"v6_{prefix_len - 1}"]

    # And the end-to-end analysis still resolves every action boundary.
    result = analyze_rules(raw)
    assert result["summary"]["ipv4_rules"] == 6
    assert result["summary"]["ipv6_rules"] == 129
    assert all(
        (p["rule_id"], p["other_rule_id"])
        in {(f"v4_{l}", f"v4_{s}") for s, l in zip(v4_levels, v4_levels[1:])}
        or p["rule_id"].startswith("v6_")
        for p in result["minimal_conflict_pairs"]
    )
    leaf = next(r for r in result["rules"] if r["rule_id"] == "v6_128")
    assert leaf["effective_cidrs"] == ["2001:db8::/128"]


def test_same_cidr_priority_and_input_order_winner_unchanged() -> None:
    raw = [
        {"rule_id": "lo1", "cidr": "10.0.0.0/8", "action": "deny", "priority": 200},
        {"rule_id": "hi", "cidr": "10.0.0.0/8", "action": "permit", "priority": 50},
        {"rule_id": "lo2", "cidr": "10.0.0.0/8", "action": "permit", "priority": 50},
        {"rule_id": "child", "cidr": "10.0.0.0/24", "action": "deny", "priority": 999},
    ]
    result = analyze_rules(raw)
    by_id = {r["rule_id"]: r for r in result["rules"]}

    # Smallest priority wins; input order breaks the exact tie (hi precedes lo2).
    assert by_id["hi"]["role"] == "winner"
    assert by_id["lo1"]["role"] == "duplicate"
    assert by_id["lo2"]["role"] == "duplicate"
    # The child conflicts with the winner (permit /8), never the duplicates.
    pairs = {(p["rule_id"], p["other_rule_id"]) for p in result["minimal_conflict_pairs"]}
    assert ("child", "hi") in pairs
    assert all(other != "lo1" and other != "lo2" for _, other in pairs)


def test_results_are_structurally_invariant_under_input_permutation() -> None:
    raw = [
        {"rule_id": f"s{third}_{fourth}", "cidr": f"10.{third}.{fourth}.0/24",
         "action": "permit" if (third + fourth) % 2 else "deny",
         "priority": (third + fourth) % 3}
        for third in range(8)
        for fourth in range(256)
    ]
    raw.append({"rule_id": "root", "cidr": "10.0.0.0/8", "action": "deny", "priority": 1})

    def _normalized(result: dict[str, Any]) -> dict[str, Any]:
        rules = sorted(
            [{k: v for k, v in row.items() if k != "index"} for row in result["rules"]],
            key=lambda row: row["rule_id"],
        )
        return {"rules": rules, "findings": result["findings"],
                "pairs": result["minimal_conflict_pairs"], "summary": result["summary"]}

    shuffled = raw[:]
    random.Random(7).shuffle(shuffled)
    assert _normalized(analyze_rules(raw)) == _normalized(analyze_rules(shuffled))


def test_ruleset_hash_analyzer_version_and_id_are_stable() -> None:
    raw = [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny"},
        {"rule_id": "c", "cidr": "2001:db8::/32", "action": "deny"},
    ]
    first = analyze_rules(raw)
    second = analyze_rules(raw)
    assert first["ruleset_hash"] == second["ruleset_hash"]
    assert first["analyzer_version"] == ANALYZER_VERSION == "1.0.0"
    assert first["minimal_conflict_pairs"] == second["minimal_conflict_pairs"]


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------
SPARSE_RULES = [
    {"rule_id": f"s{third}_{fourth}", "cidr": f"10.{third}.{fourth}.0/24",
     "action": "permit" if (third + fourth) % 2 else "deny"}
    for third in range(12)
    for fourth in range(256)
]  # 3072 mutually-disjoint /24s inside 10.0.0.0/8 ... 10.11.0.0/8


def test_prefix_index_builder_beats_brute_force_on_sparse_input() -> None:
    nodes_by_version, _ = _nodes_from_rules(SPARSE_RULES)

    start = time.perf_counter()
    expected = _brute_force_parents(nodes_by_version)
    brute_seconds = time.perf_counter() - start

    start = time.perf_counter()
    actual = _indexed_parents(nodes_by_version)
    index_seconds = time.perf_counter() - start

    assert actual == expected
    # The quadratic scan does ~9.4 million containment tests here; the index
    # walk does at most 32 dict probes per node.
    assert index_seconds * 5 < brute_seconds, (index_seconds, brute_seconds)


def test_end_to_end_analysis_of_large_sparse_ruleset_is_fast() -> None:
    start = time.perf_counter()
    result = analyze_rules(SPARSE_RULES)
    elapsed = time.perf_counter() - start

    assert len(result["rules"]) == len(SPARSE_RULES)
    assert all(rule["status"] == "active" for rule in result["rules"])
    assert result["minimal_conflict_pairs"] == []
    assert elapsed < 5.0, f"sparse analysis took {elapsed:.2f}s"


def test_end_to_end_analysis_of_deep_nesting_is_fast() -> None:
    raw = []
    v6_seed = int(ipaddress.IPv6Address("2001:db8::"))
    for prefix_len in range(0, 129):
        masked = (v6_seed >> (128 - prefix_len)) << (128 - prefix_len) if prefix_len else 0
        raw.append(
            {"rule_id": f"v6_{prefix_len}",
             "cidr": f"{ipaddress.IPv6Address(masked)}/{prefix_len}",
             "action": "permit" if prefix_len % 2 == 0 else "deny"}
        )
    start = time.perf_counter()
    result = analyze_rules(raw)
    elapsed = time.perf_counter() - start

    # Alternating actions: every non-root level is one minimal conflict pair.
    assert len(result["minimal_conflict_pairs"]) == 128
    assert elapsed < 2.0, f"deep-nesting analysis took {elapsed:.2f}s"


# ---------------------------------------------------------------------------
# HTTP consistency: POST /api/analyze vs the analyzer-backed preview
# ---------------------------------------------------------------------------
@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-tree-")
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


def _slim(result: dict[str, Any]) -> dict[str, Any]:
    """Drop identity/metadata fields so two analyses can be compared directly."""
    return {
        key: result[key]
        for key in (
            "analyzer_version",
            "ruleset_hash",
            "rules",
            "findings",
            "minimal_conflict_pairs",
            "summary",
        )
    }


def test_simulate_preview_matches_post_analyze(client: TestClient) -> None:
    sparse_tail = SPARSE_RULES[:2000]
    rules = [
        {"rule_id": "root", "cidr": "10.0.0.0/8", "action": "permit", "source_tag": "core"},
        *sparse_tail,
        {"rule_id": "v6root", "cidr": "2001:db8::/32", "action": "deny", "source_tag": "v6"},
        {"rule_id": "v6leaf", "cidr": "2001:db8::1/128", "action": "permit", "source_tag": "v6"},
    ]

    saved = client.post("/api/analyze", json={"name": "tree-check", "rules": rules})
    assert saved.status_code == 200, saved.text
    analysis_id = saved.json()["id"]

    # A replace-in-place preview keeps the rule's position and every field,
    # so the rebuilt analyzer input is identical: coverage, pairs, findings,
    # hash and analyzer version all match the direct POST /api/analyze result.
    replacement = {
        "rule_id": "v6leaf",
        "cidr": "2001:db8::1/128",
        "action": "permit",
        "priority": 100,
        "source_tag": "v6",
    }
    preview = client.post(
        f"/api/analyses/{analysis_id}/simulate",
        json={"replace": [replacement]},
    )
    assert preview.status_code == 200, preview.text
    simulated = preview.json()["simulated"]

    assert _slim(simulated) == _slim(saved.json())
    assert simulated["persisted"] is False
    # The preview base pointer agrees with the saved version identity.
    assert preview.json()["base"]["id"] == analysis_id
    assert preview.json()["base"]["ruleset_hash"] == saved.json()["ruleset_hash"]

    # And a freshly POSTed unsaved analysis of the same input is identical too.
    direct = client.post("/api/analyze", json={"save": False, "rules": rules})
    assert direct.status_code == 200, direct.text
    assert _slim(direct.json()) == _slim(saved.json())
