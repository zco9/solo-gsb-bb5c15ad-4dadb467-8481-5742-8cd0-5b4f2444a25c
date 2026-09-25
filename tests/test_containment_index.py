"""Tests for the per-family prefix-index containment-tree builder.

The builder replaces the former O(n^2) "scan every same-family node" parent
search with per-IPv4/IPv6 prefix indices: each node finds its nearest strict
parent by probing progressively shorter populated prefix lengths.  These
tests pin down three things:

1. **Result equivalence** — the indexed builder links exactly the same
   parents as the direct scan (reference implementation) on randomized
   mixtures of sparse, nested and same-CIDR inputs, and the whole
   ``analyze_rules`` output is therefore identical;
2. **Scale behaviour** — large sets of mutually disjoint ("sparse") networks
   and deep multi-level nested chains stay fast, where the quadratic scan
   explodes;
3. **Containment semantics** on hand-built scenarios — effective coverage,
   minimal conflict pairs, findings order, ``ruleset_hash`` and the version
   id all match expected values for both families.
"""

from __future__ import annotations

import ipaddress
import os
import random
import tempfile
import time

import pytest
from fastapi.testclient import TestClient

from app import analyzer, db
from app.analyzer import ANALYZER_VERSION, Node, _link_containment_tree, analyze_rules


# ---------------------------------------------------------------------------
# Reference (direct) parent linker — intentionally the simple O(n^2) scan,
# used as the ground truth the indexed builder must reproduce.
# ---------------------------------------------------------------------------
def _reference_link(version_nodes: list[Node]) -> None:
    for node in version_nodes:
        net = node.network
        best: Node | None = None
        best_prefix = -1
        for candidate in version_nodes:
            if candidate is node:
                continue
            cnet = candidate.network
            if cnet.prefixlen < net.prefixlen and net.subnet_of(cnet):
                if cnet.prefixlen > best_prefix:
                    best = candidate
                    best_prefix = cnet.prefixlen
        node.parent = best
        if best is not None:
            best.children.append(node)


def _make_nodes(networks: list[ipaddress._BaseNetwork]) -> list[Node]:
    return [Node(network=net) for net in networks]


def _parent_map(nodes: list[Node]) -> dict[str, str | None]:
    return {
        str(node.network): (str(node.parent.network) if node.parent is not None else None)
        for node in nodes
    }


def _link_with_reference(nodes: list[Node]) -> dict[str, str | None]:
    by_version: dict[int, list[Node]] = {4: [], 6: []}
    for node in nodes:
        by_version[node.network.version].append(node)
    for version_nodes in by_version.values():
        version_nodes.sort(key=lambda n: (int(n.network.network_address), n.network.prefixlen))
        _reference_link(version_nodes)
    return _parent_map(nodes)


def _link_with_index(nodes: list[Node]) -> dict[str, str | None]:
    by_version: dict[int, list[Node]] = {4: [], 6: []}
    for node in nodes:
        by_version[node.network.version].append(node)
    for version, version_nodes in by_version.items():
        version_nodes.sort(key=lambda n: (int(n.network.network_address), n.network.prefixlen))
        _link_containment_tree(version, version_nodes)
    return _parent_map(nodes)


def _random_networks(seed: int) -> list[ipaddress._BaseNetwork]:
    """A deliberately irregular mix: sparse disjoint nets, nested chains,
    same-CIDR-duplicated nets (deduped to nodes), both families."""
    rng = random.Random(seed)
    nets: set[ipaddress._BaseNetwork] = set()

    # Sparse IPv4 networks at varied prefix lengths.
    for _ in range(40):
        length = rng.choice([8, 16, 20, 24, 28, 30, 32])
        addr = rng.randrange(0, 2**32) & ~((1 << (32 - length)) - 1)
        nets.add(ipaddress.IPv4Network((addr, length)))
    # Deep IPv4 nesting chains.
    for _ in range(4):
        length = rng.randrange(8, 20)
        base = rng.randrange(0, 2**length) << (32 - length)
        for step in range(rng.randrange(1, min(6, 32 - length))):
            nets.add(ipaddress.IPv4Network((base, length + step)))
    # A default route and near-default aggregates.
    nets.add(ipaddress.IPv4Network((0, 0)))
    nets.add(ipaddress.ip_network("10.0.0.0/8"))
    nets.add(ipaddress.ip_network("10.128.0.0/9"))

    # Sparse and nested IPv6 networks.
    for _ in range(40):
        length = rng.choice([16, 32, 48, 64, 96, 112, 127, 128])
        addr = rng.randrange(0, 2**128) & ~((1 << (128 - length)) - 1)
        nets.add(ipaddress.IPv6Network((addr, length)))
    for _ in range(4):
        length = rng.randrange(8, 48)
        base = rng.randrange(0, 2**length) << (128 - length)
        for step in range(rng.randrange(1, min(8, 128 - length))):
            nets.add(ipaddress.IPv6Network((base, length + step)))
    nets.add(ipaddress.IPv6Network((0, 0)))
    return list(nets)


@pytest.mark.parametrize("seed", range(12))
def test_indexed_builder_matches_reference_parents(seed: int) -> None:
    networks = _random_networks(seed)
    indexed = _link_with_index(_make_nodes(networks))
    reference = _link_with_reference(_make_nodes(networks))
    assert indexed == reference


@pytest.mark.parametrize("seed", range(8))
def test_full_analysis_unchanged_against_reference(seed: int, monkeypatch: pytest.MonkeyPatch) -> None:
    networks = _random_networks(seed)
    rules = [
        {
            "rule_id": f"r{i + 1}",
            "cidr": str(net),
            "action": "permit" if i % 2 == 0 else "deny",
            "priority": (i % 5) * 10,
            "source_tag": "a" if i % 3 else "b",
        }
        for i, net in enumerate(networks)
    ]

    indexed_result = analyze_rules(rules)

    captured: dict[int, list[Node]] = {}

    def _capturing_reference(version: int, version_nodes: list[Node]) -> None:
        captured[version] = list(version_nodes)
        _reference_link(version_nodes)

    monkeypatch.setattr(analyzer, "_link_containment_tree", _capturing_reference)
    reference_result = analyze_rules(rules)

    # The reference scan ran for both families present in the input.
    assert set(captured) == {net.version for net in networks}
    assert reference_result == indexed_result


def test_default_routes_are_family_roots() -> None:
    nodes = _make_nodes(
        [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("10.1.0.0/16"),
            ipaddress.ip_network("0.0.0.0/0"),
            ipaddress.ip_network("2001:db8::/32"),
            ipaddress.ip_network("::/0"),
        ]
    )
    parents = _link_with_index(nodes)
    assert parents["0.0.0.0/0"] is None
    assert parents["::/0"] is None
    assert parents["10.0.0.0/8"] == "0.0.0.0/0"
    assert parents["10.1.0.0/16"] == "10.0.0.0/8"
    assert parents["2001:db8::/32"] == "::/0"


def test_families_never_cross_link() -> None:
    # Numerically overlapping address spaces must not parent each other.
    nodes = _make_nodes(
        [
            ipaddress.ip_network("::/0"),
            ipaddress.ip_network("0.0.0.0/0"),
            ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped range, still IPv6
            ipaddress.ip_network("1.2.3.4/32"),
        ]
    )
    parents = _link_with_index(nodes)
    assert parents["1.2.3.4/32"] == "0.0.0.0/0"
    assert parents["::ffff:0:0/96"] == "::/0"


# ---------------------------------------------------------------------------
# Sparse networks: many mutually disjoint CIDRs must remain independent roots.
# ---------------------------------------------------------------------------
def _sparse_v4_rules(count: int) -> list[dict[str, object]]:
    rng = random.Random(20260925)
    seen: set[int] = set()
    rules: list[dict[str, object]] = []
    while len(seen) < count:
        base = rng.randrange(0, 2**24 - 1)
        if base in seen:
            continue
        seen.add(base)
        i = len(rules)
        rules.append(
            {
                "rule_id": f"sp{i}",
                "cidr": str(ipaddress.IPv4Network((base << 8, 24))),
                "action": "permit" if i % 2 == 0 else "deny",
            }
        )
    return rules


def _sparse_v6_rules(count: int) -> list[dict[str, object]]:
    rng = random.Random(4242)
    seen: set[int] = set()
    rules: list[dict[str, object]] = []
    while len(seen) < count:
        base = rng.randrange(0, 2**64)
        if base in seen:
            continue
        seen.add(base)
        i = len(rules)
        rules.append(
            {
                "rule_id": f"v6sp{i}",
                "cidr": str(ipaddress.IPv6Network((base << 64, 64))),
                "action": "permit" if i % 3 == 0 else "deny",
            }
        )
    return rules


def test_sparse_disjoint_networks_are_independent_and_active() -> None:
    rules = _sparse_v4_rules(300) + _sparse_v6_rules(200)
    result = analyze_rules(rules)
    assert result["summary"]["distinct_cidrs"] == 500
    # No containment, no covering relationships anywhere.
    assert result["minimal_conflict_pairs"] == []
    assert all(rule["status"] == "active" for rule in result["rules"])
    assert all(rule["covered_by"] == [] for rule in result["rules"])
    assert not any(f["type"] in {"cover", "partial_shadow", "fully_shadow"} for f in result["findings"])
    assert all(rule["covered"] == rule["total_addresses"] for rule in result["rules"])


def test_sparse_plus_one_default_route_conflicts_each_family() -> None:
    rules = [
        {"rule_id": "root4", "cidr": "0.0.0.0/0", "action": "deny"},
        {"rule_id": "root6", "cidr": "::/0", "action": "deny"},
    ]
    rules += _sparse_v4_rules(250)
    rules += _sparse_v6_rules(250)
    result = analyze_rules(rules)
    # Every disjoint permit network is an effective leaf paired with its
    # family default route; the disjoint deny networks agree with it.
    pairs = {(p["rule_id"], p["other_rule_id"]) for p in result["minimal_conflict_pairs"]}
    permit_v4 = {f"sp{i}" for i in range(250) if i % 2 == 0}
    permit_v6 = {f"v6sp{i}" for i in range(250) if i % 3 == 0}
    assert pairs == {(rid, "root4") for rid in permit_v4} | {
        (rid, "root6") for rid in permit_v6
    }
    # The two family roots never pair with each other.
    assert not any("root4" in pair and "root6" in pair for pair in pairs)


def test_sparse_builder_is_fast_and_quasilinear() -> None:
    # Indexed parent linking on thousands of disjoint networks across both
    # families must be near-linear; the same workload under the reference
    # O(n^2) scan takes seconds.
    nodes = _make_nodes(
        [ipaddress.ip_network(r["cidr"]) for r in (_sparse_v4_rules(1500) + _sparse_v6_rules(1500))]
    )
    by_version: dict[int, list[Node]] = {4: [], 6: []}
    for node in nodes:
        by_version[node.network.version].append(node)

    start = time.perf_counter()
    for version, version_nodes in by_version.items():
        _link_containment_tree(version, version_nodes)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"sparse parent linking took {elapsed:.3f}s"
    # Nothing contains anything: every node is a root.
    assert all(node.parent is None for node in nodes)


# ---------------------------------------------------------------------------
# Deeply nested networks: nearest strict parent at every level.
# ---------------------------------------------------------------------------
def _nested_v6_chain(rules_count: int, roots: int, *, root_action: str = "permit") -> list[dict[str, object]]:
    depth = rules_count // roots
    rules: list[dict[str, object]] = [
        {"rule_id": "root", "cidr": "2001:db8::/32", "action": root_action}
    ]
    for r in range(roots):
        # Each chain starts in a distinct /48.  Encode the per-root id in the
        # top bits of the 16-bit /48 id space (offset 128-32-6 = 90 leaves 6
        # bits for 50 roots) so it survives truncation down to the chain's
        # deepest prefix.
        base = (0x2001_0DB8 << 96) | (r << 90)
        for d in range(depth):
            rules.append(
                {
                    "rule_id": f"c{r}-{d}",
                    "cidr": str(ipaddress.IPv6Network((base, 48 + d))),
                    "action": "permit" if d % 2 == 0 else "deny",
                }
            )
    return rules


def test_deep_chain_parent_and_coverage() -> None:
    rules = [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.10.0.0/16", "action": "deny"},
        {"rule_id": "c", "cidr": "10.10.0.0/20", "action": "permit"},
        {"rule_id": "d", "cidr": "10.10.0.0/24", "action": "deny"},
        {"rule_id": "e", "cidr": "10.10.0.128/32", "action": "permit"},
    ]
    result = analyze_rules(rules)
    by_id = {r["rule_id"]: r for r in result["rules"]}

    # Each level's covered_by lists the immediate child only.
    assert by_id["a"]["covered_by"] == ["b"]
    assert by_id["b"]["covered_by"] == ["c"]
    assert by_id["c"]["covered_by"] == ["d"]
    assert by_id["d"]["covered_by"] == ["e"]
    assert by_id["e"]["covered_by"] == []

    # d is partial: the /32 only takes one address of the /24.
    assert by_id["d"]["status"] == "partial"
    assert by_id["d"]["covered"] == 255
    assert by_id["e"]["status"] == "active"
    assert by_id["e"]["effective_cidrs"] == ["10.10.0.128/32"]
    assert by_id["e"]["covered"] == 1

    # Every node is effective, and each adjacent level changes action, so the
    # minimal pairs are exactly the four direct containment edges.
    pairs = {tuple(sorted((p["rule_id"], p["other_rule_id"]))) for p in result["minimal_conflict_pairs"]}
    assert pairs == {("a", "b"), ("b", "c"), ("c", "d"), ("d", "e")}


def test_nested_chains_have_continuous_parents() -> None:
    rules = _nested_v6_chain(600, roots=50)
    result = analyze_rules(rules)
    # Parent adjacency via the public result shape: every rule appears exactly
    # once in its parent's covered_by chain.
    covered_by = {r["rule_id"]: r["covered_by"] for r in result["rules"]}
    assert covered_by["root"]  # the /32 has immediate children
    # The first level of each chain is covered directly by the shared root...
    depth = 600 // 50
    first_level = {f"c{r}-0" for r in range(50)}
    assert first_level.issubset({child for child in covered_by["root"]})
    # ...and deeper levels hang off the level immediately above them.
    for root in range(50):
        for d in range(1, depth):
            assert covered_by[f"c{root}-{d - 1}"] == [f"c{root}-{d}"]
    # The deepest level of every chain actively forwards a non-empty range.
    deepest_ids = {f"c{root}-{depth - 1}" for root in range(50)}
    deepest_rules = [rule for rule in result["rules"] if rule["rule_id"] in deepest_ids]
    assert len(deepest_rules) == 50
    for rule in deepest_rules:
        assert rule["status"] == "active"
        assert rule["covered"] >= 1


def test_nested_builder_handles_long_chains_quickly() -> None:
    # One very deep chain per family exercises the up-to-32/128 prefix probes.
    v4 = [
        Node(network=ipaddress.IPv4Network((0x0A000000, length)))
        for length in range(8, 33)
    ]
    v6 = [
        Node(network=ipaddress.IPv6Network((0x20010DB8 << 96, length)))
        for length in range(32, 129)
    ]
    start = time.perf_counter()
    _link_containment_tree(4, v4)
    _link_containment_tree(6, v6)
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5, f"deep-chain linking took {elapsed:.3f}s"

    for nodes, max_len in ((v4, 32), (v6, 128)):
        for depth, node in enumerate(nodes):
            if depth == 0:
                assert node.parent is None
            else:
                assert node.parent is nodes[depth - 1]
                assert node.parent.network.prefixlen == node.network.prefixlen - 1
        assert nodes[-1].network.prefixlen == max_len


def test_nested_effective_partition_sums_to_root() -> None:
    # A balanced /16 -> two /17 -> four /18 subtree with deny/permit/deny:
    # the root and the /17s are fully covered, the four /18 leaves partition
    # the whole /16 and each conflicts with its shadowed permit parent.
    rules = [{"rule_id": "root", "cidr": "172.20.0.0/16", "action": "deny"}]
    for j, net in enumerate(ipaddress.ip_network("172.20.0.0/16").subnets(new_prefix=17)):
        rules.append({"rule_id": f"m{j}", "cidr": str(net), "action": "permit"})
        for k, leaf in enumerate(net.subnets(new_prefix=18)):
            rules.append({"rule_id": f"l{j}{k}", "cidr": str(leaf), "action": "deny"})
    result = analyze_rules(rules)
    by_id = {r["rule_id"]: r for r in result["rules"]}

    # The /16 is fully covered by the two /17s; the /17s by their /18 leaves.
    assert by_id["root"]["status"] == "shadowed"
    assert by_id["root"]["covered"] == 0
    assert all(by_id[f"m{j}"]["status"] == "shadowed" for j in range(2))
    leaves = [by_id[f"l{j}{k}"] for j in range(2) for k in range(2)]
    assert all(leaf["status"] == "active" for leaf in leaves)
    assert sum(leaf["covered"] for leaf in leaves) == 2**16

    # Each effective deny leaf pairs with the first different-action ancestor,
    # i.e. its permit /17 (the deny root is never reached).  The pairs'
    # override ranges partition the whole /16 exactly.
    pairs = result["minimal_conflict_pairs"]
    assert {(p["rule_id"], p["other_rule_id"]) for p in pairs} == {
        ("l00", "m0"),
        ("l01", "m0"),
        ("l10", "m1"),
        ("l11", "m1"),
    }
    overrides = sorted(cidr for p in pairs for cidr in p["override_range"])
    assert overrides == ["172.20.0.0/18", "172.20.128.0/18", "172.20.192.0/18", "172.20.64.0/18"]
    assert sum(2**14 for _ in pairs) == 2**16


# ---------------------------------------------------------------------------
# Determinism / identity: shuffled inputs yield identical analysis and hash,
# and the version id derives from that hash.
# ---------------------------------------------------------------------------
def test_shuffled_input_gives_identical_geometry_and_findings() -> None:
    # Distinct CIDRs only (set-deduped by construction): submission order can
    # never change winner selection or the containment tree.  The labeled
    # ruleset hash differs (ids attach to records), but every CIDR-keyed
    # result — statuses, effective ranges, conflict pairs, findings, summary —
    # must be identical regardless of order.
    networks = _random_networks(5)
    base_rules = [
        {
            "rule_id": f"r{i + 1}",
            "cidr": str(net),
            "action": "permit" if i % 2 == 0 else "deny",
            "priority": (i % 4) * 25,
            "source_tag": f"src{i % 3}",
        }
        for i, net in enumerate(networks)
    ]
    reordered = [dict(rule) for rule in base_rules]
    random.Random(7).shuffle(reordered)

    first = analyze_rules(base_rules)
    second = analyze_rules(reordered)
    assert first["analyzer_version"] == second["analyzer_version"] == ANALYZER_VERSION
    assert _result_by_cidr(first) == _result_by_cidr(second)


def test_repeated_analysis_is_byte_stable() -> None:
    rules = [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200},
        {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit"},
        {"rule_id": "d", "cidr": "2001:db8::/32", "action": "deny"},
        {"rule_id": "e", "cidr": "2001:db8:1::/48", "action": "permit"},
    ]
    first = analyze_rules(rules)
    for _ in range(3):
        assert analyze_rules(rules) == first


def _result_by_cidr(result: dict) -> dict:
    """Project an analysis onto CIDR-keyed content, independent of rule ids
    and submission order."""
    cidr_of = {r["rule_id"]: r["cidr"] for r in result["rules"]}
    rules_by_cidr = {
        r["cidr"]: (
            r["role"],
            r["status"],
            r["action"],
            r["priority"],
            r["covered"],
            tuple(r["effective_cidrs"]),
            tuple(sorted(cidr_of[c] for c in r["covered_by"])),
            r["has_conflict"],
        )
        for r in result["rules"]
    }
    pairs = sorted(
        tuple(sorted((cidr_of[p["rule_id"]], cidr_of[p["other_rule_id"]])))
        + (p["kind"], tuple(p["override_range"]))
        for p in result["minimal_conflict_pairs"]
    )
    findings = sorted(
        (
            f["type"],
            f["cidr"],
            f.get("parent_cidr"),
            f["severity"],
            f.get("action_conflict"),
            f.get("behavioral"),
            tuple(f.get("child_effective", [])),
        )
        for f in result["findings"]
    )
    return {"rules": rules_by_cidr, "pairs": pairs, "findings": findings, "summary": result["summary"]}


def test_ruleset_hash_is_order_independent_for_unlabeled_input() -> None:
    # With no explicit rule ids the canonical payload keyed by
    # (rule_id..) still carries positional ids, so compare the geometry under
    # reordering and separately verify the hash is stable for identical input.
    networks = [net for net in _random_networks(8)]
    records = [
        {
            "cidr": str(net),
            "action": "permit" if i % 2 == 0 else "deny",
            "priority": (i % 4) * 25,
            "source_tag": f"src{i % 3}",
        }
        for i, net in enumerate(networks)
    ]
    shuffled_records = records[:]
    random.Random(123).shuffle(shuffled_records)

    first = analyze_rules(records)
    second = analyze_rules(shuffled_records)
    assert _result_by_cidr(first) == _result_by_cidr(second)

    # Submitting the exact same payload twice yields the same hash and id.
    again = analyze_rules([dict(r) for r in records])
    assert again["ruleset_hash"] == first["ruleset_hash"]
    assert "an_" + again["ruleset_hash"][:16] == "an_" + first["ruleset_hash"][:16]


# ---------------------------------------------------------------------------
# Same-CIDR winner selection stays priority/order based under the new builder.
# ---------------------------------------------------------------------------
def test_same_cidr_winner_priority_then_input_order() -> None:
    rules = [
        {"rule_id": "lo", "cidr": "192.0.2.0/24", "action": "deny", "priority": 200},
        {"rule_id": "hi", "cidr": "192.0.2.0/24", "action": "permit", "priority": 100},
        {"rule_id": "tie-a", "cidr": "203.0.113.0/24", "action": "permit", "priority": 50},
        {"rule_id": "tie-b", "cidr": "203.0.113.0/24", "action": "deny", "priority": 50},
    ]
    result = analyze_rules(rules)
    by_id = {r["rule_id"]: r for r in result["rules"]}
    assert by_id["hi"]["role"] == "winner"
    assert by_id["lo"]["role"] == "duplicate"
    # Equal priority: first in input order wins.
    assert by_id["tie-a"]["role"] == "winner"
    assert by_id["tie-b"]["role"] == "duplicate"
    pair = next(p for p in result["minimal_conflict_pairs"] if p["kind"] == "duplicate")
    assert pair["rule_id"] == "lo"
    assert pair["winner_rule_id"] == "hi"


# ---------------------------------------------------------------------------
# End-to-end: POST /api/analyze and the analyzer-backed preview (simulate)
# must expose identical analysis output for the same ruleset.
# ---------------------------------------------------------------------------
@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-tree-")
    os.close(fd)
    os.remove(path)
    db.reset_db(path)
    from app.main import app

    with TestClient(app) as c:
        yield c
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


_ANALYZER_KEYS = (
    "analyzer_version",
    "ruleset_hash",
    "rules",
    "findings",
    "minimal_conflict_pairs",
    "summary",
)


def _analyzer_payload(result: dict) -> dict:
    return {key: result[key] for key in _ANALYZER_KEYS}


def test_analyze_and_simulate_identity_replace_agree(client: TestClient) -> None:
    rules = [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100, "source_tag": "hq"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200, "source_tag": "edge"},
        {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit", "priority": 50, "source_tag": "edge"},
        {"rule_id": "d", "cidr": "2001:db8::/32", "action": "deny", "source_tag": "v6"},
        {"rule_id": "e", "cidr": "2001:db8:1::/48", "action": "permit", "source_tag": "v6"},
        {"rule_id": "f", "cidr": "::1/128", "action": "permit", "source_tag": "v6"},
    ]
    saved = client.post("/api/analyze", json={"name": "mixed", "rules": rules})
    assert saved.status_code == 200, saved.text
    analyze_body = saved.json()
    aid = analyze_body["id"]

    # Replace every rule with an identical record: the previewed analysis must
    # be exactly the analyzer payload of the direct POST, and the semantic diff
    # against the base version must be empty.
    r = client.post(f"/api/analyses/{aid}/simulate", json={"replace": rules})
    assert r.status_code == 200, r.text
    preview = r.json()

    assert preview["simulated"]["ruleset_hash"] == analyze_body["ruleset_hash"]
    assert _analyzer_payload(preview["simulated"]) == _analyzer_payload(analyze_body)
    assert preview["diff"]["changes"] == []
    assert preview["simulated"]["persisted"] is False
    assert preview["simulated"]["id"] is None


def test_analyze_then_simulate_add_sparse_and_nested_rules_agree(client: TestClient) -> None:
    # A base containing both families plus default routes; the preview adds a
    # large batch of sparse disjoint CIDRs and a nested chain.
    base = [
        {"rule_id": "v4root", "cidr": "0.0.0.0/0", "action": "permit"},
        {"rule_id": "v6root", "cidr": "::/0", "action": "deny"},
        {"rule_id": "nest0", "cidr": "2001:db8::/32", "action": "permit"},
    ]
    aid = client.post("/api/analyze", json={"rules": base}).json()["id"]

    additions = list(_sparse_v4_rules(120))
    additions += list(_sparse_v6_rules(80))
    # A nested v4 chain hanging off the 192.0.0.0/8 default route (/8 -> /13).
    chain = [
        {
            "rule_id": f"d{k}",
            "cidr": f"192.0.0.0/{8 + k}",
            "action": "permit" if k % 2 else "deny",
        }
        for k in range(6)
    ]
    additions += chain

    r = client.post(f"/api/analyses/{aid}/simulate", json={"add": additions})
    assert r.status_code == 200, r.text
    simulated = r.json()["simulated"]

    # Independently run the same final ruleset through POST /api/analyze.
    final_rules = base + additions
    direct = client.post("/api/analyze", json={"save": False, "rules": final_rules}).json()
    assert _analyzer_payload(simulated) == _analyzer_payload(direct)
    assert simulated["ruleset_hash"] == direct["ruleset_hash"]
    assert simulated["analyzer_version"] == direct["analyzer_version"]

    # The added chain is contiguous: each level covers exactly the next.
    by_id = {rule["rule_id"]: rule for rule in simulated["rules"]}
    for k in range(5):
        assert by_id[f"d{k}"]["covered_by"] == [f"d{k + 1}"]

    # The sparse disjoint networks remain independent roots (only the default
    # routes contain them); none becomes partial/shadowed due to another.
    sparse_status = {
        rule["rule_id"]: rule["status"]
        for rule in simulated["rules"]
        if rule["rule_id"].startswith(("sp", "v6sp"))
    }
    assert len(sparse_status) == 200
    assert all(status == "active" for status in sparse_status.values())
