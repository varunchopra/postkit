"""The acceptance gate: M2, M3, and atomic visibility under composed transactions.

These attack the invariants directly, driving consolidate() from raw connections
so caller transactions (crash/rollback, concurrency) compose the way a real
worker would compose them.
"""

import json
import threading

import pytest
from postkit.memory import MemoryError, MemoryErrorCode

from tests.memory.helpers import MemoryTestHelpers

JOIN_TIMEOUT = 15

FACTS = [{"content": "zebra fact"}, {"content": "Zebra", "kind": "entity"}]
EDGES = [{"from": "n0", "to": "n1", "relation": "entity"}]


def _consolidate(cur, ns, key, source_episodes):
    cur.execute("SELECT memory.set_tenant(%s)", (ns,))
    cur.execute(
        "SELECT node_ids, skipped FROM memory.consolidate(%s, %s::jsonb, %s::jsonb, %s, %s)",
        (ns, json.dumps(FACTS), json.dumps(EDGES), list(source_episodes), key),
    )
    return cur.fetchone()


def _dump(cur, ns):
    helpers = MemoryTestHelpers(cur, ns)
    return helpers.dump_nodes(), helpers.dump_edges()


class TestM3UnderRetry:
    def test_crash_then_replay_matches_clean_run(self, make_memory, connect):
        """A rolled-back consolidate leaves no bookkeeping row, so the retry
        applies once and converges to the graph a clean run produces."""
        control = make_memory("inv_control")
        crash = make_memory("inv_crash")
        ep_c = control.record("s1", "user", "seed control")
        ep_x = crash.record("s1", "user", "seed crash")

        control.consolidate(FACTS, EDGES, [ep_c], idempotency_key="k")

        conn = connect()
        cur = conn.cursor()
        _consolidate(cur, "inv_crash", "k", [ep_x])
        conn.rollback()

        _, skipped = _consolidate(cur, "inv_crash", "k", [ep_x])
        conn.commit()
        assert skipped is False

        assert _dump(control.cursor, "inv_crash") == _dump(
            control.cursor, "inv_control"
        )


class TestAtomicVisibility:
    def test_recall_never_sees_a_partial_batch(self, make_memory, connect):
        """Another connection's uncommitted consolidate is invisible to recall,
        then its whole graph appears at once on commit."""
        client = make_memory("inv_atomic")
        ep = client.record("s1", "user", "seed")

        writer = connect()
        wcur = writer.cursor()
        _consolidate(wcur, "inv_atomic", "atomic", [ep])

        reader = connect()
        rcur = reader.cursor()
        rcur.execute("SELECT memory.set_tenant(%s)", ("inv_atomic",))
        rcur.execute(
            "SELECT count(*) FROM memory.recall(%s, NULL, %s, %s, %s)",
            ("inv_atomic", ["zebra"], 12, 2),
        )
        assert rcur.fetchone()[0] == 0
        reader.rollback()

        writer.commit()

        rcur.execute("SELECT memory.set_tenant(%s)", ("inv_atomic",))
        rcur.execute(
            "SELECT content FROM memory.recall(%s, NULL, %s, %s, %s)",
            ("inv_atomic", ["zebra"], 12, 2),
        )
        contents = {r[0] for r in rcur.fetchall()}
        reader.rollback()
        assert "zebra fact" in contents
        assert "Zebra" in contents


class TestM3UnderConcurrency:
    def test_same_key_from_two_connections_applies_once(self, make_memory, connect):
        """Two connections racing the same idempotency key apply the batch once;
        the consolidations primary key serializes them."""
        client = make_memory("inv_dup")
        ep = client.record("s1", "user", "seed")
        results: list = []

        def contender():
            conn = connect()
            try:
                _consolidate(conn.cursor(), "inv_dup", "dup", [ep])
                conn.commit()
                results.append("ok")
            except Exception as e:  # noqa: BLE001
                conn.rollback()
                results.append(e)

        threads = [threading.Thread(target=contender) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=JOIN_TIMEOUT)
            assert not t.is_alive(), "concurrent consolidate deadlocked or hung"

        assert "ok" in results
        assert client.get_stats()["total_nodes"] == len(FACTS)


class TestM2Namespace:
    def test_edge_to_foreign_namespace_node_fails(self, make_memory):
        a = make_memory("inv_a")
        b = make_memory("inv_b")
        ep_b = b.record("s1", "user", "b seed")
        foreign = b.consolidate([{"content": "b node"}], [], source_episodes=[ep_b])[
            "node_ids"
        ][0]

        ep_a = a.record("s1", "user", "a seed")
        with pytest.raises(MemoryError) as exc_info:
            a.consolidate(
                [{"content": "a node"}],
                [{"from": "n0", "to": foreign, "relation": "assoc"}],
                source_episodes=[ep_a],
            )
        assert exc_info.value.error_code == MemoryErrorCode.DATA_NODE_NOT_FOUND
