"""memory + queue: a consolidation worker that survives a crash (M3 in composition).

A worker pushes a consolidate job, pulls it, distills (canned here), and applies
the result with memory.consolidate under the job's idempotency key before acking.
A crashed attempt (rollback before ack) must leave the job re-pullable and the
retried graph identical to a never-crashed control run.
"""

import pytest
from postkit.memory import MemoryClient
from postkit.queue import QueueClient
from tests.helpers import connection_factory_for, db_connection_for, require_pgvector
from tests.memory.helpers import MemoryTestHelpers

DIM = 4
ESPRESSO = [1, 0, 0, 0]
TEA = [0, 1, 0, 0]


@pytest.fixture(scope="module")
def mem_connection():
    """Module-scoped connection with memory AND queue installed, dimension fixed."""
    require_pgvector()
    for conn in db_connection_for("memory", "queue"):
        conn.execute("SELECT memory.set_dimension(%s)", (DIM,))
        yield conn


@pytest.fixture
def worker_conn(mem_connection):
    """Factory for non-autocommit connections used to run a worker transaction."""
    yield from connection_factory_for(mem_connection)


def _canned_distill(batch):
    """Stand-in for the LLM: always the same facts and edge from any batch."""
    facts = [
        {"content": "user enjoys espresso", "embedding": ESPRESSO, "embed_model": "m"},
        {"content": "Espresso", "kind": "entity"},
    ]
    edges = [{"from": "n0", "to": "n1", "relation": "entity"}]
    return facts, edges


def _seed_episodes(client):
    for i in range(3):
        client.record(
            "morning",
            "user",
            f"morning note {i}",
            embedding=ESPRESSO,
            embed_model="m",
            keywords=["espresso"],
        )
    for i in range(3):
        client.record(
            "evening",
            "user",
            f"evening note {i}",
            embedding=TEA,
            embed_model="m",
            keywords=["tea"],
        )


def _run_worker(conn, namespace, *, crash: bool):
    """Pull one consolidate job and apply it, optionally crashing before ack.

    Creating the clients opens a transaction (set_tenant), so the pull, the
    consolidate, and the ack all live in one transaction that a crash rolls
    back wholesale.
    """
    mem = MemoryClient(conn.cursor(), namespace)
    queue = QueueClient(conn.cursor(), namespace)

    job = queue.pull("memory.consolidate", worker_id="consolidator-1")
    assert job is not None, "job should be pullable"

    batch = mem.consolidation_due()
    facts, edges = _canned_distill(batch)
    result = mem.consolidate(
        facts,
        edges,
        source_episodes=[e["id"] for e in batch],
        idempotency_key=f"job-{job['id']}",
    )

    if crash:
        conn.rollback()  # crash before ack: nothing committed
        return None

    assert queue.ack(job["id"], job["fence_token"]) is True
    conn.commit()
    return result


def _graph(cursor, namespace):
    helpers = MemoryTestHelpers(cursor, namespace)
    return helpers.dump_nodes(), helpers.dump_edges()


def test_crashed_consolidation_retries_to_identical_graph(mem_connection, worker_conn):
    """A worker that crashes mid-consolidation re-pulls the job and applies the
    same idempotency key once, converging to the graph a clean run produces."""
    control_ns = "consol_control"
    crash_ns = "consol_crash"

    control = MemoryClient(mem_connection.cursor(), control_ns)
    crash = MemoryClient(mem_connection.cursor(), crash_ns)
    control_q = QueueClient(mem_connection.cursor(), control_ns)
    crash_q = QueueClient(mem_connection.cursor(), crash_ns)

    _seed_episodes(control)
    _seed_episodes(crash)
    control_q.push("memory.consolidate", {})
    crash_q.push("memory.consolidate", {})

    control_result = _run_worker(worker_conn(), control_ns, crash=False)
    assert control_result["skipped"] is False

    assert _run_worker(worker_conn(), crash_ns, crash=True) is None

    retry_result = _run_worker(worker_conn(), crash_ns, crash=False)
    assert retry_result["skipped"] is False

    assert _graph(mem_connection.cursor(), crash_ns) == _graph(
        mem_connection.cursor(), control_ns
    )

    hits = crash.recall(query_embedding=ESPRESSO)
    assert any(h["content"] == "user enjoys espresso" for h in hits)

    stats = crash.get_stats()
    assert stats["total_episodes"] == 6
    assert stats["unconsolidated_episodes"] == 0
