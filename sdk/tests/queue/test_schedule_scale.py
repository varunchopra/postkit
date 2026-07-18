import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from postkit.queue import QueueClient

from tests.helpers import make_namespace


@pytest.mark.scale
def test_schedule_tick_large_fixture_is_bounded_ordered_and_complete(
    make_queue, connect, request
):
    namespace = make_namespace(request)
    owner = make_queue(namespace)
    connection = connect(statement_timeout_ms=30_000)
    worker = QueueClient(connection.cursor(), namespace)
    schedule_names = []

    # One transaction fixes now(); distinct intervals make processing order deterministic.
    for i in range(5_000):
        name = f"scale-{i:05d}"
        worker.create_schedule(
            name,
            "scheduled",
            {"sequence": i},
            every_interval=timedelta(microseconds=i + 1),
        )
        schedule_names.append(name)
    connection.commit()

    processed = []
    tick_seconds = 0.0
    while len(processed) < len(schedule_names):
        started = time.monotonic()
        page = worker.tick_schedules(limit=1_000)
        tick_seconds += time.monotonic() - started
        connection.commit()

        assert 0 < len(page) <= 1_000
        names = [row["schedule_name"] for row in page]
        processed.extend(names)
        for name in names:
            assert owner.delete_schedule(name)

    assert processed == schedule_names
    assert len(processed) == len(set(processed))
    assert worker.tick_schedules(limit=1_000) == []
    assert tick_seconds < 10.0, (
        f"public schedule ticks took {tick_seconds:.2f}s of database-call time"
    )


def test_concurrent_schedule_ticks_do_not_create_duplicates(
    make_queue, connect, request
):
    namespace = make_namespace(request)
    owner = make_queue(namespace)
    schedule_names = []
    for i in range(200):
        name = f"concurrent-{i:04d}"
        owner.create_schedule(
            name,
            "scheduled",
            {"sequence": i},
            every_interval=timedelta(microseconds=1),
        )
        schedule_names.append(name)

    worker_connections = [
        connect(statement_timeout_ms=30_000),
        connect(statement_timeout_ms=30_000),
    ]
    workers = [
        QueueClient(connection.cursor(), namespace) for connection in worker_connections
    ]
    start = Barrier(2)
    selected = Barrier(2)

    def tick(client, connection):
        start.wait()
        rows = client.tick_schedules(limit=200)
        selected.wait()
        connection.commit()
        return rows

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(tick, client, connection)
            for client, connection in zip(workers, worker_connections)
        ]
        results = [row for future in futures for row in future.result()]

    result_names = [row["schedule_name"] for row in results]
    assert len(result_names) == len(set(result_names))
    assert set(result_names) == set(schedule_names)
