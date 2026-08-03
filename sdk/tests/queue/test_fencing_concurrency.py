"""Concurrent outcomes guaranteed by queue fence tokens.

The actors use separate PostgreSQL connections because row locks belong to a
transaction. Barriers start actors together, and held rows establish overlap
where the old race required it. Assertions accept either valid serial winner.
"""

import threading
from datetime import timedelta
from time import monotonic

import psycopg
import pytest
from postkit.queue import QueueClient, QueueFencingError

JOIN_TIMEOUT = 10


def _client(connect, namespace):
    """Create a worker on its own connection for a concurrent actor."""
    conn = connect()
    client = QueueClient(conn.cursor(), namespace)
    conn.commit()
    return conn, client


def _pull_job(queue, *, worker="worker-a", timeout=timedelta(minutes=5)):
    queue.push("tasks", {"n": 1})
    return queue.pull("tasks", worker_id=worker, visibility_timeout=timeout)


def _run_thread(target):
    """Run an actor and retain its value or exception for the calling test."""
    result = {}

    def run():
        try:
            result["value"] = target()
            result["status"] = "ok"
        except (
            QueueFencingError,
            psycopg.Error,
            threading.BrokenBarrierError,
        ) as error:
            result["status"] = "error"
            result["error"] = error

    thread = threading.Thread(target=run)
    thread.start()
    return thread, result


def _join(thread):
    thread.join(timeout=JOIN_TIMEOUT)
    assert not thread.is_alive(), "concurrent queue operation did not finish"


def _lock_jobs(connect, namespace, job_ids):
    """Hold the job rows so concurrent statements reach the same lock boundary."""
    blocker = connect()
    blocker.execute("SELECT queue.set_tenant(%s)", (namespace,))
    blocker.execute(
        """SELECT id
           FROM queue.jobs
           WHERE namespace = %s
             AND id = ANY(%s::bigint[])
           ORDER BY id
           FOR UPDATE""",
        (namespace, job_ids),
    )
    return blocker


def _release_after_workers_block(blocker, worker_connections):
    """Release held rows only after every worker has joined their lock queue."""
    deadline = monotonic() + JOIN_TIMEOUT
    try:
        while monotonic() < deadline:
            all_waiting = all(
                blocker.execute(
                    "SELECT cardinality(pg_blocking_pids(%s)) > 0",
                    (connection.info.backend_pid,),
                ).fetchone()[0]
                for connection in worker_connections
            )
            if all_waiting:
                return
            threading.Event().wait(0.01)
        pytest.fail("concurrent queue operations did not reach the held row lock")
    finally:
        blocker.commit()


class TestExpiryAfterLockWait:
    """Expiration is checked after acquiring the job row lock."""

    def test_ack_rejects_fence_that_expires_while_waiting(self, queue, connect):
        """A statement begun in time still loses if its fence expires while waiting."""
        job = _pull_job(queue)
        blocker = connect()
        blocker.execute("SELECT queue.set_tenant(%s)", (queue.namespace,))
        blocker.execute(
            """UPDATE queue.jobs
               SET visibility_timeout_at = clock_timestamp() - interval '1 second'
               WHERE namespace = %s AND id = %s""",
            (queue.namespace, job["id"]),
        )

        worker_conn, worker = _client(connect, queue.namespace)
        started = threading.Event()

        def late_ack():
            started.set()
            return worker.ack(job["id"], job["fence_token"])

        thread, result = _run_thread(late_ack)
        assert started.wait(timeout=JOIN_TIMEOUT)
        _release_after_workers_block(blocker, [worker_conn])
        _join(thread)

        assert result["status"] == "error"
        assert isinstance(result["error"], QueueFencingError)
        worker_conn.close()
        blocker.close()


class TestRedelivery:
    """A new pull supersedes the old fence, even when it reuses the worker ID."""

    @pytest.mark.parametrize(
        "operation", ["extend_visibility", "ack", "nack", "fail", "release"]
    )
    @pytest.mark.parametrize("next_worker", ["worker-b", "worker-a"])
    def test_old_fence_cannot_change_redelivered_job(
        self, queue, test_helpers, operation, next_worker
    ):
        first = _pull_job(queue, worker="worker-a")
        test_helpers.expire_visibility_timeout(first["id"])
        assert queue.tick_timeouts()[0]["job_id"] == first["id"]
        current = queue.pull("tasks", worker_id=next_worker)

        method = getattr(queue, operation)
        with pytest.raises(QueueFencingError):
            if operation == "extend_visibility":
                method(first["id"], first["fence_token"], timedelta(minutes=1))
            else:
                method(first["id"], first["fence_token"])

        stored = test_helpers.get_job_raw(current["id"])
        assert stored["status"] == "running"
        assert stored["fence_token"] == current["fence_token"]
        assert queue.ack(current["id"], current["fence_token"]) is True


class TestTimeoutRaces:
    """Visibility changes and timeout reclamation serialize on the job row."""

    def test_visibility_extension_prevents_timeout_reclamation(
        self, queue, connect, test_helpers
    ):
        """A sweep skips the locked extension, then observes its later deadline."""
        job = _pull_job(queue, timeout=timedelta(seconds=1))
        old_deadline = job["visibility_timeout_at"]
        extending_conn, extending = _client(connect, queue.namespace)
        with extending_conn.transaction():
            assert (
                extending.extend_visibility(
                    job["id"], job["fence_token"], timedelta(minutes=1)
                )
                is True
            )

            while queue.cursor.execute(
                "SELECT clock_timestamp() < %s", (old_deadline,)
            ).fetchone()[0]:
                threading.Event().wait(0.01)

            assert queue.tick_timeouts() == []

        assert queue.tick_timeouts() == []
        assert test_helpers.get_job_raw(job["id"])["status"] == "running"
        assert queue.ack(job["id"], job["fence_token"]) is True
        extending_conn.close()

    @pytest.mark.parametrize(
        "operation", ["extend_visibility", "ack", "nack", "fail", "release"]
    )
    def test_expired_operation_cannot_prevent_timeout_reclamation(
        self, queue, connect, test_helpers, operation
    ):
        """An expired attempt cannot settle the job, regardless of lock order."""
        job = _pull_job(queue)
        test_helpers.expire_visibility_timeout(job["id"])
        operation_conn, operation_client = _client(connect, queue.namespace)
        timeout_conn, timeout_client = _client(connect, queue.namespace)
        barrier = threading.Barrier(2, timeout=JOIN_TIMEOUT)

        def operate():
            barrier.wait()
            if operation == "extend_visibility":
                return operation_client.extend_visibility(
                    job["id"], job["fence_token"], timedelta(minutes=1)
                )
            return getattr(operation_client, operation)(job["id"], job["fence_token"])

        def reclaim():
            barrier.wait()
            return timeout_client.tick_timeouts()

        operation_thread, operation_result = _run_thread(operate)
        timeout_thread, timeout_result = _run_thread(reclaim)
        _join(operation_thread)
        _join(timeout_thread)

        assert operation_result["status"] == "error"
        assert isinstance(operation_result["error"], QueueFencingError)
        assert timeout_result["status"] == "ok"
        reclaimed = [row["job_id"] for row in timeout_result["value"]]
        if not reclaimed:
            # SKIP LOCKED may let the first sweep pass while the mutation holds the row.
            reclaimed = [row["job_id"] for row in queue.tick_timeouts()]
        assert reclaimed == [job["id"]]
        stored = test_helpers.get_job_raw(job["id"])
        assert stored["status"] == "pending"
        assert stored["fence_token"] is None
        operation_conn.close()
        timeout_conn.close()


class TestConcurrentAttemptUpdates:
    """The first update clears the fence; every waiter then sees it as stale."""

    @pytest.mark.parametrize(
        ("left_operation", "right_operation"),
        [("ack", "fail"), ("nack", "release"), ("fail", "release")],
    )
    def test_exactly_one_attempt_update_succeeds(
        self, queue, connect, left_operation, right_operation
    ):
        """Two updates using one fence have exactly one successful outcome."""
        job = _pull_job(queue)
        left_conn, left = _client(connect, queue.namespace)
        right_conn, right = _client(connect, queue.namespace)
        blocker = _lock_jobs(connect, queue.namespace, [job["id"]])
        barrier = threading.Barrier(2, timeout=JOIN_TIMEOUT)

        def update_attempt(client, operation):
            barrier.wait()
            return getattr(client, operation)(job["id"], job["fence_token"])

        left_thread, left_result = _run_thread(
            lambda: update_attempt(left, left_operation)
        )
        right_thread, right_result = _run_thread(
            lambda: update_attempt(right, right_operation)
        )
        _release_after_workers_block(blocker, [left_conn, right_conn])
        _join(left_thread)
        _join(right_thread)

        results = [left_result, right_result]
        assert [result["status"] for result in results].count("ok") == 1
        winner = next(result for result in results if result["status"] == "ok")
        assert winner["value"] is True
        loser = next(result for result in results if result["status"] == "error")
        assert isinstance(loser["error"], QueueFencingError)
        left_conn.close()
        right_conn.close()
        blocker.close()

    def test_concurrent_fail_creates_one_dead_letter(
        self, queue, connect, test_helpers
    ):
        """Two fail calls cannot insert duplicate dead-letter records."""
        job = _pull_job(queue)
        left_conn, left = _client(connect, queue.namespace)
        right_conn, right = _client(connect, queue.namespace)
        blocker = _lock_jobs(connect, queue.namespace, [job["id"]])
        barrier = threading.Barrier(2, timeout=JOIN_TIMEOUT)

        def fail(client, message):
            barrier.wait()
            return client.fail(job["id"], job["fence_token"], error=message)

        left_thread, left_result = _run_thread(lambda: fail(left, "left"))
        right_thread, right_result = _run_thread(lambda: fail(right, "right"))
        _release_after_workers_block(blocker, [left_conn, right_conn])
        _join(left_thread)
        _join(right_thread)

        results = [left_result, right_result]
        assert [result["status"] for result in results].count("ok") == 1
        assert next(result["value"] for result in results if result["status"] == "ok")
        loser = next(result for result in results if result["status"] == "error")
        assert isinstance(loser["error"], QueueFencingError)
        assert test_helpers.count_dead_letters() == 1
        assert test_helpers.get_job_raw(job["id"])["status"] == "dead"
        left_conn.close()
        right_conn.close()
        blocker.close()

    def test_concurrent_fail_and_nack_leave_one_consistent_outcome(
        self, queue, connect, test_helpers
    ):
        """A retry cannot resurrect a job after a concurrent fail wins."""
        job = _pull_job(queue)
        fail_conn, fail_client = _client(connect, queue.namespace)
        nack_conn, nack_client = _client(connect, queue.namespace)
        blocker = _lock_jobs(connect, queue.namespace, [job["id"]])
        barrier = threading.Barrier(2, timeout=JOIN_TIMEOUT)

        def fail():
            barrier.wait()
            return fail_client.fail(job["id"], job["fence_token"], error="permanent")

        def nack():
            barrier.wait()
            return nack_client.nack(job["id"], job["fence_token"], error="temporary")

        fail_thread, fail_result = _run_thread(fail)
        nack_thread, nack_result = _run_thread(nack)
        _release_after_workers_block(blocker, [fail_conn, nack_conn])
        _join(fail_thread)
        _join(nack_thread)

        results = [fail_result, nack_result]
        assert [result["status"] for result in results].count("ok") == 1
        loser = next(result for result in results if result["status"] == "error")
        assert isinstance(loser["error"], QueueFencingError)

        stored = test_helpers.get_job_raw(job["id"])
        if fail_result["status"] == "ok":
            assert fail_result["value"] is True
            assert stored["status"] == "dead"
            assert test_helpers.count_dead_letters() == 1
        else:
            assert nack_result["value"] is True
            assert stored["status"] == "pending"
            assert test_helpers.count_dead_letters() == 0
        fail_conn.close()
        nack_conn.close()
        blocker.close()


class TestConcurrentBatchAcknowledgement:
    """Batch acknowledgement locks jobs in ID order to avoid deadlocks."""

    def test_reverse_input_batches_complete_without_deadlock(self, queue, connect):
        """Caller order must not alter the internal row-lock order."""
        queue.cursor.execute(
            "INSERT INTO queue.config (namespace, archive_completed) VALUES (%s, true)",
            (queue.namespace,),
        )
        for n in range(2):
            queue.push("tasks", {"n": n})
        jobs = queue.pull_batch("tasks", 2)
        forward = [(job["id"], job["fence_token"]) for job in jobs]
        reverse = list(reversed(forward))
        left_conn, left = _client(connect, queue.namespace)
        right_conn, right = _client(connect, queue.namespace)
        blocker = _lock_jobs(connect, queue.namespace, [job["id"] for job in jobs])
        barrier = threading.Barrier(2, timeout=JOIN_TIMEOUT)

        def acknowledge(client, pairs):
            barrier.wait()
            return client.ack_batch(pairs)

        left_thread, left_result = _run_thread(lambda: acknowledge(left, forward))
        right_thread, right_result = _run_thread(lambda: acknowledge(right, reverse))
        _release_after_workers_block(blocker, [left_conn, right_conn])
        _join(left_thread)
        _join(right_thread)

        results = [left_result, right_result]
        assert [result["status"] for result in results].count("ok") == 1
        assert (
            next(result["value"] for result in results if result["status"] == "ok") == 2
        )
        loser = next(result for result in results if result["status"] == "error")
        assert isinstance(loser["error"], QueueFencingError)
        left_conn.close()
        right_conn.close()
        blocker.close()
