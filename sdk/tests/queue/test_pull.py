"""Selection, ordering, and fence issuance for the three pull APIs."""

from datetime import timedelta

import pytest
from postkit.errors import QueueErrorCode
from postkit.queue import QueueValidationError


def _ack(queue, job):
    assert queue.ack(job["id"], job["fence_token"]) is True


class TestPull:
    """A single pull marks the highest-priority available job as running."""

    def test_returns_pushed_job(self, queue):
        job_id = queue.push("email", {"to": "alice@example.com"})

        job = queue.pull("email")

        assert job is not None
        assert job["id"] == job_id
        assert job["queue"] == "email"
        assert job["payload"] == {"to": "alice@example.com"}
        assert job["status"] == "running"
        assert job["attempts"] == 1
        assert job["locked_by"] == "anonymous"
        assert job["fence_token"] > 0
        _ack(queue, job)

    def test_empty_queue_returns_none(self, queue):
        assert queue.pull("email") is None

    def test_respects_priority(self, queue):
        queue.push("tasks", {"task": "low"}, priority=-10)
        queue.push("tasks", {"task": "high"}, priority=10)
        queue.push("tasks", {"task": "normal"}, priority=0)

        jobs = [queue.pull("tasks") for _ in range(3)]

        assert [job["payload"]["task"] for job in jobs] == [
            "high",
            "normal",
            "low",
        ]
        for job in jobs:
            _ack(queue, job)

    def test_respects_scheduled_at(self, queue):
        queue.push("tasks", {"task": "delayed"}, delay=timedelta(hours=1))
        queue.push("tasks", {"task": "immediate"})

        job = queue.pull("tasks")

        assert job["payload"]["task"] == "immediate"
        assert queue.pull("tasks") is None
        _ack(queue, job)

    def test_stores_worker_id(self, queue):
        queue.push("tasks", {"task": 1})

        job = queue.pull("tasks", worker_id="worker-1")

        assert job["locked_by"] == "worker-1"
        _ack(queue, job)


class TestPullBatch:
    """Batch pull marks up to its limit of available jobs as running."""

    def test_respects_limit(self, queue):
        for i in range(5):
            queue.push("tasks", {"task": i})

        jobs = queue.pull_batch("tasks", limit=3)

        assert len(jobs) == 3
        assert all(job["status"] == "running" for job in jobs)
        assert all(job["fence_token"] > 0 for job in jobs)
        assert queue.ack_batch(
            [(job["id"], job["fence_token"]) for job in jobs]
        ) == len(jobs)
        remaining = queue.pull_batch("tasks", limit=10)
        assert queue.ack_batch(
            [(job["id"], job["fence_token"]) for job in remaining]
        ) == len(remaining)

    def test_empty_queue_returns_empty_list(self, queue):
        assert queue.pull_batch("tasks", limit=10) == []

    def test_returns_fewer_than_limit(self, queue):
        queue.push("tasks", {"task": 1})
        queue.push("tasks", {"task": 2})

        jobs = queue.pull_batch("tasks", limit=10)

        assert len(jobs) == 2
        assert queue.ack_batch([(job["id"], job["fence_token"]) for job in jobs]) == 2

    def test_assigns_a_distinct_fence_to_each_job(self, queue):
        """Each job in a batch is a separate attempt with its own fence."""
        for i in range(3):
            queue.push("tasks", {"task": i})

        jobs = queue.pull_batch("tasks", limit=3)
        fences = [job["fence_token"] for job in jobs]

        assert len(fences) == 3
        assert len(set(fences)) == 3
        assert queue.ack_batch([(job["id"], job["fence_token"]) for job in jobs]) == 3


class TestPullAny:
    """The caller's queue order takes precedence across queue names."""

    def test_checks_queues_in_order(self, queue):
        queue.push("low", {"priority": "low"})
        queue.push("high", {"priority": "high"})

        high = queue.pull_any(["high", "low"])
        low = queue.pull_any(["high", "low"])

        assert high["payload"]["priority"] == "high"
        assert low["payload"]["priority"] == "low"
        _ack(queue, high)
        _ack(queue, low)

    def test_skips_empty_queues(self, queue):
        queue.push("low", {"data": 1})

        job = queue.pull_any(["high", "low"])

        assert job["queue"] == "low"
        assert job["fence_token"] > 0
        _ack(queue, job)

    def test_all_empty_returns_none(self, queue):
        assert queue.pull_any(["high", "medium", "low"]) is None

    def test_empty_list_returns_none(self, queue):
        assert queue.pull_any([]) is None


class TestVisibilityTimeout:
    """Timeout overrides are validated before a job changes state."""

    @staticmethod
    def _pull(queue, method, timeout):
        if method == "pull":
            return queue.pull("tasks", visibility_timeout=timeout)
        if method == "pull_batch":
            jobs = queue.pull_batch("tasks", visibility_timeout=timeout)
            return jobs[0] if jobs else None
        return queue.pull_any(["tasks"], visibility_timeout=timeout)

    @pytest.mark.parametrize("method", ["pull", "pull_batch", "pull_any"])
    def test_null_override_uses_config_default(self, queue, method):
        job_id = queue.push("tasks", {"ok": True})

        job = self._pull(queue, method, None)

        assert job["id"] == job_id
        assert job["attempts"] == 1
        assert job["visibility_timeout_at"] > job["locked_at"]
        assert job["fence_token"] > 0
        _ack(queue, job)

    @pytest.mark.parametrize("method", ["pull", "pull_batch", "pull_any"])
    @pytest.mark.parametrize("timeout", [timedelta(0), timedelta(seconds=-1)])
    def test_nonpositive_timeout_is_atomic(self, queue, method, timeout):
        """A rejected timeout must not consume an attempt or issue a fence."""
        job_id = queue.push("tasks", {"task": 1})

        with pytest.raises(QueueValidationError) as exc_info:
            self._pull(queue, method, timeout)
        assert exc_info.value.error_code == QueueErrorCode.VAL_INTERVAL_NOT_POSITIVE

        stats = queue.get_stats()
        assert stats["pending"] == 1
        assert stats["running"] == 0

        job = self._pull(queue, method, timedelta(minutes=1))
        assert job["id"] == job_id
        assert job["attempts"] == 1
        assert job["fence_token"] > 0
        _ack(queue, job)

    @pytest.mark.parametrize("method", ["pull", "pull_batch", "pull_any"])
    def test_deadline_uses_wall_clock_in_a_long_transaction(self, queue, method):
        """A pull must not measure visibility from the transaction's old now()."""
        connection = queue.cursor.connection
        timeout = timedelta(seconds=5)

        with connection.transaction():
            transaction_started_at = queue.cursor.execute("SELECT now()").fetchone()[0]
            queue.cursor.execute("SELECT pg_sleep(0.05)")
            queue.push("tasks", {"task": 1})
            pull_started_at = queue.cursor.execute(
                "SELECT clock_timestamp()"
            ).fetchone()[0]

            job = self._pull(queue, method, timeout)
            pull_finished_at = queue.cursor.execute(
                "SELECT clock_timestamp()"
            ).fetchone()[0]

            assert pull_started_at > transaction_started_at
            assert pull_started_at <= job["locked_at"] <= pull_finished_at
            assert job["visibility_timeout_at"] == job["locked_at"] + timeout
            assert job["updated_at"] == job["locked_at"]
            _ack(queue, job)


class TestFenceSequence:
    """The fence sequence must never reuse a token while job IDs may repeat."""

    def test_restart_identity_does_not_rewind_fences(self, queue, db_connection):
        """Resetting job IDs must not reset the separate fence sequence."""
        db_connection.execute("TRUNCATE queue.jobs RESTART IDENTITY")
        queue.push("tasks", {"attempt": 1})
        first = queue.pull("tasks")

        db_connection.execute("TRUNCATE queue.jobs RESTART IDENTITY")

        first_id_after_restart = queue.push("tasks", {"attempt": 2})
        second = queue.pull("tasks")

        assert second["id"] == first_id_after_restart
        assert second["id"] == first["id"]
        assert second["fence_token"] > first["fence_token"]
        _ack(queue, second)

    def test_sequence_is_noncycling_and_not_owned_by_jobs(self, db_connection):
        """The sequence must not cycle or participate in RESTART IDENTITY."""
        row = db_connection.execute(
            """SELECT s.seqcycle,
                      pg_get_serial_sequence('queue.jobs', 'fence_token')
               FROM pg_sequence s
               JOIN pg_class c ON c.oid = s.seqrelid
               JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = 'queue'
                 AND c.relname = 'fence_token_seq'"""
        ).fetchone()

        assert row == (False, None)
