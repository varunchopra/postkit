"""Tests for dead letter retry operations."""

from datetime import timedelta

import pytest
from postkit.errors import QueueErrorCode
from postkit.queue import QueueError, QueueValidationError


class TestRetryDeadLetter:
    """Test retry_dead_letter creates new jobs from dead-lettered entries."""

    def _make_dead_letter(self, queue, max_attempts=3):
        """Push, pull, and fail a job so it lands in dead_letters."""
        queue.push(
            "tasks",
            {"action": "retry_me"},
            priority=5,
            max_attempts=max_attempts,
            tags=["important"],
            metadata={"source": "test"},
        )
        job = queue.pull("tasks")
        queue.fail(job["id"], error="test failure")

        # Fetch the dead letter ID.
        queue.cursor.execute(
            "SELECT id FROM queue.dead_letters "
            "WHERE namespace = %s AND original_job_id = %s",
            (queue.namespace, job["id"]),
        )
        row = queue.cursor.fetchone()
        return row[0], job["id"]

    def test_retry_creates_new_pending_job(self, queue):
        """Retrying a dead letter creates a new pending job."""
        dl_id, _ = self._make_dead_letter(queue)

        new_job_id = queue.retry_dead_letter(dl_id)
        assert new_job_id is not None
        assert new_job_id > 0

        # New job should be pullable.
        job = queue.pull("tasks")
        assert job is not None
        assert job["id"] == new_job_id
        assert job["payload"] == {"action": "retry_me"}

    def test_retry_preserves_payload_priority_tags(self, queue):
        """Retried job inherits payload, priority, and tags from dead letter."""
        dl_id, _ = self._make_dead_letter(queue)

        new_job_id = queue.retry_dead_letter(dl_id)

        queue.cursor.execute(
            "SELECT payload, priority, tags, metadata "
            "FROM queue.jobs WHERE namespace = %s AND id = %s",
            (queue.namespace, new_job_id),
        )
        row = queue.cursor.fetchone()
        assert row[1] == 5  # priority preserved
        assert row[2] == ["important"]  # tags preserved
        assert row[3] == {"source": "test"}  # metadata preserved

    def test_retry_uses_original_max_attempts(self, queue):
        """Retried job uses the max_attempts preserved in the dead letter."""
        dl_id, _ = self._make_dead_letter(queue, max_attempts=7)

        new_job_id = queue.retry_dead_letter(dl_id)

        queue.cursor.execute(
            "SELECT max_attempts FROM queue.jobs WHERE namespace = %s AND id = %s",
            (queue.namespace, new_job_id),
        )
        row = queue.cursor.fetchone()
        assert row[0] == 7

    def test_retry_marks_dead_letter_as_retried(self, queue):
        """After retry, dead letter has retried_at and retry_job_id set."""
        dl_id, _ = self._make_dead_letter(queue)

        new_job_id = queue.retry_dead_letter(dl_id)

        queue.cursor.execute(
            "SELECT retried_at, retry_job_id FROM queue.dead_letters "
            "WHERE namespace = %s AND id = %s",
            (queue.namespace, dl_id),
        )
        row = queue.cursor.fetchone()
        assert row[0] is not None  # retried_at
        assert row[1] == new_job_id  # retry_job_id

    def test_retry_already_retried_raises_error(self, queue):
        """Retrying an already-retried dead letter raises an error."""
        dl_id, _ = self._make_dead_letter(queue)
        queue.retry_dead_letter(dl_id)

        with pytest.raises(QueueValidationError) as exc_info:
            queue.retry_dead_letter(dl_id)
        assert (
            exc_info.value.error_code == QueueErrorCode.BIZ_DEAD_LETTER_ALREADY_RETRIED
        )

    def test_retry_nonexistent_raises_error(self, queue):
        """Retrying a nonexistent dead letter raises not-found error."""
        with pytest.raises(QueueError) as exc_info:
            queue.retry_dead_letter(999999)
        assert exc_info.value.error_code == QueueErrorCode.DATA_DEAD_LETTER_NOT_FOUND

    def test_retry_with_queue_override(self, queue):
        """Retrying with queue override puts job in the new queue."""
        dl_id, _ = self._make_dead_letter(queue)

        new_job_id = queue.retry_dead_letter(dl_id, queue="retry_queue")

        job = queue.pull("retry_queue")
        assert job is not None
        assert job["id"] == new_job_id

        # Original queue should be empty.
        assert queue.pull("tasks") is None

    def test_retry_captures_actor_context(self, queue):
        """Retry captures the caller's actor context, not the original."""
        dl_id, _ = self._make_dead_letter(queue)

        queue.set_actor(actor_id="admin_bob", reason="customer escalation")
        new_job_id = queue.retry_dead_letter(dl_id)

        queue.cursor.execute(
            "SELECT actor_id, reason FROM queue.jobs WHERE namespace = %s AND id = %s",
            (queue.namespace, new_job_id),
        )
        row = queue.cursor.fetchone()
        assert row[0] == "admin_bob"
        assert row[1] == "customer escalation"

    def test_retry_resets_attempts_to_zero(self, queue):
        """Retried job starts with attempts=0 (fresh start)."""
        dl_id, _ = self._make_dead_letter(queue)

        new_job_id = queue.retry_dead_letter(dl_id)

        queue.cursor.execute(
            "SELECT attempts FROM queue.jobs WHERE namespace = %s AND id = %s",
            (queue.namespace, new_job_id),
        )
        row = queue.cursor.fetchone()
        assert row[0] == 0

    def test_retry_null_id_raises_validation_error(self, queue):
        """Passing None as dead_letter_id raises a validation error."""
        with pytest.raises(QueueValidationError) as exc_info:
            queue.retry_dead_letter(None)  # type: ignore[arg-type]
        assert exc_info.value.error_code == QueueErrorCode.VAL_DEAD_LETTER_ID_NULL


class TestRetryDeadLetters:
    """Test bulk retry of dead letters for a queue."""

    def _make_dead_letters(self, queue, count=3):
        """Push, pull, and fail multiple jobs to populate dead_letters."""
        for i in range(count):
            queue.push("tasks", {"task": i}, priority=i + 1, max_attempts=5)
            job = queue.pull("tasks")
            queue.fail(job["id"], error=f"failure {i}")

    def test_retries_dead_letters_by_queue(self, queue):
        """Bulk retry returns (dead_letter_id, job_id) pairs."""
        self._make_dead_letters(queue, count=3)

        results = queue.retry_dead_letters("tasks")
        assert len(results) == 3
        for r in results:
            assert "dead_letter_id" in r
            assert "job_id" in r
            assert r["job_id"] > 0

    def test_skips_already_retried(self, queue):
        """Does not double-retry dead letters that were already retried."""
        self._make_dead_letters(queue, count=2)

        first = queue.retry_dead_letters("tasks")
        assert len(first) == 2

        # Second call should find nothing to retry.
        second = queue.retry_dead_letters("tasks")
        assert len(second) == 0

    def test_respects_limit(self, queue):
        """Limit caps the number of retried dead letters."""
        self._make_dead_letters(queue, count=5)

        results = queue.retry_dead_letters("tasks", limit=2)
        assert len(results) == 2

        # Remaining 3 are still retryable.
        rest = queue.retry_dead_letters("tasks")
        assert len(rest) == 3

    def test_retried_jobs_are_pullable(self, queue):
        """New jobs created by bulk retry are pending and pullable."""
        self._make_dead_letters(queue, count=2)

        results = queue.retry_dead_letters("tasks")
        retried_ids = {r["job_id"] for r in results}

        # Pull both new jobs.
        pulled = []
        for _ in range(2):
            job = queue.pull("tasks")
            assert job is not None
            pulled.append(job["id"])

        assert set(pulled) == retried_ids

    def test_clamps_limit_to_1000(self, queue):
        """Limits above 1000 are silently clamped, not rejected."""
        self._make_dead_letters(queue, count=2)
        # Should succeed without error despite exceeding 1000.
        results = queue.retry_dead_letters("tasks", limit=5000)
        assert len(results) == 2

    def test_captures_caller_actor_context(self, queue):
        """Bulk retry captures the caller's actor context on all new jobs."""
        self._make_dead_letters(queue, count=2)

        queue.set_actor(actor_id="ops_team", reason="batch recovery")
        results = queue.retry_dead_letters("tasks")

        for r in results:
            queue.cursor.execute(
                "SELECT actor_id, reason FROM queue.jobs "
                "WHERE namespace = %s AND id = %s",
                (queue.namespace, r["job_id"]),
            )
            row = queue.cursor.fetchone()
            assert row[0] == "ops_team"
            assert row[1] == "batch recovery"


class TestPurgeDeadLetters:
    """Test purge_dead_letters deletes old un-retried dead letters."""

    def _make_dead_letter(self, queue, queue_name="tasks"):
        """Push, pull, and fail a job to create a dead letter."""
        queue.push(queue_name, {"task": "dead"})
        job = queue.pull(queue_name)
        queue.fail(job["id"], error="permanent")

    def test_purge_deletes_old_dead_letters(self, queue):
        """Dead letters older than the threshold are deleted."""
        self._make_dead_letter(queue)

        # Backdate failed_at to 60 days ago.
        queue.cursor.execute(
            "UPDATE queue.dead_letters SET failed_at = now() - interval '60 days' "
            "WHERE namespace = %s",
            (queue.namespace,),
        )

        count = queue.purge_dead_letters(older_than=timedelta(days=30))
        assert count == 1

    def test_purge_preserves_recent(self, queue):
        """Dead letters newer than the threshold are preserved."""
        self._make_dead_letter(queue)

        # Default is 30 days; freshly created dead letter should survive.
        count = queue.purge_dead_letters(older_than=timedelta(days=30))
        assert count == 0

    def test_purge_by_queue(self, queue):
        """Queue filter limits purge to a specific queue."""
        self._make_dead_letter(queue, queue_name="tasks")
        self._make_dead_letter(queue, queue_name="email")

        # Backdate both.
        queue.cursor.execute(
            "UPDATE queue.dead_letters SET failed_at = now() - interval '60 days' "
            "WHERE namespace = %s",
            (queue.namespace,),
        )

        count = queue.purge_dead_letters(queue="tasks", older_than=timedelta(days=30))
        assert count == 1

        # Email dead letter still exists.
        queue.cursor.execute(
            "SELECT count(*) FROM queue.dead_letters "
            "WHERE namespace = %s AND queue = 'email'",
            (queue.namespace,),
        )
        assert queue.cursor.fetchone()[0] == 1

    def test_purge_preserves_retried(self, queue):
        """Retried dead letters are kept even if old."""
        self._make_dead_letter(queue)

        # Retry it first.
        queue.cursor.execute(
            "SELECT id FROM queue.dead_letters WHERE namespace = %s",
            (queue.namespace,),
        )
        dl_id = queue.cursor.fetchone()[0]
        queue.retry_dead_letter(dl_id)

        # Backdate failed_at.
        queue.cursor.execute(
            "UPDATE queue.dead_letters SET failed_at = now() - interval '60 days' "
            "WHERE namespace = %s",
            (queue.namespace,),
        )

        count = queue.purge_dead_letters(older_than=timedelta(days=30))
        assert count == 0  # Retried entry preserved.
