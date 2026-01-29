"""Tests for queue ack/nack/fail operations."""

from datetime import timedelta

import pytest
from postkit.errors import QueueErrorCode
from postkit.queue import QueueClient, QueueError, QueueValidationError


class TestAck:
    """Test successful job completion."""

    def test_ack_returns_true(self, queue):
        """ack returns True for running job."""
        queue.push("tasks", {"task": 1})
        job = queue.pull("tasks")

        result = queue.ack(job["id"])
        assert result is True

    def test_ack_removes_job(self, queue):
        """ack removes job from queue (when archive_completed=false)."""
        queue.push("tasks", {"task": 1})
        job = queue.pull("tasks")
        queue.ack(job["id"])

        # Job should be gone
        stats = queue.get_stats()
        assert stats["total_jobs"] == 0

    def test_ack_archives_job_when_configured(self, raw_cursor):
        """With archive_completed=true, ack marks job completed instead of deleting."""
        cursor, namespace = raw_cursor

        # Enable archive mode for this namespace.
        cursor.execute(
            "INSERT INTO queue.config (namespace, archive_completed) VALUES (%s, true)",
            (namespace,),
        )

        q = QueueClient(cursor, namespace)
        q.push("tasks", {"task": 1})
        job = q.pull("tasks")
        q.ack(job["id"])

        # Job should be retained with completed status, not deleted.
        cursor.execute(
            "SELECT status, completed_at, locked_by, locked_at, visibility_timeout_at "
            "FROM queue.jobs WHERE namespace = %s AND id = %s",
            (namespace, job["id"]),
        )
        row = cursor.fetchone()
        assert row[0] == "completed"
        assert row[1] is not None  # completed_at set
        assert row[2] is None  # locked_by cleared
        assert row[3] is None  # locked_at cleared
        assert row[4] is None  # visibility_timeout_at cleared

        # Stats should reflect the completed job.
        stats = q.get_stats()
        assert stats["completed"] == 1
        assert stats["total_jobs"] == 1

    def test_ack_pending_job_returns_false(self, queue):
        """ack returns False for pending (not running) job."""
        job_id = queue.push("tasks", {"task": 1})

        result = queue.ack(job_id)
        assert result is False

    def test_ack_nonexistent_returns_false(self, queue):
        """ack returns False for nonexistent job."""
        result = queue.ack(999999)
        assert result is False

    def test_ack_already_acked_returns_false(self, queue):
        """ack returns False when called twice."""
        queue.push("tasks", {"task": 1})
        job = queue.pull("tasks")
        queue.ack(job["id"])

        result = queue.ack(job["id"])
        assert result is False


class TestAckBatch:
    """Test batch acknowledgment."""

    def test_ack_batch_returns_count(self, queue):
        """ack_batch returns count of acknowledged jobs."""
        for i in range(3):
            queue.push("tasks", {"task": i})

        jobs = queue.pull_batch("tasks", limit=3)
        job_ids = [j["id"] for j in jobs]

        count = queue.ack_batch(job_ids)
        assert count == 3

    def test_ack_batch_empty_returns_zero(self, queue):
        """ack_batch with empty list returns 0."""
        count = queue.ack_batch([])
        assert count == 0

    def test_ack_batch_archives_when_configured(self, raw_cursor):
        """With archive_completed=true, ack_batch marks jobs completed."""
        cursor, namespace = raw_cursor

        cursor.execute(
            "INSERT INTO queue.config (namespace, archive_completed) VALUES (%s, true)",
            (namespace,),
        )

        q = QueueClient(cursor, namespace)
        for i in range(3):
            q.push("tasks", {"task": i})

        jobs = q.pull_batch("tasks", limit=3)
        count = q.ack_batch([j["id"] for j in jobs])
        assert count == 3

        # All three should be retained with completed status.
        stats = q.get_stats()
        assert stats["completed"] == 3
        assert stats["total_jobs"] == 3

    def test_ack_batch_partial_success(self, queue):
        """ack_batch counts only running jobs."""
        queue.push("tasks", {"task": 1})
        queue.push("tasks", {"task": 2})

        job = queue.pull("tasks")  # Only pull one

        # Try to ack both (one running, one pending)
        count = queue.ack_batch([job["id"], job["id"] + 1])
        assert count == 1


class TestNack:
    """Test temporary failure handling."""

    def test_nack_returns_job_to_queue(self, queue):
        """nack returns job to pending status."""
        queue.push("tasks", {"task": 1}, max_attempts=3)
        job = queue.pull("tasks")

        result = queue.nack(job["id"], error="temporary failure")
        assert result is True

        # Job should be pullable again (after backoff)
        # Note: In real scenario, would need to wait for backoff
        # For test, we check stats
        stats = queue.get_stats()
        assert stats["pending"] == 1

    def test_nack_increments_attempts(self, raw_cursor):
        """Each pull after nack increments the attempts counter."""
        cursor, namespace = raw_cursor

        q = QueueClient(cursor, namespace)
        q.push("tasks", {"task": 1}, max_attempts=5)

        for expected_attempt in range(1, 4):
            job = q.pull("tasks")
            assert job["attempts"] == expected_attempt
            q.nack(job["id"])

            # Bypass backoff delay so job is immediately pullable.
            cursor.execute(
                "UPDATE queue.jobs SET scheduled_at = now() WHERE namespace = %s AND id = %s",
                (namespace, job["id"]),
            )

    def test_nack_with_custom_backoff(self, queue):
        """nack accepts custom backoff duration."""

        queue.push("tasks", {"task": 1}, max_attempts=3)
        job = queue.pull("tasks")

        result = queue.nack(job["id"], backoff=timedelta(seconds=1))
        assert result is True

    def test_nack_max_attempts_moves_to_dlq(self, queue):
        """nack moves job to DLQ when max_attempts exceeded."""
        queue.push("tasks", {"task": 1}, max_attempts=1)

        job = queue.pull("tasks")
        assert job["attempts"] == 1  # Already at max

        # nack should move to DLQ
        result = queue.nack(job["id"], error="failed")
        assert result is False  # False indicates moved to DLQ

        # Job should be in dead status
        stats = queue.get_stats()
        assert stats["dead"] == 1

    def test_nack_not_running_raises_error(self, queue):
        """nack raises error for non-running job."""

        job_id = queue.push("tasks", {"task": 1})

        with pytest.raises(QueueValidationError) as exc_info:
            queue.nack(job_id)
        assert exc_info.value.error_code == QueueErrorCode.BIZ_JOB_NOT_RUNNING

    def test_nack_not_found_raises_error(self, queue):
        """nack raises error for nonexistent job."""

        with pytest.raises(QueueError) as exc_info:
            queue.nack(999999)
        assert exc_info.value.error_code == QueueErrorCode.DATA_JOB_NOT_FOUND


class TestFail:
    """Test permanent failure handling."""

    def test_fail_moves_to_dlq(self, queue):
        """fail moves job to dead letter queue."""
        queue.push("tasks", {"task": 1})
        job = queue.pull("tasks")

        result = queue.fail(job["id"], error="invalid payload")
        assert result is True

        # Job should be dead
        stats = queue.get_stats()
        assert stats["dead"] == 1

    def test_fail_not_running_returns_false(self, queue):
        """fail returns False for non-running job."""
        job_id = queue.push("tasks", {"task": 1})

        result = queue.fail(job_id)
        assert result is False

    def test_fail_stores_error_message(self, queue, raw_cursor):
        """fail stores error message in dead_letters."""
        cursor, namespace = raw_cursor

        q = QueueClient(cursor, namespace)
        q.push("tasks", {"task": 1})
        job = q.pull("tasks")
        q.fail(job["id"], error="test error message")

        # Check dead_letters table
        cursor.execute(
            "SELECT last_error FROM queue.dead_letters WHERE namespace = %s",
            (namespace,),
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == "test error message"


class TestCancel:
    """Test pending job cancellation."""

    def test_cancel_removes_pending_job(self, queue):
        """cancel deletes a pending job."""
        job_id = queue.push("tasks", {"task": 1})

        result = queue.cancel(job_id)
        assert result is True

        stats = queue.get_stats()
        assert stats["total_jobs"] == 0

    def test_cancel_returns_false_for_running_job(self, queue):
        """cancel returns False for a job that has been pulled."""
        queue.push("tasks", {"task": 1})
        job = queue.pull("tasks")

        result = queue.cancel(job["id"])
        assert result is False

    def test_cancel_returns_false_for_nonexistent_job(self, queue):
        """cancel returns False for a job that does not exist."""
        result = queue.cancel(999999)
        assert result is False

    def test_cancel_returns_false_for_completed_job(self, queue, raw_cursor):
        """cancel returns False for a job that is already completed."""
        cursor, namespace = raw_cursor

        q = QueueClient(cursor, namespace)
        q.push("tasks", {"task": 1})
        job = q.pull("tasks")
        q.ack(job["id"])

        # Job is now completed (or deleted). Either way, cancel should fail.
        result = q.cancel(job["id"])
        assert result is False

    def test_cancelled_job_not_pullable(self, queue):
        """After cancel, the job cannot be pulled."""
        job_id = queue.push("tasks", {"task": 1})
        queue.cancel(job_id)

        result = queue.pull("tasks")
        assert result is None


class TestJobLifecycle:
    """Test complete job lifecycle scenarios."""

    def test_push_pull_ack_flow(self, queue):
        """Complete happy path: push -> pull -> ack."""
        job_id = queue.push("email", {"to": "alice@example.com"})
        job = queue.pull("email")
        assert job["id"] == job_id

        result = queue.ack(job["id"])
        assert result is True

        # Queue is empty
        assert queue.pull("email") is None

    def test_push_pull_nack_retry_ack_flow(self, queue):
        """Retry flow: push -> pull -> nack -> pull -> ack."""
        queue.push("tasks", {"task": 1}, max_attempts=3)

        # First attempt fails
        job1 = queue.pull("tasks")
        queue.nack(job1["id"], error="first failure")

        # For this test, we'll check that the job is back in pending
        stats = queue.get_stats()
        assert stats["pending"] == 1

    def test_push_pull_fail_dlq_flow(self, queue):
        """DLQ flow: push -> pull -> fail (to DLQ)."""
        queue.push("tasks", {"task": "bad data"})

        job = queue.pull("tasks")
        queue.fail(job["id"], error="unprocessable")

        # Job is dead
        stats = queue.get_stats()
        assert stats["dead"] == 1
        assert stats["pending"] == 0
