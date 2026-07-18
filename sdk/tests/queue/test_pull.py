"""Tests for queue pull operations."""

from datetime import timedelta

import pytest
from postkit.queue import QueueErrorCode, QueueValidationError


class TestPull:
    """Test basic pull functionality."""

    def test_pull_returns_job(self, queue):
        """Pull returns the pushed job."""
        queue.push("email", {"to": "alice@example.com"})

        job = queue.pull("email")

        assert job is not None
        assert job["queue"] == "email"
        assert job["payload"] == {"to": "alice@example.com"}
        assert job["status"] == "running"
        assert job["attempts"] == 1
        assert job["locked_by"] == "anonymous"  # Default when no worker_id provided

    def test_pull_empty_queue_returns_none(self, queue):
        """Pull from empty queue returns None."""
        job = queue.pull("email")
        assert job is None

    def test_pull_respects_priority(self, queue):
        """Higher priority jobs are pulled first."""
        queue.push("tasks", {"task": "low"}, priority=-10)
        queue.push("tasks", {"task": "high"}, priority=10)
        queue.push("tasks", {"task": "normal"}, priority=0)

        # Should get high priority first
        job1 = queue.pull("tasks")
        assert job1["payload"]["task"] == "high"

        # Then normal
        job2 = queue.pull("tasks")
        assert job2["payload"]["task"] == "normal"

        # Then low
        job3 = queue.pull("tasks")
        assert job3["payload"]["task"] == "low"

        # Ack all to clean up
        queue.ack(job1["id"])
        queue.ack(job2["id"])
        queue.ack(job3["id"])

    def test_pull_respects_scheduled_at(self, queue):
        """Delayed jobs are not visible until scheduled_at."""
        # Push a delayed job
        queue.push("tasks", {"task": "delayed"}, delay=timedelta(hours=1))

        # Push an immediate job
        queue.push("tasks", {"task": "immediate"})

        # Should only get the immediate job
        job = queue.pull("tasks")
        assert job is not None
        assert job["payload"]["task"] == "immediate"

        # Delayed job not visible yet
        job2 = queue.pull("tasks")
        assert job2 is None

        queue.ack(job["id"])

    def test_pull_with_worker_id(self, queue):
        """Worker ID is stored with pulled job."""
        queue.push("tasks", {"task": 1})

        job = queue.pull("tasks", worker_id="worker-1")

        assert job is not None
        assert job["locked_by"] == "worker-1"

        queue.ack(job["id"])


class TestPullBatch:
    """Test batch pull functionality."""

    def test_pull_batch_returns_multiple(self, queue):
        """Batch pull returns up to limit jobs."""
        for i in range(5):
            queue.push("tasks", {"task": i})

        jobs = queue.pull_batch("tasks", limit=3)

        assert len(jobs) == 3
        # All should be running
        assert all(j["status"] == "running" for j in jobs)

        # Clean up
        for j in jobs:
            queue.ack(j["id"])
        # Ack remaining
        remaining = queue.pull_batch("tasks", limit=10)
        for j in remaining:
            queue.ack(j["id"])

    def test_pull_batch_empty_returns_empty(self, queue):
        """Batch pull from empty queue returns empty list."""
        jobs = queue.pull_batch("tasks", limit=10)
        assert jobs == []

    def test_pull_batch_fewer_than_limit(self, queue):
        """Batch pull returns available jobs even if fewer than limit."""
        queue.push("tasks", {"task": 1})
        queue.push("tasks", {"task": 2})

        jobs = queue.pull_batch("tasks", limit=10)

        assert len(jobs) == 2

        for j in jobs:
            queue.ack(j["id"])


class TestPullAny:
    """Test multi-queue pull functionality."""

    def test_pull_any_checks_queues_in_order(self, queue):
        """pull_any checks queues in specified order."""
        queue.push("low", {"priority": "low"})
        queue.push("high", {"priority": "high"})

        # high is checked first
        job = queue.pull_any(["high", "low"])
        assert job["payload"]["priority"] == "high"
        queue.ack(job["id"])

        # Now low is returned
        job2 = queue.pull_any(["high", "low"])
        assert job2["payload"]["priority"] == "low"
        queue.ack(job2["id"])

    def test_pull_any_skips_empty_queues(self, queue):
        """pull_any skips empty queues."""
        queue.push("low", {"data": 1})
        # high is empty

        job = queue.pull_any(["high", "low"])
        assert job is not None
        assert job["queue"] == "low"
        queue.ack(job["id"])

    def test_pull_any_all_empty_returns_none(self, queue):
        """pull_any returns None when all queues empty."""
        job = queue.pull_any(["high", "medium", "low"])
        assert job is None

    def test_pull_any_empty_list_returns_none(self, queue):
        """pull_any with empty queue list returns None without error."""
        job = queue.pull_any([])
        assert job is None


class TestVisibilityTimeout:
    """Test visibility timeout behavior."""

    @staticmethod
    def _pull(queue, method, timeout):
        if method == "pull":
            return queue.pull("tasks", visibility_timeout=timeout)
        if method == "pull_batch":
            jobs = queue.pull_batch("tasks", visibility_timeout=timeout)
            return jobs[0] if jobs else None
        return queue.pull_any(["tasks"], visibility_timeout=timeout)

    @pytest.mark.parametrize("method", ["pull", "pull_batch", "pull_any"])
    def test_null_override_uses_valid_config_default(self, queue, method):
        job_id = queue.push("tasks", {"ok": True})

        job = self._pull(queue, method, None)

        assert job is not None
        assert job["id"] == job_id
        assert job["attempts"] == 1
        assert job["visibility_timeout_at"] > job["locked_at"]

    @pytest.mark.parametrize("method", ["pull", "pull_batch", "pull_any"])
    @pytest.mark.parametrize("timeout", [timedelta(0), timedelta(seconds=-1)])
    def test_non_positive_timeout_is_atomic(self, queue, method, timeout):
        job_id = queue.push("tasks", {"task": 1})

        with pytest.raises(QueueValidationError) as exc_info:
            self._pull(queue, method, timeout)

        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == QueueErrorCode.VAL_INTERVAL_NOT_POSITIVE

        stats = queue.get_stats()
        assert stats["pending"] == 1
        assert stats["running"] == 0
        assert queue.release_jobs("anonymous") == 0
        assert queue.extend_visibility(job_id, timedelta(minutes=1)) is False
        assert queue.tick_timeouts() == []

        job = self._pull(queue, method, timedelta(minutes=1))
        assert job is not None
        assert job["id"] == job_id
        assert job["attempts"] == 1
        assert job["locked_by"] == "anonymous"
        assert job["locked_at"] is not None
        assert job["visibility_timeout_at"] > job["locked_at"]

    def test_extend_visibility_success(self, queue):
        """extend_visibility returns True for running job."""
        queue.push("tasks", {"task": 1})
        job = queue.pull("tasks")

        result = queue.extend_visibility(job["id"], timedelta(minutes=10))
        assert result is True

        queue.ack(job["id"])

    def test_extend_visibility_not_running(self, queue):
        """extend_visibility returns False for non-running job."""
        job_id = queue.push("tasks", {"task": 1})

        # Job is pending, not running
        result = queue.extend_visibility(job_id, timedelta(minutes=10))
        assert result is False

    def test_extend_visibility_not_found(self, queue):
        """extend_visibility returns False for nonexistent job."""
        result = queue.extend_visibility(999999, timedelta(minutes=10))
        assert result is False

    @pytest.mark.parametrize(
        "extension",
        [timedelta(0), timedelta(seconds=-30)],
        ids=["zero", "negative"],
    )
    def test_extend_visibility_rejects_non_positive_extension(self, queue, extension):
        """Non-positive extension is rejected."""
        queue.push("tasks", {"task": 1})
        job = queue.pull("tasks")

        with pytest.raises(QueueValidationError) as exc_info:
            queue.extend_visibility(job["id"], extension)
        assert exc_info.value.error_code == QueueErrorCode.VAL_EXTENSION_POSITIVE

        queue.ack(job["id"])
