"""Tests for graceful worker shutdown via release_jobs."""

import pytest
from postkit.queue import QueueValidationError


class TestReleaseJobs:
    """Test release_jobs returns running jobs to pending."""

    def test_releases_jobs_for_worker(self, queue):
        """release_jobs returns running jobs held by worker to pending."""
        queue.push("tasks", {"task": 1})
        queue.push("tasks", {"task": 2})
        queue.pull("tasks", worker_id="worker-1")
        queue.pull("tasks", worker_id="worker-1")

        count = queue.release_jobs("worker-1")
        assert count == 2

        stats = queue.get_stats()
        assert stats["pending"] == 2
        assert stats["running"] == 0

    def test_returns_count_of_released_jobs(self, queue):
        """release_jobs returns the exact count of jobs released."""
        for i in range(5):
            queue.push("tasks", {"task": i})
            queue.pull("tasks", worker_id="w1")

        count = queue.release_jobs("w1")
        assert count == 5

    def test_does_not_affect_other_workers(self, queue):
        """release_jobs only releases jobs for the specified worker."""
        queue.push("tasks", {"task": 1})
        queue.push("tasks", {"task": 2})
        queue.pull("tasks", worker_id="worker-a")
        queue.pull("tasks", worker_id="worker-b")

        count = queue.release_jobs("worker-a")
        assert count == 1

        # worker-b's job is still running.
        stats = queue.get_stats()
        assert stats["running"] == 1

    def test_does_not_affect_pending_jobs(self, queue):
        """release_jobs only touches running jobs, not pending ones."""
        queue.push("tasks", {"task": 1})  # Stays pending

        count = queue.release_jobs("worker-1")
        assert count == 0

    def test_released_job_is_pullable(self, queue):
        """After release, the job can be pulled again by any worker."""
        queue.push("tasks", {"task": 1})
        job = queue.pull("tasks", worker_id="worker-1")

        queue.release_jobs("worker-1")

        repulled = queue.pull("tasks", worker_id="worker-2")
        assert repulled is not None
        assert repulled["id"] == job["id"]

    def test_preserves_attempt_count(self, queue):
        """Released jobs keep their attempts counter."""
        queue.push("tasks", {"task": 1})
        job = queue.pull("tasks", worker_id="worker-1")
        assert job["attempts"] == 1

        queue.release_jobs("worker-1")

        # Pull again — attempts should increment to 2.
        repulled = queue.pull("tasks", worker_id="worker-2")
        assert repulled["attempts"] == 2

    def test_clears_lock_fields(self, queue):
        """Released jobs have NULL locked_by, locked_at, visibility_timeout_at."""
        queue.push("tasks", {"task": 1})
        job = queue.pull("tasks", worker_id="worker-1")

        queue.release_jobs("worker-1")

        queue.cursor.execute(
            "SELECT locked_by, locked_at, visibility_timeout_at "
            "FROM queue.jobs WHERE namespace = %s AND id = %s",
            (queue.namespace, job["id"]),
        )
        row = queue.cursor.fetchone()
        assert row[0] is None  # locked_by
        assert row[1] is None  # locked_at
        assert row[2] is None  # visibility_timeout_at

    def test_null_worker_id_raises_error(self, queue):
        """release_jobs raises validation error when worker_id is None."""
        with pytest.raises(QueueValidationError):
            queue.release_jobs(None)  # type: ignore[arg-type]

    def test_returns_zero_for_unknown_worker(self, queue):
        """release_jobs returns 0 when no jobs match the worker_id."""
        queue.push("tasks", {"task": 1})
        queue.pull("tasks", worker_id="worker-1")

        count = queue.release_jobs("nonexistent-worker")
        assert count == 0
