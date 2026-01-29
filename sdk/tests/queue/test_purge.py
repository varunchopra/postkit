"""Tests for queue purge operations."""


class TestPurgeQueue:
    """Test purge_queue deletes pending jobs from a specific queue."""

    def test_purge_removes_pending_jobs(self, queue):
        """purge_queue deletes all pending jobs."""
        for i in range(5):
            queue.push("tasks", {"task": i})

        count = queue.purge_queue("tasks")
        assert count == 5

        stats = queue.get_stats()
        assert stats["pending"] == 0

    def test_purge_does_not_touch_running_jobs(self, queue):
        """purge_queue leaves running jobs alone."""
        queue.push("tasks", {"task": "pending"})
        queue.push("tasks", {"task": "running"})
        queue.pull("tasks")  # One job now running

        count = queue.purge_queue("tasks")
        assert count == 1  # Only the pending job

        stats = queue.get_stats()
        assert stats["running"] == 1

    def test_purge_returns_count(self, queue):
        """purge_queue returns the exact count of deleted jobs."""
        for i in range(3):
            queue.push("tasks", {"task": i})

        count = queue.purge_queue("tasks")
        assert count == 3

    def test_purge_scoped_to_queue(self, queue):
        """purge_queue only affects the specified queue."""
        queue.push("tasks", {"task": 1})
        queue.push("email", {"to": "alice"})

        count = queue.purge_queue("tasks")
        assert count == 1

        # Email queue unaffected.
        job = queue.pull("email")
        assert job is not None
        assert job["payload"] == {"to": "alice"}

    def test_purge_empty_queue_returns_zero(self, queue):
        """purge_queue returns 0 when queue has no pending jobs."""
        count = queue.purge_queue("tasks")
        assert count == 0
