"""Tests for per-queue statistics."""


class TestGetQueueStats:
    """Test get_queue_stats returns per-queue breakdown with operational metrics."""

    def test_returns_per_queue_breakdown(self, queue):
        """Returns one row per queue with status counts."""
        queue.push("email", {"to": "alice"})
        queue.push("email", {"to": "bob"})
        queue.push("billing", {"amount": 100})

        stats = queue.get_queue_stats()
        assert len(stats) == 2

        by_queue = {s["queue"]: s for s in stats}
        assert by_queue["email"]["pending"] == 2
        assert by_queue["billing"]["pending"] == 1

    def test_single_queue_filter(self, queue):
        """Passing queue filters to a single queue."""
        queue.push("email", {"to": "alice"})
        queue.push("billing", {"amount": 100})

        stats = queue.get_queue_stats(queue="email")
        assert len(stats) == 1
        assert stats[0]["queue"] == "email"
        assert stats[0]["pending"] == 1

    def test_includes_oldest_pending_seconds(self, queue):
        """oldest_pending_seconds is positive for jobs that have been waiting."""
        queue.push("tasks", {"task": 1})

        # Backdate scheduled_at so oldest_pending_seconds is measurable.
        queue.cursor.execute(
            "UPDATE queue.jobs SET scheduled_at = now() - interval '10 seconds' "
            "WHERE namespace = %s",
            (queue.namespace,),
        )

        stats = queue.get_queue_stats(queue="tasks")
        assert len(stats) == 1
        assert stats[0]["oldest_pending_seconds"] >= 10

    def test_oldest_pending_null_when_no_pending(self, queue):
        """oldest_pending_seconds is None when no pending jobs exist."""
        queue.push("tasks", {"task": 1})
        job = queue.pull("tasks")
        queue.ack(job["id"], job["fence_token"])

        # Push a new job and pull it so queue has only running jobs.
        queue.push("tasks", {"task": 2})
        queue.pull("tasks")

        stats = queue.get_queue_stats(queue="tasks")
        assert len(stats) == 1
        assert stats[0]["oldest_pending_seconds"] is None

    def test_includes_dead_letter_count(self, queue):
        """dead_letters column reflects DLQ entries for the queue."""
        queue.push("tasks", {"task": 1})
        queue.push("tasks", {"task": 2})

        # Fail both jobs to DLQ.
        for _ in range(2):
            job = queue.pull("tasks")
            queue.fail(job["id"], job["fence_token"], error="test")

        stats = queue.get_queue_stats(queue="tasks")
        assert len(stats) == 1
        assert stats[0]["dead_letters"] == 2

    def test_empty_namespace_returns_empty(self, queue):
        """Returns empty list when namespace has no jobs."""
        stats = queue.get_queue_stats()
        assert stats == []

    def test_dead_letters_excludes_retried(self, queue):
        """dead_letters counts only un-retried entries (actionable failures)."""
        # Create two dead letters.
        for i in range(2):
            queue.push("tasks", {"task": i})
            job = queue.pull("tasks")
            queue.fail(job["id"], job["fence_token"], error=f"failure {i}")

        stats = queue.get_queue_stats(queue="tasks")
        assert stats[0]["dead_letters"] == 2

        # Retry one dead letter.
        queue.cursor.execute(
            "SELECT id FROM queue.dead_letters "
            "WHERE namespace = %s AND retried_at IS NULL ORDER BY id LIMIT 1",
            (queue.namespace,),
        )
        dl_id = queue.cursor.fetchone()[0]
        queue.retry_dead_letter(dl_id)

        # Only the un-retried entry should count.
        stats = queue.get_queue_stats(queue="tasks")
        assert stats[0]["dead_letters"] == 1

    def test_counts_all_statuses(self, queue):
        """Counts pending, running, and dead jobs correctly."""
        queue.push("tasks", {"task": "pending"})
        queue.push("tasks", {"task": "running"})
        queue.push("tasks", {"task": "dead"})

        # Pull one (running), fail one (dead), leave one (pending).
        queue.pull("tasks")  # Now running.
        job_fail = queue.pull("tasks")
        queue.fail(job_fail["id"], job_fail["fence_token"], error="test")

        stats = queue.get_queue_stats(queue="tasks")
        assert len(stats) == 1
        assert stats[0]["pending"] == 1
        assert stats[0]["running"] == 1
        assert stats[0]["completed"] == 0  # Default config deletes on ack.
        assert stats[0]["dead"] == 1

    def test_completed_count_with_archive(self, queue):
        """completed column reflects archived jobs when archive_completed is enabled."""
        # Enable archive mode so ack retains jobs with status='completed'.
        queue.cursor.execute(
            "INSERT INTO queue.config (namespace, archive_completed) VALUES (%s, true)",
            (queue.namespace,),
        )

        queue.push("tasks", {"task": "keep"})
        job = queue.pull("tasks")
        queue.ack(job["id"], job["fence_token"])

        stats = queue.get_queue_stats(queue="tasks")
        assert len(stats) == 1
        assert stats[0]["completed"] == 1
