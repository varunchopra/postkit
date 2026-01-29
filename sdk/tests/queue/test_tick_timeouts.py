"""Tests for visibility timeout recovery via tick_timeouts."""

from datetime import timedelta


class TestTickTimeouts:
    """Test tick_timeouts reclaims stuck running jobs."""

    def _make_stuck_job(self, queue, queue_name="tasks", timeout_seconds=300):
        """Push and pull a job, then backdate its visibility timeout."""
        queue.push(queue_name, {"action": "process"})
        job = queue.pull(
            queue_name, visibility_timeout=timedelta(seconds=timeout_seconds)
        )
        # Backdate visibility_timeout_at to simulate expiry.
        queue.cursor.execute(
            "UPDATE queue.jobs SET visibility_timeout_at = now() - interval '1 minute' "
            "WHERE namespace = %s AND id = %s",
            (queue.namespace, job["id"]),
        )
        return job

    def test_reclaims_expired_running_job(self, queue):
        """Timed-out running job is returned to pending."""
        job = self._make_stuck_job(queue)

        results = queue.tick_timeouts()
        assert len(results) == 1
        assert results[0]["job_id"] == job["id"]
        assert results[0]["queue"] == "tasks"

        # Job should be pending again.
        stats = queue.get_stats()
        assert stats["pending"] == 1
        assert stats["running"] == 0

    def test_preserves_attempt_count(self, queue):
        """Reclaimed job keeps its attempts counter (not reset)."""
        job = self._make_stuck_job(queue)

        queue.tick_timeouts()

        queue.cursor.execute(
            "SELECT attempts FROM queue.jobs WHERE namespace = %s AND id = %s",
            (queue.namespace, job["id"]),
        )
        row = queue.cursor.fetchone()
        # attempts=1 from the pull; tick_timeouts does NOT reset it.
        assert row[0] == 1

    def test_clears_lock_fields(self, queue):
        """Reclaimed job has NULL locked_by, locked_at, visibility_timeout_at."""
        job = self._make_stuck_job(queue)

        queue.tick_timeouts()

        queue.cursor.execute(
            "SELECT locked_by, locked_at, visibility_timeout_at "
            "FROM queue.jobs WHERE namespace = %s AND id = %s",
            (queue.namespace, job["id"]),
        )
        row = queue.cursor.fetchone()
        assert row[0] is None  # locked_by
        assert row[1] is None  # locked_at
        assert row[2] is None  # visibility_timeout_at

    def test_does_not_reclaim_unexpired_job(self, queue):
        """Running jobs whose timeout has not expired are left alone."""
        queue.push("tasks", {"action": "running"})
        queue.pull("tasks", visibility_timeout=timedelta(hours=1))

        results = queue.tick_timeouts()
        assert len(results) == 0

    def test_does_not_touch_pending_jobs(self, queue):
        """Pending jobs are never affected by tick_timeouts."""
        queue.push("tasks", {"action": "pending"})

        results = queue.tick_timeouts()
        assert len(results) == 0

    def test_respects_limit(self, queue):
        """Limit caps the number of jobs reclaimed."""
        for _ in range(3):
            self._make_stuck_job(queue)

        results = queue.tick_timeouts(limit=2)
        assert len(results) == 2

    def test_returns_stuck_duration(self, queue):
        """Result includes a positive stuck_duration interval."""
        self._make_stuck_job(queue)

        results = queue.tick_timeouts()
        assert len(results) == 1
        assert results[0]["stuck_duration"] is not None
        assert results[0]["stuck_duration"] > timedelta(0)

    def test_reclaimed_job_is_pullable(self, queue):
        """After tick_timeouts, the job can be pulled again."""
        job = self._make_stuck_job(queue)

        queue.tick_timeouts()

        repulled = queue.pull("tasks")
        assert repulled is not None
        assert repulled["id"] == job["id"]
        # attempts=2: 1 from first pull + 1 from this pull.
        assert repulled["attempts"] == 2

    def test_empty_result_when_no_stuck_jobs(self, queue):
        """Returns empty list when no jobs have expired timeouts."""
        results = queue.tick_timeouts()
        assert results == []

    def test_only_reclaims_in_own_namespace(self, make_queue):
        """tick_timeouts only reclaims jobs from the caller's namespace."""
        q_a = make_queue("timeout_ns_a")
        q_b = make_queue("timeout_ns_b")

        # Create stuck job in namespace A.
        q_a.push("tasks", {"ns": "a"})
        job_a = q_a.pull("tasks")
        q_a.cursor.execute(
            "UPDATE queue.jobs SET visibility_timeout_at = now() - interval '1 minute' "
            "WHERE namespace = %s AND id = %s",
            ("timeout_ns_a", job_a["id"]),
        )

        # Create stuck job in namespace B.
        q_b.push("tasks", {"ns": "b"})
        job_b = q_b.pull("tasks")
        q_b.cursor.execute(
            "UPDATE queue.jobs SET visibility_timeout_at = now() - interval '1 minute' "
            "WHERE namespace = %s AND id = %s",
            ("timeout_ns_b", job_b["id"]),
        )

        # tick_timeouts from namespace A only reclaims A's job.
        results = q_a.tick_timeouts()
        assert len(results) == 1
        assert results[0]["job_id"] == job_a["id"]

        # B's job is still stuck.
        stats_b = q_b.get_stats()
        assert stats_b["running"] == 1
