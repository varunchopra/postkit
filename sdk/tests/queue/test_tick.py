"""Tests for schedule tick processing."""

from datetime import datetime, timedelta, timezone


class TestTickSchedules:
    """Test tick_schedules job creation and state advancement."""

    def _make_due_schedule(self, queue, name, **kwargs):
        """Create a schedule and set its next_run_at to the past so tick picks it up."""
        queue.create_schedule(
            name,
            kwargs.pop("target_queue", "tasks"),
            kwargs.pop("payload", {"action": name}),
            **kwargs,
        )
        # Force the schedule to be due now by backdating next_run_at.
        queue.cursor.execute(
            "UPDATE queue.schedules SET next_run_at = now() - interval '1 minute' "
            "WHERE namespace = %s AND name = %s",
            (queue.namespace, name),
        )

    def test_tick_creates_job_from_interval_schedule(self, queue):
        """Tick creates a job for a due interval schedule."""
        self._make_due_schedule(
            queue,
            "interval_sched",
            every_interval=timedelta(hours=1),
        )

        results = queue.tick_schedules()
        assert len(results) == 1
        assert results[0]["schedule_name"] == "interval_sched"
        assert results[0]["job_id"] > 0

    def test_tick_creates_job_from_cron_schedule(self, queue):
        """Tick creates a job for a due cron schedule."""
        self._make_due_schedule(
            queue,
            "cron_sched",
            cron_expression="*/5 * * * *",
        )

        results = queue.tick_schedules()
        assert len(results) == 1
        assert results[0]["schedule_name"] == "cron_sched"
        assert results[0]["job_id"] > 0

    def test_tick_advances_next_run_at(self, queue):
        """After tick, next_run_at is in the future."""
        self._make_due_schedule(
            queue,
            "advancing",
            every_interval=timedelta(hours=2),
        )

        results = queue.tick_schedules()
        assert len(results) == 1

        # next_run_at returned by tick should be in the future.
        assert results[0]["next_run_at"] is not None

        # Verify the schedule state in the database.
        schedule = queue.get_schedule("advancing")
        assert schedule["next_run_at"] is not None
        assert schedule["next_run_at"] > datetime.now(timezone.utc)
        assert schedule["next_run_at"] == results[0]["next_run_at"]

    def test_tick_increments_run_count(self, queue):
        """Each tick increments the schedule's run_count."""
        self._make_due_schedule(
            queue,
            "counting",
            every_interval=timedelta(minutes=10),
        )

        queue.tick_schedules()
        schedule = queue.get_schedule("counting")
        assert schedule["run_count"] == 1

        # Backdate again so a second tick fires.
        queue.cursor.execute(
            "UPDATE queue.schedules SET next_run_at = now() - interval '1 minute' "
            "WHERE namespace = %s AND name = %s",
            (queue.namespace, "counting"),
        )

        queue.tick_schedules()
        schedule = queue.get_schedule("counting")
        assert schedule["run_count"] == 2

    def test_tick_sets_last_job_id(self, queue):
        """Tick updates last_job_id on the schedule."""
        self._make_due_schedule(
            queue,
            "tracked",
            every_interval=timedelta(hours=1),
        )

        results = queue.tick_schedules()
        schedule = queue.get_schedule("tracked")
        assert schedule["last_job_id"] == results[0]["job_id"]

    def test_tick_skips_inactive_schedules(self, queue):
        """Inactive schedules are not processed by tick."""
        queue.create_schedule(
            "inactive_sched",
            "tasks",
            {"a": 1},
            every_interval=timedelta(hours=1),
            is_active=False,
        )

        results = queue.tick_schedules()
        assert len(results) == 0

    def test_tick_skips_not_yet_due(self, queue):
        """Schedules whose next_run_at is in the future are skipped."""
        queue.create_schedule(
            "future_sched",
            "tasks",
            {"a": 1},
            every_interval=timedelta(hours=24),
        )
        # next_run_at is ~24 hours from now, so tick should skip it.

        results = queue.tick_schedules()
        assert len(results) == 0

    def test_tick_processes_multiple_due_schedules(self, queue):
        """Tick processes all due schedules in a single call."""
        for name in ["batch_a", "batch_b", "batch_c"]:
            self._make_due_schedule(
                queue,
                name,
                every_interval=timedelta(hours=1),
            )

        results = queue.tick_schedules()
        assert len(results) == 3

        names = sorted(r["schedule_name"] for r in results)
        assert names == ["batch_a", "batch_b", "batch_c"]

    def test_tick_respects_limit(self, queue):
        """Tick limit caps the number of schedules processed."""
        for name in ["limit_a", "limit_b", "limit_c"]:
            self._make_due_schedule(
                queue,
                name,
                every_interval=timedelta(hours=1),
            )

        results = queue.tick_schedules(limit=2)
        assert len(results) == 2

    def test_tick_created_job_is_pullable(self, queue):
        """Jobs created by tick inherit the schedule's payload and options."""
        self._make_due_schedule(
            queue,
            "pullable",
            target_queue="email",
            payload={"to": "test@example.com"},
            every_interval=timedelta(hours=1),
            priority=5,
            tags=["scheduled"],
        )

        queue.tick_schedules()

        job = queue.pull("email")
        assert job is not None
        assert job["payload"]["to"] == "test@example.com"
        # Verify schedule options propagated (non-defaults to prove it's not table defaults).
        assert job["priority"] == 5
        assert job["tags"] == ["scheduled"]

    def test_tick_captures_actor_context(self, queue):
        """Jobs created by tick inherit the caller's actor context."""
        self._make_due_schedule(
            queue,
            "audited",
            every_interval=timedelta(hours=1),
        )

        # Set actor context before ticking.
        queue.set_actor(
            actor_id="scheduler-cron",
            request_id="req-abc-123",
        )
        results = queue.tick_schedules()
        assert len(results) == 1

        # Verify actor context was stored on the job row.
        queue.cursor.execute(
            "SELECT actor_id, request_id FROM queue.jobs WHERE id = %s",
            (results[0]["job_id"],),
        )
        row = queue.cursor.fetchone()
        assert row[0] == "scheduler-cron"
        assert row[1] == "req-abc-123"

    def test_only_processes_own_namespace(self, make_queue):
        """tick_schedules only processes schedules from the caller's namespace."""
        q_a = make_queue("tick_ns_a")
        q_b = make_queue("tick_ns_b")

        self._make_due_schedule(q_a, "sched_a", every_interval=timedelta(hours=1))
        self._make_due_schedule(q_b, "sched_b", every_interval=timedelta(hours=1))

        # Tick from namespace A only processes A's schedule.
        results = q_a.tick_schedules()
        assert len(results) == 1
        assert results[0]["schedule_name"] == "sched_a"

        # B's schedule still due.
        results_b = q_b.tick_schedules()
        assert len(results_b) == 1
        assert results_b[0]["schedule_name"] == "sched_b"
