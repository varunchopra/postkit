"""Tests for queue schedule CRUD operations."""

from datetime import timedelta

import pytest
from postkit.base import UniqueViolationError
from postkit.errors import QueueErrorCode
from postkit.queue import QueueValidationError


class TestCreateSchedule:
    """Test schedule creation with cron and interval modes."""

    def test_create_with_all_options(self, queue):
        """All optional parameters are stored correctly."""
        queue.create_schedule(
            "full_opts",
            "reports",
            {"type": "daily"},
            cron_expression="0 9 * * *",
            cron_timezone="America/New_York",
            priority=100,
            max_attempts=5,
            tags=["reports", "daily"],
            is_active=True,
        )

        schedule = queue.get_schedule("full_opts")
        assert schedule is not None
        assert schedule["payload"] == {"type": "daily"}
        assert schedule["cron_expression"] == "0 9 * * *"
        assert schedule["cron_timezone"] == "America/New_York"
        assert schedule["priority"] == 100
        assert schedule["max_attempts"] == 5
        assert schedule["tags"] == ["reports", "daily"]

    def test_create_rejects_max_attempts_out_of_range(self, queue):
        """max_attempts outside 1 to 30 raises validation error."""
        with pytest.raises(QueueValidationError) as exc_info:
            queue.create_schedule(
                "bad_attempts",
                "tasks",
                {"action": "noop"},
                every_interval=timedelta(hours=1),
                max_attempts=31,
            )
        assert exc_info.value.error_code == QueueErrorCode.VAL_MAX_ATTEMPTS_RANGE

    def test_create_inactive_schedule(self, queue):
        """Inactive schedule has no next_run_at."""
        queue.create_schedule(
            "paused_from_start",
            "tasks",
            {"action": "noop"},
            every_interval=timedelta(hours=1),
            is_active=False,
        )

        schedule = queue.get_schedule("paused_from_start")
        assert schedule is not None
        assert schedule["is_active"] is False
        assert schedule["next_run_at"] is None

    def test_create_populates_next_run_at(self, queue):
        """Active schedule has a non-null next_run_at."""
        queue.create_schedule(
            "active_sched",
            "tasks",
            {"action": "check"},
            every_interval=timedelta(minutes=10),
        )

        schedule = queue.get_schedule("active_sched")
        assert schedule is not None
        assert schedule["next_run_at"] is not None

    def test_create_rejects_duplicate_name(self, queue):
        """Duplicate schedule name within same namespace raises an error."""
        queue.create_schedule(
            "unique_name",
            "tasks",
            {"a": 1},
            every_interval=timedelta(hours=1),
        )

        with pytest.raises(UniqueViolationError) as exc_info:
            queue.create_schedule(
                "unique_name",
                "tasks",
                {"a": 2},
                every_interval=timedelta(hours=2),
            )

        assert exc_info.value.error_code == QueueErrorCode.BIZ_SCHEDULE_DUPLICATE

    def test_create_rejects_both_cron_and_interval(self, queue):
        """Cannot specify both cron_expression and every_interval."""
        with pytest.raises(QueueValidationError) as exc_info:
            queue.create_schedule(
                "invalid_both",
                "tasks",
                {"a": 1},
                cron_expression="0 * * * *",
                every_interval=timedelta(hours=1),
            )

        assert (
            exc_info.value.error_code == QueueErrorCode.BIZ_SCHEDULE_CRON_AND_INTERVAL
        )

    def test_create_rejects_neither_cron_nor_interval(self, queue):
        """Must specify at least one of cron_expression or every_interval."""
        with pytest.raises(QueueValidationError) as exc_info:
            queue.create_schedule(
                "invalid_neither",
                "tasks",
                {"a": 1},
            )

        assert (
            exc_info.value.error_code == QueueErrorCode.BIZ_SCHEDULE_REQUIRES_SCHEDULE
        )

    @pytest.mark.parametrize(
        "expression", ["*/0 * * * *", "*/00 * * * *", "1-5/0 * * * *"]
    )
    def test_create_rejects_zero_cron_step(self, queue, expression):
        with pytest.raises(QueueValidationError) as exc_info:
            queue.create_schedule(
                "zero_step", "tasks", {"a": 1}, cron_expression=expression
            )
        assert exc_info.value.error_code == QueueErrorCode.VAL_CRON_STEP_ZERO

    def test_cron_length_boundary(self, queue):
        expression = " " * 247 + "* * * * *"
        assert len(expression) == 256
        queue.create_schedule(
            "max_cron_length", "tasks", {"a": 1}, cron_expression=expression
        )

        with pytest.raises(QueueValidationError) as exc_info:
            queue.create_schedule(
                "oversized_cron",
                "tasks",
                {"a": 1},
                cron_expression=" " + expression,
            )
        assert exc_info.value.error_code == QueueErrorCode.VAL_CRON_TOO_LONG

    @pytest.mark.parametrize("expression", [" " * 257, "*/1" * 86])
    def test_oversized_cron_rejected_before_normalization(self, queue, expression):
        with pytest.raises(QueueValidationError) as exc_info:
            queue.create_schedule(
                "oversized_cron", "tasks", {"a": 1}, cron_expression=expression
            )
        assert exc_info.value.error_code == QueueErrorCode.VAL_CRON_TOO_LONG

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            ("0 9 * * 0", "0 9 * * 7"),
            ("0 9 * * 5-7", "0 9 * * 5,6,0"),
            ("0 9 * * 0,7", "0 9 * * 0"),
            ("0 0 15 * 0-7", "0 0 * * *"),
        ],
    )
    def test_equivalent_weekday_forms_have_same_next_run(self, queue, left, right):
        queue.create_schedule("left", "tasks", {"a": 1}, cron_expression=left)
        queue.create_schedule("right", "tasks", {"a": 1}, cron_expression=right)

        assert queue.get_schedule("left")["next_run_at"] == queue.get_schedule(
            "right"
        )["next_run_at"]

    @pytest.mark.parametrize(
        "interval", [timedelta(0), timedelta(seconds=-1), timedelta(days=-1)]
    )
    def test_create_rejects_non_positive_interval(self, queue, interval):
        with pytest.raises(QueueValidationError) as exc_info:
            queue.create_schedule(
                "bad_interval", "tasks", {"a": 1}, every_interval=interval
            )
        assert exc_info.value.error_code == QueueErrorCode.VAL_INTERVAL_NOT_POSITIVE

    @pytest.mark.parametrize(
        "interval", [timedelta(microseconds=1), timedelta(days=365)]
    )
    def test_create_accepts_positive_interval_boundaries(self, queue, interval):
        queue.create_schedule(
            "positive_interval", "tasks", {"a": 1}, every_interval=interval
        )
        assert queue.get_schedule("positive_interval") is not None


class TestGetSchedule:
    """Test schedule retrieval by name."""

    def test_get_existing_schedule(self, queue):
        """Returns all schedule fields for an existing schedule."""
        queue.create_schedule(
            "my_schedule",
            "email",
            {"to": "admin@example.com"},
            cron_expression="*/5 * * * *",
            cron_timezone="UTC",
            priority=10,
            max_attempts=5,
            tags=["alerts"],
        )

        schedule = queue.get_schedule("my_schedule")
        assert schedule is not None
        assert schedule["name"] == "my_schedule"
        assert schedule["queue"] == "email"
        assert schedule["payload"] == {"to": "admin@example.com"}
        assert schedule["priority"] == 10
        assert schedule["max_attempts"] == 5
        assert schedule["cron_expression"] == "*/5 * * * *"
        assert schedule["cron_timezone"] == "UTC"
        assert schedule["is_active"] is True
        assert schedule["run_count"] == 0
        assert schedule["tags"] == ["alerts"]

    def test_get_nonexistent_returns_none(self, queue):
        """Returns None for a schedule that does not exist."""
        schedule = queue.get_schedule("does_not_exist")
        assert schedule is None


class TestListSchedules:
    """Test schedule listing with filters and pagination."""

    def test_list_returns_ordered_by_name(self, queue):
        """Schedules are returned in alphabetical order by name."""
        for name in ["charlie", "alpha", "bravo"]:
            queue.create_schedule(
                name,
                "tasks",
                {"name": name},
                every_interval=timedelta(hours=1),
            )

        schedules = queue.list_schedules()
        names = [s["name"] for s in schedules]
        assert names == ["alpha", "bravo", "charlie"]

    def test_list_filter_by_queue(self, queue):
        """Filter schedules by target queue name."""
        queue.create_schedule(
            "email_sched",
            "email",
            {"a": 1},
            every_interval=timedelta(hours=1),
        )
        queue.create_schedule(
            "sms_sched",
            "sms",
            {"a": 2},
            every_interval=timedelta(hours=1),
        )

        email_schedules = queue.list_schedules(queue="email")
        assert len(email_schedules) == 1
        assert email_schedules[0]["name"] == "email_sched"

    def test_list_filter_by_active_status(self, queue):
        """Filter schedules by is_active flag."""
        queue.create_schedule(
            "active_one",
            "tasks",
            {"a": 1},
            every_interval=timedelta(hours=1),
            is_active=True,
        )
        queue.create_schedule(
            "paused_one",
            "tasks",
            {"a": 2},
            every_interval=timedelta(hours=1),
            is_active=False,
        )

        active = queue.list_schedules(is_active=True)
        assert len(active) == 1
        assert active[0]["name"] == "active_one"

        paused = queue.list_schedules(is_active=False)
        assert len(paused) == 1
        assert paused[0]["name"] == "paused_one"

    def test_list_cursor_pagination(self, queue):
        """Cursor-based pagination returns the next page."""
        for name in ["a_first", "b_second", "c_third"]:
            queue.create_schedule(
                name,
                "tasks",
                {"name": name},
                every_interval=timedelta(hours=1),
            )

        # First page: limit 2
        page1 = queue.list_schedules(limit=2)
        assert len(page1) == 2
        assert page1[0]["name"] == "a_first"
        assert page1[1]["name"] == "b_second"

        # Second page: cursor = last name from page 1
        page2 = queue.list_schedules(limit=2, cursor="b_second")
        assert len(page2) == 1
        assert page2[0]["name"] == "c_third"

    def test_list_empty_namespace(self, queue):
        """Returns empty list when no schedules exist."""
        schedules = queue.list_schedules()
        assert schedules == []


class TestDeleteSchedule:
    """Test schedule deletion."""

    def test_delete_existing_schedule(self, queue):
        """Deleting an existing schedule returns True."""
        queue.create_schedule(
            "to_delete",
            "tasks",
            {"a": 1},
            every_interval=timedelta(hours=1),
        )

        result = queue.delete_schedule("to_delete")
        assert result is True

        # Verify it is gone.
        assert queue.get_schedule("to_delete") is None

    def test_delete_nonexistent_returns_false(self, queue):
        """Deleting a nonexistent schedule returns False."""
        result = queue.delete_schedule("no_such_schedule")
        assert result is False


class TestPauseResumeSchedule:
    """Test pausing and resuming schedules."""

    def test_pause_active_schedule(self, queue):
        """Pausing an active schedule clears next_run_at."""
        queue.create_schedule(
            "pausable",
            "tasks",
            {"a": 1},
            every_interval=timedelta(hours=1),
        )

        result = queue.pause_schedule("pausable")
        assert result is True

        schedule = queue.get_schedule("pausable")
        assert schedule["is_active"] is False
        assert schedule["next_run_at"] is None

    def test_pause_already_paused_returns_false(self, queue):
        """Pausing an already-paused schedule returns False."""
        queue.create_schedule(
            "already_paused",
            "tasks",
            {"a": 1},
            every_interval=timedelta(hours=1),
            is_active=False,
        )

        result = queue.pause_schedule("already_paused")
        assert result is False

    def test_resume_paused_schedule(self, queue):
        """Resuming a paused schedule recalculates next_run_at."""
        queue.create_schedule(
            "resumable",
            "tasks",
            {"a": 1},
            every_interval=timedelta(hours=1),
        )
        queue.pause_schedule("resumable")

        result = queue.resume_schedule("resumable")
        assert result is True

        schedule = queue.get_schedule("resumable")
        assert schedule["is_active"] is True
        assert schedule["next_run_at"] is not None

    def test_resume_cron_schedule_recalculates_next_run(self, queue):
        """Resuming a cron schedule recalculates next_run_at via cron evaluation."""
        queue.create_schedule(
            "cron_resumable",
            "tasks",
            {"a": 1},
            cron_expression="0 * * * *",
        )
        queue.pause_schedule("cron_resumable")

        # Verify paused state.
        paused = queue.get_schedule("cron_resumable")
        assert paused["is_active"] is False
        assert paused["next_run_at"] is None

        result = queue.resume_schedule("cron_resumable")
        assert result is True

        schedule = queue.get_schedule("cron_resumable")
        assert schedule["is_active"] is True
        assert schedule["next_run_at"] is not None

    def test_resume_already_active_returns_false(self, queue):
        """Resuming an already-active schedule returns False."""
        queue.create_schedule(
            "already_active",
            "tasks",
            {"a": 1},
            every_interval=timedelta(hours=1),
        )

        result = queue.resume_schedule("already_active")
        assert result is False

    def test_pause_nonexistent_returns_false(self, queue):
        """Pausing a nonexistent schedule returns False."""
        result = queue.pause_schedule("ghost")
        assert result is False

    def test_resume_nonexistent_returns_false(self, queue):
        """Resuming a nonexistent schedule returns False."""
        result = queue.resume_schedule("ghost")
        assert result is False

    @pytest.mark.parametrize("interval", [timedelta(0), timedelta(seconds=-1)])
    def test_resume_rejects_corrupt_non_positive_interval(self, queue, interval):
        queue.create_schedule(
            "corrupt_interval",
            "tasks",
            {"a": 1},
            every_interval=timedelta(hours=1),
        )
        queue.pause_schedule("corrupt_interval")
        queue.cursor.execute(
            "UPDATE queue.schedules SET every_interval = %s "
            "WHERE namespace = %s AND name = 'corrupt_interval'",
            (interval, queue.namespace),
        )

        with pytest.raises(QueueValidationError) as exc_info:
            queue.resume_schedule("corrupt_interval")
        assert exc_info.value.error_code == QueueErrorCode.VAL_INTERVAL_NOT_POSITIVE
