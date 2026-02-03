"""Tests for cron expression parsing and next-run calculation."""

from datetime import datetime, timezone


class TestCronParseField:
    """Test internal _cron_parse_field function."""

    def test_star_returns_full_range(self, raw_cursor):
        cursor, _ = raw_cursor
        cursor.execute("SELECT queue._cron_parse_field('*', 0, 59)")
        assert cursor.fetchone()[0] == list(range(0, 60))

    def test_single_value(self, raw_cursor):
        cursor, _ = raw_cursor
        cursor.execute("SELECT queue._cron_parse_field('5', 0, 59)")
        assert cursor.fetchone()[0] == [5]

    def test_range(self, raw_cursor):
        cursor, _ = raw_cursor
        cursor.execute("SELECT queue._cron_parse_field('1-5', 0, 59)")
        assert cursor.fetchone()[0] == [1, 2, 3, 4, 5]

    def test_step_on_star(self, raw_cursor):
        cursor, _ = raw_cursor
        cursor.execute("SELECT queue._cron_parse_field('*/15', 0, 59)")
        assert cursor.fetchone()[0] == [0, 15, 30, 45]

    def test_step_on_range(self, raw_cursor):
        cursor, _ = raw_cursor
        cursor.execute("SELECT queue._cron_parse_field('1-10/3', 0, 59)")
        assert cursor.fetchone()[0] == [1, 4, 7, 10]

    def test_list(self, raw_cursor):
        cursor, _ = raw_cursor
        cursor.execute("SELECT queue._cron_parse_field('1,3,5', 0, 59)")
        assert cursor.fetchone()[0] == [1, 3, 5]

    def test_filters_out_of_range_values(self, raw_cursor):
        """Values outside [min, max] are excluded from the result."""
        cursor, _ = raw_cursor

        # 7 is above max=6, so only 0 is kept (filtered, not clamped).
        cursor.execute("SELECT queue._cron_parse_field('0,7', 0, 6)")
        assert cursor.fetchone()[0] == [0]

        # 30 is above max=12, so result is empty.
        cursor.execute("SELECT queue._cron_parse_field('30', 1, 12)")
        assert cursor.fetchone()[0] == []

    def test_reverse_range_returns_empty(self, raw_cursor):
        """Reverse range like '5-1' produces empty result, matching standard cron."""
        cursor, _ = raw_cursor
        cursor.execute("SELECT queue._cron_parse_field('5-1', 0, 59)")
        assert cursor.fetchone()[0] == []


class TestCronNextRun:
    """Test _cron_next_run calculation."""

    def test_every_5_minutes(self, raw_cursor):
        """Next 5-minute mark after 10:03 is 10:05."""
        cursor, _ = raw_cursor
        cursor.execute(
            "SELECT queue._cron_next_run('*/5 * * * *', 'UTC', '2025-01-15 10:03:00+00'::timestamptz)"
        )
        result = cursor.fetchone()[0]
        assert result == datetime(2025, 1, 15, 10, 5, tzinfo=timezone.utc)

    def test_midnight_wraps_to_next_day(self, raw_cursor):
        """Midnight cron after 23:30 yields next day 00:00."""
        cursor, _ = raw_cursor
        cursor.execute(
            "SELECT queue._cron_next_run('0 0 * * *', 'UTC', '2025-01-15 23:30:00+00'::timestamptz)"
        )
        result = cursor.fetchone()[0]
        assert result == datetime(2025, 1, 16, 0, 0, tzinfo=timezone.utc)

    def test_day_of_week_monday(self, raw_cursor):
        """Monday-only cron from Wednesday finds next Monday."""
        cursor, _ = raw_cursor
        # 2025-01-15 is Wednesday, next Monday is 2025-01-20
        cursor.execute(
            "SELECT queue._cron_next_run('0 9 * * 1', 'UTC', '2025-01-15 10:00:00+00'::timestamptz)"
        )
        result = cursor.fetchone()[0]
        assert result == datetime(2025, 1, 20, 9, 0, tzinfo=timezone.utc)

    def test_monthly_first(self, raw_cursor):
        """1st of month cron from mid-month finds next month."""
        cursor, _ = raw_cursor
        cursor.execute(
            "SELECT queue._cron_next_run('0 0 1 * *', 'UTC', '2025-01-15 00:00:00+00'::timestamptz)"
        )
        result = cursor.fetchone()[0]
        assert result == datetime(2025, 2, 1, 0, 0, tzinfo=timezone.utc)

    def test_yearly(self, raw_cursor):
        """Yearly cron (Jan 1 midnight) from mid-year."""
        cursor, _ = raw_cursor
        cursor.execute(
            "SELECT queue._cron_next_run('0 0 1 1 *', 'UTC', '2025-06-15 00:00:00+00'::timestamptz)"
        )
        result = cursor.fetchone()[0]
        assert result == datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)


class TestCronEdgeCases:
    """Test edge cases in cron calculation."""

    def test_february_29_finds_leap_year(self, raw_cursor):
        """Feb 29 schedule from 2025 finds 2028 (next leap year)."""
        cursor, _ = raw_cursor
        cursor.execute(
            "SELECT queue._cron_next_run('0 0 29 2 *', 'UTC', '2025-01-01 00:00:00+00'::timestamptz)"
        )
        result = cursor.fetchone()[0]
        assert result == datetime(2028, 2, 29, 0, 0, tzinfo=timezone.utc)

    def test_day_31_skips_short_months(self, raw_cursor):
        """Day 31 after March 31 skips April (30 days) to May 31."""
        cursor, _ = raw_cursor
        cursor.execute(
            "SELECT queue._cron_next_run('0 0 31 * *', 'UTC', '2025-03-31 00:01:00+00'::timestamptz)"
        )
        result = cursor.fetchone()[0]
        assert result == datetime(2025, 5, 31, 0, 0, tzinfo=timezone.utc)

    def test_every_minute(self, raw_cursor):
        """Every-minute cron returns the next minute."""
        cursor, _ = raw_cursor
        cursor.execute(
            "SELECT queue._cron_next_run('* * * * *', 'UTC', '2025-01-15 10:30:00+00'::timestamptz)"
        )
        result = cursor.fetchone()[0]
        assert result == datetime(2025, 1, 15, 10, 31, tzinfo=timezone.utc)

    def test_impossible_schedule_returns_none(self, raw_cursor):
        """Feb 30 never exists; function returns NULL after exhausting search."""
        cursor, _ = raw_cursor
        cursor.execute(
            "SELECT queue._cron_next_run('0 0 30 2 *', 'UTC', '2025-01-01 00:00:00+00'::timestamptz)"
        )
        assert cursor.fetchone()[0] is None


class TestCronPosixOr:
    """Test POSIX OR semantics when both day-of-month and day-of-week are restricted."""

    def test_dom_or_dow_matches_earlier_dow(self, raw_cursor):
        """When both day-of-month and day-of-week are set, POSIX says match EITHER.

        '0 9 15 * 1' = 9 AM on the 15th of any month OR any Monday.
        From Wed Jan 15 2025 at 10:00 (15th already passed today),
        next Monday is Jan 20, next 15th is Feb 15. Monday comes first.
        """
        cursor, _ = raw_cursor
        cursor.execute(
            "SELECT queue._cron_next_run('0 9 15 * 1', 'UTC', "
            "'2025-01-15 10:00:00+00'::timestamptz)"
        )
        result = cursor.fetchone()[0]
        assert result == datetime(2025, 1, 20, 9, 0, tzinfo=timezone.utc)

    def test_step_on_wildcard_is_restricted(self, raw_cursor):
        """Step expressions like */2 are restricted — POSIX OR still applies.

        '0 0 */2 * 5' = midnight on odd-numbered days OR Fridays.
        From Sat Jan 4 2025 at 01:00: next odd day is Jan 5 (Sun),
        next Friday is Jan 10. Jan 5 comes first (dom match).
        """
        cursor, _ = raw_cursor
        cursor.execute(
            "SELECT queue._cron_next_run('0 0 */2 * 5', 'UTC', "
            "'2025-01-04 01:00:00+00'::timestamptz)"
        )
        result = cursor.fetchone()[0]
        assert result == datetime(2025, 1, 5, 0, 0, tzinfo=timezone.utc)


class TestCronTimezone:
    """Test timezone handling in cron calculation."""

    def test_new_york_offset(self, raw_cursor):
        """9 AM New York in January is 14:00 UTC (EST = UTC-5)."""
        cursor, _ = raw_cursor
        # Base: 14:30 UTC = 9:30 AM ET. Next 9 AM ET is next day at 14:00 UTC.
        cursor.execute(
            "SELECT queue._cron_next_run('0 9 * * *', 'America/New_York', '2025-01-15 14:30:00+00'::timestamptz)"
        )
        result = cursor.fetchone()[0]
        assert result == datetime(2025, 1, 16, 14, 0, tzinfo=timezone.utc)
