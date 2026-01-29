"""Tests for _format_interval helper.

Verifies that timedelta-to-PostgreSQL interval conversion uses exact
integer arithmetic, not float approximation.
"""

from datetime import timedelta

from postkit.queue.client import _format_interval


class TestFormatInterval:
    """Interval formatting for PostgreSQL compatibility."""

    def test_whole_seconds(self):
        assert _format_interval(timedelta(seconds=90)) == "0:01:30"

    def test_hours_minutes_seconds(self):
        assert _format_interval(timedelta(hours=1, minutes=30)) == "1:30:00"

    def test_sub_second_milliseconds(self):
        """Millisecond precision is preserved as microseconds."""
        assert _format_interval(timedelta(milliseconds=500)) == "0:00:00.500000"

    def test_sub_second_microseconds(self):
        """Single-microsecond precision is preserved."""
        assert (
            _format_interval(timedelta(seconds=90, microseconds=1)) == "0:01:30.000001"
        )

    def test_large_interval(self):
        """Intervals exceeding 24 hours produce correct hour counts."""
        # 2 days + 3 hours = 51 hours exactly.
        assert _format_interval(timedelta(days=2, hours=3)) == "51:00:00"

    def test_large_interval_with_minutes(self):
        """Days, hours, and minutes combine correctly."""
        # 1 day + 2 hours + 30 minutes = 26 hours 30 minutes.
        assert _format_interval(timedelta(days=1, hours=2, minutes=30)) == "26:30:00"

    def test_zero(self):
        assert _format_interval(timedelta(0)) == "0:00:00"

    def test_exact_one_microsecond(self):
        """Smallest representable sub-second interval."""
        assert _format_interval(timedelta(microseconds=1)) == "0:00:00.000001"

    def test_max_microseconds(self):
        """999999 microseconds does not roll over into seconds."""
        assert _format_interval(timedelta(microseconds=999999)) == "0:00:00.999999"
