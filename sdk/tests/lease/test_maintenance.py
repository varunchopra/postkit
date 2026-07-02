"""Tests for get_stats, get_events, and prune_events."""

from datetime import timedelta

import pytest
from postkit.lease import LeaseErrorCode, LeaseValidationError


class TestGetStats:
    def test_counts(self, lease, test_helpers):
        got_live = lease.acquire("live", "w1")
        lease.acquire("dead", "w1")
        test_helpers.set_expires_at("dead", "-1 second")
        got_released = lease.acquire("gone", "w1")
        lease.release("gone", "w1", got_released["fence_token"])

        stats = lease.get_stats()
        assert stats["total_leases"] == 2
        assert stats["live"] == 1
        assert stats["expired"] == 1
        # Counter rows survive release: all three names ever used
        assert stats["total_names"] == 3
        # acquired x3 + released x1
        assert stats["total_events"] == 4
        assert got_live["acquired"] is True

    def test_empty_namespace(self, lease):
        stats = lease.get_stats()
        assert stats["total_leases"] == 0
        assert stats["total_events"] == 0


class TestGetEvents:
    def test_newest_first_with_limit(self, lease):
        for i in range(3):
            got = lease.acquire("job", f"w{i}")
            lease.release("job", f"w{i}", got["fence_token"])

        events = lease.get_events("job", limit=2)
        assert len(events) == 2
        assert [e["event"] for e in events] == ["released", "acquired"]
        assert events[0]["id"] > events[1]["id"]

    def test_name_filter(self, lease):
        lease.acquire("a", "w1")
        lease.acquire("b", "w1")

        assert {e["name"] for e in lease.get_events()} == {"a", "b"}
        assert {e["name"] for e in lease.get_events("a")} == {"a"}

    def test_limit_must_be_positive(self, lease):
        with pytest.raises(LeaseValidationError) as exc_info:
            lease.get_events(limit=0)
        assert exc_info.value.error_code == LeaseErrorCode.VAL_NOT_POSITIVE


class TestPruneEvents:
    def test_prunes_only_old_events(self, lease, test_helpers):
        got = lease.acquire("old", "w1")
        lease.release("old", "w1", got["fence_token"])
        test_helpers.age_events("40 days")
        lease.acquire("fresh", "w1")

        deleted = lease.prune_events(timedelta(days=30))
        assert deleted == 2  # old's acquired + released
        assert [e["name"] for e in lease.get_events()] == ["fresh"]

    def test_name_filter(self, lease, test_helpers):
        lease.acquire("a", "w1")
        lease.acquire("b", "w1")
        test_helpers.age_events("40 days")

        assert lease.prune_events(timedelta(days=30), name="a") == 1
        assert {e["name"] for e in lease.get_events()} == {"b"}

    def test_nothing_to_prune(self, lease):
        lease.acquire("job", "w1")
        assert lease.prune_events(timedelta(days=30)) == 0

    def test_retention_required_and_positive(self, lease):
        """No default retention: the event log is the audit surface, so
        deleting history requires an explicit, positive interval."""
        with pytest.raises(TypeError):
            lease.prune_events()  # older_than is a required argument

        with pytest.raises(LeaseValidationError) as exc_info:
            lease.prune_events(timedelta(seconds=-1))
        assert (
            exc_info.value.error_code == LeaseErrorCode.VAL_PRUNE_INTERVAL_NOT_POSITIVE
        )
