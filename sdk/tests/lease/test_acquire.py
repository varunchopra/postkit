"""Tests for lease.acquire branch semantics via the SDK client."""

from datetime import timedelta, timezone

import pytest
from postkit.lease import LeaseErrorCode, LeaseValidationError


class TestFreshAcquire:
    def test_fresh_acquire_fields(self, lease):
        got = lease.acquire("scheduler", "w1")
        assert got["acquired"] is True
        assert got["fence_token"] == 1
        assert got["current_holder"] == "w1"
        assert got["expires_at"].tzinfo is not None

    def test_metadata_roundtrip(self, lease, test_helpers):
        lease.acquire("scheduler", "w1", metadata={"region": "us-east", "pid": 42})
        row = test_helpers.get_lease_row("scheduler")
        assert row["metadata"] == {"region": "us-east", "pid": 42}

    def test_ttl_defaults_from_config(self, lease, test_helpers):
        test_helpers.set_config(default_ttl=timedelta(minutes=5))
        got = lease.acquire("scheduler", "w1")
        row = test_helpers.get_lease_row("scheduler")
        lifetime = row["expires_at"] - row["acquired_at"]
        assert lifetime == timedelta(minutes=5)
        assert got["expires_at"] == row["expires_at"]

    def test_explicit_ttl(self, lease, test_helpers):
        lease.acquire("scheduler", "w1", ttl=timedelta(seconds=90))
        row = test_helpers.get_lease_row("scheduler")
        assert row["expires_at"] - row["acquired_at"] == timedelta(seconds=90)

    def test_ttl_exceeding_max_rejected(self, lease):
        with pytest.raises(LeaseValidationError) as exc_info:
            lease.acquire("scheduler", "w1", ttl=timedelta(days=2))
        assert exc_info.value.error_code == LeaseErrorCode.VAL_TTL_EXCEEDS_MAX

    def test_ttl_not_positive_rejected(self, lease):
        with pytest.raises(LeaseValidationError) as exc_info:
            lease.acquire("scheduler", "w1", ttl=timedelta(seconds=-5))
        assert exc_info.value.error_code == LeaseErrorCode.VAL_TTL_NOT_POSITIVE


class TestExpiredTakeover:
    def test_expired_lease_taken_over(self, lease, test_helpers):
        first = lease.acquire("job", "w1")
        test_helpers.set_expires_at("job", "-1 second")

        second = lease.acquire("job", "w2")
        assert second["acquired"] is True
        assert second["fence_token"] > first["fence_token"]
        assert second["current_holder"] == "w2"

        events = test_helpers.get_events("job")
        assert events[-1]["event"] == "taken_over"
        assert events[-1]["previous_holder"] == "w1"
        assert events[-1]["holder_id"] == "w2"

    def test_own_expired_lease_is_takeover_with_new_fence(self, lease, test_helpers):
        first = lease.acquire("job", "w1")
        test_helpers.set_expires_at("job", "-1 second")

        again = lease.acquire("job", "w1")
        assert again["acquired"] is True
        assert again["fence_token"] > first["fence_token"]


class TestLiveReacquire:
    def test_same_holder_reacquire_renews_with_same_fence(self, lease, test_helpers):
        first = lease.acquire("job", "w1", metadata={"v": 1})
        again = lease.acquire("job", "w1", ttl=timedelta(minutes=10), metadata={"v": 2})
        assert again["acquired"] is True
        assert again["fence_token"] == first["fence_token"]

        # Unlike renew(), this branch also updates metadata
        row = test_helpers.get_lease_row("job")
        assert row["metadata"] == {"v": 2}
        assert row["expires_at"] == again["expires_at"]

    def test_other_holder_gets_observability_info(self, lease):
        first = lease.acquire("job", "w1")
        second = lease.acquire("job", "w2")
        assert second["acquired"] is False
        assert second["fence_token"] is None
        assert second["current_holder"] == "w1"
        assert second["expires_at"] == first["expires_at"]


class TestInspection:
    def test_current_returns_row_even_expired(self, lease, test_helpers):
        got = lease.acquire("job", "w1")
        test_helpers.set_expires_at("job", "-1 second")

        current = lease.current("job")
        assert current is not None
        assert current["holder_id"] == "w1"
        assert current["fence_token"] == got["fence_token"]
        assert current["expires_at"] < current["expires_at"].now(tz=timezone.utc)

    def test_current_absent(self, lease):
        assert lease.current("nothing") is None

    def test_list_filters_expired(self, lease, test_helpers):
        lease.acquire("live", "w1")
        lease.acquire("dead", "w1")
        test_helpers.set_expires_at("dead", "-1 second")

        names_all = {row["name"] for row in lease.list_leases()}
        assert names_all == {"live", "dead"}

        names_live = {row["name"] for row in lease.list_leases(include_expired=False)}
        assert names_live == {"live"}
