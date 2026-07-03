"""Tests for lease.acquire branch semantics via the SDK client."""

import threading
from datetime import timedelta, timezone

import pytest
from postkit.lease import LeaseErrorCode, LeaseValidationError

from tests.lease.test_invariants import acquire


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

    def test_none_metadata_keeps_stored_value(self, lease, test_helpers):
        """Re-acquiring a live lease without metadata must keep what acquire
        stored - a keepalive loop passing nothing must not wipe it."""
        lease.acquire("job", "w1", metadata={"task": 123})
        again = lease.acquire("job", "w1")
        assert again["acquired"] is True
        assert test_helpers.get_lease_row("job")["metadata"] == {"task": 123}

    def test_other_holder_gets_observability_info(self, lease):
        first = lease.acquire("job", "w1")
        second = lease.acquire("job", "w2")
        assert second["acquired"] is False
        assert second["fence_token"] is None
        assert second["current_holder"] == "w1"
        assert second["expires_at"] == first["expires_at"]


class TestWallClockExpiry:
    def test_acquire_in_idle_transaction_stamps_the_present(
        self, test_helpers, connect
    ):
        """TTL math must use clock_timestamp(): acquiring inside a
        transaction that has been idling stamps acquired_at with the real
        present, not the pinned transaction start (which would backdate the
        lease and shorten its effective protection)."""
        ns = test_helpers.namespace
        conn = connect()
        cur = conn.cursor()
        cur.execute("SELECT 1")  # pins this transaction's now()

        checks = 0
        while True:
            cur.execute("SELECT clock_timestamp() - now() > interval '0.25 seconds'")
            if cur.fetchone()[0]:
                break
            checks += 1
            assert checks < 500, "wall clock never advanced past the pinned now()"
            threading.Event().wait(0.02)

        acquire(cur, ns, "job", "w1")
        cur.execute(
            "SELECT acquired_at - now() > interval '0.2 seconds', "
            "expires_at - acquired_at FROM lease.leases "
            "WHERE namespace = %s AND name = %s",
            (ns, "job"),
        )
        later_than_txn_start, lifetime = cur.fetchone()
        conn.commit()
        assert later_than_txn_start is True
        # Exact equality with the seeded default_ttl: acquire reads the
        # clock once, so the pair of timestamps cannot drift apart
        assert lifetime == timedelta(seconds=30)


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
