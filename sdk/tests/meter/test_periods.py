"""
Billing period management tests for postkit.meter.

Tests for:
- Period configuration (set_period_config)
- Period closure with carry-over and expiration (close_period)
- Period opening with allocation (open_period)
- Expired reservation cleanup (release_expired_reservations)
- Full period lifecycle integration
"""

from datetime import date

import pytest
from postkit.meter import MeterError, MeterErrorCode


class TestSetPeriodConfig:
    """Tests for meter.set_period_config() - configure billing period settings."""

    def test_creates_account_with_period_config(self, meter, test_helpers):
        """Setting period config on non-existent account creates it."""
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=10000,
            carry_over_limit=2000,
        )

        account = test_helpers.get_account_raw("alice", "llm_call", "tokens")
        assert account is not None
        assert account["period_start"] == date(2025, 1, 1)
        assert float(account["period_allocation"]) == 10000
        assert float(account["carry_over_limit"]) == 2000
        # Balance starts at 0 when created via set_period_config.
        assert float(account["balance"]) == 0

    def test_updates_existing_account_period_config(self, meter, test_helpers):
        """Setting period config on existing account updates only period fields."""
        # Create account with initial balance.
        meter.allocate("alice", "llm_call", 5000, "tokens")

        # Add period config.
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 2, 1),
            period_allocation=8000,
            carry_over_limit=1000,
        )

        account = test_helpers.get_account_raw("alice", "llm_call", "tokens")
        # Balance preserved from allocation.
        assert float(account["balance"]) == 5000
        # Period config updated.
        assert account["period_start"] == date(2025, 2, 1)
        assert float(account["period_allocation"]) == 8000
        assert float(account["carry_over_limit"]) == 1000

    def test_null_carry_over_limit_means_unlimited(self, meter, test_helpers):
        """NULL carry_over_limit allows unlimited rollover."""
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=10000,
            carry_over_limit=None,
        )

        account = test_helpers.get_account_raw("alice", "llm_call", "tokens")
        assert account["carry_over_limit"] is None

    def test_zero_carry_over_limit_means_no_rollover(self, meter, test_helpers):
        """Zero carry_over_limit means nothing carries forward."""
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=10000,
            carry_over_limit=0,
        )

        account = test_helpers.get_account_raw("alice", "llm_call", "tokens")
        assert float(account["carry_over_limit"]) == 0

    def test_config_with_resource(self, meter, test_helpers):
        """Period config can be set per resource."""
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource="claude-sonnet",
            period_start=date(2025, 1, 1),
            period_allocation=50000,
            carry_over_limit=10000,
        )

        account = test_helpers.get_account_raw(
            "alice", "llm_call", "tokens", "claude-sonnet"
        )
        assert account is not None
        assert float(account["period_allocation"]) == 50000


class TestClosePeriod:
    """Tests for meter.close_period() - end billing period with carry-over."""

    def test_closes_period_with_unlimited_carry_over(self, meter):
        """With NULL carry_over_limit, all available balance carries over."""
        # Setup: balance=1000, no carry-over limit.
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=1000,
            carry_over_limit=None,
        )
        meter.allocate("alice", "llm_call", 1000, "tokens")

        result = meter.close_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_end=date(2025, 1, 31),
        )

        # State: all 1000 carries over, nothing expires.
        assert float(result["expired"]) == 0
        assert float(result["carried_over"]) == 1000
        assert float(result["new_balance"]) == 1000

    def test_closes_period_with_limited_carry_over(self, meter):
        """With positive carry_over_limit, excess expires."""
        # Setup: balance=1000, carry_over_limit=200.
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=1000,
            carry_over_limit=200,
        )
        meter.allocate("alice", "llm_call", 1000, "tokens")

        result = meter.close_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_end=date(2025, 1, 31),
        )

        # State: 200 carries, 800 expires.
        assert float(result["expired"]) == 800
        assert float(result["carried_over"]) == 200
        assert float(result["new_balance"]) == 200

    def test_closes_period_with_zero_carry_over(self, meter):
        """With zero carry_over_limit, all available expires."""
        # Setup: balance=1000, carry_over_limit=0.
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=1000,
            carry_over_limit=0,
        )
        meter.allocate("alice", "llm_call", 1000, "tokens")

        result = meter.close_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_end=date(2025, 1, 31),
        )

        # State: everything expires.
        assert float(result["expired"]) == 1000
        assert float(result["carried_over"]) == 0
        assert float(result["new_balance"]) == 0

    def test_closes_period_respects_reserved_balance(self, meter):
        """Reserved balance is excluded from carry-over/expiration calculations."""
        # Setup: balance=1000, reserved=400, available=600, carry_over_limit=300.
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=1000,
            carry_over_limit=300,
        )
        meter.allocate("alice", "llm_call", 1000, "tokens")
        meter.reserve("alice", "llm_call", 400, "tokens", ttl_seconds=3600)

        result = meter.close_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_end=date(2025, 1, 31),
        )

        # Available = 1000 - 400 = 600.
        # Carry = min(600, 300) = 300.
        # Expire = 600 - 300 = 300.
        # New balance = 1000 - 300 = 700 (reserved 400 + carried 300).
        assert float(result["expired"]) == 300
        assert float(result["carried_over"]) == 300
        assert float(result["new_balance"]) == 700

    def test_closes_period_creates_expiration_ledger_entry(self, meter, test_helpers):
        """Period closure with expiration creates an expiration ledger entry."""
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=1000,
            carry_over_limit=200,
        )
        meter.allocate("alice", "llm_call", 1000, "tokens")

        meter.close_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_end=date(2025, 1, 31),
        )

        # Verify expiration ledger entry exists with correct amount.
        expiration_count = test_helpers.count_ledger_entries("expiration")
        assert expiration_count == 1

        # Balance=1000, carry_over_limit=200 → 800 expired.
        ledger = meter.get_ledger("alice", "llm_call", "tokens")
        expiration = [e for e in ledger if e["entry_type"] == "expiration"][0]
        assert expiration["amount"] == -800
        assert expiration["balance_after"] == 200

    def test_closes_period_no_expiration_entry_when_nothing_expires(
        self, meter, test_helpers
    ):
        """No expiration ledger entry created when nothing expires."""
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=1000,
            carry_over_limit=None,
        )
        meter.allocate("alice", "llm_call", 1000, "tokens")

        meter.close_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_end=date(2025, 1, 31),
        )

        # No expiration entry.
        expiration_count = test_helpers.count_ledger_entries("expiration")
        assert expiration_count == 0

    def test_closes_period_nonexistent_account_returns_zeros(self, meter):
        """Closing period for non-existent account returns zeros safely."""
        result = meter.close_period(
            user_id="nonexistent",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_end=date(2025, 1, 31),
        )

        assert float(result["expired"]) == 0
        assert float(result["carried_over"]) == 0
        assert float(result["new_balance"]) == 0


class TestOpenPeriod:
    """Tests for meter.open_period() - start new billing period with allocation."""

    def test_opens_period_with_explicit_allocation(self, meter):
        """Open period with explicit allocation amount."""
        # Create account first.
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=10000,
            carry_over_limit=2000,
        )

        new_balance = meter.open_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 2, 1),
            allocation=5000,
        )

        # Explicit allocation used, not period_allocation.
        assert new_balance == 5000

    def test_opens_period_with_default_allocation(self, meter):
        """Open period uses period_allocation when allocation not specified."""
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=10000,
            carry_over_limit=2000,
        )

        new_balance = meter.open_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 2, 1),
            allocation=None,
        )

        # Uses period_allocation from config.
        assert new_balance == 10000

    def test_opens_period_adds_to_existing_balance(self, meter):
        """Open period adds allocation to existing balance (carry-over scenario)."""
        # Setup account with carry-over balance.
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=10000,
            carry_over_limit=2000,
        )
        meter.allocate("alice", "llm_call", 2000, "tokens")

        # State: balance=2000 (simulating carry-over).
        new_balance = meter.open_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 2, 1),
            allocation=10000,
        )

        # 2000 (carried) + 10000 (allocated) = 12000.
        assert new_balance == 12000

    def test_opens_period_creates_allocation_ledger_entry(self, meter, test_helpers):
        """Period opening creates an allocation ledger entry."""
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=10000,
            carry_over_limit=2000,
        )

        meter.open_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 2, 1),
        )

        # Verify allocation ledger entry exists with correct amount.
        allocation_count = test_helpers.count_ledger_entries("allocation")
        assert allocation_count == 1

        ledger = meter.get_ledger("alice", "llm_call", "tokens")
        allocation = [e for e in ledger if e["entry_type"] == "allocation"][0]
        assert allocation["amount"] == 10000
        assert allocation["balance_after"] == 10000

    def test_opens_period_updates_period_start(self, meter, test_helpers):
        """Open period updates the account's period_start date."""
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=10000,
            carry_over_limit=2000,
        )

        meter.open_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 2, 1),
        )

        account = test_helpers.get_account_raw("alice", "llm_call", "tokens")
        assert account["period_start"] == date(2025, 2, 1)

    def test_opens_period_nonexistent_account_raises(self, meter):
        """Opening period for non-existent account raises error."""
        with pytest.raises(MeterError) as exc_info:
            meter.open_period(
                user_id="nonexistent",
                event_type="llm_call",
                unit="tokens",
                resource=None,
                period_start=date(2025, 2, 1),
                allocation=10000,
            )
        assert exc_info.value.error_code == MeterErrorCode.DATA_ACCOUNT_NOT_FOUND

    def test_opens_period_no_allocation_raises(self, meter):
        """Opening period without allocation (explicit or default) raises."""
        # Create account without period_allocation.
        meter.allocate("alice", "llm_call", 1000, "tokens")

        with pytest.raises(MeterError) as exc_info:
            meter.open_period(
                user_id="alice",
                event_type="llm_call",
                unit="tokens",
                resource=None,
                period_start=date(2025, 2, 1),
                allocation=None,
            )
        assert exc_info.value.error_code == MeterErrorCode.VAL_ALLOCATION_REQUIRED


class TestPeriodLifecycle:
    """Integration tests for complete period lifecycle: config -> close -> open."""

    def test_monthly_billing_cycle(self, meter, test_helpers):
        """Full monthly billing cycle: allocate, consume, close, open."""
        # January setup.
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=10000,
            carry_over_limit=2000,
        )
        meter.open_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
        )

        # State: balance=10000.
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 10000

        # Consume 7000 during January.
        meter.consume("alice", "llm_call", 7000, "tokens")

        # State: balance=3000.
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 3000

        # Close January.
        result = meter.close_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_end=date(2025, 1, 31),
        )

        # 3000 available, carry_over_limit=2000, so 1000 expires.
        assert float(result["expired"]) == 1000
        assert float(result["carried_over"]) == 2000
        assert float(result["new_balance"]) == 2000

        # Open February.
        new_balance = meter.open_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 2, 1),
        )

        # 2000 (carried) + 10000 (new allocation) = 12000.
        assert new_balance == 12000

    def test_period_close_then_open_sequence(self, meter):
        """Close and open must be called in sequence for proper accounting."""
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=10000,
            carry_over_limit=0,
        )
        meter.allocate("alice", "llm_call", 5000, "tokens")

        # Close period (all expires with carry_over_limit=0).
        result = meter.close_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_end=date(2025, 1, 31),
        )
        assert float(result["new_balance"]) == 0

        # Open new period.
        new_balance = meter.open_period(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 2, 1),
        )
        assert new_balance == 10000

    def test_multiple_period_transitions(self, meter):
        """Multiple period transitions accumulate correctly."""
        meter.set_period_config(
            user_id="alice",
            event_type="llm_call",
            unit="tokens",
            resource=None,
            period_start=date(2025, 1, 1),
            period_allocation=1000,
            carry_over_limit=500,
        )

        # Period 1: allocate 1000, use 200, close (carry 500, expire 300).
        meter.open_period("alice", "llm_call", "tokens", None, date(2025, 1, 1))
        meter.consume("alice", "llm_call", 200, "tokens")
        meter.close_period("alice", "llm_call", "tokens", None, date(2025, 1, 31))

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 500

        # Period 2: add 1000, balance = 1500, use 1000, close (carry 500).
        meter.open_period("alice", "llm_call", "tokens", None, date(2025, 2, 1))
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 1500

        meter.consume("alice", "llm_call", 1000, "tokens")
        meter.close_period("alice", "llm_call", "tokens", None, date(2025, 2, 28))

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 500

        # Period 3: add 1000, balance = 1500.
        meter.open_period("alice", "llm_call", "tokens", None, date(2025, 3, 1))
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 1500


class TestReleaseExpiredReservations:
    """Tests for meter.release_expired_reservations() - maintenance function."""

    def test_releases_expired_reservation(self, meter, test_helpers, db_connection):
        """Expired reservation is released and reserved amount reduced."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        reservation = meter.reserve(
            "alice", "llm_call", 200, "tokens", ttl_seconds=3600
        )

        # Force expiration by manipulating expires_at directly.
        test_helpers.set_reservation_expired(reservation["reservation_id"])

        # State before release.
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["reserved"] == 200

        # Release expired reservations.
        count = meter.release_expired_reservations()

        assert count == 1

        # State after release: reserved reduced.
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["reserved"] == 0
        # Balance unchanged (reservations don't affect balance).
        assert balance["balance"] == 1000

    def test_releases_multiple_expired_reservations(
        self, meter, test_helpers, db_connection
    ):
        """Multiple expired reservations are released in one call."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        r1 = meter.reserve("alice", "llm_call", 100, "tokens", ttl_seconds=3600)
        r2 = meter.reserve("alice", "llm_call", 150, "tokens", ttl_seconds=3600)
        r3 = meter.reserve("alice", "llm_call", 200, "tokens", ttl_seconds=3600)

        # Expire all three.
        test_helpers.set_reservation_expired(r1["reservation_id"])
        test_helpers.set_reservation_expired(r2["reservation_id"])
        test_helpers.set_reservation_expired(r3["reservation_id"])

        count = meter.release_expired_reservations()
        assert count == 3

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["reserved"] == 0

    def test_preserves_active_reservations(self, meter, test_helpers):
        """Active (non-expired) reservations are not affected."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        expired_res = meter.reserve(
            "alice", "llm_call", 200, "tokens", ttl_seconds=3600
        )
        # Active reservation - not expired, should be preserved.
        meter.reserve("alice", "llm_call", 300, "tokens", ttl_seconds=3600)

        # Only expire one.
        test_helpers.set_reservation_expired(expired_res["reservation_id"])

        count = meter.release_expired_reservations()
        assert count == 1

        # Active reservation still present.
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["reserved"] == 300

    def test_marks_status_as_expired(self, meter, test_helpers):
        """Expired reservations have status='expired' (distinct from 'released')."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        reservation = meter.reserve(
            "alice", "llm_call", 200, "tokens", ttl_seconds=3600
        )

        test_helpers.set_reservation_expired(reservation["reservation_id"])
        meter.release_expired_reservations()

        # Verify status is 'expired', not 'released', with completion timestamp.
        res = test_helpers.get_reservation_raw(reservation["reservation_id"])
        assert res["status"] == "expired"
        assert res["completed_at"] is not None

    def test_handles_no_expired_reservations(self, meter):
        """Returns 0 when no expired reservations exist."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        meter.reserve("alice", "llm_call", 200, "tokens", ttl_seconds=3600)

        # No expiration manipulation - all active.
        count = meter.release_expired_reservations()
        assert count == 0

    def test_updates_account_reserved_amount(self, meter, test_helpers):
        """Account's reserved amount is correctly reduced by total released."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        r1 = meter.reserve("alice", "llm_call", 100, "tokens", ttl_seconds=3600)
        # Second reservation - will remain active.
        meter.reserve("alice", "llm_call", 150, "tokens", ttl_seconds=3600)

        # State: reserved = 250.
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["reserved"] == 250

        # Expire first only.
        test_helpers.set_reservation_expired(r1["reservation_id"])
        meter.release_expired_reservations()

        # State: reserved = 150 (only r2 remains).
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["reserved"] == 150
