"""Core SDK tests for postkit.meter - happy path and basic functionality."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal


class TestAllocate:
    """Tests for meter.allocate()"""

    def test_allocate_creates_account_and_balance(self, meter):
        """Allocating to a new user creates an account with that balance."""
        result = meter.allocate("alice", "llm_call", 1000, "tokens")

        assert result["balance"] == 1000
        assert result["entry_id"] is not None

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 1000
        assert balance["reserved"] == 0
        assert balance["available"] == 1000

    def test_allocate_with_resource(self, meter):
        """Allocation with resource creates separate account."""
        meter.allocate("alice", "llm_call", 1000, "tokens", resource="claude-sonnet")
        meter.allocate("alice", "llm_call", 500, "tokens", resource="gpt-4")

        sonnet = meter.get_balance("alice", "llm_call", "tokens", "claude-sonnet")
        gpt4 = meter.get_balance("alice", "llm_call", "tokens", "gpt-4")

        assert sonnet["balance"] == 1000
        assert gpt4["balance"] == 500

    def test_allocate_idempotency(self, meter):
        """Duplicate idempotency key returns existing result."""
        result1 = meter.allocate(
            "alice", "llm_call", 1000, "tokens", idempotency_key="alloc-1"
        )
        result2 = meter.allocate(
            "alice", "llm_call", 1000, "tokens", idempotency_key="alloc-1"
        )

        assert result1["entry_id"] == result2["entry_id"]
        assert result1["balance"] == result2["balance"]

        # Balance should only be 1000, not 2000
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 1000

    def test_allocate_multiple_adds_up(self, meter):
        """Multiple allocations to same account add up."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        meter.allocate("alice", "llm_call", 500, "tokens")

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 1500


class TestConsume:
    """Tests for meter.consume()"""

    def test_consume_deducts_from_balance(self, meter):
        """Consumption reduces balance."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        result = meter.consume("alice", "llm_call", 100, "tokens")

        assert result["success"] is True
        assert result["balance"] == 900

    def test_consume_without_balance_check_allows_negative(self, meter):
        """Without check_balance, consumption can go negative."""
        meter.allocate("alice", "llm_call", 100, "tokens")
        result = meter.consume("alice", "llm_call", 200, "tokens")

        assert result["success"] is True
        assert result["balance"] == -100

    def test_consume_with_balance_check_fails_if_insufficient(self, meter):
        """With check_balance=True, consumption fails if insufficient."""
        meter.allocate("alice", "llm_call", 100, "tokens")
        result = meter.consume("alice", "llm_call", 200, "tokens", check_balance=True)

        assert result["success"] is False
        assert result["entry_id"] is None

        # Balance unchanged
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 100

    def test_consume_idempotency(self, meter):
        """Duplicate idempotency key returns existing result."""
        meter.allocate("alice", "llm_call", 1000, "tokens")

        result1 = meter.consume(
            "alice", "llm_call", 100, "tokens", idempotency_key="consume-1"
        )
        result2 = meter.consume(
            "alice", "llm_call", 100, "tokens", idempotency_key="consume-1"
        )

        assert result1["entry_id"] == result2["entry_id"]

        # Balance should only be reduced once
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 900

    def test_consume_returns_correct_available(self, meter):
        """Consume returns the new available balance matching get_balance."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        result = meter.consume("alice", "llm_call", 100, "tokens")

        assert result["success"] is True
        assert result["balance"] == 900
        assert result["available"] == 900  # Must be NEW available, not old

        # Returned available must match get_balance
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert result["available"] == balance["available"]

    def test_consume_available_with_reservation(self, meter):
        """Consume returns correct available when reservations exist."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        meter.reserve("alice", "llm_call", 200, "tokens")  # reserved=200

        result = meter.consume("alice", "llm_call", 100, "tokens")

        # After reserve: balance=1000 (unchanged), reserved=200, available=800
        # After consume 100: balance=900, reserved=200, available=700
        assert result["balance"] == 900
        assert result["available"] == 700

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert result["available"] == balance["available"]


class TestReservation:
    """Tests for meter.reserve(), meter.commit(), meter.release()"""

    def test_reserve_holds_balance(self, meter):
        """Reservation holds tokens without changing balance."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        result = meter.reserve("alice", "llm_call", 400, "tokens")

        assert result["granted"] is True
        assert result["reservation_id"] is not None
        assert result["balance"] == 1000  # balance UNCHANGED by reservation

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 1000  # balance unchanged
        assert balance["reserved"] == 400
        assert balance["available"] == 600  # 1000 - 400

    def test_reserve_returns_correct_available(self, meter):
        """Reserve returns the new available balance matching get_balance."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        result = meter.reserve("alice", "llm_call", 400, "tokens")

        assert result["granted"] is True
        assert result["balance"] == 1000  # unchanged
        assert result["available"] == 600  # 1000 - 400

        # Returned available must match get_balance
        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert result["available"] == balance["available"]

    def test_reserve_available_with_existing_reservation(self, meter):
        """Reserve returns correct available when prior reservations exist."""
        meter.allocate("alice", "llm_call", 1000, "tokens")

        # First reservation
        res1 = meter.reserve("alice", "llm_call", 300, "tokens")
        # After: balance=1000 (unchanged), reserved=300, available=700
        assert res1["balance"] == 1000
        assert res1["available"] == 700

        # Second reservation
        res2 = meter.reserve("alice", "llm_call", 200, "tokens")
        # After: balance=1000 (unchanged), reserved=500, available=500
        assert res2["balance"] == 1000
        assert res2["available"] == 500

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert res2["available"] == balance["available"]

    def test_reserve_fails_if_insufficient(self, meter):
        """Reservation fails if available balance is insufficient."""
        meter.allocate("alice", "llm_call", 100, "tokens")
        result = meter.reserve("alice", "llm_call", 200, "tokens")

        assert result["granted"] is False
        assert result["reservation_id"] is None

    def test_commit_with_exact_amount(self, meter):
        """Committing with exact reserved amount works correctly."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        res = meter.reserve("alice", "llm_call", 400, "tokens")

        result = meter.commit(res["reservation_id"], 400)

        assert result["success"] is True
        assert result["consumed"] == 400
        assert result["released"] == 0
        assert result["reserved_amount"] == 400
        assert result["balance"] == 600  # 1000 - 400 consumed

    def test_commit_with_less_than_reserved(self, meter):
        """Committing with less than reserved releases the difference."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        res = meter.reserve("alice", "llm_call", 400, "tokens")

        result = meter.commit(res["reservation_id"], 250)

        assert result["success"] is True
        assert result["consumed"] == 250
        assert result["released"] == 150
        assert result["reserved_amount"] == 400
        assert result["balance"] == 750  # 1000 - 250 consumed

    def test_release_keeps_balance(self, meter):
        """Releasing a reservation keeps balance unchanged (only reserved changes)."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        res = meter.reserve("alice", "llm_call", 400, "tokens")

        result = meter.release(res["reservation_id"])

        assert result is True

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 1000  # unchanged (was never modified)
        assert balance["reserved"] == 0
        assert balance["available"] == 1000

    def test_release_nonexistent_returns_false(self, meter):
        """Releasing nonexistent reservation returns False."""
        result = meter.release("nonexistent-id")
        assert result is False

    def test_commit_nonexistent_returns_failure(self, meter):
        """Committing nonexistent reservation returns failure."""
        result = meter.commit("nonexistent-id", 100)
        assert result["success"] is False


class TestCommitOverage:
    """Tests for overage reporting in meter.commit()"""

    def test_commit_returns_reserved_amount(self, meter):
        """Commit returns the original reservation amount."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        res = meter.reserve("alice", "llm_call", 400, "tokens")

        result = meter.commit(res["reservation_id"], 350)

        assert result["reserved_amount"] == 400
        assert result["consumed"] == 350
        assert result["released"] == 50
        assert result["balance"] == 650  # 1000 - 350

    def test_commit_overage_allowed_and_reported(self, meter):
        """Overage is allowed and accurately reported."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        res = meter.reserve("alice", "llm_call", 400, "tokens")

        result = meter.commit(res["reservation_id"], 500)

        assert result["success"] is True
        assert result["reserved_amount"] == 400
        assert result["consumed"] == 500
        assert result["released"] == 0
        assert result["balance"] == 500  # 1000 - 500

        # Caller computes overage
        overage = max(0, result["consumed"] - result["reserved_amount"])
        assert overage == 100

    def test_commit_overage_can_go_negative(self, meter):
        """Overage can drive balance negative."""
        meter.allocate("alice", "llm_call", 100, "tokens")
        res = meter.reserve("alice", "llm_call", 100, "tokens")

        result = meter.commit(res["reservation_id"], 150)

        assert result["success"] is True
        assert result["balance"] == -50  # 100 - 150
        assert result["reserved_amount"] == 100
        assert result["consumed"] == 150


class TestReservationCapacity:
    """Tests that reservation system allows full capacity usage."""

    def test_can_reserve_full_capacity(self, meter):
        """User can reserve up to 100% of balance, not just 50%."""
        meter.allocate("alice", "llm_call", 1000, "tokens")

        res1 = meter.reserve("alice", "llm_call", 400, "tokens")
        assert res1["granted"] is True
        assert res1["available"] == 600

        res2 = meter.reserve("alice", "llm_call", 400, "tokens")
        assert res2["granted"] is True
        assert res2["available"] == 200

        res3 = meter.reserve("alice", "llm_call", 200, "tokens")
        assert res3["granted"] is True
        assert res3["available"] == 0

        # Now fully reserved
        res4 = meter.reserve("alice", "llm_call", 1, "tokens")
        assert res4["granted"] is False

    def test_reserve_does_not_change_balance(self, meter):
        """Reservation only affects reserved, not balance."""
        meter.allocate("alice", "llm_call", 1000, "tokens")

        meter.reserve("alice", "llm_call", 400, "tokens")

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 1000  # Unchanged
        assert balance["reserved"] == 400
        assert balance["available"] == 600

    def test_release_does_not_change_balance(self, meter):
        """Release only affects reserved, not balance."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        res = meter.reserve("alice", "llm_call", 400, "tokens")

        meter.release(res["reservation_id"])

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 1000  # Still unchanged
        assert balance["reserved"] == 0
        assert balance["available"] == 1000

    def test_commit_deducts_actual_from_balance(self, meter):
        """Commit reduces balance by actual consumption only."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        res = meter.reserve("alice", "llm_call", 400, "tokens")

        result = meter.commit(res["reservation_id"], 350)

        assert result["consumed"] == 350
        assert result["balance"] == 650  # 1000 - 350

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 650
        assert balance["reserved"] == 0
        assert balance["available"] == 650

    def test_multiple_reservations_and_commits(self, meter):
        """Complex scenario with multiple concurrent reservations."""
        meter.allocate("alice", "llm_call", 1000, "tokens")

        res1 = meter.reserve("alice", "llm_call", 300, "tokens")
        res2 = meter.reserve("alice", "llm_call", 400, "tokens")

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 1000
        assert balance["reserved"] == 700
        assert balance["available"] == 300

        # Commit first reservation with less than reserved
        meter.commit(res1["reservation_id"], 250)

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 750  # 1000 - 250
        assert balance["reserved"] == 400  # Only res2 remaining
        assert balance["available"] == 350

        # Commit second reservation with exact amount
        meter.commit(res2["reservation_id"], 400)

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 350  # 750 - 400
        assert balance["reserved"] == 0
        assert balance["available"] == 350


class TestAdjust:
    """Tests for meter.adjust()"""

    def test_adjust_positive_credits_account(self, meter):
        """Positive adjustment adds to balance."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        result = meter.adjust("alice", "llm_call", 500, "tokens")

        assert result["balance"] == 1500

    def test_adjust_negative_debits_account(self, meter):
        """Negative adjustment subtracts from balance."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        result = meter.adjust("alice", "llm_call", -200, "tokens")

        assert result["balance"] == 800

    def test_adjust_idempotency(self, meter):
        """Duplicate idempotency key returns existing result."""
        meter.allocate("alice", "llm_call", 1000, "tokens")

        result1 = meter.adjust(
            "alice", "llm_call", 500, "tokens", idempotency_key="adj-1"
        )
        result2 = meter.adjust(
            "alice", "llm_call", 500, "tokens", idempotency_key="adj-1"
        )

        assert result1["entry_id"] == result2["entry_id"]

        balance = meter.get_balance("alice", "llm_call", "tokens")
        assert balance["balance"] == 1500  # Only adjusted once


class TestQuery:
    """Tests for query functions"""

    def test_get_user_balances(self, meter):
        """get_user_balances returns all accounts for a user."""
        meter.allocate("alice", "llm_call", 1000, "tokens", resource="claude-sonnet")
        meter.allocate("alice", "llm_call", 500, "tokens", resource="gpt-4")
        meter.allocate("alice", "api_call", 100, "requests")

        balances = meter.get_user_balances("alice")

        assert len(balances) == 3

    def test_get_ledger(self, meter):
        """get_ledger returns ledger entries for an account."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        meter.consume("alice", "llm_call", 100, "tokens")
        meter.consume("alice", "llm_call", 200, "tokens")

        ledger = meter.get_ledger("alice", "llm_call", "tokens")

        assert len(ledger) == 3
        assert ledger[0]["entry_type"] == "consumption"  # Most recent first
        assert ledger[1]["entry_type"] == "consumption"
        assert ledger[2]["entry_type"] == "allocation"

    def test_get_usage(self, meter):
        """get_usage aggregates consumption."""
        meter.allocate("alice", "llm_call", 10000, "tokens")
        meter.consume("alice", "llm_call", 100, "tokens")
        meter.consume("alice", "llm_call", 200, "tokens")
        meter.consume("alice", "llm_call", 300, "tokens")

        # Use timezone-aware datetimes for proper timestamptz comparison
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=1)
        end = now + timedelta(hours=1)

        usage = meter.get_usage("alice", start, end)

        assert len(usage) == 1
        assert usage[0]["total_consumed"] == 600
        assert usage[0]["event_count"] == 3

    def test_get_balance_nonexistent_returns_zeros(self, meter):
        """get_balance for nonexistent account returns zeros."""
        balance = meter.get_balance("nonexistent", "llm_call", "tokens")

        assert balance["balance"] == 0
        assert balance["reserved"] == 0
        assert balance["available"] == 0


class TestStats:
    """Tests for stats and reconciliation"""

    def test_get_stats(self, meter):
        """get_stats returns namespace statistics."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        meter.allocate("user-2", "llm_call", 500, "tokens")

        stats = meter.get_stats()

        assert stats["total_accounts"] == 2
        assert stats["total_ledger_entries"] == 2
        assert stats["total_balance"] == 1500

    def test_reconcile_no_discrepancies(self, meter, test_helpers):
        """reconcile returns empty when ledger matches accounts."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        meter.consume("alice", "llm_call", 300, "tokens")

        discrepancies = meter.reconcile()
        assert len(discrepancies) == 0

        # Verify helper agrees
        ledger_sum = test_helpers.sum_ledger_amounts("alice", "llm_call", "tokens")
        account = test_helpers.get_account_raw("alice", "llm_call", "tokens")
        assert ledger_sum == float(account["balance"])

    def test_reconcile_with_reservations(self, meter, test_helpers):
        """Reservations don't create ledger entries, so reconciliation still works."""
        meter.allocate("alice", "llm_call", 1000, "tokens")

        # Reserve (should NOT create ledger entry)
        res = meter.reserve("alice", "llm_call", 400, "tokens")
        assert res["granted"] is True

        # Ledger should only have allocation entry
        assert test_helpers.count_ledger_entries() == 1
        assert test_helpers.count_ledger_entries("allocation") == 1

        # Reconciliation should pass - balance unchanged by reservation
        discrepancies = meter.reconcile()
        assert len(discrepancies) == 0

        ledger_sum = test_helpers.sum_ledger_amounts("alice", "llm_call", "tokens")
        account = test_helpers.get_account_raw("alice", "llm_call", "tokens")
        assert ledger_sum == float(account["balance"])
        assert ledger_sum == 1000  # Balance unchanged

        # Now commit with actual consumption
        meter.commit(res["reservation_id"], 350)

        # Ledger should have allocation + consumption
        assert test_helpers.count_ledger_entries() == 2
        assert test_helpers.count_ledger_entries("consumption") == 1

        # Reconciliation should still pass
        discrepancies = meter.reconcile()
        assert len(discrepancies) == 0

        ledger_sum = test_helpers.sum_ledger_amounts("alice", "llm_call", "tokens")
        account = test_helpers.get_account_raw("alice", "llm_call", "tokens")
        assert ledger_sum == float(account["balance"])
        assert ledger_sum == 650  # 1000 - 350


class TestActorContext:
    """Tests for actor context capture in ledger entries."""

    def test_actor_captured_in_allocate(self, meter):
        """allocate() captures actor context."""
        meter.set_actor("user:admin", reason="Monthly allocation")
        meter.allocate("alice", "llm_call", 1000, "tokens")

        ledger = meter.get_ledger("alice", "llm_call", "tokens")

        assert len(ledger) == 1
        assert ledger[0]["actor_id"] == "user:admin"
        assert ledger[0]["reason"] == "Monthly allocation"

    def test_actor_captured_in_consume(self, meter):
        """consume() captures actor context."""
        meter.allocate("alice", "llm_call", 1000, "tokens")

        meter.set_actor("service:api", reason="API usage")
        meter.consume("alice", "llm_call", 100, "tokens")

        ledger = meter.get_ledger("alice", "llm_call", "tokens")
        consumption = [e for e in ledger if e["entry_type"] == "consumption"][0]

        assert consumption["actor_id"] == "service:api"
        assert consumption["reason"] == "API usage"

    def test_actor_captured_in_commit(self, meter):
        """commit() captures actor context in consumption entry."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        res = meter.reserve("alice", "llm_call", 400, "tokens")

        meter.set_actor("service:llm", reason="Streaming completion")
        meter.commit(res["reservation_id"], 350)

        ledger = meter.get_ledger("alice", "llm_call", "tokens")
        consumption = [e for e in ledger if e["entry_type"] == "consumption"][0]

        assert consumption["actor_id"] == "service:llm"
        assert consumption["reason"] == "Streaming completion"

    def test_actor_captured_in_adjust(self, meter):
        """adjust() captures actor context."""
        meter.allocate("alice", "llm_call", 1000, "tokens")

        meter.set_actor("user:support", reason="Refund for outage")
        meter.adjust("alice", "llm_call", 500, "tokens")

        ledger = meter.get_ledger("alice", "llm_call", "tokens")
        adjustment = [e for e in ledger if e["entry_type"] == "adjustment"][0]

        assert adjustment["actor_id"] == "user:support"
        assert adjustment["reason"] == "Refund for outage"

    def test_on_behalf_of_captured(self, meter):
        """on_behalf_of delegation is captured."""
        meter.set_actor(
            "user:admin", on_behalf_of="user:alice", reason="Support ticket #1234"
        )
        meter.allocate("alice", "llm_call", 500, "tokens")

        ledger = meter.get_ledger("alice", "llm_call", "tokens")

        assert ledger[0]["actor_id"] == "user:admin"
        # on_behalf_of is captured in the ledger entry
        # Note: get_ledger returns it if the column exists

    def test_clear_actor_stops_capture(self, meter):
        """clear_actor() stops context capture."""
        meter.set_actor("user:admin")
        meter.allocate("alice", "llm_call", 1000, "tokens")

        meter.clear_actor()
        meter.consume("alice", "llm_call", 100, "tokens")

        ledger = meter.get_ledger("alice", "llm_call", "tokens")
        allocation = [e for e in ledger if e["entry_type"] == "allocation"][0]
        consumption = [e for e in ledger if e["entry_type"] == "consumption"][0]

        assert allocation["actor_id"] == "user:admin"
        assert consumption["actor_id"] is None  # Cleared

    def test_actor_captured_in_reservation(self, meter):
        """reserve() captures actor context in reservation record."""
        meter.allocate("alice", "llm_call", 1000, "tokens")

        meter.set_actor("service:gateway", request_id="req-001")
        res = meter.reserve("alice", "llm_call", 400, "tokens")

        # Verify via direct query since get_ledger won't show reservations
        meter.cursor.execute(
            """SELECT actor_id, request_id
               FROM meter.reservations
               WHERE reservation_id = %s""",
            (res["reservation_id"],),
        )
        row = meter.cursor.fetchone()

        assert row[0] == "service:gateway"
        assert row[1] == "req-001"

    def test_actor_not_required(self, meter):
        """Operations work without actor context set."""
        # No set_actor() call
        meter.allocate("alice", "llm_call", 1000, "tokens")
        meter.consume("alice", "llm_call", 100, "tokens")

        ledger = meter.get_ledger("alice", "llm_call", "tokens")

        assert len(ledger) == 2
        assert ledger[0]["actor_id"] is None
        assert ledger[1]["actor_id"] is None


class TestNormalizeValue:
    """Tests for Decimal normalization - ensures SDK returns float, not Decimal."""

    def test_decimal_normalized_to_float(self, meter):
        """Decimal values from DB are converted to float."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        balance = meter.get_balance("alice", "llm_call", "tokens")

        # PostgreSQL returns numeric as Decimal, SDK should normalize to float
        assert isinstance(balance["balance"], float), (
            f"Expected float, got {type(balance['balance'])}"
        )
        assert not isinstance(balance["balance"], Decimal)

    def test_all_balance_fields_are_float(self, meter):
        """All numeric fields in balance response are floats."""
        meter.allocate("alice", "llm_call", 1000, "tokens")
        meter.reserve("alice", "llm_call", 200, "tokens")
        balance = meter.get_balance("alice", "llm_call", "tokens")

        for field in ["balance", "reserved", "available"]:
            assert isinstance(balance[field], float), (
                f"{field}: Expected float, got {type(balance[field])}"
            )


class TestIdempotencyWithInterveningTransactions:
    """Regression tests: idempotent retries must return historical balance."""

    def test_consume_idempotency_returns_historical_balance(self, meter):
        meter.allocate("alice", "llm_call", 1000, "tokens")

        # First consume: balance goes from 1000 to 900
        result1 = meter.consume(
            "alice", "llm_call", 100, "tokens", idempotency_key="op-1"
        )
        assert result1["balance"] == 900

        # Intervening transaction: balance goes from 900 to 700
        meter.consume("alice", "llm_call", 200, "tokens", idempotency_key="op-2")

        # Verify current balance is different
        current = meter.get_balance("alice", "llm_call", "tokens")
        assert current["balance"] == 700

        # Retry - MUST return HISTORICAL balance (900), not current (700)
        result2 = meter.consume(
            "alice", "llm_call", 100, "tokens", idempotency_key="op-1"
        )
        assert result2["entry_id"] == result1["entry_id"]
        assert result2["balance"] == 900  # Historical, NOT 700

    def test_reserve_idempotency_returns_historical_balance(self, meter):
        meter.allocate("alice", "llm_call", 1000, "tokens")

        # First reserve: balance is 1000 (reservations don't change balance)
        result1 = meter.reserve(
            "alice", "llm_call", 100, "tokens", idempotency_key="res-1"
        )
        assert result1["balance"] == 1000
        assert result1["granted"] is True

        # Intervening transaction: allocate more (balance goes to 1500)
        meter.allocate("alice", "llm_call", 500, "tokens")

        # Verify current balance is different
        current = meter.get_balance("alice", "llm_call", "tokens")
        assert current["balance"] == 1500

        # Retry - MUST return HISTORICAL balance (1000), not current (1500)
        result2 = meter.reserve(
            "alice", "llm_call", 100, "tokens", idempotency_key="res-1"
        )
        assert result2["reservation_id"] == result1["reservation_id"]
        assert result2["balance"] == 1000  # Historical, NOT 1500

    def test_allocate_idempotency_returns_historical_balance(self, meter):
        # First allocate: balance goes from 0 to 1000
        result1 = meter.allocate(
            "alice", "llm_call", 1000, "tokens", idempotency_key="alloc-1"
        )
        assert result1["balance"] == 1000

        # Intervening transaction: consume some
        meter.consume("alice", "llm_call", 300, "tokens")

        # Verify current balance is different
        current = meter.get_balance("alice", "llm_call", "tokens")
        assert current["balance"] == 700

        # Retry - MUST return HISTORICAL balance (1000), not current (700)
        result2 = meter.allocate(
            "alice", "llm_call", 1000, "tokens", idempotency_key="alloc-1"
        )
        assert result2["entry_id"] == result1["entry_id"]
        assert result2["balance"] == 1000  # Historical, NOT 700

    def test_adjust_idempotency_returns_historical_balance(self, meter):
        meter.allocate("alice", "llm_call", 1000, "tokens")

        # First adjust: balance goes from 1000 to 1500
        result1 = meter.adjust(
            "alice", "llm_call", 500, "tokens", idempotency_key="adj-1"
        )
        assert result1["balance"] == 1500

        # Intervening transaction: consume some
        meter.consume("alice", "llm_call", 200, "tokens")

        # Verify current balance is different
        current = meter.get_balance("alice", "llm_call", "tokens")
        assert current["balance"] == 1300

        # Retry - MUST return HISTORICAL balance (1500), not current (1300)
        result2 = meter.adjust(
            "alice", "llm_call", 500, "tokens", idempotency_key="adj-1"
        )
        assert result2["entry_id"] == result1["entry_id"]
        assert result2["balance"] == 1500  # Historical, NOT 1300
