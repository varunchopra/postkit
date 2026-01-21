"""Postkit Meter SDK - Usage tracking for metering."""

from __future__ import annotations

import json
from datetime import date, datetime
from decimal import Decimal

from postkit.base import BaseClient, PostkitError


class MeterError(PostkitError):
    """Exception for meter operations."""


class MeterValidationError(MeterError):
    """Raised when input validation fails."""


class MeterClient(BaseClient):
    """Client for Postkit meter module.

    Double-entry ledger for usage tracking with reservations.
    Meter measures. It does not price.

    Example:
        meter = MeterClient(cursor, namespace="acme")

        # Allocate quota
        meter.allocate("alice", "llm_call", 100000, "tokens", "claude-sonnet")

        # Record consumption
        meter.consume("alice", "llm_call", 1500, "tokens", "claude-sonnet")

        # Reserve for streaming (uncertain consumption)
        res = meter.reserve("alice", "llm_call", 4000, "tokens", "claude-sonnet")
        # ... streaming operation ...
        meter.commit(res["reservation_id"], actual_amount=2347)

        # Check balance
        balance = meter.get_balance("alice", "llm_call", "tokens", "claude-sonnet")
    """

    _schema = "meter"
    _error_class = MeterError
    _module_sqlstate_map = {
        "22023": MeterValidationError,  # invalid_parameter_value
        "22004": MeterValidationError,  # null_value_not_allowed
        "22001": MeterValidationError,  # string_data_right_truncation
        "22026": MeterValidationError,  # string_data_length_mismatch
    }

    def __init__(self, cursor, namespace: str):
        """Initialize the meter client.

        Args:
            cursor: A DB-API 2.0 cursor (psycopg2, psycopg3, etc.)
            namespace: Tenant namespace for multi-tenancy
        """
        super().__init__(cursor, namespace)

    def _apply_actor_context(self) -> None:
        """Apply actor context via meter.set_actor()."""
        self.cursor.execute(
            """SELECT meter.set_actor(
                p_actor_id := %s,
                p_request_id := %s,
                p_on_behalf_of := %s,
                p_reason := %s
            )""",
            (self._actor_id, self._request_id, self._on_behalf_of, self._reason),
        )

    def allocate(
        self,
        user_id: str | None,
        event_type: str,
        amount: float | int | Decimal,
        unit: str,
        resource: str | None = None,
        idempotency_key: str | None = None,
        event_time: datetime | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Add quota/credits to an account.

        Args:
            user_id: User ID (None for namespace-level pool)
            event_type: Event type ('llm_call', 'api_request', etc.)
            amount: Amount to allocate (must be positive)
            unit: Unit of measurement ('tokens', 'requests', 'bytes')
            resource: Optional resource identifier ('claude-sonnet', 'gpt-4')
            idempotency_key: Optional dedup key for safe retries
            event_time: When allocation occurred (defaults to now)
            metadata: Optional JSON metadata

        Returns:
            Dict with 'balance' and 'entry_id'
        """
        return self._fetch_one(
            "SELECT balance, entry_id FROM meter.allocate(%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)",
            (
                user_id,
                event_type,
                amount,
                unit,
                resource,
                idempotency_key,
                event_time,
                json.dumps(metadata) if metadata else None,
                self.namespace,
            ),
            write=True,
        )

    def consume(
        self,
        user_id: str,
        event_type: str,
        amount: float | int | Decimal,
        unit: str,
        resource: str | None = None,
        check_balance: bool = False,
        idempotency_key: str | None = None,
        event_time: datetime | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Record consumption.

        Args:
            user_id: User ID (required)
            event_type: Event type
            amount: Amount consumed (must be positive)
            unit: Unit of measurement
            resource: Optional resource identifier
            check_balance: If True, fails when insufficient balance
            idempotency_key: Optional dedup key for safe retries
            event_time: When consumption occurred (defaults to now)
            metadata: Optional JSON metadata

        Returns:
            Dict with 'success', 'balance', 'available', 'entry_id'
        """
        return self._fetch_one(
            """SELECT success, balance, available, entry_id
               FROM meter.consume(%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)""",
            (
                user_id,
                event_type,
                amount,
                unit,
                resource,
                check_balance,
                idempotency_key,
                event_time,
                json.dumps(metadata) if metadata else None,
                self.namespace,
            ),
            write=True,
        )

    def reserve(
        self,
        user_id: str,
        event_type: str,
        amount: float | int | Decimal,
        unit: str,
        resource: str | None = None,
        ttl_seconds: int = 300,
        idempotency_key: str | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Reserve quota for pending operation (streaming, uncertain consumption).

        Reservations are HOLDS, not balance changes. They don't create ledger
        entries. The hold is tracked in accounts.reserved and the reservations
        table. Only actual consumption (via commit) affects balance.

        Args:
            user_id: User ID (required)
            event_type: Event type
            amount: Amount to reserve
            unit: Unit of measurement
            resource: Optional resource identifier
            ttl_seconds: Time until reservation auto-expires (default 300 = 5 min)
            idempotency_key: Optional dedup key for safe retries
            metadata: Optional JSON metadata

        Returns:
            Dict with 'granted', 'reservation_id', 'balance', 'available', 'expires_at'
        """
        return self._fetch_one(
            """SELECT granted, reservation_id, balance, available, expires_at
               FROM meter.reserve(%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)""",
            (
                user_id,
                event_type,
                amount,
                unit,
                resource,
                ttl_seconds,
                idempotency_key,
                json.dumps(metadata) if metadata else None,
                self.namespace,
            ),
            write=True,
        )

    def commit(
        self,
        reservation_id: str,
        actual_amount: float | int | Decimal,
        metadata: dict | None = None,
    ) -> dict:
        """Commit a reservation with actual consumption.

        Meter measures. It does not enforce. If actual consumption exceeds
        reserved amount, the overage is recorded accurately. Caller decides
        policy (reject, allow, draw from parent pool, alert, etc.).

        Args:
            reservation_id: Reservation to commit
            actual_amount: Actual amount consumed (can be more or less than reserved)
            metadata: Optional JSON metadata

        Returns:
            Dict with 'success', 'consumed', 'released', 'reserved_amount',
            'balance', 'entry_id'

        Example:
            result = meter.commit(res_id, actual_tokens)
            overage = max(0, result["consumed"] - result["reserved_amount"])
            if overage > 0:
                handle_overage(overage)  # caller's policy
        """
        return self._fetch_one(
            """SELECT success, consumed, released, reserved_amount, balance, entry_id
               FROM meter.commit(%s, %s, %s::jsonb, %s)""",
            (
                reservation_id,
                actual_amount,
                json.dumps(metadata) if metadata else None,
                self.namespace,
            ),
            write=True,
        )

    def release(self, reservation_id: str) -> bool:
        """Release a reservation without consuming.

        Args:
            reservation_id: Reservation to release

        Returns:
            True if released, False if not found
        """
        return self._fetch_val(
            "SELECT meter.release(%s, %s)",
            (reservation_id, self.namespace),
            write=True,
        )

    def adjust(
        self,
        user_id: str,
        event_type: str,
        amount: float | int | Decimal,
        unit: str,
        resource: str | None = None,
        reference_id: int | None = None,
        idempotency_key: str | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Create an adjustment entry (correction, refund, etc.).

        Args:
            user_id: User ID
            event_type: Event type
            amount: Adjustment amount (positive = credit, negative = debit)
            unit: Unit of measurement
            resource: Optional resource identifier
            reference_id: Optional ledger entry ID being corrected
            idempotency_key: Optional dedup key for safe retries
            metadata: Optional JSON metadata

        Returns:
            Dict with 'balance' and 'entry_id'
        """
        return self._fetch_one(
            "SELECT balance, entry_id FROM meter.adjust(%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)",
            (
                user_id,
                event_type,
                amount,
                unit,
                resource,
                reference_id,
                idempotency_key,
                json.dumps(metadata) if metadata else None,
                self.namespace,
            ),
            write=True,
        )

    def get_balance(
        self,
        user_id: str,
        event_type: str,
        unit: str,
        resource: str | None = None,
    ) -> dict:
        """Get current balance for an account.

        Use this to check if a user can afford an operation before starting,
        or to display remaining quota in the UI.

        Args:
            user_id: User ID
            event_type: Event type (e.g., "llm_call", "api_request")
            unit: Unit of measurement (e.g., "tokens", "requests")
            resource: Optional resource identifier (e.g., "claude-sonnet")

        Returns:
            Dict with:
            - balance: Total balance (allocations minus consumption)
            - reserved: Amount currently held in active reservations
            - available: balance - reserved (what can be used right now)

        Example:
            # Check if user can afford an operation before starting
            balance = meter.get_balance(user_id, "llm_call", "tokens", "claude-sonnet")
            if balance["available"] >= estimated_tokens:
                # Proceed with operation
                result = call_llm(prompt)
                meter.consume(user_id, "llm_call", result.tokens_used, "tokens", "claude-sonnet")
            else:
                # Show quota exceeded message
                raise QuotaExceededError(
                    f"Need {estimated_tokens} tokens but only {balance['available']} available"
                )

            # Display remaining quota in UI
            balance = meter.get_balance(user_id, "api_request", "requests")
            print(f"API calls remaining: {balance['available']}")
        """
        return self._fetch_one(
            "SELECT balance, reserved, available FROM meter.get_balance(%s, %s, %s, %s, %s)",
            (user_id, event_type, unit, resource, self.namespace),
        ) or {"balance": 0.0, "reserved": 0.0, "available": 0.0}

    def get_user_balances(self, user_id: str) -> list[dict]:
        """Get all balances for a user across all event types and resources.

        Args:
            user_id: User ID

        Returns:
            List of dicts with 'event_type', 'resource', 'unit', 'balance',
            'reserved', 'available'
        """
        return self._fetch_all(
            """SELECT event_type, resource, unit, balance, reserved, available
               FROM meter.get_user_balances(%s, %s)""",
            (user_id, self.namespace),
        )

    def get_usage(
        self,
        user_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[dict]:
        """Get aggregated consumption for a user.

        Args:
            user_id: User ID
            start_time: Start of period
            end_time: End of period

        Returns:
            List of dicts with 'event_type', 'resource', 'unit',
            'total_consumed', 'event_count'
        """
        return self._fetch_all(
            """SELECT event_type, resource, unit, total_consumed, event_count
               FROM meter.get_usage(%s, %s, %s, %s)""",
            (user_id, start_time, end_time, self.namespace),
        )

    def get_ledger(
        self,
        user_id: str,
        event_type: str,
        unit: str,
        resource: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Get ledger entries for an account.

        Args:
            user_id: User ID
            event_type: Event type
            unit: Unit of measurement
            resource: Optional resource identifier
            start_time: Optional start time filter
            end_time: Optional end time filter
            limit: Maximum entries to return (default 100, max 10000)

        Returns:
            List of ledger entry dicts
        """
        return self._fetch_all(
            """SELECT id, entry_type, amount, balance_after, event_time,
                      reservation_id, reference_id, actor_id, reason, metadata
               FROM meter.get_ledger(%s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                user_id,
                event_type,
                unit,
                resource,
                start_time,
                end_time,
                limit,
                self.namespace,
            ),
        )

    def set_period_config(
        self,
        user_id: str,
        event_type: str,
        unit: str,
        resource: str | None,
        period_start: date,
        period_allocation: float | int | Decimal,
        carry_over_limit: float | int | Decimal | None = None,
    ) -> None:
        """Configure period settings for an account.

        Args:
            user_id: User ID
            event_type: Event type
            unit: Unit of measurement
            resource: Optional resource identifier
            period_start: First day of the period
            period_allocation: Amount granted each period
            carry_over_limit: Max unused to roll forward (None = no limit)
        """
        self._fetch_val(
            "SELECT meter.set_period_config(%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                user_id,
                event_type,
                unit,
                resource,
                period_start,
                period_allocation,
                carry_over_limit,
                self.namespace,
            ),
            write=True,
        )

    def close_period(
        self,
        user_id: str,
        event_type: str,
        unit: str,
        resource: str | None,
        period_end: date,
    ) -> dict:
        """Close a billing period, handle expiration and carry-over.

        Args:
            user_id: User ID
            event_type: Event type
            unit: Unit of measurement
            resource: Optional resource identifier
            period_end: Last day of the period being closed

        Returns:
            Dict with 'expired', 'carried_over', 'new_balance'
        """
        return self._fetch_one(
            "SELECT expired, carried_over, new_balance FROM meter.close_period(%s, %s, %s, %s, %s, %s)",
            (user_id, event_type, unit, resource, period_end, self.namespace),
            write=True,
        )

    def open_period(
        self,
        user_id: str,
        event_type: str,
        unit: str,
        resource: str | None,
        period_start: date,
        allocation: float | int | Decimal | None = None,
    ) -> float:
        """Open a new billing period with allocation.

        Args:
            user_id: User ID
            event_type: Event type
            unit: Unit of measurement
            resource: Optional resource identifier
            period_start: First day of new period
            allocation: Amount to allocate (uses period_allocation if None)

        Returns:
            New balance
        """
        result = self._fetch_val(
            "SELECT meter.open_period(%s, %s, %s, %s, %s, %s, %s)",
            (
                user_id,
                event_type,
                unit,
                resource,
                period_start,
                allocation,
                self.namespace,
            ),
            write=True,
        )
        return float(result)

    def release_expired_reservations(self) -> int:
        """Release all expired reservations for this namespace.

        Returns:
            Count of reservations released
        """
        return self._fetch_val(
            "SELECT meter.release_expired_reservations(%s)",
            (self.namespace,),
            write=True,
        )

    def reconcile(self) -> list[dict]:
        """Check for discrepancies in account invariants.

        Checks two invariants:
        1. balance_mismatch: account.balance != SUM(ledger.amount)
        2. reserved_mismatch: account.reserved != SUM(active_reservations.amount)

        Returns:
            List of dicts with 'user_id', 'event_type', 'resource', 'unit',
            'issue_type', 'expected', 'actual', 'discrepancy'
        """
        return self._fetch_all(
            """SELECT user_id, event_type, resource, unit, issue_type, expected, actual, discrepancy
               FROM meter.reconcile(%s)""",
            (self.namespace,),
        )

    def get_stats(self) -> dict:
        """Get namespace statistics.

        Returns:
            Dict with counts and totals
        """
        return self._fetch_one(
            """SELECT total_accounts, total_ledger_entries, active_reservations,
                      total_balance, total_reserved
               FROM meter.get_stats(%s)""",
            (self.namespace,),
        ) or {
            "total_accounts": 0,
            "total_ledger_entries": 0,
            "active_reservations": 0,
            "total_balance": 0.0,
            "total_reserved": 0.0,
        }

    def get_audit_events(self, *args, **kwargs) -> list[dict]:
        """Not supported - meter module does not have audit events.

        The meter module uses a ledger-based design where all transactions
        are recorded in the ledger table. Use get_ledger() for transaction
        history instead.

        Raises:
            NotImplementedError: Always raised. Use get_ledger() instead.
        """
        raise NotImplementedError(
            "MeterClient does not support audit events. "
            "Use get_ledger() for transaction history."
        )
