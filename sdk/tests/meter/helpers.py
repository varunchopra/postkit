"""Test helpers for meter - direct table access for test setup/teardown."""

from tests.helpers import fetch_row


def cleanup_namespace(cursor, namespace: str):
    """Delete all meter data for a namespace."""
    cursor.execute("DELETE FROM meter.reservations WHERE namespace = %s", (namespace,))
    cursor.execute(
        "DELETE FROM meter.period_openings WHERE namespace = %s", (namespace,)
    )
    # Disable immutability trigger for cleanup, then re-enable.
    cursor.execute("ALTER TABLE meter.ledger DISABLE TRIGGER ledger_no_delete")
    cursor.execute("DELETE FROM meter.ledger WHERE namespace = %s", (namespace,))
    cursor.execute("ALTER TABLE meter.ledger ENABLE TRIGGER ledger_no_delete")
    cursor.execute("DELETE FROM meter.accounts WHERE namespace = %s", (namespace,))


class MeterTestHelpers:
    """
    Direct table access for test setup/teardown that bypasses the SDK.

    Use cases:
    - Checking ledger entry counts
    - Verifying account state directly
    - Testing edge cases that require direct table manipulation
    """

    def __init__(self, cursor, namespace: str):
        self.cursor = cursor
        self.namespace = namespace
        self.cursor.execute("SELECT meter.set_tenant(%s)", (namespace,))

    def count_accounts(self) -> int:
        """Count total accounts in namespace."""
        self.cursor.execute(
            "SELECT COUNT(*) FROM meter.accounts WHERE namespace = %s",
            (self.namespace,),
        )
        return self.cursor.fetchone()[0]

    def count_ledger_entries(self, entry_type: str | None = None) -> int:
        """Count ledger entries, optionally filtered by type."""
        if entry_type:
            self.cursor.execute(
                "SELECT COUNT(*) FROM meter.ledger WHERE namespace = %s AND entry_type = %s",
                (self.namespace, entry_type),
            )
        else:
            self.cursor.execute(
                "SELECT COUNT(*) FROM meter.ledger WHERE namespace = %s",
                (self.namespace,),
            )
        return self.cursor.fetchone()[0]

    def count_reservations(self, status: str | None = "active") -> int:
        """Count reservations in namespace, optionally filtered by status.

        Args:
            status: Filter by status ('active', 'committed', 'released', 'expired').
                   Pass None to count all reservations regardless of status.
        """
        if status:
            self.cursor.execute(
                "SELECT COUNT(*) FROM meter.reservations WHERE namespace = %s AND status = %s",
                (self.namespace, status),
            )
        else:
            self.cursor.execute(
                "SELECT COUNT(*) FROM meter.reservations WHERE namespace = %s",
                (self.namespace,),
            )
        return self.cursor.fetchone()[0]

    def get_account_raw(
        self, user_id: str, event_type: str, unit: str, resource: str | None = None
    ) -> dict | None:
        """Get an account directly from the table."""
        self.cursor.execute(
            """SELECT * FROM meter.accounts
               WHERE namespace = %s
                 AND user_id = %s
                 AND event_type = %s
                 AND resource = %s
                 AND unit = %s""",
            (self.namespace, user_id, event_type, resource or "", unit),
        )
        return fetch_row(self.cursor)

    def get_ledger_entry_raw(self, entry_id: int) -> dict | None:
        """Get a ledger entry directly by ID."""
        self.cursor.execute(
            "SELECT * FROM meter.ledger WHERE id = %s AND namespace = %s",
            (entry_id, self.namespace),
        )
        return fetch_row(self.cursor)

    def get_reservation_raw(self, reservation_id: str) -> dict | None:
        """Get a reservation directly from the table."""
        self.cursor.execute(
            "SELECT * FROM meter.reservations WHERE reservation_id = %s AND namespace = %s",
            (reservation_id, self.namespace),
        )
        return fetch_row(self.cursor)

    def sum_ledger_amounts(
        self, user_id: str, event_type: str, unit: str, resource: str | None = None
    ) -> float:
        """Sum all ledger amounts for an account (for reconciliation testing)."""
        self.cursor.execute(
            """SELECT COALESCE(SUM(amount), 0) FROM meter.ledger
               WHERE namespace = %s
                 AND user_id = %s
                 AND event_type = %s
                 AND resource = %s
                 AND unit = %s""",
            (self.namespace, user_id, event_type, resource or "", unit),
        )
        return float(self.cursor.fetchone()[0])

    def set_reservation_expired(self, reservation_id: str) -> None:
        """Force a reservation to be expired for testing.

        Sets expires_at to one hour in the past, making it eligible for
        release_expired_reservations() cleanup.
        """
        self.cursor.execute(
            "UPDATE meter.reservations SET expires_at = now() - interval '1 hour' "
            "WHERE reservation_id = %s AND namespace = %s",
            (reservation_id, self.namespace),
        )
