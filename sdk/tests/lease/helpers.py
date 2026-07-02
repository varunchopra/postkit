"""Test helpers for lease - direct table access for test setup/teardown."""

from tests.helpers import fetch_row


def cleanup_namespace(cursor, namespace: str):
    """Delete all lease data for a namespace."""
    cursor.execute("DELETE FROM lease.events WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM lease.leases WHERE namespace = %s", (namespace,))
    cursor.execute(
        "DELETE FROM lease.fence_counters WHERE namespace = %s", (namespace,)
    )
    cursor.execute("DELETE FROM lease.config WHERE namespace = %s", (namespace,))


class LeaseTestHelpers:
    """
    Direct table access for test setup/teardown that bypasses the SDK.

    Use cases:
    - Forcing lease expiry without sleeping (set_expires_at)
    - Inspecting raw lease/counter/event state
    """

    def __init__(self, cursor, namespace: str):
        self.cursor = cursor
        self.namespace = namespace
        self.cursor.execute("SELECT lease.set_tenant(%s)", (namespace,))

    def get_lease_row(self, name: str) -> dict | None:
        """Get a lease directly from the table."""
        self.cursor.execute(
            "SELECT * FROM lease.leases WHERE namespace = %s AND name = %s",
            (self.namespace, name),
        )
        return fetch_row(self.cursor)

    def get_counter(self, name: str) -> int | None:
        """Get the fence counter for a lease name."""
        self.cursor.execute(
            "SELECT counter FROM lease.fence_counters "
            "WHERE namespace = %s AND name = %s",
            (self.namespace, name),
        )
        row = self.cursor.fetchone()
        return row[0] if row else None

    def count_events(self, name: str | None = None, event: str | None = None) -> int:
        """Count events, optionally filtered by lease name and/or event type."""
        conditions = ["namespace = %s"]
        params: list = [self.namespace]

        if name:
            conditions.append("name = %s")
            params.append(name)
        if event:
            conditions.append("event = %s")
            params.append(event)

        self.cursor.execute(
            f"SELECT COUNT(*) FROM lease.events WHERE {' AND '.join(conditions)}",
            tuple(params),
        )
        return self.cursor.fetchone()[0]

    def get_events(self, name: str) -> list[dict]:
        """Get all events for a lease name in id order."""
        self.cursor.execute(
            "SELECT * FROM lease.events WHERE namespace = %s AND name = %s ORDER BY id",
            (self.namespace, name),
        )
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    def set_expires_at(self, name: str, interval: str) -> None:
        """Force a lease's expiry relative to now (e.g. '-1 minute' to expire).

        Direct UPDATE so tests never sleep to cross a TTL boundary.
        acquired_at is backdated too, keeping leases_expiry_sane satisfied.
        """
        self.cursor.execute(
            "UPDATE lease.leases SET expires_at = now() + %s::interval, "
            "acquired_at = now() + %s::interval - interval '1 hour' "
            "WHERE namespace = %s AND name = %s",
            (interval, interval, self.namespace, name),
        )

    def age_events(self, age: str, name: str | None = None) -> None:
        """Backdate event timestamps to simulate aging (e.g. '40 days')."""
        if name:
            self.cursor.execute(
                "UPDATE lease.events SET at = now() - %s::interval "
                "WHERE namespace = %s AND name = %s",
                (age, self.namespace, name),
            )
        else:
            self.cursor.execute(
                "UPDATE lease.events SET at = now() - %s::interval "
                "WHERE namespace = %s",
                (age, self.namespace),
            )

    def set_config(self, **kwargs) -> None:
        """Upsert this namespace's lease config row with the given columns."""
        cols = list(kwargs.keys())
        vals = list(kwargs.values())
        assignments = ", ".join(f"{c} = EXCLUDED.{c}" for c in cols)
        self.cursor.execute(
            f"INSERT INTO lease.config (namespace, {', '.join(cols)}) "
            f"VALUES (%s, {', '.join(['%s'] * len(cols))}) "
            f"ON CONFLICT (namespace) DO UPDATE SET {assignments}",
            (self.namespace, *vals),
        )
