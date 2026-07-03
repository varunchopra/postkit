"""Test helpers for presence - direct table access for test setup/teardown."""

from tests.helpers import fetch_row


def cleanup_namespace(cursor, namespace: str):
    """Delete all presence data for a namespace."""
    cursor.execute(
        "DELETE FROM presence.transitions WHERE namespace = %s", (namespace,)
    )
    cursor.execute("DELETE FROM presence.entities WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM presence.config WHERE namespace = %s", (namespace,))


class PresenceTestHelpers:
    """
    Direct table access for test setup/teardown that bypasses the SDK.

    Use cases:
    - Backdating last_seen so tests never sleep across dead_after
    - Backdating flap_window_started so tests never sleep across the window
    - Inspecting raw entity/transition state
    """

    def __init__(self, cursor, namespace: str):
        self.cursor = cursor
        self.namespace = namespace
        self.cursor.execute("SELECT presence.set_tenant(%s)", (namespace,))

    def get_entity_row(self, entity: str) -> dict | None:
        """Get an entity directly from the table."""
        self.cursor.execute(
            "SELECT * FROM presence.entities WHERE namespace = %s AND entity_id = %s",
            (self.namespace, entity),
        )
        return fetch_row(self.cursor)

    def get_transitions(self, entity: str | None = None) -> list[dict]:
        """Get transitions in id order (oldest first)."""
        self.cursor.execute(
            "SELECT * FROM presence.transitions "
            "WHERE namespace = %s AND (%s::text IS NULL OR entity_id = %s) "
            "ORDER BY id",
            (self.namespace, entity, entity),
        )
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]

    def set_last_seen(self, entity: str, interval: str) -> None:
        """Force last_seen relative to now (e.g. '-10 minutes' = overdue).

        Direct UPDATE so tests never sleep across a liveness boundary.
        """
        self.cursor.execute(
            "UPDATE presence.entities "
            "SET last_seen = clock_timestamp() + %s::interval "
            "WHERE namespace = %s AND entity_id = %s",
            (interval, self.namespace, entity),
        )

    def set_flap_window_started(self, entity: str, interval: str) -> None:
        """Force the flap window start relative to now (e.g. '-1 hour')."""
        self.cursor.execute(
            "UPDATE presence.entities "
            "SET flap_window_started = clock_timestamp() + %s::interval "
            "WHERE namespace = %s AND entity_id = %s",
            (interval, self.namespace, entity),
        )

    def age_transitions(self, age: str) -> None:
        """Backdate transition timestamps to make them trim-eligible."""
        self.cursor.execute(
            "UPDATE presence.transitions SET at = now() - %s::interval "
            "WHERE namespace = %s",
            (age, self.namespace),
        )

    def set_config(self, kind: str = "default", **kwargs) -> None:
        """Upsert a config row for this namespace with the given columns."""
        cols = list(kwargs.keys())
        vals = list(kwargs.values())
        assignments = ", ".join(f"{c} = EXCLUDED.{c}" for c in cols)
        self.cursor.execute(
            f"INSERT INTO presence.config (namespace, kind, {', '.join(cols)}) "
            f"VALUES (%s, %s, {', '.join(['%s'] * len(cols))}) "
            f"ON CONFLICT (namespace, kind) DO UPDATE SET {assignments}",
            (self.namespace, kind, *vals),
        )
