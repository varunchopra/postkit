"""Test helpers for config - direct table access for test setup/teardown."""

from tests.helpers import fetch_row


def cleanup_namespace(cursor, namespace: str):
    """Delete all config data for a namespace."""
    cursor.execute("DELETE FROM config.audit_events WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM config.entries WHERE namespace = %s", (namespace,))
    cursor.execute(
        "DELETE FROM config.version_counters WHERE namespace = %s", (namespace,)
    )


class ConfigTestHelpers:
    """
    Direct table access for test setup/teardown that bypasses the SDK.

    Use cases:
    - Inserting specific version states for testing
    - Counting records for verification
    - Testing edge cases that require direct table manipulation
    """

    def __init__(self, cursor, namespace: str):
        self.cursor = cursor
        self.namespace = namespace
        self.cursor.execute("SELECT config.set_tenant(%s)", (namespace,))

    def count_entries(self) -> int:
        """Count total entries (all versions) in namespace."""
        self.cursor.execute(
            "SELECT COUNT(*) FROM config.entries WHERE namespace = %s",
            (self.namespace,),
        )
        return self.cursor.fetchone()[0]

    def count_keys(self) -> int:
        """Count unique keys in namespace."""
        self.cursor.execute(
            "SELECT COUNT(DISTINCT key) FROM config.entries WHERE namespace = %s",
            (self.namespace,),
        )
        return self.cursor.fetchone()[0]

    def count_versions(self, key: str) -> int:
        """Count versions for a specific key."""
        self.cursor.execute(
            "SELECT COUNT(*) FROM config.entries WHERE namespace = %s AND key = %s",
            (self.namespace, key),
        )
        return self.cursor.fetchone()[0]

    def get_active_version(self, key: str) -> int | None:
        """Get the active version number for a key."""
        self.cursor.execute(
            "SELECT version FROM config.entries WHERE namespace = %s AND key = %s AND is_active = true",
            (self.namespace, key),
        )
        row = self.cursor.fetchone()
        return row[0] if row else None

    def get_entry_raw(self, key: str, version: int) -> dict | None:
        """Get an entry directly from the table."""
        self.cursor.execute(
            "SELECT * FROM config.entries WHERE namespace = %s AND key = %s AND version = %s",
            (self.namespace, key, version),
        )
        return fetch_row(self.cursor)

    def count_audit_events(self, event_type: str | None = None) -> int:
        """Count audit events, optionally filtered by type."""
        if event_type:
            self.cursor.execute(
                "SELECT COUNT(*) FROM config.audit_events WHERE namespace = %s AND event_type = %s",
                (self.namespace, event_type),
            )
        else:
            self.cursor.execute(
                "SELECT COUNT(*) FROM config.audit_events WHERE namespace = %s",
                (self.namespace,),
            )
        return self.cursor.fetchone()[0]
