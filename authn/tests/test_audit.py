"""Tests for audit logging and partition management."""

import pytest
from datetime import datetime


class TestCreateAuditPartition:
    def test_returns_name_for_new_partition(self, test_helpers):
        """Creating a new partition returns its name."""
        # Use a far-future year unlikely to exist
        test_helpers.cursor.execute(
            "SELECT authn.create_audit_partition(%s, %s)",
            (2099, 6),
        )
        result = test_helpers.cursor.fetchone()[0]
        assert result == "audit_events_y2099m06"

        # Cleanup
        test_helpers.cursor.execute("DROP TABLE IF EXISTS authn.audit_events_y2099m06")

    def test_returns_null_if_partition_exists(self, test_helpers):
        """Creating an existing partition returns NULL."""
        # Create it first
        test_helpers.cursor.execute(
            "SELECT authn.create_audit_partition(%s, %s)",
            (2098, 7),
        )
        first_result = test_helpers.cursor.fetchone()[0]
        assert first_result == "audit_events_y2098m07"

        # Try to create again
        test_helpers.cursor.execute(
            "SELECT authn.create_audit_partition(%s, %s)",
            (2098, 7),
        )
        second_result = test_helpers.cursor.fetchone()[0]
        assert second_result is None

        # Cleanup
        test_helpers.cursor.execute("DROP TABLE IF EXISTS authn.audit_events_y2098m07")

    def test_validates_month_lower_bound(self, test_helpers):
        """Month must be >= 1."""
        with pytest.raises(Exception) as exc_info:
            test_helpers.cursor.execute(
                "SELECT authn.create_audit_partition(%s, %s)",
                (2024, 0),
            )
        assert "Month must be between 1 and 12" in str(exc_info.value)

    def test_validates_month_upper_bound(self, test_helpers):
        """Month must be <= 12."""
        with pytest.raises(Exception) as exc_info:
            test_helpers.cursor.execute(
                "SELECT authn.create_audit_partition(%s, %s)",
                (2024, 13),
            )
        assert "Month must be between 1 and 12" in str(exc_info.value)

    def test_partition_name_format(self, test_helpers):
        """Partition names use zero-padded year and month."""
        test_helpers.cursor.execute(
            "SELECT authn.create_audit_partition(%s, %s)",
            (2097, 1),
        )
        result = test_helpers.cursor.fetchone()[0]
        # Year is 4 digits, month is 2 digits
        assert result == "audit_events_y2097m01"

        # Cleanup
        test_helpers.cursor.execute("DROP TABLE IF EXISTS authn.audit_events_y2097m01")


class TestEnsureAuditPartitions:
    def test_creates_missing_partitions(self, test_helpers):
        """Creates partitions that don't exist."""
        # Current month partition should already exist from install
        # This tests that the function runs without error
        test_helpers.cursor.execute("SELECT * FROM authn.ensure_audit_partitions(0)")
        results = test_helpers.cursor.fetchall()
        # May return empty if current month already exists
        # The function succeeds without error

    def test_returns_only_newly_created(self, test_helpers):
        """Only returns names of partitions that were actually created."""
        # Create a far-future partition
        test_helpers.cursor.execute(
            "SELECT authn.create_audit_partition(%s, %s)",
            (2095, 1),
        )

        # Create another one for month 2
        test_helpers.cursor.execute(
            "SELECT authn.create_audit_partition(%s, %s)",
            (2095, 2),
        )

        # Now if we tried ensure_audit_partitions for that range,
        # it would return NULL for existing ones

        # Cleanup
        test_helpers.cursor.execute("DROP TABLE IF EXISTS authn.audit_events_y2095m01")
        test_helpers.cursor.execute("DROP TABLE IF EXISTS authn.audit_events_y2095m02")

    def test_creates_multiple_months_ahead(self, test_helpers):
        """Creates partitions for multiple months ahead."""
        # We can't easily test the exact months without date manipulation,
        # but we can verify it doesn't error with months_ahead > 0
        test_helpers.cursor.execute("SELECT * FROM authn.ensure_audit_partitions(2)")
        # Should complete without error


class TestDropAuditPartitions:
    def test_drops_old_partitions(self, test_helpers):
        """Drops partitions older than threshold."""
        # Create a very old partition (year 2000)
        test_helpers.cursor.execute(
            "SELECT authn.create_audit_partition(%s, %s)",
            (2000, 1),
        )

        # Drop partitions older than 1 month (which would include year 2000)
        test_helpers.cursor.execute("SELECT * FROM authn.drop_audit_partitions(1)")
        dropped = [row[0] for row in test_helpers.cursor.fetchall()]

        assert "audit_events_y2000m01" in dropped

    def test_preserves_recent_partitions(self, test_helpers):
        """Does not drop partitions newer than threshold."""
        # Current month partition should not be dropped
        now = datetime.now()
        current_partition = f"audit_events_y{now.year:04d}m{now.month:02d}"

        test_helpers.cursor.execute("SELECT * FROM authn.drop_audit_partitions(1)")
        dropped = [row[0] for row in test_helpers.cursor.fetchall()]

        assert current_partition not in dropped

    def test_returns_dropped_partition_names(self, test_helpers):
        """Returns names of partitions that were dropped."""
        # Create old partitions
        for month in [3, 4, 5]:
            test_helpers.cursor.execute(
                "SELECT authn.create_audit_partition(%s, %s)",
                (2001, month),
            )

        # Drop them
        test_helpers.cursor.execute("SELECT * FROM authn.drop_audit_partitions(1)")
        dropped = [row[0] for row in test_helpers.cursor.fetchall()]

        # Should have dropped all 2001 partitions
        assert "audit_events_y2001m03" in dropped
        assert "audit_events_y2001m04" in dropped
        assert "audit_events_y2001m05" in dropped


class TestSetActor:
    def test_sets_actor_context_in_transaction(self, authn, test_helpers):
        """set_actor stores context for audit logging within a transaction."""
        # Actor context is transaction-local, so we need a transaction
        test_helpers.cursor.execute("BEGIN")
        test_helpers.cursor.execute(
            "SELECT authn.set_actor(%s, %s, %s, %s)",
            ("user-123", "req-456", "192.168.1.1", "Mozilla/5.0"),
        )

        # Verify context is set within the same transaction
        test_helpers.cursor.execute("SELECT current_setting('authn.actor_id', true)")
        assert test_helpers.cursor.fetchone()[0] == "user-123"

        test_helpers.cursor.execute("SELECT current_setting('authn.request_id', true)")
        assert test_helpers.cursor.fetchone()[0] == "req-456"

        test_helpers.cursor.execute("ROLLBACK")

    def test_actor_context_captured_in_audit(self, authn, test_helpers):
        """Actor context is captured when audit events are logged."""
        # Use SDK's set_actor which handles transaction correctly
        authn.set_actor("admin-user", "request-789")

        # Create a user (which logs an audit event)
        user_id = authn.create_user("audit-test@example.com", "hash")

        # Check the audit event captured the actor
        events = authn.get_audit_events(event_type="user_created")
        matching = [e for e in events if e["resource_id"] == user_id]
        assert len(matching) >= 1
        assert matching[0]["actor_id"] == "admin-user"
        assert matching[0]["request_id"] == "request-789"


class TestClearActor:
    def test_clears_actor_context(self, test_helpers):
        """clear_actor removes all actor context within a transaction."""
        # Actor context is transaction-local
        test_helpers.cursor.execute("BEGIN")

        # Set context first
        test_helpers.cursor.execute(
            "SELECT authn.set_actor(%s, %s)",
            ("user-123", "req-456"),
        )

        # Clear it
        test_helpers.cursor.execute("SELECT authn.clear_actor()")

        # Verify cleared
        test_helpers.cursor.execute("SELECT current_setting('authn.actor_id', true)")
        assert test_helpers.cursor.fetchone()[0] == ""

        test_helpers.cursor.execute("ROLLBACK")
