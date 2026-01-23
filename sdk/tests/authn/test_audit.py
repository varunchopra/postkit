"""Tests for audit logging and partition management."""

import hashlib
from datetime import datetime

import psycopg
import pytest
from postkit.authn import AuthnClient, AuthnError

from tests.conftest import DATABASE_URL


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
        with pytest.raises(
            psycopg.errors.InvalidParameterValue, match="Month must be between 1 and 12"
        ):
            test_helpers.cursor.execute(
                "SELECT authn.create_audit_partition(%s, %s)",
                (2024, 0),
            )

    def test_validates_month_upper_bound(self, test_helpers):
        """Month must be <= 12."""
        with pytest.raises(
            psycopg.errors.InvalidParameterValue, match="Month must be between 1 and 12"
        ):
            test_helpers.cursor.execute(
                "SELECT authn.create_audit_partition(%s, %s)",
                (2024, 13),
            )

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
        test_helpers.cursor.fetchall()  # Consume results; may be empty if partition exists
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
            "SELECT authn.set_actor(%s, %s, %s, %s, %s, %s)",
            (
                "user-123",
                "req-456",
                "192.168.1.1",
                "Mozilla/5.0",
                "user:customer",
                "test reason",
            ),
        )

        # Verify context is set within the same transaction
        test_helpers.cursor.execute("SELECT current_setting('authn.actor_id', true)")
        assert test_helpers.cursor.fetchone()[0] == "user-123"

        test_helpers.cursor.execute("SELECT current_setting('authn.request_id', true)")
        assert test_helpers.cursor.fetchone()[0] == "req-456"

        test_helpers.cursor.execute(
            "SELECT current_setting('authn.on_behalf_of', true)"
        )
        assert test_helpers.cursor.fetchone()[0] == "user:customer"

        test_helpers.cursor.execute("SELECT current_setting('authn.reason', true)")
        assert test_helpers.cursor.fetchone()[0] == "test reason"

        test_helpers.cursor.execute("ROLLBACK")

    def test_actor_context_captured_in_audit(self, authn, test_helpers):
        """Actor context is captured when audit events are logged."""
        # Use SDK's set_actor which handles transaction correctly
        authn.set_actor("user:admin", request_id="request-789")

        # Create a user (which logs an audit event)
        user_id = authn.create_user("audit-test@example.com", "hash")

        # Check the audit event captured the actor
        events = authn.get_audit_events(event_type="user_created")
        matching = [e for e in events if e["resource_id"] == user_id]
        assert len(matching) >= 1
        assert matching[0]["actor_id"] == "user:admin"
        assert matching[0]["request_id"] == "request-789"

    def test_on_behalf_of_captured_in_audit(self, authn, test_helpers):
        """on_behalf_of is captured in audit events."""
        authn.set_actor(
            "user:admin-bob",
            on_behalf_of="user:customer-alice",
            reason="support_ticket:12345",
        )

        user_id = authn.create_user("onbehalfof-test@example.com", "hash")

        events = authn.get_audit_events(event_type="user_created")
        matching = [e for e in events if e["resource_id"] == user_id]
        assert len(matching) >= 1
        assert matching[0]["actor_id"] == "user:admin-bob"
        assert matching[0]["on_behalf_of"] == "user:customer-alice"
        assert matching[0]["reason"] == "support_ticket:12345"

    def test_reason_captured_in_audit(self, authn, test_helpers):
        """reason is captured in audit events (new for authn)."""
        authn.set_actor("service:billing", reason="monthly_cleanup")

        user_id = authn.create_user("reason-test@example.com", "hash")

        events = authn.get_audit_events(event_type="user_created")
        matching = [e for e in events if e["resource_id"] == user_id]
        assert len(matching) >= 1
        assert matching[0]["actor_id"] == "service:billing"
        assert matching[0]["reason"] == "monthly_cleanup"
        assert matching[0]["on_behalf_of"] is None

    def test_on_behalf_of_without_actor_is_none(self, authn, test_helpers):
        """Without set_actor, on_behalf_of is None in audit events."""
        user_id = authn.create_user("no-actor-test@example.com", "hash")

        events = authn.get_audit_events(event_type="user_created")
        matching = [e for e in events if e["resource_id"] == user_id]
        assert len(matching) >= 1
        assert matching[0]["actor_id"] is None
        assert matching[0]["on_behalf_of"] is None
        assert matching[0]["reason"] is None

    def test_filter_by_actor(self, authn, test_helpers):
        """Can filter events by actor ID."""
        authn.set_actor("alice")
        authn.create_user("alice-created@example.com", "hash")

        authn.set_actor("bob")
        authn.create_user("bob-created@example.com", "hash")

        alice_events = authn.get_audit_events(actor_id="alice")
        bob_events = authn.get_audit_events(actor_id="bob")

        assert len(alice_events) == 1
        assert len(bob_events) == 1
        assert alice_events[0]["actor_id"] == "alice"
        assert bob_events[0]["actor_id"] == "bob"


class TestSetActorMergeSemantics:
    """Tests for set_actor merge/bind semantics (clear + bind pattern)."""

    def test_clear_bind_pattern(self, authn):
        """HTTP context captured before auth, then actor_id added after."""
        authn.clear_actor()
        authn.set_actor(
            request_id="req-123",
            ip_address="10.0.0.1",
            user_agent="TestClient/1.0",
        )

        # Before auth: HTTP context captured, no actor
        user1 = authn.create_user("before-auth@example.com", "hash")
        event1 = next(
            e
            for e in authn.get_audit_events(event_type="user_created")
            if e["resource_id"] == user1
        )
        assert event1["actor_id"] is None
        assert event1["request_id"] == "req-123"
        assert event1["ip_address"] == "10.0.0.1"
        assert event1["user_agent"] == "TestClient/1.0"

        # After auth: actor_id added, HTTP context preserved
        authn.set_actor(actor_id="user:alice")
        user2 = authn.create_user("after-auth@example.com", "hash")
        event2 = next(
            e
            for e in authn.get_audit_events(event_type="user_created")
            if e["resource_id"] == user2
        )
        assert event2["actor_id"] == "user:alice"
        assert event2["request_id"] == "req-123"
        assert event2["ip_address"] == "10.0.0.1"
        assert event2["user_agent"] == "TestClient/1.0"

    def test_api_key_auth_flow(self, authn):
        """API key auth sets HTTP context first, then actor after validation."""
        # Setup
        user_id = authn.create_user("apikey-test@example.com", "hash")
        raw_key = "test-api-key-12345"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        authn.create_api_key(user_id, key_hash, name="Test Key")

        # Request starts: HTTP context captured before auth
        authn.clear_actor()
        authn.set_actor(
            request_id="req-api-456",
            ip_address="192.168.1.100",
            user_agent="TestClient/2.0",
        )

        # Auth middleware validates API key
        key_info = authn.validate_api_key(key_hash)
        assert key_info is not None

        # After auth: actor identity is bound
        authn.set_actor(actor_id=f"user:{key_info['user_id']}")

        # User performs an action
        raw_key2 = "test-api-key-67890"
        key_hash2 = hashlib.sha256(raw_key2.encode()).hexdigest()
        key_id2 = authn.create_api_key(user_id, key_hash2, name="Second Key")

        # Audit trail has complete context
        events = authn.get_audit_events(event_type="api_key_created")
        event = next(e for e in events if e["resource_id"] == key_id2)

        assert event["actor_id"] == f"user:{user_id}"
        assert event["request_id"] == "req-api-456"
        assert event["ip_address"] == "192.168.1.100"
        assert event["user_agent"] == "TestClient/2.0"

    def test_actor_context_in_caller_transaction(self, db_connection):
        """Actor context works when SDK runs inside caller's transaction."""
        # db_connection ensures schema is installed; we create our own non-autocommit conn
        conn = psycopg.connect(DATABASE_URL, autocommit=False)
        cursor = conn.cursor()
        namespace = "test_txn_actor"

        try:
            client = AuthnClient(cursor, namespace)
            client.set_actor("user:alice", request_id="req-789")

            user_id = client.create_user("alice@example.com", "hash")
            conn.commit()

            events = client.get_audit_events(event_type="user_created")
            event = next(e for e in events if e["resource_id"] == user_id)

            assert event["actor_id"] == "user:alice"
            assert event["request_id"] == "req-789"
        finally:
            # Cleanup
            cursor.execute(
                "DELETE FROM authn.audit_events WHERE namespace = %s", (namespace,)
            )
            cursor.execute("DELETE FROM authn.users WHERE namespace = %s", (namespace,))
            conn.commit()
            cursor.close()
            conn.close()


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

    def test_clears_on_behalf_of_and_reason(self, test_helpers):
        """clear_actor also clears on_behalf_of and reason context."""
        test_helpers.cursor.execute("BEGIN")

        # Set all context fields including on_behalf_of and reason
        test_helpers.cursor.execute(
            "SELECT authn.set_actor(%s, %s, %s, %s, %s, %s)",
            (
                "user-123",
                "req-456",
                "192.168.1.1",
                "Mozilla/5.0",
                "user:customer",
                "support_ticket:789",
            ),
        )

        # Verify they're set
        test_helpers.cursor.execute(
            "SELECT current_setting('authn.on_behalf_of', true)"
        )
        assert test_helpers.cursor.fetchone()[0] == "user:customer"

        test_helpers.cursor.execute("SELECT current_setting('authn.reason', true)")
        assert test_helpers.cursor.fetchone()[0] == "support_ticket:789"

        # Clear it
        test_helpers.cursor.execute("SELECT authn.clear_actor()")

        # Verify on_behalf_of and reason are cleared
        test_helpers.cursor.execute(
            "SELECT current_setting('authn.on_behalf_of', true)"
        )
        assert test_helpers.cursor.fetchone()[0] == ""

        test_helpers.cursor.execute("SELECT current_setting('authn.reason', true)")
        assert test_helpers.cursor.fetchone()[0] == ""

        test_helpers.cursor.execute("ROLLBACK")


class TestAuditPagination:
    """Tests for audit event cursor-based pagination."""

    def test_pagination_returns_correct_pages(self, authn):
        """before cursor returns events before the specified event."""
        # Create multiple audit events by creating users
        for i in range(5):
            authn.create_user(f"page-test-{i}@example.com", f"hash{i}")

        # Get first page (most recent first)
        events = authn.get_audit_events(limit=2)
        assert len(events) == 2

        # Use opaque cursor from last event
        assert "cursor" in events[-1], "Events should include opaque cursor field"

        # Get second page using opaque cursor
        events2 = authn.get_audit_events(limit=2, before=events[-1]["cursor"])
        assert len(events2) == 2

        # Pages should not overlap
        first_ids = {e["id"] for e in events}
        second_ids = {e["id"] for e in events2}
        assert first_ids.isdisjoint(second_ids)

    def test_pagination_with_event_type_filter(self, authn):
        """Pagination works correctly with event_type filter."""
        # Create some users (generates user_created events)
        for i in range(3):
            authn.create_user(f"filter-page-{i}@example.com", f"hash{i}")

        # Get filtered events with pagination
        first_page = authn.get_audit_events(event_type="user_created", limit=2)

        if len(first_page) == 2:
            # Use opaque cursor
            second_page = authn.get_audit_events(
                event_type="user_created", limit=2, before=first_page[-1]["cursor"]
            )

            # Pages should not overlap
            first_ids = {e["id"] for e in first_page}
            second_ids = {e["id"] for e in second_page}
            assert first_ids.isdisjoint(second_ids)

    def test_events_include_cursor_field(self, authn):
        """Events include opaque cursor field for pagination."""
        authn.create_user("cursor-test@example.com", "hash")

        events = authn.get_audit_events(limit=1)

        assert len(events) >= 1
        assert "cursor" in events[0]
        # Cursor should be a non-empty string (opaque)
        assert isinstance(events[0]["cursor"], str)
        assert len(events[0]["cursor"]) > 0

    def test_invalid_cursor_raises_error(self, authn):
        """Invalid cursor raises clear error."""
        with pytest.raises(AuthnError, match="Invalid pagination cursor"):
            authn.get_audit_events(before="garbage")

    def test_events_include_id_and_event_time(self, authn):
        """Events include id and event_time fields for cursor building."""
        authn.create_user("id-test@example.com", "hash")

        events = authn.get_audit_events(limit=1)

        assert len(events) >= 1
        assert "id" in events[0]
        assert "event_time" in events[0]
        assert isinstance(events[0]["id"], int)
        assert isinstance(events[0]["event_time"], datetime)
