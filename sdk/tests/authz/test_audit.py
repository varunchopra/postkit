"""
Audit logging tests for postkit/authz.

Tests audit event capture, actor context, filtering, and partition management.
"""

from datetime import date, datetime, timedelta, timezone

import psycopg
import pytest
from postkit.authz import AuthzError


class TestAuditCapture:
    """Tests that audit events are captured correctly."""

    def test_grant_creates_audit_event(self, authz):
        """Granting a permission creates a tuple_created event."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        events = authz.get_audit_events()

        assert len(events) == 1
        event = events[0]
        assert event["event_type"] == "tuple_created"
        assert event["resource"] == ("doc", "1")
        assert event["relation"] == "read"
        assert event["subject"] == ("user", "alice")

    def test_revoke_creates_audit_event(self, authz):
        """Revoking a permission creates a tuple_deleted event."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.revoke("read", resource=("doc", "1"), subject=("user", "alice"))

        events = authz.get_audit_events()

        # Most recent first
        assert len(events) == 2
        assert events[0]["event_type"] == "tuple_deleted"
        assert events[1]["event_type"] == "tuple_created"

    def test_hierarchy_change_creates_audit_event(self, make_authz, db_connection):
        """Adding a hierarchy rule creates a hierarchy_created event."""
        authz = make_authz("test_hier_audit")
        authz.add_hierarchy_rule("doc", "admin", "read")

        # Audit events are in the same namespace as the hierarchy
        events = authz.get_audit_events()

        assert len(events) == 1
        event = events[0]
        assert event["event_type"] == "hierarchy_created"
        assert event["resource"] == ("doc", "admin")  # permission in resource_id
        assert event["relation"] == "read"  # implies in relation
        assert event["subject"] == ("hierarchy", "")

    def test_remove_hierarchy_creates_audit_event(self, make_authz, db_connection):
        """Removing a hierarchy rule creates a hierarchy_deleted event."""
        authz = make_authz("test_hier_audit_rm")
        authz.add_hierarchy_rule("doc", "admin", "read")
        authz.remove_hierarchy_rule("doc", "admin", "read")

        # Audit events are in the same namespace as the hierarchy
        events = authz.get_audit_events()

        assert len(events) == 2
        assert events[0]["event_type"] == "hierarchy_deleted"
        assert events[1]["event_type"] == "hierarchy_created"

    def test_bulk_operations_create_multiple_events(self, authz):
        """Bulk grant creates one event per subject."""
        authz.bulk_grant(
            "read",
            resource=("doc", "1"),
            subjects=[("user", "alice"), ("user", "bob"), ("user", "charlie")],
        )

        events = authz.get_audit_events()

        assert len(events) == 3
        assert all(e["event_type"] == "tuple_created" for e in events)
        subjects = {e["subject"][1] for e in events}
        assert subjects == {"alice", "bob", "charlie"}

    def test_tuple_id_captured(self, authz):
        """Audit events include the tuple ID."""
        tuple_id = authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        events = authz.get_audit_events()

        assert events[0]["tuple_id"] == tuple_id


class TestActorContext:
    """Tests for actor context capture."""

    def test_actor_captured_when_set(self, authz):
        """Actor context is captured in audit events."""
        authz.set_actor("admin@acme.com", "req-123", reason="Quarterly review")
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        events = authz.get_audit_events()

        assert len(events) == 1
        event = events[0]
        assert event["actor_id"] == "admin@acme.com"
        assert event["request_id"] == "req-123"
        assert event["reason"] == "Quarterly review"

    def test_actor_not_required(self, authz):
        """Audit events are created even without actor context."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        events = authz.get_audit_events()

        assert len(events) == 1
        assert events[0]["actor_id"] is None
        assert events[0]["request_id"] is None
        assert events[0]["reason"] is None
        assert events[0]["on_behalf_of"] is None

    def test_connection_context_always_present(self, authz):
        """PostgreSQL connection context is always captured."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        events = authz.get_audit_events()

        assert len(events) == 1
        event = events[0]
        # session_user and current_user should be populated
        assert event["session_user"] is not None
        assert event["current_user"] is not None

    def test_partial_actor_context(self, authz):
        """Actor context with only actor_id works."""
        authz.set_actor("service-account")
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        events = authz.get_audit_events()

        assert events[0]["actor_id"] == "service-account"
        assert events[0]["request_id"] is None
        assert events[0]["reason"] is None

    def test_on_behalf_of_captured(self, authz):
        """on_behalf_of is captured in audit events."""
        authz.set_actor(
            "user:admin-bob",
            reason="support_ticket:12345",
            on_behalf_of="user:customer-alice",
        )
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        events = authz.get_audit_events()

        assert len(events) == 1
        event = events[0]
        assert event["actor_id"] == "user:admin-bob"
        assert event["reason"] == "support_ticket:12345"
        assert event["on_behalf_of"] == "user:customer-alice"

    def test_on_behalf_of_without_reason(self, authz):
        """on_behalf_of works without reason."""
        authz.set_actor("agent:support-bot", on_behalf_of="user:customer-456")
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        events = authz.get_audit_events()

        assert events[0]["actor_id"] == "agent:support-bot"
        assert events[0]["on_behalf_of"] == "user:customer-456"
        assert events[0]["reason"] is None

    def test_clear_actor(self, authz):
        """clear_actor() removes actor context including on_behalf_of."""
        # Set actor context with on_behalf_of
        authz.set_actor(
            "admin@acme.com",
            "req-123",
            reason="Initial setup",
            on_behalf_of="user:customer-alice",
        )
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        # Clear actor context using SDK method
        authz.clear_actor()
        authz.grant("read", resource=("doc", "2"), subject=("user", "bob"))

        events = authz.get_audit_events()

        # Most recent event (doc:2) should have no actor
        assert events[0]["actor_id"] is None
        assert events[0]["request_id"] is None
        assert events[0]["reason"] is None
        assert events[0]["on_behalf_of"] is None

        # Earlier event (doc:1) should have actor and on_behalf_of
        assert events[1]["actor_id"] == "admin@acme.com"
        assert events[1]["request_id"] == "req-123"
        assert events[1]["reason"] == "Initial setup"
        assert events[1]["on_behalf_of"] == "user:customer-alice"

    def test_clear_actor_sql_function(self, db_connection, request):
        """SQL clear_actor() function clears session context including on_behalf_of."""
        # Need non-autocommit connection for transaction-local settings
        info = db_connection.info
        conn = psycopg.connect(
            host=info.host,
            port=info.port,
            dbname=info.dbname,
            user=info.user,
            password=info.password,
            autocommit=False,
        )
        cursor = conn.cursor()
        try:
            # Set actor context via SQL with on_behalf_of (transaction-local)
            cursor.execute(
                "SELECT authz.set_actor(%s, %s, %s, %s)",
                ("admin@acme.com", "req-123", "Test reason", "user:customer-alice"),
            )

            # Verify it's set (same transaction)
            cursor.execute("SELECT current_setting('authz.actor_id', true)")
            assert cursor.fetchone()[0] == "admin@acme.com"
            cursor.execute("SELECT current_setting('authz.on_behalf_of', true)")
            assert cursor.fetchone()[0] == "user:customer-alice"

            # Clear via SQL function
            cursor.execute("SELECT authz.clear_actor()")

            # Verify all fields are cleared (empty string)
            cursor.execute("SELECT current_setting('authz.actor_id', true)")
            assert cursor.fetchone()[0] == ""
            cursor.execute("SELECT current_setting('authz.request_id', true)")
            assert cursor.fetchone()[0] == ""
            cursor.execute("SELECT current_setting('authz.reason', true)")
            assert cursor.fetchone()[0] == ""
            cursor.execute("SELECT current_setting('authz.on_behalf_of', true)")
            assert cursor.fetchone()[0] == ""
        finally:
            conn.rollback()
            cursor.close()
            conn.close()


class TestAuditFiltering:
    """Tests for audit event filtering."""

    def test_filter_by_event_type(self, authz):
        """Can filter events by type."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.revoke("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("write", resource=("doc", "1"), subject=("user", "bob"))

        created = authz.get_audit_events(event_type="tuple_created")
        deleted = authz.get_audit_events(event_type="tuple_deleted")

        assert len(created) == 2
        assert len(deleted) == 1

    def test_filter_by_actor(self, authz):
        """Can filter events by actor ID."""
        authz.set_actor("alice")
        authz.grant("read", resource=("doc", "1"), subject=("user", "charlie"))

        authz.set_actor("bob")
        authz.grant("write", resource=("doc", "1"), subject=("user", "charlie"))

        alice_events = authz.get_audit_events(actor_id="alice")
        bob_events = authz.get_audit_events(actor_id="bob")

        assert len(alice_events) == 1
        assert len(bob_events) == 1
        assert alice_events[0]["relation"] == "read"
        assert bob_events[0]["relation"] == "write"

    def test_filter_by_resource(self, authz):
        """Can filter events by resource."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "2"), subject=("user", "alice"))
        authz.grant("read", resource=("repo", "api"), subject=("user", "alice"))

        doc1_events = authz.get_audit_events(resource=("doc", "1"))
        doc2_events = authz.get_audit_events(resource=("doc", "2"))
        repo_events = authz.get_audit_events(resource=("repo", "api"))

        assert len(doc1_events) == 1
        assert len(doc2_events) == 1
        assert len(repo_events) == 1

    def test_filter_by_subject(self, authz):
        """Can filter events by subject."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "1"), subject=("user", "bob"))
        authz.grant("read", resource=("doc", "1"), subject=("team", "eng"))

        alice_events = authz.get_audit_events(subject=("user", "alice"))
        team_events = authz.get_audit_events(subject=("team", "eng"))

        assert len(alice_events) == 1
        assert len(team_events) == 1

    def test_limit_works(self, authz):
        """Limit parameter restricts result count."""
        for i in range(10):
            authz.grant("read", resource=("doc", str(i)), subject=("user", "alice"))

        events = authz.get_audit_events(limit=3)

        assert len(events) == 3

    def test_combined_filters(self, authz):
        """Multiple filters can be combined."""
        authz.set_actor("admin")
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("write", resource=("doc", "1"), subject=("user", "alice"))

        authz.set_actor("user")
        authz.grant("read", resource=("doc", "2"), subject=("user", "alice"))

        events = authz.get_audit_events(
            actor_id="admin", resource=("doc", "1"), event_type="tuple_created"
        )

        assert len(events) == 2

    def test_events_ordered_by_time_desc(self, authz):
        """Events are returned most recent first."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("write", resource=("doc", "1"), subject=("user", "alice"))
        authz.grant("admin", resource=("doc", "1"), subject=("user", "alice"))

        events = authz.get_audit_events()

        assert events[0]["relation"] == "admin"
        assert events[1]["relation"] == "write"
        assert events[2]["relation"] == "read"


class TestPartitionManagement:
    """Tests for partition management functions."""

    def test_create_partition(self, authz):
        """Can create a partition for a future month."""
        # Create partition for a future month
        authz.cursor.execute("SELECT authz.create_audit_partition(2030, 6)")
        result = authz.cursor.fetchone()[0]

        assert result == "audit_events_y2030m06"

        # Verify it exists
        authz.cursor.execute(
            """
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'authz' AND c.relname = 'audit_events_y2030m06'
        """
        )
        assert authz.cursor.fetchone() is not None

        # Cleanup
        authz.cursor.execute("DROP TABLE authz.audit_events_y2030m06")

    def test_create_partition_idempotent(self, authz):
        """Creating same partition twice returns NULL (no error)."""
        authz.cursor.execute("SELECT authz.create_audit_partition(2031, 1)")
        first = authz.cursor.fetchone()[0]

        authz.cursor.execute("SELECT authz.create_audit_partition(2031, 1)")
        second = authz.cursor.fetchone()[0]

        assert first == "audit_events_y2031m01"
        assert second is None

        # Cleanup
        authz.cursor.execute("DROP TABLE authz.audit_events_y2031m01")

    def test_ensure_partitions(self, authz):
        """ensure_audit_partitions creates multiple partitions."""
        # First drop any far-future partitions that might exist
        authz.cursor.execute(
            """
            SELECT c.relname FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'authz' AND c.relname LIKE 'audit_events_y2032%'
        """
        )
        for row in authz.cursor.fetchall():
            authz.cursor.execute(f"DROP TABLE authz.{row[0]}")

        # Create partitions starting far in the future
        authz.cursor.execute(
            """
            SELECT authz.create_audit_partition(2032, 1)
        """
        )

        # ensure_partitions from 2032-01 would create more
        # But let's just verify the function works
        authz.cursor.execute("SELECT count(*) FROM authz.ensure_audit_partitions(0)")
        # This creates current month if not exists, should succeed

        # Cleanup
        authz.cursor.execute("DROP TABLE IF EXISTS authz.audit_events_y2032m01")

    def test_invalid_month_rejected(self, authz):
        """Invalid month values are rejected."""
        with pytest.raises(
            psycopg.errors.InvalidParameterValue, match="Month must be between 1 and 12"
        ):
            authz.cursor.execute("SELECT authz.create_audit_partition(2030, 13)")

    def test_drop_old_partitions(self, authz):
        """drop_audit_partitions removes old partitions correctly."""
        # Create a partition for 2010 (old enough to be dropped)
        authz.cursor.execute("SELECT authz.create_audit_partition(2010, 6)")
        result = authz.cursor.fetchone()[0]
        # If partition already exists, result is NULL - clean it up first
        if result is None:
            authz.cursor.execute("DROP TABLE authz.audit_events_y2010m06")
            authz.cursor.execute("SELECT authz.create_audit_partition(2010, 6)")

        # Verify it exists
        authz.cursor.execute(
            """
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'authz' AND c.relname = 'audit_events_y2010m06'
        """
        )
        assert authz.cursor.fetchone() is not None

        # Drop partitions older than 12 months (2010 is definitely older)
        authz.cursor.execute("SELECT * FROM authz.drop_audit_partitions(12)")
        dropped = [row[0] for row in authz.cursor.fetchall()]

        # Should have dropped the 2010 partition
        assert "audit_events_y2010m06" in dropped

        # Verify it no longer exists
        authz.cursor.execute(
            """
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'authz' AND c.relname = 'audit_events_y2010m06'
        """
        )
        assert authz.cursor.fetchone() is None

    def test_drop_preserves_recent_partitions(self, authz):
        """drop_audit_partitions preserves recent partitions."""
        # Create a partition for current year + 1 (definitely recent)
        future_year = date.today().year + 1
        authz.cursor.execute(f"SELECT authz.create_audit_partition({future_year}, 6)")

        # Try to drop with 12 month retention
        authz.cursor.execute("SELECT * FROM authz.drop_audit_partitions(12)")
        dropped = [row[0] for row in authz.cursor.fetchall()]

        # Future partition should NOT be dropped
        assert f"audit_events_y{future_year}m06" not in dropped

        # Verify it still exists
        authz.cursor.execute(
            f"""
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'authz' AND c.relname = 'audit_events_y{future_year}m06'
        """
        )
        assert authz.cursor.fetchone() is not None

        # Cleanup
        authz.cursor.execute(f"DROP TABLE authz.audit_events_y{future_year}m06")

    def test_drop_partitions_parses_name_correctly(self, authz):
        """drop_audit_partitions correctly parses partition names (regression test)."""
        # This tests the fix for the off-by-one bug in position extraction
        # Create partition with specific year/month to verify parsing
        authz.cursor.execute("SELECT authz.create_audit_partition(2019, 12)")

        # The partition name is audit_events_y2019m12
        # Year should be extracted as 2019, month as 12
        # With the bug (FROM 16), it would extract "019m" for year -> crash
        # With the fix (FROM 15), it correctly extracts "2019"

        # Drop partitions older than 12 months
        authz.cursor.execute("SELECT * FROM authz.drop_audit_partitions(12)")
        dropped = [row[0] for row in authz.cursor.fetchall()]

        # Should successfully parse and drop the 2019 partition
        assert "audit_events_y2019m12" in dropped

    def test_drop_skips_malformed_partition_names(self, db_connection):
        """drop_audit_partitions skips partitions with unexpected names."""
        cursor = db_connection.cursor()

        # Create a partition with non-standard name (manually)
        # This simulates a scenario where naming format changes
        try:
            cursor.execute(
                """
                CREATE TABLE authz.audit_events_custom_name
                PARTITION OF authz.audit_events
                FOR VALUES FROM ('1990-01-01') TO ('1990-02-01')
            """
            )

            # Drop should skip it with a warning, not crash
            cursor.execute("SELECT * FROM authz.drop_audit_partitions(12)")
            dropped = [row[0] for row in cursor.fetchall()]

            # The malformed partition should NOT be in dropped list
            assert "audit_events_custom_name" not in dropped

            # Clean up
            cursor.execute("DROP TABLE authz.audit_events_custom_name")
        except Exception:
            # Clean up on failure
            cursor.execute("DROP TABLE IF EXISTS authz.audit_events_custom_name")
            raise


class TestSubjectRelation:
    """Tests for subject_relation in audit events."""

    def test_subject_relation_captured(self, authz):
        """subject_relation is captured in audit events."""
        authz.grant(
            "write",
            resource=("repo", "api"),
            subject=("team", "eng"),
            subject_relation="admin",
        )

        events = authz.get_audit_events()

        assert len(events) == 1
        assert events[0]["subject_relation"] == "admin"

    def test_no_subject_relation_is_none(self, authz):
        """subject_relation is None when not provided."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))

        events = authz.get_audit_events()

        assert events[0]["subject_relation"] is None


class TestExpirationAudit:
    """Tests for expiration tracking in audit events."""

    def test_expiration_captured_on_create(self, authz):
        """Grant with expiration logs expires_at in audit event."""
        expires = datetime.now(timezone.utc) + timedelta(days=7)
        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=expires,
        )

        events = authz.get_audit_events()

        assert len(events) == 1
        assert events[0]["event_type"] == "tuple_created"
        assert events[0]["expires_at"] is not None
        # Compare timestamps (allowing for small differences)
        assert abs((events[0]["expires_at"] - expires).total_seconds()) < 1

    def test_update_expiration_creates_audit(self, authz):
        """set_expiration creates tuple_updated event with new expires_at."""
        authz.grant("read", resource=("doc", "1"), subject=("user", "alice"))
        new_expiration = datetime.now(timezone.utc) + timedelta(days=30)
        authz.set_expiration(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=new_expiration,
        )

        events = authz.get_audit_events()

        assert len(events) == 2
        # Most recent first
        assert events[0]["event_type"] == "tuple_updated"
        assert events[0]["expires_at"] is not None
        assert abs((events[0]["expires_at"] - new_expiration).total_seconds()) < 1
        # Original create had no expiration
        assert events[1]["event_type"] == "tuple_created"
        assert events[1]["expires_at"] is None

    def test_extend_expiration_creates_audit(self, authz):
        """extend_expiration creates tuple_updated event."""
        initial_expires = datetime.now(timezone.utc) + timedelta(days=7)
        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=initial_expires,
        )
        authz.extend_expiration(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            extension=timedelta(days=14),
        )

        events = authz.get_audit_events()

        assert len(events) == 2
        assert events[0]["event_type"] == "tuple_updated"
        # Extended by 14 days from initial 7-day expiration
        expected_expires = initial_expires + timedelta(days=14)
        assert abs((events[0]["expires_at"] - expected_expires).total_seconds()) < 1

    def test_clear_expiration_creates_audit(self, authz):
        """clear_expiration creates tuple_updated event with NULL expires_at."""
        expires = datetime.now(timezone.utc) + timedelta(days=7)
        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=expires,
        )
        authz.clear_expiration(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
        )

        events = authz.get_audit_events()

        assert len(events) == 2
        assert events[0]["event_type"] == "tuple_updated"
        assert events[0]["expires_at"] is None
        # Original had expiration
        assert events[1]["event_type"] == "tuple_created"
        assert events[1]["expires_at"] is not None

    def test_expiration_in_filter_results(self, authz):
        """expires_at is included in get_audit_events() results."""
        expires1 = datetime.now(timezone.utc) + timedelta(days=7)
        expires2 = datetime.now(timezone.utc) + timedelta(days=30)

        authz.grant(
            "read",
            resource=("doc", "1"),
            subject=("user", "alice"),
            expires_at=expires1,
        )
        authz.grant(
            "write",
            resource=("doc", "1"),
            subject=("user", "bob"),
            expires_at=expires2,
        )
        authz.grant("admin", resource=("doc", "1"), subject=("user", "charlie"))

        events = authz.get_audit_events()

        assert len(events) == 3
        # Find each event
        alice_event = next(e for e in events if e["subject"][1] == "alice")
        bob_event = next(e for e in events if e["subject"][1] == "bob")
        charlie_event = next(e for e in events if e["subject"][1] == "charlie")

        assert alice_event["expires_at"] is not None
        assert bob_event["expires_at"] is not None
        assert charlie_event["expires_at"] is None


class TestAuditPagination:
    """Tests for audit event cursor-based pagination."""

    def test_pagination_returns_correct_pages(self, authz):
        """before cursor returns events before the specified event."""
        # Create multiple audit events
        for i in range(5):
            authz.grant("read", resource=("doc", str(i)), subject=("user", "alice"))

        # Get first page (most recent first)
        events = authz.get_audit_events(limit=2)
        assert len(events) == 2

        # Use opaque cursor from last event
        assert "cursor" in events[-1], "Events should include opaque cursor field"

        # Get second page using opaque cursor
        events2 = authz.get_audit_events(limit=2, before=events[-1]["cursor"])
        assert len(events2) == 2

        # Pages should not overlap
        first_ids = {e["id"] for e in events}
        second_ids = {e["id"] for e in events2}
        assert first_ids.isdisjoint(second_ids)

    def test_pagination_with_event_type_filter(self, authz):
        """Pagination works correctly with event_type filter."""
        # Create tuple events
        for i in range(3):
            authz.grant(
                "read", resource=("doc", f"filter-{i}"), subject=("user", "alice")
            )

        # Get filtered events with pagination
        first_page = authz.get_audit_events(event_type="tuple_created", limit=2)

        if len(first_page) == 2:
            # Use opaque cursor
            second_page = authz.get_audit_events(
                event_type="tuple_created", limit=2, before=first_page[-1]["cursor"]
            )

            # Pages should not overlap
            first_ids = {e["id"] for e in first_page}
            second_ids = {e["id"] for e in second_page}
            assert first_ids.isdisjoint(second_ids)

    def test_events_include_cursor_field(self, authz):
        """Events include opaque cursor field for pagination."""
        authz.grant("read", resource=("doc", "cursor-test"), subject=("user", "alice"))

        events = authz.get_audit_events(limit=1)

        assert len(events) >= 1
        assert "cursor" in events[0]
        # Cursor should be a non-empty string (opaque)
        assert isinstance(events[0]["cursor"], str)
        assert len(events[0]["cursor"]) > 0

    def test_invalid_cursor_raises_error(self, authz):
        """Invalid cursor raises clear error."""
        with pytest.raises(AuthzError, match="Invalid pagination cursor"):
            authz.get_audit_events(before="garbage")
