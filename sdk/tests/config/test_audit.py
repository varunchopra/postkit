"""Tests for audit logging and actor context."""

from datetime import datetime

import pytest
from postkit.config import ConfigError, ConfigErrorCode, ConfigValidationError

from tests.helpers import (
    assert_audit_fields,
    assert_partition_create,
    assert_partition_idempotent,
    assert_partition_rejects_invalid_month,
    cleanup_partition,
)


class TestSetActor:
    """Actor context is captured in audit events when set."""

    def test_captures_actor_in_audit(self, config):
        """Actor context is captured in audit events."""
        config.set_actor("user:alice")
        config.set("prompts/bot", {"v": 1})

        events = config.get_audit_events(event_type="entry_created")

        assert len(events) == 1
        assert events[0]["actor_id"] == "user:alice"

    def test_captures_request_id(self, config):
        """Request ID is captured in audit events."""
        config.set_actor("user:alice", request_id="req-123")
        config.set("prompts/bot", {"v": 1})

        events = config.get_audit_events(event_type="entry_created")

        assert events[0]["request_id"] == "req-123"

    def test_captures_on_behalf_of(self, config):
        """on_behalf_of is captured in audit events."""
        config.set_actor(
            "user:admin-bob",
            on_behalf_of="user:customer-alice",
            reason="support_ticket:12345",
        )
        config.set("prompts/bot", {"v": 1})

        events = config.get_audit_events(event_type="entry_created")

        assert_audit_fields(
            events[0],
            actor_id="user:admin-bob",
            on_behalf_of="user:customer-alice",
            reason="support_ticket:12345",
        )

    def test_reason_without_on_behalf_of(self, config):
        """Reason can be set without on_behalf_of."""
        config.set_actor("service:deploy", reason="deployment:v1.2.3")
        config.set("prompts/bot", {"v": 1})

        events = config.get_audit_events(event_type="entry_created")

        assert_audit_fields(
            events[0],
            actor_id="service:deploy",
            reason="deployment:v1.2.3",
            on_behalf_of=None,
        )


class TestClearActor:
    """Clearing actor context stops capture in subsequent events."""

    def test_clears_actor_context(self, config):
        """clear_actor() removes actor context."""
        config.set_actor("user:alice", request_id="req-123")
        config.set("prompts/bot1", {"v": 1})

        config.clear_actor()
        config.set("prompts/bot2", {"v": 1})

        events = config.get_audit_events(key="prompts/bot2")

        assert events[0]["actor_id"] is None
        assert events[0]["request_id"] is None


class TestAuditEvents:
    """Tests for audit event logging."""

    def test_entry_created_event(self, config):
        """entry_created event is logged on set()."""
        config.set("prompts/bot", {"template": "hello"})

        events = config.get_audit_events(event_type="entry_created")

        assert len(events) == 1
        assert events[0]["key"] == "prompts/bot"
        assert events[0]["version"] == 1
        assert events[0]["new_value"]["template"] == "hello"

    def test_entry_created_captures_old_value(self, config):
        """entry_created captures old value when updating."""
        config.set("prompts/bot", {"template": "v1"})
        config.set("prompts/bot", {"template": "v2"})

        events = config.get_audit_events(key="prompts/bot", event_type="entry_created")

        # Most recent first
        assert events[0]["version"] == 2
        assert events[0]["old_value"]["template"] == "v1"
        assert events[0]["new_value"]["template"] == "v2"

    def test_entry_activated_event(self, config):
        """entry_activated event is logged on activate()."""
        config.set("prompts/bot", {"template": "v1"})
        config.set("prompts/bot", {"template": "v2"})
        config.activate("prompts/bot", 1)

        events = config.get_audit_events(event_type="entry_activated")

        assert len(events) == 1
        assert events[0]["key"] == "prompts/bot"
        assert events[0]["version"] == 1

    def test_activate_same_version_skips_audit(self, config):
        """Activating the already-active version does not log an audit event."""
        config.set("prompts/bot", {"v": 1})
        config.activate("prompts/bot", 1)

        events = config.get_audit_events(event_type="entry_activated")

        assert len(events) == 0

    def test_entry_deleted_event(self, config):
        """entry_deleted event is logged on delete()."""
        config.set("prompts/bot", {"template": "hello"})
        config.delete("prompts/bot")

        events = config.get_audit_events(event_type="entry_deleted")

        assert len(events) == 1
        assert events[0]["key"] == "prompts/bot"
        assert events[0]["old_value"]["template"] == "hello"

    def test_entry_version_deleted_event(self, config):
        """entry_version_deleted event is logged on delete_version()."""
        config.set("prompts/bot", {"template": "v1"})
        config.set("prompts/bot", {"template": "v2"})
        config.delete_version("prompts/bot", 1)

        events = config.get_audit_events(event_type="entry_version_deleted")

        assert len(events) == 1
        assert events[0]["key"] == "prompts/bot"
        assert events[0]["version"] == 1

    def test_audit_without_actor(self, config):
        """Audit events are created even without actor context."""
        config.set("prompts/bot", {"template": "hello"})

        events = config.get_audit_events()

        assert len(events) == 1
        assert events[0]["actor_id"] is None

    def test_filter_by_actor(self, config):
        """Can filter events by actor ID."""
        config.set_actor("alice")
        config.set("prompts/alice-bot", {"template": "alice's bot"})

        config.set_actor("bob")
        config.set("prompts/bob-bot", {"template": "bob's bot"})

        alice_events = config.get_audit_events(actor_id="alice")
        bob_events = config.get_audit_events(actor_id="bob")

        assert len(alice_events) == 1
        assert len(bob_events) == 1
        assert alice_events[0]["actor_id"] == "alice"
        assert bob_events[0]["actor_id"] == "bob"


class TestAuditPartitions:
    """Tests for audit partition management."""

    def test_create_partition(self, config, test_helpers):
        """create_audit_partition() creates a partition."""
        name = assert_partition_create(test_helpers.cursor, "config", 2099, 6)
        cleanup_partition(test_helpers.cursor, "config", name)

    def test_create_partition_returns_null_if_exists(self, config, test_helpers):
        """create_audit_partition() returns NULL if partition exists."""
        assert_partition_idempotent(test_helpers.cursor, "config", 2098, 7)
        cleanup_partition(test_helpers.cursor, "config", "audit_events_y2098m07")

    def test_validates_month_bounds(self, config, test_helpers):
        """create_audit_partition() validates month range."""
        assert_partition_rejects_invalid_month(test_helpers.cursor, "config")

    def test_validates_year_bounds(self, config, test_helpers):
        """create_audit_partition() validates year range."""
        import psycopg

        with pytest.raises(
            psycopg.errors.InvalidParameterValue, match="Year must be between"
        ):
            test_helpers.cursor.execute(
                "SELECT config.create_audit_partition(%s, %s)", (1969, 6)
            )

    def test_drop_old_partitions(self, config, test_helpers):
        """drop_audit_partitions() drops old partitions."""
        # Create partitions for testing (far in past)
        test_helpers.cursor.execute(
            "SELECT config.create_audit_partition(%s, %s)",
            (2010, 1),
        )
        test_helpers.cursor.execute(
            "SELECT config.create_audit_partition(%s, %s)",
            (2010, 2),
        )

        # Drop partitions older than 1 month (should drop both 2010 partitions)
        test_helpers.cursor.execute("SELECT config.drop_audit_partitions(%s)", (1,))
        dropped = [row[0] for row in test_helpers.cursor.fetchall()]

        assert "audit_events_y2010m01" in dropped
        assert "audit_events_y2010m02" in dropped

    def test_drop_partitions_keeps_recent(self, config, test_helpers):
        """drop_audit_partitions() keeps recent partitions."""
        # Create a future partition (should never be dropped)
        test_helpers.cursor.execute(
            "SELECT config.create_audit_partition(%s, %s)",
            (2099, 12),
        )

        # Drop with keep_months=1 - future partition should remain
        test_helpers.cursor.execute("SELECT config.drop_audit_partitions(%s)", (1,))
        dropped = [row[0] for row in test_helpers.cursor.fetchall()]

        assert "audit_events_y2099m12" not in dropped

        # Cleanup
        test_helpers.cursor.execute("DROP TABLE IF EXISTS config.audit_events_y2099m12")


class TestGetStats:
    """Namespace statistics are accurately reported."""

    def test_returns_key_counts(self, config):
        """get_stats() returns key and version counts."""
        config.set("prompts/a", {"v": 1})
        config.set("prompts/a", {"v": 2})
        config.set("prompts/b", {"v": 1})
        config.set("flags/x", {"enabled": True})

        stats = config.get_stats()

        assert stats["total_keys"] == 3
        assert stats["total_versions"] == 4

    def test_returns_keys_by_prefix(self, config):
        """get_stats() returns breakdown by prefix."""
        config.set("prompts/a", {"v": 1})
        config.set("prompts/b", {"v": 1})
        config.set("flags/x", {"enabled": True})

        stats = config.get_stats()

        assert stats["keys_by_prefix"]["prompts"] == 2
        assert stats["keys_by_prefix"]["flags"] == 1


class TestCleanupOldVersions:
    """Old inactive versions are removed while preserving recent history."""

    def test_removes_old_inactive_versions(self, config, test_helpers):
        """cleanup_old_versions() removes old inactive versions."""
        # Create many versions
        for i in range(5):
            config.set("prompts/bot", {"v": i + 1})

        # Keep only 2 inactive versions (plus active = 3 total)
        deleted = config.cleanup_old_versions(keep_versions=2)

        assert deleted == 2  # Deleted v1 and v2
        assert test_helpers.count_versions("prompts/bot") == 3

    def test_cleanup_when_active_not_newest(self, config, test_helpers):
        """cleanup works correctly when active version isn't the newest."""
        # Create v1, v2, v3
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})
        config.set("prompts/bot", {"v": 3})

        # Activate v1 (oldest) - now v2 and v3 are inactive
        config.activate("prompts/bot", 1)

        # Keep 1 inactive version - should delete v2 (older inactive)
        deleted = config.cleanup_old_versions(keep_versions=1)

        assert deleted == 1
        # Should have: v1 (active), v3 (kept inactive)
        assert test_helpers.count_versions("prompts/bot") == 2

    def test_rejects_negative_keep_versions(self, config):
        with pytest.raises(ConfigValidationError) as exc_info:
            config.cleanup_old_versions(keep_versions=-1)
        assert exc_info.value.error_code == ConfigErrorCode.VAL_KEEP_VERSIONS_NEGATIVE

    def test_rejects_null_without_changing_history(self, config):
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})
        before = config.history("prompts/bot")

        with pytest.raises(ConfigValidationError) as exc_info:
            config.cleanup_old_versions(keep_versions=None)

        assert exc_info.value.sqlstate == "22004"
        assert exc_info.value.error_code == ConfigErrorCode.VAL_KEEP_VERSIONS_NULL
        assert config.history("prompts/bot") == before

    def test_zero_removes_all_inactive_versions(self, config):
        config.set("prompts/bot", {"v": 1})
        config.set("prompts/bot", {"v": 2})

        assert config.cleanup_old_versions(keep_versions=0) == 1
        history = config.history("prompts/bot")
        assert [row["version"] for row in history] == [2]
        assert history[0]["is_active"] is True


class TestAuditSecurityValidation:
    """Tests for audit event query security."""

    def test_rejects_invalid_column_names(self, config):
        """SQL injection via column name is prevented."""
        # Attempt to inject SQL via column name
        with pytest.raises(ValueError, match="Invalid column name"):
            config._get_audit_events(filters={"1=1; DROP TABLE--": "value"})

    def test_rejects_column_names_with_spaces(self, config):
        """Column names with spaces are rejected."""
        with pytest.raises(ValueError, match="Invalid column name"):
            config._get_audit_events(filters={"key or 1=1": "value"})

    def test_rejects_column_names_with_operators(self, config):
        """Column names with SQL operators are rejected."""
        with pytest.raises(ValueError, match="Invalid column name"):
            config._get_audit_events(filters={"key=": "value"})

    def test_accepts_valid_column_names(self, config):
        """Valid Python identifiers are accepted as column names."""
        # This should not raise - 'key' is a valid identifier
        result = config._get_audit_events(filters={"key": "nonexistent"})
        assert result == []  # No matching events, but query executed safely


class TestAuditPagination:
    """Tests for audit event cursor-based pagination."""

    def test_pagination_returns_correct_pages(self, config):
        """before cursor returns events before the specified event."""
        # Create multiple audit events by setting config entries
        for i in range(5):
            config.set(f"pagination/test-{i}", {"value": i})

        # Get first page (most recent first)
        events = config.get_audit_events(limit=2)
        assert len(events) == 2

        # Use opaque cursor from last event
        assert "cursor" in events[-1], "Events should include opaque cursor field"

        # Get second page using opaque cursor
        events2 = config.get_audit_events(limit=2, before=events[-1]["cursor"])
        assert len(events2) == 2

        # Pages should not overlap
        first_ids = {e["id"] for e in events}
        second_ids = {e["id"] for e in events2}
        assert first_ids.isdisjoint(second_ids)

    def test_pagination_with_event_type_filter(self, config):
        """Pagination works correctly with event_type filter."""
        # Create config entries (generates entry_created events)
        for i in range(3):
            config.set(f"filter-page/test-{i}", {"v": i})

        # Get filtered events with pagination
        first_page = config.get_audit_events(event_type="entry_created", limit=2)

        assert len(first_page) == 2

        # Use opaque cursor
        second_page = config.get_audit_events(
            event_type="entry_created", limit=2, before=first_page[-1]["cursor"]
        )

        # Pages should not overlap
        first_ids = {e["id"] for e in first_page}
        second_ids = {e["id"] for e in second_page}
        assert first_ids.isdisjoint(second_ids)

    def test_events_include_pagination_fields(self, config):
        """Events include id, event_time, and opaque cursor for pagination."""
        config.set("cursor-test/test", {"v": 1})

        events = config.get_audit_events(limit=1)

        assert len(events) == 1
        event = events[0]
        assert isinstance(event["id"], int)
        assert isinstance(event["event_time"], datetime)
        assert isinstance(event["cursor"], str)
        assert len(event["cursor"]) > 0

    def test_invalid_cursor_raises_error(self, config):
        """Invalid cursor raises clear error."""
        with pytest.raises(ConfigError, match="Invalid pagination cursor"):
            config.get_audit_events(before="garbage")
