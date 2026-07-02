"""Event log tests: sequence, negative assertions, actor context."""

import psycopg
import pytest

from tests.helpers import assert_audit_fields


class TestEventSequence:
    def test_acquire_release_sequence(self, lease, test_helpers):
        got = lease.acquire("job", "w1")
        lease.release("job", "w1", got["fence_token"])

        events = test_helpers.get_events("job")
        assert [e["event"] for e in events] == ["acquired", "released"]
        assert events[0]["holder_id"] == "w1"
        assert events[0]["fence_token"] == got["fence_token"]

    def test_taken_over_carries_previous_holder(self, lease, test_helpers):
        lease.acquire("job", "w1")
        test_helpers.set_expires_at("job", "-1 second")
        lease.acquire("job", "w2")

        events = test_helpers.get_events("job")
        assert [e["event"] for e in events] == ["acquired", "taken_over"]
        assert events[1]["previous_holder"] == "w1"
        assert events[1]["holder_id"] == "w2"


class TestRenewalsNeverLogged:
    """Renewals fire at ~ttl/3, so logging them would be unbounded growth.
    These assertions ensure renewal logging is never (re)introduced."""

    def test_renew_emits_no_event(self, lease, test_helpers):
        got = lease.acquire("job", "w1")
        before = test_helpers.count_events("job")
        lease.renew("job", "w1", got["fence_token"])
        lease.renew("job", "w1", got["fence_token"])
        assert test_helpers.count_events("job") == before

    def test_same_holder_live_reacquire_emits_no_event(self, lease, test_helpers):
        lease.acquire("job", "w1")
        before = test_helpers.count_events("job")
        lease.acquire("job", "w1")
        assert test_helpers.count_events("job") == before

    def test_schema_rejects_renewed_event_type(self, test_helpers):
        """Schema-level backstop: the CHECK constraint has no 'renewed'."""
        with pytest.raises(psycopg.errors.CheckViolation):
            test_helpers.cursor.execute(
                "INSERT INTO lease.events (namespace, name, event) "
                "VALUES (%s, %s, 'renewed')",
                (test_helpers.namespace, "job"),
            )


class TestActorContext:
    def test_actor_context_on_lease_and_events(self, lease, test_helpers):
        lease.set_actor(
            actor_id="user:alice",
            request_id="req-123",
            reason="deploy singleton",
        )
        got = lease.acquire("job", "w1")

        row = test_helpers.get_lease_row("job")
        assert_audit_fields(
            row,
            actor_id="user:alice",
            request_id="req-123",
            on_behalf_of=None,
            reason="deploy singleton",
        )

        events = test_helpers.get_events("job")
        assert_audit_fields(
            events[0],
            actor_id="user:alice",
            request_id="req-123",
            on_behalf_of=None,
            reason="deploy singleton",
        )

        lease.release("job", "w1", got["fence_token"])
        events = test_helpers.get_events("job")
        assert_audit_fields(events[-1], actor_id="user:alice")

    def test_no_actor_context_is_null(self, lease, test_helpers):
        lease.acquire("job", "w1")
        events = test_helpers.get_events("job")
        assert_audit_fields(
            events[0], actor_id=None, request_id=None, on_behalf_of=None, reason=None
        )
