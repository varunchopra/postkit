"""O2: an event exists iff the transaction that emitted it committed."""

import json

import psycopg
import pytest

from tests.helpers import channel_name
from tests.outbox.test_horizon import emit


class TestTransactionalEmit:
    def test_rollback_leaves_no_event(self, test_helpers, connect):
        ns = test_helpers.namespace
        conn = connect()
        emit(conn.cursor(), ns, "orders")
        conn.rollback()
        assert test_helpers.count_events("orders") == 0

    def test_commit_leaves_event(self, test_helpers, connect):
        ns = test_helpers.namespace
        conn = connect()
        event_id = emit(conn.cursor(), ns, "orders", '{"n": 1}')
        conn.commit()
        assert test_helpers.event_ids("orders") == [event_id]

    def test_distinct_pairs_get_distinct_channels(self, connect):
        conn = connect()
        row = conn.execute(
            "SELECT outbox.channel_name('acme', 'billing/invoices'),"
            "       outbox.channel_name('acme/billing', 'invoices')"
        ).fetchone()
        assert row[0] != row[1]

    def test_notify_only_on_commit(self, test_helpers, connect):
        """The wake-up must never precede the event: LISTEN before emitting,
        assert silence while the transaction is open, delivery after commit."""
        ns = test_helpers.namespace

        listener = connect()
        channel = channel_name(listener.cursor(), "outbox", ns, "orders")
        listener.execute(f'LISTEN "{channel}"')
        listener.commit()

        conn = connect()
        event_id = emit(conn.cursor(), ns, "orders")

        assert list(listener.notifies(timeout=0.3)) == []

        conn.commit()
        got = list(listener.notifies(timeout=10, stop_after=1))
        assert len(got) == 1
        assert json.loads(got[0].payload) == {"topic": "orders", "id": event_id}

    def test_notify_disabled_by_config(self, test_helpers, connect):
        ns = test_helpers.namespace
        test_helpers.set_config(notify=False)

        listener = connect()
        channel = channel_name(listener.cursor(), "outbox", ns, "orders")
        listener.execute(f'LISTEN "{channel}"')
        listener.commit()

        conn = connect()
        emit(conn.cursor(), ns, "orders")
        conn.commit()
        assert list(listener.notifies(timeout=0.3)) == []

    def test_actor_context_lands_on_event(self, test_helpers, connect):
        """set_actor is transaction-local, so it must share the emit's
        transaction (an autocommit set_actor evaporates immediately)."""
        ns = test_helpers.namespace
        conn = connect()
        cur = conn.cursor()
        cur.execute(
            "SELECT outbox.set_actor(p_actor_id := %s, p_request_id := %s)",
            ("user:alice", "req-9"),
        )
        emit(cur, ns, "orders")
        conn.commit()

        test_helpers.cursor.execute(
            "SELECT actor_id, request_id FROM outbox.events WHERE namespace = %s",
            (ns,),
        )
        assert test_helpers.cursor.fetchone() == ("user:alice", "req-9")

    def test_null_payload_rejected(self, test_helpers):
        with pytest.raises(psycopg.errors.NullValueNotAllowed) as exc_info:
            test_helpers.cursor.execute(
                "SELECT outbox.emit(%s, 'orders', 'test.event', NULL)",
                (test_helpers.namespace,),
            )
        assert exc_info.value.diag.message_hint == "postkit:outbox:VAL_PAYLOAD_NULL"
