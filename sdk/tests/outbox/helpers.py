"""Test helpers for outbox - direct table access for test setup/teardown."""

import time


def cleanup_namespace(cursor, namespace: str):
    """Delete all outbox data for a namespace."""
    cursor.execute("DELETE FROM outbox.events WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM outbox.cursors WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM outbox.topics WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM outbox.config WHERE namespace = %s", (namespace,))


class OutboxTestHelpers:
    """
    Direct table access for test setup/teardown that bypasses the SDK.

    Use cases:
    - Counting and inspecting raw event/cursor/topic state
    - Backdating event timestamps to make them trim-eligible
    - Reading events WITHOUT the horizon gate, to demonstrate what it prevents

    Positions are (xid, id) pairs of Python ints throughout.
    """

    def __init__(self, cursor, namespace: str):
        self.cursor = cursor
        self.namespace = namespace
        self.cursor.execute("SELECT outbox.set_tenant(%s)", (namespace,))

    def count_events(self, topic: str | None = None) -> int:
        if topic:
            self.cursor.execute(
                "SELECT COUNT(*) FROM outbox.events "
                "WHERE namespace = %s AND topic = %s",
                (self.namespace, topic),
            )
        else:
            self.cursor.execute(
                "SELECT COUNT(*) FROM outbox.events WHERE namespace = %s",
                (self.namespace,),
            )
        return self.cursor.fetchone()[0]

    def get_cursor(self, topic: str, consumer: str) -> tuple[int, int] | None:
        self.cursor.execute(
            "SELECT position_xid::text, position_id FROM outbox.cursors "
            "WHERE namespace = %s AND topic = %s AND consumer = %s",
            (self.namespace, topic, consumer),
        )
        row = self.cursor.fetchone()
        return (int(row[0]), row[1]) if row else None

    def get_trimmed_through(self, topic: str) -> tuple[int, int] | None:
        self.cursor.execute(
            "SELECT trimmed_xid::text, trimmed_id FROM outbox.topics "
            "WHERE namespace = %s AND topic = %s",
            (self.namespace, topic),
        )
        row = self.cursor.fetchone()
        return (int(row[0]), row[1]) if row else None

    def event_ids(self, topic: str) -> list[int]:
        """Ids in delivery order: (xid, id), the order every read uses."""
        self.cursor.execute(
            "SELECT id FROM outbox.events "
            "WHERE namespace = %s AND topic = %s ORDER BY xid, id",
            (self.namespace, topic),
        )
        return [r[0] for r in self.cursor.fetchall()]

    def event_position(self, topic: str, event_id: int) -> tuple[int, int]:
        """The (xid, id) pair of a stored event, read without gating."""
        self.cursor.execute(
            "SELECT xid::text, id FROM outbox.events "
            "WHERE namespace = %s AND topic = %s AND id = %s",
            (self.namespace, topic, event_id),
        )
        row = self.cursor.fetchone()
        assert row is not None, f"event {event_id} not found on {topic!r}"
        return (int(row[0]), row[1])

    def ungated_ids_after(self, topic: str, position: int) -> list[int]:
        """The naive read every hand-rolled outbox ships: id > cursor with
        no visibility gate. Exists so tests can show what the gate prevents."""
        self.cursor.execute(
            "SELECT id FROM outbox.events "
            "WHERE namespace = %s AND topic = %s AND id > %s ORDER BY id",
            (self.namespace, topic, position),
        )
        return [r[0] for r in self.cursor.fetchall()]

    def wait_readable(self, topic: str, event_id: int, timeout: float = 15.0) -> None:
        """Block until a committed event is below the visibility horizon.

        The horizon is database-global, so under parallel test runs other
        workers' open transactions delay visibility of freshly committed
        events - the same wait a real consumer's poll loop performs. Tests
        that assert on just-emitted events call this first.
        """
        target = self.event_position(topic, event_id)
        deadline = time.monotonic() + timeout
        while True:
            self.cursor.execute(
                "SELECT head_xid::text, head_id FROM outbox._gated_head(%s, %s)",
                (self.namespace, topic),
            )
            head_xid, head_id = self.cursor.fetchone()
            if (int(head_xid), head_id) >= target:
                return
            assert time.monotonic() < deadline, (
                f"event {event_id} on {topic!r} never became readable"
            )
            time.sleep(0.02)

    def age_events(self, age: str, topic: str | None = None) -> None:
        """Backdate event timestamps to make them trim-eligible (e.g. '40 days')."""
        if topic:
            self.cursor.execute(
                "UPDATE outbox.events SET created_at = now() - %s::interval "
                "WHERE namespace = %s AND topic = %s",
                (age, self.namespace, topic),
            )
        else:
            self.cursor.execute(
                "UPDATE outbox.events SET created_at = now() - %s::interval "
                "WHERE namespace = %s",
                (age, self.namespace),
            )

    def set_config(self, topic: str = "*", **kwargs) -> None:
        """Upsert a config row for this namespace with the given columns."""
        cols = list(kwargs.keys())
        vals = list(kwargs.values())
        assignments = ", ".join(f"{c} = EXCLUDED.{c}" for c in cols)
        self.cursor.execute(
            f"INSERT INTO outbox.config (namespace, topic, {', '.join(cols)}) "
            f"VALUES (%s, %s, {', '.join(['%s'] * len(cols))}) "
            f"ON CONFLICT (namespace, topic) DO UPDATE SET {assignments}",
            (self.namespace, topic, *vals),
        )
