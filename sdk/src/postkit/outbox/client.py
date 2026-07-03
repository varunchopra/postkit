"""Postkit Outbox SDK - transactional event feed with durable cursors."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, NoReturn

import psycopg
from psycopg import pq
from psycopg.abc import Buffer
from psycopg.adapt import Loader

from postkit.base import BaseClient, PostkitError


class _Xid8Loader(Loader):
    """Load xid8 values as plain ints.

    psycopg has no built-in xid8 loader and would return strings; cursor
    positions must round-trip as integers so callers can store and compare
    them without caring about the Postgres type.
    """

    def load(self, data: Buffer) -> int:
        return int(bytes(data))


class _Xid8BinaryLoader(Loader):
    """The binary-protocol twin of _Xid8Loader (uint64, network order).

    Loaders are per wire format; without this, a caller-supplied
    cursor(binary=True) would get raw bytes instead of ints.
    """

    format = pq.Format.BINARY

    def load(self, data: Buffer) -> int:
        return int.from_bytes(bytes(data), "big")


class OutboxError(PostkitError):
    """Exception for outbox operations."""


class OutboxValidationError(OutboxError):
    """Raised when input validation fails."""


class OutboxCursorLostError(OutboxError):
    """Raised when a position falls below the oldest retained event.

    The events between the position and the oldest retained one are gone.
    Recovery: resync state from your source of truth, then replay (or
    read_from) at the oldest available position, which the error message
    carries.
    """


class OutboxClient(BaseClient):
    """Client for Postkit outbox module.

    A transactional event feed: emit() appends inside your transaction, so
    the event exists exactly when the state change it describes committed.
    Consumers subscribe once, then poll and ack forward independently.

    Positions are (xid, id) pairs taken verbatim from polled rows; treat
    them as opaque.

    Example:
        outbox = OutboxClient(cursor, namespace="acme")

        # Producer, inside the domain transaction:
        with conn.transaction():
            create_order(...)
            outbox.emit("orders", "order.created", {"order_id": 42})

        # Consumer:
        outbox.subscribe("orders", "billing", from_="start")   # once
        events = outbox.poll("orders", "billing")
        for event in events:
            process(event)
        if events:
            outbox.ack("orders", "billing", events[-1]["xid"], events[-1]["id"])
    """

    _schema = "outbox"
    _error_class = OutboxError
    _module_sqlstate_map = {
        "22023": OutboxValidationError,  # invalid_parameter_value
        "22004": OutboxValidationError,  # null_value_not_allowed
        "22001": OutboxValidationError,  # string_data_right_truncation
        "22026": OutboxValidationError,  # string_data_length_mismatch
    }

    def __init__(self, cursor: psycopg.Cursor, namespace: str) -> None:
        super().__init__(cursor, namespace)
        cursor.connection.adapters.register_loader("xid8", _Xid8Loader)
        cursor.connection.adapters.register_loader("xid8", _Xid8BinaryLoader)

    def _handle_error(self, e: psycopg.Error) -> NoReturn:
        # CURSOR_LOST shares SQLSTATE 22023 with plain validation errors;
        # only the hint distinguishes the recovery path (resync and replay
        # versus fix your input).
        hint = e.diag.message_hint if hasattr(e, "diag") and e.diag else None
        if hint == "postkit:outbox:BIZ_CURSOR_LOST":
            raise OutboxCursorLostError(
                str(e), getattr(e, "sqlstate", None), hint
            ) from e
        super()._handle_error(e)

    def _apply_actor_context(self) -> None:
        """Apply actor context via outbox.set_actor()."""
        self.cursor.execute(
            """SELECT outbox.set_actor(
                p_actor_id := %s,
                p_request_id := %s,
                p_on_behalf_of := %s,
                p_reason := %s
            )""",
            (self._actor_id, self._request_id, self._on_behalf_of, self._reason),
        )

    def emit(
        self,
        topic: str,
        type: str,
        payload: dict[str, Any],
        *,
        key: str | None = None,
    ) -> int:
        """Append an event inside the caller's open transaction.

        Must share a transaction with the state change it describes; that is
        what makes the event trustworthy. Without one the event would commit
        on its own, describing nothing, so this method refuses to run.

        Args:
            topic: Topic name
            type: Event type (consumers switch on this)
            payload: Event payload (must be JSON-serializable)
            key: Optional entity key, an aid for downstream sharding

        Returns:
            The event id

        Raises:
            OutboxError: No transaction is open on the connection.
        """
        if self.cursor.connection.info.transaction_status == 0:
            raise OutboxError(
                "emit() requires an open transaction: an event emitted on "
                "its own describes no committed state change. Open a "
                "transaction around the state change and the emit."
            )
        result = self._fetch_val(
            """SELECT outbox.emit(
                p_namespace := %s,
                p_topic := %s,
                p_type := %s,
                p_payload := %s::jsonb,
                p_key := %s
            )""",
            (self.namespace, topic, type, json.dumps(payload), key),
            write=True,
        )
        if result is None:
            raise OutboxError("outbox.emit returned no value")
        return result

    def subscribe(self, topic: str, consumer: str, *, from_: str) -> dict[str, int]:
        """Register a consumer and set its starting position.

        Args:
            topic: Topic name
            consumer: Consumer name
            from_: 'start' (replay everything retained) or 'head' (only new
                events). Required; there is no safe silent default.

        Returns:
            Dict with position_xid and position_id, the starting pair
        """
        result = self._fetch_one(
            "SELECT * FROM outbox.subscribe(%s, %s, %s, %s)",
            (self.namespace, topic, consumer, from_),
            write=True,
        )
        if result is None:
            raise OutboxError("outbox.subscribe returned no row")
        return result

    def poll(
        self, topic: str, consumer: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Read the next events for a consumer. Does not advance the cursor.

        Args:
            topic: Topic name
            consumer: Consumer name (must be subscribed)
            limit: Maximum events to return

        Returns:
            Event dicts in delivery order; each carries the xid and id that
            together form its ack position

        Raises:
            OutboxCursorLostError: The cursor fell below the oldest retained
                event; resync from your source of truth, then replay.
        """
        return self._fetch_all(
            "SELECT * FROM outbox.poll(%s, %s, %s, %s)",
            (self.namespace, topic, consumer, limit),
        )

    def ack(self, topic: str, consumer: str, xid: int, id: int) -> bool:
        """Advance a consumer's cursor after processing.

        Pass the xid and id of the last event processed, straight from the
        polled row: event["xid"], event["id"].

        Args:
            topic: Topic name
            consumer: Consumer name
            xid: The event's xid column
            id: The event's id column

        Returns:
            True if the cursor advanced, False if the pair was not ahead of it
        """
        result = self._fetch_val(
            "SELECT outbox.ack(%s, %s, %s, %s::xid8, %s)",
            (self.namespace, topic, consumer, str(xid), id),
            write=True,
        )
        return bool(result)

    def read_from(
        self, topic: str, xid: int, id: int, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Read events after a position, for callers keeping their own cursor.

        Store both components of the last row read (its xid and id) and
        pass them back; the pair is opaque. (0, 0) reads everything
        retained.

        Args:
            topic: Topic name
            xid: Transaction component of the last-seen position
            id: Id component of the last-seen position
            limit: Maximum events to return

        Returns:
            Event dicts in delivery order

        Raises:
            OutboxCursorLostError: The position fell below the oldest
                retained event; resync, then read from the position in the
                error message.
        """
        return self._fetch_all(
            "SELECT * FROM outbox.read_from(%s, %s, %s::xid8, %s, %s)",
            (self.namespace, topic, str(xid), id, limit),
        )

    def replay(self, topic: str, consumer: str, xid: int, id: int) -> None:
        """Move an existing consumer's cursor to a chosen position.

        Take the pair from a previously polled row, from a CURSOR_LOST
        message, or (0, 0) for everything retained.

        Args:
            topic: Topic name
            consumer: Consumer name
            xid: Transaction component of the new position
            id: Id component (events after the pair are delivered again)
        """
        self._fetch_val(
            "SELECT outbox.replay(%s, %s, %s, %s::xid8, %s)",
            (self.namespace, topic, consumer, str(xid), id),
            write=True,
        )

    def trim(
        self,
        older_than: timedelta,
        *,
        topic: str | None = None,
        limit: int = 10000,
    ) -> list[dict[str, Any]]:
        """Delete old events. Retention has no default; pass it explicitly.

        Args:
            older_than: Delete events older than this (required, positive)
            topic: Topic filter (None = all topics in the namespace)
            limit: Maximum events to delete per topic per call

        Returns:
            One dict per topic touched, with the deleted count
        """
        return self._fetch_all(
            "SELECT * FROM outbox.trim(%s, %s, %s, %s)",
            (older_than, self.namespace, topic, limit),
            write=True,
        )

    def lag(self, topic: str | None = None) -> list[dict[str, Any]]:
        """Per-consumer backlog, plus the current visibility horizon.

        Args:
            topic: Topic filter (None = all topics)

        Returns:
            One dict per consumer: position_xid, position_id, lag_events,
            lag_time, horizon
        """
        return self._fetch_all(
            "SELECT * FROM outbox.lag(%s, %s)", (self.namespace, topic)
        )

    def get_stats(self) -> dict[str, Any]:
        """Get namespace-wide outbox statistics.

        Returns:
            Dict with total_events, total_topics, total_consumers, and
            max_lag_events counts
        """
        result = self._fetch_one(
            "SELECT * FROM outbox.get_stats(%s)", (self.namespace,)
        )
        return result or {}

    def list_consumers(self, topic: str | None = None) -> list[dict[str, Any]]:
        """List consumer cursors in the namespace.

        Args:
            topic: Topic filter (None = all topics)

        Returns:
            List of cursor row dicts
        """
        return self._fetch_all(
            "SELECT * FROM outbox.list_consumers(%s, %s)", (self.namespace, topic)
        )
