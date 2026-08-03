<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Outbox Python SDK

### ack

```python
ack(topic: str, consumer: str, xid: int, id: int) -> bool
```

Advance a consumer's cursor after processing.

Pass the xid and id of the last event processed, straight from the polled row: event["xid"], event["id"].

**Parameters:**
- `topic`: Topic name
- `consumer`: Consumer name
- `xid`: The event's xid column
- `id`: The event's id column

**Returns:** True if the cursor advanced, False if the pair was not ahead of it

*Source: sdk/src/postkit/outbox/client.py:238*

---

### assert_rls_active

```python
assert_rls_active() -> None
```

Raise unless row-level security applies to the connection's role.

Call from CI setup: a suite connecting as a superuser or BYPASSRLS role bypasses every policy and exercises none of the tenancy model.

*Source: sdk/src/postkit/base.py:397*

---

### clear_actor

```python
clear_actor() -> None
```

Clear actor context.

*Source: sdk/src/postkit/base.py:390*

---

### emit

```python
emit(topic: str, type: str, payload: dict[str, Any], *, key: str | None = None) -> int
```

Append an event inside the caller's open transaction.

Must share a transaction with the state change it describes; that is what makes the event trustworthy. Without one the event would commit on its own, describing nothing, so this method refuses to run.

**Parameters:**
- `topic`: Topic name
- `type`: Event type (consumers switch on this)
- `payload`: Event payload (must be JSON-serializable)
- `key`: Optional entity key, an aid for downstream sharding

**Returns:** The event id

*Source: sdk/src/postkit/outbox/client.py:124*

---

### get_stats

```python
get_stats() -> dict[str, Any]
```

Get namespace-wide outbox statistics.

**Returns:** Dict with total_events, total_topics, total_consumers, and
max_lag_events counts

*Source: sdk/src/postkit/outbox/client.py:344*

---

### has_pending

```python
has_pending(topic: str, consumer: str) -> bool
```

Whether readable events exist past the consumer's cursor.

Takes no locks and counts nothing, so it is safe at heartbeat frequency where poll() would serialize against real consumption. A cursor below the oldest retained event reads as pending; the next poll() then raises OutboxCursorLostError with the recovery position.

**Parameters:**
- `topic`: Topic name
- `consumer`: Consumer name (must be subscribed)

**Returns:** True iff a readable event lies past the cursor or the cursor
is below the retained range

*Source: sdk/src/postkit/outbox/client.py:215*

---

### horizon_blockers

```python
horizon_blockers() -> list[dict[str, Any]]
```

Backends whose open write transactions pin the visibility horizon.

Database-global, like the horizon itself. Seeing other sessions requires pg_read_all_stats (or superuser).

**Returns:** One dict per in-progress write transaction, oldest first:
pid, datname, xact_age, state, application_name, query,
is_horizon

*Source: sdk/src/postkit/outbox/client.py:369*

---

### lag

```python
lag(topic: str | None = None) -> list[dict[str, Any]]
```

Per-consumer backlog, plus the current visibility horizon.

**Parameters:**
- `topic`: Topic filter (None = all topics)

**Returns:** One dict per consumer: position_xid, position_id, lag_events,
lag_time, horizon

*Source: sdk/src/postkit/outbox/client.py:330*

---

### list_consumers

```python
list_consumers(topic: str | None = None) -> list[dict[str, Any]]
```

List consumer cursors in the namespace.

**Parameters:**
- `topic`: Topic filter (None = all topics)

**Returns:** List of cursor row dicts

*Source: sdk/src/postkit/outbox/client.py:356*

---

### poll

```python
poll(topic: str, consumer: str, *, limit: int = 100) -> list[dict[str, Any]]
```

Read the next events for a consumer. Does not advance the cursor.

**Parameters:**
- `topic`: Topic name
- `consumer`: Consumer name (must be subscribed)
- `limit`: Maximum events to return

**Returns:** Event dicts in delivery order; each carries the xid and id that
together form its ack position

*Source: sdk/src/postkit/outbox/client.py:192*

---

### read_from

```python
read_from(topic: str, xid: int, id: int, *, limit: int = 100) -> list[dict[str, Any]]
```

Read events after a position, for callers keeping their own cursor.

Store both components of the last row read (its xid and id) and pass them back; the pair is opaque. (0, 0) reads everything retained.

**Parameters:**
- `topic`: Topic name
- `xid`: Transaction component of the last-seen position
- `id`: Id component of the last-seen position
- `limit`: Maximum events to return

**Returns:** Event dicts in delivery order

*Source: sdk/src/postkit/outbox/client.py:260*

---

### replay

```python
replay(topic: str, consumer: str, xid: int, id: int) -> None
```

Move an existing consumer's cursor to a chosen position.

Take the pair from a previously polled row, from a CURSOR_LOST message, or (0, 0) for everything retained.

**Parameters:**
- `topic`: Topic name
- `consumer`: Consumer name
- `xid`: Transaction component of the new position
- `id`: Id component (events after the pair are delivered again)

*Source: sdk/src/postkit/outbox/client.py:288*

---

### set_actor

```python
set_actor(actor_id: str | None = None, request_id: str | None = None, on_behalf_of: str | None = None, reason: str | None = None) -> None
```

Set actor context for audit logging. Only updates fields that are passed.

**Parameters:**
- `actor_id`: The actor making changes (e.g., 'user:alice', 'service:billing')
- `request_id`: Request/correlation ID for tracing
- `on_behalf_of`: Principal being represented (e.g., 'user:customer')
- `reason`: Reason for the action (e.g., 'support_ticket:123')

**Example:**
```python
client.clear_actor()
client.set_actor(request_id="req-123")  # Set request context first
client.set_actor(actor_id="user:alice")  # Add actor after auth
```

*Source: sdk/src/postkit/base.py:361*

---

### subscribe

```python
subscribe(topic: str, consumer: str, *, from_: str) -> dict[str, int]
```

Register a consumer and set its starting position.

**Parameters:**
- `topic`: Topic name
- `consumer`: Consumer name
- `from_`: 'start' (replay everything retained) or 'head' (only new events). Required; there is no safe silent default.

**Returns:** Dict with position_xid and position_id, the starting pair

*Source: sdk/src/postkit/outbox/client.py:171*

---

### trim

```python
trim(older_than: timedelta, *, topic: str | None = None, limit: int = 10000) -> list[dict[str, Any]]
```

Delete old events. Retention has no default; pass it explicitly.

**Parameters:**
- `older_than`: Delete events older than this (required, positive)
- `topic`: Topic filter (None scans all topics in the namespace)
- `limit`: Maximum direct event deletions across all topics; this does not bound topic discovery.

**Returns:** One dict per topic touched, with the deleted count

*Source: sdk/src/postkit/outbox/client.py:306*

---
