<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Outbox SQL API

## Context

### outbox.assert_rls_active

```sql
outbox.assert_rls_active() -> void
```

Raise unless row-level security applies to the current role.

**Example:**
```sql
SELECT outbox.assert_rls_active();
Call from CI setup: a suite connecting as a superuser or BYPASSRLS role
bypasses every policy and exercises none of the tenancy model.
```

*Source: outbox/src/functions/080_rls.sql:98*

---

### outbox.clear_actor

```sql
outbox.clear_actor() -> void
```

Clear actor context. Call before returning connections to pool.

*Source: outbox/src/functions/080_rls.sql:52*

---

### outbox.clear_tenant

```sql
outbox.clear_tenant() -> void
```

Clear the tenant context. Call before returning connections to pool.

*Source: outbox/src/functions/080_rls.sql:19*

---

### outbox.set_actor

```sql
outbox.set_actor(p_actor_id: text, p_request_id: text, p_on_behalf_of: text, p_reason: text) -> void
```

Set actor context, captured on emitted events.

**Parameters:**
- `p_actor_id`: ID of the user/system performing the action
- `p_request_id`: Optional request/trace ID for correlation
- `p_on_behalf_of`: Optional ID if acting on behalf of another user
- `p_reason`: Optional reason for the action

*Source: outbox/src/functions/080_rls.sql:30*

---

### outbox.set_tenant

```sql
outbox.set_tenant(p_tenant_id: text) -> void
```

Set the tenant context for RLS policies.

**Parameters:**
- `p_tenant_id`: Tenant/namespace identifier Must be called before any operations. Transaction-local scope.

*Source: outbox/src/functions/080_rls.sql:1*

---

## Emit

### outbox.emit

```sql
outbox.emit(p_namespace: text, p_topic: text, p_type: text, p_payload: jsonb, p_key: text) -> int8
```

Append an event inside the caller's transaction.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_topic`: Topic name
- `p_type`: Event type (consumers switch on this)
- `p_payload`: Event payload (JSONB)
- `p_key`: Optional entity key, an aid for downstream sharding

**Returns:** The event id

**Example:**
```sql
SELECT outbox.emit('default', 'orders', 'order.created', '{"order_id": 42}');
```

*Source: outbox/src/functions/010_emit.sql:1*

---

## Inspection

### outbox.get_stats

```sql
outbox.get_stats(p_namespace: text) -> table(total_events: int8, total_topics: int8, total_consumers: int8, max_lag_events: int8)
```

Get namespace-wide outbox statistics.

**Parameters:**
- `p_namespace`: Tenant namespace

**Returns:** Row with total_events, total_topics, total_consumers, max_lag_events

**Example:**
```sql
SELECT * FROM outbox.get_stats('default');
```

*Source: outbox/src/functions/040_inspect.sql:65*

---

### outbox.horizon_blockers

```sql
outbox.horizon_blockers() -> table(pid: int4, datname: text, xact_age: interval, state: text, application_name: text, query: text, is_horizon: bool)
```

Backends whose open write transactions pin the visibility horizon.

**Returns:** One row per in-progress write transaction, oldest first

**Example:**
```sql
SELECT * FROM outbox.horizon_blockers();
```

*Source: outbox/src/functions/040_inspect.sql:123*

---

### outbox.lag

```sql
outbox.lag(p_namespace: text, p_topic: text) -> table(topic: text, consumer: text, position_xid: xid8, position_id: int8, lag_events: int8, lag_time: interval, horizon: xid8)
```

Per-consumer backlog for a topic (or all topics).

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_topic`: Topic filter (NULL = all topics)

**Returns:** One row per consumer: position pair, backlog count, age of the oldest unprocessed event, and the current visibility horizon

**Example:**
```sql
SELECT * FROM outbox.lag('default', 'orders');
```

*Source: outbox/src/functions/040_inspect.sql:1*

---

### outbox.list_consumers

```sql
outbox.list_consumers(p_namespace: text, p_topic: text) -> setof outbox.cursors
```

List consumer cursors in a namespace.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_topic`: Topic filter (NULL = all topics)

**Returns:** Cursor rows

**Example:**
```sql
SELECT * FROM outbox.list_consumers('default', 'orders');
```

*Source: outbox/src/functions/040_inspect.sql:95*

---

## Maintenance

### outbox.trim

```sql
outbox.trim(p_older_than: interval, p_namespace: text, p_topic: text, p_limit: int4) -> table(namespace: text, topic: text, deleted: int4)
```

Delete old events, keeping deletions a contiguous (xid, id) prefix.

**Parameters:**
- `p_older_than`: Delete events older than this interval (required)
- `p_namespace`: Tenant namespace (NULL = all namespaces, requires RLS bypass)
- `p_topic`: Topic filter (NULL = all topics)
- `p_limit`: Maximum events to delete per topic per call

**Returns:** One row per topic touched: (namespace, topic, deleted count)

**Example:**
```sql
SELECT * FROM outbox.trim('30 days', 'default');
```

*Source: outbox/src/functions/050_maintenance.sql:1*

---

## Poll and Ack

### outbox.ack

```sql
outbox.ack(p_namespace: text, p_topic: text, p_consumer: text, p_xid: xid8, p_id: int8) -> bool
```

Advance a consumer's cursor after processing.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_topic`: Topic name
- `p_consumer`: Consumer name
- `p_xid`: Transaction component of the last event processed (its xid column)
- `p_id`: Id component of the last event processed (its id column)

**Returns:** True if the cursor advanced, false if the pair is not ahead of it

**Example:**
```sql
SELECT outbox.ack('default', 'orders', 'billing', '742', 42);
```

*Source: outbox/src/functions/030_poll.sql:211*

---

### outbox.has_pending

```sql
outbox.has_pending(p_namespace: text, p_topic: text, p_consumer: text) -> bool
```

Whether a consumer has readable events past its cursor.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_topic`: Topic name
- `p_consumer`: Consumer name (must be subscribed)

**Returns:** True iff a readable event lies past the cursor or the cursor is below the retained range

**Example:**
```sql
SELECT outbox.has_pending('default', 'orders', 'billing');
```

*Source: outbox/src/functions/030_poll.sql:82*

---

### outbox.poll

```sql
outbox.poll(p_namespace: text, p_topic: text, p_consumer: text, p_limit: int4) -> setof outbox.events
```

Read the next events for a consumer. Does not advance the cursor.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_topic`: Topic name
- `p_consumer`: Consumer name (must be subscribed)
- `p_limit`: Maximum events to return

**Returns:** Events after the cursor, in (xid, id) order

**Example:**
```sql
SELECT * FROM outbox.poll('default', 'orders', 'billing');
```

*Source: outbox/src/functions/030_poll.sql:1*

---

### outbox.read_from

```sql
outbox.read_from(p_namespace: text, p_topic: text, p_xid: xid8, p_id: int8, p_limit: int4) -> setof outbox.events
```

Read events from a position, for callers that keep their own cursor.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_topic`: Topic name
- `p_xid`: Transaction component of the last-seen position
- `p_id`: Id component of the last-seen position
- `p_limit`: Maximum events to return

**Returns:** Events after the position, in (xid, id) order

**Example:**
```sql
SELECT * FROM outbox.read_from('default', 'orders', '0', 0, 50);
```

*Source: outbox/src/functions/030_poll.sql:153*

---

## Subscribe

### outbox.replay

```sql
outbox.replay(p_namespace: text, p_topic: text, p_consumer: text, p_xid: xid8, p_id: int8) -> void
```

Move an existing consumer's cursor to a chosen position.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_topic`: Topic name
- `p_consumer`: Consumer name
- `p_xid`: Transaction component of the new position
- `p_id`: Id component of the new position (events after the pair are delivered again)

**Example:**
```sql
SELECT outbox.replay('default', 'orders', 'billing', '0', 0);
```

*Source: outbox/src/functions/020_subscribe.sql:75*

---

### outbox.subscribe

```sql
outbox.subscribe(p_namespace: text, p_topic: text, p_consumer: text, p_from: text) -> table(position_xid: xid8, position_id: int8)
```

Register a consumer on a topic and set its starting position.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_topic`: Topic name
- `p_consumer`: Consumer name
- `p_from`: Starting point: 'start' (replay everything retained) or 'head' (only new events)

**Returns:** The starting position pair (position_xid, position_id)

**Example:**
```sql
SELECT * FROM outbox.subscribe('default', 'orders', 'billing', 'start');
```

*Source: outbox/src/functions/020_subscribe.sql:1*

---
