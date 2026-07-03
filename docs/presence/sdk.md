<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Presence Python SDK

### clear_actor

```python
clear_actor() -> None
```

Clear actor context.

*Source: sdk/src/postkit/base.py:395*

---

### deregister

```python
deregister(entity: str) -> bool
```

Remove an entity deliberately, emitting a departed transition.

Intentional exit is not death: no death hooks fire and nobody gets paged for a planned shutdown. Idempotent - removing an absent entity returns False, never raises.

**Parameters:**
- `entity`: Entity id

**Returns:** True if the entity existed and was removed

*Source: sdk/src/postkit/presence/client.py:171*

---

### get_stats

```python
get_stats() -> dict[str, Any]
```

Get namespace-wide presence statistics.

**Returns:** Dict with total_entities, alive, dead, unknown, overdue, and
total_transitions counts

*Source: sdk/src/postkit/presence/client.py:246*

---

### get_transitions

```python
get_transitions(entity: str | None = None, *, limit: int = 100) -> list[dict[str, Any]]
```

Read the transition history, newest first.

History, not a feed: delivery is the queue hooks and NOTIFY; do not poll this by id.

**Parameters:**
- `entity`: Entity filter (None = all entities)
- `limit`: Maximum transitions to return

**Returns:** List of transition dicts with actor context

*Source: sdk/src/postkit/presence/client.py:226*

---

### heartbeat

```python
heartbeat(entity: str) -> str
```

Report an entity alive.

A dead or never-seen entity revives here and now - the revival transition is emitted by this call, never deferred to a sweep. An unregistered entity raises (registration is explicit; heartbeat_many reports 'unknown' instead of raising).

**Parameters:**
- `entity`: Entity id (must be registered)

**Returns:** The resulting status (always 'alive')

*Source: sdk/src/postkit/presence/client.py:110*

---

### heartbeat_many

```python
heartbeat_many(entities: list[str]) -> list[dict[str, Any]]
```

Report a batch of entities alive in one round trip.

Per-entity semantics match heartbeat(), including revivals. Unregistered entities come back with status 'unknown' instead of raising - one typo must not abort a fleet batch.

**Parameters:**
- `entities`: Entity ids

**Returns:** One dict per distinct entity: entity_id and its resulting status

*Source: sdk/src/postkit/presence/client.py:133*

---

### list_entities

```python
list_entities(*, kind: str | None = None, status: str | None = None) -> list[dict[str, Any]]
```

List entities in the namespace.

**Parameters:**
- `kind`: Kind filter (None = all kinds)
- `status`: Status filter: 'unknown', 'alive', or 'dead'

**Returns:** List of entity row dicts

*Source: sdk/src/postkit/presence/client.py:209*

---

### register

```python
register(entity: str, *, kind: str | None = None, timeout: timedelta | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any]
```

Register an entity for liveness tracking, or update its attributes.

Idempotent: None arguments preserve what is stored, so deploys can re-run register safely. Re-registering is an attribute update, not a heartbeat - liveness only changes through heartbeat() and sweep(). A new entity starts at 'unknown' and cannot die before its first heartbeat.

**Parameters:**
- `entity`: Entity id (e.g. 'worker-7', 'sensor:eu:42')
- `kind`: Entity kind, keys the config row. None means 'default' for a new entity and keeps the current kind on re-register
- `timeout`: Per-entity liveness window replacing the kind's dead_after. None keeps the current override
- `metadata`: Metadata stored on the entity; None keeps the existing metadata on re-register (new entities start empty)

**Returns:** The entity row dict

*Source: sdk/src/postkit/presence/client.py:61*

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

*Source: sdk/src/postkit/base.py:366*

---

### status

```python
status(entity: str) -> dict[str, Any] | None
```

Inspect one entity, with the wall-clock truth alongside the cache.

The stored status lags until the next sweep; the returned overdue flag is true when the entity is nominally alive but already past its liveness window.

**Parameters:**
- `entity`: Entity id

**Returns:** Dict with the liveness fields plus overdue, or None when the
entity is not registered

*Source: sdk/src/postkit/presence/client.py:191*

---

### sweep

```python
sweep(*, limit: int = 1000) -> list[dict[str, Any]]
```

Mark overdue entities dead and deliver deferred death alerts.

Call from a cron or timer; nothing runs on its own, and death is detected no faster than the sweep cadence. Deaths emit transitions and fire the configured queue hooks in the same transaction.

**Parameters:**
- `limit`: Maximum entities to process per call

**Returns:** The death transitions emitted by this call

*Source: sdk/src/postkit/presence/client.py:152*

---

### trim

```python
trim(older_than: timedelta, *, limit: int = 10000) -> list[dict[str, Any]]
```

Delete old transitions. Retention has no default; pass it explicitly.

**Parameters:**
- `older_than`: Delete transitions older than this (required, positive)
- `limit`: Maximum transitions to delete per call

**Returns:** One dict per namespace touched, with the deleted count

*Source: sdk/src/postkit/presence/client.py:258*

---
