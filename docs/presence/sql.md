<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Presence SQL API

## Context

### presence.assert_rls_active

```sql
presence.assert_rls_active() -> void
```

Raise unless row-level security applies to the current role.

**Example:**
```sql
SELECT presence.assert_rls_active();
Call from CI setup: a suite connecting as a superuser or BYPASSRLS role
bypasses every policy and exercises none of the tenancy model.
```

*Source: presence/src/functions/080_rls.sql:99*

---

### presence.clear_actor

```sql
presence.clear_actor() -> void
```

Clear actor context. Call before returning connections to pool.

*Source: presence/src/functions/080_rls.sql:53*

---

### presence.clear_tenant

```sql
presence.clear_tenant() -> void
```

Clear the tenant context. Call before returning connections to pool.

*Source: presence/src/functions/080_rls.sql:19*

---

### presence.set_actor

```sql
presence.set_actor(p_actor_id: text, p_request_id: text, p_on_behalf_of: text, p_reason: text) -> void
```

Set actor context for the transition history.

**Parameters:**
- `p_actor_id`: ID of the user/system performing the action
- `p_request_id`: Optional request/trace ID for correlation
- `p_on_behalf_of`: Optional ID if acting on behalf of another user
- `p_reason`: Optional reason for the action Actor context is captured on entities and presence.transitions rows.

*Source: presence/src/functions/080_rls.sql:30*

---

### presence.set_tenant

```sql
presence.set_tenant(p_tenant_id: text) -> void
```

Set the tenant context for RLS policies.

**Parameters:**
- `p_tenant_id`: Tenant/namespace identifier Must be called before any operations. Transaction-local scope.

*Source: presence/src/functions/080_rls.sql:1*

---

## Heartbeat

### presence.heartbeat

```sql
presence.heartbeat(p_namespace: text, p_entity: text) -> text
```

Report an entity alive.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_entity`: Entity id (must be registered)

**Returns:** The resulting status (always 'alive')

**Example:**
```sql
SELECT presence.heartbeat('default', 'worker-7');
```

*Source: presence/src/functions/020_heartbeat.sql:94*

---

### presence.heartbeat_many

```sql
presence.heartbeat_many(p_namespace: text, p_entities: text[]) -> table(entity_id: text, status: text)
```

Report a batch of entities alive in one round trip.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_entities`: Entity ids

**Returns:** One row per distinct entity: its resulting status, or 'unknown' for entities that are not registered (no row is created)

**Example:**
```sql
SELECT * FROM presence.heartbeat_many('default', ARRAY['w1', 'w2']);
```

*Source: presence/src/functions/020_heartbeat.sql:135*

---

## Inspection

### presence.get_stats

```sql
presence.get_stats(p_namespace: text) -> table(total_entities: int8, alive: int8, dead: int8, unknown: int8, overdue: int8, total_transitions: int8)
```

Get namespace-wide presence statistics.

**Parameters:**
- `p_namespace`: Tenant namespace

**Returns:** Row with total_entities, alive, dead, unknown, overdue, total_transitions

**Example:**
```sql
SELECT * FROM presence.get_stats('default');
```

*Source: presence/src/functions/040_inspect.sql:144*

---

### presence.get_transitions

```sql
presence.get_transitions(p_namespace: text, p_entity: text, p_limit: int4) -> setof presence.transitions
```

Read the transition history, newest first.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_entity`: Entity filter (NULL = all entities)
- `p_limit`: Maximum transitions to return

**Returns:** Transition rows with actor context

**Example:**
```sql
SELECT * FROM presence.get_transitions('default', 'worker-7');
```

*Source: presence/src/functions/040_inspect.sql:109*

---

### presence.list

```sql
presence.list(p_namespace: text, p_kind: text, p_status: text) -> setof presence.entities
```

List entities in a namespace.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_kind`: Kind filter (NULL = all kinds)
- `p_status`: Status filter (NULL = all statuses)

**Returns:** Entity rows, per kind and entity id

**Example:**
```sql
SELECT * FROM presence.list('default', p_status := 'dead');
```

*Source: presence/src/functions/040_inspect.sql:70*

---

### presence.status

```sql
presence.status(p_namespace: text, p_entity: text) -> table(entity_id: text, kind: text, status: text, last_seen: timestamptz, alive_since: timestamptz, dead_since: timestamptz, timeout_override: interval, metadata: jsonb, overdue: bool)
```

Inspect one entity, with the wall-clock truth alongside the cache.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_entity`: Entity id

**Returns:** The entity's liveness fields plus overdue; empty when not registered

**Example:**
```sql
SELECT * FROM presence.status('default', 'worker-7');
```

*Source: presence/src/functions/040_inspect.sql:1*

---

## Maintenance

### presence.trim

```sql
presence.trim(p_older_than: interval, p_namespace: text, p_limit: int4) -> table(namespace: text, deleted: int4)
```

Delete old transitions.

**Parameters:**
- `p_older_than`: Delete transitions older than this interval (required)
- `p_namespace`: Tenant namespace (NULL = all namespaces, requires RLS bypass)
- `p_limit`: Maximum transitions to delete per call

**Returns:** One row per namespace touched: (namespace, deleted count)

**Example:**
```sql
SELECT * FROM presence.trim('90 days', 'default');
```

*Source: presence/src/functions/050_maintenance.sql:1*

---

## Register

### presence.deregister

```sql
presence.deregister(p_namespace: text, p_entity: text) -> bool
```

Remove an entity deliberately, emitting a departed transition.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_entity`: Entity id

**Returns:** True if the entity existed and was removed, false otherwise (idempotent - never raises for an absent entity)

**Example:**
```sql
SELECT presence.deregister('default', 'worker-7');
```

*Source: presence/src/functions/010_register.sql:72*

---

### presence.register

```sql
presence.register(p_namespace: text, p_entity: text, p_kind: text, p_timeout: interval, p_metadata: jsonb) -> presence.entities
```

Register an entity for liveness tracking, or update its attributes.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_entity`: Entity id (e.g. 'worker-7', 'sensor:eu:42')
- `p_kind`: Entity kind, keys the config row. NULL means 'default' for a new entity and keeps the current kind on re-register
- `p_timeout`: Per-entity liveness window replacing the kind's dead_after. NULL keeps the current override; clearing one back to the kind default is a direct UPDATE of timeout_override (an ergonomic clear parameter is backlog)
- `p_metadata`: Metadata stored on the entity. NULL keeps the existing metadata on re-register; new entities store '{}' when NULL

**Returns:** The entity row

**Example:**
```sql
SELECT * FROM presence.register('default', 'worker-7');
```

*Source: presence/src/functions/010_register.sql:1*

---

## Sweep

### presence.sweep

```sql
presence.sweep(p_namespace: text, p_limit: int4) -> setof presence.transitions
```

Mark overdue entities dead and deliver deferred death alerts.

**Parameters:**
- `p_namespace`: Tenant namespace (NULL = all namespaces, requires RLS bypass)
- `p_limit`: Maximum entities to process per call

**Returns:** The death transitions emitted by this call

**Example:**
```sql
SELECT * FROM presence.sweep('default');
```

*Source: presence/src/functions/030_sweep.sql:1*

---
