<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Lease SQL API

## Acquire

### lease.acquire

```sql
lease.acquire(p_namespace: text, p_name: text, p_holder: text, p_ttl: interval, p_metadata: jsonb) -> table(acquired: bool, fence_token: int8, expires_at: timestamptz, current_holder: text)
```

Acquire or take over a named lease.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_name`: Lease name (e.g. 'scheduler', 'exporter:cust_42')
- `p_holder`: Opaque holder identity (hostname, pod name, worker ID)
- `p_ttl`: Lease duration (default from config; capped at max_ttl)
- `p_metadata`: Metadata stored on the lease. NULL keeps the existing metadata on a live same-holder re-acquire; new acquisitions and takeovers store '{}' when NULL

**Returns:** acquired flag, fence token (NULL when the lease is held by another live holder), expiry, and current holder. On a lock timeout (a competing transaction held the row for more than 2 seconds) the result is acquired=false with all other columns NULL – the holder is unknown; callers treat it like any contended miss and retry.

**Example:**
```sql
SELECT * FROM lease.acquire('default', 'scheduler', 'worker-1');
```

*Source: lease/src/functions/010_acquire.sql:49*

---

## Context

### lease.assert_rls_active

```sql
lease.assert_rls_active() -> void
```

Raise unless row-level security applies to the current role.

**Example:**
```sql
SELECT lease.assert_rls_active();
```

*Source: lease/src/functions/080_rls.sql:107*

---

### lease.clear_actor

```sql
lease.clear_actor() -> void
```

Clear actor context. Call before returning connections to pool.

*Source: lease/src/functions/080_rls.sql:59*

---

### lease.clear_tenant

```sql
lease.clear_tenant() -> void
```

Clear the tenant context. Call before returning connections to pool.

*Source: lease/src/functions/080_rls.sql:25*

---

### lease.set_actor

```sql
lease.set_actor(p_actor_id: text, p_request_id: text, p_on_behalf_of: text, p_reason: text) -> void
```

Set actor context for the event log.

**Parameters:**
- `p_actor_id`: ID of the user/system performing the action
- `p_request_id`: Optional request/trace ID for correlation
- `p_on_behalf_of`: Optional ID if acting on behalf of another user
- `p_reason`: Optional reason for the action Actor context is captured on leases and lease.events rows.

*Source: lease/src/functions/080_rls.sql:40*

---

### lease.set_tenant

```sql
lease.set_tenant(p_tenant_id: text) -> void
```

Set the tenant context for RLS policies.

**Parameters:**
- `p_tenant_id`: Tenant/namespace identifier Must be called before any operations. Transaction-local scope.

*Source: lease/src/functions/080_rls.sql:13*

---

## Inspection

### lease.current

```sql
lease.current(p_namespace: text, p_name: text) -> table(holder_id: text, fence_token: int8, expires_at: timestamptz, metadata: jsonb)
```

Inspect a lease without locking it.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_name`: Lease name

**Returns:** Holder, fence token, expiry, and metadata; empty when no row exists

**Example:**
```sql
SELECT * FROM lease.current('default', 'scheduler');
```

*Source: lease/src/functions/040_inspect.sql:13*

---

### lease.get_events

```sql
lease.get_events(p_namespace: text, p_name: text, p_limit: int4) -> setof lease.events
```

Read the lease event log, newest first.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_name`: Lease name filter (NULL = all names)
- `p_limit`: Maximum events to return

**Returns:** Event rows (acquired, released, taken_over) with actor context

**Example:**
```sql
SELECT * FROM lease.get_events('default', 'scheduler');
```

*Source: lease/src/functions/040_inspect.sql:107*

---

### lease.get_stats

```sql
lease.get_stats(p_namespace: text) -> table(total_leases: int8, live: int8, expired: int8, total_names: int8, total_events: int8)
```

Get namespace-wide lease statistics.

**Parameters:**
- `p_namespace`: Tenant namespace

**Returns:** Row with total_leases, live, expired, total_names, total_events

**Example:**
```sql
SELECT * FROM lease.get_stats('default');
```

*Source: lease/src/functions/040_inspect.sql:75*

---

### lease.list

```sql
lease.list(p_namespace: text, p_include_expired: bool) -> setof lease.leases
```

List leases in a namespace.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_include_expired`: Include rows past their expiry (default true)

**Returns:** Lease rows, most recently acquired first

**Example:**
```sql
SELECT * FROM lease.list('default', p_include_expired := false);
```

*Source: lease/src/functions/040_inspect.sql:45*

---

## Maintenance

### lease.prune_events

```sql
lease.prune_events(p_namespace: text, p_older_than: interval, p_name: text, p_limit: int4) -> int4
```

Delete old lease events.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_older_than`: Delete events older than this interval (required)
- `p_name`: Lease name filter (NULL = all names)
- `p_limit`: Maximum events to delete per call

**Returns:** Count of deleted events

**Example:**
```sql
SELECT lease.prune_events('default', '90 days');
```

*Source: lease/src/functions/050_maintenance.sql:17*

---

## Notifications

### lease.channel_name

```sql
lease.channel_name(p_namespace: text, p_name: text) -> text
```

NOTIFY channel for a lease; LISTEN on this to receive release wake-ups.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_name`: Lease name

**Returns:** Channel name The namespace and name are joined with the control character U+001F before hashing. Names and namespaces can never contain control characters, so two different (namespace, name) pairs can never produce the same channel. md5 keeps the channel inside PostgreSQL's 63-byte identifier limit and is not used for security; replace it with pgcrypto where md5 is prohibited.

**Example:**
```sql
SELECT lease.channel_name('default', 'daily-report');
```

*Source: lease/src/functions/003_channel.sql:15*

---

## Renew and Release

### lease.release

```sql
lease.release(p_namespace: text, p_name: text, p_holder: text, p_fence: int8) -> bool
```

Release a lease you hold.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_name`: Lease name
- `p_holder`: Holder identity (must match the lease)
- `p_fence`: Fence token from acquire (must match the lease)

**Returns:** True if released, false if the lease was not held with this holder and fence (idempotent – never raises)

**Example:**
```sql
SELECT lease.release('default', 'scheduler', 'worker-1', 42);
```

*Source: lease/src/functions/020_renew_release.sql:95*

---

### lease.renew

```sql
lease.renew(p_namespace: text, p_name: text, p_holder: text, p_fence: int8, p_ttl: interval) -> table(renewed: bool, expires_at: timestamptz)
```

Extend a live lease you hold.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_name`: Lease name
- `p_holder`: Holder identity (must match the lease)
- `p_fence`: Fence token from acquire (must match the lease)
- `p_ttl`: New duration from now (default from config; capped at max_ttl)

**Returns:** renewed flag and the new expiry (NULLs when not renewed)

**Example:**
```sql
SELECT * FROM lease.renew('default', 'scheduler', 'worker-1', 42);
```

*Source: lease/src/functions/020_renew_release.sql:26*

---

## Verify

### lease.verify

```sql
lease.verify(p_namespace: text, p_name: text, p_holder: text, p_fence: int8) -> void
```

Assert, inside your transaction, that you still hold a lease.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_name`: Lease name
- `p_holder`: Holder identity (must match the lease)
- `p_fence`: Fence token from acquire (must match the lease)

**Example:**
```sql
SELECT lease.verify('default', 'exporter:cust_42', 'worker-1', 42);
```

*Source: lease/src/functions/030_verify.sql:50*

---
