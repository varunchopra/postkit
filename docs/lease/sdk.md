<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Lease Python SDK

### acquire

```python
acquire(name: str, holder: str, *, ttl: timedelta | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any]
```

Acquire or take over a named lease.

A free or expired lease makes the caller the holder with a new fence token (takeovers are event-logged). Re-acquiring a lease you already hold live extends it with the SAME fence; passing metadata replaces the stored value, passing None keeps it. A lease held live by someone else is not touched.

Do not call verify() then acquire() on the same name inside one transaction: under concurrency that can abort as a deadlock (SQLSTATE 40P01, retryable).

**Parameters:**
- `name`: Lease name (e.g. 'scheduler', 'exporter:cust_42')
- `holder`: Opaque holder identity (hostname, pod name, worker ID)
- `ttl`: Lease duration (default from config; capped at max_ttl)
- `metadata`: Metadata stored on the lease; None keeps the existing metadata on a live re-acquire (new acquisitions start empty)

**Returns:** Dict with acquired (bool), fence_token (None when held by
another live holder), expires_at, and current_holder (all
None on a lock timeout - an ordinary contended miss).

*Source: sdk/src/postkit/lease/client.py:83*

---

### clear_actor

```python
clear_actor() -> None
```

Clear actor context.

*Source: sdk/src/postkit/base.py:395*

---

### current

```python
current(name: str) -> dict[str, Any] | None
```

Inspect a lease without locking it.

Returns the row even when past its expiry (compare expires_at to judge liveness); use verify() for a fenced check.

**Parameters:**
- `name`: Lease name

**Returns:** Dict with holder_id, fence_token, expires_at, metadata,
or None when no lease row exists

*Source: sdk/src/postkit/lease/client.py:232*

---

### get_events

```python
get_events(name: str | None = None, *, limit: int = 100) -> list[dict[str, Any]]
```

Read the lease event log, newest first.

**Parameters:**
- `name`: Lease name filter (None = all names)
- `limit`: Maximum events to return

**Returns:** List of event dicts (acquired, released, taken_over) with
actor context

*Source: sdk/src/postkit/lease/client.py:262*

---

### get_stats

```python
get_stats() -> dict[str, Any]
```

Get namespace-wide lease statistics.

**Returns:** Dict with total_leases, live, expired, total_names (every lease
name ever used), and total_events counts

*Source: sdk/src/postkit/lease/client.py:249*

---

### list_leases

```python
list_leases(*, include_expired: bool = True) -> list[dict[str, Any]]
```

List leases in the namespace, most recently acquired first.

**Parameters:**
- `include_expired`: Include rows past their expiry (default True)

**Returns:** List of lease row dicts

*Source: sdk/src/postkit/lease/client.py:305*

---

### prune_events

```python
prune_events(older_than: timedelta, name: str | None = None, *, limit: int = 10000) -> int
```

Delete old lease events.

The event log is the module's audit surface, so retention has no default – pass it explicitly and call this from a maintenance loop. Each call deletes at most `limit` events; call repeatedly until the return value is below the limit.

**Parameters:**
- `older_than`: Delete events older than this (required, positive)
- `name`: Lease name filter (None = all names)
- `limit`: Maximum events to delete per call

**Returns:** Count of deleted events

*Source: sdk/src/postkit/lease/client.py:280*

---

### release

```python
release(name: str, holder: str, fence: int) -> bool
```

Release a lease you hold.

Idempotent: releasing a lease you no longer hold returns False, never raises.

**Parameters:**
- `name`: Lease name
- `holder`: Holder identity (must match the lease)
- `fence`: Fence token from acquire (must match the lease)

**Returns:** True if released, False if not held with this holder and fence

*Source: sdk/src/postkit/lease/client.py:172*

---

### renew

```python
renew(name: str, holder: str, fence: int, *, ttl: timedelta | None = None) -> dict[str, Any]
```

Extend a live lease you hold.

Fails (renewed=False) once the lease is past its expiry – even if nobody else has taken it. Re-acquire to continue, receiving a new fence. Does not update metadata (acquire's same-holder path does).

**Parameters:**
- `name`: Lease name
- `holder`: Holder identity (must match the lease)
- `fence`: Fence token from acquire (must match the lease)
- `ttl`: New duration from now (default from config; capped at max_ttl)

**Returns:** Dict with renewed (bool) and expires_at (None when not renewed)

*Source: sdk/src/postkit/lease/client.py:135*

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

### verify

```python
verify(name: str, holder: str, fence: int) -> None
```

Assert, inside your transaction, that you still hold a lease.

Must be called inside the same open transaction as the writes the lease protects; the check and the writes then commit or abort together. Without one (autocommit, or between transactions) the fence lock would be released immediately and protect nothing, so this method refuses to run.

Do not call verify() then acquire() on the same name inside one transaction: under concurrency that can abort as a deadlock (SQLSTATE 40P01, retryable).

**Parameters:**
- `name`: Lease name
- `holder`: Holder identity (must match the lease)
- `fence`: Fence token from acquire (must match the lease)

*Source: sdk/src/postkit/lease/client.py:193*

---
