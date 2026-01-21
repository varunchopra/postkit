<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Meter Python SDK

### adjust

```python
adjust(user_id: str, event_type: str, amount: float | int | Decimal, unit: str, resource: str | None = None, reference_id: int | None = None, idempotency_key: str | None = None, metadata: dict | None = None) -> dict
```

Create an adjustment entry (correction, refund, etc.).

**Parameters:**
- `user_id`: User ID
- `event_type`: Event type
- `amount`: Adjustment amount (positive = credit, negative = debit)
- `unit`: Unit of measurement
- `resource`: Optional resource identifier
- `reference_id`: Optional ledger entry ID being corrected
- `idempotency_key`: Optional dedup key for safe retries
- `metadata`: Optional JSON metadata

**Returns:** Dict with 'balance' and 'entry_id'

*Source: sdk/src/postkit/meter/client.py:263*

---

### allocate

```python
allocate(user_id: str | None, event_type: str, amount: float | int | Decimal, unit: str, resource: str | None = None, idempotency_key: str | None = None, event_time: datetime | None = None, metadata: dict | None = None) -> dict
```

Add quota/credits to an account.

**Parameters:**
- `user_id`: User ID (None for namespace-level pool)
- `event_type`: Event type ('llm_call', 'api_request', etc.)
- `amount`: Amount to allocate (must be positive)
- `unit`: Unit of measurement ('tokens', 'requests', 'bytes')
- `resource`: Optional resource identifier ('claude-sonnet', 'gpt-4')
- `idempotency_key`: Optional dedup key for safe retries
- `event_time`: When allocation occurred (defaults to now)
- `metadata`: Optional JSON metadata

**Returns:** Dict with 'balance' and 'entry_id'

*Source: sdk/src/postkit/meter/client.py:74*

---

### clear_actor

```python
clear_actor() -> None
```

Clear actor context.

*Source: sdk/src/postkit/base.py:363*

---

### close_period

```python
close_period(user_id: str, event_type: str, unit: str, resource: str | None, period_end: date) -> dict
```

Close a billing period, handle expiration and carry-over.

**Parameters:**
- `user_id`: User ID
- `event_type`: Event type
- `unit`: Unit of measurement
- `resource`: Optional resource identifier
- `period_end`: Last day of the period being closed

**Returns:** Dict with 'expired', 'carried_over', 'new_balance'

*Source: sdk/src/postkit/meter/client.py:466*

---

### commit

```python
commit(reservation_id: str, actual_amount: float | int | Decimal, metadata: dict | None = None) -> dict
```

Commit a reservation with actual consumption.

**Parameters:**
- `reservation_id`: Reservation to commit
- `actual_amount`: Actual amount consumed (can be more or less than reserved)
- `metadata`: Optional JSON metadata

**Returns:** Dict with 'success', 'consumed', 'released', 'reserved_amount',
'balance', 'entry_id'

**Example:**
```python
result = meter.commit(res_id, actual_tokens)
overage = max(0, result["consumed"] - result["reserved_amount"])
if overage > 0:
    handle_overage(overage)  # caller's policy
```

*Source: sdk/src/postkit/meter/client.py:209*

---

### consume

```python
consume(user_id: str, event_type: str, amount: float | int | Decimal, unit: str, resource: str | None = None, check_balance: bool = False, idempotency_key: str | None = None, event_time: datetime | None = None, metadata: dict | None = None) -> dict
```

Record consumption.

**Parameters:**
- `user_id`: User ID (required)
- `event_type`: Event type
- `amount`: Amount consumed (must be positive)
- `unit`: Unit of measurement
- `resource`: Optional resource identifier
- `check_balance`: If True, fails when insufficient balance
- `idempotency_key`: Optional dedup key for safe retries
- `event_time`: When consumption occurred (defaults to now)
- `metadata`: Optional JSON metadata

**Returns:** Dict with 'success', 'balance', 'available', 'entry_id'

*Source: sdk/src/postkit/meter/client.py:116*

---

### get_audit_events

```python
get_audit_events(*args, **kwargs) -> list[dict]
```

Not supported - meter module does not have audit events.

*Source: sdk/src/postkit/meter/client.py:577*

---

### get_balance

```python
get_balance(user_id: str, event_type: str, unit: str, resource: str | None = None) -> dict
```

Get current balance for an account.

**Parameters:**
- `user_id`: User ID
- `event_type`: Event type (e.g., "llm_call", "api_request")
- `unit`: Unit of measurement (e.g., "tokens", "requests")
- `resource`: Optional resource identifier (e.g., "claude-sonnet")

**Returns:** Dict with:
- balance: Total balance (allocations minus consumption)
- reserved: Amount currently held in active reservations
- available: balance - reserved (what can be used right now)

**Example:**
```python
# Check if user can afford an operation before starting
balance = meter.get_balance(user_id, "llm_call", "tokens", "claude-sonnet")
if balance["available"] >= estimated_tokens:
    # Proceed with operation
    result = call_llm(prompt)
    meter.consume(user_id, "llm_call", result.tokens_used, "tokens", "claude-sonnet")
else:
    # Show quota exceeded message
    raise QuotaExceededError(
        f"Need {estimated_tokens} tokens but only {balance['available']} available"
    )

# Display remaining quota in UI
balance = meter.get_balance(user_id, "api_request", "requests")
print(f"API calls remaining: {balance['available']}")
```

*Source: sdk/src/postkit/meter/client.py:305*

---

### get_ledger

```python
get_ledger(user_id: str, event_type: str, unit: str, resource: str | None = None, start_time: datetime | None = None, end_time: datetime | None = None, limit: int = 100) -> list[dict]
```

Get ledger entries for an account.

**Parameters:**
- `user_id`: User ID
- `event_type`: Event type
- `unit`: Unit of measurement
- `resource`: Optional resource identifier
- `start_time`: Optional start time filter
- `end_time`: Optional end time filter
- `limit`: Maximum entries to return (default 100, max 10000)

**Returns:** List of ledger entry dicts

*Source: sdk/src/postkit/meter/client.py:390*

---

### get_stats

```python
get_stats() -> dict
```

Get namespace statistics.

**Returns:** Dict with counts and totals

*Source: sdk/src/postkit/meter/client.py:558*

---

### get_usage

```python
get_usage(user_id: str, start_time: datetime, end_time: datetime) -> list[dict]
```

Get aggregated consumption for a user.

**Parameters:**
- `user_id`: User ID
- `start_time`: Start of period
- `end_time`: End of period

**Returns:** List of dicts with 'event_type', 'resource', 'unit',
'total_consumed', 'event_count'

*Source: sdk/src/postkit/meter/client.py:367*

---

### get_user_balances

```python
get_user_balances(user_id: str) -> list[dict]
```

Get all balances for a user across all event types and resources.

**Parameters:**
- `user_id`: User ID

**Returns:** List of dicts with 'event_type', 'resource', 'unit', 'balance',
'reserved', 'available'

*Source: sdk/src/postkit/meter/client.py:351*

---

### open_period

```python
open_period(user_id: str, event_type: str, unit: str, resource: str | None, period_start: date, allocation: float | int | Decimal | None = None) -> float
```

Open a new billing period with allocation.

**Parameters:**
- `user_id`: User ID
- `event_type`: Event type
- `unit`: Unit of measurement
- `resource`: Optional resource identifier
- `period_start`: First day of new period
- `allocation`: Amount to allocate (uses period_allocation if None)

**Returns:** New balance

*Source: sdk/src/postkit/meter/client.py:492*

---

### reconcile

```python
reconcile() -> list[dict]
```

Check for discrepancies in account invariants.

**Returns:** List of dicts with 'user_id', 'event_type', 'resource', 'unit',
'issue_type', 'expected', 'actual', 'discrepancy'

*Source: sdk/src/postkit/meter/client.py:541*

---

### release

```python
release(reservation_id: str) -> bool
```

Release a reservation without consuming.

**Parameters:**
- `reservation_id`: Reservation to release

**Returns:** True if released, False if not found

*Source: sdk/src/postkit/meter/client.py:248*

---

### release_expired_reservations

```python
release_expired_reservations() -> int
```

Release all expired reservations for this namespace.

**Returns:** Count of reservations released

*Source: sdk/src/postkit/meter/client.py:529*

---

### reserve

```python
reserve(user_id: str, event_type: str, amount: float | int | Decimal, unit: str, resource: str | None = None, ttl_seconds: int = 300, idempotency_key: str | None = None, metadata: dict | None = None) -> dict
```

Reserve quota for pending operation (streaming, uncertain consumption).

**Parameters:**
- `user_id`: User ID (required)
- `event_type`: Event type
- `amount`: Amount to reserve
- `unit`: Unit of measurement
- `resource`: Optional resource identifier
- `ttl_seconds`: Time until reservation auto-expires (default 300 = 5 min)
- `idempotency_key`: Optional dedup key for safe retries
- `metadata`: Optional JSON metadata

**Returns:** Dict with 'granted', 'reservation_id', 'balance', 'available', 'expires_at'

*Source: sdk/src/postkit/meter/client.py:162*

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

*Source: sdk/src/postkit/base.py:334*

---

### set_period_config

```python
set_period_config(user_id: str, event_type: str, unit: str, resource: str | None, period_start: date, period_allocation: float | int | Decimal, carry_over_limit: float | int | Decimal | None = None) -> None
```

Configure period settings for an account.

**Parameters:**
- `user_id`: User ID
- `event_type`: Event type
- `unit`: Unit of measurement
- `resource`: Optional resource identifier
- `period_start`: First day of the period
- `period_allocation`: Amount granted each period
- `carry_over_limit`: Max unused to roll forward (None = no limit)

*Source: sdk/src/postkit/meter/client.py:430*

---
