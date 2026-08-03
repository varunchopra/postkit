<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Meter Python SDK

### adjust

```python
adjust(user_id: str, event_type: str, amount: float | Decimal, unit: str, resource: str | None = None, reference_id: int | None = None, idempotency_key: str | None = None, metadata: dict | None = None) -> dict
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

*Source: sdk/src/postkit/meter/client.py:282*

---

### allocate

```python
allocate(user_id: str | None, event_type: str, amount: float | Decimal, unit: str, resource: str | None = None, idempotency_key: str | None = None, event_time: datetime | None = None, metadata: dict | None = None) -> dict
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

*Source: sdk/src/postkit/meter/client.py:75*

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

### close_period

```python
close_period(user_id: str, event_type: str, unit: str, resource: str | None, period_end: date) -> dict
```

Close a billing period, handling expiration and carry-over.

This is a ONE-WAY OPERATION. Expired balance is permanently removed from the account via an 'expiration' ledger entry. There is no "unclose".

The carry-over calculation uses AVAILABLE balance (balance minus reserved), not total balance. Active reservations are protected from expiration.

Calling close_period multiple times is safe but will recalculate based on current balance, which may produce different results if balance changed. For non-existent accounts, returns zeros without error.

**Parameters:**
- `user_id`: User ID
- `event_type`: Event type
- `unit`: Unit of measurement
- `resource`: Optional resource identifier
- `period_end`: Last day of the period being closed

**Returns:** Dict with expired (amount removed), carried_over (amount preserved),
and new_balance (balance after expiration)

*Source: sdk/src/postkit/meter/client.py:497*

---

### commit

```python
commit(reservation_id: str, actual_amount: float | Decimal, metadata: dict | None = None, idempotency_key: str | None = None) -> dict
```

Commit a reservation with actual consumption.

Meter measures. It does not enforce. If actual consumption exceeds reserved amount, the overage is recorded accurately. Caller decides policy (reject, allow, draw from parent pool, alert, etc.).

**Parameters:**
- `reservation_id`: Reservation to commit
- `actual_amount`: Actual amount consumed (can be more or less than reserved)
- `metadata`: Optional JSON metadata
- `idempotency_key`: Optional dedup key; a replay returns the original result

**Returns:** Dict with 'success', 'consumed', 'released', 'reserved_amount',
'balance', 'entry_id'

**Example:**
```python
result = meter.commit(res_id, actual_tokens)
overage = max(0, result["consumed"] - result["reserved_amount"])
if overage > 0:
    handle_overage(overage)  # caller's policy
```

*Source: sdk/src/postkit/meter/client.py:219*

---

### consume

```python
consume(user_id: str | None, event_type: str, amount: float | Decimal, unit: str, resource: str | None = None, check_balance: bool = False, idempotency_key: str | None = None, event_time: datetime | None = None, metadata: dict | None = None) -> dict
```

Record consumption.

**Parameters:**
- `user_id`: User ID (None for namespace-level pool)
- `event_type`: Event type
- `amount`: Amount consumed (must be positive)
- `unit`: Unit of measurement
- `resource`: Optional resource identifier
- `check_balance`: If True, fails when insufficient balance
- `idempotency_key`: Optional dedup key for safe retries
- `event_time`: When consumption occurred (defaults to now)
- `metadata`: Optional JSON metadata

**Returns:** Dict with 'success', 'balance', 'available', 'entry_id'

*Source: sdk/src/postkit/meter/client.py:120*

---

### get_audit_events

```python
get_audit_events(*args, **kwargs) -> list[dict]
```

Not supported - meter module does not have audit events.

The meter module uses a ledger-based design where all transactions are recorded in the ledger table. Use get_ledger() for transaction history instead.

*Source: sdk/src/postkit/meter/client.py:657*

---

### get_balance

```python
get_balance(user_id: str, event_type: str, unit: str, resource: str | None = None) -> dict
```

Get current balance for an account.

Use this to check if a user can afford an operation before starting, or to display remaining quota in the UI.

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
    # Insufficient quota - handle based on your application's needs
    return {"error": "quota_exceeded", "available": balance["available"]}

# Display remaining quota in UI
balance = meter.get_balance(user_id, "api_request", "requests")
print(f"API calls remaining: {balance['available']}")
```

*Source: sdk/src/postkit/meter/client.py:327*

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

*Source: sdk/src/postkit/meter/client.py:410*

---

### get_stats

```python
get_stats() -> dict
```

Get namespace statistics.

**Returns:** Dict with counts and totals

*Source: sdk/src/postkit/meter/client.py:638*

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

*Source: sdk/src/postkit/meter/client.py:387*

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

*Source: sdk/src/postkit/meter/client.py:371*

---

### open_period

```python
open_period(user_id: str, event_type: str, unit: str, resource: str | None, period_start: date, allocation: float | Decimal | None = None) -> float
```

Open a new billing period with allocation.

Adds the allocation to the current balance (which includes any carry-over from a previous close_period call). Creates an 'allocation' ledger entry.

The account must already exist (created via allocate() or set_period_config()). This is intentional: open_period is for recurring allocations, not initial account setup.

Repeated calls for the same account and period_start return the first call's balance without allocating again. The retry's allocation is ignored, and the result may differ from the current balance. Use allocate() with a distinct idempotency_key to add credit.

**Parameters:**
- `user_id`: User ID
- `event_type`: Event type
- `unit`: Unit of measurement
- `resource`: Optional resource identifier
- `period_start`: First day of the new period
- `allocation`: Amount to allocate (uses period_allocation if None)

**Returns:** Balance returned by the first successful call.

*Source: sdk/src/postkit/meter/client.py:537*

---

### reconcile

```python
reconcile() -> list[dict]
```

Check for discrepancies in account invariants.

Checks two invariants:
1. balance_mismatch: balance != ledger_checkpoint + SUM(retained ledger
amounts).
2. reserved_mismatch: reserved != SUM(active reservation amounts).

**Returns:** List of dicts with 'user_id', 'event_type', 'resource', 'unit',
'issue_type', 'expected', 'actual', 'discrepancy'

*Source: sdk/src/postkit/meter/client.py:620*

---

### release

```python
release(reservation_id: str, idempotency_key: str | None = None) -> bool
```

Release a reservation without consuming.

**Parameters:**
- `reservation_id`: Reservation to release
- `idempotency_key`: Optional dedup key; a replay of a completed release returns True

**Returns:** True if released, False if not found

*Source: sdk/src/postkit/meter/client.py:264*

---

### release_expired_reservations

```python
release_expired_reservations() -> int
```

Release all expired reservations for this namespace.

Finds all reservations where expires_at has passed and status is 'active', marks them as 'expired' (distinct from 'released' to distinguish automatic expiry from manual release), and reduces the corresponding account's reserved amount.

This is a maintenance operation typically run on a schedule (e.g., every minute via cron). Uses advisory locks to prevent concurrent execution for the same namespace.

No ledger entries are created because reservations are holds on existing balance, not balance changes themselves.

**Returns:** Count of reservations that were expired and released.

*Source: sdk/src/postkit/meter/client.py:593*

---

### reserve

```python
reserve(user_id: str | None, event_type: str, amount: float | Decimal, unit: str, resource: str | None = None, ttl_seconds: int = 300, idempotency_key: str | None = None, metadata: dict | None = None) -> dict
```

Reserve quota for pending operation (streaming, uncertain consumption).

Reservations are HOLDS, not balance changes. They don't create ledger entries. The hold is tracked in accounts.reserved and the reservations table. Only actual consumption (via commit) affects balance.

**Parameters:**
- `user_id`: User ID (None for namespace-level pool)
- `event_type`: Event type
- `amount`: Amount to reserve
- `unit`: Unit of measurement
- `resource`: Optional resource identifier
- `ttl_seconds`: Time until reservation auto-expires (default 300 = 5 min)
- `idempotency_key`: Optional dedup key for safe retries
- `metadata`: Optional JSON metadata

**Returns:** Dict with 'granted', 'reservation_id', 'balance', 'available', 'expires_at'

*Source: sdk/src/postkit/meter/client.py:169*

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

### set_period_config

```python
set_period_config(user_id: str, event_type: str, unit: str, resource: str | None, period_start: date, period_allocation: float | Decimal, carry_over_limit: float | Decimal | None = None) -> None
```

Configure period settings for an account.

Sets up recurring allocation parameters for period-based billing. If the account does not exist, it is created with zero balance. If it exists, only the period fields are updated; existing balance is preserved.

Period dates use the DATE type (not TIMESTAMP). Timezone handling is the caller's responsibility; dates represent calendar day boundaries in your application's billing context.

**Parameters:**
- `user_id`: User ID
- `event_type`: Event type ('llm_call', 'api_request', etc.)
- `unit`: Unit of measurement ('tokens', 'requests', etc.)
- `resource`: Optional resource identifier ('claude-sonnet', etc.)
- `period_start`: First day of the billing period
- `period_allocation`: Amount to allocate each period (must be positive)
- `carry_over_limit`: Maximum unused balance to carry forward at period close. None means unlimited carry-over. Zero means strict expiration with no carry-over. Must not be negative

*Source: sdk/src/postkit/meter/client.py:451*

---
