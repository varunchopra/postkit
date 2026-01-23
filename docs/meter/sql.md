<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Meter SQL API

## Maintenance

### meter.create_partition

```sql
meter.create_partition(p_year: int4, p_month: int4) -> text
```

Create a monthly partition for ledger

**Parameters:**
- `p_year`: Year (e.g., 2025)
- `p_month`: Month (1-12)

**Returns:** Partition name if created, NULL if already exists

**Example:**
```sql
SELECT meter.create_partition(2025, 1);
```

*Source: meter/src/functions/040_maintenance.sql:1*

---

### meter.drop_old_partitions

```sql
meter.drop_old_partitions(p_older_than_months: int4) -> setof text
```

Drop partitions older than retention period

**Parameters:**
- `p_older_than_months`: Months to retain (default 24)

**Returns:** Names of dropped partitions

**Example:**
```sql
SELECT * FROM meter.drop_old_partitions(12);
```

*Source: meter/src/functions/040_maintenance.sql:75*

---

### meter.ensure_partitions

```sql
meter.ensure_partitions(p_months_ahead: int4) -> setof text
```

Create partitions for upcoming months

**Parameters:**
- `p_months_ahead`: Number of months ahead to create (default 3)

**Returns:** Names of created partitions

**Example:**
```sql
SELECT * FROM meter.ensure_partitions(6);
```

*Source: meter/src/functions/040_maintenance.sql:44*

---

### meter.get_stats

```sql
meter.get_stats(p_namespace: text) -> table(total_accounts: int8, total_ledger_entries: int8, active_reservations: int8, total_balance: numeric, total_reserved: numeric)
```

Get namespace statistics

**Parameters:**
- `p_namespace`: Tenant namespace

**Returns:** Counts and totals

**Example:**
```sql
SELECT * FROM meter.get_stats();
```

*Source: meter/src/functions/040_maintenance.sql:200*

---

### meter.reconcile

```sql
meter.reconcile(p_namespace: text) -> table(user_id: text, event_type: text, resource: text, unit: text, issue_type: text, expected: numeric, actual: numeric, discrepancy: numeric)
```

Verify account invariants: balance vs ledger sum, reserved vs active reservations

**Parameters:**
- `p_namespace`: Tenant namespace

**Returns:** Accounts with discrepancies (issue_type: 'balance_mismatch' or 'reserved_mismatch')

**Example:**
```sql
SELECT * FROM meter.reconcile();
```

*Source: meter/src/functions/040_maintenance.sql:123*

---

## Multi-tenancy

### meter.clear_actor

```sql
meter.clear_actor() -> void
```

Clear actor context

**Example:**
```sql
SELECT meter.clear_actor();
```

*Source: meter/src/functions/050_rls.sql:52*

---

### meter.clear_tenant

```sql
meter.clear_tenant() -> void
```

Clear tenant context (fail-closed: queries return no rows). Call before returning pooled connections or when switching tenants.

**Example:**
```sql
SELECT meter.clear_tenant();
```

*Source: meter/src/functions/050_rls.sql:17*

---

### meter.set_actor

```sql
meter.set_actor(p_actor_id: text, p_request_id: text, p_on_behalf_of: text, p_reason: text) -> void
```

Set actor context for audit trail

**Parameters:**
- `p_actor_id`: The actor making changes
- `p_request_id`: Optional request/correlation ID
- `p_on_behalf_of`: Optional principal being represented
- `p_reason`: Optional reason for the action

**Example:**
```sql
SELECT meter.set_actor('user:admin-bob', 'req-123', 'user:alice', 'refund');
```

*Source: meter/src/functions/050_rls.sql:29*

---

### meter.set_tenant

```sql
meter.set_tenant(p_tenant_id: text) -> void
```

Set tenant context for RLS (transaction-local, clears on commit). Use BEGIN/COMMIT when autocommit is enabled.

**Parameters:**
- `p_tenant_id`: Tenant ID

**Example:**
```sql
BEGIN;
SELECT meter.set_tenant('acme-corp');
SELECT * FROM meter.balances;
COMMIT;
```

*Source: meter/src/functions/050_rls.sql:1*

---

## Periods

### meter.close_period

```sql
meter.close_period(p_user_id: text, p_event_type: text, p_unit: text, p_resource: text, p_period_end: date, p_namespace: text) -> table(expired: numeric, carried_over: numeric, new_balance: numeric)
```

Close a billing period, handle expiration and carry-over

**Parameters:**
- `p_user_id`: User ID
- `p_event_type`: Event type
- `p_unit`: Unit of measurement
- `p_resource`: Optional resource identifier
- `p_period_end`: Last day of the period being closed
- `p_namespace`: Tenant namespace

**Returns:** expired amount, carried_over amount, new_balance

**Example:**
```sql
SELECT * FROM meter.close_period('alice', 'llm_call', 'tokens', NULL, '2025-01-31');
```

*Source: meter/src/functions/030_periods.sql:48*

---

### meter.open_period

```sql
meter.open_period(p_user_id: text, p_event_type: text, p_unit: text, p_resource: text, p_period_start: date, p_allocation: numeric, p_namespace: text) -> numeric
```

Open a new billing period with fresh allocation

**Parameters:**
- `p_user_id`: User ID
- `p_event_type`: Event type
- `p_unit`: Unit of measurement
- `p_resource`: Optional resource identifier
- `p_period_start`: First day of new period
- `p_allocation`: Amount to allocate (uses period_allocation if NULL)
- `p_namespace`: Tenant namespace

**Returns:** New balance

**Example:**
```sql
SELECT meter.open_period('alice', 'llm_call', 'tokens', NULL, '2025-02-01');
```

*Source: meter/src/functions/030_periods.sql:128*

---

### meter.release_expired_reservations

```sql
meter.release_expired_reservations(p_namespace: text) -> int4
```

Mark expired reservations as 'expired' and release their holds. Distinct from 'released' to distinguish automatic expiry. No ledger entries.

**Parameters:**
- `p_namespace`: Optional namespace filter (NULL = all namespaces)

**Returns:** Count of reservations expired

**Example:**
```sql
SELECT meter.release_expired_reservations();
```

*Source: meter/src/functions/030_periods.sql:208*

---

### meter.set_period_config

```sql
meter.set_period_config(p_user_id: text, p_event_type: text, p_unit: text, p_resource: text, p_period_start: date, p_period_allocation: numeric, p_carry_over_limit: numeric, p_namespace: text) -> void
```

Configure period settings for an account

**Parameters:**
- `p_user_id`: User ID
- `p_event_type`: Event type
- `p_unit`: Unit of measurement
- `p_resource`: Optional resource identifier
- `p_period_start`: First day of the period
- `p_period_allocation`: Amount granted each period
- `p_carry_over_limit`: Max unused to roll forward (NULL = no limit)
- `p_namespace`: Tenant namespace

**Example:**
```sql
SELECT meter.set_period_config('alice', 'llm_call', 'tokens', NULL, '2025-01-01', 100000, 10000);
```

*Source: meter/src/functions/030_periods.sql:1*

---

## Querying

### meter.get_account

```sql
meter.get_account(p_user_id: text, p_event_type: text, p_unit: text, p_resource: text, p_namespace: text) -> meter.accounts
```

Get full account details

**Parameters:**
- `p_user_id`: User ID
- `p_event_type`: Event type
- `p_unit`: Unit of measurement
- `p_resource`: Optional resource identifier
- `p_namespace`: Tenant namespace

**Returns:** Full account row

**Example:**
```sql
SELECT * FROM meter.get_account('alice', 'llm_call', 'tokens');
```

*Source: meter/src/functions/020_query.sql:42*

---

### meter.get_balance

```sql
meter.get_balance(p_user_id: text, p_event_type: text, p_unit: text, p_resource: text, p_namespace: text) -> table(balance: numeric, reserved: numeric, available: numeric)
```

Get current balance for an account

**Parameters:**
- `p_user_id`: User ID
- `p_event_type`: Event type
- `p_unit`: Unit of measurement
- `p_resource`: Optional resource identifier
- `p_namespace`: Tenant namespace

**Returns:** balance, reserved, available (balance - reserved) PERFORMANCE: Hot path - called for balance checks and UI displays. Single index lookup on accounts PK (namespace, user_id, event_type, resource, unit). IS NOT DISTINCT FROM handles NULL user_id for namespace-level accounts.

**Example:**
```sql
SELECT * FROM meter.get_balance('alice', 'llm_call', 'tokens', 'claude-sonnet');
```

*Source: meter/src/functions/020_query.sql:1*

---

### meter.get_ledger

```sql
meter.get_ledger(p_user_id: text, p_event_type: text, p_unit: text, p_resource: text, p_start_time: timestamptz, p_end_time: timestamptz, p_limit: int4, p_namespace: text) -> table(id: int8, entry_type: text, amount: numeric, balance_after: numeric, event_time: timestamptz, reservation_id: text, reference_id: int8, actor_id: text, reason: text, metadata: jsonb)
```

Get ledger entries for an account

**Parameters:**
- `p_user_id`: User ID
- `p_event_type`: Event type
- `p_unit`: Unit of measurement
- `p_resource`: Optional resource identifier
- `p_start_time`: Optional start time filter
- `p_end_time`: Optional end time filter
- `p_limit`: Maximum entries to return (default 100, max 10000)
- `p_namespace`: Tenant namespace

**Returns:** Ledger entries

**Example:**
```sql
SELECT * FROM meter.get_ledger('alice', 'llm_call', 'tokens', p_limit := 50);
```

*Source: meter/src/functions/020_query.sql:105*

---

### meter.get_namespace_usage

```sql
meter.get_namespace_usage(p_start_time: timestamptz, p_end_time: timestamptz, p_namespace: text) -> table(event_type: text, resource: text, unit: text, total_consumed: numeric, event_count: int8, unique_users: int8)
```

Get org-level usage totals across all users

**Parameters:**
- `p_start_time`: Start of period
- `p_end_time`: End of period
- `p_namespace`: Tenant namespace

**Returns:** Aggregated consumption per event_type/resource/unit with user counts

**Example:**
```sql
SELECT * FROM meter.get_namespace_usage('2025-01-01', '2025-02-01');
```

*Source: meter/src/functions/020_query.sql:207*

---

### meter.get_usage

```sql
meter.get_usage(p_user_id: text, p_start_time: timestamptz, p_end_time: timestamptz, p_namespace: text) -> table(event_type: text, resource: text, unit: text, total_consumed: numeric, event_count: int8)
```

Get aggregated usage (consumption only) for a user

**Parameters:**
- `p_user_id`: User ID
- `p_start_time`: Start of period
- `p_end_time`: End of period
- `p_namespace`: Tenant namespace

**Returns:** Aggregated consumption per event_type/resource/unit

**Example:**
```sql
SELECT * FROM meter.get_usage('alice', '2025-01-01', '2025-02-01');
```

*Source: meter/src/functions/020_query.sql:164*

---

### meter.get_user_balances

```sql
meter.get_user_balances(p_user_id: text, p_namespace: text) -> table(event_type: text, resource: text, unit: text, balance: numeric, reserved: numeric, available: numeric)
```

Get all balances for a user across all event types and resources

**Parameters:**
- `p_user_id`: User ID
- `p_namespace`: Tenant namespace

**Returns:** List of balances per event_type/resource/unit

**Example:**
```sql
SELECT * FROM meter.get_user_balances('alice');
```

*Source: meter/src/functions/020_query.sql:68*

---

## Recording

### meter.adjust

```sql
meter.adjust(p_user_id: text, p_event_type: text, p_amount: numeric, p_unit: text, p_resource: text, p_reference_id: int8, p_idempotency_key: text, p_metadata: jsonb, p_namespace: text) -> table(balance: numeric, entry_id: int8)
```

Create an adjustment entry (correction, refund, etc.)

**Parameters:**
- `p_user_id`: User ID
- `p_event_type`: Event type
- `p_amount`: Adjustment amount (positive = credit, negative = debit)
- `p_unit`: Unit of measurement
- `p_resource`: Optional resource identifier
- `p_reference_id`: Optional ledger entry ID being corrected
- `p_idempotency_key`: Optional dedup key for safe retries
- `p_metadata`: Optional JSON metadata
- `p_namespace`: Tenant namespace

**Returns:** New balance and entry_id

**Example:**
```sql
SELECT * FROM meter.adjust('alice', 'llm_call', -500, 'tokens', 'claude-sonnet', p_reference_id := 12345);
```

*Source: meter/src/functions/013_adjust.sql:1*

---

### meter.allocate

```sql
meter.allocate(p_user_id: text, p_event_type: text, p_amount: numeric, p_unit: text, p_resource: text, p_idempotency_key: text, p_event_time: timestamptz, p_metadata: jsonb, p_namespace: text) -> table(balance: numeric, entry_id: int8)
```

Add quota/credits to an account

**Parameters:**
- `p_user_id`: User ID (NULL for namespace-level pool)
- `p_event_type`: Event type ('llm_call', 'api_request', etc.)
- `p_amount`: Amount to allocate (must be positive)
- `p_unit`: Unit of measurement ('tokens', 'requests', 'bytes')
- `p_resource`: Optional resource identifier ('claude-sonnet', 'gpt-4')
- `p_idempotency_key`: Optional dedup key for safe retries
- `p_event_time`: When the allocation occurred (defaults to now)
- `p_metadata`: Optional JSON metadata
- `p_namespace`: Tenant namespace

**Returns:** New balance and entry_id

**Example:**
```sql
SELECT * FROM meter.allocate('alice', 'llm_call', 100000, 'tokens', 'claude-sonnet');
```

*Source: meter/src/functions/010_allocate.sql:1*

---

### meter.commit

```sql
meter.commit(p_reservation_id: text, p_actual_amount: numeric, p_metadata: jsonb, p_namespace: text) -> table(success: bool, consumed: numeric, released: numeric, reserved_amount: numeric, balance: numeric, entry_id: int8)
```

Commit a reservation with actual consumption. Only actual consumption affects balance. The hold is released and reservation marked 'committed'.

**Parameters:**
- `p_reservation_id`: Reservation to commit
- `p_actual_amount`: Actual amount consumed (can exceed reserved; overage policy is caller's responsibility)
- `p_metadata`: Optional JSON metadata
- `p_namespace`: Tenant namespace

**Returns:** success, consumed, released, reserved_amount, balance, entry_id

**Example:**
```sql
SELECT * FROM meter.commit('res_abc123', 2347);
SELECT consumed - reserved_amount AS overage FROM meter.commit('res_abc123', 500);
```

*Source: meter/src/functions/012_reserve.sql:129*

---

### meter.consume

```sql
meter.consume(p_user_id: text, p_event_type: text, p_amount: numeric, p_unit: text, p_resource: text, p_check_balance: bool, p_idempotency_key: text, p_event_time: timestamptz, p_metadata: jsonb, p_namespace: text) -> table(success: bool, balance: numeric, available: numeric, entry_id: int8)
```

Record consumption (debit from account)

**Parameters:**
- `p_user_id`: User ID (required for consumption)
- `p_event_type`: Event type
- `p_amount`: Amount consumed (must be positive, stored as negative)
- `p_unit`: Unit of measurement
- `p_resource`: Optional resource identifier
- `p_check_balance`: If true, fails when insufficient balance
- `p_idempotency_key`: Optional dedup key for safe retries
- `p_event_time`: When consumption occurred (defaults to now)
- `p_metadata`: Optional JSON metadata
- `p_namespace`: Tenant namespace

**Returns:** success flag, new balance, available balance, entry_id PERFORMANCE: Hot path - called for every usage event. Uses advisory lock on idempotency key for safe retries without read-before-write races. Account upsert uses ON CONFLICT for single round-trip insert-or-update.

**Example:**
```sql
SELECT * FROM meter.consume('alice', 'llm_call', 1500, 'tokens', 'claude-sonnet');
```

*Source: meter/src/functions/011_consume.sql:1*

---

### meter.release

```sql
meter.release(p_reservation_id: text, p_namespace: text) -> bool
```

Release a reservation without consuming. Does not affect balance or create ledger entries. Only releases the hold and marks reservation 'released'.

**Parameters:**
- `p_reservation_id`: Reservation to release
- `p_namespace`: Tenant namespace

**Returns:** True if released, false if not found

**Example:**
```sql
SELECT meter.release('res_abc123');
```

*Source: meter/src/functions/012_reserve.sql:232*

---

### meter.reserve

```sql
meter.reserve(p_user_id: text, p_event_type: text, p_amount: numeric, p_unit: text, p_resource: text, p_ttl_seconds: int4, p_idempotency_key: text, p_metadata: jsonb, p_namespace: text) -> table(granted: bool, reservation_id: text, balance: numeric, available: numeric, expires_at: timestamptz)
```

Reserve quota for pending operation. Reservations are HOLDS, not balance changes. They don't create ledger entries. Only commit affects balance.

**Parameters:**
- `p_user_id`: User ID (required)
- `p_event_type`: Event type
- `p_amount`: Amount to reserve
- `p_unit`: Unit of measurement
- `p_resource`: Optional resource identifier
- `p_ttl_seconds`: Time until reservation auto-expires (default 300 = 5 min)
- `p_idempotency_key`: Optional dedup key for safe retries
- `p_metadata`: Optional JSON metadata
- `p_namespace`: Tenant namespace

**Returns:** granted flag, reservation_id, balance, available, expires_at

**Example:**
```sql
SELECT * FROM meter.reserve('alice', 'llm_call', 4000, 'tokens', 'claude-sonnet');
```

*Source: meter/src/functions/012_reserve.sql:1*

---
