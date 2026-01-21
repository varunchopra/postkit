# meter

Double-entry ledger for usage tracking. Handles quotas, consumption, reservations, and billing periods. Meter measures - it does not price.

**Good fit:** SaaS apps with usage-based billing, AI/LLM token tracking, API rate limiting with quotas, or any system needing atomic balance checks with an immutable audit trail.

**Not a fit:** Converting usage into prices, generating invoices, or processing payments. Meter tracks quantities - you'll need to add your own billing integration.

## Install

See [installation instructions](../README.md#install) in the main README.

## Quick Start

```sql
-- Grant tokens to a user
SELECT * FROM meter.allocate('alice', 'llm_call', 100000, 'tokens', 'claude-sonnet');
-- -> balance: 100000, entry_id: 1

-- Record consumption (immediate, known amount)
SELECT * FROM meter.consume('alice', 'llm_call', 1500, 'tokens', 'claude-sonnet');
-- -> success: true, balance: 98500, available: 98500, entry_id: 2

-- Check balance
SELECT * FROM meter.get_balance('alice', 'llm_call', 'tokens', 'claude-sonnet');
-- -> balance: 98500, reserved: 0, available: 98500
```

## Key Concept: Reservations

For operations where you don't know the final cost upfront (streaming LLM calls, uploads, etc.), use the reserve -> commit pattern:

```sql
-- 1. Reserve before starting (holds tokens, doesn't deduct)
SELECT * FROM meter.reserve('alice', 'llm_call', 4000, 'tokens', 'claude-sonnet');
-- -> granted: true, reservation_id: 'res_abc123', balance: 98500, available: 94500, expires_at: ...

-- 2. Do your streaming LLM call...

-- 3. Commit with actual usage (creates ledger entry, releases hold)
SELECT * FROM meter.commit('res_abc123', 2347);
-- -> success: true, consumed: 2347, released: 1653, reserved_amount: 4000, balance: 96153, entry_id: 3

-- Or if the operation failed/was cancelled:
SELECT meter.release('res_abc123');
-- -> true (hold released, no consumption recorded)
```

Reservations auto-expire after 5 minutes (configurable). Run `meter.release_expired_reservations()` periodically to clean up.

## Billing Periods

For monthly quotas with optional carry-over:

```sql
-- Configure account: 50k tokens/month, carry up to 10k unused
SELECT meter.set_period_config(
    'alice', 'llm_call', 'tokens',
    p_period_allocation := 50000,
    p_carry_over_limit := 10000
);

-- Open January with 50k allocation
SELECT meter.open_period('alice', 'llm_call', 'tokens', '2025-01-01');

-- ... user consumes 35k during January ...

-- Close January (15k unused, 10k carries over, 5k expires)
SELECT * FROM meter.close_period('alice', 'llm_call', 'tokens', '2025-01-01');
-- -> expired: 5000, carried_over: 10000

-- Open February (10k carried + 50k new = 60k available)
SELECT meter.open_period('alice', 'llm_call', 'tokens', '2025-02-01');
```

## Usage Queries

```sql
-- All balances for a user
SELECT * FROM meter.get_user_balances('alice');

-- Consumption in a time period
SELECT * FROM meter.get_usage('alice', '2025-01-01', '2025-02-01');

-- Org-wide usage totals
SELECT * FROM meter.get_namespace_usage('2025-01-01', '2025-02-01');

-- Full ledger history
SELECT * FROM meter.get_ledger('alice', 'llm_call', 'tokens', p_limit := 50);
```

## Idempotency

All write operations support idempotency keys for safe retries:

```sql
SELECT * FROM meter.consume(
    'alice', 'llm_call', 1500, 'tokens',
    p_idempotency_key := 'req-abc-123'
);
-- Safe to retry - same key returns same result without double-charging
```

See [docs/meter/](../docs/meter/) for full API reference.

## Connection Pooling

When using connection pools (e.g., PgBouncer, application-level pools), clear context before returning connections:

```python
# After request completes, before returning connection to pool
meter.clear_actor()  # Clear audit actor context
```

Tenant context (`meter.tenant_id`) is set per-request via `MeterClient(cursor, namespace=...)`, so it's automatically overwritten on next use.
