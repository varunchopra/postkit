# lease

Postgres-native locks with expiry and fencing tokens. A lease is a named lock a worker holds for a limited time and renews to keep; the fencing token lets the database reject writes from a worker that lost its lease without noticing.

**Good fit:** Running a job on exactly one worker - singleton crons, leader election, migration runners, "one export per customer at a time" - when the protected writes live in this Postgres.

**Not a fit:** Locks scoped to one process's call stack (use advisory locks), callers that want to queue and wait (there is no queue - poll or listen), or protecting writes in another system (the token can be carried there, but not checked there).

## Install

See [installation instructions](../README.md#install) in the main README.

## Quick Start

```sql
-- Set tenant context
SELECT lease.set_tenant('acme');

-- Acquire a lease (duration from config, default 30 seconds)
SELECT * FROM lease.acquire('acme', 'scheduler', 'worker-1');
-- -> acquired: true, fence_token: 1, expires_at: ..., current_holder: worker-1

-- Another worker is refused immediately and told who holds it
SELECT * FROM lease.acquire('acme', 'scheduler', 'worker-2');
-- -> acquired: false, fence_token: NULL, current_holder: worker-1

-- Renew before expiry (a good rhythm: every third of the duration)
SELECT * FROM lease.renew('acme', 'scheduler', 'worker-1', 1);
-- -> renewed: true, expires_at: ...

-- Release when done
SELECT lease.release('acme', 'scheduler', 'worker-1', 1);
-- -> true
```

## Key Concept: Fencing Tokens

A worker can lose its lease without noticing - a long pause, a network hiccup - and then wake up and finish a write that overwrites the new holder's work. Every acquisition therefore gets a token higher than all before it, and `verify` rejects old tokens. Run it inside the transaction it protects, and the check and the writes commit or abort together:

```sql
BEGIN;
  -- Raises if this worker no longer holds the lease with this token,
  -- aborting the whole transaction, writes included
  SELECT lease.verify('acme', 'exporter:cust_42', 'worker-1', 42);
  UPDATE exports SET ...;
COMMIT;
```

When `verify` fails, the token is permanently dead: acquire again and redo the work. Never retry the same transaction with the same token.

## Leader Election

Every candidate runs the same loop; whoever acquires becomes the leader:

```python
while True:
    got = lease.acquire("leader", holder=me, ttl=timedelta(seconds=30))
    if got["acquired"]:
        fence = got["fence_token"]
        while True:
            do_one_increment(fence)       # calls lease.verify(...) in its transaction
            if not lease.renew("leader", me, fence)["renewed"]:
                break                     # lease lost: stop at once, rejoin
    time.sleep(10)                        # candidates poll (or LISTEN for release)
```

Renew at about a third of the duration, `verify` inside every writing transaction, and stop the moment either fails.

## Expiry and Tokens

Nothing runs in the background: an expired lease simply becomes acquirable, and the takeover is recorded in `lease.events`. Once expired, `renew` and `verify` fail with the old token even if nobody else took the lease - acquiring again issues a fresh one. Tokens increase within one lease name (gaps are legal) and mean nothing across names. Name leases after the resource they protect (`exporter:cust_42`), never per job: every name keeps a permanent counter row.

## Common Operations

```sql
-- Inspect a lease without locking it
SELECT * FROM lease.current('acme', 'scheduler');

-- List leases in a namespace
SELECT * FROM lease.list('acme', p_include_expired := false);

-- Namespace-wide stats
SELECT * FROM lease.get_stats('acme');
-- -> total_leases, live, expired, total_names, total_events

-- Read the event log (acquired, released, taken_over)
SELECT * FROM lease.get_events('acme', 'scheduler');

-- Delete old events from a cron job; retention is yours to choose
SELECT lease.prune_events('acme', '90 days');
```

Renewals are not logged (a healthy worker renews every few seconds); the lease row's `updated_at` shows the last one.

See [docs/lease/](../docs/lease/) for full API reference.

## Connection Pooling

When using connection pools (e.g., PgBouncer, application-level pools), clear context before returning connections:

```python
# After request completes, before returning connection to pool
lease.clear_actor()  # Clear audit actor context
```

Tenant context (`lease.tenant_id`) is set per-request via `LeaseClient(cursor, namespace=...)`, so it's automatically overwritten on next use.
