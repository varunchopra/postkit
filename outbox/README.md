# outbox

Postgres-native transactional event feed. Events are emitted inside the same transaction as the state change they describe, so an event exists exactly when the change committed. Consumers each keep a durable cursor and read every event in order.

**Good fit:** Webhook delivery, cache and search-index sync, realtime UI updates, offline-first client sync, warehouse ETL, microservice integration - several readers that each need every event, in order, from changes made in this Postgres.

**Not a fit:** Competing workers sharing one backlog (that is [queue](../queue/)), thousands of consumers per topic (use a broker), or push delivery (consumers pull; NOTIFY only wakes them).

## Install

See [installation instructions](../README.md#install) in the main README.

## Quick Start

```sql
-- Set tenant context
SELECT outbox.set_tenant('acme');

-- Consumers register once, choosing where to start
SELECT * FROM outbox.subscribe('acme', 'orders', 'billing', 'start');
-- -> position_xid: 0, position_id: 0

-- Producers emit inside the transaction that changes state
BEGIN;
  INSERT INTO orders ...;
  SELECT outbox.emit('acme', 'orders', 'order.created', '{"order_id": 42}');
COMMIT;
-- -> 1 (event id)

-- Consumers poll, process, then ack with the last row's xid and id
SELECT * FROM outbox.poll('acme', 'orders', 'billing');
-- -> id: 1, xid: 742, event_type: order.created, payload: {...}

SELECT outbox.ack('acme', 'orders', 'billing', '742', 1);
-- -> true
```

Poll then ack is at-least-once delivery: a consumer that crashes before acking sees the events again, so make processing idempotent. Processing and acking in one transaction (when the effect lives in this database) is exactly-once. Cursors are independent: acking `billing` never affects another consumer.

## Key Concept: Transaction-Ordered Cursors

Event ids are assigned at emit, but rows appear at commit, and neither happens in a single global order. Worse, a transaction's xid is assigned at its first write, which for the documented usage (emit after your business writes) is long before the emit:

```
transaction A            transaction B          consumer of 'orders'
BEGIN
UPDATE orders ...        BEGIN
                         emit -> id 100
emit -> id 101
COMMIT
                                                reads 101, acks past 100
                         COMMIT
                                                id 100 is behind the cursor: lost
```

No cursor made of ids alone survives that interleaving. What is stable is transaction order: reads in this module return only events whose transaction has finished, and everything that appears later belongs to a younger transaction. So cursors are (transaction, event) pairs, delivery follows that pair order, and B's event sorts after A's however their ids interleave. Treat the pair as opaque: poll gives you each row's `xid` and `id`, and ack takes them back.

The consequence of the visibility gate: one long-running write transaction anywhere delays delivery. A transaction pins the horizon from the moment it is assigned an xid, which happens at its first write, and events from every transaction whose first write came later stay unreadable until the stalled transaction finishes. Reads never pin: a transaction that only reads is never assigned an xid, so an hours-long report or `pg_dump` run does not delay delivery (it holds back vacuum, which is a different horizon). "Write" is broader than it sounds, though: `SELECT FOR UPDATE` takes row locks, and filling a temporary table is a write, so both assign an xid and pin like any other write transaction. The horizon is also wider than this database: the xid space is cluster-wide, so a stalled write transaction in a different database of the same cluster pins it too, and in a multi-tenant deployment one tenant's open transaction delays delivery for every tenant.

The operational guardrails depend on the PostgreSQL version. On every version, set `idle_in_transaction_session_timeout` and consider `statement_timeout`; together they kill idle transactions and single slow statements, but they cannot bound a transaction that stays busy running many short statements. PostgreSQL 17 adds `transaction_timeout`, which caps total transaction duration and turns the worst-case horizon stall into a number you configure. On 14 through 16 the worst case is unbounded by configuration, and observability is the remedy. One blocker class survives every timeout: a prepared transaction (two-phase commit) holds its xid in progress until `COMMIT PREPARED` or `ROLLBACK PREPARED` and is exempt from `transaction_timeout` by design, so an orphaned one pins the horizon until an operator resolves it. `outbox.lag` returns the horizon so a stall is visible, and `outbox.horizon_blockers()` names what is holding it back: open write transactions (pid, transaction age, query; seeing other sessions requires `pg_read_all_stats` or superuser) and prepared transactions, reported with the gid that `ROLLBACK PREPARED` takes.

A per-namespace horizon is out of scope, permanently, not pending design: advancing namespace A's horizon past an in-flight transaction requires knowing that transaction will never emit into A, and that knowledge does not exist server-side. Uncommitted rows are invisible, and intent registered in a side table is invisible until the same commit, which is circular. Bounded staleness (delivering younger committed events past a stalled transaction after a timeout) is rejected by contract for the same reason cursors exist at all: it breaks the contiguous (xid, id) prefix that cursors, `read_from`, and trim's boundary logic are built on. Production systems have hit exactly this failure: the two best-known implementations of the timeout heuristic, [Marten's async projection daemon](https://martendb.io/events/projections/async-daemon.html) (which counts and audits its gap skips) and [SqlStreamStore](https://github.com/SQLStreamStore/SQLStreamStore/issues/121), both document consumers missing events under concurrent load. Among the designs that need no daemon, the snapshot-horizon gate is the one that never loses an event, and its price is the latency sensitivity described above.

If that price is too high for a deployment, two escape hatches exist outside this module. Where tenants cannot share a horizon, use per-tenant databases. Where delivery latency must not depend on unrelated transactions at all, consume in commit order from the write-ahead log: `outbox.events` is a plain table, so a change-data-capture pipeline (Debezium's outbox event router, or any logical-decoding consumer) can stream it directly. That buys commit-order delivery at the cost of `wal_level = logical`, replication-slot monitoring, and a daemon.

## Retention and Lost Cursors

Nothing is deleted unless you call `outbox.trim`, and retention has no default:

```sql
-- From a cron job: delete events older than 30 days
SELECT * FROM outbox.trim('30 days', 'acme');
-- -> one row per topic trimmed, with the deleted count
```

With `protect_cursors` on (the config default), trim never deletes past the slowest consumer's cursor. If a position does fall below the retained range, reads raise CURSOR_LOST instead of skipping silently; recover by resyncing from your source of truth and calling `outbox.replay` with the position from the error message.

Clients that keep their own position (mobile sync, customer webhook endpoints) read with `outbox.read_from` and get the same CURSOR_LOST behavior. Their positions are invisible to `protect_cursors`, though, and trim skips topics that have no registered consumers - so set `protect_cursors = false` in config for externally-consumed topics and choose the retention window accordingly.

## Common Operations

```sql
-- Read without a registered cursor (external cursor holders store both
-- components of the last row they saw)
SELECT * FROM outbox.read_from('acme', 'orders', '0', 0, 50);

-- Move a cursor deliberately (re-deliver or skip); ('0', 0) = everything
SELECT outbox.replay('acme', 'orders', 'billing', '0', 0);

-- Check for readable events past a cursor; no lock, no count, safe to
-- call on every heartbeat
SELECT outbox.has_pending('acme', 'orders', 'billing');

-- Per-consumer backlog and the current horizon
SELECT * FROM outbox.lag('acme', 'orders');
-- -> consumer, position_xid, position_id, lag_events, lag_time, horizon

-- Namespace-wide stats
SELECT * FROM outbox.get_stats('acme');
-- -> total_events, total_topics, total_consumers, max_lag_events

-- List consumers
SELECT * FROM outbox.list_consumers('acme');
```

See [docs/outbox/](../docs/outbox/) for full API reference.

## Connection Pooling

When using connection pools (e.g., PgBouncer, application-level pools), clear context before returning connections:

```python
# After request completes, before returning connection to pool
outbox.clear_actor()  # Clear audit actor context
```

Tenant context (`outbox.tenant_id`) is set per-request via `OutboxClient(cursor, namespace=...)`, so it's automatically overwritten on next use.
