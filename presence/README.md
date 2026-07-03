# presence

Postgres-native heartbeat liveness with edge detection. Entities register once and heartbeat while they run; a periodic sweep marks the silent ones dead. The product is the transition stream - every `alive -> dead -> alive` edge is recorded exactly once, and each edge can enqueue an alert job in the same transaction that detected it.

**Good fit:** Worker fleets, cron dead-man's switches, IoT and edge device check-in, on-prem connectors at customer sites, driver or agent online status - anything that reports in and must page someone exactly once when it stops.

**Not a fit:** Probing (entities report in; the module never calls out), health quality metrics (this is liveness, not APM), alert routing (that is the queue consumer's job), or millions of sub-second heartbeats (each heartbeat is a WAL-bearing write; the practical ceiling is low thousands of writes per second).

## Install

See [installation instructions](../README.md#install) in the main README.

Presence is fully standalone; the queue hooks are optional. Install and run it with nothing else - heartbeats, sweeps, and transitions (with NOTIFY) work on their own. If you also install [queue](../queue/), transitions can enqueue jobs in the same transaction, and an alert cannot be lost between detection and dispatch.

## Quick Start

```sql
-- Set tenant context
SELECT presence.set_tenant('acme');

-- Register once (idempotent), then heartbeat while running
SELECT presence.register('acme', 'worker-7');
SELECT presence.heartbeat('acme', 'worker-7');
-- -> alive

-- From a cron, every 30 seconds or so: mark the silent ones dead
SELECT * FROM presence.sweep('acme');
-- -> one row per death: entity_id, from_status, to_status, silent_for, ...

-- Who is out there right now?
SELECT * FROM presence.status('acme', 'worker-7');
-- -> status: alive, last_seen: ..., overdue: false
```

An entity is `unknown` until its first heartbeat, `alive` while it reports in, and `dead` once a sweep notices it has been silent longer than `dead_after` (90 seconds by default, configurable per kind, overridable per entity). A dead entity that heartbeats again revives immediately - revival never waits for a sweep.

## Key Concept: Transitions, Not Statuses

Everyone with a fleet builds `last_seen` plus a cron, and the hard 20% is always the same: what you act on is the *edge*, not the state. Naive sweeps miss edges, double-fire on races, and thrash on flappy entities. This module makes the edge stream the product:

```sql
SELECT from_status, to_status, at, silent_for FROM presence.get_transitions('acme', 'worker-7');
-- unknown -> alive    (first contact)
-- alive   -> dead     silent_for: 00:04:12
-- dead    -> alive    (revived)
```

Each logical edge is recorded exactly once, even with sweeps and heartbeats racing: transitions happen under the entity's row lock, and concurrent sweeps skip locked rows. Deregistering is not dying - a planned shutdown emits `departed` and pages nobody.

The status column is a cache of the last edge. It lags the wall clock by up to the sweep interval, so `status()` also returns `overdue` - true when an entity is nominally alive but already past its liveness window. Death detection latency is at most `dead_after` plus your sweep cadence; run heartbeats at a third of `dead_after` or faster, and sweep at least twice per `dead_after`.

## Alert Hooks

With queue installed, configure a hook and the death and its alert job commit together:

```sql
INSERT INTO presence.config (namespace, kind, on_death_queue)
VALUES ('acme', 'default', 'ops-alerts')
ON CONFLICT (namespace, kind) DO UPDATE SET on_death_queue = EXCLUDED.on_death_queue;

-- Now every death sweep pushes a job carrying entity_id, the edge, and silent_for
```

If you configure a hook without queue installed, or with a bad queue name, sweeps fail loudly rather than silently skipping alerts. That is deliberate: a liveness system that quietly stops alerting is worse than one that stops visibly. Fix the config or remove the hook.

Flappy entities (more than `flap_threshold` edges inside `flap_window`) keep recording transitions but stop firing hooks and NOTIFY until the window quiets. A death hook suppressed this way is not dropped: once the window expires and the entity is still dead, the next sweep delivers the alert once, carrying the real death time - up to `flap_window` late, which is the price of damping.

## Common Operations

```sql
-- Batch heartbeats, one round trip; unknown entities are reported, not errors
SELECT * FROM presence.heartbeat_many('acme', ARRAY['w1', 'w2', 'w3']);

-- Planned shutdown: departed, not dead, no alarm
SELECT presence.deregister('acme', 'worker-7');

-- Fleet views
SELECT * FROM presence.list('acme', p_status := 'dead');
SELECT * FROM presence.get_stats('acme');
-- -> total_entities, alive, dead, unknown, overdue, total_transitions

-- Delete old transition history from a cron; retention is yours to choose
SELECT * FROM presence.trim('90 days', 'acme');
```

The transitions table is queryable history, not a pollable feed - consume edges through hooks and NOTIFY. High-frequency user presence can set `heartbeat_coalesce` so heartbeats fresher than the interval skip the write entirely.

See [docs/presence/](../docs/presence/) for full API reference.

## Connection Pooling

When using connection pools (e.g., PgBouncer, application-level pools), clear context before returning connections:

```python
# After request completes, before returning connection to pool
presence.clear_actor()  # Clear audit actor context
```

Tenant context (`presence.tenant_id`) is set per-request via `PresenceClient(cursor, namespace=...)`, so it's automatically overwritten on next use.
