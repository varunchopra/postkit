# memory

Durable memory for agents, in Postgres. An agent appends what happens as it happens, and a language model periodically distills those raw events into facts it can query. Everything lives in your database, so a memory write commits in the caller's transaction.

Memory has two layers, and the agent moves data between them:

```
   agent ──record()──► episode log ──consolidate()──► knowledge graph
     ▲                      │                               │
     └───────── recall() ◄──┴───────────────────────────────┘
```

The **episode log** holds one append-only row per message or event, written as it happens and never edited.

The **knowledge graph** stores the distilled facts and the entities they concern as nodes, joined by typed edges (`entity`, `causal`, `assoc`). Consolidation builds it: your model reads a batch of episodes and returns the facts and edges to store.

**Recall** ranks episodes and facts against a query embedding, a keyword set, or both, then follows edges outward from the top-matching facts. Its score combines similarity, recency, and the confidence attached to a fact.

Corrections never mutate. A changed fact is recorded as a new node that **supersedes** the old one, so the history stays queryable.

A support assistant shows the whole loop. It hears "my apartment has hard water" and calls `record`. A background worker later pulls the batch with `consolidation_due`, has the model distill it, and calls `consolidate` to store the fact `apartment has hard water` linked to an `apartment` entity. Weeks on, the user asks how to descale a coffee machine, and the assistant calls `recall` first, gets the fact back by similarity, and answers without being told again. When the user moves, the next consolidation supersedes the fact and recall stops surfacing it.

**Good fit:** cross-session, cross-process agent memory, with embeddings produced client-side.

**Not a fit:** static-corpus document search (use pgvector directly), servers without pgvector, or designs that expect the database to call the model.

## Install

Memory is not part of the combined `postkit.sql` bundle: it depends on pgvector, so it installs separately on a server where the extension is available.

```bash
curl -fsSL https://github.com/varunchopra/postkit/releases/latest/download/memory.sql | psql -v ON_ERROR_STOP=1 "$DATABASE_URL"
```

The other eight postkit modules stay extension-free; see [installation instructions](../README.md#install) in the main README.

## Quick Start

Fix the embedding dimension before storing any embeddings. It is your embedding model's output width, commonly 384, 768, or 1536, and it differs from one model to the next. Setting it is one-way: it cannot change afterward, and every stored vector must match it. The call builds the vector indexes and is DDL, so a table owner runs it once:

```sql
SELECT memory.set_dimension(1536);
```

`set_tenant` scopes every later call under RLS:

```sql
SELECT memory.set_tenant('acme');

-- record(namespace, session, role, content, embedding, embed_model, keywords)
SELECT memory.record('acme', 'session-1', 'user', 'my apartment has hard water',
                     NULL, NULL, ARRAY['apartment', 'water']);

SELECT * FROM memory.recall('acme', NULL, ARRAY['water']);
```

## Consolidation

Consolidation is the caller's responsibility, because distilling episodes into facts calls your model. The module exposes the two ends and you run the loop between them: `consolidation_due` returns the episodes waiting to be distilled, your model turns a batch into facts and edges, and `consolidate` writes them back.

`consolidate` applies a batch atomically and is idempotent under a caller-supplied key, for example a hash of the episode ids: a crashed worker retries safely because a replay with a seen key is a no-op.

Memory calls no other module. For an event feed of new episodes, compose `memory.record` with `outbox.emit` in one transaction; for a worker loop, wrap `consolidation_due` and `consolidate` in `queue` and `lease`. With `notify_on_record` set, `record` fires a NOTIFY so a worker can wake without polling, but `consolidation_due` stays the source of truth.

## Corrections

Nothing is edited in place. Episodes are immutable except for the `consolidated_at` stamp, and deletion is your retention policy. Facts are immutable too, so a correction records a new fact and retires the old one:

```sql
-- node 10: "user's apartment has hard water". The user moved, so node 11
-- records the new fact and supersedes 10.
SELECT memory.supersede('acme', 10, 11);
```

The retired node keeps `valid_until`, `invalidated_at`, and `superseded_by`, so point-in-time queries resolve. Recall never returns superseded, invalidated, or expired facts. The replacement must be live, which keeps supersession acyclic.

## What This Module Does Not Include

Edge reinforcement on co-recall and any time decay or forgetting are excluded pending a benchmark; recall is read-only. Clustering, community-summary nodes, hub-degree analytics, and materialized similarity edges are excluded as derivable at query time or coupled to reinforcement.

## Common Operations

```sql
-- Browse the log and the graph, newest first, keyset-paginated
SELECT * FROM memory.list_episodes('acme');
SELECT * FROM memory.list_nodes('acme', p_kind := 'fact');

-- Nodes one edge from a node, both directions
SELECT * FROM memory.neighbors('acme', 42);

-- Namespace-wide counts
SELECT * FROM memory.get_stats('acme');
-- -> total_episodes, unconsolidated_episodes, total_nodes, live_nodes, total_edges, embedding_dim
```

See [docs/memory/](../docs/memory/) for the full API reference.

## Connection Pooling

With a connection pool (PgBouncer, an application-level pool), clear context before returning a connection:

```python
# After the request, before returning the connection to the pool
memory.clear_actor()
```

Tenant context (`memory.tenant_id`) is set per request by `MemoryClient(cursor, namespace=...)`, so it is overwritten on next use.
