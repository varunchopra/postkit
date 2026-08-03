<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Memory Python SDK

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

### consolidate

```python
consolidate(facts: list[dict[str, Any]], edges: list[dict[str, Any]], source_episodes: Sequence[int], *, idempotency_key: str | None = None) -> dict[str, Any]
```

Apply a distillation batch in one transaction.

Inserts facts and entities (entities dedup by content), links edges, and marks the source episodes consolidated. Fact elements carry content, optional kind ('fact'|'entity'), embedding/embed_model, confidence, valid_from/valid_until, and evidence. Edge elements reference endpoints by node id or "n<i>" (the i-th fact, 0-based) and a relation.

**Parameters:**
- `facts`: Fact elements to insert
- `edges`: Edge elements to link
- `source_episodes`: Episode ids the batch was distilled from
- `idempotency_key`: Optional replay key; a repeat with the same key is a no-op and returns skipped=True

**Returns:** Dict with node_ids (inserted or matched, in fact order) and skipped

**Example:**
```python
memory.consolidate(
    [{"content": "User's apartment has hard water"}],
    [],
    source_episodes=[1, 2],
    idempotency_key="job-42",
)
```

*Source: sdk/src/postkit/memory/client.py:241*

---

### consolidation_due

```python
consolidation_due(*, batch_size: int | None = None) -> list[dict[str, Any]]
```

Surface unconsolidated episodes for a distillation worker.

Read-only. Claiming and serialization are the worker's job (hold a lease, heartbeat through presence); this only reports what is due.

**Parameters:**
- `batch_size`: Maximum episodes to return (defaults to config)

**Returns:** One dict per due episode: id, session_id, role, content, occurred_at,
oldest first

*Source: sdk/src/postkit/memory/client.py:221*

---

### get_node

```python
get_node(node_id: int) -> dict[str, Any]
```

Fetch a single node including its evidence episode ids.

**Parameters:**
- `node_id`: Node id

**Returns:** The node dict (embedding omitted)

*Source: sdk/src/postkit/memory/client.py:395*

---

### get_stats

```python
get_stats() -> dict[str, Any]
```

Namespace-wide memory counts.

**Returns:** Dict with total_episodes, unconsolidated_episodes, total_nodes,
live_nodes, total_edges, embedding_dim

*Source: sdk/src/postkit/memory/client.py:321*

---

### list_episodes

```python
list_episodes(*, session: str | None = None, limit: int = 100, before: str | None = None) -> list[dict[str, Any]]
```

List episodes newest first, with cursor pagination.

**Parameters:**
- `session`: Optional session filter
- `limit`: Maximum rows to return
- `before`: Opaque cursor from a previous row's ['cursor'] for the next page

**Returns:** Episode dicts (embedding omitted); each carries a 'cursor' field to
pass back as before

*Source: sdk/src/postkit/memory/client.py:333*

---

### list_nodes

```python
list_nodes(*, kind: str | None = None, include_superseded: bool = False, limit: int = 100, before: str | None = None) -> list[dict[str, Any]]
```

List nodes newest first, with cursor pagination.

**Parameters:**
- `kind`: Optional kind filter ('fact' or 'entity')
- `include_superseded`: Include invalidated/superseded nodes (default False)
- `limit`: Maximum rows to return
- `before`: Opaque cursor from a previous row's ['cursor'] for the next page

**Returns:** Node dicts (embedding omitted); each carries a 'cursor' field to pass
back as before

*Source: sdk/src/postkit/memory/client.py:363*

---

### neighbors

```python
neighbors(node: int, *, relation: str | None = None) -> list[dict[str, Any]]
```

Return the nodes one edge away from a node, in either direction.

**Parameters:**
- `node`: Node whose neighbors to list
- `relation`: Optional relation filter ('entity', 'causal', 'assoc')

**Returns:** One dict per neighbor: node_id, relation, weight, direction
('out'|'in'), kind, content

*Source: sdk/src/postkit/memory/client.py:199*

---

### recall

```python
recall(*, query_embedding: Sequence[float] | None = None, keywords: Sequence[str] | None = None, k: int = 12, hops: int | None = None) -> list[dict[str, Any]]
```

Find memories relevant to a query by meaning, keywords, and connection.

Read-only. Entry points are fused from a vector arm (cosine over embeddings) and a lexical arm (full-text ranking over keywords), then node entry points expand over stored edges up to the effective hop depth. At least one of query_embedding or keywords must be given.

**Parameters:**
- `query_embedding`: Optional query embedding for the vector arm
- `keywords`: Optional keywords for the lexical arm
- `k`: Maximum rows to return (positive)
- `hops`: Expansion depth (defaults to and capped by config.recall_max_hops)

**Returns:** Scored rows, each a dict with source ('episode'|'node'), id, kind,
content, score, hops, and occurred_at, highest score first

**Example:**
```python
hits = memory.recall(keywords=["water"])
```

*Source: sdk/src/postkit/memory/client.py:160*

---

### record

```python
record(session: str, role: str, content: str, *, embedding: Sequence[float] | None = None, embed_model: str | None = None, keywords: Sequence[str] | None = None, occurred_at: datetime | None = None, metadata: dict[str, Any] | None = None) -> int
```

Append one episode to the interaction log.

The insert is the hot path and touches no other table. Embedding and its model travel together or not at all.

**Parameters:**
- `session`: Session identifier the episode belongs to
- `role`: Message role (e.g. 'user', 'assistant', 'tool')
- `content`: Raw message or event text
- `embedding`: Optional embedding of the content
- `embed_model`: Model that produced the embedding (required iff embedding is given)
- `keywords`: Optional keywords for the lexical recall arm
- `occurred_at`: When the episode happened (defaults to now())
- `metadata`: Optional JSON metadata

**Returns:** The new episode id

**Example:**
```python
memory.record("s1", "user", "hello", keywords=["hello"])
```

*Source: sdk/src/postkit/memory/client.py:98*

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

### set_dimension

```python
set_dimension(dim: int) -> None
```

Fix the embedding dimension and build the vector search indexes.

A deployment-level, one-time DDL step run after install by a role that owns the tables. Setting the same dimension again is a no-op; a different one after it is fixed raises BIZ_DIMENSION_ALREADY_SET.

**Parameters:**
- `dim`: Embedding dimension (1-16000)

*Source: sdk/src/postkit/memory/client.py:309*

---

### supersede

```python
supersede(node: int, replacement: int) -> None
```

Replace a node with a newer one, keeping the old for history.

**Parameters:**
- `node`: Node being superseded
- `replacement`: Node that replaces it

*Source: sdk/src/postkit/memory/client.py:290*

---
