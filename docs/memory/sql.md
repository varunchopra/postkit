<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Memory SQL API

## Consolidation

### memory.consolidate

```sql
memory.consolidate(p_namespace: text, p_facts: jsonb, p_edges: jsonb, p_source_episodes: int8[], p_idempotency_key: text) -> table(node_ids: int8[], skipped: bool)
```

Apply a distillation batch: insert facts and entities, link edges, mark episodes.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_facts`: JSON array of fact elements (see below)
- `p_edges`: JSON array of edge elements (see below)
- `p_source_episodes`: Episode ids the batch was distilled from
- `p_idempotency_key`: Optional replay key; a repeat with the same key is a no-op (M3)

**Returns:** node_ids (inserted or matched, in fact order) and skipped (true on replay)

*Source: memory/src/functions/030_consolidate.sql:70*

---

### memory.consolidation_due

```sql
memory.consolidation_due(p_namespace: text, p_batch_size: int4) -> table(id: int8, session_id: text, role: text, content: text, occurred_at: timestamptz)
```

Surface unconsolidated episodes for a distillation worker to process.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_batch_size`: Maximum episodes to return (defaults to config.consolidation_batch_size)

**Returns:** id, session_id, role, content, occurred_at for each due episode, oldest first

**Example:**
```sql
SELECT * FROM memory.consolidation_due('default');
```

*Source: memory/src/functions/030_consolidate.sql:14*

---

## Context

### memory.assert_rls_active

```sql
memory.assert_rls_active() -> void
```

Raise unless row-level security applies to the current role.

**Example:**
```sql
SELECT memory.assert_rls_active();
```

*Source: memory/src/functions/080_rls.sql:107*

---

### memory.clear_actor

```sql
memory.clear_actor() -> void
```

Clear actor context. Call before returning connections to pool.

*Source: memory/src/functions/080_rls.sql:59*

---

### memory.clear_tenant

```sql
memory.clear_tenant() -> void
```

Clear the tenant context. Call before returning connections to pool.

*Source: memory/src/functions/080_rls.sql:25*

---

### memory.set_actor

```sql
memory.set_actor(p_actor_id: text, p_request_id: text, p_on_behalf_of: text, p_reason: text) -> void
```

Set actor context for episode and node attribution.

**Parameters:**
- `p_actor_id`: ID of the user/system performing the action
- `p_request_id`: Optional request/trace ID for correlation
- `p_on_behalf_of`: Optional ID if acting on behalf of another user
- `p_reason`: Optional reason for the action Actor context is captured on episodes and nodes rows.

*Source: memory/src/functions/080_rls.sql:40*

---

### memory.set_tenant

```sql
memory.set_tenant(p_tenant_id: text) -> void
```

Set the tenant context for RLS policies.

**Parameters:**
- `p_tenant_id`: Tenant/namespace identifier Must be called before any operations. Transaction-local scope.

*Source: memory/src/functions/080_rls.sql:13*

---

## Dimension

### memory.set_dimension

```sql
memory.set_dimension(p_dim: int4) -> void
```

Fix the embedding dimension and build the vector search indexes.

**Parameters:**
- `p_dim`: Embedding dimension to set (1-16000)

**Returns:** void

**Example:**
```sql
SELECT memory.set_dimension(1536);
```

*Source: memory/src/functions/050_dimension.sql:17*

---

## Inspection

### memory.get_node

```sql
memory.get_node(p_namespace: text, p_id: int8) -> table(id: int8, kind: text, content: text, embed_model: text, confidence: float4, valid_from: timestamptz, valid_until: timestamptz, recorded_at: timestamptz, invalidated_at: timestamptz, superseded_by: int8, evidence: int8[], actor_id: text, request_id: text, on_behalf_of: text, reason: text, created_at: timestamptz)
```

Fetch a single node including its evidence episode ids.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_id`: Node id

**Returns:** The node row (embedding omitted)

**Example:**
```sql
SELECT * FROM memory.get_node('default', 42);
```

*Source: memory/src/functions/060_inspect.sql:158*

---

### memory.get_stats

```sql
memory.get_stats(p_namespace: text) -> table(total_episodes: int8, unconsolidated_episodes: int8, total_nodes: int8, live_nodes: int8, total_edges: int8, embedding_dim: int4)
```

Namespace-wide memory counts.

**Parameters:**
- `p_namespace`: Tenant namespace

**Returns:** total_episodes, unconsolidated_episodes, total_nodes, live_nodes, total_edges, embedding_dim

**Example:**
```sql
SELECT * FROM memory.get_stats('default');
```

*Source: memory/src/functions/060_inspect.sql:8*

---

### memory.list_episodes

```sql
memory.list_episodes(p_namespace: text, p_session: text, p_limit: int4, p_before_at: timestamptz, p_before_id: int8) -> table(id: int8, session_id: text, role: text, content: text, embed_model: text, keywords: text[], occurred_at: timestamptz, consolidated_at: timestamptz, metadata: jsonb, actor_id: text, request_id: text, on_behalf_of: text, reason: text, created_at: timestamptz)
```

List episodes newest first, with keyset pagination.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_session`: Optional session filter
- `p_limit`: Maximum rows to return
- `p_before_at`: Keyset cursor: occurred_at of the last row seen
- `p_before_id`: Keyset cursor: id of the last row seen

**Returns:** Episode rows (embedding omitted), ordered by (occurred_at, id) descending

**Example:**
```sql
SELECT * FROM memory.list_episodes('default');
```

*Source: memory/src/functions/060_inspect.sql:50*

---

### memory.list_nodes

```sql
memory.list_nodes(p_namespace: text, p_kind: text, p_include_superseded: bool, p_limit: int4, p_before_at: timestamptz, p_before_id: int8) -> table(id: int8, kind: text, content: text, embed_model: text, confidence: float4, valid_from: timestamptz, valid_until: timestamptz, recorded_at: timestamptz, invalidated_at: timestamptz, superseded_by: int8, evidence: int8[], actor_id: text, request_id: text, on_behalf_of: text, reason: text, created_at: timestamptz)
```

List nodes newest first, with keyset pagination.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_kind`: Optional kind filter ('fact' or 'entity')
- `p_include_superseded`: Include invalidated/superseded nodes (default false)
- `p_limit`: Maximum rows to return
- `p_before_at`: Keyset cursor: recorded_at of the last row seen
- `p_before_id`: Keyset cursor: id of the last row seen

**Returns:** Node rows (embedding omitted), ordered by (recorded_at, id) descending

**Example:**
```sql
SELECT * FROM memory.list_nodes('default');
```

*Source: memory/src/functions/060_inspect.sql:102*

---

## Notifications

### memory.channel_name

```sql
memory.channel_name(p_namespace: text) -> text
```

NOTIFY channel for a namespace; LISTEN on this to receive record wake-ups.

**Parameters:**
- `p_namespace`: Tenant namespace

**Returns:** Channel name md5 keeps the channel inside PostgreSQL's 63-byte identifier limit and is not used for security; replace it with pgcrypto where md5 is prohibited. record() notifies this channel when the namespace config has notify_on_record enabled, so a consolidation worker can wake instead of polling; consolidation_due() remains the source of truth for what is due.

**Example:**
```sql
SELECT memory.channel_name('default');
```

*Source: memory/src/functions/003_channel.sql:13*

---

## Recall

### memory.neighbors

```sql
memory.neighbors(p_namespace: text, p_node: int8, p_relation: text) -> table(node_id: int8, relation: text, weight: float4, direction: text, kind: text, content: text)
```

Return the nodes one edge away from a node, in either direction.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_node`: Node whose neighbors to list
- `p_relation`: Optional relation filter ('entity', 'causal', 'assoc')

**Returns:** node_id, relation, weight, direction ('out'|'in'), kind, content

**Example:**
```sql
SELECT * FROM memory.neighbors('default', 42);
```

*Source: memory/src/functions/020_recall.sql:226*

---

### memory.recall

```sql
memory.recall(p_namespace: text, p_query_embedding: vector, p_keywords: text[], p_k: int4, p_hops: int4) -> table(source: text, id: int8, kind: text, content: text, score: float8, hops: int4, occurred_at: timestamptz)
```

Find memories relevant to a query by meaning, keywords, and connection.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_query_embedding`: Optional query embedding for the vector arm
- `p_keywords`: Optional keyword array for the lexical arm
- `p_k`: Maximum rows to return (positive)
- `p_hops`: Graph expansion depth (defaults to and capped by config.recall_max_hops)

**Returns:** Scored episodes and nodes: source, id, kind, content, score, hops, occurred_at

**Example:**
```sql
SELECT * FROM memory.recall('default', NULL, ARRAY['hello']);
```

*Source: memory/src/functions/020_recall.sql:25*

---

## Recording

### memory.record

```sql
memory.record(p_namespace: text, p_session: text, p_role: text, p_content: text, p_embedding: vector, p_embed_model: text, p_keywords: text[], p_occurred_at: timestamptz, p_metadata: jsonb) -> int8
```

Append one episode to the interaction log.

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_session`: Session identifier the episode belongs to
- `p_role`: Message role (e.g. 'user', 'assistant', 'tool')
- `p_content`: Raw message or event text
- `p_embedding`: Optional embedding of the content (paired with p_embed_model)
- `p_embed_model`: Model that produced the embedding (required iff p_embedding is set)
- `p_keywords`: Optional keyword array for the lexical recall arm
- `p_occurred_at`: When the episode happened (defaults to now())
- `p_metadata`: Optional JSON metadata

**Returns:** The new episode id

**Example:**
```sql
SELECT memory.record('default', 's1', 'user', 'hello', NULL, NULL, ARRAY['hello']);
```

*Source: memory/src/functions/010_record.sql:22*

---

## Supersession

### memory.supersede

```sql
memory.supersede(p_namespace: text, p_node: int8, p_replacement: int8) -> void
```

Replace a node with a newer one, keeping the old for history (M4).

**Parameters:**
- `p_namespace`: Tenant namespace
- `p_node`: Node being superseded
- `p_replacement`: Node that replaces it

**Returns:** void

**Example:**
```sql
SELECT memory.supersede('default', 10, 11);
```

*Source: memory/src/functions/040_supersede.sql:19*

---
