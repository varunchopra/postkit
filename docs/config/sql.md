<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Config SQL API

## Audit

### config.clear_actor

```sql
config.clear_actor() -> void
```

Clear actor context

*Source: config/src/functions/030_audit.sql:24*

---

### config.create_audit_partition

```sql
config.create_audit_partition(p_year: int4, p_month: int4) -> text
```

Create a monthly partition for audit events

**Parameters:**
- `p_year`: The year (e.g., 2024)
- `p_month`: The month (1-12)

**Returns:** Partition name if created, NULL if already exists

*Source: config/src/functions/030_audit.sql:38*

---

### config.drop_audit_partitions

```sql
config.drop_audit_partitions(p_keep_months: int4) -> setof text
```

Delete old audit partitions

**Parameters:**
- `p_keep_months`: Number of months to keep (default 84 = 7 years)

**Returns:** Names of dropped partitions

*Source: config/src/functions/030_audit.sql:123*

---

### config.ensure_audit_partitions

```sql
config.ensure_audit_partitions(p_months_ahead: int4) -> setof text
```

Create partitions for upcoming months

**Parameters:**
- `p_months_ahead`: Number of months ahead to create partitions for (default 3)

**Returns:** Names of created partitions

*Source: config/src/functions/030_audit.sql:90*

---

### config.set_actor

```sql
config.set_actor(p_actor_id: text, p_request_id: text, p_on_behalf_of: text, p_reason: text) -> void
```

Set actor context for audit logging

**Parameters:**
- `p_actor_id`: The actor making changes (e.g., 'user:admin-bob', 'agent:deploy-bot')
- `p_request_id`: Optional request/correlation ID for tracing
- `p_on_behalf_of`: Optional principal being represented (e.g., 'user:customer-alice')
- `p_reason`: Optional reason for the action (e.g., 'deployment:v1.2.3')

**Example:**
```sql
SELECT config.set_actor('user:admin-bob', on_behalf_of := 'user:customer-alice');
```

*Source: config/src/functions/030_audit.sql:1*

---

## Entries

### config.activate

```sql
config.activate(p_key: text, p_version: int4, p_namespace: text) -> bool
```

Activate a specific version (for rollback or promotion)

**Returns:** True if version was found and activated

**Example:**
```sql
SELECT config.activate('prompts/support-bot', 2);
```

*Source: config/src/functions/010_entries.sql:184*

---

### config.delete

```sql
config.delete(p_key: text, p_namespace: text) -> int4
```

Delete all versions of a config entry

**Returns:** Count of versions deleted

**Example:**
```sql
SELECT config.delete('prompts/deprecated-bot');
```

*Source: config/src/functions/010_entries.sql:365*

---

### config.delete_version

```sql
config.delete_version(p_key: text, p_version: int4, p_namespace: text) -> bool
```

Delete a specific version (cannot delete active version)

**Returns:** True if deleted

**Example:**
```sql
SELECT config.delete_version('prompts/support-bot', 1);
```

*Source: config/src/functions/010_entries.sql:404*

---

### config.exists

```sql
config.exists(p_key: text, p_namespace: text) -> bool
```

Check if a config key exists (has an active version)

**Returns:** True if key exists and has an active version

**Example:**
```sql
IF config.exists('flags/new-checkout') THEN ...
```

*Source: config/src/functions/010_entries.sql:455*

---

### config.get

```sql
config.get(p_key: text, p_version: int4, p_namespace: text) -> table(value: jsonb, version: int4, created_at: timestamptz)
```

Get a config entry (active version or specific version)

**Parameters:**
- `p_key`: The config key
- `p_version`: Optional specific version (default: active version)

**Returns:** value, version, created_at PERFORMANCE: Hot path - called for every config read. Uses unique partial index entries_single_active_idx on (namespace, key) WHERE is_active for O(1) lookup. For high-throughput scenarios, consider application-layer caching.

**Example:**
```sql
SELECT * FROM config.get('prompts/support-bot');
SELECT * FROM config.get('prompts/support-bot', 3);
```

*Source: config/src/functions/010_entries.sql:105*

---

### config.get_batch

```sql
config.get_batch(p_keys: text[], p_namespace: text) -> table(key: text, value: jsonb, version: int4, created_at: timestamptz)
```

Get multiple config entries in one query

**Parameters:**
- `p_keys`: Array of config keys to fetch

**Returns:** key, value, version, created_at for each found key

**Example:**
```sql
SELECT * FROM config.get_batch(ARRAY['prompts/bot-a', 'prompts/bot-b', 'flags/checkout']);
```

*Source: config/src/functions/010_entries.sql:154*

---

### config.get_path

```sql
config.get_path(p_key: text, p_path: text[], p_namespace: text) -> jsonb
```

Get a specific JSON path from active config

**Parameters:**
- `p_key`: Config key
- `p_path`: JSON path as text array (e.g., ARRAY['model', 'name'])

**Returns:** The value at the path, or NULL if not found

**Example:**
```sql
SELECT config.get_path('prompts/bot', ARRAY['temperature']);
SELECT config.get_path('flags/checkout', ARRAY['rollout']);
```

*Source: config/src/functions/010_entries.sql:477*

---

### config.history

```sql
config.history(p_key: text, p_namespace: text, p_limit: int4) -> table(version: int4, value: jsonb, is_active: bool, created_at: timestamptz, created_by: text)
```

Get version history for a key

**Returns:** version, value, is_active, created_at, created_by

**Example:**
```sql
SELECT * FROM config.history('prompts/support-bot');
```

*Source: config/src/functions/010_entries.sql:329*

---

### config.list

```sql
config.list(p_prefix: text, p_namespace: text, p_limit: int4, p_cursor: text) -> table(key: text, value: jsonb, version: int4, created_at: timestamptz)
```

List all active config entries

**Parameters:**
- `p_prefix`: Optional prefix filter (e.g., 'prompts/' to list all prompts)
- `p_limit`: Max results (default 100, max 1000)
- `p_cursor`: Pagination cursor (last key from previous page)

**Returns:** key, value, version, created_at

**Example:**
```sql
SELECT * FROM config.list();
SELECT * FROM config.list('prompts/');
SELECT * FROM config.list('flags/');
```

*Source: config/src/functions/010_entries.sql:286*

---

### config.merge

```sql
config.merge(p_key: text, p_changes: jsonb, p_namespace: text) -> int4
```

Merge changes into config, creating new version

**Parameters:**
- `p_key`: Config key
- `p_changes`: JSON object with fields to merge (shallow merge)

**Returns:** New version number

**Example:**
```sql
SELECT config.merge('prompts/bot', '{"temperature": 0.8}');
SELECT config.merge('flags/checkout', '{"rollout": 0.75}');
```

*Source: config/src/functions/010_entries.sql:507*

---

### config.rollback

```sql
config.rollback(p_key: text, p_namespace: text) -> int4
```

Activate the previous version

**Returns:** New active version number, or NULL if no previous version

**Example:**
```sql
SELECT config.rollback('prompts/support-bot');
```

*Source: config/src/functions/010_entries.sql:241*

---

### config.search

```sql
config.search(p_contains: jsonb, p_prefix: text, p_namespace: text, p_limit: int4) -> table(key: text, value: jsonb, version: int4, created_at: timestamptz)
```

Find configs where value contains given JSON

**Parameters:**
- `p_contains`: JSON to search for (uses containment operator)
- `p_prefix`: Optional key prefix filter

**Returns:** Matching entries with key, value, version, created_at

**Example:**
```sql
SELECT * FROM config.search('{"enabled": true}');
SELECT * FROM config.search('{"model": "claude-sonnet-4-20250514"}', 'prompts/');
```

*Source: config/src/functions/010_entries.sql:547*

---

### config.set

```sql
config.set(p_key: text, p_value: jsonb, p_namespace: text) -> int4
```

Create a new version of a config entry and activate it

**Parameters:**
- `p_key`: The config key (e.g., 'prompts/support-bot', 'flags/checkout-v2')
- `p_value`: The config value as JSON
- `p_namespace`: Namespace (default: 'default')

**Returns:** New version number

**Example:**
```sql
SELECT config.set('prompts/support-bot', '{"template": "You are...", "model": "claude-sonnet-4-20250514"}');
SELECT config.set('flags/new-checkout', '{"enabled": true, "rollout": 0.5}');
SELECT config.set('secrets/OPENAI_API_KEY', '{"encrypted": "aes256gcm:..."}');
```

*Source: config/src/functions/010_entries.sql:1*

---

### config.set_default

```sql
config.set_default(p_key: text, p_value: jsonb, p_namespace: text) -> table(version: int4, created: bool)
```

Set a config value only if the key doesn't exist (for seeding/defaults)

**Parameters:**
- `p_key`: The config key
- `p_value`: The default value as JSON
- `p_namespace`: Namespace (default: 'default')

**Returns:** version (1 if created, existing version if already exists), created (true if new)

**Example:**
```sql
-- Seed default plans
SELECT * FROM config.set_default('plans/free', '{"tokens": 10000}');
-- Won't overwrite existing value
SELECT * FROM config.set_default('plans/free', '{"tokens": 5000}'); -- returns (1, false)
```

*Source: config/src/functions/010_entries.sql:58*

---

## Internal

### config.delete_schema

```sql
config.delete_schema(p_key_pattern: text) -> bool
```

Delete a schema by its key pattern

**Parameters:**
- `p_key_pattern`: Pattern to delete

**Returns:** true if deleted, false if not found

*Source: config/src/functions/060_schemas.sql:154*

---

### config.get_schema

```sql
config.get_schema(p_key: text) -> jsonb
```

Get the JSON Schema that applies to a config key

**Parameters:**
- `p_key`: The config key to find schema for

**Returns:** JSON Schema document, or NULL if no matching schema

**Example:**
```sql
SELECT config.get_schema('flags/checkout');
Matching precedence:
1. Exact match wins over prefix
2. Longer prefix wins over shorter
3. No match = returns NULL (no validation required)
```

*Source: config/src/functions/060_schemas.sql:111*

---

### config.list_schemas

```sql
config.list_schemas(p_prefix: text, p_limit: int4) -> table(key_pattern: text, schema: jsonb, description: text, created_at: timestamptz, updated_at: timestamptz)
```

List all schemas, optionally filtered by prefix

**Parameters:**
- `p_prefix`: Optional prefix to filter by
- `p_limit`: Maximum number of results (default 100)

**Returns:** Table of schemas

*Source: config/src/functions/060_schemas.sql:177*

---

## Maintenance

### config.cleanup_old_versions

```sql
config.cleanup_old_versions(p_keep_versions: int4, p_namespace: text) -> int4
```

Delete old inactive versions, keeping N most recent per key

**Parameters:**
- `p_keep_versions`: Number of inactive versions to keep per key (default 10)

**Returns:** Count of versions deleted

**Example:**
```sql
SELECT config.cleanup_old_versions(5);
```

*Source: config/src/functions/020_maintenance.sql:1*

---

### config.get_stats

```sql
config.get_stats(p_namespace: text) -> table(total_keys: int8, total_versions: int8, keys_by_prefix: jsonb)
```

Get namespace statistics

**Example:**
```sql
SELECT * FROM config.get_stats();
```

*Source: config/src/functions/020_maintenance.sql:38*

---

## Multi-tenancy

### config.clear_tenant

```sql
config.clear_tenant() -> void
```

Clear tenant context (fail-closed: queries return no rows). Call before returning pooled connections or when switching tenants.

**Example:**
```sql
SELECT config.clear_tenant();
```

*Source: config/src/functions/040_rls.sql:18*

---

### config.set_tenant

```sql
config.set_tenant(p_tenant_id: text) -> void
```

Set tenant context for RLS (transaction-local, clears on commit). Use BEGIN/COMMIT when autocommit is enabled.

**Parameters:**
- `p_tenant_id`: Tenant ID

**Example:**
```sql
BEGIN;
SELECT config.set_tenant('acme-corp');
SELECT * FROM config.entries;
COMMIT;
```

*Source: config/src/functions/040_rls.sql:1*

---
