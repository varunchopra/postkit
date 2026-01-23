<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Config Python SDK

### activate

```python
activate(key: str, version: int) -> bool
```

Activate a specific version.

**Parameters:**
- `key`: Config key
- `version`: Version to activate

**Returns:** True if version was found and activated

*Source: sdk/src/postkit/config/client.py:287*

---

### cleanup_old_versions

```python
cleanup_old_versions(keep_versions: int = 10) -> int
```

Delete old inactive versions, keeping N most recent per key.

**Parameters:**
- `keep_versions`: Number of inactive versions to keep per key (default 10)

**Returns:** Count of versions deleted

*Source: sdk/src/postkit/config/client.py:409*

---

### clear_actor

```python
clear_actor() -> None
```

Clear actor context.

*Source: sdk/src/postkit/base.py:363*

---

### delete

```python
delete(key: str) -> int
```

Delete all versions of a config entry.

**Parameters:**
- `key`: Config key

**Returns:** Count of versions deleted

*Source: sdk/src/postkit/config/client.py:354*

---

### delete_schema

```python
delete_schema(key_pattern: str) -> bool
```

Delete a schema by its key pattern.

**Parameters:**
- `key_pattern`: Pattern to delete

**Returns:** True if deleted, False if not found

Note:
    Requires admin connection that bypasses RLS.

*Source: sdk/src/postkit/config/client.py:539*

---

### delete_version

```python
delete_version(key: str, version: int) -> bool
```

Delete a specific version (cannot delete active version).

**Parameters:**
- `key`: Config key
- `version`: Version to delete

**Returns:** True if deleted

*Source: sdk/src/postkit/config/client.py:367*

---

### exists

```python
exists(key: str) -> bool
```

Check if a config key exists.

**Parameters:**
- `key`: Config key

**Returns:** True if key exists and has an active version

*Source: sdk/src/postkit/config/client.py:383*

---

### get

```python
get(key: str, version: int | None = None) -> dict | None
```

Get config entry.

**Parameters:**
- `key`: Config key
- `version`: Specific version (default: active version)

**Returns:** Dict with 'value', 'version', 'created_at' or None if not found

*Source: sdk/src/postkit/config/client.py:163*

---

### get_audit_events

```python
get_audit_events(limit: int = 100, event_type: str | None = None, actor_id: str | None = None, key: str | None = None, before: str | None = None) -> list[dict]
```

Query audit events with optional filters.

**Parameters:**
- `limit`: Maximum number of events to return (default 100)
- `event_type`: Filter by event type (e.g., 'entry_created', 'entry_deleted')
- `actor_id`: Filter by actor ID (who made the change)
- `key`: Filter by config key
- `before`: Opaque cursor from a previous response's event['cursor']

**Returns:** List of audit event dictionaries. Each event includes a 'cursor' field
that can be passed to 'before' for pagination.

**Example:**
```python
events = config.get_audit_events(limit=50)
if events:
    more = config.get_audit_events(limit=50, before=events[-1]["cursor"])
```

*Source: sdk/src/postkit/config/client.py:424*

---

### get_batch

```python
get_batch(keys: list[str]) -> list[dict]
```

Get multiple config entries in one query.

**Parameters:**
- `keys`: List of config keys to fetch

**Returns:** List of dicts with 'key', 'value', 'version', 'created_at'

*Source: sdk/src/postkit/config/client.py:193*

---

### get_path

```python
get_path(key: str, *path: str) -> Any
```

Get a specific path within a config value.

**Parameters:**
- `key`: Config key

**Returns:** The value at the path, or None if not found

**Example:**
```python
config.get_path("prompts/bot", "temperature")
config.get_path("flags/checkout", "rollout")
config.get_path("settings/model", "params", "temperature")
```

*Source: sdk/src/postkit/config/client.py:207*

---

### get_schema

```python
get_schema(key: str) -> dict | None
```

Get the JSON Schema that applies to a config key.

**Parameters:**
- `key`: Config key to find schema for

**Returns:** JSON Schema document, or None if no matching schema

Note:
    All connections (admin and tenant) can read schemas.

*Source: sdk/src/postkit/config/client.py:520*

---

### get_stats

```python
get_stats() -> dict
```

Get namespace statistics.

**Returns:** Dict with 'total_keys', 'total_versions', 'keys_by_prefix'

*Source: sdk/src/postkit/config/client.py:394*

---

### get_value

```python
get_value(key: str, default: Any = None) -> Any
```

Get just the value (convenience method).

**Parameters:**
- `key`: Config key
- `default`: Default value if key doesn't exist

**Returns:** The config value, or default if not found

*Source: sdk/src/postkit/config/client.py:178*

---

### history

```python
history(key: str, limit: int = 50) -> list[dict]
```

Get version history for a key.

**Parameters:**
- `key`: Config key
- `limit`: Max versions to return

**Returns:** List of dicts with 'version', 'value', 'is_active', 'created_at', 'created_by'

*Source: sdk/src/postkit/config/client.py:339*

---

### list

```python
list(prefix: str | None = None, limit: int = 100, cursor: str | None = None) -> list[dict]
```

List active config entries.

**Parameters:**
- `prefix`: Filter by key prefix (e.g., 'prompts/')
- `limit`: Max results (default 100, max 1000)
- `cursor`: Pagination cursor (last key from previous page)

**Returns:** List of dicts with 'key', 'value', 'version', 'created_at'

*Source: sdk/src/postkit/config/client.py:318*

---

### list_schemas

```python
list_schemas(prefix: str | None = None, limit: int = 100) -> list[dict]
```

List all schemas, optionally filtered by prefix.

**Parameters:**
- `prefix`: Optional prefix to filter by
- `limit`: Maximum number of results (default 100)

**Returns:** List of dicts with 'key_pattern', 'schema', 'description',
'created_at', 'updated_at'

*Source: sdk/src/postkit/config/client.py:555*

---

### merge

```python
merge(key: str, changes: dict) -> int
```

Merge changes into config, creating new version.

**Parameters:**
- `key`: Config key
- `changes`: Dict of fields to merge

**Returns:** New version number

**Example:**
```python
config.merge("flags/checkout", {"rollout": 0.75})
config.merge("prompts/bot", {"temperature": 0.8, "max_tokens": 2000})
```

*Source: sdk/src/postkit/config/client.py:227*

---

### rollback

```python
rollback(key: str) -> int | None
```

Rollback to previous version.

**Parameters:**
- `key`: Config key

**Returns:** New active version number, or None if no previous version

*Source: sdk/src/postkit/config/client.py:303*

---

### search

```python
search(contains: dict, prefix: str | None = None, limit: int = 100) -> list[dict]
```

Find configs where value contains given JSON.

**Parameters:**
- `contains`: JSON object to search for (uses containment)
- `prefix`: Optional key prefix filter
- `limit`: Max results (default 100)

**Returns:** List of dicts with 'key', 'value', 'version', 'created_at'

**Example:**
```python
config.search({"enabled": True})  # All enabled flags
config.search({"model": "claude-sonnet-4-20250514"}, prefix="prompts/")
```

*Source: sdk/src/postkit/config/client.py:265*

---

### set

```python
set(key: str, value: Any) -> int
```

Create a new version and activate it.

**Parameters:**
- `key`: Config key (e.g., 'prompts/support-bot', 'flags/checkout')
- `value`: Config value (will be stored as JSONB)

**Returns:** New version number

*Source: sdk/src/postkit/config/client.py:99*

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

*Source: sdk/src/postkit/base.py:334*

---

### set_default

```python
set_default(key: str, value: Any) -> tuple[int, bool]
```

Set a config value only if the key doesn't exist.

**Parameters:**
- `key`: Config key (e.g., 'plans/free', 'flags/default-feature')
- `value`: Default config value (will be stored as JSONB)

**Returns:** Tuple of (version, was_created) where version is 1 if created.

**Example:**
```python
version, created = config.set_default("plans/free", {"tokens": 10000})
```

*Source: sdk/src/postkit/config/client.py:128*

---

### set_schema

```python
set_schema(key_pattern: str, schema: dict, description: str | None = None) -> None
```

Register a JSON Schema for validating config values.

**Parameters:**
- `key_pattern`: Prefix ending in '/' or exact key
- `schema`: JSON Schema document (Draft 7)
- `description`: Human-readable description

*Source: sdk/src/postkit/config/client.py:460*

---
