# config

Versioned configuration storage with version history and rollback.

**Good fit:** Prompts, feature flags, app settings, or any JSON config needing version history and instant rollback.

**Not a fit:** Binary files, large blobs, or high-frequency writes (>100/sec per key).

## Install

See [installation instructions](../README.md#install) in the main README.

## Quick Start

```sql
-- Store config (creates version 1, activates it)
SELECT config.set('prompts/support-bot', '{
    "template": "You are a helpful support agent...",
    "model": "claude-sonnet-4-20250514",
    "temperature": 0.7
}');

-- Get active version
SELECT * FROM config.get('prompts/support-bot');

-- Update (creates version 2, activates it)
SELECT config.set('prompts/support-bot', '{
    "template": "You are an expert support agent...",
    "model": "claude-sonnet-4-20250514",
    "temperature": 0.5
}');

-- Rollback to previous version
SELECT config.rollback('prompts/support-bot');

-- Or activate specific version
SELECT config.activate('prompts/support-bot', 2);
```

## Key Naming Conventions

Use prefixes to organize configuration:

| Prefix | Purpose | Example |
|--------|---------|---------|
| `prompts/` | LLM system prompts | `prompts/support-bot` |
| `flags/` | Feature flags | `flags/new-checkout` |
| `secrets/` | Encrypted credentials | `secrets/OPENAI_API_KEY` |
| `settings/` | App configuration | `settings/limits` |

## Common Operations

```sql
-- List by prefix
SELECT * FROM config.list('prompts/');

-- Batch fetch (single query)
SELECT * FROM config.get_batch(ARRAY['prompts/bot-a', 'flags/checkout']);

-- Partial read
SELECT config.get_path('prompts/bot', ARRAY['temperature']);

-- Partial update (creates new version)
SELECT config.merge('flags/checkout', '{"rollout": 0.75}');

-- Search by content
SELECT * FROM config.search('{"enabled": true}', 'flags/');
```

## Version History

```sql
-- View all versions
SELECT * FROM config.history('prompts/support-bot');

-- Get specific version
SELECT * FROM config.get('prompts/support-bot', 3);

-- Delete old version (cannot delete active)
SELECT config.delete_version('prompts/support-bot', 1);

-- Cleanup old versions (keep last N per key)
SELECT config.cleanup_old_versions(10);
```

See [docs/config/](../docs/config/) for full API reference.

## Connection Pooling

When using connection pools (e.g., PgBouncer, application-level pools), clear context before returning connections:

```python
# After request completes, before returning connection to pool
config.clear_actor()  # Clear audit actor context
```

Tenant context (`config.tenant_id`) is set per-request via `ConfigClient(cursor, namespace=...)`, so it's automatically overwritten on next use.
