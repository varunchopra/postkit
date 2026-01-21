# authz

Relationship-Based Access Control (ReBAC) for PostgreSQL. Answers "can user X do Y to resource Z?"

**Good fit:** SaaS apps, internal tools, document systems - anywhere you need "users and teams with permissions on things."

**Not a fit:** Attribute-based rules (location, time, IP), AWS IAM-style policies, or simple role-only systems where users just need roles without resource-level grants.

## Install

See [installation instructions](../README.md#install) in the main README.

## Quick Start

```sql
-- Permission hierarchy: admin -> write -> read
SELECT authz.add_hierarchy('repo', 'admin', 'write');
SELECT authz.add_hierarchy('repo', 'write', 'read');

-- Create a team
SELECT authz.write('team', 'engineering', 'member', 'user', 'alice');
SELECT authz.write('team', 'engineering', 'member', 'user', 'bob');

-- Grant the team admin access
SELECT authz.write('repo', 'acme/api', 'admin', 'team', 'engineering');

-- Check permissions
SELECT authz.check('user', 'alice', 'read', 'repo', 'acme/api');   -- true (admin implies read)
SELECT authz.check('user', 'alice', 'admin', 'repo', 'acme/api');  -- true (via team)
SELECT authz.check('user', 'charlie', 'read', 'repo', 'acme/api'); -- false (not on team)
```

See [docs/authz/](../docs/authz/) for full API reference.

## Security Model

Tenant isolation uses PostgreSQL RLS. Set `authz.tenant_id` before operations.

Cross-tenant "shared with me" is enabled by default via `tuples_recipient_visibility`. Users can see grants where they're the subject across all namespaces. This means users can enumerate which orgs have shared with them. Disable this policy if tenant existence is sensitive.

Global permission hierarchies (`namespace = 'global'`) are read-only for tenants. The `hierarchy_global_write_protection` policy blocks writes even if a tenant sets `tenant_id = 'global'`.

Audit logging is mandatory. If the audit INSERT fails, the tuple operation rolls back. Run `ensure_audit_partitions()` during deployment. A default partition catches failures but check `verify_integrity()` if rows land there.

Recursion depth is capped at 50 for groups, resources, and permission hierarchies.

## Connection Pooling

When using connection pools (e.g., PgBouncer, application-level pools), clear context before returning connections:

```python
# After request completes, before returning connection to pool
authz.clear_viewer()  # Clear cross-namespace viewer context
authz.clear_actor()   # Clear audit actor context
```

Tenant context (`authz.tenant_id`) is set per-request via `AuthzClient(cursor, namespace=...)`, so it's automatically overwritten on next use. However, `set_viewer()` persists for the session and must be explicitly cleared to prevent context leakage between requests.
