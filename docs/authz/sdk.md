<!-- AUTO-GENERATED. DO NOT EDIT. Run `make docs` to regenerate. -->

# Authz Python SDK

### add_hierarchy_rule

```python
add_hierarchy_rule(resource_type: str, permission: str, implies: str)
```

Add a single hierarchy rule (for complex/branching hierarchies).

Hierarchies are stored in the client's namespace:
- Use namespace="global" for app-wide defaults (all tenants inherit)
- Use tenant namespace (e.g., "org:xxx") for org-specific customizations

Permission checks look at BOTH global AND tenant hierarchies.

**Parameters:**
- `resource_type`: The resource type
- `permission`: The higher permission
- `implies`: The permission it implies

**Example:**
```python
# App-wide defaults (global client)
global_authz = AuthzClient(cursor, namespace="global")
global_authz.add_hierarchy_rule("doc", "owner", "edit")

# Org-specific customization (tenant client)
org_authz = AuthzClient(cursor, namespace="org:acme")
org_authz.add_hierarchy_rule("doc", "legal_approver", "view")
```

*Source: sdk/src/postkit/authz/client.py:834*

---

### bulk_grant

```python
bulk_grant(permission: str, *, resource: Entity, subjects: list[Entity]) -> int
```

Grant permission to many subjects at once.

Subjects are grouped by type and inserted efficiently. Supports mixed subject types in a single call.

**Parameters:**
- `permission`: The permission to grant
- `resource`: The resource as (type, id) tuple
- `subjects`: List of subjects as (type, id) tuples

**Returns:** Count of tuples inserted

**Example:**
```python
authz.bulk_grant("read", resource=("doc", "1"), subjects=[
    ("user", "alice"),
    ("user", "bob"),
    ("api_key", "key-123"),
])
```

*Source: sdk/src/postkit/authz/client.py:1041*

---

### bulk_grant_resources

```python
bulk_grant_resources(permission: str, *, resource_type: str, resource_ids: list[str], subject: Entity, subject_relation: str | None = None) -> int
```

Grant permission to a subject on many resources at once.

Optimized for bulk operations: uses single recompute instead of per-resource triggers.

Returns count of tuples inserted.

**Example:**
```python
authz.bulk_grant_resources(
    "read",
    resource_type="doc",
    resource_ids=["doc-1", "doc-2", "doc-3"],
    subject=("team", "engineering"),
)
```

*Source: sdk/src/postkit/authz/client.py:1095*

---

### check

```python
check(subject: Entity, permission: str, resource: Entity) -> bool
```

Check if a subject has a permission on a resource.

This is the core authorization check - the question every service asks.

**Parameters:**
- `subject`: The subject as (type, id) tuple (e.g., ("user", "alice"))
- `permission`: The permission to check (e.g., "read", "write")
- `resource`: The resource as (type, id) tuple

**Returns:** True if the subject has the permission

**Example:**
```python
if authz.check(("user", "alice"), "read", ("repo", "api")):
    return repo_contents
if authz.check(("api_key", "key-123"), "read", ("repo", "api")):
    return repo_contents
```

*Source: sdk/src/postkit/authz/client.py:297*

---

### check_all

```python
check_all(subject: Entity, permissions: list[str], resource: Entity) -> bool
```

Check if a subject has all of the specified permissions.

Useful for operations requiring multiple permissions.

**Parameters:**
- `subject`: The subject as (type, id) tuple
- `permissions`: List of permissions (subject needs all of them)
- `resource`: The resource as (type, id) tuple

**Returns:** True if the subject has all of the permissions

*Source: sdk/src/postkit/authz/client.py:366*

---

### check_any

```python
check_any(subject: Entity, permissions: list[str], resource: Entity) -> bool
```

Check if a subject has any of the specified permissions.

Useful for "can edit OR admin" style checks. More efficient than multiple check() calls.

**Parameters:**
- `subject`: The subject as (type, id) tuple
- `permissions`: List of permissions (subject needs at least one)
- `resource`: The resource as (type, id) tuple

**Returns:** True if the subject has at least one of the permissions

*Source: sdk/src/postkit/authz/client.py:333*

---

### cleanup_expired

```python
cleanup_expired() -> dict
```

Remove expired grants.

This is optional for storage management - expired entries are automatically filtered at query time.

**Returns:** Dictionary with count of deleted tuples

**Example:**
```python
result = authz.cleanup_expired()
print(f"Removed {result['tuples_deleted']} expired grants")
```

*Source: sdk/src/postkit/authz/client.py:1168*

---

### clear_actor

```python
clear_actor() -> None
```

Clear actor context.

*Source: sdk/src/postkit/base.py:395*

---

### clear_expiration

```python
clear_expiration(permission: str, *, resource: Entity, subject: Entity) -> bool
```

Remove expiration from a grant (make it permanent).

**Parameters:**
- `permission`: The permission/relation
- `resource`: The resource as (type, id) tuple
- `subject`: The subject as (type, id) tuple

**Returns:** True if grant was found and updated

**Example:**
```python
authz.clear_expiration("read", resource=("doc", "1"), subject=("user", "alice"))
```

*Source: sdk/src/postkit/authz/client.py:1233*

---

### clear_hierarchy

```python
clear_hierarchy(resource_type: str) -> int
```

Clear all hierarchy rules for a resource type in the client's namespace.

*Source: sdk/src/postkit/authz/client.py:872*

---

### clear_viewer

```python
clear_viewer() -> None
```

Clear the viewer context.

Should be called at end of request to prevent context leakage between requests in connection pools.

*Source: sdk/src/postkit/authz/client.py:119*

---

### count_subjects

```python
count_subjects(permission: str, resource: Entity, *, subject_type: str | None = None) -> int
```

Count subjects who have a permission on a resource.

More efficient than len(list_subjects(...)) when you only need the count.

**Parameters:**
- `permission`: The permission to check
- `resource`: The resource as (type, id) tuple
- `subject_type`: Filter to specific type (e.g., "user")

**Returns:** Count of subjects with the permission

**Example:**
```python
member_count = authz.count_subjects("member", ("team", "eng"))
user_count = authz.count_subjects("member", ("team", "eng"), subject_type="user")
```

*Source: sdk/src/postkit/authz/client.py:477*

---

### explain

```python
explain(subject: Entity, permission: str, resource: Entity) -> list[str]
```

Explain why a subject has a permission.

Returns the permission paths - useful for debugging and auditing.

**Parameters:**
- `subject`: The subject as (type, id) tuple
- `permission`: The permission to explain
- `resource`: The resource as (type, id) tuple

**Returns:** List of human-readable explanation strings

**Example:**
```python
paths = authz.explain(("user", "alice"), "read", ("repo", "api"))
# ["HIERARCHY: user:alice is member of team:eng which has admin (admin -> read) on repo:api"]
```

*Source: sdk/src/postkit/authz/client.py:398*

---

### extend_expiration

```python
extend_expiration(permission: str, *, resource: Entity, subject: Entity, extension: timedelta) -> datetime
```

Extend an existing expiration by a given interval.

**Parameters:**
- `permission`: The permission/relation
- `resource`: The resource as (type, id) tuple
- `subject`: The subject as (type, id) tuple
- `extension`: Time to add to current expiration

**Returns:** The new expiration time

**Example:**
```python
new_expires = authz.extend_expiration("read", resource=("doc", "1"),
                                      subject=("user", "alice"),
                                      extension=timedelta(days=30))
```

*Source: sdk/src/postkit/authz/client.py:1271*

---

### filter_authorized

```python
filter_authorized(subject: Entity, resource_type: str, permission: str, resource_ids: list[str]) -> list[str]
```

Batch-check which resources a subject can access.

Use instead of calling check() in a loop - single query regardless of list size.

**Parameters:**
- `subject`: The subject as (type, id) tuple
- `resource_type`: The resource type to check
- `permission`: The permission to check
- `resource_ids`: List of resource IDs to filter

**Returns:** Subset of resource_ids the subject has permission on

**Example:**
```python
visible = authz.filter_authorized(("user", uid), "note", "view", note_ids)
```

*Source: sdk/src/postkit/authz/client.py:779*

---

### get_audit_events

```python
get_audit_events(*, limit: int = 100, before: str | None = None, event_type: str | None = None, actor_id: str | None = None, resource: Entity | None = None, subject: Entity | None = None) -> list[dict]
```

Query audit events with optional filters.

**Parameters:**
- `limit`: Maximum number of events to return (default 100)
- `before`: Opaque cursor from a previous response's event['cursor']
- `event_type`: Filter by event type (e.g., 'tuple_created')
- `actor_id`: Filter by actor ID
- `resource`: Filter by resource as (type, id) tuple
- `subject`: Filter by subject as (type, id) tuple

**Returns:** List of audit event dictionaries. Each event includes a 'cursor' field
that can be passed to 'before' for pagination.

**Example:**
```python
events = authz.get_audit_events(actor_id="admin@acme.com", limit=50)
if events:
    more = authz.get_audit_events(
        actor_id="admin@acme.com", limit=50, before=events[-1]["cursor"]
    )
```

*Source: sdk/src/postkit/authz/client.py:892*

---

### get_stats

```python
get_stats() -> dict
```

Get namespace statistics for monitoring.

**Returns:** Dictionary with:
- tuple_count: Number of relationship tuples
- hierarchy_rule_count: Number of hierarchy rules
- unique_users: Distinct users with permissions
- unique_resources: Distinct resources with permissions

**Example:**
```python
stats = authz.get_stats()
print(f"Tuples: {stats['tuple_count']}, Users: {stats['unique_users']}")
```

*Source: sdk/src/postkit/authz/client.py:1018*

---

### grant

```python
grant(permission: str, *, resource: Entity, subject: Entity, subject_relation: str | None = None, expires_at: datetime | None = None) -> int
```

Grant a permission on a resource to a subject.

**Parameters:**
- `permission`: The permission to grant (e.g., "admin", "read")
- `resource`: The resource as (type, id) tuple (e.g., ("repo", "api"))
- `subject`: The subject as (type, id) tuple (e.g., ("team", "eng"))
- `subject_relation`: Optional relation on the subject (e.g., "admin" for team#admin)
- `expires_at`: Optional expiration time for time-bound permissions

**Returns:** The tuple ID

**Example:**
```python
authz.grant("admin", resource=("repo", "api"), subject=("team", "eng"))
authz.grant("read", resource=("repo", "api"), subject=("user", "alice"))
# Grant only to team admins:
authz.grant("write", resource=("repo", "api"), subject=("team", "eng"), subject_relation="admin")
# Grant with expiration:
authz.grant("read", resource=("doc", "1"), subject=("user", "bob"),
           expires_at=datetime.now(timezone.utc) + timedelta(days=30))
```

*Source: sdk/src/postkit/authz/client.py:173*

---

### list_expiring

```python
list_expiring(within: timedelta = datetime.timedelta(days=7)) -> list[dict]
```

List grants expiring within the given timeframe.

**Parameters:**
- `within`: Time window to check (default 7 days).

**Returns:** List of grants with their expiration times

**Example:**
```python
expiring = authz.list_expiring(within=timedelta(days=30))
for grant in expiring:
    print(f"{grant['subject']} access to {grant['resource']} expires {grant['expires_at']}")
```

*Source: sdk/src/postkit/authz/client.py:1138*

---

### list_external_resources

```python
list_external_resources(subject: Entity, resource_type: str, permission: str) -> list[dict]
```

List resources shared with a subject from other namespaces.

Returns resources where the subject is the recipient of a grant from a different namespace. The viewer context is automatically set to the subject if not already matching, enabling cross-namespace visibility.

Note: If set_viewer() was previously called with a different subject, this method updates the viewer context to match the subject parameter.

**Parameters:**
- `subject`: The subject as (type, id) tuple (e.g., ("user", "alice"))
- `resource_type`: Resource type (e.g., "note")
- `permission`: Minimum permission level (uses global hierarchy)

**Returns:** List of dicts with: namespace, resource_id, relation, created_at,
expires_at

**Example:**
```python
# Viewer is automatically set; explicit call not required.
shared = authz.list_external_resources(("user", "alice"), "note", "view")
```

*Source: sdk/src/postkit/authz/client.py:552*

---

### list_grants

```python
list_grants(subject: Entity, *, resource_type: str | None = None) -> list[dict]
```

List all grants for a subject.

Useful for inspecting what permissions an entity has, such as viewing API key scopes or auditing service access.

**Parameters:**
- `subject`: The subject as (type, id) tuple (e.g., ("api_key", "key-123"))
- `resource_type`: Optional filter by resource type

**Returns:** List of grant dictionaries with resource, relation, and expires_at

**Example:**
```python
# Get all grants for an API key
grants = authz.list_grants(("api_key", key_id))
for grant in grants:
    print(f"{grant['relation']} on {grant['resource']}")

# Get only note-related grants
note_grants = authz.list_grants(("api_key", key_id), resource_type="note")
```

*Source: sdk/src/postkit/authz/client.py:627*

---

### list_resources

```python
list_resources(subject: Entity, resource_type: str, permission: str, *, limit: int | None = None, cursor: str | None = None) -> list[str]
```

List resources a subject has a permission on.

**Parameters:**
- `subject`: The subject as (type, id) tuple (e.g., ("user", "alice"))
- `resource_type`: The resource type to list
- `permission`: The permission to check
- `limit`: Maximum number of results (optional)
- `cursor`: Pagination cursor (optional)

**Returns:** List of resource IDs

**Example:**
```python
repos = authz.list_resources(("user", "alice"), "repo", "read")
# ["api", "frontend", "docs"]
```

*Source: sdk/src/postkit/authz/client.py:510*

---

### list_subjects

```python
list_subjects(permission: str, resource: Entity, *, subject_type: str | None = None, limit: int | None = None, cursor: Entity | None = None) -> list[Entity]
```

List subjects who have a permission on a resource.

**Parameters:**
- `permission`: The permission to check
- `resource`: The resource as (type, id) tuple
- `subject_type`: Filter to specific type (e.g., "user")
- `limit`: Maximum number of results
- `cursor`: Pagination cursor as (type, id) tuple from last result

**Returns:** List of subjects as (type, id) tuples

**Example:**
```python
subjects = authz.list_subjects("read", ("repo", "api"))
users_only = authz.list_subjects("read", ("repo", "api"), subject_type="user")
```

*Source: sdk/src/postkit/authz/client.py:431*

---

### remove_hierarchy_rule

```python
remove_hierarchy_rule(resource_type: str, permission: str, implies: str)
```

Remove a hierarchy rule from the client's namespace.

*Source: sdk/src/postkit/authz/client.py:864*

---

### revoke

```python
revoke(permission: str, *, resource: Entity, subject: Entity, subject_relation: str | None = None) -> bool
```

Revoke a permission on a resource from a subject.

**Parameters:**
- `permission`: The permission to revoke
- `resource`: The resource as (type, id) tuple
- `subject`: The subject as (type, id) tuple
- `subject_relation`: Optional relation on the subject (e.g., "admin" for team#admin)

**Returns:** True if a tuple was deleted

**Example:**
```python
authz.revoke("read", resource=("repo", "api"), subject=("user", "alice"))
# Revoke from team admins only:
authz.revoke("write", resource=("repo", "api"), subject=("team", "eng"), subject_relation="admin")
```

*Source: sdk/src/postkit/authz/client.py:240*

---

### revoke_all_grants

```python
revoke_all_grants(subject: Entity, *, resource_type: str | None = None) -> int
```

Revoke all grants for a subject (e.g., when deleting an API key).

This is useful for cleanup when removing an entity that may have accumulated many permissions across different resources.

**Parameters:**
- `subject`: The subject as (type, id) tuple (e.g., ("api_key", "key-123"))
- `resource_type`: Optional filter to only revoke grants on specific resource type

**Returns:** Number of grants revoked

**Example:**
```python
# Revoke all grants for an API key before deletion
count = authz.revoke_all_grants(("api_key", key_id))
print(f"Revoked {count} grants")

# Revoke only note-related grants
count = authz.revoke_all_grants(("api_key", key_id), resource_type="note")
```

*Source: sdk/src/postkit/authz/client.py:670*

---

### revoke_resource_grants

```python
revoke_resource_grants(resource: Entity, *, permission: str | None = None) -> int
```

Revoke all grants ON a resource. Call before deleting the resource.

**Parameters:**
- `resource`: The resource as (type, id) tuple
- `permission`: Specific permission to revoke, or None for all

**Returns:** Count of grants revoked

**Example:**
```python
authz.revoke_resource_grants(("note", note_id))
db.execute("DELETE FROM notes WHERE id = %s", (note_id,))
```

*Source: sdk/src/postkit/authz/client.py:707*

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

*Source: sdk/src/postkit/base.py:366*

---

### set_expiration

```python
set_expiration(permission: str, *, resource: Entity, subject: Entity, expires_at: datetime | None) -> bool
```

Set or update expiration on an existing grant.

**Parameters:**
- `permission`: The permission/relation
- `resource`: The resource as (type, id) tuple
- `subject`: The subject as (type, id) tuple
- `expires_at`: New expiration time (None to make permanent)

**Returns:** True if grant was found and updated

**Example:**
```python
authz.set_expiration("read", resource=("doc", "1"), subject=("user", "alice"),
                    expires_at=datetime.now(timezone.utc) + timedelta(days=30))
```

*Source: sdk/src/postkit/authz/client.py:1191*

---

### set_hierarchy

```python
set_hierarchy(resource_type: str, *permissions: str)
```

Define permission hierarchy for a resource type.

Each permission implies the next in the chain.

**Parameters:**
- `resource_type`: The resource type (e.g., "repo")

**Example:**
```python
authz.set_hierarchy("repo", "admin", "write", "read")
# Now admin implies write, write implies read
```

*Source: sdk/src/postkit/authz/client.py:817*

---

### set_viewer

```python
set_viewer(subject: Entity) -> None
```

Set the viewer context for cross-namespace queries.

This enables the recipient_visibility RLS policy, allowing subjects to see grants where they are the recipient across ALL namespaces. Required for "Shared with me" / external resources functionality.

The setting is session-scoped. With an in-process connection pool, prefer viewer_context(), which clears it however the block exits. Behind PgBouncer in session pooling mode, DISCARD ALL between clients also clears it; in transaction pooling mode session-scoped settings are unsafe (they persist on some server connection for a later client) AND unreliable (your next statement may run on a different server connection), so do not use set_viewer there - set the context transaction-locally instead (inside a transaction, run set_config('authz.viewer_type', ..., true) and the same for viewer_id).

**Parameters:**
- `subject`: The subject as (type, id) tuple (e.g., ("user", "alice"))

**Example:**
```python
authz.set_viewer(("user", "alice"))
# Now queries can see grants TO alice across all namespaces
shared = authz.list_external_resources(("user", "alice"), "note", "view")
```

*Source: sdk/src/postkit/authz/client.py:81*

---

### transfer_grant

```python
transfer_grant(permission: str, *, resource: Entity, from_subject: Entity, to_subject: Entity) -> bool
```

Transfer a grant from one subject to another.

Deletes the grant from the current holder and creates it for the new holder in a single SQL call.  Expiration is preserved: if the source grant has an expiration, the transferred grant keeps it.  Expired grants cannot be transferred (returns False, same as no grant).

**Parameters:**
- `permission`: The permission to transfer
- `resource`: The resource as (type, id) tuple
- `from_subject`: Current holder as (type, id) tuple
- `to_subject`: New holder as (type, id) tuple

**Returns:** True if the grant was transferred, False if source had no active grant

*Source: sdk/src/postkit/authz/client.py:736*

---

### verify

```python
verify() -> list[dict]
```

Check for data integrity issues (e.g., group membership cycles).

Returns list of issues (empty if healthy).

**Example:**
```python
issues = authz.verify()
for issue in issues:
    print(f"{issue['status']}: {issue['details']}")
```

*Source: sdk/src/postkit/authz/client.py:1002*

---

### viewer_context

```python
viewer_context(subject: Entity) -> Iterator[None]
```

Set the viewer context for the duration of a block.

Equivalent to set_viewer() followed by a guaranteed clear_viewer(), so the session-scoped viewer identity cannot leak to the next user of a pooled connection, whichever way the block exits. Exiting clears the viewer entirely; it does not restore one that was set before the block.

If the connection died inside the block, the clearing call raises too; the original exception is chained as its __context__, and a dead session cannot leak, so nothing is suppressed here.

**Parameters:**
- `subject`: The subject as (type, id) tuple (e.g., ("user", "alice"))

**Example:**
```python
with authz.viewer_context(("user", "alice")):
    shared = authz.list_external_resources(
        ("user", "alice"), "note", "view"
    )
```

*Source: sdk/src/postkit/authz/client.py:132*

---
