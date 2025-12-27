# Product Design Document: postkit Admin UI

## Overview

A web-based admin interface for postkit/authz. Enables operators to view permissions, manage access, investigate issues, and audit changes without writing SQL.

## Problem Statement

postkit/authz is SQL-native by design. This is powerful for developers but creates friction for:

- Security teams investigating access issues
- Ops teams debugging permission problems
- Compliance teams running access reviews
- Developers exploring the permission model during integration

Currently, all of these require SQL queries or building custom tooling.

## Target Users

| User | Primary Goal | Frequency |
|------|--------------|-----------|
| **Security Engineer** | "Who has access to this resource?" | Weekly access reviews |
| **Developer** | "Why can't Alice access this?" | Debugging during integration |
| **Compliance Officer** | "Show me all admin grants last quarter" | Quarterly audits |
| **Ops Engineer** | "What changed that broke access?" | Incident response |

## Goals

1. Answer common permission questions without SQL
2. Provide audit trail visibility for compliance
3. Enable basic access management (grant/revoke)
4. Support multi-tenant deployments

## Non-Goals

- Replace SQL for complex queries
- User-facing permission management (end users don't see this)
- Role management / RBAC builder (authz is lower-level)
- SSO integration (v1 uses database auth)

---

## Information Architecture

```
postkit Admin
|
+-- Dashboard
|   - Stats (tuple count, computed count, amplification)
|   - Recent activity
|
+-- Resources
|   - Browse by type
|   - View resource details
|   - See who has access
|   - Grant/revoke access
|
+-- Users
|   - List users
|   - View user details
|   - See what they can access
|   - See group memberships
|
+-- Groups
|   - List groups
|   - View members
|   - See group permissions
|   - Add/remove members
|
+-- Hierarchy
|   - View by resource type
|   - See permission chains
|   - Add/remove rules
|
+-- Audit Log
|   - Search events
|   - Filter by actor, resource, time
|   - Export
|
+-- Query Tool
|   - Interactive permission checker
|   - "Can X do Y on Z?"
|   - Show explanation path
```

---

## Feature Details

### Dashboard

**Purpose:** At-a-glance health and activity.

**Content:**
- Namespace selector (top-level, persists across pages)
- Stats: tuple count, computed count, amplification factor
- Recent audit events (last 10)
- Quick actions: Check permission, Grant access

```
+------------------------------------------------------------------+
|  postkit Admin                    Namespace: [production v]     |
+------------------------------------------------------------------+
|                                                                  |
|  Stats                                                           |
|  +----------------+  +----------------+  +-------------------+   |
|  | Tuples         |  | Computed       |  | Amplification     |   |
|  | 12,847         |  | 156,302        |  | 12.2x             |   |
|  +----------------+  +----------------+  +-------------------+   |
|                                                                  |
|  Recent Activity                                                 |
|  +------------------------------------------------------------+  |
|  | 10:23  admin@acme.com  GRANTED  repo:api#admin -> team:eng |  |
|  | 10:21  admin@acme.com  ADDED    user:alice -> team:eng     |  |
|  | 09:45  system          REVOKED  doc:123#read -> user:bob   |  |
|  | ...                                                        |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  Quick Actions                                                   |
|  [Check Permission]  [Grant Access]                              |
|                                                                  |
+------------------------------------------------------------------+
```

---

### Resources

**Purpose:** Answer "Who has access to this resource?"

**List View:**
- Filter by resource type
- Search by resource ID
- Show permission count per resource

**Detail View:**
- Resource type and ID
- All users with access (from computed table)
- Grouped by permission level
- Direct grants vs inherited (via group)
- Grant/revoke actions

```
+------------------------------------------------------------------+
|  Resources > repo > api                                          |
+------------------------------------------------------------------+
|                                                                  |
|  repo:api                                                        |
|                                                                  |
|  Access Summary                                                  |
|  +------------------------------------------------------------+  |
|  | admin (3 users)                                            |  |
|  |   alice         direct                        [Revoke]     |  |
|  |   bob           via team:engineering          [Revoke]     |  |
|  |   carol         via team:engineering          [Revoke]     |  |
|  +------------------------------------------------------------+  |
|  | write (5 users)                                            |  |
|  |   alice         inherited (admin)                          |  |
|  |   bob           inherited (admin)                          |  |
|  |   carol         inherited (admin)                          |  |
|  |   dave          direct                        [Revoke]     |  |
|  |   eve           via team:contractors          [Revoke]     |  |
|  +------------------------------------------------------------+  |
|  | read (12 users)                                            |  |
|  |   ...                                                      |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  [Grant Access]                                                  |
|                                                                  |
|  Audit Log (this resource)                                       |
|  +------------------------------------------------------------+  |
|  | 10:23  admin@acme.com  GRANTED  admin -> team:eng          |  |
|  | 09:15  admin@acme.com  REVOKED  read -> user:frank         |  |
|  +------------------------------------------------------------+  |
|                                                                  |
+------------------------------------------------------------------+
```

---

### Users

**Purpose:** Answer "What can this user access?"

**List View:**
- Search by user ID
- Show resource count per user

**Detail View:**
- User ID
- Group memberships
- All accessible resources (from computed table)
- Grouped by resource type, then permission

```
+------------------------------------------------------------------+
|  Users > alice                                                   |
+------------------------------------------------------------------+
|                                                                  |
|  user:alice                                                      |
|                                                                  |
|  Group Memberships                                               |
|  +------------------------------------------------------------+  |
|  | team:engineering     member                   [Remove]      |  |
|  | team:platform        admin                    [Remove]      |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  Accessible Resources                                            |
|  +------------------------------------------------------------+  |
|  | repo (3)                                                   |  |
|  |   repo:api           admin (direct)                        |  |
|  |   repo:frontend      write (via team:engineering)          |  |
|  |   repo:docs          read (via team:engineering)           |  |
|  +------------------------------------------------------------+  |
|  | doc (15)                                                   |  |
|  |   doc:roadmap        admin (direct)                        |  |
|  |   doc:specs          read (via team:platform)              |  |
|  |   ...                                                      |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  [Grant Access]                                                  |
|                                                                  |
+------------------------------------------------------------------+
```

---

### Groups

**Purpose:** Manage group membership.

**List View:**
- List all groups (resource_type where tuples have subject_type='user' and relation='member')
- Show member count

**Detail View:**
- Group ID and type
- Members list
- Permissions granted to this group
- Add/remove members

```
+------------------------------------------------------------------+
|  Groups > team:engineering                                       |
+------------------------------------------------------------------+
|                                                                  |
|  team:engineering                                                |
|                                                                  |
|  Members (12)                                                    |
|  +------------------------------------------------------------+  |
|  | alice         member                          [Remove]      |  |
|  | bob           member                          [Remove]      |  |
|  | carol         admin                           [Remove]      |  |
|  | ...                                                         |  |
|  +------------------------------------------------------------+  |
|  [Add Member]                                                    |
|                                                                  |
|  Group Permissions                                               |
|  +------------------------------------------------------------+  |
|  | repo:api            admin                                  |  |
|  | repo:frontend       write                                  |  |
|  | doc:specs           read                                   |  |
|  +------------------------------------------------------------+  |
|                                                                  |
+------------------------------------------------------------------+
```

---

### Hierarchy

**Purpose:** View and manage permission hierarchies.

**View:**
- Select resource type
- Show permission graph (text-based)
- Add/remove rules

```
+------------------------------------------------------------------+
|  Hierarchy > repo                                                |
+------------------------------------------------------------------+
|                                                                  |
|  Resource Type: [repo v]                                         |
|                                                                  |
|  Permission Chain                                                |
|  +------------------------------------------------------------+  |
|  |                                                            |  |
|  |  owner                                                     |  |
|  |    |                                                       |  |
|  |    +--> admin                                              |  |
|  |           |                                                |  |
|  |           +--> write                                       |  |
|  |           |      |                                         |  |
|  |           |      +--> read                                 |  |
|  |           |                                                |  |
|  |           +--> delete                                      |  |
|  |                                                            |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  Rules                                                           |
|  +------------------------------------------------------------+  |
|  | owner  --> admin                              [Remove]      |  |
|  | admin  --> write                              [Remove]      |  |
|  | admin  --> delete                             [Remove]      |  |
|  | write  --> read                               [Remove]      |  |
|  +------------------------------------------------------------+  |
|  [Add Rule]                                                      |
|                                                                  |
+------------------------------------------------------------------+
```

---

### Audit Log

**Purpose:** Compliance and incident investigation.

**Features:**
- Time range filter
- Actor filter
- Resource filter
- Event type filter
- Export to CSV

```
+------------------------------------------------------------------+
|  Audit Log                                                       |
+------------------------------------------------------------------+
|                                                                  |
|  Filters                                                         |
|  Time: [Last 24 hours v]  Actor: [__________]                    |
|  Resource: [__________]   Type: [All v]       [Search]           |
|                                                                  |
|  Results (1,247)                                        [Export] |
|  +------------------------------------------------------------+  |
|  | Time       | Actor            | Event   | Details          |  |
|  +------------------------------------------------------------+  |
|  | 10:23:01   | admin@acme.com   | GRANTED | repo:api#admin   |  |
|  |            |                  |         | -> team:eng      |  |
|  +------------------------------------------------------------+  |
|  | 10:21:45   | admin@acme.com   | ADDED   | user:alice       |  |
|  |            |                  |         | -> team:eng      |  |
|  +------------------------------------------------------------+  |
|  | 09:45:12   | system           | REVOKED | doc:123#read     |  |
|  |            |                  |         | -> user:bob      |  |
|  +------------------------------------------------------------+  |
|  | ...                                                        |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  [< Prev]  Page 1 of 125  [Next >]                               |
|                                                                  |
+------------------------------------------------------------------+
```

---

### Query Tool

**Purpose:** Interactive permission debugging.

**Features:**
- Check if user has permission
- Show explanation (why allowed/denied)
- Show path through groups and hierarchy

```
+------------------------------------------------------------------+
|  Query Tool                                                      |
+------------------------------------------------------------------+
|                                                                  |
|  Check Permission                                                |
|  +------------------------------------------------------------+  |
|  | User:       [alice_____________]                           |  |
|  | Permission: [read______________]                           |  |
|  | Resource:   [repo__] : [api____]                           |  |
|  |                                                            |  |
|  | [Check]                                                    |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  Result                                                          |
|  +------------------------------------------------------------+  |
|  |                                                            |  |
|  |  ALLOWED                                                   |  |
|  |                                                            |  |
|  |  Explanation:                                              |  |
|  |                                                            |  |
|  |  alice                                                     |  |
|  |    |                                                       |  |
|  |    +--> member of team:engineering                         |  |
|  |           |                                                |  |
|  |           +--> has admin on repo:api                       |  |
|  |                  |                                         |  |
|  |                  +--> admin implies write (hierarchy)      |  |
|  |                         |                                  |  |
|  |                         +--> write implies read (hierarchy)|  |
|  |                                                            |  |
|  +------------------------------------------------------------+  |
|                                                                  |
+------------------------------------------------------------------+
```

---

## User Flows

### Flow 1: Access Review

**Scenario:** Security engineer doing quarterly access review.

```
1. Open Admin UI
2. Select namespace "production"
3. Go to Resources
4. Filter by type "repo"
5. Click into "repo:payments"
6. Review who has admin access
7. Revoke access for contractors who left
8. Go to Audit Log
9. Export last quarter for compliance report
```

### Flow 2: Debug Permission Issue

**Scenario:** Developer investigating "user can't access resource" bug.

```
1. Open Admin UI
2. Go to Query Tool
3. Enter user, permission, resource
4. Click Check
5. See "DENIED"
6. See explanation: user not in any group with access
7. Go to Users > [user]
8. See group memberships
9. Realize user was never added to team
10. Add user to team
11. Re-check in Query Tool: "ALLOWED"
```

### Flow 3: Incident Response

**Scenario:** Ops engineer investigating unexpected access.

```
1. Open Admin UI
2. Go to Audit Log
3. Filter by resource "doc:confidential"
4. Filter time range to last 24 hours
5. See who granted access
6. Click actor to see full activity
7. Identify unauthorized grant
8. Revoke access
9. Export log for incident report
```

---

## Technical Considerations

### Backend

- FastAPI (thin wrapper over authz functions)
- Direct database connection
- Respects RLS (must set tenant context)

### Frontend

- Server-rendered HTML (FastAPI templates)
- HTMX for interactivity (no build step)
- Minimal CSS (Pico or similar classless framework)

### Deployment

- Single Docker image
- docker-compose with postkit and admin UI
- Environment variables for database connection

### Auth

- v1: HTTP Basic Auth (username/password)
- Database connection uses these credentials
- RLS enforces tenant access

---

## Open Questions

1. **Namespace selection:** Dropdown vs URL path (`/admin/production/resources`)?
2. **Pagination:** How many items per page?
3. **Export format:** CSV only, or also JSON?
4. **Bulk operations:** Support bulk revoke in v1?
5. **Read-only mode:** Option to disable write operations?

---

## Milestones

| Milestone | Features | Deliverable |
|-----------|----------|-------------|
| **v0.1** | Dashboard, Query Tool (read-only) | Demo-able prototype |
| **v0.2** | Resources, Users (read-only) | Useful for debugging |
| **v0.3** | Groups, Hierarchy (read-only) | Complete read view |
| **v0.4** | Grant/Revoke actions | Full CRUD |
| **v0.5** | Audit Log with export | Compliance ready |

---

## Success Metrics

1. **Demo success:** Prospect can understand postkit in 5 minutes
2. **Self-service:** Security team can do access review without developer help
3. **Debug time:** Permission issues diagnosed in < 5 minutes
4. **Adoption:** Customers use admin UI instead of raw SQL