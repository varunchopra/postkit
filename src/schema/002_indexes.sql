-- =============================================================================
-- INDEXES - Optimized query access patterns
-- =============================================================================
--
-- DESIGN PRINCIPLES
-- -----------------
-- 1. Writes are expensive, reads are cheap (pre-computed permissions)
-- 2. Most queries hit the computed table, not tuples
-- 3. Recompute needs efficient group expansion
--
-- QUERY PATTERNS SUPPORTED
-- ------------------------
-- check():              computed unique constraint (namespace, resource_type, resource_id, permission, user_id)
-- list_resources():     computed_user_access_idx
-- list_users():         computed unique constraint
-- filter_authorized():  computed unique constraint
-- recompute (phase 2):  tuples_membership_expansion_idx
-- cascade detection:    tuples_subject_idx
-- cycle detection:      permission_hierarchy_cycle_idx
--
-- =============================================================================

-- Tuples: uniqueness constraint (enforced via index because COALESCE expression is needed)
-- This ensures no duplicate tuples exist, treating NULL and '' as equivalent for subject_relation
CREATE UNIQUE INDEX tuples_unique_idx ON authz.tuples(
    namespace,
    resource_type,
    resource_id,
    relation,
    subject_type,
    subject_id,
    COALESCE(subject_relation, '')
);

-- Tuples: lookup by resource
CREATE INDEX tuples_resource_idx ON authz.tuples(
    namespace,
    resource_type,
    resource_id
);

-- Tuples: lookup by subject (covering index for cascade queries)
-- INCLUDE clause enables index-only scans when looking up resources
-- where a given subject appears, avoiding heap fetches
CREATE INDEX tuples_subject_idx ON authz.tuples(
    namespace,
    subject_type,
    subject_id
) INCLUDE (resource_type, resource_id);

-- Tuples: optimized for group membership expansion during recompute
-- Covers the join in recompute_resource Phase 2 where we look up all members
-- of a group (e.g., all users with 'member' relation on 'team:engineering')
CREATE INDEX tuples_membership_expansion_idx ON authz.tuples(
    namespace,
    resource_type,
    resource_id,
    relation,
    subject_type
) INCLUDE (subject_id);

-- Computed: optimized for "what can user X access?" queries
-- Note: check() and list_users() use the UNIQUE constraint's index
-- (namespace, resource_type, resource_id, permission, user_id)
CREATE INDEX computed_user_access_idx ON authz.computed(
    namespace,
    user_id,
    resource_type,
    permission,
    resource_id
);

-- Permission hierarchy: lookup during recompute
CREATE INDEX permission_hierarchy_lookup_idx ON authz.permission_hierarchy(
    namespace,
    resource_type,
    permission
);

-- Permission hierarchy: lookup for cycle detection (follows 'implies' edges)
CREATE INDEX permission_hierarchy_cycle_idx ON authz.permission_hierarchy(
    namespace,
    resource_type,
    implies
);

-- Tuples: expiration lookup for cleanup queries (partial index for efficiency)
CREATE INDEX tuples_expires_at_idx ON authz.tuples (namespace, expires_at)
    WHERE expires_at IS NOT NULL;

-- Computed: expiration lookup for cleanup queries (partial index for efficiency)
CREATE INDEX computed_expires_at_idx ON authz.computed (namespace, expires_at)
    WHERE expires_at IS NOT NULL;
