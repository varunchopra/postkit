-- =============================================================================
-- RECOMPUTE RESOURCE PERMISSIONS
-- =============================================================================
--
-- THE CORE ALGORITHM
-- ==================
-- This function computes all effective permissions for a single resource.
-- It's called automatically by triggers whenever tuples change.
--
-- Three phases:
--   1. DIRECT PERMISSIONS - tuples where subject_type = 'user'
--   2. GROUP EXPANSION    - users inherit permissions via group membership
--   3. HIERARCHY EXPANSION - permissions imply other permissions (admin → read)
--
-- EXAMPLE WALKTHROUGH
-- ===================
-- Given these tuples:
--   (repo, api, admin, team, engineering)    -- team has admin
--   (team, engineering, member, user, alice) -- alice is on team
--
-- And hierarchy rule:
--   (repo, admin, read)                      -- admin implies read
--
-- Phase 1: No direct user permissions on repo:api
-- Phase 2: alice gets 'admin' via team:engineering membership
-- Phase 3: alice gets 'read' because admin implies read
--
-- Result in computed table:
--   (repo, api, admin, alice)
--   (repo, api, read, alice)
--
-- FIXED-POINT ITERATION
-- =====================
-- Phase 3 uses a loop because hierarchies can be multi-level:
--   admin → write → read
--
-- We keep adding implied permissions until no new ones are found.
-- This is called "fixed-point iteration" - we iterate until the result
-- stops changing.

CREATE OR REPLACE FUNCTION authz.recompute_resource(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_namespace TEXT DEFAULT 'default'
) RETURNS INT AS $$
DECLARE
    v_count INT := 0;
    v_rows INT;
    v_iteration INT := 0;
    v_max_iterations CONSTANT INT := 100;  -- Reasonable depth limit for hierarchies
BEGIN
    -- Acquire advisory lock to serialize concurrent recomputes for the same resource.
    -- Note: For normal write operations, the namespace-level lock in write_tuple/delete_tuple
    -- already serializes operations. This lock handles direct recompute_resource() calls
    -- and recompute_all() which may process multiple resources.
    -- The lock is automatically released when the transaction commits/rollbacks.
    PERFORM pg_advisory_xact_lock(
        hashtext(p_namespace || '/' || p_resource_type || '/' || p_resource_id)
    );

    -- Clear existing computed permissions for this resource
    -- We recompute from scratch to ensure consistency
    DELETE FROM authz.computed
    WHERE namespace = p_namespace
      AND resource_type = p_resource_type
      AND resource_id = p_resource_id;

    -- PHASE 1: Direct permissions
    -- Find tuples where a user is directly granted access to this resource
    -- Skip already expired tuples
    INSERT INTO authz.computed (namespace, resource_type, resource_id, permission, user_id, expires_at)
    SELECT DISTINCT
        t.namespace,
        t.resource_type,
        t.resource_id,
        t.relation AS permission,
        t.subject_id AS user_id,
        t.expires_at
    FROM authz.tuples t
    WHERE t.namespace = p_namespace
      AND t.resource_type = p_resource_type
      AND t.resource_id = p_resource_id
      AND t.subject_type = 'user'
      AND t.subject_relation IS NULL
      AND (t.expires_at IS NULL OR t.expires_at > now())
    ON CONFLICT (namespace, resource_type, resource_id, permission, user_id) DO NOTHING;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    -- PHASE 2: Group expansion
    -- Find tuples where a non-user subject (team, org, role) has access,
    -- then find users who are members of that subject
    -- Expiration: use minimum of grant expiration and membership expiration
    INSERT INTO authz.computed (namespace, resource_type, resource_id, permission, user_id, expires_at)
    SELECT DISTINCT
        t.namespace,
        t.resource_type,
        t.resource_id,
        t.relation AS permission,
        membership.subject_id AS user_id,
        authz.min_expiration(t.expires_at, membership.expires_at)
    FROM authz.tuples t
    -- Join to find membership tuples for this group
    JOIN authz.tuples membership
      ON membership.namespace = t.namespace
      AND membership.resource_type = t.subject_type      -- e.g., 'team'
      AND membership.resource_id = t.subject_id          -- e.g., 'engineering'
      AND membership.relation = COALESCE(t.subject_relation, authz.default_membership_relation())
      AND membership.subject_type = 'user'               -- only expand to users
      AND (membership.expires_at IS NULL OR membership.expires_at > now())
    WHERE t.namespace = p_namespace
      AND t.resource_type = p_resource_type
      AND t.resource_id = p_resource_id
      AND t.subject_type != 'user'  -- only for group-like subjects
      AND (t.expires_at IS NULL OR t.expires_at > now())
    ON CONFLICT (namespace, resource_type, resource_id, permission, user_id) DO NOTHING;

    GET DIAGNOSTICS v_rows = ROW_COUNT;
    v_count := v_count + v_rows;

    -- PHASE 3: Hierarchy expansion (fixed-point iteration)
    -- Keep adding implied permissions until no new ones are found
    -- Expiration: inherit from source permission
    --
    -- MVCC SAFETY NOTE:
    -- This loop reads from and writes to authz.computed in each iteration.
    -- PostgreSQL's MVCC ensures each INSERT sees a stable snapshot of the table
    -- as it existed at the start of the statement. The ON CONFLICT DO NOTHING
    -- handles any duplicates. Termination is guaranteed because:
    --   1. Each iteration can only add NEW permissions from hierarchy rules
    --   2. The hierarchy is acyclic (enforced by check_hierarchy_cycle trigger)
    --   3. Maximum iterations = depth of deepest hierarchy chain
    --   4. The v_max_iterations limit is a safety net for unexpected cases
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE EXCEPTION 'Permission hierarchy cycle detected or exceeds maximum depth of %', v_max_iterations;
        END IF;

        INSERT INTO authz.computed (namespace, resource_type, resource_id, permission, user_id, expires_at)
        SELECT DISTINCT
            c.namespace,
            c.resource_type,
            c.resource_id,
            h.implies AS permission,
            c.user_id,
            c.expires_at  -- Inherit expiration from source permission
        FROM authz.computed c
        JOIN authz.permission_hierarchy h
          ON h.namespace = c.namespace
          AND h.resource_type = c.resource_type
          AND h.permission = c.permission
        WHERE c.namespace = p_namespace
          AND c.resource_type = p_resource_type
          AND c.resource_id = p_resource_id
          AND (c.expires_at IS NULL OR c.expires_at > now())
        ON CONFLICT (namespace, resource_type, resource_id, permission, user_id) DO NOTHING;

        GET DIAGNOSTICS v_rows = ROW_COUNT;
        v_count := v_count + v_rows;

        -- Fixed-point reached when no new permissions added
        EXIT WHEN v_rows = 0;
    END LOOP;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- =============================================================================
-- INCREMENTAL UPDATE FUNCTIONS
-- =============================================================================
--
-- PROBLEM
-- =======
-- The full recompute_resource() function is O(G × H) where G = group members
-- and H = hierarchy depth. For a 10,000-member group, adding one user triggers
-- a full recompute that touches all 10,000 members - even though only one
-- user's permissions changed.
--
-- SOLUTION
-- ========
-- These incremental functions handle specific operation types efficiently:
--
--   | Operation              | Full Recompute | Incremental        |
--   |------------------------|----------------|---------------------|
--   | Add user to group      | O(G × H)       | O(R × H)           |
--   | Remove user from group | O(G × H)       | O(R × H) + verify  |
--   | Direct grant to user   | O(G × H)       | O(H)               |
--   | Direct revoke          | O(G × H)       | O(H) + verify      |
--   | Grant to group         | O(G × H)       | O(G × H) (same)    |
--   | Revoke from group      | O(G × H)       | O(G × H) + verify  |
--
-- Where: G = group size, H = hierarchy depth, R = resources group can access
--
-- For single-user operations (add/remove from group, direct grant/revoke),
-- the improvement is dramatic: O(1) vs O(G) in the group size dimension.
--
-- REMOVAL COMPLEXITY
-- ==================
-- Removals are trickier than additions because a user might have access
-- through multiple paths:
--
--   Alice is in team:eng AND team:platform
--   Both teams have read on doc:1
--   Removing Alice from team:eng should NOT remove her read on doc:1
--
-- So before deleting a computed entry, we must verify no alternate path exists.
-- This is done by user_has_alternate_path() which checks:
--   1. Direct grants on the resource
--   2. Access via other groups (excluding the one being removed)
--
-- TRIGGER ROUTING
-- ===============
-- The trigger (001_recompute_trigger.sql) detects the operation type:
--   - Single tuple with subject_type='user' and relation='member' → add/remove user from group
--   - Single tuple with subject_type='user' and relation!='member' → direct grant/revoke
--   - Single tuple with subject_type!='user' → grant/revoke to group
--   - Multiple tuples → fall back to full recompute (batch operations)
--
-- CASCADE HANDLING
-- ================
-- When a user joins a group, they need permissions on all resources where
-- that group is a subject. This IS handled by incremental_add_user_to_group.
--
-- Example: alice joins team:eng, and team:eng has admin on repo:api
--   → incremental_add_user_to_group finds (repo, api, admin, team, eng)
--   → adds alice's permissions on repo:api
--
-- NOTE: Nested groups and resource hierarchies are NOT supported (per README).
-- These functions assume single-level groups only.

-- -----------------------------------------------------------------------------
-- expand_hierarchy_for_user: Apply permission hierarchy for one user
-- -----------------------------------------------------------------------------
-- Given a user who already has some base permission on a resource, expand
-- the hierarchy to add implied permissions.
--
-- Example: If alice has 'admin' on repo:api, and admin→write→read,
-- this adds 'write' and 'read' for alice on repo:api.
--
-- Uses fixed-point iteration: keeps adding implied permissions until
-- no new ones are found. Safe because hierarchy is acyclic (enforced
-- by check_hierarchy_cycle trigger).
CREATE OR REPLACE FUNCTION authz.expand_hierarchy_for_user(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_user_id TEXT,
    p_namespace TEXT DEFAULT 'default'
) RETURNS INT AS $$
DECLARE
    v_count INT := 0;
    v_rows INT;
    v_iteration INT := 0;
    v_max_iterations CONSTANT INT := 100;
BEGIN
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE EXCEPTION 'Permission hierarchy exceeds maximum depth of %', v_max_iterations;
        END IF;

        INSERT INTO authz.computed (namespace, resource_type, resource_id, permission, user_id, expires_at)
        SELECT DISTINCT
            c.namespace,
            c.resource_type,
            c.resource_id,
            h.implies AS permission,
            c.user_id,
            c.expires_at  -- Inherit expiration from source permission
        FROM authz.computed c
        JOIN authz.permission_hierarchy h
          ON h.namespace = c.namespace
          AND h.resource_type = c.resource_type
          AND h.permission = c.permission
        WHERE c.namespace = p_namespace
          AND c.resource_type = p_resource_type
          AND c.resource_id = p_resource_id
          AND c.user_id = p_user_id
          AND (c.expires_at IS NULL OR c.expires_at > now())
        ON CONFLICT (namespace, resource_type, resource_id, permission, user_id) DO NOTHING;

        GET DIAGNOSTICS v_rows = ROW_COUNT;
        v_count := v_count + v_rows;

        EXIT WHEN v_rows = 0;
    END LOOP;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- -----------------------------------------------------------------------------
-- user_has_alternate_path: Check if user can access resource another way
-- -----------------------------------------------------------------------------
-- CRITICAL for safe removals. Before deleting a computed entry, we must verify
-- the user doesn't have access through another path.
--
-- Example: Alice is in team:eng AND team:platform. Both have read on doc:1.
-- If we remove Alice from team:eng, we must NOT delete her read on doc:1
-- because she still has it via team:platform.
--
-- Checks two types of alternate paths:
--   1. DIRECT GRANTS: User has this permission (or one that implies it) directly
--   2. OTHER GROUPS: User is member of another group that has this permission
--
-- The p_exclude_* parameters let us exclude the specific group#relation we're
-- removing from when checking for alternate paths. This is important because a
-- user can have MULTIPLE relations on the same group (e.g., both member AND admin).
--
-- Example: Alice is member AND admin of team:eng.
--   team:eng#member has read on doc:1
--   team:eng#admin has write on doc:1 (write→read hierarchy)
--   When removing Alice's member relation, we exclude only team:eng#member,
--   NOT team:eng#admin. Alice still has read via admin→write→read.
--
-- NOTE: The NULL check uses IS NULL pattern to handle SQL's three-valued logic.
CREATE OR REPLACE FUNCTION authz.user_has_alternate_path(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_permission TEXT,
    p_user_id TEXT,
    p_namespace TEXT,
    p_exclude_group_type TEXT DEFAULT NULL,
    p_exclude_group_id TEXT DEFAULT NULL,
    p_exclude_subject_relation TEXT DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_exclude_relation TEXT;
BEGIN
    -- Normalize the exclude relation (NULL means default membership)
    v_exclude_relation := COALESCE(p_exclude_subject_relation, authz.default_membership_relation());

    -- Use recursive CTE to find all permissions that imply the target permission.
    -- This handles chained hierarchies like admin → write → read.
    -- If checking for 'read', we find {read, write, admin} as valid source permissions.
    RETURN EXISTS (
        WITH RECURSIVE implies_target AS (
            -- Base: the permission itself
            SELECT p_permission AS permission

            UNION

            -- Recursive: permissions that imply something we already have
            SELECT h.permission
            FROM implies_target it
            JOIN authz.permission_hierarchy h
              ON h.namespace = p_namespace
              AND h.resource_type = p_resource_type
              AND h.implies = it.permission
        ),
        valid_permissions AS (
            SELECT permission FROM implies_target
        )
        -- Direct grant of a valid permission?
        SELECT 1 FROM authz.tuples t
        JOIN valid_permissions vp ON vp.permission = t.relation
        WHERE t.namespace = p_namespace
          AND t.resource_type = p_resource_type
          AND t.resource_id = p_resource_id
          AND t.subject_type = 'user'
          AND t.subject_id = p_user_id

        UNION ALL

        -- Access via another group with a valid permission?
        SELECT 1 FROM authz.tuples t
        JOIN valid_permissions vp ON vp.permission = t.relation
        JOIN authz.tuples membership
          ON membership.namespace = t.namespace
          AND membership.resource_type = t.subject_type
          AND membership.resource_id = t.subject_id
          AND membership.relation = COALESCE(t.subject_relation, authz.default_membership_relation())
          AND membership.subject_type = 'user'
          AND membership.subject_id = p_user_id
        WHERE t.namespace = p_namespace
          AND t.resource_type = p_resource_type
          AND t.resource_id = p_resource_id
          AND t.subject_type != 'user'
          -- Exclude only the specific group#relation we're removing from
          -- (user may have other relations on the same group)
          AND (p_exclude_group_type IS NULL
               OR NOT (t.subject_type = p_exclude_group_type
                       AND t.subject_id = p_exclude_group_id
                       AND COALESCE(t.subject_relation, authz.default_membership_relation()) = v_exclude_relation))
    );
END;
$$ LANGUAGE plpgsql STABLE SET search_path = authz, pg_temp;

-- -----------------------------------------------------------------------------
-- incremental_add_user_to_group: User joins a group with a specific relation
-- -----------------------------------------------------------------------------
-- When a user joins a group (with any relation), they inherit permissions
-- from tuples that reference that group#relation.
--
-- OPTIMIZATION: Uses bulk INSERT instead of per-resource loops.
-- Previous implementation called expand_hierarchy_for_user inside a FOR LOOP.
-- This version does one bulk INSERT for base permissions, then one batch
-- hierarchy expansion across all resources.
--
-- Algorithm:
--   1. Add the relation entry (alice:member on team:eng) to computed
--   2. Bulk INSERT base permissions for ALL resources this group#relation accesses
--   3. Batch hierarchy expansion for this user across ALL their resources
--
-- Example: Alice joins team:eng as member. team:eng#member has read on 100 repos.
--   → Insert (team, eng, member, alice) to computed
--   → Bulk insert read permission for all 100 repos
--   → Batch expand hierarchy for alice across all resources
CREATE OR REPLACE FUNCTION authz.incremental_add_user_to_group(
    p_group_type TEXT,
    p_group_id TEXT,
    p_user_id TEXT,
    p_namespace TEXT DEFAULT 'default',
    p_relation TEXT DEFAULT NULL  -- NULL means use default membership relation
) RETURNS INT AS $$
DECLARE
    v_count INT := 0;
    v_rows INT;
    v_relation TEXT;
    v_iteration INT := 0;
    v_max_iterations CONSTANT INT := 100;
    v_membership_expires TIMESTAMPTZ;
BEGIN
    v_relation := COALESCE(p_relation, authz.default_membership_relation());

    -- Get the membership expiration from the tuple that triggered this
    SELECT expires_at INTO v_membership_expires
    FROM authz.tuples
    WHERE namespace = p_namespace
      AND resource_type = p_group_type
      AND resource_id = p_group_id
      AND relation = v_relation
      AND subject_type = 'user'
      AND subject_id = p_user_id;

    -- Add the relation itself to computed (with membership expiration)
    INSERT INTO authz.computed (namespace, resource_type, resource_id, permission, user_id, expires_at)
    VALUES (p_namespace, p_group_type, p_group_id, v_relation, p_user_id, v_membership_expires)
    ON CONFLICT (namespace, resource_type, resource_id, permission, user_id) DO NOTHING;

    GET DIAGNOSTICS v_rows = ROW_COUNT;
    v_count := v_count + v_rows;

    -- BULK INSERT: Add base permissions for ALL resources this group#relation can access
    -- Expiration: minimum of grant expiration and membership expiration
    INSERT INTO authz.computed (namespace, resource_type, resource_id, permission, user_id, expires_at)
    SELECT DISTINCT
        t.namespace,
        t.resource_type,
        t.resource_id,
        t.relation,
        p_user_id,
        authz.min_expiration(t.expires_at, v_membership_expires)
    FROM authz.tuples t
    WHERE t.namespace = p_namespace
      AND t.subject_type = p_group_type
      AND t.subject_id = p_group_id
      AND COALESCE(t.subject_relation, authz.default_membership_relation()) = v_relation
      AND (t.expires_at IS NULL OR t.expires_at > now())
    ON CONFLICT (namespace, resource_type, resource_id, permission, user_id) DO NOTHING;

    GET DIAGNOSTICS v_rows = ROW_COUNT;
    v_count := v_count + v_rows;

    -- BATCH HIERARCHY EXPANSION: Expand for this user across ALL their resources at once
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE EXCEPTION 'Permission hierarchy exceeds maximum depth of %', v_max_iterations;
        END IF;

        INSERT INTO authz.computed (namespace, resource_type, resource_id, permission, user_id, expires_at)
        SELECT DISTINCT
            c.namespace,
            c.resource_type,
            c.resource_id,
            h.implies AS permission,
            c.user_id,
            c.expires_at  -- Inherit expiration from source permission
        FROM authz.computed c
        JOIN authz.permission_hierarchy h
          ON h.namespace = c.namespace
          AND h.resource_type = c.resource_type
          AND h.permission = c.permission
        WHERE c.namespace = p_namespace
          AND c.user_id = p_user_id
          AND (c.expires_at IS NULL OR c.expires_at > now())
        ON CONFLICT (namespace, resource_type, resource_id, permission, user_id) DO NOTHING;

        GET DIAGNOSTICS v_rows = ROW_COUNT;
        v_count := v_count + v_rows;

        EXIT WHEN v_rows = 0;
    END LOOP;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- -----------------------------------------------------------------------------
-- incremental_remove_user_from_group: User leaves a group (any relation)
-- -----------------------------------------------------------------------------
-- When a user's relation to a group is removed, we must carefully remove only
-- permissions that came exclusively from that group#relation.
--
-- CRITICAL: A user might have the same permission via multiple paths:
--   - Direct grant on the resource
--   - Same relation in another group with the same permission
--   - Different relation in the same or another group
--
-- Algorithm:
--   1. Remove the relation entry from computed
--   2. For each resource the group#relation had access to:
--      - Check if user has alternate path (direct or other group)
--      - Only delete computed entry if NO alternate path exists
--
-- Example: Alice is in team:eng AND team:platform. Both have read on doc:1.
--   Removing Alice from team:eng:
--   → Delete (team, eng, member, alice) from computed
--   → Check doc:1 - alice has alternate path via team:platform, so DON'T delete
--   → Result: alice still has read on doc:1 (correct!)
CREATE OR REPLACE FUNCTION authz.incremental_remove_user_from_group(
    p_group_type TEXT,
    p_group_id TEXT,
    p_user_id TEXT,
    p_namespace TEXT DEFAULT 'default',
    p_relation TEXT DEFAULT NULL  -- NULL means use default membership relation
) RETURNS INT AS $$
DECLARE
    v_count INT := 0;
    v_rows INT;
    v_relation TEXT;
BEGIN
    -- Use default membership relation if not specified
    v_relation := COALESCE(p_relation, authz.default_membership_relation());

    -- Remove the relation entry from computed ONLY if no alternate path exists
    -- E.g., if revoking (doc, 1, read, user, alice), check if alice has read
    -- on doc:1 via a group before removing.
    DELETE FROM authz.computed
    WHERE namespace = p_namespace
      AND resource_type = p_group_type
      AND resource_id = p_group_id
      AND permission = v_relation
      AND user_id = p_user_id
      AND NOT authz.user_has_alternate_path(
          p_group_type, p_group_id, v_relation, p_user_id, p_namespace,
          NULL, NULL  -- No group to exclude for direct grants
      );

    GET DIAGNOSTICS v_rows = ROW_COUNT;
    v_count := v_count + v_rows;

    -- Also remove any hierarchy-implied permissions on this resource that
    -- no longer have an alternate path
    DELETE FROM authz.computed c
    WHERE c.namespace = p_namespace
      AND c.resource_type = p_group_type
      AND c.resource_id = p_group_id
      AND c.user_id = p_user_id
      AND c.permission != v_relation  -- Already handled above
      AND NOT authz.user_has_alternate_path(
          c.resource_type, c.resource_id, c.permission, p_user_id, p_namespace,
          NULL, NULL
      );

    GET DIAGNOSTICS v_rows = ROW_COUNT;
    v_count := v_count + v_rows;

    -- Delete computed entries for this user on resources where:
    -- 1. The group#relation had access
    -- 2. User has no alternate path (direct or via another group)
    WITH group_resources AS (
        -- Resources this group#relation has access to
        -- Only include tuples where subject_relation matches our relation
        SELECT DISTINCT t.resource_type, t.resource_id, t.relation
        FROM authz.tuples t
        WHERE t.namespace = p_namespace
          AND t.subject_type = p_group_type
          AND t.subject_id = p_group_id
          AND COALESCE(t.subject_relation, authz.default_membership_relation()) = v_relation
    ),
    to_remove AS (
        -- Computed entries that might need removal
        SELECT c.id, c.resource_type, c.resource_id, c.permission
        FROM authz.computed c
        JOIN group_resources gr
          ON gr.resource_type = c.resource_type
          AND gr.resource_id = c.resource_id
        WHERE c.namespace = p_namespace
          AND c.user_id = p_user_id
          -- Only remove if no alternate path exists
          -- Pass v_relation so we only exclude this specific group#relation,
          -- not other relations user might have on the same group
          AND NOT authz.user_has_alternate_path(
              c.resource_type, c.resource_id, c.permission, p_user_id, p_namespace,
              p_group_type, p_group_id, v_relation
          )
    )
    DELETE FROM authz.computed
    WHERE id IN (SELECT id FROM to_remove);

    GET DIAGNOSTICS v_rows = ROW_COUNT;
    v_count := v_count + v_rows;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- -----------------------------------------------------------------------------
-- incremental_add_direct_grant: Grant permission directly to a user
-- -----------------------------------------------------------------------------
-- Simplest case: grant a permission directly to a user (no group involved).
-- This is O(H) where H = hierarchy depth.
--
-- Algorithm:
--   1. Insert the base permission into computed
--   2. Expand hierarchy (e.g., admin → write → read)
--
-- Example: Grant alice admin on repo:api
--   → Insert (repo, api, admin, alice) to computed
--   → Expand: add write and read for alice on repo:api
CREATE OR REPLACE FUNCTION authz.incremental_add_direct_grant(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_permission TEXT,
    p_user_id TEXT,
    p_namespace TEXT DEFAULT 'default'
) RETURNS INT AS $$
DECLARE
    v_count INT := 0;
    v_expires_at TIMESTAMPTZ;
BEGIN
    -- Get the expiration from the tuple that triggered this
    SELECT expires_at INTO v_expires_at
    FROM authz.tuples
    WHERE namespace = p_namespace
      AND resource_type = p_resource_type
      AND resource_id = p_resource_id
      AND relation = p_permission
      AND subject_type = 'user'
      AND subject_id = p_user_id;

    -- Insert base permission with expiration
    INSERT INTO authz.computed (namespace, resource_type, resource_id, permission, user_id, expires_at)
    VALUES (p_namespace, p_resource_type, p_resource_id, p_permission, p_user_id, v_expires_at)
    ON CONFLICT (namespace, resource_type, resource_id, permission, user_id) DO NOTHING;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    -- Expand hierarchy (inherits expiration via expand_hierarchy_for_user)
    v_count := v_count + authz.expand_hierarchy_for_user(
        p_resource_type, p_resource_id, p_user_id, p_namespace
    );

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- -----------------------------------------------------------------------------
-- incremental_remove_direct_grant: Revoke direct permission from user
-- -----------------------------------------------------------------------------
-- When revoking a direct grant, we must check if the user has the same
-- permission through another path (e.g., group membership).
--
-- Algorithm:
--   1. For each computed entry for this user on this resource:
--      - Check if user has alternate path (via group membership)
--      - Only delete if NO alternate path exists
--
-- Example: Alice has direct admin on repo:api AND is in team:eng which has admin.
--   Revoking direct admin:
--   → Check if alice has alternate path (yes, via team:eng)
--   → DON'T delete the computed entry
--   → Result: alice still has admin on repo:api (correct!)
CREATE OR REPLACE FUNCTION authz.incremental_remove_direct_grant(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_permission TEXT,
    p_user_id TEXT,
    p_namespace TEXT DEFAULT 'default'
) RETURNS INT AS $$
DECLARE
    v_count INT := 0;
BEGIN
    -- Delete if no alternate path
    DELETE FROM authz.computed c
    WHERE c.namespace = p_namespace
      AND c.resource_type = p_resource_type
      AND c.resource_id = p_resource_id
      AND c.user_id = p_user_id
      AND NOT authz.user_has_alternate_path(
          c.resource_type, c.resource_id, c.permission, p_user_id, p_namespace,
          NULL, NULL
      );

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- -----------------------------------------------------------------------------
-- incremental_add_group_grant: Grant permission to a group
-- -----------------------------------------------------------------------------
-- When a group gets a new permission on a resource, all members of that group
-- should get the permission. This is O(G × H) where G = group size.
--
-- OPTIMIZATION: Uses bulk INSERT instead of per-user loops.
-- Previous implementation did 1000 function calls for 1000 users, each doing
-- individual INSERTs. This version does one bulk INSERT for the base permission,
-- then bulk hierarchy expansion.
--
-- Algorithm:
--   1. Bulk INSERT base permission for ALL group members at once
--   2. Bulk expand hierarchy (fixed-point iteration on all users)
--
-- Example: Grant team:eng admin on repo:api. team:eng has alice and bob.
--   → Bulk insert: (repo, api, admin, alice), (repo, api, admin, bob)
--   → Hierarchy iteration 1: add write for both
--   → Hierarchy iteration 2: add read for both
CREATE OR REPLACE FUNCTION authz.incremental_add_group_grant(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_permission TEXT,
    p_group_type TEXT,
    p_group_id TEXT,
    p_subject_relation TEXT DEFAULT NULL,
    p_namespace TEXT DEFAULT 'default'
) RETURNS INT AS $$
DECLARE
    v_count INT := 0;
    v_rows INT;
    v_iteration INT := 0;
    v_max_iterations CONSTANT INT := 100;
    v_grant_expires TIMESTAMPTZ;
BEGIN
    -- Get the grant expiration from the tuple that triggered this
    SELECT expires_at INTO v_grant_expires
    FROM authz.tuples
    WHERE namespace = p_namespace
      AND resource_type = p_resource_type
      AND resource_id = p_resource_id
      AND relation = p_permission
      AND subject_type = p_group_type
      AND subject_id = p_group_id
      AND COALESCE(subject_relation, '') = COALESCE(p_subject_relation, '');

    -- PHASE 1: Bulk insert base permission for ALL group members at once
    -- Expiration: minimum of grant expiration and membership expiration
    INSERT INTO authz.computed (namespace, resource_type, resource_id, permission, user_id, expires_at)
    SELECT DISTINCT
        p_namespace,
        p_resource_type,
        p_resource_id,
        p_permission,
        m.subject_id,
        authz.min_expiration(v_grant_expires, m.expires_at)
    FROM authz.tuples m
    WHERE m.namespace = p_namespace
      AND m.resource_type = p_group_type
      AND m.resource_id = p_group_id
      AND m.relation = COALESCE(p_subject_relation, authz.default_membership_relation())
      AND m.subject_type = 'user'
      AND (m.expires_at IS NULL OR m.expires_at > now())
    ON CONFLICT (namespace, resource_type, resource_id, permission, user_id) DO NOTHING;

    GET DIAGNOSTICS v_rows = ROW_COUNT;
    v_count := v_count + v_rows;

    -- PHASE 2: Bulk hierarchy expansion for this resource
    -- Fixed-point iteration: keep adding implied permissions until no new ones found
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE EXCEPTION 'Permission hierarchy exceeds maximum depth of %', v_max_iterations;
        END IF;

        INSERT INTO authz.computed (namespace, resource_type, resource_id, permission, user_id, expires_at)
        SELECT DISTINCT
            c.namespace,
            c.resource_type,
            c.resource_id,
            h.implies AS permission,
            c.user_id,
            c.expires_at  -- Inherit expiration from source permission
        FROM authz.computed c
        JOIN authz.permission_hierarchy h
          ON h.namespace = c.namespace
          AND h.resource_type = c.resource_type
          AND h.permission = c.permission
        WHERE c.namespace = p_namespace
          AND c.resource_type = p_resource_type
          AND c.resource_id = p_resource_id
          AND (c.expires_at IS NULL OR c.expires_at > now())
        ON CONFLICT (namespace, resource_type, resource_id, permission, user_id) DO NOTHING;

        GET DIAGNOSTICS v_rows = ROW_COUNT;
        v_count := v_count + v_rows;

        -- Fixed-point reached when no new permissions added
        EXIT WHEN v_rows = 0;
    END LOOP;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- -----------------------------------------------------------------------------
-- incremental_remove_group_grant: Revoke permission from a group
-- -----------------------------------------------------------------------------
-- When revoking a group's permission on a resource, we must check each member
-- individually because they might have alternate access paths.
--
-- CRITICAL: Each member might have the permission through:
--   - Direct grant on the resource
--   - Membership in another group with the same permission
--
-- Algorithm:
--   1. Find all members of the group with the matching relation
--   2. For each member: check for alternate paths, delete only if none
--
-- Example: Revoke team:eng#admin write on repo:api.
--   Charlie is team:eng#admin, alice is team:eng#member.
--   → Only charlie is affected (he had write via team:eng#admin)
--   → Alice is NOT affected (she wasn't getting write via this grant)
CREATE OR REPLACE FUNCTION authz.incremental_remove_group_grant(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_permission TEXT,
    p_group_type TEXT,
    p_group_id TEXT,
    p_subject_relation TEXT DEFAULT NULL,
    p_namespace TEXT DEFAULT 'default'
) RETURNS INT AS $$
DECLARE
    v_count INT := 0;
    v_deleted INT;
BEGIN
    -- For each member with matching relation, remove computed entries if no alternate path
    WITH group_members AS (
        SELECT DISTINCT m.subject_id AS user_id
        FROM authz.tuples m
        WHERE m.namespace = p_namespace
          AND m.resource_type = p_group_type
          AND m.resource_id = p_group_id
          AND m.relation = COALESCE(p_subject_relation, authz.default_membership_relation())
          AND m.subject_type = 'user'
    ),
    to_remove AS (
        SELECT c.id
        FROM authz.computed c
        JOIN group_members gm ON gm.user_id = c.user_id
        WHERE c.namespace = p_namespace
          AND c.resource_type = p_resource_type
          AND c.resource_id = p_resource_id
          -- Pass p_subject_relation so we only exclude this specific group#relation,
          -- not other relations users might have on the same group
          AND NOT authz.user_has_alternate_path(
              c.resource_type, c.resource_id, c.permission, c.user_id, p_namespace,
              p_group_type, p_group_id, p_subject_relation
          )
    )
    DELETE FROM authz.computed
    WHERE id IN (SELECT id FROM to_remove);

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- =============================================================================
-- BULK RECOMPUTE
-- =============================================================================
-- Optimized full recompute for a namespace using:
-- 1. Drop secondary index (fast inserts)
-- 2. Single recursive CTE (compute all permissions at once)
-- 3. Recreate index
--
-- This is ~4x faster than per-resource recompute for large datasets.
-- Use for: initial loads, bulk grants, repair operations.

CREATE OR REPLACE FUNCTION authz.recompute_namespace_bulk(
    p_namespace TEXT DEFAULT 'default'
) RETURNS INT AS $$
DECLARE
    v_count INT;
BEGIN
    -- Serialize writes for this namespace
    PERFORM pg_advisory_xact_lock(hashtext('authz:write'), hashtext(p_namespace));

    -- Drop secondary index for faster inserts
    DROP INDEX IF EXISTS authz.computed_user_access_idx;

    -- Clear existing computed entries
    DELETE FROM authz.computed WHERE namespace = p_namespace;

    -- Compute ALL permissions in one recursive CTE:
    -- 1. Base: direct user grants + group-expanded grants (with expiration)
    -- 2. Recursive: hierarchy expansion (inherits expiration)
    WITH RECURSIVE
    base_perms AS (
        -- Direct user permissions
        SELECT DISTINCT
            t.namespace, t.resource_type, t.resource_id,
            t.relation AS permission, t.subject_id AS user_id,
            t.expires_at
        FROM authz.tuples t
        WHERE t.namespace = p_namespace
          AND t.subject_type = 'user'
          AND t.subject_relation IS NULL
          AND (t.expires_at IS NULL OR t.expires_at > now())

        UNION

        -- Group-expanded permissions (expiration = min of grant and membership)
        SELECT DISTINCT
            t.namespace, t.resource_type, t.resource_id,
            t.relation AS permission, m.subject_id AS user_id,
            authz.min_expiration(t.expires_at, m.expires_at)
        FROM authz.tuples t
        JOIN authz.tuples m
          ON m.namespace = t.namespace
          AND m.resource_type = t.subject_type
          AND m.resource_id = t.subject_id
          AND m.relation = COALESCE(t.subject_relation, authz.default_membership_relation())
          AND m.subject_type = 'user'
          AND (m.expires_at IS NULL OR m.expires_at > now())
        WHERE t.namespace = p_namespace
          AND t.subject_type != 'user'
          AND (t.expires_at IS NULL OR t.expires_at > now())
    ),
    all_perms AS (
        SELECT * FROM base_perms

        UNION

        -- Hierarchy expansion (inherits expiration from source)
        SELECT e.namespace, e.resource_type, e.resource_id, h.implies AS permission, e.user_id, e.expires_at
        FROM all_perms e
        JOIN authz.permission_hierarchy h
          ON h.namespace = e.namespace
          AND h.resource_type = e.resource_type
          AND h.permission = e.permission
        WHERE e.expires_at IS NULL OR e.expires_at > now()
    )
    INSERT INTO authz.computed (namespace, resource_type, resource_id, permission, user_id, expires_at)
    SELECT DISTINCT namespace, resource_type, resource_id, permission, user_id, expires_at FROM all_perms;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    -- Recreate index
    CREATE INDEX computed_user_access_idx
    ON authz.computed(namespace, user_id, resource_type, permission, resource_id);

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- -----------------------------------------------------------------------------
-- grant_to_resources_bulk: Grant permission to many resources at once
-- -----------------------------------------------------------------------------
-- Optimized for bulk operations: disables triggers, inserts all tuples,
-- then does one bulk recompute.

CREATE OR REPLACE FUNCTION authz.grant_to_resources_bulk(
    p_resource_type TEXT,
    p_resource_ids TEXT[],
    p_relation TEXT,
    p_subject_type TEXT,
    p_subject_id TEXT,
    p_subject_relation TEXT DEFAULT NULL,
    p_namespace TEXT DEFAULT 'default'
) RETURNS INT AS $$
DECLARE
    v_tuple_count INT;
BEGIN
    -- Validate inputs
    PERFORM pg_advisory_xact_lock(hashtext('authz:write'), hashtext(p_namespace));
    PERFORM authz.validate_namespace(p_namespace);
    PERFORM authz.validate_identifier(p_resource_type, 'resource_type');
    PERFORM authz.validate_identifier(p_relation, 'relation');
    PERFORM authz.validate_identifier(p_subject_type, 'subject_type');
    PERFORM authz.validate_id(p_subject_id, 'subject_id');
    IF p_subject_relation IS NOT NULL THEN
        PERFORM authz.validate_identifier(p_subject_relation, 'subject_relation');
    END IF;

    -- Disable trigger for bulk insert
    ALTER TABLE authz.tuples DISABLE TRIGGER recompute_on_tuple_insert;

    BEGIN
        -- Bulk insert all tuples
        INSERT INTO authz.tuples (namespace, resource_type, resource_id, relation, subject_type, subject_id, subject_relation)
        SELECT p_namespace, p_resource_type, unnest(p_resource_ids), p_relation, p_subject_type, p_subject_id, p_subject_relation
        ON CONFLICT (namespace, resource_type, resource_id, relation, subject_type, subject_id, COALESCE(subject_relation, '')) DO NOTHING;

        GET DIAGNOSTICS v_tuple_count = ROW_COUNT;

        -- Re-enable trigger
        ALTER TABLE authz.tuples ENABLE TRIGGER recompute_on_tuple_insert;

        -- Single bulk recompute
        PERFORM authz.recompute_namespace_bulk(p_namespace);
    EXCEPTION WHEN OTHERS THEN
        -- Ensure trigger is re-enabled on error
        ALTER TABLE authz.tuples ENABLE TRIGGER recompute_on_tuple_insert;
        RAISE;
    END;

    RETURN v_tuple_count;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- =============================================================================
-- FULL RECOMPUTE (uses bulk implementation)
-- =============================================================================

CREATE OR REPLACE FUNCTION authz.recompute_all(
    p_namespace TEXT DEFAULT 'default'
) RETURNS INT AS $$
BEGIN
    RETURN authz.recompute_namespace_bulk(p_namespace);
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;
