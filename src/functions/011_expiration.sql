-- =============================================================================
-- EXPIRATION MANAGEMENT FUNCTIONS
-- =============================================================================
--
-- These functions manage time-bound permissions:
-- - set_expiration: Set or update expiration on an existing grant
-- - clear_expiration: Remove expiration (make permanent)
-- - cleanup_expired: Remove expired entries for storage optimization
-- - list_expiring: List grants expiring within a time window
--
-- DESIGN NOTES
-- ============
-- Expiration is checked at query time (in check(), list_users(), etc.).
-- cleanup_expired() is optional, for storage management only.
-- NULL expires_at means "never expires" (permanent).

-- =============================================================================
-- SET EXPIRATION
-- =============================================================================
-- Update the expiration on an existing grant and recompute affected permissions.
--
-- USAGE:
--   SELECT authz.set_expiration('repo', 'api', 'admin', 'user', 'alice',
--                                now() + interval '30 days', 'default');
--
-- NOTES:
-- - Returns true if the tuple was found and updated
-- - Triggers recompute to propagate new expiration to computed table
-- - Use NULL to clear expiration (or use clear_expiration() for clarity)

CREATE OR REPLACE FUNCTION authz.set_expiration(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_relation TEXT,
    p_subject_type TEXT,
    p_subject_id TEXT,
    p_expires_at TIMESTAMPTZ,
    p_namespace TEXT DEFAULT 'default'
) RETURNS BOOLEAN AS $$
DECLARE
    v_updated BOOLEAN;
BEGIN
    -- Acquire same lock as write operations to prevent races
    PERFORM pg_advisory_xact_lock(hashtext('authz:write'), hashtext(p_namespace));

    UPDATE authz.tuples
    SET expires_at = p_expires_at
    WHERE namespace = p_namespace
      AND resource_type = p_resource_type
      AND resource_id = p_resource_id
      AND relation = p_relation
      AND subject_type = p_subject_type
      AND subject_id = p_subject_id;

    v_updated := FOUND;

    IF v_updated THEN
        -- Trigger recompute for affected resource
        PERFORM authz.recompute_resource(p_resource_type, p_resource_id, p_namespace);
    END IF;

    RETURN v_updated;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- =============================================================================
-- CLEAR EXPIRATION
-- =============================================================================
-- Remove expiration from a grant (make it permanent).
--
-- USAGE:
--   SELECT authz.clear_expiration('repo', 'api', 'admin', 'user', 'alice', 'default');

CREATE OR REPLACE FUNCTION authz.clear_expiration(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_relation TEXT,
    p_subject_type TEXT,
    p_subject_id TEXT,
    p_namespace TEXT DEFAULT 'default'
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN authz.set_expiration(
        p_resource_type, p_resource_id, p_relation,
        p_subject_type, p_subject_id, NULL, p_namespace
    );
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- =============================================================================
-- CLEANUP EXPIRED
-- =============================================================================
-- Remove expired tuples and computed entries for storage optimization.
-- This is optional - expired entries are filtered at query time regardless.
--
-- USAGE:
--   SELECT * FROM authz.cleanup_expired('default');
--
-- NOTES:
-- - Run periodically via cron for storage management
-- - Audit events are preserved (cleanup only affects tuples/computed)
-- - Returns count of deleted entries

CREATE OR REPLACE FUNCTION authz.cleanup_expired(
    p_namespace TEXT DEFAULT 'default'
) RETURNS TABLE(tuples_deleted BIGINT, computed_deleted BIGINT) AS $$
DECLARE
    v_tuples BIGINT;
    v_computed BIGINT;
BEGIN
    -- Delete from computed first (no triggers, audit not needed)
    DELETE FROM authz.computed
    WHERE namespace = p_namespace
      AND expires_at IS NOT NULL
      AND expires_at < now();
    GET DIAGNOSTICS v_computed = ROW_COUNT;

    -- Delete from tuples (audit trigger will fire if enabled)
    DELETE FROM authz.tuples
    WHERE namespace = p_namespace
      AND expires_at IS NOT NULL
      AND expires_at < now();
    GET DIAGNOSTICS v_tuples = ROW_COUNT;

    RETURN QUERY SELECT v_tuples, v_computed;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- =============================================================================
-- LIST EXPIRING
-- =============================================================================
-- List grants expiring within a time window for review/renewal workflows.
--
-- USAGE:
--   -- List grants expiring in the next 7 days (default)
--   SELECT * FROM authz.list_expiring('7 days', 'default');
--
--   -- List grants expiring in the next month
--   SELECT * FROM authz.list_expiring('30 days', 'default');
--
-- NOTES:
-- - Only returns future expirations (not already expired)
-- - Sorted by expiration time (soonest first)
-- - Use for building renewal reminder systems

CREATE OR REPLACE FUNCTION authz.list_expiring(
    p_within INTERVAL DEFAULT '7 days',
    p_namespace TEXT DEFAULT 'default'
) RETURNS TABLE(
    resource_type TEXT,
    resource_id TEXT,
    relation TEXT,
    subject_type TEXT,
    subject_id TEXT,
    subject_relation TEXT,
    expires_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        t.resource_type,
        t.resource_id,
        t.relation,
        t.subject_type,
        t.subject_id,
        t.subject_relation,
        t.expires_at
    FROM authz.tuples t
    WHERE t.namespace = p_namespace
      AND t.expires_at IS NOT NULL
      AND t.expires_at > now()
      AND t.expires_at <= now() + p_within
    ORDER BY t.expires_at ASC;
END;
$$ LANGUAGE plpgsql STABLE SET search_path = authz, pg_temp;

-- =============================================================================
-- EXTEND EXPIRATION
-- =============================================================================
-- Extend an existing expiration by a given interval.
-- Fails if the grant doesn't exist or has no expiration.
--
-- USAGE:
--   SELECT authz.extend_expiration('repo', 'api', 'admin', 'user', 'alice',
--                                   interval '30 days', 'default');

CREATE OR REPLACE FUNCTION authz.extend_expiration(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_relation TEXT,
    p_subject_type TEXT,
    p_subject_id TEXT,
    p_extension INTERVAL,
    p_namespace TEXT DEFAULT 'default'
) RETURNS TIMESTAMPTZ AS $$
DECLARE
    v_current_expiration TIMESTAMPTZ;
    v_new_expiration TIMESTAMPTZ;
BEGIN
    -- Acquire same lock as write operations to prevent races
    PERFORM pg_advisory_xact_lock(hashtext('authz:write'), hashtext(p_namespace));

    -- Get current expiration
    SELECT expires_at INTO v_current_expiration
    FROM authz.tuples
    WHERE namespace = p_namespace
      AND resource_type = p_resource_type
      AND resource_id = p_resource_id
      AND relation = p_relation
      AND subject_type = p_subject_type
      AND subject_id = p_subject_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Grant not found'
            USING ERRCODE = 'no_data_found';
    END IF;

    IF v_current_expiration IS NULL THEN
        RAISE EXCEPTION 'Grant has no expiration to extend'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Calculate new expiration from current (not from now)
    -- If already expired, extend from now instead
    IF v_current_expiration < now() THEN
        v_new_expiration := now() + p_extension;
    ELSE
        v_new_expiration := v_current_expiration + p_extension;
    END IF;

    PERFORM authz.set_expiration(
        p_resource_type, p_resource_id, p_relation,
        p_subject_type, p_subject_id, v_new_expiration, p_namespace
    );

    RETURN v_new_expiration;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;
