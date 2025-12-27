-- =============================================================================
-- EXPIRATION MANAGEMENT FUNCTIONS
-- =============================================================================
-- These functions manage time-bound permissions.
-- With lazy evaluation, expiration is checked at query time automatically.
-- =============================================================================
-- SET EXPIRATION
-- =============================================================================
CREATE OR REPLACE FUNCTION authz.set_expiration (p_resource_type text, p_resource_id text, p_relation text, p_subject_type text, p_subject_id text, p_expires_at timestamptz, p_namespace text DEFAULT 'default')
    RETURNS boolean
    AS $$
DECLARE
    v_updated int;
BEGIN
    -- Validate expiration is in the future (consistent with write_tuple)
    IF p_expires_at IS NOT NULL AND p_expires_at <= now() THEN
        RAISE EXCEPTION 'expires_at must be in the future'
            USING ERRCODE = 'check_violation';
    END IF;
    UPDATE
        authz.tuples
    SET
        expires_at = p_expires_at
    WHERE
        namespace = p_namespace
        AND resource_type = p_resource_type
        AND resource_id = p_resource_id
        AND relation = p_relation
        AND subject_type = p_subject_type
        AND subject_id = p_subject_id;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated > 0;
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;

-- =============================================================================
-- CLEAR EXPIRATION
-- =============================================================================
CREATE OR REPLACE FUNCTION authz.clear_expiration (p_resource_type text, p_resource_id text, p_relation text, p_subject_type text, p_subject_id text, p_namespace text DEFAULT 'default')
    RETURNS boolean
    AS $$
BEGIN
    RETURN authz.set_expiration (p_resource_type, p_resource_id, p_relation, p_subject_type, p_subject_id, NULL, p_namespace);
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;

-- =============================================================================
-- EXTEND EXPIRATION
-- =============================================================================
CREATE OR REPLACE FUNCTION authz.extend_expiration (p_resource_type text, p_resource_id text, p_relation text, p_subject_type text, p_subject_id text, p_extension interval, p_namespace text DEFAULT 'default')
    RETURNS timestamptz
    AS $$
DECLARE
    v_current_expiration timestamptz;
    v_new_expiration timestamptz;
BEGIN
    SELECT
        expires_at INTO v_current_expiration
    FROM
        authz.tuples
    WHERE
        namespace = p_namespace
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
            -- Extend from current expiration, or from now if already expired
            IF v_current_expiration < now() THEN
                v_new_expiration := now() + p_extension;
            ELSE
                v_new_expiration := v_current_expiration + p_extension;
            END IF;
            PERFORM
                authz.set_expiration (p_resource_type, p_resource_id, p_relation, p_subject_type, p_subject_id, v_new_expiration, p_namespace);
            RETURN v_new_expiration;
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;

-- =============================================================================
-- LIST EXPIRING
-- =============================================================================
CREATE OR REPLACE FUNCTION authz.list_expiring (p_within interval DEFAULT '7 days', p_namespace text DEFAULT 'default')
    RETURNS TABLE (
        resource_type text,
        resource_id text,
        relation text,
        subject_type text,
        subject_id text,
        subject_relation text,
        expires_at timestamptz
    )
    AS $$
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
    FROM
        authz.tuples t
    WHERE
        t.namespace = p_namespace
        AND t.expires_at IS NOT NULL
        AND t.expires_at > now()
        AND t.expires_at <= now() + p_within
    ORDER BY
        t.expires_at ASC;
END;
$$
LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER
SET search_path = authz, pg_temp;

-- =============================================================================
-- CLEANUP EXPIRED
-- =============================================================================
-- Removes expired tuples for storage optimization.
-- With lazy evaluation, this is purely for cleanup - expired tuples are
-- automatically filtered at query time.
CREATE OR REPLACE FUNCTION authz.cleanup_expired (p_namespace text DEFAULT 'default')
    RETURNS TABLE (
        tuples_deleted bigint
    )
    AS $$
DECLARE
    v_tuples bigint;
BEGIN
    DELETE FROM authz.tuples
    WHERE namespace = p_namespace
        AND expires_at IS NOT NULL
        AND expires_at < now();
    GET DIAGNOSTICS v_tuples = ROW_COUNT;
    RETURN QUERY
    SELECT
        v_tuples;
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;
