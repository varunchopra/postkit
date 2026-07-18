-- @group Maintenance

-- @function authn.cleanup_expired
-- @brief Delete expired sessions, tokens, refresh tokens, API keys, impersonation records, and old login attempts (run via cron)
-- @param p_namespace Namespace to clean up
-- @param p_batch_size Maximum direct rows deleted per call; cascades may delete additional physical rows
-- @returns sessions_deleted, tokens_deleted, refresh_tokens_deleted, api_keys_deleted, impersonations_deleted, attempts_deleted
-- @example -- Add to daily cron job
-- @example SELECT * FROM authn.cleanup_expired('default');
-- @example SELECT * FROM authn.cleanup_expired('default', 5000); -- smaller batches
--
-- Everything this function deletes belongs to p_namespace. Operator
-- impersonation sessions span namespaces and are cleaned by
-- cleanup_expired_operator_sessions, scheduled once per deployment.
-- Cleanup covers eleven independently indexed categories within one shared
-- direct-row budget. Batches below eleven prioritize earlier categories.
-- Concurrent callers cooperate through FOR UPDATE SKIP LOCKED.
CREATE OR REPLACE FUNCTION authn.cleanup_expired(
    p_namespace text DEFAULT 'default',
    p_batch_size int DEFAULT 10000
)
RETURNS TABLE(
    sessions_deleted bigint,
    tokens_deleted bigint,
    refresh_tokens_deleted bigint,
    api_keys_deleted bigint,
    impersonations_deleted bigint,
    attempts_deleted bigint
)
AS $$
DECLARE
    v_sessions_deleted bigint := 0;
    v_tokens_deleted bigint := 0;
    v_refresh_tokens_deleted bigint := 0;
    v_api_keys_deleted bigint := 0;
    v_impersonations_deleted bigint := 0;
    v_attempts_deleted bigint := 0;
    v_batch_deleted bigint;
    v_retention interval;
    v_remaining int;
    v_categories_remaining int := 11;
    v_quota int;
    v_fill_refresh_expired boolean := false;
    v_fill_refresh_inactive boolean := false;
    v_fill_impersonation_ended boolean := false;
    v_fill_impersonation_expired boolean := false;
    v_fill_session_expired boolean := false;
    v_fill_session_revoked boolean := false;
    v_fill_token_expired boolean := false;
    v_fill_token_used boolean := false;
    v_fill_api_key_revoked boolean := false;
    v_fill_api_key_expired boolean := false;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._validate_limit(p_batch_size, 'batch_size', 10000);

    v_retention := authn._login_attempts_retention();
    v_remaining := p_batch_size;

    -- Separate predicates preserve their partial-index paths.
    -- Materialization prevents the limited, locked candidate query from
    -- being rescanned while PostgreSQL executes the delete.
    IF v_remaining > 0 THEN
        v_quota := (v_remaining + v_categories_remaining - 1) / v_categories_remaining;
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.refresh_tokens WHERE namespace = p_namespace
              AND revoked_at IS NULL AND expires_at < now()
            LIMIT v_quota FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.refresh_tokens AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_fill_refresh_expired := v_batch_deleted = v_quota;
        v_refresh_tokens_deleted := v_refresh_tokens_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;
    v_categories_remaining := v_categories_remaining - 1;

    IF v_remaining > 0 THEN
        v_quota := (v_remaining + v_categories_remaining - 1) / v_categories_remaining;
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.refresh_tokens WHERE namespace = p_namespace
              AND (replaced_by IS NOT NULL OR revoked_at IS NOT NULL)
            LIMIT v_quota FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.refresh_tokens AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_fill_refresh_inactive := v_batch_deleted = v_quota;
        v_refresh_tokens_deleted := v_refresh_tokens_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;
    v_categories_remaining := v_categories_remaining - 1;

    IF v_remaining > 0 THEN
        v_quota := (v_remaining + v_categories_remaining - 1) / v_categories_remaining;
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.impersonation_sessions WHERE namespace = p_namespace
              AND ended_at IS NOT NULL
            LIMIT v_quota FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.impersonation_sessions AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_fill_impersonation_ended := v_batch_deleted = v_quota;
        v_impersonations_deleted := v_impersonations_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;
    v_categories_remaining := v_categories_remaining - 1;

    IF v_remaining > 0 THEN
        v_quota := (v_remaining + v_categories_remaining - 1) / v_categories_remaining;
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.impersonation_sessions WHERE namespace = p_namespace
              AND ended_at IS NULL AND expires_at < now()
            LIMIT v_quota FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.impersonation_sessions AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_fill_impersonation_expired := v_batch_deleted = v_quota;
        v_impersonations_deleted := v_impersonations_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;
    v_categories_remaining := v_categories_remaining - 1;

    IF v_remaining > 0 THEN
        v_quota := (v_remaining + v_categories_remaining - 1) / v_categories_remaining;
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.sessions WHERE namespace = p_namespace
              AND revoked_at IS NULL AND expires_at < now()
            LIMIT v_quota FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.sessions AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_fill_session_expired := v_batch_deleted = v_quota;
        v_sessions_deleted := v_sessions_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;
    v_categories_remaining := v_categories_remaining - 1;

    IF v_remaining > 0 THEN
        v_quota := (v_remaining + v_categories_remaining - 1) / v_categories_remaining;
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.sessions WHERE namespace = p_namespace
              AND revoked_at IS NOT NULL
            LIMIT v_quota FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.sessions AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_fill_session_revoked := v_batch_deleted = v_quota;
        v_sessions_deleted := v_sessions_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;
    v_categories_remaining := v_categories_remaining - 1;

    IF v_remaining > 0 THEN
        v_quota := (v_remaining + v_categories_remaining - 1) / v_categories_remaining;
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.tokens WHERE namespace = p_namespace
              AND used_at IS NULL AND expires_at < now()
            LIMIT v_quota FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.tokens AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_fill_token_expired := v_batch_deleted = v_quota;
        v_tokens_deleted := v_tokens_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;
    v_categories_remaining := v_categories_remaining - 1;

    IF v_remaining > 0 THEN
        v_quota := (v_remaining + v_categories_remaining - 1) / v_categories_remaining;
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.tokens WHERE namespace = p_namespace
              AND used_at IS NOT NULL
            LIMIT v_quota FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.tokens AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_fill_token_used := v_batch_deleted = v_quota;
        v_tokens_deleted := v_tokens_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;
    v_categories_remaining := v_categories_remaining - 1;

    IF v_remaining > 0 THEN
        v_quota := (v_remaining + v_categories_remaining - 1) / v_categories_remaining;
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.api_keys WHERE namespace = p_namespace
              AND revoked_at IS NOT NULL
            LIMIT v_quota FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.api_keys AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_fill_api_key_revoked := v_batch_deleted = v_quota;
        v_api_keys_deleted := v_api_keys_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;
    v_categories_remaining := v_categories_remaining - 1;

    IF v_remaining > 0 THEN
        v_quota := (v_remaining + v_categories_remaining - 1) / v_categories_remaining;
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.api_keys WHERE namespace = p_namespace
              AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at < now()
            LIMIT v_quota FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.api_keys AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_fill_api_key_expired := v_batch_deleted = v_quota;
        v_api_keys_deleted := v_api_keys_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;
    v_categories_remaining := v_categories_remaining - 1;

    IF v_remaining > 0 THEN
        v_quota := (v_remaining + v_categories_remaining - 1) / v_categories_remaining;
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.login_attempts WHERE namespace = p_namespace
              AND attempted_at < now() - v_retention
            LIMIT v_quota FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.login_attempts AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_attempts_deleted := v_attempts_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;

    -- Revisit quota-filled categories separately to preserve partial-index paths.
    IF v_remaining > 0 AND v_fill_refresh_expired THEN
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.refresh_tokens WHERE namespace = p_namespace
              AND revoked_at IS NULL AND expires_at < now()
            LIMIT v_remaining FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.refresh_tokens AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_refresh_tokens_deleted := v_refresh_tokens_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;

    IF v_remaining > 0 AND v_fill_refresh_inactive THEN
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.refresh_tokens WHERE namespace = p_namespace
              AND (replaced_by IS NOT NULL OR revoked_at IS NOT NULL)
            LIMIT v_remaining FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.refresh_tokens AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_refresh_tokens_deleted := v_refresh_tokens_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;

    IF v_remaining > 0 AND v_fill_impersonation_ended THEN
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.impersonation_sessions WHERE namespace = p_namespace
              AND ended_at IS NOT NULL
            LIMIT v_remaining FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.impersonation_sessions AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_impersonations_deleted := v_impersonations_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;

    IF v_remaining > 0 AND v_fill_impersonation_expired THEN
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.impersonation_sessions WHERE namespace = p_namespace
              AND ended_at IS NULL AND expires_at < now()
            LIMIT v_remaining FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.impersonation_sessions AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_impersonations_deleted := v_impersonations_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;

    IF v_remaining > 0 AND v_fill_session_expired THEN
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.sessions WHERE namespace = p_namespace
              AND revoked_at IS NULL AND expires_at < now()
            LIMIT v_remaining FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.sessions AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_sessions_deleted := v_sessions_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;

    IF v_remaining > 0 AND v_fill_session_revoked THEN
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.sessions WHERE namespace = p_namespace
              AND revoked_at IS NOT NULL
            LIMIT v_remaining FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.sessions AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_sessions_deleted := v_sessions_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;

    IF v_remaining > 0 AND v_fill_token_expired THEN
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.tokens WHERE namespace = p_namespace
              AND used_at IS NULL AND expires_at < now()
            LIMIT v_remaining FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.tokens AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_tokens_deleted := v_tokens_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;

    IF v_remaining > 0 AND v_fill_token_used THEN
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.tokens WHERE namespace = p_namespace
              AND used_at IS NOT NULL
            LIMIT v_remaining FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.tokens AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_tokens_deleted := v_tokens_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;

    IF v_remaining > 0 AND v_fill_api_key_revoked THEN
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.api_keys WHERE namespace = p_namespace
              AND revoked_at IS NOT NULL
            LIMIT v_remaining FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.api_keys AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_api_keys_deleted := v_api_keys_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;

    IF v_remaining > 0 AND v_fill_api_key_expired THEN
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.api_keys WHERE namespace = p_namespace
              AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at < now()
            LIMIT v_remaining FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.api_keys AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_api_keys_deleted := v_api_keys_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;

    RETURN QUERY SELECT v_sessions_deleted, v_tokens_deleted, v_refresh_tokens_deleted, v_api_keys_deleted, v_impersonations_deleted, v_attempts_deleted;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

-- @function authn.cleanup_expired_operator_sessions
-- @brief Delete ended or expired operator impersonation sessions (run once per deployment via cron)
-- @param p_batch_size Maximum direct rows deleted per call
-- @returns Number of rows deleted
-- @example -- Add to the platform's daily cron job, alongside per-namespace cleanup_expired calls
-- @example SELECT authn.cleanup_expired_operator_sessions();
-- @example -- Grant the maintenance role access before scheduling
-- @example GRANT USAGE ON SCHEMA authn TO maintenance_role;
-- @example GRANT EXECUTE ON FUNCTION authn.cleanup_expired_operator_sessions TO maintenance_role;
--
-- Operator impersonation sessions span namespaces, so their cleanup is a
-- platform duty, not part of any tenant's cleanup_expired call: a tenant
-- job must never do cluster-wide work or need privileges on cross-tenant
-- rows. SECURITY DEFINER for the same reason as the other operator
-- functions (see the security model in 085_operator_impersonation.sql):
-- the table has no RLS, and callers get exactly this delete, not direct
-- access. EXECUTE is revoked from PUBLIC; before scheduling, grant the
-- maintenance role USAGE on schema authn and EXECUTE on this function.
--
-- The two independently indexed categories share one direct-row budget. A
-- batch size of one prioritizes ended sessions. Concurrent callers cooperate
-- through FOR UPDATE SKIP LOCKED.
CREATE OR REPLACE FUNCTION authn.cleanup_expired_operator_sessions(
    p_batch_size int DEFAULT 10000
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, authn
AS $$
DECLARE
    v_deleted bigint := 0;
    v_batch_deleted bigint;
    v_remaining int;
    v_quota int;
    v_fill_ended boolean := false;
BEGIN
    PERFORM authn._validate_limit(p_batch_size, 'batch_size', 10000);
    v_remaining := p_batch_size;

    v_quota := (v_remaining + 1) / 2;
    WITH candidates AS MATERIALIZED (
        SELECT id FROM authn.operator_impersonation_sessions
        WHERE ended_at IS NOT NULL
        LIMIT v_quota FOR UPDATE SKIP LOCKED
    )
    DELETE FROM authn.operator_impersonation_sessions AS target
    USING candidates
    WHERE target.id = candidates.id;
    GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
    v_fill_ended := v_batch_deleted = v_quota;
    v_deleted := v_deleted + v_batch_deleted;
    v_remaining := v_remaining - v_batch_deleted;

    IF v_remaining > 0 THEN
        v_quota := v_remaining;
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.operator_impersonation_sessions
            WHERE ended_at IS NULL AND expires_at < now()
            LIMIT v_quota FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.operator_impersonation_sessions AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_deleted := v_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;

    -- Ended sessions may consume budget unused by expired sessions.
    IF v_remaining > 0 AND v_fill_ended THEN
        WITH candidates AS MATERIALIZED (
            SELECT id FROM authn.operator_impersonation_sessions
            WHERE ended_at IS NOT NULL
            LIMIT v_remaining FOR UPDATE SKIP LOCKED
        )
        DELETE FROM authn.operator_impersonation_sessions AS target
        USING candidates
        WHERE target.id = candidates.id;
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_deleted := v_deleted + v_batch_deleted;
        v_remaining := v_remaining - v_batch_deleted;
    END IF;

    RETURN v_deleted;
END;
$$;

-- Restrict access - grant to the platform's maintenance role only
REVOKE ALL ON FUNCTION authn.cleanup_expired_operator_sessions FROM PUBLIC;

-- @function authn.get_stats
-- @brief Get namespace statistics for monitoring dashboards
-- @returns user_count, verified_user_count, disabled_user_count,
--   active_session_count, active_refresh_token_count, active_api_key_count, credential_enabled_user_count
-- @example SELECT * FROM authn.get_stats('default');
CREATE OR REPLACE FUNCTION authn.get_stats(
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    user_count bigint,
    verified_user_count bigint,
    disabled_user_count bigint,
    active_session_count bigint,
    active_refresh_token_count bigint,
    active_api_key_count bigint,
    credential_enabled_user_count bigint
)
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        u.total_users,
        u.verified_users,
        u.disabled_users,
        s.cnt,
        r.cnt,
        a.cnt,
        c.cnt
    FROM
        (SELECT COUNT(*) AS total_users,
                COUNT(*) FILTER (WHERE email_verified_at IS NOT NULL) AS verified_users,
                COUNT(*) FILTER (WHERE disabled_at IS NOT NULL) AS disabled_users
         FROM authn.users WHERE namespace = p_namespace) u,
        (SELECT COUNT(*) AS cnt FROM authn.sessions
         WHERE namespace = p_namespace AND revoked_at IS NULL AND expires_at > now()) s,
        (SELECT COUNT(*) AS cnt FROM authn.refresh_tokens
         WHERE namespace = p_namespace AND revoked_at IS NULL AND replaced_by IS NULL AND expires_at > now()) r,
        (SELECT COUNT(*) AS cnt FROM authn.api_keys
         WHERE namespace = p_namespace AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())) a,
        (SELECT COUNT(DISTINCT user_id) AS cnt FROM authn.credentials
         WHERE namespace = p_namespace AND disabled_at IS NULL AND consumed_at IS NULL) c;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;
