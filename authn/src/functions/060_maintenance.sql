-- @group Maintenance

-- @function authn.cleanup_expired
-- @brief Delete expired sessions, tokens, refresh tokens, API keys, impersonation records, and old login attempts (run via cron)
-- @param p_namespace Namespace to clean up
-- @param p_batch_size Max rows to delete per table per iteration (default 10000, prevents long locks)
-- @returns sessions_deleted, tokens_deleted, refresh_tokens_deleted, api_keys_deleted, impersonations_deleted, attempts_deleted
-- @example -- Add to daily cron job
-- @example SELECT * FROM authn.cleanup_expired('default');
-- @example SELECT * FROM authn.cleanup_expired('default', 5000); -- smaller batches
--
-- Everything this function deletes belongs to p_namespace. Operator
-- impersonation sessions span namespaces and are cleaned by
-- cleanup_expired_operator_sessions, scheduled once per deployment.
--
-- Every table drains through one batched loop per predicate arm, never
-- one OR: an OR arm can use a partial index only when the arm alone
-- implies the index predicate, so a combined OR has no index path and
-- scans the table. Each arm matches exactly one partial index in
-- 002_indexes.sql; the plan-shape tests in test_maintenance.py hold
-- every arm to that.
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
    v_iteration int;
    v_max_iterations int := 1000;  -- Safety limit to prevent infinite loops
BEGIN
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._validate_positive_int(p_batch_size, 'batch_size');

    v_retention := authn._login_attempts_retention();

    -- Refresh tokens go BEFORE sessions: FK (refresh_tokens.session_id -> sessions.id)

    -- Expired, still-live refresh tokens (refresh_tokens_expired_idx)
    v_iteration := 0;
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE NOTICE 'cleanup_expired: refresh_tokens (expired) iteration limit reached (% iterations)', v_max_iterations;
            EXIT;
        END IF;

        DELETE FROM authn.refresh_tokens
        WHERE id IN (
            SELECT id FROM authn.refresh_tokens
            WHERE namespace = p_namespace
              AND revoked_at IS NULL AND expires_at < now()
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_refresh_tokens_deleted := v_refresh_tokens_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Replaced or revoked refresh tokens (refresh_tokens_cleanup_idx).
    -- Replaced tokens are deleted deliberately: after rotation the old
    -- token no longer authenticates (replaced_by points at its
    -- successor) and reuse detection happens at rotation time, so
    -- keeping them only grows the table. The newest token in the chain
    -- remains valid.
    v_iteration := 0;
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE NOTICE 'cleanup_expired: refresh_tokens (replaced/revoked) iteration limit reached (% iterations)', v_max_iterations;
            EXIT;
        END IF;

        DELETE FROM authn.refresh_tokens
        WHERE id IN (
            SELECT id FROM authn.refresh_tokens
            WHERE namespace = p_namespace
              AND (replaced_by IS NOT NULL OR revoked_at IS NOT NULL)
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_refresh_tokens_deleted := v_refresh_tokens_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Ended impersonation sessions (impersonation_sessions_ended_idx)
    v_iteration := 0;
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE NOTICE 'cleanup_expired: impersonation_sessions (ended) iteration limit reached (% iterations)', v_max_iterations;
            EXIT;
        END IF;

        DELETE FROM authn.impersonation_sessions
        WHERE id IN (
            SELECT id FROM authn.impersonation_sessions
            WHERE namespace = p_namespace
              AND ended_at IS NOT NULL
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_impersonations_deleted := v_impersonations_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Expired, never-ended impersonation sessions (impersonation_sessions_expired_idx)
    v_iteration := 0;
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE NOTICE 'cleanup_expired: impersonation_sessions (expired) iteration limit reached (% iterations)', v_max_iterations;
            EXIT;
        END IF;

        DELETE FROM authn.impersonation_sessions
        WHERE id IN (
            SELECT id FROM authn.impersonation_sessions
            WHERE namespace = p_namespace
              AND ended_at IS NULL AND expires_at < now()
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_impersonations_deleted := v_impersonations_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Expired, unrevoked sessions (sessions_expired_idx)
    v_iteration := 0;
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE NOTICE 'cleanup_expired: sessions (expired) iteration limit reached (% iterations)', v_max_iterations;
            EXIT;
        END IF;

        DELETE FROM authn.sessions
        WHERE id IN (
            SELECT id FROM authn.sessions
            WHERE namespace = p_namespace
              AND revoked_at IS NULL AND expires_at < now()
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_sessions_deleted := v_sessions_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Revoked sessions (sessions_revoked_idx)
    v_iteration := 0;
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE NOTICE 'cleanup_expired: sessions (revoked) iteration limit reached (% iterations)', v_max_iterations;
            EXIT;
        END IF;

        DELETE FROM authn.sessions
        WHERE id IN (
            SELECT id FROM authn.sessions
            WHERE namespace = p_namespace
              AND revoked_at IS NOT NULL
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_sessions_deleted := v_sessions_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Expired, unused tokens (tokens_expired_idx)
    v_iteration := 0;
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE NOTICE 'cleanup_expired: tokens (expired) iteration limit reached (% iterations)', v_max_iterations;
            EXIT;
        END IF;

        DELETE FROM authn.tokens
        WHERE id IN (
            SELECT id FROM authn.tokens
            WHERE namespace = p_namespace
              AND used_at IS NULL AND expires_at < now()
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_tokens_deleted := v_tokens_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Used tokens (tokens_used_idx)
    v_iteration := 0;
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE NOTICE 'cleanup_expired: tokens (used) iteration limit reached (% iterations)', v_max_iterations;
            EXIT;
        END IF;

        DELETE FROM authn.tokens
        WHERE id IN (
            SELECT id FROM authn.tokens
            WHERE namespace = p_namespace
              AND used_at IS NOT NULL
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_tokens_deleted := v_tokens_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Revoked API keys (api_keys_revoked_idx)
    v_iteration := 0;
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE NOTICE 'cleanup_expired: api_keys (revoked) iteration limit reached (% iterations)', v_max_iterations;
            EXIT;
        END IF;

        DELETE FROM authn.api_keys
        WHERE id IN (
            SELECT id FROM authn.api_keys
            WHERE namespace = p_namespace
              AND revoked_at IS NOT NULL
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_api_keys_deleted := v_api_keys_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Expired, unrevoked API keys (api_keys_expired_idx)
    v_iteration := 0;
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE NOTICE 'cleanup_expired: api_keys (expired) iteration limit reached (% iterations)', v_max_iterations;
            EXIT;
        END IF;

        DELETE FROM authn.api_keys
        WHERE id IN (
            SELECT id FROM authn.api_keys
            WHERE namespace = p_namespace
              AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at < now()
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_api_keys_deleted := v_api_keys_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Delete old login attempts (in batches)
    v_iteration := 0;
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE NOTICE 'cleanup_expired: login_attempts iteration limit reached (% iterations)', v_max_iterations;
            EXIT;
        END IF;

        DELETE FROM authn.login_attempts
        WHERE id IN (
            SELECT id FROM authn.login_attempts
            WHERE namespace = p_namespace
              AND attempted_at < now() - v_retention
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_attempts_deleted := v_attempts_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    RETURN QUERY SELECT v_sessions_deleted, v_tokens_deleted, v_refresh_tokens_deleted, v_api_keys_deleted, v_impersonations_deleted, v_attempts_deleted;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

-- @function authn.cleanup_expired_operator_sessions
-- @brief Delete ended or expired operator impersonation sessions (run once per deployment via cron)
-- @param p_batch_size Max rows to delete per iteration (default 10000, prevents long locks)
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
-- One batched loop per predicate arm, for the planner constraint stated
-- on cleanup_expired above; the arms match the partial indexes in
-- 004_operator_impersonation.sql.
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
    v_iteration int;
    v_max_iterations int := 1000;  -- Safety limit to prevent infinite loops
BEGIN
    PERFORM authn._validate_positive_int(p_batch_size, 'batch_size');

    -- Ended sessions (operator_imp_sessions_ended_idx)
    v_iteration := 0;
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE NOTICE 'cleanup_expired_operator_sessions: ended iteration limit reached (% iterations)', v_max_iterations;
            EXIT;
        END IF;

        DELETE FROM authn.operator_impersonation_sessions
        WHERE id IN (
            SELECT id FROM authn.operator_impersonation_sessions
            WHERE ended_at IS NOT NULL
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_deleted := v_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Expired, never-ended sessions (operator_imp_sessions_expired_idx)
    v_iteration := 0;
    LOOP
        v_iteration := v_iteration + 1;
        IF v_iteration > v_max_iterations THEN
            RAISE NOTICE 'cleanup_expired_operator_sessions: expired iteration limit reached (% iterations)', v_max_iterations;
            EXIT;
        END IF;

        DELETE FROM authn.operator_impersonation_sessions
        WHERE id IN (
            SELECT id FROM authn.operator_impersonation_sessions
            WHERE ended_at IS NULL AND expires_at < now()
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_deleted := v_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

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

