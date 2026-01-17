-- @group Maintenance

-- @function authn.cleanup_expired
-- @brief Delete expired sessions, tokens, refresh tokens, API keys, impersonation records, and old login attempts (run via cron)
-- @param p_namespace Namespace to clean up
-- @param p_batch_size Max rows to delete per table per iteration (default 10000, prevents long locks)
-- @returns sessions_deleted, tokens_deleted, refresh_tokens_deleted, api_keys_deleted, impersonations_deleted, operator_impersonations_deleted, attempts_deleted
-- @example -- Add to daily cron job
-- @example SELECT * FROM authn.cleanup_expired('default');
-- @example SELECT * FROM authn.cleanup_expired('default', 5000); -- smaller batches
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
    operator_impersonations_deleted bigint,
    attempts_deleted bigint
)
AS $$
DECLARE
    v_sessions_deleted bigint := 0;
    v_tokens_deleted bigint := 0;
    v_refresh_tokens_deleted bigint := 0;
    v_api_keys_deleted bigint := 0;
    v_impersonations_deleted bigint := 0;
    v_operator_impersonations_deleted bigint := 0;
    v_attempts_deleted bigint := 0;
    v_batch_deleted bigint;
    v_retention interval;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    v_retention := authn._login_attempts_retention();

    -- Delete expired, revoked, or replaced refresh tokens (in batches)
    -- Must happen BEFORE sessions due to FK (refresh_tokens.session_id -> sessions.id)
    --
    -- NOTE: We intentionally delete tokens where replaced_by IS NOT NULL. After token
    -- rotation, the old token is no longer valid for authentication (replaced_by points
    -- to the new token). Keeping replaced tokens is only useful for reuse detection,
    -- which is handled at rotation time. Cleaning them up prevents unbounded table growth
    -- in high-rotation scenarios. The new token in the chain remains valid.
    LOOP
        DELETE FROM authn.refresh_tokens
        WHERE id IN (
            SELECT id FROM authn.refresh_tokens
            WHERE namespace = p_namespace
              AND (expires_at < now() OR revoked_at IS NOT NULL OR replaced_by IS NOT NULL)
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_refresh_tokens_deleted := v_refresh_tokens_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Delete ended or expired impersonation sessions (in batches)
    LOOP
        DELETE FROM authn.impersonation_sessions
        WHERE id IN (
            SELECT id FROM authn.impersonation_sessions
            WHERE namespace = p_namespace
              AND (ended_at IS NOT NULL OR expires_at < now())
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_impersonations_deleted := v_impersonations_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Delete expired or revoked sessions (in batches)
    LOOP
        DELETE FROM authn.sessions
        WHERE id IN (
            SELECT id FROM authn.sessions
            WHERE namespace = p_namespace
              AND (expires_at < now() OR revoked_at IS NOT NULL)
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_sessions_deleted := v_sessions_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Delete expired or used tokens (in batches)
    LOOP
        DELETE FROM authn.tokens
        WHERE id IN (
            SELECT id FROM authn.tokens
            WHERE namespace = p_namespace
              AND (expires_at < now() OR used_at IS NOT NULL)
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_tokens_deleted := v_tokens_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Delete expired or revoked API keys (in batches)
    LOOP
        DELETE FROM authn.api_keys
        WHERE id IN (
            SELECT id FROM authn.api_keys
            WHERE namespace = p_namespace
              AND (revoked_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at < now()))
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_api_keys_deleted := v_api_keys_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    -- Delete old login attempts (in batches)
    LOOP
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

    -- Delete ended or expired operator impersonation sessions (in batches)
    -- Note: These are cross-namespace, so we clean up ALL expired ones regardless of p_namespace
    LOOP
        DELETE FROM authn.operator_impersonation_sessions
        WHERE id IN (
            SELECT id FROM authn.operator_impersonation_sessions
            WHERE ended_at IS NOT NULL OR expires_at < now()
            LIMIT p_batch_size
            FOR UPDATE SKIP LOCKED
        );
        GET DIAGNOSTICS v_batch_deleted = ROW_COUNT;
        v_operator_impersonations_deleted := v_operator_impersonations_deleted + v_batch_deleted;
        EXIT WHEN v_batch_deleted < p_batch_size;
    END LOOP;

    RETURN QUERY SELECT v_sessions_deleted, v_tokens_deleted, v_refresh_tokens_deleted, v_api_keys_deleted, v_impersonations_deleted, v_operator_impersonations_deleted, v_attempts_deleted;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

-- @function authn.get_stats
-- @brief Get namespace statistics for monitoring dashboards
-- @returns user_count, verified_user_count, disabled_user_count,
--   active_session_count, active_refresh_token_count, active_api_key_count, mfa_enabled_user_count
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
    mfa_enabled_user_count bigint
)
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        (SELECT COUNT(*) FROM authn.users WHERE namespace = p_namespace),
        (SELECT COUNT(*) FROM authn.users WHERE namespace = p_namespace AND email_verified_at IS NOT NULL),
        (SELECT COUNT(*) FROM authn.users WHERE namespace = p_namespace AND disabled_at IS NOT NULL),
        (SELECT COUNT(*) FROM authn.sessions WHERE namespace = p_namespace AND revoked_at IS NULL AND expires_at > now()),
        (SELECT COUNT(*) FROM authn.refresh_tokens WHERE namespace = p_namespace AND revoked_at IS NULL AND replaced_by IS NULL AND expires_at > now()),
        (SELECT COUNT(*) FROM authn.api_keys WHERE namespace = p_namespace AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())),
        (SELECT COUNT(DISTINCT user_id) FROM authn.mfa_secrets WHERE namespace = p_namespace);
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;

