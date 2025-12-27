-- =============================================================================
-- MAINTENANCE FOR POSTKIT/AUTHN
-- =============================================================================
-- Cleanup expired data and statistics.
-- =============================================================================


-- =============================================================================
-- CLEANUP EXPIRED
-- =============================================================================
-- Deletes expired or revoked sessions, expired or used tokens, and old login attempts.
CREATE OR REPLACE FUNCTION authn.cleanup_expired(
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    sessions_deleted bigint,
    tokens_deleted bigint,
    attempts_deleted bigint
)
AS $$
DECLARE
    v_sessions_deleted bigint;
    v_tokens_deleted bigint;
    v_attempts_deleted bigint;
    v_retention interval;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    v_retention := authn._login_attempts_retention();

    -- Delete expired or revoked sessions
    DELETE FROM authn.sessions
    WHERE namespace = p_namespace
      AND (expires_at < now() OR revoked_at IS NOT NULL);
    GET DIAGNOSTICS v_sessions_deleted = ROW_COUNT;

    -- Delete expired or used tokens
    DELETE FROM authn.tokens
    WHERE namespace = p_namespace
      AND (expires_at < now() OR used_at IS NOT NULL);
    GET DIAGNOSTICS v_tokens_deleted = ROW_COUNT;

    -- Delete old login attempts
    DELETE FROM authn.login_attempts
    WHERE namespace = p_namespace
      AND attempted_at < now() - v_retention;
    GET DIAGNOSTICS v_attempts_deleted = ROW_COUNT;

    RETURN QUERY SELECT v_sessions_deleted, v_tokens_deleted, v_attempts_deleted;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.cleanup_expired(text) IS
'Deletes expired sessions, tokens, and old login attempts.';


-- =============================================================================
-- GET STATS
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.get_stats(
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    user_count bigint,
    verified_user_count bigint,
    disabled_user_count bigint,
    active_session_count bigint,
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
        (SELECT COUNT(DISTINCT user_id) FROM authn.mfa_secrets WHERE namespace = p_namespace);
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.get_stats(text) IS
'Returns authentication statistics for a namespace.';
