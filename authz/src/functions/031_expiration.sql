-- @group Expiration

-- @function authz.set_expiration
-- @brief Add or update expiration on an existing grant
-- @param p_expires_at When the permission should auto-revoke (NULL to make permanent)
-- @returns True if grant was found and updated
-- @example -- Contractor access expires in 90 days
-- @example SELECT authz.set_expiration('repo', 'api', 'read', 'user', 'contractor-bob',
-- @example   now() + interval '90 days', 'default');
CREATE OR REPLACE FUNCTION authz.set_expiration (p_resource_type text, p_resource_id text, p_relation text, p_subject_type text, p_subject_id text, p_expires_at timestamptz, p_namespace text DEFAULT 'default')
    RETURNS boolean
    AS $$
DECLARE
    v_updated int;
BEGIN
    -- Validate expiration is in the future (consistent with write_tuple)
    IF p_expires_at IS NOT NULL AND p_expires_at <= now() THEN
        RAISE EXCEPTION 'expires_at must be in the future'
            USING ERRCODE = 'check_violation',
                  HINT = 'postkit:authz:VAL_EXPIRATION_FUTURE';
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

-- @function authz.clear_expiration
-- @brief Make a grant permanent (remove expiration)
-- @example SELECT authz.clear_expiration('repo', 'api', 'read', 'user', 'alice', 'default');
CREATE OR REPLACE FUNCTION authz.clear_expiration (p_resource_type text, p_resource_id text, p_relation text, p_subject_type text, p_subject_id text, p_namespace text DEFAULT 'default')
    RETURNS boolean
    AS $$
BEGIN
    RETURN authz.set_expiration (p_resource_type, p_resource_id, p_relation, p_subject_type, p_subject_id, NULL, p_namespace);
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;

-- @function authz.extend_expiration
-- @brief Extend an existing grant's expiration by an interval
-- @param p_extension Time to add (e.g., '30 days')
-- @returns New expiration timestamp
-- @example -- Give alice another 30 days
-- @example SELECT authz.extend_expiration('repo', 'api', 'read', 'user', 'alice',
-- @example   interval '30 days', 'default');
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
            USING ERRCODE = 'no_data_found',
                  HINT = 'postkit:authz:DATA_GRANT_NOT_FOUND';
        END IF;
        IF v_current_expiration IS NULL THEN
            RAISE EXCEPTION 'Grant has no expiration to extend'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:authz:BIZ_GRANT_NO_EXPIRATION';
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

-- @function authz.list_expiring
-- @brief Find grants that will expire soon (for renewal reminders)
-- @param p_within Time window to check (default 7 days)
-- @returns Grants expiring within the window, ordered by expiration
-- @example -- Email users whose access expires this week
-- @example SELECT * FROM authz.list_expiring(interval '7 days', 'default');
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

-- @function authz.cleanup_expired
-- @brief Delete expired grants to reclaim storage (optional, run via cron)
-- @returns Count of grants deleted
-- @example SELECT * FROM authz.cleanup_expired('default');
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
