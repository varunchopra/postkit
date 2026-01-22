-- @group Operator Impersonation

-- =============================================================================
-- OPERATOR IMPERSONATION FUNCTIONS
-- =============================================================================
-- Cross-namespace operator impersonation for platform support staff.
--
-- MECHANISM vs POLICY:
-- These functions provide the MECHANISM for cross-namespace impersonation.
-- The calling application must provide POLICY (who is an operator).
-- Functions validate that:
--   - Operator has a valid session (in any namespace)
--   - Target user exists and is not disabled
-- Functions do NOT validate:
--   - Whether the caller is authorized as an "operator"
--   - Business rules about which users can be impersonated
-- The application MUST enforce these policies before calling these functions.
--
-- This separation is similar to how AWS IAM separates policy evaluation from
-- resource APIs - the database provides secure cross-namespace capability,
-- and the application layer decides who can use it.
--
-- SECURITY MODEL:
-- 1. All functions use REVOKE ALL FROM PUBLIC - not callable by arbitrary DB users
-- 2. The SDK/application must authenticate the operator before calling these functions
-- 3. Cross-namespace access is intentional - operators need to access customer namespaces
-- 4. Full audit trail is maintained in operator_audit_events table
--
-- SEARCH_PATH NOTE:
-- These functions use `pg_catalog, authn` (not `authn, pg_temp`) because they are
-- SECURITY DEFINER functions. Putting pg_catalog first ensures built-in functions
-- like now() and jsonb_build_object() cannot be shadowed by user-defined functions,
-- providing defense-in-depth for privileged operations.
-- =============================================================================

-- =============================================================================
-- CONFIG FUNCTIONS
-- =============================================================================

-- @function authn._operator_impersonation_default_duration
-- @brief Returns default operator impersonation duration
-- @returns Interval (default: 30 minutes - shorter than regular impersonation)
-- Override with SET authn.operator_impersonation_default_duration.
CREATE OR REPLACE FUNCTION authn._operator_impersonation_default_duration()
RETURNS interval
AS $$
BEGIN
    RETURN COALESCE(
        current_setting('authn.operator_impersonation_default_duration', true)::interval,
        '30 minutes'::interval
    );
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authn, pg_catalog, pg_temp;


-- @function authn._operator_impersonation_max_duration
-- @brief Returns maximum allowed operator impersonation duration
-- @returns Interval (default: 4 hours - shorter than regular impersonation)
-- Override with SET authn.operator_impersonation_max_duration.
CREATE OR REPLACE FUNCTION authn._operator_impersonation_max_duration()
RETURNS interval
AS $$
BEGIN
    RETURN COALESCE(
        current_setting('authn.operator_impersonation_max_duration', true)::interval,
        '4 hours'::interval
    );
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authn, pg_catalog, pg_temp;


-- =============================================================================
-- INTERNAL HELPERS
-- =============================================================================

-- @function authn._log_operator_audit_event
-- @brief Internal helper that inserts operator audit events
-- @param p_event_type Type of event
-- @param p_operator_namespace Operator's namespace
-- @param p_operator_id Operator's user ID
-- @param p_operator_email Operator's email (snapshot)
-- @param p_target_namespace Target user's namespace
-- @param p_target_user_id Target user's ID
-- @param p_target_user_email Target user's email (snapshot)
-- @param p_reason Reason for impersonation
-- @param p_ticket_reference Optional ticket reference
-- @param p_impersonation_session_id Optional impersonation session ID
-- @param p_operator_original_session_id Operator's original session ID
-- @param p_details Additional details (jsonb)
CREATE OR REPLACE FUNCTION authn._log_operator_audit_event(
    p_event_type text,
    p_operator_namespace text,
    p_operator_id uuid,
    p_operator_email text,
    p_target_namespace text,
    p_target_user_id uuid,
    p_target_user_email text,
    p_reason text,
    p_ticket_reference text DEFAULT NULL,
    p_impersonation_session_id uuid DEFAULT NULL,
    p_operator_original_session_id uuid DEFAULT NULL,
    p_details jsonb DEFAULT '{}'
)
RETURNS void
AS $$
DECLARE
    v_ip inet;
BEGIN
    -- Read IP from session config if available
    v_ip := inet(nullif(current_setting('authn.ip_address', true), ''));

    INSERT INTO authn.operator_audit_events (
        event_type,
        operator_namespace,
        operator_id,
        operator_email,
        target_namespace,
        target_user_id,
        target_user_email,
        reason,
        ticket_reference,
        impersonation_session_id,
        operator_original_session_id,
        ip_address,
        user_agent,
        details
    ) VALUES (
        p_event_type,
        p_operator_namespace,
        p_operator_id,
        p_operator_email,
        p_target_namespace,
        p_target_user_id,
        p_target_user_email,
        p_reason,
        p_ticket_reference,
        p_impersonation_session_id,
        p_operator_original_session_id,
        v_ip,
        nullif(current_setting('authn.user_agent', true), ''),
        p_details
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, authn;


-- =============================================================================
-- MAIN FUNCTIONS
-- =============================================================================

-- @function authn.start_operator_impersonation
-- @brief Start cross-namespace operator impersonation
-- @param p_operator_session_id Valid session ID of the operator (any namespace)
-- @param p_target_user_id User ID to impersonate
-- @param p_target_namespace Namespace of the target user
-- @param p_token_hash SHA-256 hash of the impersonation session token
-- @param p_reason Required justification for impersonation
-- @param p_duration How long the impersonation lasts (default 30 minutes, max 4 hours)
-- @param p_ticket_reference Optional external ticket reference (Zendesk, Jira, etc.)
-- @returns impersonation_id, impersonation_session_id, expires_at
--
-- IMPORTANT: This function only validates MECHANISM:
--   - Operator has valid session (not revoked, not expired, user not disabled)
--   - Target user exists and is not disabled
-- The calling application MUST validate POLICY:
--   - Whether the session owner is authorized as an operator
--   - Any other business rules about who can impersonate whom
--
-- @example
-- -- App validates operator status first, then calls:
-- SELECT * FROM authn.start_operator_impersonation(
--     operator_session_id, target_user_id, 'customer_ns', token_hash,
--     'Support ticket #123', '30 minutes', 'ZENDESK-456'
-- );
CREATE OR REPLACE FUNCTION authn.start_operator_impersonation(
    p_operator_session_id uuid,
    p_target_user_id uuid,
    p_target_namespace text,
    p_token_hash text,
    p_reason text,
    p_duration interval DEFAULT NULL,
    p_ticket_reference text DEFAULT NULL
)
RETURNS TABLE(
    impersonation_id uuid,
    impersonation_session_id uuid,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, authn
AS $$
DECLARE
    v_operator_id uuid;
    v_operator_email text;
    v_operator_namespace text;
    v_target_user_email text;
    v_impersonation_id uuid;
    v_session_id uuid;
    v_expires_at timestamptz;
    v_duration interval;
    v_max_duration interval;
BEGIN
    -- Validate inputs
    PERFORM authn._validate_hash(p_token_hash, 'token_hash', false);
    PERFORM authn._validate_namespace(p_target_namespace);

    -- Validate reason is not empty
    IF p_reason IS NULL OR trim(p_reason) = '' THEN
        RAISE EXCEPTION 'Reason cannot be null or empty'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:authn:VAL_REASON_REQUIRED';
    END IF;

    -- MECHANISM: Validate operator has real, valid session (any namespace)
    -- No FK constraint - we query across namespaces
    SELECT u.id, u.email, s.namespace
    INTO v_operator_id, v_operator_email, v_operator_namespace
    FROM authn.sessions s
    JOIN authn.users u ON u.id = s.user_id AND u.namespace = s.namespace
    WHERE s.id = p_operator_session_id
      AND s.revoked_at IS NULL
      AND s.expires_at > now()
      AND u.disabled_at IS NULL;

    IF v_operator_id IS NULL THEN
        RAISE EXCEPTION 'Operator session not found or invalid'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:SESSION_OPERATOR_INVALID';
    END IF;

    -- MECHANISM: Validate target user exists in target namespace and is not disabled
    SELECT email INTO v_target_user_email
    FROM authn.users
    WHERE id = p_target_user_id
      AND namespace = p_target_namespace
      AND disabled_at IS NULL;

    IF v_target_user_email IS NULL THEN
        RAISE EXCEPTION 'Target user not found or disabled'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:SESSION_TARGET_INVALID';
    END IF;

    -- Prevent operator from impersonating themselves
    IF v_operator_id = p_target_user_id AND v_operator_namespace = p_target_namespace THEN
        RAISE EXCEPTION 'Cannot impersonate yourself'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:BIZ_IMPERSONATE_SELF';
    END IF;

    -- Prevent chaining (cannot use any impersonation session to start another)
    -- Check both operator impersonation sessions and regular impersonation sessions
    IF EXISTS (
        SELECT 1 FROM authn.operator_impersonation_sessions ois
        WHERE ois.impersonation_session_id = p_operator_session_id
          AND ois.ended_at IS NULL
    ) OR EXISTS (
        SELECT 1 FROM authn.impersonation_sessions is_
        WHERE is_.impersonation_session_id = p_operator_session_id
          AND is_.ended_at IS NULL
    ) THEN
        RAISE EXCEPTION 'Cannot start operator impersonation from an impersonation session'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:BIZ_IMPERSONATE_CHAIN';
    END IF;

    -- Calculate duration (enforce max)
    v_max_duration := authn._operator_impersonation_max_duration();
    v_duration := COALESCE(p_duration, authn._operator_impersonation_default_duration());

    IF v_duration > v_max_duration THEN
        RAISE EXCEPTION 'Impersonation duration % exceeds maximum allowed %', v_duration, v_max_duration
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:LIMIT_DURATION_EXCEEDED';
    END IF;

    IF v_duration <= interval '0 seconds' THEN
        RAISE EXCEPTION 'Impersonation duration must be positive'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:VAL_DURATION_POSITIVE';
    END IF;

    v_expires_at := now() + v_duration;

    -- Create an impersonation session in the TARGET namespace (a real session as target user)
    INSERT INTO authn.sessions (
        namespace, user_id, token_hash, expires_at, ip_address, user_agent
    ) VALUES (
        p_target_namespace, p_target_user_id, p_token_hash, v_expires_at, NULL, 'operator_impersonation'
    )
    RETURNING id INTO v_session_id;

    -- Create the operator impersonation record
    INSERT INTO authn.operator_impersonation_sessions (
        operator_id, operator_email, operator_namespace, original_session_id,
        target_user_id, target_user_email, target_namespace, impersonation_session_id,
        reason, ticket_reference, expires_at
    ) VALUES (
        v_operator_id, v_operator_email, v_operator_namespace, p_operator_session_id,
        p_target_user_id, v_target_user_email, p_target_namespace, v_session_id,
        trim(p_reason), nullif(trim(COALESCE(p_ticket_reference, '')), ''), v_expires_at
    )
    RETURNING id INTO v_impersonation_id;

    -- Log audit event
    PERFORM authn._log_operator_audit_event(
        'operator_impersonation_started',
        v_operator_namespace,
        v_operator_id,
        v_operator_email,
        p_target_namespace,
        p_target_user_id,
        v_target_user_email,
        trim(p_reason),
        nullif(trim(COALESCE(p_ticket_reference, '')), ''),
        v_session_id,
        p_operator_session_id,
        jsonb_build_object(
            'impersonation_id', v_impersonation_id,
            'expires_at', v_expires_at,
            'duration', v_duration::text
        )
    );

    RETURN QUERY SELECT v_impersonation_id, v_session_id, v_expires_at;
END;
$$;

-- Restrict access - only call via app with operator validation
REVOKE ALL ON FUNCTION authn.start_operator_impersonation FROM PUBLIC;


-- @function authn.end_operator_impersonation
-- @brief End an operator impersonation session early
-- @param p_impersonation_id The impersonation to end
-- @returns true if ended, false if not found or already ended
-- @example SELECT authn.end_operator_impersonation(impersonation_id);
CREATE OR REPLACE FUNCTION authn.end_operator_impersonation(
    p_impersonation_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, authn
AS $$
DECLARE
    v_impersonation authn.operator_impersonation_sessions%ROWTYPE;
BEGIN
    -- Find and lock the impersonation record
    SELECT * INTO v_impersonation
    FROM authn.operator_impersonation_sessions ois
    WHERE ois.id = p_impersonation_id
      AND ois.ended_at IS NULL
    FOR UPDATE;

    IF v_impersonation.id IS NULL THEN
        RETURN false;
    END IF;

    -- End the impersonation
    UPDATE authn.operator_impersonation_sessions
    SET ended_at = now()
    WHERE id = p_impersonation_id;

    -- Revoke the impersonation session
    IF v_impersonation.impersonation_session_id IS NOT NULL THEN
        UPDATE authn.sessions
        SET revoked_at = now()
        WHERE id = v_impersonation.impersonation_session_id
          AND revoked_at IS NULL;
    END IF;

    -- Log audit event
    PERFORM authn._log_operator_audit_event(
        'operator_impersonation_ended',
        v_impersonation.operator_namespace,
        v_impersonation.operator_id,
        v_impersonation.operator_email,
        v_impersonation.target_namespace,
        v_impersonation.target_user_id,
        v_impersonation.target_user_email,
        v_impersonation.reason,
        v_impersonation.ticket_reference,
        v_impersonation.impersonation_session_id,
        v_impersonation.original_session_id,
        jsonb_build_object(
            'impersonation_id', p_impersonation_id,
            'started_at', v_impersonation.started_at,
            'was_expired', v_impersonation.expires_at <= now(),
            'duration', (now() - v_impersonation.started_at)::text
        )
    );

    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION authn.end_operator_impersonation FROM PUBLIC;


-- @function authn.get_operator_impersonation_context
-- @brief Get operator impersonation context for a session
-- @param p_session_id The session to check
-- @returns is_operator_impersonating, impersonation details if true
--   Returns is_operator_impersonating=false with NULLs if not an operator impersonation session
-- @example SELECT * FROM authn.get_operator_impersonation_context(session_id);
CREATE OR REPLACE FUNCTION authn.get_operator_impersonation_context(
    p_session_id uuid
)
RETURNS TABLE(
    is_operator_impersonating boolean,
    impersonation_id uuid,
    operator_id uuid,
    operator_email text,
    operator_namespace text,
    target_user_id uuid,
    target_user_email text,
    target_namespace text,
    reason text,
    ticket_reference text,
    started_at timestamptz,
    expires_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, authn
AS $$
BEGIN
    RETURN QUERY
    SELECT
        true AS is_operator_impersonating,
        ois.id AS impersonation_id,
        ois.operator_id,
        ois.operator_email,
        ois.operator_namespace,
        ois.target_user_id,
        ois.target_user_email,
        ois.target_namespace,
        ois.reason,
        ois.ticket_reference,
        ois.started_at,
        ois.expires_at
    FROM authn.operator_impersonation_sessions ois
    JOIN authn.sessions s ON s.id = ois.impersonation_session_id
    JOIN authn.users operator ON operator.id = ois.operator_id AND operator.namespace = ois.operator_namespace
    WHERE ois.impersonation_session_id = p_session_id
      AND ois.ended_at IS NULL
      AND ois.expires_at > now()
      AND s.revoked_at IS NULL
      AND operator.disabled_at IS NULL;

    -- If no rows returned, return a single row with is_operator_impersonating=false
    IF NOT FOUND THEN
        RETURN QUERY SELECT
            false::boolean AS is_operator_impersonating,
            NULL::uuid AS impersonation_id,
            NULL::uuid AS operator_id,
            NULL::text AS operator_email,
            NULL::text AS operator_namespace,
            NULL::uuid AS target_user_id,
            NULL::text AS target_user_email,
            NULL::text AS target_namespace,
            NULL::text AS reason,
            NULL::text AS ticket_reference,
            NULL::timestamptz AS started_at,
            NULL::timestamptz AS expires_at;
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION authn.get_operator_impersonation_context FROM PUBLIC;


-- @function authn.list_operator_impersonations_for_target
-- @brief List operator impersonation history affecting a target namespace
-- @param p_target_namespace Namespace to query (tenant sees who accessed their users)
-- @param p_limit Maximum records to return
-- @param p_target_user_id Optional filter by specific target user
-- @returns Impersonation records affecting the namespace
-- @example SELECT * FROM authn.list_operator_impersonations_for_target('customer_ns', 100);
CREATE OR REPLACE FUNCTION authn.list_operator_impersonations_for_target(
    p_target_namespace text,
    p_limit int DEFAULT 100,
    p_target_user_id uuid DEFAULT NULL
)
RETURNS TABLE(
    impersonation_id uuid,
    operator_id uuid,
    operator_email text,
    operator_namespace text,
    target_user_id uuid,
    target_user_email text,
    reason text,
    ticket_reference text,
    started_at timestamptz,
    expires_at timestamptz,
    ended_at timestamptz,
    is_active boolean
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, authn
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_target_namespace);

    RETURN QUERY
    SELECT
        ois.id AS impersonation_id,
        ois.operator_id,
        ois.operator_email,
        ois.operator_namespace,
        ois.target_user_id,
        ois.target_user_email,
        ois.reason,
        ois.ticket_reference,
        ois.started_at,
        ois.expires_at,
        ois.ended_at,
        (ois.ended_at IS NULL AND ois.expires_at > now() AND s.id IS NOT NULL AND s.revoked_at IS NULL) AS is_active
    FROM authn.operator_impersonation_sessions ois
    LEFT JOIN authn.sessions s ON s.id = ois.impersonation_session_id
    WHERE ois.target_namespace = p_target_namespace
      AND (p_target_user_id IS NULL OR ois.target_user_id = p_target_user_id)
    ORDER BY ois.started_at DESC
    LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION authn.list_operator_impersonations_for_target FROM PUBLIC;


-- @function authn.list_operator_impersonations_by_operator
-- @brief List impersonations performed by an operator
-- @param p_operator_id Operator user ID to query
-- @param p_operator_namespace Operator's namespace
-- @param p_limit Maximum records to return
-- @returns Impersonation records by the operator
-- @example SELECT * FROM authn.list_operator_impersonations_by_operator(operator_id, 'platform');
CREATE OR REPLACE FUNCTION authn.list_operator_impersonations_by_operator(
    p_operator_id uuid,
    p_operator_namespace text,
    p_limit int DEFAULT 100
)
RETURNS TABLE(
    impersonation_id uuid,
    target_user_id uuid,
    target_user_email text,
    target_namespace text,
    reason text,
    ticket_reference text,
    started_at timestamptz,
    expires_at timestamptz,
    ended_at timestamptz,
    is_active boolean
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, authn
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_operator_namespace);

    RETURN QUERY
    SELECT
        ois.id AS impersonation_id,
        ois.target_user_id,
        ois.target_user_email,
        ois.target_namespace,
        ois.reason,
        ois.ticket_reference,
        ois.started_at,
        ois.expires_at,
        ois.ended_at,
        (ois.ended_at IS NULL AND ois.expires_at > now() AND s.id IS NOT NULL AND s.revoked_at IS NULL) AS is_active
    FROM authn.operator_impersonation_sessions ois
    LEFT JOIN authn.sessions s ON s.id = ois.impersonation_session_id
    WHERE ois.operator_id = p_operator_id
      AND ois.operator_namespace = p_operator_namespace
    ORDER BY ois.started_at DESC
    LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION authn.list_operator_impersonations_by_operator FROM PUBLIC;


-- @function authn.list_active_operator_impersonations
-- @brief List all active operator impersonations (platform admin view)
-- @param p_limit Maximum records to return
-- @returns Active impersonation records
-- @example SELECT * FROM authn.list_active_operator_impersonations(100);
CREATE OR REPLACE FUNCTION authn.list_active_operator_impersonations(
    p_limit int DEFAULT 100
)
RETURNS TABLE(
    impersonation_id uuid,
    operator_id uuid,
    operator_email text,
    operator_namespace text,
    target_user_id uuid,
    target_user_email text,
    target_namespace text,
    reason text,
    ticket_reference text,
    started_at timestamptz,
    expires_at timestamptz,
    impersonation_session_id uuid
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, authn
AS $$
BEGIN
    RETURN QUERY
    SELECT
        ois.id AS impersonation_id,
        ois.operator_id,
        ois.operator_email,
        ois.operator_namespace,
        ois.target_user_id,
        ois.target_user_email,
        ois.target_namespace,
        ois.reason,
        ois.ticket_reference,
        ois.started_at,
        ois.expires_at,
        ois.impersonation_session_id
    FROM authn.operator_impersonation_sessions ois
    JOIN authn.sessions s ON s.id = ois.impersonation_session_id
    WHERE ois.ended_at IS NULL
      AND ois.expires_at > now()
      AND s.revoked_at IS NULL
    ORDER BY ois.started_at DESC
    LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION authn.list_active_operator_impersonations FROM PUBLIC;


-- @function authn.get_operator_audit_events
-- @brief Query operator audit events
-- @param p_limit Maximum records to return
-- @param p_event_type Optional filter by event type
-- @param p_operator_namespace Optional filter by operator namespace
-- @param p_target_namespace Optional filter by target namespace
-- @returns Operator audit event records
-- @example SELECT * FROM authn.get_operator_audit_events(100, NULL, NULL, 'customer_ns');
CREATE OR REPLACE FUNCTION authn.get_operator_audit_events(
    p_limit int DEFAULT 100,
    p_event_type text DEFAULT NULL,
    p_operator_namespace text DEFAULT NULL,
    p_target_namespace text DEFAULT NULL
)
RETURNS TABLE(
    event_id uuid,
    event_type text,
    occurred_at timestamptz,
    operator_namespace text,
    operator_id uuid,
    operator_email text,
    target_namespace text,
    target_user_id uuid,
    target_user_email text,
    reason text,
    ticket_reference text,
    ip_address inet,
    user_agent text,
    details jsonb
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, authn
AS $$
BEGIN
    RETURN QUERY
    SELECT
        oae.id AS event_id,
        oae.event_type,
        oae.occurred_at,
        oae.operator_namespace,
        oae.operator_id,
        oae.operator_email,
        oae.target_namespace,
        oae.target_user_id,
        oae.target_user_email,
        oae.reason,
        oae.ticket_reference,
        oae.ip_address,
        oae.user_agent,
        oae.details
    FROM authn.operator_audit_events oae
    WHERE (p_event_type IS NULL OR oae.event_type = p_event_type)
      AND (p_operator_namespace IS NULL OR oae.operator_namespace = p_operator_namespace)
      AND (p_target_namespace IS NULL OR oae.target_namespace = p_target_namespace)
    ORDER BY oae.occurred_at DESC
    LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION authn.get_operator_audit_events FROM PUBLIC;


-- @function authn._end_operator_impersonations_for_operator
-- @brief End all operator impersonation sessions for a disabled operator (cross-namespace)
CREATE OR REPLACE FUNCTION authn._end_operator_impersonations_for_operator(
    p_operator_id uuid,
    p_operator_namespace text
)
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, authn
AS $$
DECLARE
    v_count int := 0;
    v_imp RECORD;
BEGIN
    -- Must loop to audit each impersonation individually
    FOR v_imp IN
        SELECT ois.id, ois.impersonation_session_id,
               ois.target_namespace, ois.target_user_id, ois.target_user_email,
               ois.reason, ois.ticket_reference, ois.original_session_id,
               ois.operator_email
        FROM authn.operator_impersonation_sessions ois
        WHERE ois.operator_id = p_operator_id
          AND ois.operator_namespace = p_operator_namespace
          AND ois.ended_at IS NULL
        FOR UPDATE
    LOOP
        UPDATE authn.operator_impersonation_sessions
        SET ended_at = now()
        WHERE id = v_imp.id;

        UPDATE authn.sessions
        SET revoked_at = now()
        WHERE id = v_imp.impersonation_session_id
          AND revoked_at IS NULL;

        PERFORM authn._log_operator_audit_event(
            'operator_impersonation_ended_operator_disabled',
            p_operator_namespace, p_operator_id, v_imp.operator_email,
            v_imp.target_namespace, v_imp.target_user_id, v_imp.target_user_email,
            v_imp.reason, v_imp.ticket_reference,
            v_imp.impersonation_session_id, v_imp.original_session_id,
            jsonb_build_object('impersonation_id', v_imp.id)
        );

        v_count := v_count + 1;
    END LOOP;

    RETURN v_count;
END;
$$;

REVOKE ALL ON FUNCTION authn._end_operator_impersonations_for_operator FROM PUBLIC;
