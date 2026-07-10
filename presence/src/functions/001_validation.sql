-- @group Internal

-- @function presence._name_violation
-- @brief Check a name against the shared name rules; NULL means the name is fine.
-- @param p_value Name to check
-- @param p_max_len Maximum length in characters
-- @returns The rule that was broken ('null', 'empty', 'too_long', 'invalid_chars', 'whitespace'), or NULL
-- Every name field follows the same rules: a name must exist, must not be
-- empty or only whitespace, must fit the length limit, must not contain
-- control characters (including the Unicode line separators U+0085, U+2028,
-- and U+2029), and must not start or end with whitespace. The per-field
-- validators turn the result into their own error, keeping each HINT code a
-- literal string because the SDK error-code sync test finds codes by
-- scanning the source.
CREATE OR REPLACE FUNCTION presence._name_violation(p_value text, p_max_len int)
RETURNS text AS $$
DECLARE
    v_trimmed text := trim(p_value);
BEGIN
    IF p_value IS NULL THEN
        RETURN 'null';
    END IF;
    IF v_trimmed = '' THEN
        RETURN 'empty';
    END IF;
    IF length(p_value) > p_max_len THEN
        RETURN 'too_long';
    END IF;
    IF p_value ~ '[\x00-\x1F\x7F\u0085\u2028\u2029]' THEN
        RETURN 'invalid_chars';
    END IF;
    IF p_value != v_trimmed THEN
        RETURN 'whitespace';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence._validate_namespace
-- @brief Validate namespace format.
-- @param p_value Namespace to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-1024 characters.
CREATE OR REPLACE FUNCTION presence._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    CASE presence._name_violation(p_value, 1024)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Namespace cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:presence:VAL_NAMESPACE_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Namespace cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:presence:VAL_NAMESPACE_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:presence:VAL_NAMESPACE_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Namespace contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:presence:VAL_NAMESPACE_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:presence:VAL_NAMESPACE_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence._validate_entity_id
-- @brief Validate entity id format.
-- @param p_value Entity id to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-1024 characters.
CREATE OR REPLACE FUNCTION presence._validate_entity_id(p_value text)
RETURNS void AS $$
BEGIN
    CASE presence._name_violation(p_value, 1024)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Entity id cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:presence:VAL_ENTITY_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Entity id cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:presence:VAL_ENTITY_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Entity id exceeds maximum length of 1024 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:presence:VAL_ENTITY_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Entity id contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:presence:VAL_ENTITY_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Entity id cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:presence:VAL_ENTITY_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence._validate_kind
-- @brief Validate kind format.
-- @param p_value Kind to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-256 characters.
CREATE OR REPLACE FUNCTION presence._validate_kind(p_value text)
RETURNS void AS $$
BEGIN
    CASE presence._name_violation(p_value, 256)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Kind cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:presence:VAL_KIND_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Kind cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:presence:VAL_KIND_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Kind exceeds maximum length of 256 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:presence:VAL_KIND_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Kind contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:presence:VAL_KIND_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Kind cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:presence:VAL_KIND_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence._validate_timeout
-- @brief Validate an optional per-entity timeout override.
-- @param p_value Timeout to validate (NULL is OK, the kind's dead_after applies)
CREATE OR REPLACE FUNCTION presence._validate_timeout(p_value interval)
RETURNS void AS $$
BEGIN
    IF p_value IS NOT NULL AND p_value <= interval '0 seconds' THEN
        RAISE EXCEPTION 'Timeout must be a positive interval'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:presence:VAL_TIMEOUT_NOT_POSITIVE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence._validate_positive_int
-- @brief Validate that an integer is positive.
-- @param p_value Value to validate
-- @param p_name Name of the parameter for error message
CREATE OR REPLACE FUNCTION presence._validate_positive_int(p_value int, p_name text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL OR p_value <= 0 THEN
        RAISE EXCEPTION '% must be a positive integer', p_name
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:presence:VAL_NOT_POSITIVE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence._validate_hook_queue
-- @brief Validate a configured hook queue name (on_death_queue/on_revival_queue).
-- @param p_value Queue name to validate (callers guard NULL, which means no hook)
-- Hook queue names are checked twice. This function always applies the
-- shared name rules (queue is an optional module and may not be installed).
-- When queue is installed, the config trigger also runs queue's own
-- validator (_delegate_hook_queue_validation), so a name the queue module would
-- reject fails when the config is written, not later when the hook fires.
-- Accepts any name that passes the shared name rules (see _name_violation);
-- 1-256 characters.
CREATE OR REPLACE FUNCTION presence._validate_hook_queue(p_value text)
RETURNS void AS $$
BEGIN
    -- NULL means "no hook configured" (callers guard NULL); pass it through.
    IF p_value IS NULL THEN
        RETURN;
    END IF;

    CASE presence._name_violation(p_value, 256)
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Hook queue name cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:presence:VAL_HOOK_QUEUE_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Hook queue name exceeds maximum length of 256 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:presence:VAL_HOOK_QUEUE_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Hook queue name contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:presence:VAL_HOOK_QUEUE_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Hook queue name cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:presence:VAL_HOOK_QUEUE_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence._warn_namespace_mismatch
-- @brief Warns if namespace doesn't match RLS tenant context.
-- @param p_namespace The namespace being queried
-- Called at start of query functions to alert developers of likely misconfiguration.
CREATE OR REPLACE FUNCTION presence._warn_namespace_mismatch(p_namespace text)
RETURNS void AS $$
DECLARE
    v_tenant_id text;
BEGIN
    v_tenant_id := current_setting('presence.tenant_id', true);
    IF v_tenant_id IS NOT NULL AND v_tenant_id != '' AND p_namespace != v_tenant_id THEN
        RAISE WARNING 'Querying namespace "%" but RLS tenant context is "%". Results will be empty due to row-level security.',
            p_namespace, v_tenant_id;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = presence, pg_temp;
