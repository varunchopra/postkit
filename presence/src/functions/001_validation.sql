-- @group Internal

-- @function presence._validate_namespace
-- @brief Validate namespace format.
-- @param p_value Namespace to validate
-- Flexible: allows any string except control characters and leading/trailing whitespace.
CREATE OR REPLACE FUNCTION presence._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Namespace cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:presence:VAL_NAMESPACE_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Namespace cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:presence:VAL_NAMESPACE_EMPTY';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:presence:VAL_NAMESPACE_TOO_LONG';
    END IF;

    -- Reject control characters (0x00-0x1F, 0x7F)
    IF p_value ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION 'Namespace contains invalid control characters'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:presence:VAL_NAMESPACE_INVALID_CHARS';
    END IF;

    -- Reject leading/trailing whitespace (causes subtle matching bugs)
    IF p_value != trim(p_value) THEN
        RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:presence:VAL_NAMESPACE_WHITESPACE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence._validate_entity_id
-- @brief Validate entity id format.
-- @param p_value Entity id to validate
-- Permissive like lease names (not the strict infrastructure charset):
-- entity ids are opaque caller identity and commonly encode structure with
-- separators, e.g. 'worker-7', 'sensor:eu:42'. Rejects only control
-- characters, leading/trailing whitespace, and length > 1024.
CREATE OR REPLACE FUNCTION presence._validate_entity_id(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Entity id cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:presence:VAL_ENTITY_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Entity id cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:presence:VAL_ENTITY_EMPTY';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION 'Entity id exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:presence:VAL_ENTITY_TOO_LONG';
    END IF;

    IF p_value ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION 'Entity id contains invalid control characters'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:presence:VAL_ENTITY_INVALID_CHARS';
    END IF;

    IF p_value != trim(p_value) THEN
        RAISE EXCEPTION 'Entity id cannot have leading or trailing whitespace'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:presence:VAL_ENTITY_WHITESPACE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence._validate_kind
-- @brief Validate kind format.
-- @param p_value Kind to validate
-- Strict charset: kinds are infrastructure names that key config rows (the
-- outbox-topic precedent) - identifier characters only, starting with a
-- letter.
CREATE OR REPLACE FUNCTION presence._validate_kind(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Kind cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:presence:VAL_KIND_NULL';
    END IF;

    IF p_value = '' THEN
        RAISE EXCEPTION 'Kind cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:presence:VAL_KIND_EMPTY';
    END IF;

    IF length(p_value) > 256 THEN
        RAISE EXCEPTION 'Kind exceeds maximum length of 256 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:presence:VAL_KIND_TOO_LONG';
    END IF;

    IF p_value !~ '^[a-zA-Z][a-zA-Z0-9_.-]*$' THEN
        RAISE EXCEPTION 'Kind must start with a letter and contain only letters, digits, underscore, dot, or hyphen'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:presence:VAL_KIND_FORMAT';
    END IF;
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
-- Rules mirror queue._validate_queue_name, duplicated rather than delegated
-- because queue is a soft dependency and may not be installed here.
CREATE OR REPLACE FUNCTION presence._validate_hook_queue(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value = '' THEN
        RAISE EXCEPTION 'Hook queue name cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:presence:VAL_HOOK_QUEUE_EMPTY';
    END IF;

    IF length(p_value) > 256 THEN
        RAISE EXCEPTION 'Hook queue name exceeds maximum length of 256 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:presence:VAL_HOOK_QUEUE_TOO_LONG';
    END IF;

    IF p_value !~ '^[a-zA-Z_][a-zA-Z0-9_-]*$' THEN
        RAISE EXCEPTION 'Hook queue name must start with a letter or underscore and contain only letters, digits, underscores, and hyphens (got: %)', p_value
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:presence:VAL_HOOK_QUEUE_FORMAT';
    END IF;
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
