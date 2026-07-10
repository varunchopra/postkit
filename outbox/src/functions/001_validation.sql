-- @group Internal

-- @function outbox._name_violation
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
CREATE OR REPLACE FUNCTION outbox._name_violation(p_value text, p_max_len int)
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
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._validate_namespace
-- @brief Validate namespace format.
-- @param p_value Namespace to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-1024 characters.
CREATE OR REPLACE FUNCTION outbox._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    CASE outbox._name_violation(p_value, 1024)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Namespace cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:outbox:VAL_NAMESPACE_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Namespace cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:outbox:VAL_NAMESPACE_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:outbox:VAL_NAMESPACE_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Namespace contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:outbox:VAL_NAMESPACE_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:outbox:VAL_NAMESPACE_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._validate_topic
-- @brief Validate topic name format.
-- @param p_value Topic name to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-256 characters.
-- '*' is reserved as the config wildcard.
CREATE OR REPLACE FUNCTION outbox._validate_topic(p_value text)
RETURNS void AS $$
BEGIN
    CASE outbox._name_violation(p_value, 256)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Topic cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:outbox:VAL_TOPIC_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Topic cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:outbox:VAL_TOPIC_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Topic exceeds maximum length of 256 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:outbox:VAL_TOPIC_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Topic contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:outbox:VAL_TOPIC_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Topic cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:outbox:VAL_TOPIC_WHITESPACE';
        ELSE
            NULL;
    END CASE;

    IF p_value = '*' THEN
        RAISE EXCEPTION 'Topic ''*'' is reserved for configuration wildcards'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:VAL_TOPIC_RESERVED';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._validate_consumer
-- @brief Validate consumer name format.
-- @param p_value Consumer name to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-256 characters.
CREATE OR REPLACE FUNCTION outbox._validate_consumer(p_value text)
RETURNS void AS $$
BEGIN
    CASE outbox._name_violation(p_value, 256)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Consumer cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:outbox:VAL_CONSUMER_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Consumer cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:outbox:VAL_CONSUMER_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Consumer exceeds maximum length of 256 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:outbox:VAL_CONSUMER_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Consumer contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:outbox:VAL_CONSUMER_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Consumer cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:outbox:VAL_CONSUMER_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._validate_event_type
-- @brief Validate event type format.
-- @param p_value Event type to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-256 characters.
CREATE OR REPLACE FUNCTION outbox._validate_event_type(p_value text)
RETURNS void AS $$
BEGIN
    CASE outbox._name_violation(p_value, 256)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Event type cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:outbox:VAL_EVENT_TYPE_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Event type cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:outbox:VAL_EVENT_TYPE_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Event type exceeds maximum length of 256 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:outbox:VAL_EVENT_TYPE_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Event type contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:outbox:VAL_EVENT_TYPE_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Event type cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:outbox:VAL_EVENT_TYPE_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._validate_positive_int
-- @brief Validate that an integer is positive.
-- @param p_value Value to validate
-- @param p_name Name of the parameter for error message
CREATE OR REPLACE FUNCTION outbox._validate_positive_int(p_value int, p_name text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL OR p_value <= 0 THEN
        RAISE EXCEPTION '% must be a positive integer', p_name
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:VAL_NOT_POSITIVE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._validate_position
-- @brief Validate a cursor position pair.
-- @param p_xid Transaction component of the position
-- @param p_id Id component of the position
-- Positions are last-acked (xid, id) pairs: ('0', 0) is legal (nothing
-- acked yet), NULL components and negative ids are not.
CREATE OR REPLACE FUNCTION outbox._validate_position(p_xid xid8, p_id bigint)
RETURNS void AS $$
BEGIN
    IF p_xid IS NULL OR p_id IS NULL OR p_id < 0 THEN
        RAISE EXCEPTION 'Position must be an (xid, id) pair with a non-negative id'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:VAL_POSITION_INVALID';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._warn_namespace_mismatch
-- @brief Warns if namespace doesn't match RLS tenant context.
-- @param p_namespace The namespace being queried
-- Called at start of query functions to alert developers of likely misconfiguration.
CREATE OR REPLACE FUNCTION outbox._warn_namespace_mismatch(p_namespace text)
RETURNS void AS $$
DECLARE
    v_tenant_id text;
BEGIN
    v_tenant_id := current_setting('outbox.tenant_id', true);
    IF v_tenant_id IS NOT NULL AND v_tenant_id != '' AND p_namespace != v_tenant_id THEN
        RAISE WARNING 'Querying namespace "%" but RLS tenant context is "%". Results will be empty due to row-level security.',
            p_namespace, v_tenant_id;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = outbox, pg_temp;
