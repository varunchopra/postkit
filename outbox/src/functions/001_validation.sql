-- @group Internal

-- @function outbox._validate_namespace
-- @brief Validate namespace format.
-- @param p_value Namespace to validate
-- Flexible: allows any string except control characters and leading/trailing whitespace.
CREATE OR REPLACE FUNCTION outbox._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Namespace cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:outbox:VAL_NAMESPACE_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Namespace cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:outbox:VAL_NAMESPACE_EMPTY';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:outbox:VAL_NAMESPACE_TOO_LONG';
    END IF;

    -- Reject control characters (0x00-0x1F, 0x7F)
    IF p_value ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION 'Namespace contains invalid control characters'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:VAL_NAMESPACE_INVALID_CHARS';
    END IF;

    -- Reject leading/trailing whitespace (causes subtle matching bugs)
    IF p_value != trim(p_value) THEN
        RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:VAL_NAMESPACE_WHITESPACE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._validate_topic
-- @brief Validate topic name format.
-- @param p_value Topic name to validate
-- Topics are infrastructure names (enumerable, config-addressable), so the
-- charset is strict: alphanumeric with underscores and hyphens, starting
-- with a letter or underscore, 1-256 characters. This keeps '*' free as the
-- config wildcard.
CREATE OR REPLACE FUNCTION outbox._validate_topic(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Topic cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:outbox:VAL_TOPIC_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Topic cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:outbox:VAL_TOPIC_EMPTY';
    END IF;

    IF length(p_value) > 256 THEN
        RAISE EXCEPTION 'Topic exceeds maximum length of 256 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:outbox:VAL_TOPIC_TOO_LONG';
    END IF;

    IF p_value = '*' THEN
        RAISE EXCEPTION 'Topic ''*'' is reserved for configuration wildcards'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:VAL_TOPIC_RESERVED';
    END IF;

    IF p_value !~ '^[a-zA-Z_][a-zA-Z0-9_-]*$' THEN
        RAISE EXCEPTION 'Topic must start with a letter or underscore and contain only alphanumeric characters, underscores, and hyphens (got: %)', p_value
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:VAL_TOPIC_FORMAT';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._validate_consumer
-- @brief Validate consumer name format.
-- @param p_value Consumer name to validate
-- Same strict charset as topics: consumer names key the cursors table and
-- appear in lag output.
CREATE OR REPLACE FUNCTION outbox._validate_consumer(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Consumer cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:outbox:VAL_CONSUMER_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Consumer cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:outbox:VAL_CONSUMER_EMPTY';
    END IF;

    IF length(p_value) > 256 THEN
        RAISE EXCEPTION 'Consumer exceeds maximum length of 256 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:outbox:VAL_CONSUMER_TOO_LONG';
    END IF;

    IF p_value !~ '^[a-zA-Z_][a-zA-Z0-9_-]*$' THEN
        RAISE EXCEPTION 'Consumer must start with a letter or underscore and contain only alphanumeric characters, underscores, and hyphens (got: %)', p_value
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:VAL_CONSUMER_FORMAT';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._validate_event_type
-- @brief Validate event type format.
-- @param p_value Event type to validate
-- Same strict charset as topics: event types are enumerable names consumers
-- switch on.
CREATE OR REPLACE FUNCTION outbox._validate_event_type(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Event type cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:outbox:VAL_EVENT_TYPE_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Event type cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:outbox:VAL_EVENT_TYPE_EMPTY';
    END IF;

    IF length(p_value) > 256 THEN
        RAISE EXCEPTION 'Event type exceeds maximum length of 256 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:outbox:VAL_EVENT_TYPE_TOO_LONG';
    END IF;

    IF p_value !~ '^[a-zA-Z_][a-zA-Z0-9_.-]*$' THEN
        RAISE EXCEPTION 'Event type must start with a letter or underscore and contain only alphanumeric characters, underscores, dots, and hyphens (got: %)', p_value
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:VAL_EVENT_TYPE_FORMAT';
    END IF;
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
