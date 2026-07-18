-- @group Internal

-- @function memory._name_violation
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
CREATE OR REPLACE FUNCTION memory._name_violation(p_value text, p_max_len int)
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
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory._validate_namespace
-- @brief Validate namespace format.
-- @param p_value Namespace to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-1024 characters.
CREATE OR REPLACE FUNCTION memory._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    CASE memory._name_violation(p_value, 1024)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Namespace cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:memory:VAL_NAMESPACE_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Namespace cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:memory:VAL_NAMESPACE_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:memory:VAL_NAMESPACE_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Namespace contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:memory:VAL_NAMESPACE_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:memory:VAL_NAMESPACE_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory._validate_session
-- @brief Validate session identifier format.
-- @param p_value Session ID to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-1024 characters.
CREATE OR REPLACE FUNCTION memory._validate_session(p_value text)
RETURNS void AS $$
BEGIN
    CASE memory._name_violation(p_value, 1024)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Session cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:memory:VAL_SESSION_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Session cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:memory:VAL_SESSION_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Session exceeds maximum length of 1024 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:memory:VAL_SESSION_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Session contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:memory:VAL_SESSION_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Session cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:memory:VAL_SESSION_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory._validate_role
-- @brief Validate message role format.
-- @param p_value Role to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-256 characters.
CREATE OR REPLACE FUNCTION memory._validate_role(p_value text)
RETURNS void AS $$
BEGIN
    CASE memory._name_violation(p_value, 256)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Role cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:memory:VAL_ROLE_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Role cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:memory:VAL_ROLE_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Role exceeds maximum length of 256 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:memory:VAL_ROLE_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Role contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:memory:VAL_ROLE_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Role cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:memory:VAL_ROLE_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory._validate_embed_model
-- @brief Validate embedding model identifier format.
-- @param p_value Embedding model to validate
-- Called only when embed_model IS NOT NULL. Accepts any name that passes the
-- shared name rules (see _name_violation); 1-1024 characters.
CREATE OR REPLACE FUNCTION memory._validate_embed_model(p_value text)
RETURNS void AS $$
BEGIN
    CASE memory._name_violation(p_value, 1024)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Embedding model cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:memory:VAL_EMBED_MODEL_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Embedding model cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:memory:VAL_EMBED_MODEL_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Embedding model exceeds maximum length of 1024 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:memory:VAL_EMBED_MODEL_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Embedding model contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:memory:VAL_EMBED_MODEL_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Embedding model cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:memory:VAL_EMBED_MODEL_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory._validate_content
-- @brief Validate episode or fact content is present.
-- @param p_value Content to validate
-- Content is the message or fact body and carries no length limit; only
-- null and empty are rejected, reusing the name family's ERRCODEs.
CREATE OR REPLACE FUNCTION memory._validate_content(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Content cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:memory:VAL_CONTENT_NULL';
    END IF;
    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Content cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:memory:VAL_CONTENT_EMPTY';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory._validate_positive_int
-- @brief Validate that an integer is positive.
-- @param p_value Value to validate
-- @param p_field Name of the parameter for the error message
CREATE OR REPLACE FUNCTION memory._validate_positive_int(p_value int, p_field text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL OR p_value <= 0 THEN
        RAISE EXCEPTION '% must be a positive integer', p_field
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:memory:VAL_NOT_POSITIVE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = memory, pg_temp;

CREATE OR REPLACE FUNCTION memory._validate_limit(p_value int, p_name text, p_max int)
RETURNS void AS $$
BEGIN
    PERFORM memory._validate_positive_int(p_value, p_name);
    IF p_value > p_max THEN
        RAISE EXCEPTION '% (%) exceeds maximum of %', p_name, p_value, p_max
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:memory:VAL_LIMIT_TOO_LARGE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = memory, pg_temp;

CREATE OR REPLACE FUNCTION memory._validate_batch_size(p_size int, p_name text, p_max int DEFAULT 1000)
RETURNS void AS $$
BEGIN
    IF p_size > p_max THEN
        RAISE EXCEPTION '% contains % items; maximum is %', p_name, p_size, p_max
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:memory:VAL_BATCH_TOO_LARGE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory._validate_kind
-- @brief Validate a node kind against the allowed vocabulary.
-- @param p_value Kind to validate ('fact' or 'entity')
CREATE OR REPLACE FUNCTION memory._validate_kind(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL OR p_value NOT IN ('fact', 'entity') THEN
        RAISE EXCEPTION 'Node kind must be one of: fact, entity'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:memory:VAL_KIND_INVALID';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory._validate_relation
-- @brief Validate an edge relation against the allowed vocabulary.
-- @param p_value Relation to validate ('entity', 'causal' or 'assoc')
CREATE OR REPLACE FUNCTION memory._validate_relation(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL OR p_value NOT IN ('entity', 'causal', 'assoc') THEN
        RAISE EXCEPTION 'Edge relation must be one of: entity, causal, assoc'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:memory:VAL_RELATION_INVALID';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory._warn_namespace_mismatch
-- @brief Warns if namespace doesn't match RLS tenant context.
-- @param p_namespace The namespace being queried
-- Called at start of query functions to alert developers of likely misconfiguration.
CREATE OR REPLACE FUNCTION memory._warn_namespace_mismatch(p_namespace text)
RETURNS void AS $$
DECLARE
    v_tenant_id text;
BEGIN
    v_tenant_id := current_setting('memory.tenant_id', true);
    IF v_tenant_id IS NOT NULL AND v_tenant_id != '' AND p_namespace != v_tenant_id THEN
        RAISE WARNING 'Querying namespace "%" but RLS tenant context is "%". Results will be empty due to row-level security.',
            p_namespace, v_tenant_id;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = memory, pg_temp;
