-- @group Entries

-- @function config.set
-- @brief Create a new version of a config entry and activate it
-- @param p_key The config key (e.g., 'prompts/support-bot', 'flags/checkout-v2')
-- @param p_value The config value as JSON
-- @param p_namespace Namespace (default: 'default')
-- @returns New version number
-- @example SELECT config.set('prompts/support-bot', '{"template": "You are...", "model": "claude-sonnet-4-20250514"}');
-- @example SELECT config.set('flags/new-checkout', '{"enabled": true, "rollout": 0.5}');
-- @example SELECT config.set('secrets/OPENAI_API_KEY', '{"encrypted": "aes256gcm:..."}');
CREATE OR REPLACE FUNCTION config.set(
    p_key text,
    p_value jsonb,
    p_namespace text DEFAULT 'default'
)
RETURNS int
AS $$
DECLARE
    v_next_version int;
    v_old_value jsonb;
BEGIN
    PERFORM config._validate_key(p_key);
    PERFORM config._validate_namespace(p_namespace);

    INSERT INTO config.version_counters (namespace, key, max_version)
    VALUES (p_namespace, p_key, 1)
    ON CONFLICT (namespace, key)
    DO UPDATE SET max_version = config.version_counters.max_version + 1
    RETURNING max_version INTO v_next_version;

    UPDATE config.entries
    SET is_active = false
    WHERE namespace = p_namespace AND key = p_key AND is_active = true
    RETURNING value INTO v_old_value;

    INSERT INTO config.entries (namespace, key, version, value, is_active, created_by)
    VALUES (
        p_namespace,
        p_key,
        v_next_version,
        p_value,
        true,
        nullif(current_setting('config.actor_id', true), '')
    );

    PERFORM config._log_event(
        'entry_created', p_namespace, p_key, v_next_version,
        v_old_value, p_value
    );

    RETURN v_next_version;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.set_default
-- @brief Set a config value only if the key doesn't exist (for seeding/defaults)
-- @param p_key The config key
-- @param p_value The default value as JSON
-- @param p_namespace Namespace (default: 'default')
-- @returns version (1 if created, existing version if already exists), created (true if new)
-- @example -- Seed default plans
-- @example SELECT * FROM config.set_default('plans/free', '{"tokens": 10000}');
-- @example -- Won't overwrite existing value
-- @example SELECT * FROM config.set_default('plans/free', '{"tokens": 5000}'); -- returns (1, false)
CREATE OR REPLACE FUNCTION config.set_default(
    p_key text,
    p_value jsonb,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    version int,
    created boolean
)
AS $$
DECLARE
    v_existing_version int;
BEGIN
    PERFORM config._validate_key(p_key);
    PERFORM config._validate_namespace(p_namespace);
    PERFORM config._lock_key(p_namespace, p_key);

    SELECT e.version INTO v_existing_version
    FROM config.entries e
    WHERE e.namespace = p_namespace
      AND e.key = p_key
      AND e.is_active = true
    FOR UPDATE;

    IF v_existing_version IS NOT NULL THEN
        RETURN QUERY SELECT v_existing_version, false;
        RETURN;
    END IF;

    RETURN QUERY SELECT config.set(p_key, p_value, p_namespace), true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.get
-- @brief Get a config entry (active version or specific version)
-- @param p_key The config key
-- @param p_version Optional specific version (default: active version)
-- @returns value, version, created_at
--
-- PERFORMANCE: Hot path - called for every config read. Uses unique partial index
-- entries_single_active_idx on (namespace, key) WHERE is_active for O(1) lookup.
-- For high-throughput scenarios, consider application-layer caching.
--
-- @example SELECT * FROM config.get('prompts/support-bot');
-- @example SELECT * FROM config.get('prompts/support-bot', 3);
CREATE OR REPLACE FUNCTION config.get(
    p_key text,
    p_version int DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    value jsonb,
    version int,
    created_at timestamptz
)
AS $$
BEGIN
    PERFORM config._validate_key(p_key);
    PERFORM config._validate_namespace(p_namespace);
    PERFORM config._warn_namespace_mismatch(p_namespace);

    IF p_version IS NOT NULL THEN
        -- Specific version
        RETURN QUERY
        SELECT e.value, e.version, e.created_at
        FROM config.entries e
        WHERE e.namespace = p_namespace
          AND e.key = p_key
          AND e.version = p_version;
    ELSE
        -- Active version
        RETURN QUERY
        SELECT e.value, e.version, e.created_at
        FROM config.entries e
        WHERE e.namespace = p_namespace
          AND e.key = p_key
          AND e.is_active = true;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.get_batch
-- @brief Get multiple config entries in one query
-- @param p_keys Array of config keys to fetch
-- @returns key, value, version, created_at for each found key
-- @example SELECT * FROM config.get_batch(ARRAY['prompts/bot-a', 'prompts/bot-b', 'flags/checkout']);
CREATE OR REPLACE FUNCTION config.get_batch(
    p_keys text[],
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    key text,
    value jsonb,
    version int,
    created_at timestamptz
)
AS $$
BEGIN
    PERFORM config._validate_namespace(p_namespace);
    PERFORM config._validate_batch_size(cardinality(p_keys), 'keys');
    PERFORM config._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT e.key, e.value, e.version, e.created_at
    FROM config.entries e
    WHERE e.namespace = p_namespace
      AND e.key = ANY(p_keys)
      AND e.is_active = true;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.activate
-- @brief Activate a specific version (for rollback or promotion)
-- @returns True if version was found and activated
-- @example SELECT config.activate('prompts/support-bot', 2);
CREATE OR REPLACE FUNCTION config.activate(
    p_key text,
    p_version int,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_old_version int;
    v_old_value jsonb;
    v_new_value jsonb;
    v_rows_updated int;
BEGIN
    PERFORM config._validate_key(p_key);
    PERFORM config._validate_namespace(p_namespace);
    PERFORM config._lock_key(p_namespace, p_key);

    SELECT value INTO v_new_value
    FROM config.entries
    WHERE namespace = p_namespace AND key = p_key AND version = p_version
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    SELECT value, version INTO v_old_value, v_old_version
    FROM config.entries
    WHERE namespace = p_namespace AND key = p_key AND is_active = true;

    IF v_old_version = p_version THEN
        RETURN true;
    END IF;

    -- Deactivate current active version first, then activate target.
    -- Two separate UPDATEs because a single UPDATE that flips is_active
    -- on two rows can violate entries_single_active_idx - PostgreSQL
    -- checks unique indexes per-row, not per-statement, so row
    -- processing order determines whether the constraint sees a
    -- transient duplicate.
    UPDATE config.entries
    SET is_active = false
    WHERE namespace = p_namespace
      AND key = p_key
      AND is_active = true;

    UPDATE config.entries
    SET is_active = true
    WHERE namespace = p_namespace
      AND key = p_key
      AND version = p_version;

    GET DIAGNOSTICS v_rows_updated = ROW_COUNT;

    IF v_rows_updated <> 1 THEN
        RAISE EXCEPTION 'Config version disappeared during activation'
            USING ERRCODE = 'serialization_failure';
    END IF;

    IF v_old_version IS DISTINCT FROM p_version THEN
        PERFORM config._log_event(
            'entry_activated', p_namespace, p_key, p_version,
            v_old_value, v_new_value
        );
    END IF;

    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.rollback
-- @brief Activate the previous version
-- @returns New active version number, or NULL if no previous version remains
-- @example SELECT config.rollback('prompts/support-bot');
CREATE OR REPLACE FUNCTION config.rollback(
    p_key text,
    p_namespace text DEFAULT 'default'
)
RETURNS int
AS $$
DECLARE
    v_current_version int;
    v_previous_version int;
BEGIN
    PERFORM config._validate_key(p_key);
    PERFORM config._validate_namespace(p_namespace);
    PERFORM config._lock_key(p_namespace, p_key);

    SELECT version INTO v_current_version
    FROM config.entries
    WHERE namespace = p_namespace AND key = p_key AND is_active = true;

    IF v_current_version IS NULL THEN
        RETURN NULL;
    END IF;

    SELECT version INTO v_previous_version
    FROM config.entries
    WHERE namespace = p_namespace AND key = p_key AND version < v_current_version
    ORDER BY version DESC
    LIMIT 1;

    IF v_previous_version IS NULL THEN
        RETURN NULL;
    END IF;

    IF NOT config.activate(p_key, v_previous_version, p_namespace) THEN
        RETURN NULL;
    END IF;

    RETURN v_previous_version;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.list
-- @brief List all active config entries
-- @param p_prefix Optional prefix filter (e.g., 'prompts/' to list all prompts)
-- @param p_limit Max results (default 100, max 1000)
-- @param p_cursor Pagination cursor (last key from previous page)
-- @returns key, value, version, created_at
-- @example SELECT * FROM config.list();
-- @example SELECT * FROM config.list('prompts/');
-- @example SELECT * FROM config.list('flags/');
CREATE OR REPLACE FUNCTION config.list(
    p_prefix text DEFAULT NULL,
    p_namespace text DEFAULT 'default',
    p_limit int DEFAULT 100,
    p_cursor text DEFAULT NULL
)
RETURNS TABLE(
    key text,
    value jsonb,
    version int,
    created_at timestamptz
)
AS $$
BEGIN
    PERFORM config._validate_namespace(p_namespace);
    PERFORM config._warn_namespace_mismatch(p_namespace);

    PERFORM config._validate_limit(p_limit, 'limit', 1000);

    RETURN QUERY
    SELECT e.key, e.value, e.version, e.created_at
    FROM config.entries e
    WHERE e.namespace = p_namespace
      AND e.is_active = true
      AND (p_prefix IS NULL OR e.key LIKE config._escape_like_prefix(p_prefix) || '%' ESCAPE '\')
      AND (p_cursor IS NULL OR e.key > p_cursor)
    ORDER BY e.key
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.history
-- @brief Get version history for a key
-- @returns version, value, is_active, created_at, created_by
-- @example SELECT * FROM config.history('prompts/support-bot');
CREATE OR REPLACE FUNCTION config.history(
    p_key text,
    p_namespace text DEFAULT 'default',
    p_limit int DEFAULT 50
)
RETURNS TABLE(
    version int,
    value jsonb,
    is_active boolean,
    created_at timestamptz,
    created_by text
)
AS $$
BEGIN
    PERFORM config._validate_key(p_key);
    PERFORM config._validate_namespace(p_namespace);
    PERFORM config._warn_namespace_mismatch(p_namespace);

    PERFORM config._validate_limit(p_limit, 'limit', 1000);

    RETURN QUERY
    SELECT e.version, e.value, e.is_active, e.created_at, e.created_by
    FROM config.entries e
    WHERE e.namespace = p_namespace AND e.key = p_key
    ORDER BY e.version DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.delete
-- @brief Delete all versions of a config entry
-- @returns Count of versions deleted
-- @example SELECT config.delete('prompts/deprecated-bot');
CREATE OR REPLACE FUNCTION config.delete(
    p_key text,
    p_namespace text DEFAULT 'default'
)
RETURNS int
AS $$
DECLARE
    v_count int;
    v_active_value jsonb;
BEGIN
    PERFORM config._validate_key(p_key);
    PERFORM config._validate_namespace(p_namespace);
    PERFORM config._lock_key(p_namespace, p_key);

    SELECT value INTO v_active_value
    FROM config.entries
    WHERE namespace = p_namespace AND key = p_key AND is_active = true;

    DELETE FROM config.entries
    WHERE namespace = p_namespace AND key = p_key;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        PERFORM config._log_event(
            'entry_deleted', p_namespace, p_key, NULL,
            v_active_value, NULL
        );
    END IF;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.delete_version
-- @brief Delete a specific version (cannot delete active version)
-- @returns True if deleted
-- @example SELECT config.delete_version('prompts/support-bot', 1);
CREATE OR REPLACE FUNCTION config.delete_version(
    p_key text,
    p_version int,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_is_active boolean;
    v_count int;
    v_old_value jsonb;
BEGIN
    PERFORM config._validate_key(p_key);
    PERFORM config._validate_namespace(p_namespace);
    PERFORM config._lock_key(p_namespace, p_key);

    SELECT is_active, value INTO v_is_active, v_old_value
    FROM config.entries
    WHERE namespace = p_namespace AND key = p_key AND version = p_version;

    IF v_is_active IS NULL THEN
        RETURN false;
    END IF;

    IF v_is_active = true THEN
        RAISE EXCEPTION 'Cannot delete active version. Activate a different version first.'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:config:BIZ_DELETE_ACTIVE_VERSION';
    END IF;

    DELETE FROM config.entries
    WHERE namespace = p_namespace AND key = p_key AND version = p_version;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        PERFORM config._log_event(
            'entry_version_deleted', p_namespace, p_key, p_version,
            v_old_value, NULL
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.exists
-- @brief Check if a config key exists (has an active version)
-- @returns True if key exists and has an active version
-- @example IF config.exists('flags/new-checkout') THEN ...
CREATE OR REPLACE FUNCTION config.exists(
    p_key text,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
BEGIN
    PERFORM config._validate_key(p_key);
    PERFORM config._validate_namespace(p_namespace);

    RETURN EXISTS (
        SELECT 1 FROM config.entries
        WHERE namespace = p_namespace AND key = p_key AND is_active = true
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.get_path
-- @brief Get a specific JSON path from active config
-- @param p_key Config key
-- @param p_path JSON path as text array (e.g., ARRAY['model', 'name'])
-- @returns The value at the path, or NULL if not found
-- @example SELECT config.get_path('prompts/bot', ARRAY['temperature']);
-- @example SELECT config.get_path('flags/checkout', ARRAY['rollout']);
CREATE OR REPLACE FUNCTION config.get_path(
    p_key text,
    p_path text[],
    p_namespace text DEFAULT 'default'
)
RETURNS jsonb
AS $$
BEGIN
    PERFORM config._validate_key(p_key);
    PERFORM config._validate_namespace(p_namespace);
    PERFORM config._warn_namespace_mismatch(p_namespace);

    RETURN (
        SELECT value #> p_path
        FROM config.entries
        WHERE namespace = p_namespace
          AND key = p_key
          AND is_active = true
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.merge
-- @brief Merge changes into config, creating new version
-- @param p_key Config key
-- @param p_changes JSON object with fields to merge (shallow merge)
-- @returns New version number
-- @example SELECT config.merge('prompts/bot', '{"temperature": 0.8}');
-- @example SELECT config.merge('flags/checkout', '{"rollout": 0.75}');
CREATE OR REPLACE FUNCTION config.merge(
    p_key text,
    p_changes jsonb,
    p_namespace text DEFAULT 'default'
)
RETURNS int
AS $$
DECLARE
    v_current jsonb;
    v_merged jsonb;
BEGIN
    PERFORM config._validate_key(p_key);
    PERFORM config._validate_namespace(p_namespace);
    PERFORM config._lock_key(p_namespace, p_key);

    SELECT value INTO v_current
    FROM config.entries
    WHERE namespace = p_namespace AND key = p_key AND is_active = true
    FOR UPDATE;

    IF v_current IS NULL THEN
        RETURN config.set(p_key, p_changes, p_namespace);
    END IF;

    v_merged := v_current || p_changes;

    RETURN config.set(p_key, v_merged, p_namespace);
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.search
-- @brief Find configs where value contains given JSON
-- @param p_contains JSON to search for (uses containment operator)
-- @param p_prefix Optional key prefix filter
-- @returns Matching entries with key, value, version, created_at
-- @example SELECT * FROM config.search('{"enabled": true}');
-- @example SELECT * FROM config.search('{"model": "claude-sonnet-4-20250514"}', 'prompts/');
CREATE OR REPLACE FUNCTION config.search(
    p_contains jsonb,
    p_prefix text DEFAULT NULL,
    p_namespace text DEFAULT 'default',
    p_limit int DEFAULT 100
)
RETURNS TABLE(key text, value jsonb, version int, created_at timestamptz)
AS $$
BEGIN
    PERFORM config._validate_namespace(p_namespace);
    PERFORM config._warn_namespace_mismatch(p_namespace);

    PERFORM config._validate_limit(p_limit, 'limit', 1000);

    RETURN QUERY
    SELECT e.key, e.value, e.version, e.created_at
    FROM config.entries e
    WHERE e.namespace = p_namespace
      AND e.is_active = true
      AND e.value @> p_contains
      AND (p_prefix IS NULL OR e.key LIKE config._escape_like_prefix(p_prefix) || '%' ESCAPE '\')
    ORDER BY e.key
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = config, pg_temp;
