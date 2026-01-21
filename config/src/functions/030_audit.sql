-- @group Audit

-- @function config.set_actor
-- @brief Set actor context for audit logging
-- @param p_actor_id The actor making changes (e.g., 'user:admin-bob', 'agent:deploy-bot')
-- @param p_request_id Optional request/correlation ID for tracing
-- @param p_on_behalf_of Optional principal being represented (e.g., 'user:customer-alice')
-- @param p_reason Optional reason for the action (e.g., 'deployment:v1.2.3')
-- @example SELECT config.set_actor('user:admin-bob', on_behalf_of := 'user:customer-alice');
CREATE OR REPLACE FUNCTION config.set_actor(
    p_actor_id text,
    p_request_id text DEFAULT NULL,
    p_on_behalf_of text DEFAULT NULL,
    p_reason text DEFAULT NULL
)
RETURNS void
AS $$
BEGIN
    PERFORM set_config('config.actor_id', COALESCE(p_actor_id, ''), true);
    PERFORM set_config('config.request_id', COALESCE(p_request_id, ''), true);
    PERFORM set_config('config.on_behalf_of', COALESCE(p_on_behalf_of, ''), true);
    PERFORM set_config('config.reason', COALESCE(p_reason, ''), true);
END;
$$ LANGUAGE plpgsql SET search_path = config, pg_temp;


-- @function config.clear_actor
-- @brief Clear actor context
CREATE OR REPLACE FUNCTION config.clear_actor()
RETURNS void
AS $$
BEGIN
    PERFORM set_config('config.actor_id', '', true);
    PERFORM set_config('config.request_id', '', true);
    PERFORM set_config('config.on_behalf_of', '', true);
    PERFORM set_config('config.reason', '', true);
END;
$$ LANGUAGE plpgsql SET search_path = config, pg_temp;


-- @function config.create_audit_partition
-- @brief Create a monthly partition for audit events
-- @param p_year The year (e.g., 2024)
-- @param p_month The month (1-12)
-- @returns Partition name if created, NULL if already exists
CREATE OR REPLACE FUNCTION config.create_audit_partition(
    p_year int,
    p_month int
)
RETURNS text
AS $$
DECLARE
    v_partition_name text;
    v_start_date date;
    v_end_date date;
BEGIN
    IF p_year < 1970 OR p_year > 9999 THEN
        RAISE EXCEPTION 'Year must be between 1970 and 9999'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:config:VAL_YEAR_OUT_OF_RANGE';
    END IF;
    IF p_month < 1 OR p_month > 12 THEN
        RAISE EXCEPTION 'Month must be between 1 and 12'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:config:VAL_MONTH_OUT_OF_RANGE';
    END IF;

    v_partition_name := format('audit_events_y%sm%s',
        to_char(p_year, 'FM0000'),
        to_char(p_month, 'FM00'));

    v_start_date := make_date(p_year, p_month, 1);
    v_end_date := v_start_date + interval '1 month';

    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'config' AND c.relname = v_partition_name
    ) THEN
        RETURN NULL;
    END IF;

    EXECUTE format(
        'CREATE TABLE config.%I PARTITION OF config.audit_events FOR VALUES FROM (%L) TO (%L)',
        v_partition_name, v_start_date, v_end_date
    );

    RETURN v_partition_name;
END;
$$ LANGUAGE plpgsql SET search_path = config, pg_temp;


-- @function config.ensure_audit_partitions
-- @brief Create partitions for upcoming months
-- @param p_months_ahead Number of months ahead to create partitions for (default 3)
-- @returns Names of created partitions
CREATE OR REPLACE FUNCTION config.ensure_audit_partitions(
    p_months_ahead int DEFAULT 3
)
RETURNS SETOF text
AS $$
DECLARE
    v_current date;
    v_target date;
    v_result text;
BEGIN
    v_current := date_trunc('month', CURRENT_DATE)::date;
    v_target := v_current + (p_months_ahead || ' months')::interval;

    WHILE v_current <= v_target LOOP
        v_result := config.create_audit_partition(
            EXTRACT(YEAR FROM v_current)::int,
            EXTRACT(MONTH FROM v_current)::int
        );
        IF v_result IS NOT NULL THEN
            RETURN NEXT v_result;
        END IF;
        v_current := v_current + interval '1 month';
    END LOOP;

    RETURN;
END;
$$ LANGUAGE plpgsql SET search_path = config, pg_temp;


-- @function config.drop_audit_partitions
-- @brief Delete old audit partitions
-- @param p_keep_months Number of months to keep (default 84 = 7 years)
-- @returns Names of dropped partitions
CREATE OR REPLACE FUNCTION config.drop_audit_partitions(
    p_keep_months int DEFAULT 84
)
RETURNS SETOF text
AS $$
DECLARE
    v_cutoff_date date;
    v_partition record;
    v_partition_date date;
BEGIN
    v_cutoff_date := date_trunc('month', CURRENT_DATE - (p_keep_months || ' months')::interval)::date;

    FOR v_partition IN
        SELECT c.relname as partition_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class parent ON parent.oid = i.inhparent
        WHERE n.nspname = 'config'
          AND parent.relname = 'audit_events'
          AND c.relname ~ '^audit_events_y[0-9]{4}m[0-9]{2}$'
    LOOP
        -- Extract date from partition name (audit_events_y2024m01 -> 2024-01-01)
        v_partition_date := make_date(
            substring(v_partition.partition_name FROM 15 FOR 4)::int,  -- year
            substring(v_partition.partition_name FROM 20 FOR 2)::int,  -- month
            1
        );

        IF v_partition_date < v_cutoff_date THEN
            EXECUTE format('DROP TABLE config.%I', v_partition.partition_name);
            RETURN NEXT v_partition.partition_name;
        END IF;
    END LOOP;

    RETURN;
END;
$$ LANGUAGE plpgsql SET search_path = config, pg_temp;


-- Initialize partitions for current and upcoming months
SELECT config.ensure_audit_partitions(3);
