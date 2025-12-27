-- =============================================================================
-- AUDIT FUNCTIONS FOR POSTKIT/AUTHN
-- =============================================================================
-- Actor context and partition management for audit logs.
-- =============================================================================


-- =============================================================================
-- SET ACTOR CONTEXT
-- =============================================================================
-- Sets transaction-local context that will be captured in audit events.
-- Call this at the start of an operation to record who made changes.
CREATE OR REPLACE FUNCTION authn.set_actor(
    p_actor_id text,
    p_request_id text DEFAULT NULL,
    p_ip_address text DEFAULT NULL,
    p_user_agent text DEFAULT NULL
)
RETURNS void
AS $$
BEGIN
    -- Validate IP address format if provided (fail early, not during audit insert)
    IF p_ip_address IS NOT NULL AND p_ip_address != '' THEN
        BEGIN
            PERFORM p_ip_address::inet;
        EXCEPTION WHEN invalid_text_representation THEN
            RAISE EXCEPTION 'ip_address must be valid (got: %)', p_ip_address
                USING ERRCODE = 'invalid_parameter_value';
        END;
    END IF;

    PERFORM set_config('authn.actor_id', COALESCE(p_actor_id, ''), true);
    PERFORM set_config('authn.request_id', COALESCE(p_request_id, ''), true);
    PERFORM set_config('authn.ip_address', COALESCE(p_ip_address, ''), true);
    PERFORM set_config('authn.user_agent', COALESCE(p_user_agent, ''), true);
END;
$$ LANGUAGE plpgsql SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.set_actor(text, text, text, text) IS
'Sets transaction-local actor context for audit logging.';


-- =============================================================================
-- CLEAR ACTOR CONTEXT
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.clear_actor()
RETURNS void
AS $$
BEGIN
    PERFORM set_config('authn.actor_id', '', true);
    PERFORM set_config('authn.request_id', '', true);
    PERFORM set_config('authn.ip_address', '', true);
    PERFORM set_config('authn.user_agent', '', true);
END;
$$ LANGUAGE plpgsql SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.clear_actor() IS
'Clears transaction-local actor context.';


-- =============================================================================
-- CREATE AUDIT PARTITION
-- =============================================================================
-- Creates a partition for a specific year/month.
-- Safe to call multiple times (returns NULL if partition exists).
CREATE OR REPLACE FUNCTION authn.create_audit_partition(
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
    -- Validate inputs
    IF p_year < 1970 OR p_year > 9999 THEN
        RAISE EXCEPTION 'Year must be between 1970 and 9999, got %', p_year
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_month < 1 OR p_month > 12 THEN
        RAISE EXCEPTION 'Month must be between 1 and 12, got %', p_month
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Build partition name
    v_partition_name := format('audit_events_y%sm%s',
        to_char(p_year, 'FM0000'),
        to_char(p_month, 'FM00'));

    -- Calculate date range
    v_start_date := make_date(p_year, p_month, 1);
    v_end_date := v_start_date + interval '1 month';

    -- Check if partition already exists
    IF EXISTS (
        SELECT 1
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'authn'
          AND c.relname = v_partition_name
    ) THEN
        RETURN NULL;  -- Already exists
    END IF;

    -- Create the partition
    EXECUTE format(
        'CREATE TABLE authn.%I PARTITION OF authn.audit_events
         FOR VALUES FROM (%L) TO (%L)',
        v_partition_name, v_start_date, v_end_date
    );

    RETURN v_partition_name;
END;
$$ LANGUAGE plpgsql SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.create_audit_partition(int, int) IS
'Creates an audit partition for a specific year/month.';


-- =============================================================================
-- ENSURE AUDIT PARTITIONS
-- =============================================================================
-- Creates partitions from current month through N months ahead.
-- Run this periodically (e.g., monthly via cron) to ensure partitions exist.
CREATE OR REPLACE FUNCTION authn.ensure_audit_partitions(
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
        v_result := authn.create_audit_partition(
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
$$ LANGUAGE plpgsql SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.ensure_audit_partitions(int) IS
'Creates audit partitions for current month through N months ahead.';


-- =============================================================================
-- DROP AUDIT PARTITIONS
-- =============================================================================
-- Drops partitions older than the specified threshold.
-- Default retention is 84 months (7 years) per common compliance requirements:
--   - SOX: 7 years for financial records
--   - HIPAA: 6 years minimum
--   - GDPR: "no longer than necessary" (7 years is defensible)
CREATE OR REPLACE FUNCTION authn.drop_audit_partitions(
    p_older_than_months int DEFAULT 84  -- 7 years
)
RETURNS SETOF text
AS $$
DECLARE
    v_cutoff date;
    v_partition RECORD;
    v_partition_end date;
BEGIN
    v_cutoff := date_trunc('month', CURRENT_DATE)::date - (p_older_than_months || ' months')::interval;

    -- Find all audit_events partitions
    FOR v_partition IN
        SELECT c.relname AS name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class parent ON parent.oid = i.inhparent
        WHERE n.nspname = 'authn'
          AND parent.relname = 'audit_events'
          AND c.relname LIKE 'audit_events_y%'
        ORDER BY c.relname
    LOOP
        -- Validate partition name format
        IF v_partition.name !~ '^audit_events_y\d{4}m\d{2}$' THEN
            RAISE WARNING 'Skipping partition with unexpected name format: %', v_partition.name;
            CONTINUE;
        END IF;

        -- Extract year and month from partition name
        v_partition_end := make_date(
            substring(v_partition.name FROM 15 FOR 4)::int,
            substring(v_partition.name FROM 20 FOR 2)::int,
            1
        ) + interval '1 month';

        -- Drop if partition ends before cutoff
        IF v_partition_end <= v_cutoff THEN
            EXECUTE format('DROP TABLE authn.%I', v_partition.name);
            RETURN NEXT v_partition.name;
        END IF;
    END LOOP;

    RETURN;
END;
$$ LANGUAGE plpgsql SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.drop_audit_partitions(int) IS
'Drops audit partitions older than N months. Default 84 (7 years).';


-- =============================================================================
-- INITIALIZE PARTITIONS
-- =============================================================================
-- Create initial partitions (current month + 3 months ahead)
SELECT authn.ensure_audit_partitions(3);
