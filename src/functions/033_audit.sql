-- =============================================================================
-- AUDIT FUNCTIONS
-- =============================================================================
--
-- Functions for setting actor context and managing audit partitions.
--
-- =============================================================================
-- =============================================================================
-- SET ACTOR CONTEXT
-- =============================================================================
--
-- PURPOSE
-- -------
-- Sets transaction-local context that will be captured in audit events.
-- Call this at the start of an operation to record who made changes.
--
-- SCOPE
-- =====
-- Context is transaction-local (set_config with is_local=true).
-- It automatically clears when the transaction commits or rolls back.
--
-- EXAMPLE
-- =======
--   SELECT authz.set_actor('admin@acme.com', 'req-abc123', 'Quarterly review');
--   SELECT authz.write('repo', 'api', 'admin', 'team', 'eng');
--   -- Audit event will include actor_id, request_id, and reason
CREATE OR REPLACE FUNCTION authz.set_actor (p_actor_id text, p_request_id text DEFAULT NULL, p_reason text DEFAULT NULL)
    RETURNS VOID
    AS $$
BEGIN
    PERFORM
        set_config('authz.actor_id', COALESCE(p_actor_id, ''), TRUE);
    PERFORM
        set_config('authz.request_id', COALESCE(p_request_id, ''), TRUE);
    PERFORM
        set_config('authz.reason', COALESCE(p_reason, ''), TRUE);
END;
$$
LANGUAGE plpgsql
SET search_path = authz, pg_temp;

-- =============================================================================
-- CREATE AUDIT PARTITION
-- =============================================================================
--
-- PURPOSE
-- -------
-- Creates a partition for a specific year/month.
-- Safe to call multiple times (returns NULL if partition exists).
--
-- NAMING
-- ======
-- Partitions are named: audit_events_y{YYYY}m{MM}
-- Example: audit_events_y2024m01 for January 2024
CREATE OR REPLACE FUNCTION authz.create_audit_partition (p_year int, p_month int)
    RETURNS text
    AS $$
DECLARE
    v_partition_name text;
    v_start_date date;
    v_end_date date;
BEGIN
    -- Validate inputs
    IF p_month < 1 OR p_month > 12 THEN
        RAISE EXCEPTION 'Month must be between 1 and 12, got %', p_month;
    END IF;
    -- Build partition name
    v_partition_name := format('audit_events_y%sm%s', to_char(p_year, 'FM0000'), to_char(p_month, 'FM00'));
    -- Calculate date range
    v_start_date := make_date(p_year, p_month, 1);
    v_end_date := v_start_date + interval '1 month';
    -- Check if partition already exists
    IF EXISTS (
        SELECT
            1
        FROM
            pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE
            n.nspname = 'authz'
            AND c.relname = v_partition_name) THEN
    RETURN NULL;
    -- Already exists
END IF;
    -- Create the partition
    EXECUTE format('CREATE TABLE authz.%I PARTITION OF authz.audit_events
         FOR VALUES FROM (%L) TO (%L)', v_partition_name, v_start_date, v_end_date);
    RETURN v_partition_name;
END;
$$
LANGUAGE plpgsql
SET search_path = authz, pg_temp;

-- =============================================================================
-- ENSURE AUDIT PARTITIONS
-- =============================================================================
--
-- PURPOSE
-- -------
-- Creates partitions from current month through N months ahead.
-- Run this periodically (e.g., monthly via cron) to ensure partitions exist.
--
-- RETURNS
-- =======
-- Names of newly created partitions (empty if all already exist).
CREATE OR REPLACE FUNCTION authz.ensure_audit_partitions (p_months_ahead int DEFAULT 3)
    RETURNS SETOF TEXT
    AS $$
DECLARE
    v_current date;
    v_target date;
    v_result text;
BEGIN
    v_current := date_trunc('month', CURRENT_DATE)::date;
    v_target := v_current + (p_months_ahead || ' months')::interval;
    WHILE v_current <= v_target LOOP
        v_result := authz.create_audit_partition (EXTRACT(YEAR FROM v_current)::int, EXTRACT(MONTH FROM v_current)::int);
        IF v_result IS NOT NULL THEN
            RETURN NEXT v_result;
        END IF;
        v_current := v_current + interval '1 month';
    END LOOP;
    RETURN;
END;
$$
LANGUAGE plpgsql
SET search_path = authz, pg_temp;

-- =============================================================================
-- DROP AUDIT PARTITIONS
-- =============================================================================
--
-- PURPOSE
-- -------
-- Drops partitions older than the specified threshold.
-- Default is 84 months (7 years) for compliance requirements.
--
-- SAFETY
-- ======
-- Only drops partitions whose END date is before the cutoff.
-- This means data from the threshold month is preserved.
--
-- RETURNS
-- =======
-- Names of dropped partitions.
CREATE OR REPLACE FUNCTION authz.drop_audit_partitions (p_older_than_months int DEFAULT 84)
    RETURNS SETOF TEXT
    AS $$
DECLARE
    v_cutoff date;
    v_partition RECORD;
    v_partition_end date;
BEGIN
    v_cutoff := date_trunc('month', CURRENT_DATE)::date - (p_older_than_months || ' months')::interval;
    -- Find all audit_events partitions
    FOR v_partition IN
    SELECT
        c.relname AS name
    FROM
        pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class parent ON parent.oid = i.inhparent
    WHERE
        n.nspname = 'authz'
        AND parent.relname = 'audit_events'
        AND c.relname LIKE 'audit_events_y%'
    ORDER BY
        c.relname LOOP
            -- Validate partition name format before parsing
            -- Expected: audit_events_yYYYYmMM (21 chars, e.g., audit_events_y2024m01)
            IF v_partition.name !~ '^audit_events_y\d{4}m\d{2}$' THEN
                RAISE WARNING 'Skipping partition with unexpected name format: %', v_partition.name;
                CONTINUE;
            END IF;

            -- Extract year and month from partition name
            -- Format: audit_events_yYYYYmMM
            --         123456789012345678901
            --                  1111111111222
            -- Year at positions 15-18, month at positions 20-21
            v_partition_end := make_date(
                substring(v_partition.name FROM 15 FOR 4)::int,
                substring(v_partition.name FROM 20 FOR 2)::int,
                1
            ) + interval '1 month';
            -- Drop if partition ends before cutoff
            IF v_partition_end <= v_cutoff THEN
                EXECUTE format('DROP TABLE authz.%I', v_partition.name);
                RETURN NEXT v_partition.name;
            END IF;
        END LOOP;
    RETURN;
END;
$$
LANGUAGE plpgsql
SET search_path = authz, pg_temp;

-- =============================================================================
-- INITIALIZE PARTITIONS
-- =============================================================================
-- Create initial partitions (current month + 3 months ahead)
SELECT
    authz.ensure_audit_partitions (3);
