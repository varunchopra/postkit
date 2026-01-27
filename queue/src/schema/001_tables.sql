-- =============================================================================
-- SCHEMA AND TABLES FOR POSTKIT/QUEUE
-- =============================================================================
-- Postgres-native job queues with multi-tenant support.
-- Jobs commit or rollback with your transaction.
--
-- Design principles:
--   1. Transactional: Jobs enqueue atomically with your data
--   2. Multi-tenant: Namespace isolation via RLS
--   3. Concurrent-safe: SKIP LOCKED for efficient worker distribution
--   4. Deduplication: Optional unique_key prevents duplicate jobs
--   5. Visibility timeout: Jobs auto-return to queue if worker dies

CREATE SCHEMA IF NOT EXISTS queue;

-- =============================================================================
-- JOBS TABLE
-- =============================================================================
-- Main job storage. Status transitions:
--   pending -> running -> completed (success)
--   pending -> running -> pending (nack/timeout, retry)
--   pending -> running -> dead (max attempts exceeded or explicit fail)

CREATE TABLE queue.jobs (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    namespace text NOT NULL,
    queue text NOT NULL,

    -- Job content
    payload jsonb NOT NULL,

    -- Scheduling
    priority int NOT NULL DEFAULT 0,           -- Higher = processed first
    scheduled_at timestamptz NOT NULL DEFAULT now(),  -- Visible after this time

    -- State machine
    status text NOT NULL DEFAULT 'pending',
    attempts int NOT NULL DEFAULT 0,
    max_attempts int NOT NULL DEFAULT 3,

    -- Locking (for running jobs)
    locked_by text,                            -- Worker ID for debugging
    locked_at timestamptz,
    visibility_timeout_at timestamptz,         -- Job returns to pending after this

    -- Completion
    completed_at timestamptz,
    error text,

    -- Deduplication
    unique_key text,                           -- NULL = no dedup

    -- Metadata
    tags text[] DEFAULT '{}',
    metadata jsonb,

    -- Actor context (captured at push time)
    actor_id text,
    request_id text,

    -- Timestamps
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    -- Constraints
    CONSTRAINT jobs_status_valid CHECK (
        status IN ('pending', 'running', 'completed', 'dead')
    ),
    CONSTRAINT jobs_locked_consistency CHECK (
        (status = 'running' AND locked_by IS NOT NULL AND locked_at IS NOT NULL AND visibility_timeout_at IS NOT NULL)
        OR (status != 'running' AND locked_by IS NULL AND locked_at IS NULL AND visibility_timeout_at IS NULL)
    ),
    CONSTRAINT jobs_completed_consistency CHECK (
        (status IN ('completed', 'dead') AND completed_at IS NOT NULL)
        OR (status NOT IN ('completed', 'dead') AND completed_at IS NULL)
    ),
    CONSTRAINT jobs_priority_range CHECK (priority BETWEEN -1000 AND 1000)
);

-- Critical index for pull() - must be efficient for concurrent workers
-- Covers: WHERE namespace = X AND queue = Y AND status = 'pending' AND scheduled_at <= now()
-- ORDER BY priority DESC, scheduled_at, id
CREATE INDEX jobs_pull_idx ON queue.jobs (namespace, queue, priority DESC, scheduled_at, id)
    WHERE status = 'pending';

-- Deduplication: unique_key must be unique per namespace/queue for active jobs
CREATE UNIQUE INDEX jobs_unique_key_idx ON queue.jobs (namespace, queue, unique_key)
    WHERE unique_key IS NOT NULL AND status IN ('pending', 'running');

-- Timeout recovery: find jobs with expired visibility
CREATE INDEX jobs_timeout_idx ON queue.jobs (visibility_timeout_at)
    WHERE status = 'running';

-- Queue listing and stats
CREATE INDEX jobs_namespace_queue_idx ON queue.jobs (namespace, queue);

-- =============================================================================
-- DEAD LETTERS TABLE
-- =============================================================================
-- Jobs that exceeded max_attempts or were explicitly failed.
-- Retained for debugging and manual retry.

CREATE TABLE queue.dead_letters (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    namespace text NOT NULL,
    queue text NOT NULL,
    original_job_id bigint NOT NULL,

    -- Original job data
    payload jsonb NOT NULL,
    priority int NOT NULL,
    tags text[] DEFAULT '{}',
    metadata jsonb,

    -- Failure info
    failed_at timestamptz NOT NULL DEFAULT now(),
    attempts int NOT NULL,
    last_error text,

    -- Retry tracking
    retried_at timestamptz,                    -- When retry was initiated
    retry_job_id bigint,                       -- New job ID if retried

    -- Actor context from original push
    actor_id text,
    request_id text,

    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX dead_letters_queue_idx ON queue.dead_letters (namespace, queue, failed_at DESC);

-- =============================================================================
-- SCHEDULES TABLE
-- =============================================================================
-- Recurring job definitions. External scheduler calls tick_schedules() periodically.
-- Supports either cron expression OR interval, not both.

CREATE TABLE queue.schedules (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    namespace text NOT NULL,
    name text NOT NULL,                        -- Unique per namespace
    queue text NOT NULL,

    -- Job template
    payload jsonb NOT NULL,
    priority int NOT NULL DEFAULT 0,
    max_attempts int NOT NULL DEFAULT 3,
    tags text[] DEFAULT '{}',

    -- Schedule definition (mutually exclusive)
    cron_expression text,                      -- Standard 5-field cron
    cron_timezone text DEFAULT 'UTC',
    every_interval interval,                   -- Alternative to cron

    -- State
    is_active boolean NOT NULL DEFAULT true,

    -- Execution tracking
    last_run_at timestamptz,
    last_job_id bigint,
    next_run_at timestamptz,
    run_count bigint NOT NULL DEFAULT 0,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT schedules_name_unique UNIQUE (namespace, name),
    CONSTRAINT schedules_has_schedule CHECK (
        (cron_expression IS NOT NULL AND every_interval IS NULL)
        OR (cron_expression IS NULL AND every_interval IS NOT NULL)
    ),
    CONSTRAINT schedules_cron_has_timezone CHECK (
        cron_expression IS NULL OR cron_timezone IS NOT NULL
    ),
    CONSTRAINT schedules_priority_range CHECK (priority BETWEEN -1000 AND 1000)
);

CREATE INDEX schedules_next_run_idx ON queue.schedules (namespace, next_run_at)
    WHERE is_active = true;

-- =============================================================================
-- CONFIG TABLE
-- =============================================================================
-- Per-tenant configuration with global defaults.
-- 'global' row provides defaults; tenants can override with their own row.

CREATE TABLE queue.config (
    namespace text NOT NULL PRIMARY KEY,
    archive_completed boolean NOT NULL DEFAULT false,      -- Keep completed jobs?
    notify_on_push boolean NOT NULL DEFAULT true,          -- NOTIFY on push?
    default_visibility_timeout interval NOT NULL DEFAULT '5 minutes',
    default_max_attempts int NOT NULL DEFAULT 3,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Global defaults (read by all, write-protected via RLS)
INSERT INTO queue.config (namespace) VALUES ('global') ON CONFLICT DO NOTHING;

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================
-- Fail-closed: empty tenant context returns zero rows.
-- current_setting(..., TRUE) returns '' when not set.

-- Jobs: standard tenant isolation
ALTER TABLE queue.jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE queue.jobs FORCE ROW LEVEL SECURITY;

CREATE POLICY jobs_tenant_isolation ON queue.jobs
    USING (
        current_setting('queue.tenant_id', TRUE) != ''
        AND namespace = current_setting('queue.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('queue.tenant_id', TRUE) != ''
        AND namespace = current_setting('queue.tenant_id', TRUE)
    );

-- Dead letters: standard tenant isolation
ALTER TABLE queue.dead_letters ENABLE ROW LEVEL SECURITY;
ALTER TABLE queue.dead_letters FORCE ROW LEVEL SECURITY;

CREATE POLICY dead_letters_tenant_isolation ON queue.dead_letters
    USING (
        current_setting('queue.tenant_id', TRUE) != ''
        AND namespace = current_setting('queue.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('queue.tenant_id', TRUE) != ''
        AND namespace = current_setting('queue.tenant_id', TRUE)
    );

-- Schedules: standard tenant isolation
ALTER TABLE queue.schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE queue.schedules FORCE ROW LEVEL SECURITY;

CREATE POLICY schedules_tenant_isolation ON queue.schedules
    USING (
        current_setting('queue.tenant_id', TRUE) != ''
        AND namespace = current_setting('queue.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('queue.tenant_id', TRUE) != ''
        AND namespace = current_setting('queue.tenant_id', TRUE)
    );

-- Config: global readable, tenant can only write their own row
ALTER TABLE queue.config ENABLE ROW LEVEL SECURITY;
ALTER TABLE queue.config FORCE ROW LEVEL SECURITY;

-- All tenants can read global config
CREATE POLICY config_global_read ON queue.config
    FOR SELECT
    USING (namespace = 'global');

-- Tenants can read/write their own config
CREATE POLICY config_tenant_isolation ON queue.config
    USING (
        current_setting('queue.tenant_id', TRUE) != ''
        AND namespace = current_setting('queue.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('queue.tenant_id', TRUE) != ''
        AND namespace = current_setting('queue.tenant_id', TRUE)
    );

-- Prevent any tenant from writing to global (RESTRICTIVE policy)
CREATE POLICY config_global_write_protection ON queue.config
    AS RESTRICTIVE
    FOR ALL
    USING (TRUE)
    WITH CHECK (namespace != 'global');
