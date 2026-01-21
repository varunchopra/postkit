-- =============================================================================
-- AUDIT LOGGING SCHEMA FOR POSTKIT/CONFIG
-- =============================================================================

CREATE TABLE config.audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY,
    event_id uuid DEFAULT gen_random_uuid(),
    event_type text NOT NULL,
    event_time timestamptz NOT NULL DEFAULT now(),

    -- Actor context (set via config.set_actor())
    actor_id text,
    request_id text,
    reason text,
    on_behalf_of text,

    -- Tenant and resource identification
    namespace text NOT NULL,
    key text NOT NULL,
    version int,

    -- Change tracking
    old_value jsonb,
    new_value jsonb,

    PRIMARY KEY (id, event_time),

    CONSTRAINT audit_events_type_valid CHECK (event_type IN (
        'entry_created', 'entry_activated', 'entry_deleted', 'entry_version_deleted'
    ))
) PARTITION BY RANGE (event_time);

-- Indexes
CREATE INDEX audit_events_namespace_time_idx ON config.audit_events (namespace, event_time DESC);
CREATE INDEX audit_events_key_idx ON config.audit_events (namespace, key, event_time DESC);
CREATE INDEX audit_events_actor_idx ON config.audit_events (actor_id, event_time DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_events_event_id_idx ON config.audit_events (event_id);

-- RLS
ALTER TABLE config.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE config.audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_tenant_isolation ON config.audit_events
    USING (
        current_setting('config.tenant_id', TRUE) != ''
        AND namespace = current_setting('config.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('config.tenant_id', TRUE) != ''
        AND namespace = current_setting('config.tenant_id', TRUE)
    );
