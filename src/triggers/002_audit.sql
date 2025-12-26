-- =============================================================================
-- AUDIT TRIGGERS
-- =============================================================================
--
-- PURPOSE
-- -------
-- Automatically logs all tuple and hierarchy changes to authz.audit_events.
-- Captures both the change data and actor/connection context.
--
-- TRIGGER TIMING
-- ==============
-- AFTER INSERT OR UPDATE OR DELETE - we log after the change succeeds.
-- FOR EACH ROW - we need individual row data for the audit log.
--
-- SECURITY
-- ========
-- SECURITY DEFINER ensures the trigger can insert into audit_events
-- regardless of the caller's permissions.
--
-- =============================================================================

-- =============================================================================
-- TUPLE AUDIT TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION authz._audit_tuple_trigger()
RETURNS TRIGGER AS $$
DECLARE
    v_event_type TEXT;
    v_tuple RECORD;
    v_actor_id TEXT;
    v_request_id TEXT;
    v_reason TEXT;
BEGIN
    -- Determine event type and get the tuple record
    IF TG_OP = 'INSERT' THEN
        v_event_type := 'tuple_created';
        v_tuple := NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        v_event_type := 'tuple_updated';
        v_tuple := NEW;
    ELSIF TG_OP = 'DELETE' THEN
        v_event_type := 'tuple_deleted';
        v_tuple := OLD;
    ELSE
        -- Should never happen, but guard anyway
        RETURN NULL;
    END IF;

    -- Read actor context from transaction-local settings
    -- nullif converts empty strings to NULL
    v_actor_id := nullif(current_setting('authz.actor_id', true), '');
    v_request_id := nullif(current_setting('authz.request_id', true), '');
    v_reason := nullif(current_setting('authz.reason', true), '');

    -- Insert audit event
    INSERT INTO authz.audit_events (
        event_type,
        actor_id,
        request_id,
        reason,
        namespace,
        resource_type,
        resource_id,
        relation,
        subject_type,
        subject_id,
        subject_relation,
        tuple_id,
        expires_at
    ) VALUES (
        v_event_type,
        v_actor_id,
        v_request_id,
        v_reason,
        v_tuple.namespace,
        v_tuple.resource_type,
        v_tuple.resource_id,
        v_tuple.relation,
        v_tuple.subject_type,
        v_tuple.subject_id,
        v_tuple.subject_relation,
        v_tuple.id,
        v_tuple.expires_at
    );

    -- Return the tuple
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql
   SECURITY DEFINER
   SET search_path = authz, pg_temp;


-- =============================================================================
-- HIERARCHY AUDIT TRIGGER
-- =============================================================================
--
-- For hierarchy events, we map the fields as follows:
--   - resource_id: the permission (e.g., 'admin')
--   - relation: the implied permission (e.g., 'read')
--   - subject_type: 'hierarchy' (marker)
--   - subject_id: empty string
--
-- This allows consistent querying across tuple and hierarchy events.

CREATE OR REPLACE FUNCTION authz._audit_hierarchy_trigger()
RETURNS TRIGGER AS $$
DECLARE
    v_event_type TEXT;
    v_hierarchy RECORD;
    v_actor_id TEXT;
    v_request_id TEXT;
    v_reason TEXT;
BEGIN
    -- Determine event type and get the hierarchy record
    IF TG_OP = 'INSERT' THEN
        v_event_type := 'hierarchy_created';
        v_hierarchy := NEW;
    ELSIF TG_OP = 'DELETE' THEN
        v_event_type := 'hierarchy_deleted';
        v_hierarchy := OLD;
    ELSE
        RETURN NULL;
    END IF;

    -- Read actor context
    v_actor_id := nullif(current_setting('authz.actor_id', true), '');
    v_request_id := nullif(current_setting('authz.request_id', true), '');
    v_reason := nullif(current_setting('authz.reason', true), '');

    -- Insert audit event
    -- Map hierarchy fields to audit event columns
    INSERT INTO authz.audit_events (
        event_type,
        actor_id,
        request_id,
        reason,
        namespace,
        resource_type,
        resource_id,
        relation,
        subject_type,
        subject_id,
        subject_relation,
        tuple_id
    ) VALUES (
        v_event_type,
        v_actor_id,
        v_request_id,
        v_reason,
        v_hierarchy.namespace,
        v_hierarchy.resource_type,
        v_hierarchy.permission,    -- permission stored in resource_id
        v_hierarchy.implies,       -- implies stored in relation
        'hierarchy',               -- marker for hierarchy events
        '',                        -- no subject_id for hierarchy
        NULL,                      -- no subject_relation
        NULL                       -- no tuple_id for hierarchy
    );

    -- Return the record
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    ELSE
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql
   SECURITY DEFINER
   SET search_path = authz, pg_temp;


-- =============================================================================
-- CREATE TRIGGERS
-- =============================================================================

-- Tuple audit trigger
CREATE TRIGGER audit_tuples
    AFTER INSERT OR UPDATE OR DELETE ON authz.tuples
    FOR EACH ROW
    EXECUTE FUNCTION authz._audit_tuple_trigger();

-- Hierarchy audit trigger
CREATE TRIGGER audit_hierarchy
    AFTER INSERT OR DELETE ON authz.permission_hierarchy
    FOR EACH ROW
    EXECUTE FUNCTION authz._audit_hierarchy_trigger();

