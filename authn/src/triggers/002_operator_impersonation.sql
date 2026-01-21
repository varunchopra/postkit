-- =============================================================================
-- OPERATOR IMPERSONATION TRIGGERS
-- =============================================================================

-- Revoke impersonation session when operator impersonation record is deleted
CREATE OR REPLACE FUNCTION authn._revoke_operator_impersonation_session_on_delete()
RETURNS trigger AS $$
BEGIN
    IF OLD.impersonation_session_id IS NOT NULL THEN
        UPDATE authn.sessions
        SET revoked_at = now()
        WHERE id = OLD.impersonation_session_id
          AND revoked_at IS NULL;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER operator_impersonation_deleted_revoke_session
    BEFORE DELETE ON authn.operator_impersonation_sessions
    FOR EACH ROW
    EXECUTE FUNCTION authn._revoke_operator_impersonation_session_on_delete();
