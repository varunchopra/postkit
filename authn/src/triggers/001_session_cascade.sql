-- =============================================================================
-- SESSION CASCADE TRIGGERS
-- =============================================================================

-- Cascade session revocation to refresh tokens
-- When a session is revoked, automatically revoke its refresh tokens
CREATE OR REPLACE FUNCTION authn._cascade_session_revocation()
RETURNS trigger AS $$
BEGIN
    UPDATE authn.refresh_tokens
    SET revoked_at = NEW.revoked_at
    WHERE session_id = NEW.id
      AND revoked_at IS NULL;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER session_revoked_cascade
    AFTER UPDATE OF revoked_at ON authn.sessions
    FOR EACH ROW
    WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
    EXECUTE FUNCTION authn._cascade_session_revocation();

-- Revoke impersonation session when impersonation record is deleted
-- This prevents orphaned sessions when original_session_id is cascade deleted
CREATE OR REPLACE FUNCTION authn._revoke_impersonation_session_on_delete()
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

CREATE TRIGGER impersonation_deleted_revoke_session
    BEFORE DELETE ON authn.impersonation_sessions
    FOR EACH ROW
    EXECUTE FUNCTION authn._revoke_impersonation_session_on_delete();
