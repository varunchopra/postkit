"""Tests for refresh token rotation."""

from datetime import datetime, timedelta, timezone

import pytest
from postkit.authn import AuthnError
from postkit.base import UniqueViolationError


class TestCreateRefreshToken:
    def test_creates_refresh_token(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")

        result = authn.create_refresh_token(session_id, "refresh_hash")

        assert result["refresh_token_id"] is not None
        assert result["family_id"] is not None
        # Verify expiry is approximately 30 days from now (default)
        expected = datetime.now(timezone.utc) + timedelta(days=30)
        actual = result["expires_at"]
        assert abs((expected - actual).total_seconds()) < 60

    def test_fails_for_invalid_session(self, authn):
        with pytest.raises(AuthnError):
            authn.create_refresh_token("00000000-0000-0000-0000-000000000000", "hash")

    def test_fails_for_revoked_session(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.revoke_session("session_hash")

        with pytest.raises(AuthnError):
            authn.create_refresh_token(session_id, "refresh_hash")

    def test_uses_custom_expiry(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")

        result = authn.create_refresh_token(
            session_id, "refresh_hash", expires_in=timedelta(days=7)
        )

        # Verify custom expiry was applied (7 days, not default 30)
        expected = datetime.now(timezone.utc) + timedelta(days=7)
        actual = result["expires_at"]
        assert abs((expected - actual).total_seconds()) < 60

    def test_creates_audit_event(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")

        authn.create_refresh_token(session_id, "refresh_hash")

        events = authn.get_audit_events(event_type="refresh_token_created")
        assert len(events) == 1
        assert events[0]["new_values"]["user_id"] == user_id
        assert events[0]["new_values"]["session_id"] == session_id


class TestRotateRefreshToken:
    def test_rotates_token(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "refresh_hash_1")

        result = authn.rotate_refresh_token("refresh_hash_1", "refresh_hash_2")

        assert result is not None
        assert str(result["user_id"]) == user_id
        assert str(result["session_id"]) == session_id
        assert result["generation"] == 2

    def test_increments_generation(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "refresh_hash_1")

        result = authn.rotate_refresh_token("refresh_hash_1", "refresh_hash_2")
        assert result["generation"] == 2

        result = authn.rotate_refresh_token("refresh_hash_2", "refresh_hash_3")
        assert result["generation"] == 3

        result = authn.rotate_refresh_token("refresh_hash_3", "refresh_hash_4")
        assert result["generation"] == 4

    def test_preserves_family_id(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        initial = authn.create_refresh_token(session_id, "refresh_hash_1")

        result = authn.rotate_refresh_token("refresh_hash_1", "refresh_hash_2")

        assert str(result["family_id"]) == str(initial["family_id"])

    def test_returns_none_for_unknown_token(self, authn):
        result = authn.rotate_refresh_token("unknown", "new_hash")
        assert result is None

    def test_returns_none_for_expired_token(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        test_helpers.insert_expired_refresh_token(user_id, session_id, "expired_hash")

        result = authn.rotate_refresh_token("expired_hash", "new_hash")
        assert result is None

    def test_returns_none_for_disabled_user(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "refresh_hash")
        authn.disable_user(user_id)

        result = authn.rotate_refresh_token("refresh_hash", "new_hash")
        assert result is None

    def test_returns_none_for_revoked_session(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "refresh_hash")
        authn.revoke_session("session_hash")

        result = authn.rotate_refresh_token("refresh_hash", "new_hash")
        assert result is None

    def test_creates_audit_event(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "refresh_hash_1")

        authn.rotate_refresh_token("refresh_hash_1", "refresh_hash_2")

        events = authn.get_audit_events(event_type="refresh_token_rotated")
        assert len(events) == 1
        assert events[0]["new_values"]["generation"] == 2


class TestTokenReuseDetection:
    """Critical security tests for token reuse detection."""

    def test_reuse_revokes_entire_family(self, authn, test_helpers):
        """Using an already-rotated token revokes the entire family."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        initial = authn.create_refresh_token(session_id, "token_1")
        family_id = str(initial["family_id"])

        # Normal rotations
        authn.rotate_refresh_token("token_1", "token_2")
        authn.rotate_refresh_token("token_2", "token_3")

        # Reuse attack: attacker uses stolen token_1
        result = authn.rotate_refresh_token("token_1", "attacker_token")
        assert result is None

        # Current token_3 should also be revoked
        result = authn.rotate_refresh_token("token_3", "new_token")
        assert result is None

        # Verify no active tokens in family
        active_count = test_helpers.count_active_refresh_tokens_in_family(family_id)
        assert active_count == 0

    def test_reuse_creates_security_audit_event(self, authn):
        """Token reuse creates a security audit event."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "token_1")
        authn.rotate_refresh_token("token_1", "token_2")

        # Reuse attack
        authn.rotate_refresh_token("token_1", "attacker_token")

        events = authn.get_audit_events(event_type="refresh_token_reuse_detected")
        assert len(events) == 1
        assert events[0]["new_values"]["user_id"] == user_id
        assert "tokens_revoked" in events[0]["new_values"]

    def test_old_token_is_marked_replaced(self, authn, test_helpers):
        """After rotation, old token has replaced_by set."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "token_1")

        authn.rotate_refresh_token("token_1", "token_2")

        old_token = test_helpers.get_refresh_token_raw("token_1")
        assert old_token is not None
        assert old_token["replaced_by"] is not None


class TestValidateRefreshToken:
    def test_returns_token_info(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "refresh_hash")

        result = authn.validate_refresh_token("refresh_hash")

        assert result is not None
        assert str(result["user_id"]) == user_id
        assert str(result["session_id"]) == session_id
        assert result["generation"] == 1
        assert result["is_current"] is True

    def test_returns_none_for_unknown_token(self, authn):
        result = authn.validate_refresh_token("unknown")
        assert result is None

    def test_returns_none_for_revoked_token(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        initial = authn.create_refresh_token(session_id, "refresh_hash")
        authn.revoke_refresh_token_family(str(initial["family_id"]))

        result = authn.validate_refresh_token("refresh_hash")
        assert result is None

    def test_returns_none_for_replaced_token(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "token_1")
        authn.rotate_refresh_token("token_1", "token_2")

        # Old token should not validate
        result = authn.validate_refresh_token("token_1")
        assert result is None

        # New token should validate
        result = authn.validate_refresh_token("token_2")
        assert result is not None


class TestRefreshTokenRevocation:
    def test_revoke_family(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        result = authn.create_refresh_token(session_id, "refresh_hash")
        family_id = str(result["family_id"])

        count = authn.revoke_refresh_token_family(family_id)

        assert count == 1
        assert authn.validate_refresh_token("refresh_hash") is None

    def test_revoke_family_includes_all_tokens(self, authn, test_helpers):
        """Revoking a family revokes all non-revoked tokens in the family."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        initial = authn.create_refresh_token(session_id, "token_1")
        family_id = str(initial["family_id"])
        authn.rotate_refresh_token("token_1", "token_2")
        authn.rotate_refresh_token("token_2", "token_3")

        # Revoke family - revokes all 3 tokens (replaced ones weren't revoked)
        count = authn.revoke_refresh_token_family(family_id)

        # All 3 tokens in the family get revoked
        assert count == 3
        assert authn.validate_refresh_token("token_3") is None

    def test_revoke_all_user_tokens(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session1 = authn.create_session(user_id, "session_hash_1")
        session2 = authn.create_session(user_id, "session_hash_2")
        authn.create_refresh_token(session1, "refresh_hash_1")
        authn.create_refresh_token(session2, "refresh_hash_2")

        count = authn.revoke_all_refresh_tokens(user_id)

        assert count == 2
        assert authn.validate_refresh_token("refresh_hash_1") is None
        assert authn.validate_refresh_token("refresh_hash_2") is None

    def test_session_revocation_cascades(self, authn):
        """Revoking a session automatically revokes its refresh tokens."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "refresh_hash")

        # Verify token is valid
        assert authn.validate_refresh_token("refresh_hash") is not None

        # Revoke session
        authn.revoke_session("session_hash")

        # Token should now be invalid
        assert authn.validate_refresh_token("refresh_hash") is None

    def test_creates_audit_event(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        result = authn.create_refresh_token(session_id, "refresh_hash")
        family_id = str(result["family_id"])

        authn.revoke_refresh_token_family(family_id)

        events = authn.get_audit_events(event_type="refresh_token_family_revoked")
        assert len(events) == 1
        assert events[0]["resource_id"] == family_id


class TestListRefreshTokens:
    def test_lists_active_tokens(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "refresh_hash")

        tokens = authn.list_refresh_tokens(user_id)

        assert len(tokens) == 1
        assert "token_hash" not in tokens[0]  # Security: don't expose hash
        assert "family_id" in tokens[0]
        assert tokens[0]["generation"] == 1

    def test_excludes_replaced_tokens(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "token_1")
        authn.rotate_refresh_token("token_1", "token_2")
        authn.rotate_refresh_token("token_2", "token_3")

        tokens = authn.list_refresh_tokens(user_id)

        assert len(tokens) == 1
        assert tokens[0]["generation"] == 3  # Only current token listed

    def test_excludes_revoked_tokens(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        result = authn.create_refresh_token(session_id, "refresh_hash")
        authn.revoke_refresh_token_family(str(result["family_id"]))

        tokens = authn.list_refresh_tokens(user_id)

        assert len(tokens) == 0

    def test_lists_multiple_families(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session1 = authn.create_session(user_id, "session_hash_1")
        session2 = authn.create_session(user_id, "session_hash_2")
        authn.create_refresh_token(session1, "refresh_hash_1")
        authn.create_refresh_token(session2, "refresh_hash_2")

        tokens = authn.list_refresh_tokens(user_id)

        assert len(tokens) == 2


class TestRefreshTokenEdgeCases:
    """Edge case tests for refresh token security."""

    def test_duplicate_token_hash_rejected(self, authn):
        """Cannot create two tokens with same hash."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "same_hash")

        with pytest.raises(UniqueViolationError):
            authn.create_refresh_token(session_id, "same_hash")

    def test_revoked_token_does_not_trigger_reuse_detection(self, authn):
        """Using a revoked (not replaced) token doesn't trigger reuse detection."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        initial = authn.create_refresh_token(session_id, "token1")
        authn.revoke_refresh_token_family(str(initial["family_id"]))

        # Try to use revoked token - should fail silently, NOT trigger reuse
        result = authn.rotate_refresh_token("token1", "token2")
        assert result is None

        # Verify no reuse detection event was created
        events = authn.get_audit_events(event_type="refresh_token_reuse_detected")
        assert len(events) == 0

    def test_rotation_extends_expiry(self, authn):
        """Each rotation extends the token expiry."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")

        # Create with short expiry
        initial = authn.create_refresh_token(
            session_id, "token1", expires_in=timedelta(days=1)
        )
        initial_expiry = initial["expires_at"]

        # Rotate - new token should have fresh expiry (default 30 days)
        result = authn.rotate_refresh_token("token1", "token2")

        # New expiry should be ~30 days out, not 1 day
        assert result["expires_at"] > initial_expiry + timedelta(days=7)
