"""Tests for session management functions."""

import pytest
from datetime import timedelta


class TestCreateSession:
    def test_creates_session(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "token_hash")

        assert session_id is not None

    def test_stores_ip_and_user_agent(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(
            user_id,
            "token_hash",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

        sessions = authn.list_sessions(user_id)
        assert len(sessions) == 1
        assert str(sessions[0]["ip_address"]) == "192.168.1.1"
        assert sessions[0]["user_agent"] == "Mozilla/5.0"

    def test_uses_custom_expiry(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token_hash", expires_in=timedelta(hours=1))

        sessions = authn.list_sessions(user_id)
        assert len(sessions) == 1
        # Session exists and is active (not expired)


class TestValidateSession:
    def test_returns_user_for_valid_session(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "token_hash")

        result = authn.validate_session("token_hash")

        assert result is not None
        assert str(result["user_id"]) == user_id
        assert result["email"] == "alice@example.com"
        assert str(result["session_id"]) == session_id

    def test_returns_none_for_unknown_token(self, authn):
        result = authn.validate_session("unknown_token")
        assert result is None

    def test_returns_none_for_expired_session(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        test_helpers.insert_expired_session(user_id, "expired_token")

        result = authn.validate_session("expired_token")
        assert result is None

    def test_returns_none_for_revoked_session(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token_hash")
        authn.revoke_session("token_hash")

        result = authn.validate_session("token_hash")
        assert result is None

    def test_returns_none_for_disabled_user(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token_hash")
        authn.disable_user(user_id)

        result = authn.validate_session("token_hash")
        assert result is None

    def test_does_not_log_audit_event(self, authn):
        """Performance requirement: validate_session is hot path."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token_hash")

        # Get event count before
        events_before = len(authn.get_audit_events())

        # Validate many times
        for _ in range(10):
            authn.validate_session("token_hash")

        # Event count should not increase
        events_after = len(authn.get_audit_events())
        assert events_after == events_before


class TestExtendSession:
    def test_extends_session(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token_hash", expires_in=timedelta(hours=1))

        new_expires_at = authn.extend_session("token_hash", extend_by=timedelta(days=7))

        assert new_expires_at is not None
        # Should be about 7 days from now

    def test_returns_none_for_unknown_token(self, authn):
        result = authn.extend_session("unknown_token")
        assert result is None

    def test_returns_none_for_expired_session(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        test_helpers.insert_expired_session(user_id, "expired_token")

        result = authn.extend_session("expired_token")
        assert result is None


class TestRevokeSession:
    def test_revokes_session(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token_hash")

        result = authn.revoke_session("token_hash")

        assert result is True
        assert authn.validate_session("token_hash") is None

    def test_returns_false_for_unknown_token(self, authn):
        result = authn.revoke_session("unknown_token")
        assert result is False

    def test_returns_false_if_already_revoked(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token_hash")
        authn.revoke_session("token_hash")

        result = authn.revoke_session("token_hash")
        assert result is False


class TestRevokeAllSessions:
    def test_revokes_all_user_sessions(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token1")
        authn.create_session(user_id, "token2")
        authn.create_session(user_id, "token3")

        count = authn.revoke_all_sessions(user_id)

        assert count == 3
        assert authn.validate_session("token1") is None
        assert authn.validate_session("token2") is None
        assert authn.validate_session("token3") is None

    def test_returns_zero_if_no_sessions(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        count = authn.revoke_all_sessions(user_id)
        assert count == 0


class TestListSessions:
    def test_lists_active_sessions(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token1")
        authn.create_session(user_id, "token2")

        sessions = authn.list_sessions(user_id)

        assert len(sessions) == 2
        # Token hash should not be returned
        for s in sessions:
            assert "token_hash" not in s

    def test_excludes_revoked_sessions(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token1")
        authn.create_session(user_id, "token2")
        authn.revoke_session("token1")

        sessions = authn.list_sessions(user_id)
        assert len(sessions) == 1

    def test_excludes_expired_sessions(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "active_token")
        test_helpers.insert_expired_session(user_id, "expired_token")

        sessions = authn.list_sessions(user_id)
        assert len(sessions) == 1
