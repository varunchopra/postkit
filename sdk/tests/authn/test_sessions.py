"""Tests for session management functions."""

from datetime import timedelta


class TestCreateSession:
    def test_stores_ip_and_user_agent(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(
            user_id,
            "token_hash",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
        )
        assert session_id is not None

        sessions = authn.list_sessions(user_id)
        assert len(sessions) == 1
        assert str(sessions[0]["ip_address"]) == "192.168.1.1"
        assert sessions[0]["user_agent"] == "Mozilla/5.0"

    def test_uses_custom_expiry(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token_hash", expires_in=timedelta(hours=1))

        sessions = authn.list_sessions(user_id)
        assert len(sessions) == 1
        # Verify custom expiry was applied, not the 7-day default.
        delta = sessions[0]["expires_at"] - sessions[0]["created_at"]
        assert delta < timedelta(hours=2)

    def test_creates_audit_event(self, authn):
        """Creating a session logs a session_created audit event."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "token_hash")

        events = authn.get_audit_events(event_type="session_created")
        assert len(events) == 1
        event = events[0]
        assert event["resource_type"] == "session"
        assert event["resource_id"] == session_id
        assert event["new_values"]["user_id"] == user_id


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
        # Verify extension is ~7 days from creation, not the original ~1 hour.
        sessions = authn.list_sessions(user_id)
        delta = new_expires_at - sessions[0]["created_at"]
        assert timedelta(days=6) < delta < timedelta(days=8)

    def test_returns_none_for_unknown_token(self, authn):
        result = authn.extend_session("unknown_token")
        assert result is None

    def test_returns_none_for_expired_session(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        test_helpers.insert_expired_session(user_id, "expired_token")

        result = authn.extend_session("expired_token")
        assert result is None

    def test_creates_audit_event(self, authn):
        """Extending a session creates a session_extended audit event."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "token_hash")

        authn.extend_session("token_hash", extend_by=timedelta(days=7))

        events = authn.get_audit_events(event_type="session_extended")
        assert len(events) == 1
        event = events[0]
        assert event["resource_type"] == "session"
        assert event["resource_id"] == session_id
        assert event["new_values"]["user_id"] == user_id

    def test_audit_event_captures_actor_context(self, authn):
        """Actor context is captured in session_extended audit events."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token_hash")

        authn.set_actor("admin@acme.com", "req-123", reason="Remember me enabled")
        authn.extend_session("token_hash", extend_by=timedelta(days=30))

        events = authn.get_audit_events(event_type="session_extended")
        assert len(events) == 1
        event = events[0]
        assert event["actor_id"] == "admin@acme.com"
        assert event["request_id"] == "req-123"
        assert event["reason"] == "Remember me enabled"

    def test_no_audit_event_for_invalid_session(self, authn):
        """No audit event is created when extending an invalid session."""
        # Count events before
        events_before = len(authn.get_audit_events())

        # Try to extend a non-existent session
        result = authn.extend_session("nonexistent_token")
        assert result is None

        # Event count should not increase
        events_after = len(authn.get_audit_events())
        assert events_after == events_before


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

    def test_creates_audit_event(self, authn):
        """Revoking a session logs a session_revoked audit event."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "token_hash")
        authn.revoke_session("token_hash")

        events = authn.get_audit_events(event_type="session_revoked")
        assert len(events) == 1
        assert events[0]["resource_type"] == "session"
        assert events[0]["resource_id"] == session_id


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


class TestRevokeSessionById:
    def test_revokes_session_by_id(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "token_hash")

        result = authn.revoke_session_by_id(session_id, user_id)

        assert result is True
        assert authn.validate_session("token_hash") is None

    def test_requires_ownership(self, authn):
        """User cannot revoke another user's session."""
        alice_id = authn.create_user("alice@example.com", "hash1")
        bob_id = authn.create_user("bob@example.com", "hash2")
        alice_session = authn.create_session(alice_id, "alice_token")

        result = authn.revoke_session_by_id(alice_session, bob_id)

        assert result is False
        assert authn.validate_session("alice_token") is not None

    def test_returns_false_for_unknown_session(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        fake_id = "00000000-0000-0000-0000-000000000000"

        result = authn.revoke_session_by_id(fake_id, user_id)

        assert result is False

    def test_returns_false_if_already_revoked(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "token_hash")
        authn.revoke_session("token_hash")

        result = authn.revoke_session_by_id(session_id, user_id)

        assert result is False


class TestRevokeOtherSessions:
    def test_revokes_all_except_current(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token1")
        current_session = authn.create_session(user_id, "token2")
        authn.create_session(user_id, "token3")

        count = authn.revoke_other_sessions(user_id, current_session)

        assert count == 2
        assert authn.validate_session("token1") is None
        assert authn.validate_session("token2") is not None
        assert authn.validate_session("token3") is None

    def test_returns_zero_if_only_current_session(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "token_hash")

        count = authn.revoke_other_sessions(user_id, session_id)

        assert count == 0
        assert authn.validate_session("token_hash") is not None

    def test_does_not_affect_other_users(self, authn):
        alice_id = authn.create_user("alice@example.com", "hash1")
        bob_id = authn.create_user("bob@example.com", "hash2")
        alice_current = authn.create_session(alice_id, "alice_current")
        authn.create_session(alice_id, "alice_other")
        authn.create_session(bob_id, "bob_token")

        count = authn.revoke_other_sessions(alice_id, alice_current)

        assert count == 1
        assert authn.validate_session("bob_token") is not None
