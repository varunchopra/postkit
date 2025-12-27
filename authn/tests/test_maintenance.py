"""Tests for maintenance functions."""

from datetime import timedelta


class TestCleanupExpired:
    def test_deletes_expired_sessions(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "active_token")
        test_helpers.insert_expired_session(user_id, "expired_token")

        result = authn.cleanup_expired()

        assert result["sessions_deleted"] == 1
        # Active session still exists
        assert authn.validate_session("active_token") is not None

    def test_deletes_revoked_sessions(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token1")
        authn.create_session(user_id, "token2")
        authn.revoke_session("token1")

        result = authn.cleanup_expired()

        assert result["sessions_deleted"] == 1

    def test_deletes_used_tokens(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "token1", "password_reset")
        authn.create_token(user_id, "token2", "password_reset")
        authn.consume_token("token1", "password_reset")

        result = authn.cleanup_expired()

        assert result["tokens_deleted"] >= 1

    def test_deletes_old_login_attempts(self, authn, test_helpers):
        # Insert old attempts
        for i in range(5):
            test_helpers.cursor.execute(
                """
                INSERT INTO authn.login_attempts
                (namespace, email, success, attempted_at)
                VALUES (%s, %s, false, now() - interval '60 days')
                """,
                (authn.namespace, "alice@example.com"),
            )

        # Insert recent attempt
        authn.record_login_attempt("alice@example.com", False)

        result = authn.cleanup_expired()

        # Old attempts deleted, recent kept
        assert result["attempts_deleted"] == 5
        attempts = authn.get_recent_attempts("alice@example.com")
        assert len(attempts) == 1


class TestGetStats:
    def test_returns_counts(self, authn):
        # Create users
        user1 = authn.create_user("alice@example.com", "hash")
        user2 = authn.create_user("bob@example.com", "hash")

        # Verify one
        authn.create_token(user1, "token", "email_verify")
        authn.verify_email("token")

        # Disable one
        authn.disable_user(user2)

        # Create sessions
        authn.create_session(user1, "session1")
        authn.create_session(user1, "session2")

        # Add MFA
        authn.add_mfa(user1, "totp", "secret")

        stats = authn.get_stats()

        assert stats["user_count"] == 2
        assert stats["verified_user_count"] == 1
        assert stats["disabled_user_count"] == 1
        assert stats["active_session_count"] == 2
        assert stats["mfa_enabled_user_count"] == 1

    def test_returns_zeros_for_empty_namespace(self, authn):
        stats = authn.get_stats()

        assert stats["user_count"] == 0
        assert stats["verified_user_count"] == 0
        assert stats["disabled_user_count"] == 0
        assert stats["active_session_count"] == 0
        assert stats["mfa_enabled_user_count"] == 0
