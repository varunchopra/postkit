"""Tests for token management functions."""

import pytest
from datetime import timedelta
from authn_sdk import AuthnError


class TestCreateToken:
    def test_creates_token(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        token_id = authn.create_token(user_id, "token_hash", "password_reset")

        assert token_id is not None

    def test_validates_token_type(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")

        with pytest.raises(AuthnError):
            authn.create_token(user_id, "token_hash", "invalid_type")

    def test_valid_token_types(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")

        for token_type in ["password_reset", "email_verify", "magic_link"]:
            token_id = authn.create_token(user_id, f"hash_{token_type}", token_type)
            assert token_id is not None


class TestConsumeToken:
    def test_consumes_token_and_returns_user(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "token_hash", "password_reset")

        result = authn.consume_token("token_hash", "password_reset")

        assert result is not None
        assert str(result["user_id"]) == user_id
        assert result["email"] == "alice@example.com"

    def test_marks_token_as_used(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "token_hash", "password_reset")

        # First consume succeeds
        result1 = authn.consume_token("token_hash", "password_reset")
        assert result1 is not None

        # Second consume fails
        result2 = authn.consume_token("token_hash", "password_reset")
        assert result2 is None

    def test_returns_none_for_wrong_type(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "token_hash", "password_reset")

        result = authn.consume_token("token_hash", "email_verify")
        assert result is None

    def test_returns_none_for_expired_token(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        test_helpers.insert_expired_token(user_id, "expired_hash", "password_reset")

        result = authn.consume_token("expired_hash", "password_reset")
        assert result is None

    def test_returns_none_for_unknown_token(self, authn):
        result = authn.consume_token("unknown_hash", "password_reset")
        assert result is None


class TestVerifyEmail:
    def test_verifies_email(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "token_hash", "email_verify")

        result = authn.verify_email("token_hash")

        assert result is not None
        assert str(result["user_id"]) == user_id

        # Check user is verified
        user = authn.get_user(user_id)
        assert user["email_verified_at"] is not None

    def test_returns_none_for_wrong_token_type(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "token_hash", "password_reset")

        result = authn.verify_email("token_hash")
        assert result is None

    def test_logs_email_verified_event(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "token_hash", "email_verify")
        authn.verify_email("token_hash")

        events = authn.get_audit_events(
            event_type="email_verified",
            resource_id=user_id,
        )
        assert len(events) >= 1


class TestInvalidateTokens:
    def test_invalidates_all_tokens_of_type(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "token1", "password_reset")
        authn.create_token(user_id, "token2", "password_reset")
        authn.create_token(user_id, "token3", "email_verify")  # Different type

        count = authn.invalidate_tokens(user_id, "password_reset")

        assert count == 2

        # Password reset tokens should be consumed
        assert authn.consume_token("token1", "password_reset") is None
        assert authn.consume_token("token2", "password_reset") is None

        # Email verify token should still work
        assert authn.consume_token("token3", "email_verify") is not None

    def test_returns_zero_if_no_tokens(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        count = authn.invalidate_tokens(user_id, "password_reset")
        assert count == 0
