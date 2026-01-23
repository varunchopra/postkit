"""Tests for disabled user security checks across authn functions.

These tests verify that disabled users cannot perform actions they shouldn't,
ensuring consistent security boundary enforcement across all auth functions.
"""

import pytest
from postkit.authn import AuthnError


class TestCreateTokenDisabledUser:
    """Tests for create_token rejecting disabled users."""

    def test_create_token_fails_for_disabled_user(self, authn):
        """create_token raises error when user is disabled."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.disable_user(user_id)

        with pytest.raises(AuthnError):
            authn.create_token(user_id, "token_hash", "password_reset")

    def test_create_token_succeeds_for_enabled_user(self, authn):
        """create_token works for enabled users (non-breaking change)."""
        user_id = authn.create_user("alice@example.com", "hash")
        token_id = authn.create_token(user_id, "token_hash", "password_reset")
        assert token_id is not None


class TestConsumeTokenDisabledUser:
    """Tests for consume_token rejecting disabled users."""

    def test_consume_token_returns_none_for_disabled_user(self, authn):
        """consume_token returns None when user is disabled after token creation."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "token_hash", "password_reset")
        authn.disable_user(user_id)

        result = authn.consume_token("token_hash", "password_reset")
        assert result is None

    def test_consume_token_succeeds_for_enabled_user(self, authn):
        """consume_token works for enabled users (non-breaking change)."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "token_hash", "password_reset")

        result = authn.consume_token("token_hash", "password_reset")
        assert result is not None
        assert str(result["user_id"]) == user_id


class TestVerifyEmailDisabledUser:
    """Tests for verify_email rejecting disabled users (via consume_token)."""

    def test_verify_email_returns_none_for_disabled_user(self, authn):
        """verify_email returns None when user is disabled after token creation."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "token_hash", "email_verify")
        authn.disable_user(user_id)

        result = authn.verify_email("token_hash")
        assert result is None

        # Also verify email_verified_at was NOT set
        user = authn.get_user(user_id)
        assert user["email_verified_at"] is None

    def test_verify_email_succeeds_for_enabled_user(self, authn):
        """verify_email works for enabled users (non-breaking change)."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "token_hash", "email_verify")

        result = authn.verify_email("token_hash")
        assert result is not None

        # Verify email_verified_at was set
        user = authn.get_user(user_id)
        assert user["email_verified_at"] is not None


class TestCreateRefreshTokenDisabledUser:
    """Tests for create_refresh_token rejecting disabled users."""

    def test_create_refresh_token_fails_for_disabled_user(self, authn):
        """create_refresh_token raises error when user is disabled."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.disable_user(user_id)

        with pytest.raises(AuthnError):
            authn.create_refresh_token(session_id, "refresh_hash")

    def test_create_refresh_token_succeeds_for_enabled_user(self, authn):
        """create_refresh_token works for enabled users (non-breaking change)."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")

        result = authn.create_refresh_token(session_id, "refresh_hash")
        assert result is not None
        assert result["refresh_token_id"] is not None


class TestExtendSessionDisabledUser:
    """Tests for extend_session rejecting disabled users."""

    def test_extend_session_returns_none_for_disabled_user(self, authn):
        """extend_session returns None when user is disabled."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "session_hash")
        authn.disable_user(user_id)

        result = authn.extend_session("session_hash")
        assert result is None

    def test_extend_session_succeeds_for_enabled_user(self, authn):
        """extend_session works for enabled users (non-breaking change)."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "session_hash")

        result = authn.extend_session("session_hash")
        assert result is not None


class TestAddCredentialDisabledUser:
    """Tests for add_credential rejecting disabled users."""

    def test_add_credential_fails_for_disabled_user(self, authn):
        """add_credential raises error when user is disabled."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.disable_user(user_id)

        with pytest.raises(AuthnError):
            authn.add_credential(user_id, "totp", secret_data="JBSWY3DPEHPK3PXP")

    def test_add_credential_succeeds_for_enabled_user(self, authn):
        """add_credential works for enabled users (non-breaking change)."""
        user_id = authn.create_user("alice@example.com", "hash")

        credential_id = authn.add_credential(
            user_id, "totp", secret_data="JBSWY3DPEHPK3PXP"
        )
        assert credential_id is not None


class TestReenabledUser:
    """Tests verifying operations work after user is re-enabled."""

    def test_create_token_works_after_reenable(self, authn):
        """create_token works after user is re-enabled."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.disable_user(user_id)
        authn.enable_user(user_id)

        token_id = authn.create_token(user_id, "token_hash", "password_reset")
        assert token_id is not None

    def test_old_token_invalid_after_reenable(self, authn):
        """Tokens created before disable remain invalid after re-enable (security fix).

        This is the expected security behavior: disable_user() invalidates all
        existing tokens. After re-enable, user must create new tokens.
        """
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "token_hash", "password_reset")
        authn.disable_user(user_id)
        authn.enable_user(user_id)

        # Old token was invalidated on disable, remains invalid after re-enable
        result = authn.consume_token("token_hash", "password_reset")
        assert result is None

    def test_new_token_works_after_reenable_user(self, authn):
        """User can create and consume new tokens after re-enable."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.disable_user(user_id)
        authn.enable_user(user_id)

        # Create new token after re-enable
        authn.create_token(user_id, "new_token_hash", "password_reset")
        result = authn.consume_token("new_token_hash", "password_reset")
        assert result is not None

    def test_extend_session_works_after_reenable(self, authn):
        """extend_session works after user is re-enabled."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "session_hash")
        authn.disable_user(user_id)
        authn.enable_user(user_id)

        # disable_user revokes sessions, so this returns None
        assert authn.extend_session("session_hash") is None


# =============================================================================
# SECURITY FIX TESTS: Comprehensive credential revocation on disable
# =============================================================================


class TestDisableUserRevokesAPIKeys:
    """Tests that disable_user revokes all API keys."""

    def test_api_keys_revoked_on_disable(self, authn):
        """API keys are revoked when user is disabled."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_api_key(user_id, "key_hash_1", name="Key 1")
        authn.create_api_key(user_id, "key_hash_2", name="Key 2")

        # Verify keys work before disable
        result = authn.validate_api_key("key_hash_1")
        assert result is not None

        authn.disable_user(user_id)

        # Verify keys no longer work after disable
        assert authn.validate_api_key("key_hash_1") is None
        assert authn.validate_api_key("key_hash_2") is None

    def test_api_keys_not_restored_on_reenable(self, authn):
        """API keys remain revoked after user is re-enabled (security fix)."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_api_key(user_id, "key_hash", name="Key")

        # Verify key works
        assert authn.validate_api_key("key_hash") is not None

        # Disable then re-enable
        authn.disable_user(user_id)
        authn.enable_user(user_id)

        # Key was explicitly revoked, NOT just blocked by user status
        # So it should remain revoked after re-enable
        assert authn.validate_api_key("key_hash") is None

    def test_new_api_key_works_after_reenable(self, authn):
        """User can create new API keys after re-enable."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_api_key(user_id, "old_key_hash", name="Old Key")

        authn.disable_user(user_id)
        authn.enable_user(user_id)

        # Old key is revoked
        assert authn.validate_api_key("old_key_hash") is None

        # New key works
        authn.create_api_key(user_id, "new_key_hash", name="New Key")
        assert authn.validate_api_key("new_key_hash") is not None


class TestDisableUserRevokesRefreshTokens:
    """Tests that disable_user revokes all refresh tokens."""

    def test_refresh_tokens_revoked_on_disable(self, authn):
        """Refresh tokens are revoked when user is disabled."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "refresh_hash")

        # Verify token works before disable
        result = authn.validate_refresh_token("refresh_hash")
        assert result is not None

        authn.disable_user(user_id)

        # Verify token no longer works after disable
        assert authn.validate_refresh_token("refresh_hash") is None

    def test_rotation_fails_after_disable(self, authn):
        """Cannot rotate refresh token after user is disabled."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "refresh_hash")

        authn.disable_user(user_id)

        # Rotation should fail because token is revoked
        result = authn.rotate_refresh_token("refresh_hash", "new_hash")
        assert result is None

    def test_refresh_tokens_not_restored_on_reenable(self, authn):
        """Refresh tokens remain revoked after re-enable (security fix)."""
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_hash")
        authn.create_refresh_token(session_id, "refresh_hash")

        authn.disable_user(user_id)
        authn.enable_user(user_id)

        # Token was explicitly revoked, should remain revoked
        assert authn.validate_refresh_token("refresh_hash") is None


class TestDisableUserEndsImpersonations:
    """Tests that disable_user ends impersonation sessions."""

    def test_ends_impersonation_where_user_is_actor(self, authn):
        """Impersonation ends when actor (admin) is disabled."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Support ticket #123", token_hash="imp_token"
        )
        imp_session_id = str(imp["impersonation_session_id"])

        # Verify impersonation is active
        context = authn.get_impersonation_context(imp_session_id)
        assert context["is_impersonating"] is True

        # Disable the actor (admin)
        authn.disable_user(admin_id)

        # Impersonation should be ended
        context = authn.get_impersonation_context(imp_session_id)
        assert context["is_impersonating"] is False

    def test_ends_impersonation_where_user_is_target(self, authn):
        """Impersonation ends when target user is disabled."""
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Support", token_hash="imp_token"
        )
        imp_session_id = str(imp["impersonation_session_id"])

        # Verify impersonation is active
        context = authn.get_impersonation_context(imp_session_id)
        assert context["is_impersonating"] is True

        # Disable the target
        authn.disable_user(target_id)

        # Impersonation should be ended
        context = authn.get_impersonation_context(imp_session_id)
        assert context["is_impersonating"] is False


class TestDisableUserEndsOperatorImpersonations:
    """Tests that disable_user ends operator impersonation sessions."""

    def test_ends_operator_impersonation_when_operator_disabled(self, make_authn):
        """Operator impersonation ends when operator is disabled (cross-namespace)."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        # Create operator in platform namespace
        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "op_token")

        # Create target in customer namespace
        target_id = customer.create_user("target@customer.com", "hash2")

        # Start operator impersonation
        imp = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Support ticket #456",
        )
        imp_session_id = str(imp["impersonation_session_id"])

        # Verify impersonation is active
        context = platform.get_operator_impersonation_context(imp_session_id)
        assert context["is_operator_impersonating"] is True

        # Disable the operator
        platform.disable_user(operator_id)

        # Impersonation should be ended
        context = platform.get_operator_impersonation_context(imp_session_id)
        assert context["is_operator_impersonating"] is False

    def test_operator_impersonation_session_revoked_on_disable(self, make_authn):
        """The impersonation session itself is revoked when operator is disabled."""
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "op_token")
        target_id = customer.create_user("target@customer.com", "hash2")

        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Support",
        )

        platform.disable_user(operator_id)

        # The impersonation session should be revoked (in customer namespace)
        # Trying to validate it should fail
        result = customer.validate_session("imp_token")
        assert result is None


class TestDisableUserInvalidatesTokens:
    """Tests that disable_user invalidates one-time tokens."""

    def test_password_reset_token_invalidated(self, authn):
        """Password reset token is invalidated when user is disabled."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "reset_hash", "password_reset")

        authn.disable_user(user_id)

        # Token should be invalid (marked as used)
        result = authn.consume_token("reset_hash", "password_reset")
        assert result is None

    def test_tokens_not_restored_on_reenable(self, authn):
        """One-time tokens remain invalidated after re-enable."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "reset_hash", "password_reset")

        authn.disable_user(user_id)
        authn.enable_user(user_id)

        # Token was marked as used, should remain invalid
        result = authn.consume_token("reset_hash", "password_reset")
        assert result is None

    def test_new_token_works_after_reenable(self, authn):
        """User can create new tokens after re-enable."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "old_hash", "password_reset")

        authn.disable_user(user_id)
        authn.enable_user(user_id)

        # Old token is invalid
        assert authn.consume_token("old_hash", "password_reset") is None

        # New token works
        authn.create_token(user_id, "new_hash", "password_reset")
        result = authn.consume_token("new_hash", "password_reset")
        assert result is not None
