"""Tests for input validation functions."""

import psycopg
import pytest
from postkit.authn import AuthnError, AuthnErrorCode, AuthnValidationError

from tests.helpers import (
    NAMESPACE_ERROR_CASES,
    VALID_NAMESPACES,
)


class TestEmailValidation:
    """Email must be valid format, normalized to lowercase."""

    def test_valid_emails(self, authn):
        valid_emails = [
            "alice@example.com",
            "user.name@domain.org",
            "user+tag@example.com",
            "123@numeric.com",
        ]
        for email in valid_emails:
            user_id = authn.create_user(email, "hash")
            assert user_id is not None

    def test_rejects_null(self, authn):
        """Null email is rejected."""
        with pytest.raises(AuthnValidationError) as exc_info:
            authn.create_user(None, "hash")
        assert exc_info.value.error_code == AuthnErrorCode.VAL_EMAIL_NULL

    def test_rejects_empty(self, authn):
        """Empty email is rejected."""
        with pytest.raises(AuthnValidationError) as exc_info:
            authn.create_user("", "hash")
        assert exc_info.value.error_code == AuthnErrorCode.VAL_EMAIL_EMPTY

    def test_rejects_whitespace_only(self, authn):
        """Whitespace-only email is rejected as empty after trim."""
        with pytest.raises(AuthnValidationError) as exc_info:
            authn.create_user("   ", "hash")
        assert exc_info.value.error_code == AuthnErrorCode.VAL_EMAIL_EMPTY

    def test_rejects_no_at_sign(self, authn):
        """Email without @ sign has invalid format."""
        with pytest.raises(AuthnValidationError) as exc_info:
            authn.create_user("no-at-sign", "hash")
        assert exc_info.value.error_code == AuthnErrorCode.VAL_EMAIL_INVALID_FORMAT

    def test_rejects_spaces(self, authn):
        """Email with spaces has invalid format."""
        with pytest.raises(AuthnValidationError) as exc_info:
            authn.create_user("has space@example.com", "hash")
        assert exc_info.value.error_code == AuthnErrorCode.VAL_EMAIL_INVALID_FORMAT

    def test_rejects_control_chars(self, authn):
        """Emails with control characters are rejected."""
        with pytest.raises(AuthnValidationError) as exc_info:
            authn.create_user("user\x01@example.com", "hash")
        assert exc_info.value.error_code == AuthnErrorCode.VAL_EMAIL_INVALID_CHARS

    def test_normalizes_to_lowercase(self, authn):
        user_id = authn.create_user("UPPER@EXAMPLE.COM", "hash")
        user = authn.get_user(user_id)
        assert user["email"] == "upper@example.com"

    def test_trims_whitespace(self, authn):
        user_id = authn.create_user("  alice@example.com  ", "hash")
        user = authn.get_user(user_id)
        assert user["email"] == "alice@example.com"


class TestHashValidation:
    """Password hash must be non-empty string or null (for SSO users)."""

    def test_allows_valid_hash(self, authn):
        user_id = authn.create_user("alice@example.com", "$argon2id$v=19$...")
        assert user_id is not None

    def test_allows_null_for_password(self, authn):
        """SSO users have no password."""
        user_id = authn.create_user("sso@example.com")
        assert user_id is not None

    def test_rejects_empty_password(self, authn):
        """Empty password hash is rejected."""
        with pytest.raises(AuthnValidationError) as exc_info:
            authn.create_user("alice@example.com", "")
        assert exc_info.value.error_code == AuthnErrorCode.VAL_HASH_EMPTY

    def test_rejects_whitespace_only_password(self, authn):
        """Whitespace-only password hash is rejected as empty after trim."""
        with pytest.raises(AuthnValidationError) as exc_info:
            authn.create_user("alice@example.com", "   ")
        assert exc_info.value.error_code == AuthnErrorCode.VAL_HASH_EMPTY

    def test_rejects_empty_token_hash(self, authn):
        """Empty token hash is rejected."""
        user_id = authn.create_user("alice@example.com", "hash")
        with pytest.raises(AuthnValidationError) as exc_info:
            authn.create_session(user_id, "")
        assert exc_info.value.error_code == AuthnErrorCode.VAL_HASH_EMPTY

    def test_rejects_control_chars(self, authn):
        """Password hashes with control characters are rejected."""
        with pytest.raises(AuthnValidationError) as exc_info:
            authn.create_user("alice@example.com", "hash\x01value")
        assert exc_info.value.error_code == AuthnErrorCode.VAL_HASH_INVALID_CHARS


class TestTokenTypeValidation:
    """Token type must be password_reset, email_verify, or magic_link."""

    def test_valid_types(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")

        for token_type in ["password_reset", "email_verify", "magic_link"]:
            token_id = authn.create_token(user_id, f"hash_{token_type}", token_type)
            assert token_id is not None

    def test_rejects_invalid_type(self, authn):
        """Invalid token type is rejected."""
        user_id = authn.create_user("alice@example.com", "hash")

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.create_token(user_id, "hash", "invalid_type")
        assert exc_info.value.error_code == AuthnErrorCode.VAL_TOKEN_TYPE_INVALID

    def test_rejects_null_type(self, authn):
        """Null token type is rejected."""
        user_id = authn.create_user("alice@example.com", "hash")

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.create_token(user_id, "hash", None)
        assert exc_info.value.error_code == AuthnErrorCode.VAL_TOKEN_TYPE_NULL


class TestCredentialTypeValidation:
    """Credential type must be totp, webauthn, or recovery_code."""

    def test_valid_types(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")

        for cred_type in ["totp", "webauthn", "recovery_code"]:
            if cred_type == "totp":
                cred_id = authn.add_credential(user_id, cred_type, secret_data="seed")
            elif cred_type == "recovery_code":
                cred_id = authn.add_credential(user_id, cred_type, lookup_key="hash")
            else:  # webauthn
                cred_id = authn.add_credential(
                    user_id, cred_type, lookup_key="cred_id", secret_data="pubkey"
                )
            assert cred_id is not None

    def test_rejects_invalid_type(self, authn):
        """Invalid credential type is rejected."""
        user_id = authn.create_user("alice@example.com", "hash")

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.add_credential(user_id, "invalid_type", secret_data="secret")
        assert exc_info.value.error_code == AuthnErrorCode.VAL_CREDENTIAL_TYPE_INVALID

    def test_rejects_null_type(self, authn):
        """Null credential type is rejected."""
        user_id = authn.create_user("alice@example.com", "hash")

        with pytest.raises(AuthnValidationError) as exc_info:
            authn.add_credential(user_id, None, secret_data="secret")
        assert exc_info.value.error_code == AuthnErrorCode.VAL_CREDENTIAL_TYPE_NULL


class TestNamespaceValidation:
    """Namespace must be 1-1024 chars, no control chars or leading/trailing whitespace."""

    def test_valid_namespaces(self, make_authn):
        for ns in VALID_NAMESPACES:
            client = make_authn(ns)
            user_id = client.create_user("test@example.com", "hash")
            assert user_id is not None


class TestEmailEdgeCases:
    """Edge case tests for email validation."""

    def test_accepts_email_at_exact_max_length(self, authn):
        """Email at exactly 1024 characters should be accepted."""
        # 1024 - 1 (for @) - 4 (for .com) = 1019 chars for local + domain base
        local_part = "a" * 510
        domain = "b" * 509 + ".com"  # 513 chars
        email = f"{local_part}@{domain}"  # 510 + 1 + 513 = 1024 chars
        assert len(email) == 1024

        user_id = authn.create_user(email, "hash")
        assert user_id is not None

    def test_rejects_email_one_over_max_length(self, authn):
        """Email at 1025 characters should be rejected."""
        local_part = "a" * 511
        domain = "b" * 509 + ".com"  # 513 chars
        email = f"{local_part}@{domain}"  # 511 + 1 + 513 = 1025 chars
        assert len(email) == 1025

        with pytest.raises(AuthnError):
            authn.create_user(email, "hash")


class TestHashEdgeCases:
    """Edge case tests for hash validation."""

    def test_accepts_hash_at_exact_max_length(self, authn):
        """Hash at exactly 1024 characters should be accepted."""
        hash_at_limit = "x" * 1024
        assert len(hash_at_limit) == 1024
        user_id = authn.create_user("alice@example.com", hash_at_limit)
        assert user_id is not None

    def test_rejects_hash_one_over_max_length(self, authn):
        """Hash at 1025 characters should be rejected."""
        hash_over_limit = "x" * 1025
        assert len(hash_over_limit) == 1025
        with pytest.raises(AuthnError):
            authn.create_user("bob@example.com", hash_over_limit)


class TestIpAddressValidation:
    """Tests for IP address validation in set_actor."""

    def test_accepts_valid_ipv4(self, test_helpers):
        """Valid IPv4 addresses should be accepted."""
        test_helpers.cursor.execute("BEGIN")
        test_helpers.cursor.execute(
            "SELECT authn.set_actor(%s, %s, %s, %s)",
            ("user-1", "req-1", "192.168.1.1", "Mozilla/5.0"),
        )
        test_helpers.cursor.execute("ROLLBACK")

    def test_accepts_valid_ipv6(self, test_helpers):
        """Valid IPv6 addresses should be accepted."""
        test_helpers.cursor.execute("BEGIN")
        test_helpers.cursor.execute(
            "SELECT authn.set_actor(%s, %s, %s, %s)",
            ("user-1", "req-1", "::1", None),
        )
        test_helpers.cursor.execute("ROLLBACK")

    def test_accepts_null_ip(self, test_helpers):
        """NULL IP address should be accepted."""
        test_helpers.cursor.execute("BEGIN")
        test_helpers.cursor.execute(
            "SELECT authn.set_actor(%s, %s, %s, %s)",
            ("user-1", None, None, None),
        )
        test_helpers.cursor.execute("ROLLBACK")

    def test_rejects_invalid_ip(self, test_helpers):
        """Invalid IP address should be rejected."""
        with pytest.raises(
            psycopg.errors.InvalidParameterValue, match="ip_address must be valid"
        ):
            test_helpers.cursor.execute(
                "SELECT authn.set_actor(%s, %s, %s, %s)",
                ("user-1", None, "not-an-ip", None),
            )


class TestValidationErrorType:
    """Validation errors raise AuthnValidationError for precise error handling."""

    @pytest.mark.parametrize("ns, error_code_name", NAMESPACE_ERROR_CASES)
    def test_namespace_validation_raises_correct_error(
        self, make_authn, ns, error_code_name
    ):
        with pytest.raises(AuthnValidationError) as exc_info:
            make_authn(ns)
        assert exc_info.value.error_code == getattr(AuthnErrorCode, error_code_name)

    def test_authn_validation_error_is_authn_error(self):
        """AuthnValidationError is a subclass of AuthnError for backwards compatibility."""
        assert issubclass(AuthnValidationError, AuthnError)
