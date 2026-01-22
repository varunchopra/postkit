"""Tests for input validation functions."""

import psycopg
import pytest
from postkit.authn import AuthnError, AuthnValidationError


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
        with pytest.raises(AuthnError):
            authn.create_user(None, "hash")

    def test_rejects_empty(self, authn):
        with pytest.raises(AuthnError):
            authn.create_user("", "hash")

    def test_rejects_whitespace_only(self, authn):
        with pytest.raises(AuthnError):
            authn.create_user("   ", "hash")

    def test_rejects_no_at_sign(self, authn):
        with pytest.raises(AuthnError):
            authn.create_user("no-at-sign", "hash")

    def test_rejects_spaces(self, authn):
        with pytest.raises(AuthnError):
            authn.create_user("has space@example.com", "hash")

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
        with pytest.raises(AuthnError):
            authn.create_user("alice@example.com", "")

    def test_rejects_whitespace_only_password(self, authn):
        with pytest.raises(AuthnError):
            authn.create_user("alice@example.com", "   ")

    def test_rejects_empty_token_hash(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        with pytest.raises(AuthnError):
            authn.create_session(user_id, "")


class TestTokenTypeValidation:
    """Token type must be password_reset, email_verify, or magic_link."""

    def test_valid_types(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")

        for token_type in ["password_reset", "email_verify", "magic_link"]:
            token_id = authn.create_token(user_id, f"hash_{token_type}", token_type)
            assert token_id is not None

    def test_rejects_invalid_type(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")

        with pytest.raises(AuthnError):
            authn.create_token(user_id, "hash", "invalid_type")


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
        user_id = authn.create_user("alice@example.com", "hash")

        with pytest.raises(AuthnError):
            authn.add_credential(user_id, "invalid_type", secret_data="secret")


class TestNamespaceValidation:
    """Namespace must be 1-1024 chars, no control chars or leading/trailing whitespace."""

    def test_valid_namespaces(self, make_authn):
        """Valid namespace formats should be accepted."""
        valid = [
            "default",
            "tenant_123",
            "acme-corp",
            "550e8400-e29b-41d4-a716-446655440000",
            "org:my-org-123",  # colon format
            "MyOrganization",  # uppercase
            "a" * 1024,  # max length
        ]
        for ns in valid:
            client = make_authn(ns)
            user_id = client.create_user("test@example.com", "hash")
            assert user_id is not None

    def test_rejects_null(self, make_authn):
        with pytest.raises(AuthnError):
            make_authn(None)

    def test_rejects_empty(self, make_authn):
        with pytest.raises(AuthnError):
            make_authn("")

    def test_rejects_whitespace_only(self, make_authn):
        with pytest.raises(AuthnError):
            make_authn("   ")

    def test_rejects_leading_whitespace(self, make_authn):
        with pytest.raises(AuthnError):
            make_authn(" leading")

    def test_rejects_trailing_whitespace(self, make_authn):
        with pytest.raises(AuthnError):
            make_authn("trailing ")

    def test_rejects_control_characters(self, make_authn):
        with pytest.raises(AuthnError):
            make_authn("has\ttab")

    def test_rejects_over_max_length(self, make_authn):
        with pytest.raises(AuthnError):
            make_authn("a" * 1025)


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

    def test_null_validation_raises_authn_validation_error(self, make_authn):
        """Null validation raises AuthnValidationError (SQLSTATE 22004)."""
        with pytest.raises(AuthnValidationError) as exc_info:
            make_authn(None)
        assert exc_info.value.error_code == "VAL_NAMESPACE_NULL"

    def test_empty_validation_raises_authn_validation_error(self, make_authn):
        """Empty string validation raises AuthnValidationError (SQLSTATE 22026)."""
        with pytest.raises(AuthnValidationError) as exc_info:
            make_authn("")
        assert exc_info.value.error_code == "VAL_NAMESPACE_EMPTY"

    def test_length_validation_raises_authn_validation_error(self, make_authn):
        """Length exceeded validation raises AuthnValidationError (SQLSTATE 22001)."""
        with pytest.raises(AuthnValidationError) as exc_info:
            make_authn("a" * 1025)
        assert exc_info.value.error_code == "VAL_NAMESPACE_TOO_LONG"

    def test_format_validation_raises_authn_validation_error(self, make_authn):
        """Format validation raises AuthnValidationError (SQLSTATE 22023)."""
        with pytest.raises(AuthnValidationError) as exc_info:
            make_authn("has\ttab")
        assert exc_info.value.error_code == "VAL_NAMESPACE_INVALID_CHARS"

    def test_authn_validation_error_is_authn_error(self):
        """AuthnValidationError is a subclass of AuthnError for backwards compatibility."""
        assert issubclass(AuthnValidationError, AuthnError)
