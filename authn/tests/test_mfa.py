"""Tests for MFA management functions."""

import pytest
from authn_sdk import AuthnError


class TestAddMfa:
    def test_adds_mfa_method(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        mfa_id = authn.add_mfa(user_id, "totp", "JBSWY3DPEHPK3PXP")

        assert mfa_id is not None

    def test_adds_mfa_with_name(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        mfa_id = authn.add_mfa(
            user_id, "webauthn", "credential_data", name="Work Yubikey"
        )

        methods = authn.list_mfa(user_id)
        assert len(methods) == 1
        assert methods[0]["name"] == "Work Yubikey"

    def test_validates_mfa_type(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")

        with pytest.raises(AuthnError):
            authn.add_mfa(user_id, "invalid_type", "secret")

    def test_valid_mfa_types(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")

        for mfa_type in ["totp", "webauthn", "recovery_codes"]:
            mfa_id = authn.add_mfa(user_id, mfa_type, f"secret_{mfa_type}")
            assert mfa_id is not None


class TestGetMfa:
    def test_returns_secrets_for_verification(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_mfa(user_id, "totp", "JBSWY3DPEHPK3PXP", name="Authenticator")

        methods = authn.get_mfa(user_id, "totp")

        assert len(methods) == 1
        assert methods[0]["secret"] == "JBSWY3DPEHPK3PXP"
        assert methods[0]["name"] == "Authenticator"

    def test_returns_multiple_methods(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_mfa(user_id, "webauthn", "key1", name="Yubikey 1")
        authn.add_mfa(user_id, "webauthn", "key2", name="Yubikey 2")

        methods = authn.get_mfa(user_id, "webauthn")
        assert len(methods) == 2

    def test_returns_empty_if_no_methods(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        methods = authn.get_mfa(user_id, "totp")
        assert methods == []


class TestListMfa:
    def test_lists_all_mfa_methods(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_mfa(user_id, "totp", "secret1")
        authn.add_mfa(user_id, "webauthn", "secret2")

        methods = authn.list_mfa(user_id)

        assert len(methods) == 2
        # Secrets should NOT be returned
        for m in methods:
            assert "secret" not in m

    def test_returns_empty_if_no_methods(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        methods = authn.list_mfa(user_id)
        assert methods == []


class TestRemoveMfa:
    def test_removes_mfa_method(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        mfa_id = authn.add_mfa(user_id, "totp", "secret")

        result = authn.remove_mfa(mfa_id)

        assert result is True
        assert authn.list_mfa(user_id) == []

    def test_returns_false_for_unknown_id(self, authn):
        result = authn.remove_mfa("00000000-0000-0000-0000-000000000000")
        assert result is False


class TestRecordMfaUse:
    def test_updates_last_used_at(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        mfa_id = authn.add_mfa(user_id, "totp", "secret")

        # Initially null
        methods = authn.list_mfa(user_id)
        assert methods[0]["last_used_at"] is None

        result = authn.record_mfa_use(mfa_id)
        assert result is True

        # Now set
        methods = authn.list_mfa(user_id)
        assert methods[0]["last_used_at"] is not None

    def test_returns_false_for_unknown_id(self, authn):
        result = authn.record_mfa_use("00000000-0000-0000-0000-000000000000")
        assert result is False


class TestHasMfa:
    def test_returns_true_if_mfa_enabled(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_mfa(user_id, "totp", "secret")

        assert authn.has_mfa(user_id) is True

    def test_returns_false_if_no_mfa(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")

        assert authn.has_mfa(user_id) is False

    def test_returns_false_after_removal(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        mfa_id = authn.add_mfa(user_id, "totp", "secret")
        authn.remove_mfa(mfa_id)

        assert authn.has_mfa(user_id) is False
