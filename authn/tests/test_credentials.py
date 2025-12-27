"""Tests for credential management functions."""

import pytest
from authn_sdk import AuthnError


class TestGetCredentials:
    def test_returns_credentials_for_login(self, authn):
        user_id = authn.create_user("alice@example.com", "argon2_hash")
        creds = authn.get_credentials("alice@example.com")

        assert creds is not None
        assert str(creds["user_id"]) == user_id
        assert creds["password_hash"] == "argon2_hash"
        assert creds["disabled_at"] is None

    def test_returns_disabled_at_for_disabled_user(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.disable_user(user_id)

        creds = authn.get_credentials("alice@example.com")

        assert creds["disabled_at"] is not None

    def test_returns_none_for_unknown_email(self, authn):
        creds = authn.get_credentials("unknown@example.com")
        assert creds is None

    def test_normalizes_email_for_lookup(self, authn):
        authn.create_user("alice@example.com", "hash")
        creds = authn.get_credentials("ALICE@EXAMPLE.COM")
        assert creds is not None

    def test_returns_null_hash_for_sso_user(self, authn):
        authn.create_user("sso@example.com")
        creds = authn.get_credentials("sso@example.com")

        assert creds is not None
        assert creds["password_hash"] is None


class TestUpdatePassword:
    def test_updates_password_hash(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "old_hash")
        result = authn.update_password(user_id, "new_hash")

        assert result is True

        # Verify via raw access
        user = test_helpers.get_user_raw(user_id)
        assert user["password_hash"] == "new_hash"

    def test_returns_false_for_unknown_user(self, authn):
        result = authn.update_password(
            "00000000-0000-0000-0000-000000000000",
            "new_hash",
        )
        assert result is False

    def test_rejects_empty_hash(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        with pytest.raises(AuthnError):
            authn.update_password(user_id, "")

    def test_logs_audit_event_without_hash(self, authn):
        user_id = authn.create_user("alice@example.com", "old_hash")
        authn.update_password(user_id, "new_hash")

        events = authn.get_audit_events(
            event_type="password_updated",
            resource_id=user_id,
        )

        assert len(events) >= 1
        # Verify hash is NOT logged
        event = events[0]
        assert event.get("old_values") is None
        assert event.get("new_values") is None
