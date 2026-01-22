"""Tests for credential management functions (TOTP, WebAuthn, recovery codes)."""

import pytest
from postkit.authn import AuthnError
from postkit.base import UniqueViolationError


class TestAddCredential:
    """Tests for add_credential()."""

    def test_adds_totp_credential(self, authn):
        """TOTP credential stores secret_data, no lookup_key."""
        user_id = authn.create_user("alice@example.com", "hash")
        credential_id = authn.add_credential(
            user_id, "totp", secret_data="JBSWY3DPEHPK3PXP"
        )
        assert credential_id is not None

    def test_adds_totp_with_name(self, authn):
        """TOTP credential can have a friendly name."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_credential(
            user_id, "totp", secret_data="JBSWY3DPEHPK3PXP", name="Authenticator App"
        )

        creds = authn.list_user_credentials(user_id)
        assert len(creds) == 1
        assert creds[0]["name"] == "Authenticator App"

    def test_adds_recovery_code(self, authn):
        """Recovery code stores lookup_key (hash), no secret_data."""
        user_id = authn.create_user("alice@example.com", "hash")
        credential_id = authn.add_credential(
            user_id, "recovery_code", lookup_key="sha256_of_code_1"
        )
        assert credential_id is not None

    def test_adds_webauthn_credential(self, authn):
        """WebAuthn stores both lookup_key (credential_id) and secret_data (public key)."""
        user_id = authn.create_user("alice@example.com", "hash")
        credential_id = authn.add_credential(
            user_id,
            "webauthn",
            lookup_key="credential_id_base64",
            secret_data="cose_public_key",
            name="YubiKey 5",
        )
        assert credential_id is not None

    def test_validates_credential_type(self, authn):
        """Invalid credential type is rejected."""
        user_id = authn.create_user("alice@example.com", "hash")

        with pytest.raises(AuthnError):
            authn.add_credential(user_id, "invalid_type", secret_data="secret")

    def test_valid_credential_types(self, authn):
        """All valid credential types are accepted."""
        user_id = authn.create_user("alice@example.com", "hash")

        for ctype in ["totp", "recovery_code", "webauthn"]:
            if ctype == "totp":
                cred_id = authn.add_credential(user_id, ctype, secret_data="seed")
            elif ctype == "recovery_code":
                cred_id = authn.add_credential(user_id, ctype, lookup_key="hash")
            else:  # webauthn
                cred_id = authn.add_credential(
                    user_id, ctype, lookup_key="cred_id", secret_data="pubkey"
                )
            assert cred_id is not None

    def test_requires_lookup_or_secret(self, authn):
        """At least one of lookup_key or secret_data must be provided."""
        user_id = authn.create_user("alice@example.com", "hash")

        with pytest.raises(AuthnError):
            authn.add_credential(user_id, "totp")


class TestGetCredentials:
    """Tests for get_user_credentials()."""

    def test_returns_secrets_for_verification(self, authn):
        """get_user_credentials returns secret_data for verification."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_credential(user_id, "totp", secret_data="JBSWY3DPEHPK3PXP")

        creds = authn.get_user_credentials(user_id, "totp")

        assert len(creds) == 1
        assert creds[0]["secret_data"] == "JBSWY3DPEHPK3PXP"

    def test_returns_multiple_credentials(self, authn):
        """User can have multiple credentials of same type."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_credential(
            user_id, "webauthn", lookup_key="key1", secret_data="pk1", name="YubiKey 1"
        )
        authn.add_credential(
            user_id, "webauthn", lookup_key="key2", secret_data="pk2", name="YubiKey 2"
        )

        creds = authn.get_user_credentials(user_id, "webauthn")
        assert len(creds) == 2

    def test_returns_empty_if_no_credentials(self, authn):
        """Empty list returned when no credentials exist."""
        user_id = authn.create_user("alice@example.com", "hash")
        creds = authn.get_user_credentials(user_id, "totp")
        assert creds == []

    def test_excludes_disabled_credentials(self, authn):
        """Disabled credentials are not returned."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "totp", secret_data="seed")
        authn.disable_credential(cred_id, "Testing disabled exclusion")

        creds = authn.get_user_credentials(user_id, "totp")
        assert creds == []

    def test_excludes_consumed_credentials(self, authn):
        """Consumed credentials (recovery codes) are not returned."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "recovery_code", lookup_key="hash1")
        authn.consume_credential(cred_id)

        creds = authn.get_user_credentials(user_id, "recovery_code")
        assert creds == []


class TestGetCredentialByLookup:
    """Tests for get_credential_by_lookup()."""

    def test_returns_credential_by_hash(self, authn):
        """Can lookup recovery code by hash."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_credential(user_id, "recovery_code", lookup_key="sha256_hash")

        cred = authn.get_credential_by_lookup(user_id, "sha256_hash", "recovery_code")

        assert cred is not None
        assert cred["consumed_at"] is None

    def test_returns_none_if_not_found(self, authn):
        """Returns None when lookup key doesn't exist."""
        user_id = authn.create_user("alice@example.com", "hash")

        cred = authn.get_credential_by_lookup(user_id, "nonexistent", "recovery_code")
        assert cred is None

    def test_returns_consumed_at_for_used_codes(self, authn):
        """Returns consumed_at so caller knows if code was already used."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "recovery_code", lookup_key="hash1")
        authn.consume_credential(cred_id)

        cred = authn.get_credential_by_lookup(user_id, "hash1", "recovery_code")
        assert cred is not None
        assert cred["consumed_at"] is not None

    def test_requires_correct_user_id(self, authn):
        """Lookup requires correct user_id (enumeration prevention)."""
        user1 = authn.create_user("alice@example.com", "hash")
        user2 = authn.create_user("bob@example.com", "hash")

        authn.add_credential(user1, "recovery_code", lookup_key="alice_code")

        # User2 cannot find User1's recovery code
        cred = authn.get_credential_by_lookup(user2, "alice_code", "recovery_code")
        assert cred is None


class TestRecordCredentialUse:
    """Tests for record_credential_use()."""

    def test_updates_last_used_at(self, authn):
        """Recording use updates last_used_at."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "totp", secret_data="seed")

        # Initially null
        creds = authn.list_user_credentials(user_id)
        assert creds[0]["last_used_at"] is None

        authn.record_credential_use(cred_id)

        # Now set
        creds = authn.list_user_credentials(user_id)
        assert creds[0]["last_used_at"] is not None


class TestConsumeCredential:
    """Tests for consume_credential()."""

    def test_consumes_recovery_code(self, authn):
        """Consuming a recovery code sets consumed_at."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "recovery_code", lookup_key="hash1")

        result = authn.consume_credential(cred_id)
        assert result is True

        creds = authn.list_user_credentials(user_id)
        assert creds[0]["consumed_at"] is not None

    def test_returns_false_for_already_consumed(self, authn):
        """Returns False when trying to consume an already consumed credential."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "recovery_code", lookup_key="hash1")

        authn.consume_credential(cred_id)
        result = authn.consume_credential(cred_id)

        assert result is False

    def test_returns_false_for_disabled(self, authn):
        """Returns False when trying to consume a disabled credential."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "recovery_code", lookup_key="hash1")
        authn.disable_credential(cred_id, "Disabled for test")

        result = authn.consume_credential(cred_id)
        assert result is False


class TestUpdateSignCount:
    """Tests for update_sign_count() (WebAuthn clone detection)."""

    def test_updates_sign_count(self, authn):
        """Sign count is updated when new count is greater."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(
            user_id, "webauthn", lookup_key="cred_id", secret_data="pubkey"
        )

        result = authn.update_sign_count(cred_id, 5)
        assert result is True

        # Update again with higher count
        result = authn.update_sign_count(cred_id, 10)
        assert result is True

    def test_detects_clone_attack(self, authn):
        """Returns False when new count <= current (clone detection)."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(
            user_id, "webauthn", lookup_key="cred_id", secret_data="pubkey"
        )

        authn.update_sign_count(cred_id, 10)

        # Attempt with lower count (clone attack!)
        result = authn.update_sign_count(cred_id, 5)
        assert result is False

        # Attempt with same count (also clone attack!)
        result = authn.update_sign_count(cred_id, 10)
        assert result is False


class TestDisableCredential:
    """Tests for disable_credential()."""

    def test_disables_credential(self, authn):
        """Credential can be disabled with a reason."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "totp", secret_data="seed")

        result = authn.disable_credential(cred_id, "Reported as compromised")
        assert result is True

        creds = authn.list_user_credentials(user_id, include_disabled=True)
        assert creds[0]["disabled_at"] is not None
        assert creds[0]["disabled_reason"] == "Reported as compromised"

    def test_requires_reason(self, authn):
        """Disabling without reason raises error."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "totp", secret_data="seed")

        with pytest.raises(AuthnError):
            authn.disable_credential(cred_id, "")

    def test_returns_false_for_already_disabled(self, authn):
        """Returns False when credential is already disabled."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "totp", secret_data="seed")

        authn.disable_credential(cred_id, "First disable")
        result = authn.disable_credential(cred_id, "Second disable")

        assert result is False


class TestRemoveCredential:
    """Tests for remove_credential()."""

    def test_removes_credential(self, authn):
        """Credential is permanently deleted."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "totp", secret_data="seed")

        result = authn.remove_credential(cred_id)
        assert result is True

        creds = authn.list_user_credentials(user_id, include_disabled=True)
        assert len(creds) == 0

    def test_returns_false_for_nonexistent(self, authn):
        """Returns False when credential doesn't exist."""
        result = authn.remove_credential("00000000-0000-0000-0000-000000000000")
        assert result is False


class TestListCredentials:
    """Tests for list_user_credentials()."""

    def test_lists_all_credentials(self, authn):
        """Lists all credentials for a user."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_credential(user_id, "totp", secret_data="seed")
        authn.add_credential(user_id, "webauthn", lookup_key="key", secret_data="pk")

        creds = authn.list_user_credentials(user_id)
        assert len(creds) == 2

    def test_filters_by_type(self, authn):
        """Can filter credentials by type."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_credential(user_id, "totp", secret_data="seed")
        authn.add_credential(user_id, "webauthn", lookup_key="key", secret_data="pk")

        creds = authn.list_user_credentials(user_id, credential_type="totp")
        assert len(creds) == 1
        assert creds[0]["credential_type"] == "totp"

    def test_excludes_disabled_by_default(self, authn):
        """Disabled credentials are excluded by default."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "totp", secret_data="seed")
        authn.disable_credential(cred_id, "Testing")

        creds = authn.list_user_credentials(user_id)
        assert len(creds) == 0

    def test_includes_disabled_when_requested(self, authn):
        """Disabled credentials are included when include_disabled=True."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "totp", secret_data="seed")
        authn.disable_credential(cred_id, "Testing")

        creds = authn.list_user_credentials(user_id, include_disabled=True)
        assert len(creds) == 1

    def test_does_not_return_secrets(self, authn):
        """Listing does NOT return secret_data or lookup_key."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_credential(user_id, "totp", secret_data="seed")

        creds = authn.list_user_credentials(user_id)
        for cred in creds:
            assert "secret_data" not in cred
            assert "lookup_key" not in cred


class TestHasCredential:
    """Tests for has_credential()."""

    def test_returns_true_if_active_credential_exists(self, authn):
        """Returns True when user has active credential of type."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_credential(user_id, "totp", secret_data="seed")

        assert authn.has_credential(user_id, "totp") is True

    def test_returns_false_if_no_credential(self, authn):
        """Returns False when user has no credential of type."""
        user_id = authn.create_user("alice@example.com", "hash")

        assert authn.has_credential(user_id, "totp") is False

    def test_returns_false_if_credential_disabled(self, authn):
        """Returns False when only credential is disabled."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "totp", secret_data="seed")
        authn.disable_credential(cred_id, "Testing")

        assert authn.has_credential(user_id, "totp") is False

    def test_returns_false_if_credential_consumed(self, authn):
        """Returns False when only credential is consumed."""
        user_id = authn.create_user("alice@example.com", "hash")
        cred_id = authn.add_credential(user_id, "recovery_code", lookup_key="hash")
        authn.consume_credential(cred_id)

        assert authn.has_credential(user_id, "recovery_code") is False


class TestDisableAllCredentials:
    """Tests for disable_all_credentials()."""

    def test_disables_all_credentials(self, authn):
        """All credentials for user are disabled."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_credential(user_id, "totp", secret_data="seed1")
        authn.add_credential(user_id, "totp", secret_data="seed2")
        authn.add_credential(user_id, "webauthn", lookup_key="key", secret_data="pk")

        count = authn.disable_all_credentials(user_id, "Device stolen")
        assert count == 3

        creds = authn.list_user_credentials(user_id)
        assert len(creds) == 0

        # All preserved with reason
        creds = authn.list_user_credentials(user_id, include_disabled=True)
        assert len(creds) == 3
        for cred in creds:
            assert cred["disabled_reason"] == "Device stolen"

    def test_returns_zero_if_no_credentials(self, authn):
        """Returns 0 when user has no active credentials."""
        user_id = authn.create_user("alice@example.com", "hash")

        count = authn.disable_all_credentials(user_id, "Test reason")
        assert count == 0

    def test_requires_reason(self, authn):
        """Bulk disable without reason raises error."""
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_credential(user_id, "totp", secret_data="seed")

        with pytest.raises(AuthnError):
            authn.disable_all_credentials(user_id, "")


class TestWebAuthnUniqueIndex:
    """Tests for WebAuthn credential_id uniqueness."""

    def test_webauthn_credential_id_globally_unique(self, authn):
        """Same WebAuthn credential_id cannot be registered twice."""
        user1 = authn.create_user("alice@example.com", "hash")
        user2 = authn.create_user("bob@example.com", "hash")

        # User1 registers credential_id
        authn.add_credential(
            user1, "webauthn", lookup_key="same_cred_id", secret_data="pk1"
        )

        # User2 cannot register same credential_id
        with pytest.raises(UniqueViolationError):
            authn.add_credential(
                user2, "webauthn", lookup_key="same_cred_id", secret_data="pk2"
            )


class TestRecoveryCodeEnumeration:
    """Tests for recovery code enumeration prevention."""

    def test_same_hash_different_users_allowed(self, authn):
        """Same recovery code hash can exist for different users."""
        user1 = authn.create_user("alice@example.com", "hash")
        user2 = authn.create_user("bob@example.com", "hash")

        # Same hash for different users is OK (unlike WebAuthn)
        authn.add_credential(user1, "recovery_code", lookup_key="same_hash")
        authn.add_credential(user2, "recovery_code", lookup_key="same_hash")

        # Each user can find their own
        cred1 = authn.get_credential_by_lookup(user1, "same_hash", "recovery_code")
        cred2 = authn.get_credential_by_lookup(user2, "same_hash", "recovery_code")

        assert cred1 is not None
        assert cred2 is not None
        assert cred1["id"] != cred2["id"]

    def test_cannot_enumerate_other_users_codes(self, authn):
        """Cannot find another user's recovery code by hash."""
        user1 = authn.create_user("alice@example.com", "hash")
        user2 = authn.create_user("bob@example.com", "hash")

        authn.add_credential(user1, "recovery_code", lookup_key="alice_hash")

        # User2 cannot enumerate User1's codes
        cred = authn.get_credential_by_lookup(user2, "alice_hash", "recovery_code")
        assert cred is None
