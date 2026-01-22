"""Tests for user management functions."""

import pytest
from postkit.authn import AuthnError
from postkit.base import UniqueViolationError


class TestCreateUser:
    def test_creates_user_with_email_and_password(self, authn):
        user_id = authn.create_user("alice@example.com", "argon2_hash_here")
        assert user_id is not None

        user = authn.get_user(user_id)
        assert user["email"] == "alice@example.com"
        assert user["email_verified_at"] is None
        assert user["disabled_at"] is None

    def test_creates_user_without_password(self, authn):
        """SSO-only users have no password hash."""
        user_id = authn.create_user("sso@example.com")
        assert user_id is not None

        user = authn.get_user(user_id)
        assert user["email"] == "sso@example.com"

    def test_normalizes_email_to_lowercase(self, authn):
        user_id = authn.create_user("ALICE@EXAMPLE.COM", "hash")
        user = authn.get_user(user_id)
        assert user["email"] == "alice@example.com"

    def test_trims_email_whitespace(self, authn):
        user_id = authn.create_user("  alice@example.com  ", "hash")
        user = authn.get_user(user_id)
        assert user["email"] == "alice@example.com"

    def test_rejects_duplicate_email_in_namespace(self, authn):
        authn.create_user("alice@example.com", "hash1")
        with pytest.raises(UniqueViolationError):
            authn.create_user("alice@example.com", "hash2")

    def test_allows_same_email_different_namespace(self, make_authn):
        tenant_a = make_authn("tenant_a")
        tenant_b = make_authn("tenant_b")

        user_a = tenant_a.create_user("alice@example.com", "hash")
        user_b = tenant_b.create_user("alice@example.com", "hash")

        assert user_a is not None
        assert user_b is not None
        assert user_a != user_b

    def test_rejects_null_email(self, authn):
        with pytest.raises(AuthnError):
            authn.create_user(None, "hash")

    def test_rejects_empty_email(self, authn):
        with pytest.raises(AuthnError):
            authn.create_user("", "hash")

    def test_rejects_invalid_email_format(self, authn):
        with pytest.raises(AuthnError):
            authn.create_user("not-an-email", "hash")

    def test_rejects_empty_password_hash(self, authn):
        with pytest.raises(AuthnError):
            authn.create_user("alice@example.com", "")

    def test_logs_audit_event(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")

        events = authn.get_audit_events(event_type="user_created")
        assert len(events) >= 1
        assert events[0]["resource_id"] == user_id


class TestGetUser:
    def test_returns_user_by_id(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        user = authn.get_user(user_id)

        assert user["user_id"] == user_id  # UUIDs returned as strings
        assert user["email"] == "alice@example.com"
        assert "password_hash" not in user  # Security: excluded

    def test_returns_none_for_unknown_id(self, authn):
        user = authn.get_user("00000000-0000-0000-0000-000000000000")
        assert user is None


class TestGetUserByEmail:
    def test_returns_user_by_email(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        user = authn.get_user_by_email("alice@example.com")

        assert user["user_id"] == user_id  # UUIDs returned as strings
        assert user["email"] == "alice@example.com"

    def test_normalizes_email_for_lookup(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        user = authn.get_user_by_email("ALICE@EXAMPLE.COM")
        assert user["user_id"] == user_id  # UUIDs returned as strings

    def test_returns_none_for_unknown_email(self, authn):
        user = authn.get_user_by_email("unknown@example.com")
        assert user is None


class TestUpdateEmail:
    def test_updates_email(self, authn):
        user_id = authn.create_user("old@example.com", "hash")
        result = authn.update_email(user_id, "new@example.com")

        assert result is True
        user = authn.get_user(user_id)
        assert user["email"] == "new@example.com"

    def test_clears_email_verified_at(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")

        # Manually set verified_at
        test_helpers.cursor.execute(
            "UPDATE authn.users SET email_verified_at = now() WHERE id = %s::uuid",
            (user_id,),
        )

        authn.update_email(user_id, "new@example.com")
        user = authn.get_user(user_id)
        assert user["email_verified_at"] is None

    def test_returns_false_for_unknown_user(self, authn):
        result = authn.update_email(
            "00000000-0000-0000-0000-000000000000", "new@example.com"
        )
        assert result is False


class TestDisableUser:
    def test_disables_user(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        result = authn.disable_user(user_id)

        assert result is True
        user = authn.get_user(user_id)
        assert user["disabled_at"] is not None

    def test_revokes_all_sessions(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token1")
        authn.create_session(user_id, "token2")

        authn.disable_user(user_id)

        # Sessions should be revoked
        assert authn.validate_session("token1") is None
        assert authn.validate_session("token2") is None

    def test_returns_false_if_already_disabled(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.disable_user(user_id)
        result = authn.disable_user(user_id)
        assert result is False


class TestEnableUser:
    def test_enables_disabled_user(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.disable_user(user_id)

        result = authn.enable_user(user_id)

        assert result is True
        user = authn.get_user(user_id)
        assert user["disabled_at"] is None

    def test_returns_false_if_not_disabled(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        result = authn.enable_user(user_id)
        assert result is False


class TestDeleteUser:
    def test_deletes_user(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        result = authn.delete_user(user_id)

        assert result is True
        assert authn.get_user(user_id) is None

    def test_cascades_to_sessions(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_session(user_id, "token")
        assert test_helpers.count_sessions(user_id) == 1

        authn.delete_user(user_id)
        assert test_helpers.count_sessions(user_id) == 0

    def test_cascades_to_credentials(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.add_credential(user_id, "totp", secret_data="seed")
        assert len(authn.list_user_credentials(user_id)) == 1

        authn.delete_user(user_id)
        assert len(authn.list_user_credentials(user_id)) == 0

    def test_returns_false_for_unknown_user(self, authn):
        result = authn.delete_user("00000000-0000-0000-0000-000000000000")
        assert result is False


class TestListUsers:
    def test_lists_users(self, authn):
        authn.create_user("alice@example.com", "hash")
        authn.create_user("bob@example.com", "hash")

        users = authn.list_users()

        assert len(users) == 2
        emails = {u["email"] for u in users}
        assert "alice@example.com" in emails
        assert "bob@example.com" in emails

    def test_respects_limit(self, authn):
        for i in range(5):
            authn.create_user(f"user{i}@example.com", "hash")

        users = authn.list_users(limit=2)
        assert len(users) == 2

    def test_supports_cursor_pagination(self, authn):
        for i in range(5):
            authn.create_user(f"user{i}@example.com", "hash")

        page1 = authn.list_users(limit=2)
        assert len(page1) == 2

        page2 = authn.list_users(limit=2, cursor=page1[-1]["user_id"])
        assert len(page2) == 2

        # Pages should be different
        ids1 = {u["user_id"] for u in page1}
        ids2 = {u["user_id"] for u in page2}
        assert ids1.isdisjoint(ids2)

    def test_clamps_limit_to_maximum(self, authn):
        """Limit values above 1000 are clamped to 1000."""
        # Create a few users to verify function works correctly
        for i in range(3):
            authn.create_user(f"limituser{i}@example.com", "hash")

        # Request with limit exceeding max - should not error
        users = authn.list_users(limit=5000)
        # Should get all 3 users (less than clamped limit of 1000)
        assert len(users) == 3


class TestGetUsersBatch:
    """Tests for batch user fetching."""

    def test_returns_multiple_users(self, authn):
        user1_id = authn.create_user("alice@example.com", "hash")
        user2_id = authn.create_user("bob@example.com", "hash")
        user3_id = authn.create_user("charlie@example.com", "hash")

        users = authn.get_users_batch([user1_id, user2_id, user3_id])

        assert len(users) == 3
        assert users[user1_id]["email"] == "alice@example.com"
        assert users[user2_id]["email"] == "bob@example.com"
        assert users[user3_id]["email"] == "charlie@example.com"

    def test_omits_missing_ids(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        fake_id = "00000000-0000-0000-0000-000000000000"

        users = authn.get_users_batch([user_id, fake_id])

        assert len(users) == 1
        assert user_id in users
        assert fake_id not in users

    def test_returns_empty_dict_for_empty_list(self, authn):
        users = authn.get_users_batch([])
        assert users == {}

    def test_excludes_password_hash(self, authn):
        user_id = authn.create_user("alice@example.com", "secret_hash")

        users = authn.get_users_batch([user_id])

        assert "password_hash" not in users[user_id]

    def test_respects_namespace_isolation(self, make_authn):
        tenant_a = make_authn("tenant_a")
        tenant_b = make_authn("tenant_b")

        user_a = tenant_a.create_user("alice@example.com", "hash")
        user_b = tenant_b.create_user("bob@example.com", "hash")

        # Tenant A can't see Tenant B's user
        users = tenant_a.get_users_batch([user_a, user_b])
        assert len(users) == 1
        assert user_a in users
        assert user_b not in users


class TestGetOrCreateUser:
    """Tests for atomic get-or-create user functionality."""

    def test_creates_new_user(self, authn):
        user_id, created = authn.get_or_create_user("alice@example.com")

        assert user_id is not None
        assert created is True

        user = authn.get_user(user_id)
        assert user["email"] == "alice@example.com"

    def test_returns_existing_user(self, authn):
        # Create user first
        original_id = authn.create_user("alice@example.com", "hash")

        # get_or_create should return existing user
        user_id, created = authn.get_or_create_user("alice@example.com")

        assert user_id == original_id
        assert created is False

    def test_creates_sso_user_without_password(self, authn):
        user_id, created = authn.get_or_create_user("sso@example.com", None)

        assert user_id is not None
        assert created is True

    def test_normalizes_email(self, authn):
        user_id1, created1 = authn.get_or_create_user("Alice@Example.COM")
        user_id2, created2 = authn.get_or_create_user("alice@example.com")

        assert user_id1 == user_id2
        assert created1 is True
        assert created2 is False

    def test_raises_for_disabled_user(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.disable_user(user_id)

        with pytest.raises(AuthnError, match="disabled"):
            authn.get_or_create_user("alice@example.com")
