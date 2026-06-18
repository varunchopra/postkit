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
        assert len(events) == 1
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

    def test_rejects_duplicate_email_in_namespace(self, authn):
        authn.create_user("alice@example.com", "hash")
        bob_id = authn.create_user("bob@example.com", "hash")
        with pytest.raises(UniqueViolationError):
            authn.update_email(bob_id, "alice@example.com")

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

        assert authn.disable_user(user_id) is True

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

        assert authn.delete_user(user_id) is True
        assert len(authn.list_user_credentials(user_id)) == 0

    def test_returns_false_for_unknown_user(self, authn):
        result = authn.delete_user("00000000-0000-0000-0000-000000000000")
        assert result is False


class TestListUsers:
    def test_lists_users_with_total(self, authn):
        authn.create_user("alice@example.com", "hash")
        authn.create_user("bob@example.com", "hash")

        users, total = authn.list_users()

        assert total == 2
        assert {u["email"] for u in users} == {"alice@example.com", "bob@example.com"}

    def test_orders_by_email(self, authn):
        authn.create_user("charlie@example.com", "hash")
        authn.create_user("alice@example.com", "hash")
        authn.create_user("bob@example.com", "hash")

        users, _ = authn.list_users()

        assert [u["email"] for u in users] == [
            "alice@example.com",
            "bob@example.com",
            "charlie@example.com",
        ]

    def test_total_is_full_match_count_not_page_size(self, authn):
        for i in range(5):
            authn.create_user(f"user{i}@example.com", "hash")

        users, total = authn.list_users(limit=2)

        assert len(users) == 2
        assert total == 5

    def test_offset_paginates_in_email_order(self, authn):
        for i in range(5):
            authn.create_user(f"user{i}@example.com", "hash")

        page1, total1 = authn.list_users(limit=2, offset=0)
        page2, total2 = authn.list_users(limit=2, offset=2)

        assert total1 == total2 == 5
        assert [u["email"] for u in page1] == ["user0@example.com", "user1@example.com"]
        assert [u["email"] for u in page2] == ["user2@example.com", "user3@example.com"]
        assert {u["user_id"] for u in page1}.isdisjoint(u["user_id"] for u in page2)

    def test_clamps_limit_to_maximum(self, authn):
        """Limits above 1000 are clamped rather than erroring."""
        for i in range(3):
            authn.create_user(f"limituser{i}@example.com", "hash")

        users, total = authn.list_users(limit=5000)

        assert len(users) == 3
        assert total == 3

    def test_search_filters_by_email_substring(self, authn):
        authn.create_user("alice@acme.com", "hash")
        authn.create_user("bob@acme.com", "hash")
        authn.create_user("carol@other.com", "hash")

        users, total = authn.list_users(search="acme")

        assert total == 2
        assert {u["email"] for u in users} == {"alice@acme.com", "bob@acme.com"}

    def test_search_matches_local_part_and_domain(self, authn):
        """Substring match, not prefix: 'acme' finds it in the local part or domain."""
        authn.create_user("acme@example.com", "hash")
        authn.create_user("user@acme.com", "hash")

        _, total = authn.list_users(search="acme")

        assert total == 2

    def test_search_is_case_insensitive(self, authn):
        authn.create_user("Alice@Example.com", "hash")  # stored lowercased

        users, total = authn.list_users(search="ALICE")

        assert total == 1
        assert users[0]["email"] == "alice@example.com"

    def test_search_no_match_returns_empty_and_zero(self, authn):
        authn.create_user("alice@example.com", "hash")

        users, total = authn.list_users(search="zzz")

        assert users == []
        assert total == 0

    @pytest.mark.parametrize("local", ["a_b", "a%b"], ids=["underscore", "percent"])
    def test_search_treats_like_wildcards_as_literals(self, authn, local):
        """Operator-typed _ and % match literally, not as SQL LIKE wildcards."""
        authn.create_user(f"{local}@example.com", "hash")
        authn.create_user(
            "axb@example.com", "hash"
        )  # would match if _/% were wildcards

        users, total = authn.list_users(search=local)

        assert total == 1
        assert users[0]["email"] == f"{local}@example.com"

    def test_search_finds_matches_beyond_the_page(self, authn):
        """Filtering happens before LIMIT, so matches past the first page are
        counted and reachable (the original bug filtered in memory after a
        capped fetch, silently dropping them)."""
        for name in ("amy", "ben", "cara"):
            authn.create_user(f"{name}@acme.com", "hash")
        authn.create_user("dan@other.com", "hash")

        page, total = authn.list_users(search="acme", limit=2)
        rest, _ = authn.list_users(search="acme", limit=2, offset=2)

        assert total == 3  # all matches counted, not capped at the limit
        assert len(page) == 2
        assert len(rest) == 1  # the third match is reachable, not lost
        assert {u["email"] for u in page + rest} == {
            "amy@acme.com",
            "ben@acme.com",
            "cara@acme.com",
        }

    def test_includes_disabled_users(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.disable_user(user_id)

        users, total = authn.list_users(search="alice")

        assert total == 1
        assert users[0]["disabled_at"] is not None

    def test_excludes_password_hash(self, authn):
        authn.create_user("alice@example.com", "secret_hash")

        users, _ = authn.list_users()

        assert "password_hash" not in users[0]

    def test_respects_namespace_isolation(self, make_authn):
        tenant_a = make_authn("tenant_a")
        tenant_b = make_authn("tenant_b")
        tenant_a.create_user("alice@acme.com", "hash")
        tenant_b.create_user("bob@acme.com", "hash")

        users, total = tenant_a.list_users(search="acme")

        assert total == 1
        assert users[0]["email"] == "alice@acme.com"


class TestCountUsers:
    def test_counts_all_users(self, authn):
        for i in range(3):
            authn.create_user(f"user{i}@example.com", "hash")

        assert authn.count_users() == 3

    def test_counts_zero_for_empty_namespace(self, authn):
        assert authn.count_users() == 0

    def test_counts_matching_search(self, authn):
        authn.create_user("alice@acme.com", "hash")
        authn.create_user("bob@acme.com", "hash")
        authn.create_user("carol@other.com", "hash")

        assert authn.count_users(search="acme") == 2

    def test_count_zero_when_no_match(self, authn):
        authn.create_user("alice@example.com", "hash")

        assert authn.count_users(search="zzz") == 0

    def test_count_equals_list_total(self, authn):
        for name in ("amy", "ben", "cara"):
            authn.create_user(f"{name}@acme.com", "hash")
        authn.create_user("dan@other.com", "hash")

        _, total = authn.list_users(search="acme")

        assert authn.count_users(search="acme") == total == 3

    def test_count_is_case_insensitive(self, authn):
        authn.create_user("Alice@Example.com", "hash")

        assert authn.count_users(search="ALICE") == 1

    def test_count_treats_underscore_as_literal(self, authn):
        authn.create_user("a_b@example.com", "hash")
        authn.create_user("axb@example.com", "hash")

        assert authn.count_users(search="a_b") == 1

    def test_count_respects_namespace_isolation(self, make_authn):
        tenant_a = make_authn("tenant_a")
        tenant_b = make_authn("tenant_b")
        tenant_a.create_user("alice@acme.com", "hash")
        tenant_b.create_user("bob@acme.com", "hash")

        assert tenant_a.count_users(search="acme") == 1


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
