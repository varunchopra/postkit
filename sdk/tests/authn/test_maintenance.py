"""Tests for maintenance functions."""


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

        assert result["tokens_deleted"] == 1

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

    def test_deletes_expired_refresh_tokens(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_token")
        authn.create_refresh_token(session_id, "active_refresh")
        test_helpers.insert_expired_refresh_token(
            user_id, session_id, "expired_refresh"
        )

        result = authn.cleanup_expired()

        assert result["refresh_tokens_deleted"] == 1
        assert authn.validate_refresh_token("active_refresh") is not None

    def test_deletes_revoked_refresh_tokens(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_token")
        initial = authn.create_refresh_token(session_id, "refresh_hash")
        authn.revoke_refresh_token_family(str(initial["family_id"]))

        result = authn.cleanup_expired()

        assert result["refresh_tokens_deleted"] == 1

    def test_deletes_replaced_refresh_tokens(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        session_id = authn.create_session(user_id, "session_token")
        authn.create_refresh_token(session_id, "token1")
        authn.rotate_refresh_token("token1", "token2")
        authn.rotate_refresh_token("token2", "token3")

        result = authn.cleanup_expired()

        # token1 and token2 were replaced
        assert result["refresh_tokens_deleted"] == 2
        assert authn.validate_refresh_token("token3") is not None

    def test_deletes_revoked_api_keys(self, authn):
        user_id = authn.create_user("alice@example.com", "hash")
        key1_id = authn.create_api_key(user_id, "key_hash_1", "Active Key")
        key2_id = authn.create_api_key(user_id, "key_hash_2", "To Revoke")
        authn.revoke_api_key(key2_id)

        result = authn.cleanup_expired()

        assert result["api_keys_deleted"] == 1
        keys = authn.list_api_keys(user_id)
        assert len(keys) == 1
        assert str(keys[0]["key_id"]) == key1_id

    def test_deletes_expired_api_keys(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_api_key(user_id, "active_key_hash", "Active Key")
        test_helpers.insert_expired_api_key(user_id, "expired_key_hash")

        result = authn.cleanup_expired()

        assert result["api_keys_deleted"] == 1
        keys = authn.list_api_keys(user_id)
        assert len(keys) == 1

    def test_deletes_ended_impersonation_sessions(self, authn):
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        imp = authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token_1"
        )
        authn.end_impersonation(str(imp["impersonation_id"]))

        authn.start_impersonation(
            admin_session, target_id, "Active support", token_hash="imp_token_2"
        )

        result = authn.cleanup_expired()

        assert result["impersonations_deleted"] == 1
        active = authn.list_active_impersonations()
        assert len(active) == 1

    def test_deletes_expired_impersonation_sessions(self, authn):
        admin_id = authn.create_user("admin@example.com", "hash1")
        target_id = authn.create_user("target@example.com", "hash2")
        admin_session = authn.create_session(admin_id, "admin_token")

        authn.start_impersonation(
            admin_session, target_id, "Support ticket", token_hash="imp_token"
        )
        authn.cursor.execute(
            "UPDATE authn.impersonation_sessions SET expires_at = now() - interval '1 minute' WHERE namespace = %s",
            (authn.namespace,),
        )

        result = authn.cleanup_expired()

        assert result["impersonations_deleted"] == 1

    def test_deletes_ended_operator_impersonation_sessions(self, make_authn):
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")
        target_id = customer.create_user("target@customer.com", "hash2")

        imp = platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token_1",
            reason="Support ticket",
        )
        platform.end_operator_impersonation(str(imp["impersonation_id"]))

        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token_2",
            reason="Active support",
        )

        result = platform.cleanup_expired()

        assert result["operator_impersonations_deleted"] == 1
        active = platform.list_active_operator_impersonations()
        assert len(active) == 1

    def test_deletes_expired_operator_impersonation_sessions(self, make_authn):
        platform = make_authn("platform")
        customer = make_authn("customer")

        operator_id = platform.create_user("operator@platform.com", "hash1")
        operator_session = platform.create_session(operator_id, "operator_token")
        target_id = customer.create_user("target@customer.com", "hash2")

        platform.start_operator_impersonation(
            operator_session_id=operator_session,
            target_user_id=target_id,
            target_namespace="customer",
            token_hash="imp_token",
            reason="Support ticket",
        )
        platform.cursor.execute(
            "UPDATE authn.operator_impersonation_sessions SET expires_at = now() - interval '1 minute'"
        )

        result = platform.cleanup_expired()

        assert result["operator_impersonations_deleted"] == 1

    def test_deletes_expired_tokens(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "active_token", "password_reset")
        test_helpers.insert_expired_token(user_id, "expired_token", "password_reset")

        result = authn.cleanup_expired()

        assert result["tokens_deleted"] == 1
        assert test_helpers.count_tokens(user_id) == 1


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

        # Create API key
        authn.create_api_key(user1, "api_key_hash", "My Key")

        # Create refresh token
        session3 = authn.create_session(user1, "session3")
        authn.create_refresh_token(session3, "refresh1")

        # Add credential (TOTP)
        authn.add_credential(user1, "totp", secret_data="secret")

        stats = authn.get_stats()

        assert stats["user_count"] == 2
        assert stats["verified_user_count"] == 1
        assert stats["disabled_user_count"] == 1
        assert stats["active_session_count"] == 3
        assert stats["active_api_key_count"] == 1
        assert stats["active_refresh_token_count"] == 1
        assert stats["credential_enabled_user_count"] == 1

    def test_returns_zeros_for_empty_namespace(self, authn):
        stats = authn.get_stats()

        assert stats["user_count"] == 0
        assert stats["verified_user_count"] == 0
        assert stats["disabled_user_count"] == 0
        assert stats["active_session_count"] == 0
        assert stats["active_api_key_count"] == 0
        assert stats["active_refresh_token_count"] == 0
        assert stats["credential_enabled_user_count"] == 0
