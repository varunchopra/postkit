"""Tests for maintenance functions."""


def _operator_session(client):
    """One operator user with a session, the actor for impersonations."""
    operator_id = client.create_user(f"operator@{client.namespace}.com", "hash")
    return client.create_session(operator_id, f"{client.namespace}_op_token")


def _impersonation(client, operator_session_id, target_id, token_hash, ended=True):
    imp = client.start_operator_impersonation(
        operator_session_id=operator_session_id,
        target_user_id=target_id,
        target_namespace="customer",
        token_hash=token_hash,
        reason="Support ticket",
    )
    if ended:
        client.end_operator_impersonation(str(imp["impersonation_id"]))
    return imp


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

    def test_cleanup_expired_leaves_operator_impersonation_sessions(self, make_authn):
        platform = make_authn("platform")
        customer = make_authn("customer")
        target_id = customer.create_user("target@customer.com", "hash")
        _impersonation(platform, _operator_session(platform), target_id, "imp_token_1")

        platform.cleanup_expired()

        assert platform.cleanup_expired_operator_sessions() == 1

    def test_deletes_expired_tokens(self, authn, test_helpers):
        user_id = authn.create_user("alice@example.com", "hash")
        authn.create_token(user_id, "active_token", "password_reset")
        test_helpers.insert_expired_token(user_id, "expired_token", "password_reset")

        result = authn.cleanup_expired()

        assert result["tokens_deleted"] == 1
        assert test_helpers.count_tokens(user_id) == 1


class TestCleanupExpiredOperatorSessions:
    def test_deletes_ended_operator_impersonation_sessions(self, make_authn):
        platform = make_authn("platform")
        customer = make_authn("customer")
        target_id = customer.create_user("target@customer.com", "hash")
        operator_session = _operator_session(platform)
        _impersonation(platform, operator_session, target_id, "imp_token_1")
        _impersonation(
            platform, operator_session, target_id, "imp_token_2", ended=False
        )

        deleted = platform.cleanup_expired_operator_sessions()

        assert deleted == 1
        active = platform.list_active_operator_impersonations()
        assert len(active) == 1

    def test_deletes_expired_operator_impersonation_sessions(self, make_authn):
        platform = make_authn("platform")
        customer = make_authn("customer")
        target_id = customer.create_user("target@customer.com", "hash")
        _impersonation(
            platform, _operator_session(platform), target_id, "imp_token", ended=False
        )
        platform.cursor.execute(
            "UPDATE authn.operator_impersonation_sessions SET expires_at = now() - interval '1 minute'"
        )

        assert platform.cleanup_expired_operator_sessions() == 1

    def test_deletes_across_operator_namespaces(self, make_authn):
        customer = make_authn("customer")
        target_id = customer.create_user("target@customer.com", "hash")

        operators = [make_authn(ns) for ns in ("platform", "platform2")]
        for operator in operators:
            _impersonation(
                operator,
                _operator_session(operator),
                target_id,
                f"{operator.namespace}_imp_token",
            )

        assert operators[0].cleanup_expired_operator_sessions() == 2


class TestCleanupPlanShape:
    """Every cleanup harvest keeps an index path: a Seq Scan here means an
    arm predicate stopped implying its partial index (see the per-arm note
    on authn.cleanup_expired)."""

    HARVESTS = [
        ("refresh_tokens", "revoked_at IS NULL AND expires_at < now()"),
        ("refresh_tokens", "(replaced_by IS NOT NULL OR revoked_at IS NOT NULL)"),
        ("impersonation_sessions", "ended_at IS NOT NULL"),
        ("impersonation_sessions", "ended_at IS NULL AND expires_at < now()"),
        ("sessions", "revoked_at IS NULL AND expires_at < now()"),
        ("sessions", "revoked_at IS NOT NULL"),
        ("tokens", "used_at IS NULL AND expires_at < now()"),
        ("tokens", "used_at IS NOT NULL"),
        ("api_keys", "revoked_at IS NOT NULL"),
        (
            "api_keys",
            "revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at < now()",
        ),
    ]
    OPERATOR_HARVESTS = [
        "ended_at IS NOT NULL",
        "ended_at IS NULL AND expires_at < now()",
    ]

    def _assert_no_seq_scan(self, cursor, harvest_sql):
        cursor.execute(f"EXPLAIN (COSTS OFF) {harvest_sql}")
        plan = "\n".join(r[0] for r in cursor.fetchall())
        assert "Seq Scan" not in plan, f"{harvest_sql}\n{plan}"

    def test_every_arm_has_an_index_path(self, authn, test_helpers):
        cur = test_helpers.cursor
        ns = authn.namespace
        actor = authn.create_user("actor@example.com", "hash")
        target = authn.create_user("target@example.com", "hash")
        anchor_session = authn.create_session(actor, "anchor_token")

        # ~1% of rows match each arm, the steady-state shape where a seq
        # scan would be the wrong plan
        expired = "CASE WHEN g %% 100 = 0 THEN now() - interval '1 hour' ELSE now() + interval '1 hour' END"
        dead = "CASE WHEN g %% 200 = 100 THEN now() ELSE NULL END"
        seeds = [
            f"""INSERT INTO authn.sessions (namespace, user_id, token_hash, expires_at, revoked_at)
                SELECT %(ns)s, %(actor)s, 'plan_s' || g, {expired}, {dead}
                FROM generate_series(1, 10000) g""",
            f"""INSERT INTO authn.refresh_tokens
                (namespace, user_id, session_id, token_hash, family_id, expires_at, revoked_at)
                SELECT %(ns)s, %(actor)s, %(session)s, 'plan_rt' || g, gen_random_uuid(), {expired}, {dead}
                FROM generate_series(1, 10000) g""",
            f"""INSERT INTO authn.tokens (namespace, user_id, token_hash, token_type, expires_at, used_at)
                SELECT %(ns)s, %(actor)s, 'plan_t' || g, 'password_reset', {expired}, {dead}
                FROM generate_series(1, 10000) g""",
            f"""INSERT INTO authn.api_keys (namespace, user_id, key_hash, expires_at, revoked_at)
                SELECT %(ns)s, %(actor)s, 'plan_k' || g, {expired}, {dead}
                FROM generate_series(1, 10000) g""",
            f"""INSERT INTO authn.impersonation_sessions
                (namespace, actor_id, target_user_id, original_session_id, reason, expires_at, ended_at)
                SELECT %(ns)s, %(actor)s, %(target)s, %(session)s, 'plan', {expired}, {dead}
                FROM generate_series(1, 10000) g""",
            f"""INSERT INTO authn.operator_impersonation_sessions
                (operator_id, operator_email, operator_namespace, original_session_id,
                 target_user_id, target_user_email, target_namespace, reason, expires_at, ended_at)
                SELECT %(actor)s, 'op@example.com', %(ns)s, gen_random_uuid(),
                       %(target)s, 't@example.com', %(ns)s, 'plan', {expired}, {dead}
                FROM generate_series(1, 10000) g""",
        ]
        params = {"ns": ns, "actor": actor, "target": target, "session": anchor_session}
        tables = [
            "sessions",
            "refresh_tokens",
            "tokens",
            "api_keys",
            "impersonation_sessions",
            "operator_impersonation_sessions",
        ]
        for seed in seeds:
            cur.execute(seed, params)
        for table in tables:
            cur.execute(f"ANALYZE authn.{table}")

        for table, arm in self.HARVESTS:
            self._assert_no_seq_scan(
                cur,
                f"SELECT id FROM authn.{table} "
                f"WHERE namespace = '{ns}' AND {arm} "
                f"LIMIT 10000 FOR UPDATE SKIP LOCKED",
            )
        for arm in self.OPERATOR_HARVESTS:
            self._assert_no_seq_scan(
                cur,
                f"SELECT id FROM authn.operator_impersonation_sessions "
                f"WHERE {arm} LIMIT 10000 FOR UPDATE SKIP LOCKED",
            )


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
