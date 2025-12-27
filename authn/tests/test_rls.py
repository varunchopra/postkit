"""Tests for RLS (Row-Level Security) functions."""


class TestTenantIsolation:
    def test_users_isolated_by_namespace(self, make_authn):
        tenant_a = make_authn("tenant_a")
        tenant_b = make_authn("tenant_b")

        # Create users in different namespaces
        user_a = tenant_a.create_user("alice@example.com", "hash")
        user_b = tenant_b.create_user("bob@example.com", "hash")

        # Each tenant only sees their own users
        assert tenant_a.get_user(user_a) is not None
        assert tenant_a.get_user(user_b) is None

        assert tenant_b.get_user(user_b) is not None
        assert tenant_b.get_user(user_a) is None

    def test_sessions_isolated_by_namespace(self, make_authn):
        tenant_a = make_authn("tenant_a")
        tenant_b = make_authn("tenant_b")

        user_a = tenant_a.create_user("alice@example.com", "hash")
        user_b = tenant_b.create_user("bob@example.com", "hash")

        tenant_a.create_session(user_a, "token_a")
        tenant_b.create_session(user_b, "token_b")

        # Each tenant only validates their own sessions
        assert tenant_a.validate_session("token_a") is not None
        assert tenant_a.validate_session("token_b") is None

        assert tenant_b.validate_session("token_b") is not None
        assert tenant_b.validate_session("token_a") is None

    def test_same_email_different_namespaces(self, make_authn):
        tenant_a = make_authn("tenant_a")
        tenant_b = make_authn("tenant_b")

        # Same email in different namespaces
        user_a = tenant_a.create_user("shared@example.com", "hash_a")
        user_b = tenant_b.create_user("shared@example.com", "hash_b")

        # Different users
        assert user_a != user_b

        # Each gets their own credentials
        creds_a = tenant_a.get_credentials("shared@example.com")
        creds_b = tenant_b.get_credentials("shared@example.com")

        assert creds_a["password_hash"] == "hash_a"
        assert creds_b["password_hash"] == "hash_b"

    def test_lockout_isolated_by_namespace(self, make_authn):
        tenant_a = make_authn("tenant_a")
        tenant_b = make_authn("tenant_b")

        # Lock out email in tenant_a
        for _ in range(5):
            tenant_a.record_login_attempt("alice@example.com", False)

        assert tenant_a.is_locked_out("alice@example.com") is True
        assert tenant_b.is_locked_out("alice@example.com") is False

    def test_mfa_isolated_by_namespace(self, make_authn):
        tenant_a = make_authn("tenant_a")
        tenant_b = make_authn("tenant_b")

        user_a = tenant_a.create_user("alice@example.com", "hash")
        user_b = tenant_b.create_user("bob@example.com", "hash")

        mfa_a = tenant_a.add_mfa(user_a, "totp", "secret_a")

        # Tenant A can access their MFA
        assert tenant_a.has_mfa(user_a) is True

        # Tenant B can't access Tenant A's MFA
        assert tenant_b.has_mfa(user_a) is False
