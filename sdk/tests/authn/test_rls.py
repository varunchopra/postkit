"""Row-Level Security tests for the authn module.

RLS is enforced for non-superuser roles only. These tests create a
separate role to verify RLS policies work correctly, including
tenant context recovery after commits and in autocommit mode.
"""

import psycopg
import pytest
from postkit.authn import AuthnClient

from tests.authn.helpers import cleanup_namespace
from tests.helpers import connect_as_rls_user, ensure_rls_role


class TestAuthnRowLevelSecurity:
    """Verify RLS enforces tenant isolation for authn tables."""

    @pytest.fixture
    def rls_connection(self, db_connection):
        """Non-superuser connection for RLS testing.

        Uses autocommit=False because tenant context is transaction-local.
        """
        ensure_rls_role(db_connection, "authn")
        conn = connect_as_rls_user(db_connection, "authn", autocommit=False)
        yield conn
        conn.close()

    @pytest.fixture(autouse=True)
    def cleanup(self, db_connection):
        """Remove test data after each test via superuser (bypasses RLS)."""
        yield
        cursor = db_connection.cursor()
        for ns in ("rls_a", "rls_b", "rls_commit", "rls_autocommit"):
            cleanup_namespace(cursor, ns)

    # =========================================================================
    # Core RLS Tests
    # =========================================================================

    def test_no_tenant_returns_empty(self, rls_connection):
        """Without tenant context, queries return nothing (fail-closed)."""
        cursor = rls_connection.cursor()
        cursor.execute("RESET authn.tenant_id")

        cursor.execute("SELECT * FROM authn.users")
        assert cursor.fetchall() == []

    def test_tenant_isolation_read(self, rls_connection, db_connection):
        """Tenant A's data is invisible to tenant B."""
        # Superuser creates user in rls_a.
        su = db_connection.cursor()
        tenant_a = AuthnClient(su, "rls_a")
        tenant_a.create_user("alice@example.com", "hash")

        # Non-superuser as rls_b cannot see rls_a's users.
        cursor = rls_connection.cursor()
        AuthnClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM authn.users WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []

        # Non-superuser as rls_a CAN see rls_a's users.
        AuthnClient(cursor, "rls_a")
        cursor.execute("SELECT * FROM authn.users WHERE namespace = 'rls_a'")
        assert len(cursor.fetchall()) == 1

    def test_tenant_isolation_write(self, rls_connection):
        """Cannot write to a different namespace than tenant context."""
        cursor = rls_connection.cursor()
        AuthnClient(cursor, "rls_a")

        # Direct INSERT into rls_b namespace is blocked by RLS.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cursor.execute(
                """
                INSERT INTO authn.users (namespace, email, password_hash)
                VALUES ('rls_b', 'bob@example.com', 'hash')
                """
            )

    def test_context_survives_commit(self, rls_connection):
        """SDK operations work after an explicit commit.

        This is the core regression test. Before the fix, set_tenant was
        called once in __init__ with is_local=true. After commit, the
        transaction-local setting was gone and subsequent operations saw
        an empty tenant_id, causing RLS to silently block everything.
        """
        cursor = rls_connection.cursor()
        authn = AuthnClient(cursor, "rls_commit")

        # First operation within the __init__ transaction.
        user_id = authn.create_user("alice@example.com", "hash")
        assert user_id is not None

        rls_connection.commit()

        # After commit, tenant context is gone at the PostgreSQL level.
        # The SDK must re-apply it for subsequent operations.
        user = authn.get_user(user_id)
        assert user is not None
        assert user["email"] == "alice@example.com"

    def test_autocommit_mode(self, db_connection):
        """Each autocommit statement is its own transaction - context must be re-applied.

        In autocommit mode, __init__'s set_tenant call commits immediately.
        Every subsequent SDK call starts a fresh transaction with no tenant
        context. The SDK must re-apply tenant context per operation.
        """
        ensure_rls_role(db_connection, "authn")
        conn = connect_as_rls_user(db_connection, "authn", autocommit=True)
        try:
            cursor = conn.cursor()
            authn = AuthnClient(cursor, "rls_autocommit")

            # create_user runs in a separate implicit transaction from __init__.
            user_id = authn.create_user("alice@example.com", "hash")
            assert user_id is not None

            # Read operations also work.
            user = authn.get_user(user_id)
            assert user is not None
        finally:
            conn.close()

    def test_set_tenant_clears_on_commit(self, rls_connection):
        """Tenant context is transaction-local and clears on commit.

        This is a safety property: is_local=true prevents cross-tenant
        leakage when connections are returned to a pool without cleanup.
        """
        cursor = rls_connection.cursor()
        AuthnClient(cursor, "rls_a")

        cursor.execute("SELECT current_setting('authn.tenant_id', true)")
        assert cursor.fetchone()[0] == "rls_a"

        rls_connection.commit()

        # After commit, the transaction-local setting is gone.
        cursor.execute("SELECT current_setting('authn.tenant_id', true)")
        assert cursor.fetchone()[0] == ""

    def test_superuser_bypasses_rls(self, db_connection):
        """Superusers can see all data regardless of tenant context."""
        cursor = db_connection.cursor()

        AuthnClient(cursor, "rls_a").create_user("alice@example.com", "hash")

        # Switch to rls_b context - superuser still sees rls_a data.
        AuthnClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM authn.users WHERE namespace = 'rls_a'")
        assert len(cursor.fetchall()) >= 1

    # =========================================================================
    # Table-Specific RLS Tests
    # =========================================================================

    def test_sessions_rls(self, rls_connection, db_connection):
        """Sessions table respects RLS."""
        su = db_connection.cursor()
        tenant_a = AuthnClient(su, "rls_a")
        user_id = tenant_a.create_user("alice@example.com", "hash")
        tenant_a.create_session(user_id, "token_a")

        cursor = rls_connection.cursor()
        AuthnClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM authn.sessions WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []

    def test_refresh_tokens_rls(self, rls_connection, db_connection):
        """Refresh tokens table respects RLS."""
        su = db_connection.cursor()
        tenant_a = AuthnClient(su, "rls_a")
        user_id = tenant_a.create_user("alice@example.com", "hash")
        session_id = tenant_a.create_session(user_id, "token")
        tenant_a.create_refresh_token(session_id, "refresh_hash")

        cursor = rls_connection.cursor()
        AuthnClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM authn.refresh_tokens WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []

    def test_tokens_rls(self, rls_connection, db_connection):
        """One-time tokens table respects RLS."""
        su = db_connection.cursor()
        tenant_a = AuthnClient(su, "rls_a")
        user_id = tenant_a.create_user("alice@example.com", "hash")
        tenant_a.create_token(user_id, "token_hash", "password_reset")

        cursor = rls_connection.cursor()
        AuthnClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM authn.tokens WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []

    def test_credentials_rls(self, rls_connection, db_connection):
        """Credentials table respects RLS."""
        su = db_connection.cursor()
        tenant_a = AuthnClient(su, "rls_a")
        user_id = tenant_a.create_user("alice@example.com", "hash")
        tenant_a.add_credential(user_id, "totp", secret_data="secret")

        cursor = rls_connection.cursor()
        AuthnClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM authn.credentials WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []

    def test_login_attempts_rls(self, rls_connection, db_connection):
        """Login attempts table respects RLS."""
        su = db_connection.cursor()
        tenant_a = AuthnClient(su, "rls_a")
        tenant_a.record_login_attempt("alice@example.com", False)

        cursor = rls_connection.cursor()
        AuthnClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM authn.login_attempts WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []

    def test_api_keys_rls(self, rls_connection, db_connection):
        """API keys table respects RLS."""
        su = db_connection.cursor()
        tenant_a = AuthnClient(su, "rls_a")
        user_id = tenant_a.create_user("alice@example.com", "hash")
        tenant_a.create_api_key(user_id, "key_hash", "test key")

        cursor = rls_connection.cursor()
        AuthnClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM authn.api_keys WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []

    def test_impersonation_sessions_rls(self, rls_connection, db_connection):
        """Impersonation sessions table respects RLS."""
        su = db_connection.cursor()
        tenant_a = AuthnClient(su, "rls_a")
        admin_id = tenant_a.create_user("admin@example.com", "hash")
        target_id = tenant_a.create_user("target@example.com", "hash")
        admin_session = tenant_a.create_session(admin_id, "admin_token")
        tenant_a.start_impersonation(admin_session, target_id, "support", "imp_token")

        cursor = rls_connection.cursor()
        AuthnClient(cursor, "rls_b")
        cursor.execute(
            "SELECT * FROM authn.impersonation_sessions WHERE namespace = 'rls_a'"
        )
        assert cursor.fetchall() == []
