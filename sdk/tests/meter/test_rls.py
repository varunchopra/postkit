"""Row-Level Security tests for the meter module.

RLS is enforced for non-superuser roles only. These tests create a
separate role to verify RLS policies work correctly, including
tenant context recovery after commits and in autocommit mode.
"""

import psycopg
import pytest
from postkit.meter import MeterClient
from tests.helpers import connect_as_rls_user, ensure_rls_role
from tests.meter.helpers import cleanup_namespace


class TestMeterRowLevelSecurity:
    """Verify RLS enforces tenant isolation for meter tables."""

    @pytest.fixture
    def rls_connection(self, db_connection):
        """Non-superuser connection for RLS testing.

        Uses autocommit=False because tenant context is transaction-local.
        """
        ensure_rls_role(db_connection, "meter")
        conn = connect_as_rls_user(db_connection, "meter", autocommit=False)
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
        cursor.execute("RESET meter.tenant_id")

        cursor.execute("SELECT * FROM meter.accounts")
        assert cursor.fetchall() == []

    def test_tenant_isolation_read(self, rls_connection, db_connection):
        """Tenant A's data is invisible to tenant B."""
        # Superuser creates account in rls_a.
        su = db_connection.cursor()
        tenant_a = MeterClient(su, "rls_a")
        tenant_a.allocate("user1", "api_call", 1000, "count")

        # Non-superuser as rls_b cannot see rls_a's accounts.
        cursor = rls_connection.cursor()
        MeterClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM meter.accounts WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []

        # Non-superuser as rls_a CAN see rls_a's accounts.
        MeterClient(cursor, "rls_a")
        cursor.execute("SELECT * FROM meter.accounts WHERE namespace = 'rls_a'")
        assert len(cursor.fetchall()) == 1

    def test_tenant_isolation_write(self, rls_connection):
        """Cannot write to a different namespace than tenant context."""
        cursor = rls_connection.cursor()
        MeterClient(cursor, "rls_a")

        # Direct INSERT into rls_b namespace is blocked by RLS.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cursor.execute(
                """
                INSERT INTO meter.accounts
                    (namespace, user_id, event_type, resource, unit, balance)
                VALUES ('rls_b', 'user1', 'api_call', '', 'count', 100)
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
        meter = MeterClient(cursor, "rls_commit")

        # First operation within the __init__ transaction.
        meter.allocate("user1", "api_call", 1000, "count")

        rls_connection.commit()

        # After commit, tenant context is gone at the PostgreSQL level.
        # The SDK must re-apply it for subsequent operations.
        balance = meter.get_balance("user1", "api_call", "count")
        assert balance["balance"] == 1000

    def test_autocommit_mode(self, db_connection):
        """Each autocommit statement is its own transaction — context must be re-applied.

        In autocommit mode, __init__'s set_tenant call commits immediately.
        Every subsequent SDK call starts a fresh transaction with no tenant
        context. The SDK must re-apply tenant context per operation.
        """
        ensure_rls_role(db_connection, "meter")
        conn = connect_as_rls_user(db_connection, "meter", autocommit=True)
        try:
            cursor = conn.cursor()
            meter = MeterClient(cursor, "rls_autocommit")

            # allocate runs in a separate implicit transaction from __init__.
            meter.allocate("user1", "api_call", 1000, "count")

            # Read operations also work.
            balance = meter.get_balance("user1", "api_call", "count")
            assert balance["balance"] == 1000
        finally:
            conn.close()

    def test_set_tenant_clears_on_commit(self, rls_connection):
        """Tenant context is transaction-local and clears on commit.

        This is a safety property: is_local=true prevents cross-tenant
        leakage when connections are returned to a pool without cleanup.
        """
        cursor = rls_connection.cursor()
        MeterClient(cursor, "rls_a")

        cursor.execute("SELECT current_setting('meter.tenant_id', true)")
        assert cursor.fetchone()[0] == "rls_a"

        rls_connection.commit()

        # After commit, the transaction-local setting is gone.
        cursor.execute("SELECT current_setting('meter.tenant_id', true)")
        assert cursor.fetchone()[0] == ""

    def test_superuser_bypasses_rls(self, db_connection):
        """Superusers can see all data regardless of tenant context."""
        cursor = db_connection.cursor()

        MeterClient(cursor, "rls_a").allocate("user1", "api_call", 100, "count")

        # Switch to rls_b context — superuser still sees rls_a data.
        MeterClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM meter.accounts WHERE namespace = 'rls_a'")
        assert len(cursor.fetchall()) >= 1

    # =========================================================================
    # Table-Specific RLS Tests
    # =========================================================================

    def test_accounts_rls(self, rls_connection, db_connection):
        """Accounts table respects RLS."""
        su = db_connection.cursor()
        tenant_a = MeterClient(su, "rls_a")
        tenant_a.allocate("user1", "api_call", 1000, "count")
        tenant_a.allocate("user2", "api_call", 500, "count")

        cursor = rls_connection.cursor()
        MeterClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM meter.accounts WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []

    def test_ledger_rls(self, rls_connection, db_connection):
        """Ledger table respects RLS."""
        su = db_connection.cursor()
        tenant_a = MeterClient(su, "rls_a")
        tenant_a.allocate("user1", "api_call", 1000, "count")  # Creates ledger entry

        cursor = rls_connection.cursor()
        MeterClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM meter.ledger WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []

    def test_reservations_rls(self, rls_connection, db_connection):
        """Reservations table respects RLS."""
        su = db_connection.cursor()
        tenant_a = MeterClient(su, "rls_a")
        tenant_a.allocate("user1", "api_call", 1000, "count")
        tenant_a.reserve("user1", "api_call", 100, "count")  # Creates reservation

        cursor = rls_connection.cursor()
        MeterClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM meter.reservations WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []
