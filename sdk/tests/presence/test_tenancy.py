"""RLS tenant isolation across the presence surface, as a non-superuser role."""

import psycopg
import pytest

from tests.helpers import connect_as_rls_user, ensure_rls_role
from tests.presence.helpers import cleanup_namespace


@pytest.fixture(scope="module")
def rls_role(db_connection):
    ensure_rls_role(db_connection, "presence")


@pytest.fixture
def rls_cursor(db_connection, rls_role, request):
    """Cursor connected as the non-BYPASSRLS role."""
    conn = connect_as_rls_user(db_connection, "presence", autocommit=True)
    cursor = conn.cursor()
    yield cursor
    cursor.close()
    conn.close()


@pytest.fixture
def victim(db_connection, request):
    """A live entity owned by tenant_a."""
    cursor = db_connection.cursor()
    cursor.execute("SELECT presence.register(%s, %s)", ("tenant_a", "worker-1"))
    cursor.execute("SELECT presence.heartbeat(%s, %s)", ("tenant_a", "worker-1"))
    yield {"entity": "worker-1"}
    cleanup_namespace(cursor, "tenant_a")
    cursor.close()


class TestCrossTenantIsolation:
    def test_no_context_fails_closed(self, rls_cursor, victim):
        rls_cursor.execute("SELECT COUNT(*) FROM presence.entities")
        assert rls_cursor.fetchone()[0] == 0

    def test_cross_tenant_reads_see_nothing(self, rls_cursor, victim):
        rls_cursor.execute("SELECT presence.set_tenant(%s)", ("tenant_b",))

        rls_cursor.execute(
            "SELECT * FROM presence.status(%s, 'worker-1')", ("tenant_a",)
        )
        assert rls_cursor.fetchall() == []

        rls_cursor.execute("SELECT * FROM presence.list(%s)", ("tenant_a",))
        assert rls_cursor.fetchall() == []

        rls_cursor.execute("SELECT * FROM presence.get_stats(%s)", ("tenant_a",))
        assert rls_cursor.fetchone() == (0, 0, 0, 0, 0, 0)

        rls_cursor.execute("SELECT * FROM presence.get_transitions(%s)", ("tenant_a",))
        assert rls_cursor.fetchall() == []

    def test_cross_tenant_writes_blocked_or_noop(self, rls_cursor, victim):
        rls_cursor.execute("SELECT presence.set_tenant(%s)", ("tenant_b",))

        # register into tenant_a violates the WITH CHECK policy
        with pytest.raises(psycopg.Error):
            rls_cursor.execute(
                "SELECT presence.register(%s, 'intruder')", ("tenant_a",)
            )

        # heartbeat against tenant_a's entity: RLS hides the row, so the
        # module reports it unknown rather than touching it
        with pytest.raises(psycopg.Error):
            rls_cursor.execute(
                "SELECT presence.heartbeat(%s, 'worker-1')", ("tenant_a",)
            )

        # sweep against tenant_a marks nothing (rows are hidden)
        rls_cursor.execute("SELECT * FROM presence.sweep(%s)", ("tenant_a",))
        assert rls_cursor.fetchall() == []

    def test_victim_untouched(self, db_connection, rls_cursor, victim):
        rls_cursor.execute("SELECT presence.set_tenant(%s)", ("tenant_b",))
        rls_cursor.execute("SELECT * FROM presence.sweep(%s)", ("tenant_a",))

        cursor = db_connection.cursor()
        cursor.execute(
            "SELECT status FROM presence.entities "
            "WHERE namespace = 'tenant_a' AND entity_id = 'worker-1'"
        )
        assert cursor.fetchone()[0] == "alive"
        cursor.close()


class TestConfigPolicies:
    def test_global_config_readable_not_writable(self, rls_cursor):
        rls_cursor.execute("SELECT presence.set_tenant(%s)", ("tenant_b",))
        rls_cursor.execute(
            "SELECT namespace, kind FROM presence.config WHERE namespace = 'global'"
        )
        assert rls_cursor.fetchone() == ("global", "default")

        rls_cursor.execute(
            "UPDATE presence.config SET notify = false WHERE namespace = 'global'"
        )
        assert rls_cursor.rowcount == 0

        with pytest.raises(psycopg.Error):
            rls_cursor.execute(
                "INSERT INTO presence.config (namespace, kind) "
                "VALUES ('global', 'default') "
                "ON CONFLICT (namespace, kind) DO UPDATE SET notify = false"
            )
