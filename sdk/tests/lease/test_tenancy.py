"""RLS tenant-isolation tests: the adversarial cross-tenant surface.

Run as a non-superuser role (superusers bypass RLS), attempting every
public function across a tenant boundary.
"""

import psycopg
import pytest

from tests.helpers import connect_as_rls_user, ensure_rls_role
from tests.lease.helpers import cleanup_namespace


@pytest.fixture(scope="module")
def rls_role(db_connection):
    ensure_rls_role(db_connection, "lease")


@pytest.fixture
def rls_cursor(db_connection, rls_role, request):
    """Cursor connected as the non-BYPASSRLS role."""
    conn = connect_as_rls_user(db_connection, "lease", autocommit=True)
    cursor = conn.cursor()
    yield cursor
    cursor.close()
    conn.close()


@pytest.fixture
def victim(db_connection, request):
    """A lease owned by tenant_a, created by the superuser connection."""
    cursor = db_connection.cursor()
    cursor.execute(
        "SELECT * FROM lease.acquire(%s, %s, %s)", ("tenant_a", "secret", "w1")
    )
    fence = cursor.fetchone()[1]
    yield {"namespace": "tenant_a", "name": "secret", "holder": "w1", "fence": fence}
    cleanup_namespace(cursor, "tenant_a")
    cursor.close()


class TestCrossTenantIsolation:
    def test_no_context_fails_closed(self, rls_cursor, victim):
        """Without set_tenant, RLS returns zero rows everywhere."""
        rls_cursor.execute(
            "SELECT * FROM lease.current(%s, %s)", ("tenant_a", "secret")
        )
        assert rls_cursor.fetchone() is None

        rls_cursor.execute("SELECT * FROM lease.list(%s)", ("tenant_a",))
        assert rls_cursor.fetchall() == []

    def test_cross_tenant_reads_see_nothing(self, rls_cursor, victim):
        rls_cursor.execute("SELECT lease.set_tenant(%s)", ("tenant_b",))
        rls_cursor.execute(
            "SELECT * FROM lease.current(%s, %s)", ("tenant_a", "secret")
        )
        assert rls_cursor.fetchone() is None

        rls_cursor.execute("SELECT COUNT(*) FROM lease.leases")
        assert rls_cursor.fetchone()[0] == 0
        rls_cursor.execute("SELECT COUNT(*) FROM lease.events")
        assert rls_cursor.fetchone()[0] == 0
        rls_cursor.execute("SELECT COUNT(*) FROM lease.fence_counters")
        assert rls_cursor.fetchone()[0] == 0

    def test_cross_tenant_writes_blocked(self, rls_cursor, victim):
        """With tenant_b context, every mutating function either raises on the
        RLS WITH CHECK or silently no-ops against tenant_a's lease."""
        rls_cursor.execute("SELECT lease.set_tenant(%s)", ("tenant_b",))

        # acquire into tenant_a: the INSERT violates the WITH CHECK policy
        with pytest.raises(psycopg.Error):
            rls_cursor.execute(
                "SELECT * FROM lease.acquire(%s, %s, %s)",
                ("tenant_a", "secret", "attacker"),
            )

        # renew/release/verify: RLS filters the row away – false / stale
        rls_cursor.execute(
            "SELECT * FROM lease.renew(%s, %s, %s, %s)",
            ("tenant_a", "secret", victim["holder"], victim["fence"]),
        )
        assert rls_cursor.fetchone()[0] is False

        rls_cursor.execute(
            "SELECT lease.release(%s, %s, %s, %s)",
            ("tenant_a", "secret", victim["holder"], victim["fence"]),
        )
        assert rls_cursor.fetchone()[0] is False

        with pytest.raises(psycopg.Error):
            rls_cursor.execute(
                "SELECT lease.verify(%s, %s, %s, %s)",
                ("tenant_a", "secret", victim["holder"], victim["fence"]),
            )

    def test_victim_untouched(self, db_connection, rls_cursor, victim):
        """After the attack attempts, tenant_a's lease is intact."""
        rls_cursor.execute("SELECT lease.set_tenant(%s)", ("tenant_b",))
        rls_cursor.execute(
            "SELECT * FROM lease.renew(%s, %s, %s, %s)",
            ("tenant_a", "secret", victim["holder"], victim["fence"]),
        )

        cursor = db_connection.cursor()
        cursor.execute(
            "SELECT holder_id, fence_token FROM lease.leases "
            "WHERE namespace = %s AND name = %s",
            ("tenant_a", "secret"),
        )
        row = cursor.fetchone()
        assert row == (victim["holder"], victim["fence"])
        cursor.close()


class TestStatsEventsPruneIsolation:
    """get_stats / get_events / prune_events across a tenant boundary."""

    def test_stats_and_events_see_nothing_cross_tenant(self, rls_cursor, victim):
        rls_cursor.execute("SELECT lease.set_tenant(%s)", ("tenant_b",))

        rls_cursor.execute("SELECT * FROM lease.get_stats(%s)", ("tenant_a",))
        stats = rls_cursor.fetchone()
        assert stats == (0, 0, 0, 0, 0)

        rls_cursor.execute("SELECT * FROM lease.get_events(%s)", ("tenant_a",))
        assert rls_cursor.fetchall() == []

    def test_prune_cross_tenant_deletes_nothing(
        self, db_connection, rls_cursor, victim
    ):
        # Backdate tenant_a's events (superuser) so they WOULD be prunable
        cursor = db_connection.cursor()
        cursor.execute(
            "UPDATE lease.events SET at = now() - interval '40 days' "
            "WHERE namespace = %s",
            ("tenant_a",),
        )

        rls_cursor.execute("SELECT lease.set_tenant(%s)", ("tenant_b",))
        rls_cursor.execute(
            "SELECT lease.prune_events(%s, %s::interval)",
            ("tenant_a", "30 days"),
        )
        assert rls_cursor.fetchone()[0] == 0

        cursor.execute(
            "SELECT COUNT(*) FROM lease.events WHERE namespace = %s", ("tenant_a",)
        )
        assert cursor.fetchone()[0] > 0
        cursor.close()


class TestConfigPolicies:
    def test_global_config_readable_not_writable(self, rls_cursor):
        rls_cursor.execute("SELECT lease.set_tenant(%s)", ("tenant_b",))
        rls_cursor.execute(
            "SELECT namespace FROM lease.config WHERE namespace = 'global'"
        )
        assert rls_cursor.fetchone() == ("global",)

        # UPDATE: the global row is SELECT-visible only, so the UPDATE
        # matches zero rows (silent no-op, not an error)
        rls_cursor.execute(
            "UPDATE lease.config SET notify_on_release = true "
            "WHERE namespace = 'global'"
        )
        assert rls_cursor.rowcount == 0

        # INSERT into global: blocked by the RESTRICTIVE write-protection policy
        with pytest.raises(psycopg.Error):
            rls_cursor.execute(
                "INSERT INTO lease.config (namespace) VALUES ('global') "
                "ON CONFLICT (namespace) DO UPDATE SET notify_on_release = true"
            )
