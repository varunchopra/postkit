"""RLS tenant isolation across the outbox surface, as a non-superuser role."""

import time
from datetime import timedelta

import pytest
from postkit.outbox import OutboxClient

from tests.helpers import connect_as_rls_user, ensure_rls_role
from tests.outbox.helpers import cleanup_namespace


@pytest.fixture(scope="module")
def rls_role(db_connection):
    ensure_rls_role(db_connection, "outbox")


@pytest.fixture
def rls_cursor(db_connection, rls_role, request):
    """Cursor connected as the non-BYPASSRLS role."""
    conn = connect_as_rls_user(db_connection, "outbox", autocommit=True)
    cursor = conn.cursor()
    yield cursor
    cursor.close()
    conn.close()


@pytest.fixture
def victim(db_connection, request):
    """A topic with events and a consumer, owned by tenant_a."""
    cursor = db_connection.cursor()
    cursor.execute(
        "SELECT outbox.subscribe(%s, %s, %s, %s)",
        ("tenant_a", "orders", "billing", "start"),
    )
    cursor.execute(
        "SELECT outbox.emit(%s, %s, %s, %s)",
        ("tenant_a", "orders", "order.created", '{"secret": true}'),
    )
    event_id = cursor.fetchone()[0]
    yield {"event_id": event_id}
    cleanup_namespace(cursor, "tenant_a")
    cursor.close()


class TestCrossTenantIsolation:
    def test_trim_works_for_matching_non_bypass_tenant(self, db_connection, rls_cursor):
        rls_cursor.connection.autocommit = False
        try:
            client = OutboxClient(rls_cursor, "tenant_b")
            client.subscribe("trim-test", "test", from_="start")
            client.emit("trim-test", "old.event", {})
            rls_cursor.connection.commit()

            deadline = time.monotonic() + 10
            while True:
                events = client.poll("trim-test", "test")
                if events:
                    break
                assert time.monotonic() < deadline
                time.sleep(0.01)
            client.ack("trim-test", "test", events[-1]["xid"], events[-1]["id"])
            time.sleep(0.01)
            assert client.trim(timedelta(microseconds=1), topic="trim-test") == [
                {"namespace": "tenant_b", "topic": "trim-test", "deleted": 1}
            ]
            rls_cursor.connection.commit()
        finally:
            rls_cursor.connection.rollback()
            rls_cursor.connection.autocommit = True
        owner = db_connection.cursor()
        cleanup_namespace(owner, "tenant_b")
        owner.close()

    def test_no_context_fails_closed(self, rls_cursor, victim):
        rls_cursor.execute("SELECT COUNT(*) FROM outbox.events")
        assert rls_cursor.fetchone()[0] == 0

    def test_cross_tenant_reads_see_nothing(self, rls_cursor, victim):
        rls_cursor.execute("SELECT outbox.set_tenant(%s)", ("tenant_b",))

        rls_cursor.execute(
            "SELECT * FROM outbox.read_from(%s, 'orders', '0', 0)", ("tenant_a",)
        )
        assert rls_cursor.fetchall() == []

        rls_cursor.execute("SELECT * FROM outbox.lag(%s)", ("tenant_a",))
        assert rls_cursor.fetchall() == []

        rls_cursor.execute("SELECT * FROM outbox.get_stats(%s)", ("tenant_a",))
        assert rls_cursor.fetchone() == (0, 0, 0, 0)

        rls_cursor.execute("SELECT * FROM outbox.list_consumers(%s)", ("tenant_a",))
        assert rls_cursor.fetchall() == []

    def test_cross_tenant_writes_blocked_or_noop(self, rls_cursor, victim):
        rls_cursor.execute("SELECT outbox.set_tenant(%s)", ("tenant_b",))

        # emit into tenant_a violates the WITH CHECK policy
        with pytest.raises(Exception):
            rls_cursor.execute(
                "SELECT outbox.emit(%s, 'orders', 'e.x', '{}')", ("tenant_a",)
            )

        # poll against tenant_a's consumer: RLS hides the cursor row
        with pytest.raises(Exception):
            rls_cursor.execute(
                "SELECT * FROM outbox.poll(%s, 'orders', 'billing')", ("tenant_a",)
            )

        # trim against tenant_a deletes nothing (topics rows are hidden)
        rls_cursor.execute(
            "SELECT * FROM outbox.trim(%s, %s)",
            (timedelta(seconds=1), "tenant_a"),
        )
        assert rls_cursor.fetchall() == []

    def test_victim_untouched(self, db_connection, rls_cursor, victim):
        rls_cursor.execute("SELECT outbox.set_tenant(%s)", ("tenant_b",))
        rls_cursor.execute(
            "SELECT * FROM outbox.trim(%s, %s)",
            (timedelta(seconds=1), "tenant_a"),
        )

        cursor = db_connection.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM outbox.events WHERE namespace = 'tenant_a'"
        )
        assert cursor.fetchone()[0] == 1
        cursor.close()


class TestConfigPolicies:
    def test_global_config_readable_not_writable(self, rls_cursor):
        rls_cursor.execute("SELECT outbox.set_tenant(%s)", ("tenant_b",))
        rls_cursor.execute(
            "SELECT namespace, topic FROM outbox.config WHERE namespace = 'global'"
        )
        assert rls_cursor.fetchone() == ("global", "*")

        rls_cursor.execute(
            "UPDATE outbox.config SET notify = false WHERE namespace = 'global'"
        )
        assert rls_cursor.rowcount == 0

        with pytest.raises(Exception):
            rls_cursor.execute(
                "INSERT INTO outbox.config (namespace, topic) VALUES ('global', '*') "
                "ON CONFLICT (namespace, topic) DO UPDATE SET notify = false"
            )
