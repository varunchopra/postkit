"""presence + queue composition: transition hooks enqueue jobs atomically.

These tests need both schemas installed, so they live in the integration
suite (the module suites run in parallel workers and must not depend on
each other's schemas being present or absent).
"""

from datetime import datetime
from pathlib import Path

import psycopg
import pytest
from tests.conftest import DATABASE_URL
from tests.helpers import connect_as_rls_user, ensure_rls_role, make_namespace
from tests.presence.helpers import PresenceTestHelpers
from tests.presence.helpers import cleanup_namespace as _cleanup_presence


@pytest.fixture(scope="module")
def hooks_connection():
    """Module-scoped connection with presence AND queue installed."""
    conn = psycopg.connect(DATABASE_URL, autocommit=True)
    conn.execute("DROP SCHEMA IF EXISTS presence CASCADE")
    conn.execute("DROP SCHEMA IF EXISTS queue CASCADE")

    dist_dir = Path(__file__).parent.parent.parent.parent / "dist"
    for schema in ["presence", "queue"]:
        sql_file = dist_dir / f"{schema}.sql"
        if not sql_file.exists():
            pytest.fail(f"dist/{schema}.sql not found. Run 'make build' first.")
        conn.execute(sql_file.read_text())

    ensure_rls_role(conn, "presence")
    role = "presence_rls_user"
    conn.execute(f"GRANT USAGE ON SCHEMA queue TO {role}")
    conn.execute(f"GRANT ALL ON ALL TABLES IN SCHEMA queue TO {role}")
    conn.execute(f"GRANT ALL ON ALL SEQUENCES IN SCHEMA queue TO {role}")
    conn.execute(f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA queue TO {role}")

    yield conn

    conn.execute("DROP SCHEMA IF EXISTS presence CASCADE")
    conn.execute("DROP SCHEMA IF EXISTS queue CASCADE")
    conn.close()


@pytest.fixture
def revival_hook_case(hooks_connection, request):
    namespace = make_namespace(request)
    setup = hooks_connection.cursor()
    with hooks_connection.transaction():
        helper = PresenceTestHelpers(setup, namespace)
        helper.set_config(on_revival_queue="alerts")
        setup.execute("SELECT presence.register(%s, 'w1')", (namespace,))

    conn = connect_as_rls_user(hooks_connection, "presence")
    cursor = conn.cursor()
    cursor.execute("SELECT presence.assert_rls_active()")
    cursor.execute("SELECT queue.assert_rls_active()")
    conn.commit()

    yield cursor, namespace

    conn.rollback()
    cursor.close()
    conn.close()
    with hooks_connection.transaction():
        _cleanup_presence(setup, namespace)
    setup.close()


@pytest.fixture
def helpers(hooks_connection, request):
    namespace = make_namespace(request)
    cursor = hooks_connection.cursor()
    h = PresenceTestHelpers(cursor, namespace)
    cursor.execute("SELECT queue.set_tenant(%s)", (namespace,))

    yield h

    _cleanup_presence(cursor, namespace)
    for table in ("jobs", "dead_letters", "schedules", "config"):
        cursor.execute(f"DELETE FROM queue.{table} WHERE namespace = %s", (namespace,))
    cursor.close()


def register_and_kill_setup(h, entity="w1", **config):
    """Register a live entity with a death hook configured, then backdate it."""
    h.set_config(on_death_queue="alerts", **config)
    h.cursor.execute("SELECT presence.register(%s, %s)", (h.namespace, entity))
    h.cursor.execute("SELECT presence.heartbeat(%s, %s)", (h.namespace, entity))
    h.set_last_seen(entity, "-10 minutes")


def alert_jobs(h) -> list[dict]:
    h.cursor.execute(
        "SELECT payload FROM queue.jobs "
        "WHERE namespace = %s AND queue = 'alerts' ORDER BY id",
        (h.namespace,),
    )
    return [r[0] for r in h.cursor.fetchall()]


class TestHookQueueTenant:
    def test_revival_hook_enqueues_under_rls_without_queue_context(
        self, revival_hook_case
    ):
        cursor, namespace = revival_hook_case

        with cursor.connection.transaction(force_rollback=True):
            cursor.execute("SELECT presence.set_tenant(%s)", (namespace,))
            cursor.execute("SELECT presence.heartbeat(%s, 'w1')", (namespace,))
            assert cursor.fetchone()[0] == "alive"

            cursor.execute("SELECT count(*) FROM queue.jobs")
            assert cursor.fetchone()[0] == 0

            cursor.execute("SELECT queue.set_tenant(%s)", (namespace,))
            cursor.execute(
                "SELECT payload FROM queue.jobs "
                "WHERE namespace = %s AND queue = 'alerts'",
                (namespace,),
            )
            assert cursor.fetchone()[0]["entity_id"] == "w1"

    def test_revival_hook_preserves_existing_queue_context(self, revival_hook_case):
        cursor, namespace = revival_hook_case
        previous_queue_namespace = f"{namespace}_queue"

        with cursor.connection.transaction(force_rollback=True):
            cursor.execute("SELECT presence.set_tenant(%s)", (namespace,))
            cursor.execute("SELECT queue.set_tenant(%s)", (previous_queue_namespace,))
            cursor.execute("SELECT presence.heartbeat(%s, 'w1')", (namespace,))
            assert cursor.fetchone()[0] == "alive"

            cursor.execute(
                "SELECT queue.push(%s, 'probe', '{}'::jsonb)",
                (previous_queue_namespace,),
            )
            assert cursor.fetchone()[0] is not None

            cursor.execute("SELECT queue.set_tenant(%s)", (namespace,))
            cursor.execute(
                "SELECT payload FROM queue.jobs "
                "WHERE namespace = %s AND queue = 'alerts'",
                (namespace,),
            )
            assert cursor.fetchone()[0]["entity_id"] == "w1"


class TestDeathHook:
    def test_death_pushes_exactly_one_job(self, helpers):
        register_and_kill_setup(helpers)
        helpers.cursor.execute(
            "SELECT entity_id FROM presence.sweep(%s)", (helpers.namespace,)
        )
        assert [r[0] for r in helpers.cursor.fetchall()] == ["w1"]

        jobs = alert_jobs(helpers)
        assert len(jobs) == 1
        assert jobs[0]["entity_id"] == "w1"
        assert jobs[0]["to"] == "dead"
        assert jobs[0]["silent_for"] is not None

    def test_death_and_job_commit_together(self, hooks_connection, helpers):
        """The atomicity claim: roll back the sweeping transaction and
        neither the death nor the alert job exists."""
        register_and_kill_setup(helpers)

        info = hooks_connection.info
        conn = psycopg.connect(
            host=info.host,
            port=info.port,
            dbname=info.dbname,
            user=info.user,
            password=info.password,
        )
        cur = conn.cursor()
        cur.execute("SELECT entity_id FROM presence.sweep(%s)", (helpers.namespace,))
        assert [r[0] for r in cur.fetchall()] == ["w1"]
        conn.rollback()
        conn.close()

        assert alert_jobs(helpers) == []
        assert helpers.get_entity_row("w1")["status"] == "alive"
        assert helpers.get_transitions("w1")[-1]["to_status"] == "alive"

    def test_revival_hook_fires_on_revival(self, helpers):
        helpers.set_config(on_revival_queue="alerts")
        helpers.cursor.execute(
            "SELECT presence.register(%s, 'w1')", (helpers.namespace,)
        )
        helpers.cursor.execute(
            "SELECT presence.heartbeat(%s, 'w1')", (helpers.namespace,)
        )

        jobs = alert_jobs(helpers)
        assert len(jobs) == 1
        assert jobs[0]["to"] == "alive"
        assert jobs[0]["from"] == "unknown"


class TestDeferredTerminalAlert:
    def test_flap_into_suppression_then_real_death_alerts_once(self, helpers):
        """The P5 catch-up: a death suppressed by flap damping is delivered
        by a later sweep once the window expires - exactly one job, no new
        transitions row, flag cleared, payload carrying the REAL death
        time."""
        register_and_kill_setup(helpers, flap_threshold=1)
        # first contact was edge 1; this death is edge 2 > threshold 1
        helpers.cursor.execute(
            "SELECT entity_id FROM presence.sweep(%s)", (helpers.namespace,)
        )
        assert [r[0] for r in helpers.cursor.fetchall()] == ["w1"]
        assert alert_jobs(helpers) == []  # suppressed
        row = helpers.get_entity_row("w1")
        assert row["hook_suppressed"] is True
        transitions_before = len(helpers.get_transitions("w1"))

        # The flap window expires while the entity is still dead
        helpers.set_flap_window_started("w1", "-1 hour")
        helpers.cursor.execute(
            "SELECT entity_id FROM presence.sweep(%s)", (helpers.namespace,)
        )
        assert helpers.cursor.fetchall() == []  # no new transition returned

        jobs = alert_jobs(helpers)
        assert len(jobs) == 1
        assert jobs[0]["to"] == "dead"
        row = helpers.get_entity_row("w1")
        assert row["hook_suppressed"] is False
        assert len(helpers.get_transitions("w1")) == transitions_before
        # at carries the real death time, not the catch-up sweep's time
        assert datetime.fromisoformat(jobs[0]["at"]) == row["dead_since"]

    def test_catch_up_fires_only_once(self, helpers):
        register_and_kill_setup(helpers, flap_threshold=1)
        helpers.cursor.execute("SELECT * FROM presence.sweep(%s)", (helpers.namespace,))
        helpers.cursor.fetchall()
        helpers.set_flap_window_started("w1", "-1 hour")

        for _ in range(3):
            helpers.cursor.execute(
                "SELECT * FROM presence.sweep(%s)", (helpers.namespace,)
            )
            helpers.cursor.fetchall()

        assert len(alert_jobs(helpers)) == 1


class TestAllNamespacesSweep:
    def test_bypassrls_sweep_pushes_into_tenant_queue(self, hooks_connection, helpers):
        """The deployment mode: one cron, all namespaces, as a role that
        bypasses RLS for presence must still land the job in the tenant's
        queue rows correctly."""
        register_and_kill_setup(helpers)

        # The superuser session with NULL namespace is the all-namespaces
        # deployment shape (the test connection is a superuser)
        cur = hooks_connection.cursor()
        cur.execute("SELECT namespace, entity_id FROM presence.sweep(NULL)")
        swept = cur.fetchall()
        assert (helpers.namespace, "w1") in swept

        jobs = alert_jobs(helpers)
        assert len(jobs) == 1
        assert jobs[0]["namespace"] == helpers.namespace
        cur.close()


class TestSweepHookIsolation:
    """A poison death-hook is isolated to its own entity: one tenant's invalid
    on_death_queue does not abort another tenant's deaths in the same
    sweep(NULL) pass."""

    def _setup_overdue_entity(self, cur, namespace, queue_name):
        h = PresenceTestHelpers(cur, namespace)
        h.set_config(on_death_queue=queue_name)
        cur.execute("SELECT presence.register(%s, 'w1')", (namespace,))
        cur.execute("SELECT presence.heartbeat(%s, 'w1')", (namespace,))
        h.set_last_seen("w1", "-10 minutes")
        return h

    def test_poison_hook_does_not_roll_back_a_healthy_death(
        self, hooks_connection, request
    ):
        cur = hooks_connection.cursor()
        base = make_namespace(request)
        ns_healthy, ns_poison = base + "_a", base + "_z"

        h_healthy = self._setup_overdue_entity(cur, ns_healthy, "alerts")
        h_poison = self._setup_overdue_entity(cur, ns_poison, "poison_alerts")

        # The poison is a valid queue name (config-write accepts it) whose
        # enqueue fails at hook-fire time, standing in for an operator
        # constraint the death payload violates.
        cur.execute(
            "CREATE OR REPLACE FUNCTION public._reject_poison_alerts() "
            "RETURNS trigger AS $$ BEGIN "
            "IF NEW.queue = 'poison_alerts' THEN "
            "RAISE EXCEPTION 'poison payload rejected'; END IF; "
            "RETURN NEW; END; $$ LANGUAGE plpgsql"
        )
        cur.execute(
            "CREATE OR REPLACE TRIGGER reject_poison_alerts "
            "BEFORE INSERT ON queue.jobs FOR EACH ROW "
            "EXECUTE FUNCTION public._reject_poison_alerts()"
        )

        try:
            cur.execute("SELECT presence.sweep(NULL)")

            assert h_healthy.get_entity_row("w1")["status"] == "dead"
            assert len(alert_jobs(h_healthy)) == 1

            assert h_poison.get_entity_row("w1")["status"] == "alive"
            cur.execute(
                "SELECT count(*) FROM queue.jobs WHERE namespace = %s", (ns_poison,)
            )
            assert cur.fetchone()[0] == 0
        finally:
            cur.execute("DROP TRIGGER IF EXISTS reject_poison_alerts ON queue.jobs")
            cur.execute("DROP FUNCTION IF EXISTS public._reject_poison_alerts()")
            for ns in (ns_healthy, ns_poison):
                _cleanup_presence(cur, ns)
                for table in ("jobs", "dead_letters", "schedules", "config"):
                    cur.execute(
                        f"DELETE FROM queue.{table} WHERE namespace = %s", (ns,)
                    )
            cur.close()

    def test_bad_on_death_queue_is_rejected_at_config_time(
        self, hooks_connection, request
    ):
        cur = hooks_connection.cursor()
        ns = make_namespace(request)
        h = PresenceTestHelpers(cur, ns)
        try:
            with pytest.raises(psycopg.errors.InvalidParameterValue):
                h.set_config(on_death_queue="bad\tqueue")
        finally:
            _cleanup_presence(cur, ns)
            cur.close()
