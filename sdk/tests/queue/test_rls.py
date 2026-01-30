"""Row-Level Security tests for the queue module.

RLS is enforced for non-superuser roles only. These tests create a
separate role to verify RLS policies work correctly, including
tenant context recovery after commits and in autocommit mode.
"""

import psycopg
import pytest
from postkit.queue import QueueClient


def _ensure_rls_role(db_connection):
    """Create the non-superuser role and grant queue schema access.

    Idempotent — safe to call multiple times per session.
    """
    db_connection.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'queue_rls_user') THEN
                CREATE ROLE queue_rls_user LOGIN PASSWORD 'queue_rls_pass';
            END IF;
        END $$;
    """
    )
    db_connection.execute("GRANT USAGE ON SCHEMA queue TO queue_rls_user")
    db_connection.execute("GRANT ALL ON ALL TABLES IN SCHEMA queue TO queue_rls_user")
    db_connection.execute(
        "GRANT ALL ON ALL SEQUENCES IN SCHEMA queue TO queue_rls_user"
    )
    db_connection.execute(
        "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA queue TO queue_rls_user"
    )


def _connect_as_rls_user(db_connection, *, autocommit: bool = False):
    """Connect to the same database as a non-superuser."""
    info = db_connection.info
    return psycopg.connect(
        host=info.host,
        port=info.port,
        dbname=info.dbname,
        user="queue_rls_user",
        password="queue_rls_pass",
        autocommit=autocommit,
    )


class TestQueueRowLevelSecurity:
    """Verify RLS enforces tenant isolation for queue tables."""

    @pytest.fixture
    def rls_connection(self, db_connection):
        """Non-superuser connection for RLS testing.

        Uses autocommit=False because tenant context is transaction-local.
        """
        _ensure_rls_role(db_connection)

        conn = _connect_as_rls_user(db_connection, autocommit=False)
        yield conn
        conn.close()

    @pytest.fixture(autouse=True)
    def cleanup(self, db_connection):
        """Remove test data after each test via superuser (bypasses RLS)."""
        yield
        for ns in ("rls_a", "rls_b", "rls_commit", "rls_autocommit"):
            db_connection.execute(
                "DELETE FROM queue.dead_letters WHERE namespace = %s", (ns,)
            )
            db_connection.execute(
                "DELETE FROM queue.schedules WHERE namespace = %s", (ns,)
            )
            db_connection.execute("DELETE FROM queue.jobs WHERE namespace = %s", (ns,))
            db_connection.execute(
                "DELETE FROM queue.config WHERE namespace = %s", (ns,)
            )

    def test_no_tenant_returns_empty(self, rls_connection):
        """Without tenant context, queries return nothing."""
        cursor = rls_connection.cursor()
        cursor.execute("RESET queue.tenant_id")

        cursor.execute("SELECT * FROM queue.jobs")
        assert cursor.fetchall() == []

    def test_tenant_isolation_read(self, rls_connection, db_connection):
        """Tenant A's jobs are invisible to tenant B."""
        # Superuser pushes a job for rls_a.
        su = db_connection.cursor()
        tenant_a = QueueClient(su, "rls_a")
        tenant_a.push("email", {"to": "alice@example.com"})

        # Non-superuser as rls_b cannot see rls_a's jobs.
        cursor = rls_connection.cursor()
        QueueClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM queue.jobs WHERE namespace = 'rls_a'")
        assert cursor.fetchall() == []

        # Non-superuser as rls_a CAN see rls_a's jobs.
        QueueClient(cursor, "rls_a")
        cursor.execute("SELECT * FROM queue.jobs WHERE namespace = 'rls_a'")
        assert len(cursor.fetchall()) == 1

    def test_tenant_isolation_write(self, rls_connection):
        """Cannot write to a different namespace than tenant context."""
        cursor = rls_connection.cursor()
        QueueClient(cursor, "rls_a")

        # Direct INSERT into rls_b namespace is blocked by RLS.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cursor.execute(
                """
                INSERT INTO queue.jobs
                    (namespace, queue, payload, status, max_attempts,
                     priority, attempts)
                VALUES
                    ('rls_b', 'tasks', '{}', 'pending', 3, 0, 0)
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
        q = QueueClient(cursor, "rls_commit")

        # First operation within the __init__ transaction.
        job_id = q.push("tasks", {"step": 1})
        assert job_id is not None

        rls_connection.commit()

        # After commit, tenant context is gone at the PostgreSQL level.
        # The SDK must re-apply it for subsequent operations.
        stats = q.get_stats()
        assert stats["total_jobs"] == 1

        # Write operations also work after commit.
        job_id_2 = q.push("tasks", {"step": 2})
        assert job_id_2 is not None

        stats = q.get_stats()
        assert stats["total_jobs"] == 2

    def test_autocommit_mode(self, db_connection):
        """Each autocommit statement is its own transaction — context must be re-applied.

        In autocommit mode, __init__'s set_tenant call commits immediately.
        Every subsequent SDK call starts a fresh transaction with no tenant
        context. The SDK must re-apply tenant context per operation.
        """
        _ensure_rls_role(db_connection)
        conn = _connect_as_rls_user(db_connection, autocommit=True)
        try:
            cursor = conn.cursor()
            q = QueueClient(cursor, "rls_autocommit")

            # push() runs in a separate implicit transaction from __init__.
            job_id = q.push("tasks", {"step": 1})
            assert job_id is not None

            # Read operations also work.
            stats = q.get_stats()
            assert stats["total_jobs"] == 1
        finally:
            conn.close()

    def test_set_tenant_clears_on_commit(self, rls_connection):
        """Tenant context is transaction-local and clears on commit.

        This is a safety property: is_local=true prevents cross-tenant
        leakage when connections are returned to a pool without cleanup.
        """
        cursor = rls_connection.cursor()
        QueueClient(cursor, "rls_a")

        cursor.execute("SELECT current_setting('queue.tenant_id', true)")
        assert cursor.fetchone()[0] == "rls_a"

        rls_connection.commit()

        # After commit, the transaction-local setting is gone.
        cursor.execute("SELECT current_setting('queue.tenant_id', true)")
        assert cursor.fetchone()[0] == ""

    def test_pull_respects_rls(self, rls_connection, db_connection):
        """pull() only returns jobs visible to the current tenant."""
        # Superuser pushes jobs for two tenants.
        su = db_connection.cursor()
        QueueClient(su, "rls_a").push("tasks", {"owner": "a"})
        QueueClient(su, "rls_b").push("tasks", {"owner": "b"})

        # Non-superuser as rls_a can only pull rls_a's job.
        cursor = rls_connection.cursor()
        q = QueueClient(cursor, "rls_a")
        job = q.pull("tasks")
        assert job is not None
        assert job["payload"]["owner"] == "a"

        # No more jobs visible to rls_a.
        assert q.pull("tasks") is None

    def test_superuser_bypasses_rls(self, db_connection):
        """Superusers can see all data regardless of tenant context."""
        cursor = db_connection.cursor()

        QueueClient(cursor, "rls_a").push("tasks", {"owner": "a"})

        # Switch to rls_b context — superuser still sees rls_a data.
        QueueClient(cursor, "rls_b")
        cursor.execute("SELECT * FROM queue.jobs WHERE namespace = 'rls_a'")
        assert len(cursor.fetchall()) >= 1
