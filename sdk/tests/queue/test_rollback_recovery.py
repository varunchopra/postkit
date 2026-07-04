"""Recovery calls after a consumer rollback.

A transactional consumer's claim (pull's status update) lives in the
consumer's own transaction and vanishes with a rollback, returning the
job to pending. nack and fail accept pending jobs so the consumer's
intent survives its rollback: schedule the retry or dead-letter the
poison job. The worker_id argument refuses jobs another worker has
since re-pulled.
"""

import psycopg
import pytest
from postkit.errors import QueueErrorCode
from postkit.queue import QueueClient, QueueValidationError

from tests.conftest import DATABASE_URL
from tests.helpers import make_namespace
from tests.queue.helpers import cleanup_namespace


@pytest.fixture
def consumer(db_connection, request):
    """Transactional consumer: autocommit-off connection with its own client.

    Yields (conn, client, namespace). The claim from a pull joins the
    connection's open transaction, so a rollback models a mid-handler
    failure exactly.
    """
    namespace = make_namespace(request)
    conn = psycopg.connect(DATABASE_URL, autocommit=False)
    cursor = conn.cursor()
    client = QueueClient(cursor, namespace)
    conn.commit()

    yield conn, client, namespace

    conn.rollback()
    conn.close()
    cleanup_namespace(db_connection.cursor(), namespace)


def _pull_and_roll_back(conn, client, worker_id="worker-a"):
    """Claim a job inside an open transaction, then discard the claim."""
    conn.execute("SELECT 1")
    assert client.pull("tasks", worker_id=worker_id) is not None
    conn.rollback()


class TestRecoveryAfterRollback:
    """nack/fail on the pending job a rollback left behind."""

    def test_nack_after_rollback_schedules_the_retry(self, consumer, db_connection):
        conn, client, namespace = consumer
        job_id = client.push("tasks", {"n": 1})
        conn.commit()

        _pull_and_roll_back(conn, client)

        assert client.nack(job_id, error="ssh timeout") is True
        conn.commit()

        row = db_connection.execute(
            "SELECT status, error, scheduled_at > now() FROM queue.jobs "
            "WHERE namespace = %s AND id = %s",
            (namespace, job_id),
        ).fetchone()
        assert row == ("pending", "ssh timeout", True)

    def test_fail_after_rollback_dead_letters_the_job(self, consumer, db_connection):
        conn, client, namespace = consumer
        job_id = client.push("tasks", {"n": 1})
        conn.commit()

        _pull_and_roll_back(conn, client)

        assert client.fail(job_id, error="poison payload") is True
        conn.commit()

        status = db_connection.execute(
            "SELECT status FROM queue.jobs WHERE namespace = %s AND id = %s",
            (namespace, job_id),
        ).fetchone()[0]
        assert status == "dead"

        dlq_count = db_connection.execute(
            "SELECT COUNT(*) FROM queue.dead_letters "
            "WHERE namespace = %s AND original_job_id = %s",
            (namespace, job_id),
        ).fetchone()[0]
        assert dlq_count == 1

    def test_nack_on_reclaimed_job_at_max_attempts_dead_letters(
        self, queue, test_helpers
    ):
        """tick_timeouts preserves attempts, so the recovery nack routes to DLQ."""
        queue.push("tasks", {"n": 1}, max_attempts=1)
        job = queue.pull("tasks", worker_id="worker-a")

        test_helpers.expire_visibility_timeout(job["id"])
        reclaimed = queue.tick_timeouts()
        assert [r["job_id"] for r in reclaimed] == [job["id"]]

        assert queue.nack(job["id"], error="still failing") is False

        assert test_helpers.get_job_raw(job["id"])["status"] == "dead"
        assert test_helpers.count_dead_letters() == 1


class TestWorkerOwnership:
    """worker_id refuses recovery calls on a job another worker now owns."""

    def _reclaim_by_other_worker(self, consumer, db_connection):
        """A's claim rolls back; B re-pulls and holds the job."""
        conn, client, namespace = consumer
        job_id = client.push("tasks", {"n": 1})
        conn.commit()

        _pull_and_roll_back(conn, client, worker_id="worker-a")

        cursor_b = db_connection.cursor()
        client_b = QueueClient(cursor_b, namespace)
        job_b = client_b.pull("tasks", worker_id="worker-b")
        assert job_b["id"] == job_id
        return conn, client, namespace, job_id

    def _assert_claim_untouched(self, db_connection, namespace, job_id):
        row = db_connection.execute(
            "SELECT status, locked_by FROM queue.jobs WHERE namespace = %s AND id = %s",
            (namespace, job_id),
        ).fetchone()
        assert row == ("running", "worker-b")

    def test_nack_with_worker_id_refuses_a_job_reclaimed_by_another_worker(
        self, consumer, db_connection
    ):
        conn, client, namespace, job_id = self._reclaim_by_other_worker(
            consumer, db_connection
        )

        with pytest.raises(QueueValidationError) as exc_info:
            client.nack(job_id, error="ssh timeout", worker_id="worker-a")
        assert exc_info.value.error_code == QueueErrorCode.BIZ_JOB_NOT_YOURS
        conn.rollback()

        self._assert_claim_untouched(db_connection, namespace, job_id)

    def test_fail_with_worker_id_leaves_anothers_claim_alone(
        self, consumer, db_connection
    ):
        conn, client, namespace, job_id = self._reclaim_by_other_worker(
            consumer, db_connection
        )

        assert client.fail(job_id, error="poison", worker_id="worker-a") is False
        conn.commit()

        self._assert_claim_untouched(db_connection, namespace, job_id)
        dlq_count = db_connection.execute(
            "SELECT COUNT(*) FROM queue.dead_letters WHERE namespace = %s",
            (namespace,),
        ).fetchone()[0]
        assert dlq_count == 0
