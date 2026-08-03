"""Transaction boundaries for pulls and their fence tokens.

Rolling back a pull restores the pending row and its attempt count, but the
sequence value returned as its fence is still consumed. That orphaned fence
must never authorize a later attempt. Database-only work can instead keep the
pull, application writes, and acknowledgement in one atomic transaction.
"""

from datetime import timedelta

import pytest
from postkit.queue import QueueClient, QueueFencingError

from tests.helpers import make_namespace
from tests.queue.helpers import cleanup_namespace


@pytest.fixture
def consumer(db_connection, connect, request):
    """Provide an isolated transactional worker and remove its queue rows."""
    namespace = make_namespace(request)
    conn = connect()
    client = QueueClient(conn.cursor(), namespace)
    conn.commit()

    yield conn, client, namespace

    conn.rollback()
    conn.close()
    cleanup_namespace(db_connection.cursor(), namespace)


def _pull_then_rollback(conn, client):
    """Return a pull result after deliberately rolling back its transaction."""
    with conn.transaction(force_rollback=True):
        job = client.pull("tasks", worker_id="worker-a")
        assert job is not None
    return job


@pytest.mark.parametrize(
    "operation", ["extend_visibility", "ack", "nack", "fail", "release"]
)
def test_rolled_back_pull_leaves_job_pending_and_fence_invalid(
    consumer, db_connection, operation
):
    """No running-job operation may use a fence from a rolled-back pull."""
    conn, client, namespace = consumer
    job_id = client.push("tasks", {"n": 1})
    rolled_back = _pull_then_rollback(conn, client)

    row = db_connection.execute(
        "SELECT status, attempts, fence_token FROM queue.jobs "
        "WHERE namespace = %s AND id = %s",
        (namespace, job_id),
    ).fetchone()
    assert row == ("pending", 0, None)

    with pytest.raises(QueueFencingError):
        if operation == "extend_visibility":
            client.extend_visibility(
                job_id, rolled_back["fence_token"], timedelta(minutes=1)
            )
        else:
            getattr(client, operation)(job_id, rolled_back["fence_token"])

    row = db_connection.execute(
        "SELECT status, attempts, fence_token FROM queue.jobs "
        "WHERE namespace = %s AND id = %s",
        (namespace, job_id),
    ).fetchone()
    assert row == ("pending", 0, None)

    current = client.pull("tasks")
    assert current["id"] == job_id
    assert client.ack(current["id"], current["fence_token"]) is True


def test_pull_application_write_and_ack_commit_together(consumer, db_connection):
    """Database work and acknowledgement can commit with the pull atomically."""
    conn, client, namespace = consumer
    conn.execute(
        "CREATE TEMP TABLE application_results "
        "(job_id bigint PRIMARY KEY, result text NOT NULL)"
    )
    conn.commit()
    job_id = client.push("tasks", {"n": 1})

    with conn.transaction():
        job = client.pull("tasks")
        conn.execute(
            "INSERT INTO application_results (job_id, result) VALUES (%s, %s)",
            (job["id"], "done"),
        )
        assert client.ack(job["id"], job["fence_token"]) is True

    assert conn.execute(
        "SELECT result FROM application_results WHERE job_id = %s", (job_id,)
    ).fetchone() == ("done",)
    assert (
        db_connection.execute(
            "SELECT 1 FROM queue.jobs WHERE namespace = %s AND id = %s",
            (namespace, job_id),
        ).fetchone()
        is None
    )


def test_pull_application_write_and_ack_roll_back_together(consumer, db_connection):
    """Rolling back the transaction restores both the job and application state."""
    conn, client, namespace = consumer
    conn.execute(
        "CREATE TEMP TABLE application_results "
        "(job_id bigint PRIMARY KEY, result text NOT NULL)"
    )
    conn.commit()
    job_id = client.push("tasks", {"n": 1})

    with conn.transaction(force_rollback=True):
        job = client.pull("tasks")
        conn.execute(
            "INSERT INTO application_results (job_id, result) VALUES (%s, %s)",
            (job["id"], "discarded"),
        )
        assert client.ack(job["id"], job["fence_token"]) is True

    assert conn.execute("SELECT * FROM application_results").fetchall() == []
    row = db_connection.execute(
        "SELECT status, attempts, fence_token FROM queue.jobs "
        "WHERE namespace = %s AND id = %s",
        (namespace, job_id),
    ).fetchone()
    assert row == ("pending", 0, None)


def test_rolled_back_fence_cannot_change_next_pull(consumer, db_connection):
    """A later pull gets a new fence that the rolled-back worker cannot use."""
    conn, client, namespace = consumer
    job_id = client.push("tasks", {"n": 1})
    rolled_back = _pull_then_rollback(conn, client)

    current = client.pull("tasks", worker_id="worker-b")
    assert current["id"] == job_id
    assert current["fence_token"] > rolled_back["fence_token"]

    with pytest.raises(QueueFencingError):
        client.fail(job_id, rolled_back["fence_token"], error="obsolete pull result")

    row = db_connection.execute(
        "SELECT status, locked_by, fence_token FROM queue.jobs "
        "WHERE namespace = %s AND id = %s",
        (namespace, job_id),
    ).fetchone()
    assert row == ("running", "worker-b", current["fence_token"])
    assert client.ack(job_id, current["fence_token"]) is True


def test_reclaimed_job_at_max_attempts_moves_to_dlq(queue, test_helpers):
    """Timeout reclamation preserves attempts, so the last retry reaches the DLQ."""
    queue.push("tasks", {"n": 1}, max_attempts=2)
    first = queue.pull("tasks", worker_id="worker-a")
    test_helpers.expire_visibility_timeout(first["id"])
    assert queue.tick_timeouts()[0]["job_id"] == first["id"]

    second = queue.pull("tasks", worker_id="worker-b")
    assert second["attempts"] == 2
    assert (
        queue.nack(second["id"], second["fence_token"], error="still failing") is False
    )

    assert test_helpers.get_job_raw(second["id"])["status"] == "dead"
    assert test_helpers.count_dead_letters() == 1
