"""Completion operations guarded by the fence returned from pull.

A job ID survives redelivery, so it cannot identify a running attempt by itself.
Operations reject pending or missing jobs, expired attempts, and tokens from
earlier pulls.
Batch acknowledgement adds an all-or-nothing guarantee across jobs.
"""

from datetime import timedelta

import psycopg
import pytest
from postkit.errors import QueueErrorCode
from postkit.queue import QueueError, QueueFencingError, QueueValidationError


def _pull(queue, *, max_attempts=3, worker_id=None, timeout=None):
    job_id = queue.push("tasks", {"job": "test"}, max_attempts=max_attempts)
    job = queue.pull("tasks", worker_id=worker_id, visibility_timeout=timeout)
    assert job["id"] == job_id
    return job


def _assert_stale_fence(call):
    """Assert that FENCE_STALE maps to QueueFencingError."""
    with pytest.raises(QueueFencingError) as exc_info:
        call()
    assert exc_info.value.sqlstate == "40001"
    assert exc_info.value.error_code == QueueErrorCode.FENCE_STALE


def test_serialization_failure_without_fence_hint_is_not_a_fencing_error(queue):
    """SQLSTATE 40001 alone must not be mistaken for the queue's fence error."""
    error = psycopg.errors.SerializationFailure("could not serialize access")

    with pytest.raises(QueueError) as exc_info:
        queue._handle_error(error)

    assert type(exc_info.value) is QueueError
    assert exc_info.value.sqlstate == "40001"


class TestExtendVisibility:
    """Visibility extension adds time only to the current attempt."""

    def test_adds_to_current_deadline(self, queue):
        job = _pull(queue, timeout=timedelta(hours=1))
        old_deadline = job["visibility_timeout_at"]

        assert (
            queue.extend_visibility(
                job["id"], job["fence_token"], timedelta(seconds=10)
            )
            is True
        )

        row = queue.cursor.execute(
            "SELECT visibility_timeout_at FROM queue.jobs WHERE id = %s",
            (job["id"],),
        ).fetchone()
        assert row[0] == old_deadline + timedelta(seconds=10)
        assert queue.ack(job["id"], job["fence_token"]) is True

    @pytest.mark.parametrize("extension", [None, timedelta(0), timedelta(seconds=-1)])
    def test_rejects_nonpositive_extension(self, queue, extension):
        job = _pull(queue)
        with pytest.raises(QueueValidationError) as exc_info:
            queue.extend_visibility(job["id"], job["fence_token"], extension)
        assert exc_info.value.error_code == QueueErrorCode.VAL_EXTENSION_POSITIVE


class TestAck:
    """Acknowledgement either deletes a job or archives it as completed."""

    def test_returns_true_and_removes_job(self, queue, test_helpers):
        job = _pull(queue)

        assert queue.ack(job["id"], job["fence_token"]) is True
        assert test_helpers.get_job_raw(job["id"]) is None

    def test_archives_job_when_configured(self, queue, test_helpers):
        """Archive mode must clear every field that belonged to the attempt."""
        queue.cursor.execute(
            "INSERT INTO queue.config (namespace, archive_completed) VALUES (%s, true)",
            (queue.namespace,),
        )
        job = _pull(queue)

        assert queue.ack(job["id"], job["fence_token"]) is True

        stored = test_helpers.get_job_raw(job["id"])
        assert stored["status"] == "completed"
        assert stored["completed_at"] is not None
        assert stored["locked_by"] is None
        assert stored["locked_at"] is None
        assert stored["visibility_timeout_at"] is None
        assert stored["fence_token"] is None
        assert queue.get_stats()["completed"] == 1
        assert queue.get_stats()["total_jobs"] == 1

    def test_pending_job_raises_stale_fence(self, queue):
        job_id = queue.push("tasks", {"state": "pending"})
        _assert_stale_fence(lambda: queue.ack(job_id, 1))

    def test_missing_job_raises_stale_fence(self, queue):
        _assert_stale_fence(lambda: queue.ack(9_999_999, 1))

    def test_acknowledged_job_raises_stale_fence(self, queue):
        queue.cursor.execute(
            "INSERT INTO queue.config (namespace, archive_completed) VALUES (%s, true)",
            (queue.namespace,),
        )
        job = _pull(queue)
        assert queue.ack(job["id"], job["fence_token"]) is True

        _assert_stale_fence(lambda: queue.ack(job["id"], job["fence_token"]))

    def test_rejects_null_identifiers(self, queue):
        with pytest.raises(QueueValidationError) as exc_info:
            queue.ack(None, 1)  # type: ignore[arg-type]
        assert exc_info.value.error_code == QueueErrorCode.VAL_JOB_ID_NULL

        with pytest.raises(QueueValidationError) as exc_info:
            queue.ack(1, None)  # type: ignore[arg-type]
        assert exc_info.value.error_code == QueueErrorCode.VAL_FENCE_NULL


class TestAckBatch:
    """Batch acknowledgement validates every attempt before settling any."""

    @staticmethod
    def _pull_jobs(queue, count=3):
        for n in range(count):
            queue.push("tasks", {"n": n})
        return queue.pull_batch("tasks", count)

    @staticmethod
    def _pairs(jobs):
        return [(job["id"], job["fence_token"]) for job in jobs]

    def test_returns_count(self, queue, test_helpers):
        jobs = self._pull_jobs(queue)

        assert queue.ack_batch(self._pairs(jobs)) == 3
        assert test_helpers.count_jobs() == 0

    def test_empty_batch_returns_zero(self, queue):
        assert queue.ack_batch([]) == 0

    def test_archives_when_configured(self, queue, test_helpers):
        queue.cursor.execute(
            "INSERT INTO queue.config (namespace, archive_completed) VALUES (%s, true)",
            (queue.namespace,),
        )
        jobs = self._pull_jobs(queue)

        assert queue.ack_batch(self._pairs(jobs)) == 3
        assert test_helpers.count_jobs(status="completed") == 3
        for job in jobs:
            assert test_helpers.get_job_raw(job["id"])["fence_token"] is None

    def test_nonrunning_member_aborts_whole_batch(self, queue, test_helpers):
        """A released member must not allow the other running members to settle."""
        jobs = self._pull_jobs(queue, 2)
        assert queue.release(jobs[0]["id"], jobs[0]["fence_token"]) is True

        _assert_stale_fence(lambda: queue.ack_batch(self._pairs(jobs)))

        assert test_helpers.get_job_raw(jobs[0]["id"])["status"] == "pending"
        assert test_helpers.get_job_raw(jobs[1]["id"])["status"] == "running"

    def test_old_fence_for_redelivered_job_aborts_whole_batch(
        self, queue, test_helpers
    ):
        """A running replacement attempt must not accept its predecessor's fence."""
        jobs = self._pull_jobs(queue, 2)
        first, second = jobs
        assert queue.release(first["id"], first["fence_token"]) is True
        current = queue.pull("tasks")
        assert current["id"] == first["id"]
        assert current["fence_token"] != first["fence_token"]

        _assert_stale_fence(lambda: queue.ack_batch(self._pairs(jobs)))

        for job in (current, second):
            stored = test_helpers.get_job_raw(job["id"])
            assert stored["status"] == "running"
            assert stored["fence_token"] == job["fence_token"]
        assert queue.ack_batch(self._pairs([current, second])) == 2

    def test_expired_member_aborts_whole_batch(self, queue, test_helpers):
        """An expired member must not allow another running member to settle."""
        jobs = self._pull_jobs(queue, 2)
        test_helpers.expire_visibility_timeout(jobs[0]["id"])

        _assert_stale_fence(lambda: queue.ack_batch(self._pairs(jobs)))

        for job in jobs:
            assert test_helpers.get_job_raw(job["id"])["status"] == "running"

    def test_missing_member_aborts_whole_batch(self, queue, test_helpers):
        """A missing member must not allow a running member to settle."""
        job = self._pull_jobs(queue, 1)[0]

        _assert_stale_fence(
            lambda: queue.ack_batch([(job["id"], job["fence_token"]), (9_999_999, 1)])
        )

        stored = test_helpers.get_job_raw(job["id"])
        assert stored["status"] == "running"
        assert stored["fence_token"] == job["fence_token"]

    def test_sql_treats_two_null_arrays_as_empty(self, queue):
        result = queue.cursor.execute(
            "SELECT queue.ack_batch(%s, NULL::bigint[], NULL::bigint[])",
            (queue.namespace,),
        ).fetchone()[0]
        assert result == 0

    def test_sql_rejects_mismatched_arrays(self, queue):
        with pytest.raises(psycopg.Error) as exc_info:
            queue.cursor.execute(
                "SELECT queue.ack_batch(%s, %s::bigint[], %s::bigint[])",
                (queue.namespace, [1, 2], [1]),
            )
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.diag.message_hint == "postkit:queue:VAL_ACK_BATCH_LENGTH"

    @pytest.mark.parametrize(
        ("job_ids", "fences", "code"),
        [
            ([None], [1], "VAL_JOB_ID_NULL"),
            ([1], [None], "VAL_FENCE_NULL"),
            ([1, 1], [1, 2], "VAL_ACK_BATCH_DUPLICATE_JOB"),
        ],
    )
    def test_sql_validates_elements_and_duplicate_jobs(
        self, queue, job_ids, fences, code
    ):
        with pytest.raises(psycopg.Error) as exc_info:
            queue.cursor.execute(
                "SELECT queue.ack_batch(%s, %s::bigint[], %s::bigint[])",
                (queue.namespace, job_ids, fences),
            )
        assert exc_info.value.diag.message_hint == f"postkit:queue:{code}"


class TestNack:
    """Nack schedules a retry or dead-letters the final attempt."""

    def test_returns_job_to_queue_and_stores_error(self, queue, test_helpers):
        job = _pull(queue)

        assert (
            queue.nack(job["id"], job["fence_token"], error="temporary failure") is True
        )

        stored = test_helpers.get_job_raw(job["id"])
        assert stored["status"] == "pending"
        assert stored["error"] == "temporary failure"
        assert stored["fence_token"] is None

    def test_repeated_retries_increment_attempts(self, queue):
        queue.push("tasks", {"task": 1}, max_attempts=5)

        for expected_attempt in range(1, 4):
            job = queue.pull("tasks")
            assert job["attempts"] == expected_attempt
            assert queue.nack(job["id"], job["fence_token"]) is True
            # Ignore backoff here; the contract under test is the attempt count.
            queue.cursor.execute(
                "UPDATE queue.jobs SET scheduled_at = now() "
                "WHERE namespace = %s AND id = %s",
                (queue.namespace, job["id"]),
            )

    def test_custom_backoff_is_used(self, queue, test_helpers):
        job = _pull(queue)

        assert (
            queue.nack(
                job["id"],
                job["fence_token"],
                backoff=timedelta(seconds=5),
            )
            is True
        )

        stored = test_helpers.get_job_raw(job["id"])
        assert stored["scheduled_at"] - stored["updated_at"] == timedelta(seconds=5)

    def test_default_backoff_is_capped_at_one_hour(self, queue, test_helpers):
        job = _pull(queue, max_attempts=30)
        # Reach the exponential-backoff ceiling without performing 28 retries.
        queue.cursor.execute(
            "UPDATE queue.jobs SET attempts = 29 WHERE namespace = %s AND id = %s",
            (queue.namespace, job["id"]),
        )
        assert queue.nack(job["id"], job["fence_token"]) is True

        stored = test_helpers.get_job_raw(job["id"])
        assert stored["scheduled_at"] - stored["updated_at"] == timedelta(hours=1)

    def test_max_attempts_moves_job_to_dlq(self, queue, test_helpers):
        job = _pull(queue, max_attempts=1)

        assert queue.nack(job["id"], job["fence_token"], error="still failing") is False

        stored = test_helpers.get_job_raw(job["id"])
        assert stored["status"] == "dead"
        assert stored["fence_token"] is None
        assert test_helpers.count_dead_letters() == 1

    def test_settled_job_raises_stale_fence(self, queue):
        job = _pull(queue)
        assert queue.fail(job["id"], job["fence_token"], error="poison") is True

        _assert_stale_fence(lambda: queue.nack(job["id"], job["fence_token"]))


class TestFail:
    """Fail bypasses retries and records the job in the dead-letter queue."""

    def test_moves_job_to_dlq_and_stores_error(self, queue, test_helpers):
        job = _pull(queue)

        assert (
            queue.fail(job["id"], job["fence_token"], error="invalid payload") is True
        )

        stored = test_helpers.get_job_raw(job["id"])
        assert stored["status"] == "dead"
        assert stored["fence_token"] is None
        queue.cursor.execute(
            "SELECT last_error FROM queue.dead_letters "
            "WHERE namespace = %s AND original_job_id = %s",
            (queue.namespace, job["id"]),
        )
        assert queue.cursor.fetchone()[0] == "invalid payload"

    def test_pending_job_raises_stale_fence(self, queue):
        job_id = queue.push("tasks", {"state": "pending"})
        _assert_stale_fence(lambda: queue.fail(job_id, 1))


class TestRelease:
    """Release is the graceful-shutdown path for one current attempt.

    It returns the job immediately instead of waiting for timeout recovery and
    preserves the attempt count.
    """

    def test_returns_only_selected_job_to_pending(self, queue, test_helpers):
        first = _pull(queue, worker_id="worker-a")
        second = _pull(queue, worker_id="worker-a")

        assert queue.release(first["id"], first["fence_token"]) is True

        released = test_helpers.get_job_raw(first["id"])
        assert released["status"] == "pending"
        assert released["attempts"] == 1
        assert released["locked_by"] is None
        assert released["locked_at"] is None
        assert released["visibility_timeout_at"] is None
        assert released["fence_token"] is None
        assert test_helpers.get_job_raw(second["id"])["status"] == "running"

        redelivered = queue.pull("tasks", worker_id="worker-b")
        assert redelivered["id"] == first["id"]
        assert redelivered["attempts"] == 2
        assert redelivered["fence_token"] != first["fence_token"]
        assert queue.ack(redelivered["id"], redelivered["fence_token"]) is True
        assert queue.ack(second["id"], second["fence_token"]) is True


class TestCancel:
    """Cancellation deletes pending jobs but never running or completed jobs."""

    def test_removes_pending_job_and_makes_it_unpullable(self, queue):
        job_id = queue.push("tasks", {"state": "pending"})

        assert queue.cancel(job_id) is True
        assert queue.cancel(job_id) is False
        assert queue.pull("tasks") is None

    def test_returns_false_for_running_job(self, queue):
        job = _pull(queue)

        assert queue.cancel(job["id"]) is False
        assert queue.ack(job["id"], job["fence_token"]) is True

    def test_returns_false_for_completed_job(self, queue):
        # Archive mode keeps the completed row, distinguishing it from a missing job.
        queue.cursor.execute(
            "INSERT INTO queue.config (namespace, archive_completed) VALUES (%s, true)",
            (queue.namespace,),
        )
        job = _pull(queue)
        assert queue.ack(job["id"], job["fence_token"]) is True

        assert queue.cancel(job["id"]) is False

    def test_rejects_null_job_id(self, queue):
        with pytest.raises(QueueValidationError) as exc_info:
            queue.cancel(None)  # type: ignore[arg-type]
        assert exc_info.value.error_code == QueueErrorCode.VAL_JOB_ID_NULL
