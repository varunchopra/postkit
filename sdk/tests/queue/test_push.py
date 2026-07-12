"""Tests for queue push operations."""

import json

import psycopg
import psycopg.errors
import pytest
from postkit.errors import QueueErrorCode
from postkit.queue import QueueValidationError

from tests.conftest import DATABASE_URL
from tests.helpers import channel_name


class TestPushNotify:
    """queue.channel_name(namespace, queue) is the channel to LISTEN on for
    push wake-ups; two different (namespace, queue) pairs never share one."""

    def test_distinct_pairs_get_distinct_channels(self, db_connection):
        cur = db_connection.cursor()
        cur.execute(
            "SELECT queue.channel_name('acme', 'corp/jobs'),"
            "       queue.channel_name('acme/corp', 'jobs')"
        )
        first, second = cur.fetchone()
        assert first != second

    def test_push_notifies_on_helper_channel(self, queue, db_connection):
        channel = channel_name(db_connection.cursor(), "queue", queue.namespace, "jobs")
        listener = psycopg.connect(DATABASE_URL, autocommit=True)
        try:
            listener.execute(f'LISTEN "{channel}"')
            job_id = queue.push("jobs", {"n": 1})
            got = list(listener.notifies(timeout=10, stop_after=1))
            assert len(got) == 1
            assert json.loads(got[0].payload) == {"id": job_id, "queue": "jobs"}
        finally:
            listener.close()


class TestPush:
    """Test basic push functionality."""

    def test_push_returns_job_id(self, queue):
        """Push returns a positive job ID."""
        job_id = queue.push("email", {"to": "alice@example.com"})

        assert job_id is not None
        assert job_id > 0

    def test_push_with_all_options(self, queue):
        """Push stores all optional parameters correctly."""
        job_id = queue.push(
            "email",
            {"to": "alice@example.com", "subject": "Hello"},
            priority=1000,
            max_attempts=5,
            unique_key="email:alice:welcome",
            tags=["welcome", "onboarding"],
            metadata={"source": "signup"},
        )

        assert job_id is not None

        # Verify options were actually stored
        job = queue.pull("email")
        assert job is not None
        assert job["id"] == job_id
        assert job["priority"] == 1000
        assert job["max_attempts"] == 5
        assert job["tags"] == ["welcome", "onboarding"]
        assert job["metadata"] == {"source": "signup"}
        assert job["unique_key"] == "email:alice:welcome"

        queue.ack(job["id"])


class TestPushDeduplication:
    """Test unique_key deduplication."""

    def test_unique_key_prevents_duplicates(self, queue):
        """Same unique_key returns None on second push."""
        job_id1 = queue.push("sync", {"user": 1}, unique_key="sync:user:1")
        job_id2 = queue.push("sync", {"user": 1}, unique_key="sync:user:1")

        assert job_id1 is not None
        assert job_id2 is None  # Deduplicated

    def test_unique_key_allows_different_keys(self, queue):
        """Different unique_keys create separate jobs."""
        job_id1 = queue.push("sync", {"user": 1}, unique_key="sync:user:1")
        job_id2 = queue.push("sync", {"user": 2}, unique_key="sync:user:2")

        assert job_id1 is not None
        assert job_id2 is not None
        assert job_id1 != job_id2

    def test_unique_key_allows_same_key_different_queue(self, queue):
        """Same unique_key in different queues creates separate jobs."""
        job_id1 = queue.push("email", {"user": 1}, unique_key="notify:1")
        job_id2 = queue.push("sms", {"user": 1}, unique_key="notify:1")

        assert job_id1 is not None
        assert job_id2 is not None
        assert job_id1 != job_id2

    def test_unique_key_allows_reuse_after_completion(self, queue):
        """Unique key can be reused after job completes."""
        # Push and complete first job
        queue.push("sync", {"user": 1}, unique_key="sync:user:1")
        job = queue.pull("sync")
        queue.ack(job["id"])

        # Same unique_key should work now
        job_id2 = queue.push("sync", {"user": 1}, unique_key="sync:user:1")
        assert job_id2 is not None


class TestPushBatch:
    """Test batch push functionality."""

    def test_push_batch_returns_job_ids(self, queue):
        """Batch push returns array of job IDs."""
        payloads = [
            {"to": "alice@example.com"},
            {"to": "bob@example.com"},
            {"to": "carol@example.com"},
        ]
        job_ids = queue.push_batch("email", payloads)

        assert len(job_ids) == 3
        assert all(job_id > 0 for job_id in job_ids)
        # IDs should be unique
        assert len(set(job_ids)) == 3

    def test_push_batch_empty_returns_empty(self, queue):
        """Empty batch returns empty array."""
        job_ids = queue.push_batch("email", [])
        assert job_ids == []

    def test_push_batch_with_options(self, queue):
        """Batch push propagates priority, max_attempts, and tags to all jobs."""
        payloads = [{"msg": "alert1"}, {"msg": "alert2"}]
        job_ids = queue.push_batch(
            "alerts",
            payloads,
            priority=100,
            max_attempts=1,
            tags=["critical"],
        )

        assert len(job_ids) == 2

        # Pull jobs and verify options were propagated
        jobs = queue.pull_batch("alerts", limit=2)
        assert len(jobs) == 2
        for job in jobs:
            assert job["priority"] == 100
            assert job["max_attempts"] == 1
            assert job["tags"] == ["critical"]

        for job in jobs:
            queue.ack(job["id"])


class TestPushValidation:
    """Test push input validation."""

    def test_push_rejects_empty_queue_name(self, queue):
        """Empty queue name raises validation error."""

        with pytest.raises(QueueValidationError) as exc_info:
            queue.push("", {"data": 1})
        assert exc_info.value.error_code == QueueErrorCode.VAL_QUEUE_EMPTY

    def test_push_rejects_priority_out_of_range(self, queue):
        """Priority outside -1000 to 1000 raises validation error."""

        with pytest.raises(QueueValidationError) as exc_info:
            queue.push("test", {"data": 1}, priority=2000)
        assert exc_info.value.error_code == QueueErrorCode.VAL_PRIORITY_RANGE

        with pytest.raises(QueueValidationError) as exc_info:
            queue.push("test", {"data": 1}, priority=-2000)
        assert exc_info.value.error_code == QueueErrorCode.VAL_PRIORITY_RANGE

    def test_push_rejects_max_attempts_out_of_range(self, queue):
        """max_attempts outside 1 to 30 raises validation error."""

        with pytest.raises(QueueValidationError) as exc_info:
            queue.push("test", {"data": 1}, max_attempts=31)
        assert exc_info.value.error_code == QueueErrorCode.VAL_MAX_ATTEMPTS_RANGE

        with pytest.raises(QueueValidationError) as exc_info:
            queue.push("test", {"data": 1}, max_attempts=0)
        assert exc_info.value.error_code == QueueErrorCode.VAL_MAX_ATTEMPTS_RANGE

    def test_push_batch_rejects_max_attempts_out_of_range(self, queue):
        """max_attempts outside 1 to 30 raises validation error."""

        with pytest.raises(QueueValidationError) as exc_info:
            queue.push_batch("test", [{"data": 1}], max_attempts=31)
        assert exc_info.value.error_code == QueueErrorCode.VAL_MAX_ATTEMPTS_RANGE

    def test_push_batch_rejects_null_payload_element(self, raw_cursor):
        """Batch push with a NULL array element raises null_value_not_allowed."""
        cursor, namespace = raw_cursor

        with pytest.raises(psycopg.errors.NullValueNotAllowed) as exc_info:
            cursor.execute(
                """SELECT queue.push_batch(
                    p_namespace := %s,
                    p_queue := %s,
                    p_payloads := ARRAY[NULL::jsonb, '{"valid":true}'::jsonb]
                )""",
                (namespace, "test_queue"),
            )
        assert "VAL_PAYLOAD_NULL" in exc_info.value.diag.message_hint
