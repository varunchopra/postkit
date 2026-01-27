"""Tests for queue push operations."""

from datetime import timedelta

import pytest


class TestPush:
    """Test basic push functionality."""

    def test_push_returns_job_id(self, queue):
        """Push returns a positive job ID."""
        job_id = queue.push("email", {"to": "alice@example.com"})

        assert job_id is not None
        assert job_id > 0

    def test_push_with_all_options(self, queue):
        """Push accepts all optional parameters."""
        job_id = queue.push(
            "email",
            {"to": "alice@example.com", "subject": "Hello"},
            delay=timedelta(minutes=5),
            priority=10,
            max_attempts=5,
            unique_key="email:alice:welcome",
            tags=["welcome", "onboarding"],
            metadata={"source": "signup"},
        )

        assert job_id is not None

    def test_push_with_high_priority(self, queue):
        """High priority jobs are valid."""
        job_id = queue.push("alert", {"msg": "server down"}, priority=1000)
        assert job_id is not None

    def test_push_with_low_priority(self, queue):
        """Negative priority jobs are valid."""
        job_id = queue.push("bulk", {"data": [1, 2, 3]}, priority=-500)
        assert job_id is not None


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
        """Batch push accepts priority and tags."""
        payloads = [{"msg": "alert1"}, {"msg": "alert2"}]
        job_ids = queue.push_batch(
            "alerts",
            payloads,
            priority=100,
            max_attempts=1,
            tags=["critical"],
        )

        assert len(job_ids) == 2


class TestPushValidation:
    """Test push input validation."""

    def test_push_rejects_empty_queue_name(self, queue):
        """Empty queue name raises validation error."""
        from postkit.queue import ValidationError

        with pytest.raises(ValidationError):
            queue.push("", {"data": 1})

    def test_push_rejects_invalid_queue_name(self, queue):
        """Invalid queue name format raises validation error."""
        from postkit.queue import ValidationError

        with pytest.raises(ValidationError):
            queue.push("123-starts-with-number", {"data": 1})

    def test_push_rejects_priority_out_of_range(self, queue):
        """Priority outside -1000 to 1000 raises validation error."""
        from postkit.queue import ValidationError

        with pytest.raises(ValidationError):
            queue.push("test", {"data": 1}, priority=2000)

        with pytest.raises(ValidationError):
            queue.push("test", {"data": 1}, priority=-2000)
