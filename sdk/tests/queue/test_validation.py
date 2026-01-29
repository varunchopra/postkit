"""Namespace and queue name validation tests for queue module."""

import pytest
from postkit.errors import QueueErrorCode
from postkit.queue import QueueError, QueueValidationError


class TestNamespaceValidation:
    """Namespace must be 1-1024 chars, no control chars or leading/trailing whitespace."""

    def test_valid_namespaces(self, make_queue):
        """Valid namespace formats should be accepted."""
        valid = ["default", "tenant_123", "org:my-org", "MyOrg", "a" * 1024]
        for ns in valid:
            client = make_queue(ns)
            client.push("test_queue", {"data": 1})

    def test_rejects_null(self, make_queue):
        with pytest.raises(QueueError) as exc_info:
            make_queue(None)
        assert exc_info.value.error_code == QueueErrorCode.VAL_NAMESPACE_NULL

    def test_rejects_empty(self, make_queue):
        with pytest.raises(QueueError) as exc_info:
            make_queue("")
        assert exc_info.value.error_code == QueueErrorCode.VAL_NAMESPACE_EMPTY

    def test_rejects_whitespace_only(self, make_queue):
        with pytest.raises(QueueError) as exc_info:
            make_queue("   ")
        assert exc_info.value.error_code == QueueErrorCode.VAL_NAMESPACE_EMPTY

    def test_rejects_leading_whitespace(self, make_queue):
        with pytest.raises(QueueError) as exc_info:
            make_queue(" leading")
        assert exc_info.value.error_code == QueueErrorCode.VAL_NAMESPACE_WHITESPACE

    def test_rejects_trailing_whitespace(self, make_queue):
        with pytest.raises(QueueError) as exc_info:
            make_queue("trailing ")
        assert exc_info.value.error_code == QueueErrorCode.VAL_NAMESPACE_WHITESPACE

    def test_rejects_control_characters(self, make_queue):
        with pytest.raises(QueueError) as exc_info:
            make_queue("has\ttab")
        assert exc_info.value.error_code == QueueErrorCode.VAL_NAMESPACE_INVALID_CHARS

    def test_rejects_over_max_length(self, make_queue):
        with pytest.raises(QueueError) as exc_info:
            make_queue("a" * 1025)
        assert exc_info.value.error_code == QueueErrorCode.VAL_NAMESPACE_TOO_LONG


class TestQueueNameBoundaries:
    """Queue name boundary validation for null, length limits, and allowed characters."""

    def test_rejects_null_queue_name(self, queue):
        with pytest.raises(QueueValidationError) as exc_info:
            queue.push(None, {"data": 1})
        assert exc_info.value.error_code == QueueErrorCode.VAL_QUEUE_NULL

    def test_rejects_too_long_queue_name(self, queue):
        with pytest.raises(QueueValidationError) as exc_info:
            queue.push("a" * 257, {"data": 1})
        assert exc_info.value.error_code == QueueErrorCode.VAL_QUEUE_TOO_LONG

    def test_accepts_max_length_queue_name(self, queue):
        """256-character queue name is at the limit and should be accepted."""
        job_id = queue.push("a" * 256, {"data": 1})
        assert job_id is not None

    def test_accepts_underscore_prefix(self, queue):
        job_id = queue.push("_private", {"data": 1})
        assert job_id is not None

    def test_accepts_hyphens_and_underscores(self, queue):
        job_id = queue.push("my-queue_name", {"data": 1})
        assert job_id is not None


class TestValidationErrorType:
    """Validation errors raise QueueValidationError for precise error handling."""

    def test_null_raises_queue_validation_error(self, make_queue):
        """Null namespace raises QueueValidationError (SQLSTATE 22004)."""
        with pytest.raises(QueueValidationError) as exc_info:
            make_queue(None)
        assert exc_info.value.error_code == QueueErrorCode.VAL_NAMESPACE_NULL

    def test_empty_raises_queue_validation_error(self, make_queue):
        """Empty namespace raises QueueValidationError (SQLSTATE 22026)."""
        with pytest.raises(QueueValidationError) as exc_info:
            make_queue("")
        assert exc_info.value.error_code == QueueErrorCode.VAL_NAMESPACE_EMPTY

    def test_length_raises_queue_validation_error(self, make_queue):
        """Length exceeded raises QueueValidationError (SQLSTATE 22001)."""
        with pytest.raises(QueueValidationError) as exc_info:
            make_queue("a" * 1025)
        assert exc_info.value.error_code == QueueErrorCode.VAL_NAMESPACE_TOO_LONG

    def test_format_raises_queue_validation_error(self, make_queue):
        """Format violation raises QueueValidationError (SQLSTATE 22023)."""
        with pytest.raises(QueueValidationError) as exc_info:
            make_queue("has\ttab")
        assert exc_info.value.error_code == QueueErrorCode.VAL_NAMESPACE_INVALID_CHARS

    def test_queue_validation_error_is_queue_error(self):
        """QueueValidationError is a subclass of QueueError for backwards compatibility."""
        assert issubclass(QueueValidationError, QueueError)
