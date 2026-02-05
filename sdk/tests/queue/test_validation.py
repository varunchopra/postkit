"""Namespace and queue name validation tests for queue module."""

import pytest
from postkit.errors import QueueErrorCode
from postkit.queue import QueueError, QueueValidationError

from tests.helpers import (
    NAMESPACE_ERROR_CASES,
    VALID_NAMESPACES,
)


class TestNamespaceValidation:
    """Namespace must be 1-1024 chars, no control chars or leading/trailing whitespace."""

    def test_valid_namespaces(self, make_queue):
        for ns in VALID_NAMESPACES:
            client = make_queue(ns)
            client.push("test_queue", {"data": 1})


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

    @pytest.mark.parametrize("ns, error_code_name", NAMESPACE_ERROR_CASES)
    def test_namespace_validation_raises_correct_error(
        self, make_queue, ns, error_code_name
    ):
        with pytest.raises(QueueValidationError) as exc_info:
            make_queue(ns)
        assert exc_info.value.error_code == getattr(QueueErrorCode, error_code_name)

    def test_queue_validation_error_is_queue_error(self):
        """QueueValidationError is a subclass of QueueError for backwards compatibility."""
        assert issubclass(QueueValidationError, QueueError)
