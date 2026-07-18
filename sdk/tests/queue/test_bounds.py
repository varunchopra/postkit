import pytest
from postkit.queue import QueueValidationError


def test_every_bounded_queue_api_rejects_max_plus_one(queue):
    calls = (
        (lambda: queue.push_batch("jobs", [{}] * 1001), "VAL_BATCH_TOO_LARGE"),
        (lambda: queue.pull_batch("jobs", limit=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: queue.pull_any(["jobs"] * 1001), "VAL_BATCH_TOO_LARGE"),
        (lambda: queue.ack_batch([0] * 1001), "VAL_BATCH_TOO_LARGE"),
        (lambda: queue.list_schedules(limit=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: queue.tick_schedules(limit=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: queue.tick_timeouts(limit=1001), "VAL_LIMIT_TOO_LARGE"),
        (lambda: queue.retry_dead_letters("jobs", limit=1001), "VAL_LIMIT_TOO_LARGE"),
    )
    for call, code in calls:
        with pytest.raises(QueueValidationError) as exc_info:
            call()
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == code


def test_queue_boundaries_accept_max_and_rejected_batch_is_atomic(queue):
    assert len(queue.push_batch("bounds", [{"i": i} for i in range(1000)])) == 1000
    before = queue.get_stats()["total_jobs"]
    with pytest.raises(QueueValidationError):
        queue.push_batch("atomic", [{"i": i} for i in range(1001)])
    assert queue.get_stats()["total_jobs"] == before

    for bad in (None, 0, -1):
        with pytest.raises(QueueValidationError) as exc_info:
            queue.list_schedules(limit=bad)
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == "VAL_NOT_POSITIVE"
