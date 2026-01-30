"""Test helpers for queue - direct table access for test setup/teardown."""

from datetime import timedelta

from tests.helpers import fetch_row


def cleanup_namespace(cursor, namespace: str):
    """Delete all queue data for a namespace."""
    cursor.execute("DELETE FROM queue.dead_letters WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM queue.schedules WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM queue.jobs WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM queue.config WHERE namespace = %s", (namespace,))


class QueueTestHelpers:
    """
    Direct table access for test setup/teardown that bypasses the SDK.

    Use cases:
    - Counting jobs and dead letters for verification
    - Backdating timestamps to simulate timeouts and aging
    - Inspecting raw job/schedule state
    """

    def __init__(self, cursor, namespace: str):
        self.cursor = cursor
        self.namespace = namespace
        self.cursor.execute("SELECT queue.set_tenant(%s)", (namespace,))

    def count_jobs(self, queue: str | None = None, status: str | None = None) -> int:
        """Count jobs, optionally filtered by queue and/or status."""
        conditions = ["namespace = %s"]
        params: list = [self.namespace]

        if queue:
            conditions.append("queue = %s")
            params.append(queue)
        if status:
            conditions.append("status = %s")
            params.append(status)

        self.cursor.execute(
            f"SELECT COUNT(*) FROM queue.jobs WHERE {' AND '.join(conditions)}",
            tuple(params),
        )
        return self.cursor.fetchone()[0]

    def count_dead_letters(self, queue: str | None = None) -> int:
        """Count dead letters, optionally filtered by queue."""
        if queue:
            self.cursor.execute(
                "SELECT COUNT(*) FROM queue.dead_letters "
                "WHERE namespace = %s AND queue = %s",
                (self.namespace, queue),
            )
        else:
            self.cursor.execute(
                "SELECT COUNT(*) FROM queue.dead_letters WHERE namespace = %s",
                (self.namespace,),
            )
        return self.cursor.fetchone()[0]

    def count_schedules(self) -> int:
        """Count schedules in namespace."""
        self.cursor.execute(
            "SELECT COUNT(*) FROM queue.schedules WHERE namespace = %s",
            (self.namespace,),
        )
        return self.cursor.fetchone()[0]

    def get_job_raw(self, job_id: int) -> dict | None:
        """Get a job directly from the table."""
        self.cursor.execute(
            "SELECT * FROM queue.jobs WHERE namespace = %s AND id = %s",
            (self.namespace, job_id),
        )
        return fetch_row(self.cursor)

    def get_dead_letter_raw(self, dead_letter_id: int) -> dict | None:
        """Get a dead letter directly from the table."""
        self.cursor.execute(
            "SELECT * FROM queue.dead_letters WHERE namespace = %s AND id = %s",
            (self.namespace, dead_letter_id),
        )
        return fetch_row(self.cursor)

    def expire_visibility_timeout(self, job_id: int) -> None:
        """Backdate a job's visibility timeout so tick_timeouts reclaims it.

        Sets visibility_timeout_at to one minute in the past.
        """
        self.cursor.execute(
            "UPDATE queue.jobs SET visibility_timeout_at = now() - interval '1 minute' "
            "WHERE namespace = %s AND id = %s",
            (self.namespace, job_id),
        )

    def expire_schedule_next_run(self, name: str) -> None:
        """Backdate a schedule's next_run_at so tick_schedules processes it.

        Sets next_run_at to one minute in the past.
        """
        self.cursor.execute(
            "UPDATE queue.schedules SET next_run_at = now() - interval '1 minute' "
            "WHERE namespace = %s AND name = %s",
            (self.namespace, name),
        )

    def age_dead_letters(
        self, age: timedelta = timedelta(days=60), queue: str | None = None
    ) -> None:
        """Backdate dead letter failed_at timestamps to simulate aging.

        Args:
            age: how far back to set failed_at
            queue: if provided, only age dead letters in this queue
        """
        if queue:
            self.cursor.execute(
                "UPDATE queue.dead_letters SET failed_at = now() - %s "
                "WHERE namespace = %s AND queue = %s",
                (age, self.namespace, queue),
            )
        else:
            self.cursor.execute(
                "UPDATE queue.dead_letters SET failed_at = now() - %s "
                "WHERE namespace = %s",
                (age, self.namespace),
            )
