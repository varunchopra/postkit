"""Tests for multi-tenancy isolation in the queue module."""


class TestNamespaceIsolation:
    """Verify that queue operations are scoped to the calling tenant's namespace."""

    def test_pull_does_not_return_other_tenants_jobs(self, make_queue):
        """Jobs pushed by tenant A are invisible to tenant B's pull."""
        tenant_a = make_queue("iso_pull_a")
        tenant_b = make_queue("iso_pull_b")

        tenant_a.push("email", {"to": "alice@example.com"})

        # Tenant B sees nothing on the same queue name
        job = tenant_b.pull("email")
        assert job is None

        # Tenant A can still pull their own job
        job = tenant_a.pull("email")
        assert job is not None
        assert job["payload"]["to"] == "alice@example.com"
        tenant_a.ack(job["id"])

    def test_stats_scoped_to_namespace(self, make_queue):
        """get_stats() only counts the calling tenant's jobs."""
        tenant_a = make_queue("iso_stats_a")
        tenant_b = make_queue("iso_stats_b")

        tenant_a.push("tasks", {"task": 1})
        tenant_a.push("tasks", {"task": 2})
        tenant_b.push("tasks", {"task": 3})

        a_stats = tenant_a.get_stats()
        b_stats = tenant_b.get_stats()

        assert a_stats["total_jobs"] == 2
        assert b_stats["total_jobs"] == 1

    def test_ack_does_not_affect_other_tenants_job(self, make_queue):
        """Tenant A cannot ack a job belonging to tenant B."""
        tenant_a = make_queue("iso_ack_a")
        tenant_b = make_queue("iso_ack_b")

        # Tenant B pushes and pulls a job (status becomes "running")
        tenant_b.push("tasks", {"task": "b_job"})
        job_b = tenant_b.pull("tasks")
        assert job_b is not None

        # Tenant A tries to ack tenant B's job ID
        result = tenant_a.ack(job_b["id"])
        assert result is False

        # Tenant B's job is still running
        b_stats = tenant_b.get_stats()
        assert b_stats["running"] == 1

        tenant_b.ack(job_b["id"])

    def test_empty_namespace_returns_no_rows(self, make_queue):
        """A tenant with no jobs gets empty results from all operations."""
        tenant_a = make_queue("iso_empty_a")
        tenant_b = make_queue("iso_empty_b")

        tenant_a.push("tasks", {"task": 1})

        # Tenant B sees nothing
        assert tenant_b.pull("tasks") is None
        assert tenant_b.pull_batch("tasks") == []

        b_stats = tenant_b.get_stats()
        assert b_stats["total_jobs"] == 0
