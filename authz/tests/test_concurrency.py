"""
Concurrency tests for postkit/authz.

With lazy evaluation, writes don't require serialization for correctness
since there's no precomputed table to maintain. These tests verify that
concurrent operations work correctly.
"""

import os
import pytest
import psycopg
import threading
import time

from authz_sdk import AuthzTestHelpers

# Database connection from environment or default (matches Makefile)
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/postgres"
)


class TestWriteSerialization:
    """Verify concurrent writes work correctly with lazy evaluation."""

    def test_concurrent_writes_always_correct(self, db_connection):
        """
        Concurrent writes produce correct results with lazy evaluation.

        Scenario:
        T1: Add Alice to team:eng
        T2: Add team:eng as admin on repo:api

        Result: Alice MUST have admin on repo:api
        """
        namespace = "test_serialized_writes"

        cursor = db_connection.cursor()
        cursor.execute("DELETE FROM authz.tuples WHERE namespace = %s", (namespace,))

        results = {"t1_done": False, "t2_done": False, "errors": []}
        barrier = threading.Barrier(2)

        def transaction_1():
            try:
                conn = psycopg.connect(DATABASE_URL)
                cur = conn.cursor()
                barrier.wait()
                cur.execute(
                    "SELECT authz.write('team', 'eng', 'member', 'user', 'alice', %s)",
                    (namespace,),
                )
                conn.commit()
                results["t1_done"] = True
                conn.close()
            except Exception as e:
                results["errors"].append(f"T1: {e}")

        def transaction_2():
            try:
                conn = psycopg.connect(DATABASE_URL)
                cur = conn.cursor()
                barrier.wait()
                cur.execute(
                    "SELECT authz.write('repo', 'api', 'admin', 'team', 'eng', %s)",
                    (namespace,),
                )
                conn.commit()
                results["t2_done"] = True
                conn.close()
            except Exception as e:
                results["errors"].append(f"T2: {e}")

        t1 = threading.Thread(target=transaction_1)
        t2 = threading.Thread(target=transaction_2)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert not results["errors"], f"Errors: {results['errors']}"
        assert results["t1_done"] and results["t2_done"]

        # The critical assertion: Alice MUST have access
        # With lazy evaluation, this is computed at query time
        cursor.execute(
            "SELECT authz.check('alice', 'admin', 'repo', 'api', %s)", (namespace,)
        )
        has_permission = cursor.fetchone()[0]
        assert has_permission, "Alice MUST have admin on repo:api via team:eng"

        # Cleanup
        cursor.execute("DELETE FROM authz.tuples WHERE namespace = %s", (namespace,))

    def test_concurrent_same_resource_all_succeed(self, db_connection):
        """Multiple concurrent grants to the same resource should all succeed."""
        namespace = "test_concurrent_same_resource"

        cursor = db_connection.cursor()
        cursor.execute("DELETE FROM authz.tuples WHERE namespace = %s", (namespace,))

        num_users = 10
        results = {"completed": 0, "errors": []}
        results_lock = threading.Lock()
        barrier = threading.Barrier(num_users)

        def grant_to_user(user_id):
            try:
                conn = psycopg.connect(DATABASE_URL)
                cur = conn.cursor()
                barrier.wait()
                cur.execute(
                    "SELECT authz.write('doc', 'shared', 'read', 'user', %s, %s)",
                    (user_id, namespace),
                )
                conn.commit()
                with results_lock:
                    results["completed"] += 1
                conn.close()
            except Exception as e:
                with results_lock:
                    results["errors"].append(f"User {user_id}: {e}")

        threads = [
            threading.Thread(target=grant_to_user, args=(f"user-{i}",))
            for i in range(num_users)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not results["errors"], f"Errors: {results['errors']}"
        assert results["completed"] == num_users

        # All users should have read permission
        for i in range(num_users):
            cursor.execute(
                "SELECT authz.check(%s, 'read', 'doc', 'shared', %s)",
                (f"user-{i}", namespace),
            )
            assert cursor.fetchone()[0], f"user-{i} should have read permission"

        # Cleanup
        cursor.execute("DELETE FROM authz.tuples WHERE namespace = %s", (namespace,))


class TestNamespaceIsolation:
    """Verify different namespaces can write in parallel."""

    def test_different_namespaces_not_blocked(self, db_connection):
        """Writes to different namespaces proceed in parallel."""
        ns1 = "test_parallel_ns1"
        ns2 = "test_parallel_ns2"

        cursor = db_connection.cursor()
        for ns in [ns1, ns2]:
            cursor.execute("DELETE FROM authz.tuples WHERE namespace = %s", (ns,))

        results = {"start_times": {}, "end_times": {}, "errors": []}
        barrier = threading.Barrier(2)

        def write_to_namespace(ns, thread_id):
            try:
                conn = psycopg.connect(DATABASE_URL)
                cur = conn.cursor()
                barrier.wait()
                results["start_times"][thread_id] = time.time()
                cur.execute(
                    "SELECT authz.write('doc', '1', 'read', 'user', 'alice', %s)",
                    (ns,),
                )
                # Simulate some work to make overlap measurable
                cur.execute("SELECT pg_sleep(0.05)")
                conn.commit()
                results["end_times"][thread_id] = time.time()
                conn.close()
            except Exception as e:
                results["errors"].append(f"{thread_id}: {e}")

        t1 = threading.Thread(target=write_to_namespace, args=(ns1, "T1"))
        t2 = threading.Thread(target=write_to_namespace, args=(ns2, "T2"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert not results["errors"], f"Errors: {results['errors']}"

        # Both should have overlapping execution (parallel)
        t1_start = results["start_times"]["T1"]
        t1_end = results["end_times"]["T1"]
        t2_start = results["start_times"]["T2"]
        t2_end = results["end_times"]["T2"]

        # Check for overlap: T1 started before T2 ended AND T2 started before T1 ended
        overlapped = (t1_start < t2_end) and (t2_start < t1_end)
        assert overlapped, "Different namespaces should execute in parallel"

        # Cleanup
        for ns in [ns1, ns2]:
            cursor.execute("DELETE FROM authz.tuples WHERE namespace = %s", (ns,))


class TestConcurrentHierarchyChanges:
    """Test hierarchy changes concurrent with tuple writes."""

    def test_hierarchy_change_during_writes(self, make_authz):
        """Hierarchy change while writes are happening stays consistent."""
        namespace = "test_concurrent_hierarchy"
        checker = make_authz(namespace)

        results = {"errors": []}
        results_lock = threading.Lock()
        barrier = threading.Barrier(3)

        def write_tuples(thread_id):
            try:
                conn = psycopg.connect(DATABASE_URL)
                cur = conn.cursor()
                barrier.wait()
                for i in range(20):
                    cur.execute(
                        "SELECT authz.write('doc', %s, 'admin', 'user', 'alice', %s)",
                        (f"doc-{thread_id}-{i}", namespace),
                    )
                    conn.commit()
                conn.close()
            except Exception as e:
                with results_lock:
                    results["errors"].append(f"writer-{thread_id}: {e}")

        def modify_hierarchy():
            try:
                conn = psycopg.connect(DATABASE_URL)
                cur = conn.cursor()
                barrier.wait()
                # Add, then remove, then add again
                for _ in range(3):
                    cur.execute(
                        "SELECT authz.add_hierarchy('doc', 'admin', 'read', %s)",
                        (namespace,),
                    )
                    conn.commit()
                    time.sleep(0.01)
                    cur.execute(
                        "SELECT authz.remove_hierarchy('doc', 'admin', 'read', %s)",
                        (namespace,),
                    )
                    conn.commit()
                conn.close()
            except Exception as e:
                with results_lock:
                    results["errors"].append(f"hierarchy: {e}")

        threads = [
            threading.Thread(target=write_tuples, args=(1,)),
            threading.Thread(target=write_tuples, args=(2,)),
            threading.Thread(target=modify_hierarchy),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not results["errors"], f"Errors: {results['errors']}"


class TestConcurrentCyclePrevention:
    """Test that concurrent transactions cannot create cycles."""

    def test_concurrent_cycle_one_rejected(self, db_connection):
        """
        Two concurrent transactions cannot both create edges that form a cycle.

        Scenario:
        T1: write('team', 'B', 'member', 'team', 'A')  -- A is member of B
        T2: write('team', 'A', 'member', 'team', 'B')  -- B is member of A

        Only ONE should succeed. The other should be rejected by cycle detection
        (after waiting for the first to commit/rollback due to dual advisory lock).
        """
        namespace = "test_concurrent_cycle"

        cursor = db_connection.cursor()
        cursor.execute("DELETE FROM authz.tuples WHERE namespace = %s", (namespace,))

        results = {
            "t1_success": False,
            "t2_success": False,
            "t1_error": None,
            "t2_error": None,
        }
        barrier = threading.Barrier(2)

        def transaction_1():
            try:
                conn = psycopg.connect(DATABASE_URL)
                cur = conn.cursor()
                barrier.wait()
                cur.execute(
                    "SELECT authz.write_tuple('team', 'B', 'member', 'team', 'A', NULL, %s)",
                    (namespace,),
                )
                conn.commit()
                results["t1_success"] = True
                conn.close()
            except Exception as e:
                results["t1_error"] = str(e)

        def transaction_2():
            try:
                conn = psycopg.connect(DATABASE_URL)
                cur = conn.cursor()
                barrier.wait()
                cur.execute(
                    "SELECT authz.write_tuple('team', 'A', 'member', 'team', 'B', NULL, %s)",
                    (namespace,),
                )
                conn.commit()
                results["t2_success"] = True
                conn.close()
            except Exception as e:
                results["t2_error"] = str(e)

        t1 = threading.Thread(target=transaction_1)
        t2 = threading.Thread(target=transaction_2)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Exactly one should succeed, one should fail with cycle error
        successes = sum([results["t1_success"], results["t2_success"]])
        assert successes == 1, (
            f"Expected exactly 1 success, got {successes}. "
            f"T1: success={results['t1_success']}, error={results['t1_error']}. "
            f"T2: success={results['t2_success']}, error={results['t2_error']}"
        )

        # The failure should be a cycle error
        error = results["t1_error"] or results["t2_error"]
        assert "circular" in error.lower(), f"Expected cycle error, got: {error}"

        # Cleanup
        cursor.execute("DELETE FROM authz.tuples WHERE namespace = %s", (namespace,))

    def test_lock_ordering_prevents_deadlock(self, db_connection):
        """
        Deterministic lock ordering prevents deadlocks.

        Both transactions lock in the same order (lexicographically smaller key first),
        so no deadlock is possible even with concurrent cycle-forming writes.

        With idempotent writes:
        - All threads trying one direction (e.g., X->Y) succeed (same edge, idempotent)
        - All threads trying the opposite direction (Y->X) fail with cycle error
        """
        namespace = "test_lock_ordering"

        cursor = db_connection.cursor()
        cursor.execute("DELETE FROM authz.tuples WHERE namespace = %s", (namespace,))

        # Run many concurrent potential-cycle writes to stress test lock ordering
        num_attempts = 20
        results = {"successes": 0, "cycle_errors": 0, "other_errors": []}
        lock = threading.Lock()

        def attempt_cycle_edge(i):
            """Each thread tries to create one edge of a potential cycle."""
            try:
                conn = psycopg.connect(DATABASE_URL)
                cur = conn.cursor()
                # Alternate direction to create potential cycles
                if i % 2 == 0:
                    cur.execute(
                        "SELECT authz.write_tuple('team', 'X', 'member', 'team', 'Y', NULL, %s)",
                        (namespace,),
                    )
                else:
                    cur.execute(
                        "SELECT authz.write_tuple('team', 'Y', 'member', 'team', 'X', NULL, %s)",
                        (namespace,),
                    )
                conn.commit()
                with lock:
                    results["successes"] += 1
                conn.close()
            except Exception as e:
                with lock:
                    if "circular" in str(e).lower():
                        results["cycle_errors"] += 1
                    else:
                        results["other_errors"].append(str(e))

        threads = [
            threading.Thread(target=attempt_cycle_edge, args=(i,))
            for i in range(num_attempts)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No deadlock errors (would show as timeout or other_errors)
        # This is the key assertion - deadlocks would appear here
        assert not results[
            "other_errors"
        ], f"Unexpected errors: {results['other_errors']}"

        # With idempotent writes: half succeed (one direction), half fail (opposite direction)
        # All threads of one direction succeed (idempotent), all of other direction fail (cycle)
        assert (
            results["successes"] == num_attempts // 2
        ), f"Expected {num_attempts // 2} successes (one direction), got {results['successes']}"
        assert (
            results["cycle_errors"] == num_attempts // 2
        ), f"Expected {num_attempts // 2} cycle errors (opposite direction), got {results['cycle_errors']}"

        # Cleanup
        cursor.execute("DELETE FROM authz.tuples WHERE namespace = %s", (namespace,))


class TestConcurrentIdempotency:
    """Test idempotency under concurrent access."""

    def test_concurrent_identical_grants_idempotent(self, make_authz, db_connection):
        """Multiple concurrent identical grants don't create duplicates."""
        namespace = "test_idempotent"
        checker = make_authz(namespace)

        results = {"ids": [], "errors": []}
        barrier = threading.Barrier(5)
        lock = threading.Lock()

        def grant_same_permission(thread_id):
            try:
                conn = psycopg.connect(DATABASE_URL)
                cur = conn.cursor()
                barrier.wait()
                cur.execute(
                    "SELECT authz.write('doc', '1', 'read', 'user', 'alice', %s)",
                    (namespace,),
                )
                tuple_id = cur.fetchone()[0]
                conn.commit()
                with lock:
                    results["ids"].append(tuple_id)
                conn.close()
            except Exception as e:
                with lock:
                    results["errors"].append(str(e))

        threads = [
            threading.Thread(target=grant_same_permission, args=(i,)) for i in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not results["errors"], f"Errors: {results['errors']}"
        # All threads should get the same tuple ID (idempotent)
        assert len(set(results["ids"])) == 1, "All grants should return same ID"

        # With lazy evaluation, we just verify the permission works
        assert checker.check("alice", "read", ("doc", "1"))
