"""Performance guards for batch pulls and timeout scans.

The ordinary behavior tests would still pass if a batch pull issued one UPDATE
per job or a timeout scan walked every future deadline.
"""


def _plan_nodes(node: dict):
    """Walk PostgreSQL's nested JSON plan tree."""
    yield node
    for child in node.get("Plans", []):
        yield from _plan_nodes(child)


def test_pull_batch_uses_one_update_statement(queue):
    """Pulling a batch must not issue one UPDATE per job."""
    for n in range(5):
        queue.push("tasks", {"n": n})

    queue.cursor.execute(
        "SELECT set_config('test.queue_update_statements', '0', false)"
    )
    queue.cursor.execute(
        """CREATE OR REPLACE FUNCTION pg_temp.count_queue_update_statements()
           RETURNS trigger AS $$
           BEGIN
               PERFORM set_config(
                   'test.queue_update_statements',
                   (current_setting('test.queue_update_statements')::int + 1)::text,
                   false
               );
               RETURN NULL;
           END;
           $$ LANGUAGE plpgsql"""
    )
    queue.cursor.execute(
        """CREATE TRIGGER pull_batch_statement_counter
           AFTER UPDATE ON queue.jobs
           FOR EACH STATEMENT
           EXECUTE FUNCTION pg_temp.count_queue_update_statements()"""
    )

    try:
        jobs = queue.pull_batch("tasks", limit=5)
        updates = queue.cursor.execute(
            "SELECT current_setting('test.queue_update_statements')::int"
        ).fetchone()[0]
    finally:
        queue.cursor.execute("DROP TRIGGER pull_batch_statement_counter ON queue.jobs")

    assert len(jobs) == 5
    assert updates == 1
    assert queue.ack_batch([(job["id"], job["fence_token"]) for job in jobs]) == 5


def test_timeout_candidate_scan_has_an_index_upper_bound(queue):
    """The timeout index condition must exclude future deadlines."""
    queue.cursor.execute(
        """INSERT INTO queue.jobs (
               namespace, queue, payload, status, attempts,
               locked_by, locked_at, visibility_timeout_at, fence_token
           )
           SELECT %s, 'tasks', '{}'::jsonb, 'running', 1,
                  'worker', clock_timestamp(),
                  clock_timestamp() + interval '1 hour' + g * interval '1 second',
                  nextval('queue.fence_token_seq'::regclass)
           FROM generate_series(1, 5000) AS g""",
        (queue.namespace,),
    )
    queue.cursor.execute("ANALYZE queue.jobs")
    cutoff = queue.cursor.execute("SELECT clock_timestamp()").fetchone()[0]

    plan = queue.cursor.execute(
        """EXPLAIN (FORMAT JSON)
           SELECT j.namespace, j.id, j.queue, j.locked_at, j.fence_token
           FROM queue.jobs j
           WHERE j.status = 'running'
             AND j.visibility_timeout_at <= %s
             AND j.namespace = %s
           ORDER BY j.visibility_timeout_at
           LIMIT 100
           FOR UPDATE SKIP LOCKED""",
        (cutoff, queue.namespace),
    ).fetchone()[0][0]["Plan"]

    bounded_scan = any(
        node.get("Index Name") == "jobs_timeout_idx"
        and "visibility_timeout_at" in node.get("Index Cond", "")
        for node in _plan_nodes(plan)
    )
    assert bounded_scan, plan

    definition = queue.cursor.execute(
        "SELECT pg_get_functiondef('queue.tick_timeouts(text,integer)'::regprocedure)"
    ).fetchone()[0]
    assert "v_candidate_cutoff := clock_timestamp();" in definition
    assert "j.visibility_timeout_at <= v_candidate_cutoff" in definition
