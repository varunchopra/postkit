"""Hot-path account lookups stay off sequential scans.

The balance-write and balance-read functions key an account by
(namespace, user_id, event_type, resource, unit). Writing the user_id match as
`IS NOT DISTINCT FROM` is not index-sargable and silently degrades every such
lookup to a full scan of meter.accounts. This is the automated form of the
EXPLAIN-verify convention: it seeds a realistically sized namespace and asserts
the point lookup the functions issue is served by an index, not a Seq Scan.
"""


def _seq_scanned_relations(node: dict) -> set[str]:
    """Relation names reached through a Seq Scan anywhere in a plan tree."""
    found = set()
    if node.get("Node Type") == "Seq Scan":
        found.add(node.get("Relation Name"))
    for child in node.get("Plans", []):
        found |= _seq_scanned_relations(child)
    return found


def _plan(cursor, sql: str, params: tuple) -> dict:
    cursor.execute("EXPLAIN (FORMAT JSON) " + sql, params)
    return cursor.fetchone()[0][0]["Plan"]


# Mirrors the (namespace, user_id, event_type, resource, unit) predicate the
# balance functions use, NULL-safe on user_id so it covers pool rows too.
_POINT_LOOKUP = (
    "SELECT balance FROM meter.accounts "
    "WHERE namespace = %s "
    "AND (user_id = %s OR (user_id IS NULL AND %s::text IS NULL)) "
    "AND event_type = 'llm_call' AND resource = 'claude' AND unit = 'tokens'"
)


class TestAccountLookupPlans:
    def _seed(self, meter, n: int = 2000) -> None:
        # Enough per-user rows sharing one meter that a Seq Scan would be the
        # planner's choice iff the predicate cannot use an index.
        meter.cursor.execute(
            "INSERT INTO meter.accounts "
            "(namespace, user_id, event_type, resource, unit, balance) "
            "SELECT %s, 'u' || g, 'llm_call', 'claude', 'tokens', 1000 "
            "FROM generate_series(1, %s) g",
            (meter.namespace, n),
        )
        meter.cursor.execute(
            "INSERT INTO meter.accounts "
            "(namespace, user_id, event_type, resource, unit, balance) "
            "VALUES (%s, NULL, 'llm_call', 'claude', 'tokens', 1000)",
            (meter.namespace,),
        )
        meter.cursor.execute("ANALYZE meter.accounts")

    def test_per_user_point_lookup_is_index_served(self, meter):
        self._seed(meter)
        plan = _plan(meter.cursor, _POINT_LOOKUP, (meter.namespace, "u1000", "u1000"))
        assert "accounts" not in _seq_scanned_relations(plan)

    def test_pool_point_lookup_is_index_served(self, meter):
        self._seed(meter)
        plan = _plan(meter.cursor, _POINT_LOOKUP, (meter.namespace, None, None))
        assert "accounts" not in _seq_scanned_relations(plan)
