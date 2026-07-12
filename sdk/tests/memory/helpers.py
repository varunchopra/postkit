"""Test helpers for memory - direct table access for setup/teardown."""

from tests.helpers import fetch_row


def cleanup_namespace(cursor, namespace: str):
    """Delete all memory data for a namespace, in FK-safe order.

    Edges reference nodes, so they go first. Nodes carry a self-referential
    superseded_by FK, so that pointer is cleared before the node rows are
    deleted.
    """
    cursor.execute("DELETE FROM memory.edges WHERE namespace = %s", (namespace,))
    cursor.execute(
        "UPDATE memory.nodes SET superseded_by = NULL WHERE namespace = %s",
        (namespace,),
    )
    cursor.execute("DELETE FROM memory.nodes WHERE namespace = %s", (namespace,))
    cursor.execute("DELETE FROM memory.episodes WHERE namespace = %s", (namespace,))
    cursor.execute(
        "DELETE FROM memory.consolidations WHERE namespace = %s", (namespace,)
    )
    cursor.execute("DELETE FROM memory.config WHERE namespace = %s", (namespace,))


class MemoryTestHelpers:
    """Direct table access for test setup/teardown that bypasses the SDK.

    Use cases:
    - Exercising M1 immutability with raw UPDATE/DELETE
    - Backdating occurred_at/recorded_at without sleeping
    - Dumping the node/edge graph for invariant comparisons
    """

    def __init__(self, cursor, namespace: str):
        self.cursor = cursor
        self.namespace = namespace
        self.cursor.execute("SELECT memory.set_tenant(%s)", (namespace,))

    # --- raw row access -----------------------------------------------------

    def get_episode(self, episode_id: int) -> dict | None:
        self.cursor.execute(
            "SELECT * FROM memory.episodes WHERE namespace = %s AND id = %s",
            (self.namespace, episode_id),
        )
        return fetch_row(self.cursor)

    def get_node(self, node_id: int) -> dict | None:
        self.cursor.execute(
            "SELECT * FROM memory.nodes WHERE namespace = %s AND id = %s",
            (self.namespace, node_id),
        )
        return fetch_row(self.cursor)

    def count(self, table: str) -> int:
        self.cursor.execute(
            f"SELECT count(*) FROM memory.{table} WHERE namespace = %s",
            (self.namespace,),
        )
        return self.cursor.fetchone()[0]

    def dump_nodes(self) -> list[tuple]:
        """(kind, content) for every node, sorted, for graph equality checks."""
        self.cursor.execute(
            "SELECT kind, content FROM memory.nodes WHERE namespace = %s "
            "ORDER BY kind, content",
            (self.namespace,),
        )
        return self.cursor.fetchall()

    def dump_edges(self) -> list[tuple]:
        """(from_content, to_content, relation) for every edge, sorted."""
        self.cursor.execute(
            """
            SELECT nf.content, nt.content, e.relation
            FROM memory.edges e
            JOIN memory.nodes nf ON nf.namespace = e.namespace AND nf.id = e.from_node
            JOIN memory.nodes nt ON nt.namespace = e.namespace AND nt.id = e.to_node
            WHERE e.namespace = %s
            ORDER BY nf.content, nt.content, e.relation
            """,
            (self.namespace,),
        )
        return self.cursor.fetchall()

    # --- M1 immutability probes --------------------------------------------

    def update_episode_content(self, episode_id: int, content: str) -> None:
        """Direct UPDATE of episode content (M1 forbids this)."""
        self.cursor.execute(
            "UPDATE memory.episodes SET content = %s WHERE namespace = %s AND id = %s",
            (content, self.namespace, episode_id),
        )

    def mark_consolidated(self, episode_id: int) -> None:
        """Direct UPDATE setting consolidated_at (M1 allows this once, from NULL)."""
        self.cursor.execute(
            "UPDATE memory.episodes SET consolidated_at = now() "
            "WHERE namespace = %s AND id = %s",
            (self.namespace, episode_id),
        )

    def delete_episode(self, episode_id: int) -> None:
        """Direct DELETE of an episode (M1 allows this; retention is the deployer's)."""
        self.cursor.execute(
            "DELETE FROM memory.episodes WHERE namespace = %s AND id = %s",
            (self.namespace, episode_id),
        )

    # --- config -------------------------------------------------------------

    def set_config(self, **kwargs) -> None:
        """Upsert this namespace's memory config row with the given columns."""
        cols = list(kwargs.keys())
        vals = list(kwargs.values())
        assignments = ", ".join(f"{c} = EXCLUDED.{c}" for c in cols)
        self.cursor.execute(
            f"INSERT INTO memory.config (namespace, {', '.join(cols)}) "
            f"VALUES (%s, {', '.join(['%s'] * len(cols))}) "
            f"ON CONFLICT (namespace) DO UPDATE SET {assignments}",
            (self.namespace, *vals),
        )
