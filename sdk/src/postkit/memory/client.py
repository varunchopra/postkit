"""Postkit Memory SDK - durable agent memory in Postgres (pgvector)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Sequence

import psycopg
from psycopg.abc import Buffer
from psycopg.adapt import Loader
from psycopg.types import TypeInfo

from postkit.base import BaseClient, PostkitError


class _VectorLoader(Loader):
    """Load pgvector values as plain list[float].

    pgvector's text form is a JSON array (`[0.1,0.2,...]`), so json.loads
    parses it directly into a list.
    """

    def load(self, data: Buffer) -> list[float]:
        return json.loads(bytes(data))


class MemoryError(PostkitError):
    """Exception for memory operations."""


class MemoryValidationError(MemoryError):
    """Raised when input validation fails."""


class MemoryClient(BaseClient):
    """Client for Postkit memory module.

    Durable agent memory: an append-only episode log, distilled facts and
    entities above it, and typed edges between them. record() appends one
    episode; recall() finds relevant memories by embedding, keywords, and graph
    expansion; consolidate() applies an LLM distillation batch. Embeddings are
    produced by the caller's model and passed in; the module stores and indexes
    them. Requires the pgvector extension.

    Example:
        memory = MemoryClient(cursor, namespace="acme")

        memory.set_dimension(1536)  # once, after install
        memory.record("session-1", "user", "my apartment has hard water",
                       embedding=embed(text), embed_model="text-embedding-3-small",
                       keywords=["apartment", "water"])
        hits = memory.recall(query_embedding=embed(query), keywords=["water"])
    """

    _schema = "memory"
    _error_class = MemoryError
    _module_sqlstate_map = {
        "22023": MemoryValidationError,  # invalid_parameter_value
        "22004": MemoryValidationError,  # null_value_not_allowed
        "22001": MemoryValidationError,  # string_data_right_truncation
        "22026": MemoryValidationError,  # string_data_length_mismatch
    }

    def __init__(self, cursor: psycopg.Cursor, namespace: str) -> None:
        super().__init__(cursor, namespace)
        # vector is a pgvector extension type, so its OID is not in psycopg's
        # static registry the way a builtin like xid8 is; it must be fetched
        # from the catalog. Clients are built per request, so the fetched type
        # is kept in the connection's type registry and the catalog round-trip
        # is paid once per connection, not once per client.
        conn = cursor.connection
        if conn.adapters.types.get("vector") is None:
            info = TypeInfo.fetch(conn, "vector")
            if info is not None:
                info.register(conn)
                conn.adapters.register_loader(info.oid, _VectorLoader)

    def _apply_actor_context(self) -> None:
        self.cursor.execute(
            """SELECT memory.set_actor(
                p_actor_id := %s,
                p_request_id := %s,
                p_on_behalf_of := %s,
                p_reason := %s
            )""",
            (self._actor_id, self._request_id, self._on_behalf_of, self._reason),
        )

    @staticmethod
    def _vec(v: Sequence[float] | None) -> str | None:
        """Serialize an embedding to the pgvector text literal, or None."""
        if v is None:
            return None
        return "[" + ",".join(repr(float(x)) for x in v) + "]"

    def record(
        self,
        session: str,
        role: str,
        content: str,
        *,
        embedding: Sequence[float] | None = None,
        embed_model: str | None = None,
        keywords: Sequence[str] | None = None,
        occurred_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Append one episode to the interaction log.

        The insert is the hot path and touches no other table. Embedding and
        its model travel together or not at all.

        Args:
            session: Session identifier the episode belongs to
            role: Message role (e.g. 'user', 'assistant', 'tool')
            content: Raw message or event text
            embedding: Optional embedding of the content
            embed_model: Model that produced the embedding (required iff embedding is given)
            keywords: Optional keywords for the lexical recall arm
            occurred_at: When the episode happened (defaults to now())
            metadata: Optional JSON metadata

        Returns:
            The new episode id

        Example:
            memory.record("s1", "user", "hello", keywords=["hello"])
        """
        result = self._fetch_val(
            """SELECT memory.record(
                p_namespace := %s,
                p_session := %s,
                p_role := %s,
                p_content := %s,
                p_embedding := %s::vector,
                p_embed_model := %s,
                p_keywords := %s,
                p_occurred_at := %s,
                p_metadata := %s::jsonb
            )""",
            (
                self.namespace,
                session,
                role,
                content,
                self._vec(embedding),
                embed_model,
                list(keywords) if keywords is not None else None,
                occurred_at,
                json.dumps(metadata) if metadata is not None else None,
            ),
            write=True,
        )
        if result is None:
            raise MemoryError("memory.record returned no value")
        return int(result)

    def recall(
        self,
        *,
        query_embedding: Sequence[float] | None = None,
        keywords: Sequence[str] | None = None,
        k: int = 12,
        hops: int | None = None,
    ) -> list[dict[str, Any]]:
        """Find memories relevant to a query by meaning, keywords, and connection.

        Read-only. Entry points are fused from a vector arm (cosine over
        embeddings) and a lexical arm (full-text ranking over keywords), then
        node entry points expand over stored edges up to the effective hop
        depth. At least one of query_embedding or keywords must be given.

        Args:
            query_embedding: Optional query embedding for the vector arm
            keywords: Optional keywords for the lexical arm
            k: Maximum rows to return (positive)
            hops: Expansion depth (defaults to and capped by config.recall_max_hops)

        Returns:
            Scored rows, each a dict with source ('episode'|'node'), id, kind,
            content, score, hops, and occurred_at, highest score first

        Example:
            hits = memory.recall(keywords=["water"])
        """
        return self._fetch_all(
            "SELECT * FROM memory.recall(%s, %s::vector, %s, %s, %s)",
            (
                self.namespace,
                self._vec(query_embedding),
                list(keywords) if keywords is not None else None,
                k,
                hops,
            ),
        )

    def neighbors(
        self, node: int, *, relation: str | None = None
    ) -> list[dict[str, Any]]:
        """Return the nodes one edge away from a node, in either direction.

        Args:
            node: Node whose neighbors to list
            relation: Optional relation filter ('entity', 'causal', 'assoc')

        Returns:
            One dict per neighbor: node_id, relation, weight, direction
            ('out'|'in'), kind, content

        Raises:
            MemoryError: The node does not exist or is not visible
                (error_code DATA_NODE_NOT_FOUND)
        """
        return self._fetch_all(
            "SELECT * FROM memory.neighbors(%s, %s, %s)",
            (self.namespace, node, relation),
        )

    def consolidation_due(
        self, *, batch_size: int | None = None
    ) -> list[dict[str, Any]]:
        """Surface unconsolidated episodes for a distillation worker.

        Read-only. Claiming and serialization are the worker's job (hold a lease,
        heartbeat through presence); this only reports what is due.

        Args:
            batch_size: Maximum episodes to return (defaults to config)

        Returns:
            One dict per due episode: id, session_id, role, content, occurred_at,
            oldest first
        """
        return self._fetch_all(
            "SELECT * FROM memory.consolidation_due(%s, %s)",
            (self.namespace, batch_size),
        )

    def consolidate(
        self,
        facts: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        source_episodes: Sequence[int],
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Apply a distillation batch in one transaction.

        Inserts facts and entities (entities dedup by content), links edges, and
        marks the source episodes consolidated. Fact elements carry content,
        optional kind ('fact'|'entity'), embedding/embed_model, confidence,
        valid_from/valid_until, and evidence. Edge elements reference endpoints
        by node id or "n<i>" (the i-th fact, 0-based) and a relation.

        Args:
            facts: Fact elements to insert
            edges: Edge elements to link
            source_episodes: Episode ids the batch was distilled from
            idempotency_key: Optional replay key; a repeat with the same key is a
                no-op and returns skipped=True

        Returns:
            Dict with node_ids (inserted or matched, in fact order) and skipped

        Example:
            memory.consolidate(
                [{"content": "User's apartment has hard water"}],
                [],
                source_episodes=[1, 2],
                idempotency_key="job-42",
            )
        """
        result = self._fetch_one(
            "SELECT * FROM memory.consolidate(%s, %s::jsonb, %s::jsonb, %s, %s)",
            (
                self.namespace,
                json.dumps(facts),
                json.dumps(edges),
                list(source_episodes),
                idempotency_key,
            ),
            write=True,
        )
        if result is None:
            raise MemoryError("memory.consolidate returned no row")
        return result

    def supersede(self, node: int, replacement: int) -> None:
        """Replace a node with a newer one, keeping the old for history.

        Args:
            node: Node being superseded
            replacement: Node that replaces it

        Raises:
            MemoryError: node equals replacement (BIZ_SUPERSEDE_SELF), the node
                is already superseded (BIZ_ALREADY_SUPERSEDED), the replacement
                is itself invalidated (BIZ_REPLACEMENT_INVALIDATED), or either
                node is missing (DATA_NODE_NOT_FOUND)
        """
        self._fetch_val(
            "SELECT memory.supersede(%s, %s, %s)",
            (self.namespace, node, replacement),
            write=True,
        )

    def set_dimension(self, dim: int) -> None:
        """Fix the embedding dimension and build the vector search indexes.

        A deployment-level, one-time DDL step run after install by a role that
        owns the tables. Setting the same dimension again is a no-op; a different
        one after it is fixed raises BIZ_DIMENSION_ALREADY_SET.

        Args:
            dim: Embedding dimension (1-16000)
        """
        self._fetch_val("SELECT memory.set_dimension(%s)", (dim,), write=True)

    def get_stats(self) -> dict[str, Any]:
        """Namespace-wide memory counts.

        Returns:
            Dict with total_episodes, unconsolidated_episodes, total_nodes,
            live_nodes, total_edges, embedding_dim
        """
        result = self._fetch_one(
            "SELECT * FROM memory.get_stats(%s)", (self.namespace,)
        )
        return result or {}

    def list_episodes(
        self,
        *,
        session: str | None = None,
        limit: int = 100,
        before: str | None = None,
    ) -> list[dict[str, Any]]:
        """List episodes newest first, with cursor pagination.

        Args:
            session: Optional session filter
            limit: Maximum rows to return
            before: Opaque cursor from a previous row's ['cursor'] for the next page

        Returns:
            Episode dicts (embedding omitted); each carries a 'cursor' field to
            pass back as before
        """
        before_at, before_id = (None, None)
        if before is not None:
            before_at, before_id = self._decode_cursor(before)

        rows = self._fetch_all(
            "SELECT * FROM memory.list_episodes(%s, %s, %s, %s, %s)",
            (self.namespace, session, limit, before_at, before_id),
        )
        for row in rows:
            row["cursor"] = self._encode_cursor(row["occurred_at"], row["id"])
        return rows

    def list_nodes(
        self,
        *,
        kind: str | None = None,
        include_superseded: bool = False,
        limit: int = 100,
        before: str | None = None,
    ) -> list[dict[str, Any]]:
        """List nodes newest first, with cursor pagination.

        Args:
            kind: Optional kind filter ('fact' or 'entity')
            include_superseded: Include invalidated/superseded nodes (default False)
            limit: Maximum rows to return
            before: Opaque cursor from a previous row's ['cursor'] for the next page

        Returns:
            Node dicts (embedding omitted); each carries a 'cursor' field to pass
            back as before
        """
        before_at, before_id = (None, None)
        if before is not None:
            before_at, before_id = self._decode_cursor(before)

        rows = self._fetch_all(
            "SELECT * FROM memory.list_nodes(%s, %s, %s, %s, %s, %s)",
            (self.namespace, kind, include_superseded, limit, before_at, before_id),
        )
        for row in rows:
            row["cursor"] = self._encode_cursor(row["recorded_at"], row["id"])
        return rows

    def get_node(self, node_id: int) -> dict[str, Any]:
        """Fetch a single node including its evidence episode ids.

        Args:
            node_id: Node id

        Returns:
            The node dict (embedding omitted)

        Raises:
            MemoryError: The node does not exist (DATA_NODE_NOT_FOUND)
        """
        result = self._fetch_one(
            "SELECT * FROM memory.get_node(%s, %s)", (self.namespace, node_id)
        )
        if result is None:
            raise MemoryError("memory.get_node returned no row")
        return result
