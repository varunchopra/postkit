"""set_dimension(): the one-time DDL that fixes embedding dimension.

set_dimension is database-global, so each case runs against a freshly created
throwaway database rather than the shared suite schema. That isolation is what
lets these tests exercise the unset state and the one-way transition without
disturbing the rest of the memory suite.
"""

from pathlib import Path

import psycopg
import pytest
from postkit.memory import MemoryClient, MemoryError, MemoryErrorCode

from tests.conftest import DATABASE_URL
from tests.helpers import require_pgvector

_DIST_SQL = Path(__file__).resolve().parents[3] / "dist" / "memory.sql"
_DIM_DB = "postkit_mem_dim_test"


@pytest.fixture
def dim_client():
    """A MemoryClient on a fresh database with the memory schema, dimension unset."""
    require_pgvector()
    if not _DIST_SQL.exists():
        pytest.fail("dist/memory.sql not found. Run 'make build' first.")

    admin = psycopg.connect(DATABASE_URL, autocommit=True)
    admin.execute(f"DROP DATABASE IF EXISTS {_DIM_DB} WITH (FORCE)")
    admin.execute(f"CREATE DATABASE {_DIM_DB}")

    info = admin.info
    work = psycopg.connect(
        host=info.host,
        port=info.port,
        dbname=_DIM_DB,
        user=info.user,
        password=info.password,
        autocommit=True,
    )
    work.execute(_DIST_SQL.read_text())
    client = MemoryClient(work.cursor(), "dim")

    yield client

    work.close()
    admin.execute(f"DROP DATABASE IF EXISTS {_DIM_DB} WITH (FORCE)")
    admin.close()


class TestSetDimension:
    @pytest.mark.parametrize("dim", [0, -1, 16001])
    def test_invalid_dimension_rejected(self, dim_client, dim):
        with pytest.raises(MemoryError) as exc_info:
            dim_client.set_dimension(dim)
        assert exc_info.value.error_code == MemoryErrorCode.VAL_DIMENSION_INVALID

    def test_keyword_recall_works_before_dimension_set(self, dim_client):
        dim_client.record("s1", "user", "unset dim keyword", keywords=["keyword"])
        hits = dim_client.recall(keywords=["keyword"])
        assert any(h["content"] == "unset dim keyword" for h in hits)

    def test_set_then_vector_recall_works(self, dim_client):
        dim_client.set_dimension(4)
        dim_client.record("s1", "user", "vec", embedding=[1, 0, 0, 0], embed_model="m")
        hits = dim_client.recall(query_embedding=[1, 0, 0, 0])
        assert any(h["content"] == "vec" for h in hits)
        assert dim_client.get_stats()["embedding_dim"] == 4

    def test_same_dimension_is_noop(self, dim_client):
        dim_client.set_dimension(4)
        dim_client.set_dimension(4)  # no error
        assert dim_client.get_stats()["embedding_dim"] == 4

    def test_different_dimension_rejected(self, dim_client):
        dim_client.set_dimension(4)
        with pytest.raises(MemoryError) as exc_info:
            dim_client.set_dimension(8)
        assert exc_info.value.error_code == MemoryErrorCode.BIZ_DIMENSION_ALREADY_SET

    def test_preexisting_wrong_dim_row_blocks_set(self, dim_client):
        # A 3-dim embedding is accepted while the dimension is unset.
        dim_client.record(
            "s1", "user", "three dims", embedding=[1, 0, 0], embed_model="m"
        )
        with pytest.raises(MemoryError) as exc_info:
            dim_client.set_dimension(4)
        assert exc_info.value.error_code == MemoryErrorCode.BIZ_DIMENSION_MISMATCH

    def test_wrong_dim_row_in_another_namespace_blocks_set(self, dim_client):
        # The offending row lives outside the caller's tenant context, where
        # row-level security hides it from ordinary reads.
        other = MemoryClient(dim_client.cursor, "dimother")
        other.record("s1", "user", "three dims", embedding=[1, 0, 0], embed_model="m")
        with pytest.raises(MemoryError) as exc_info:
            dim_client.set_dimension(4)
        assert exc_info.value.error_code == MemoryErrorCode.BIZ_DIMENSION_MISMATCH

    def test_wrong_dim_record_after_set_rejected(self, dim_client):
        dim_client.set_dimension(4)
        with pytest.raises(MemoryError) as exc_info:
            dim_client.record("s1", "user", "bad", embedding=[1, 0, 0], embed_model="m")
        assert (
            exc_info.value.error_code
            == MemoryErrorCode.BIZ_EMBEDDING_DIMENSION_MISMATCH
        )
