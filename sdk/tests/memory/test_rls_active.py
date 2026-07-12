"""assert_rls_active: catch test setups whose role bypasses RLS."""

import pytest
from postkit.memory import MemoryClient, MemoryError, MemoryErrorCode

from tests.helpers import connect_as_rls_user, ensure_rls_role


class TestAssertRlsActive:
    """Raises for bypass roles, passes when RLS applies."""

    def test_raises_for_bypass_role(self, db_connection):
        client = MemoryClient(db_connection.cursor(), "rls_assert")

        with pytest.raises(MemoryError) as exc_info:
            client.assert_rls_active()
        assert exc_info.value.error_code == MemoryErrorCode.BIZ_RLS_NOT_ACTIVE

    def test_passes_for_rls_role(self, db_connection):
        ensure_rls_role(db_connection, "memory")
        conn = connect_as_rls_user(db_connection, "memory")
        try:
            MemoryClient(conn.cursor(), "rls_assert").assert_rls_active()
            conn.rollback()
        finally:
            conn.close()
