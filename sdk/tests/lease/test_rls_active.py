"""assert_rls_active: catch test setups whose role bypasses RLS."""

import pytest
from postkit.lease import LeaseClient, LeaseError, LeaseErrorCode

from tests.helpers import (
    assert_global_row_delete_protected,
    connect_as_rls_user,
    ensure_rls_role,
)


class TestAssertRlsActive:
    """Raises for bypass roles, passes when RLS applies."""

    def test_raises_for_bypass_role(self, db_connection):
        client = LeaseClient(db_connection.cursor(), "rls_assert")

        with pytest.raises(LeaseError) as exc_info:
            client.assert_rls_active()
        assert exc_info.value.error_code == LeaseErrorCode.BIZ_RLS_NOT_ACTIVE

    def test_passes_for_rls_role(self, db_connection):
        ensure_rls_role(db_connection, "lease")
        conn = connect_as_rls_user(db_connection, "lease")
        try:
            LeaseClient(conn.cursor(), "rls_assert").assert_rls_active()
            conn.rollback()
        finally:
            conn.close()


def test_global_config_row_delete_protected(db_connection):
    assert_global_row_delete_protected(db_connection, "lease", "lease.config")
