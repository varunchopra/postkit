"""assert_rls_active: catch test setups whose role bypasses RLS."""

import pytest
from postkit.authz import AuthzClient, AuthzError, AuthzErrorCode

from tests.helpers import connect_as_rls_user, ensure_rls_role


class TestAssertRlsActive:
    """Raises for bypass roles, passes when RLS applies."""

    def test_raises_for_bypass_role(self, db_connection):
        client = AuthzClient(db_connection.cursor(), "rls_assert")

        with pytest.raises(AuthzError) as exc_info:
            client.assert_rls_active()
        assert exc_info.value.error_code == AuthzErrorCode.BIZ_RLS_NOT_ACTIVE

    def test_passes_for_rls_role(self, db_connection):
        ensure_rls_role(db_connection, "authz")
        conn = connect_as_rls_user(db_connection, "authz")
        try:
            AuthzClient(conn.cursor(), "rls_assert").assert_rls_active()
            conn.rollback()
        finally:
            conn.close()
