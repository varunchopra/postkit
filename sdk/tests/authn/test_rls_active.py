"""assert_rls_active: catch test setups whose role bypasses RLS."""

import pytest
from postkit.authn import AuthnClient, AuthnError, AuthnErrorCode

from tests.helpers import connect_as_rls_user, ensure_rls_role


class TestAssertRlsActive:
    """Raises for bypass roles, passes when RLS applies."""

    def test_raises_for_bypass_role(self, db_connection):
        client = AuthnClient(db_connection.cursor(), "rls_assert")

        with pytest.raises(AuthnError) as exc_info:
            client.assert_rls_active()
        assert exc_info.value.error_code == AuthnErrorCode.BIZ_RLS_NOT_ACTIVE

    def test_passes_for_rls_role(self, db_connection):
        ensure_rls_role(db_connection, "authn")
        conn = connect_as_rls_user(db_connection, "authn")
        try:
            AuthnClient(conn.cursor(), "rls_assert").assert_rls_active()
            conn.rollback()
        finally:
            conn.close()
