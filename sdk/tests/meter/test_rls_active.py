"""assert_rls_active and the all-namespaces sweep guard for meter."""

import psycopg
import pytest
from postkit.meter import MeterClient, MeterError, MeterErrorCode
from tests.helpers import connect_as_rls_user, ensure_rls_role

GUARDED_CALLS = [
    "SELECT meter.release_expired_reservations(p_namespace := {ns})",
]


class TestAssertRlsActive:
    """Raises for bypass roles, passes when RLS applies."""

    def test_raises_for_bypass_role(self, db_connection):
        client = MeterClient(db_connection.cursor(), "rls_assert")

        with pytest.raises(MeterError) as exc_info:
            client.assert_rls_active()
        assert exc_info.value.error_code == MeterErrorCode.BIZ_RLS_NOT_ACTIVE

    def test_passes_for_rls_role(self, db_connection):
        ensure_rls_role(db_connection, "meter")
        conn = connect_as_rls_user(db_connection, "meter")
        try:
            MeterClient(conn.cursor(), "rls_assert").assert_rls_active()
            conn.rollback()
        finally:
            conn.close()


class TestAllNamespacesGuard:
    """NULL-namespace sweeps refuse roles subject to RLS."""

    @pytest.fixture
    def rls_conn(self, db_connection):
        ensure_rls_role(db_connection, "meter")
        conn = connect_as_rls_user(db_connection, "meter")
        yield conn
        conn.close()

    @pytest.mark.parametrize("call", GUARDED_CALLS)
    def test_null_namespace_raises_without_bypass(self, rls_conn, call):
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc_info:
            rls_conn.execute(call.format(ns="NULL"))
        assert "BIZ_ALL_NAMESPACES_REQUIRES_BYPASS" in exc_info.value.diag.message_hint
        rls_conn.rollback()

    @pytest.mark.parametrize("call", GUARDED_CALLS)
    def test_explicit_namespace_works_without_bypass(self, rls_conn, call):
        MeterClient(rls_conn.cursor(), "rls_guard")

        rls_conn.execute(call.format(ns="'rls_guard'"))
        rls_conn.rollback()
