"""assert_rls_active and the all-namespaces sweep guard for outbox."""

import psycopg
import pytest
from postkit.outbox import OutboxClient, OutboxError, OutboxErrorCode

from tests.helpers import (
    assert_global_row_delete_protected,
    connect_as_rls_user,
    ensure_rls_role,
)

GUARDED_CALLS = [
    "SELECT * FROM outbox.trim(p_older_than := interval '30 days', p_namespace := {ns})",
]


class TestAssertRlsActive:
    """Raises for bypass roles, passes when RLS applies."""

    def test_raises_for_bypass_role(self, db_connection):
        client = OutboxClient(db_connection.cursor(), "rls_assert")

        with pytest.raises(OutboxError) as exc_info:
            client.assert_rls_active()
        assert exc_info.value.error_code == OutboxErrorCode.BIZ_RLS_NOT_ACTIVE

    def test_passes_for_rls_role(self, db_connection):
        ensure_rls_role(db_connection, "outbox")
        conn = connect_as_rls_user(db_connection, "outbox")
        try:
            OutboxClient(conn.cursor(), "rls_assert").assert_rls_active()
            conn.rollback()
        finally:
            conn.close()


class TestAllNamespacesGuard:
    """NULL-namespace sweeps refuse roles subject to RLS."""

    @pytest.fixture
    def rls_conn(self, db_connection):
        ensure_rls_role(db_connection, "outbox")
        conn = connect_as_rls_user(db_connection, "outbox")
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
        OutboxClient(rls_conn.cursor(), "rls_guard")

        rls_conn.execute(call.format(ns="'rls_guard'"))
        rls_conn.rollback()

    def test_null_namespace_sweeps_for_bypass_role(self, db_connection):
        """Superuser NULL trim runs unguarded (30-day cutoff deletes nothing)."""
        db_connection.execute(
            "SELECT * FROM outbox.trim(p_older_than := interval '30 days',"
            " p_namespace := NULL)"
        )


def test_global_config_row_delete_protected(db_connection):
    assert_global_row_delete_protected(db_connection, "outbox", "outbox.config")
