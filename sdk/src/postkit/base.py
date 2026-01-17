"""Base client for postkit modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Callable, NoReturn, TypeVar
from uuid import UUID

import psycopg
from psycopg.rows import dict_row, kwargs_row

T = TypeVar("T")

# Known row factories that return dict-like objects (iteration yields keys, not values)
_DICT_LIKE_FACTORIES = frozenset({dict_row, kwargs_row})

# SQLSTATE to exception class mapping
# Reference: https://www.postgresql.org/docs/current/errcodes-appendix.html
_SQLSTATE_EXCEPTIONS: dict[
    str, type[PostkitError]
] = {}  # Populated after class definitions


class PostkitError(Exception):
    """Base exception for postkit operations."""

    def __init__(self, message: str, sqlstate: str | None = None):
        super().__init__(message)
        self.sqlstate = sqlstate


class UniqueViolationError(PostkitError):
    """Raised when a unique constraint is violated (e.g., duplicate email)."""

    pass


class ForeignKeyViolationError(PostkitError):
    """Raised when a foreign key constraint is violated."""

    pass


class CheckViolationError(PostkitError):
    """Raised when a check constraint is violated (e.g., invalid format)."""

    pass


# Populate SQLSTATE mapping after classes are defined
_SQLSTATE_EXCEPTIONS.update(
    {
        "23505": UniqueViolationError,  # unique_violation
        "23503": ForeignKeyViolationError,  # foreign_key_violation
        "23514": CheckViolationError,  # check_violation
    }
)


class BaseClient(ABC):
    """Abstract base class for postkit clients.

    Provides shared functionality:
    - Database helper methods (fetch_val, fetch_one, fetch_all)
    - Error handling with SQLSTATE preservation
    - Tenant context (RLS)
    - Actor context for audit logging

    Subclasses must define:
    - _schema: The PostgreSQL schema name ("authn", "authz", "config", "meter")
    - _error_class: The exception class to raise on errors
    - _apply_actor_context(): How to apply actor context via SQL
    """

    _schema: str  # Must be a valid SQL identifier
    _error_class: type[PostkitError] = PostkitError

    def __init__(self, cursor: psycopg.Cursor[tuple[Any, ...]], namespace: str) -> None:
        """Initialize the client.

        Args:
            cursor: A psycopg3 cursor with default (tuple) row factory.
                Do NOT use row_factory=dict_row - the SDK returns dicts automatically.
            namespace: Tenant namespace for multi-tenancy

        Raises:
            ValueError: If cursor has a dict-returning row factory, or schema is invalid.
        """
        # Validate schema name is a safe identifier
        if not self._schema.isidentifier():
            raise ValueError(f"Invalid schema name: {self._schema}")

        # Check against known dict-returning factories by identity
        if (
            hasattr(cursor, "row_factory")
            and cursor.row_factory in _DICT_LIKE_FACTORIES
        ):
            raise ValueError(
                "postkit requires tuple row factory (the default). "
                "Remove row_factory=dict_row or kwargs_row from your cursor/connection. "
                "The SDK returns dicts automatically by combining column names with tuple values."
            )

        self.cursor = cursor
        self.namespace = namespace
        # Core actor context fields (shared by all clients)
        self._actor_id: str | None = None
        self._request_id: str | None = None
        self._on_behalf_of: str | None = None
        self._reason: str | None = None
        # Set tenant context for RLS
        try:
            self.cursor.execute(f"SELECT {self._schema}.set_tenant(%s)", (namespace,))
        except psycopg.Error as e:
            self._handle_error(e)

    def _handle_error(self, e: psycopg.Error) -> NoReturn:
        """Convert psycopg errors to SDK exceptions, preserving SQLSTATE.

        Uses specific exception subclasses for common database errors
        (unique violation, foreign key violation, etc.) to enable
        precise error handling by callers.
        """
        sqlstate = getattr(e, "sqlstate", None)
        message = str(e)

        # Use specific exception class if we have one for this SQLSTATE
        exc_class = _SQLSTATE_EXCEPTIONS.get(sqlstate, self._error_class)

        raise exc_class(message, sqlstate) from e

    def _normalize_value(self, value: Any) -> Any:
        """Normalize database values to Python types."""
        if isinstance(value, Decimal):
            return float(value)
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, (IPv4Address, IPv6Address)):
            return str(value)
        return value

    @abstractmethod
    def _apply_actor_context(self) -> None:
        """Apply actor context via schema-specific SQL.

        Subclasses implement this to call their schema's set_actor() function
        with the appropriate parameters.
        """
        ...

    def _has_context(self) -> bool:
        """Check if any context field is set."""
        return bool(
            self._actor_id or self._request_id or self._on_behalf_of or self._reason
        )

    def _with_actor(self, executor: Callable[[], T]) -> T:
        """Execute operation with actor context for audit logging.

        Actor context uses PostgreSQL's transaction-local settings (SET LOCAL).
        This requires a transaction to persist between setting context and executing.

        - In autocommit mode: We wrap in an explicit transaction
        - In manual transaction mode: Caller controls the transaction

        Note: This method assumes single-threaded cursor access.
        psycopg cursors are not thread-safe; do not share clients across threads.

        Args:
            executor: Callable that performs the actual SQL execution and returns result
        """
        if not self._has_context():
            return executor()

        conn = self.cursor.connection
        in_transaction = conn.info.transaction_status != 0

        if in_transaction:
            # Caller manages transaction - just set actor context
            self._apply_actor_context()
            return executor()
        else:
            # Use psycopg's transaction manager for proper cleanup
            with conn.transaction():
                self._apply_actor_context()
                return executor()

    def _fetch_val(
        self, sql: str, params: tuple[Any, ...], *, write: bool = False
    ) -> Any | None:
        """Execute SQL and return single value from first row.

        Args:
            sql: SQL query to execute
            params: Query parameters
            write: If True, applies actor context for audit logging

        Returns:
            First column of first row, or None if no rows
        """

        def execute() -> Any | None:
            try:
                self.cursor.execute(sql, params)
                row = self.cursor.fetchone()
                return self._normalize_value(row[0]) if row else None
            except psycopg.Error as e:
                self._handle_error(e)

        return self._with_actor(execute) if write else execute()

    def _fetch_one(
        self, sql: str, params: tuple[Any, ...], *, write: bool = False
    ) -> dict[str, Any] | None:
        """Execute SQL and return single row as dict.

        Args:
            sql: SQL query to execute
            params: Query parameters
            write: If True, applies actor context for audit logging

        Returns:
            Row as dict with column names as keys, or None if no rows
        """

        def execute() -> dict[str, Any] | None:
            try:
                self.cursor.execute(sql, params)
                row = self.cursor.fetchone()
                if row is None:
                    return None
                columns = [desc[0] for desc in self.cursor.description]
                return {
                    col: self._normalize_value(val) for col, val in zip(columns, row)
                }
            except psycopg.Error as e:
                self._handle_error(e)

        return self._with_actor(execute) if write else execute()

    def _fetch_all(
        self, sql: str, params: tuple[Any, ...], *, write: bool = False
    ) -> list[dict[str, Any]]:
        """Execute SQL and return all rows as list of dicts.

        Args:
            sql: SQL query to execute
            params: Query parameters
            write: If True, applies actor context for audit logging

        Returns:
            List of rows, each as dict with column names as keys
        """

        def execute() -> list[dict[str, Any]]:
            try:
                self.cursor.execute(sql, params)
                columns = [desc[0] for desc in self.cursor.description]
                rows = self.cursor.fetchall()

                # Defensive runtime check for dict-like rows
                if rows and isinstance(rows[0], dict):
                    raise self._error_class(
                        "Cursor returned dict rows. postkit requires tuple row factory. "
                        "The SDK builds dicts internally from tuple rows.",
                        sqlstate=None,
                    )

                return [
                    {col: self._normalize_value(val) for col, val in zip(columns, row)}
                    for row in rows
                ]
            except psycopg.Error as e:
                self._handle_error(e)

        return self._with_actor(execute) if write else execute()

    def _fetch_raw(self, sql: str, params: tuple[Any, ...]) -> list[tuple[Any, ...]]:
        """Execute SQL and return all rows as raw tuples.

        Use this for special cases where you need raw tuple access
        (e.g., single-column results as list[str], or combining columns into tuples).

        Args:
            sql: SQL query to execute
            params: Query parameters

        Returns:
            List of rows as tuples
        """
        try:
            self.cursor.execute(sql, params)
            return self.cursor.fetchall()
        except psycopg.Error as e:
            self._handle_error(e)

    def set_actor(
        self,
        actor_id: str | None = None,
        request_id: str | None = None,
        on_behalf_of: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Set actor context for audit logging. Only updates fields that are passed.

        Args:
            actor_id: The actor making changes (e.g., 'user:alice', 'service:billing')
            request_id: Request/correlation ID for tracing
            on_behalf_of: Principal being represented (e.g., 'user:customer')
            reason: Reason for the action (e.g., 'support_ticket:123')

        Example:
            client.clear_actor()
            client.set_actor(request_id="req-123")  # Set request context first
            client.set_actor(actor_id="user:alice")  # Add actor after auth
        """
        if actor_id is not None:
            self._actor_id = actor_id
        if request_id is not None:
            self._request_id = request_id
        if on_behalf_of is not None:
            self._on_behalf_of = on_behalf_of
        if reason is not None:
            self._reason = reason

    def clear_actor(self) -> None:
        """Clear actor context."""
        self._actor_id = None
        self._request_id = None
        self._on_behalf_of = None
        self._reason = None

    def _get_audit_events(
        self,
        limit: int = 100,
        event_type: str | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Internal helper for audit event queries.

        Subclasses should define their own public get_audit_events() with
        explicit parameters and call this helper.

        Args:
            limit: Maximum number of events to return
            event_type: Filter by event type
            filters: Pre-validated column:value pairs (keys MUST be safe identifiers)

        Returns:
            List of audit event dictionaries
        """
        conditions = ["namespace = %s"]
        params: list[Any] = [self.namespace]

        if event_type is not None:
            conditions.append("event_type = %s")
            params.append(event_type)

        if filters:
            for col, val in filters.items():
                if val is not None:
                    # Defense-in-depth: validate column name is safe identifier
                    if not col.isidentifier():
                        raise ValueError(f"Invalid column name: {col}")
                    conditions.append(f"{col} = %s")
                    params.append(val)

        params.append(limit)

        sql = f"""
            SELECT *
            FROM {self._schema}.audit_events
            WHERE {" AND ".join(conditions)}
            ORDER BY event_time DESC, id DESC
            LIMIT %s
        """

        return self._fetch_all(sql, tuple(params))

    def get_audit_events(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        """Query audit events. Subclasses must override with explicit parameters."""
        raise NotImplementedError(
            f"{self.__class__.__name__} must override get_audit_events() with explicit parameters"
        )

    def get_stats(self) -> dict:
        """Get namespace statistics. Subclasses should override with module-specific stats."""
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement get_stats()"
        )
