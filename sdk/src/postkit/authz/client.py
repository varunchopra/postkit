"""
postkit.authz - Authorization client for PostgreSQL-native ReBAC.

This module provides:
- AuthzClient: SDK-style interface for authorization operations
- Exception classes: AuthzError, AuthzValidationError, AuthzCycleError
- Type aliases: Entity tuple type
"""

from __future__ import annotations

from datetime import datetime, timedelta

from postkit.base import BaseClient, PostkitError

__all__ = [
    "AuthzClient",
    "AuthzError",
    "AuthzValidationError",
    "AuthzCycleError",
    "Entity",
]


# Type alias for resource/subject tuples
Entity = tuple[str, str]  # (type, id) e.g., ("repo", "payments-api")


class AuthzError(PostkitError):
    """Base exception for authz operations."""


class AuthzValidationError(AuthzError):
    """Raised when input validation fails."""


class AuthzCycleError(AuthzError):
    """Raised when a hierarchy cycle is detected."""


class AuthzClient(BaseClient):
    """
    SDK-style client for postkit/authz.

    This is the interface customers would use. It wraps the SQL functions
    with a Pythonic API using named parameters and tuple-based entities.

    Example:
        authz = AuthzClient(cursor, namespace="production")

        # Set actor context for audit logging
        authz.set_actor("admin@acme.com", "req-123", reason="Quarterly review")

        # Grant permission (actor context automatically included in audit)
        authz.grant("admin", resource=("repo", "api"), subject=("team", "eng"))

        # Check permission
        if authz.check(("user", "alice"), "read", ("repo", "api")):
            allow_access()
    """

    _schema = "authz"
    _error_class = AuthzError
    _module_sqlstate_map = {
        "22023": AuthzValidationError,  # invalid_parameter_value
        "22004": AuthzValidationError,  # null_value_not_allowed
        "22001": AuthzValidationError,  # string_data_right_truncation
        "22026": AuthzValidationError,  # string_data_length_mismatch
        "PK001": AuthzCycleError,  # postkit cycle error
    }

    def __init__(self, cursor, namespace: str):
        super().__init__(cursor, namespace)
        self._viewer: Entity | None = None

    def set_viewer(self, subject: Entity) -> None:
        """
        Set the viewer context for cross-namespace queries.

        This enables the recipient_visibility RLS policy, allowing subjects
        to see grants where they are the recipient across ALL namespaces.
        Required for "Shared with me" / external resources functionality.

        Args:
            subject: The subject as (type, id) tuple (e.g., ("user", "alice"))

        Example:
            authz.set_viewer(("user", "alice"))
            # Now queries can see grants TO alice across all namespaces
            shared = authz.list_external_resources(("user", "alice"), "note", "view")
        """
        self._viewer = subject
        subject_type, subject_id = subject
        # Store both type and id for RLS policy
        self.cursor.execute(
            "SELECT set_config('authz.viewer_type', %s, false), "
            "set_config('authz.viewer_id', %s, false)",
            (subject_type, subject_id),
        )

    def clear_viewer(self) -> None:
        """
        Clear the viewer context.

        Should be called at end of request to prevent context leakage
        between requests in connection pools.
        """
        self._viewer = None
        self.cursor.execute(
            "SELECT set_config('authz.viewer_type', '', false), "
            "set_config('authz.viewer_id', '', false)"
        )

    def _apply_actor_context(self) -> None:
        """Apply actor context via authz.set_actor()."""
        self.cursor.execute(
            """SELECT authz.set_actor(
                p_actor_id := %s,
                p_request_id := %s,
                p_on_behalf_of := %s,
                p_reason := %s
            )""",
            (self._actor_id, self._request_id, self._on_behalf_of, self._reason),
        )

    def grant(
        self,
        permission: str,
        *,
        resource: Entity,
        subject: Entity,
        subject_relation: str | None = None,
        expires_at: datetime | None = None,
    ) -> int:
        """
        Grant a permission on a resource to a subject.

        Args:
            permission: The permission to grant (e.g., "admin", "read")
            resource: The resource as (type, id) tuple (e.g., ("repo", "api"))
            subject: The subject as (type, id) tuple (e.g., ("team", "eng"))
            subject_relation: Optional relation on the subject (e.g., "admin" for team#admin)
            expires_at: Optional expiration time for time-bound permissions

        Returns:
            The tuple ID

        Example:
            authz.grant("admin", resource=("repo", "api"), subject=("team", "eng"))
            authz.grant("read", resource=("repo", "api"), subject=("user", "alice"))
            # Grant only to team admins:
            authz.grant("write", resource=("repo", "api"), subject=("team", "eng"), subject_relation="admin")
            # Grant with expiration:
            authz.grant("read", resource=("doc", "1"), subject=("user", "bob"),
                       expires_at=datetime.now(timezone.utc) + timedelta(days=30))
        """
        resource_type, resource_id = resource
        subject_type, subject_id = subject

        if subject_relation is not None:
            return self._fetch_val(
                "SELECT authz.write_tuple(%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    resource_type,
                    resource_id,
                    permission,
                    subject_type,
                    subject_id,
                    subject_relation,
                    self.namespace,
                    expires_at,
                ),
                write=True,
            )
        else:
            return self._fetch_val(
                "SELECT authz.write(%s, %s, %s, %s, %s, %s, %s)",
                (
                    resource_type,
                    resource_id,
                    permission,
                    subject_type,
                    subject_id,
                    self.namespace,
                    expires_at,
                ),
                write=True,
            )

    def revoke(
        self,
        permission: str,
        *,
        resource: Entity,
        subject: Entity,
        subject_relation: str | None = None,
    ) -> bool:
        """
        Revoke a permission on a resource from a subject.

        Args:
            permission: The permission to revoke
            resource: The resource as (type, id) tuple
            subject: The subject as (type, id) tuple
            subject_relation: Optional relation on the subject (e.g., "admin" for team#admin)

        Returns:
            True if a tuple was deleted

        Example:
            authz.revoke("read", resource=("repo", "api"), subject=("user", "alice"))
            # Revoke from team admins only:
            authz.revoke("write", resource=("repo", "api"), subject=("team", "eng"), subject_relation="admin")
        """
        resource_type, resource_id = resource
        subject_type, subject_id = subject

        if subject_relation is not None:
            result = self._fetch_val(
                "SELECT authz.delete_tuple(%s, %s, %s, %s, %s, %s, %s)",
                (
                    resource_type,
                    resource_id,
                    permission,
                    subject_type,
                    subject_id,
                    subject_relation,
                    self.namespace,
                ),
                write=True,
            )
        else:
            result = self._fetch_val(
                "SELECT authz.delete(%s, %s, %s, %s, %s, %s)",
                (
                    resource_type,
                    resource_id,
                    permission,
                    subject_type,
                    subject_id,
                    self.namespace,
                ),
                write=True,
            )
        return bool(result)

    def check(self, subject: Entity, permission: str, resource: Entity) -> bool:
        """
        Check if a subject has a permission on a resource.

        This is the core authorization check - the question every service asks.

        Args:
            subject: The subject as (type, id) tuple (e.g., ("user", "alice"))
            permission: The permission to check (e.g., "read", "write")
            resource: The resource as (type, id) tuple

        Returns:
            True if the subject has the permission

        Example:
            if authz.check(("user", "alice"), "read", ("repo", "api")):
                return repo_contents
            if authz.check(("api_key", "key-123"), "read", ("repo", "api")):
                return repo_contents
        """
        subject_type, subject_id = subject
        resource_type, resource_id = resource
        return self._fetch_val(
            "SELECT authz.check(%s, %s, %s, %s, %s, %s)",
            (
                subject_type,
                subject_id,
                permission,
                resource_type,
                resource_id,
                self.namespace,
            ),
        )

    def check_any(
        self, subject: Entity, permissions: list[str], resource: Entity
    ) -> bool:
        """
        Check if a subject has any of the specified permissions.

        Useful for "can edit OR admin" style checks. More efficient than
        multiple check() calls.

        Args:
            subject: The subject as (type, id) tuple
            permissions: List of permissions (subject needs at least one)
            resource: The resource as (type, id) tuple

        Returns:
            True if the subject has at least one of the permissions
        """
        subject_type, subject_id = subject
        resource_type, resource_id = resource
        return self._fetch_val(
            "SELECT authz.check_any(%s, %s, %s, %s, %s, %s)",
            (
                subject_type,
                subject_id,
                permissions,
                resource_type,
                resource_id,
                self.namespace,
            ),
        )

    def check_all(
        self, subject: Entity, permissions: list[str], resource: Entity
    ) -> bool:
        """
        Check if a subject has all of the specified permissions.

        Useful for operations requiring multiple permissions.

        Args:
            subject: The subject as (type, id) tuple
            permissions: List of permissions (subject needs all of them)
            resource: The resource as (type, id) tuple

        Returns:
            True if the subject has all of the permissions
        """
        subject_type, subject_id = subject
        resource_type, resource_id = resource
        return self._fetch_val(
            "SELECT authz.check_all(%s, %s, %s, %s, %s, %s)",
            (
                subject_type,
                subject_id,
                permissions,
                resource_type,
                resource_id,
                self.namespace,
            ),
        )

    def explain(self, subject: Entity, permission: str, resource: Entity) -> list[str]:
        """
        Explain why a subject has a permission.

        Returns the permission paths - useful for debugging and auditing.

        Args:
            subject: The subject as (type, id) tuple
            permission: The permission to explain
            resource: The resource as (type, id) tuple

        Returns:
            List of human-readable explanation strings

        Example:
            paths = authz.explain(("user", "alice"), "read", ("repo", "api"))
            # ["HIERARCHY: user:alice is member of team:eng which has admin (admin -> read) on repo:api"]
        """
        subject_type, subject_id = subject
        resource_type, resource_id = resource
        rows = self._fetch_raw(
            "SELECT * FROM authz.explain_text(%s, %s, %s, %s, %s, %s)",
            (
                subject_type,
                subject_id,
                permission,
                resource_type,
                resource_id,
                self.namespace,
            ),
        )
        return [row[0] for row in rows]

    def list_subjects(
        self,
        permission: str,
        resource: Entity,
        *,
        subject_type: str | None = None,
        limit: int | None = None,
        cursor: Entity | None = None,
    ) -> list[Entity]:
        """
        List subjects who have a permission on a resource.

        Args:
            permission: The permission to check
            resource: The resource as (type, id) tuple
            subject_type: Filter to specific type (e.g., "user")
            limit: Maximum number of results
            cursor: Pagination cursor as (type, id) tuple from last result

        Returns:
            List of subjects as (type, id) tuples

        Example:
            subjects = authz.list_subjects("read", ("repo", "api"))
            users_only = authz.list_subjects("read", ("repo", "api"), subject_type="user")
        """
        resource_type, resource_id = resource
        cursor_type = cursor[0] if cursor else None
        cursor_id = cursor[1] if cursor else None

        # Always pass all parameters to ensure consistent behavior
        rows = self._fetch_raw(
            "SELECT * FROM authz.list_subjects(%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                resource_type,
                resource_id,
                permission,
                self.namespace,
                limit if limit is not None else 100,
                subject_type,
                cursor_type,
                cursor_id,
            ),
        )
        return [(row[0], row[1]) for row in rows]

    def count_subjects(
        self,
        permission: str,
        resource: Entity,
        *,
        subject_type: str | None = None,
    ) -> int:
        """
        Count subjects who have a permission on a resource.

        More efficient than len(list_subjects(...)) when you only need the count.

        Args:
            permission: The permission to check
            resource: The resource as (type, id) tuple
            subject_type: Filter to specific type (e.g., "user")

        Returns:
            Count of subjects with the permission

        Example:
            member_count = authz.count_subjects("member", ("team", "eng"))
            user_count = authz.count_subjects("member", ("team", "eng"), subject_type="user")
        """
        resource_type, resource_id = resource
        return self._fetch_val(
            "SELECT authz.count_subjects(%s, %s, %s, %s, %s)",
            (resource_type, resource_id, permission, self.namespace, subject_type),
        )

    def list_resources(
        self,
        subject: Entity,
        resource_type: str,
        permission: str,
        *,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> list[str]:
        """
        List resources a subject has a permission on.

        Args:
            subject: The subject as (type, id) tuple (e.g., ("user", "alice"))
            resource_type: The resource type to list
            permission: The permission to check
            limit: Maximum number of results (optional)
            cursor: Pagination cursor (optional)

        Returns:
            List of resource IDs

        Example:
            repos = authz.list_resources(("user", "alice"), "repo", "read")
            # ["api", "frontend", "docs"]
        """
        subject_type, subject_id = subject
        if limit is not None:
            rows = self._fetch_raw(
                "SELECT * FROM authz.list_resources(%s, %s, %s, %s, %s, %s, %s)",
                (
                    subject_type,
                    subject_id,
                    resource_type,
                    permission,
                    self.namespace,
                    limit,
                    cursor,
                ),
            )
        else:
            rows = self._fetch_raw(
                "SELECT * FROM authz.list_resources(%s, %s, %s, %s, %s)",
                (subject_type, subject_id, resource_type, permission, self.namespace),
            )
        return [row[0] for row in rows]

    def list_external_resources(
        self,
        subject: Entity,
        resource_type: str,
        permission: str,
    ) -> list[dict]:
        """
        List resources shared with a subject from other namespaces.

        Returns resources where the subject is the recipient of a grant from
        a different namespace. Requires set_viewer() to enable cross-namespace
        visibility.

        Args:
            subject: The subject as (type, id) tuple (e.g., ("user", "alice"))
            resource_type: Resource type (e.g., "note")
            permission: Minimum permission level (uses global hierarchy)

        Returns:
            List of dicts: namespace, resource_id, relation, created_at, expires_at

        Example:
            authz.set_viewer(("user", "alice"))
            shared = authz.list_external_resources(("user", "alice"), "note", "view")
        """
        subject_type, subject_id = subject
        if self._viewer != subject:
            self.set_viewer(subject)

        rows = self._fetch_raw(
            """
            SELECT t.namespace, t.resource_id, t.relation, t.created_at, t.expires_at
            FROM authz.tuples t
            WHERE t.subject_type = %s
              AND t.subject_id = %s
              AND t.resource_type = %s
              AND (
                  t.relation = %s
                  OR EXISTS (
                      SELECT 1 FROM authz.permission_hierarchy h
                      WHERE h.resource_type = %s
                        AND h.permission = t.relation
                        AND h.implies = %s
                        AND h.namespace = 'global'
                  )
              )
              AND t.namespace != %s
              AND (t.expires_at IS NULL OR t.expires_at > now())
            ORDER BY t.created_at DESC
            """,
            (
                subject_type,
                subject_id,
                resource_type,
                permission,
                resource_type,
                permission,
                self.namespace,
            ),
        )
        return [
            {
                "namespace": row[0],
                "resource_id": row[1],
                "relation": row[2],
                "created_at": row[3],
                "expires_at": row[4],
            }
            for row in rows
        ]

    def list_grants(
        self,
        subject: Entity,
        *,
        resource_type: str | None = None,
    ) -> list[dict]:
        """
        List all grants for a subject.

        Useful for inspecting what permissions an entity has,
        such as viewing API key scopes or auditing service access.

        Args:
            subject: The subject as (type, id) tuple (e.g., ("api_key", "key-123"))
            resource_type: Optional filter by resource type

        Returns:
            List of grant dictionaries with resource, relation, and expires_at

        Example:
            # Get all grants for an API key
            grants = authz.list_grants(("api_key", key_id))
            for grant in grants:
                print(f"{grant['relation']} on {grant['resource']}")

            # Get only note-related grants
            note_grants = authz.list_grants(("api_key", key_id), resource_type="note")
        """
        subject_type, subject_id = subject
        rows = self._fetch_raw(
            "SELECT * FROM authz.list_subject_grants(%s, %s, %s, %s)",
            (subject_type, subject_id, self.namespace, resource_type),
        )
        return [
            {
                "resource": (row[0], row[1]),
                "relation": row[2],
                "subject_relation": row[3],
                "expires_at": row[4],
            }
            for row in rows
        ]

    def revoke_all_grants(
        self,
        subject: Entity,
        *,
        resource_type: str | None = None,
    ) -> int:
        """
        Revoke all grants for a subject (e.g., when deleting an API key).

        This is useful for cleanup when removing an entity that may have
        accumulated many permissions across different resources.

        Args:
            subject: The subject as (type, id) tuple (e.g., ("api_key", "key-123"))
            resource_type: Optional filter to only revoke grants on specific resource type

        Returns:
            Number of grants revoked

        Example:
            # Revoke all grants for an API key before deletion
            count = authz.revoke_all_grants(("api_key", key_id))
            print(f"Revoked {count} grants")

            # Revoke only note-related grants
            count = authz.revoke_all_grants(("api_key", key_id), resource_type="note")
        """
        subject_type, subject_id = subject
        return self._fetch_val(
            "SELECT authz.revoke_subject_grants(%s, %s, %s, %s)",
            (subject_type, subject_id, self.namespace, resource_type),
            write=True,
        )

    def revoke_resource_grants(
        self,
        resource: Entity,
        *,
        permission: str | None = None,
    ) -> int:
        """Revoke all grants ON a resource. Call before deleting the resource.

        Args:
            resource: The resource as (type, id) tuple
            permission: Specific permission to revoke, or None for all

        Returns:
            Count of grants revoked

        Example:
            authz.revoke_resource_grants(("note", note_id))
            db.execute("DELETE FROM notes WHERE id = %s", (note_id,))
        """
        resource_type, resource_id = resource
        return self._fetch_val(
            "SELECT authz.revoke_resource_grants(%s, %s, %s, %s)",
            (resource_type, resource_id, self.namespace, permission),
            write=True,
        )

    def transfer_grant(
        self,
        permission: str,
        *,
        resource: Entity,
        from_subject: Entity,
        to_subject: Entity,
    ) -> bool:
        """Transfer a grant from one subject to another.

        Atomically grants to the new subject then revokes from the old subject.

        Args:
            permission: The permission to transfer
            resource: The resource as (type, id) tuple
            from_subject: Current holder as (type, id) tuple
            to_subject: New holder as (type, id) tuple

        Returns:
            True if revoke succeeded (grant always succeeds or raises)
        """
        # Grant to new subject first
        self.grant(permission, resource=resource, subject=to_subject)

        # Revoke from old subject
        return self.revoke(permission, resource=resource, subject=from_subject)

    def filter_authorized(
        self,
        subject: Entity,
        resource_type: str,
        permission: str,
        resource_ids: list[str],
    ) -> list[str]:
        """
        Batch-check which resources a subject can access.

        Use instead of calling check() in a loop - single query regardless of list size.

        Args:
            subject: The subject as (type, id) tuple
            resource_type: The resource type to check
            permission: The permission to check
            resource_ids: List of resource IDs to filter

        Returns:
            Subset of resource_ids the subject has permission on

        Example:
            visible = authz.filter_authorized(("user", uid), "note", "view", note_ids)
        """
        subject_type, subject_id = subject
        result = self._fetch_val(
            "SELECT authz.filter_authorized(%s, %s, %s, %s, %s, %s)",
            (
                subject_type,
                subject_id,
                resource_type,
                permission,
                resource_ids,
                self.namespace,
            ),
        )
        return result if result else []

    def set_hierarchy(self, resource_type: str, *permissions: str):
        """
        Define permission hierarchy for a resource type.

        Each permission implies the next in the chain.

        Args:
            resource_type: The resource type (e.g., "repo")
            *permissions: Permissions in order of power (e.g., "admin", "write", "read")

        Example:
            authz.set_hierarchy("repo", "admin", "write", "read")
            # Now admin implies write, write implies read
        """
        for i in range(len(permissions) - 1):
            self.add_hierarchy_rule(resource_type, permissions[i], permissions[i + 1])

    def add_hierarchy_rule(self, resource_type: str, permission: str, implies: str):
        """
        Add a single hierarchy rule (for complex/branching hierarchies).

        Hierarchies are stored in the client's namespace:
        - Use namespace="global" for app-wide defaults (all tenants inherit)
        - Use tenant namespace (e.g., "org:xxx") for org-specific customizations

        Permission checks look at BOTH global AND tenant hierarchies.

        Args:
            resource_type: The resource type
            permission: The higher permission
            implies: The permission it implies

        Example:
            # App-wide defaults (global client)
            global_authz = AuthzClient(cursor, namespace="global")
            global_authz.add_hierarchy_rule("doc", "owner", "edit")

            # Org-specific customization (tenant client)
            org_authz = AuthzClient(cursor, namespace="org:acme")
            org_authz.add_hierarchy_rule("doc", "legal_approver", "view")
        """
        self._fetch_val(
            "SELECT authz.add_hierarchy(%s, %s, %s, %s)",
            (resource_type, permission, implies, self.namespace),
            write=True,
        )

    def remove_hierarchy_rule(self, resource_type: str, permission: str, implies: str):
        """Remove a hierarchy rule from the client's namespace."""
        self._fetch_val(
            "SELECT authz.remove_hierarchy(%s, %s, %s, %s)",
            (resource_type, permission, implies, self.namespace),
            write=True,
        )

    def clear_hierarchy(self, resource_type: str) -> int:
        """Clear all hierarchy rules for a resource type in the client's namespace."""
        return self._fetch_val(
            "SELECT authz.clear_hierarchy(%s, %s)",
            (resource_type, self.namespace),
            write=True,
        )

    # NOTE: This method uses keyword-only arguments (`*,`) unlike other clients.
    # This is intentional because:
    # 1. The authz audit schema has composite resource/subject pairs (type, id)
    #    that are passed as Entity tuples - positional args would be confusing
    # 2. This method has a custom implementation (doesn't call super()) because
    #    the return structure differs - it returns tuples like ("doc", "1")
    #    instead of flat strings like other modules
    # 3. The underlying audit_events table has different columns (subject_type,
    #    subject_id, subject_relation) that don't exist in authn/config
    def get_audit_events(
        self,
        *,
        limit: int = 100,
        before: str | None = None,
        event_type: str | None = None,
        actor_id: str | None = None,
        resource: Entity | None = None,
        subject: Entity | None = None,
    ) -> list[dict]:
        """
        Query audit events with optional filters.

        Args:
            limit: Maximum number of events to return (default 100)
            before: Opaque cursor from a previous response's event['cursor']
            event_type: Filter by event type (e.g., 'tuple_created')
            actor_id: Filter by actor ID
            resource: Filter by resource as (type, id) tuple
            subject: Filter by subject as (type, id) tuple

        Returns:
            List of audit event dictionaries. Each event includes a 'cursor' field
            that can be passed to 'before' for pagination.

        Example:
            events = authz.get_audit_events(actor_id="admin@acme.com", limit=50)
            if events:
                more = authz.get_audit_events(
                    actor_id="admin@acme.com", limit=50, before=events[-1]["cursor"]
                )
        """
        conditions = ["namespace = %s"]
        params: list = [self.namespace]

        if event_type is not None:
            conditions.append("event_type = %s")
            params.append(event_type)

        if actor_id is not None:
            conditions.append("actor_id = %s")
            params.append(actor_id)

        if resource is not None:
            conditions.append("resource_type = %s")
            conditions.append("resource_id = %s")
            params.extend(resource)

        if subject is not None:
            conditions.append("subject_type = %s")
            conditions.append("subject_id = %s")
            params.extend(subject)

        if before is not None:
            cursor_time, cursor_id = self._decode_cursor(before)
            conditions.append("(event_time, id) < (%s::timestamptz, %s::bigint)")
            params.extend([cursor_time, cursor_id])

        params.append(limit)

        sql = f"""
            SELECT
                id, event_id, event_type, event_time,
                actor_id, request_id, reason, on_behalf_of,
                session_user_name, current_user_name, client_addr, application_name,
                resource_type, resource_id, relation,
                subject_type, subject_id, subject_relation,
                tuple_id, expires_at
            FROM authz.audit_events
            WHERE {" AND ".join(conditions)}
            ORDER BY event_time DESC, id DESC
            LIMIT %s
        """

        rows = self._fetch_raw(sql, tuple(params))

        return [
            {
                "id": row[0],
                "event_id": str(row[1]),
                "event_type": row[2],
                "event_time": row[3],
                "cursor": self._encode_cursor(row[3], row[0]),
                "actor_id": row[4],
                "request_id": row[5],
                "reason": row[6],
                "on_behalf_of": row[7],
                "session_user": row[8],
                "current_user": row[9],
                "client_addr": str(row[10]) if row[10] else None,
                "application_name": row[11],
                "resource": (row[12], row[13]),
                "relation": row[14],
                "subject": (row[15], row[16]),
                "subject_relation": row[17],
                "tuple_id": row[18],
                "expires_at": row[19],
            }
            for row in rows
        ]

    def verify(self) -> list[dict]:
        """
        Check for data integrity issues (e.g., group membership cycles).

        Returns list of issues (empty if healthy).

        Example:
            issues = authz.verify()
            for issue in issues:
                print(f"{issue['status']}: {issue['details']}")
        """
        return self._fetch_all(
            "SELECT resource_type, resource_id, status, details FROM authz.verify_integrity(%s)",
            (self.namespace,),
        )

    def get_stats(self) -> dict:
        """
        Get namespace statistics for monitoring.

        Returns:
            Dictionary with:
            - tuple_count: Number of relationship tuples
            - hierarchy_rule_count: Number of hierarchy rules
            - unique_users: Distinct users with permissions
            - unique_resources: Distinct resources with permissions

        Example:
            stats = authz.get_stats()
            print(f"Tuples: {stats['tuple_count']}, Users: {stats['unique_users']}")
        """
        return (
            self._fetch_one(
                "SELECT tuple_count, hierarchy_rule_count, unique_users, unique_resources FROM authz.get_stats(%s)",
                (self.namespace,),
            )
            or {}
        )

    def bulk_grant(
        self, permission: str, *, resource: Entity, subjects: list[Entity]
    ) -> int:
        """
        Grant permission to many subjects at once.

        Subjects are grouped by type and inserted efficiently. Supports
        mixed subject types in a single call.

        Args:
            permission: The permission to grant
            resource: The resource as (type, id) tuple
            subjects: List of subjects as (type, id) tuples

        Returns:
            Count of tuples inserted

        Example:
            authz.bulk_grant("read", resource=("doc", "1"), subjects=[
                ("user", "alice"),
                ("user", "bob"),
                ("api_key", "key-123"),
            ])
        """
        resource_type, resource_id = resource

        # Group subjects by type for efficient batch inserts.
        # Design note: We make one SQL call per subject type rather than a single
        # mixed-type call. This keeps the SQL simpler and real-world bulk grants
        # typically share subject types (e.g., inviting many users). A mixed-type
        # SQL function would add complexity for marginal benefit.
        by_type: dict[str, list[str]] = {}
        for subject_type, subject_id in subjects:
            by_type.setdefault(subject_type, []).append(subject_id)

        total = 0
        for subject_type, subject_ids in by_type.items():
            total += self._fetch_val(
                "SELECT authz.write_tuples_bulk(%s, %s, %s, %s, %s, %s)",
                (
                    resource_type,
                    resource_id,
                    permission,
                    subject_type,
                    subject_ids,
                    self.namespace,
                ),
                write=True,
            )
        return total

    def bulk_grant_resources(
        self,
        permission: str,
        *,
        resource_type: str,
        resource_ids: list[str],
        subject: Entity,
        subject_relation: str | None = None,
    ) -> int:
        """
        Grant permission to a subject on many resources at once.

        Optimized for bulk operations: uses single recompute instead of
        per-resource triggers.

        Returns count of tuples inserted.

        Example:
            authz.bulk_grant_resources(
                "read",
                resource_type="doc",
                resource_ids=["doc-1", "doc-2", "doc-3"],
                subject=("team", "engineering"),
            )
        """
        subject_type, subject_id = subject
        return self._fetch_val(
            "SELECT authz.grant_to_resources_bulk(%s, %s, %s, %s, %s, %s, %s)",
            (
                resource_type,
                resource_ids,
                permission,
                subject_type,
                subject_id,
                subject_relation,
                self.namespace,
            ),
            write=True,
        )

    def list_expiring(self, within: timedelta = timedelta(days=7)) -> list[dict]:
        """
        List grants expiring within the given timeframe.

        Args:
            within: Time window to check (default 7 days).

        Returns:
            List of grants with their expiration times

        Example:
            expiring = authz.list_expiring(within=timedelta(days=30))
            for grant in expiring:
                print(f"{grant['subject']} access to {grant['resource']} expires {grant['expires_at']}")
        """
        rows = self._fetch_raw(
            "SELECT * FROM authz.list_expiring(%s, %s)",
            (within, self.namespace),
        )
        return [
            {
                "resource": (row[0], row[1]),
                "relation": row[2],
                "subject": (row[3], row[4]),
                "subject_relation": row[5],
                "expires_at": row[6],
            }
            for row in rows
        ]

    def cleanup_expired(self) -> dict:
        """
        Remove expired grants.

        This is optional for storage management - expired entries are
        automatically filtered at query time.

        Returns:
            Dictionary with count of deleted tuples

        Example:
            result = authz.cleanup_expired()
            print(f"Removed {result['tuples_deleted']} expired grants")
        """
        result = self._fetch_val(
            "SELECT authz.cleanup_expired(%s)",
            (self.namespace,),
            write=True,
        )
        return {"tuples_deleted": result}

    def set_expiration(
        self,
        permission: str,
        *,
        resource: Entity,
        subject: Entity,
        expires_at: datetime | None,
    ) -> bool:
        """
        Set or update expiration on an existing grant.

        Args:
            permission: The permission/relation
            resource: The resource as (type, id) tuple
            subject: The subject as (type, id) tuple
            expires_at: New expiration time (None to make permanent)

        Returns:
            True if grant was found and updated

        Example:
            authz.set_expiration("read", resource=("doc", "1"), subject=("user", "alice"),
                                expires_at=datetime.now(timezone.utc) + timedelta(days=30))
        """
        resource_type, resource_id = resource
        subject_type, subject_id = subject
        return self._fetch_val(
            "SELECT authz.set_expiration(%s, %s, %s, %s, %s, %s, %s)",
            (
                resource_type,
                resource_id,
                permission,
                subject_type,
                subject_id,
                expires_at,
                self.namespace,
            ),
            write=True,
        )

    def clear_expiration(
        self,
        permission: str,
        *,
        resource: Entity,
        subject: Entity,
    ) -> bool:
        """
        Remove expiration from a grant (make it permanent).

        Args:
            permission: The permission/relation
            resource: The resource as (type, id) tuple
            subject: The subject as (type, id) tuple

        Returns:
            True if grant was found and updated

        Example:
            authz.clear_expiration("read", resource=("doc", "1"), subject=("user", "alice"))
        """
        resource_type, resource_id = resource
        subject_type, subject_id = subject
        return self._fetch_val(
            "SELECT authz.clear_expiration(%s, %s, %s, %s, %s, %s)",
            (
                resource_type,
                resource_id,
                permission,
                subject_type,
                subject_id,
                self.namespace,
            ),
            write=True,
        )

    def extend_expiration(
        self,
        permission: str,
        *,
        resource: Entity,
        subject: Entity,
        extension: timedelta,
    ) -> datetime:
        """
        Extend an existing expiration by a given interval.

        Args:
            permission: The permission/relation
            resource: The resource as (type, id) tuple
            subject: The subject as (type, id) tuple
            extension: Time to add to current expiration

        Returns:
            The new expiration time

        Example:
            new_expires = authz.extend_expiration("read", resource=("doc", "1"),
                                                  subject=("user", "alice"),
                                                  extension=timedelta(days=30))
        """
        resource_type, resource_id = resource
        subject_type, subject_id = subject
        return self._fetch_val(
            "SELECT authz.extend_expiration(%s, %s, %s, %s, %s, %s, %s)",
            (
                resource_type,
                resource_id,
                permission,
                subject_type,
                subject_id,
                extension,
                self.namespace,
            ),
            write=True,
        )
