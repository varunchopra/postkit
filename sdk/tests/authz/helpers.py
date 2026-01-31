"""Test helpers for authz - direct table access for test setup/teardown."""

from postkit.authz import Entity


def cleanup_namespace(cursor, namespace: str):
    """Delete all authz data for a namespace.

    Order matters: tuples and hierarchy deletes fire audit triggers, so
    audit_events must be deleted last to clean up trigger-generated rows.
    """
    cursor.execute("DELETE FROM authz.tuples WHERE namespace = %s", (namespace,))
    cursor.execute(
        "DELETE FROM authz.permission_hierarchy WHERE namespace = %s", (namespace,)
    )
    cursor.execute("DELETE FROM authz.audit_events WHERE namespace = %s", (namespace,))


class AuthzTestHelpers:
    """
    Direct table access for test setup/teardown that bypasses the SDK.

    Use cases:
    - Inserting invalid/expired data that SDK would reject
    - Counting tuples for verification
    - Cleaning up specific resources
    - Testing edge cases that require direct table manipulation

    For normal test operations, prefer AuthzClient (the `authz` fixture).
    """

    def __init__(self, cursor, namespace: str):
        self.cursor = cursor
        self.namespace = namespace
        # Set tenant context for RLS (consistent with AuthzClient)
        self.cursor.execute("SELECT authz.set_tenant(%s)", (namespace,))

    def delete_tuples(self, resource: Entity):
        """Delete tuples directly."""
        resource_type, resource_id = resource
        self.cursor.execute(
            """
            DELETE FROM authz.tuples
            WHERE namespace = %s AND resource_type = %s AND resource_id = %s
        """,
            (self.namespace, resource_type, resource_id),
        )

    def count_tuples(
        self,
        resource: Entity | None = None,
        relation: str | None = None,
    ) -> int:
        """Count tuples matching the given filters."""
        if resource and relation:
            self.cursor.execute(
                """SELECT COUNT(*) FROM authz.tuples
                   WHERE namespace = %s AND resource_type = %s
                   AND resource_id = %s AND relation = %s""",
                (self.namespace, resource[0], resource[1], relation),
            )
        elif resource:
            self.cursor.execute(
                """SELECT COUNT(*) FROM authz.tuples
                   WHERE namespace = %s AND resource_type = %s AND resource_id = %s""",
                (self.namespace, resource[0], resource[1]),
            )
        elif relation:
            self.cursor.execute(
                """SELECT COUNT(*) FROM authz.tuples
                   WHERE namespace = %s AND relation = %s""",
                (self.namespace, relation),
            )
        else:
            self.cursor.execute(
                "SELECT COUNT(*) FROM authz.tuples WHERE namespace = %s",
                (self.namespace,),
            )
        result = self.cursor.fetchone()
        return result[0] if result else 0
