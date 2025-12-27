"""
Input validation tests for postkit/authz.

Tests for:
- Boundary conditions (max length, min length)
- Invalid input handling
- Special characters
- Edge cases
- SDK validation behavior
- Exception handling
"""

import pytest
import psycopg
from authz_sdk import AuthzError


class TestBoundaryConditions:
    """Test edge cases and boundary conditions."""

    def test_max_length_identifiers(self, authz):
        """Identifiers at max length (1024) work correctly."""
        long_id = "a" * 1024
        authz.grant("read", resource=("doc", long_id), subject=("user", "alice"))
        assert authz.check("alice", "read", ("doc", long_id))

    def test_identifier_over_max_length_rejected(self, authz):
        """Identifiers over 1024 chars are rejected."""
        too_long = "a" * 1025
        with pytest.raises(AuthzError, match="exceeds maximum length"):
            authz.grant("read", resource=("doc", too_long), subject=("user", "alice"))

    def test_single_char_identifiers(self, authz):
        """Single character identifiers work."""
        authz.grant("r", resource=("d", "1"), subject=("user", "a"))
        assert authz.check("a", "r", ("d", "1"))

    def test_numeric_looking_ids(self, authz):
        """IDs that look like numbers work correctly."""
        authz.grant("read", resource=("doc", "12345"), subject=("user", "67890"))
        assert authz.check("67890", "read", ("doc", "12345"))

    def test_uuid_style_ids(self, authz):
        """UUID-style IDs work correctly."""
        uuid_id = "550e8400-e29b-41d4-a716-446655440000"
        authz.grant("read", resource=("doc", uuid_id), subject=("user", "alice"))
        assert authz.check("alice", "read", ("doc", uuid_id))

    def test_special_chars_in_ids(self, authz):
        """IDs with allowed special characters work."""
        # Underscores, hyphens, dots are typically allowed
        special_id = "my-doc_v1.0"
        authz.grant("read", resource=("doc", special_id), subject=("user", "alice"))
        assert authz.check("alice", "read", ("doc", special_id))

    def test_empty_id_rejected(self, authz):
        """Empty IDs are rejected."""
        with pytest.raises(AuthzError):
            authz.grant("read", resource=("doc", ""), subject=("user", "alice"))

    def test_empty_user_rejected(self, authz):
        """Empty user IDs are rejected."""
        with pytest.raises(AuthzError):
            authz.grant("read", resource=("doc", "1"), subject=("user", ""))

    def test_whitespace_only_rejected(self, authz):
        """Whitespace-only identifiers are rejected."""
        with pytest.raises(AuthzError):
            authz.grant("read", resource=("doc", "   "), subject=("user", "alice"))

    def test_null_bytes_rejected_by_driver(self, authz):
        """Null bytes are rejected (by psycopg at protocol level, not our validation)."""
        # Note: psycopg rejects null bytes before SQL execution, so we get AuthnError
        # (the generic SDK error) rather than AuthzError
        with pytest.raises(Exception):  # Could be psycopg or SDK error
            authz.grant(
                "read", resource=("doc", "bad\x00id"), subject=("user", "alice")
            )


class TestBulkValidation:
    """Test bulk operation input validation."""

    def test_bulk_grant_rejects_empty_subject_id(self, authz):
        """bulk_grant rejects arrays with empty strings."""
        with pytest.raises(AuthzError, match=r"subject_ids\[2\] is empty"):
            authz.bulk_grant(
                "read", resource=("doc", "1"), subject_ids=["alice", "", "bob"]
            )

    def test_bulk_grant_rejects_whitespace_only(self, authz):
        """bulk_grant rejects arrays with whitespace-only strings."""
        with pytest.raises(AuthzError, match=r"subject_ids\[2\] is empty"):
            authz.bulk_grant(
                "read", resource=("doc", "1"), subject_ids=["alice", "   ", "bob"]
            )

    def test_bulk_grant_rejects_too_long(self, authz):
        """bulk_grant rejects arrays with overly long strings."""
        too_long = "a" * 1025
        with pytest.raises(AuthzError, match=r"subject_ids\[2\] exceeds 1024"):
            authz.bulk_grant(
                "read", resource=("doc", "1"), subject_ids=["alice", too_long]
            )

    def test_bulk_grant_valid_array_succeeds(self, authz):
        """bulk_grant works with valid arrays."""
        count = authz.bulk_grant(
            "read", resource=("doc", "1"), subject_ids=["alice", "bob", "carol"]
        )
        assert count == 3
        assert authz.check("alice", "read", ("doc", "1"))
        assert authz.check("bob", "read", ("doc", "1"))
        assert authz.check("carol", "read", ("doc", "1"))

    def test_bulk_grant_resources_rejects_group_membership(self, authz):
        """bulk_grant_resources rejects group-to-group memberships (cycle risk)."""
        with pytest.raises(AuthzError, match="cannot create group-to-group"):
            authz.bulk_grant_resources(
                "member",
                resource_type="team",
                resource_ids=["eng", "sales"],
                subject=("team", "platform"),
            )

    def test_bulk_grant_resources_rejects_parent_relation(self, authz):
        """bulk_grant_resources rejects parent relations (cycle risk)."""
        with pytest.raises(AuthzError, match="cannot create parent"):
            authz.bulk_grant_resources(
                "parent",
                resource_type="folder",
                resource_ids=["docs", "images"],
                subject=("folder", "root"),
            )

    def test_bulk_grant_resources_allows_user_member(self, authz):
        """bulk_grant_resources allows member relation for users (no cycle risk)."""
        count = authz.bulk_grant_resources(
            "member",
            resource_type="team",
            resource_ids=["eng", "sales"],
            subject=("user", "alice"),
        )
        assert count == 2

    def test_write_tuples_bulk_rejects_group_membership(self, db_connection, request):
        """write_tuples_bulk rejects group-to-group memberships (cycle risk)."""
        namespace = "t_" + request.node.name.lower()[:50]
        cursor = db_connection.cursor()
        try:
            with pytest.raises(psycopg.Error, match="cannot create group-to-group"):
                cursor.execute(
                    "SELECT authz.write_tuples_bulk(%s, %s, %s, %s, %s, %s)",
                    ("team", "eng", "member", "team", ["platform", "infra"], namespace),
                )
        finally:
            cursor.execute(
                "DELETE FROM authz.tuples WHERE namespace = %s", (namespace,)
            )
            cursor.close()

    def test_write_tuples_bulk_rejects_parent_relation(self, db_connection, request):
        """write_tuples_bulk rejects parent relations (cycle risk)."""
        namespace = "t_" + request.node.name.lower()[:50]
        cursor = db_connection.cursor()
        try:
            with pytest.raises(psycopg.Error, match="cannot create parent"):
                cursor.execute(
                    "SELECT authz.write_tuples_bulk(%s, %s, %s, %s, %s, %s)",
                    ("folder", "docs", "parent", "folder", ["root"], namespace),
                )
        finally:
            cursor.execute(
                "DELETE FROM authz.tuples WHERE namespace = %s", (namespace,)
            )
            cursor.close()

    def test_write_tuples_bulk_allows_user_member(self, db_connection, request):
        """write_tuples_bulk allows member relation for users (no cycle risk)."""
        namespace = "t_" + request.node.name.lower()[:50]
        cursor = db_connection.cursor()
        try:
            cursor.execute(
                "SELECT authz.write_tuples_bulk(%s, %s, %s, %s, %s, %s)",
                ("team", "eng", "member", "user", ["alice", "bob"], namespace),
            )
            result = cursor.fetchone()[0]
            assert result == 2
        finally:
            cursor.execute(
                "DELETE FROM authz.tuples WHERE namespace = %s", (namespace,)
            )
            cursor.close()


class TestSDKValidation:
    """Input validation - SDK raises exceptions for invalid inputs."""

    def test_invalid_resource_type_raises(self, authz):
        with pytest.raises(AuthzError, match="must start with lowercase"):
            authz.grant("read", resource=("INVALID", "1"), subject=("user", "alice"))

    def test_invalid_permission_raises(self, authz):
        with pytest.raises(AuthzError, match="must start with lowercase"):
            authz.grant("READ", resource=("doc", "1"), subject=("user", "alice"))

    def test_invalid_subject_type_raises(self, authz):
        with pytest.raises(AuthzError, match="must start with lowercase"):
            authz.grant("read", resource=("doc", "1"), subject=("USER", "alice"))

    def test_empty_resource_id_raises(self, authz):
        with pytest.raises(AuthzError, match="cannot be empty"):
            authz.grant("read", resource=("doc", ""), subject=("user", "alice"))

    def test_flexible_resource_ids_allowed(self, authz):
        # IDs can have slashes, @, uppercase - they're flexible
        authz.grant(
            "read",
            resource=("doc", "acme/doc-1"),
            subject=("user", "alice@example.com"),
        )

        assert authz.check("alice@example.com", "read", ("doc", "acme/doc-1"))


class TestValidationEdgeCases:
    """Edge cases in input validation."""

    def test_unicode_in_ids(self, authz):
        """Unicode characters in IDs work correctly."""
        authz.grant("read", resource=("doc", "文档-1"), subject=("user", "用户-alice"))
        assert authz.check("用户-alice", "read", ("doc", "文档-1"))

    def test_special_chars_in_ids(self, authz):
        """Special characters in IDs work correctly."""
        authz.grant(
            "read",
            resource=("doc", "path/to/doc#section?v=1"),
            subject=("user", "alice+test@example.com"),
        )
        assert authz.check(
            "alice+test@example.com",
            "read",
            ("doc", "path/to/doc#section?v=1"),
        )


class TestExceptionHandling:
    """Test that SDK raises proper exception types."""

    def test_validation_error_on_empty_id(self, authz):
        """Empty ID raises AuthzError."""
        with pytest.raises(AuthzError):
            authz.grant("read", resource=("doc", ""), subject=("user", "alice"))

    def test_cycle_error_on_hierarchy_cycle(self, authz):
        """Hierarchy cycle raises AuthzError."""
        authz.add_hierarchy_rule("doc", "admin", "write")
        authz.add_hierarchy_rule("doc", "write", "read")

        with pytest.raises(AuthzError):
            authz.add_hierarchy_rule("doc", "read", "admin")


class TestDeleteValidation:
    """Test that delete_tuple validates inputs like write_tuple."""

    def test_delete_rejects_invalid_resource_type(self, authz):
        """delete rejects invalid resource_type."""
        with pytest.raises(AuthzError, match="must start with lowercase"):
            authz.revoke("read", resource=("INVALID", "1"), subject=("user", "alice"))

    def test_delete_rejects_invalid_relation(self, authz):
        """delete rejects invalid relation."""
        with pytest.raises(AuthzError, match="must start with lowercase"):
            authz.revoke("READ", resource=("doc", "1"), subject=("user", "alice"))

    def test_delete_rejects_invalid_subject_type(self, authz):
        """delete rejects invalid subject_type."""
        with pytest.raises(AuthzError, match="must start with lowercase"):
            authz.revoke("read", resource=("doc", "1"), subject=("USER", "alice"))

    def test_delete_rejects_empty_resource_id(self, authz):
        """delete rejects empty resource_id."""
        with pytest.raises(AuthzError, match="cannot be empty"):
            authz.revoke("read", resource=("doc", ""), subject=("user", "alice"))

    def test_delete_rejects_empty_subject_id(self, authz):
        """delete rejects empty subject_id."""
        with pytest.raises(AuthzError, match="cannot be empty"):
            authz.revoke("read", resource=("doc", "1"), subject=("user", ""))

    def test_delete_valid_input_succeeds(self, authz):
        """delete with valid input succeeds (even if tuple doesn't exist)."""
        # Should not raise, just return False
        result = authz.revoke("read", resource=("doc", "1"), subject=("user", "alice"))
        assert result is False
