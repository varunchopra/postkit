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

import psycopg
import pytest
from postkit.authz import AuthzError, AuthzValidationError


class TestBoundaryConditions:
    """Test edge cases and boundary conditions."""

    def test_max_length_identifiers(self, authz):
        """Identifiers at max length (1024) work correctly."""
        long_id = "a" * 1024
        authz.grant("read", resource=("doc", long_id), subject=("user", "alice"))
        assert authz.check(("user", "alice"), "read", ("doc", long_id))

    def test_identifier_over_max_length_rejected(self, authz):
        """Identifiers over 1024 chars are rejected."""
        too_long = "a" * 1025
        with pytest.raises(AuthzError) as exc_info:
            authz.grant("read", resource=("doc", too_long), subject=("user", "alice"))
        assert exc_info.value.error_code == "VAL_ID_TOO_LONG"

    def test_single_char_identifiers(self, authz):
        """Single character identifiers work."""
        authz.grant("r", resource=("d", "1"), subject=("user", "a"))
        assert authz.check(("user", "a"), "r", ("d", "1"))

    def test_numeric_looking_ids(self, authz):
        """IDs that look like numbers work correctly."""
        authz.grant("read", resource=("doc", "12345"), subject=("user", "67890"))
        assert authz.check(("user", "67890"), "read", ("doc", "12345"))

    def test_uuid_style_ids(self, authz):
        """UUID-style IDs work correctly."""
        uuid_id = "550e8400-e29b-41d4-a716-446655440000"
        authz.grant("read", resource=("doc", uuid_id), subject=("user", "alice"))
        assert authz.check(("user", "alice"), "read", ("doc", uuid_id))

    def test_special_chars_in_ids(self, authz):
        """IDs with allowed special characters work."""
        # Underscores, hyphens, dots are typically allowed
        special_id = "my-doc_v1.0"
        authz.grant("read", resource=("doc", special_id), subject=("user", "alice"))
        assert authz.check(("user", "alice"), "read", ("doc", special_id))

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
        # psycopg rejects null bytes before SQL execution, SDK wraps as AuthzError
        with pytest.raises(AuthzError, match="NUL"):
            authz.grant(
                "read", resource=("doc", "bad\x00id"), subject=("user", "alice")
            )


class TestBulkValidation:
    """Test bulk operation input validation."""

    def test_bulk_grant_rejects_empty_subject_id(self, authz):
        """bulk_grant rejects arrays with empty strings."""
        with pytest.raises(AuthzError) as exc_info:
            authz.bulk_grant(
                "read",
                resource=("doc", "1"),
                subjects=[("user", "alice"), ("user", ""), ("user", "bob")],
            )
        assert exc_info.value.error_code == "VAL_ARRAY_ELEMENT_INVALID"

    def test_bulk_grant_rejects_whitespace_only(self, authz):
        """bulk_grant rejects arrays with whitespace-only strings."""
        with pytest.raises(AuthzError) as exc_info:
            authz.bulk_grant(
                "read",
                resource=("doc", "1"),
                subjects=[("user", "alice"), ("user", "   "), ("user", "bob")],
            )
        assert exc_info.value.error_code == "VAL_ARRAY_ELEMENT_INVALID"

    def test_bulk_grant_rejects_too_long(self, authz):
        """bulk_grant rejects arrays with overly long strings."""
        too_long = "a" * 1025
        with pytest.raises(AuthzError) as exc_info:
            authz.bulk_grant(
                "read",
                resource=("doc", "1"),
                subjects=[("user", "alice"), ("user", too_long)],
            )
        assert exc_info.value.error_code == "VAL_ARRAY_ELEMENT_INVALID"

    def test_bulk_grant_valid_array_succeeds(self, authz):
        """bulk_grant works with valid arrays."""
        count = authz.bulk_grant(
            "read",
            resource=("doc", "1"),
            subjects=[("user", "alice"), ("user", "bob"), ("user", "carol")],
        )
        assert count == 3
        assert authz.check(("user", "alice"), "read", ("doc", "1"))
        assert authz.check(("user", "bob"), "read", ("doc", "1"))
        assert authz.check(("user", "carol"), "read", ("doc", "1"))

    def test_bulk_grant_resources_rejects_group_membership(self, authz):
        """bulk_grant_resources rejects group-to-group memberships (cycle risk)."""
        with pytest.raises(AuthzError) as exc_info:
            authz.bulk_grant_resources(
                "member",
                resource_type="team",
                resource_ids=["eng", "sales"],
                subject=("team", "platform"),
            )
        assert exc_info.value.error_code == "BIZ_BULK_GROUP_MEMBERSHIP"

    def test_bulk_grant_resources_rejects_parent_relation(self, authz):
        """bulk_grant_resources rejects parent relations (cycle risk)."""
        with pytest.raises(AuthzError) as exc_info:
            authz.bulk_grant_resources(
                "parent",
                resource_type="folder",
                resource_ids=["docs", "images"],
                subject=("folder", "root"),
            )
        assert exc_info.value.error_code == "BIZ_BULK_PARENT_RELATION"

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
        with pytest.raises(AuthzError) as exc_info:
            authz.grant("read", resource=("INVALID", "1"), subject=("user", "alice"))
        assert exc_info.value.error_code == "VAL_IDENTIFIER_FORMAT"

    def test_invalid_permission_raises(self, authz):
        with pytest.raises(AuthzError) as exc_info:
            authz.grant("READ", resource=("doc", "1"), subject=("user", "alice"))
        assert exc_info.value.error_code == "VAL_IDENTIFIER_FORMAT"

    def test_invalid_subject_type_raises(self, authz):
        with pytest.raises(AuthzError) as exc_info:
            authz.grant("read", resource=("doc", "1"), subject=("USER", "alice"))
        assert exc_info.value.error_code == "VAL_IDENTIFIER_FORMAT"

    def test_invalid_subject_relation_raises(self, authz):
        """grant rejects invalid subject_relation (must be lowercase identifier)."""
        with pytest.raises(AuthzError) as exc_info:
            authz.grant(
                "read",
                resource=("doc", "1"),
                subject=("team", "eng"),
                subject_relation="ADMIN",
            )
        assert exc_info.value.error_code == "VAL_IDENTIFIER_FORMAT"

    def test_empty_resource_id_raises(self, authz):
        with pytest.raises(AuthzError) as exc_info:
            authz.grant("read", resource=("doc", ""), subject=("user", "alice"))
        assert exc_info.value.error_code == "VAL_ID_EMPTY"

    def test_flexible_resource_ids_allowed(self, authz):
        # IDs can have slashes, @, uppercase - they're flexible
        authz.grant(
            "read",
            resource=("doc", "acme/doc-1"),
            subject=("user", "alice@example.com"),
        )

        assert authz.check(("user", "alice@example.com"), "read", ("doc", "acme/doc-1"))


class TestValidationEdgeCases:
    """Edge cases in input validation."""

    def test_unicode_in_ids(self, authz):
        """Unicode characters in IDs work correctly."""
        authz.grant("read", resource=("doc", "文档-1"), subject=("user", "用户-alice"))
        assert authz.check(("user", "用户-alice"), "read", ("doc", "文档-1"))

    def test_special_chars_in_ids(self, authz):
        """Special characters in IDs work correctly."""
        authz.grant(
            "read",
            resource=("doc", "path/to/doc#section?v=1"),
            subject=("user", "alice+test@example.com"),
        )
        assert authz.check(
            ("user", "alice+test@example.com"),
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
        with pytest.raises(AuthzError) as exc_info:
            authz.revoke("read", resource=("INVALID", "1"), subject=("user", "alice"))
        assert exc_info.value.error_code == "VAL_IDENTIFIER_FORMAT"

    def test_delete_rejects_invalid_relation(self, authz):
        """delete rejects invalid relation."""
        with pytest.raises(AuthzError) as exc_info:
            authz.revoke("READ", resource=("doc", "1"), subject=("user", "alice"))
        assert exc_info.value.error_code == "VAL_IDENTIFIER_FORMAT"

    def test_delete_rejects_invalid_subject_type(self, authz):
        """delete rejects invalid subject_type."""
        with pytest.raises(AuthzError) as exc_info:
            authz.revoke("read", resource=("doc", "1"), subject=("USER", "alice"))
        assert exc_info.value.error_code == "VAL_IDENTIFIER_FORMAT"

    def test_delete_rejects_empty_resource_id(self, authz):
        """delete rejects empty resource_id."""
        with pytest.raises(AuthzError) as exc_info:
            authz.revoke("read", resource=("doc", ""), subject=("user", "alice"))
        assert exc_info.value.error_code == "VAL_ID_EMPTY"

    def test_delete_rejects_empty_subject_id(self, authz):
        """delete rejects empty subject_id."""
        with pytest.raises(AuthzError) as exc_info:
            authz.revoke("read", resource=("doc", "1"), subject=("user", ""))
        assert exc_info.value.error_code == "VAL_ID_EMPTY"

    def test_delete_rejects_invalid_subject_relation(self, authz):
        """revoke rejects invalid subject_relation."""
        with pytest.raises(AuthzError) as exc_info:
            authz.revoke(
                "read",
                resource=("doc", "1"),
                subject=("team", "eng"),
                subject_relation="ADMIN",
            )
        assert exc_info.value.error_code == "VAL_IDENTIFIER_FORMAT"

    def test_delete_valid_input_succeeds(self, authz):
        """delete with valid input succeeds (even if tuple doesn't exist)."""
        # Should not raise, just return False
        result = authz.revoke("read", resource=("doc", "1"), subject=("user", "alice"))
        assert result is False


class TestNamespaceValidation:
    """Namespace must be 1-1024 chars, no control chars or leading/trailing whitespace."""

    def test_valid_namespaces(self, make_authz):
        """Valid namespace formats should be accepted."""
        valid = ["default", "tenant_123", "org:my-org", "MyOrg", "a" * 1024]
        for ns in valid:
            client = make_authz(ns)
            client.grant("read", resource=("doc", "1"), subject=("user", "alice"))
            assert client.check(("user", "alice"), "read", ("doc", "1"))

    def test_rejects_null(self, make_authz):
        with pytest.raises(AuthzError):
            make_authz(None)

    def test_rejects_empty(self, make_authz):
        with pytest.raises(AuthzError):
            make_authz("")

    def test_rejects_whitespace_only(self, make_authz):
        with pytest.raises(AuthzError):
            make_authz("   ")

    def test_rejects_leading_whitespace(self, make_authz):
        with pytest.raises(AuthzError):
            make_authz(" leading")

    def test_rejects_trailing_whitespace(self, make_authz):
        with pytest.raises(AuthzError):
            make_authz("trailing ")

    def test_rejects_control_characters(self, make_authz):
        with pytest.raises(AuthzError):
            make_authz("has\ttab")

    def test_rejects_over_max_length(self, make_authz):
        with pytest.raises(AuthzError):
            make_authz("a" * 1025)


class TestValidationErrorType:
    """Validation errors raise AuthzValidationError for precise error handling."""

    def test_null_validation_raises_authz_validation_error(self, make_authz):
        """Null validation raises AuthzValidationError (SQLSTATE 22004)."""
        with pytest.raises(AuthzValidationError) as exc_info:
            make_authz(None)
        assert exc_info.value.error_code == "VAL_NAMESPACE_NULL"

    def test_empty_validation_raises_authz_validation_error(self, make_authz):
        """Empty string validation raises AuthzValidationError (SQLSTATE 22026)."""
        with pytest.raises(AuthzValidationError) as exc_info:
            make_authz("")
        assert exc_info.value.error_code == "VAL_NAMESPACE_EMPTY"

    def test_length_validation_raises_authz_validation_error(self, make_authz):
        """Length exceeded validation raises AuthzValidationError (SQLSTATE 22001)."""
        with pytest.raises(AuthzValidationError) as exc_info:
            make_authz("a" * 1025)
        assert exc_info.value.error_code == "VAL_NAMESPACE_TOO_LONG"

    def test_format_validation_raises_authz_validation_error(self, make_authz):
        """Format validation raises AuthzValidationError (SQLSTATE 22023)."""
        with pytest.raises(AuthzValidationError) as exc_info:
            make_authz("has\ttab")
        assert exc_info.value.error_code == "VAL_NAMESPACE_INVALID_CHARS"

    def test_authz_validation_error_is_authz_error(self):
        """AuthzValidationError is a subclass of AuthzError for backwards compatibility."""
        assert issubclass(AuthzValidationError, AuthzError)
