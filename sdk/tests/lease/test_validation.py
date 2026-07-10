"""Input validation tests across the lease surface."""

import pytest
from postkit.lease import (
    LeaseError,
    LeaseErrorCode,
    LeaseFencingError,
    LeaseValidationError,
)

from tests.helpers import (
    ACCEPTED_NAMES,
    NAMESPACE_ERROR_CASES,
    VALID_NAMESPACES,
    name_error_cases,
)


class TestNamespaceValidation:
    """Namespace must be 1-1024 chars, no control chars or edge whitespace."""

    def test_valid_namespaces(self, make_lease):
        for ns in VALID_NAMESPACES:
            client = make_lease(ns)
            assert client.acquire("job", "w1")["acquired"] is True

    @pytest.mark.parametrize(("ns", "error_code_name"), NAMESPACE_ERROR_CASES)
    def test_namespace_validation_raises_correct_error(
        self, make_lease, ns, error_code_name
    ):
        with pytest.raises(LeaseValidationError) as exc_info:
            make_lease(ns)
        assert exc_info.value.error_code == getattr(LeaseErrorCode, error_code_name)

    def test_error_hierarchy(self):
        assert issubclass(LeaseValidationError, LeaseError)
        assert issubclass(LeaseFencingError, LeaseError)


class TestNameAndHolderValidation:
    def test_lease_name_permissive_charset(self, lease):
        """Names with :, /, . are legal – 'exporter:cust_42' is the canonical
        example (queue-style strict charsets would reject it)."""
        got = lease.acquire("exporter:cust_42/eu.west", "w1")
        assert got["acquired"] is True

    @pytest.mark.parametrize(
        ("name", "code"),
        [
            (None, LeaseErrorCode.VAL_LEASE_NAME_NULL),
            ("", LeaseErrorCode.VAL_LEASE_NAME_EMPTY),
            ("a" * 1025, LeaseErrorCode.VAL_LEASE_NAME_TOO_LONG),
        ],
    )
    def test_bad_lease_names(self, lease, name, code):
        with pytest.raises(LeaseValidationError) as exc_info:
            lease.acquire(name, "w1")
        assert exc_info.value.error_code == code

    @pytest.mark.parametrize(
        ("holder", "code"),
        [
            (None, LeaseErrorCode.VAL_HOLDER_NULL),
            ("", LeaseErrorCode.VAL_HOLDER_EMPTY),
            ("a" * 1025, LeaseErrorCode.VAL_HOLDER_TOO_LONG),
        ],
    )
    def test_bad_holders(self, lease, holder, code):
        with pytest.raises(LeaseValidationError) as exc_info:
            lease.acquire("job", holder)
        assert exc_info.value.error_code == code

    @pytest.mark.parametrize(("name", "code_name"), name_error_cases("VAL_LEASE_NAME"))
    def test_lease_name_violations(self, lease, name, code_name):
        with pytest.raises(LeaseValidationError) as exc_info:
            lease.acquire(name, "w1")
        assert exc_info.value.error_code == getattr(LeaseErrorCode, code_name)

    @pytest.mark.parametrize(("holder", "code_name"), name_error_cases("VAL_HOLDER"))
    def test_holder_violations(self, lease, holder, code_name):
        with pytest.raises(LeaseValidationError) as exc_info:
            lease.acquire("job", holder)
        assert exc_info.value.error_code == getattr(LeaseErrorCode, code_name)

    @pytest.mark.parametrize("name", ACCEPTED_NAMES)
    def test_flexible_names_accepted(self, lease, name):
        assert lease.acquire(name, name)["acquired"] is True

    def test_null_fence_rejected(self, lease):
        lease.acquire("job", "w1")
        with pytest.raises(LeaseValidationError) as exc_info:
            lease.renew("job", "w1", None)
        assert exc_info.value.error_code == LeaseErrorCode.VAL_FENCE_NULL

        with pytest.raises(LeaseValidationError) as exc_info:
            with lease.cursor.connection.transaction():
                lease.verify("job", "w1", None)
        assert exc_info.value.error_code == LeaseErrorCode.VAL_FENCE_NULL

        with pytest.raises(LeaseValidationError) as exc_info:
            lease.release("job", "w1", None)
        assert exc_info.value.error_code == LeaseErrorCode.VAL_FENCE_NULL
