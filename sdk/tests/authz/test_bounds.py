import pytest
from postkit.authz import AuthzValidationError


def test_every_bounded_authz_api_rejects_max_plus_one(authz):
    calls = (
        (
            lambda: authz.bulk_grant(
                "read",
                resource=("doc", "one"),
                subjects=[("user", f"u{i}") for i in range(1001)],
            ),
            "VAL_BATCH_TOO_LARGE",
        ),
        (
            lambda: authz.bulk_grant_resources(
                "read",
                resource_type="doc",
                resource_ids=[f"d{i}" for i in range(1001)],
                subject=("user", "alice"),
            ),
            "VAL_BATCH_TOO_LARGE",
        ),
        (
            lambda: authz.check_any(("user", "alice"), ["read"] * 1001, ("doc", "one")),
            "VAL_BATCH_TOO_LARGE",
        ),
        (
            lambda: authz.check_all(("user", "alice"), ["read"] * 1001, ("doc", "one")),
            "VAL_BATCH_TOO_LARGE",
        ),
        (
            lambda: authz.list_resources(("user", "alice"), "doc", "read", limit=1001),
            "VAL_LIMIT_TOO_LARGE",
        ),
        (
            lambda: authz.list_subjects("read", ("doc", "one"), limit=1001),
            "VAL_LIMIT_TOO_LARGE",
        ),
        (
            lambda: authz.filter_authorized(
                ("user", "alice"), "doc", "read", ["missing"] * 1001
            ),
            "VAL_BATCH_TOO_LARGE",
        ),
    )
    for call, code in calls:
        with pytest.raises(AuthzValidationError) as exc_info:
            call()
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == code


def test_filter_authorized_accepts_exact_batch_maximum_without_writes(authz):
    assert (
        authz.filter_authorized(
            ("user", "alice"), "doc", "read", [f"missing-{i}" for i in range(1000)]
        )
        == []
    )


def test_bulk_grant_exact_max_succeeds_and_oversize_is_atomic(authz):
    subjects = [("user", f"subject-{i}") for i in range(1000)]
    assert (
        authz.bulk_grant("read", resource=("doc", "bounds"), subjects=subjects) == 1000
    )
    with pytest.raises(AuthzValidationError):
        authz.bulk_grant(
            "write",
            resource=("doc", "atomic"),
            subjects=[("user", f"oversized-{i}") for i in range(1001)],
        )
    assert not authz.check(("user", "oversized-0"), "write", ("doc", "atomic"))
    assert not authz.check(("user", "oversized-1000"), "write", ("doc", "atomic"))


def test_authz_scalar_bounds_reject_nonpositive(authz):
    for bad in (None, 0, -1):
        with pytest.raises(AuthzValidationError) as exc_info:
            authz.list_resources(("user", "alice"), "doc", "read", limit=bad)
        assert exc_info.value.sqlstate == "22023"
        assert exc_info.value.error_code == "VAL_NOT_POSITIVE"
