import time

import pytest
from postkit.authz import AuthzClient

from tests.helpers import make_namespace


@pytest.mark.scale
def test_list_resources_scales_across_overlapping_hierarchies(connect, request):
    connection = connect(statement_timeout_ms=30_000)
    authz = AuthzClient(connection.cursor(), make_namespace(request))
    subject = ("user", "scale-reader")
    expected: set[str] = set()

    for i in range(500):
        resource_id = f"direct-{i:04d}"
        authz.grant("read", resource=("doc", resource_id), subject=subject)
        expected.add(resource_id)

    root = ("folder", "broad-root")
    authz.grant("read", resource=root, subject=subject)
    for branch_index in range(40):
        branch = ("folder", f"branch-{branch_index:02d}")
        authz.grant("parent", resource=branch, subject=root)
        if branch_index < 20:
            authz.grant("read", resource=branch, subject=subject)

        for doc_index in range(25):
            resource_id = f"broad-{branch_index:02d}-{doc_index:02d}"
            doc = ("doc", resource_id)
            authz.grant("parent", resource=doc, subject=branch)
            if doc_index == 0:
                authz.grant("read", resource=doc, subject=subject)
            expected.add(resource_id)

    deep_root = ("folder", "deep-00")
    authz.grant("read", resource=deep_root, subject=subject)
    parent = deep_root
    for depth in range(1, 31):
        child = ("folder", f"deep-{depth:02d}")
        authz.grant("parent", resource=child, subject=parent)
        parent = child

    deep_doc = "deep-leaf"
    authz.grant("parent", resource=("doc", deep_doc), subject=parent)
    expected.add(deep_doc)

    listed: list[str] = []
    cursor = None
    started = time.monotonic()
    while True:
        page = authz.list_resources(subject, "doc", "read", limit=200, cursor=cursor)
        listed.extend(page)
        if len(page) < 200:
            break
        cursor = page[-1]
    elapsed = time.monotonic() - started

    assert listed == sorted(expected)
    assert len(listed) == len(set(listed))
    assert elapsed < 10.0, (
        f"public listing pagination took {elapsed:.2f}s for {len(expected)} resources"
    )


@pytest.mark.scale
def test_list_subjects_scales_across_many_direct_grantees(connect, request):
    connection = connect(statement_timeout_ms=30_000)
    authz = AuthzClient(connection.cursor(), make_namespace(request))
    expected = [("user", f"grantee-{i:05d}") for i in range(20_000)]

    for offset in range(0, len(expected), 1000):
        authz.bulk_grant(
            "read",
            resource=("doc", "shared"),
            subjects=expected[offset : offset + 1000],
        )

    listed = []
    cursor = None
    started = time.monotonic()
    while True:
        page = authz.list_subjects("read", ("doc", "shared"), limit=1000, cursor=cursor)
        listed.extend(page)
        if len(page) < 1000:
            break
        cursor = page[-1]
    count = authz.count_subjects("read", ("doc", "shared"))
    elapsed = time.monotonic() - started

    assert listed == expected
    assert len(listed) == len(set(listed))
    assert count == len(expected)
    assert elapsed < 30.0, (
        f"public subject pagination took {elapsed:.2f}s for {len(expected)} grantees"
    )


@pytest.mark.scale
def test_sparse_subject_listing_ignores_unrelated_memberships(connect, request):
    namespace = make_namespace(request)
    setup_connection = connect(statement_timeout_ms=30_000)
    setup_authz = AuthzClient(setup_connection.cursor(), namespace)

    for offset in range(0, 200_000, 1000):
        setup_authz.bulk_grant_resources(
            "member",
            resource_type="team",
            resource_ids=[f"unrelated-{i:06d}" for i in range(offset, offset + 1000)],
            subject=("user", "unrelated-member"),
        )
    setup_authz.grant(
        "read", resource=("doc", "shared"), subject=("user", "only-grantee")
    )
    setup_connection.commit()

    worker_connection = connect(statement_timeout_ms=5_000)
    worker_authz = AuthzClient(worker_connection.cursor(), namespace)

    started = time.monotonic()
    for _ in range(5):
        assert worker_authz.list_subjects("read", ("doc", "shared")) == [
            ("user", "only-grantee")
        ]
        assert worker_authz.count_subjects("read", ("doc", "shared")) == 1
    elapsed = time.monotonic() - started

    assert elapsed < 1.5, f"five sparse subject list/count pairs took {elapsed:.2f}s"
