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
