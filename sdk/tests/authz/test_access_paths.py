def test_checks_resolve_each_public_access_path(authz):
    subject = ("user", "alice")
    authz.set_hierarchy("doc", "admin", "read")
    authz.grant("read", resource=("doc", "direct"), subject=subject)
    authz.grant("admin", resource=("doc", "implied"), subject=subject)
    authz.grant("parent", resource=("doc", "inherited"), subject=("folder", "shared"))
    authz.grant("read", resource=("folder", "shared"), subject=subject)
    authz.grant("member", resource=("team", "eng"), subject=subject)
    authz.grant("read", resource=("doc", "group"), subject=("team", "eng"))
    assert authz.check(subject, "read", ("doc", "direct"))
    assert authz.check(subject, "read", ("doc", "implied"))
    assert authz.check(subject, "read", ("doc", "inherited"))
    assert authz.check(subject, "read", ("doc", "group"))
    assert not authz.check(subject, "read", ("doc", "denied"))
    assert authz.check_any(subject, ["write", "read"], ("doc", "implied"))

    candidates = ["direct", "implied", "inherited", "group", "denied"]
    assert authz.filter_authorized(subject, "doc", "read", candidates) == [
        "direct",
        "group",
        "implied",
        "inherited",
    ]
