"""Canonical-equivalence matching of authz principal ids.

Principal ids (subject_id, resource_id) are matched by Unicode canonical
equivalence (the authz.canonical collation), so a grant written in one
normalization form is found by a check, revoke, transfer, or expiry call
arriving in a canonically-equal form. A revoke arriving in a different
normalization form would otherwise miss the grant and leave it live.
Stored bytes are never rewritten: callers read back exactly what they wrote.
"""

from datetime import datetime, timedelta, timezone

import pytest
from postkit.authz import AuthzCycleError

# "café" in two canonically-equal encodings.
NFD = "cafe" + chr(0x301)  # c a f e + U+0301 combining acute
NFC = "caf" + chr(0xE9)  # c a f + U+00E9 precomposed é


class TestCanonicalEquivalence:
    def test_check_matches_across_normalization(self, authz):
        authz.grant("read", resource=("doc", "x"), subject=("user", NFD))
        assert authz.check(("user", NFC), "read", ("doc", "x")) is True

    def test_revoke_matches_across_normalization(self, authz):
        authz.grant("read", resource=("doc", "x"), subject=("user", NFD))
        assert (
            authz.revoke("read", resource=("doc", "x"), subject=("user", NFC)) is True
        )
        assert authz.check(("user", NFD), "read", ("doc", "x")) is False

    def test_consistent_nfd_caller_not_regressed(self, authz):
        authz.grant("read", resource=("doc", "y"), subject=("user", NFD))
        assert authz.check(("user", NFD), "read", ("doc", "y")) is True

    def test_transfer_matches_nfd_source(self, authz):
        authz.grant("read", resource=("doc", "z"), subject=("user", NFD))
        assert (
            authz.transfer_grant(
                "read",
                resource=("doc", "z"),
                from_subject=("user", NFC),
                to_subject=("user", "bob"),
            )
            is True
        )
        assert authz.check(("user", "bob"), "read", ("doc", "z")) is True
        assert authz.check(("user", NFD), "read", ("doc", "z")) is False

    def test_self_transfer_across_forms_is_noop(self, authz):
        authz.grant("read", resource=("doc", "s"), subject=("user", NFD))
        assert (
            authz.transfer_grant(
                "read",
                resource=("doc", "s"),
                from_subject=("user", NFC),
                to_subject=("user", NFD),
            )
            is True
        )
        assert authz.check(("user", NFD), "read", ("doc", "s")) is True

    def test_set_expiration_matches_nfd_grant(self, authz):
        authz.grant("read", resource=("doc", "e"), subject=("user", NFD))
        future = datetime.now(timezone.utc) + timedelta(days=1)
        assert (
            authz.set_expiration(
                "read", resource=("doc", "e"), subject=("user", NFC), expires_at=future
            )
            is True
        )

    def test_list_grants_matches_across_normalization(self, authz):
        authz.grant("read", resource=("doc", "l"), subject=("user", NFD))
        grants = authz.list_grants(("user", NFC))
        assert ("doc", "l") in [g["resource"] for g in grants]

    def test_canonical_duplicate_collapses(self, authz):
        authz.grant("read", resource=("doc", "d"), subject=("user", NFD))
        authz.grant("read", resource=("doc", "d"), subject=("user", NFC))
        assert len(authz.list_grants(("user", NFC))) == 1

    def test_stored_bytes_round_trip(self, authz):
        authz.grant("read", resource=("doc", NFD), subject=("user", "alice"))
        grants = authz.list_grants(("user", "alice"))
        assert [g["resource"] for g in grants] == [("doc", NFD)]

    def test_cursor_matches_across_normalization(self, authz):
        authz.grant("read", resource=("doc", NFD), subject=("user", "alice"))
        authz.grant("read", resource=("doc", "zzz"), subject=("user", "alice"))
        page = authz.list_resources(("user", "alice"), "doc", "read", cursor=NFC)
        assert page == ["zzz"]

    def test_self_membership_guard_across_forms(self, authz):
        with pytest.raises(AuthzCycleError):
            authz.grant("member", resource=("team", NFD), subject=("team", NFC))

    def test_external_resources_match_across_forms(self, make_authz):
        org_a = make_authz("canon-ext-a")
        org_b = make_authz("canon-ext-b")
        org_a.grant("view", resource=("note", "n1"), subject=("user", NFD))
        shared = org_b.list_external_resources(("user", NFC), "note", "view")
        assert [(s["namespace"], s["resource_id"]) for s in shared] == [
            ("canon-ext-a", "n1")
        ]

    def test_audit_filter_matches_across_forms(self, authz):
        authz.grant("read", resource=("doc", "a1"), subject=("user", NFD))
        events = authz.get_audit_events(subject=("user", NFC))
        assert len(events) >= 1
