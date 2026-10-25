"""
test_identity.py — Unit tests for identity.py.

Tests:
  - Current email resolution
  - Historical email resolution (from user_audit_log)
  - Case-insensitive email matching
  - No-match returns found=False
  - Alias list includes current + historical emails, hashes, phones
  - all_identifiers set is correctly populated
"""

import pytest
from datetime import datetime, timezone

from ghost_audit.identity import IdentityResolution, IdentityResolver
from ghost_audit.schemas import IdentifierType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

IDENTITIES = {
    "user_01": {
        "user_id": "user_01",
        "name": "Amina El-Masri",
        "email": "amina.elmasri@gmail.com",
        "phone": "+971 50 482 7316",
        "email_hash": "d4e1f59abcf9a1e0cfdc7c27ad6c07ed4ff88b326a16ed5eed5ec6bc31618c93",
        "updated_at": "2026-05-28T04:03:00Z",
    },
    "user_02": {
        "user_id": "user_02",
        "name": "Mateo Ríos",
        "email": "mateo.rios@outlook.com",
        "phone": "+34 612 847 593",
        "email_hash": "fad1c282b6b8ff346ee92e617331f69c2b6bb345af954eeb44581c57529eab9d",
        "updated_at": "2026-04-24T07:44:00Z",
    },
    "user_03": {
        "user_id": "user_03",
        "name": "Oliver Bennett",
        "email": "oliver-bennett@gmail.com",
        "phone": "+1 (202) 555-0103",
        "email_hash": "1fa7764c96e40e8570cbb7569f707f6d84c593cecbe5c1ed2b0a07a624dba039",
        "updated_at": "2026-03-14T14:21:00Z",
    },
}

# user_02 previously had email mateo.rios.old@outlook.com
# user_03 previously had email o.bennett.old@gmail.com
AUDIT_LOG = [
    {
        "audit_id": "audit_01",
        "user_id": "user_02",
        "event_time": "2025-06-01T10:00:00Z",
        "field_name": "email",
        "old_value": "mateo.rios.old@outlook.com",
        "new_value": "mateo.rios@outlook.com",
    },
    {
        "audit_id": "audit_02",
        "user_id": "user_02",
        "event_time": "2025-06-01T10:00:00Z",
        "field_name": "email_hash",
        "old_value": "oldhash_for_user_02",
        "new_value": "fad1c282b6b8ff346ee92e617331f69c2b6bb345af954eeb44581c57529eab9d",
    },
    {
        "audit_id": "audit_03",
        "user_id": "user_03",
        "event_time": "2025-09-15T08:30:00Z",
        "field_name": "email",
        "old_value": "o.bennett.old@gmail.com",
        "new_value": "oliver-bennett@gmail.com",
    },
    {
        "audit_id": "audit_04",
        "user_id": "user_01",
        "event_time": "2025-01-10T12:00:00Z",
        "field_name": "phone",
        "old_value": "+971 50 111 2222",
        "new_value": "+971 50 482 7316",
    },
]


@pytest.fixture
def resolver():
    return IdentityResolver(IDENTITIES, AUDIT_LOG, dataset_root="dataset")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCurrentEmailResolution:
    def test_resolves_current_email(self, resolver):
        r = resolver.resolve("amina.elmasri@gmail.com")
        assert r.found
        assert r.user_id == "user_01"
        assert r.match_type == "current"

    def test_case_insensitive_match(self, resolver):
        r = resolver.resolve("AMINA.ELMASRI@GMAIL.COM")
        assert r.found
        assert r.user_id == "user_01"

    def test_mixed_case_email(self, resolver):
        r = resolver.resolve("Mateo.Rios@Outlook.Com")
        assert r.found
        assert r.user_id == "user_02"

    def test_current_email_is_in_aliases(self, resolver):
        r = resolver.resolve("amina.elmasri@gmail.com")
        email_aliases = [a for a in r.aliases if a.identifier_type == IdentifierType.EMAIL]
        current_emails = [a for a in email_aliases if a.is_current]
        assert len(current_emails) == 1
        assert current_emails[0].value == "amina.elmasri@gmail.com"


class TestHistoricalEmailResolution:
    def test_resolves_historical_email(self, resolver):
        r = resolver.resolve("mateo.rios.old@outlook.com")
        assert r.found
        assert r.user_id == "user_02"
        assert r.match_type == "historical"

    def test_historical_email_in_aliases(self, resolver):
        r = resolver.resolve("mateo.rios.old@outlook.com")
        hist_aliases = [a for a in r.aliases if not a.is_current and a.identifier_type == IdentifierType.EMAIL]
        values = [a.value for a in hist_aliases]
        assert "mateo.rios.old@outlook.com" in values

    def test_historical_email_case_insensitive(self, resolver):
        r = resolver.resolve("MATEO.RIOS.OLD@OUTLOOK.COM")
        assert r.found
        assert r.user_id == "user_02"

    def test_old_phone_in_aliases(self, resolver):
        r = resolver.resolve("amina.elmasri@gmail.com")
        phones = [a for a in r.aliases if a.identifier_type == IdentifierType.PHONE]
        phone_values = [a.value for a in phones]
        # Both old and current phone should appear
        assert "+971 50 482 7316" in phone_values  # current
        assert "+971 50 111 2222" in phone_values  # historical


class TestNoMatch:
    def test_unknown_email_returns_not_found(self, resolver):
        r = resolver.resolve("nobody@nowhere.com")
        assert not r.found
        assert r.user_id is None
        assert r.match_type == "none"

    def test_aliases_empty_for_no_match(self, resolver):
        r = resolver.resolve("nobody@nowhere.com")
        assert r.aliases == []


class TestAllIdentifiers:
    def test_all_identifiers_includes_user_id(self, resolver):
        r = resolver.resolve("amina.elmasri@gmail.com")
        assert "user_01" in r.all_identifiers

    def test_all_identifiers_includes_email_hash(self, resolver):
        r = resolver.resolve("amina.elmasri@gmail.com")
        assert "d4e1f59abcf9a1e0cfdc7c27ad6c07ed4ff88b326a16ed5eed5ec6bc31618c93" in r.all_identifiers

    def test_all_identifiers_includes_historical_email(self, resolver):
        r = resolver.resolve("mateo.rios@outlook.com")
        assert "mateo.rios.old@outlook.com" in r.all_identifiers

    def test_all_emails_returns_only_emails(self, resolver):
        r = resolver.resolve("mateo.rios@outlook.com")
        emails = r.all_emails
        assert "mateo.rios@outlook.com" in emails
        assert "mateo.rios.old@outlook.com" in emails
        # No hashes or user_ids
        for e in emails:
            assert "@" in e or e == ""  # emails contain @


class TestProvenance:
    def test_current_alias_source_file(self, resolver):
        r = resolver.resolve("amina.elmasri@gmail.com")
        current = [a for a in r.aliases if a.is_current and a.identifier_type == IdentifierType.EMAIL]
        assert current[0].source_file == "dataset/user_identities.csv"
        assert current[0].source_row_id == "user_01"

    def test_historical_alias_source_row_id(self, resolver):
        r = resolver.resolve("mateo.rios@outlook.com")
        historical = [a for a in r.aliases if not a.is_current and a.identifier_type == IdentifierType.EMAIL]
        assert historical[0].source_row_id == "audit_01"
