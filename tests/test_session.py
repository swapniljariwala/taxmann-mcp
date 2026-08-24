"""
v0.4 tests — stateless session manager.

Covers _CachedTaxMann (machine-ID + client-IP class caches), credential
loading/decryption, the login → call → logout lifecycle, error mapping, and
per-uid serialization of concurrent calls.
"""

import asyncio
import os
import time
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

import main
from taxmann.exceptions import AuthError, DocumentError, SearchError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _StubResponse:
    """Minimal requests-like response for stubbing SDK network calls."""

    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


def _set_user_creds(db, uid, email, enc_blob):
    """Point /users/{uid} at a doc carrying (email, encrypted password)."""
    doc = MagicMock()
    doc.exists = True
    doc.to_dict.return_value = {
        "taxmann_email": email,
        "taxmann_enc_password": enc_blob,
    }
    db.collection.return_value.document.return_value.get.return_value = doc
    return doc


def _set_missing_user(db, uid):
    """Point /users/{uid} at a non-existent doc."""
    doc = MagicMock()
    doc.exists = False
    doc.to_dict.return_value = {}
    db.collection.return_value.document.return_value.get.return_value = doc


class FakeTaxMann:
    """Drop-in for main._CachedTaxMann that records the login/logout cycle."""

    instances = []

    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.login_called = False
        self.logout_called = False
        FakeTaxMann.instances.append(self)

    def login(self):
        self.login_called = True

    def logout(self):
        self.logout_called = True


class AuthErrorTaxMann(FakeTaxMann):
    def login(self):
        self.login_called = True
        raise AuthError("Invalid credentials provided")


class FailingLogoutTaxMann(FakeTaxMann):
    def logout(self):
        super().logout()
        raise RuntimeError("network down")


@pytest.fixture(autouse=True)
def reset_locks():
    """Fresh per-uid lock table for every test (module-global otherwise)."""
    main._LOCKS.clear()
    yield


# ---------------------------------------------------------------------------
# 1. _CachedTaxMann — machine-ID cache
# ---------------------------------------------------------------------------

def test_cached_taxmann_machine_id_fetched_once(monkeypatch):
    monkeypatch.setattr(main.TaxMann, "_fetch_secret_key", lambda self: "fake-key")
    monkeypatch.setattr(main._CachedTaxMann, "_machine_id_cache", None)
    calls = {"n": 0}

    def fake_fetch_machine_id(self):
        calls["n"] += 1
        return f"mid-{calls['n']}"

    monkeypatch.setattr(main.TaxMann, "_fetch_machine_id", fake_fetch_machine_id)

    c1 = main._CachedTaxMann("user@example.com", "pw")
    c2 = main._CachedTaxMann("user@example.com", "pw")

    assert calls["n"] == 1  # fetched once, not once per instance
    assert c1._machine_id == c2._machine_id == "mid-1"
    assert main._CachedTaxMann._machine_id_cache == "mid-1"


# ---------------------------------------------------------------------------
# 2. _CachedTaxMann — client-IP cache (fresh short-circuits, expiry refetches)
# ---------------------------------------------------------------------------

def test_cached_taxmann_ip_cache_fresh_short_circuits(monkeypatch):
    monkeypatch.setattr(main._CachedTaxMann, "_client_ip_cache", "203.0.113.7")
    monkeypatch.setattr(main._CachedTaxMann, "_client_ip_ts", time.monotonic())

    class FakeSession:
        def __init__(self):
            self.headers = {}

        def post(self, url, *args, **kwargs):
            raise AssertionError(f"cached login must not hit the network: {url}")

    def fake_super_login(self):
        # Mirrors the SDK's getclientipbydomain step inside login().
        resp = self._session.post(
            main._CLIENT_IP_URL,
            json={"domainname": "stag.taxmann.ai"},
            timeout=10,
        )
        assert resp.status_code == 200
        assert resp.json() == {"data": ["203.0.113.7"]}  # served from cache
        self._ip_address = resp.json()["data"][0]

    monkeypatch.setattr(main.TaxMann, "login", fake_super_login)

    client = object.__new__(main._CachedTaxMann)
    client._session = FakeSession()
    client._ip_address = None

    client.login()

    assert client._ip_address == "203.0.113.7"


def test_cached_taxmann_ip_cache_expired_refetches(monkeypatch):
    monkeypatch.setattr(main._CachedTaxMann, "_client_ip_cache", "203.0.113.7")
    monkeypatch.setattr(main._CachedTaxMann, "_client_ip_ts", time.monotonic() - 7200)

    class FakeSession:
        def __init__(self):
            self.headers = {}
            self.post_calls = []

        def post(self, url, *args, **kwargs):
            self.post_calls.append(url)
            return _StubResponse(payload={"data": ["198.51.100.9", "0"]})

    def fake_super_login(self):
        resp = self._session.post(
            main._CLIENT_IP_URL,
            json={"domainname": "stag.taxmann.ai"},
            timeout=10,
        )
        self._ip_address = resp.json()["data"][0]

    monkeypatch.setattr(main.TaxMann, "login", fake_super_login)

    client = object.__new__(main._CachedTaxMann)
    client._session = FakeSession()
    client._ip_address = None

    client.login()

    assert client._session.post_calls == [main._CLIENT_IP_URL]  # real network hit
    assert client._ip_address == "198.51.100.9"
    # Cache refreshed with the freshly resolved IP.
    assert main._CachedTaxMann._client_ip_cache == "198.51.100.9"


# ---------------------------------------------------------------------------
# 3. _stateless_call happy path
# ---------------------------------------------------------------------------

async def test_stateless_call_happy_path(monkeypatch, db):
    dek = os.urandom(32)
    monkeypatch.setattr(main, "_dek", dek)
    _set_user_creds(db, "u1", "user@example.com", main._encrypt_password("pw", dek))
    monkeypatch.setattr(main, "_CachedTaxMann", FakeTaxMann)
    FakeTaxMann.instances = []

    result = await main._stateless_call("u1", lambda client: client.email)

    assert result == "user@example.com"
    inst = FakeTaxMann.instances[0]
    assert inst.login_called
    assert inst.logout_called  # session slot always released


# ---------------------------------------------------------------------------
# 4. Missing creds → 403
# ---------------------------------------------------------------------------

async def test_stateless_call_missing_creds_403(monkeypatch, db):
    _set_missing_user(db, "u1")
    monkeypatch.setattr(main, "_CachedTaxMann", object)  # must never be reached

    with pytest.raises(HTTPException) as exc:
        await main._stateless_call("u1", lambda client: None)

    assert exc.value.status_code == 403
    assert "No TaxMann credentials configured" in exc.value.detail


# ---------------------------------------------------------------------------
# 5. AuthError on login → 403 "invalid or expired"
# ---------------------------------------------------------------------------

async def test_stateless_call_auth_error_403(monkeypatch, db):
    dek = os.urandom(32)
    monkeypatch.setattr(main, "_dek", dek)
    _set_user_creds(db, "u1", "user@example.com", main._encrypt_password("pw", dek))
    monkeypatch.setattr(main, "_CachedTaxMann", AuthErrorTaxMann)

    with pytest.raises(HTTPException) as exc:
        await main._stateless_call("u1", lambda client: None)

    assert exc.value.status_code == 403
    assert "invalid or expired" in exc.value.detail


# ---------------------------------------------------------------------------
# 6. SearchError from fn → 502 with message
# ---------------------------------------------------------------------------

async def test_stateless_call_search_error_502(monkeypatch, db):
    dek = os.urandom(32)
    monkeypatch.setattr(main, "_dek", dek)
    _set_user_creds(db, "u1", "user@example.com", main._encrypt_password("pw", dek))
    monkeypatch.setattr(main, "_CachedTaxMann", FakeTaxMann)

    def boom(client):
        raise SearchError("search exploded")

    with pytest.raises(HTTPException) as exc:
        await main._stateless_call("u1", boom)

    assert exc.value.status_code == 502
    assert "Search failed: search exploded" in exc.value.detail


# ---------------------------------------------------------------------------
# 6b. DocumentError DOCUMENT_ACCESS_LIMIT_EXCEED / 503 → session-limit 502
# ---------------------------------------------------------------------------

async def test_stateless_call_document_limit_exceeded_502(monkeypatch, db):
    dek = os.urandom(32)
    monkeypatch.setattr(main, "_dek", dek)
    _set_user_creds(db, "u1", "user@example.com", main._encrypt_password("pw", dek))
    monkeypatch.setattr(main, "_CachedTaxMann", FakeTaxMann)

    def boom(client):
        raise DocumentError("DOCUMENT_ACCESS_LIMIT_EXCEED (503)")

    with pytest.raises(HTTPException) as exc:
        await main._stateless_call("u1", boom)

    assert exc.value.status_code == 502
    assert "session limit reached" in exc.value.detail


# ---------------------------------------------------------------------------
# 7. Logout failure never masks the tool result
# ---------------------------------------------------------------------------

async def test_stateless_call_logout_failure_does_not_mask_success(monkeypatch, db):
    dek = os.urandom(32)
    monkeypatch.setattr(main, "_dek", dek)
    _set_user_creds(db, "u1", "user@example.com", main._encrypt_password("pw", dek))
    monkeypatch.setattr(main, "_CachedTaxMann", FailingLogoutTaxMann)

    result = await main._stateless_call("u1", lambda client: "ok")

    assert result == "ok"


# ---------------------------------------------------------------------------
# 8. Per-uid lock serializes concurrent calls for the same account
# ---------------------------------------------------------------------------

async def test_stateless_call_serializes_same_uid(monkeypatch, db):
    dek = os.urandom(32)
    monkeypatch.setattr(main, "_dek", dek)
    _set_user_creds(db, "user-123", "user@example.com", main._encrypt_password("pw", dek))

    events = []

    class SlowTaxMann:
        def __init__(self, email, password):
            pass

        def login(self):
            events.append(("start", time.monotonic()))
            time.sleep(0.05)
            events.append(("end", time.monotonic()))

        def logout(self):
            pass

    monkeypatch.setattr(main, "_CachedTaxMann", SlowTaxMann)
    main._LOCKS.clear()  # fresh per-uid lock for a deterministic run

    async def call(query):
        return await main._stateless_call("user-123", lambda client: query)

    r1, r2 = await asyncio.gather(call("first"), call("second"))

    assert {r1, r2} == {"first", "second"}
    kinds = [kind for kind, _ in events]
    assert kinds == ["start", "end", "start", "end"]  # strict alternation → no overlap
