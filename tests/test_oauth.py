"""
v0.5 tests — OAuth 2.0 Authorization Code + PKCE endpoints and the /mcp auth
middleware.

Drives the real FastAPI routes through TestClient. The conftest autouse
reset_main_globals provides a fresh main._db / main.storage.bucket /
_user_uid ContextVar per test.

Covers:
  GET  /.well-known/oauth-protected-resource
  GET  /.well-known/oauth-authorization-server
  POST /oauth/register
  GET  /auth/authorize
  POST /auth/complete
  POST /auth/token
  /mcp middleware (401 without Bearer; pass-through with a valid session)
"""

import base64
import hashlib
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

import main
from conftest import make_mock_firestore_doc


def _client() -> TestClient:
    return TestClient(main.app)


def make_pkce_pair():
    """Return a valid (code_verifier, code_challenge) PKCE S256 pair (RFC 7636 B)."""
    verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    digest    = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

class TestProtectedResource:
    def test_returns_resource_and_auth_server(self):
        with _client() as client:
            resp = client.get("/.well-known/oauth-protected-resource")
        assert resp.status_code == 200
        body = resp.json()
        assert body["resource"].endswith("/mcp")
        assert len(body["authorization_servers"]) == 1

    def test_base_url_honours_forwarded_proto(self):
        with _client() as client:
            resp = client.get(
                "/.well-known/oauth-protected-resource",
                headers={"X-Forwarded-Proto": "https"},
            )
        assert resp.status_code == 200
        assert resp.json()["resource"].startswith("https://")


class TestAuthServerMetadata:
    def test_returns_required_fields(self):
        with _client() as client:
            resp = client.get("/.well-known/oauth-authorization-server")
        assert resp.status_code == 200
        data = resp.json()
        assert data["authorization_endpoint"].endswith("/auth/authorize")
        assert data["token_endpoint"].endswith("/auth/token")
        assert data["registration_endpoint"].endswith("/oauth/register")
        assert "S256" in data["code_challenge_methods_supported"]
        assert "authorization_code" in data["grant_types_supported"]
        assert "code" in data["response_types_supported"]


class TestOAuthRegister:
    def test_registers_dynamic_client(self):
        with _client() as client:
            resp = client.post("/oauth/register", json={
                "redirect_uris": ["http://localhost:12345/callback"],
                "grant_types":   ["authorization_code"],
                "response_types": ["code"],
            })
        assert resp.status_code == 201
        body = resp.json()
        assert body["client_id"]
        assert body["token_endpoint_auth_method"] == "none"
        assert body["redirect_uris"] == ["http://localhost:12345/callback"]
        assert body["grant_types"] == ["authorization_code"]


# ---------------------------------------------------------------------------
# /auth/authorize
# ---------------------------------------------------------------------------

class TestAuthorize:
    _QUERY = {
        "redirect_uri":          "http://localhost:12345/callback",
        "code_challenge":        "abc123challenge",
        "code_challenge_method": "S256",
        "state":                 "random-state",
        "client_id":             "claude-desktop",
    }

    def test_redirects_to_portal_with_request_id(self, db):
        col = MagicMock()
        db.collection.return_value = col

        with _client() as client:
            resp = client.get("/auth/authorize", params=self._QUERY, follow_redirects=False)

        assert resp.status_code == 302
        assert "auth_request_id=" in resp.headers["location"]
        col.document.return_value.set.assert_called_once()

    def test_stores_oauth_request_in_firestore(self, db):
        col = MagicMock()
        db.collection.return_value = col

        with _client() as client:
            client.get("/auth/authorize", params=self._QUERY, follow_redirects=False)

        stored = col.document.return_value.set.call_args[0][0]
        assert stored["redirect_uri"] == "http://localhost:12345/callback"
        assert stored["code_challenge"] == "abc123challenge"
        assert stored["code_challenge_method"] == "S256"
        assert stored["state"] == "random-state"
        assert stored["client_id"] == "claude-desktop"

    def test_missing_redirect_uri_returns_422(self):
        # FastAPI query validation, not the handler: redirect_uri is required.
        with _client() as client:
            resp = client.get("/auth/authorize", params={"code_challenge": "abc"})
        assert resp.status_code == 422

    def test_missing_code_challenge_returns_422(self):
        with _client() as client:
            resp = client.get(
                "/auth/authorize",
                params={"redirect_uri": "http://localhost/callback"},
            )
        assert resp.status_code == 422

    def test_non_s256_method_returns_400(self):
        with _client() as client:
            resp = client.get(
                "/auth/authorize",
                params={**self._QUERY, "code_challenge_method": "plain"},
            )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /auth/complete
# ---------------------------------------------------------------------------

class TestAuthComplete:
    def _make_request_doc(self, age_seconds=0):
        created_at = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
        return make_mock_firestore_doc({
            "redirect_uri":   "http://localhost:12345/callback",
            "code_challenge": "abc123challenge",
            "state":          "my-state",
            "created_at":     created_at,
        })

    def _verify_uid(self, monkeypatch, uid="user-abc"):
        monkeypatch.setattr(main.fb_auth, "verify_id_token", lambda token: {"uid": uid})

    def test_success_returns_code_and_state(self, monkeypatch, db):
        self._verify_uid(monkeypatch)
        req_doc   = self._make_request_doc()
        codes_col = MagicMock()
        reqs_col  = MagicMock()
        reqs_col.document.return_value.get.return_value = req_doc

        def col_side_effect(name):
            return codes_col if name == "auth_codes" else reqs_col
        db.collection.side_effect = col_side_effect

        with _client() as client:
            resp = client.post("/auth/complete", json={
                "auth_request_id":   "req-1",
                "firebase_id_token": "valid-fb-token",
            })

        assert resp.status_code == 200
        body = resp.json()
        assert "code" in body
        assert body["state"] == "my-state"
        assert body["redirect_uri"] == "http://localhost:12345/callback"

    def test_stores_code_hash_not_raw_code(self, monkeypatch, db):
        self._verify_uid(monkeypatch)
        req_doc   = self._make_request_doc()
        codes_col = MagicMock()
        reqs_col  = MagicMock()
        reqs_col.document.return_value.get.return_value = req_doc

        def col_side_effect(name):
            return codes_col if name == "auth_codes" else reqs_col
        db.collection.side_effect = col_side_effect

        with _client() as client:
            resp = client.post("/auth/complete", json={
                "auth_request_id":   "req-1",
                "firebase_id_token": "valid",
            })

        raw_code  = resp.json()["code"]
        code_hash = hashlib.sha256(raw_code.encode()).hexdigest()
        stored_key = codes_col.document.call_args[0][0]
        assert stored_key == code_hash

    def test_invalid_firebase_token_returns_401(self, monkeypatch):
        def boom(token):
            raise Exception("bad token")
        monkeypatch.setattr(main.fb_auth, "verify_id_token", boom)

        with _client() as client:
            resp = client.post("/auth/complete", json={
                "auth_request_id":   "req-1",
                "firebase_id_token": "bad-token",
            })
        assert resp.status_code == 401

    def test_unknown_request_id_returns_400(self, monkeypatch, db):
        self._verify_uid(monkeypatch)
        db.collection.return_value.document.return_value.get.return_value = \
            make_mock_firestore_doc({}, exists=False)

        with _client() as client:
            resp = client.post("/auth/complete", json={
                "auth_request_id":   "unknown",
                "firebase_id_token": "valid",
            })
        assert resp.status_code == 400

    def test_expired_request_returns_400(self, monkeypatch, db):
        self._verify_uid(monkeypatch)
        expired_doc = self._make_request_doc(age_seconds=700)  # > 600s TTL
        db.collection.return_value.document.return_value.get.return_value = expired_doc

        with _client() as client:
            resp = client.post("/auth/complete", json={
                "auth_request_id":   "req-1",
                "firebase_id_token": "valid",
            })
        assert resp.status_code == 400
        assert "expired" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# /auth/token
# ---------------------------------------------------------------------------

class TestToken:
    def _setup_valid_code(self, db, verifier, challenge, age_seconds=0):
        """Put a valid, unused auth code doc into the mock db."""
        created_at = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
        raw_code  = "raw-auth-code"
        code_hash = hashlib.sha256(raw_code.encode()).hexdigest()

        code_doc = make_mock_firestore_doc({
            "uid":            "user-abc",
            "redirect_uri":   "http://localhost:12345/callback",
            "code_challenge": challenge,
            "created_at":     created_at,
            "used":           False,
        })

        sessions_col = MagicMock()
        codes_col    = MagicMock()
        codes_col.document.return_value.get.return_value = code_doc

        def col_side_effect(name):
            return codes_col if name == "auth_codes" else sessions_col
        db.collection.side_effect = col_side_effect
        return raw_code, sessions_col

    def test_success_returns_access_token(self, db):
        verifier, challenge = make_pkce_pair()
        raw_code, _ = self._setup_valid_code(db, verifier, challenge)

        with _client() as client:
            resp = client.post("/auth/token", data={
                "grant_type":    "authorization_code",
                "code":          raw_code,
                "code_verifier": verifier,
                "redirect_uri":  "http://localhost:12345/callback",
            })

        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"

    def test_access_token_hash_stored_in_sessions(self, db):
        verifier, challenge = make_pkce_pair()
        raw_code, sessions_col = self._setup_valid_code(db, verifier, challenge)

        with _client() as client:
            resp = client.post("/auth/token", data={
                "grant_type":    "authorization_code",
                "code":          raw_code,
                "code_verifier": verifier,
            })

        access_token = resp.json()["access_token"]
        token_hash   = hashlib.sha256(access_token.encode()).hexdigest()
        stored_key   = sessions_col.document.call_args[0][0]
        assert stored_key == token_hash

    def test_wrong_grant_type_returns_400(self):
        # All Form fields are required by FastAPI, so supply them all.
        with _client() as client:
            resp = client.post("/auth/token", data={
                "grant_type":    "implicit",
                "code":          "whatever",
                "code_verifier": "whatever",
            })
        assert resp.status_code == 400

    def test_unknown_code_returns_400(self, db):
        db.collection.return_value.document.return_value.get.return_value = \
            make_mock_firestore_doc({}, exists=False)

        with _client() as client:
            resp = client.post("/auth/token", data={
                "grant_type":    "authorization_code",
                "code":          "unknown-code",
                "code_verifier": "verifier",
            })
        assert resp.status_code == 400

    def test_already_used_code_returns_400(self, db):
        verifier, challenge = make_pkce_pair()
        code_doc = make_mock_firestore_doc({
            "uid": "user-abc", "redirect_uri": "",
            "code_challenge": challenge,
            "created_at": datetime.now(timezone.utc),
            "used": True,
        })
        db.collection.return_value.document.return_value.get.return_value = code_doc

        with _client() as client:
            resp = client.post("/auth/token", data={
                "grant_type":    "authorization_code",
                "code":          "some-code",
                "code_verifier": verifier,
            })
        assert resp.status_code == 400
        assert "already used" in resp.json()["detail"]

    def test_expired_code_returns_400(self, db):
        verifier, challenge = make_pkce_pair()
        raw_code, _ = self._setup_valid_code(db, verifier, challenge, age_seconds=400)  # > 300s TTL

        with _client() as client:
            resp = client.post("/auth/token", data={
                "grant_type":    "authorization_code",
                "code":          raw_code,
                "code_verifier": verifier,
            })
        assert resp.status_code == 400
        assert "expired" in resp.json()["detail"]

    def test_pkce_failure_returns_400(self, db):
        verifier, challenge = make_pkce_pair()
        raw_code, _ = self._setup_valid_code(db, verifier, challenge)

        with _client() as client:
            resp = client.post("/auth/token", data={
                "grant_type":    "authorization_code",
                "code":          raw_code,
                "code_verifier": "wrong-verifier",
            })
        assert resp.status_code == 400
        assert "PKCE" in resp.json()["detail"]

    def test_redirect_uri_mismatch_returns_400(self, db):
        verifier, challenge = make_pkce_pair()
        raw_code, _ = self._setup_valid_code(db, verifier, challenge)

        with _client() as client:
            resp = client.post("/auth/token", data={
                "grant_type":    "authorization_code",
                "code":          raw_code,
                "code_verifier": verifier,
                "redirect_uri":  "http://evil.com/callback",
            })
        assert resp.status_code == 400
        assert "mismatch" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# /mcp auth middleware
# ---------------------------------------------------------------------------

class TestMcpAuth:
    def test_no_bearer_returns_401_with_www_authenticate(self):
        with _client() as client:
            resp = client.post("/mcp", json={
                "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            })

        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers
        ww = resp.headers["WWW-Authenticate"]
        assert "Bearer" in ww
        assert "oauth-protected-resource" in ww

    def test_invalid_token_returns_401(self, db):
        db.collection.return_value.document.return_value.get.return_value = \
            make_mock_firestore_doc({}, exists=False)

        with _client() as client:
            resp = client.post("/mcp",
                               headers={"Authorization": "Bearer bad-token"},
                               json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert resp.status_code == 401

    def test_valid_session_token_passes_middleware(self, db):
        """Full Streamable HTTP handshake: initialize → tools/list, all 3 tools exposed."""
        raw_token   = "valid-raw-token"
        token_hash  = hashlib.sha256(raw_token.encode()).hexdigest()
        session_doc = make_mock_firestore_doc({"uid": "user-123"})
        col = MagicMock()
        col.document.return_value.get.return_value = session_doc
        db.collection.return_value = col

        headers = {
            "Authorization": "Bearer valid-raw-token",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        init = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"},
            },
        }

        with _client() as client:
            resp = client.post("/mcp", headers=headers, json=init)
            assert resp.status_code == 200
            assert "mcp-session-id" in resp.headers
            session_id = resp.headers["mcp-session-id"]

            client.post(
                "/mcp",
                headers={**headers, "Mcp-Session-Id": session_id},
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            )

            resp = client.post(
                "/mcp",
                headers={**headers, "Mcp-Session-Id": session_id},
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            )

        assert resp.status_code == 200
        names = {t["name"] for t in resp.json()["result"]["tools"]}
        assert names == {"search_documents", "get_tabs", "open_document"}
        session_doc.reference.update.assert_called()  # last_used ping per /mcp request
