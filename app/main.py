"""
TaxMann Research Tool — FastAPI + fastapi-mcp server (v0.1 scaffold)
--------------------------------------------------------------------
Wraps the TaxMann SDK (taxmann-scraper) as an MCP service.

Planned authentication: OAuth 2.0 Authorization Code + PKCE
  LLM client → /mcp (401) → browser OAuth flow → access token → /mcp

Multi-user design:
  Each user supplies their own TaxMann credentials (email/password), stored
  encrypted at rest in Firestore:
    /users/{uid}.taxmann_email         — plaintext email
    /users/{uid}.taxmann_enc_password  — AES-GCM-encrypted blob (v0.3)
  Per-request lifecycle: login() → call → logout(), so no long-lived TaxMann
  sessions are kept server-side — a TaxMann session lives only for the
  duration of a single tool invocation.

Firestore OAuth state (v0.3):
  /auth_requests/{id}   — short-lived OAuth request (AUTH_REQ_TTL)
  /auth_codes/{hash}    — short-lived auth code (AUTH_CODE_TTL, single-use)
  /sessions/{hash}      — long-lived session (revoke by deleting from Firestore)
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import hashlib
import json
import logging
import math
import os
import pathlib
import secrets
import sys
import time
from datetime import datetime, timezone
from typing import Annotated, Any, Callable, Optional

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("taxmann-mcp")

# ---------------------------------------------------------------------------
# TaxMann SDK import — local dev path vs Docker image
# ---------------------------------------------------------------------------
# Local dev: the taxmann-scraper repo is a sibling of this project, so add its
# parent directory to sys.path. (In the Docker image this path does not exist
# and parents[2] raises IndexError — the SDK is COPYed into /app/taxmann by
# the Dockerfile instead, reachable via PYTHONPATH=/app.)
try:
    sys.path.insert(
        0,
        str(pathlib.Path(__file__).resolve().parents[2] / "taxmann-scraper"),
    )
except Exception:
    pass  # Docker image: no sibling repo, SDK already on PYTHONPATH

# Guarded so the service still boots if the SDK is missing; v0.3 tools will
# surface a clear error at call time.
try:
    import taxmann  # noqa: F401
    from taxmann.client import TaxMann  # noqa: F401
    from taxmann.models import Document, SearchResult  # noqa: F401
    from taxmann.exceptions import (  # noqa: F401
        AuthError,
        DocumentError,
        SearchError,
        TaxMannError,
    )
    log.info("taxmann SDK imported successfully")
except ImportError as e:
    log.warning("taxmann SDK not importable at startup: %s", e)
    # Keep the guarded names bound so v0.4+ can check and route at call time.
    TaxMann = None
    AuthError = None
    DocumentError = None
    SearchError = None

import firebase_admin
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from firebase_admin import auth as fb_auth, firestore, storage
from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi_mcp import FastApiMCP
from google.cloud.firestore import SERVER_TIMESTAMP
from starlette.concurrency import run_in_threadpool

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CHUNK_SIZE    = 10_000
AUTH_CODE_TTL = 300   # 5 minutes
AUTH_REQ_TTL  = 600   # 10 minutes

# Session context: holds the authenticated user's uid for the current request.
# Set by the v0.3 MCP auth middleware once per MCP session; read by tool
# handlers to fetch that user's TaxMann credentials fresh from Firestore so
# portal changes take effect immediately without reconnecting.
_user_uid: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "user_uid", default=None
)

# ---------------------------------------------------------------------------
# Firebase Admin SDK — uses Application Default Credentials on Cloud Run
# ---------------------------------------------------------------------------

log.info("Initializing Firebase Admin SDK...")
_storage_bucket = os.environ.get("STORAGE_BUCKET", "taxmann-mcp.firebasestorage.app")
firebase_admin.initialize_app(options={"storageBucket": _storage_bucket})
log.info("Firebase Admin SDK initialized. Storage bucket: %s", _storage_bucket)
_db: firestore.Client | None = None


def get_db() -> firestore.Client:
    """Lazily create and cache the Firestore client."""
    global _db
    if _db is None:
        log.info("Creating Firestore client...")
        _db = firestore.client()
        log.info("Firestore client created.")
    return _db


# ---------------------------------------------------------------------------
# Usage accounting
# ---------------------------------------------------------------------------

def _increment_usage(endpoint: str) -> None:
    """Increment today's usage counter for the current user. Non-fatal."""
    try:
        uid = _user_uid.get()
        if not uid:
            return
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        ref  = get_db().collection("usage").document(uid).collection(date).document("counters")
        ref.set({endpoint: firestore.Increment(1), "updated_at": SERVER_TIMESTAMP}, merge=True)
    except Exception as e:
        log.warning("usage increment error [%s]: %s", endpoint, e)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="TaxMann Research Tool",
    description="TaxMann legal research database MCP server",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# v0.3+ roadmap — all delivered in v0.3–v0.5:
#
#   1. /mcp auth middleware (mcp_auth_middleware) + _base_url() helper   [v0.5]
#   2. OAuth discovery (RFC 8414)                                         [v0.5]
#   3. OAuth dynamic client registration (RFC 7591): /oauth/register     [v0.5]
#   4. OAuth authorize:          GET  /auth/authorize                    [v0.5]
#   5. OAuth complete (portal):  POST /auth/complete                     [v0.5]
#   6. OAuth token exchange:     POST /auth/token                        [v0.5]
#   7. Credential crypto: AES-GCM /users/{uid}.taxmann_enc_password     [v0.3]
#   8. Session manager: _load_creds() + _run_with_client() +
#      _stateless_call()                                                 [v0.4]
#   9. Tools: FastApiMCP mount (include_tags=["tools"]) exposing
#      search_documents / get_tabs / open_document                       [v0.5]
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Healthcheck
# ---------------------------------------------------------------------------

@app.get("/health", include_in_schema=False)
async def health() -> dict:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# v0.3 — Credential management
#
# TaxMann passwords are stored per-user in Firestore /users/{uid}, encrypted
# at rest with AES-256-GCM. Blob layout:
#   base64( nonce(12 bytes) || ciphertext || tag(16 bytes) )
# The DEK is server-side only — the portal client cannot encrypt, so both
# write paths live here, authenticated by a Firebase ID token in the JSON
# body (OAuth arrives in v0.5).
# ---------------------------------------------------------------------------

_dek: bytes | None = None


def _load_dek() -> bytes | None:
    """
    Load the 32-byte DEK once at startup: TAXMANN_DEK env var (base64) →
    Google Secret Manager secret taxmann_creds_dek → None (endpoints that
    need it then return 500 "Server encryption key not configured").
    """
    global _dek
    if _dek is not None:
        return _dek

    encoded = os.environ.get("TAXMANN_DEK", "").strip()
    if encoded:
        try:
            _dek = base64.b64decode(encoded, validate=True)
        except Exception:
            _dek = None
            log.error("TAXMANN_DEK is not valid base64")
        if _dek is not None and len(_dek) != 32:
            _dek = None
            log.error("TAXMANN_DEK must decode to exactly 32 bytes")
        return _dek

    project = os.environ.get("SECRET_MANAGER_PROJECT", "").strip()
    if project:
        try:
            from google.cloud import secretmanager
            client = secretmanager.SecretManagerServiceClient()
            name = f"projects/{project}/secrets/taxmann_creds_dek/versions/latest"
            _dek = client.access_secret_version(name=name).payload.data
        except Exception as e:
            _dek = None
            log.error("Failed to load DEK from Secret Manager: %s", e)
        if _dek is not None and len(_dek) != 32:
            _dek = None
            log.error("Secret Manager DEK must be exactly 32 bytes")
        return _dek

    _dek = None
    log.error(
        "Server encryption key not configured: set TAXMANN_DEK or "
        "SECRET_MANAGER_PROJECT before credentials can be saved"
    )
    return None


def _encrypt_password(plaintext: str, dek: bytes) -> str:
    """AES-256-GCM encrypt → base64(nonce(12) || ciphertext || tag(16))."""
    nonce = secrets.token_bytes(12)
    ct = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def _decrypt_password(blob: str, dek: bytes) -> str:
    """Inverse of _encrypt_password (used by v0.4 tools)."""
    raw = base64.b64decode(blob)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(dek).decrypt(nonce, ct, None).decode("utf-8")


def _verify_id_token(token: str) -> str:
    """Return the uid for a Firebase ID token, or raise 401."""
    try:
        return fb_auth.verify_id_token(token)["uid"]
    except Exception:
        raise HTTPException(401, "Invalid or expired token")


def _verify_taxmann_login(email: str, password: str) -> None:
    """Blocking login() → logout() so the TaxMann session slot is always released."""
    client = None
    try:
        client = TaxMann(email, password)
        client.login()
    finally:
        if client is not None:
            client.logout()


@app.post("/auth/test_credentials", include_in_schema=False)
async def test_credentials(request: Request) -> dict:
    """Run a real login/logout cycle against TaxMann for the given credentials."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    uid      = _verify_id_token(body.get("firebase_id_token", ""))
    email    = (body.get("email") or "").strip()
    password = body.get("password") or ""

    if not email or not password:
        raise HTTPException(400, "email and password are required")

    try:
        await run_in_threadpool(_verify_taxmann_login, email, password)
    except AuthError as e:
        log.info("TaxMann credential test failed [uid=%s]", uid)
        return {"success": False, "message": str(e)}

    log.info("TaxMann credential test succeeded [uid=%s]", uid)
    return {"success": True, "message": "Credentials verified. Login and logout succeeded."}


@app.post("/auth/save_credentials", include_in_schema=False)
async def save_credentials(request: Request) -> dict:
    """Encrypt and store TaxMann credentials on /users/{uid} (merge)."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    uid      = _verify_id_token(body.get("firebase_id_token", ""))
    email    = (body.get("email") or "").strip()
    password = body.get("password") or ""

    if not email or not password:
        raise HTTPException(400, "email and password are required")
    if _dek is None:
        raise HTTPException(500, "Server encryption key not configured")

    try:
        blob = _encrypt_password(password, _dek)
    except Exception:
        log.exception("Password encryption failed [uid=%s]", uid)
        raise HTTPException(500, "Password encryption failed")

    get_db().collection("users").document(uid).set(
        {
            "taxmann_email":        email,
            "taxmann_enc_password": blob,
            "updated_at":           SERVER_TIMESTAMP,
        },
        merge=True,
    )
    log.info("TaxMann credentials saved [uid=%s]", uid)
    return {"success": True}


# Load the DEK once at startup (env var → Secret Manager → None).
_load_dek()


# ---------------------------------------------------------------------------
# v0.4 — Stateless session manager
#
# Every tool call runs as a self-contained login() → call → logout() cycle
# against a fresh _CachedTaxMann client — no TaxMann session is held between
# requests. Global (device-level, not per-user) caches keep the cycle cheap:
#   secret_key — already cached per bundle URL inside the SDK
#   machine_id — class-level cache on _CachedTaxMann
#   client_ip  — class-level cache with a 1h TTL (server's own public IP)
# A per-uid asyncio.Lock serializes concurrent calls per TaxMann account (the
# portal allows a limited number of concurrent content sessions), so requests
# queue instead of racing on the account's session slot.
# ---------------------------------------------------------------------------

_CLIENT_IP_URL = "https://session-live.taxmann.com/api/auth/getclientipbydomain"

# Optional in-memory per-user session pool (uid → logged-in TaxMann instance
# with idle TTL / LRU eviction). Deliberately OFF for v0.4: we always
# login → call → logout. Re-evaluate only if login rate limits bite.
SESSION_POOL_ENABLED = False


if TaxMann is None:
    _CachedTaxMann = None  # SDK unavailable — tools surface a 503 at call time
else:
    class _CachedTaxMann(TaxMann):
        """
        SDK subclass with class-level caches for the two per-instance network
        calls that are really device-level (identical for every user):

          * machine ID — fetched from researchapi-live.../machineId and
            AES-decrypted; cached for the process lifetime.
          * client IP  — resolved by getclientipbydomain during login();
            cached for _IP_TTL (1h) so login() skips that network call.

        No credentials are logged here; the SDK already logs the email at
        INFO inside login() (accepted).
        """

        # machine-ID cache — global to the process (one machine ID for every
        # session; the portal derives it from the server's public IP).
        _machine_id_cache: str | None = None

        # client-IP cache — the server's own public IP as seen by TaxMann.
        _client_ip_cache: str | None = None
        _client_ip_ts: float = 0.0
        _IP_TTL = 3600  # seconds (1h)

        def _fetch_machine_id(self) -> str:
            """Return the cached machine ID, fetching and caching on first use."""
            if _CachedTaxMann._machine_id_cache is not None:
                return _CachedTaxMann._machine_id_cache
            machine_id = super()._fetch_machine_id()
            _CachedTaxMann._machine_id_cache = machine_id
            # The parent already sets this header in __init__; re-setting keeps
            # them in sync if login()/_check_session() ever re-derives it.
            self._session.headers["machineid"] = machine_id
            return machine_id

        def login(self) -> None:
            """
            Login as usual, but skip the getclientipbydomain network call when
            a fresh cached client IP exists (the IP is the server's own and
            stable); afterwards refresh the cache from the resolved IP.
            """
            cached_ip = _CachedTaxMann._client_ip_cache
            ip_fresh = bool(cached_ip) and (
                time.monotonic() - _CachedTaxMann._client_ip_ts
            ) < _CachedTaxMann._IP_TTL

            original_post = self._session.post
            try:
                if ip_fresh:
                    # Pre-seed the IP the SDK would have resolved, and fake
                    # the getclientipbydomain response so login() never hits
                    # the network for it.
                    self._ip_address = cached_ip

                    class _FakeIpResponse:
                        status_code = 200

                        def json(self) -> dict:
                            return {"data": [cached_ip]}

                    def _short_circuited_post(url, *args, **kwargs):
                        if url == _CLIENT_IP_URL:
                            return _FakeIpResponse()
                        return original_post(url, *args, **kwargs)

                    self._session.post = _short_circuited_post

                super().login()
            finally:
                # Always restore the real post, even when login fails.
                self._session.post = original_post

            if self._ip_address:
                _CachedTaxMann._client_ip_cache = self._ip_address
                _CachedTaxMann._client_ip_ts = time.monotonic()


# ---------------------------------------------------------------------------
# Per-uid concurrency lock — one TaxMann account allows a limited number of
# concurrent content sessions, so serialize tool calls per account (queue,
# not error). Locks are in-memory: they only serialize within one server
# instance (cross-instance races surface as DOCUMENT_ACCESS_LIMIT_EXCEED,
# mapped to a clear 502 in _stateless_call).
# ---------------------------------------------------------------------------

_LOCKS: dict[str, asyncio.Lock] = {}
_LOCKS_GUARD = asyncio.Lock()


async def _get_uid_lock(uid: str) -> asyncio.Lock:
    """Return (creating on demand) the per-uid lock for a TaxMann account."""
    async with _LOCKS_GUARD:
        lock = _LOCKS.get(uid)
        if lock is None:
            lock = asyncio.Lock()
            _LOCKS[uid] = lock
        return lock


# ---------------------------------------------------------------------------
# Credential loading + session lifecycle (blocking; call via threadpool)
# ---------------------------------------------------------------------------

def _load_creds(uid: str) -> tuple[str, str]:
    """
    Read /users/{uid} from Firestore and return (email, decrypted password).

    Raises HTTPException(403) when the doc/fields are missing or the stored
    blob cannot be decrypted; HTTPException(500) when the DEK is not loaded.
    """
    doc = get_db().collection("users").document(uid).get()
    if not doc.exists:
        raise HTTPException(403, "No TaxMann credentials configured. Add them at /settings.")
    data = doc.to_dict() or {}
    email = (data.get("taxmann_email") or "").strip()
    enc = data.get("taxmann_enc_password") or ""
    if not email or not enc:
        raise HTTPException(403, "No TaxMann credentials configured. Add them at /settings.")
    if _dek is None:
        raise HTTPException(500, "Server encryption key not configured")
    try:
        password = _decrypt_password(enc, _dek)
    except Exception:
        log.exception("Credential decryption failed [uid=%s]", uid)
        raise HTTPException(403, "Stored credentials could not be decrypted. Re-save them at /settings.")
    return email, password


def _run_with_client(email: str, password: str, fn: Callable[[Any], Any]) -> Any:
    """
    Fresh client → login() → fn(client) → logout() in finally. Blocking
    (network + crypto) — call via run_in_threadpool.
    """
    if _CachedTaxMann is None:
        raise HTTPException(503, "TaxMann SDK unavailable on server")

    client = None
    try:
        client = _CachedTaxMann(email, password)
        client.login()
        return fn(client)
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:
                # A logout failure must never mask the tool result or turn a
                # success into an error. The session slot may leak — log it
                # loudly so operators can investigate.
                log.warning(
                    "TaxMann logout failed — session slot may not be released",
                    exc_info=True,
                )


async def _stateless_call(uid: str, fn: Callable[[Any], Any]) -> Any:
    """
    Run fn(client) against a fresh TaxMann session for the given user.

    Serializes calls per uid (one session slot per account), loads + decrypts
    the user's Firestore creds, and maps SDK errors to user-safe HTTP codes.
    v0.5 tool endpoints will call this from async handlers.
    """
    async with await _get_uid_lock(uid):
        email, password = await run_in_threadpool(_load_creds, uid)
        try:
            return await run_in_threadpool(_run_with_client, email, password, fn)
        except HTTPException:
            raise
        except AuthError:
            raise HTTPException(
                403,
                "TaxMann credentials are invalid or expired. Update them at /settings.",
            )
        except DocumentError as e:
            msg = str(e)
            cause = e.__cause__ or e.__context__
            if (
                "DOCUMENT_ACCESS_LIMIT_EXCEED" in msg
                or "503" in msg
                or getattr(cause, "status_code", None) == 503
            ):
                raise HTTPException(
                    502,
                    "TaxMann account session limit reached. Try again shortly.",
                )
            raise HTTPException(502, f"Document retrieval failed: {e}")
        except SearchError as e:
            raise HTTPException(502, f"Search failed: {e}")
        except Exception:
            log.exception("Unexpected TaxMann error [uid=%s]", uid)
            raise HTTPException(502, "Unexpected TaxMann error")


# ---------------------------------------------------------------------------
# v0.5 — MCP auth, OAuth, and tools
#
# 1. mcp_auth_middleware + _base_url() — every request under /mcp must carry
#    a Bearer access token; the token is SHA-256 hashed and looked up in
#    Firestore /sessions/{hash}. 401 responses carry an RFC 8414
#    resource-metadata URI so OAuth clients (mcp-remote, Claude Desktop) know
#    where to start the auth flow.
# 2. OAuth discovery + RFC 7591 dynamic registration + Authorization Code +
#    PKCE (S256 only): authorize → portal Firebase login → complete → token.
# 3. require_uid() dependency — surfaces the middleware-set _user_uid to tool
#    handlers (403 if the middleware never ran, e.g. a direct HTTP call).
# 4. Shared Storage doc cache — /docs/{file_id}.html + .json, shared across
#    all users, so each file is fetched from TaxMann (and billed to the portal
#    session) only once per unique file.
# 5. Tools: search_documents / get_tabs / open_document, each running through
#    the v0.4 stateless session manager and exposed to MCP by the FastApiMCP
#    mount (include_tags=["tools"]).
# ---------------------------------------------------------------------------


def _base_url(request: Request) -> str:
    base = str(request.base_url).rstrip("/")
    proto = request.headers.get("X-Forwarded-Proto")
    if proto and base.startswith("http://"):
        base = "https://" + base[len("http://"):]
    return base


@app.middleware("http")
async def mcp_auth_middleware(request: Request, call_next):
    log.debug("→ %s %s", request.method, request.url.path)

    if not request.url.path.startswith("/mcp"):
        response = await call_next(request)
        log.debug("← %s %s → %s", request.method, request.url.path, response.status_code)
        return response

    auth_header = request.headers.get("Authorization", "")
    base = _base_url(request)
    resource_meta = f'{base}/.well-known/oauth-protected-resource'

    if not auth_header.startswith("Bearer "):
        log.info("/mcp: no Bearer token → 401")
        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized"},
            headers={"WWW-Authenticate": f'Bearer resource_metadata="{resource_meta}"'},
        )

    raw_token  = auth_header.split("Bearer ", 1)[1].strip()
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    log.info("/mcp: verifying session hash=%s...", token_hash[:8])
    session    = get_db().collection("sessions").document(token_hash).get()

    if not session.exists:
        log.info("/mcp: session not found → 401")
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid or revoked token"},
            headers={"WWW-Authenticate": f'Bearer resource_metadata="{resource_meta}"'},
        )

    session_data = session.to_dict()
    uid = session_data.get("uid")
    log.info("/mcp: session valid, uid=%s", uid)
    session.reference.update({"last_used": SERVER_TIMESTAMP})

    _user_uid.set(uid)
    response = await call_next(request)
    log.debug("← /mcp → %s", response.status_code)
    return response


# ---------------------------------------------------------------------------
# OAuth dynamic client registration (RFC 7591) — required by mcp-remote
# ---------------------------------------------------------------------------

@app.post("/oauth/register", include_in_schema=False)
async def oauth_register(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}

    return JSONResponse(status_code=201, content={
        "client_id":                  secrets.token_urlsafe(16),
        "client_id_issued_at":        int(__import__("time").time()),
        "redirect_uris":              body.get("redirect_uris", []),
        "grant_types":                body.get("grant_types", ["authorization_code"]),
        "response_types":             body.get("response_types", ["code"]),
        "token_endpoint_auth_method": "none",
    })


# ---------------------------------------------------------------------------
# OAuth discovery + authorize
# ---------------------------------------------------------------------------

@app.get("/.well-known/oauth-protected-resource", include_in_schema=False)
async def oauth_protected_resource(request: Request):
    base = _base_url(request)
    log.info("oauth-protected-resource: base=%s", base)
    return {"resource": f"{base}/mcp", "authorization_servers": [base]}


@app.get("/.well-known/oauth-authorization-server", include_in_schema=False)
async def oauth_authorization_server(request: Request):
    base = _base_url(request)
    log.info("oauth-authorization-server: base=%s", base)
    return {
        "issuer":                                base,
        "authorization_endpoint":                f"{base}/auth/authorize",
        "token_endpoint":                        f"{base}/auth/token",
        "registration_endpoint":                 f"{base}/oauth/register",
        "response_types_supported":              ["code"],
        "grant_types_supported":                 ["authorization_code"],
        "code_challenge_methods_supported":      ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }


@app.get("/auth/authorize", include_in_schema=False)
async def auth_authorize(
    request:               Request,
    redirect_uri:          str = Query(...),
    code_challenge:        str = Query(...),
    code_challenge_method: str = Query("S256"),
    state:                 str = Query(""),
    client_id:             str = Query(""),
):
    log.info("auth_authorize: client_id=%s redirect_uri=%s", client_id, redirect_uri)
    if code_challenge_method != "S256":
        raise HTTPException(400, "Only S256 code_challenge_method is supported")

    request_id = secrets.token_urlsafe(24)
    log.info("auth_authorize: storing auth_request id=%s", request_id)
    get_db().collection("auth_requests").document(request_id).set({
        "redirect_uri":          redirect_uri,
        "code_challenge":        code_challenge,
        "code_challenge_method": code_challenge_method,
        "state":                 state,
        "client_id":             client_id,
        "created_at":            SERVER_TIMESTAMP,
    })

    base = _base_url(request)
    return RedirectResponse(f"{base}/?auth_request_id={request_id}", status_code=302)


# ---------------------------------------------------------------------------
# OAuth complete (called by portal after Firebase login)
# ---------------------------------------------------------------------------

@app.post("/auth/complete", include_in_schema=False)
async def auth_complete(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    auth_request_id   = body.get("auth_request_id", "")
    firebase_id_token = body.get("firebase_id_token", "")

    if not auth_request_id or not firebase_id_token:
        raise HTTPException(400, "Missing auth_request_id or firebase_id_token")

    try:
        decoded = fb_auth.verify_id_token(firebase_id_token)
    except Exception as e:
        raise HTTPException(401, f"Invalid Firebase token: {e}")

    uid = decoded["uid"]
    db  = get_db()

    req_doc = db.collection("auth_requests").document(auth_request_id).get()
    if not req_doc.exists:
        raise HTTPException(400, "auth_request_id not found or expired")

    req_data   = req_doc.to_dict()
    created_at = req_data.get("created_at")
    if created_at:
        age = (datetime.now(timezone.utc) - created_at).total_seconds()
        if age > AUTH_REQ_TTL:
            req_doc.reference.delete()
            raise HTTPException(400, "Authorization request expired. Please try again.")

    raw_code  = secrets.token_urlsafe(32)
    code_hash = hashlib.sha256(raw_code.encode()).hexdigest()
    db.collection("auth_codes").document(code_hash).set({
        "uid":            uid,
        "redirect_uri":   req_data["redirect_uri"],
        "code_challenge": req_data["code_challenge"],
        "created_at":     SERVER_TIMESTAMP,
        "used":           False,
    })
    req_doc.reference.delete()

    return {
        "code":         raw_code,
        "state":        req_data.get("state", ""),
        "redirect_uri": req_data["redirect_uri"],
    }


# ---------------------------------------------------------------------------
# OAuth token exchange
# ---------------------------------------------------------------------------

@app.post("/auth/token", include_in_schema=False)
async def auth_token(
    request:       Request,
    code:          str = Form(...),
    code_verifier: str = Form(...),
    redirect_uri:  str = Form(""),
    grant_type:    str = Form(...),
):
    if grant_type != "authorization_code":
        raise HTTPException(400, "unsupported_grant_type")

    db        = get_db()
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    code_doc  = db.collection("auth_codes").document(code_hash).get()

    if not code_doc.exists:
        raise HTTPException(400, "invalid_grant: code not found")

    code_data = code_doc.to_dict()
    if code_data.get("used"):
        raise HTTPException(400, "invalid_grant: code already used")

    created_at = code_data.get("created_at")
    if created_at:
        age = (datetime.now(timezone.utc) - created_at).total_seconds()
        if age > AUTH_CODE_TTL:
            code_doc.reference.delete()
            raise HTTPException(400, "invalid_grant: code expired")

    if redirect_uri and redirect_uri != code_data.get("redirect_uri"):
        raise HTTPException(400, "invalid_grant: redirect_uri mismatch")

    digest    = hashlib.sha256(code_verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    if challenge != code_data.get("code_challenge"):
        raise HTTPException(400, "invalid_grant: PKCE verification failed")

    code_doc.reference.update({"used": True})

    raw_token  = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    db.collection("sessions").document(token_hash).set({
        "uid":        code_data["uid"],
        "created_at": SERVER_TIMESTAMP,
        "last_used":  SERVER_TIMESTAMP,
    })

    return {"access_token": raw_token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Tool auth dependency + shared Storage doc cache
# ---------------------------------------------------------------------------

def require_uid() -> str:
    """FastAPI dependency — the uid the MCP auth middleware stored for this request."""
    uid = _user_uid.get()
    if not uid:
        raise HTTPException(status_code=403, detail="Not authenticated.")
    return uid


def _get_bucket():
    return storage.bucket()


def _cache_get_document(file_id: str) -> dict | None:
    """Return cached doc dict (html + metadata) or None on miss. Non-fatal."""
    try:
        bucket    = _get_bucket()
        html_blob = bucket.blob(f"docs/{file_id}.html")
        meta_blob = bucket.blob(f"docs/{file_id}.json")
        if not html_blob.exists() or not meta_blob.exists():
            return None
        html_text = html_blob.download_as_text(encoding="utf-8")
        meta      = json.loads(meta_blob.download_as_text(encoding="utf-8"))
        log.info("cache HIT: doc %s (%d chars)", file_id, len(html_text))
        return {"html": html_text, **meta}
    except Exception as e:
        log.warning("cache read error for doc %s: %s", file_id, e)
        return None


def _cache_put_document(file_id: str, html_text: str, meta: dict) -> None:
    """Write HTML and metadata to cache. Errors are non-fatal."""
    try:
        bucket = _get_bucket()
        html_blob = bucket.blob(f"docs/{file_id}.html")
        html_blob.upload_from_string(html_text, content_type="text/html; charset=utf-8")
        meta_blob = bucket.blob(f"docs/{file_id}.json")
        meta_blob.upload_from_string(json.dumps(meta), content_type="application/json")
        log.info("cache WRITE: doc %s (%d chars)", file_id, len(html_text))
    except Exception as e:
        log.warning("cache write error for doc %s: %s", file_id, e)


# ---------------------------------------------------------------------------
# MCP tools
#
# Each tool is an async endpoint taking `uid` from require_uid and calling
# _stateless_call (login → call → logout) in a threadpool. _stateless_call may
# raise HTTPException (403 creds, 502 SDK/search/document errors, 503 SDK
# unavailable) — those propagate to FastAPI untouched.
# ---------------------------------------------------------------------------

@app.post(
    "/tools/search_documents",
    operation_id="search_documents",
    tags=["tools"],
    summary="Search the TaxMann database for legal documents, judgments, and commentary. Returns up to 20 results per page.",
)
async def search_documents(
    query:      Annotated[str,            Query(description="Search terms.")],
    page:       Annotated[int,            Query(description="Page number, 1-indexed.")] = 1,
    page_size:  Annotated[int,            Query(description="Results per page (default 20, max 50).")] = 20,
    sort_by:    Annotated[str,            Query(description="Sort field (default 'relevance').")] = "relevance",
    tab_filter: Annotated[Optional[str],  Query(description="Optional JSON-encoded tab filter dict from get_tabs (e.g. {\"id\": [\"111050000000000060\"], \"name\": \"Case Laws\"}). Omit to search all tabs.")] = None,
    uid:        str = Depends(require_uid),
):
    page_size = max(1, min(page_size, 50))
    tab = None
    if tab_filter:
        try:
            tab = json.loads(tab_filter)
        except Exception:
            raise HTTPException(400, "tab_filter must be a JSON-encoded object")

    results = await _stateless_call(
        uid,
        # Must stay synchronous — _stateless_call runs it in a threadpool.
        lambda client: client.search(query, tab, page, page_size, sort_by),
    )

    trimmed = [{
        "file_id":       r.file_id,
        "title":         r.title,
        "category":      r.category,
        "category_slug": r.category_slug,
        "description":   r.description,
    } for r in results]

    _increment_usage("search_documents")
    return {
        "query":     query,
        "page":      page,
        "page_size": page_size,
        "total":     len(trimmed),
        "results":   trimmed,
    }


@app.post(
    "/tools/get_tabs",
    operation_id="get_tabs",
    tags=["tools"],
    summary="List the tab filters available for a search query. Pass the chosen tab as tab_filter to search_documents.",
)
async def get_tabs(
    query: Annotated[str, Query(description="Search terms to fetch tabs for.")],
    uid:   str = Depends(require_uid),
):
    tabs = await _stateless_call(uid, lambda client: client.get_tabs(query))
    _increment_usage("get_tabs")
    return {"query": query, "tabs": tabs}


@app.post(
    "/tools/open_document",
    operation_id="open_document",
    tags=["tools"],
    summary="Retrieve a document in 10,000-character chunks. Costs 1 portal document access per file (first fetch only; later fetches are served from the shared cache). Start with chunk=0 and request subsequent chunks.",
)
async def open_document(
    file_id:       Annotated[str, Query(description="Document file_id from search_documents.")],
    category_name: Annotated[str, Query(description="Category name of the document (from search_documents).")],
    search_text:   Annotated[str, Query(description="Optional search text to highlight in the document.")] = "",
    chunk:         Annotated[int, Query(description="Chunk index, 0-indexed.")] = 0,
    uid:           str = Depends(require_uid),
):
    cached = _cache_get_document(file_id)
    if cached:
        html_text = cached["html"]
        meta      = {k: v for k, v in cached.items() if k != "html"}
    else:
        def _fetch_and_cache(client):
            doc = client.open_document(file_id, category_name, search_text)
            # Blocking Storage I/O — keep it inside the threadpool with the
            # SDK call, never on the event loop.
            _cache_put_document(
                doc.file_id,
                doc.html_content,
                {"title": doc.title, "category": doc.category, "metadata": doc.metadata},
            )
            return doc

        doc       = await _stateless_call(uid, _fetch_and_cache)
        html_text = doc.html_content
        meta      = {"title": doc.title, "category": doc.category, "metadata": doc.metadata}
        _increment_usage("open_document")  # first fetch only — matches cost semantics

    total_chars  = len(html_text)
    total_chunks = math.ceil(total_chars / CHUNK_SIZE) if total_chars else 1
    start        = chunk * CHUNK_SIZE

    return {
        "file_id":      file_id,
        "title":        meta.get("title"),
        "category":     meta.get("category"),
        "chunk":        chunk,
        "total_chunks": total_chunks,
        "total_chars":  total_chars,
        "text":         html_text[start: start + CHUNK_SIZE],
    }


# ---------------------------------------------------------------------------
# Mount MCP — must come AFTER the tool route definitions so FastApiMCP can
# discover the three tools (tagged "tools").
# ---------------------------------------------------------------------------

mcp = FastApiMCP(
    app,
    name="TaxMann Research Tool",
    description="TaxMann legal research database — search, tabs, and document retrieval",
    include_tags=["tools"],
)
mcp.mount_http()


# ---------------------------------------------------------------------------
# Mount portal static files LAST so API routes take priority.
# html=True makes StaticFiles serve index.html for directory paths (/).
# ---------------------------------------------------------------------------

_portal_dir = os.path.join(os.path.dirname(__file__), "..", "portal")
app.mount("/", StaticFiles(directory=_portal_dir, html=True), name="portal")
