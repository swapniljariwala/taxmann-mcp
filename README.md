# TaxMann Research Tool — MCP Service

Source: https://github.com/swapniljariwala/taxmann-mcp

A Firebase-hosted, multi-user MCP service exposing the TaxMann legal research
portal (taxmann.com) as MCP tools. Modeled on the `indiakanoon-mcp` project.

Two deliberate differences from indiakanoon-mcp:

1. **Credentials are TaxMann username/password, not an API key** — stored per
   user, AES-256-GCM encrypted at rest (DEK in Google Secret Manager).
2. **The MCP server is stateless** — no persistent TaxMann login session;
   every tool call is a self-contained `login() → call → logout()` cycle that
   releases the account's content-session slot.

## Architecture

```
LLM client ── POST /mcp (Bearer <access_token>) ──▶ Cloud Run (FastAPI + fastapi-mcp)
                                                      │  OAuth PKCE: /auth/authorize,
                                                      │  /auth/complete, /auth/token
                                                      ├─ Firestore /sessions → uid
                                                      ├─ Firestore /users/{uid}  → encrypted TaxMann creds
                                                      ├─ upstream TaxMann call (per-user creds)
                                                      ├─ Firebase Storage doc cache (shared)
                                                      └─ Firestore /usage/{uid}/{date} counters
                                                      ▲
                          Firebase Hosting (portal): / (login), /settings, /dashboard
```

| Service | Purpose |
|---|---|
| Firebase Auth | Portal identity (email/password accounts, admin-created). |
| Cloud Run (Python, FastAPI) | MCP HTTP server — one service, all routes. |
| Firestore | Encrypted per-user TaxMann creds, OAuth state, usage counters. |
| Firebase Storage | Shared document HTML/meta cache across all users. |
| Firebase Hosting | Static portal (plain HTML/JS, Bulma CDN, no build step). |

## MCP Tools

| Tool | SDK method | Notes |
|---|---|---|
| `search_documents` | `search()` | Trimmed results: id, title, category, category_slug, description. `page_size` clamped to 50. |
| `get_tabs` | `get_tabs()` | Raw tab list for a query. |
| `open_document` | `open_document()` | 10,000-char chunks. First fetch per file hits TaxMann and populates the shared cache; later fetches are served from Storage. |

## Stateless session design

Each tool call runs through `_stateless_call(uid, fn)` (app/main.py):

1. Load + decrypt the caller's creds from Firestore `/users/{uid}`.
2. Acquire a per-uid `asyncio.Lock` (one TaxMann account = limited concurrent
   sessions; requests queue rather than race).
3. Build a fresh `_CachedTaxMann` client with global (device-level) caches:
   - secret key — cached per bundle URL inside the SDK,
   - machine ID — process-lifetime class cache,
   - client IP — 1h TTL class cache (server's own public IP),
4. `login()` → run the tool's call → `logout()` in a `finally` (always
   releases the session slot; logout failures never mask tool results).
5. Map SDK errors: `AuthError` → 403 "credentials invalid, update at
   /settings"; `SearchError`/`DocumentError` → 502; `DOCUMENT_ACCESS_LIMIT_EXCEED`
   / 503 → 502 "session limit reached, try again shortly".

An optional in-memory per-user session pool (idle TTL, LRU) is deliberately
OFF (`SESSION_POOL_ENABLED = False`) — enable only if login rate limits bite.

## Security

- Passwords encrypted with AES-256-GCM: `base64(nonce(12) || ct || tag(16))`.
- DEK (32 bytes) loaded once at startup: `TAXMANN_DEK` env var (base64) or
  Secret Manager secret `taxmann_creds_dek` (project `SECRET_MANAGER_PROJECT`)
  take precedence; otherwise a fallback DEK is baked into the image (dev
  convenience — rotate in Secret Manager / env before this ships beyond dev).
- The portal client cannot encrypt (DEK is server-side); `/auth/test_credentials`
  runs a real login/logout before `/auth/save_credentials` persists anything.
  Unverified creds are never stored.
- No email/password/tokens are logged anywhere in the service.
- Revocation: "Remove" button on `/settings` deletes the stored creds.
- Firestore rules: users read/write only their own `/users/{uid}` and
  `/usage/{uid}/**`; OAuth collections and everything else are deny-all.
  Storage is server-write only (deny-all client access).

## Local development

```bash
python -m venv venv
venv/Scripts/pip install -r app/requirements.txt -r requirements-dev.txt

# Run tests (Firebase is mocked; no project needed)
venv/Scripts/python -m pytest

# Live smoke test (uses ../taxmann-scraper/.env credentials against the real portal)
venv/Scripts/python scripts/live_smoke.py
```

## Dependencies

- **TaxMann SDK** — the `taxmann` package from the sibling repo
  `../taxmann-scraper` (private: https://github.com/swapniljariwala/taxmann-scraper).
  Imported by path (no packaging metadata): `app/main.py` adds the sibling
  repo to `sys.path` for local dev/tests; the Docker image embeds it via
  `COPY taxmann-scraper/taxmann ./taxmann/` (build context = parent of both
  repos). SDK deps (requests, pycryptodome, loguru) are mirrored in
  `app/requirements.txt`.
- **Pin**: `mcp>=1.12.0,<2.0.0` — fastapi-mcp 0.4.0 is incompatible with
  mcp 2.x.

## Deployment checklist

Actual project values (what this repo is deployed as):

| Value | Value in use |
|---|---|
| GCP / Firebase project id | `my-primary-project-228515` |
| Region | `asia-south1` |
| Cloud Run service / image | `taxmann-mcp` / `asia-south1-docker.pkg.dev/my-primary-project-228515/taxmann-mcp/taxmann-mcp` |
| Service URL | `https://taxmann-mcp-jjsa4ya54a-el.a.run.app` |
| Storage bucket | `my-primary-project-228515.appspot.com` |
| OAuth endpoint | `https://taxmann-mcp-jjsa4ya54a-el.a.run.app/mcp` |
| Portal | `https://taxmann-mcp-jjsa4ya54a-el.a.run.app/` (Cloud Run hosts the static portal) |

`portal/firebase-config.js` already contains the real Web-app config for the
`my-primary-project-228515` project (apiKey, authDomain, storageBucket,
messagingSenderId, appId). `app/main.py` defaults `STORAGE_BUCKET` to
`my-primary-project-228515.appspot.com`, `.firebaserc` defaults the project to
`my-primary-project-228515`.

Prereqs: the Firebase/GCP project, Firebase Auth enabled with admin-created
email/password users, `firebase` + `gcloud` CLI installed, Cloud Run API
enabled, ADC configured (`gcloud auth application-default login`).

1. **Grant the Cloud Run service account access to Firestore and Storage**
   (missing this is what breaks `/auth/authorize` and every Firestore-backed
   route with a `500` / `403 PermissionDenied`):
   ```bash
   # SA is the default compute SA unless the service pins a custom one:
   #   gcloud run services describe taxmann-mcp --region asia-south1 \
   #     --format "value(spec.template.spec.serviceAccountName)"
   SA=1045524373148-compute@developer.gserviceaccount.com
   gcloud projects add-iam-policy-binding my-primary-project-228515 \
     --member="serviceAccount:$SA" --role="roles/datastore.user"   # Firestore
   gcloud projects add-iam-policy-binding my-primary-project-228515 \
     --member="serviceAccount:$SA" --role="roles/storage.admin"    # doc cache
   ```
   Firestore uses the Datastore IAM roles; reads *and* writes need
   `roles/datastore.user`. IAM propagation takes ~1–3 min before a redeployed
   service picks it up.

2. **Deploy the Cloud Run service** (Docker build — the image embeds the
   TaxMann SDK from the sibling repo, so the build context must be the parent
   of both repos; see AGENTS.md):
   ```bash
   cd C:/Users/swapnil/pyapps
   docker build -f taxmann-mcp/Dockerfile -t taxmann-mcp .

   # authenticate docker once:
   gcloud auth configure-docker asia-south1-docker.pkg.dev
   docker tag taxmann-mcp \
     asia-south1-docker.pkg.dev/my-primary-project-228515/taxmann-mcp/taxmann-mcp
   docker push asia-south1-docker.pkg.dev/my-primary-project-228515/taxmann-mcp/taxmann-mcp
   gcloud run deploy taxmann-mcp \
     --image asia-south1-docker.pkg.dev/my-primary-project-228515/taxmann-mcp/taxmann-mcp \
     --region asia-south1 --allow-unauthenticated \
     --set-env-vars STORAGE_BUCKET=my-primary-project-228515.appspot.com
   ```
   (No DEK env var needed — the image ships a fallback DEK; override with
   `TAXMANN_DEK` or Secret Manager `taxmann_creds_dek` when you rotate.)

3. **Deploy Hosting + rules** (productively, CLI Login page later
   — currently the static portal is served by Cloud Run, so this step is
   optional unless Firebase Hosting is used):
   ```bash
   cd taxmann-mcp
   firebase use my-primary-project-228515
   firebase deploy --only hosting,firestore:rules,storage:rules
   ```

4. **Smoke test the OAuth flow** — the authorize endpoint must redirect
   (302) to the portal, never 500:
   ```bash
   curl -i "https://taxmann-mcp-jjsa4ya54a-el.a.run.app/auth/authorize?\
   response_type=code&client_id=<id>&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback&\
   code_challenge=<verifier-sha256-b64url>&code_challenge_method=S256&state=test"
   # expect: 302 Location /?auth_request_id=...
   ```
   Then in any MCP client (Claude Desktop, mcp-remote) point at
   `https://taxmann-mcp-jjsa4ya54a-el.a.run.app/mcp`. The OAuth flow opens
   the portal for Firebase login; then configure TaxMann creds on `/settings`
   (Test & Save), run a search → open a document, confirm chunk 1 is a Storage
   cache hit, and check `/dashboard` counters.

## Open questions (from memory/mcp-plan.md)

- Per-user vs shared TaxMann account (default: per-user).
- Login rate limits — if the portal throttles repeated login/logout, the
  session pool becomes mandatory.
- `getclientipbydomain` IP stability (cached 1h; verified stable across
  repeated logins from this host).
- Session-slot release timing — logout releases the slot immediately (verified
  live), settle time unknown.
