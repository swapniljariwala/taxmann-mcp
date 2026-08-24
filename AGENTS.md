# AGENTS.md

## Project Overview

`taxmann-mcp` is a Firebase-hosted, multi-user MCP service exposing the
TaxMann legal research portal (taxmann.com) as MCP tools. Single FastAPI app
(`app/main.py`) with OAuth 2.0 + PKCE, per-user TaxMann credentials (AES-GCM
encrypted at rest), a stateless `login → call → logout` session manager, and
a shared Firebase Storage document cache.

Main entry points: `app/main.py` (all server code), `portal/` (login /
settings / dashboard pages, plain HTML/JS + Bulma CDN), `tests/` (pytest,
Firebase fully mocked).

## Hard Dependencies

- **TaxMann SDK** — `taxmann` package from the sibling repo
  `../taxmann-scraper` (private dependency repo:
  https://github.com/swapniljariwala/taxmann-scraper). It has no packaging
  metadata, so it is imported by path, never pip-installed:
  - Local dev / tests: `app/main.py` inserts the sibling repo into `sys.path`
    (`parents[2] / "taxmann-scraper"`) inside a guarded try/except.
  - Docker: the image embeds the package via
    `COPY taxmann-scraper/taxmann ./taxmann/` — the build context MUST be the
    parent directory of both repos:
    `cd C:/Users/swapnil/pyapps && docker build -f taxmann-mcp/Dockerfile -t taxmann-mcp .`
  - The SDK deps (requests, pycryptodome, loguru) are listed in
    `app/requirements.txt`; keep them in sync with the SDK's own
    `requirements.txt`.
- **Pin**: `mcp>=1.12.0,<2.0.0` in `app/requirements.txt` — fastapi-mcp 0.4.0
  is incompatible with mcp 2.x (Server signature changed). Do not bump mcp to
  2.x until fastapi-mcp supports it.

## Essential Commands

Windows project; everything runs in the local venv:

- **Run tests**: `venv/Scripts/python -m pytest` (58 tests; Firebase mocked —
  no project or credentials needed)
- **Live smoke test** (real TaxMann API): `venv/Scripts/python scripts/live_smoke.py`
  — needs `TAXMANN_EMAIL`/`TAXMANN_PASSWORD` in `../taxmann-scraper/.env`
- **Docker build**: from `C:/Users/swapnil/pyapps` (see above)
- **Install deps**: edit `app/requirements.txt` (or `requirements-dev.txt`)
  manually, then `venv/Scripts/pip install -r ...` — never `pip install <pkg>`
  directly, never `pip freeze`.

## Architecture Notes

- `_stateless_call(uid, fn)` (app/main.py) is the core: per-uid asyncio lock →
  load+decrypt creds from Firestore → fresh `_CachedTaxMann` → `login()` →
  run `fn(client)` → `logout()` in finally. Error mapping: AuthError→403
  ("update at /settings"), SearchError/DocumentError→502,
  DOCUMENT_ACCESS_LIMIT_EXCEED/503→502 session-limit.
- `_CachedTaxMann` subclasses the SDK with process-wide caches: machine ID
  (lifetime) and client IP (1h TTL, short-circuits `getclientipbydomain`).
  The SDK's own `_SECRET_KEY_CACHE` covers the decryption key.
- `_user_uid` ContextVar is set by the /mcp auth middleware; `require_uid()`
  dependency gates the tools. Direct /tools calls need `_user_uid` set.
- Tools: `search_documents` (page_size clamped to 50, tab_filter is a
  JSON-encoded string param), `get_tabs`, `open_document` (10k chunks; first
  fetch per file is cached to Storage; cache hit is not billed).
- Usage counters increment under Firestore `/usage/{uid}/{YYYY-MM-DD}/counters`
  with UTC date keys (the dashboard reads the same keys).

## Conventions

- 4-space Python, banner-comment section separators in main.py, defensive
  `.get()` chains, no secrets in logs (never log email/password/tokens).
- Tests must work against mocked Firebase (see tests/conftest.py) — no real
  project needed.
- Follow the milestone plan in the parent repo:
  `../taxmann-scraper/memory/mcp-plan.md`.
