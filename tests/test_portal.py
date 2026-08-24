"""
v0.2 portal tests — /settings and /dashboard pages exist, are served by the
static mount, and contain the auth-guard wiring (onAuthStateChanged redirect,
logout button). The guard itself runs in the browser; we assert structure.
"""

from fastapi.testclient import TestClient

import main


def _page_ok(path: str, markers: list[str]):
    with TestClient(main.app) as client:
        resp = client.get(path)
    assert resp.status_code == 200
    body = resp.text
    for marker in markers:
        assert marker in body, f"{path} missing {marker!r}"


def test_settings_page_served():
    _page_ok("/settings", [
        "TaxMann Research Tool — Settings",
        'href="/dashboard"',
        'href="/settings"',
        'id="logout-btn"',
        'window.location.href = "/"',
        'id="mcp-url"',
        'id="tx-email"',
        'id="tx-password"',
        'id="tx-test-save-btn"',
        'id="tx-remove-btn"',
    ])


def test_dashboard_page_served():
    _page_ok("/dashboard", [
        "TaxMann Research Tool — Dashboard",
        'href="/settings"',
        'id="logout-btn"',
        'window.location.href = "/"',
        'id="usage-tbody"',
        'id="date-range"',
        'id="card-total"',
        'id="card-docs"',
        'id="card-searches"',
        "search_documents",
        "open_document",
    ])
