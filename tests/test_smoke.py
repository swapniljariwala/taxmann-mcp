"""
v0.1 smoke tests — app boots, serves /health, and mounts the portal.
"""

from fastapi.testclient import TestClient

import main


def test_health_ok():
    with TestClient(main.app) as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_portal_index_served():
    with TestClient(main.app) as client:
        resp = client.get("/")
    assert resp.status_code == 200
    assert "TaxMann Research Tool" in resp.text


def test_style_css_served():
    with TestClient(main.app) as client:
        resp = client.get("/style.css")
    assert resp.status_code == 200
    assert "text/css" in resp.headers.get("content-type", "")
