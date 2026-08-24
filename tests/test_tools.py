"""
v0.5 tests — MCP tool endpoints (search_documents / get_tabs / open_document).

Drives the real FastAPI routes through TestClient. The v0.4 stateless session
manager is replaced with FakeTaxMann (canned search/get_tabs/open_document),
so no network or real login happens. The middleware is bypassed for direct
/tools calls by setting main._user_uid directly (that is exactly what the MCP
auth middleware sets before FastApiMCP dispatches a tools/call, and what
require_uid reads). AnyIO portals copy the caller's context per request, so
the set is visible inside the app.
"""

import os
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

import main
from taxmann.exceptions import AuthError
from taxmann.models import Document, SearchResult

UID = "user-123"


def _client() -> TestClient:
    return TestClient(main.app)


def _setup_user(monkeypatch, db, uid=UID):
    """Store valid (email, AES-GCM-encrypted password) on /users/{uid}."""
    dek = os.urandom(32)
    monkeypatch.setattr(main, "_dek", dek)
    doc = MagicMock()
    doc.exists = True
    doc.to_dict.return_value = {
        "taxmann_email":        "user@example.com",
        "taxmann_enc_password": main._encrypt_password("pw", dek),
    }
    db.collection.return_value.document.return_value.get.return_value = doc
    return dek


def _cache_miss(bucket):
    """Make every Storage blob report a cache miss."""
    miss_blob = MagicMock()
    miss_blob.exists.return_value = False
    bucket.blob.return_value = miss_blob
    return miss_blob


class FakeTaxMann:
    """Drop-in for main._CachedTaxMann with canned tool responses."""

    instances = []

    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.login_called = False
        self.logout_called = False
        self.search_calls = []
        self.tabs_calls = []
        self.open_calls = []
        FakeTaxMann.instances.append(self)

    def login(self):
        self.login_called = True

    def logout(self):
        self.logout_called = True

    def search(self, query, tab_filter=None, page=1, page_size=20, sort_by="relevance"):
        self.search_calls.append((query, tab_filter, page, page_size, sort_by))
        return [
            SearchResult(
                file_id="doc-1", title="GST on software supply",
                category="GST", category_slug="gst-new",
                description="Some snippet", metadata={"extra": "not-in-response"},
            ),
            SearchResult(
                file_id="doc-2", title="Input tax credit",
                category="GST", category_slug="gst-new", description=None,
            ),
        ]

    def get_tabs(self, query):
        self.tabs_calls.append(query)
        return [{"id": "gst-new", "name": "GST"}, {"id": "income-tax", "name": "Income Tax"}]

    def open_document(self, file_id, category_name, search_text=""):
        self.open_calls.append((file_id, category_name, search_text))
        return Document(
            file_id=file_id,
            title="GST on software supply",
            category=category_name,
            html_content="A" * 25_000,
            metadata={"word_count": 4000},
        )


class AuthErrorTaxMann(FakeTaxMann):
    def login(self):
        self.login_called = True
        raise AuthError("Invalid credentials provided")


# ---------------------------------------------------------------------------
# search_documents
# ---------------------------------------------------------------------------

class TestSearchDocuments:
    def test_success_trims_results_and_increments_usage(self, monkeypatch, db):
        _setup_user(monkeypatch, db)
        monkeypatch.setattr(main, "_CachedTaxMann", FakeTaxMann)
        FakeTaxMann.instances = []
        main._user_uid.set(UID)

        with _client() as client:
            resp = client.post("/tools/search_documents", params={"query": "gst"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["query"] == "gst"
        assert body["page"] == 1
        assert body["page_size"] == 20
        assert body["total"] == 2
        assert len(body["results"]) == 2

        first = body["results"][0]
        assert set(first) == {"file_id", "title", "category", "category_slug", "description"}
        assert first["file_id"] == "doc-1"
        assert "extra" not in first  # SDK-only metadata trimmed

        inst = FakeTaxMann.instances[0]
        assert inst.login_called and inst.logout_called  # session slot released
        assert inst.search_calls == [("gst", None, 1, 20, "relevance")]

        usage_calls = [c for c in db.collection.call_args_list if c[0][0] == "usage"]
        assert len(usage_calls) == 1

    def test_passes_page_page_size_sort_by(self, monkeypatch, db):
        _setup_user(monkeypatch, db)
        monkeypatch.setattr(main, "_CachedTaxMann", FakeTaxMann)
        FakeTaxMann.instances = []
        main._user_uid.set(UID)

        with _client() as client:
            resp = client.post("/tools/search_documents", params={
                "query": "gst", "page": 2, "page_size": 10, "sort_by": "date",
            })

        assert resp.status_code == 200
        inst = FakeTaxMann.instances[0]
        assert inst.search_calls[0][2:] == (2, 10, "date")

    def test_all_tools_require_uid(self):
        main._user_uid.set(None)
        with _client() as client:
            r1 = client.post("/tools/search_documents", params={"query": "gst"})
            r2 = client.post("/tools/get_tabs", params={"query": "gst"})
            r3 = client.post("/tools/open_document",
                             params={"file_id": "doc-1", "category_name": "GST"})
        assert r1.status_code == r2.status_code == r3.status_code == 403

    def test_auth_error_maps_to_403(self, monkeypatch, db):
        _setup_user(monkeypatch, db)
        monkeypatch.setattr(main, "_CachedTaxMann", AuthErrorTaxMann)
        FakeTaxMann.instances = []
        main._user_uid.set(UID)

        with _client() as client:
            resp = client.post("/tools/search_documents", params={"query": "gst"})
        assert resp.status_code == 403
        assert "invalid or expired" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# get_tabs
# ---------------------------------------------------------------------------

class TestGetTabs:
    def test_success(self, monkeypatch, db):
        _setup_user(monkeypatch, db)
        monkeypatch.setattr(main, "_CachedTaxMann", FakeTaxMann)
        FakeTaxMann.instances = []
        main._user_uid.set(UID)

        with _client() as client:
            resp = client.post("/tools/get_tabs", params={"query": "gst"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["query"] == "gst"
        assert [t["id"] for t in body["tabs"]] == ["gst-new", "income-tax"]

        inst = FakeTaxMann.instances[0]
        assert inst.tabs_calls == ["gst"]
        assert inst.login_called and inst.logout_called

        usage_calls = [c for c in db.collection.call_args_list if c[0][0] == "usage"]
        assert len(usage_calls) == 1


# ---------------------------------------------------------------------------
# open_document
# ---------------------------------------------------------------------------

class TestOpenDocument:
    SAMPLE_HTML = "A" * 25_000  # 2.5 chunks at CHUNK_SIZE=10_000

    def _post(self, params):
        with _client() as client:
            return client.post("/tools/open_document", params=params)

    def test_chunk_0_returns_first_10000_chars(self, monkeypatch, db, bucket):
        _setup_user(monkeypatch, db)
        monkeypatch.setattr(main, "_CachedTaxMann", FakeTaxMann)
        FakeTaxMann.instances = []
        main._user_uid.set(UID)
        _cache_miss(bucket)

        resp = self._post({"file_id": "doc-1", "category_name": "GST"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["file_id"] == "doc-1"
        assert body["title"] == "GST on software supply"
        assert body["category"] == "GST"
        assert body["chunk"] == 0
        assert body["total_chars"] == 25_000
        assert body["total_chunks"] == 3
        assert body["text"] == self.SAMPLE_HTML[:10_000]

        inst = FakeTaxMann.instances[0]
        assert inst.open_calls == [("doc-1", "GST", "")]
        assert inst.login_called and inst.logout_called

        usage_calls = [c for c in db.collection.call_args_list if c[0][0] == "usage"]
        assert len(usage_calls) == 1  # first fetch is billed

    def test_chunk_2_returns_last_5000_chars(self, monkeypatch, db, bucket):
        _setup_user(monkeypatch, db)
        monkeypatch.setattr(main, "_CachedTaxMann", FakeTaxMann)
        FakeTaxMann.instances = []
        main._user_uid.set(UID)
        _cache_miss(bucket)

        resp = self._post({"file_id": "doc-1", "category_name": "GST", "chunk": 2})

        assert resp.status_code == 200
        body = resp.json()
        assert body["chunk"] == 2
        assert body["total_chunks"] == 3
        assert body["text"] == self.SAMPLE_HTML[20_000:]  # 5000 chars

    def test_miss_writes_cache_inside_threadpool(self, monkeypatch, db, bucket):
        _setup_user(monkeypatch, db)
        monkeypatch.setattr(main, "_CachedTaxMann", FakeTaxMann)
        FakeTaxMann.instances = []
        main._user_uid.set(UID)
        miss_blob = _cache_miss(bucket)

        resp = self._post({"file_id": "doc-1", "category_name": "GST"})

        assert resp.status_code == 200
        # 2 uploads: /docs/doc-1.html + /docs/doc-1.json
        assert miss_blob.upload_from_string.call_count == 2

    def test_cache_hit_skips_sdk_and_usage(self, monkeypatch, db, bucket):
        _setup_user(monkeypatch, db)
        monkeypatch.setattr(main, "_CachedTaxMann", FakeTaxMann)
        FakeTaxMann.instances = []
        main._user_uid.set(UID)

        html_blob = MagicMock()
        html_blob.exists.return_value = True
        html_blob.download_as_text.return_value = self.SAMPLE_HTML
        meta_blob = MagicMock()
        meta_blob.exists.return_value = True
        meta_blob.download_as_text.return_value = (
            '{"title": "Cached Title", "category": "GST"}'
        )

        def blob_side(path):
            return html_blob if path.endswith(".html") else meta_blob
        bucket.blob.side_effect = blob_side

        resp = self._post({"file_id": "doc-1", "category_name": "GST"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["title"] == "Cached Title"      # from cache meta
        assert body["category"] == "GST"
        assert body["total_chunks"] == 3
        assert FakeTaxMann.instances == []          # no login → no SDK call
        usage_calls = [c for c in db.collection.call_args_list if c[0][0] == "usage"]
        assert len(usage_calls) == 0                # cache hit is not billed
