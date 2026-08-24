"""
v0.7 live smoke test — exercises the real stateless cycle end-to-end against
the live TaxMann portal, using the production code paths (main._CachedTaxMann
with the machine-id / client-IP caches):

  cycle: login → search → get_tabs → open_document → logout

Runs twice to verify the login/logout cycle is repeatable and releases the
session slot each time. Credentials come from ../taxmann-scraper/.env.
Firebase is mocked because the MCP server parts (Firestore/Storage) are not
needed for this SDK-level smoke test.
"""

import os
import sys
import pathlib
from unittest.mock import MagicMock

# Mock Firebase before importing app.main (Firestore/Storage not needed here)
for mod in ("firebase_admin", "firebase_admin.auth", "firebase_admin.credentials",
            "firebase_admin.firestore", "firebase_admin.storage", "google", "google.cloud"):
    sys.modules.setdefault(mod, MagicMock())
sys.modules["google.cloud.firestore"] = MagicMock()

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "app"))

from dotenv import load_dotenv
load_dotenv(pathlib.Path(__file__).resolve().parents[2] / "taxmann-scraper" / ".env")

from main import _CachedTaxMann  # noqa: E402

email = os.environ.get("TAXMANN_EMAIL", "")
password = os.environ.get("TAXMANN_PASSWORD", "")
if not email or not password:
    sys.exit("TAXMANN_EMAIL/TAXMANN_PASSWORD missing from taxmann-scraper/.env")

QUERY = "section 80C"

for i in range(2):
    client = None
    try:
        client = _CachedTaxMann(email, password)
        client.login()
        print(f"cycle {i + 1}: login OK")

        results = client.search(QUERY, page=1, page_size=5)
        assert results, "search returned no results"
        print(f"cycle {i + 1}: search OK ({len(results)} results), first: {results[0].title[:60]!r}")

        tabs = client.get_tabs(QUERY)
        print(f"cycle {i + 1}: get_tabs OK ({len(tabs)} tabs)")

        first = results[0]
        doc = client.open_document(first.file_id, first.category_slug, "")
        assert len(doc.html_content) > 1000, "document HTML suspiciously short"
        chunks = (len(doc.html_content) + 9999) // 10000
        print(f"cycle {i + 1}: open_document OK ({len(doc.html_content)} chars, {chunks} chunks)")
    finally:
        if client is not None:
            client.logout()
            print(f"cycle {i + 1}: logout OK")

print("LIVE SMOKE PASSED")
