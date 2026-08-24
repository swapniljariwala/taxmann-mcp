"""
Live smoke test — validates the stateless per-request cycle that the MCP
session manager is built on: build a fresh TaxMann client, login(), and
logout() in a finally block (session slot must be released).

Uses credentials from ../taxmann-scraper/.env (TAXMANN_EMAIL/TAXMANN_PASSWORD).
"""

import os
import sys
import pathlib
from dotenv import load_dotenv

load_dotenv(pathlib.Path(__file__).resolve().parents[2] / "taxmann-scraper" / ".env")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "taxmann-scraper"))

from taxmann.client import TaxMann  # noqa: E402

email = os.environ.get("TAXMANN_EMAIL", "")
password = os.environ.get("TAXMANN_PASSWORD", "")
if not email or not password:
    sys.exit("TAXMANN_EMAIL/TAXMANN_PASSWORD missing from taxmann-scraper/.env")

for i in range(2):
    client = None
    try:
        client = TaxMann(email, password)
        client.login()
        print(f"cycle {i + 1}: login OK")
    finally:
        if client is not None:
            client.logout()
            print(f"cycle {i + 1}: logout OK")

print("LIVE CYCLE PASSED")
