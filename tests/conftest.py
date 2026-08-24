"""
Pytest configuration and shared fixtures.

Firebase Admin SDK and google.cloud.firestore are mocked at the sys.modules
level before app/main.py is imported, so no real Firebase project, emulator,
or credentials file is needed to run the unit tests.
"""

import hashlib
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Add app/ to path so `import main` works
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).parent.parent / "app"))
sys.path.insert(0, str(Path(__file__).parent))  # allow `from helpers import ...`

# ---------------------------------------------------------------------------
# Mock Firebase + google.cloud before importing main
# ---------------------------------------------------------------------------

_mock_firestore_module = MagicMock()
_mock_firestore_module.Increment        = lambda n: {"__increment__": n}
_mock_firestore_module.SERVER_TIMESTAMP = "__server_timestamp__"

sys.modules.setdefault("firebase_admin",             MagicMock())
sys.modules.setdefault("firebase_admin.auth",        MagicMock())
sys.modules.setdefault("firebase_admin.credentials", MagicMock())
sys.modules.setdefault("firebase_admin.firestore",   MagicMock())
sys.modules.setdefault("firebase_admin.storage",     MagicMock())
sys.modules.setdefault("google",                     MagicMock())
sys.modules.setdefault("google.cloud",               MagicMock())
sys.modules["google.cloud.firestore"]                = _mock_firestore_module

# Import the module under test (Firebase init runs here, against mocks)
import main  # noqa: E402


def make_mock_firestore_doc(data: dict, exists: bool = True):
    """A minimal stand-in for a Firestore DocumentSnapshot."""
    doc = MagicMock()
    doc.exists = exists
    doc.to_dict.return_value = data
    return doc


def make_mock_ref(doc=None, set_result=None, update_result=None):
    """A minimal stand-in for a Firestore DocumentReference."""
    ref = MagicMock()
    ref.get.return_value = doc
    if set_result is not None:
        ref.set.return_value = set_result
    if update_result is not None:
        ref.update.return_value = update_result
    return ref


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_main_globals(monkeypatch):
    """Fresh db and bucket mocks for every test."""
    mock_db     = MagicMock()
    mock_bucket = MagicMock()
    monkeypatch.setattr(main, "_db",     mock_db)
    monkeypatch.setattr(main.storage, "bucket", lambda: mock_bucket)
    monkeypatch.setattr(main, "_user_uid", __import__("contextvars").ContextVar("user_uid", default=None))
    return mock_db, mock_bucket


@pytest.fixture()
def db(reset_main_globals):
    mock_db, _ = reset_main_globals
    return mock_db


@pytest.fixture()
def bucket(reset_main_globals):
    _, mock_bucket = reset_main_globals
    return mock_bucket


@pytest.fixture()
def valid_session(db):
    """
    Configures db so a known raw token resolves to uid='user-123' with stored
    TaxMann credentials.
    """
    raw_token   = "valid-raw-token"
    token_hash  = hashlib.sha256(raw_token.encode()).hexdigest()
    session_doc = make_mock_firestore_doc({"uid": "user-123"})
    user_doc    = make_mock_firestore_doc({
        "taxmann_email": "someone@example.com",
        "taxmann_enc_password": "ciphertext",
    })

    def col_side(name):
        col = MagicMock()
        col.document.return_value.get.return_value = (
            session_doc if name == "sessions" else user_doc
        )
        return col

    db.collection.side_effect = col_side
    return raw_token, "user-123"
