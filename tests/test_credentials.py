"""
v0.3 tests — credential encryption (AES-256-GCM) and the
/auth/test_credentials + /auth/save_credentials endpoints.
"""

import base64
import os

import pytest
from fastapi.testclient import TestClient

import main
from taxmann.exceptions import AuthError


def _client() -> TestClient:
    return TestClient(main.app)


def _verify_uid(uid="u1"):
    return lambda token: {"uid": uid}


# ---------------------------------------------------------------------------
# AES-GCM round trip
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip(monkeypatch):
    dek = os.urandom(32)
    blob = main._encrypt_password("s3cret-p@ss", dek)
    assert blob != "s3cret-p@ss"
    raw = base64.b64decode(blob)
    assert len(raw) == 12 + len(b"s3cret-p@ss") + 16  # nonce + ct + tag
    assert main._decrypt_password(blob, dek) == "s3cret-p@ss"


def test_decrypt_wrong_key_fails(monkeypatch):
    dek1 = os.urandom(32)
    dek2 = os.urandom(32)
    blob = main._encrypt_password("secret", dek1)
    with pytest.raises(Exception):
        main._decrypt_password(blob, dek2)


# ---------------------------------------------------------------------------
# /auth/test_credentials
# ---------------------------------------------------------------------------

class FakeTaxMann:
    instances = []

    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.login_called = False
        self.logout_called = False
        FakeTaxMann.instances.append(self)

    def login(self):
        self.login_called = True
        if self.password == "bad":
            raise AuthError("Invalid credentials provided")

    def logout(self):
        self.logout_called = True


def test_test_credentials_success(monkeypatch):
    monkeypatch.setattr(main.fb_auth, "verify_id_token", _verify_uid())
    monkeypatch.setattr(main, "TaxMann", FakeTaxMann)
    FakeTaxMann.instances = []

    with _client() as client:
        resp = client.post("/auth/test_credentials", json={
            "firebase_id_token": "tok", "email": "a@b.c", "password": "good",
        })

    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    inst = FakeTaxMann.instances[0]
    assert inst.login_called and inst.logout_called  # session slot released


def test_test_credentials_bad_creds(monkeypatch):
    monkeypatch.setattr(main.fb_auth, "verify_id_token", _verify_uid())
    monkeypatch.setattr(main, "TaxMann", FakeTaxMann)

    with _client() as client:
        resp = client.post("/auth/test_credentials", json={
            "firebase_id_token": "tok", "email": "a@b.c", "password": "bad",
        })

    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is False
    assert "Invalid credentials" in body["message"]


def test_test_credentials_requires_valid_token(monkeypatch):
    def boom(token):
        raise ValueError("bad token")

    monkeypatch.setattr(main.fb_auth, "verify_id_token", boom)

    with _client() as client:
        resp = client.post("/auth/test_credentials", json={
            "firebase_id_token": "nope", "email": "a@b.c", "password": "good",
        })
    assert resp.status_code == 401


def test_test_credentials_missing_fields(monkeypatch):
    monkeypatch.setattr(main.fb_auth, "verify_id_token", _verify_uid())

    with _client() as client:
        resp = client.post("/auth/test_credentials", json={
            "firebase_id_token": "tok", "email": "", "password": "good",
        })
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /auth/save_credentials
# ---------------------------------------------------------------------------

def test_save_credentials_encrypts_and_stores(monkeypatch, db):
    monkeypatch.setattr(main.fb_auth, "verify_id_token", _verify_uid())
    monkeypatch.setattr(main, "_dek", os.urandom(32))

    with _client() as client:
        resp = client.post("/auth/save_credentials", json={
            "firebase_id_token": "tok",
            "email": "user@taxmann.com",
            "password": "plain-password",
        })

    assert resp.status_code == 200
    assert resp.json()["success"] is True

    doc_ref = db.collection("users").document("u1")
    args, kwargs = doc_ref.set.call_args
    stored = args[0]
    assert stored["taxmann_email"] == "user@taxmann.com"
    assert stored["taxmann_enc_password"] != "plain-password"
    assert "plain-password" not in stored["taxmann_enc_password"]
    assert kwargs.get("merge") is True


def test_save_credentials_without_dek(monkeypatch):
    monkeypatch.setattr(main.fb_auth, "verify_id_token", _verify_uid())
    monkeypatch.setattr(main, "_dek", None)

    with _client() as client:
        resp = client.post("/auth/save_credentials", json={
            "firebase_id_token": "tok",
            "email": "user@taxmann.com",
            "password": "plain-password",
        })
    assert resp.status_code == 500


def test_dek_loading_from_env(monkeypatch):
    dek = os.urandom(32)
    monkeypatch.setattr(main, "_dek", None)
    monkeypatch.setenv("TAXMANN_DEK", base64.b64encode(dek).decode())
    monkeypatch.delenv("SECRET_MANAGER_PROJECT", raising=False)
    assert main._load_dek() == dek
