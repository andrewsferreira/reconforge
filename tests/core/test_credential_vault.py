"""Tests for core.credential_vault – CredentialVault."""

import json
from pathlib import Path

import pytest

from core.credential_vault import CredentialVault, Credential


# ── basic add / get ─────────────────────────────────────────────

def test_add_password():
    vault = CredentialVault()
    cred = vault.add_password("admin", "P@ss123", source="hydra", module="network")
    assert cred is not None
    assert cred.username == "admin"
    assert vault.count() == 1


def test_add_hash():
    vault = CredentialVault()
    cred = vault.add_hash("aad3b435b51404ee", "NTLM", username="admin")
    assert cred.cred_type == "hash_ntlm"
    hashes = vault.get_hashes()
    assert len(hashes) == 1


def test_add_token():
    vault = CredentialVault()
    cred = vault.add_token("eyJhbGciOi...", token_type="jwt", source="burp")
    assert cred.cred_type == "token_jwt"
    assert len(vault.get_tokens()) == 1


def test_add_api_key():
    vault = CredentialVault()
    cred = vault.add_api_key("AKIA...", source="trufflehog")
    assert cred.cred_type == "api_key"


def test_add_ssh_key():
    vault = CredentialVault()
    cred = vault.add_ssh_key("-----BEGIN RSA PRIVATE KEY-----", username="root")
    assert cred.cred_type == "ssh_key"


def test_add_username():
    vault = CredentialVault()
    cred = vault.add_username("jsmith", source="ldap")
    assert cred.cred_type == "username"
    assert "jsmith" in vault.get_usernames()


# ── deduplication ───────────────────────────────────────────────

def test_duplicate_password_rejected():
    vault = CredentialVault()
    vault.add_password("admin", "P@ss123")
    dup = vault.add_password("admin", "P@ss123")
    assert dup is None
    assert vault.count() == 1


def test_different_passwords_accepted():
    vault = CredentialVault()
    vault.add_password("admin", "P@ss123")
    vault.add_password("admin", "Qwerty1!")
    assert vault.count() == 2


# ── queries ─────────────────────────────────────────────────────

def test_get_by_type():
    vault = CredentialVault()
    vault.add_password("u1", "p1")
    vault.add_hash("h1", "NTLM")
    assert len(vault.get_by_type("password")) == 1
    assert len(vault.get_by_type("hash_ntlm")) == 1


def test_get_passwords():
    vault = CredentialVault()
    vault.add_password("a", "b")
    assert len(vault.get_passwords()) == 1


def test_get_for_service():
    vault = CredentialVault()
    vault.add_password("admin", "pass", service="ssh")
    vault.add_password("admin", "pass2", service="smb")
    assert len(vault.get_for_service("ssh")) == 1


def test_get_for_module():
    vault = CredentialVault()
    vault.add_password("a", "b", module="network")
    vault.add_password("c", "d", module="ad")
    assert len(vault.get_for_module("network")) == 1


def test_summary():
    vault = CredentialVault()
    vault.add_password("a", "b")
    vault.add_hash("h", "NTLM")
    vault.add_token("t", "jwt")
    s = vault.summary()
    assert s["password"] == 1
    assert s["hash_ntlm"] == 1
    assert s["token_jwt"] == 1


# ── validation ──────────────────────────────────────────────────

def test_mark_validated():
    vault = CredentialVault()
    cred = vault.add_password("admin", "P@ss")
    vault.mark_validated(cred.id)
    validated = vault.get_validated()
    assert len(validated) == 1
    assert validated[0].validated is True


# ── loot integration ────────────────────────────────────────────

def test_ingest_from_loot():
    """Vault ingests credentials from a LootManager."""
    from core.loot_manager import LootManager
    loot = LootManager()
    loot.add_credential("user1", "pass1", "hydra", "network", service="ssh")
    loot.add_hash("aad3b435", "NTLM", "secretsdump", "ad", username="admin")

    vault = CredentialVault()
    imported = vault.ingest_from_loot(loot)
    assert imported >= 1
    assert vault.count() >= 1


def test_contribute_to_loot():
    """Vault contributes credentials back to a LootManager."""
    from core.loot_manager import LootManager
    vault = CredentialVault()
    vault.add_password("admin", "secret", source="vault", module="ad")

    loot = LootManager()
    contributed = vault.contribute_to_loot(loot)
    assert contributed >= 1


# ── serialisation ───────────────────────────────────────────────

def test_save_and_load_json(tmp_path):
    vault = CredentialVault()
    vault.add_password("admin", "P@ss123", source="test")
    vault.add_hash("aad3b435", "NTLM", username="admin")

    path = tmp_path / "vault.json"
    vault.save(path)
    assert path.exists()

    vault2 = CredentialVault()
    vault2.load(path)
    assert vault2.count() == vault.count()


def test_to_json():
    vault = CredentialVault()
    vault.add_password("admin", "P@ss")
    data = json.loads(vault.to_json())
    # to_json returns a list of credential dicts
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["username"] == "admin"


def test_export_usernames(tmp_path):
    vault = CredentialVault()
    vault.add_password("alice", "pass1")
    vault.add_password("bob", "pass2")
    vault.add_username("charlie")

    path = tmp_path / "users.txt"
    names = vault.export_usernames(path)
    assert "alice" in names
    assert "bob" in names
    assert "charlie" in names
    assert path.read_text().strip().count("\n") >= 2
