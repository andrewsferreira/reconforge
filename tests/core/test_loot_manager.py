"""Tests for core.loot_manager – LootManager."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from core.loot_manager import LootManager, LootItem


def test_add_and_get_all():
    lm = LootManager()
    lm.add("credential", "admin:pass", "nmap", "network")
    assert len(lm.get_all()) == 1


def test_duplicate_prevention():
    lm = LootManager()
    lm.add("credential", "admin:pass", "nmap", "network")
    lm.add("credential", "admin:pass", "nmap", "network")
    assert len(lm.get_all()) == 1


def test_add_credential():
    lm = LootManager()
    item = lm.add_credential("user", "pass123", "hydra", "network", service="ssh")
    assert item.loot_type == "credential"
    creds = lm.get_credentials()
    assert len(creds) == 1
    assert creds[0]["username"] == "user"


def test_add_hash():
    lm = LootManager()
    lm.add_hash("aad3b435...", "NTLM", "secretsdump", "ad", username="admin")
    hashes = lm.get_by_type("hash")
    assert len(hashes) == 1


def test_add_user():
    lm = LootManager()
    lm.add_user("jsmith", "ldap", "ad", domain="corp.local")
    assert "jsmith" in lm.get_users()


def test_add_share():
    lm = LootManager()
    lm.add_share("\\\\dc01\\share$", "READ", "smbclient", "network", anonymous=True)
    shares = lm.get_by_type("share")
    assert len(shares) == 1


def test_add_service():
    lm = LootManager()
    lm.add_service("ssh", "OpenSSH 8.9", 22, "nmap", "network")
    services = lm.get_by_type("service")
    assert len(services) == 1


def test_to_json():
    lm = LootManager()
    lm.add("token", "abc123", "web", "web")
    data = json.loads(lm.to_json())
    assert len(data) == 1
    assert data[0]["loot_type"] == "token"


def test_save_plaintext(tmp_path):
    lm = LootManager()
    lm.add("credential", "root:toor", "test", "test")
    path = tmp_path / "loot.json"
    with pytest.warns(UserWarning, match="PLAINTEXT"):
        lm.save(path)
    assert path.exists()
    data = json.loads(path.read_text())
    assert len(data) == 1


def test_save_plaintext_sets_restrictive_permissions(tmp_path):
    lm = LootManager()
    lm.add("credential", "root:toor", "test", "test")
    path = tmp_path / "loot.json"
    with pytest.warns(UserWarning, match="PLAINTEXT"):
        lm.save(path)
    assert (path.stat().st_mode & 0o777) == 0o600


def test_summary():
    lm = LootManager()
    lm.add("credential", "a:b", "s", "m")
    lm.add("credential", "c:d", "s", "m")
    lm.add("hash", "abc", "s", "m")
    summary = lm.summary()
    assert summary["credential"] == 2
    assert summary["hash"] == 1


# ── Encryption tests (only if cryptography installed) ─────────────

def _has_crypto():
    try:
        from cryptography.fernet import Fernet
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _has_crypto(), reason="cryptography not installed")
def test_encrypt_decrypt_cycle(tmp_path, monkeypatch):
    """SEC-2: loot encrypt → decrypt round-trip."""
    # Override key dir to avoid touching real ~/.reconforge
    import core.loot_manager as lm_mod
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    monkeypatch.setattr(lm_mod, "_KEY_DIR", key_dir)
    monkeypatch.setattr(lm_mod, "_KEY_FILE", key_dir / "loot.key")

    lm = LootManager(encrypt=True)
    lm.add("credential", "admin:secret", "test", "network")

    out = tmp_path / "loot.json"
    lm.save(out)

    enc_path = out.with_suffix(".json.enc")
    assert enc_path.exists()
    assert not out.exists()  # plaintext should NOT be written

    plaintext = LootManager.load_encrypted(enc_path)
    data = json.loads(plaintext)
    assert len(data) == 1
    assert data[0]["value"] == "admin:secret"


@pytest.mark.skipif(not _has_crypto(), reason="cryptography not installed")
def test_encrypted_save_sets_restrictive_permissions(tmp_path, monkeypatch):
    import core.loot_manager as lm_mod
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    monkeypatch.setattr(lm_mod, "_KEY_DIR", key_dir)
    monkeypatch.setattr(lm_mod, "_KEY_FILE", key_dir / "loot.key")

    lm = LootManager(encrypt=True)
    lm.add("credential", "admin:secret", "test", "network")
    out = tmp_path / "loot.json"
    lm.save(out)

    enc_path = out.with_suffix(".json.enc")
    assert (enc_path.stat().st_mode & 0o777) == 0o600


@pytest.mark.skipif(not _has_crypto(), reason="cryptography not installed")
def test_env_var_key_used_instead_of_file(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet
    import core.loot_manager as lm_mod

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    monkeypatch.setattr(lm_mod, "_KEY_DIR", key_dir)
    monkeypatch.setattr(lm_mod, "_KEY_FILE", key_dir / "loot.key")
    monkeypatch.setenv("RECONFORGE_LOOT_KEY", Fernet.generate_key().decode())

    lm = LootManager(encrypt=True)
    lm.add("credential", "admin:secret", "test", "network")
    out = tmp_path / "loot.json"
    lm.save(out)

    assert not (key_dir / "loot.key").exists()  # env key used, no file written
    plaintext = LootManager.load_encrypted(out.with_suffix(".json.enc"))
    assert json.loads(plaintext)[0]["value"] == "admin:secret"
