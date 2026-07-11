"""ReconForge Credential Vault - Centralized credential storage and reuse.

Author: Andrews Ferreira

Provides a unified credential store that modules can contribute to and
draw from.  Supports multiple credential types (usernames, passwords,
hashes, tokens, API keys, SSH keys), automatic deduplication, optional
Fernet encryption, and export/import capabilities.

Security properties and limitations (read before relying on this for
anything beyond a lab/engagement laptop you control):

- Encryption is Fernet (AES-128-CBC + HMAC-SHA256), a solid symmetric
  scheme for data at rest — it is NOT a secret-management system. There
  is no access control, no audit trail, no rotation, and no separation
  of duties.
- By default the key is generated once and stored at a fixed path
  (``~/.reconforge/vault.key``, mode 0600). Anyone with read access to
  that path AND the vault file — i.e. the same local user account —
  can decrypt everything. This protects against casual disk browsing,
  accidental inclusion in backups/screenshots/git, and loss of a single
  file, but not against compromise of the operator's own account.
- Set ``RECONFORGE_VAULT_KEY`` (a base64 urlsafe Fernet key) to supply
  the key out-of-band instead of relying on the on-disk key file —
  recommended when the vault file itself may be shared, synced, or
  backed up somewhere the key should not follow it.
- Saving with ``encrypt=False`` writes plaintext credentials to disk. A
  warning is logged/emitted every time this happens; it is never silent.

Usage::

    vault = CredentialVault()
    vault.add_password("admin", "P@ss123", source="hydra", module="network")
    vault.add_hash("aad3b435…", "NTLM", username="admin", source="secretsdump", module="ad")

    # Auto-discover from a LootManager
    vault.ingest_from_loot(loot_manager)

    # Inject available creds into the next module
    creds = vault.get_for_service("smb")
"""

import json
import os
import re
import uuid
import warnings
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.exceptions import CredentialVaultError

try:
    from cryptography.fernet import Fernet
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# ── Credential types ─────────────────────────────────────────────────

CREDENTIAL_TYPES = {
    "password",
    "hash_ntlm",
    "hash_ntlmv2",
    "hash_other",
    "token_jwt",
    "token_bearer",
    "api_key",
    "ssh_key",
    "username",
    "cookie",
    "certificate",
}


# ── Data classes ─────────────────────────────────────────────────────

@dataclass
class Credential:
    """A single credential entry."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    cred_type: str = "password"
    username: str = ""
    secret: str = ""  # password, hash, token, key material, etc.
    domain: str = ""
    service: str = ""  # e.g. "smb", "ssh", "http", "ldap"
    source: str = ""   # tool that discovered it
    module: str = ""   # module that discovered it
    confidence: str = "medium"  # confirmed, high, medium, low
    validated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ── Vault ────────────────────────────────────────────────────────────

class CredentialVault:
    """Centralized credential storage with deduplication and encryption.

    Args:
        encrypt: Encrypt vault files with Fernet.
        key_path: Custom path for the encryption key file.
    """

    def __init__(self, encrypt: bool = False,
                 key_path: Optional[Path] = None):
        self._credentials: List[Credential] = []
        self._seen: Set[str] = set()  # dedup fingerprints
        self.encrypt = encrypt and _HAS_CRYPTO
        self._key_path = key_path or Path.home() / ".reconforge" / "vault.key"

        if encrypt and not _HAS_CRYPTO:
            import warnings
            warnings.warn(
                "cryptography package not installed — vault will be stored "
                "in plaintext. Install with: pip install cryptography"
            )

    # ── Fingerprinting (dedup) ───────────────────────────────────────

    @staticmethod
    def _fingerprint(cred_type: str, username: str, secret: str,
                     domain: str, service: str) -> str:
        """Unique fingerprint for deduplication."""
        return f"{cred_type}|{username}|{secret}|{domain}|{service}"

    # ── Add methods ──────────────────────────────────────────────────

    def _add(self, cred: Credential) -> Optional[Credential]:
        """Internal add with dedup check."""
        fp = self._fingerprint(
            cred.cred_type, cred.username, cred.secret,
            cred.domain, cred.service,
        )
        if fp in self._seen:
            return None
        self._seen.add(fp)
        self._credentials.append(cred)
        return cred

    def add_password(self, username: str, password: str, *,
                     source: str = "", module: str = "",
                     domain: str = "", service: str = "",
                     confidence: str = "confirmed",
                     metadata: Optional[Dict] = None) -> Optional[Credential]:
        """Add a username/password credential."""
        return self._add(Credential(
            cred_type="password", username=username, secret=password,
            domain=domain, service=service, source=source, module=module,
            confidence=confidence, metadata=metadata or {},
        ))

    def add_hash(self, hash_value: str, hash_type: str, *,
                 username: str = "", source: str = "", module: str = "",
                 domain: str = "", service: str = "",
                 confidence: str = "confirmed",
                 metadata: Optional[Dict] = None) -> Optional[Credential]:
        """Add a hash credential (NTLM, NTLMv2, other)."""
        type_map = {
            "ntlm": "hash_ntlm",
            "ntlmv2": "hash_ntlmv2",
        }
        cred_type = type_map.get(hash_type.lower(), "hash_other")
        return self._add(Credential(
            cred_type=cred_type, username=username, secret=hash_value,
            domain=domain, service=service, source=source, module=module,
            confidence=confidence,
            metadata={**(metadata or {}), "hash_type": hash_type},
        ))

    def add_token(self, token: str, token_type: str = "bearer", *,
                  username: str = "", source: str = "", module: str = "",
                  service: str = "", confidence: str = "confirmed",
                  metadata: Optional[Dict] = None) -> Optional[Credential]:
        """Add a token (JWT, Bearer, etc.)."""
        type_map = {"jwt": "token_jwt", "bearer": "token_bearer"}
        cred_type = type_map.get(token_type.lower(), "token_bearer")
        return self._add(Credential(
            cred_type=cred_type, username=username, secret=token,
            service=service, source=source, module=module,
            confidence=confidence, metadata=metadata or {},
        ))

    def add_api_key(self, key: str, *, username: str = "",
                    source: str = "", module: str = "",
                    service: str = "", confidence: str = "confirmed",
                    metadata: Optional[Dict] = None) -> Optional[Credential]:
        """Add an API key."""
        return self._add(Credential(
            cred_type="api_key", username=username, secret=key,
            service=service, source=source, module=module,
            confidence=confidence, metadata=metadata or {},
        ))

    def add_ssh_key(self, key_material: str, *, username: str = "",
                    source: str = "", module: str = "",
                    service: str = "ssh", confidence: str = "confirmed",
                    metadata: Optional[Dict] = None) -> Optional[Credential]:
        """Add an SSH private key."""
        return self._add(Credential(
            cred_type="ssh_key", username=username, secret=key_material,
            service=service, source=source, module=module,
            confidence=confidence, metadata=metadata or {},
        ))

    def add_username(self, username: str, *, source: str = "",
                     module: str = "", domain: str = "",
                     confidence: str = "high",
                     metadata: Optional[Dict] = None) -> Optional[Credential]:
        """Add a bare username (no password yet)."""
        return self._add(Credential(
            cred_type="username", username=username, secret="",
            domain=domain, source=source, module=module,
            confidence=confidence, metadata=metadata or {},
        ))

    # ── Query methods ────────────────────────────────────────────────

    def get_all(self) -> List[Credential]:
        """Return all stored credentials."""
        return list(self._credentials)

    def get_by_type(self, cred_type: str) -> List[Credential]:
        """Filter credentials by type."""
        return [c for c in self._credentials if c.cred_type == cred_type]

    def get_passwords(self) -> List[Credential]:
        """Return all password credentials."""
        return self.get_by_type("password")

    def get_hashes(self) -> List[Credential]:
        """Return all hash credentials."""
        return [c for c in self._credentials if c.cred_type.startswith("hash_")]

    def get_tokens(self) -> List[Credential]:
        """Return all token credentials."""
        return [c for c in self._credentials if c.cred_type.startswith("token_")]

    def get_usernames(self) -> List[str]:
        """Return a deduplicated list of all known usernames."""
        names: set = set()
        for c in self._credentials:
            if c.username:
                names.add(c.username)
        return sorted(names)

    def get_for_service(self, service: str) -> List[Credential]:
        """Return credentials applicable to a given service."""
        service = service.lower()
        return [c for c in self._credentials
                if c.service.lower() == service or not c.service]

    def get_for_module(self, module: str) -> List[Credential]:
        """Return credentials discovered by a specific module."""
        return [c for c in self._credentials if c.module == module]

    def count(self) -> int:
        """Total credential count."""
        return len(self._credentials)

    def summary(self) -> Dict[str, int]:
        """Count credentials by type."""
        counts: Dict[str, int] = {}
        for c in self._credentials:
            counts[c.cred_type] = counts.get(c.cred_type, 0) + 1
        return counts

    # ── Auto-discovery from LootManager ──────────────────────────────

    def ingest_from_loot(self, loot_manager) -> int:
        """Parse a LootManager and auto-import credentials.

        Recognises loot types: credential, hash, token, user.

        Returns:
            Number of new credentials added.
        """
        added = 0
        for item in loot_manager.get_all():
            cred = None
            if item.loot_type == "credential":
                meta = item.metadata or {}
                cred = self.add_password(
                    username=meta.get("username", ""),
                    password=meta.get("password", item.value),
                    source=item.source, module=item.module,
                    service=meta.get("service", ""),
                    confidence=item.confidence,
                )
            elif item.loot_type == "hash":
                meta = item.metadata or {}
                cred = self.add_hash(
                    hash_value=item.value,
                    hash_type=meta.get("hash_type", "other"),
                    username=meta.get("username", ""),
                    source=item.source, module=item.module,
                    confidence=item.confidence,
                )
            elif item.loot_type == "token":
                cred = self.add_token(
                    token=item.value, source=item.source,
                    module=item.module, confidence=item.confidence,
                )
            elif item.loot_type == "user":
                meta = item.metadata or {}
                cred = self.add_username(
                    username=item.value, source=item.source,
                    module=item.module, domain=meta.get("domain", ""),
                    confidence=item.confidence,
                )
            if cred is not None:
                added += 1
        return added

    def contribute_to_loot(self, loot_manager) -> int:
        """Push vault credentials back into a LootManager.

        Returns:
            Number of new loot items added.
        """
        added = 0
        for c in self._credentials:
            if c.cred_type == "password":
                item = loot_manager.add_credential(
                    c.username, c.secret, c.source, c.module,
                    service=c.service, confidence=c.confidence,
                )
            elif c.cred_type.startswith("hash_"):
                ht = c.metadata.get("hash_type", "other")
                item = loot_manager.add_hash(
                    c.secret, ht, c.source, c.module, username=c.username,
                )
            elif c.cred_type == "username":
                item = loot_manager.add_user(
                    c.username, c.source, c.module, domain=c.domain,
                    confidence=c.confidence,
                )
            else:
                item = loot_manager.add(
                    c.cred_type, c.secret, c.source, c.module,
                    confidence=c.confidence,
                    metadata={"username": c.username, **c.metadata},
                )
            # LootManager.add returns existing item on dup; not None
            if item is not None:
                added += 1
        return added

    # ── Validation ───────────────────────────────────────────────────

    def mark_validated(self, cred_id: str, validated: bool = True):
        """Mark a credential as validated / invalid."""
        for c in self._credentials:
            if c.id == cred_id:
                c.validated = validated
                return
        raise CredentialVaultError(f"Credential {cred_id} not found")

    def get_validated(self) -> List[Credential]:
        """Return only validated credentials."""
        return [c for c in self._credentials if c.validated]

    # ── Persistence ──────────────────────────────────────────────────

    def to_json(self) -> str:
        """Serialise the vault to JSON."""
        return json.dumps([asdict(c) for c in self._credentials], indent=2)

    def save(self, path: Path):
        """Save the vault to a file (optionally encrypted)."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        plaintext = self.to_json()

        if self.encrypt:
            key = self._get_or_create_key()
            fernet = Fernet(key)
            enc = fernet.encrypt(plaintext.encode())
            enc_path = path.with_suffix(path.suffix + ".enc")
            enc_path.write_bytes(enc)
            enc_path.chmod(0o600)
        else:
            warnings.warn(
                f"Writing credential vault to {path} in PLAINTEXT (encrypt=False). "
                "Pass encrypt=True / --encrypt-loot to encrypt vault files at rest.",
                stacklevel=2,
            )
            path.write_text(plaintext)
            path.chmod(0o600)

    def load(self, path: Path):
        """Load credentials from a JSON (or encrypted) file.

        Deduplication is applied against the current vault contents.
        """
        path = Path(path)
        if path.suffix == ".enc":
            if not _HAS_CRYPTO:
                raise CredentialVaultError("cryptography package required to decrypt vault")
            key = self._get_or_create_key()
            fernet = Fernet(key)
            data_str = fernet.decrypt(path.read_bytes()).decode()
        else:
            data_str = path.read_text()

        items = json.loads(data_str)
        for item in items:
            item.pop("id", None)
            item.pop("timestamp", None)
            cred = Credential(**item)
            self._add(cred)

    def _get_or_create_key(self) -> bytes:
        """Resolve the Fernet encryption key.

        Precedence:
          1. RECONFORGE_VAULT_KEY env var (base64 urlsafe Fernet key) —
             keeps the key off disk entirely, recommended if the vault
             file itself may leave this machine.
          2. Existing on-disk key file.
          3. Newly generated on-disk key file (mode 0600).
        """
        env_key = os.environ.get("RECONFORGE_VAULT_KEY", "").strip()
        if env_key:
            return env_key.encode()

        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        if self._key_path.exists():
            return self._key_path.read_bytes().strip()
        key = Fernet.generate_key()
        self._key_path.write_bytes(key)
        self._key_path.chmod(0o600)
        return key

    # ── Export helpers ────────────────────────────────────────────────

    def export_usernames(self, path: Optional[Path] = None) -> List[str]:
        """Export unique usernames (optionally to a file)."""
        names = self.get_usernames()
        if path:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(names) + "\n")
        return names

    def export_passwords(self, path: Optional[Path] = None) -> List[str]:
        """Export unique passwords (optionally to a file)."""
        passwords = sorted({c.secret for c in self.get_passwords() if c.secret})
        if path:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(passwords) + "\n")
        return passwords

    def export_hashes(self, path: Optional[Path] = None) -> List[str]:
        """Export hashes in ``username:hash`` format."""
        lines = [f"{c.username}:{c.secret}" for c in self.get_hashes()]
        if path:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(lines) + "\n")
        return lines

    def __len__(self) -> int:
        return len(self._credentials)

    def __repr__(self) -> str:
        return f"<CredentialVault credentials={len(self._credentials)}>"
