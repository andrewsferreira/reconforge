"""ReconForge Loot Manager - Credential, hash, and loot tracking.

Supports optional Fernet symmetric encryption via ``--encrypt-loot``.
When encryption is enabled, loot files are written as encrypted blobs
and a key file is stored in ``~/.reconforge/loot.key``.
"""

import base64
import json
import os
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
from pathlib import Path
from datetime import datetime
from core.data_contracts import build_contract

try:
    from cryptography.fernet import Fernet
    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover – optional dependency
    _HAS_CRYPTO = False


_KEY_DIR = Path.home() / ".reconforge"
_KEY_FILE = _KEY_DIR / "loot.key"


def _get_or_create_key() -> bytes:
    """Load existing Fernet key or generate a new one.

    The key is stored at ``~/.reconforge/loot.key`` with mode 0600.
    """
    _KEY_DIR.mkdir(parents=True, exist_ok=True)
    if _KEY_FILE.exists():
        return _KEY_FILE.read_bytes().strip()
    key = Fernet.generate_key()
    _KEY_FILE.write_bytes(key)
    _KEY_FILE.chmod(0o600)
    return key


@dataclass
class LootItem:
    """A single piece of loot."""
    loot_type: str  # credential, hash, token, share, user, service
    value: str
    source: str
    module: str
    confidence: str = "medium"
    metadata: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class LootManager:
    """Track and manage all loot discovered during recon.

    Args:
        encrypt: If ``True``, loot files are encrypted with Fernet.
                 Requires the ``cryptography`` package.
    """

    def __init__(self, encrypt: bool = False):
        self._loot: List[LootItem] = []
        self.encrypt = encrypt and _HAS_CRYPTO
        if encrypt and not _HAS_CRYPTO:
            import warnings
            warnings.warn(
                "cryptography package not installed — loot will be stored in plaintext. "
                "Install with: pip install cryptography"
            )

    def add(self, loot_type: str, value: str, source: str, module: str,
            confidence: str = "medium", metadata: Optional[Dict] = None) -> LootItem:
        """Add a loot item."""
        item = LootItem(
            loot_type=loot_type, value=value, source=source,
            module=module, confidence=confidence, metadata=metadata or {}
        )
        # Avoid duplicates
        for existing in self._loot:
            if existing.loot_type == loot_type and existing.value == value:
                return existing
        self._loot.append(item)
        return item

    def add_credential(self, username: str, password: str, source: str,
                       module: str, service: str = "", confidence: str = "confirmed") -> LootItem:
        """Add a credential pair."""
        return self.add("credential", f"{username}:{password}", source, module,
                        confidence, {"username": username, "password": password, "service": service})

    def add_hash(self, hash_value: str, hash_type: str, source: str,
                 module: str, username: str = "") -> LootItem:
        """Add a password hash."""
        return self.add("hash", hash_value, source, module, "confirmed",
                        {"hash_type": hash_type, "username": username})

    def add_user(self, username: str, source: str, module: str,
                 domain: str = "", confidence: str = "high") -> LootItem:
        """Add an enumerated username."""
        return self.add("user", username, source, module, confidence,
                        {"domain": domain})

    def add_share(self, share_path: str, permissions: str, source: str,
                  module: str, anonymous: bool = False) -> LootItem:
        """Add an accessible share."""
        return self.add("share", share_path, source, module, "confirmed",
                        {"permissions": permissions, "anonymous": anonymous})

    def add_service(self, service: str, version: str, port: int,
                    source: str, module: str) -> LootItem:
        """Add a service/version finding."""
        return self.add("service", f"{service}/{version}", source, module, "confirmed",
                        {"service": service, "version": version, "port": port})

    def get_by_type(self, loot_type: str) -> List[LootItem]:
        """Get all loot of a specific type."""
        return [item for item in self._loot if item.loot_type == loot_type]

    def get_all(self) -> List[LootItem]:
        """Get all loot items."""
        return list(self._loot)

    def get_users(self) -> List[str]:
        """Get all enumerated usernames."""
        return [item.value for item in self._loot if item.loot_type == "user"]

    def get_credentials(self) -> List[Dict]:
        """Get all credentials."""
        return [item.metadata for item in self._loot if item.loot_type == "credential"]

    def to_json(self) -> str:
        """Export loot as JSON."""
        return json.dumps([asdict(item) for item in self._loot], indent=2)

    def to_contract_json(self, execution_id: str = "", module: str = "") -> str:
        payload = [asdict(item) for item in self._loot]
        contract = build_contract("loot", payload, execution_id=execution_id, module=module)
        return json.dumps(contract, indent=2)

    def save(self, path: Path):
        """Save loot to file.

        If encryption is enabled, the output file is written as an
        encrypted blob (binary) with a ``.enc`` suffix appended, and
        the Fernet key is stored in ``~/.reconforge/loot.key``.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        plaintext = self.to_json()

        if self.encrypt:
            key = _get_or_create_key()
            fernet = Fernet(key)
            encrypted = fernet.encrypt(plaintext.encode("utf-8"))
            enc_path = path.with_suffix(path.suffix + ".enc")
            enc_path.write_bytes(encrypted)
        else:
            path.write_text(plaintext)

    def save_contract(self, path: Path, execution_id: str = "", module: str = "") -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_contract_json(execution_id=execution_id, module=module))

    @staticmethod
    def load_encrypted(path: Path) -> str:
        """Decrypt and return loot JSON from an encrypted file.

        Args:
            path: Path to the ``.enc`` file.

        Returns:
            Decrypted JSON string.

        Raises:
            RuntimeError: If cryptography is not installed.
            FileNotFoundError: If the key file is missing.
        """
        if not _HAS_CRYPTO:
            raise RuntimeError("cryptography package required to decrypt loot")
        if not _KEY_FILE.exists():
            raise FileNotFoundError(f"Loot key not found at {_KEY_FILE}")
        key = _KEY_FILE.read_bytes().strip()
        fernet = Fernet(key)
        encrypted = Path(path).read_bytes()
        return fernet.decrypt(encrypted).decode("utf-8")

    def summary(self) -> Dict[str, int]:
        """Get loot summary counts."""
        counts: Dict[str, int] = {}
        for item in self._loot:
            counts[item.loot_type] = counts.get(item.loot_type, 0) + 1
        return counts
