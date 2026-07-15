"""Secret resolution with pluggable providers.

Supported providers:
- env (default)
- file (JSON key/value map)
- aws_secretsmanager (optional boto3)
- vault (HashiCorp Vault KV v2 over HTTP API)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class SecretManager:
    """Resolve secrets by key from configured providers.

    Providers:
      - env: environment variables
      - file: JSON file key-value map
      - aws_secretsmanager: AWS Secrets Manager (requires boto3)
      - vault: HashiCorp Vault KV v2
    """

    def __init__(self, provider: str = "env", file_path: str = ""):
        self.provider = provider
        self.file_path = file_path
        self._file_cache: dict[str, Any] | None = None
        self._aws_cache: dict[str, dict[str, Any]] = {}

    def _load_file(self) -> dict[str, Any]:
        if self._file_cache is not None:
            return self._file_cache
        if not self.file_path:
            self._file_cache = {}
            return self._file_cache
        p = Path(self.file_path)
        if not p.exists():
            self._file_cache = {}
            return self._file_cache
        try:
            self._file_cache = json.loads(p.read_text())
        except Exception:
            self._file_cache = {}
        return self._file_cache

    def get(self, key: str, default: str = "") -> str:
        if self.provider == "file":
            data = self._load_file()
            value = data.get(key, default)
            return str(value) if value is not None else default
        if self.provider == "aws_secretsmanager":
            return self._from_aws(key, default)
        if self.provider == "vault":
            return self._from_vault(key, default)
        value = os.getenv(key, default)
        return value if value is not None else default

    def _from_aws(self, key: str, default: str) -> str:
        """Resolve KEY from AWS Secrets Manager.

        Expected format:
            <secret_id>:<field>
        Example:
            prod/reconforge:siem_token
        """
        try:  # optional dependency
            import boto3
        except Exception:
            return os.getenv(key, default) or default

        if ":" not in key:
            return default
        secret_id, field = key.split(":", 1)
        cache_key = secret_id.strip()
        if cache_key not in self._aws_cache:
            region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
            client = boto3.client("secretsmanager", region_name=region)
            try:
                response = client.get_secret_value(SecretId=cache_key)
                secret_str = response.get("SecretString", "{}")
                self._aws_cache[cache_key] = json.loads(secret_str)
            except Exception:
                self._aws_cache[cache_key] = {}
        value = self._aws_cache.get(cache_key, {}).get(field.strip(), default)
        return str(value) if value is not None else default

    def _from_vault(self, key: str, default: str) -> str:
        """Resolve KEY from Vault KV v2.

        Expected format:
            <mount>/<path>#<field>
        Example:
            secret/reconforge/prod#siem_token
        """
        base_url = os.getenv("VAULT_ADDR", "").rstrip("/")
        token = os.getenv("VAULT_TOKEN", "")
        if not base_url or not token or "#" not in key:
            return default
        if not base_url.startswith(("http://", "https://")):
            # VAULT_ADDR is operator-set config, not attacker input, but
            # reject non-http(s) schemes before urlopen regardless.
            return default

        path_ref, field = key.split("#", 1)
        parts = path_ref.strip("/").split("/", 1)
        if len(parts) != 2:
            return default
        mount, secret_path = parts
        url = f"{base_url}/v1/{mount}/data/{secret_path}"
        req = urllib.request.Request(url, method="GET")
        req.add_header("X-Vault-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310 - scheme checked above
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
            return default

        data = payload.get("data", {}).get("data", {})
        value = data.get(field.strip(), default)
        return str(value) if value is not None else default
