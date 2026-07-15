"""Shared pytest fixtures for ReconForge tests."""

import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def tmp_dir(tmp_path):
    """Provide a clean temporary directory."""
    return tmp_path


@pytest.fixture
def config_dir(tmp_path):
    """Create a temporary config directory with minimal YAML files."""
    cfg = tmp_path / "config"
    cfg.mkdir()

    (cfg / "tools.yaml").write_text(
        "tools:\n"
        "  nmap:\n"
        "    binary: nmap\n"
        "    default_timeout: 600\n"
        "  ffuf:\n"
        "    binary: ffuf\n"
        "    default_timeout: 300\n"
    )

    (cfg / "profiles.yaml").write_text(
        "profiles:\n"
        "  stealth:\n"
        "    opsec_mode: stealth\n"
        "    timing:\n"
        "      nmap_timing: T2\n"
        "      scan_delay: 500ms\n"
        "      max_retries: 1\n"
        "    allowed_noise_levels:\n"
        "      - low\n"
        "  normal:\n"
        "    opsec_mode: normal\n"
        "    timing:\n"
        "      nmap_timing: T3\n"
        "      scan_delay: '0'\n"
        "      max_retries: 2\n"
        "    allowed_noise_levels:\n"
        "      - low\n"
        "      - medium\n"
        "  aggressive:\n"
        "    opsec_mode: aggressive\n"
        "    timing:\n"
        "      nmap_timing: T4\n"
        "      scan_delay: '0'\n"
        "      max_retries: 3\n"
        "    allowed_noise_levels:\n"
        "      - low\n"
        "      - medium\n"
        "      - high\n"
        "  stealth_web:\n"
        "    opsec_mode: stealth\n"
        "    timing:\n"
        "      nmap_timing: T1\n"
        "    web:\n"
        "      phases:\n"
        "        - surface\n"
    )

    return cfg
