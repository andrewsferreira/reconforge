"""Phase 5-C: ADModule validates --domain through core.validators.validate_domain."""

import pytest

from core.exceptions import ValidationError
from modules.ad.ad_module import ADModule


def test_ad_module_accepts_valid_domain(config_dir):
    mod = ADModule("10.10.10.1", domain="corp.local", config_dir=config_dir)
    assert mod.domain == "corp.local"


def test_ad_module_accepts_empty_domain(config_dir):
    """Empty domain is valid — it means 'not yet known', discovered mid-run."""
    mod = ADModule("10.10.10.1", config_dir=config_dir)
    assert mod.domain == ""


def test_ad_module_rejects_invalid_domain(config_dir):
    with pytest.raises(ValidationError):
        ADModule("10.10.10.1", domain="not a domain; rm -rf /", config_dir=config_dir)


def test_ad_module_rejects_single_label_domain(config_dir):
    with pytest.raises(ValidationError):
        ADModule("10.10.10.1", domain="corp", config_dir=config_dir)
