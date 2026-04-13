from unittest.mock import patch

from core.external_integrations import dispatch_workflow_event


class _Resp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_dispatch_workflow_event_optional(monkeypatch):
    monkeypatch.delenv("RECONFORGE_SIEM_WEBHOOK", raising=False)
    monkeypatch.delenv("RECONFORGE_TICKETING_WEBHOOK", raising=False)
    monkeypatch.delenv("RECONFORGE_APPROVAL_WEBHOOK", raising=False)
    assert dispatch_workflow_event({"ok": True}) == []


def test_dispatch_workflow_event_sends_to_configured(monkeypatch):
    monkeypatch.setenv("RECONFORGE_SIEM_WEBHOOK", "https://example.com/siem")
    with patch("urllib.request.urlopen", return_value=_Resp()):
        sent = dispatch_workflow_event({"workflow": "complete"})
    assert sent == ["siem"]
