"""Tests for core.notes_manager – NotesManager, focused on secret redaction.

Session notes are persisted to disk as plain Markdown, so anything routed
through add_command_note() must never carry a plaintext secret through.
"""

from core.notes_manager import NotesManager


def test_add_command_note_redacts_password_in_command():
    notes = NotesManager(target="10.10.10.1")
    notes.add_command_note("smbclient -U admin -p SuperSecret123 //10.10.10.1/share", "OK")
    md = notes.to_markdown()
    assert "SuperSecret123" not in md
    assert "REDACTED" in md


def test_add_command_note_redacts_secret_in_result_summary():
    notes = NotesManager(target="10.10.10.1")
    notes.add_command_note("curl http://x", "Auth succeeded with password=hunter2hunter2")
    md = notes.to_markdown()
    assert "hunter2hunter2" not in md
    assert "REDACTED" in md


def test_add_command_note_preserves_clean_content():
    notes = NotesManager(target="10.10.10.1")
    notes.add_command_note("nmap -sV 10.10.10.1", "12 open ports found")
    md = notes.to_markdown()
    assert "nmap -sV 10.10.10.1" in md
    assert "12 open ports found" in md
