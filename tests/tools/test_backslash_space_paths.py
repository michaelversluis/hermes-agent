"""Regression tests for backslash-escaped space in LLM-supplied paths (#42556).

Root cause: _resolve_path_for_task() called Path(filepath).expanduser() without
first unescaping shell-style '\\ ' (backslash-space) sequences, so a path like
'~/Documents/Obsidian\\ Vault/test.md' created a directory literally named
'Obsidian\\ Vault' instead of writing to 'Obsidian Vault'.

Core invariants pinned by these tests:
  - POSIX: backslash-space is unescaped before path resolution
  - Windows (mocked): backslash is the separator and must NOT be touched
  - Paths without backslash-space are unchanged (regression guard)
"""

import json
import sys
import unittest.mock
from pathlib import Path

import pytest

import tools.file_tools as ft


# ── Unit tests for _unescape_shell_path ──────────────────────────────────────


class TestUnescapeShellPath:
    def test_unescapes_backslash_space_on_posix(self, monkeypatch):
        monkeypatch.setattr(ft.sys, "platform", "linux")
        assert ft._unescape_shell_path("Obsidian\\ Vault") == "Obsidian Vault"

    def test_multiple_backslash_spaces(self, monkeypatch):
        monkeypatch.setattr(ft.sys, "platform", "linux")
        assert ft._unescape_shell_path("My\\ Docs/Some\\ Folder/file.md") == "My Docs/Some Folder/file.md"

    def test_tilde_prefix_with_escaped_space(self, monkeypatch):
        monkeypatch.setattr(ft.sys, "platform", "linux")
        result = ft._unescape_shell_path("~/Obsidian\\ Vault/test.md")
        assert result == "~/Obsidian Vault/test.md"

    def test_plain_path_unchanged(self, monkeypatch):
        monkeypatch.setattr(ft.sys, "platform", "linux")
        assert ft._unescape_shell_path("/home/user/docs/file.txt") == "/home/user/docs/file.txt"

    def test_windows_backslash_not_touched(self, monkeypatch):
        monkeypatch.setattr(ft.sys, "platform", "win32")
        # On Windows, backslash is a separator — must not be modified
        assert ft._unescape_shell_path("C:\\Users\\user\\docs") == "C:\\Users\\user\\docs"

    def test_windows_backslash_space_not_touched(self, monkeypatch):
        monkeypatch.setattr(ft.sys, "platform", "win32")
        raw = "C:\\Documents\\ Notes\\file.txt"
        assert ft._unescape_shell_path(raw) == raw

    def test_darwin_treated_as_posix(self, monkeypatch):
        monkeypatch.setattr(ft.sys, "platform", "darwin")
        assert ft._unescape_shell_path("~/My\\ Vault/note.md") == "~/My Vault/note.md"


# ── _resolve_path_for_task: POSIX backslash-space ────────────────────────────


class TestResolvePathBackslashSpace:
    @pytest.fixture(autouse=True)
    def _posix(self, monkeypatch):
        monkeypatch.setattr(ft.sys, "platform", "linux")

    @pytest.fixture
    def workspace(self, tmp_path, monkeypatch):
        ws = tmp_path / "Obsidian Vault"
        ws.mkdir()
        monkeypatch.setattr(ft, "_get_live_tracking_cwd", lambda task_id="default": str(tmp_path))
        return ws

    def test_escaped_relative_path_resolves_to_unescaped_dir(self, workspace, tmp_path):
        resolved = ft._resolve_path_for_task("Obsidian\\ Vault/note.md")
        assert resolved == tmp_path / "Obsidian Vault" / "note.md"
        assert "\\" not in str(resolved)

    def test_escaped_absolute_path_resolves_correctly(self, tmp_path):
        escaped = str(tmp_path) + "/Obsidian\\ Vault/note.md"
        resolved = ft._resolve_path_for_task(escaped)
        assert resolved == tmp_path / "Obsidian Vault" / "note.md"
        assert "\\" not in str(resolved)

    def test_tilde_path_with_escaped_space(self, monkeypatch, tmp_path):
        fake_home = tmp_path / "home"
        vault = fake_home / "Obsidian Vault"
        vault.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setattr(ft, "_get_live_tracking_cwd", lambda task_id="default": None)
        monkeypatch.delenv("TERMINAL_CWD", raising=False)

        resolved = ft._resolve_path_for_task("~/Obsidian\\ Vault/test.md")
        assert resolved == fake_home / "Obsidian Vault" / "test.md"
        assert "\\" not in str(resolved)

    def test_plain_path_unchanged(self, workspace, tmp_path):
        resolved = ft._resolve_path_for_task("Obsidian Vault/note.md")
        assert resolved == tmp_path / "Obsidian Vault" / "note.md"

    def test_no_literal_backslash_dir_created(self, tmp_path, monkeypatch):
        """The regression: backslash-space must NOT create a dir named 'Obsidian\\ Vault'."""
        monkeypatch.setattr(ft, "_get_live_tracking_cwd", lambda task_id="default": str(tmp_path))
        resolved = ft._resolve_path_for_task("Obsidian\\ Vault/note.md")
        assert "Obsidian\\ Vault" not in str(resolved)
        assert "Obsidian Vault" in str(resolved)

    def test_windows_backslash_separator_not_touched(self, monkeypatch, tmp_path):
        monkeypatch.setattr(ft.sys, "platform", "win32")
        monkeypatch.setattr(ft, "_get_live_tracking_cwd", lambda task_id="default": str(tmp_path))
        # On Windows, "dir\\ file.txt" is a path separator sequence — do not mangle
        raw = str(tmp_path) + "/plain_file.txt"
        resolved = ft._resolve_path_for_task(raw)
        assert resolved == Path(raw).resolve()


# ── write_file_tool: end-to-end escaped-path write ───────────────────────────


class TestWriteFileBackslashSpace:
    @pytest.fixture(autouse=True)
    def _posix(self, monkeypatch):
        monkeypatch.setattr(ft.sys, "platform", "linux")
        # Bypass the sensitive-path guard — tmp_path on macOS is under
        # /private/var/folders, which matches the _SENSITIVE_PATH_PREFIXES
        # guard. We're testing path unescaping, not sensitive-path filtering.
        monkeypatch.setattr(ft, "_check_sensitive_path", lambda path, task_id="default": None)

    def test_write_file_with_escaped_space_lands_at_unescaped_path(self, tmp_path, monkeypatch):
        vault = tmp_path / "Obsidian Vault"
        vault.mkdir()
        monkeypatch.setattr(ft, "_get_live_tracking_cwd", lambda task_id="default": str(tmp_path))

        escaped = str(tmp_path) + "/Obsidian\\ Vault/test.md"
        out = json.loads(ft.write_file_tool(escaped, "hello\n", task_id="t1"))

        assert not out.get("error"), out
        expected = str((vault / "test.md").resolve())
        assert out.get("resolved_path") == expected
        assert out.get("files_modified") == [expected]
        assert (vault / "test.md").read_text() == "hello\n"
        # No directory with a literal backslash should exist
        assert not (tmp_path / "Obsidian\\ Vault").exists()

    def test_write_file_relative_escaped_path(self, tmp_path, monkeypatch):
        vault = tmp_path / "My Notes"
        vault.mkdir()
        monkeypatch.setattr(ft, "_get_live_tracking_cwd", lambda task_id="default": str(tmp_path))

        out = json.loads(ft.write_file_tool("My\\ Notes/idea.txt", "content\n", task_id="t2"))

        assert not out.get("error"), out
        assert (vault / "idea.txt").read_text() == "content\n"

    def test_write_file_plain_path_unaffected(self, tmp_path, monkeypatch):
        notes = tmp_path / "notes"
        notes.mkdir()
        monkeypatch.setattr(ft, "_get_live_tracking_cwd", lambda task_id="default": str(tmp_path))

        out = json.loads(ft.write_file_tool(str(tmp_path) + "/notes/file.txt", "data\n", task_id="t3"))

        assert not out.get("error"), out
        assert (notes / "file.txt").read_text() == "data\n"


# ── read_file_tool: escaped-path read ────────────────────────────────────────


class TestReadFileBackslashSpace:
    @pytest.fixture(autouse=True)
    def _posix(self, monkeypatch):
        monkeypatch.setattr(ft.sys, "platform", "linux")

    def test_read_file_with_escaped_space(self, tmp_path, monkeypatch):
        vault = tmp_path / "Obsidian Vault"
        vault.mkdir()
        (vault / "note.md").write_text("# My Note\n")
        monkeypatch.setattr(ft, "_get_live_tracking_cwd", lambda task_id="default": str(tmp_path))

        escaped = str(tmp_path) + "/Obsidian\\ Vault/note.md"
        out = json.loads(ft.read_file_tool(escaped, task_id="t1"))

        assert not out.get("error"), out
        assert "# My Note" in out.get("content", "")

    def test_read_file_plain_path_unaffected(self, tmp_path, monkeypatch):
        (tmp_path / "plain.txt").write_text("plain content\n")
        monkeypatch.setattr(ft, "_get_live_tracking_cwd", lambda task_id="default": str(tmp_path))

        out = json.loads(ft.read_file_tool(str(tmp_path) + "/plain.txt", task_id="t2"))

        assert not out.get("error"), out
        assert "plain content" in out.get("content", "")


# ── patch_tool: escaped-path replace ─────────────────────────────────────────


class TestPatchToolBackslashSpace:
    @pytest.fixture(autouse=True)
    def _posix(self, monkeypatch):
        monkeypatch.setattr(ft.sys, "platform", "linux")
        # Bypass the sensitive-path guard for the same macOS tmp_path reason
        # as in TestWriteFileBackslashSpace.
        monkeypatch.setattr(ft, "_check_sensitive_path", lambda path, task_id="default": None)

    def test_patch_replace_with_escaped_space_path(self, tmp_path, monkeypatch):
        vault = tmp_path / "Obsidian Vault"
        vault.mkdir()
        (vault / "note.md").write_text("ORIGINAL_CONTENT\n")
        monkeypatch.setattr(ft, "_get_live_tracking_cwd", lambda task_id="default": str(tmp_path))

        escaped = str(tmp_path) + "/Obsidian\\ Vault/note.md"
        out = json.loads(ft.patch_tool(
            mode="replace", path=escaped,
            old_string="ORIGINAL_CONTENT", new_string="PATCHED_CONTENT",
            task_id="t1",
        ))

        assert not out.get("error"), out
        assert (vault / "note.md").read_text() == "PATCHED_CONTENT\n"
        expected = str((vault / "note.md").resolve())
        assert out.get("resolved_path") == expected
        assert out.get("files_modified") == [expected]

    def test_patch_replace_relative_escaped_path(self, tmp_path, monkeypatch):
        vault = tmp_path / "My Notes"
        vault.mkdir()
        (vault / "idea.txt").write_text("draft\n")
        monkeypatch.setattr(ft, "_get_live_tracking_cwd", lambda task_id="default": str(tmp_path))

        out = json.loads(ft.patch_tool(
            mode="replace", path="My\\ Notes/idea.txt",
            old_string="draft", new_string="final",
            task_id="t2",
        ))

        assert not out.get("error"), out
        assert (vault / "idea.txt").read_text() == "final\n"

    def test_patch_plain_path_unaffected(self, tmp_path, monkeypatch):
        (tmp_path / "script.py").write_text("x = 1\n")
        monkeypatch.setattr(ft, "_get_live_tracking_cwd", lambda task_id="default": str(tmp_path))

        out = json.loads(ft.patch_tool(
            mode="replace", path=str(tmp_path) + "/script.py",
            old_string="x = 1", new_string="x = 2",
            task_id="t3",
        ))

        assert not out.get("error"), out
        assert (tmp_path / "script.py").read_text() == "x = 2\n"


# ── _is_blocked_device: escaped device paths ─────────────────────────────────


class TestIsBlockedDeviceBackslashSpace:
    @pytest.fixture(autouse=True)
    def _posix(self, monkeypatch):
        monkeypatch.setattr(ft.sys, "platform", "linux")

    def test_escaped_dev_zero_is_blocked(self):
        # '/dev/ze\ ro' would unescape to '/dev/ze ro' — not a real device,
        # so this checks we're not falsely matching. Real concern: ensure a
        # plain '/dev/zero' is still blocked after the refactor.
        assert ft._is_blocked_device("/dev/zero") is True

    def test_plain_path_not_blocked(self, tmp_path):
        assert ft._is_blocked_device(str(tmp_path / "file.txt")) is False
