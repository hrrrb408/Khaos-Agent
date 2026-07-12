"""Tests for strict LSP URI → workspace path mapping (spec §4).

Covers:
    - Workspace-internal URI acceptance
    - Workspace-external URI rejection
    - Other Task Workspace URI rejection
    - Non-file URI rejection
    - ``..`` traversal rejection
    - URI percent-decode (spaces, Unicode)
    - Unicode filenames
    - Symlink escape rejection
    - macOS/Linux case semantics (resolve-based comparison)
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from khaos.coding.intelligence.lsp.uri import (
    NonFileUriError,
    SymlinkEscapeError,
    WorkspaceEscapeError,
    map_lsp_uri_to_workspace_path,
    path_to_file_uri,
    workspace_root_from_uri,
)


def _make_workspace(tmp_path: Path) -> Path:
    """Create a workspace root with a source file inside."""
    root = tmp_path / "workspace"
    root.mkdir(parents=True)
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return root.resolve()


class TestWorkspaceInternalUri:
    def test_internal_uri_accepted(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        uri = (root / "src" / "app.py").as_uri()
        result = map_lsp_uri_to_workspace_path(uri, root)
        assert result == "src/app.py"

    def test_root_level_file_accepted(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        (root / "main.py").write_text("x = 1\n", encoding="utf-8")
        uri = (root / "main.py").as_uri()
        result = map_lsp_uri_to_workspace_path(uri, root)
        assert result == "main.py"

    def test_nested_directory_accepted(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        (root / "src" / "deep" / "nested").mkdir(parents=True)
        (root / "src" / "deep" / "nested" / "mod.py").write_text("y = 2\n", encoding="utf-8")
        uri = (root / "src" / "deep" / "nested" / "mod.py").as_uri()
        result = map_lsp_uri_to_workspace_path(uri, root)
        assert result == "src/deep/nested/mod.py"


class TestWorkspaceExternalRejection:
    def test_external_path_rejected(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        # File outside the workspace
        external = tmp_path / "external.py"
        external.write_text("z = 3\n", encoding="utf-8")
        uri = external.as_uri()
        with pytest.raises(WorkspaceEscapeError) as exc_info:
            map_lsp_uri_to_workspace_path(uri, root)
        assert exc_info.value.code == "workspace-external"

    def test_other_task_workspace_rejected(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        other_root = tmp_path / "other-workspace"
        other_root.mkdir()
        (other_root / "secret.py").write_text("secret = 1\n", encoding="utf-8")
        other_resolved = other_root.resolve()
        uri = (other_root / "secret.py").as_uri()
        with pytest.raises(WorkspaceEscapeError) as exc_info:
            map_lsp_uri_to_workspace_path(uri, root, other_workspace_roots=(other_resolved,))
        assert exc_info.value.code == "other-task-workspace"

    def test_non_file_uri_rejected(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        with pytest.raises(NonFileUriError) as exc_info:
            map_lsp_uri_to_workspace_path("http://example.com/file.py", root)
        assert exc_info.value.code == "non-file-uri"

    def test_ftp_uri_rejected(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        with pytest.raises(NonFileUriError):
            map_lsp_uri_to_workspace_path("ftp://host/file.py", root)

    def test_dotdot_traversal_rejected(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        # Build a URI with .. in the path
        uri = "file://" + str(root / "src" / ".." / ".." / "etc" / "passwd")
        with pytest.raises(WorkspaceEscapeError) as exc_info:
            map_lsp_uri_to_workspace_path(uri, root)
        assert exc_info.value.code == "dotdot-traversal"


class TestPercentDecode:
    def test_space_in_filename_decoded(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        (root / "my file.py").write_text("a = 1\n", encoding="utf-8")
        # Manually construct a percent-encoded URI
        uri = "file://" + str(root).replace(" ", "%20") + "/my%20file.py"
        result = map_lsp_uri_to_workspace_path(uri, root)
        assert result == "my file.py"

    def test_unicode_filename_decoded(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        unicode_name = "数据.py"
        (root / unicode_name).write_text("b = 2\n", encoding="utf-8")
        # Percent-encode the Unicode filename
        from urllib.parse import quote
        encoded = quote(unicode_name)
        uri = "file://" + str(root) + "/" + encoded
        result = map_lsp_uri_to_workspace_path(uri, root)
        assert result == unicode_name

    def test_chinese_path_decoded(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        (root / "源码").mkdir()
        (root / "源码" / "模块.py").write_text("c = 3\n", encoding="utf-8")
        from urllib.parse import quote
        uri = "file://" + str(root) + "/" + quote("源码") + "/" + quote("模块.py")
        result = map_lsp_uri_to_workspace_path(uri, root)
        assert result == "源码/模块.py"


class TestSymlinkEscape:
    @pytest.mark.skipif(os.name != "posix", reason="symlink semantics are POSIX-only")
    def test_symlink_escaping_workspace_rejected(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        # Create a symlink inside the workspace pointing outside
        external = tmp_path / "external_target.py"
        external.write_text("escaped = True\n", encoding="utf-8")
        link = root / "link_to_external.py"
        os.symlink(external, link)
        uri = link.as_uri()
        with pytest.raises((SymlinkEscapeError, WorkspaceEscapeError)):
            map_lsp_uri_to_workspace_path(uri, root)

    @pytest.mark.skipif(os.name != "posix", reason="symlink semantics are POSIX-only")
    def test_symlink_within_workspace_accepted(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        # Create a symlink inside the workspace pointing to another file inside
        target = root / "src" / "target.py"
        target.write_text("inner = True\n", encoding="utf-8")
        link = root / "link_to_inner.py"
        os.symlink(target, link)
        uri = link.as_uri()
        # The symlink target is inside the workspace, so it should be accepted.
        # The result will be the resolved target path, not the link path.
        result = map_lsp_uri_to_workspace_path(uri, root)
        assert result == "src/target.py"


class TestPathToUri:
    def test_path_to_file_uri_roundtrip(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        file = root / "src" / "app.py"
        uri = path_to_file_uri(file)
        assert uri.startswith("file://")
        # Round-trip: decode back to path
        decoded = workspace_root_from_uri(uri)
        assert decoded.resolve() == file.resolve()

    def test_path_to_file_uri_no_backslashes(self, tmp_path: Path):
        root = _make_workspace(tmp_path)
        file = root / "src" / "app.py"
        uri = path_to_file_uri(file)
        assert "\\" not in uri
