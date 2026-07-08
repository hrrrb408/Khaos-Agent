from pathlib import Path

from khaos.security.path_guard import PathGuard


def test_read_safe(tmp_path):
    file_path = tmp_path / "note.txt"
    file_path.write_text("hello", encoding="utf-8")

    result = PathGuard(project_root=str(tmp_path)).check_read(str(file_path))

    assert result.safe is True
    assert result.risk_level == "safe"


def test_read_sensitive_file():
    result = PathGuard().check_read("/etc/shadow")

    assert result.safe is False
    assert result.risk_level == "sensitive"


def test_read_ssh_key():
    result = PathGuard().check_read("~/.ssh/id_rsa")

    assert result.safe is False
    assert result.risk_level == "sensitive"


def test_write_protected_dir():
    result = PathGuard().check_write("/etc/khaos.conf")

    assert result.safe is False
    assert result.risk_level == "protected"


def test_write_system_dir():
    result = PathGuard().check_write("/usr/local/bin/khaos")

    assert result.safe is False
    assert result.risk_level == "protected"


def test_write_home_allowed():
    result = PathGuard().check_write("~/khaos-note.txt")

    assert result.safe is True


def test_path_traversal(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    traversal = root / ".." / ".." / "etc" / "passwd"

    result = PathGuard(project_root=str(root), allow_writes_to_home=False).check_read(
        str(traversal)
    )

    assert result.safe is False
    assert result.risk_level == "protected"


def test_symlink_escape(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = root / "link.txt"
    link.symlink_to(outside)

    result = PathGuard(project_root=str(root), allow_writes_to_home=False).check_write(str(link))

    assert result.safe is False
    assert result.risk_level == "protected"


def test_relative_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file_path = Path("note.txt")

    result = PathGuard(project_root=str(tmp_path)).check_write(str(file_path))

    assert result.safe is True
    assert result.normalized_path == str((tmp_path / "note.txt").resolve())
