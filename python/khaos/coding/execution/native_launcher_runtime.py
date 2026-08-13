"""Explicit-development process boundary matching the Rust launcher."""

# KHAOS-PRIVILEGED-SPAWN owner=NativeLauncherTCB threat-model=fd-bound-exec-and-codesign boundary=native-launcher

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile

try:
    import resource
except ModuleNotFoundError:  # pragma: no cover - resource is POSIX-only
    resource = None  # type: ignore[assignment]

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from khaos.security.authorityd_protocol import SignedAuthorizationReceipt


def main(argv: list[str]) -> int:
    options, command = _parse(argv)
    if options.get("require_authority_receipt"):
        receipt_fd = options.get("authority_receipt_fd")
        public_key_fd = options.get("authority_public_key_fd")
        if receipt_fd is None or public_key_fd is None:
            raise PermissionError("signed authority receipt is required")
        _verify_authority_receipt(int(receipt_fd), int(public_key_fd))
    if options.get("new_session"):
        os.setsid()
    for prefix in ("root", "cwd"):
        fd = options.get(f"{prefix}_fd")
        if fd is None:
            continue
        _verify_fd(
            int(fd),
            int(options[f"{prefix}_device"]),
            int(options[f"{prefix}_inode"]),
            prefix,
        )
    if "cwd_fd" in options:
        os.fchdir(int(options["cwd_fd"]))
    executable_fd = options.get("exec_fd")
    interpreter_fd = options.get("interpreter_fd")
    if executable_fd is not None:
        _verify_executable_fd(
            int(executable_fd), str(options.get("exec_digest") or "")
        )
        if interpreter_fd is not None:
            _verify_executable_fd(
                int(interpreter_fd), str(options.get("interpreter_digest") or "")
            )
    preserve_directory_fds = bool(options.get("preserve_directory_fds"))
    if preserve_directory_fds and (
        options.get("root_fd") is None or options.get("cwd_fd") is None
    ):
        raise ValueError(
            "preserving directory descriptors requires root and cwd bindings"
        )
    preserved = tuple(
        dict.fromkeys(
            int(options[key])
            for key in ("root_fd", "cwd_fd")
            if options.get(key) is not None
        )
    ) if preserve_directory_fds else ()
    authority_fds = (
        (int(executable_fd),)
        if executable_fd is not None
        else ()
    ) + ((int(interpreter_fd),) if interpreter_fd is not None else ())
    preserved = tuple(dict.fromkeys((*preserved, *authority_fds)))
    # Directory descriptors are authority capabilities, not child-process
    # resources.  The explicit-development launcher mirrors the Rust
    # launcher's stdio-only inheritance policy before exec.  Bubblewrap is
    # the one explicit protocol exception: it resolves a validated workspace
    # source through /proc/self/fd before constructing its mount namespace.
    _close_inherited_fds(preserved)
    staged_paths: list[str] = []
    try:
        if executable_fd is not None and interpreter_fd is not None:
            if sys.platform != "darwin":
                # The script descriptor is O_CLOEXEC. Keep it alive for the
                # interpreter exec so /proc/self/fd/<N> remains a stable
                # object path on Linux; macOS uses private staging instead.
                os.set_inheritable(int(executable_fd), True)
            interpreter_argv0 = str(
                options.get("interpreter_argv0") or "interpreter"
            )
            interpreter_path = _authority_path(
                int(interpreter_fd),
                "interpreter",
                staged_paths,
                interpreter_argv0,
            )
            script_path = _authority_path(
                int(executable_fd), "script", staged_paths, command[0]
            )
            interpreter_args = tuple(
                str(value) for value in options.get("interpreter_args", ())
            )
            exec_argv = [
                interpreter_argv0,
                *interpreter_args,
                script_path,
                *command[1:],
            ]
            _set_limit("RLIMIT_FSIZE", options)
            _set_limit("RLIMIT_NOFILE", options)
            _set_limit("RLIMIT_CPU", options)
            _set_limit("RLIMIT_AS", options)
            os.execve(interpreter_path, exec_argv, os.environ)
        elif executable_fd is not None:
            executable_path = _authority_path(
                int(executable_fd), "executable", staged_paths, command[0]
            )
            _set_limit("RLIMIT_FSIZE", options)
            _set_limit("RLIMIT_NOFILE", options)
            _set_limit("RLIMIT_CPU", options)
            _set_limit("RLIMIT_AS", options)
            os.execve(executable_path, command, os.environ)
        else:
            _set_limit("RLIMIT_FSIZE", options)
            _set_limit("RLIMIT_NOFILE", options)
            _set_limit("RLIMIT_CPU", options)
            _set_limit("RLIMIT_AS", options)
            os.execvpe(command[0], command, os.environ)
    finally:
        for path in staged_paths:
            try:
                os.unlink(path)
            except OSError:
                pass
            try:
                os.rmdir(os.path.dirname(path))
            except OSError:
                pass
    return 126


def _parse(argv: list[str]) -> tuple[dict[str, object], list[str]]:
    options: dict[str, object] = {}
    index = 0
    while index < len(argv):
        value = argv[index]
        if value == "--":
            command = argv[index + 1 :]
            if not command:
                raise ValueError("command required")
            _validate_authority_options(options)
            return options, command
        if value == "--new-session":
            if options.get("new_session"):
                raise ValueError("duplicate --new-session")
            options["new_session"] = True
            index += 1
            continue
        if value == "--preserve-directory-fds":
            if options.get("preserve_directory_fds"):
                raise ValueError("duplicate --preserve-directory-fds")
            options["preserve_directory_fds"] = True
            index += 1
            continue
        if value == "--require-authority-receipt":
            if options.get("require_authority_receipt"):
                raise ValueError("duplicate --require-authority-receipt")
            options["require_authority_receipt"] = True
            index += 1
            continue
        if not value.startswith("--") or index + 1 >= len(argv):
            raise ValueError(f"invalid launcher option: {value}")
        key = value[2:].replace("-", "_")
        if key not in {
            "root_fd",
            "root_device",
            "root_inode",
            "cwd_fd",
            "cwd_device",
            "cwd_inode",
            "rlimit_fsize",
            "rlimit_nofile",
            "rlimit_cpu",
            "rlimit_as",
            "exec_fd",
            "exec_digest",
            "interpreter_fd",
            "interpreter_digest",
            "interpreter_argv0",
            "interpreter_arg",
            "authority_receipt_fd",
            "authority_public_key_fd",
        }:
            raise ValueError(f"unknown launcher option: {value}")
        if key == "interpreter_arg":
            options.setdefault("interpreter_args", []).append(argv[index + 1])
            index += 2
            continue
        if key == "interpreter_argv0":
            if not argv[index + 1]:
                raise ValueError("interpreter argv0 must not be empty")
            options[key] = argv[index + 1]
            index += 2
            continue
        if key in options:
            raise ValueError(f"duplicate launcher option: {value}")
        raw = argv[index + 1]
        if key in {"exec_digest", "interpreter_digest"}:
            if len(raw) != 64 or any(char not in "0123456789abcdefABCDEF" for char in raw):
                raise ValueError(f"invalid launcher digest: {value}")
            options[key] = raw
        else:
            parsed = int(raw, 10)
            if parsed < 0:
                raise ValueError(f"negative launcher option: {value}")
            options[key] = parsed
        index += 2
    raise ValueError("launcher command separator is required")


def _validate_authority_options(options: dict[str, object]) -> None:
    executable_fd = options.get("exec_fd")
    executable_digest = options.get("exec_digest")
    if (executable_fd is None) != (executable_digest is None):
        raise ValueError("incomplete executable authority")
    interpreter_fd = options.get("interpreter_fd")
    interpreter_digest = options.get("interpreter_digest")
    if (interpreter_fd is None) != (interpreter_digest is None):
        raise ValueError("incomplete interpreter authority")
    if interpreter_fd is not None and executable_fd is None:
        raise ValueError("interpreter authority requires executable authority")
    if options.get("interpreter_argv0") and interpreter_fd is None:
        raise ValueError("interpreter argv0 requires interpreter authority")
    interpreter_args = options.get("interpreter_args", ())
    if interpreter_args and interpreter_fd is None:
        raise ValueError("interpreter arguments require interpreter authority")
    receipt_fd = options.get("authority_receipt_fd")
    public_key_fd = options.get("authority_public_key_fd")
    if (receipt_fd is None) != (public_key_fd is None):
        raise ValueError("incomplete signed authority receipt")
    if options.get("require_authority_receipt") and (
        receipt_fd is None or public_key_fd is None
    ):
        raise ValueError("signed authority receipt is required")


def _verify_fd(fd: int, device: int, inode: int, label: str) -> None:
    info = os.fstat(fd)
    if not _same_identity(info, device, inode):
        raise PermissionError(f"{label} directory identity changed before exec")


def _same_identity(info, device: int, inode: int) -> bool:
    return int(info.st_dev) == device and int(info.st_ino) == inode


def _verify_executable_fd(fd: int, expected_digest: str) -> None:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or not (info.st_mode & 0o111):
        raise PermissionError("executable authority descriptor is not executable")
    if len(expected_digest) != 64:
        raise PermissionError("executable authority digest is invalid")
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    if digest.hexdigest() != expected_digest:
        raise PermissionError("executable authority content changed before exec")


def _verify_authority_receipt(receipt_fd: int, public_key_fd: int) -> None:
    """Verify the same signed receipt contract as the Rust launcher."""
    receipt_payload = _read_fd(receipt_fd, 64 * 1024)
    public_key_payload = _read_fd(public_key_fd, 4096)
    try:
        receipt = SignedAuthorizationReceipt.from_dict(json.loads(receipt_payload))
        key_bytes = public_key_payload
        if len(key_bytes) != 32:
            import base64

            key_bytes = base64.b64decode(key_bytes, validate=True)
        receipt.verify(Ed25519PublicKey.from_public_bytes(key_bytes))
    except (OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise PermissionError("signed authority receipt is invalid") from exc


def _read_fd(fd: int, maximum: int) -> bytes:
    duplicate = os.dup(fd)
    try:
        os.lseek(duplicate, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(duplicate, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
        raise PermissionError("authority descriptor exceeds its bound")
    finally:
        os.close(duplicate)


def _fd_path(fd: int) -> str:
    for prefix in ("/proc/self/fd", "/dev/fd"):
        candidate = f"{prefix}/{fd}"
        if os.path.exists(candidate):
            return candidate
    raise PermissionError("executable authority descriptor has no stable fd path")


def _authority_path(
    fd: int, label: str, staged_paths: list[str], preferred_name: str
) -> str:
    """Return an executable-object path, staging only on macOS.

    Darwin does not provide Linux's ``execveat(AT_EMPTY_PATH)`` and its
    ``/dev/fd`` entries are not a reliable executable-object API.  The
    descriptor was already hashed and retained across the final boundary, so
    copying it to a private, mode-0700 O_EXCL file with the original basename
    preserves the approved generation without reopening the mutable pathname.
    macOS also requires an ad-hoc signature for copied Mach-O objects; a
    signing failure is fail-closed.
    """
    if sys.platform != "darwin":
        return _fd_path(fd)
    staging_directory = tempfile.mkdtemp(prefix=f"khaos-{label}-")
    basename = os.path.basename(preferred_name) or label
    path = os.path.join(staging_directory, basename)
    try:
        staged_fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o700,
        )
    except BaseException:
        try:
            os.rmdir(staging_directory)
        except OSError:
            pass
        raise
    staged_paths.append(path)
    try:
        with os.fdopen(staged_fd, "wb") as stream:
            offset = 0
            while True:
                chunk = os.pread(fd, 1024 * 1024, offset)
                if not chunk:
                    break
                stream.write(chunk)
                offset += len(chunk)
            stream.flush()
            os.fchmod(stream.fileno(), 0o700)
        signature = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if signature.returncode == 0:
            # Preserve a valid embedded CodeDirectory from platform-signed
            # binaries such as /bin/cat.  Replacing it with an ad-hoc
            # signature can make macOS AMFI kill the staged process with
            # SIGKILL even though the bytes and digest are unchanged.
            return path
        completed = subprocess.run(
            ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if completed.returncode != 0:
            raise PermissionError("macOS rejected ad-hoc signing of staged executable")
        return path
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        if path in staged_paths:
            staged_paths.remove(path)
        try:
            os.rmdir(staging_directory)
        except OSError:
            pass
        raise


def _set_limit(name: str, options: dict[str, object]) -> None:
    key = name.lower()
    if resource is None or key not in options or not hasattr(resource, name):
        return
    resource_id = getattr(resource, name)
    requested = int(options[key])
    _soft, hard = resource.getrlimit(resource_id)
    effective = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
    resource.setrlimit(resource_id, (effective, effective))


def _close_inherited_fds(preserved: tuple[int, ...] = ()) -> None:
    """Close inherited descriptors except stdio and explicit protocol FDs."""
    preserved_fds = set(preserved)
    try:
        maximum = int(os.sysconf("SC_OPEN_MAX"))
    except (AttributeError, OSError, ValueError):
        maximum = 1024
    for fd in range(3, max(3, maximum)):
        if fd in preserved_fds:
            continue
        try:
            os.close(fd)
        except OSError:
            continue


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, PermissionError, ValueError) as exc:
        print(f"khaos-exec-launcher: {exc}", file=sys.stderr)
        raise SystemExit(126) from exc
