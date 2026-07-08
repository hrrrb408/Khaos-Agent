"""Sensitive data detection in tool outputs and file contents."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    (
        re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"),
        "API Key",
    ),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key"),
    (
        re.compile(
            r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        "AWS Secret Key",
    ),
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), "GitHub Token"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}"), "Bearer Token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private Key"),
    (re.compile(r"(?i)password\s*[=:]\s*['\"]([^'\"]{8,})['\"]"), "Password"),
    (re.compile(r"(?i)(?:postgres|mysql|mongodb|redis)://[^\s]+:[^\s]+@"), "Database URL with credentials"),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "JWT Token",
    ),
]

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


@dataclass
class SecretMatch:
    """一个敏感信息匹配。"""

    category: str
    line_number: int
    matched_text: str
    masked: str


@dataclass
class ScanResult:
    """扫描结果。"""

    has_secrets: bool
    secrets: list[SecretMatch] = field(default_factory=list)
    total_lines_scanned: int = 0


class SecretScanner:
    """扫描文本中的敏感信息。"""

    def __init__(self, max_matches: int = 20):
        self.max_matches = max_matches

    def scan_text(self, text: str) -> ScanResult:
        """扫描文本内容。"""
        secrets: list[SecretMatch] = []
        lines = text.splitlines()
        for line_number, line in enumerate(lines, start=1):
            for pattern, category in SECRET_PATTERNS:
                for match in pattern.finditer(line):
                    matched_text = match.group(1) if match.groups() else match.group(0)
                    secrets.append(
                        SecretMatch(
                            category=category,
                            line_number=line_number,
                            matched_text=matched_text,
                            masked=self._mask_match(matched_text),
                        )
                    )
                    if len(secrets) >= self.max_matches:
                        return ScanResult(
                            has_secrets=True,
                            secrets=secrets,
                            total_lines_scanned=len(lines),
                        )
        return ScanResult(
            has_secrets=bool(secrets),
            secrets=secrets,
            total_lines_scanned=len(lines),
        )

    def scan_file(self, file_path: str) -> ScanResult:
        """扫描文件内容。"""
        path = Path(file_path).expanduser().resolve()
        try:
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                return ScanResult(has_secrets=False, total_lines_scanned=0)
            data = path.read_bytes()
        except OSError as exc:
            logger.warning("failed to read file for secret scan: %s", exc)
            return ScanResult(has_secrets=False, total_lines_scanned=0)
        if b"\x00" in data:
            return ScanResult(has_secrets=False, total_lines_scanned=0)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return ScanResult(has_secrets=False, total_lines_scanned=0)
        return self.scan_text(text)

    def _mask_match(self, text: str) -> str:
        """遮掩敏感信息：保留前后 4 字符，中间替换为 ***。"""
        if len(text) <= 12:
            return text[:4] + "***"
        return text[:4] + "***" + text[-4:]
