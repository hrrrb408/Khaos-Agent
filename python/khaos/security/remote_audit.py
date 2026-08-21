"""HTTPS append-only audit writer used by ``khaos-authorityd``."""

from __future__ import annotations

import hashlib
import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from khaos.security.authorityd_protocol import RemoteAuditUnavailableError, _canonical


@dataclass(frozen=True, slots=True)
class RemoteWormAuditWriter:
    """Small synchronous writer with no local fallback.

    The endpoint must be HTTPS.  Deployment may add mTLS or a pinned CA at
    the process boundary; this class only accepts a standard CA bundle and
    treats every non-2xx response or transport error as an execution refusal.
    """

    endpoint: str
    bearer_token: str | None = None
    timeout_seconds: float = 3.0
    ca_file: Path | None = None

    def __post_init__(self) -> None:
        parsed = urlparse(self.endpoint)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("remote WORM audit endpoint must use HTTPS")
        if self.timeout_seconds <= 0:
            raise ValueError("remote WORM audit timeout must be positive")
        if self.ca_file is not None and (
            not self.ca_file.is_absolute()
            or self.ca_file.is_symlink()
            or not self.ca_file.is_file()
        ):
            raise ValueError("remote WORM audit CA file must be an absolute regular file")

    def append(self, record: dict[str, object]) -> None:
        body = _canonical(
            {
                "schema_version": 1,
                "record": record,
                "record_digest": hashlib.sha256(_canonical(record)).hexdigest(),
            }
        )
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": hashlib.sha256(body).hexdigest(),
        }
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        request = Request(self.endpoint, data=body, headers=headers, method="POST")
        try:
            context = ssl.create_default_context(
                cafile=str(self.ca_file) if self.ca_file is not None else None
            )
            with urlopen(request, timeout=self.timeout_seconds, context=context) as response:
                if not 200 <= int(response.status) < 300:
                    raise RemoteAuditUnavailableError(
                        f"remote WORM audit rejected record: HTTP {response.status}"
                    )
        except RemoteAuditUnavailableError:
            raise
        except OSError as exc:
            detail = str(exc).strip()[:256] or type(exc).__name__
            raise RemoteAuditUnavailableError(
                f"remote WORM audit endpoint is unavailable: {detail}"
            ) from exc


def writer_from_environment() -> RemoteWormAuditWriter:
    """Build the writer from deployment-only environment values."""
    endpoint = os.environ.get("KHAOS_AUDIT_WORM_ENDPOINT")
    if not endpoint:
        raise RemoteAuditUnavailableError(
            "KHAOS_AUDIT_WORM_ENDPOINT is required for production authorityd"
        )
    return RemoteWormAuditWriter(
        endpoint,
        bearer_token=os.environ.get("KHAOS_AUDIT_WORM_TOKEN"),
        ca_file=(
            Path(ca_file_value)
            if (ca_file_value := os.environ.get("KHAOS_AUDIT_WORM_CA_FILE"))
            else None
        ),
    )


__all__ = ["RemoteWormAuditWriter", "writer_from_environment"]
