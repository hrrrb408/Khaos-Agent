"""HTTPS append-only audit writer used by ``khaos-authorityd``."""

from __future__ import annotations

import hashlib
import os
import ssl
from dataclasses import dataclass
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

    def __post_init__(self) -> None:
        parsed = urlparse(self.endpoint)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("remote WORM audit endpoint must use HTTPS")
        if self.timeout_seconds <= 0:
            raise ValueError("remote WORM audit timeout must be positive")

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
            with urlopen(request, timeout=self.timeout_seconds, context=ssl.create_default_context()) as response:
                if not 200 <= int(response.status) < 300:
                    raise RemoteAuditUnavailableError(
                        f"remote WORM audit rejected record: HTTP {response.status}"
                    )
        except RemoteAuditUnavailableError:
            raise
        except OSError as exc:
            raise RemoteAuditUnavailableError(
                "remote WORM audit endpoint is unavailable"
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
    )


__all__ = ["RemoteWormAuditWriter", "writer_from_environment"]
