"""Receipt signing authority separation using Ed25519."""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


@dataclass(frozen=True)
class ReceiptPublicVerifier:
    key_id: str
    public_key: str
    key_version: int
    boot_epoch: int

    def verify_payload_digest(self, payload_digest: str, signature: str) -> bool:
        try:
            key = Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public_key))
            key.verify(base64.b64decode(signature), payload_digest.encode("ascii"))
            return True
        except (ValueError, InvalidSignature):
            return False


class _ReceiptSigningAuthority:
    """Broker-private signer; repr and public verifier never expose private bytes."""
    __slots__ = ("__private_key", "_verifier")

    def __init__(self, *, boot_epoch: int = 0, key_version: int = 1) -> None:
        private = Ed25519PrivateKey.generate()
        public_bytes = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        public_text = base64.b64encode(public_bytes).decode("ascii")
        key_id = hashlib.sha256(public_bytes).hexdigest()[:24]
        self.__private_key = private
        self._verifier = ReceiptPublicVerifier(key_id, public_text, key_version, boot_epoch)

    @property
    def verifier(self) -> ReceiptPublicVerifier:
        return self._verifier

    def _sign_payload_digest(self, payload_digest: str) -> str:
        return base64.b64encode(self.__private_key.sign(payload_digest.encode("ascii"))).decode("ascii")

    def __repr__(self) -> str:
        return "<_ReceiptSigningAuthority private_key=hidden>"
