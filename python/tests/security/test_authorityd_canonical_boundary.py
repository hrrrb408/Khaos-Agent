"""Contract tests for authorityd's shared canonical wire primitives."""

from khaos.security import authorityd, authorityd_protocol
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes


def test_authorityd_and_protocol_consume_the_single_canonical_owner() -> None:
    assert authorityd.canonical_digest is canonical_digest
    assert authorityd.canonical_json_bytes is canonical_json_bytes
    assert authorityd_protocol.canonical_digest is canonical_digest
    assert authorityd_protocol.canonical_json_bytes is canonical_json_bytes


def test_authorityd_protocol_does_not_reintroduce_private_canonical_wrappers() -> None:
    assert not hasattr(authorityd, "_canonical")
    assert not hasattr(authorityd, "_digest")
    assert not hasattr(authorityd_protocol, "_canonical")
    assert not hasattr(authorityd_protocol, "_digest")
