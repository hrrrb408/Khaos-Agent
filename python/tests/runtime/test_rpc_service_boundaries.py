"""Contract tests for the RPC application-service migration seams."""

from khaos.grpc_server import AuditService as LegacyAuditService
from khaos.grpc_server import MemoryService as LegacyMemoryService
from khaos.grpc_server import SessionService as LegacySessionService
from khaos.rpc import AuditService, MemoryService, SessionService


def test_grpc_server_reexports_rpc_application_services() -> None:
    """Keep legacy imports working while ``khaos.rpc`` owns the classes."""
    assert LegacyAuditService is AuditService
    assert LegacyMemoryService is MemoryService
    assert LegacySessionService is SessionService
