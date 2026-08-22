"""Contract tests for the RPC application-service owner boundaries."""

import khaos.grpc_server as grpc_server
from khaos.rpc import AuditService, MemoryService, SessionService
from khaos.rpc.agent_service import AgentService
from khaos.rpc.models import ChatRequest, ConfirmRequest
from khaos.rpc.task_service import TaskService


def test_transport_does_not_reexport_application_services() -> None:
    """The transport module must not become a second service owner."""
    for name in (
        "AgentService",
        "TaskService",
        "ChatRequest",
        "ConfirmRequest",
        "AuditService",
        "MemoryService",
        "SessionService",
    ):
        assert not hasattr(grpc_server, name)


def test_each_application_service_has_a_stable_owner_module() -> None:
    assert AgentService.__module__ == "khaos.rpc.agent_service"
    assert TaskService.__module__ == "khaos.rpc.task_service"
    assert ChatRequest.__module__ == "khaos.rpc.models"
    assert ConfirmRequest.__module__ == "khaos.rpc.models"
    assert AuditService.__module__ == "khaos.rpc.audit_service"
    assert MemoryService.__module__ == "khaos.rpc.memory_service"
    assert SessionService.__module__ == "khaos.rpc.session_service"
