"""RPC application services.

Transport framing and process lifecycle remain in :mod:`khaos.grpc_server`.
Domain-oriented RPC services live here so they can be tested and migrated
without adding more responsibilities to the transport module.
"""

from khaos.rpc.memory_service import MemoryService

__all__ = ["MemoryService"]
