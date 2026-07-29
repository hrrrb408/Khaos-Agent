"""Generated from security/browser-kernel-protocol-v1.json; do not edit."""

from typing import Final

PROTOCOL_VERSION: Final = 1
MAX_MESSAGE_BYTES: Final = 8192
REQUEST_FIELDS: Final = frozenset(['protocol_version', 'request_id', 'boot_id', 'client_pid', 'client_start_time', 'principal_id', 'project_id', 'runtime_id', 'task_id', 'sandbox_token', 'runtime_capability', 'op', 'port', 'target_pid', 'target_start_time'])
OPERATIONS: Final = frozenset(['authorize', 'setup', 'allow_proxy', 'revoke_proxy', 'attach_process', 'join', 'teardown', 'status'])
SANDBOX_TOKEN_PATTERN: Final = '^[0-9a-fA-F]{32,128}$'
RESPONSE_FIELDS: Final = frozenset(['protocol_version', 'request_id', 'ok', 'error_code', 'error', 'status', 'runtime_capability'])
ERROR_CODES: Final = frozenset(['invalid_request', 'peer_authentication_failed', 'authorization_denied', 'replay_detected', 'resource_not_found', 'resource_conflict', 'resource_exhausted', 'deadline_exceeded', 'tcb_integrity_failure', 'kernel_operation_failed', 'internal_error'])
STATUS_FIELDS: Final = frozenset(['helper_authenticated', 'network_namespace', 'nft_default_deny', 'cgroup_attached', 'process_isolated', 'resource_registry_verified', 'quarantined', 'proxy_host'])
