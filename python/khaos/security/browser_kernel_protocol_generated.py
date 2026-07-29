"""Generated from security/browser-kernel-protocol-v1.json; do not edit."""

from typing import Final

PROTOCOL_VERSION: Final = 1
MAX_MESSAGE_BYTES: Final = 8192
REQUEST_FIELDS: Final = frozenset(['protocol_version', 'request_id', 'boot_id', 'client_pid', 'client_start_time', 'principal_id', 'project_id', 'runtime_id', 'task_id', 'sandbox_token', 'runtime_capability', 'op', 'port', 'target_pid', 'target_start_time'])
OPERATIONS: Final = frozenset(['authorize', 'setup', 'allow_proxy', 'revoke_proxy', 'attach_process', 'join', 'teardown', 'status'])
SANDBOX_TOKEN_PATTERN: Final = '^[0-9a-fA-F]{32,128}$'
