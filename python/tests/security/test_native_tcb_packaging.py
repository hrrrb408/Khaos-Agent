"""Static deployment contracts for the native privileged TCB."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]


def _environment_values(service: dict) -> set[str]:
    environment = service.get("environment", {})
    if isinstance(environment, dict):
        return {f"{key}={value}" for key, value in environment.items()}
    return set(environment)


def _command_values(service: dict) -> list[str]:
    command = service.get("command", [])
    return command if isinstance(command, list) else [command]


def test_python_container_is_non_root_and_contains_no_kernel_cli() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    python_stage = dockerfile.split(" AS kernel-helper", 1)[0]

    assert "USER 10001:10001" in python_stage
    assert "khaos-sandbox-launcher" in python_stage
    assert "HOME=/var/lib/khaos" in python_stage
    assert 'CMD ["python", "-m", "khaos.cli", "start", "--socket", "/run/khaos/agent.sock", "--gateway-uid", "10002", "--gateway-gid", "0"]' in python_stage
    assert "chown khaos:root /run/khaos" in python_stage
    assert "chmod 02750 /run/khaos" in python_stage
    assert '"--db", "/app/data/khaos.db"' not in python_stage
    secret_init = (ROOT / "packaging/docker/agent-secret-init.py").read_text(encoding="utf-8")
    assert "os.getuid() != 0" in secret_init
    assert "os.fchown(fd, service_uid, service_gid)" in secret_init
    assert "STAGED_CAPABILITY" in secret_init
    assert "\n    iproute2" not in python_stage
    assert "\n    nftables" not in python_stage
    assert "khaos-browser-kernel-helper" not in python_stage.split(
        "FROM python:3.11-slim-bookworm@sha256:", 1
    )[1]


def test_python_container_consumes_frozen_dependency_authority() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    python_stage = dockerfile.split(" AS kernel-helper", 1)[0]

    assert re.search(
        r"FROM rust:\d+\.\d+-bookworm@sha256:[0-9a-f]{64}", dockerfile
    )
    assert "FROM python:3.11-slim-bookworm@sha256:" in dockerfile
    assert "FROM debian:bookworm-slim@sha256:" in dockerfile
    assert "FROM golang:1.22-alpine@sha256:" in dockerfile
    assert "FROM alpine:3.19@sha256:" in dockerfile
    assert "COPY pyproject.toml uv.lock ./" in python_stage
    assert "COPY python/bootstrap-requirements.txt" in python_stage
    assert "python -m pip install --no-cache-dir --require-hashes" in python_stage
    assert "UV_PROJECT_ENVIRONMENT=/usr/local uv sync --frozen --no-dev --no-install-project" in python_stage
    assert "PYTHONPATH=/app/python" in python_stage
    assert "pip install --no-cache-dir -e ." not in python_stage
    assert "pip install -e ." not in python_stage


def test_compose_routes_kernel_authority_to_dedicated_root_sidecar() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    init = compose["services"]["khaos-agent-init"]
    agent = compose["services"]["khaos-agent"]
    helper = compose["services"]["khaos-kernel-helper"]

    assert init["user"] == "0:0"
    assert init["entrypoint"] == ["python", "/usr/local/sbin/khaos-agent-secret-init.py"]
    assert "khaos-state:/var/lib/khaos" in init["volumes"]
    assert init["restart"] == "no"
    assert agent["build"]["target"] == "python-agent"
    assert "KHAOS_DEV_MODE=0" in agent["environment"]
    assert "KHAOS_PYTHON_CAPABILITY_FILE=/var/lib/khaos/rpc-capability" in agent["environment"]
    assert agent["depends_on"]["khaos-agent-init"]["condition"] == "service_completed_successfully"
    assert "secrets" not in agent
    assert helper["build"]["target"] == "kernel-helper"
    assert helper["user"] == "0:0"
    assert helper["pid"] == "service:khaos-agent"
    assert set(helper["cap_add"]) == {"NET_ADMIN", "SYS_ADMIN"}
    assert helper["cap_drop"] == ["ALL"]
    assert helper["read_only"] is True
    assert helper["pids_limit"] == 64
    assert helper["mem_limit"] == "256m"
    assert helper["cpus"] == "1.0"
    assert "KHAOS_BROWSER_KERNEL_HELPER_UID=10001" in helper["environment"]
    assert "KHAOS_BROWSER_KERNEL_HELPER_CLIENT_PID=1" in helper["environment"]
    assert "KHAOS_BROWSER_HELPER_NETNS_ROOT=/run/khaos-helper/netns" in helper[
        "environment"
    ]
    assert "KHAOS_BROWSER_HELPER_CGROUP_ROOT=/run/khaos-helper/cgroup" in helper[
        "environment"
    ]
    assert any(
        volume.endswith(":/run/khaos-helper/cgroup:rw")
        and "/sys/fs/cgroup" in volume
        for volume in helper["volumes"]
    )
    assert not any("/sys/fs/cgroup:/sys/fs/cgroup" in volume for volume in helper["volumes"])
    assert "khaos-helper-netns:/run/khaos-helper/netns" in helper["volumes"]
    assert not any("/run/netns" in volume for volume in helper["volumes"])


def test_default_compose_is_loopback_only_and_uses_secret_files() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    agent = compose["services"]["khaos-agent"]
    gateway = compose["services"]["khaos-gateway"]
    env = _environment_values(gateway)
    command = _command_values(gateway)

    assert gateway["network_mode"] == "host"
    assert "ports" not in gateway
    assert "127.0.0.1:8080" in command
    assert "--project-root" in command
    assert "/app" in command
    assert "KHAOS_API_KEY_FILE=/run/secrets/khaos_api_key" in env
    assert not any(item.startswith("KHAOS_API_KEY=") for item in env)
    assert "KHAOS_PROJECT_ROOT=/app" in env
    assert "khaos-state:/var/lib/khaos" in agent["volumes"]
    assert "khaos_api_key" in compose["secrets"]
    assert "file" in compose["secrets"]["khaos_api_key"]
    assert "healthcheck" in gateway
    assert "khaos-runtime:/run/khaos:ro" in gateway["volumes"]


def test_explicit_dev_compose_matches_loopback_contract() -> None:
    compose = yaml.safe_load((ROOT / "compose.dev.yaml").read_text(encoding="utf-8"))
    gateway = compose["services"]["khaos-gateway"]
    assert gateway["network_mode"] == "host"
    assert "127.0.0.1:8080" in _command_values(gateway)
    assert "ports" not in gateway


def test_production_compose_requires_tls_and_host_allowlist() -> None:
    compose = yaml.safe_load((ROOT / "compose.prod.yaml").read_text(encoding="utf-8"))
    gateway = compose["services"]["khaos-gateway"]
    command = _command_values(gateway)
    env = _environment_values(gateway)

    assert gateway["ports"] == ["8443:8443"]
    assert "0.0.0.0:8443" in command
    assert command[command.index("--tls-cert") + 1] == "/run/secrets/khaos_tls_cert"
    assert command[command.index("--tls-key") + 1] == "/run/secrets/khaos_tls_key"
    assert "--allowed-hosts" in command
    assert "KHAOS_API_KEY_FILE=/run/secrets/khaos_api_key" in env
    assert {"khaos_tls_cert", "khaos_tls_key"}.issubset(compose["secrets"])
    assert "file" in compose["secrets"]["khaos_tls_cert"]
    assert "file" in compose["secrets"]["khaos_tls_key"]
    assert "khaos-runtime:/run/khaos:ro" in gateway["volumes"]


def test_production_compose_has_independent_authorityd_sidecar() -> None:
    compose = yaml.safe_load((ROOT / "compose.prod.yaml").read_text(encoding="utf-8"))
    init = compose["services"]["khaos-authorityd-init"]
    authority = compose["services"]["khaos-authorityd"]
    agent = compose["services"]["khaos-agent"]

    assert init["user"] == "0:0"
    assert init["restart"] == "no"
    assert init["entrypoint"] == [
        "python",
        "/usr/local/sbin/khaos-authorityd-key-init.py",
    ]
    assert authority["user"] == "10003:10003"
    assert authority["environment"].count("KHAOS_DEV_MODE=0") == 1
    assert authority["depends_on"]["khaos-authorityd-init"]["condition"] == (
        "service_completed_successfully"
    )
    assert authority["environment"].count(
        "KHAOS_AUDIT_WORM_ENDPOINT=${KHAOS_AUDIT_WORM_ENDPOINT:?KHAOS_AUDIT_WORM_ENDPOINT must be an HTTPS WORM endpoint}"
    ) == 1
    assert agent["depends_on"]["khaos-authorityd"]["condition"] == "service_healthy"
    assert "KHAOS_AUTHORITYD_SOCKET=/run/khaos-authorityd/authorityd.sock" in agent[
        "environment"
    ]
    assert "KHAOS_AUTHORITYD_PUBLIC_KEY_PATH=/run/khaos-authorityd/authorityd.pub" in agent[
        "environment"
    ]
    assert "10003" in {str(value) for value in agent["group_add"]}
    assert "khaos-authority-runtime:/run/khaos-authorityd:ro" in agent["volumes"]
    assert "${KHAOS_PRODUCTION_DATA_SOURCE:-khaos-data}:/app/data" in agent[
        "volumes"
    ]
    assert (
        "${KHAOS_EXECUTION_CGROUP_SOURCE:?KHAOS_EXECUTION_CGROUP_SOURCE must point to a delegated cgroup v2 subtree}:/run/khaos-execution-cgroup:rw"
        in agent["volumes"]
    )
    assert "KHAOS_CGROUP_ROOT=/run/khaos-execution-cgroup" in agent["environment"]
    assert agent["security_opt"] == [
        "${KHAOS_DOCKER_SECCOMP_OPT:?KHAOS_DOCKER_SECCOMP_OPT must select an approved seccomp profile}",
        "${KHAOS_DOCKER_APPARMOR_OPT:?KHAOS_DOCKER_APPARMOR_OPT must select an approved AppArmor profile}",
        "${KHAOS_DOCKER_SYSTEMPATHS_OPT:?KHAOS_DOCKER_SYSTEMPATHS_OPT must select an approved system-path profile}",
    ]
    assert "SYS_ADMIN" not in agent.get("cap_add", [])


def test_compose_security_probe_supplies_only_disposable_outer_profiles() -> None:
    script = (ROOT / "scripts/compose-security-e2e.sh").read_text(encoding="utf-8")

    assert "validate_docker_outer_profiles.py\" --disposable" in script
    assert 'KHAOS_DOCKER_SECCOMP_OPT:-seccomp=unconfined' in script
    assert 'KHAOS_DOCKER_APPARMOR_OPT:-apparmor=unconfined' in script
    assert 'KHAOS_DOCKER_SYSTEMPATHS_OPT:-systempaths=unconfined' in script
    assert "KHAOS_EXECUTION_CGROUP_SOURCE" in script
    assert "validate_execution_cgroup_source" in script
    assert "KHAOS_PRODUCTION_DATA_SOURCE" in script
    assert "validate_production_workspace_source" in script
    assert "findmnt -T" in script
    assert "production deployment must provide host-reviewed" in script
    assert "seccomp:unconfined" not in script
    assert "apparmor:unconfined" not in script
    assert "systempaths:unconfined" not in script


def test_systemd_units_deprivilege_python_and_pin_helper_client_pid() -> None:
    agent = (ROOT / "packaging/systemd/khaos-agent.service").read_text(
        encoding="utf-8"
    )
    authority = (ROOT / "packaging/systemd/khaos-authorityd.service").read_text(
        encoding="utf-8"
    )
    helper = (
        ROOT / "packaging/systemd/khaos-browser-kernel-helper.service"
        ).read_text(encoding="utf-8")

    assert "User=khaos" in agent
    assert "CapabilityBoundingSet=\n" in agent
    assert "AmbientCapabilities=\n" in agent
    assert "KHAOS_DEV_MODE=0" in agent
    assert "Requires=khaos-authorityd.service" in agent
    assert "SupplementaryGroups=khaos-authority" in agent
    assert "User=khaos-authority" in authority
    assert "Group=khaos-authority" in authority
    assert "EnvironmentFile=/etc/khaos/authorityd.env" in authority
    assert "ExecStartPre=/usr/local/sbin/khaos-authorityd-key-init.py" in authority
    assert "User=root" in helper
    assert "systemctl show --property MainPID" in helper
    assert "KHAOS_BROWSER_KERNEL_HELPER_CLIENT_PID" in helper
    assert "KHAOS_BROWSER_HELPER_NETNS_ROOT=/run/khaos-helper/netns" in helper
    assert "KHAOS_BROWSER_HELPER_CGROUP_ROOT=/sys/fs/cgroup/khaos-browser" in helper
    assert "CAP_NET_ADMIN CAP_SYS_ADMIN" in helper
    assert "sha256sum" in helper
    assert ".sha256" in helper
    assert "/run/netns" not in helper


def test_installer_never_grants_kernel_capabilities_to_python() -> None:
    installer = (ROOT / "scripts/install-native-tcb.sh").read_text(encoding="utf-8")

    assert "setcap cap_sys_admin=ep /usr/local/bin/khaos-sandbox-launcher" in installer
    assert "khaos-browser-kernel-helper" in installer
    assert "khaos-browser-kernel-helper.sha256" in installer
    assert "setcap" not in "\n".join(
        line for line in installer.splitlines() if "python" in line.lower()
    )


def test_kernel_helper_reaps_journaled_orphans_before_accepting_requests() -> None:
    helper = (
        ROOT / "rust/khaos-core/src/bin/khaos-browser-kernel-helper.rs"
    ).read_text(encoding="utf-8")

    assert "fn recover(state: &Arc<State>)" in helper
    assert "recover(&state)?;" in helper
    assert "process_start_time(record.identity.client_pid)" in helper
    assert ".with_extension(\"quarantine\")" in helper
    assert "KHAOS_BROWSER_HELPER_CGROUP_ROOT" in helper
    assert "validate_cgroup_root(&cgroup_root)?;" in helper
    assert "validate_managed_cgroup_path(&state.cgroup_root" in helper
    assert helper.index("recover(&state)?;") < helper.index("UnixListener::bind")
