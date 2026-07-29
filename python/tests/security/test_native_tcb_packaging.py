"""Static deployment contracts for the native privileged TCB."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]


def test_python_container_is_non_root_and_contains_no_kernel_cli() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    python_stage = dockerfile.split("FROM debian:bookworm-slim AS kernel-helper")[0]

    assert "USER 10001:10001" in python_stage
    assert "khaos-sandbox-launcher" in python_stage
    assert "\n    iproute2" not in python_stage
    assert "\n    nftables" not in python_stage
    assert "khaos-browser-kernel-helper" not in python_stage.split(
        "FROM python:3.11-slim AS python-agent", 1
    )[1]


def test_compose_routes_kernel_authority_to_dedicated_root_sidecar() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    agent = compose["services"]["khaos-agent"]
    helper = compose["services"]["khaos-kernel-helper"]

    assert agent["build"]["target"] == "python-agent"
    assert "KHAOS_DEV_MODE=0" in agent["environment"]
    assert helper["build"]["target"] == "kernel-helper"
    assert helper["user"] == "0:0"
    assert helper["pid"] == "service:khaos-agent"
    assert set(helper["cap_add"]) == {"NET_ADMIN", "SYS_ADMIN"}
    assert "KHAOS_BROWSER_KERNEL_HELPER_UID=10001" in helper["environment"]
    assert "KHAOS_BROWSER_KERNEL_HELPER_CLIENT_PID=1" in helper["environment"]
    assert any("/sys/fs/cgroup" in volume and volume.endswith(":rw") for volume in helper["volumes"])


def test_systemd_units_deprivilege_python_and_pin_helper_client_pid() -> None:
    agent = (ROOT / "packaging/systemd/khaos-agent.service").read_text(
        encoding="utf-8"
    )
    helper = (
        ROOT / "packaging/systemd/khaos-browser-kernel-helper.service"
    ).read_text(encoding="utf-8")

    assert "User=khaos" in agent
    assert "CapabilityBoundingSet=\n" in agent
    assert "AmbientCapabilities=\n" in agent
    assert "KHAOS_DEV_MODE=0" in agent
    assert "User=root" in helper
    assert "systemctl show --property MainPID" in helper
    assert "KHAOS_BROWSER_KERNEL_HELPER_CLIENT_PID" in helper
    assert "CAP_NET_ADMIN CAP_SYS_ADMIN" in helper


def test_installer_never_grants_kernel_capabilities_to_python() -> None:
    installer = (ROOT / "scripts/install-native-tcb.sh").read_text(encoding="utf-8")

    assert "setcap cap_sys_admin=ep /usr/local/bin/khaos-sandbox-launcher" in installer
    assert "khaos-browser-kernel-helper" in installer
    assert "setcap" not in "\n".join(
        line for line in installer.splitlines() if "python" in line.lower()
    )
