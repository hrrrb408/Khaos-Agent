#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
secret_dir="$(mktemp -d "${TMPDIR:-/tmp}/khaos-compose-e2e.XXXXXX")"
project_name="${COMPOSE_PROJECT_NAME:-khaos-compose-e2e}"
active_compose_file=""
worm_pid=""
worm_store="$secret_dir/worm-audit.jsonl"

cleanup() {
    if [[ -n "$worm_pid" ]]; then
        kill "$worm_pid" 2>/dev/null || true
        wait "$worm_pid" 2>/dev/null || true
    fi
    if [[ -n "$active_compose_file" ]]; then
        docker compose \
            --project-name "$project_name" \
            --project-directory "$repo_root" \
            --file "$repo_root/$active_compose_file" \
            down --volumes --remove-orphans || true
    fi
    rm -rf -- "$secret_dir"
}
trap cleanup EXIT

umask 077
openssl rand -hex 32 > "$secret_dir/python-capability"
openssl rand -hex 32 > "$secret_dir/browser-helper-secret"
openssl rand -hex 32 > "$secret_dir/gateway-api-key"
chmod 0400 \
    "$secret_dir/python-capability" \
    "$secret_dir/browser-helper-secret" \
    "$secret_dir/gateway-api-key"
bash "$repo_root/scripts/generate-dev-cert.sh" "$secret_dir"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$secret_dir/worm-key.pem" \
    -out "$secret_dir/worm-cert.pem" \
    -subj "/CN=host.docker.internal" \
    -addext "subjectAltName=DNS:host.docker.internal,IP:127.0.0.1"
chmod 0400 "$secret_dir/worm-key.pem"
chmod 0444 "$secret_dir/worm-cert.pem"
python3 "$repo_root/scripts/ci-worm-server.py" \
    --bind 0.0.0.0 \
    --port "${KHAOS_WORM_PORT:-9443}" \
    --cert "$secret_dir/worm-cert.pem" \
    --key "$secret_dir/worm-key.pem" \
    --store "$worm_store" \
    >"$secret_dir/worm-server.log" 2>&1 &
worm_pid="$!"
for attempt in $(seq 1 50); do
    if curl --silent --show-error --fail \
        --cacert "$secret_dir/worm-cert.pem" \
        "https://127.0.0.1:${KHAOS_WORM_PORT:-9443}/healthz" >/dev/null; then
        break
    fi
    sleep 0.1
done
curl --silent --show-error --fail \
    --cacert "$secret_dir/worm-cert.pem" \
    "https://127.0.0.1:${KHAOS_WORM_PORT:-9443}/healthz" >/dev/null
# Standalone Docker Compose ignores the long-syntax secret mode and exposes
# file-backed secrets with the source file's mode. The temporary directory
# remains 0700, while direct Gateway secrets must be readable by its non-root
# UID inside the container. The runtime rejects any group/other write bit.
chmod 0444 \
    "$secret_dir/python-capability" \
    "$secret_dir/gateway-api-key" \
    "$secret_dir/tls-key.pem"

export KHAOS_PYTHON_CAPABILITY_FILE="$secret_dir/python-capability"
export KHAOS_BROWSER_HELPER_SECRET_FILE="$secret_dir/browser-helper-secret"
export KHAOS_API_KEY_FILE="$secret_dir/gateway-api-key"
export KHAOS_TLS_CERT_FILE="$secret_dir/tls-cert.pem"
export KHAOS_TLS_KEY_FILE="$secret_dir/tls-key.pem"
export KHAOS_ALLOWED_HOSTS="localhost,127.0.0.1"

# The production profile deliberately refuses to start without the digest of
# the *compiled* effective policy.  Compute it inside the same Python image
# that will run the agent, so this smoke test cannot drift from the runtime's
# YAML parser or policy compiler.  An explicitly supplied digest is accepted
# for deployment-driven runs, but is still format-checked below.  The typed
# resource catalog is generated in that same image and uses /app as its
# workspace root, matching the production container's runtime identity.
policy_image="${project_name}-policy-digest"
if [[ -z "${KHAOS_EFFECTIVE_POLICY_DIGEST:-}" || -z "${KHAOS_TYPED_RESOURCE_CATALOG_FILE:-}" ]]; then
    docker build \
        --quiet \
        --target python-agent \
        --tag "$policy_image" \
        "$repo_root" >/dev/null
    KHAOS_EFFECTIVE_POLICY_DIGEST="$({
        docker run --rm \
            --read-only \
            --tmpfs /tmp \
            --env HOME=/var/lib/khaos \
            --volume "$repo_root/khaos_policy.yaml:/app/khaos_policy.yaml:ro" \
            "$policy_image" \
            python -c 'from pathlib import Path; from khaos.security.effective_policy import load_effective_policy; print(load_effective_policy(Path("/app")).digest)'
    })"
fi
if [[ ! "$KHAOS_EFFECTIVE_POLICY_DIGEST" =~ ^[0-9a-f]{64}$ ]]; then
    printf '%s\n' "KHAOS_EFFECTIVE_POLICY_DIGEST must be a compiled 64-character SHA-256 digest" >&2
    exit 1
fi
export KHAOS_EFFECTIVE_POLICY_DIGEST

if [[ -z "${KHAOS_TYPED_RESOURCE_CATALOG_FILE:-}" ]]; then
    KHAOS_TYPED_RESOURCE_CATALOG_FILE="$secret_dir/typed-resource-catalog.json"
    docker run --rm \
        --read-only \
        --tmpfs /tmp \
        --user "$(id -u):$(id -g)" \
        --env HOME=/tmp \
        --volume "$repo_root/khaos_policy.yaml:/app/khaos_policy.yaml:ro" \
        --volume "$repo_root/scripts:/src/scripts:ro" \
        --volume "$secret_dir:/run/khaos-catalog:rw" \
        "$policy_image" \
        python /src/scripts/generate_typed_resource_catalog.py \
        --workspace-root /app \
        --policy-digest "$KHAOS_EFFECTIVE_POLICY_DIGEST" \
        --output /run/khaos-catalog/typed-resource-catalog.json
    chmod 0444 "$KHAOS_TYPED_RESOURCE_CATALOG_FILE"
fi
if [[ "$KHAOS_TYPED_RESOURCE_CATALOG_FILE" != /* || -L "$KHAOS_TYPED_RESOURCE_CATALOG_FILE" || ! -s "$KHAOS_TYPED_RESOURCE_CATALOG_FILE" ]]; then
    printf '%s\n' "KHAOS_TYPED_RESOURCE_CATALOG_FILE must be an absolute, non-symlink, non-empty catalog" >&2
    exit 1
fi
export KHAOS_TYPED_RESOURCE_CATALOG_FILE

# The production profile must reach an actual HTTPS append-only fixture.  This
# is separate from the application health endpoint so authorityd cannot pass
# by merely having a syntactically valid WORM URL.
export KHAOS_AUDIT_WORM_ENDPOINT="https://host.docker.internal:${KHAOS_WORM_PORT:-9443}/ci-worm-audit"
export KHAOS_AUDIT_WORM_CA_FILE="$secret_dir/worm-cert.pem"

cd "$repo_root"

validate_execution_cgroup_source() {
    local source="${KHAOS_EXECUTION_CGROUP_SOURCE:-}"
    local parent="${KHAOS_EXECUTION_CGROUP_PARENT:-}"
    local canonical
    if [[ -z "$parent" ]]; then
        printf '%s\n' "KHAOS_EXECUTION_CGROUP_PARENT is required for the production composition probe" >&2
        return 1
    fi
    if [[ -z "$source" ]]; then
        printf '%s\n' "KHAOS_EXECUTION_CGROUP_SOURCE is required for the production composition probe" >&2
        return 1
    fi
    if [[ "$source" != /sys/fs/cgroup/* || "$source" == "/sys/fs/cgroup" ]]; then
        printf '%s\n' "KHAOS_EXECUTION_CGROUP_SOURCE must be a child of /sys/fs/cgroup" >&2
        return 1
    fi
    if [[ -L "$source" || ! -d "$source" ]]; then
        printf '%s\n' "KHAOS_EXECUTION_CGROUP_SOURCE must be a real, non-symlink directory" >&2
        return 1
    fi
    if ! canonical="$(realpath -e -- "$source")" || [[ "$canonical" != /sys/fs/cgroup/* ]]; then
        printf '%s\n' "KHAOS_EXECUTION_CGROUP_SOURCE must resolve inside /sys/fs/cgroup" >&2
        return 1
    fi
    for entry in cgroup.controllers cgroup.procs cgroup.subtree_control; do
        if [[ ! -f "$canonical/$entry" ]]; then
            printf '%s\n' "delegated cgroup subtree is missing $entry: $canonical" >&2
            return 1
        fi
    done
    for controller in cpu memory pids io; do
        if ! grep -qw "$controller" "$canonical/cgroup.controllers"; then
            printf '%s\n' "delegated cgroup subtree lacks controller $controller: $canonical" >&2
            return 1
        fi
        if ! grep -qw "$controller" "$canonical/cgroup.subtree_control"; then
            printf '%s\n' "delegated cgroup subtree has not enabled controller $controller: $canonical" >&2
            return 1
        fi
    done
    printf '%s\n' "validated delegated execution cgroup v2 parent: $parent ($canonical)"
}

validate_production_workspace_source() {
    local source="${KHAOS_PRODUCTION_DATA_SOURCE:-}"
    local canonical
    local mount_source
    local mount_fstype
    if [[ -z "$source" ]]; then
        printf '%s\n' "using Compose-managed khaos-data for /app/data; the exact-effect probe must still prove io.max support"
        return 0
    fi
    if [[ "$source" != /* || -L "$source" || ! -d "$source" ]]; then
        printf '%s\n' "KHAOS_PRODUCTION_DATA_SOURCE must be an absolute, real, non-symlink directory" >&2
        return 1
    fi
    if ! canonical="$(realpath -e -- "$source")"; then
        printf '%s\n' "KHAOS_PRODUCTION_DATA_SOURCE must resolve to an existing directory" >&2
        return 1
    fi
    if [[ ! -w "$canonical" ]]; then
        printf '%s\n' "KHAOS_PRODUCTION_DATA_SOURCE must be writable before Compose startup" >&2
        return 1
    fi
    if ! command -v findmnt >/dev/null 2>&1; then
        printf '%s\n' "findmnt is required to validate the block-backed production workspace" >&2
        return 1
    fi
    if ! read -r mount_source mount_fstype < <(
        findmnt -T "$canonical" -no SOURCE,FSTYPE
    ); then
        printf '%s\n' "unable to identify the filesystem backing KHAOS_PRODUCTION_DATA_SOURCE" >&2
        return 1
    fi
    if [[ "$mount_source" != /dev/* || "$mount_fstype" == "overlay" || "$mount_fstype" == "tmpfs" ]]; then
        printf '%s\n' "KHAOS_PRODUCTION_DATA_SOURCE must resolve to a block-backed filesystem: ${mount_source:-unknown} ${mount_fstype:-unknown}" >&2
        return 1
    fi
    printf '%s\n' "validated block-backed production workspace: $canonical ($mount_source $mount_fstype)"
}

validate_agent_cgroup_parent() {
    local compose_file="$1"
    local expected_parent="${KHAOS_EXECUTION_CGROUP_PARENT:-}"
    local expected_path
    if [[ -z "$expected_parent" ]]; then
        printf '%s\n' "KHAOS_EXECUTION_CGROUP_PARENT is required before Agent cgroup validation" >&2
        return 1
    fi
    if [[ "$expected_parent" == /* ]]; then
        expected_path="${expected_parent%/}"
    else
        expected_path="/${expected_parent%/}"
    fi
    docker compose \
        --project-name "$project_name" \
        --project-directory "$repo_root" \
        --file "$repo_root/$compose_file" \
        exec -T \
        -e KHAOS_EXPECTED_CGROUP_PARENT="$expected_path" \
        khaos-agent \
        python -c '
import os
from pathlib import Path

expected = os.environ["KHAOS_EXPECTED_CGROUP_PARENT"]
line = next(
    (line for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines() if line.startswith("0::")),
    "",
)
actual = line[3:]
if actual != expected and not actual.startswith(expected + "/"):
    raise SystemExit(
        f"Agent cgroup {actual!r} is not below delegated parent {expected!r}"
    )
print(f"validated Agent cgroup parent: {expected} (current={actual})")
'
}

run_profile() {
    local compose_file="$1"
    local health_url="$2"
    local -a curl_options=(
        --fail
        --silent
        --show-error
        --retry 20
        --retry-connrefused
        --retry-delay 1
        --header "X-Khaos-Key: $(<"$KHAOS_API_KEY_FILE")"
    )

    if [[ "$health_url" == https://* ]]; then
        curl_options+=(--insecure)
    fi

    active_compose_file="$compose_file"
    if [[ "$compose_file" == "compose.prod.yaml" ]]; then
        validate_execution_cgroup_source
        validate_production_workspace_source
    fi
    docker compose \
        --project-name "$project_name" \
        --project-directory "$repo_root" \
        --file "$repo_root/$compose_file" \
        config --quiet
    if ! docker compose \
        --project-name "$project_name" \
        --project-directory "$repo_root" \
        --file "$repo_root/$compose_file" \
        up --build --wait; then
        printf '%s\n' "Compose profile $compose_file failed; collecting service diagnostics"
        docker compose \
            --project-name "$project_name" \
            --project-directory "$repo_root" \
            --file "$repo_root/$compose_file" \
            ps || true
        docker compose \
            --project-name "$project_name" \
            --project-directory "$repo_root" \
            --file "$repo_root/$compose_file" \
            logs --no-color --tail=200 khaos-gateway khaos-agent || true
        return 1
    fi

    if [[ "$compose_file" == "compose.prod.yaml" ]] && ! validate_agent_cgroup_parent "$compose_file"; then
        docker compose \
            --project-name "$project_name" \
            --project-directory "$repo_root" \
            --file "$repo_root/$compose_file" \
            ps || true
        return 1
    fi

    curl "${curl_options[@]}" "$health_url"

    if [[ "$compose_file" == "compose.prod.yaml" ]]; then
        if ! docker compose \
            --project-name "$project_name" \
            --project-directory "$repo_root" \
            --file "$repo_root/$compose_file" \
            exec -T khaos-agent \
            python -m khaos.security.production_composition_probe; then
            docker compose \
                --project-name "$project_name" \
                --project-directory "$repo_root" \
                --file "$repo_root/$compose_file" \
                logs --no-color --tail=200 khaos-authorityd khaos-agent || true
            return 1
        fi
        python3 - "$worm_store" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    kinds = [json.loads(line)["record"]["kind"] for line in stream if line.strip()]
required = ["execution.prepare", "execution.claimed", "execution.success"]
missing = [kind for kind in required if kind not in kinds]
if missing:
    raise SystemExit(f"WORM fixture is missing authority evidence: {missing}")
print("production WORM evidence:", ", ".join(required))
PY
    fi

    docker compose \
        --project-name "$project_name" \
        --project-directory "$repo_root" \
        --file "$repo_root/$compose_file" \
        down --volumes --remove-orphans
    active_compose_file=""
}

# compose.prod.yaml deliberately requires explicit outer profiles and has no
# deployment default. These values are scoped to this disposable CI/local
# composition probe only; a production deployment must provide host-reviewed
# profiles through its own environment and must not inherit this test setup.
export KHAOS_DOCKER_SECCOMP_OPT="${KHAOS_DOCKER_SECCOMP_OPT:-seccomp=unconfined}"
export KHAOS_DOCKER_APPARMOR_OPT="${KHAOS_DOCKER_APPARMOR_OPT:-apparmor=unconfined}"
export KHAOS_DOCKER_SYSTEMPATHS_OPT="${KHAOS_DOCKER_SYSTEMPATHS_OPT:-systempaths=unconfined}"
python3 "$repo_root/scripts/validate_docker_outer_profiles.py" --disposable

run_profile compose.dev.yaml http://127.0.0.1:8080/api/health
run_profile compose.prod.yaml https://127.0.0.1:8443/api/health
printf '%s\n' "Compose development and production security smoke tests passed"
