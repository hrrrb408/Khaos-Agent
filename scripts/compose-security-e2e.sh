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
# for deployment-driven runs, but is still format-checked below.
policy_image="${project_name}-policy-digest"
if [[ -z "${KHAOS_EFFECTIVE_POLICY_DIGEST:-}" ]]; then
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

# The production profile must reach an actual HTTPS append-only fixture.  This
# is separate from the application health endpoint so authorityd cannot pass
# by merely having a syntactically valid WORM URL.
export KHAOS_AUDIT_WORM_ENDPOINT="https://host.docker.internal:${KHAOS_WORM_PORT:-9443}/ci-worm-audit"
export KHAOS_AUDIT_WORM_CA_FILE="$secret_dir/worm-cert.pem"

cd "$repo_root"

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
