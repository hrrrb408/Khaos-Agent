#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
secret_dir="$(mktemp -d "${TMPDIR:-/tmp}/khaos-compose-e2e.XXXXXX")"
project_name="${COMPOSE_PROJECT_NAME:-khaos-compose-e2e}"
active_compose_file=""

cleanup() {
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

# The smoke profile does not issue an authority mutation, so it only needs a
# syntactically valid HTTPS endpoint to prove production wiring.  Real
# deployments must provide their independent WORM service explicitly; this
# loopback placeholder is never a usable audit authority outside this health
# check.
if [[ -z "${KHAOS_AUDIT_WORM_ENDPOINT:-}" ]]; then
    export KHAOS_AUDIT_WORM_ENDPOINT="https://127.0.0.1:9443/ci-worm-audit"
fi

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

    docker compose \
        --project-name "$project_name" \
        --project-directory "$repo_root" \
        --file "$repo_root/$compose_file" \
        down --volumes --remove-orphans
    active_compose_file=""
}

run_profile compose.dev.yaml http://127.0.0.1:8080/api/health
run_profile compose.prod.yaml https://127.0.0.1:8443/api/health
printf '%s\n' "Compose development and production security smoke tests passed"
