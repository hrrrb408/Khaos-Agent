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

export KHAOS_PYTHON_CAPABILITY_FILE="$secret_dir/python-capability"
export KHAOS_BROWSER_HELPER_SECRET_FILE="$secret_dir/browser-helper-secret"
export KHAOS_API_KEY_FILE="$secret_dir/gateway-api-key"
export KHAOS_TLS_CERT_FILE="$secret_dir/tls-cert.pem"
export KHAOS_TLS_KEY_FILE="$secret_dir/tls-key.pem"
export KHAOS_ALLOWED_HOSTS="localhost,127.0.0.1"

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
    docker compose \
        --project-name "$project_name" \
        --project-directory "$repo_root" \
        --file "$repo_root/$compose_file" \
        up --build --wait

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
