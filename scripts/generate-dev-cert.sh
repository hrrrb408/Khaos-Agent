#!/usr/bin/env bash
set -euo pipefail

secret_dir="${1:-.secrets}"
mkdir -p "$secret_dir"

openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout "$secret_dir/tls-key.pem" \
  -out "$secret_dir/tls-cert.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 0400 "$secret_dir/tls-key.pem"
chmod 0444 "$secret_dir/tls-cert.pem"
printf 'Generated short-lived development TLS material in %s\n' "$secret_dir"
