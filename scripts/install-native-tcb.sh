#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "install-native-tcb.sh must run as root" >&2
  exit 1
fi

if ! id -u khaos >/dev/null 2>&1; then
  useradd --system --uid 10001 --home-dir /var/lib/khaos \
    --shell /usr/sbin/nologin khaos
elif [ "$(id -u khaos)" -ne 10001 ]; then
  echo "khaos service user must have UID 10001" >&2
  exit 1
fi

if ! id -u khaos-authority >/dev/null 2>&1; then
  useradd --system --uid 10003 --home-dir /nonexistent \
    --shell /usr/sbin/nologin khaos-authority
fi

if ! id -u khaos-job >/dev/null 2>&1; then
  useradd --system --uid 10004 --home-dir /nonexistent \
    --shell /usr/sbin/nologin khaos-job
fi

repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repository"

cargo build --locked --release --no-default-features \
  --manifest-path rust/khaos-core/Cargo.toml \
  --bin khaos-sandbox-launcher \
  --bin khaos-exec-launcher \
  --bin khaos-browser-kernel-helper

install -o root -g root -m 0755 \
  rust/khaos-core/target/release/khaos-sandbox-launcher \
  /usr/local/bin/khaos-sandbox-launcher
install -o root -g root -m 0755 \
  rust/khaos-core/target/release/khaos-sandbox-launcher \
  /usr/local/bin/khaos-execution-sandbox-launcher
install -o root -g root -m 0755 \
  rust/khaos-core/target/release/khaos-exec-launcher \
  /usr/local/bin/khaos-exec-launcher
install -o root -g root -m 0755 \
  rust/khaos-core/target/release/khaos-browser-kernel-helper \
  /usr/local/sbin/khaos-browser-kernel-helper
sha256sum /usr/local/sbin/khaos-browser-kernel-helper \
  > /usr/local/sbin/khaos-browser-kernel-helper.sha256
chown root:root /usr/local/sbin/khaos-browser-kernel-helper.sha256
chmod 0444 /usr/local/sbin/khaos-browser-kernel-helper.sha256
setcap cap_sys_admin=ep /usr/local/bin/khaos-sandbox-launcher

install -d -o root -g root -m 0755 /var/lib/khaos
install -d -o root -g root -m 0755 /opt/khaos-playwright
install -d -o khaos -g khaos -m 0700 /var/lib/khaos/.khaos
chown root:root /var/lib/khaos
chmod 0755 /var/lib/khaos
chown root:root /opt/khaos-playwright
chmod 0755 /opt/khaos-playwright
chown khaos:khaos /var/lib/khaos/.khaos
chmod 0700 /var/lib/khaos/.khaos
if [ -L /var/lib/khaos/rpc-capability ] || [ -e /var/lib/khaos/rpc-capability ]; then
  if [ -L /var/lib/khaos/rpc-capability ] || [ ! -f /var/lib/khaos/rpc-capability ]; then
    echo "/var/lib/khaos/rpc-capability must be a regular non-symlink file" >&2
    exit 1
  fi
else
  umask 077
  head -c 48 /dev/urandom | base64 | tr -d '\n' > /var/lib/khaos/rpc-capability
fi
chown khaos:khaos /var/lib/khaos/rpc-capability
chmod 0400 /var/lib/khaos/rpc-capability
if [ ! -e /var/lib/khaos/browser-helper.secret ]; then
  umask 077
  head -c 32 /dev/urandom > /var/lib/khaos/browser-helper.secret
fi
chown root:root /var/lib/khaos/browser-helper.secret
chmod 0600 /var/lib/khaos/browser-helper.secret

install -o root -g root -m 0644 \
  packaging/systemd/khaos-agent.service \
  /etc/systemd/system/khaos-agent.service
install -o root -g root -m 0755 \
  packaging/docker/authorityd-key-init.py \
  /usr/local/sbin/khaos-authorityd-key-init.py
install -o root -g root -m 0644 \
  packaging/systemd/khaos-authorityd.service \
  /etc/systemd/system/khaos-authorityd.service
install -o root -g root -m 0644 \
  packaging/systemd/khaos-browser-kernel-helper.service \
  /etc/systemd/system/khaos-browser-kernel-helper.service
systemctl daemon-reload

echo "Native TCB installed. Review /opt/khaos and /var/lib/khaos ownership, then enable both units."
