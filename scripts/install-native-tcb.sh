#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "install-native-tcb.sh must run as root" >&2
  exit 1
fi

if ! id -u khaos-authority >/dev/null 2>&1; then
  useradd --system --uid 10003 --home-dir /nonexistent \
    --shell /usr/sbin/nologin khaos-authority
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
