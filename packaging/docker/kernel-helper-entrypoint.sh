#!/bin/sh
set -eu

install -d -o root -g root -m 0755 /var/lib/khaos /run/khaos-helper
install -d -o root -g root -m 0700 /run/khaos-helper/journal
install -o root -g root -m 0600 \
  /run/secrets/khaos_browser_helper_secret \
  /var/lib/khaos/browser-helper.secret

exec /usr/local/sbin/khaos-browser-kernel-helper
