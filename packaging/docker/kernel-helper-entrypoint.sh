#!/bin/sh
set -eu

install -d -o root -g root -m 0755 /var/lib/khaos /run/khaos-helper
install -d -o root -g root -m 0700 /run/khaos-helper/journal
install -o root -g root -m 0600 \
  /run/secrets/khaos_browser_helper_secret \
  /var/lib/khaos/browser-helper.secret

expected_digest="$(awk '{print $1}' /usr/local/sbin/khaos-browser-kernel-helper.sha256)"
actual_digest="$(sha256sum /usr/local/sbin/khaos-browser-kernel-helper | awk '{print $1}')"
test -n "$expected_digest"
test "$actual_digest" = "$expected_digest"

exec /usr/local/sbin/khaos-browser-kernel-helper
