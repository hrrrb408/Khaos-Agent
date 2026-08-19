#!/bin/sh
set -eu

# Production signing is mandatory.  Ad-hoc signing is intentionally not a
# supported production mode; a CI-only probe must opt in explicitly and its
# artifact is not closure evidence for a signed deployment.
: "${KHAOS_CODESIGN_IDENTITY:?set KHAOS_CODESIGN_IDENTITY for native authority signing}"
: "${KHAOS_TEAM_ID:?set KHAOS_TEAM_ID for Keychain access-group binding}"
: "${KHAOS_AGENT_CODE_SIGNATURE:?set KHAOS_AGENT_CODE_SIGNATURE for peer binding}"
# The designated requirement the XPC frontend will enforce for the Agent
# peer.  Without a Team-ID anchored requirement the frontend fails closed.
if [ -z "${KHAOS_AGENT_CODE_REQUIREMENT:-}" ]; then
  KHAOS_AGENT_CODE_REQUIREMENT="identifier \"${KHAOS_AGENT_CODE_SIGNATURE}\" and anchor apple generic and certificate leaf[subject.OU] = ${KHAOS_TEAM_ID}"
fi
export KHAOS_AGENT_CODE_REQUIREMENT

PREFIX=${KHAOS_NATIVE_PREFIX:-/usr/local/libexec}
BUILD_DIR=${KHAOS_NATIVE_BUILD_DIR:-$(pwd)/build/macos-native-authority}
mkdir -p "$BUILD_DIR" "$PREFIX"

CLANG=${KHAOS_CLANG:-$(xcrun --find clang)}
# The XPC service is compiled without ARC: the XPC C API manages object
# lifetimes explicitly through xpc_release, which ARC forbids.  Blocks for
# the event handler require -fblocks.  XPC symbols live in libSystem; there
# is no separate -lxpc to link against.
"$CLANG" -Wall -Wextra -Werror -fblocks \
  packaging/macos/khaos-authorityd-xpc.m \
  -o "$BUILD_DIR/khaos-authorityd-xpc" \
  -framework Security -framework CoreFoundation -framework Foundation \
  -framework SystemConfiguration
"$CLANG" -Wall -Wextra -Werror -fblocks \
  packaging/macos/khaos-authorityd-xpc-client.c \
  -o "$BUILD_DIR/khaos-authorityd-xpc-client" \
  -framework Foundation

codesign --force --sign "$KHAOS_CODESIGN_IDENTITY" \
  --entitlements packaging/macos/khaos-authorityd.entitlements \
  --options runtime "$BUILD_DIR/khaos-authorityd-xpc"
codesign --force --sign "$KHAOS_CODESIGN_IDENTITY" \
  --options runtime "$BUILD_DIR/khaos-authorityd-xpc-client"
install -m 0555 "$BUILD_DIR/khaos-authorityd-xpc" "$PREFIX/khaos-authorityd-xpc"
install -m 0555 "$BUILD_DIR/khaos-authorityd-xpc-client" "$PREFIX/khaos-authorityd-xpc-client"
codesign --verify --strict --verbose=2 "$PREFIX/khaos-authorityd-xpc"
codesign --verify --strict --verbose=2 "$PREFIX/khaos-authorityd-xpc-client"
# Verify the deployed binaries actually satisfy a Team-ID anchored
# requirement: signing "succeeded" is not proof unless the Security
# framework accepts the same requirement the XPC frontend will enforce.
codesign --verify --strict --verbose=2 \
  -R="anchor apple generic and certificate leaf[subject.OU] = ${KHAOS_TEAM_ID}" \
  "$PREFIX/khaos-authorityd-xpc"
codesign --verify --strict --verbose=2 \
  -R="anchor apple generic and certificate leaf[subject.OU] = ${KHAOS_TEAM_ID}" \
  "$PREFIX/khaos-authorityd-xpc-client"
# Emit the exact requirement expression for the deployment configuration.
printf '%s\n' "$KHAOS_AGENT_CODE_REQUIREMENT" > "$BUILD_DIR/agent-code-requirement.txt"
