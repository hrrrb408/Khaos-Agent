#!/bin/sh
set -eu

# Production signing is mandatory.  Ad-hoc signing is intentionally not a
# supported production mode; a CI-only probe must opt in explicitly and its
# artifact is not closure evidence for a signed deployment.
: "${KHAOS_CODESIGN_IDENTITY:?set KHAOS_CODESIGN_IDENTITY for native authority signing}"
: "${KHAOS_TEAM_ID:?set KHAOS_TEAM_ID for Keychain access-group binding}"
: "${KHAOS_AGENT_CODE_SIGNATURE:?set KHAOS_AGENT_CODE_SIGNATURE for peer binding}"

PREFIX=${KHAOS_NATIVE_PREFIX:-/usr/local/libexec}
BUILD_DIR=${KHAOS_NATIVE_BUILD_DIR:-$(pwd)/build/macos-native-authority}
mkdir -p "$BUILD_DIR" "$PREFIX"

CLANG=${KHAOS_CLANG:-$(xcrun --find clang)}
"$CLANG" -Wall -Wextra -Werror -fobjc-arc \
  packaging/macos/khaos-authorityd-xpc.m \
  -o "$BUILD_DIR/khaos-authorityd-xpc" \
  -framework Security -framework CoreFoundation -framework Foundation \
  -framework SystemConfiguration -lxpc
"$CLANG" -Wall -Wextra -Werror -fobjc-arc \
  packaging/macos/khaos-authorityd-xpc-client.c \
  -o "$BUILD_DIR/khaos-authorityd-xpc-client" \
  -framework Foundation -lxpc

codesign --force --sign "$KHAOS_CODESIGN_IDENTITY" \
  --entitlements packaging/macos/khaos-authorityd.entitlements \
  --options runtime "$BUILD_DIR/khaos-authorityd-xpc"
codesign --force --sign "$KHAOS_CODESIGN_IDENTITY" \
  --options runtime "$BUILD_DIR/khaos-authorityd-xpc-client"
install -m 0555 "$BUILD_DIR/khaos-authorityd-xpc" "$PREFIX/khaos-authorityd-xpc"
install -m 0555 "$BUILD_DIR/khaos-authorityd-xpc-client" "$PREFIX/khaos-authorityd-xpc-client"
codesign --verify --strict --verbose=2 "$PREFIX/khaos-authorityd-xpc"
codesign --verify --strict --verbose=2 "$PREFIX/khaos-authorityd-xpc-client"
