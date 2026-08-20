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

# Xcode expands build settings in an Xcode target, but this deployment is
# intentionally command-line driven.  Render a concrete plist before
# codesign; signing the source placeholder would either leave an unusable
# entitlement or bind the binary to a literal ``$(...)`` group.
case "$KHAOS_TEAM_ID" in
  ""|*[!A-Za-z0-9]*)
    echo "KHAOS_TEAM_ID must be an alphanumeric Team ID" >&2
    exit 2
    ;;
esac
ENTITLEMENTS="$BUILD_DIR/khaos-authorityd.rendered.entitlements"
cp packaging/macos/khaos-authorityd.entitlements "$ENTITLEMENTS"
/usr/libexec/PlistBuddy -c \
  "Set :com.apple.security.application-groups:0 ${KHAOS_TEAM_ID}.com.khaos.authority" \
  "$ENTITLEMENTS"
/usr/libexec/PlistBuddy -c \
  "Set :keychain-access-groups:0 ${KHAOS_TEAM_ID}.com.khaos.authority" \
  "$ENTITLEMENTS"

verify_entitlements() {
  target="$1"
  dump="$BUILD_DIR/$(basename "$target").signed-entitlements.plist"
  codesign --display --entitlements :- "$target" 2>/dev/null > "$dump"
  group=$(/usr/libexec/PlistBuddy -c "Print :keychain-access-groups:0" "$dump")
  application_group=$(/usr/libexec/PlistBuddy -c \
    "Print :com.apple.security.application-groups:0" "$dump")
  expected="${KHAOS_TEAM_ID}.com.khaos.authority"
  [ "$group" = "$expected" ] || {
    echo "signed keychain access group is not concrete" >&2
    exit 1
  }
  [ "$application_group" = "$expected" ] || {
    echo "signed application group is not concrete" >&2
    exit 1
  }
  ! grep -Fq '$(' "$dump" || {
    echo "signed entitlements contain an unresolved build placeholder" >&2
    exit 1
  }
}

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
"$CLANG" -Wall -Wextra -Werror \
  packaging/macos/khaos-authorityd-keychain-provision.c \
  -o "$BUILD_DIR/khaos-authorityd-keychain-provision" \
  -framework Security -framework CoreFoundation

codesign --force --sign "$KHAOS_CODESIGN_IDENTITY" \
  --entitlements "$ENTITLEMENTS" \
  --options runtime "$BUILD_DIR/khaos-authorityd-xpc"
codesign --force --sign "$KHAOS_CODESIGN_IDENTITY" \
  --options runtime "$BUILD_DIR/khaos-authorityd-xpc-client"
# The provisioner must carry the same keychain-access-groups entitlement
# as the frontend: SecItemAdd can only create an item inside an access
# group the signing identity is entitled to.
codesign --force --sign "$KHAOS_CODESIGN_IDENTITY" \
  --entitlements "$ENTITLEMENTS" \
  --options runtime "$BUILD_DIR/khaos-authorityd-keychain-provision"
verify_entitlements "$BUILD_DIR/khaos-authorityd-xpc"
verify_entitlements "$BUILD_DIR/khaos-authorityd-keychain-provision"
install -m 0555 "$BUILD_DIR/khaos-authorityd-xpc" "$PREFIX/khaos-authorityd-xpc"
install -m 0555 "$BUILD_DIR/khaos-authorityd-xpc-client" "$PREFIX/khaos-authorityd-xpc-client"
install -m 0555 "$BUILD_DIR/khaos-authorityd-keychain-provision" "$PREFIX/khaos-authorityd-keychain-provision"
codesign --verify --strict --verbose=2 "$PREFIX/khaos-authorityd-xpc"
codesign --verify --strict --verbose=2 "$PREFIX/khaos-authorityd-xpc-client"
codesign --verify --strict --verbose=2 "$PREFIX/khaos-authorityd-keychain-provision"
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
