/*
 * khaos-authorityd-keychain-provision — provision the protected-key item.
 *
 * The XPC frontend binds a Keychain presence check into its identity proof:
 * SecItemCopyMatching(kSecClassGenericPassword, account=PROTECTED_KEY_REF,
 * accessgroup=KEYCHAIN_GROUP) must succeed before it serves a request.
 * That item is a *presence marker* proving the protected-key slot is
 * materialized for the service identity — the attestation signing key
 * itself is the file Ed25519 key (0400, authority-uid owned); this tool
 * never writes key material.
 *
 * `security add-generic-password` cannot set kSecAttrAccessGroup, so the
 * item must be created through the Security framework by a binary whose
 * keychain-access-groups entitlement contains the target group — hence this
 * tool is built and signed with the same entitlements as the frontend.
 *
 * Usage: khaos-authorityd-keychain-provision ACCOUNT ACCESS_GROUP
 * Exit 0 on provision or already-present (errSecDuplicateItem); nonzero
 * means the item does not exist and the frontend will fail closed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s ACCOUNT ACCESS_GROUP\n", argv[0]);
        return 2;
    }
    /* Random marker value: a guessable constant would weaken the presence
     * proof to "anyone could have pre-provisioned it". */
    unsigned char entropy[32];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(entropy), entropy) != errSecSuccess) {
        fprintf(stderr, "CSPRNG failure: refusing to provision a guessable marker\n");
        return 3;
    }
    CFStringRef account = CFStringCreateWithCString(NULL, argv[1], kCFStringEncodingUTF8);
    CFStringRef group = CFStringCreateWithCString(NULL, argv[2], kCFStringEncodingUTF8);
    CFDataRef value = CFDataCreate(NULL, entropy, sizeof(entropy));
    if (account == NULL || group == NULL || value == NULL) {
        fprintf(stderr, "could not allocate keychain account, group, or marker data\n");
        if (account != NULL) CFRelease(account);
        if (group != NULL) CFRelease(group);
        if (value != NULL) CFRelease(value);
        return 4;
    }
    const void *keys[] = {kSecClass, kSecAttrAccount, kSecAttrAccessGroup, kSecValueData};
    const void *values[] = {kSecClassGenericPassword, account, group, value};
    CFDictionaryRef attributes = CFDictionaryCreate(
        NULL, keys, values, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus status = attributes == NULL ? errSecParam : SecItemAdd(attributes, NULL);
    if (attributes != NULL) CFRelease(attributes);
    CFRelease(account);
    CFRelease(group);
    CFRelease(value);
    if (status == errSecSuccess) {
        return 0;
    }
    if (status == errSecDuplicateItem) {
        return 0; /* idempotent re-provisioning */
    }
    fprintf(stderr, "SecItemAdd failed with %d\n", (int)status);
    return 1;
}
