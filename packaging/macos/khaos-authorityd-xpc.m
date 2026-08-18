/*
 * Khaos macOS launchd/XPC authority transport.
 *
 * The process is launched by launchd under the dedicated authority account.
 * It accepts only the privileged Mach service connection, validates the
 * caller's audit token and code signature, checks a Keychain item without
 * exporting its secret, and forwards bounded JSON to the authority backend
 * over a private socket owned by that account.  It has no same-UID Python or
 * Unix-socket fallback for Agent callers.
 */

#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <xpc/xpc.h>

#define MAX_MESSAGE_BYTES (64U * 1024U)

static int load_configuration(void) {
    const char *path = getenv("KHAOS_AUTHORITYD_CONFIG_PATH");
    if (path == NULL || path[0] != '/' || strlen(path) >= PATH_MAX) return 0;
    int descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) return 0;
    struct stat metadata = {0};
    int valid = fstat(descriptor, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
        metadata.st_size <= MAX_MESSAGE_BYTES &&
        (metadata.st_uid == 0 || metadata.st_uid == geteuid()) &&
        (metadata.st_mode & (S_IWGRP | S_IWOTH)) == 0;
    if (!valid) {
        close(descriptor);
        return 0;
    }
    char buffer[MAX_MESSAGE_BYTES + 1] = {0};
    ssize_t length = read(descriptor, buffer, sizeof(buffer) - 1);
    close(descriptor);
    if (length < 0 || (size_t)length >= sizeof(buffer)) return 0;
    buffer[length] = '\0';
    char *line = strtok(buffer, "\n");
    while (line != NULL) {
        char *separator = strchr(line, '=');
        if (separator != NULL) {
            *separator = '\0';
            const char *name = line;
            const char *value = separator + 1;
            if (name[0] == 'K' && value[0] != '\0' &&
                (strcmp(name, "KHAOS_AGENT_UID") == 0 ||
                 strcmp(name, "KHAOS_AUTHORITYD_AGENT_CODE_SIGNATURE") == 0 ||
                 strcmp(name, "KHAOS_AUTHORITYD_AGENT_CODE_REQUIREMENT") == 0 ||
                 strcmp(name, "KHAOS_AUTHORITYD_KEYCHAIN_GROUP") == 0 ||
                 strcmp(name, "KHAOS_AUTHORITYD_PROTECTED_KEY_REF") == 0 ||
                 strcmp(name, "KHAOS_AUTHORITYD_SERVICE_CODE_SIGNATURE") == 0 ||
                 strcmp(name, "KHAOS_AUTHORITYD_SERVICE_CODE_REQUIREMENT") == 0 ||
                 strcmp(name, "KHAOS_AUTHORITYD_BACKEND_SOCKET") == 0 ||
                 strcmp(name, "KHAOS_AUTHORITYD_XPC_SERVICE") == 0)) {
                if (setenv(name, value, 1) != 0) return 0;
            }
        }
        line = strtok(NULL, "\n");
    }
    return 1;
}

static const char *env_required(const char *name) {
    const char *value = getenv(name);
    if (value == NULL || value[0] == '\0') {
        return NULL;
    }
    return value;
}

static int parse_uid(const char *value, uid_t *result) {
    if (value == NULL || result == NULL) {
        return 0;
    }
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (end == value || *end != '\0' || parsed > UINT_MAX) {
        return 0;
    }
    *result = (uid_t)parsed;
    return 1;
}

static int requirement_from_env(const char *name, SecRequirementRef *out) {
    /* Build a designated code requirement from deployment configuration.
     * The requirement expression (identifier + anchor + Team ID binding)
     * is the only accepted peer identity; an identifier alone is not. */
    const char *text = env_required(name);
    if (text == NULL) return 0;
    CFStringRef expression = CFStringCreateWithCString(
        kCFAllocatorDefault, text, kCFStringEncodingUTF8);
    if (expression == NULL) return 0;
    OSStatus status = SecRequirementCreateWithString(expression, kSecCSDefaultFlags, out);
    CFRelease(expression);
    return status == errSecSuccess;
}

static void digest_hex(const char *text, char output[65]) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(text, (CC_LONG)strlen(text), digest);
    for (size_t index = 0; index < sizeof(digest); ++index) {
        snprintf(output + (index * 2), 3, "%02x", digest[index]);
    }
    output[64] = '\0';
}

static int copy_code_identity(
    pid_t pid,
    SecRequirementRef requirement,
    char *identifier,
    size_t identifier_capacity,
    char *team_id,
    size_t team_capacity,
    char *cdhash_hex,
    size_t cdhash_capacity
) {
    if (pid <= 0 || requirement == NULL || identifier == NULL || identifier_capacity == 0 ||
        team_id == NULL || team_capacity == 0 || cdhash_hex == NULL || cdhash_capacity < 41) {
        return 0;
    }
    CFNumberRef pid_number = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pid);
    if (pid_number == NULL) {
        return 0;
    }
    const void *keys[] = { kSecGuestAttributePid };
    const void *values[] = { pid_number };
    CFDictionaryRef attributes = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    SecCodeRef guest = NULL;
    CFDictionaryRef signing = NULL;
    int valid = attributes != NULL &&
        SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &guest) == errSecSuccess;
    /* The designated requirement is evaluated by the Security framework
     * itself: same UID + identifier alone can never satisfy a Team-ID
     * anchored requirement.  Unsigned, ad-hoc, or modified binaries fail
     * this check. */
    if (valid) {
        valid = SecCodeCheckValidity(guest, kSecCSDefaultFlags, requirement) == errSecSuccess;
    }
    if (valid) {
        valid = SecCodeCopySigningInformation(guest, kSecCSSigningInformation, &signing) == errSecSuccess;
    }
    if (valid) {
        CFStringRef code_identifier = CFDictionaryGetValue(signing, kSecCodeInfoIdentifier);
        valid = code_identifier != NULL && CFStringGetCString(
            code_identifier, identifier, (CFIndex)identifier_capacity, kCFStringEncodingUTF8);
    }
    if (valid) {
        CFStringRef team = CFDictionaryGetValue(signing, kSecCodeInfoTeamIdentifier);
        valid = team != NULL && CFStringGetCString(
            team, team_id, (CFIndex)team_capacity, kCFStringEncodingUTF8);
    }
    if (valid) {
        /* kSecCodeInfoUnique is the binary code-directory hash that
         * uniquely identifies the exact signed code the peer runs. */
        CFDataRef unique = CFDictionaryGetValue(signing, kSecCodeInfoUnique);
        valid = unique != NULL && CFDataGetLength(unique) == 20;
        if (valid) {
            const unsigned char *bytes = CFDataGetBytePtr(unique);
            for (size_t index = 0; index < 20; ++index) {
                snprintf(cdhash_hex + (index * 2), 3, "%02x", bytes[index]);
            }
            cdhash_hex[40] = '\0';
        }
    }
    if (signing != NULL) CFRelease(signing);
    if (guest != NULL) CFRelease(guest);
    if (attributes != NULL) CFRelease(attributes);
    CFRelease(pid_number);
    return valid;
}

static int verify_keychain_item(const char *key_ref, const char *access_group) {
    if (key_ref == NULL || access_group == NULL) {
        return 0;
    }
    CFStringRef account = CFStringCreateWithCString(kCFAllocatorDefault, key_ref, kCFStringEncodingUTF8);
    CFStringRef group = CFStringCreateWithCString(kCFAllocatorDefault, access_group, kCFStringEncodingUTF8);
    if (account == NULL || group == NULL) {
        if (account != NULL) CFRelease(account);
        if (group != NULL) CFRelease(group);
        return 0;
    }
    const void *keys[] = { kSecClass, kSecAttrAccount, kSecAttrAccessGroup, kSecMatchLimit, kSecReturnAttributes };
    const void *values[] = { kSecClassGenericPassword, account, group, kSecMatchLimitOne, kCFBooleanTrue };
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef result = NULL;
    OSStatus status = query == NULL ? errSecParam : SecItemCopyMatching(query, &result);
    if (result != NULL) CFRelease(result);
    if (query != NULL) CFRelease(query);
    CFRelease(account);
    CFRelease(group);
    return status == errSecSuccess;
}

struct peer_identity {
    char identifier[256];
    char team_id[64];
    char cdhash[41];
    char requirement_digest[65];
};

static int verify_peer(xpc_connection_t peer, struct peer_identity *identity) {
    uid_t peer_uid = xpc_connection_get_euid(peer);
    pid_t peer_pid = xpc_connection_get_pid(peer);
    au_asid_t peer_asid = xpc_connection_get_asid(peer);
    uid_t agent_uid = 0;
    const char *configured_uid = env_required("KHAOS_AGENT_UID");
    const char *expected_identity = env_required("KHAOS_AUTHORITYD_AGENT_CODE_SIGNATURE");
    const char *requirement_text = env_required("KHAOS_AUTHORITYD_AGENT_CODE_REQUIREMENT");
    SecRequirementRef requirement = NULL;
    if (!parse_uid(configured_uid, &agent_uid) || expected_identity == NULL ||
        requirement_text == NULL ||
        peer_uid != agent_uid || peer_uid == geteuid() || peer_pid <= 0 ||
        peer_asid == 0) {
        return 0;
    }
    if (!requirement_from_env("KHAOS_AUTHORITYD_AGENT_CODE_REQUIREMENT", &requirement)) {
        return 0;
    }
    int valid = copy_code_identity(
        peer_pid,
        requirement,
        identity->identifier,
        sizeof(identity->identifier),
        identity->team_id,
        sizeof(identity->team_id),
        identity->cdhash,
        sizeof(identity->cdhash));
    CFRelease(requirement);
    if (!valid) {
        return 0;
    }
    digest_hex(requirement_text, identity->requirement_digest);
    /* Defense in depth: the designated requirement already anchors the
     * Team ID; the plain identifier comparison additionally rejects a
     * requirement that accidentally matched a different bundle id. */
    return strcmp(identity->identifier, expected_identity) == 0;
}

static int verify_self_identity(struct peer_identity *identity) {
    SecRequirementRef requirement = NULL;
    const char *requirement_text = env_required("KHAOS_AUTHORITYD_SERVICE_CODE_REQUIREMENT");
    const char *expected_identity = env_required("KHAOS_AUTHORITYD_SERVICE_CODE_SIGNATURE");
    SecCodeRef self = NULL;
    if (requirement_text == NULL || expected_identity == NULL ||
        !requirement_from_env("KHAOS_AUTHORITYD_SERVICE_CODE_REQUIREMENT", &requirement)) {
        return 0;
    }
    int valid = SecCodeCopySelf(kSecCSDefaultFlags, &self) == errSecSuccess &&
        SecCodeCheckValidity(self, kSecCSDefaultFlags, requirement) == errSecSuccess;
    CFRelease(requirement);
    if (self != NULL) CFRelease(self);
    if (!valid) {
        return 0;
    }
    snprintf(identity->identifier, sizeof(identity->identifier), "%s", expected_identity);
    snprintf(identity->team_id, sizeof(identity->team_id), "%s", requirement_text);
    identity->cdhash[0] = '\0';
    digest_hex(requirement_text, identity->requirement_digest);
    return 1;
}

static void service_instance_id(char output[33]) {
    static char instance[33] = {0};
    if (instance[0] == '\0') {
        unsigned char entropy[16] = {0};
        if (SecRandomCopyBytes(kSecRandomDefault, sizeof(entropy), entropy) != errSecSuccess) {
            /* A missing CSPRNG must never produce a constant instance id. */
            exit(78);
        }
        for (size_t index = 0; index < sizeof(entropy); ++index) {
            snprintf(instance + (index * 2), 3, "%02x", entropy[index]);
        }
        instance[32] = '\0';
    }
    snprintf(output, 33, "%s", instance);
}

static void digest_for_peer(
    const char *service_id,
    const struct peer_identity *peer,
    const struct peer_identity *service,
    const char *instance_id,
    const char *key_ref,
    char output[65]
) {
    /* The proof digest covers every identity field the transport proved:
     * service, peer, Team ID, code-directory hash, requirement digests,
     * the service instance, and the protected key reference. */
    char input[2048];
    int written = snprintf(
        input, sizeof(input),
        "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
        service_id,
        service->identifier,
        peer->identifier,
        peer->team_id,
        peer->cdhash,
        peer->requirement_digest,
        service->requirement_digest,
        instance_id,
        key_ref,
        "native-authority-proof-v2");
    if (written < 0 || (size_t)written >= sizeof(input)) {
        output[0] = '\0';
        return;
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(input, (CC_LONG)written, digest);
    for (size_t index = 0; index < sizeof(digest); ++index) {
        snprintf(output + (index * 2), 3, "%02x", digest[index]);
    }
    output[64] = '\0';
}

static int send_all(int descriptor, const unsigned char *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = send(descriptor, buffer + offset, length - offset, 0);
        if (written <= 0) return 0;
        offset += (size_t)written;
    }
    return 1;
}

static int verify_backend_socket(const char *path) {
    /* The backend socket must be a socket owned by this service's own
     * authority identity with no group/other access.  A symlink, a regular
     * file, or a socket owned by another UID (for example the agent user)
     * is rejected before connect(). */
    if (path == NULL || path[0] != '/') return 0;
    struct stat metadata = {0};
    if (lstat(path, &metadata) != 0) return 0;
    if (!S_ISSOCK(metadata.st_mode)) return 0;
    if (metadata.st_uid != geteuid()) return 0;
    if ((metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) return 0;
    return 1;
}

static int backend_request(const char *request, char *response, size_t capacity) {
    const char *path = env_required("KHAOS_AUTHORITYD_BACKEND_SOCKET");
    if (path == NULL || path[0] != '/' || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 0;
    if (!verify_backend_socket(path)) return 0;
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) return 0;
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    strlcpy(address.sun_path, path, sizeof(address.sun_path));
    int connected = connect(descriptor, (struct sockaddr *)&address, sizeof(address)) == 0;
    size_t request_length = strlen(request);
    if (connected) connected = request_length < MAX_MESSAGE_BYTES && send_all(descriptor, (const unsigned char *)request, request_length);
    if (connected) connected = send_all(descriptor, (const unsigned char *)"\n", 1);
    size_t offset = 0;
    while (connected && offset + 1 < capacity) {
        ssize_t read_count = recv(descriptor, response + offset, capacity - offset - 1, 0);
        if (read_count < 0) { connected = 0; break; }
        if (read_count == 0) break;
        offset += (size_t)read_count;
        if (memchr(response, '\n', offset) != NULL) break;
    }
    close(descriptor);
    if (!connected || offset == 0) return 0;
    response[offset] = '\0';
    char *newline = strchr(response, '\n');
    if (newline != NULL) *newline = '\0';
    return response[0] == '{' && response[strlen(response) - 1] == '}';
}

static void reply_error(xpc_object_t reply, const char *message) {
    xpc_dictionary_set_string(reply, "error", message);
}

static void handle_message(xpc_connection_t peer, xpc_object_t event) {
    xpc_object_t reply = xpc_dictionary_create(NULL, NULL, 0);
    const char *service_id = env_required("KHAOS_AUTHORITYD_XPC_SERVICE");
    const char *key_ref = env_required("KHAOS_AUTHORITYD_PROTECTED_KEY_REF");
    const char *access_group = env_required("KHAOS_AUTHORITYD_KEYCHAIN_GROUP");
    struct peer_identity agent = {0};
    struct peer_identity service = {0};
    int peer_ok = verify_peer(peer, &agent);
    int service_ok = service_id != NULL && key_ref != NULL && access_group != NULL &&
        verify_self_identity(&service);
    int key_ok = key_ref != NULL && access_group != NULL && verify_keychain_item(key_ref, access_group);
    char instance_id[33] = {0};
    service_instance_id(instance_id);
    char proof_digest[65] = {0};
    if (service_id != NULL && peer_ok && service_ok && key_ok) {
        digest_for_peer(service_id, &agent, &service, instance_id, key_ref, proof_digest);
    }
    const char *kind = xpc_dictionary_get_string(event, "kind");
    if (kind == NULL || !peer_ok || !service_ok || !key_ok || proof_digest[0] == '\0') {
        reply_error(reply, "native XPC identity proof failed");
    } else if (strcmp(kind, "probe") == 0) {
        char proof_json[MAX_MESSAGE_BYTES];
        snprintf(proof_json, sizeof(proof_json),
            "{\"platform\":\"darwin\",\"transport\":\"xpc\",\"service_id\":\"%s\",\"service_pid\":%d,"
            "\"service_identity\":\"%s\",\"peer_identity\":\"%s\","
            "\"peer_team_id\":\"%s\",\"peer_cdhash\":\"%s\","
            "\"designated_requirement_digest\":\"%s\","
            "\"service_instance_id\":\"%s\","
            "\"protected_key_ref\":\"%s\",\"challenge_digest\":\"%s\","
            "\"peer_verified\":true,\"transport_verified\":true,\"protected_key_verified\":true}",
            service_id, getpid(),
            service.identifier,
            agent.identifier,
            agent.team_id,
            agent.cdhash,
            agent.requirement_digest,
            instance_id,
            key_ref, proof_digest);
        xpc_dictionary_set_string(reply, "proof_json", proof_json);
    } else if (strcmp(kind, "request") == 0) {
        size_t request_length = 0;
        const void *request_data = xpc_dictionary_get_data(event, "request_json", &request_length);
        char request[MAX_MESSAGE_BYTES];
        char backend_response[MAX_MESSAGE_BYTES];
        if (request_data == NULL || request_length == 0 || request_length >= sizeof(request)) {
            reply_error(reply, "native XPC request is empty or oversized");
        } else {
            memcpy(request, request_data, request_length);
            request[request_length] = '\0';
            if (!backend_request(request, backend_response, sizeof(backend_response))) {
                reply_error(reply, "authority backend is unavailable");
            } else {
                char *body = backend_response + 1;
                size_t body_length = strlen(body);
                if (body_length == 0 || backend_response[strlen(backend_response) - 1] != '}') {
                    reply_error(reply, "authority backend returned malformed JSON");
                } else {
                    backend_response[strlen(backend_response) - 1] = '\0';
                    char wrapped[MAX_MESSAGE_BYTES];
                    snprintf(wrapped, sizeof(wrapped), "{\"native_transport\":\"xpc\",\"proof_digest\":\"%s\",%s", proof_digest, body);
                    xpc_dictionary_set_string(reply, "response_json", wrapped);
                }
            }
        }
    } else {
        reply_error(reply, "unknown native XPC request kind");
    }
    xpc_connection_send_message(peer, reply);
    xpc_release(reply);
}

static void service_connection(xpc_connection_t peer) {
    xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
            handle_message(peer, event);
        }
    });
    xpc_connection_resume(peer);
}

/* NOTE: this translation unit is built without -fobjc-arc (see
 * build-native-authority.sh) because the XPC C API is managed manually
 * through xpc_release.  Do not add ARC-only Objective-C code here. */

int main(void) {
    if (!load_configuration()) {
        return 78;
    }
    xpc_main(service_connection);
    return 0;
}
