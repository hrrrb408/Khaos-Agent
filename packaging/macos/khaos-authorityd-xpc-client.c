/*
 * Khaos macOS authority client.
 *
 * This is intentionally a small XPC-only transport client.  It never opens
 * the authority backend socket and never contains signing material.  The
 * launchd Mach service proves the peer audit token, code signature and
 * Keychain access-group before forwarding a bounded request to the
 * separately owned authority backend.
 *
 * Every probe/request carries a client-generated 256-bit challenge nonce
 * (ADR-023).  The response must contain a backend-signed attestation that
 * covers this exact nonce; the Python adapter verifies the signature with
 * the authority public key.  This client only transports the challenge.
 */

#include <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xpc/xpc.h>

#define MAX_REQUEST_BYTES (64U * 1024U)

static void fail(const char *message) {
    fprintf(stderr, "khaos-authority-xpc-client: %s\n", message);
    exit(1);
}

static int valid_service_id(const char *value) {
    if (value == NULL || value[0] == '\0') {
        return 0;
    }
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor; ++cursor) {
        if (!(('a' <= *cursor && *cursor <= 'z') ||
              ('A' <= *cursor && *cursor <= 'Z') ||
              ('0' <= *cursor && *cursor <= '9') ||
              *cursor == '.' || *cursor == '-' || *cursor == '_')) {
            return 0;
        }
    }
    return 1;
}

static int valid_challenge(const char *value) {
    if (value == NULL || strlen(value) != 64) {
        return 0;
    }
    for (const char *cursor = value; *cursor; ++cursor) {
        if (!((*cursor >= '0' && *cursor <= '9') ||
              (*cursor >= 'a' && *cursor <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static char *read_request(void) {
    char *buffer = calloc(1, MAX_REQUEST_BYTES + 1U);
    if (buffer == NULL) {
        fail("request allocation failed");
    }
    size_t length = fread(buffer, 1, MAX_REQUEST_BYTES + 1U, stdin);
    if (ferror(stdin) || length > MAX_REQUEST_BYTES) {
        free(buffer);
        fail("request exceeds the native transport budget");
    }
    buffer[length] = '\0';
    return buffer;
}

static xpc_object_t send_message(const char *service_id, xpc_object_t message) {
    xpc_connection_t connection = xpc_connection_create_mach_service(
        service_id,
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
        XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    if (connection == NULL) {
        fail("could not create the launchd Mach-service connection");
    }
    xpc_connection_resume(connection);
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(connection, message);
    xpc_release(message);
    xpc_connection_cancel(connection);
    if (reply == NULL || xpc_get_type(reply) == XPC_TYPE_ERROR) {
        if (reply != NULL) {
            const char *description = xpc_dictionary_get_string(reply, XPC_ERROR_KEY_DESCRIPTION);
            if (description != NULL) {
                fprintf(stderr, "khaos-authority-xpc-client: %s\n", description);
            }
            xpc_release(reply);
        }
        fail("launchd/XPC authority did not return a reply");
    }
    return reply;
}

int main(int argc, char **argv) {
    if (argc < 4 || (strcmp(argv[1], "--probe") != 0 && strcmp(argv[1], "--request") != 0) ||
        strcmp(argv[2], "--service-id") != 0 || !valid_service_id(argv[3])) {
        fail("usage: --probe|--request --service-id <launchd-mach-service> [--challenge <64-hex>]");
    }
    const char *challenge = NULL;
    if (argc == 6 && strcmp(argv[4], "--challenge") == 0) {
        challenge = argv[5];
        if (!valid_challenge(challenge)) {
            fail("challenge nonce must be 64 lowercase hex characters");
        }
    } else if (argc != 4) {
        fail("usage: --probe|--request --service-id <launchd-mach-service> [--challenge <64-hex>]");
    }

    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "challenge_nonce", challenge == NULL ? "" : challenge);
    if (strcmp(argv[1], "--probe") == 0) {
        xpc_dictionary_set_string(message, "kind", "probe");
    } else {
        char *request = read_request();
        xpc_dictionary_set_string(message, "kind", "request");
        xpc_dictionary_set_data(message, "request_json", request, strlen(request));
        free(request);
    }
    xpc_object_t reply = send_message(argv[3], message);
    const char *json = xpc_dictionary_get_string(reply, "response_json");
    if (json == NULL || json[0] == '\0' || strlen(json) > MAX_REQUEST_BYTES) {
        const char *error = xpc_dictionary_get_string(reply, "error");
        if (error != NULL) {
            fprintf(stderr, "khaos-authority-xpc-client: %s\n", error);
        }
        xpc_release(reply);
        fail("native authority returned an empty or oversized JSON response");
    }
    puts(json);
    xpc_release(reply);
    return 0;
}
