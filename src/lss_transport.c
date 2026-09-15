#include <lua.h>
#include <stdio.h>
#include <stdlib.h>
#include "lss_transport.h"

void
lss_close_context(lss_connection* conn) {
    switch (conn->kind) {
        case LSS_PLAINTEXT_CONTEXT_KIND: lss_close_connection(conn->context.plaintext); break;
        case LSS_TLS_CONTEXT_KIND: lss_close_tls_connection(conn->context.tls); break;
        default: return; /* already closed */
    }
    conn->kind = 0;
}

int
lss_close(lss_connection* conn) {
    lss_close_context(conn);
    free(conn); /* only for malloc-owned wrappers; Lua userdata uses lss_close_context */
    return 0;
}

int32_t
lss_recv(lss_connection* conn, void* pBuffer, size_t bytesToRecv) {
    switch (conn->kind) {
        case LSS_TLS_CONTEXT_KIND: return mbedtls_recv(conn->context.tls, pBuffer, bytesToRecv);
        case LSS_PLAINTEXT_CONTEXT_KIND: return plaintext_recv(conn->context.plaintext, pBuffer, bytesToRecv);
        default: fprintf(stderr, "ERROR: lss_recv: unknown connection kind: %d\n", conn->kind); return -1;
    }
}

int32_t
lss_send(lss_connection* conn, const void* pBuffer, size_t bytesToSend) {
    switch (conn->kind) {
        case LSS_TLS_CONTEXT_KIND: return mbedtls_send(conn->context.tls, pBuffer, bytesToSend);
        case LSS_PLAINTEXT_CONTEXT_KIND: return plaintext_send(conn->context.plaintext, pBuffer, bytesToSend);
        default: fprintf(stderr, "ERROR: lss_recv: unknown connection kind: %d\n", conn->kind); return -1;
    }
}

int32_t
lss_send_until(lss_connection* conn, const void* pBuffer, size_t bytesToSend, uint64_t deadline) {
    switch (conn->kind) {
        case LSS_TLS_CONTEXT_KIND: return mbedtls_send_until(conn->context.tls, pBuffer, bytesToSend, deadline);
        case LSS_PLAINTEXT_CONTEXT_KIND: return plaintext_send_until(conn->context.plaintext, pBuffer, bytesToSend, deadline);
        default: return -1;
    }
}
