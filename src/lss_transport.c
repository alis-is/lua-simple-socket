#include <lua.h>
#include <stdio.h>
#include <stdlib.h>
#include "lss_transport.h"

int
lss_close(lss_connection* conn) {
    switch (conn->kind) {
        case LSS_PLAINTEXT_CONTEXT_KIND: lss_close_connection(conn->context.plaintext); break;
        case LSS_TLS_CONTEXT_KIND: lss_close_tls_connection(conn->context.tls); break;
    }
    free(conn);
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