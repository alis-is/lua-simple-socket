#include "lss_transport.h"
#include "transport_mbedtls.h"

int
mbedtls_recv(lss_tls_connection_context* context, void* pBuffer, size_t bytesToRecv) {
    if (bytesToRecv == 0) return 0;
    /* Preserve the one-byte probe used by corehttp; other default reads wait. */
    uint64_t deadline = context->read_timeout > 0 ? lss_monotonic_ms() + context->read_timeout
        : bytesToRecv == 1U && context->read_timeout == 0 ? lss_monotonic_ms() : UINT64_MAX;
    for (;;) {
        /* Read first so buffered plaintext is returned without polling. */
        int received = mbedtls_ssl_read(&context->ssl, pBuffer, bytesToRecv);
        if (received == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
            if (deadline != UINT64_MAX && lss_monotonic_ms() >= deadline) return 0;
            continue;
        }
        if (received == MBEDTLS_ERR_SSL_WANT_READ || received == MBEDTLS_ERR_SSL_WANT_WRITE) {
            int err = lss_tls_wait(context, received, deadline);
            if (err == MBEDTLS_ERR_SSL_TIMEOUT) return 0;
            if (err != 0) return err;
            continue;
        }
        if (received == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            /* Remember the authenticated close: the next read returns 0 even
             * though the stream ended cleanly. */
            context->clean_eof = 1;
            return LSS_TRANSPORT_EOF;
        }
        if (received == 0) {
            // TCP EOF without close_notify cannot authenticate a close-delimited body.
            return context->clean_eof ? LSS_TRANSPORT_EOF : MBEDTLS_ERR_SSL_CONN_EOF;
        }
        return received;
    }
}

int
mbedtls_send(lss_tls_connection_context* context, const void* pBuffer, size_t bytesToSend) {
    uint64_t deadline = context->write_timeout > 0 ? lss_monotonic_ms() + context->write_timeout : UINT64_MAX;
    return mbedtls_send_until(context, pBuffer, bytesToSend, deadline);
}

int
mbedtls_send_until(lss_tls_connection_context* context, const void* pBuffer, size_t bytesToSend, uint64_t deadline) {
    if (bytesToSend == 0) return 0;
    if (deadline != UINT64_MAX && lss_monotonic_ms() >= deadline) return MBEDTLS_ERR_SSL_TIMEOUT;
    for (;;) {
        int sent = mbedtls_ssl_write(&context->ssl, pBuffer, bytesToSend);
        if (sent != MBEDTLS_ERR_SSL_WANT_READ && sent != MBEDTLS_ERR_SSL_WANT_WRITE) return sent;
        /* Retry with identical arguments as required by mbedtls. A timeout is
         * an error, not zero progress that Lua's write loop would retry forever. */
        int err = lss_tls_wait(context, sent, deadline);
        if (err != 0) {
            /* A pending TLS write cannot be retried with different data. */
            mbedtls_net_free(&context->socket);
            return err;
        }
    }
}
