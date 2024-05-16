#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#endif
#include "transport_mbedtls.h"

int
mbedtls_recv(lss_tls_connection_context* context, void* pBuffer, size_t bytesToRecv) {
    int bytesReceived = -1, pollStatus = 1;
#ifdef _WIN32
    WSAPOLLFD pollFds;
    pollFds.events = POLLIN;
#else
    struct pollfd pollFds;
    pollFds.events = POLLIN | POLLPRI;
#endif
    pollFds.revents = 0;
    pollFds.fd = context->socket.fd;

    if (bytesToRecv == 1U || context->read_timeout > 0) {
#ifdef _WIN32
        pollStatus = WSAPoll(&pollFds, 1, context->read_timeout);
#else
        pollStatus = poll(&pollFds, 1, context->read_timeout);
#endif
    }

    if (pollStatus > 0) // socket is ready for reading
    {
        bytesReceived = mbedtls_ssl_read(&context->ssl, pBuffer, bytesToRecv);
        // TODO: session tickets?
        while (bytesReceived == MBEDTLS_ERR_SSL_WANT_READ || bytesReceived == MBEDTLS_ERR_SSL_WANT_WRITE
               || bytesReceived == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
            bytesReceived = mbedtls_ssl_read(&context->ssl, pBuffer, bytesToRecv);
        };
    } else if (pollStatus < 0) // failed to poll
    {
        bytesReceived = -1;
    } else { // socket is not ready for reading
        bytesReceived = 0;
    }

    if ((pollStatus > 0) && (bytesReceived == 0)) {
        // context closed
        bytesReceived = -1;
    }
    return bytesReceived;
}

int
mbedtls_send(lss_tls_connection_context* context, const void* pBuffer, size_t bytesToSend) {
    int bytesSent = -1, pollStatus = -1;
#ifdef _WIN32
    WSAPOLLFD pollFds;
#else
    struct pollfd pollFds;
#endif

    // return mbedtls_ssl_write(&context->ssl, pBuffer, bytesToSend);
    pollFds.events = POLLOUT;
    pollFds.revents = 0;
    pollFds.fd = context->socket.fd;

#ifdef _WIN32
    pollStatus = WSAPoll(&pollFds, 1, context->write_timeout);
#else
    pollStatus = poll(&pollFds, 1, context->write_timeout);
#endif

    if (pollStatus > 0) // socket is ready for writing
    {
        bytesSent = mbedtls_ssl_write(&context->ssl, pBuffer, bytesToSend);
    } else if (pollStatus < 0) // failed to poll
    {
        bytesSent = -1;
    } else // socket is not ready for writing
    {
        bytesSent = 0;
    }

    return bytesSent;
}