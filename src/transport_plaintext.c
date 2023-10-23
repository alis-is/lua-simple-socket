#include <stdio.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")
#else
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#endif
#include "transport_plaintext.h"

int
plaintext_recv(lss_connection_context* context, void* pBuffer, size_t bytesToRecv) {
    size_t bytesReceived = -1;
    int pollStatus = 1;
#ifdef _WIN32
    WSAPOLLFD pollFds;
    pollFds.events = POLLIN;
#else
    struct pollfd pollFds;
    pollFds.events = POLLIN | POLLPRI;
#endif
    pollFds.revents = 0;
    pollFds.fd = context->sd;

    if (bytesToRecv == 1U || context->read_timeout > 0) {
#ifdef _WIN32
        pollStatus = WSAPoll(&pollFds, 1, context->read_timeout);
#else
        pollStatus = poll(&pollFds, 1, context->read_timeout);
#endif
    }

    if (pollStatus > 0) {
        bytesReceived = recv(context->sd, pBuffer, bytesToRecv, 0);
    } else if (pollStatus < 0) {
        bytesReceived = -1;
    } else { // socket is not ready for reading
        bytesReceived = 0;
    }

    if ((pollStatus > 0) && (bytesReceived == 0)) {
        // connection closed
        bytesReceived = -1;
    }
    return bytesReceived;
}

int
plaintext_send(lss_connection_context* context, const void* pBuffer, size_t bytesToSend) {
    size_t bytesSent = -1;
    int pollStatus = -1;
#ifdef _WIN32
    WSAPOLLFD pollFds;
#else
    struct pollfd pollFds;
#endif

    pollFds.events = POLLOUT;
    pollFds.revents = 0;
    pollFds.fd = context->sd;

#ifdef _WIN32
    pollStatus = WSAPoll(&pollFds, 1, context->write_timeout);
#else
    pollStatus = poll(&pollFds, 1, context->write_timeout);
#endif

    if (pollStatus > 0) {
        bytesSent = send(context->sd, pBuffer, bytesToSend, 0);
    } else if (pollStatus < 0) {
        // failed to poll
        bytesSent = -1;
    } else {
        // socket not available for sending
        bytesSent = 0;
    }

    return bytesSent;
}