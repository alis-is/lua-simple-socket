#include <stdio.h>
#include <errno.h>
#include <limits.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")
#else
#include <poll.h>
#include <sys/socket.h>
#endif
#include "lss_transport.h"
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
        // orderly connection close, distinct from transport failure
        bytesReceived = LSS_TRANSPORT_EOF;
    }
    return bytesReceived;
}

int
plaintext_send(lss_connection_context* context, const void* pBuffer, size_t bytesToSend) {
    uint64_t deadline = context->write_timeout > 0 ? lss_monotonic_ms() + context->write_timeout : UINT64_MAX;
    return plaintext_send_until(context, pBuffer, bytesToSend, deadline);
}

int
plaintext_send_until(lss_connection_context* context, const void* pBuffer, size_t bytesToSend, uint64_t deadline) {
    if (bytesToSend == 0) return 0;
    int sent = -1;
    int size = bytesToSend > INT_MAX ? INT_MAX : (int)bytesToSend;
#ifdef _WIN32
    /* Connections are blocking for reads; only sends temporarily change mode.
     * ponytail: the FIONBIO flip is not safe if a socket is shared across threads. */
    u_long mode = 1;
    if (ioctlsocket(context->sd, FIONBIO, &mode) != 0) return -1;
    WSAPOLLFD pfd;
#else
    struct pollfd pfd;
#endif
    for (;;) {
        int timeout = -1;
        if (deadline != UINT64_MAX) {
            uint64_t now = lss_monotonic_ms();
            if (now >= deadline) { errno = ETIMEDOUT; break; }
            uint64_t remaining = deadline - now;
            timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
        }
        pfd.fd = context->sd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
#ifdef _WIN32
        int ready = WSAPoll(&pfd, 1, timeout);
        if (ready < 0 && WSAGetLastError() == WSAEINTR) continue;
#else
        int ready = poll(&pfd, 1, timeout);
        if (ready < 0 && errno == EINTR) continue;
#endif
        if (ready == 0) errno = ETIMEDOUT;
        if (ready <= 0) break;
#ifdef _WIN32
        sent = send(context->sd, pBuffer, size, 0);
        int err = WSAGetLastError();
        if (sent < 0 && (err == WSAEWOULDBLOCK || err == WSAEINTR)) continue;
#else
        /* Readiness does not guarantee a blocking send can finish. */
#ifdef MSG_NOSIGNAL
        sent = send(context->sd, pBuffer, size, MSG_DONTWAIT | MSG_NOSIGNAL);
#else
        sent = send(context->sd, pBuffer, size, MSG_DONTWAIT);
#endif
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
#endif
        break;
    }
#ifdef _WIN32
    mode = 0;
    if (ioctlsocket(context->sd, FIONBIO, &mode) != 0) return -1;
#endif
    return sent > 0 ? sent : -1;
}
