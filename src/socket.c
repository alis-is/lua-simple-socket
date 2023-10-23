#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "socket.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

lss_connection_result
lss_open_connection(const char* hostname, int portno, lss_open_connection_options* options) {
#ifdef _WIN32
    SOCKET sd;
#else
    int sd;
#endif
    int err;
    struct addrinfo hints, *addrs;
    char portno_str[16];

    lss_connection_result result = {NULL, 0, ERR_SRC_NONE};

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    sprintf(portno_str, "%d", portno);
    err = getaddrinfo(hostname, portno_str, &hints, &addrs);
    if (err != 0) {
        result.error_num = err;
        result.error_source = ERR_SRC_GETADDRINFO;
        return result;
    }

    for (struct addrinfo* addr = addrs; addr != NULL; addr = addr->ai_next) {
        sd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sd == -1) {
            continue;
        }
#ifdef _WIN32
        u_long mode = 1; // 1 to enable non-blocking mode, 0 to disable
        ioctlsocket(sd, FIONBIO, &mode);
#else
        fcntl(sd, F_SETFL, O_NONBLOCK);
#endif
        int connect_timeout = 5 * 60 * 1000; // 5 minutes
        if (options != NULL) {
            if (options->connect_timeout > 0) {
                connect_timeout = options->connect_timeout;
            }
        }

        int conn_result = connect(sd, addr->ai_addr, addr->ai_addrlen);
        int connected = conn_result == 0;
#ifdef _WIN32
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
#else
        if (errno == EINPROGRESS) {
#endif
            struct pollfd pfd;
            pfd.fd = sd;
            pfd.events = POLLOUT;
#ifdef _WIN32
            switch (WSAPoll(&pfd, 1, connect_timeout)) {
#else
            switch (poll(&pfd, 1, connect_timeout)) {
#endif
                case -1: break; // error
                case 0:         // connection timeout
#ifdef _WIN32
                    errno = WSAETIMEDOUT;
#else
                    errno = ETIMEDOUT;
#endif
                    continue;
                default: // success
                    connected = 1;
                    break;
            }
        }
        if (connected) {
#ifdef _WIN32
            u_long mode = 0; // 0 to disable non-blocking mode
            ioctlsocket(sd, FIONBIO, &mode);
#else
            int flags = fcntl(sd, F_GETFL, 0);
            fcntl(sd, F_SETFL, flags & ~O_NONBLOCK);
#endif
            break;
        }

#ifdef _WIN32
        err = WSAGetLastError();
        closesocket(sd);
#else
        err = errno;
        close(sd);
#endif
        sd = -1;
    }

    freeaddrinfo(addrs);
    if (sd == -1) {
        result.error_num = err;
        result.error_source = ERR_SRC_ERRNO;
        return result;
    }
    result.context = malloc(sizeof(lss_connection_context));
    result.context->sd = sd;
    result.context->read_timeout = options->read_timeout;
    result.context->write_timeout = options->write_timeout;
    return result;
}

lss_connection_result
lss_close_connection(lss_connection_context* context) {
    lss_connection_result result = {NULL, 0, ERR_SRC_NONE};
    if (context == NULL || context->sd == -1) {
        return result;
    }
#ifdef _WIN32
    if (closesocket(context->sd) == 0) {
        free(context);
        return result;
    }
#else
    if (close(context->sd) == 0) {
        free(context);
        return result;
    }
#endif
    result.error_num = errno;
    result.error_source = ERR_SRC_ERRNO;

    return result;
}

// ListeningResult listen_on(const char *address, int portno)
// {
//     int sd, err;
//     struct addrinfo hints, *addrs;
//     char portno_str[16];

//     ListeningResult result = {-1, 0};

//     memset(&hints, 0, sizeof hints);
//     hints.ai_family = AF_UNSPEC;
//     hints.ai_socktype = SOCK_STREAM;
//     hints.ai_protocol = IPPROTO_TCP;
//     hints.ai_flags = AI_PASSIVE;

//     sprintf(portno_str, "%d", portno);
//     err = getaddrinfo(address, portno_str, &hints, &addrs);
//     if (err != 0)
//     {
//         // TODO: constant for address resolution error
//         result.error_num = err;
//         return result;
//     }

//     for (struct addrinfo *addr = addrs; addrs != NULL; addrs = addrs->ai_next)
//     {
//         sd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
//         if (sd == -1)
//             continue;

//         int yes = 1;
//         if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
//         {
//             close(sd);
//             sd = -1;
//             continue;
//         }
//         if (addr->ai_family == AF_INET6) {
//             int no = 0;
//             setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
//         }

//         if (bind(sd, addr->ai_addr, addr->ai_addrlen) == -1)
//         {
//             close(sd);
//             sd = -1;
//             continue;
//         }

//         if (listen(sd, SOMAXCONN) == -1)
//         {
//             close(sd);
//             sd = -1;
//             continue;
//         }

//         break;
//     }

//     freeaddrinfo(addrs);
//     if (sd == -1)
//     {
//         result.error_num = -1;
//         return result;
//     }

//     result.socket = sd;
//     return result;
// }

// typedef struct IncomingConnectionResult {
//     int socket;
//     int error_num;
//     struct sockaddr_storage client_addr;
//     socklen_t addr_len;
// } IncomingConnectionResult;

// IncomingConnectionResult accept_connection(int sd) {
//     if (sd == -1) {
//         return (IncomingConnectionResult) { -1, 0 };
//     }

//     struct sockaddr_storage client_addr;
//     socklen_t addr_len = sizeof(client_addr);
//     int new_sd = accept(sd, (struct sockaddr *)&client_addr, &addr_len);
//     if (new_sd == -1) {
//         return (IncomingConnectionResult) { -1, errno };
//     }

//     return (IncomingConnectionResult) { new_sd, 0, client_addr, addr_len };
// }
