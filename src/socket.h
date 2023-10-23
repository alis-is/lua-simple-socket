#ifndef SOCKET_H
#define SOCKET_H

// FILEPATH: /home/v/projects/eli/deps/lua-simple-socket/src/socket.h
#include "errors.h"
#include "time.h"
#ifdef _WIN32
#include <winsock2.h>
#endif

typedef struct lss_open_connection_options {
    int connect_timeout;
    int read_timeout;
    int write_timeout;
} lss_open_connection_options;

typedef struct lss_connection_context {
#ifdef _WIN32
    SOCKET sd;
#else
    int sd;
#endif

    int read_timeout;
    int write_timeout;
} lss_connection_context;

typedef struct lss_connection_result {
    lss_connection_context* context;
    int error_num;
    ErrorSource error_source;
} lss_connection_result;

// typedef struct
// {
//     int socket;
//     int error_num;
//     ErrorSource error_source;
// } ListeningResult;

lss_connection_result lss_open_connection(const char* hostname, int portno, lss_open_connection_options* options);
lss_connection_result lss_close_connection(lss_connection_context* context);

#endif // SOCKET_H
