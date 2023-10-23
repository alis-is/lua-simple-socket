#ifndef LSS_TRANSPORT_H
#define LSS_TRANSPORT_H

#include <lua.h>
#include "transport_mbedtls.h"
#include "transport_plaintext.h"

#define LSS_TLS_CONTEXT_KIND       1
#define LSS_PLAINTEXT_CONTEXT_KIND 2

#define DEFAULT_LSS_BUFFER_SIZE    16384   /* 16KB */
#define MINIMUM_LSS_BUFFER_SIZE    1024    /* 1KB */
#define MAXIMUM_LSS_BUFFER_SIZE    1048576 /* 1MB */

typedef enum lss_connection_kind { LSS_CONNECTION_KIND_PLAINTEXT, LSS_CONNECTION_KIND_TLS } lss_connection_kind;

typedef union TransportContext {
    lss_connection_context* plaintext;
    lss_tls_connection_context* tls;
} TransportContext;

typedef struct NetworkContext {
    int kind;
    TransportContext context;
} lss_connection;

int32_t lss_recv(lss_connection* conn, void* pBuffer, size_t bytesToRecv);
int32_t lss_send(lss_connection* conn, const void* pBuffer, size_t bytesToSend);
int lss_close(lss_connection* conn);

#endif /* LSS_TRANSPORT_H */