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

/* Distinct EOF result: transports return >= 0 for data/retryable inactivity
 * and negative for errors, so callers could not tell a clean shutdown from a
 * failure. */
#define LSS_TRANSPORT_EOF (-2)

int32_t lss_recv(lss_connection* conn, void* pBuffer, size_t bytesToRecv);
int32_t lss_send(lss_connection* conn, const void* pBuffer, size_t bytesToSend);
int32_t lss_send_until(lss_connection* conn, const void* pBuffer, size_t bytesToSend, uint64_t deadline);
/* Closes the transport and invalidates the wrapper; does not free it. */
void lss_close_context(lss_connection* conn);
/* Closes and frees a malloc-owned wrapper. Never pass Lua userdata. */
int lss_close(lss_connection* conn);

#endif /* LSS_TRANSPORT_H */
