#ifndef LSS_TRANSPORT_MBEDTLS_H
#define LSS_TRANSPORT_MBEDTLS_H

#include "socket_mbedtls.h"

int mbedtls_recv(lss_tls_connection_context* connection, void* pBuffer, size_t bytesToRecv);

int mbedtls_send(lss_tls_connection_context* connection, const void* pBuffer, size_t bytesToSend);
int mbedtls_send_until(lss_tls_connection_context* connection, const void* pBuffer, size_t bytesToSend, uint64_t deadline);

#endif /* LSS_TRANSPORT_MBEDTLS_H */
