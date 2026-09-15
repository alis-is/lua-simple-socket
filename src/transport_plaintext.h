#ifndef LSS_TRANSPORT_PLAINTEXT_H
#define LSS_TRANSPORT_PLAINTEXT_H

#include "socket.h"
#include <stdint.h>

int plaintext_recv(lss_connection_context* context, void* pBuffer, size_t bytesToRecv);

int plaintext_send(lss_connection_context* context, const void* pBuffer, size_t bytesToSend);
int plaintext_send_until(lss_connection_context* context, const void* pBuffer, size_t bytesToSend, uint64_t deadline);

#endif /* LSS_TRANSPORT_PLAINTEXT_H */
