#ifndef LSS_TRANSPORT_PLAINTEXT_H
#define LSS_TRANSPORT_PLAINTEXT_H

#include "socket.h"

int plaintext_recv(lss_connection_context* context, void* pBuffer, size_t bytesToRecv);

int plaintext_send(lss_connection_context* context, const void* pBuffer, size_t bytesToSend);

#endif /* LSS_TRANSPORT_PLAINTEXT_H */
