#ifndef LSS_SOCKET_OPTIONS_H
#define LSS_SOCKET_OPTIONS_H

#include <lua.h>
#include "transport_mbedtls.h"
#include "transport_plaintext.h"

#define LSS_PLAINTEXT 0
#define LSS_TLS       1

lss_open_connection_options* lss_load_plaintext_connection_options(lua_State* L);
void lss_free_plain_connection_options(lss_open_connection_options* options);
lss_open_tls_connection_options* lss_load_tls_connection_options(lua_State* L);
void lss_free_tls_connection_options(lss_open_tls_connection_options* options);

#endif /* LSS_SOCKET_OPTIONS_H */