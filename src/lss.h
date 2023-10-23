#ifdef _WIN32
#define LUA_SIMPLE_SOCKET_EXPORT __declspec(dllexport)
#else
#define LUA_SIMPLE_SOCKET_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include <lua.h>
#include "lss_transport.h"

#define LSS_CONNECTION_METATABLE "LSS_CONNECTION"

LUA_SIMPLE_SOCKET_EXPORT int luaopen_lua_simple_socket(lua_State* L);

int lua_init_simple_socket(lua_State* L);

#ifdef __cplusplus
}
#endif