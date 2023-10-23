
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <stdlib.h>
#include "lss.h"
#include "lss_options.h"
#include "lss_transport.h"
#include "lutil.h"

static int loaded = 0;

#ifdef _WIN32
#include <winsock2.h>

static WSADATA wsadata;
#endif

int
lss_connect(lua_State* L) {
    const char* host = luaL_checkstring(L, 1);
    int port = luaL_checkinteger(L, 2);

    int connectionType = LSS_PLAINTEXT;

    if (lua_type(L, 3) == LUA_TSTRING) {
        // string opt to LSS_PLAINTEXT/LSS_TLS from "plaintext"/"tls" use luaL_checkoption
        connectionType = luaL_checkoption(L, 3, "plaintext", (const char*[]){"plaintext", "tls", NULL});
    }

    lss_connection* context = lua_newuserdatauv(L, sizeof(lss_connection), 0);

    switch (connectionType) {
        case LSS_PLAINTEXT: {
            lss_open_connection_options* options =
                lua_type(L, -1) == LUA_TTABLE ? lss_load_plaintext_connection_options(L) : NULL;
            lss_connection_result connectionResult = lss_open_connection(host, port, options);
            lss_free_plain_connection_options(options);
            if (connectionResult.error_num != 0) {
                return push_error(L, "failed to open plaintext connection");
            }
            context->context.plaintext = connectionResult.context;
            context->kind = LSS_PLAINTEXT_CONTEXT_KIND;
            break;
        }
        case LSS_TLS: {
            lss_open_tls_connection_options* options =
                lua_type(L, -1) == LUA_TTABLE ? lss_load_tls_connection_options(L) : NULL;
            lss_tls_connection_result connectionResult = lss_open_tls_connection(host, port, options);
            lss_free_tls_connection_options(options);
            if (connectionResult.error_num != 0) {
                return push_error(L, "failed to open tls connection");
            }
            context->context.tls = connectionResult.context;
            context->kind = LSS_TLS_CONTEXT_KIND;
            break;
        }
    }

    luaL_getmetatable(L, LSS_CONNECTION_METATABLE);
    lua_setmetatable(L, -2);

    return 1;
}

int
lss_write(lua_State* L) {
    lss_connection* context = luaL_checkudata(L, 1, LSS_CONNECTION_METATABLE);
    size_t len;
    const char* data = luaL_checklstring(L, 2, &len);
    size_t bytesRemaining = len;
    while (bytesRemaining > 0) {
        int32_t bytesSent = lss_send(context, data, bytesRemaining);
        if (bytesSent < 0) {
            return push_error(L, "failed to send data");
        }
        bytesRemaining -= bytesSent;
        data = data + bytesSent;
    }
    return 0;
}

int
lss_read(lua_State* L) {
    lss_connection* context = luaL_checkudata(L, 1, LSS_CONNECTION_METATABLE);
    size_t len = luaL_optinteger(L, 2, DEFAULT_LSS_BUFFER_SIZE);
    if (len > MAXIMUM_LSS_BUFFER_SIZE) {
        len = MAXIMUM_LSS_BUFFER_SIZE;
    } else if (len < MINIMUM_LSS_BUFFER_SIZE) {
        len = MINIMUM_LSS_BUFFER_SIZE;
    }
    char* buffer = malloc(len);
    int32_t bytesReceived = lss_recv(context, buffer, len);
    if (bytesReceived < 0) {
        free(buffer);
        return push_error(L, "failed to receive data");
    }
    lua_pushlstring(L, buffer, bytesReceived);
    free(buffer);
    return 1;
}

int
lss_gc(lua_State* L) {
    lss_connection* context = luaL_checkudata(L, 1, LSS_CONNECTION_METATABLE);
    lss_close(context);
    return 0;
}

int
lss_create_connection_meta(lua_State* L) {
    luaL_newmetatable(L, LSS_CONNECTION_METATABLE);
    /* Metamethods */
    lua_newtable(L);
    lua_pushcfunction(L, lss_write);
    lua_setfield(L, -2, "write");
    lua_pushcfunction(L, lss_read);
    lua_setfield(L, -2, "read");
    lua_pushcfunction(L, lss_gc);
    lua_setfield(L, -2, "__gc");
    lua_pushstring(L, LSS_CONNECTION_METATABLE);
    lua_setfield(L, -2, "__type");
    /* Metamethods */
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, lss_gc);
    lua_setfield(L, -2, "__close");

    return 0;
}

int
lss_unload(lua_State* L) {
    if (loaded == 0) {
        return 0;
    }
    loaded = 0;
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

int
lua_init_simple_socket(lua_State* L) {
    if (loaded != 0) {
        return 0;
    }
    loaded = 1;
#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
        return push_error(L, "failed to initialize winsock");
    }
#endif
    // register lss_unload in global ____UNLOAD_MODULE table
    lua_getglobal(L, "____UNLOAD_MODULE");
    if (lua_type(L, -1) != LUA_TTABLE) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_setglobal(L, "____UNLOAD_MODULE");
        lua_getglobal(L, "____UNLOAD_MODULE");
    }
    lua_pushcfunction(L, lss_unload);
    lua_setfield(L, -2, "simple-socket");
    lua_pop(L, 1);
    return 0;
}

static const struct luaL_Reg lua_simple_socket[] = {
    /*
    ---#DES 'is_tty.is_stdin_tty'
    ---
    ---Returns true if stdin is tty
    ---@return boolean
    */
    {"connect", lss_connect},
    {NULL, NULL}};

int
luaopen_lua_simple_socket(lua_State* L) {
    int results = lua_init_simple_socket(L);
    if (results != 0) {
        return results;
    }

    lss_create_connection_meta(L);

    lua_newtable(L);
    luaL_setfuncs(L, lua_simple_socket, 0);

    return 1;
}
