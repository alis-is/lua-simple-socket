#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <lauxlib.h>
#include "lss_options.h"

static int fail_at, allocations, live, opens;
static int expected_timeout = -1;
static void* tracked_malloc(size_t size) {
    void* p = malloc(size);
    if (p) live++;
    return p;
}
static void tracked_free(void* p) {
    if (p) live--;
    free(p);
}
static void* fault_malloc(size_t size) {
    if (++allocations == fail_at) return NULL;
    return tracked_malloc(size);
}
static void* fault_calloc(size_t count, size_t size) {
    void* p = fault_malloc(count * size);
    if (p) memset(p, 0, count * size);
    return p;
}
static char* fault_strdup(const char* s) {
    char* p = fault_malloc(strlen(s) + 1);
    if (p) strcpy(p, s);
    return p;
}
#define malloc fault_malloc
#define calloc fault_calloc
#define strdup fault_strdup
#define free tracked_free
#include "../src/lss_options.c"
#undef malloc
#undef calloc
#undef strdup
#undef free

static lss_tls_connection_result fake_open(const char* host, int port,
                                           lss_open_tls_connection_options* options) {
    (void)host; (void)port; (void)options;
    if (expected_timeout == -2) {
        lss_tls_connection_result result = lss_open_tls_connection(host, port, options);
        assert(result.error_num == EINVAL && result.context == NULL);
        return result;
    }
    if (expected_timeout >= 0) assert(options && options->connect_timeout == expected_timeout);
    opens++;
    return (lss_tls_connection_result){NULL, ENOMEM, ERR_SRC_ERRNO};
}
static lss_connection_result fake_plain_open(const char* host, int port,
                                             lss_open_connection_options* options) {
    (void)host; (void)port;
    if (expected_timeout == -2) {
        lss_connection_result result = lss_open_connection(host, port, options);
        assert(result.error_num == EINVAL && result.context == NULL);
        return result;
    }
    assert(options && options->connect_timeout == expected_timeout);
    opens++;
    return (lss_connection_result){NULL, ECONNREFUSED, ERR_SRC_ERRNO};
}
#define lss_open_connection fake_plain_open
#define lss_open_tls_connection fake_open
#include "../src/lss.c"
#define malloc tracked_malloc
#define free tracked_free
#include "../../lua-corehttp/src/lcorehttp_client.c"
#undef malloc
#undef free
#undef lss_open_tls_connection
#undef lss_open_connection

static void push_options(lua_State* L) {
    assert(luaL_dostring(L,
        "return {use_bundled_root_certificates=false, verify_peer=true,"
        "drgb_seed='seed', ca_certificates={'a\\0b','second'},"
        "client_certificate={certificate='cert',key='key',password='password'}}") == LUA_OK);
}

int main(void) {
    lua_State* L = luaL_newstate();
    assert(L);
    push_options(L);
    lss_open_tls_connection_options* options = lss_load_tls_connection_options(L);
    assert(options && !options->use_bundled_root_certificates && options->verify_peer);
    assert(options->ca_certificates->count == 2);
    assert(options->ca_certificates->sizes[0] == 3);
    assert(memcmp(options->ca_certificates->certificates[0], "a\0b", 3) == 0);
    int total = allocations;
    lss_free_tls_connection_options(options);
    assert(live == 0 && lua_gettop(L) == 1);
    for (fail_at = 1; fail_at <= total; fail_at++) {
        allocations = 0;
        assert(lss_load_tls_connection_options(L) == NULL);
        assert(errno == ENOMEM && live == 0 && lua_gettop(L) == 1);
    }
    lua_settop(L, 0);
    l_corehttp_client_create_meta(L);
    lua_settop(L, 0);
    for (int caller = 0; caller < 2; caller++) {
        for (fail_at = 0; fail_at <= total; fail_at++) {
            lua_settop(L, 0);
            if (caller == 0) {
                lua_pushcfunction(L, lss_connect);
                lua_pushliteral(L, "localhost");
                lua_pushinteger(L, 443);
                lua_pushliteral(L, "tls");
            } else {
                lua_pushcfunction(L, l_corehttp_client_request);
                lcorehttp_client* client = lua_newuserdatauv(L, sizeof(*client), 0);
                *client = (lcorehttp_client){.hostname="localhost", .hostname_len=9,
                    .portno=443, .kind=LSS_CONNECTION_KIND_TLS};
                /* No __gc: hostname is a string literal owned by the test. */
                luaL_getmetatable(L, LCOREHTTP_CLIENT_METATABLE);
                lua_pushnil(L);
                lua_setfield(L, -2, "__gc");
                lua_setmetatable(L, -2);
                lua_pushliteral(L, "/");
                lua_pushliteral(L, "GET");
            }
            if (fail_at) push_options(L);
            else lua_pushnil(L);
            allocations = 0;
            opens = 0;
            assert(lua_pcall(L, 4, 3, 0) == LUA_OK);
            assert(lua_isnil(L, -3));
            assert(opens == (fail_at == 0) && live == 0);
            assert(strstr(lua_tostring(L, -2), fail_at
                ? "failed to allocate tls options" : "failed to open tls connection"));
            if (fail_at) assert(lua_tointeger(L, -1) == ENOMEM);
        }
    }
    /* Plaintext option allocation failure must be reported, not ignored. */
    for (int caller = 0; caller < 2; caller++) {
        lua_settop(L, 0);
        if (caller == 0) {
            lua_pushcfunction(L, lss_connect);
            lua_pushliteral(L, "localhost");
            lua_pushinteger(L, 80);
            lua_pushliteral(L, "plaintext");
        } else {
            lua_pushcfunction(L, l_corehttp_client_request);
            lcorehttp_client* client = lua_newuserdatauv(L, sizeof(*client), 0);
            *client = (lcorehttp_client){.hostname="localhost", .hostname_len=9,
                .portno=80, .kind=LSS_CONNECTION_KIND_PLAINTEXT};
            /* No __gc: hostname is a string literal owned by the test. */
            luaL_getmetatable(L, LCOREHTTP_CLIENT_METATABLE);
            lua_pushnil(L);
            lua_setfield(L, -2, "__gc");
            lua_setmetatable(L, -2);
            lua_pushliteral(L, "/");
            lua_pushliteral(L, "GET");
        }
        push_options(L);
        allocations = 0;
        opens = 0;
        fail_at = 1;
        assert(lua_pcall(L, 4, 3, 0) == LUA_OK);
        assert(lua_isnil(L, -3));
        assert(opens == 0 && live == 0);
        assert(strstr(lua_tostring(L, -2), "failed to allocate plaintext options"));
        assert(lua_tointeger(L, -1) == ENOMEM);
    }
    /* Both public socket and HTTP request paths must propagate the same names. */
    fail_at = 0;
    const char* cases[] = {
        "{}", "{connect_timeout=0,timeout=17}", "{connect_timeout=23,timeout=17}",
        "{timeout=17}", "{connect_timeout=2147483647}",
        "{connect_timeout=-1}", "{connect_timeout=2147483648}",
        "{connect_timeout=1.5}", "{connect_timeout='23'}", "{connect_timeout=false}",
        "{timeout=-1}", "{timeout=2147483648}", "{write_timeout=-1}",
        "{write_timeout=2147483648}", "{read_timeout=-2}",
        "{read_timeout=-1,write_timeout=2147483647}"
    };
    int expected[] = {0, 0, 23, 17, INT_MAX, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0};
    for (int tls = 0; tls < 2; tls++) {
        for (int caller = 0; caller < 2; caller++) {
            for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
                lua_settop(L, 0);
                if (caller == 0) {
                    lua_pushcfunction(L, lss_connect);
                    lua_pushliteral(L, "localhost");
                    lua_pushinteger(L, 80);
                    lua_pushstring(L, tls ? "tls" : "plaintext");
                } else {
                    lua_pushcfunction(L, l_corehttp_client_request);
                    lcorehttp_client* client = lua_newuserdatauv(L, sizeof(*client), 0);
                    *client = (lcorehttp_client){.hostname="localhost", .hostname_len=9,
                        .portno=80, .kind=tls ? LSS_CONNECTION_KIND_TLS : LSS_CONNECTION_KIND_PLAINTEXT};
                    luaL_setmetatable(L, LCOREHTTP_CLIENT_METATABLE);
                    lua_pushliteral(L, "/");
                    lua_pushliteral(L, "GET");
                }
                lua_pushfstring(L, "return %s", cases[i]);
                assert(luaL_loadstring(L, lua_tostring(L, -1)) == LUA_OK);
                lua_remove(L, -2);
                assert(lua_pcall(L, 0, 1, 0) == LUA_OK);
                expected_timeout = expected[i] < 0 ? -2 : expected[i];
                opens = 0;
                int status = lua_pcall(L, 4, 3, 0);
                assert(status == LUA_OK && lua_isnil(L, -3));
                assert(opens == (expected_timeout >= 0) && live == 0);
            }
        }
    }
    lua_close(L);
    return 0;
}
