#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <lauxlib.h>
#include "lss.h"
#include "lss_transport.h"
#include "../src/lss.c"

static void bounded(uint64_t start) {
    uint64_t elapsed = lss_monotonic_ms() - start;
    assert(elapsed >= 80 && elapsed < 1000);
}

#ifndef _WIN32
static void closes_on_exec(void) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(listener, (struct sockaddr*)&address, sizeof(address)) == 0);
    assert(listen(listener, 1) == 0);
    socklen_t address_len = sizeof(address);
    assert(getsockname(listener, (struct sockaddr*)&address, &address_len) == 0);

    lss_connection_result result = lss_open_connection("127.0.0.1", ntohs(address.sin_port), NULL);
    assert(result.error_num == 0);
    assert(fcntl(result.context->sd, F_GETFD) & FD_CLOEXEC);
    lss_close_connection(result.context);
    close(listener);
}
#endif

int main(void) {
    alarm(10);
#ifndef _WIN32
    closes_on_exec();
#endif
    int pair[2], size = 4096;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
    lss_connection_context plain = {.sd=pair[0], .write_timeout=100};
    lss_connection conn = {.kind=LSS_PLAINTEXT_CONTEXT_KIND, .context.plaintext=&plain};
    size_t length = 4 * 1024 * 1024;
    char* data = calloc(1, length);
    assert(data);
    /* Writable initially, but a blocking large send would never return. */
    uint64_t start = lss_monotonic_ms();
    int sent = lss_send(&conn, data, length);
    assert(sent > 0 && (size_t)sent < length);
    assert(lss_monotonic_ms() - start < 1000);
    /* MSG_DONTWAIT is not honoured for buffer-full sends on macOS, so the
     * socket itself must be non-blocking while the buffer is filled. */
    int blocking = fcntl(pair[0], F_GETFL);
    assert(blocking >= 0);
    assert(fcntl(pair[0], F_SETFL, blocking | O_NONBLOCK) == 0);
    while (send(pair[0], data, length, MSG_DONTWAIT) > 0) {}
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    assert(fcntl(pair[0], F_SETFL, blocking) == 0);
    start = lss_monotonic_ms();
    assert(lss_send(&conn, data, length) < 0);
    bounded(start);
    assert(!(fcntl(pair[0], F_GETFL) & O_NONBLOCK));

    lua_State* L = luaL_newstate();
    assert(L);
    /* Stack-owned transport: the test, rather than Lua GC, closes it. */
    luaL_newmetatable(L, LSS_CONNECTION_METATABLE);
    lua_pop(L, 1);
    for (int empty = 0; empty < 2; empty++) {
        lua_settop(L, 0);
        lua_pushcfunction(L, lss_write);
        lss_connection* ud = lua_newuserdatauv(L, sizeof(*ud), 0);
        *ud = conn;
        luaL_setmetatable(L, LSS_CONNECTION_METATABLE);
        lua_pushlstring(L, data, empty ? 0 : length);
        start = lss_monotonic_ms();
        assert(lua_pcall(L, 2, LUA_MULTRET, 0) == LUA_OK);
        if (empty) assert(lua_gettop(L) == 0);
        else { assert(lua_isnil(L, 1)); bounded(start); }
    }
    lua_close(L);

    /* Default writes wait for a draining peer, then ordinary reads still work. */
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(pair[0]);
        usleep(150000);
        char buffer[16384];
        while (recv(pair[1], buffer, sizeof(buffer), 0) > 0) {}
        assert(send(pair[1], "ok", 2, 0) == 2);
        close(pair[1]);
        _exit(0);
    }
    close(pair[1]);
    plain.write_timeout = 0;
    start = lss_monotonic_ms();
    assert(lss_send(&conn, "x", 1) == 1);
    assert(lss_monotonic_ms() - start >= 100);
    assert(shutdown(pair[0], SHUT_WR) == 0);
    plain.read_timeout = 1000;
    char buffer[2];
    assert(lss_recv(&conn, buffer, sizeof(buffer)) == 2);
    assert(memcmp(buffer, "ok", 2) == 0);
    assert(lss_recv(&conn, buffer, sizeof(buffer)) == LSS_TRANSPORT_EOF);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(pair[0]);
    free(data);
    return 0;
}
