#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <lauxlib.h>
#include "socket_mbedtls.h"

static uint64_t now;
static int handshake_mode, polls, handshakes, ready, bios;
static int poll_result = 1, read_result, reads, want, real_io;
static int retry_io, writes, closes, partial_write;
static const unsigned char* write_buffer;
static size_t write_size;
static int fake_clock(clockid_t clock, struct timespec* ts) {
    if (real_io) return clock_gettime(clock, ts);
    assert(clock == CLOCK_MONOTONIC);
    ts->tv_sec = now / 1000;
    ts->tv_nsec = (now % 1000) * 1000000;
    return 0;
}
static int fake_poll(struct pollfd* fds, nfds_t n, int timeout) {
    if (real_io) return poll(fds, n, timeout);
    assert(n == 1);
    if (handshake_mode) {
        assert(timeout == 100 - polls * 30);
        assert(fds->events == (want == MBEDTLS_ERR_SSL_WANT_READ ? POLLIN : POLLOUT));
        polls++;
        now += 30;
        if (handshake_mode == 3) { errno = EIO; return -1; }
        if (handshake_mode == 2 || polls < 3) { errno = EINTR; return -1; }
        ready = 1;
    }
    fds->revents = poll_result > 0 ? fds->events : 0;
    return poll_result;
}
static int fake_handshake(mbedtls_ssl_context* ssl) {
    if (real_io) return mbedtls_ssl_handshake(ssl);
    (void)ssl;
    handshakes++;
    return ready ? 0 : want;
}
#ifdef MSG_NOSIGNAL
static int lss_net_send(void* ctx, const unsigned char* buf, size_t len);
#endif
static void fake_bio(mbedtls_ssl_context* ssl, void* ctx,
                     mbedtls_ssl_send_t* send, mbedtls_ssl_recv_t* recv,
                      mbedtls_ssl_recv_timeout_t* timeout) {
    if (real_io) { mbedtls_ssl_set_bio(ssl, ctx, send, recv, timeout); return; }
    (void)ssl; (void)ctx;
#ifdef MSG_NOSIGNAL
    assert(send == lss_net_send && recv == mbedtls_net_recv);
#else
    assert(send == mbedtls_net_send && recv == mbedtls_net_recv);
#endif
    bios++;
    assert(timeout == NULL);
}
static int fake_read(mbedtls_ssl_context* ssl, unsigned char* buf, size_t len) {
    if (real_io) return mbedtls_ssl_read(ssl, buf, len);
    (void)ssl; (void)buf;
    assert(len > 0);
    reads++;
    if (retry_io) return ready ? 1 : want;
    if (read_result == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) now += 30;
    return read_result;
}
static int fake_write(mbedtls_ssl_context* ssl, const unsigned char* buf, size_t len) {
    if (real_io) return mbedtls_ssl_write(ssl, buf, len);
    if (partial_write) {
        writes++;
        now += 30;
        return partial_write == 1 ? 0 : 1;
    }
    assert(buf == write_buffer && len == write_size);
    writes++;
    return ready ? (int)len : want;
}
static int fake_close(mbedtls_ssl_context* ssl) {
    if (real_io) return mbedtls_ssl_close_notify(ssl);
    closes++;
    return ready ? 0 : want;
}
#define clock_gettime fake_clock
#define poll fake_poll
#define mbedtls_ssl_handshake fake_handshake
#define mbedtls_ssl_set_bio fake_bio
#define mbedtls_ssl_close_notify fake_close
#include "../src/socket_mbedtls.c"
#undef clock_gettime
#undef mbedtls_ssl_handshake
#undef mbedtls_ssl_set_bio
#undef mbedtls_ssl_close_notify
#define mbedtls_ssl_read fake_read
#define mbedtls_ssl_write fake_write
#include "../src/transport_mbedtls.c"
#undef poll
#undef mbedtls_ssl_read
#undef mbedtls_ssl_write
#include "../../lua-corehttp/src/lcorehttp_response.c"
#include "../src/lss.c"

int main(int argc, char** argv) {
    alarm(10);
    if (argc == 2) {
        real_io = 1;
        alarm(5);
        lss_open_tls_connection_options options = {.connect_timeout=1000, .read_timeout=100};
        lss_tls_connection_result result = lss_open_tls_connection("127.0.0.1", atoi(argv[1]), &options);
        assert(result.error_num == 0);
        lss_connection connection = {.kind=LSS_TLS_CONTEXT_KIND, .context.tls=result.context};
        char buffer[8];
        uint64_t start = lss_monotonic_ms();
        assert(lss_recv(&connection, buffer, sizeof(buffer)) == 0);
        uint64_t elapsed = lss_monotonic_ms() - start;
        assert(elapsed >= 80 && elapsed < 1000);
        /* A timed-out partial record must remain resumable. */
        result.context->read_timeout = 1000;
        assert(lss_recv(&connection, buffer, 1) == 1 && buffer[0] == 'h');
        assert(lss_recv(&connection, buffer, sizeof(buffer)) == 4);
        assert(memcmp(buffer, "ello", 4) == 0);
        lss_close_context(&connection);
        return 0;
    }
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    lss_tls_connection_context tls = {0};
    tls.socket.fd = sockets[0];
    for (int direction = 0; direction < 2; direction++) {
        want = direction ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_SSL_WANT_READ;
        for (handshake_mode = 1; handshake_mode <= 3; handshake_mode++) {
            now = polls = handshakes = ready = bios = 0;
            int result = lss_tls_handshake(&tls, 100);
            assert(result == (handshake_mode == 1 ? 0 : handshake_mode == 2
                ? MBEDTLS_ERR_SSL_TIMEOUT : direction ? MBEDTLS_ERR_NET_SEND_FAILED
                : MBEDTLS_ERR_NET_RECV_FAILED));
            assert(polls == (handshake_mode == 1 ? 3 : handshake_mode == 2 ? 4 : 1));
            assert(handshakes == (handshake_mode == 1 ? 2 : 1));
            assert(bios == 1);
            assert((fcntl(sockets[0], F_GETFL) & O_NONBLOCK) != 0);
        }
    }
    handshake_mode = 0;
    char buffer[8];
    read_result = MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
    assert(mbedtls_recv(&tls, buffer, sizeof(buffer)) == LSS_TRANSPORT_EOF);
    /* close_notify authenticates EOF for the rest of the connection: a later
     * zero read must stay a clean EOF, not a truncation error. */
    read_result = 0;
    assert(mbedtls_recv(&tls, buffer, sizeof(buffer)) == LSS_TRANSPORT_EOF);
    tls.clean_eof = 0; /* model a new connection for the following cases */
    read_result = MBEDTLS_ERR_SSL_INVALID_MAC;
    assert(mbedtls_recv(&tls, buffer, sizeof(buffer)) == read_result);
    reads = 0;
    assert(mbedtls_recv(&tls, buffer, 0) == 0 && reads == 0);
    poll_result = 0;
    tls.read_timeout = 100;
    read_result = MBEDTLS_ERR_SSL_WANT_READ;
    assert(mbedtls_recv(&tls, buffer, sizeof(buffer)) == 0 && reads == 1);
    poll_result = 1;

    /* Mid-record WANT_READ/WANT_WRITE and EINTR must share one deadline. */
    for (int direction = 0; direction < 2; direction++) {
        want = direction ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_SSL_WANT_READ;
        for (handshake_mode = 1; handshake_mode <= 3; handshake_mode++) {
            int error = handshake_mode == 2 ? MBEDTLS_ERR_SSL_TIMEOUT
                : direction ? MBEDTLS_ERR_NET_SEND_FAILED : MBEDTLS_ERR_NET_RECV_FAILED;
            now = polls = ready = reads = 0;
            retry_io = 1;
            assert(mbedtls_recv(&tls, buffer, sizeof(buffer)) ==
                   (handshake_mode == 1 ? 1 : handshake_mode == 2 ? 0 : error));
            assert(reads == (handshake_mode == 1 ? 2 : 1));
            retry_io = 0;
            now = polls = ready = writes = 0;
            tls.write_timeout = 100;
            tls.socket.fd = dup(sockets[0]);
            assert(tls.socket.fd >= 0);
            write_buffer = (unsigned char*)buffer;
            write_size = sizeof(buffer);
            assert(mbedtls_send(&tls, buffer, sizeof(buffer)) ==
                   (handshake_mode == 1 ? (int)sizeof(buffer) : error));
            assert(writes == (handshake_mode == 1 ? 2 : 1));
            if (handshake_mode == 1) close(tls.socket.fd);
            else assert(tls.socket.fd == -1); // pending write cannot be reused
            tls.socket.fd = sockets[0];
            now = polls = ready = closes = 0;
            lss_tls_connection_context* closing = calloc(1, sizeof(*closing));
            assert(closing);
            closing->socket.fd = dup(sockets[0]);
            int fd = closing->socket.fd;
            closing->write_timeout = 100;
            assert(lss_close_tls_connection(closing).error_num == (handshake_mode == 1 ? 0 : error));
            assert(closes == (handshake_mode == 1 ? 2 : 1));
            assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
        }
    }
    handshake_mode = 0;
    now = reads = 0;
    read_result = MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET;
    assert(mbedtls_recv(&tls, buffer, sizeof(buffer)) == 0 && reads == 4);
    tls.read_timeout = 0;
    read_result = MBEDTLS_ERR_SSL_WANT_READ;
    reads = 0;
    assert(mbedtls_recv(&tls, buffer, 1) == 0 && reads == 1);
    /* A finalizer with default options must not wait on backpressure. */
    lss_tls_connection_context* closing = calloc(1, sizeof(*closing));
    assert(closing);
    closing->socket.fd = dup(sockets[0]);
    ready = closes = 0;
    assert(lss_close_tls_connection(closing).error_num == MBEDTLS_ERR_SSL_TIMEOUT);
    assert(closes == 1);

    /* Exercise the public Lua readers through the real lss TLS dispatch. The
     * cached prefix models data received before an unauthenticated TCP EOF. */
    lua_State* L = luaL_newstate();
    assert(L);
    luaL_newmetatable(L, LCOREHTTP_RESPONSE_METATABLE);
    lua_pop(L, 1);
    lss_connection connection = {.kind=LSS_TLS_CONTEXT_KIND, .context.tls=&tls};
    TransportInterface_t transport = {.recv=lss_recv, .pNetworkContext=&connection};
    for (int clean = 0; clean < 2; clean++) {
        for (int content = 0; content < 2; content++) {
            lua_settop(L, 0);
            lua_pushcfunction(L, content ? l_corehttp_response_read_content : l_corehttp_response_read);
            lcorehttp_response* response = lua_newuserdatauv(L, sizeof(*response), 1);
            memset(response, 0, sizeof(*response));
            response->transport = &transport;
            response->contentLength = (size_t)-1;
            if (content) {
                response->response.pBody = (const uint8_t*)"body";
                response->response.bodyLen = 4;
            }
            luaL_setmetatable(L, LCOREHTTP_RESPONSE_METATABLE);
            read_result = clean ? MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY : 0;
            assert(lua_pcall(L, 1, 3, 0) == LUA_OK);
            if (clean) {
                assert(lua_type(L, 1) == LUA_TSTRING);
                assert(strcmp(lua_tostring(L, 1), content ? "body" : "") == 0);
            } else {
                assert(lua_isnil(L, 1));
                assert(strstr(lua_tostring(L, 2), "failed to read response body"));
            }
        }
    }
    lss_create_connection_meta(L);
    /* Actual collection must close the descriptor, not merely expose a method. */
    lua_settop(L, 0);
    lss_connection* collected = lua_newuserdatauv(L, sizeof(*collected), 0);
    collected->kind = LSS_PLAINTEXT_CONTEXT_KIND;
    collected->context.plaintext = calloc(1, sizeof(lss_connection_context));
    assert(collected->context.plaintext);
    int collected_fd = dup(sockets[0]);
    assert(collected_fd >= 0);
    collected->context.plaintext->sd = collected_fd;
    luaL_setmetatable(L, LSS_CONNECTION_METATABLE);
    lua_settop(L, 0);
    lua_gc(L, LUA_GCCOLLECT);
    assert(fcntl(collected_fd, F_GETFD) == -1 && errno == EBADF);
    /* __close followed by __gc must also leave Lua-owned memory intact. */
    collected = lua_newuserdatauv(L, sizeof(*collected), 0);
    collected->kind = LSS_PLAINTEXT_CONTEXT_KIND;
    collected->context.plaintext = calloc(1, sizeof(lss_connection_context));
    assert(collected->context.plaintext);
    collected_fd = dup(sockets[0]);
    assert(collected_fd >= 0);
    collected->context.plaintext->sd = collected_fd;
    luaL_setmetatable(L, LSS_CONNECTION_METATABLE);
    lua_getmetatable(L, 1);
    lua_getfield(L, -1, "__close");
    lua_pushvalue(L, 1);
    assert(lua_pcall(L, 1, 0, 0) == LUA_OK);
    assert(collected->kind == 0);
    assert(fcntl(collected_fd, F_GETFD) == -1 && errno == EBADF);
    lua_settop(L, 0);
    lua_gc(L, LUA_GCCOLLECT);
    tls.clean_eof = 0; /* model a new connection for the unauthenticated EOF case */
    for (int clean = 0; clean < 2; clean++) {
        lua_settop(L, 0);
        lss_connection* socket = lua_newuserdatauv(L, sizeof(*socket), 0);
        *socket = connection;
        luaL_setmetatable(L, LSS_CONNECTION_METATABLE);
        lua_getfield(L, 1, "read");
        lua_pushvalue(L, 1);
        read_result = clean ? MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY : 0;
        assert(lua_pcall(L, 1, 3, 0) == LUA_OK);
        socket->kind = 0; // test borrows the stack-owned TLS context
        if (clean) {
            assert(lua_type(L, 2) == LUA_TSTRING && lua_rawlen(L, 2) == 0);
            assert(lua_isnil(L, 3) && lua_isnil(L, 4));
        } else {
            assert(lua_isnil(L, 2));
            assert(strstr(lua_tostring(L, 3), "failed to receive data"));
        }
    }
    /* A whole Lua write shares its deadline across partial transport sends. */
    for (partial_write = 1; partial_write <= 2; partial_write++) {
        lua_settop(L, 0);
        lss_connection* socket = lua_newuserdatauv(L, sizeof(*socket), 0);
        *socket = connection;
        luaL_setmetatable(L, LSS_CONNECTION_METATABLE);
        lua_getfield(L, 1, "write");
        lua_pushvalue(L, 1);
        lua_pushliteral(L, "partial writes must not restart the timeout");
        now = writes = 0;
        tls.write_timeout = 100;
        assert(lua_pcall(L, 2, 3, 0) == LUA_OK);
        socket->kind = 0;
        assert(lua_isnil(L, 2));
        assert(strstr(lua_tostring(L, 3), "failed to send data"));
        assert(writes == (partial_write == 1 ? 1 : 4));
    }
    lua_close(L);
    close(sockets[0]);
    close(sockets[1]);
    return 0;
}
