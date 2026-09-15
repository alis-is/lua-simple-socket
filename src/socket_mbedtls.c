#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "socket.h"
#include "socket_mbedtls.h"
#include "lss_runtime.h"
#if defined(LSS_HAS_BUNDLED_ROOT_CERTIFICATES)
#include "certs.h"
#endif
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#if defined(MBEDTLS_DEBUG_C)
#include "mbedtls/debug.h"
#endif
#include "psa/crypto.h"

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#endif

void
free_connection(lss_tls_connection_context* context) {
    mbedtls_net_free(&context->socket);
    mbedtls_x509_crt_free(&context->cacert);
    mbedtls_x509_crt_free(&context->clicert);
    mbedtls_ssl_free(&context->ssl);
    mbedtls_ssl_config_free(&context->conf);
    mbedtls_ctr_drbg_free(&context->ctr_drbg);
    mbedtls_entropy_free(&context->entropy);
    mbedtls_pk_free(&context->pkey);
    free(context);
}

void
mbedtlsDebugPrint(void* ctx, int level, const char* pFile, int line, const char* pStr) {
    printf("mbedtlsDebugPrint: |%d| %s\n", level, pStr);
}

#ifdef _WIN32
typedef WSAPOLLFD lss_pollfd;
#else
typedef struct pollfd lss_pollfd;
#endif

uint64_t
lss_monotonic_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)(ts.tv_nsec / 1000000);
#endif
}

int
lss_tls_wait(lss_tls_connection_context* context, int want, uint64_t deadline) {
    for (;;) {
        lss_pollfd pfd;
        int poll_timeout = -1;
        if (deadline != UINT64_MAX) {
            uint64_t now = lss_monotonic_ms();
            if (now >= deadline) return MBEDTLS_ERR_SSL_TIMEOUT;
            uint64_t remaining = deadline - now;
            poll_timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
        }
        pfd.fd = context->socket.fd;
        pfd.events = want == MBEDTLS_ERR_SSL_WANT_READ ? POLLIN : POLLOUT;
        pfd.revents = 0;
#ifdef _WIN32
        if (WSAPoll(&pfd, 1, poll_timeout) < 0) {
            if (WSAGetLastError() == WSAEINTR) continue;
#else
        if (poll(&pfd, 1, poll_timeout) < 0) {
            if (errno == EINTR) continue;
#endif
            return want == MBEDTLS_ERR_SSL_WANT_READ ? MBEDTLS_ERR_NET_RECV_FAILED
                                                    : MBEDTLS_ERR_NET_SEND_FAILED;
        }
        if (pfd.revents & POLLNVAL) return MBEDTLS_ERR_NET_INVALID_CONTEXT;
        return pfd.revents == 0 ? MBEDTLS_ERR_SSL_TIMEOUT : 0;
    }
}

#ifdef MSG_NOSIGNAL
static int
lss_net_send(void* ctx, const unsigned char* buf, size_t len) {
    int fd = ((mbedtls_net_context*)ctx)->fd;
    int ret = (int)send(fd, buf, len, MSG_NOSIGNAL);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return MBEDTLS_ERR_SSL_WANT_WRITE;
        if (errno == EPIPE || errno == ECONNRESET) return MBEDTLS_ERR_NET_CONN_RESET;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return ret;
}
#endif

static int
lss_tls_handshake(lss_tls_connection_context* context, int timeout_ms) {
    uint64_t deadline = lss_monotonic_ms() + (uint64_t)timeout_ms;
    int err = mbedtls_net_set_nonblock(&context->socket);
    if (err != 0) return err;
    /* Keep the BIO nonblocking for the entire connection: readiness does not
     * guarantee that a complete TLS record is available. */
    mbedtls_ssl_set_bio(&context->ssl, &context->socket,
#ifdef MSG_NOSIGNAL
                        lss_net_send,
#else
                        mbedtls_net_send,
#endif
                        mbedtls_net_recv, NULL);
    for (;;) {
        err = mbedtls_ssl_handshake(&context->ssl);
        if (err != MBEDTLS_ERR_SSL_WANT_READ && err != MBEDTLS_ERR_SSL_WANT_WRITE) break;
        err = lss_tls_wait(context, err, deadline);
        if (err != 0) break;
    }
    return err;
}

void
lssDebugPrint(lss_open_tls_connection_options* options, const char* format, ...) {
    if (options == NULL || options->debugLevel <= 1) {
        return;
    }

    va_list args;
    va_start(args, format); // Initialize the va_list variable with the last fixed parameter

    // Print the formatted string
    printf("lssDebugPrint: ");
    vprintf(format, args);
    printf("\n");

    va_end(args); // Clean up the va_list variable
}

lss_tls_connection_result
lss_open_tls_connection(const char* hostname, int portno, lss_open_tls_connection_options* options) {
    lss_open_tls_connection_options defaultOptions = {0, 0, 0, 1, NULL, 0, 1, NULL, NULL};
    int err;
    char portno_str[16];

    lss_tls_connection_result result = {NULL, 0, ERR_SRC_NONE};

    if (options != NULL && (options->connect_timeout < 0 || options->read_timeout < -1 || options->write_timeout < 0)) {
        errno = EINVAL;
        result.error_num = EINVAL;
        result.error_source = ERR_SRC_ERRNO;
        return result;
    }

    if (eli_tls_initialize() != 0) {
        /* threading mutexes or PSA failed to initialize */
        result.error_num = errno != 0 ? errno : EIO;
        result.error_source = ERR_SRC_ERRNO;
        return result;
    }

    if (options == NULL) {
        options = &defaultOptions;
    }

    result.context = malloc(sizeof(lss_tls_connection_context));
    if (result.context == NULL) {
        result.error_num = errno;
        result.error_source = ERR_SRC_ERRNO;
        goto exit;
    }

    mbedtls_net_init(&result.context->socket);
    mbedtls_ssl_init(&result.context->ssl);
    mbedtls_ssl_config_init(&result.context->conf);
    mbedtls_x509_crt_init(&result.context->cacert);
    mbedtls_x509_crt_init(&result.context->clicert);
    mbedtls_ctr_drbg_init(&result.context->ctr_drbg);
    mbedtls_entropy_init(&result.context->entropy);
    mbedtls_pk_init(&result.context->pkey);
    result.context->read_timeout = options->read_timeout;
    result.context->write_timeout = options->write_timeout;
    result.context->clean_eof = 0;

    char* seedString = "lsstls";
    if (options->drgb_seed != NULL) {
        seedString = options->drgb_seed;
    }
    if ((err = mbedtls_ctr_drbg_seed(&result.context->ctr_drbg, mbedtls_entropy_func, &result.context->entropy,
                                     (const unsigned char*)seedString, strlen(seedString)))
        != 0) {
        lssDebugPrint(options, "mbedtls_ctr_drbg_seed failed with %d\n", err);
        result.error_num = err;
        result.error_source = ERR_SRC_MBEDTLS;
        goto exit;
    }
    snprintf(portno_str, sizeof(portno_str), "%d", portno);

    if ((err = mbedtls_ssl_config_defaults(&result.context->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT))
        != 0) {
        lssDebugPrint(options, "mbedtls_ssl_config_defaults failed with %d\n", err);
        result.error_num = err;
        result.error_source = ERR_SRC_MBEDTLS;
        goto exit;
    }

    if (options->verify_peer) {
        mbedtls_ssl_conf_authmode(&result.context->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    } else {
        mbedtls_ssl_conf_authmode(&result.context->conf, MBEDTLS_SSL_VERIFY_NONE);
    }

    mbedtls_ssl_conf_rng(&result.context->conf, mbedtls_ctr_drbg_random, &(result.context->ctr_drbg));
    //mbedtls_ssl_conf_read_timeout(&result.context->conf, options->read_timeout); // handled on transport level through poll
    mbedtls_ssl_conf_dbg(&result.context->conf, mbedtlsDebugPrint, NULL);
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(options->debugLevel);
#endif

#if defined(LSS_HAS_BUNDLED_ROOT_CERTIFICATES)
    if (options->use_bundled_root_certificates) {
        long unsigned int shift = 0;
        for (int i = 0; i < lss_cacertsCount; i++) {
            err = mbedtls_x509_crt_parse_der_nocopy(&result.context->cacert, lss_cacerts + shift, lss_cacertSizes[i]);
            if (err != 0) {
                lssDebugPrint(options, "mbedtls_x509_crt_parse_file Failed. mbedtlsError = %d\n", err);
                result.error_num = err;
                result.error_source = ERR_SRC_MBEDTLS;
                goto exit;
            }
            shift += lss_cacertSizes[i];
        }
    }
#endif
    if (options->ca_certificates != NULL) {
        for (int i = 0; i < options->ca_certificates->count; i++) {
            err = mbedtls_x509_crt_parse_der(&result.context->cacert, options->ca_certificates->certificates[i],
                                             options->ca_certificates->sizes[i]);
            if (err != 0) {
                lssDebugPrint(options, "mbedtls_x509_crt_parse_file Failed. mbedtlsError = %d\n", err);
                result.error_num = err;
                result.error_source = ERR_SRC_MBEDTLS;
                goto exit;
            }
        }
    }

    if (options->client_certificate != NULL) {
        err = mbedtls_x509_crt_parse_der(&result.context->clicert, options->client_certificate->certificate,
                                         options->client_certificate->certificateSize);
        if (err != 0) {
            lssDebugPrint(options, "mbedtls_x509_crt_parse_file Failed. mbedtlsError = %d\n", err);
            result.error_num = err;
            result.error_source = ERR_SRC_MBEDTLS;
            goto exit;
        }
        err = mbedtls_pk_parse_key(&result.context->pkey, options->client_certificate->key,
                                   options->client_certificate->keySize, options->client_certificate->password,
                                   options->client_certificate->passwordSize, mbedtls_ctr_drbg_random,
                                   &result.context->ctr_drbg);
        if (err != 0) {
            lssDebugPrint(options, "mbedtls_x509_crt_parse_file Failed. mbedtlsError = %d\n", err);
            result.error_num = err;
            result.error_source = ERR_SRC_MBEDTLS;
            goto exit;
        }
        err = mbedtls_ssl_conf_own_cert(&result.context->conf, &result.context->clicert, &result.context->pkey);
        if (err != 0) {
            lssDebugPrint(options, "mbedtls_x509_crt_parse_file Failed. mbedtlsError = %d\n", err);
            result.error_num = err;
            result.error_source = ERR_SRC_MBEDTLS;
            goto exit;
        }
    }

    mbedtls_ssl_conf_ca_chain(&result.context->conf, &result.context->cacert, NULL);

    mbedtls_ssl_set_hostname(&result.context->ssl, hostname);

    if ((err = mbedtls_ssl_setup(&result.context->ssl, &result.context->conf)) != 0) {
        lssDebugPrint(options, "mbedtls_ssl_setup failed with %d\n", err);
        result.error_num = err;
        result.error_source = ERR_SRC_MBEDTLS;
        goto exit;
    }

    lss_open_connection_options _options = {0};
    _options.connect_timeout = options->connect_timeout;
    _options.read_timeout = options->read_timeout;
    _options.write_timeout = options->write_timeout;
    lss_connection_result connResult = lss_open_connection(hostname, portno, &_options);
    if (connResult.error_num != 0) {
        lssDebugPrint(options, "lss_open_connection failed with %d\n", connResult.error_num);
        result.error_num = connResult.error_num;
        result.error_source = connResult.error_source;
        goto exit;
    }
    result.context->socket.fd = connResult.context->sd;
    free(connResult.context); // we don't need it anymore, we use tls context now

    // fails in 3.6.0 with tls1.3 - unsupported extension
    // if ((err = mbedtls_ssl_conf_max_frag_len(&result.context->conf, MBEDTLS_SSL_MAX_FRAG_LEN_4096)) != 0) {
    //     lssDebugPrint(options, "mbedtls_ssl_conf_max_frag_len failed with %d\n", err);
    //     result.error_num = err;
    //     result.error_source = ERR_SRC_MBEDTLS;
    //     goto exit;
    // }

    err = lss_tls_handshake(result.context,
                            options->connect_timeout > 0 ? options->connect_timeout : 5 * 60 * 1000);

    if (err != 0) {
        lssDebugPrint(options, "mbedtls_ssl_handshake failed with %d\n", err);
        result.error_num = err;
        result.error_source = ERR_SRC_MBEDTLS;
        goto exit;
    }

    if ((err = mbedtls_ssl_get_verify_result(&result.context->ssl)) != 0) {
        lssDebugPrint(options, "mbedtls_ssl_get_verify_result failed with %d\n", err);
        result.error_num = err;
        result.error_source = ERR_SRC_MBEDTLS;
        goto exit;
    }

exit:
    if (result.error_num != 0 && result.context) // If there's an error and context is allocated
    {
        free_connection(result.context);
        result.context = NULL; // Important to nullify the pointer after freeing
    }

    return result;
}

lss_tls_connection_result
lss_close_tls_connection(lss_tls_connection_context* context) {
    int err;
    lss_tls_connection_result result = {NULL, 0, ERR_SRC_NONE};
    /* ponytail: default close is best effort; an explicit write timeout bounds retries. */
    uint64_t deadline = lss_monotonic_ms() + (context->write_timeout > 0 ? context->write_timeout : 0);
    for (;;) {
        err = mbedtls_ssl_close_notify(&context->ssl);
        if (err != MBEDTLS_ERR_SSL_WANT_READ && err != MBEDTLS_ERR_SSL_WANT_WRITE) break;
        err = lss_tls_wait(context, err, deadline);
        if (err != 0) break;
    }

    if (err != 0) {
        lssDebugPrint(NULL, "mbedtls_ssl_close_notify failed with %d\n", err);
        result.error_num = err;
        result.error_source = ERR_SRC_MBEDTLS;
    }

    free_connection(context);
    return result;
}
