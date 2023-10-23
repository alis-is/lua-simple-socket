#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/debug.h"
#include "socket.h"
#include "socket_mbedtls.h"
#if defined(LSS_HAS_BUNDLED_ROOT_CERTIFICATES)
#include "certs.h"
#endif
#include <errno.h>
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"

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

lss_tls_connection_result
lss_open_tls_connection(const char* hostname, int portno, lss_open_tls_connection_options* options) {
    lss_open_tls_connection_options defaultOptions = {0, 0, 0, 1, NULL, 0, 1, NULL, NULL};
    int err;
    char portno_str[16];

    lss_tls_connection_result result = {NULL, 0, ERR_SRC_NONE};
    result.context = malloc(sizeof(lss_tls_connection_context));
    if (result.context == NULL) {
        result.error_num = errno;
        result.error_source = ERR_SRC_ERRNO;
        goto exit;
    }

    if (options == NULL) {
        options = &defaultOptions;
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

    char* seedString = "lsstls";
    if (options->drbgSeed != NULL) {
        seedString = options->drbgSeed;
    }
    mbedtls_ctr_drbg_seed(&result.context->ctr_drbg, mbedtls_entropy_func, &result.context->entropy,
                          (const unsigned char*)seedString, strlen(seedString));
    snprintf(portno_str, sizeof(portno_str), "%d", portno);

    if ((err = mbedtls_ssl_config_defaults(&result.context->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT))
        != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, (" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", err));
        result.error_num = err;
        result.error_source = ERR_SRC_MBEDTLS;
        goto exit;
    }

    if (options->verifyPeer) {
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
    if (options->useBundledRootCertificates) {
        long unsigned int shift = 0;
        for (int i = 0; i < lss_cacertsCount; i++) {
            err = mbedtls_x509_crt_parse_der_nocopy(&result.context->cacert, lss_cacerts + shift, lss_cacertSizes[i]);
            if (err != 0) {
                fprintf(stderr, "Mbedtls_Connect: mbedtls_x509_crt_parse_file Failed. mbedtlsError = %d\n", err);
                result.error_num = err;
                result.error_source = ERR_SRC_MBEDTLS;
                goto exit;
            }
            shift += lss_cacertSizes[i];
        }
    }
#endif
    if (options->caCertificates != NULL) {
        for (int i = 0; i < options->caCertificates->count; i++) {
            err = mbedtls_x509_crt_parse_der(&result.context->cacert, options->caCertificates->certificates[i],
                                             options->caCertificates->sizes[i]);
            if (err != 0) {
                fprintf(stderr, "Mbedtls_Connect: mbedtls_x509_crt_parse_file Failed. mbedtlsError = %d\n", err);
                result.error_num = err;
                result.error_source = ERR_SRC_MBEDTLS;
                goto exit;
            }
        }
    }

    if (options->clientCertificate != NULL) {
        err = mbedtls_x509_crt_parse_der(&result.context->cacert, options->clientCertificate->certificate,
                                         options->clientCertificate->certificateSize);
        if (err != 0) {
            fprintf(stderr, "Mbedtls_Connect: mbedtls_x509_crt_parse_file Failed. mbedtlsError = %d\n", err);
            result.error_num = err;
            result.error_source = ERR_SRC_MBEDTLS;
            goto exit;
        }
        err = mbedtls_pk_parse_key(&result.context->pkey, options->clientCertificate->key,
                                   options->clientCertificate->keySize, options->clientCertificate->password,
                                   options->clientCertificate->passwordSize, mbedtls_ctr_drbg_random,
                                   &result.context->ctr_drbg);
        if (err != 0) {
            fprintf(stderr, "Mbedtls_Connect: mbedtls_x509_crt_parse_file Failed. mbedtlsError = %d\n", err);
            result.error_num = err;
            result.error_source = ERR_SRC_MBEDTLS;
            goto exit;
        }
        err = mbedtls_ssl_conf_own_cert(&result.context->conf, &result.context->clicert, &result.context->pkey);
        if (err != 0) {
            fprintf(stderr, "Mbedtls_Connect: mbedtls_x509_crt_parse_file Failed. mbedtlsError = %d\n", err);
            result.error_num = err;
            result.error_source = ERR_SRC_MBEDTLS;
            goto exit;
        }
    }

    mbedtls_ssl_conf_ca_chain(&result.context->conf, &result.context->cacert, NULL);

    mbedtls_ssl_set_hostname(&result.context->ssl, hostname);

    if ((err = mbedtls_ssl_setup(&result.context->ssl, &result.context->conf)) != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, (" failed\n  ! mbedtls_ssl_setup returned %d\n\n", err));
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
        MBEDTLS_SSL_DEBUG_MSG(1, (" failed\n  ! mbedtls_ssl_setup returned %d\n\n", connResult.error_num));
        result.error_num = connResult.error_num;
        result.error_source = connResult.error_source;
        goto exit;
    }
    result.context->socket.fd = connResult.context->sd;
    free(connResult.context); // we don't need it anymore, we use tls context now

    mbedtls_ssl_set_bio(&result.context->ssl, (void*)&result.context->socket, mbedtls_net_send, mbedtls_net_recv,
                        mbedtls_net_recv_timeout);

    if ((err = mbedtls_ssl_conf_max_frag_len(&result.context->conf, MBEDTLS_SSL_MAX_FRAG_LEN_4096)) != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, (" failed\n  ! mbedtls_ssl_conf_max_frag_len returned %d\n\n", err));
        result.error_num = err;
        result.error_source = ERR_SRC_MBEDTLS;
        goto exit;
    }

    do {
        err = mbedtls_ssl_handshake(&result.context->ssl);
    } while ((err == MBEDTLS_ERR_SSL_WANT_READ) || (err == MBEDTLS_ERR_SSL_WANT_WRITE));

    if (err != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, (" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", err));
        result.error_num = err;
        result.error_source = ERR_SRC_MBEDTLS;
        goto exit;
    }

    if ((err = mbedtls_ssl_get_verify_result(&result.context->ssl)) != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, (" failed\n  ! mbedtls_ssl_get_verify_result returned %d\n\n", err));
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
    do {
        err = mbedtls_ssl_close_notify(&context->ssl);
    } while ((err == MBEDTLS_ERR_SSL_WANT_READ) || (err == MBEDTLS_ERR_SSL_WANT_WRITE));

    if (err != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, (" failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", err));
        result.error_num = err;
        result.error_source = ERR_SRC_MBEDTLS;
    }

    free_connection(context);
    return result;
}
