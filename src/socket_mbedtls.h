#ifndef LSS_SOCKET_MBEDTLS_H
#define LSS_SOCKET_MBEDTLS_H

#include "errors.h"
#include <stdint.h>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

typedef struct lss_tls_connection_context {
    mbedtls_net_context socket;
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert, clicert;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_pk_context pkey;
    int read_timeout;
    int write_timeout;
    /* Set once the peer's close_notify authenticated the end of the stream;
     * later zero reads must stay a clean EOF, not a truncation error. */
    int clean_eof;
} lss_tls_connection_context;

typedef struct lss_tls_connection_result {
    lss_tls_connection_context* context;
    int error_num;
    ErrorSource error_source;
} lss_tls_connection_result;

typedef struct lss_tls_ca_certificates {
    unsigned char** certificates;
    size_t* sizes;
    int count;
} lss_tls_ca_certificates;

typedef struct lss_tls_client_certificate {
    unsigned char* certificate;
    size_t certificateSize;
    unsigned char* key;
    size_t keySize;
    unsigned char* password;
    size_t passwordSize;
} lss_tls_client_certificate;

typedef struct lss_open_tls_connection_options {
    int connect_timeout;
    int read_timeout;
    int write_timeout;
    int use_bundled_root_certificates;
    char* drgb_seed;
    int debugLevel;
    int verify_peer;
    lss_tls_ca_certificates* ca_certificates;
    lss_tls_client_certificate* client_certificate;
} lss_open_tls_connection_options;

lss_tls_connection_result lss_open_tls_connection(const char* hostname, int portno,
                                                  lss_open_tls_connection_options* options);

lss_tls_connection_result lss_close_tls_connection(lss_tls_connection_context* context);

/* UINT64_MAX is an unlimited deadline; otherwise absolute monotonic milliseconds. */
uint64_t lss_monotonic_ms(void);
int lss_tls_wait(lss_tls_connection_context* context, int want, uint64_t deadline);

#endif /* MBEDTLS_SOCKET_H */
