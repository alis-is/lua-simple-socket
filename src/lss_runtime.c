#include "lss_runtime.h"

#include "c11threads.h"

#include <stdlib.h>

#include "mbedtls/threading.h"
#include "psa/crypto.h"

static once_flag tls_once = ONCE_FLAG_INIT;
static int tls_failed = 0;

static void tls_mutex_init(mbedtls_threading_mutex_t* mutex) {
    mtx_t* handle;
    mutex->ctx = NULL;
    handle = malloc(sizeof(*handle));
    if (handle == NULL) {
        return;
    }
    if (mtx_init(handle, mtx_plain) != thrd_success) {
        free(handle);
        return;
    }
    mutex->ctx = handle;
}

static void tls_mutex_free(mbedtls_threading_mutex_t* mutex) {
    if (mutex->ctx != NULL) {
        mtx_destroy((mtx_t*)mutex->ctx);
        free(mutex->ctx);
        mutex->ctx = NULL;
    }
}

static int tls_mutex_lock(mbedtls_threading_mutex_t* mutex) {
    if (mutex->ctx == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }
    return mtx_lock((mtx_t*)mutex->ctx) == thrd_success ? 0 : MBEDTLS_ERR_THREADING_MUTEX_ERROR;
}

static int tls_mutex_unlock(mbedtls_threading_mutex_t* mutex) {
    if (mutex->ctx == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }
    return mtx_unlock((mtx_t*)mutex->ctx) == thrd_success ? 0 : MBEDTLS_ERR_THREADING_MUTEX_ERROR;
}

static void tls_runtime_init(void) {
    mbedtls_threading_set_alt(tls_mutex_init, tls_mutex_free, tls_mutex_lock, tls_mutex_unlock);
    if (psa_crypto_init() != PSA_SUCCESS) {
        tls_failed = 1;
    }
}

int eli_tls_initialize(void) {
    call_once(&tls_once, tls_runtime_init);
    return tls_failed ? -1 : 0;
}
