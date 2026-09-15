#include <lua.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "lss_options.h"

static int
load_timeout(lua_State* L, const char* name, const char* alias, int minimum) {
    lua_getfield(L, -1, name);
    if (lua_isnil(L, -1) && alias != NULL) {
        lua_pop(L, 1);
        lua_getfield(L, -1, alias);
    }
    lua_Integer value = 0;
    if (!lua_isnil(L, -1)) {
        value = lua_tointeger(L, -1);
        /* Native open rejects this sentinel. Do not longjmp past allocations
         * owned by callers (HTTP already owns its request headers here). */
        if (!lua_isinteger(L, -1) || value < minimum || value > INT_MAX) value = -2;
    }
    lua_pop(L, 1);
    return (int)value;
}

lss_open_connection_options*
lss_load_plaintext_connection_options(lua_State* L) {
    int connect_timeout = load_timeout(L, "connect_timeout", "timeout", 0);
    int read_timeout = load_timeout(L, "read_timeout", NULL, -1);
    int write_timeout = load_timeout(L, "write_timeout", NULL, 0);
    lss_open_connection_options* plaintext = (lss_open_connection_options*)malloc(sizeof(lss_open_connection_options));
    if (plaintext == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    memset(plaintext, 0, sizeof(lss_open_connection_options));
    plaintext->connect_timeout = connect_timeout;
    plaintext->read_timeout = read_timeout;
    plaintext->write_timeout = write_timeout;
    return plaintext;
}

void
lss_free_plain_connection_options(lss_open_connection_options* options) {
    free(options);
}

lss_open_tls_connection_options*
lss_load_tls_connection_options(lua_State* L) {
    int top = lua_gettop(L);
    int connect_timeout = load_timeout(L, "connect_timeout", "timeout", 0);
    int read_timeout = load_timeout(L, "read_timeout", NULL, -1);
    int write_timeout = load_timeout(L, "write_timeout", NULL, 0);
    lss_open_tls_connection_options* options =
        (lss_open_tls_connection_options*)malloc(sizeof(lss_open_tls_connection_options));
    if (options == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    memset(options, 0, sizeof(lss_open_tls_connection_options));
    options->connect_timeout = connect_timeout;
    options->read_timeout = read_timeout;
    options->write_timeout = write_timeout;
    // debugLevel
    options->debugLevel = 0;
    lua_getfield(L, -1, "debugLevel");
    if (lua_isinteger(L, -1)) {
        options->debugLevel = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);
    // drgb_seed
    options->drgb_seed = NULL;
    lua_getfield(L, -1, "drgb_seed");
    if (lua_isstring(L, -1)) {
        options->drgb_seed = strdup(lua_tostring(L, -1));
        if (options->drgb_seed == NULL) goto allocation_failed;
    }
    lua_pop(L, 1);
    // use_bundled_root_certificates
    options->use_bundled_root_certificates = 1;
    lua_getfield(L, -1, "use_bundled_root_certificates");
    if (lua_isboolean(L, -1)) {
        options->use_bundled_root_certificates = lua_toboolean(L, -1);
    }
    lua_pop(L, 1);

    // ca certificates
    options->ca_certificates = NULL;
    lua_getfield(L, -1, "ca_certificates");
    if (lua_istable(L, -1)) {
        // get table len to count
        size_t count = lua_rawlen(L, -1);
        if (count > INT_MAX) goto allocation_failed;
        if (count > 0) {
            options->ca_certificates = malloc(sizeof(lss_tls_ca_certificates));
            if (options->ca_certificates == NULL) goto allocation_failed;
            options->ca_certificates->certificates = calloc(count, sizeof(unsigned char*));
            options->ca_certificates->sizes = calloc(count, sizeof(*options->ca_certificates->sizes));
            options->ca_certificates->count =
                options->ca_certificates->certificates != NULL && options->ca_certificates->sizes != NULL ? (int)count : 0;
            if (options->ca_certificates->count == 0) goto allocation_failed;

            for (size_t i = 1; i <= (size_t)options->ca_certificates->count; i++) {
                lua_rawgeti(L, -1, i);
                if (lua_isstring(L, -1)) {
                    size_t size = 0;
                    const char* certificate = lua_tolstring(L, -1, &size);
                    if (size > 0) {
                        options->ca_certificates->certificates[i - 1] = malloc(size);
                        if (options->ca_certificates->certificates[i - 1] == NULL) goto allocation_failed;
                        memcpy(options->ca_certificates->certificates[i - 1], certificate, size);
                        options->ca_certificates->sizes[i - 1] = size;
                    }
                }
                lua_pop(L, 1);
            }
        }
    }
    lua_pop(L, 1);
    // verify_peer
    options->verify_peer = 1;
    lua_getfield(L, -1, "verify_peer");
    if (lua_isboolean(L, -1)) {
        options->verify_peer = lua_toboolean(L, -1);
    }
    lua_pop(L, 1);

    // client_certificate
    options->client_certificate = NULL;
    lua_getfield(L, -1, "client_certificate");
    if (lua_istable(L, -1)) {
        options->client_certificate = calloc(1, sizeof(lss_tls_client_certificate));
        if (options->client_certificate == NULL) goto allocation_failed;
        // certificate
        options->client_certificate->certificate = NULL;
        options->client_certificate->certificateSize = 0;
        lua_getfield(L, -1, "certificate");
        if (lua_isstring(L, -1)) {
            size_t size = 0;
            const char* value = lua_tolstring(L, -1, &size);
            if (size > 0) {
                options->client_certificate->certificate = (unsigned char*)malloc(size);
                if (options->client_certificate->certificate == NULL) goto allocation_failed;
                memcpy(options->client_certificate->certificate, value, size);
                options->client_certificate->certificateSize = size;
            }
        }
        lua_pop(L, 1);
        // key
        options->client_certificate->key = NULL;
        options->client_certificate->keySize = 0;
        lua_getfield(L, -1, "key");
        if (lua_isstring(L, -1)) {
            size_t size = 0;
            const char* value = lua_tolstring(L, -1, &size);
            if (size > 0) {
                options->client_certificate->key = (unsigned char*)malloc(size);
                if (options->client_certificate->key == NULL) goto allocation_failed;
                memcpy(options->client_certificate->key, value, size);
                options->client_certificate->keySize = size;
            }
        }
        lua_pop(L, 1);
        // password
        options->client_certificate->password = NULL;
        options->client_certificate->passwordSize = 0;
        lua_getfield(L, -1, "password");
        if (lua_isstring(L, -1)) {
            size_t size = 0;
            const char* value = lua_tolstring(L, -1, &size);
            if (size > 0) {
                options->client_certificate->password = (unsigned char*)malloc(size);
                if (options->client_certificate->password == NULL) goto allocation_failed;
                memcpy(options->client_certificate->password, value, size);
                options->client_certificate->passwordSize = size;
            }
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
    return options;

allocation_failed:
    lss_free_tls_connection_options(options);
    lua_settop(L, top);
    errno = ENOMEM;
    return NULL;
}

void
lss_free_tls_connection_options(lss_open_tls_connection_options* options) {
    if (options == NULL) {
        return;
    }
    if (options->drgb_seed != NULL) {
        free((void*)options->drgb_seed);
    }
    if (options->ca_certificates != NULL) {
        for (size_t i = 0; i < options->ca_certificates->count; i++) {
            free((void*)options->ca_certificates->certificates[i]);
        }
        free((void*)options->ca_certificates->certificates);
        free((void*)options->ca_certificates->sizes);
        free((void*)options->ca_certificates);
    }
    if (options->client_certificate != NULL) {
        if (options->client_certificate->certificate != NULL) {
            free((void*)options->client_certificate->certificate);
        }
        if (options->client_certificate->key != NULL) {
            free((void*)options->client_certificate->key);
        }
        if (options->client_certificate->password != NULL) {
            free((void*)options->client_certificate->password);
        }
        free((void*)options->client_certificate);
    }
    free(options);
}
