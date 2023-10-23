#include <lua.h>
#include <stdlib.h>
#include <string.h>
#include "lss_options.h"

lss_open_connection_options*
lss_load_plaintext_connection_options(lua_State* L) {
    lss_open_connection_options* plaintext = (lss_open_connection_options*)malloc(sizeof(lss_open_connection_options));
    memset(plaintext, 0, sizeof(lss_open_connection_options));
    // timeout
    plaintext->connect_timeout = 0;
    lua_getfield(L, -1, "timeout");
    if (lua_isinteger(L, -1)) {
        plaintext->connect_timeout = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);
    // read_timeout
    plaintext->read_timeout = 0;
    lua_getfield(L, -1, "readTimeout");
    if (lua_isinteger(L, -1)) {
        plaintext->read_timeout = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);
    // write timeout
    plaintext->write_timeout = 0;
    lua_getfield(L, -1, "writeTimeout");
    if (lua_isinteger(L, -1)) {
        plaintext->write_timeout = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);
    return plaintext;
}

void
lss_free_plain_connection_options(lss_open_connection_options* options) {
    free(options);
}

lss_open_tls_connection_options*
lss_load_tls_connection_options(lua_State* L) {
    lss_open_tls_connection_options* options =
        (lss_open_tls_connection_options*)malloc(sizeof(lss_open_tls_connection_options));
    memset(options, 0, sizeof(lss_open_tls_connection_options));
    // timeout
    options->connect_timeout = 0;
    lua_getfield(L, -1, "connectTimeout");
    if (lua_isinteger(L, -1)) {
        options->connect_timeout = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);
    // read_timeout
    options->read_timeout = 0;
    lua_getfield(L, -1, "readTimeout");
    if (lua_isinteger(L, -1)) {
        options->read_timeout = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);
    // write timeout
    options->write_timeout = 0;
    lua_getfield(L, -1, "writeTimeout");
    if (lua_isinteger(L, -1)) {
        options->write_timeout = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);
    // debugLevel
    options->debugLevel = 0;
    lua_getfield(L, -1, "debugLevel");
    if (lua_isinteger(L, -1)) {
        options->debugLevel = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);
    // drbgSeed
    options->drbgSeed = NULL;
    lua_getfield(L, -1, "drbgSeed");
    if (lua_isstring(L, -1)) {
        options->drbgSeed = strdup(lua_tostring(L, -1));
    }
    lua_pop(L, 1);
    // useBundledRootCertificates
    options->useBundledRootCertificates = 1;
    lua_getfield(L, -1, "useBundledRootCertificates");
    if (lua_isboolean(L, -1)) {
        options->useBundledRootCertificates = lua_toboolean(L, -1);
    }
    lua_pop(L, 1);

    // ca certificates
    options->caCertificates = NULL;
    lua_getfield(L, -1, "caCertificates");
    if (lua_istable(L, -1)) {
        // get table len to count
        size_t count = lua_rawlen(L, -1);
        if (count > 0) {
            options->caCertificates = malloc(sizeof(lss_tls_ca_certificates));
            options->caCertificates->certificates = malloc(sizeof(unsigned char*) * count);
            options->caCertificates->sizes = malloc(sizeof(unsigned int) * count);
            options->caCertificates->count = count;

            for (size_t i = 1; i <= count; i++) {
                lua_rawgeti(L, -1, i);
                if (lua_isstring(L, -1)) {
                    size_t size = 0;
                    const char* certificate = lua_tolstring(L, -1, &size);
                    if (size > 0) {
                        options->caCertificates->certificates[i - 1] = malloc(size);
                        memcpy(options->caCertificates->certificates[i - 1], certificate, size);
                        options->caCertificates->sizes[i - 1] = size;
                    }
                }
                lua_pop(L, 1);
            }
        }
    }
    lua_pop(L, 1);
    // clientCertificate
    options->clientCertificate = NULL;
    lua_getfield(L, -1, "clientCertificate");
    if (lua_istable(L, -1)) {
        options->clientCertificate = malloc(sizeof(lss_tls_client_certificate));
        // certificate
        options->clientCertificate->certificate = NULL;
        lua_getfield(L, -1, "certificate");
        if (lua_isstring(L, -1)) {
            options->clientCertificate->certificate =
                (unsigned char*)strdup(lua_tolstring(L, -1, &options->clientCertificate->certificateSize));
        }
        lua_pop(L, 1);
        // key
        options->clientCertificate->key = NULL;
        lua_getfield(L, -1, "key");
        if (lua_isstring(L, -1)) {
            options->clientCertificate->key =
                (unsigned char*)strdup(lua_tolstring(L, -1, &options->clientCertificate->keySize));
        }
        lua_pop(L, 1);
        // password
        options->clientCertificate->password = NULL;
        lua_getfield(L, -1, "password");
        if (lua_isstring(L, -1)) {
            options->clientCertificate->password =
                (unsigned char*)strdup(lua_tolstring(L, -1, &options->clientCertificate->passwordSize));
        }
        lua_pop(L, 1);
        // verifyPeer
        options->verifyPeer = 1;
        lua_getfield(L, -1, "verifyPeer");
        if (lua_isboolean(L, -1)) {
            options->verifyPeer = lua_toboolean(L, -1);
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
    return options;
}

void
lss_free_tls_connection_options(lss_open_tls_connection_options* options) {
    if (options == NULL) {
        return;
    }
    if (options->drbgSeed != NULL) {
        free((void*)options->drbgSeed);
    }
    if (options->caCertificates != NULL) {
        for (size_t i = 0; i < options->caCertificates->count; i++) {
            free((void*)options->caCertificates->certificates[i]);
        }
        free((void*)options->caCertificates->certificates);
        free((void*)options->caCertificates->sizes);
        free((void*)options->caCertificates);
    }
    if (options->clientCertificate != NULL) {
        if (options->clientCertificate->certificate != NULL) {
            free((void*)options->clientCertificate->certificate);
        }
        if (options->clientCertificate->key != NULL) {
            free((void*)options->clientCertificate->key);
        }
        if (options->clientCertificate->password != NULL) {
            free((void*)options->clientCertificate->password);
        }
        free((void*)options->clientCertificate);
    }
    free(options);
}