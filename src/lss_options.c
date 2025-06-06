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
    lua_getfield(L, -1, "read_timeout");
    if (lua_isinteger(L, -1)) {
        plaintext->read_timeout = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);
    // write timeout
    plaintext->write_timeout = 0;
    lua_getfield(L, -1, "write_timeout");
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
    lua_getfield(L, -1, "connect_timeout");
    if (lua_isinteger(L, -1)) {
        options->connect_timeout = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);
    // read_timeout
    options->read_timeout = 0;
    lua_getfield(L, -1, "read_timeout");
    if (lua_isinteger(L, -1)) {
        options->read_timeout = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);
    // write timeout
    options->write_timeout = 0;
    lua_getfield(L, -1, "write_timeout");
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
    // drgb_seed
    options->drgb_seed = NULL;
    lua_getfield(L, -1, "drgb_seed");
    if (lua_isstring(L, -1)) {
        options->drgb_seed = strdup(lua_tostring(L, -1));
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
        if (count > 0) {
            options->ca_certificates = malloc(sizeof(lss_tls_ca_certificates));
            options->ca_certificates->certificates = malloc(sizeof(unsigned char*) * count);
            options->ca_certificates->sizes = malloc(sizeof(unsigned int) * count);
            options->ca_certificates->count = count;

            for (size_t i = 1; i <= count; i++) {
                lua_rawgeti(L, -1, i);
                if (lua_isstring(L, -1)) {
                    size_t size = 0;
                    const char* certificate = lua_tolstring(L, -1, &size);
                    if (size > 0) {
                        options->ca_certificates->certificates[i - 1] = malloc(size);
                        memcpy(options->ca_certificates->certificates[i - 1], certificate, size);
                        options->ca_certificates->sizes[i - 1] = size;
                    }
                }
                lua_pop(L, 1);
            }
        }
    }
    lua_pop(L, 1);
    // client_certificate
    options->client_certificate = NULL;
    lua_getfield(L, -1, "client_certificate");
    if (lua_istable(L, -1)) {
        options->client_certificate = malloc(sizeof(lss_tls_client_certificate));
        // certificate
        options->client_certificate->certificate = NULL;
        lua_getfield(L, -1, "certificate");
        if (lua_isstring(L, -1)) {
            options->client_certificate->certificate =
                (unsigned char*)strdup(lua_tolstring(L, -1, &options->client_certificate->certificateSize));
        }
        lua_pop(L, 1);
        // key
        options->client_certificate->key = NULL;
        lua_getfield(L, -1, "key");
        if (lua_isstring(L, -1)) {
            options->client_certificate->key =
                (unsigned char*)strdup(lua_tolstring(L, -1, &options->client_certificate->keySize));
        }
        lua_pop(L, 1);
        // password
        options->client_certificate->password = NULL;
        lua_getfield(L, -1, "password");
        if (lua_isstring(L, -1)) {
            options->client_certificate->password =
                (unsigned char*)strdup(lua_tolstring(L, -1, &options->client_certificate->passwordSize));
        }
        lua_pop(L, 1);
        // verify_peer
        options->verify_peer = 1;
        lua_getfield(L, -1, "verify_peer");
        if (lua_isboolean(L, -1)) {
            options->verify_peer = lua_toboolean(L, -1);
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