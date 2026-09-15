#ifndef LSS_RUNTIME_H
#define LSS_RUNTIME_H

/* Process-lifetime TLS/PSA runtime. Installs the C11-backed mbedtls
 * alternative mutexes exactly once and initializes PSA with error checking.
 * Returns 0 on success, -1 when initialization failed. Safe to call from any
 * thread and from every state. */
int eli_tls_initialize(void);

#endif /* LSS_RUNTIME_H */
