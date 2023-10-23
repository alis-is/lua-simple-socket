#ifndef LSS_ERRORS_H
#define LSS_ERRORS_H

typedef enum { ERR_SRC_NONE = 0, ERR_SRC_GETADDRINFO = 1, ERR_SRC_ERRNO = 2, ERR_SRC_MBEDTLS = 3 } ErrorSource;

#endif // ERRORS_H
