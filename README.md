# Lua Simple Socket

Lua Simple Socket is a lightweight C library designed to provide basic socket and transport capabilities to lua-corehttp. It extends the networking functionality by enabling secure and non-secure communications through a simplistic API. The library leverages mbed TLS for handling TLS sockets, ensuring robust security features for your Lua projects.

## Features

- Basic socket creation, ~~binding, and listening~~. (TODO)
- TCP/UDP client and server functionalities.
- TLS/SSL support through mbed TLS integration.
- Seamless integration with lua-corehttp.
- Lightweight and easy to use.

## Dependencies

- [mbed TLS](https://tls.mbed.org/)