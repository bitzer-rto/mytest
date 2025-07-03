# ABC Protocol Example

This repository provides a simple client and server implementation using mbedTLS that demonstrates the ABC protocol.  The program derives an AES key from a shared password using PBKDF2 and the TLS handshake randoms, transfers the client certificate encrypted with this key and pins the peer certificate fingerprint for future runs.

## Building

Use `make` to build both the client and server:

```sh
make
```

## Running tests

A basic test script generates certificates, starts the server and runs the client:

```sh
make test
```

The client connects to the server using the shared password `password` on port `4433`.
Certificates are generated automatically on first build.
