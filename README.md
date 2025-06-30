# ABC Protocol Example

This repository provides a simple client and server implementation using mbedTLS that demonstrates the ABC protocol.

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
