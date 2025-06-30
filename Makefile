CC=gcc
CFLAGS=-Wall -O2 $(shell pkg-config --cflags mbedtls)
LDFLAGS=$(shell pkg-config --libs mbedtls mbedx509 mbedcrypto)

SRC=src
BIN=.

all: server client

server: $(SRC)/server.c
	$(CC) $(CFLAGS) $< -o $(BIN)/server $(LDFLAGS)

client: $(SRC)/client.c
	$(CC) $(CFLAGS) $< -o $(BIN)/client $(LDFLAGS)

clean:
	rm -f server client

.PHONY: all clean test

test: all
	./tests/run.sh
