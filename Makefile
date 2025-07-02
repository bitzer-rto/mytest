CC=gcc
CFLAGS=-Wall -O2 
LDFLAGS= -lmbedtls -lmbedcrypto -lmbedx509 

SRC=src
BIN=.

all: server client mkcert

server: $(SRC)/server.c
	$(CC) $(CFLAGS) $< -o $(BIN)/server $(LDFLAGS)

client: $(SRC)/client.c
	$(CC) $(CFLAGS) $< -o $(BIN)/client $(LDFLAGS)

mkcert:	
	./scripts/generate_certs.sh


clean:
	rm -f server client
	rm *.crt; rm client*; rm server*; rm *cert; rm *key; rm -rf certs	

.PHONY: all clean test

test: all
	./tests/newunit.sh
