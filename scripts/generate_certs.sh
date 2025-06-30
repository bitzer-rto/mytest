#!/bin/bash
set -e
openssl ecparam -genkey -name prime256v1 -out server.key
openssl req -new -x509 -key server.key -subj "/CN=ABCServer" -out server.crt -days 365
openssl ecparam -genkey -name prime256v1 -out client.key
openssl req -new -x509 -key client.key -subj "/CN=ABCClient" -out client.crt -days 365
