#!/bin/bash
set -e
cd "$(dirname "$0")/.."

if [ ! -f server.crt ]; then
    ./scripts/generate_certs.sh
fi

./server 4433 password &
SERVER_PID=$!
sleep 1
./client 127.0.0.1 4433 password
kill $SERVER_PID || true
