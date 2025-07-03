#!/bin/bash
set -e
cd "$(dirname "$0")/.."

[ -f server.crt ] || ./scripts/generate_certs.sh

rm -f trusted_server.sha256 trusted_client.sha256 server.log client.log

# First run - should succeed and pin server certificate
./server 4433 password >server.log 2>&1 &
PID=$!
sleep 1
./client 127.0.0.1 4433 password >client.log 2>&1
kill $PID || true
wait $PID || true

grep -q "Server replied" client.log

echo "Initial connection succeeded"

# Second run - using pinned cert should succeed again
./server 4433 password >server.log 2>&1 &
PID=$!
sleep 1
./client 127.0.0.1 4433 password >client.log 2>&1
kill $PID || true
wait $PID || true

grep -q "Server replied" client.log

echo "Repeat connection succeeded"

# Generate alternate server certificate
openssl ecparam -genkey -name prime256v1 -out alt_server.key
openssl req -new -x509 -key alt_server.key -subj "/CN=AltServer" -out alt_server.crt -days 365

cp alt_server.crt server.crt
cp alt_server.key server.key

# Third run - client should reject new certificate
./server 4433 password >server.log 2>&1 &
PID=$!
sleep 1
if ./client 127.0.0.1 4433 password >client.log 2>&1 ; then
  echo "Pinning check failed" && cat server.log client.log && kill $PID && exit 1
fi
kill $PID || true
wait $PID || true

echo "Pinning test passed"

rm -f alt_server.crt alt_server.key server.log client.log trusted_server.sha256 trusted_client.sha256

