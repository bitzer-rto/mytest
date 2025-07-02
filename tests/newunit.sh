#!/bin/bash

set -e

SERVER_EXEC=./server
CLIENT_EXEC=./client
LOG_FILE="test_suite.log"
PORT=4433
HOST=127.0.0.1

mkdir -p certs
cd certs

# ---- Cert Generator ----
function generate_cert {
  KEY=$1
  CRT=$2
  CN=$3
  if [ ! -f "$CRT" ]; then
    echo "Generating cert: $CRT"
    openssl ecparam -genkey -name prime256v1 -out "$KEY"
    openssl req -new -x509 -key "$KEY" -subj "/CN=$CN" -out "$CRT" -days 365
  fi
}

function corrupt_cert {
  if [ ! -f client_corrupt.crt ]; then
    echo "Creating corrupted cert: client_corrupt.crt"
    cp client_cert.crt client_corrupt.crt
    echo "CORRUPT" >> client_corrupt.crt
  fi
}

# ✔ Good certs
generate_cert server.key server.cert "Server"
generate_cert client.key client_cert.crt "Client"

# ❌ Client signed by wrong CA
generate_cert client_wrong.key client_wrong.crt "BadClient"

# ❌ Server signed by wrong CA
generate_cert server_wrong.key server_untrusted.crt "BadServer"

# ❌ Corrupted cert
corrupt_cert

cd ..

# ---- Setup ----
rm -f "$LOG_FILE"
touch "$LOG_FILE"
function run_test {
  TEST_NUM=$1
  DESCRIPTION=$2
  SERVER_CERT=$3
  CLIENT_CERT=$4
  SERVER_PW=$5
  CLIENT_PW=$6
  EXPECT_SUCCESS=$7

  echo "=======================================" | tee -a "$LOG_FILE"
  echo "Running Test $TEST_NUM: $DESCRIPTION" | tee -a "$LOG_FILE"

  # Replace pinned certs
  cp "certs/$SERVER_CERT" server.cert
  cp "certs/$CLIENT_CERT" client_cert.crt

  # Start server
  ./server $PORT "$SERVER_PW" > server_output.log 2>&1 &
  SERVER_PID=$!
  sleep 1

  # Run client with timeout and capture status
  set +e
  timeout 5s ./client $HOST $PORT "$CLIENT_PW" > client_output.log 2>&1
  CLIENT_STATUS=$?
  set -e

  # Cleanup server
  kill $SERVER_PID 2>/dev/null || true
  wait $SERVER_PID 2>/dev/null || true

  # Dump logs
  {
    echo "--- Server Output ---"
    cat server_output.log
    echo "--- Client Output ---"
    cat client_output.log
  } >> "$LOG_FILE"

  # Detect timeout exit code (124 from `timeout`)
  if [[ "$CLIENT_STATUS" -eq 124 ]]; then
    echo "⚠️ Test $TEST_NUM timed out" | tee -a "$LOG_FILE"
    CLIENT_STATUS=1  # Treat timeout as failure
  fi

  # Result check
  if [[ "$EXPECT_SUCCESS" == "true" && "$CLIENT_STATUS" -eq 0 ]]; then
    echo "✅ Test $TEST_NUM PASSED" | tee -a "$LOG_FILE"
  elif [[ "$EXPECT_SUCCESS" == "false" && "$CLIENT_STATUS" -ne 0 ]]; then
    echo "✅ Test $TEST_NUM correctly FAILED" | tee -a "$LOG_FILE"
  else
    echo "❌ Test $TEST_NUM FAILED (unexpected outcome, code=$CLIENT_STATUS)" | tee -a "$LOG_FILE"
  fi

  echo "" >> "$LOG_FILE"
}

run_test 1 "Valid communication" \
  server.cert client_cert.crt \
  secret secret \
  true



run_test 2 "Client not trusted and wrong password" \
  server.cert client_wrong.crt \
  secret wrongpass \
  false

run_test 3 "Client uses wrong certificate (wrong signer)" \
  server.cert client_wrong.crt \
  secret secret \
  false

run_test 4 "Server uses wrong certificate (untrusted by client)" \
  server_untrusted.crt client_cert.crt \
  secret secret \
  false

run_test 5 "Correct certificates but incorrect password" \
  server.cert client_cert.crt \
  secret wrongpass \
  false

run_test 6 "Client certificate is corrupted" \
  server.cert client_corrupt.crt \
  secret secret \
  false

echo "🎉 All tests completed. See $LOG_FILE for details."

