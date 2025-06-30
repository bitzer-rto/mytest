#!/bin/bash
set -e
cd "$(dirname "$0")/.."

# Generate default certs if missing
if [ ! -f server.crt ]; then
    ./scripts/generate_certs.sh
fi

cp -f server.crt server.crt.orig
cp -f server.key server.key.orig
cp -f client.crt client.crt.orig
cp -f client.key client.key.orig

# create alternate certificates
if [ ! -f alt_server.crt ]; then
    openssl ecparam -genkey -name prime256v1 -out alt_server.key
    openssl req -new -x509 -key alt_server.key -subj "/CN=AltServer" -out alt_server.crt -days 365
fi
if [ ! -f alt_client.crt ]; then
    cp alt_server.crt alt_client.crt
    cp alt_server.key alt_client.key
fi

run_test() {
    desc="$1"; shift
    server_cert="$1"; shift
    expected_client="$1"; shift
    client_cert="$1"; shift
    srv_pw="$1"; shift
    cli_pw="$1"; shift
    expect_fail="$1"; shift

    if [ "$server_cert" = "server" ]; then
        cp -f server.crt.orig server.crt
        cp -f server.key.orig server.key
    else
        cp -f alt_server.crt server.crt
        cp -f alt_server.key server.key
    fi

    if [ "$expected_client" = "none" ]; then
        rm -f client.crt
    else
        cp -f client.crt.orig client.crt
    fi

    ./server 4433 "$srv_pw" &
    srv_pid=$!
    sleep 1
    if [ "$server_cert" = "alt_server" ]; then
        cp -f server.crt.orig server.crt
    fi

    if [ "$client_cert" = "client" ]; then
        cp -f client.crt.orig client.crt
        cp -f client.key.orig client.key
    else
        cp -f alt_client.crt client.crt
        cp -f alt_client.key client.key
    fi

    ./client 127.0.0.1 4433 "$cli_pw" >/tmp/test.log 2>&1 && cli_ret=0 || cli_ret=$?
    kill $srv_pid 2>/dev/null || true
    wait $srv_pid 2>/dev/null || true

    if { [ "$expect_fail" = "yes" ] && [ "$cli_ret" -ne 0 ]; } || \
       { [ "$expect_fail" = "no" ] && [ "$cli_ret" -eq 0 ]; }; then
        echo "PASS: $desc"
    else
        echo "FAIL: $desc"; cat /tmp/test.log; exit 1
    fi
}

# Test definitions
run_test "test1 no trust and wrong password" "server" "none" "alt_client" "password" "wrong" "yes"
run_test "test2 wrong client cert" "server" "client" "alt_client" "password" "password" "yes"
run_test "test3 wrong server cert" "alt_server" "client" "client" "password" "password" "yes"
run_test "test4 wrong password" "server" "client" "client" "password" "wrong" "yes"

exit 0
