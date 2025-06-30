#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <mbedtls/platform.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/sha256.h>


static void handle_error(int ret, const char *msg)
{
    char buf[128];
    mbedtls_strerror(ret, buf, sizeof(buf));
    fprintf(stderr, "%s: %s\n", msg, buf);
    exit(1);
}



static int ssl_read_exact(mbedtls_ssl_context *ssl, unsigned char *buf, size_t len)
{
    size_t read_len = 0;
    int ret;
    while (read_len < len) {
        ret = mbedtls_ssl_read(ssl, buf + read_len, len - read_len);
        if (ret <= 0)
            return ret;
        read_len += ret;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <port> <password>\n", argv[0]);
        return 1;
    }
    const char *port = argv[1];
    const char *password = argv[2];
    (void) password;

    int ret;
    mbedtls_net_context listen_fd, client_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cacert;
    mbedtls_pk_context pkey;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    const int ciphersuites[] = { MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0 };

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "abc_server";
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers))) != 0)
        handle_error(ret, "ctr_drbg_seed");

    if ((ret = mbedtls_x509_crt_parse_file(&srvcert, "server.crt")) != 0)
        handle_error(ret, "x509_crt_parse_file");

    /* load expected client certificate so that server requests it */
    if ((ret = mbedtls_x509_crt_parse_file(&cacert, "client.crt")) != 0)
        handle_error(ret, "x509_crt_parse_file client");

    if ((ret = mbedtls_pk_parse_keyfile(&pkey, "server.key", NULL)) != 0)
        handle_error(ret, "pk_parse_keyfile");

    if ((ret = mbedtls_net_bind(&listen_fd, NULL, port, MBEDTLS_NET_PROTO_TCP)) != 0)
        handle_error(ret, "net_bind");

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
        handle_error(ret, "ssl_config_defaults");

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
        handle_error(ret, "ssl_setup");

    printf("Waiting for connection on port %s...\n", port);
    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL)) != 0)
        handle_error(ret, "net_accept");

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    if ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
        handle_error(ret, "ssl_handshake");

    /* Get client certificate from handshake */
    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&ssl);
    if (!peer) {
        fprintf(stderr, "No peer certificate received\n");
        return 1;
    }
    printf("Handshake client cert length: %zu\n", peer->raw.len);

    /* Receive certificate sent inside TLS */
    unsigned char lenbuf[4];
    if ((ret = ssl_read_exact(&ssl, lenbuf, sizeof(lenbuf))) != 0)
        handle_error(ret, "ssl_read len");
    size_t enclen = ((size_t)lenbuf[0] << 24) | ((size_t)lenbuf[1] << 16) |
                    ((size_t)lenbuf[2] << 8) | (size_t)lenbuf[3];
    unsigned char *enc = malloc(enclen);
    if (!enc) return 1;
    if ((ret = ssl_read_exact(&ssl, enc, enclen)) != 0)
        handle_error(ret, "ssl_read enc");

    /* no extra encryption, data is plain */
    if (peer->raw.len != enclen || memcmp(peer->raw.p, enc, enclen) != 0) {
        unsigned char h1[32], h2[32];
        mbedtls_sha256_ret(peer->raw.p, peer->raw.len, h1, 0);
        mbedtls_sha256_ret(enc, enclen, h2, 0);
        fprintf(stderr, "Certificate mismatch\n");
        fprintf(stderr, "peer len=%zu enclen=%zu\n", peer->raw.len, enclen);
        for(int i=0;i<32;i++) fprintf(stderr, "%02x", h1[i]);
        fprintf(stderr, "\n");
        for(int i=0;i<32;i++) fprintf(stderr, "%02x", h2[i]);
        fprintf(stderr, "\n");
        free(enc);
        return 1;
    }
    free(enc);

    unsigned char expected_fp[32], peer_fp[32];
    mbedtls_sha256_ret(peer->raw.p, peer->raw.len, peer_fp, 0);
    mbedtls_sha256_ret(cacert.raw.p, cacert.raw.len, expected_fp, 0);
    if (memcmp(peer_fp, expected_fp, 32) != 0) {
        fprintf(stderr, "Unexpected client certificate\n");
        return 1;
    }
    printf("Client certificate verified successfully\n");

    unsigned char pwbuf[64];
    ret = mbedtls_ssl_read(&ssl, pwbuf, sizeof(pwbuf)-1);
    if (ret <= 0) handle_error(ret, "ssl_read password");
    pwbuf[ret] = '\0';
    if (strcmp((char *)pwbuf, password) != 0) {
        fprintf(stderr, "Invalid password\n");
        return 1;
    }
    printf("Password verified\n");

    /* Read hello message */
    char buf[64];
    ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, sizeof(buf)-1);
    if (ret <= 0) handle_error(ret, "ssl_read hello");
    buf[ret] = '\0';
    printf("Received: %s\n", buf);

    /* Echo back */
    if ((ret = mbedtls_ssl_write(&ssl, (unsigned char *)buf, ret)) <= 0)
        handle_error(ret, "ssl_write echo");

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}
