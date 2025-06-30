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

int main(int argc, char *argv[])
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <server_ip> <port> <password>\n", argv[0]);
        return 1;
    }
    const char *server_ip = argv[1];
    const char *port = argv[2];
    const char *password = argv[3];

    int ret;
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt clicert;
    mbedtls_x509_crt servercert;
    mbedtls_pk_context pkey;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    const int ciphersuites[] = { MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0 };

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&clicert);
    mbedtls_x509_crt_init(&servercert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "abc_client";
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers))) != 0)
        handle_error(ret, "ctr_drbg_seed");

    if ((ret = mbedtls_x509_crt_parse_file(&clicert, "client.crt")) != 0)
        handle_error(ret, "x509_crt_parse_file");

    if ((ret = mbedtls_x509_crt_parse_file(&servercert, "server.crt")) != 0)
        handle_error(ret, "x509_crt_parse_file server");

    if ((ret = mbedtls_pk_parse_keyfile(&pkey, "client.key", NULL)) != 0)
        handle_error(ret, "pk_parse_keyfile");

    if ((ret = mbedtls_net_connect(&server_fd, server_ip, port, MBEDTLS_NET_PROTO_TCP)) != 0)
        handle_error(ret, "net_connect");

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
        handle_error(ret, "ssl_config_defaults");

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);
    mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
        handle_error(ret, "ssl_setup");

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    if ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
        handle_error(ret, "ssl_handshake");

    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&ssl);
    if (!peer) {
        fprintf(stderr, "No server certificate received\n");
        return 1;
    }

    unsigned char fingerprint[32];
    unsigned char expected_fp[32];
    mbedtls_sha256_ret(peer->raw.p, peer->raw.len, fingerprint, 0);
    mbedtls_sha256_ret(servercert.raw.p, servercert.raw.len, expected_fp, 0);
    if (memcmp(fingerprint, expected_fp, 32) != 0) {
        fprintf(stderr, "Unexpected server certificate\n");
        return 1;
    }
    FILE *fp = fopen("server_fingerprint.sha256", "wb");
    if (fp) {
        fwrite(fingerprint, 1, sizeof(fingerprint), fp);
        fclose(fp);
    }

    /* Send client certificate */
    size_t cert_len = clicert.raw.len;
    unsigned char *buf = malloc(cert_len);
    if (!buf) return 1;
    memcpy(buf, clicert.raw.p, cert_len);
    unsigned char h1[32];
    mbedtls_sha256_ret(buf, cert_len, h1, 0);
    printf("cert sha256: ");
    for(int i=0;i<32;i++) printf("%02x", h1[i]);
    printf("\n");

    unsigned char lenbuf[4];
    lenbuf[0] = (cert_len >> 24) & 0xff;
    lenbuf[1] = (cert_len >> 16) & 0xff;
    lenbuf[2] = (cert_len >> 8) & 0xff;
    lenbuf[3] = cert_len & 0xff;

    if ((ret = mbedtls_ssl_write(&ssl, lenbuf, 4)) <= 0)
        handle_error(ret, "ssl_write len");
    size_t written = 0;
    while (written < cert_len) {
        ret = mbedtls_ssl_write(&ssl, buf + written, cert_len - written);
        if (ret <= 0)
            handle_error(ret, "ssl_write enc");
        written += ret;
    }
    free(buf);

    if ((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)password,
                                 strlen(password))) <= 0)
        handle_error(ret, "ssl_write password");

    const char *hello = "hello";
    if ((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)hello, strlen(hello))) <= 0)
        handle_error(ret, "ssl_write hello");

    unsigned char reply[64];
    ret = mbedtls_ssl_read(&ssl, reply, sizeof(reply)-1);
    if (ret <= 0)
        handle_error(ret, "ssl_read reply");
    reply[ret] = '\0';
    printf("Server replied: %s\n", reply);

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_x509_crt_free(&clicert);
    mbedtls_x509_crt_free(&servercert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}
