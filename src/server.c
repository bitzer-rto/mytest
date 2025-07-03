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
#include <mbedtls/gcm.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/md.h>
#include <sys/stat.h>

typedef struct {
    unsigned char client_random[32];
    unsigned char server_random[32];
} export_state_t;

static int export_cb(void *ctx,
                     const unsigned char *ms,
                     const unsigned char *kb,
                     size_t maclen, size_t keylen, size_t ivlen,
                     const unsigned char client_random[32],
                     const unsigned char server_random[32],
                     mbedtls_tls_prf_types tls_prf_type)
{
    export_state_t *st = (export_state_t *)ctx;
    (void)ms; (void)kb; (void)maclen; (void)keylen; (void)ivlen; (void)tls_prf_type;
    memcpy(st->client_random, client_random, 32);
    memcpy(st->server_random, server_random, 32);
    return 0;
}


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
    mbedtls_pk_context pkey;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    const int ciphersuites[] = { MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0 };

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "abc_server";
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers))) != 0)
        handle_error(ret, "ctr_drbg_seed");

    if ((ret = mbedtls_x509_crt_parse_file(&srvcert, "server.crt")) != 0)
        handle_error(ret, "x509_crt_parse_file");


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
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);

    export_state_t exp_state;
    memset(&exp_state, 0, sizeof(exp_state));
    mbedtls_ssl_conf_export_keys_ext_cb(&conf, export_cb, &exp_state);

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

    unsigned char fingerprint[32];
    mbedtls_sha256_ret(peer->raw.p, peer->raw.len, fingerprint, 0);
    unsigned char pinned[32];
    int have_pinned = 0;
    FILE *fp = fopen("trusted_client.sha256", "rb");
    if (fp) {
        if (fread(pinned, 1, sizeof(pinned), fp) == sizeof(pinned))
            have_pinned = 1;
        fclose(fp);
    }
    if (have_pinned && memcmp(pinned, fingerprint, 32) != 0) {
        fprintf(stderr, "Pinned client certificate mismatch\n");
        return 1;
    }

    unsigned char lenbuf[4];
    if ((ret = ssl_read_exact(&ssl, lenbuf, sizeof(lenbuf))) != 0)
        handle_error(ret, "ssl_read len");
    size_t enclen = ((size_t)lenbuf[0] << 24) | ((size_t)lenbuf[1] << 16) |
                    ((size_t)lenbuf[2] << 8) | (size_t)lenbuf[3];
    unsigned char iv[12];
    unsigned char tag[16];
    if ((ret = ssl_read_exact(&ssl, iv, sizeof(iv))) != 0)
        handle_error(ret, "ssl_read iv");
    if ((ret = ssl_read_exact(&ssl, tag, sizeof(tag))) != 0)
        handle_error(ret, "ssl_read tag");
    unsigned char *enc = malloc(enclen);
    if (!enc) return 1;
    if ((ret = ssl_read_exact(&ssl, enc, enclen)) != 0)
        handle_error(ret, "ssl_read enc");

    unsigned char seed[64];
    memcpy(seed, exp_state.client_random, 32);
    memcpy(seed + 32, exp_state.server_random, 32);
    unsigned char salt[32];
    mbedtls_sha256_ret(seed, sizeof(seed), salt, 0);
    unsigned char key[32];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if ((ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, (const unsigned char *)password,
                                         strlen(password), salt, sizeof(salt),
                                         1000, sizeof(key), key)) != 0)
        handle_error(ret, "pbkdf2");
    mbedtls_md_free(&md_ctx);

    unsigned char *dec = malloc(enclen);
    if (!dec) return 1;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if ((ret = mbedtls_gcm_auth_decrypt(&gcm, enclen, iv, sizeof(iv),
                                        NULL, 0, tag, sizeof(tag),
                                        enc, dec)) != 0)
        handle_error(ret, "gcm_decrypt");
    mbedtls_gcm_free(&gcm);
    free(enc);

    if (peer->raw.len != enclen || memcmp(peer->raw.p, dec, enclen) != 0) {
        fprintf(stderr, "Certificate mismatch\n");
        free(dec);
        return 1;
    }
    free(dec);

    if (!have_pinned) {
        fp = fopen("trusted_client.sha256", "wb");
        if (fp) {
            fwrite(fingerprint, 1, sizeof(fingerprint), fp);
            fclose(fp);
        }
    }

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
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}
