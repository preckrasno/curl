/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_NGTCP2
#include <ngtcp2/ngtcp2.h>
#include <openssl/err.h>
#include "urldata.h"
#include "sendf.h"
#include "quic.h"
#include "quic-crypto.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define QUIC_MAX_STREAMS (256*1024)
#define QUIC_MAX_DATA (1*1024*1024)
#define QUIC_IDLE_TIMEOUT 60 /* seconds? */
#define QUIC_CIPHERS "TLS13-AES-128-GCM-SHA256:"                \
  "TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256"
#define QUIC_GROUPS "P-256:X25519:P-384:P-521"

static void quic_printf(void *user_data, const char *fmt, ...)
{
  va_list ap;
  (void)user_data; /* TODO, use this to do infof() instead long-term */
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

static void quic_settings(ngtcp2_settings *s)
{
  s->log_printf = quic_printf;
  s->initial_ts = 0;
  s->max_stream_data_bidi_local = QUIC_MAX_STREAMS;
  s->max_stream_data_bidi_remote = QUIC_MAX_STREAMS;
  s->max_stream_data_uni = QUIC_MAX_STREAMS;
  s->max_data = QUIC_MAX_DATA;
  s->max_bidi_streams = 1;
  s->max_uni_streams = 1;
  s->idle_timeout = QUIC_IDLE_TIMEOUT;
  s->max_packet_size = NGTCP2_MAX_PKT_SIZE;
  s->ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;
}

static SSL_CTX *quic_ssl_ctx(struct Curl_easy *data)
{
  SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

  /* This makes OpenSSL client not send CCS after an initial ClientHello. */
  SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

  SSL_CTX_set_default_verify_paths(ssl_ctx);

  if(SSL_CTX_set_cipher_list(ssl_ctx, QUIC_CIPHERS) != 1) {
    failf(data, "SSL_CTX_set_cipher_list: %s",
          ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  if(SSL_CTX_set1_groups_list(ssl_ctx, QUIC_GROUPS) != 1) {
    failf(data, "SSL_CTX_set1_groups_list failed");
    return NULL;
  }

  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_QUIC_HACK);

#if 0 /* FIX! */
  if(SSL_CTX_add_custom_ext(
        ssl_ctx, NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS,
        SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
        transport_params_add_cb, transport_params_free_cb, nullptr,
        transport_params_parse_cb, nullptr) != 1) {
    failf(data, "SSL_CTX_add_custom_ext(NGTCP2_TLSEXT_QUIC_TRANSPORT_"
          "PARAMETERS) failed: %s\n",
          ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  if(config.session_file) {
    SSL_CTX_set_session_cache_mode(
      ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(ssl_ctx, new_session_cb);
  }
#endif

  return ssl_ctx;
}

/** SSL callbacks ***/

static void set_tls_alert(struct connectdata *conn,
                          uint8_t alert)
{
  struct quicsocket *qs = &conn->quic;
  qs->tls_alert = alert;
}

static int ssl_on_key(struct connectdata *conn,
                      int name, const uint8_t *secret, size_t secretlen,
                      const uint8_t *key, size_t keylen, const uint8_t *iv,
                      size_t ivlen)
{
  int rv;
  uint8_t pn[64];
  ssize_t pnlen;
  struct Context *crypto_ctx = &conn->quic.crypto_ctx;

  switch(name) {
  case SSL_KEY_CLIENT_EARLY_TRAFFIC:
  case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
  case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
  case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
  case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
    break;
  default:
    return 0;
  }

  /* TODO We don't have to call this everytime we get key generated. */
  rv = Curl_qc_negotiated_prf(crypto_ctx, conn->quic.ssl);
  if(rv != 0) {
    return -1;
  }
  rv = Curl_qc_negotiated_aead(crypto_ctx, conn->quic.ssl);
  if(rv != 0) {
    return -1;
  }

  pnlen =
    Curl_qc_derive_pkt_num_protection_key(pn, sizeof(pn),
                                          secret, secretlen, crypto_ctx);
  if(pnlen < 0)
    return -1;

  /* TODO Just call this once. */
  ngtcp2_conn_set_aead_overhead(conn->quic.conn,
                                Curl_qc_aead_max_overhead(crypto_ctx));

  switch(name) {
  case SSL_KEY_CLIENT_EARLY_TRAFFIC:
    ngtcp2_conn_set_early_keys(conn->quic.conn, key, keylen, iv, ivlen,
                               pn, pnlen);
    break;
  case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
    ngtcp2_conn_set_handshake_tx_keys(conn->quic.conn, key, keylen, iv, ivlen,
                                      pn, pnlen);
    break;
  case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
    ngtcp2_conn_update_tx_keys(conn->quic.conn, key, keylen, iv, ivlen,
                               pn, pnlen);
    break;
  case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
    ngtcp2_conn_set_handshake_rx_keys(conn->quic.conn, key, keylen, iv, ivlen,
                                      pn, pnlen);
    break;
  case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
    ngtcp2_conn_update_rx_keys(conn->quic.conn, key, keylen, iv, ivlen,
                               pn, pnlen);
    break;
  }
  return 0;
}

static void ssl_msg_cb(int write_p, int version, int content_type,
                       const void *buf, size_t len, SSL *ssl, void *user_data)
{
  int rv;
  struct connectdata *conn = (struct connectdata *)user_data;
  uint8_t *msg = (uint8_t *)buf;
  (void)version;
  (void)ssl;

  if(!write_p)
    return;

  switch(content_type) {
  case SSL3_RT_HANDSHAKE:
    break;
  case SSL3_RT_ALERT:
    assert(len == 2);
    if(msg[0] != 2 /* FATAL */) {
      return;
    }
    set_tls_alert(conn, msg[1]);
    return;
  default:
    return;
  }

  rv = ngtcp2_conn_submit_crypto_data(conn->quic.conn, buf, len);
  if(rv) {
    fprintf(stderr, "write_client_handshake failed\n");
  }
  assert(0 == rv);
}

static int ssl_key_cb(SSL *ssl, int name,
                      const unsigned char *secret,
                      size_t secretlen,
                      const unsigned char *key, size_t keylen,
                      const unsigned char *iv,
                      size_t ivlen, void *arg)
{
  struct connectdata *conn = (struct connectdata *)arg;
  (void)ssl;

  if(ssl_on_key(conn, name, secret, secretlen, key, keylen, iv, ivlen) != 0)
    return 0;

  /* log_secret(ssl, name, secret, secretlen); */

  return 1;
}

static int read_server_handshake(struct connectdata *conn,
                                 char *buf, int buflen)
{
#if 0 /* FIX! */
  size_t n = CURLMIN(buflen, shandshake_.size() - nsread);
  memcpy(buf, &shandshake[nsread], n);
  nsread += n;
  return n;
#else
  (void)conn;
  (void)buf;
  (void)buflen;
  return 0;
#endif
}

/** BIO functions ***/

static int bio_write(BIO *b, const char *buf, int len)
{
  (void)b;
  (void)buf;
  (void)len;
  assert(0);
  return -1;
}

static int bio_read(BIO *b, char *buf, int len)
{
  struct connectdata *conn;
  BIO_clear_retry_flags(b);

  conn = (struct connectdata *)BIO_get_data(b);

  len = read_server_handshake(conn, buf, len);
  if(len == 0) {
    BIO_set_retry_read(b);
    return -1;
  }

  return len;
}

static int bio_puts(BIO *b, const char *str)
{
  return bio_write(b, str, (int)strlen(str));
}

static int bio_gets(BIO *b, char *buf, int len)
{
  (void)b;
  (void)buf;
  (void)len;
  return -1;
}

static long bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
  (void)b;
  (void)cmd;
  (void)num;
  (void)ptr;
  switch(cmd) {
  case BIO_CTRL_FLUSH:
    return 1;
  }

  return 0;
}

static int bio_create(BIO *b)
{
  BIO_set_init(b, 1);
  return 1;
}

static int bio_destroy(BIO *b)
{
  if(!b)
    return 0;

  return 1;
}

static BIO_METHOD *create_bio_method(void)
{
  BIO_METHOD *meth = BIO_meth_new(BIO_TYPE_FD, "bio");
  BIO_meth_set_write(meth, bio_write);
  BIO_meth_set_read(meth, bio_read);
  BIO_meth_set_puts(meth, bio_puts);
  BIO_meth_set_gets(meth, bio_gets);
  BIO_meth_set_ctrl(meth, bio_ctrl);
  BIO_meth_set_create(meth, bio_create);
  BIO_meth_set_destroy(meth, bio_destroy);
  return meth;
}


static int quic_init_ssl(struct connectdata *conn)
{
  struct quicsocket *qs = &conn->quic;
  BIO *bio;
  const uint8_t *alpn = NULL;
  size_t alpnlen;
  /* this will need some attention when HTTPS proxy over QUIC get fixed */
  const char * const hostname = conn->host.name;

  if(qs->ssl)
    SSL_free(qs->ssl);

  qs->ssl = SSL_new(qs->sslctx);
  bio = BIO_new(create_bio_method());
  /* supposedly this can fail too? */

  BIO_set_data(bio, conn);
  SSL_set_bio(qs->ssl, bio, bio);
  SSL_set_app_data(qs->ssl, conn);
  SSL_set_connect_state(qs->ssl);
  SSL_set_msg_callback(qs->ssl, ssl_msg_cb);
  SSL_set_msg_callback_arg(qs->ssl, conn);
  SSL_set_key_callback(qs->ssl, ssl_key_cb, conn);

  switch(qs->version) {
  case NGTCP2_PROTO_VER_D14:
    alpn = (const uint8_t *)NGTCP2_ALPN_D14;
    alpnlen = strlen(NGTCP2_ALPN_D14);
    break;
  }
  if(alpn)
    SSL_set_alpn_protos(qs->ssl, alpn, (int)alpnlen);

  /* set SNI */
  SSL_set_tlsext_host_name(qs->ssl, hostname);
  return 0;
}

static int quic_tls_handshake(struct connectdata *conn,
                              bool resumption,
                              bool initial)
{
  int rv;
  struct quicsocket *qs = &conn->quic;
  ERR_clear_error();

  /* Note that SSL_SESSION_get_max_early_data() and
     SSL_get_max_early_data() return completely different value. */
  if(initial && resumption &&
     SSL_SESSION_get_max_early_data(SSL_get_session(qs->ssl))) {
    size_t nwrite;
    /* OpenSSL returns error if SSL_write_early_data is called when resumption
       is not attempted.  Sending empty string is a trick to just early_data
       extension. */
    rv = SSL_write_early_data(qs->ssl, "", 0, &nwrite);
    if(rv == 0) {
      int err = SSL_get_error(qs->ssl, rv);
      switch(err) {
      case SSL_ERROR_SSL:
        fprintf(stderr, "TLS handshake error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        return -1;
      default:
        fprintf(stderr, "TLS handshake error: %d\n", err);
        return -1;
      }
    }
  }

  rv = SSL_do_handshake(qs->ssl);
  if(rv <= 0) {
    int err = SSL_get_error(qs->ssl, rv);
    switch(err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return 0;
    case SSL_ERROR_SSL:
        fprintf(stderr, "TLS handshake error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
      return -1;
    default:
      fprintf(stderr, "TLS handshake error: %d\n", err);
      return -1;
    }
  }

  /* SSL_get_early_data_status works after handshake completes. */
  if(resumption &&
     SSL_get_early_data_status(qs->ssl) != SSL_EARLY_DATA_ACCEPTED) {
    fprintf(stderr, "Early data was rejected by server\n");
    ngtcp2_conn_early_data_rejected(conn->quic.conn);
  }

  ngtcp2_conn_handshake_completed(conn->quic.conn);
  return 0;
}

static int quic_initial(ngtcp2_conn *quic, void *user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  (void)quic;
  if(quic_tls_handshake(conn, false, true) != 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  return 0;
}

static void quic_callbacks(ngtcp2_conn_callbacks *c)
{
  memset(c, 0, sizeof(ngtcp2_conn_callbacks));
  c->client_initial = quic_initial;

}


CURLcode Curl_quic_connect(struct connectdata *conn,
                           curl_socket_t sockfd,
                           const struct sockaddr *addr,
                           socklen_t addrlen)
{
  int rc;
  (void)sockfd;
  (void)addr;
  (void)addrlen;
  infof(conn->data, "Connecting socket %d over QUIC\n", sockfd);

  conn->quic.sslctx = quic_ssl_ctx(conn->data);
  if(!conn->quic.sslctx)
    return CURLE_FAILED_INIT; /* TODO: better return code */

  if(quic_init_ssl(conn))
    return CURLE_FAILED_INIT; /* TODO: better return code */

  quic_settings(&conn->quic.settings);
  quic_callbacks(&conn->quic.callbacks);

  /* ngtcp2 master branch uses version NGTCP2_PROTO_VER_D14 */
  rc = ngtcp2_conn_client_new(&conn->quic.conn,
                              &conn->quic.dcid,
                              &conn->quic.scid,
                              NGTCP2_PROTO_VER_D14,
                              &conn->quic.callbacks,
                              &conn->quic.settings, conn);
  if(rc)
    return CURLE_FAILED_INIT; /* TODO: create a QUIC error code */

  return CURLE_OK;
}

/*
 * Store ngtp2 version info in this buffer, Prefix with a space.  Return total
 * length written.
 */
int Curl_quic_ver(char *p, size_t len)
{
  return msnprintf(p, len, " ngtc2/blabla");
}

#endif
