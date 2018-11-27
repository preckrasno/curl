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
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "quic-crypto.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

int Curl_qc_negotiated_prf(struct Context *ctx, SSL *ssl)
{
  switch(SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case 0x03001301u: /* TLS_AES_128_GCM_SHA256 */
  case 0x03001303u: /* TLS_CHACHA20_POLY1305_SHA256 */
    ctx->prf = EVP_sha256();
    return 0;
  case 0x03001302u: /* TLS_AES_256_GCM_SHA384 */
    ctx->prf = EVP_sha384();
    return 0;
  default:
    return -1;
  }
}

int Curl_qc_negotiated_aead(struct Context *ctx, SSL *ssl)
{
  switch(SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case 0x03001301u: /* TLS_AES_128_GCM_SHA256 */
    ctx->aead = EVP_aes_128_gcm();
    ctx->pn = EVP_aes_128_ctr();
    return 0;
  case 0x03001302u: /* TLS_AES_256_GCM_SHA384 */
    ctx->aead = EVP_aes_256_gcm();
    ctx->pn = EVP_aes_256_ctr();
    return 0;
  case 0x03001303u: /* TLS_CHACHA20_POLY1305_SHA256 */
    ctx->aead = EVP_chacha20_poly1305();
    ctx->pn = EVP_chacha20();
    return 0;
  default:
    return -1;
  }
}

static int hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret,
                       size_t secretlen, const uint8_t *info, size_t infolen,
                       const struct Context *ctx)
{
  void *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if(!pctx)
    return -1;

  if(EVP_PKEY_derive_init(pctx) != 1)
    goto err;

  if(EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1)
    goto err;

  if(EVP_PKEY_CTX_set_hkdf_md(pctx, ctx->prf) != 1)
    goto err;

  if(EVP_PKEY_CTX_set1_hkdf_salt(pctx, "", 0) != 1)
    goto err;

  if(EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, (int)secretlen) != 1)
    goto err;

  if(EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)infolen) != 1)
    goto err;

  if(EVP_PKEY_derive(pctx, dest, &destlen) != 1)
    goto err;

  return 0;
  err:
  EVP_PKEY_CTX_free(pctx);
  return -1;
}

static int qhkdf_expand(uint8_t *dest, size_t destlen,
                        const uint8_t *secret, size_t secretlen,
                        const uint8_t *qlabel, size_t qlabellen,
                        const struct Context *ctx)
{
  uint8_t info[256];
  static const char LABEL[] = "quic ";

  uint8_t *p = &info[0];
  *p++ = (destlen / 256) & 0xff;
  *p++ = destlen % 256;
  *p++ = (strlen(LABEL) + qlabellen) & 0xff;
  memcpy(p, LABEL, strlen(LABEL));
  p += strlen(LABEL);
  memcpy(p, qlabel, qlabellen);
  p += qlabellen;
  *p++ = 0;

  return hkdf_expand(dest, destlen, secret, secretlen, &info[0],
                     p - &info[0], ctx);
}

static size_t aead_key_length(const struct Context *ctx)
{
  return EVP_CIPHER_key_length(ctx->aead);
}

ssize_t Curl_qc_derive_pkt_num_protection_key(uint8_t *dest,
                                              size_t destlen,
                                              const uint8_t *secret,
                                              size_t secretlen,
                                              const struct Context *ctx)
{
  int rv;
  static uint8_t LABEL_PKNKEY[] = "pn";

  size_t keylen = aead_key_length(ctx);
  if(keylen > destlen)
    return -1;

  rv = qhkdf_expand(dest, keylen, secret, secretlen, LABEL_PKNKEY,
                    strlen((char *)LABEL_PKNKEY), ctx);

  if(rv != 0) {
    return -1;
  }

  return keylen;
}

static size_t aead_tag_length(const struct Context *ctx)
{
  if(ctx->aead == EVP_aes_128_gcm() || ctx->aead == EVP_aes_256_gcm()) {
    return EVP_GCM_TLS_TAG_LEN;
  }
  if(ctx->aead == EVP_chacha20_poly1305()) {
    return EVP_CHACHAPOLY_TLS_TAG_LEN;
  }
  assert(0);
}

size_t Curl_qc_aead_max_overhead(const struct Context *ctx)
{
  return aead_tag_length(ctx);
}


#endif
