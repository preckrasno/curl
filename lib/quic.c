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
#include "urldata.h"
#include "sendf.h"
#include "quic.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"
CURLcode Curl_quic_connect(struct connectdata *conn,
                           curl_socket_t sockfd,
                           const struct sockaddr *addr,
                           socklen_t addrlen)
{
  (void)sockfd;
  (void)addr;
  (void)addrlen;
  infof(conn->data, "Connecting socket %d over QUIC\n", sockfd);
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

