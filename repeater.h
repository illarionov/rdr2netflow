/*-
 * Copyright (c) 2012 Alexey Illarionov <littlesavage@rambler.ru>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _REPEATER_H
#define _REPEATER_H

#define RDR_REPEATER_DEFAULT_HOST "127.0.0.1"
#define RDR_REPEATER_DEFAULT_PORT "10001"

struct rdr_repeater_ctx_t *rdr_repeater_init();
void rdr_repeater_destroy(struct rdr_repeater_ctx_t *ctx);
int rdr_repeater_add_endpoint(struct rdr_repeater_ctx_t *ctx, const char *addrport, FILE *err_stream);

int rdr_repeater_init_connection(struct rdr_repeater_ctx_t *ctx, unsigned socket_buf_size, int verbose);
void rdr_repeater_on_select(struct rdr_repeater_ctx_t *ctx, fd_set *readfds, fd_set *writefds, int *maxfd);
int rdr_repeater_step(struct rdr_repeater_ctx_t *ctx, fd_set *readfds, fd_set *writefds);
void rdr_repeater_append(struct rdr_repeater_ctx_t *ctx, void *data, size_t data_size);


#endif /* _RDR_REPEATER_H  */
