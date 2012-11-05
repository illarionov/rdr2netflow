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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>

#include "rdr.h"
#include "repeater.h"

#define RECONNECT_TIMEOUT_S 2
#define TAG "RDR Repeater:"

struct rdr_repeater_ctx_t {
   struct endpoint_t *head;
   struct endpoint_t *tail;

   unsigned s_bufsize;
   int verbose;
};

struct endpoint_t {
   const char *hostname;
   const char *servname;

   struct addrinfo *addrinfo;

   const struct addrinfo *cur_addr;

   int s;

   enum {
      S_NOT_INITIALIZED=0,
      S_CONNECTING=1,
      S_WRITING=2,
      S_WAITING=3
   } status;

   struct timespec waiting_tmout_ts;

   struct endpoint_t *next;

   int iptr, optr;
   uint8_t buf[MAX_RDR_PACKET_SIZE*2];
};


struct rdr_repeater_ctx_t *rdr_repeater_init()
{
   struct rdr_repeater_ctx_t *ctx;

   ctx = (struct rdr_repeater_ctx_t *)malloc(sizeof(*ctx));

   if (ctx == NULL)
      return NULL;

   ctx->head = NULL;
   ctx->tail = NULL;

   return ctx;
}

static void destroy_endpoint(struct endpoint_t *ep);
static int open_socket(struct rdr_repeater_ctx_t *ctx, struct endpoint_t *ep);
static int finish_socket_opening(struct rdr_repeater_ctx_t *ctx, struct endpoint_t *ep);
static void close_socket(struct rdr_repeater_ctx_t *ctx, struct endpoint_t *ep);
static int try_reopen_socket(struct rdr_repeater_ctx_t *ctx, struct endpoint_t *ep);
static const char *get_endpoint_name(struct endpoint_t *ep);

static void purge_buffer(struct endpoint_t *ep);
static int buffered_write(struct rdr_repeater_ctx_t *ctx, struct endpoint_t *ep,
      void *data, size_t data_size);


static void destroy_endpoint(struct endpoint_t *ep)
{
   assert(ep != NULL);

   free((void *)ep->hostname);
   free((void *)ep->servname);
   if (ep->s >= 0) {
      close(ep->s);
   }
   if (ep->addrinfo != NULL)
      freeaddrinfo(ep->addrinfo);

   free(ep);
}

void rdr_repeater_destroy(struct rdr_repeater_ctx_t *ctx)
{
   struct endpoint_t *ep, *next;

   assert(ctx != NULL);

   for (ep = ctx->head; ep != NULL; ep = next) {
      next = ep->next;
      destroy_endpoint(ep);
   }

   free(ctx);
}

int rdr_repeater_add_endpoint(struct rdr_repeater_ctx_t *ctx, const char *addrport, FILE *err_stream)
{
   int error;
   char *servname;
   struct endpoint_t *ep;
   struct addrinfo hints;

   assert(ctx != NULL);
   assert(addrport != NULL);

   ep = (struct endpoint_t *)malloc(sizeof(*ep));
   if (ep == NULL) {
      return -1;
   }

   ep->hostname = NULL;
   ep->servname = NULL;
   ep->addrinfo = NULL;
   ep->cur_addr = NULL;
   ep->next = NULL;
   ep->s = -1;
   ep->status = S_NOT_INITIALIZED;
   purge_buffer(ep);

   ep->hostname = strdup(addrport);
   if (ep->hostname == NULL) {
      destroy_endpoint(ep);
      if (err_stream != NULL) fprintf(err_stream, "%s strdup() error\n", TAG);
      return -1;
   }

   if (ep->hostname[0] == '\0') {
      destroy_endpoint(ep);
      if (err_stream != NULL) fprintf(err_stream, "%s empty hostname\n", TAG);
      return -1;
   }

   servname = strrchr(ep->hostname, '/');
   if (servname != NULL) {
      *servname++ = '\0';
      if (*servname == '\0')
	 ep->servname = NULL;
      else {
	 ep->servname = strdup(servname);
	 if (ep->servname == NULL) {
	    destroy_endpoint(ep);
	    if (err_stream != NULL) fprintf(err_stream, "%s strdup() error\n", TAG);
	    return -1;
	 }
      }
      if (ep->hostname[0] == '\0') {
	 free((void *)ep->hostname);
	 ep->hostname = NULL;
	 if (ep->servname == NULL) {
	    destroy_endpoint(ep);
	    if (err_stream != NULL) fprintf(err_stream, "%s hostname not defined\n", TAG);
	    return -2;
	 }
      }
   }
   assert(! ((ep->hostname == NULL) && (ep->servname == NULL)));
   if (ep->hostname != NULL)
      assert(ep->hostname[0] != '\0');
   if (ep->servname != NULL)
      assert(ep->servname[0] != '\0');

   if (ep->hostname == NULL) {
      ep->hostname = strdup(RDR_REPEATER_DEFAULT_HOST);
      if (ep->hostname == NULL) {
	 destroy_endpoint(ep);
	 if (err_stream != NULL) fprintf(err_stream, "%s strdup() error\n", TAG);
	 return -1;
      }
   }
   if (ep->servname == NULL) {
      ep->servname = strdup(RDR_REPEATER_DEFAULT_PORT);
      if (ep->servname == NULL) {
	 destroy_endpoint(ep);
	 if (err_stream != NULL) fprintf(err_stream, "%s strdup() error\n", TAG);
	 return -1;
      }
   }

   /* resolve  */
   memset(&hints, 0, sizeof(hints));
   hints.ai_family = PF_INET;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = AI_ADDRCONFIG;
   error = getaddrinfo(ep->hostname, ep->servname, &hints, &ep->addrinfo);
   if (error) {
      if (err_stream != NULL) fprintf(err_stream, "%s getaddrinfo(%s) error: %s\n",
	    TAG, addrport, gai_strerror(error));
      destroy_endpoint(ep);
      return -2;
   }
   if (ep->addrinfo == NULL) {
      if (err_stream != NULL) fprintf(err_stream, "%s No addres found for %s\n", TAG, addrport);
      destroy_endpoint(ep);
      return -2;
   }

   if (ctx->tail == NULL) {
      assert(ctx->head == NULL);
      ctx->head = ctx->tail = ep;
   }else {
      ctx->tail->next = ep;
      ctx->tail = ep;
   }

   return 1;
}

static int open_socket(struct rdr_repeater_ctx_t *ctx, struct endpoint_t *ep)
{
   int old_status;
   int flags;

   assert(ctx);
   assert(ep);

   assert(ep->status == S_NOT_INITIALIZED);
   assert(ep->s < 0);
   assert(ep->addrinfo != NULL);
   assert(ep->cur_addr != NULL);

   if (ctx->verbose > 1)
      fprintf(stderr, "%s Trying %s...\n", TAG, get_endpoint_name(ep));
   ep->s = socket(ep->cur_addr->ai_family,
	 ep->cur_addr->ai_socktype, ep->cur_addr->ai_protocol);
   if (ep->s < 0) {
      if (ctx->verbose > 1)
	 fprintf(stderr, "%s Socket() error: %s\n", TAG, strerror(errno));
      return -1;
   }

#ifdef SO_SNDBUF
   if (ctx->s_bufsize > 0) {
      unsigned sndbuf;
      sndbuf = ctx->s_bufsize;
      if (setsockopt(ep->s, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
	 perror("setsockopt(SO_SNDBUF) error");
	 close(ep->s);
	 ep->s = -1;
	 return -1;
      }
   }
#endif

   flags = fcntl(ep->s, F_GETFL, 0);
   fcntl(ep->s, F_SETFL, flags | O_NONBLOCK);

   old_status = ep->status;
   ep->status = S_CONNECTING;
   if (connect(ep->s, ep->cur_addr->ai_addr, ep->cur_addr->ai_addrlen) < 0) {
      if (errno != EINPROGRESS) {
	 if (ctx->verbose > 1)
	    fprintf(stderr, "%s connect(%s) error: %s\n", TAG, get_endpoint_name(ep),
		  strerror(errno));
	 close(ep->s);
	 ep->s = -1;
	 ep->status = old_status;
	 return -1;
      }
   }else {
      if (finish_socket_opening(ctx, ep) < 0) {
	 close(ep->s);
	 ep->s = -1;
	 ep->status = old_status;
	 return -1;
      }
   }

   return ep->s;
}

static int finish_socket_opening(struct rdr_repeater_ctx_t *ctx, struct endpoint_t *ep)
{
   socklen_t peer_name_len;
   struct sockaddr_storage peer_name;

   assert(ctx);
   assert(ep);
   assert(ep->status == S_CONNECTING);

   /* Socket ready for writing */
   peer_name_len=sizeof(peer_name);
   if (getpeername(ep->s, (struct sockaddr *)&peer_name, &peer_name_len) < 0) {
      int error;
      socklen_t error_len;

      error_len = sizeof(error);
      error = 0;
      if (errno == ENOTCONN) {
	 if (getsockopt(ep->s, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0)
	    error = errno;
      }else
	 error = errno;
      if (ctx->verbose > 1)
	 fprintf(stderr, "%s connect(%s) error: %s\n", TAG, get_endpoint_name(ep), strerror(error));
      return -1;
   }else {
      if (ctx->verbose)
	 fprintf(stderr, "%s connection with %s established successfully\n", TAG, get_endpoint_name(ep));
      ep->status = S_WRITING;
   }

   return 1;
}

static void close_socket(struct rdr_repeater_ctx_t *ctx, struct endpoint_t *ep)
{
   assert(ctx);
   assert(ep);

   if (ep->s < 0)
      return;

   close(ep->s);
   ep->s = -1;
   ep->status = S_NOT_INITIALIZED;
}

static int try_reopen_socket(struct rdr_repeater_ctx_t *ctx, struct endpoint_t *ep)
{
   assert(ctx);
   assert(ep);
   assert(ep->addrinfo);

   if (ep->status == S_WAITING) {
      struct timespec cur_time;
      /* XXX retreive current time only once, after select() */
      clock_gettime(CLOCK_MONOTONIC, &cur_time);
      if (!(cur_time.tv_sec > ep->waiting_tmout_ts.tv_sec
	    || ((cur_time.tv_sec == ep->waiting_tmout_ts.tv_sec)
	       && (cur_time.tv_nsec > ep->waiting_tmout_ts.tv_nsec) )))
	 return S_WAITING;
   }

   close_socket(ctx, ep);

   ep->status = S_NOT_INITIALIZED;

   if (ep->cur_addr == NULL)
      ep->cur_addr = ep->addrinfo;
   else
      ep->cur_addr = ep->cur_addr->ai_next;

   while (ep->cur_addr != NULL) {
      open_socket(ctx, ep);
      if (ep->status != S_NOT_INITIALIZED)
	 return ep->status;
      ep->cur_addr = ep->cur_addr->ai_next;
   }

   ep->status = S_WAITING;
   clock_gettime(CLOCK_MONOTONIC, &ep->waiting_tmout_ts);
   ep->waiting_tmout_ts.tv_sec += RECONNECT_TIMEOUT_S;
   return S_WAITING;
}

int rdr_repeater_init_connection(struct rdr_repeater_ctx_t *ctx, unsigned socket_buf_size, int verbose)
{
   struct endpoint_t *ep;

   assert(ctx);

   ctx->s_bufsize = socket_buf_size;
   ctx->verbose = verbose;

   if (ctx->verbose && (ctx->head != NULL)) {
      fprintf(stderr, "Repeat all incoming TCP packets to hosts: ");
      for (ep = ctx->head; ep != NULL; ep = ep->next) {
	 fprintf(stderr, "%s%s", get_endpoint_name(ep), ep->next == NULL ? "\n" : ", ");
      }
   }

   for (ep = ctx->head; ep != NULL; ep = ep->next) {
      purge_buffer(ep);
      try_reopen_socket(ctx, ep);
      assert(ep->status != S_NOT_INITIALIZED);
   }

   return 1;
}

int rdr_repeater_step(struct rdr_repeater_ctx_t *ctx, fd_set *readfds, fd_set *writefds)
{
   struct endpoint_t *ep;

   assert(ctx);
   assert(readfds);
   assert(writefds);

   for (ep = ctx->head; ep != NULL; ep = ep->next) {
      switch (ep->status) {
	 case S_CONNECTING:
	    assert(ep->s >= 0);

	    if (!FD_ISSET(ep->s, writefds))
	       break;

	    /* Socket ready for writing */
	    if (finish_socket_opening(ctx, ep) < 0) {
	       try_reopen_socket(ctx, ep);
	    }
	    break;
	 case S_WRITING:
	    assert(ep->s >= 0);

	    if (FD_ISSET(ep->s, readfds)) {
	       ssize_t rcvd;
	       unsigned char buf[1];
	       tcflush(ep->s, TCIFLUSH);
	       rcvd = read(ep->s, &buf, 1);
	       if (rcvd == 0) {
		  if (ctx->verbose)
		     fprintf(stderr, "%s Connection %s closed \n", TAG, get_endpoint_name(ep));
		  try_reopen_socket(ctx, ep);
		  break;
	       }else if (rcvd < 0) {
		  if (errno != EAGAIN && (errno != EINTR)) {
		     if (ctx->verbose)
			fprintf(stderr, "%s %s read() error: %s\n", TAG, get_endpoint_name(ep), strerror(errno));
		     try_reopen_socket(ctx, ep);
		     break;
		  }
	       }
	    }

	    if (FD_ISSET(ep->s, writefds))
	       buffered_write(ctx, ep, NULL, 0);
	    break;
	 case S_WAITING:
	    try_reopen_socket(ctx, ep);
	    break;
	 case S_NOT_INITIALIZED:
	 default:
	    /* UNREACHABLE  */
	    assert(0);
	    break;
      }
   }

   return 1;
}

void rdr_repeater_on_select(struct rdr_repeater_ctx_t *ctx, fd_set *readfds, fd_set *writefds, int *maxfd)
{
   int cur_maxfd;
   struct endpoint_t *ep;

   assert(ctx);
   assert(maxfd);

   cur_maxfd = -1;
   for (ep = ctx->head; ep != NULL; ep = ep->next) {
      switch (ep->status) {
	 case S_CONNECTING:
	    FD_SET(ep->s, writefds);
	    if (ep->s > cur_maxfd)
	       cur_maxfd = ep->s;
	    break;
	 case S_WRITING:
	    FD_SET(ep->s, readfds);
	    if (ep->s > cur_maxfd)
	       cur_maxfd = ep->s;
	    if (ep->iptr != ep->optr)
	       FD_SET(ep->s, writefds);
	 case S_WAITING:
	    break;
	 case S_NOT_INITIALIZED:
	 default:
	    /* UNREACHABLE  */
	    assert(0);
	    break;
      }
   }

   *maxfd = cur_maxfd;
}

static const char *get_endpoint_name(struct endpoint_t *ep)
{
   static char res[80];
   void *in_addr;
   unsigned port;
   char addr[INET6_ADDRSTRLEN+1];

   assert(ep);

   if (ep->cur_addr == NULL) {
      snprintf(res, sizeof(res), "%s/%s",
	    ep->hostname == NULL ? "" : ep->hostname,
	    ep->servname == NULL ? "" : ep->servname
	    );
   }else {
      if (ep->cur_addr->ai_addr->sa_family == AF_INET) {
	 struct sockaddr_in *sin = (struct sockaddr_in *)ep->cur_addr->ai_addr;
	 in_addr = &sin->sin_addr;
	 port = ntohs(sin->sin_port);
      }else {
	 struct sockaddr_in6 *sin;
	 assert(ep->cur_addr->ai_addr->sa_family == AF_INET6);
	 sin = (struct sockaddr_in6 *)ep->cur_addr->ai_addr;
	 in_addr = &sin->sin6_addr;
	 port = ntohs(sin->sin6_port);
      }

      if (inet_ntop(ep->cur_addr->ai_addr->sa_family, in_addr, addr, sizeof(addr)) == NULL) {
	 addr[0]=0;
      }

      snprintf(res, sizeof(res), "%s/%u", addr, port);
   }

   return res;
}


static void purge_buffer(struct endpoint_t *ep)
{
   assert(ep);
   ep->iptr = ep->optr = 0;
}

void rdr_repeater_append(struct rdr_repeater_ctx_t *ctx, void *data, size_t data_size)
{
   struct endpoint_t *ep;

   assert(ctx);

   for (ep = ctx->head; ep != NULL; ep = ep->next) {
      buffered_write(ctx, ep, data, data_size);
   }

}

static int buffered_write(struct rdr_repeater_ctx_t *ctx, struct endpoint_t *ep,
      void *data, size_t data_size)
{
   ssize_t written;

   assert(ctx);
   assert(ep);

   /* TODO useless memory move */
   if (data != NULL) {
      /* Append data */
      if (sizeof(ep->buf) < data_size) {
	 if (ctx->verbose >= 10)
	    fprintf(stderr, "%s %s Buffer overflow. %u bytes packet skipped\n",
		  TAG, get_endpoint_name(ep), (unsigned)data_size);
	 return 0;
      }

      if (sizeof(ep->buf) - ep->iptr < data_size) {
	 if (sizeof(ep->buf) - ep->iptr + ep->optr >= data_size) {
	    memmove(ep->buf, &ep->buf[ep->optr], ep->iptr - ep->optr);
	    ep->iptr -= ep->optr;
	    ep->optr = 0;
	 }else {
	    if (ctx->verbose >= 10)
	       fprintf(stderr, "%s %s Buffer overflow. %u bytes skipped\n",
		     TAG, get_endpoint_name(ep), ep->iptr+1);
	    purge_buffer(ep);
	 }
      }
      assert(ep->iptr + data_size <= sizeof(ep->buf));
      memcpy(&ep->buf[ep->iptr], data, data_size);
      ep->iptr += data_size;
   }

   if (ep->status != S_WRITING)
      return 0;

   if (ep->iptr == ep->optr) {
      if (data == NULL) {
	 int error;
	 socklen_t error_len;

	 /* No data. Check socket status  */
	 error = 0;
	 error_len = sizeof(error);
	 if (getsockopt(ep->s, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0)
	    error = errno;
	 if (error != 0) {
	    if (ctx->verbose)
	       fprintf(stderr, "%s %s socket error: %s\n", TAG, get_endpoint_name(ep), strerror(error));
	    try_reopen_socket(ctx, ep);
	    return -1;

	 }
      }
      return 0;
   }

   assert(ep->optr < ep->iptr);

   written = write(ep->s, &ep->buf[ep->optr], ep->iptr - ep->optr);
   if (written < 0) {
      if (errno == EAGAIN || (errno == EINTR))
	 return 0;
      /* Error  */
      if (ctx->verbose)
	 fprintf(stderr, "%s write() error: %s\n", TAG, strerror(errno));
      try_reopen_socket(ctx, ep);
   }else {
      ep->optr += written;
      if (ep->optr == ep->iptr)
	 ep->iptr = ep->optr = 0;
   }

   return written;
}

