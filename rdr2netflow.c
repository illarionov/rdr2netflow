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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "rdr.h"
#include "netflow.h"

const char *progname = "rdr2netflow";
const char *revision = "$Revision: 0.1 $";

#define DEFAULT_SRC_PORT   10000
#define DEFAULT_DST_IP     "127.0.0.1"
#define DEFAULT_DST_PORT   9995

#define DEFAULT_NETFLOW_FLUSH_TMOUT 3

struct opts_t {
   struct in_addr src_addr;
   unsigned src_port;

   struct in_addr dst_addr;
   unsigned dst_port;

   unsigned s_bufsize;

   int verbose;
};

struct rdr_session_ctx_t {
   int s;
   struct sockaddr_in remote_addr;
   struct rdr_session_ctx_t *next;
   size_t pos;
   uint8_t buf[MAX_RDR_PACKET_SIZE];

   struct {
      time_t first_packet_ts;
      time_t last_packet_ts;

      unsigned records_count;
      unsigned flow_seq;
      struct netflow_v5_export_dgram dgram;
   } netflow;

};

struct ctx_t {
   struct opts_t opts;

   struct sockaddr_in src_addr;
   struct sockaddr_in dst_addr;

   int rcv_s;
   int snd_s;

   struct rdr_session_ctx_t *rdr_sessions;
   fd_set rdr_fdset;
   int rdr_maxfd;

} Ctx;


static struct rdr_session_ctx_t *remove_session(struct ctx_t *ctx, struct rdr_session_ctx_t *session);

static volatile sig_atomic_t quit = 0;


static void usage(void)
{
   fprintf(stdout, "\nUsage:\n    %s [-h] [options]\n"
	 ,progname);
   return;
}

static void version(void)
{
   fprintf(stdout,"%s %s\n",progname,revision);
}

static void help(void)
{

 printf("%s - Cisco SCE RDR to Netflow v5 converter\t\t%s\n",
       progname, revision);
 usage();
 printf(
   "\nOptions:\n"
   "    -s <address>    Address to bind for listening (default %s)\n"
   "    -p <port>       Specifies the port number to listen (default %u)\n"
   "    -d <address>    Send netflow to this remote host (default %s)\n"
   "    -P <port>       Remote port (default %u)\n"
   "    -b <size>       Set send buffer size in bytes.\n"
   "    -V <level>      Verbose output\n"
   "    -h, --help                  Help\n"
   "    -v, --version               Show version\n"
   "\n",

   "any",
   DEFAULT_SRC_PORT,
   DEFAULT_DST_IP,
   DEFAULT_DST_PORT
 );
 return;
}

static void sig_quit(int signal) {
   quit = signal;
}

static struct ctx_t *init_ctx()
{
   Ctx.opts.src_addr.s_addr = INADDR_ANY;
   Ctx.opts.dst_addr.s_addr = inet_addr(DEFAULT_DST_IP);
   Ctx.opts.src_port = 0;
   Ctx.opts.dst_port = 0;
   Ctx.opts.s_bufsize = 0;
   Ctx.rdr_sessions = NULL;
   Ctx.rdr_maxfd = 0;
   FD_ZERO(&Ctx.rdr_fdset);

   return &Ctx;
}

static void free_ctx(struct ctx_t *ctx)
{
   if (ctx == NULL)
      return;

   if (ctx->rcv_s > 0) {
      close(ctx->rcv_s);
   }

   if (ctx->snd_s > 0) {
      close(ctx->rcv_s);
   }

   while (ctx->rdr_sessions != NULL)
      remove_session(ctx, ctx->rdr_sessions);

   ctx->rdr_maxfd = 0;
   FD_ZERO(&ctx->rdr_fdset);

}

static int init_listening_socket(struct ctx_t *ctx)
{
   int flags;

   assert(ctx);

   if (ctx->opts.verbose)
      fprintf(stderr, "Litening on %s:%u\n",
	    inet_ntoa(ctx->opts.src_addr),
	    ctx->opts.src_port != 0 ? ctx->opts.src_port : DEFAULT_SRC_PORT
	    );

   ctx->rcv_s = socket(PF_INET, SOCK_STREAM, 0);
   if (ctx->rcv_s < 0) {
      perror("socket() on listening socket error");
      return -1;
   }
   memset(&ctx->src_addr, 0, sizeof(ctx->src_addr));
   ctx->src_addr.sin_family = AF_INET;
   ctx->src_addr.sin_addr.s_addr = ctx->opts.src_addr.s_addr;
   ctx->src_addr.sin_port = htons(ctx->opts.src_port != 0 ? ctx->opts.src_port : DEFAULT_SRC_PORT);

#ifdef SO_RCVBUF
   if (ctx->opts.s_bufsize > 0) {
      unsigned rcvbuf;
      rcvbuf = ctx->opts.s_bufsize;
      if (ctx->opts.verbose)
	 fprintf(stderr, "SO_RCVBUF=%u\n", rcvbuf);
      if (setsockopt(ctx->rcv_s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
	 perror("setsockopt(SO_RCVBUF) error");
	 return -1;
      }
   }
#endif

#ifdef SO_REUSEADDR
   {
      unsigned reuseaddr = !0;
      if (setsockopt(ctx->rcv_s, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) < 0) {
	 perror("setsockopt(SO_REUSEADDR) error");
	 return -1;
      }
   }
#endif

   if (bind(ctx->rcv_s, (struct sockaddr *)&ctx->src_addr, sizeof(ctx->src_addr)) < 0) {
      perror("bind() error");
      return -1;
   }

   if (listen(ctx->rcv_s, 5) < 0) {
      perror("listen() error");
      return -1;
   }

   flags = fcntl(ctx->rcv_s, F_GETFL, 0);
   fcntl(ctx->rcv_s, F_SETFL, flags | O_NONBLOCK);

   ctx->rdr_maxfd = ctx->rcv_s;
   FD_SET(ctx->rcv_s, &ctx->rdr_fdset);

   return 0;
}

static int init_sending_socket(struct ctx_t *ctx)
{
   assert(ctx);
   if (ctx->opts.verbose)
      fprintf(stderr, "Sending to %s:%u\n",
	    inet_ntoa(ctx->opts.dst_addr),
	    ctx->opts.dst_port != 0 ? ctx->opts.dst_port : DEFAULT_DST_PORT
	    );

   ctx->snd_s = socket(PF_INET, SOCK_DGRAM, 0);
   if (ctx->rcv_s < 0) {
      perror("socket() on sending socket error");
      return -1;
   }
   memset(&ctx->dst_addr, 0, sizeof(ctx->dst_addr));
   ctx->dst_addr.sin_family = AF_INET;
   ctx->dst_addr.sin_addr.s_addr = ctx->opts.dst_addr.s_addr;
   ctx->dst_addr.sin_port = htons(ctx->opts.dst_port != 0 ? ctx->opts.dst_port : DEFAULT_DST_PORT);
   if (connect(ctx->snd_s, (struct sockaddr *)&ctx->dst_addr, sizeof(ctx->dst_addr) ) < 0) {
      perror("connect() error");
      return -1;
   }
   return 0;
}

static int accept_connection(struct ctx_t *ctx)
{
   int s;
   int flags;
   struct sockaddr_in remote_addr;
   socklen_t slen;
   struct rdr_session_ctx_t *session;

   assert(ctx);
   assert(ctx->rcv_s>=0);

   slen = sizeof(remote_addr);
   s = accept(ctx->rcv_s, (struct sockaddr *)&remote_addr, &slen);
   if (s < 0) {
      perror("accept() error");
      return -1;
   }

   session = (struct rdr_session_ctx_t *)malloc(sizeof(*session));
   if (session == NULL) {
      perror("malloc() error");
      close(s);
      return -1;
   }

   flags = fcntl(s, F_GETFL, 0);
   fcntl(s, F_SETFL, flags | O_NONBLOCK);

   session->s = s;
   session->remote_addr = remote_addr;
   session->pos = 0;

   /* Netflow ctx  */
   session->netflow.first_packet_ts = 0;
   session->netflow.flow_seq = 0;
   session->netflow.records_count = 0;
   session->netflow.dgram.header.version = htons(NETFLOW_V5);
   session->netflow.dgram.header.count = 0;
   session->netflow.dgram.header.sys_uptime = 0;
   session->netflow.dgram.header.engine_type = 0;
   session->netflow.dgram.header.engine_id = 0;
   session->netflow.dgram.header.sampling_int = 0;

   session->next = ctx->rdr_sessions;
   ctx->rdr_sessions = session;

   FD_SET(s, &ctx->rdr_fdset);
   if (s > ctx->rdr_maxfd)
      ctx->rdr_maxfd = s;

   if (ctx->opts.verbose)
      fprintf(stderr, "Accepted connection from %s:%u\n",
	    inet_ntoa(remote_addr.sin_addr),
	    (unsigned)remote_addr.sin_port
	    );

   return 0;
}

static int flush_netflow_dgram(struct ctx_t *ctx, struct rdr_session_ctx_t *session)
{
   int res;
   assert(ctx);
   assert(session);

   if (session->netflow.records_count == 0)
      return 0;

   assert(session->netflow.records_count == ntohs(session->netflow.dgram.header.count));

   res = 0;
   if (send(ctx->snd_s,
	    &session->netflow.dgram,
	    sizeof(struct netflow_v5_header) +
	       sizeof(struct netflow_v5_record) * session->netflow.records_count,
	       0) < 0) {
      if (ctx->opts.verbose) {
	 perror("send() error");
	 res = -1;
      }
   }

   session->netflow.records_count = 0;

   return res;
}

static void flush_all_netflow_sessions(struct ctx_t *ctx)
{
   struct rdr_session_ctx_t *session;
   session=ctx->rdr_sessions;
   while (session != NULL) {
      flush_netflow_dgram(ctx, session);
      session = session->next;
   }
}

static int handle_rdr_packet(struct ctx_t *ctx, struct rdr_session_ctx_t *session,
      uint8_t *raw_pkt, size_t raw_pkt_size)
{
   int err;
   unsigned long long uptime;
   unsigned duration;
   struct rdr_packet_t pkt;
   struct netflow_v5_export_dgram *dg;
   struct netflow_v5_record *rc;

   if ((err = decode_rdr_packet(raw_pkt, raw_pkt_size, &pkt)) < 0) {
      if (ctx->opts.verbose)
	 fprintf(stderr, "decode_rdr_packet() error %i\n", err);
      if (ctx->opts.verbose >= 50)
	 dump_raw_rdr_packet(stderr, 1, raw_pkt, raw_pkt_size);
      return err;
   }

   if (ctx->opts.verbose >= 10) {
      dump_rdr_packet(stderr, &pkt);
      if (ctx->opts.verbose >= 50)
	 dump_raw_rdr_packet(stderr, 0, raw_pkt, raw_pkt_size);
      fprintf(stderr, "\n");
   }

   /* Not intersted in  */
   if (pkt.header.tag != TRANSACTION_USAGE_RDR)
      return 0;

   duration = (pkt.rdr.transaction_usage.millisec_duration / 1000)
      + ((pkt.rdr.transaction_usage.millisec_duration % 1000 == 0) ? 0 : 1);

   if (pkt.rdr.transaction_usage.report_time < duration) {
      duration = 0;
   }

   if ( (session->netflow.first_packet_ts == 0)
	 || (pkt.rdr.transaction_usage.report_time - duration < session->netflow.first_packet_ts)
	 ) {
      session->netflow.first_packet_ts = pkt.rdr.transaction_usage.report_time - duration;
   }

   if (pkt.rdr.transaction_usage.report_time < session->netflow.first_packet_ts) {
      if (ctx->opts.verbose)
	 fprintf(stderr, "Time went backwards. %u => %u\n", (unsigned)session->netflow.first_packet_ts,
	       (unsigned)pkt.rdr.transaction_usage.report_time);
      session->netflow.first_packet_ts = pkt.rdr.transaction_usage.report_time - duration;
   }

   session->netflow.last_packet_ts = pkt.rdr.transaction_usage.report_time;

   assert(session->netflow.last_packet_ts >= session->netflow.first_packet_ts);

   uptime = 1000*(session->netflow.last_packet_ts - session->netflow.first_packet_ts) + 1;

   assert(uptime >= pkt.rdr.transaction_usage.millisec_duration);

   dg = &session->netflow.dgram;

   assert (session->netflow.records_count+1 < NETFLOW_V5_MAX_RECORDS);

   /* Export upstream flow  */
   dg->header.sys_uptime = htonl((uint32_t)uptime);
   dg->header.unix_secs = htonl(pkt.rdr.transaction_usage.report_time);
   dg->header.unix_nsecs = 0; /* XXX  */
   dg->header.flow_seq = htonl(++session->netflow.flow_seq);

   rc = &dg->r[session->netflow.records_count++];
   dg->header.count = htons((uint16_t)session->netflow.records_count);
   rc->src_addr = pkt.rdr.transaction_usage.client_ip.s_addr;
   rc->dst_addr = pkt.rdr.transaction_usage.server_ip.s_addr;
   rc->next_hop = 0;
   rc->i_ifx = 0;
   rc->o_ifx = 0;
   rc->packets = 0; /* XXX: ???  */
   rc->octets = htonl(pkt.rdr.transaction_usage.session_upstream_volume);
   rc->first =  htonl((uint32_t)(uptime - pkt.rdr.transaction_usage.millisec_duration));
   rc->last = htonl((uint32_t)uptime);
   rc->s_port = htons(pkt.rdr.transaction_usage.client_port);
   rc->d_port = htons(pkt.rdr.transaction_usage.server_port);
   rc->pad1 = 0;
   rc->flags = 0; //* XXX  */
   rc->prot = pkt.rdr.transaction_usage.ip_protocol;
   rc->tos = 0; /* XXX  */
   rc->src_as = 0;
   rc->dst_as = 0;
   rc->src_mask = 32;
   rc->dst_mask = 32;
   rc->pad2 = 0;

   /* Export downstream flow  */
   dg->header.flow_seq = htonl(++session->netflow.flow_seq);
   rc = &dg->r[session->netflow.records_count++];
   dg->header.count = htons((uint16_t)session->netflow.records_count);
   rc->src_addr = pkt.rdr.transaction_usage.server_ip.s_addr;
   rc->dst_addr = pkt.rdr.transaction_usage.client_ip.s_addr;
   rc->next_hop = 0;
   rc->i_ifx = 0;
   rc->o_ifx = 0;
   rc->packets = 0;
   rc->octets = htonl(pkt.rdr.transaction_usage.session_downstream_volume);
   rc->first =  htonl((uint32_t)(uptime - pkt.rdr.transaction_usage.millisec_duration));
   rc->last = htonl((uint32_t)uptime);
   rc->s_port = htons(pkt.rdr.transaction_usage.server_port);
   rc->d_port = htons(pkt.rdr.transaction_usage.client_port);
   rc->pad1 = 0;
   rc->flags = 0;
   rc->prot = pkt.rdr.transaction_usage.ip_protocol;
   rc->tos = 0;
   rc->src_as = 0;
   rc->dst_as = 0;
   rc->src_mask = 32;
   rc->dst_mask = 32;
   rc->pad2 = 0;

   if (session->netflow.records_count == NETFLOW_V5_MAX_RECORDS)
      flush_netflow_dgram(ctx, session);

   return 0;
}

static int convert_rcvd_data(struct ctx_t *ctx, struct rdr_session_ctx_t *session)
{
   size_t p;
   ssize_t truncated1, truncated2;

   if (session->pos == 0)
      return 0;

   if (ctx->opts.verbose >= 20)
      fprintf(stderr, "rcvd %i bytes from %s:%i\n",
	    (int)session->pos,
	    inet_ntoa(session->remote_addr.sin_addr),
	    (int)session->remote_addr.sin_port
	    );

   p=0;
   truncated1 = truncated2 = -1;

   /* Version?  */
   while(p < session->pos) {
      int msg_size;

      msg_size = is_rdr_packet(&session->buf[p], session->pos - p);
      if (msg_size > 0) {
	 /* RDR packet  */
	 if (handle_rdr_packet(ctx, session, &session->buf[p], msg_size) < 0) {
	    /* Invalid RDR packet  */
	    p += 1;
	 }else {
	    p += msg_size;
	    truncated1 = truncated2 = -1;
	 }
      }else if (msg_size < 0) {
	 /* Trucated RDR packet  */
	 if (truncated1 < 0)
	    truncated1 = p;
	 else if (truncated2 < 0)
	    truncated2 = p;
	 p += 1;
      }else {
	 /* Not RDR  */
	 p += 1;
      }
   } /* while  */

   assert(p <= sizeof(session->buf));

   if ( (truncated1 == 0) && (p == sizeof(session->buf)))  {
      /* Buffer full  */
      truncated1 = truncated2;
      if (truncated1 < 0)
	 fprintf(stderr, "Skipped %u garbage bytes\n", (unsigned)sizeof(session->buf));
   }

   if (truncated1 < 0) {
      session->pos = 0;
   }else if (truncated1 != 0) {
      if (ctx->opts.verbose >= 20)
	 fprintf(stderr, "Received truncated message\n");
      assert(truncated1 < (ssize_t)session->pos);
      memmove(session->buf, &session->buf[truncated1], session->pos - truncated1);
      session->pos -= truncated1;
   }

   return 0;
}

static int read_data(struct ctx_t *ctx, struct rdr_session_ctx_t *session)
{
   int rcvd_total;
   ssize_t rcvd;

   assert(ctx);
   assert(session);
   assert(session->pos < sizeof(session->buf));

   rcvd_total = 0;
   for (;;) {
      rcvd = read(session->s,
	    &session->buf[session->pos],
	    sizeof(session->buf) - session->pos
	    );
      if (rcvd == 0) {
	 /* EOF  */
	 return -1;
      }

      if (rcvd < 0) {
	 switch (errno) {
	    case EAGAIN:
	    case EINTR:
	       break;
	    default:
	       if (ctx->opts.verbose) {
		  perror("read() error");
	       }
	       return -1;
	       break;
	 }
	 break;
      }

      session->pos += rcvd;
      rcvd_total += rcvd;

      convert_rcvd_data(ctx, session);
   }

   return rcvd_total;
}

static struct rdr_session_ctx_t *remove_session(struct ctx_t *ctx, struct rdr_session_ctx_t *session)
{
   struct rdr_session_ctx_t *res, **pred;

   assert(session);

   res = session->next;

   if (ctx->rdr_sessions == session) {
      pred = &ctx->rdr_sessions;
   }else {
      struct rdr_session_ctx_t *s;
      s = ctx->rdr_sessions;
      while (s->next != session) s = s->next;
      pred = &s->next;
   }

   *pred = res;
   FD_CLR(session->s, &ctx->rdr_fdset);
   if (ctx->rdr_maxfd == session->s) {
      struct rdr_session_ctx_t *s;
      ctx->rdr_maxfd = ctx->rcv_s;
      for (s=ctx->rdr_sessions; s != NULL; s=s->next) {
	 if (s->s > ctx->rdr_maxfd)
	    ctx->rdr_maxfd = s->s;
      }
   }

   close(session->s);

   if (ctx->opts.verbose)
      fprintf(stderr, "Closed connection %s:%u\n",
	    inet_ntoa(session->remote_addr.sin_addr),
	    (unsigned)session->remote_addr.sin_port
	    );

   free(session);

   return res;
}

int main(int argc, char *argv[])
{
   signed char c;
   struct ctx_t *ctx;
   struct timeval netflow_flush_tmout;

   static struct option longopts[] = {
      {"version",     no_argument,       0, 'v'},
      {"help",        no_argument,       0, 'h'},
      {"verbose",        optional_argument,       0, 'V'},
      {NULL,      required_argument, 0, 's'},
      {NULL,      required_argument, 0, 'p'},
      {NULL,      required_argument, 0, 'd'},
      {NULL,      required_argument, 0, 'P'},
      {NULL,      required_argument, 0, 'b'},
      {0, 0, 0, 0}
   };

   ctx = init_ctx();
   assert(ctx);

   while ((c = getopt_long(argc, argv, "vhV:s:p:d:P:b:",longopts,NULL)) != -1) {
      switch (c) {
	 case 's':
	    if (inet_aton(optarg, &ctx->opts.src_addr) <= 0) {
	       fprintf(stderr, "Incorrect source address\n");
	       free_ctx(ctx);
	       return 1;
	    }
	    break;
	 case 'd':
	    if (inet_aton(optarg, &ctx->opts.dst_addr) <= 0) {
	       fprintf(stderr, "Incorrect destination address\n");
	       free_ctx(ctx);
	       return 1;
	    }
	    break;
	 case 'p':
	    ctx->opts.src_port = (unsigned)strtoul(optarg, NULL, 10);
	    if (ctx->opts.src_port == 0
		  || (ctx->opts.src_port > 0xffff)) {
	       fprintf(stderr, "Incorrent source port\n");
	       free_ctx(ctx);
	       return 1;
	    }
	    break;
	 case 'P':
	    ctx->opts.dst_port = (unsigned)strtoul(optarg, NULL, 10);
	    if (ctx->opts.dst_port == 0
		  || (ctx->opts.dst_port > 0xffff)) {
	       fprintf(stderr, "Incorrent source port\n");
	       free_ctx(ctx);
	       return 1;
	    }
	    break;
	 case 'b':
	    ctx->opts.s_bufsize = (unsigned)strtoul(optarg, NULL, 0);
	    if (ctx->opts.s_bufsize == 0) {
	       fprintf(stderr, "Incorrent buffer size\n");
	       free_ctx(ctx);
	       return 1;
	    }
	    break;
	 case 'V':
	    if (optarg != NULL) {
	       ctx->opts.verbose=(unsigned)strtoul(optarg, NULL, 0);
	    }else
	       ctx->opts.verbose=1;
	    break;
	 case 'v':
	    version();
	    free_ctx(ctx);
	    exit(0);
	    break;
	 default:
	    help();
	    free_ctx(ctx);
	    exit(0);
	    break;
      }
   }
   argc -= optind;
   argv += optind;

   /* RDR socket  */
   if (init_listening_socket(ctx) < 0) {
      free_ctx(ctx);
      return -1;
   }

   /* Netflow socket  */
   if (init_sending_socket(ctx) < 0) {
      free_ctx(ctx);
      return -1;
   }

   signal(SIGHUP, sig_quit);
   signal(SIGINT, sig_quit);
   signal(SIGTERM, sig_quit);

   for (;!quit;) {
      struct rdr_session_ctx_t *session;
      int ready_cnt;

      fd_set readfds;

      readfds = ctx->rdr_fdset;

      netflow_flush_tmout.tv_sec = DEFAULT_NETFLOW_FLUSH_TMOUT;
      netflow_flush_tmout.tv_usec = 0;

      ready_cnt = select(ctx->rdr_maxfd+1, &readfds, NULL, NULL, &netflow_flush_tmout);

      if (quit)
	 break;

      if (ready_cnt < 0)
	 break;

      if (ready_cnt ==0) {
	 flush_all_netflow_sessions(ctx);
	 continue;
      }

      if (FD_ISSET(ctx->rcv_s, &readfds)) {
	 accept_connection(ctx);
      }

      session=ctx->rdr_sessions;
      while (session != NULL) {

	 if (!FD_ISSET(session->s, &readfds)) {
	    session = session->next;
	    continue;
	 }

	 if ( read_data(ctx, session) < 0) {
	    session = remove_session(ctx, session);
	 }else
	    session = session->next;
      }

   } /* for(;!quit;) */

   signal(SIGHUP, SIG_DFL);
   signal(SIGINT, SIG_DFL);
   signal(SIGTERM, SIG_DFL);

   flush_all_netflow_sessions(ctx);
   free_ctx(ctx);
   return 0;
}

