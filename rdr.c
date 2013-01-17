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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "rdr.h"

static int get_string_field(uint8_t *pkt, size_t pkt_size,
      size_t *field_pos, char *dst, size_t dst_buf_size);
static int get_int8_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, int *res);
static int get_uint8_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, unsigned *res);
static int get_int16_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, int *res);
static int get_uint16_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, unsigned *res);
static int get_int32_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, int *res);
static int get_uint32_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, unsigned *res);
static int get_ip_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, struct in_addr *ip);
static int get_time_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, time_t *time);

/*
 * >0 - RDR packet (size)
 * =0 - not RDR
 * <0 - truncated packet
 */
int is_rdr_packet(void *data, size_t data_size)
{
   uint8_t *buf;
   size_t payload_size;

   assert(data);
   assert(data_size>0);

   buf = (uint8_t *)data;

   /*  ??? XXX: wrong */
//   if (buf[0] < 0x01 || buf[0] > 0xff)
//      return 0;

   if (data_size < 5)
      return -1;

   /* Payload size  */
   if (buf[1] < '0' || buf[1] > '9')
      return 0;

   if (buf[2] < '0' || buf[2] > '9')
      return 0;

   if (buf[3] < '0' || buf[3] > '9')
      return 0;

   if (buf[4] < '0' || buf[4] > '9')
      return 0;

   payload_size = (buf[1] - '0') * 1000
      + (buf[2] - '0') * 100
      + (buf[3] - '0') * 10
      + (buf[4] - '0');

   if (payload_size < 15)
      return 0;

   if (payload_size + 5 > data_size)
      return -1;

   return payload_size+5;
}

static int decode_rdr_packet_header(void *data, size_t data_size, struct rdr_packet_t *res)
{
   int packet_size;
   struct rdrv1_header_t *rdr_header;

   packet_size = is_rdr_packet(data, data_size);

   if (packet_size <= 0)
      return packet_size;

   rdr_header = (struct rdrv1_header_t *)data;

   res->header.ppc_num = rdr_header->ppc_num;
   res->header.payload_size = packet_size-5;
   res->header.src = rdr_header->src;
   res->header.dst = rdr_header->dst;
   res->header.src_port = ntohs(rdr_header->src_port);
   res->header.dst_port = ntohs(rdr_header->dst_port);
   res->header.fc_id = ntohl(rdr_header->fc_id);
   res->header.tag = ntohl(rdr_header->tag);
   res->header.field_cnt = rdr_header->field_cnt;

   return packet_size;
}

int decode_rdr_packet(void *data, size_t data_size, struct rdr_packet_t *res)
{
   size_t field_pos;
   int packet_size;
   int err;
   struct rdrv1_header_t *rdr_header;

   assert(data);
   assert(data_size);
   assert(res);
   assert(sizeof(*rdr_header) == 20);

   rdr_header = (struct rdrv1_header_t *)data;
   field_pos = sizeof(*rdr_header);
   packet_size = decode_rdr_packet_header(data, data_size, res);
   if (packet_size < 0)
      return packet_size;

   err = 0;
   switch (res->header.tag) {
      case TRANSACTION_RDR:
	 if (rdr_header->field_cnt < 25) {
	    err = -1;
	    break;
	 }
#define GET_FIELD(_Func, _Field) \
	 err = get_ ## _Func ## _field((uint8_t *)data, data_size, \
	       &field_pos, &res->rdr._Field ); \
	 if (err < 0) { /* fprintf(stderr, "error decoding field " #_Field "\n" ); */ \
	    break; }

	 /* 1. STRING subscriber_id  */
	 err = get_string_field((uint8_t *)data, data_size,
	       &field_pos, res->rdr.transaction.subscriber_id,
	       sizeof(res->rdr.transaction.subscriber_id));
	 if (err < 0) break;
	 GET_FIELD(int16, transaction.package_id)
	 GET_FIELD(int32, transaction.service_id)
	 GET_FIELD(int16, transaction.protocol_id)
	 GET_FIELD(int32, transaction.skipped_sessions) /* XXX  */
	 /* 6. UINT32 server_ip  */
	 GET_FIELD(ip, transaction.server_ip)
	 GET_FIELD(uint16, transaction.server_port)
	 err = get_string_field((uint8_t *)data, data_size,
	       &field_pos, res->rdr.transaction.access_string,
	       sizeof(res->rdr.transaction.access_string));
	 if (err < 0) break;
	 err = get_string_field((uint8_t *)data, data_size,
	       &field_pos, res->rdr.transaction.info_string,
	       sizeof(res->rdr.transaction.info_string));
	 if (err < 0) break;
	 GET_FIELD(ip, transaction.client_ip)
	 GET_FIELD(uint16, transaction.client_port)
	 /* 12 INT8 initiating_side  */
	 GET_FIELD(int8, transaction.initiating_side)
	 GET_FIELD(time, transaction.report_time)
	 GET_FIELD(uint32, transaction.millisec_duration)
	 GET_FIELD(int8, transaction.time_frame)
	 GET_FIELD(uint32, transaction.session_upstream_volume)
	 GET_FIELD(uint32, transaction.session_downstream_volume)
	 /* 18 UINT16 subscriber_counter_id  */
	 GET_FIELD(uint16, transaction.subscriber_counter_id)
	 GET_FIELD(uint16, transaction.global_counter_id)
	 GET_FIELD(uint16, transaction.package_counter_id)
	 GET_FIELD(uint8, transaction.ip_protocol)
	 GET_FIELD(int32, transaction.protocol_signature)
	 GET_FIELD(int32, transaction.zone_id)
	 /* 24 INT32 flavor_id  */
	 GET_FIELD(int32, transaction.flavor_id)
	 GET_FIELD(uint8, transaction.flow_close_mode)
	 break;

      case TRANSACTION_USAGE_RDR:
	 if (rdr_header->field_cnt < 25) {
	    return -1;
	 }
	 /* 1. STRING subscriber_id  */
	 err = get_string_field((uint8_t *)data, data_size,
	       &field_pos, res->rdr.transaction_usage.subscriber_id,
	       sizeof(res->rdr.transaction_usage.subscriber_id));
	 if (err < 0) break;
	 GET_FIELD(int16, transaction_usage.package_id)
	 GET_FIELD(int32, transaction_usage.service_id)
	 GET_FIELD(int16, transaction_usage.protocol_id)
	 GET_FIELD(uint32, transaction_usage.generation_reason)
	 /* 6. UINT32 server_ip  */
	 GET_FIELD(ip, transaction_usage.server_ip)
	 GET_FIELD(uint16, transaction_usage.server_port)
	 err = get_string_field((uint8_t *)data, data_size,
	       &field_pos, res->rdr.transaction_usage.access_string,
	       sizeof(res->rdr.transaction_usage.access_string));
	 if (err < 0) break;
	 err = get_string_field((uint8_t *)data, data_size,
	       &field_pos, res->rdr.transaction_usage.info_string,
	       sizeof(res->rdr.transaction_usage.info_string));
	 if (err < 0) break;
	 GET_FIELD(ip, transaction_usage.client_ip)
	 GET_FIELD(uint16, transaction_usage.client_port)
	 /* 12 INT8 initiating_side  */
	 GET_FIELD(int8, transaction_usage.initiating_side)
	 GET_FIELD(time, transaction_usage.report_time)
	 GET_FIELD(uint32, transaction_usage.millisec_duration)
	 GET_FIELD(int8, transaction_usage.time_frame)
	 GET_FIELD(uint32, transaction_usage.session_upstream_volume)
	 GET_FIELD(uint32, transaction_usage.session_downstream_volume)
	 /* 18 UINT16 subscriber_counter_id  */
	 GET_FIELD(uint16, transaction_usage.subscriber_counter_id)
	 GET_FIELD(uint16, transaction_usage.global_counter_id)
	 GET_FIELD(uint16, transaction_usage.package_counter_id)
	 GET_FIELD(uint8, transaction_usage.ip_protocol)
	 GET_FIELD(int32, transaction_usage.protocol_signature)
	 GET_FIELD(int32, transaction_usage.zone_id)
	 /* 24 INT32 flavor_id  */
	 GET_FIELD(int32, transaction_usage.flavor_id)
	 GET_FIELD(uint8, transaction_usage.flow_close_mode)
	 break;
      default:
	 /* Not implemented  */
	 break;
   }
#undef GET_FIELD

   return err >= 0 ? packet_size : err;
}

static int get_string_field(uint8_t *pkt, size_t pkt_size,
      size_t *field_pos, char *dst, size_t dst_buf_size)
{
   struct rdrv1_field_t *field;
   size_t string_size;

   assert(pkt);
   assert(field_pos);
   assert(sizeof(*field)==5);

   if (*field_pos+sizeof(*field) > pkt_size)
      return -1;

   field = (struct rdrv1_field_t *)&pkt[*field_pos];

   if (field->type != RDR_TYPE_STRING)
      return -RDR_TYPE_STRING;

   string_size = ntohl(field->size);

   if (*field_pos+sizeof(*field)+string_size > pkt_size)
      return -1;

   memcpy(dst, field->data, string_size < dst_buf_size ? string_size : dst_buf_size);
   if (string_size + 1 < dst_buf_size)
      dst[string_size] = '\0';
   dst[dst_buf_size-1] = '\0';

   *field_pos += sizeof(*field) + string_size;

   return string_size+sizeof(*field);
}

static int get_int8_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, int *res)
{
   struct rdrv1_field_t *field;
   size_t payload_size;

   assert(pkt);
   assert(field_pos);
   assert(res);

   if (*field_pos+sizeof(*field) > pkt_size)
      return -1;

   field = (struct rdrv1_field_t *)&pkt[*field_pos];

   if (field->type != RDR_TYPE_INT8)
      return -RDR_TYPE_INT8;

   payload_size = ntohl(field->size);

   if (payload_size != 1)
      return -1;

   if (*field_pos+sizeof(*field)+payload_size > pkt_size)
      return -1;

   *res = (int)( ((int8_t *)field->data)[0]  );

   *field_pos += sizeof(*field) + payload_size;

   return payload_size+sizeof(*field);
}

static int get_uint8_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, unsigned *res)
{
   struct rdrv1_field_t *field;
   size_t payload_size;

   assert(pkt);
   assert(field_pos);
   assert(res);

   if (*field_pos+sizeof(*field) > pkt_size)
      return -1;

   field = (struct rdrv1_field_t *)&pkt[*field_pos];

   if (field->type != RDR_TYPE_UINT8)
      return -RDR_TYPE_UINT8;

   payload_size = ntohl(field->size);

   if (payload_size != 1)
      return -1;

   if (*field_pos+sizeof(*field)+payload_size > pkt_size)
      return -1;

   *res = (unsigned)field->data[0];

   *field_pos += sizeof(*field) + payload_size;

   return payload_size+sizeof(*field);
}

static int get_int16_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, int *res)
{
   struct rdrv1_field_t *field;
   size_t payload_size;
   union {
      uint16_t u16;
      int16_t i16;
   } pp;

   assert(pkt);
   assert(field_pos);
   assert(res);

   if (*field_pos+sizeof(*field) > pkt_size)
      return -1;

   field = (struct rdrv1_field_t *)&pkt[*field_pos];

   if (field->type != RDR_TYPE_INT16)
      return -RDR_TYPE_INT16;

   payload_size = ntohl(field->size);

   if (payload_size != 2)
      return -1;

   if (*field_pos+sizeof(*field)+payload_size > pkt_size)
      return -1;

   memcpy(&pp.u16, field->data, sizeof(pp.u16));
   pp.u16 = ntohs(pp.u16);
   *res = (int)pp.i16;

   *field_pos += sizeof(*field) + payload_size;

   return payload_size+sizeof(*field);
}

static int get_uint16_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, unsigned *res)
{
   struct rdrv1_field_t *field;
   size_t payload_size;
   uint16_t tmp;

   assert(pkt);
   assert(field_pos);
   assert(res);

   if (*field_pos+sizeof(*field) > pkt_size)
      return -1;

   field = (struct rdrv1_field_t *)&pkt[*field_pos];

   if (field->type != RDR_TYPE_UINT16)
      return -RDR_TYPE_UINT16;

   payload_size = ntohl(field->size);

   if (payload_size != 2)
      return -1;

   if (*field_pos+sizeof(*field)+payload_size > pkt_size)
      return -1;

   memcpy(&tmp, field->data, sizeof(tmp));
   *res = (unsigned)ntohs(tmp);

   *field_pos += sizeof(*field) + payload_size;

   return payload_size+sizeof(*field);
}

static int get_int32_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, int *res)
{
   struct rdrv1_field_t *field;
   size_t payload_size;
   union {
      uint32_t u32;
      int32_t i32;
   } pp;

   assert(pkt);
   assert(field_pos);
   assert(res);

   if (*field_pos+sizeof(*field) > pkt_size)
      return -1;

   field = (struct rdrv1_field_t *)&pkt[*field_pos];

   if (field->type != RDR_TYPE_INT32)
      return -RDR_TYPE_INT32;

   payload_size = ntohl(field->size);

   if (payload_size != 4)
      return -1;

   if (*field_pos+sizeof(*field)+payload_size > pkt_size)
      return -1;

   memcpy(&pp.u32, field->data, sizeof(pp.u32));
   pp.u32 = ntohl(pp.u32);
   *res = (int)pp.i32;

   *field_pos += sizeof(*field) + payload_size;

   return payload_size+sizeof(*field);
}

static int get_uint32_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, unsigned *res)
{
   struct rdrv1_field_t *field;
   size_t payload_size;
   uint32_t tmp;

   assert(pkt);
   assert(field_pos);
   assert(res);

   if (*field_pos+sizeof(*field) > pkt_size)
      return -1;

   field = (struct rdrv1_field_t *)&pkt[*field_pos];

   if (field->type != RDR_TYPE_UINT32) {
      /*   fprintf(stderr, "field type: %u\n", field->type); */
      return -RDR_TYPE_UINT32;
   }

   payload_size = ntohl(field->size);

   if (payload_size != 4)
      return -1;

   if (*field_pos+sizeof(*field)+payload_size > pkt_size)
      return -1;

   memcpy(&tmp, field->data, sizeof(tmp));
   *res = ntohl(tmp);

   *field_pos += sizeof(*field) + payload_size;

   return payload_size+sizeof(*field);
}

static int get_ip_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, struct in_addr *ip)
{
   int res;
   unsigned tmp_ip;

   res = get_uint32_field(pkt, pkt_size, field_pos, &tmp_ip);
   if (res < 0)
      return res;

   ip->s_addr = ntohl((uint32_t)tmp_ip);

   return res;
}

static int get_time_field(uint8_t *pkt, size_t pkt_size, size_t *field_pos, time_t *time)
{
   int res;
   unsigned tmp_time;

   res = get_uint32_field(pkt, pkt_size, field_pos, &tmp_time);
   if (res < 0)
      return res;

   *time = (time_t)tmp_time;

   return res;
}

static void dump_rdr_packet_header(FILE *stream, const struct rdr_packet_t *pkt)
{
   assert(pkt);
   assert(stream);

   fprintf(stream, "RDR %s(0x%x) .%u:%u -> .%u:%u, PPC: %u, FC_ID: %u, size: %u,  fields: %u\n",
	 rdr_name(pkt->header.tag),
	 pkt->header.tag,
	 pkt->header.src,
	 pkt->header.src_port,
	 pkt->header.dst,
	 pkt->header.dst_port,
	 pkt->header.ppc_num,
	 pkt->header.fc_id,
	 pkt->header.payload_size,
	 pkt->header.field_cnt
	 );
}

void dump_rdr_packet(FILE *stream, const struct rdr_packet_t *pkt)
{
   char server_ip[17], client_ip[17];
   char report_time[27];

   assert(pkt);
   assert(stream);

   dump_rdr_packet_header(stream, pkt);
   switch (pkt->header.tag) {
      case TRANSACTION_RDR:
	 fprintf(stream, "\tSubscriber: %s; package_id: %i; service_id: %i; protocol_id: %i skipped: %u\n",
	       pkt->rdr.transaction.subscriber_id,
	       pkt->rdr.transaction.package_id,
	       pkt->rdr.transaction.service_id,
	       pkt->rdr.transaction.protocol_id,
	       pkt->rdr.transaction.skipped_sessions-1
	       );

	 strncpy(server_ip, inet_ntoa(pkt->rdr.transaction.server_ip), sizeof(server_ip));
	 strncpy(client_ip, inet_ntoa(pkt->rdr.transaction.client_ip), sizeof(client_ip));
	 strncpy(report_time, ctime(&pkt->rdr.transaction.report_time), sizeof(report_time));
	 report_time[strlen(report_time)-1]='\0';
	 fprintf(stream, "\t%s %s:%u%s -> %s:%u%s %s %s\n",
	       report_time,
	       client_ip, pkt->rdr.transaction.client_port,
	       pkt->rdr.transaction.initiating_side == 0 ? "*" : " ",
	       server_ip, pkt->rdr.transaction.server_port,
	       pkt->rdr.transaction.initiating_side == 0 ? " " : "*",
	       pkt->rdr.transaction.access_string, pkt->rdr.transaction.info_string
	       );
	 fprintf(stream, "\tUp/Down: %u/%u; Duration: %ums; Time_frame: %u; Proto: %u\n",
	       pkt->rdr.transaction.session_upstream_volume,
	       pkt->rdr.transaction.session_downstream_volume,
	       pkt->rdr.transaction.millisec_duration,
	       pkt->rdr.transaction.time_frame,
	       pkt->rdr.transaction.ip_protocol);
	 fprintf(stream, "\tIDs: %u %u %u  %i %i %i %u\n",
	       pkt->rdr.transaction.subscriber_counter_id,
	       pkt->rdr.transaction.global_counter_id,
	       pkt->rdr.transaction.package_counter_id,
	       pkt->rdr.transaction.protocol_signature,
	       pkt->rdr.transaction.zone_id,
	       pkt->rdr.transaction.flavor_id,
	       pkt->rdr.transaction.flow_close_mode);
	 break;
      case TRANSACTION_USAGE_RDR:
	 fprintf(stream, "\tSubscriber: %s; package_id: %i; service_id: %i; protocol_id: %i reason: %u\n",
	       pkt->rdr.transaction_usage.subscriber_id,
	       pkt->rdr.transaction_usage.package_id,
	       pkt->rdr.transaction_usage.service_id,
	       pkt->rdr.transaction_usage.protocol_id,
	       pkt->rdr.transaction_usage.generation_reason
	       );

	 strncpy(server_ip, inet_ntoa(pkt->rdr.transaction_usage.server_ip), sizeof(server_ip));
	 strncpy(client_ip, inet_ntoa(pkt->rdr.transaction_usage.client_ip), sizeof(client_ip));
	 strncpy(report_time, ctime(&pkt->rdr.transaction_usage.report_time), sizeof(report_time));
	 report_time[strlen(report_time)-1]='\0';
	 fprintf(stream, "\t%s %s:%u%s -> %s:%u%s %s %s\n",
	       report_time,
	       client_ip, pkt->rdr.transaction_usage.client_port,
	       pkt->rdr.transaction_usage.initiating_side == 0 ? "*" : " ",
	       server_ip, pkt->rdr.transaction_usage.server_port,
	       pkt->rdr.transaction_usage.initiating_side == 0 ? " " : "*",
	       pkt->rdr.transaction_usage.access_string, pkt->rdr.transaction_usage.info_string
	       );
	 fprintf(stream, "\tUp/Down: %u/%u; Duration: %ums; Time_frame: %u; Proto: %u\n",
	       pkt->rdr.transaction_usage.session_upstream_volume,
	       pkt->rdr.transaction_usage.session_downstream_volume,
	       pkt->rdr.transaction_usage.millisec_duration,
	       pkt->rdr.transaction_usage.time_frame,
	       pkt->rdr.transaction_usage.ip_protocol);
	 fprintf(stream, "\tIDs: %u %u %u  %i %i %i %u\n",
	       pkt->rdr.transaction_usage.subscriber_counter_id,
	       pkt->rdr.transaction_usage.global_counter_id,
	       pkt->rdr.transaction_usage.package_counter_id,
	       pkt->rdr.transaction_usage.protocol_signature,
	       pkt->rdr.transaction_usage.zone_id,
	       pkt->rdr.transaction_usage.flavor_id,
	       pkt->rdr.transaction_usage.flow_close_mode);
	 break;
      default:
	 break;
   }
}

int dump_raw_rdr_packet(FILE *stream, int dump_header, void *data, size_t data_size)
{
   int res;
   unsigned field_num;
   size_t field_pos;
   int packet_size;
   struct rdr_packet_t rdr_header;

   assert(stream);
   assert(data);
   assert(data_size);

   field_pos = sizeof(struct rdrv1_header_t);
   packet_size = decode_rdr_packet_header(data, data_size, &rdr_header);
   if (packet_size < 0)
      return packet_size;

   if (dump_header)
      dump_rdr_packet_header(stream, &rdr_header);

   field_num=1;
   res = 1;
   while (res > 0 && (field_pos+sizeof(struct rdrv1_field_t) <= data_size)) {
      struct rdrv1_field_t *field;

      field = (struct rdrv1_field_t *)((uint8_t *)data + field_pos);

      fprintf(stream, "\tField %02u %6s(%02u), %02u bytes: ",
	    field_num,
	    rdr_field_type(field->type), (unsigned)field->type,
	    (unsigned)ntohl(field->size));

      switch  (field->type) {
	 case RDR_TYPE_INT8:
	    {
	       int val;
	       if ((res = get_int8_field(data, data_size, &field_pos, &val)) < 0)
		  fprintf(stream, "error %i\n", res);
	       else
		  fprintf(stream, "%i\n", val);
	    }
	    break;
	 case RDR_TYPE_INT16:
	    {
	       int val;
	       if ((res = get_int16_field(data, data_size, &field_pos, &val)) < 0)
		  fprintf(stream, "error %i\n", res);
	       else
		  fprintf(stream, "%i\n", val);
	    }
	    break;
	 case RDR_TYPE_INT32:
	    {
	       int val;
	       if ((res = get_int32_field(data, data_size, &field_pos, &val)) < 0)
		  fprintf(stream, "error %i\n", res);
	       else
		  fprintf(stream, "%i\n", val);
	    }
	    break;
	 case RDR_TYPE_UINT8:
	    {
	       unsigned val;
	       if ((res = get_uint8_field(data, data_size, &field_pos, &val)) < 0)
		  fprintf(stream, "error %i\n", res);
	       else
		  fprintf(stream, "%u\n", val);
	    }
	    break;
	 case RDR_TYPE_UINT16:
	    {
	       unsigned val;
	       if ((res = get_uint16_field(data, data_size, &field_pos, &val)) < 0)
		  fprintf(stream, "error %i\n", res);
	       else
		  fprintf(stream, "%u\n", val);
	    }
	    break;
	 case RDR_TYPE_UINT32:
	    {
	       unsigned val;
	       if ((res = get_uint32_field(data, data_size, &field_pos, &val)) < 0)
		  fprintf(stream, "error %i\n", res);
	       else
		  fprintf(stream, "%u\n", val);
	    }
	    break;
	 case RDR_TYPE_STRING:
	    {
	       char str[80];
	       if ((res = get_string_field(data, data_size, &field_pos, str, sizeof(str))) < 0)
		  fprintf(stream, "error %i\n", res);
	       else
		  fprintf(stream, "%s\n", str);
	    }
	    break;
	 case RDR_TYPE_FLOAT:
	 case RDR_TYPE_BOOLEAN:
	 default:
	    fprintf(stderr, "...\n");
	    field_pos += sizeof(*field) + ntohl(field->size);
	    break;
      }
      field_num += 1;
   }

   return res;
}


const char *rdr_name(unsigned tag)
{
   const char *name;

   switch (tag) {
      case SUBSCRIBER_USAGE_RDR: name="SUBSCRIBER_USAGE_RDR"; break;
      case REALTIME_SUBSCRIBER_USAGE_RDR: name="REALTIME_SUBSCRIBER_USAGE_RDR"; break;
      case PACKAGE_USAGE_RDR: name="PACKAGE_USAGE_RDR"; break;
      case LINK_USAGE_RDR: name="LINK_USAGE_RDR"; break;
      case VIRTUAL_LINKS_USAGE_RDR: name="VIRTUAL_LINKS_USAGE_RDR"; break;
      case TRANSACTION_RDR: name="TRANSACTION_RDR"; break;
      case TRANSACTION_USAGE_RDR: name="TRANSACTION_USAGE_RDR"; break;
      case HTTP_TRANSACTION_USAGE_RDR: name="HTTP_TRANSACTION_USAGE_RDR"; break;
      case RTSP_TRANSACTION_USAGE_RDR: name="RTSP_TRANSACTION_USAGE_RDR"; break;
      case VOIP_TRANSACTION_USAGE_RDR: name="VOIP_TRANSACTION_USAGE_RDR"; break;
      case ANONYMIZED_HTTP_TRANSACTION_USAGE_RDR: name="ANONYMIZED_HTTP_TRANSACTION_USAGE_RDR"; break;
      case SERVICE_BLOCK_RDR: name="SERVICE_BLOCK_RDR"; break;
      case QUOTA_BREACH_RDR: name="QUOTA_BREACH_RDR"; break;
      case REMAINING_QUOTA_RDR: name="REMAINING_QUOTA_RDR"; break;
      case QUOTA_THRESHOLD_BREACH_RDR: name="QUOTA_THRESHOLD_BREACH_RDR"; break;
      case QUOTA_STATE_RESTORE_RDR: name="QUOTA_STATE_RESTORE_RDR"; break;
      case RADIUS_RDR: name="RADIUS_RDR"; break;
      case DHCP_RDR: name="DHCP_RDR"; break;
      case FLOW_START_RDR: name="FLOW_START_RDR"; break;
      case FLOW_END_RDR: name="FLOW_END_RDR"; break;
      case MEDIA_FLOW_RDR: name="MEDIA_FLOW_RDR"; break;
      case FLOW_ONGOING_RDR: name="FLOW_ONGOING_RDR"; break;
      case ATTACK_START_RDR: name="ATTACK_START_RDR"; break;
      case ATTACK_END_RDR: name="ATTACK_END_RDR"; break;
      case MALICIOUS_TRAFFIC_PERIODIC_RDR: name="MALICIOUS_TRAFFIC_PERIODIC_RDR"; break;
      case SPAM_RDR: name="SPAM_RDR"; break;
      case GENERIC_USAGE_RDR: name="GENERIC_USAGE_RDR"; break;
      default: name = "UNKNOWN"; break;
   }

   return name;
}

const char *rdr_field_type(unsigned type)
{
   const char *name;

   switch (type) {
      case RDR_TYPE_INT8: name="INT8"; break;
      case RDR_TYPE_INT16: name="INT16"; break;
      case RDR_TYPE_INT32: name="INT32"; break;
      case RDR_TYPE_UINT8: name="UINT8"; break;
      case RDR_TYPE_UINT16: name="UINT16"; break;
      case RDR_TYPE_UINT32: name="UINT32"; break;
      case RDR_TYPE_FLOAT: name="FLOAT"; break;
      case RDR_TYPE_BOOLEAN: name="BOOLEAN"; break;
      case RDR_TYPE_STRING: name="STRING"; break;
      default: name="UNKNOWN"; break;
   }
   return name;
}

