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

#ifndef _RDR_H
#define _RDR_H

#define MAX_RDR_PACKET_SIZE 9999+5+1

#define SUBSCRIBER_USAGE_RDR	    0xf0f0f000
#define REALTIME_SUBSCRIBER_USAGE_RDR  0xf0f0f002
#define PACKAGE_USAGE_RDR	    0xf0f0f004
#define LINK_USAGE_RDR		    0xf0f0f005
#define VIRTUAL_LINKS_USAGE_RDR	    0xf0f0f006
#define TRANSACTION_RDR		    0xf0f0f010
#define TRANSACTION_USAGE_RDR	    0xf0f0f438
#define HTTP_TRANSACTION_USAGE_RDR  0xf0f0f43c
#define RTSP_TRANSACTION_USAGE_RDR  0xf0f0f440
#define VOIP_TRANSACTION_USAGE_RDR  0xf0f0f46a
#define ANONYMIZED_HTTP_TRANSACTION_USAGE_RDR   0xf0f0f53c
#define SERVICE_BLOCK_RDR	    0xf0f0f040
#define QUOTA_BREACH_RDR	    0xf0f0f022
#define REMAINING_QUOTA_RDR	    0xf0f0f030
#define QUOTA_THRESHOLD_BREACH_RDR  0xf0f0f031
#define QUOTA_STATE_RESTORE_RDR	    0xf0f0f032
#define RADIUS_RDR		    0xf0f0f043
#define DHCP_RDR		    0xf0f0f042
#define FLOW_START_RDR		    0xf0f0f016
#define FLOW_END_RDR		    0xf0f0f018
#define MEDIA_FLOW_RDR		    0xf0f0f46c
#define FLOW_ONGOING_RDR	    0xf0f0f017
#define ATTACK_START_RDR	    0xf0f0f019
#define ATTACK_END_RDR		    0xf0f0f01a
#define MALICIOUS_TRAFFIC_PERIODIC_RDR 0xf0f0f050
#define SPAM_RDR		    0xf0f0f080
#define GENERIC_USAGE_RDR	    0xf0f0f090

#define RDR_TYPE_INT8		    11
#define RDR_TYPE_INT16		    12
#define RDR_TYPE_INT32		    13
#define RDR_TYPE_UINT8		    14
#define RDR_TYPE_UINT16		    15
#define RDR_TYPE_UINT32		    16
#define RDR_TYPE_FLOAT		    21
#define RDR_TYPE_BOOLEAN	    31
#define RDR_TYPE_STRING		    41

struct rdrv1_header_t {
   uint8_t ppc_num;
   uint8_t payload_size[4];
   uint8_t src;
   uint8_t dst;
   uint16_t src_port;
   uint16_t dst_port;
   uint32_t fc_id;
   uint32_t tag;
   uint8_t field_cnt;
   uint8_t rdr_fields[];
}  __attribute__((__packed__));

struct rdrv1_field_t {
   uint8_t type;
   uint32_t size;
   uint8_t data[];
} __attribute__((__packed__));


struct rdr_packet_t {
   struct {
      unsigned ppc_num;
      unsigned payload_size;
      unsigned src;
      unsigned dst;
      unsigned src_port;
      unsigned dst_port;
      unsigned fc_id;
      unsigned tag;
      unsigned field_cnt;
   } header;

   union {
      /* TRANSACTION_RDR  */
      struct {
	 char subscriber_id[64+1];
	 int package_id;
	 int service_id;
	 int protocol_id;
	 int skipped_sessions; /* XXX: unsigned? */
	 struct in_addr server_ip;
	 unsigned server_port;
	 char access_string[160];
	 char info_string[160];
	 struct in_addr client_ip;
	 unsigned client_port;
	 int initiating_side;
	 time_t report_time;
	 unsigned millisec_duration;
	 int time_frame;
	 unsigned session_upstream_volume;
	 unsigned session_downstream_volume;
	 unsigned subscriber_counter_id;
	 unsigned global_counter_id;
	 unsigned package_counter_id;
	 unsigned ip_protocol;
	 int protocol_signature;
	 int zone_id;
	 int flavor_id;
	 unsigned flow_close_mode;
	 /* XXX: 3 undocumented fields  */
      } transaction;

      /* TRANSACTION_USAGE_RDR  */
      struct {
	 char subscriber_id[64+1];
	 int package_id;
	 int service_id;
	 int protocol_id;
	 unsigned generation_reason;
	 struct in_addr server_ip;
	 unsigned server_port;
	 char access_string[160];
	 char info_string[160];
	 struct in_addr client_ip;
	 unsigned client_port;
	 int initiating_side;
	 time_t report_time;
	 unsigned millisec_duration;
	 int time_frame;
	 unsigned session_upstream_volume;
	 unsigned session_downstream_volume;
	 unsigned subscriber_counter_id;
	 unsigned global_counter_id;
	 unsigned package_counter_id;
	 unsigned ip_protocol;
	 int protocol_signature;
	 int zone_id;
	 int flavor_id;
	 unsigned flow_close_mode;
	 /* XXX: 4 undocumented fields  */
      } transaction_usage;

   } rdr;
};


/*
 * Return values:
 *    >0 - RDR packet (size)
 *    =0 - not RDR
 *    <0 - truncated RDRpacket
 */
int is_rdr_packet(void *data, size_t data_size);

/*
 * Return values:
 *    >0 - RDR packet (size)
 *    =0 - not RDR
 *    <0 - truncated RDRpacket
 */
int decode_rdr_packet(void *data, size_t data_size, struct rdr_packet_t *res);

const char *rdr_name(unsigned tag);
const char *rdr_field_type(unsigned type);

void dump_rdr_packet(FILE *stream, const struct rdr_packet_t *pkt);
int dump_raw_rdr_packet(FILE *stream, int dump_header, void *data, size_t data_size);

#endif /* _RDR_H  */
