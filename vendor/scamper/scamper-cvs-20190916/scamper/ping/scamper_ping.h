/*
 * scamper_ping.h
 *
 * $Id: scamper_ping.h,v 1.51 2019/07/12 23:08:22 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Author: Matthew Luckie
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef __SCAMPER_PING_H
#define __SCAMPER_PING_H

#define SCAMPER_PING_REPLY_IS_ICMP(reply) (        \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 && \
  (reply)->reply_proto == 1) ||                    \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 && \
  (reply)->reply_proto == 58))

#define SCAMPER_PING_REPLY_IS_TCP(reply) ( \
 ((reply)->reply_proto == 6))

#define SCAMPER_PING_REPLY_IS_UDP(reply) ( \
 ((reply)->reply_proto == 17))

#define SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply) (     \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 0) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->reply_proto == 58 && (reply)->icmp_type == 129))

#define SCAMPER_PING_REPLY_IS_ICMP_UNREACH(reply) (        \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 3) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->reply_proto == 58 && (reply)->icmp_type == 1))

#define SCAMPER_PING_REPLY_IS_ICMP_UNREACH_PORT(reply) (   \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->reply_proto == 1 &&                             \
  (reply)->icmp_type == 3 && (reply)->icmp_code == 3) ||   \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->reply_proto == 58 &&                            \
  (reply)->icmp_type == 1 && (reply)->icmp_code == 4))

#define SCAMPER_PING_REPLY_IS_ICMP_TTL_EXP(reply) (         \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&          \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 11) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&          \
  (reply)->reply_proto == 58 && (reply)->icmp_type == 3))

#define SCAMPER_PING_REPLY_IS_ICMP_TSREPLY(reply) ( \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 && \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 14))

#define SCAMPER_PING_METHOD_IS_ICMP(ping) (\
 ((ping)->probe_method == SCAMPER_PING_METHOD_ICMP_ECHO) || \
  (ping)->probe_method == SCAMPER_PING_METHOD_ICMP_TIME)

#define SCAMPER_PING_METHOD_IS_TCP(ping) (                    \
 ((ping)->probe_method == SCAMPER_PING_METHOD_TCP_ACK ||      \
  (ping)->probe_method == SCAMPER_PING_METHOD_TCP_ACK_SPORT || \
  (ping)->probe_method == SCAMPER_PING_METHOD_TCP_SYN || \
  (ping)->probe_method == SCAMPER_PING_METHOD_TCP_SYNACK || \
  (ping)->probe_method == SCAMPER_PING_METHOD_TCP_RST))

#define SCAMPER_PING_METHOD_IS_UDP(ping) (                \
 ((ping)->probe_method == SCAMPER_PING_METHOD_UDP ||      \
  (ping)->probe_method == SCAMPER_PING_METHOD_UDP_DPORT))

#define SCAMPER_PING_METHOD_IS_ICMP_TIME(ping) (\
 ((ping)->probe_method == SCAMPER_PING_METHOD_ICMP_TIME))

#define SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping) (\
 ((ping)->probe_method == SCAMPER_PING_METHOD_ICMP_ECHO))

#define SCAMPER_PING_REPLY_FROM_TARGET(ping, reply) ( \
 (SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping) &&           \
  SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply)) ||    \
 (SCAMPER_PING_METHOD_IS_ICMP_TIME(ping) &&           \
  SCAMPER_PING_REPLY_IS_ICMP_TSREPLY(reply)) ||       \
 (SCAMPER_PING_METHOD_IS_TCP(ping) &&                 \
  SCAMPER_PING_REPLY_IS_TCP(reply)) ||                \
 (SCAMPER_PING_METHOD_IS_UDP(ping) &&                 \
  SCAMPER_PING_REPLY_IS_ICMP_UNREACH_PORT(reply)))

#define SCAMPER_PING_STOP_NONE      0x00 /* null reason */
#define SCAMPER_PING_STOP_COMPLETED 0x01 /* sent all probes */
#define SCAMPER_PING_STOP_ERROR     0x02 /* error occured during ping */
#define SCAMPER_PING_STOP_HALTED    0x03 /* halted */

#define SCAMPER_PING_REPLY_FLAG_REPLY_TTL  0x01 /* reply ttl included */
#define SCAMPER_PING_REPLY_FLAG_REPLY_IPID 0x02 /* reply ipid included */
#define SCAMPER_PING_REPLY_FLAG_PROBE_IPID 0x04 /* probe ipid included */

#define SCAMPER_PING_METHOD_ICMP_ECHO     0x00
#define SCAMPER_PING_METHOD_TCP_ACK       0x01
#define SCAMPER_PING_METHOD_TCP_ACK_SPORT 0x02
#define SCAMPER_PING_METHOD_UDP           0x03
#define SCAMPER_PING_METHOD_UDP_DPORT     0x04
#define SCAMPER_PING_METHOD_ICMP_TIME     0x05
#define SCAMPER_PING_METHOD_TCP_SYN       0x06
#define SCAMPER_PING_METHOD_TCP_SYNACK    0x07
#define SCAMPER_PING_METHOD_TCP_RST       0x08

#define SCAMPER_PING_FLAG_V4RR            0x01 /* -R: IPv4 record route */
#define SCAMPER_PING_FLAG_SPOOF           0x02 /* -O spoof: spoof src */
#define SCAMPER_PING_FLAG_PAYLOAD         0x04 /* probe_data is payload */
#define SCAMPER_PING_FLAG_TSONLY          0x08 /* -T tsonly */
#define SCAMPER_PING_FLAG_TSANDADDR       0x10 /* -T tsandaddr */
#define SCAMPER_PING_FLAG_ICMPSUM         0x20 /* -C csum */
#define SCAMPER_PING_FLAG_DL              0x40 /* always use datalink socket */
#define SCAMPER_PING_FLAG_TBT             0x80 /* -O tbt: too big trick */
#define SCAMPER_PING_FLAG_NOSRC           0x100 /* -O nosrc: do not embed src */

/*
 * scamper_ping_reply_v4rr
 *
 * if the ping probes are using the IP record route option, this structure
 * contains the interfaces extracted from the response.
 */
typedef struct scamper_ping_reply_v4rr
{
  scamper_addr_t **rr;
  uint8_t          rrc;
} scamper_ping_reply_v4rr_t;

/*
 * scamper_ping_reply_v4ts
 *
 * if the ping probes are using the IPv4 timestamp option, this structure
 * contains data extracted from the response.  if the ping->flags field
 * has SCAMPER_PING_FLAG_TSONLY set, then there are no IP addresses included.
 * otherwise, if SCAMPER_PING_FLAG_TSANDADDR is set then there are IP
 * addresses.
 */
typedef struct scamper_ping_reply_v4ts
{
  scamper_addr_t **ips; /* IP addresses, if SCAMPER_PING_FLAG_TSANDADDR */
  uint32_t        *tss; /* timestamps */
  uint8_t          tsc; /* the number of timestamps (ip addresses) */
} scamper_ping_reply_v4ts_t;

/*
 * scamper_ping_reply_tsreply
 *
 * if the ping probes are ICMP timestamp requests, these are the timestamps
 * recorded in the response.
 */
typedef struct scamper_ping_reply_tsreply
{
  uint32_t         tso;
  uint32_t         tsr;
  uint32_t         tst;
} scamper_ping_reply_tsreply_t;

/*
 * scamper_ping_v4ts
 *
 * if the ping probe is using the IPv4 pre-specified timestamp option, this
 * structure contains the IP addresses to include.  a maximum of four.
 */
typedef struct scamper_ping_v4ts
{
  scamper_addr_t **ips;
  uint8_t          ipc;
} scamper_ping_v4ts_t;

/*
 * scamper_ping_reply
 *
 * a ping reply structure keeps track of how a ping packet was responded to.
 */
typedef struct scamper_ping_reply
{
  /* where the response came from */
  scamper_addr_t            *addr;

  /* the TTL / size of the packet that is returned */
  uint16_t                   probe_id;
  uint16_t                   probe_ipid;
  uint8_t                    reply_proto;
  uint8_t                    reply_ttl;
  uint16_t                   reply_size;
  uint16_t                   reply_ipid;
  uint32_t                   reply_ipid32;

  /* flags defined by SCAMPER_PING_REPLY_FLAG_* */
  uint8_t                    flags;

  /* the icmp type / code returned */
  uint8_t                    icmp_type;
  uint8_t                    icmp_code;

  /* the tcp flags returned */
  uint8_t                    tcp_flags;

  /* the time elapsed between sending the probe and getting this response */
  struct timeval             tx;
  struct timeval             rtt;

  /* data found in IP options, if any */
  scamper_ping_reply_v4rr_t *v4rr;
  scamper_ping_reply_v4ts_t *v4ts;
  scamper_ping_reply_tsreply_t *tsreply;

  /* if a single probe gets more than one response, they get chained */
  struct scamper_ping_reply *next;

} scamper_ping_reply_t;

/*
 * scamper_ping
 *
 * this structure contains details of a ping between a source and a
 * destination.  is specifies the parameters to the ping and the
 * replies themselves.
 */
typedef struct scamper_ping
{
  /* the list / cycle that this ping is in relation to */
  scamper_list_t        *list;
  scamper_cycle_t       *cycle;
  uint32_t               userid;

  /* source and destination addresses of the ping */
  scamper_addr_t        *src;          /* -S option */
  scamper_addr_t        *dst;

  /* when the ping started */
  struct timeval         start;

  /* why the ping finished */
  uint8_t                stop_reason;
  uint8_t                stop_data;

  /* the data to use inside of a probe.  if null then all zeros */
  uint8_t               *probe_data;
  uint16_t               probe_datalen;

  /* ping options */
  uint16_t               probe_count;   /* -c */
  uint16_t               probe_size;    /* -s */
  uint8_t                probe_method;  /* -P */
  uint8_t                probe_ttl;     /* -m */
  uint8_t                probe_tos;     /* -z */
  uint8_t                probe_timeout; /* -W */
  uint8_t                probe_wait;    /* -i */
  uint32_t               probe_wait_us; /* -i */
  uint16_t               probe_sport;   /* -F */
  uint16_t               probe_dport;   /* -d */
  uint16_t               probe_icmpsum; /* -C */
  uint32_t               probe_tcpseq;  /* -A with tcp-syn and tcp-rst */
  uint32_t               probe_tcpack;  /* -A with other tcp probe methods */
  uint16_t               reply_count;   /* -o */
  uint16_t               reply_pmtu;    /* -M */
  scamper_ping_v4ts_t   *probe_tsps;    /* -T */
  uint32_t               flags;

  /* actual data collected with the ping */
  scamper_ping_reply_t **ping_replies;
  uint16_t               ping_sent;
} scamper_ping_t;

/* basic routines to allocate and free scamper_ping structures */
scamper_ping_t *scamper_ping_alloc(void);
void scamper_ping_free(scamper_ping_t *ping);
scamper_addr_t *scamper_ping_addr(const void *va);
int scamper_ping_setdata(scamper_ping_t *ping, uint8_t *bytes, uint16_t len);

/* utility function for allocating an array for recording replies */
int scamper_ping_replies_alloc(scamper_ping_t *ping, int count);

/* basic routines to allocate and free scamper_ping_reply structures */
scamper_ping_reply_t *scamper_ping_reply_alloc(void);
void scamper_ping_reply_free(scamper_ping_reply_t *reply);
int scamper_ping_reply_append(scamper_ping_t *p, scamper_ping_reply_t *reply);
uint32_t scamper_ping_reply_count(const scamper_ping_t *ping);

scamper_ping_reply_tsreply_t *scamper_ping_reply_tsreply_alloc(void);
void scamper_ping_reply_tsreply_free(scamper_ping_reply_tsreply_t *tsr);

scamper_ping_reply_v4rr_t *scamper_ping_reply_v4rr_alloc(uint8_t rrc);
void scamper_ping_reply_v4rr_free(scamper_ping_reply_v4rr_t *rr);

scamper_ping_reply_v4ts_t *scamper_ping_reply_v4ts_alloc(uint8_t tsc, int ip);
void scamper_ping_reply_v4ts_free(scamper_ping_reply_v4ts_t *ts);

scamper_ping_v4ts_t *scamper_ping_v4ts_alloc(uint8_t ipc);
void scamper_ping_v4ts_free(scamper_ping_v4ts_t *ts);

typedef struct scamper_ping_stats
{
  uint32_t nreplies;
  uint32_t ndups;
  uint16_t nloss;
  struct timeval min_rtt;
  struct timeval max_rtt;
  struct timeval avg_rtt;
  struct timeval stddev_rtt;
} scamper_ping_stats_t;

/* routine to return basic stats for the measurement */
int scamper_ping_stats(const scamper_ping_t *ping,scamper_ping_stats_t *stats);

char *scamper_ping_method2str(const scamper_ping_t *, char *, size_t);

#endif /* __SCAMPER_PING_H */
