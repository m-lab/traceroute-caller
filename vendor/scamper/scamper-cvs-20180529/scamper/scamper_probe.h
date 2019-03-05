/*
 * scamper_probe.h
 *
 * $Id: scamper_probe.h,v 1.44 2015/04/06 18:31:17 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
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

#ifndef __SCAMPER_PROBE_H
#define __SCAMPER_PROBE_H

/*
 * scamper_probe_ipopt
 *
 * this structure is used to hold IPv4 options and IPv6 extension headers.
 */
typedef struct scamper_probe_ipopt
{
  uint8_t type;

  union
  {
    struct v4tsps
    {
      struct in_addr   ips[4];
      uint8_t          ipc;
    } v4tsps;

    struct v6rh0
    {
      struct in6_addr *ips;
      uint8_t          ipc;
    } v6rh0;

    struct v6frag
    {
      uint16_t         off;
      uint32_t         id;
    } v6frag;

    struct quickstart
    {
      uint8_t          func;
      uint8_t          rate;
      uint8_t          ttl;
      uint32_t         nonce;
    } quickstart;
  } un;
} scamper_probe_ipopt_t;

#define opt_v4tsps_ips un.v4tsps.ips
#define opt_v4tsps_ipc un.v4tsps.ipc
#define opt_v6rh0_ips  un.v6rh0.ips
#define opt_v6rh0_ipc  un.v6rh0.ipc
#define opt_v6frag_off un.v6frag.off
#define opt_v6frag_id  un.v6frag.id
#define opt_qs_nonce   un.quickstart.nonce
#define opt_qs_ttl     un.quickstart.ttl
#define opt_qs_rate    un.quickstart.rate
#define opt_qs_func    un.quickstart.func

#define SCAMPER_PROBE_IPOPTS_V6ROUTE0   0
#define SCAMPER_PROBE_IPOPTS_V6FRAG     1
#define SCAMPER_PROBE_IPOPTS_V4RR       2
#define SCAMPER_PROBE_IPOPTS_V4TSPS     3 /* TS: prespecified interfaces */
#define SCAMPER_PROBE_IPOPTS_V4TSO      4 /* TS: record only timestamps */
#define SCAMPER_PROBE_IPOPTS_V4TSAA     5 /* TS: record IP and timestamps */
#define SCAMPER_PROBE_IPOPTS_QUICKSTART 6 /* RFC 4782 */

#define SCAMPER_PROBE_FLAG_IPID       0x0001
#define SCAMPER_PROBE_FLAG_NOFRAG     0x0002
#define SCAMPER_PROBE_FLAG_SPOOF      0x0004
#define SCAMPER_PROBE_FLAG_DL         0x0008

#define SCAMPER_PROBE_TCPOPT_SACK     0x01
#define SCAMPER_PROBE_TCPOPT_TS       0x02
#define SCAMPER_PROBE_TCPOPT_FO       0x04
#define SCAMPER_PROBE_TCPOPT_FO_EXP   0x08

#define SCAMPER_PROBE_IS_IPID(pr) (                                      \
  ((pr)->pr_flags & SCAMPER_PROBE_FLAG_IPID) != 0 &&                     \
  (pr)->pr_ip_dst != NULL && SCAMPER_ADDR_TYPE_IS_IPV4((pr)->pr_ip_dst))

/*
 * scamper_probe
 *
 * this structure details how a probe should be formed and sent.
 * it records any error code
 */
typedef struct scamper_probe
{
  /*
   * the following fields define the socket to use.  note: they are optional
   * (and ignored) if the scamper_probe_task function is called with a
   * scamper_probe structure as it determines how to send the packet.
   * if the caller requires the packet to be sent on a datalink socket, it
   * must supply the datalink socket to use (in pr_dl) and a datalink header.
   */
  int                    pr_fd;
  scamper_dl_t          *pr_dl;
  uint8_t               *pr_dl_buf;
  uint16_t               pr_dl_len;

  /* flags set on input */
  uint16_t               pr_flags;

  /* IP header parameters */
  scamper_addr_t        *pr_ip_src;
  scamper_addr_t        *pr_ip_dst;
  uint8_t                pr_ip_tos;
  uint8_t                pr_ip_ttl;
  uint8_t                pr_ip_proto;
  uint16_t               pr_ip_id;        /* IPv4 ID */
  uint16_t               pr_ip_off;
  uint32_t               pr_ip_flow;      /* IPv6 flow id */

  /* IPv4 options / IPv6 extension headers */
  scamper_probe_ipopt_t *pr_ipopts;
  int                    pr_ipoptc;

  /* UDP header parameters */
  uint16_t               pr_udp_sport;
  uint16_t               pr_udp_dport;

  /* ICMP header parameters */
  uint8_t                pr_icmp_type;
  uint8_t                pr_icmp_code;
  uint16_t               pr_icmp_sum;
  uint16_t               pr_icmp_id;
  uint16_t               pr_icmp_seq;
  uint16_t               pr_icmp_mtu;

  /* TCP header parameters */
  uint16_t               pr_tcp_sport;
  uint16_t               pr_tcp_dport;
  uint32_t               pr_tcp_seq;
  uint32_t               pr_tcp_ack;
  uint8_t                pr_tcp_flags;
  uint8_t                pr_tcp_opts;
  uint8_t                pr_tcp_wscale;
  uint16_t               pr_tcp_win;
  uint16_t               pr_tcp_mss;
  uint32_t               pr_tcp_tsval;
  uint32_t               pr_tcp_tsecr;
  uint32_t               pr_tcp_sack[8];
  uint8_t                pr_tcp_sackb;
  uint8_t               *pr_tcp_fo_cookie;
  uint8_t                pr_tcp_fo_cookielen;

  /* the contents of the packet's body */
  uint8_t               *pr_data;
  uint16_t               pr_len;

  /* the time immediately before the call to sendto was made */
  struct timeval         pr_tx;

  /* the actual transmitted packet, IP header and down, when datalink tx'd */
  uint8_t               *pr_tx_raw;
  uint16_t               pr_tx_rawlen;

  /* if an error occurs in the probe function, the errno is recorded */
  int                    pr_errno;
} scamper_probe_t;

int scamper_probe(scamper_probe_t *probe);

#ifdef __SCAMPER_TASK_H
int scamper_probe_task(scamper_probe_t *probe, scamper_task_t *task);
#endif

/* convenience macro to construct an ICMP echo packet */
#define SCAMPER_PROBE_ICMP_ECHO(pr, id, seq) do {		\
  assert((pr)->pr_ip_dst != NULL);				\
  assert((pr)->pr_ip_dst->type == SCAMPER_ADDR_TYPE_IPV4 ||	\
	 (pr)->pr_ip_dst->type == SCAMPER_ADDR_TYPE_IPV6);	\
  if((pr)->pr_ip_dst->type == SCAMPER_ADDR_TYPE_IPV4)		\
    {								\
      (pr)->pr_ip_proto  = IPPROTO_ICMP;			\
      (pr)->pr_icmp_type = ICMP_ECHO;				\
    }								\
  else								\
    {								\
      (pr)->pr_ip_proto  = IPPROTO_ICMPV6;			\
      (pr)->pr_icmp_type = ICMP6_ECHO_REQUEST;			\
    }								\
  (pr)->pr_icmp_id = (id);					\
  (pr)->pr_icmp_seq = (seq);					\
  } while(0)

/* convenience macro to construct an ICMP timestamp request packet */
#define SCAMPER_PROBE_ICMP_TIME(pr, id, seq) do {		\
  assert((pr)->pr_ip_dst != NULL);				\
  assert((pr)->pr_ip_dst->type == SCAMPER_ADDR_TYPE_IPV4);	\
  (pr)->pr_ip_proto = IPPROTO_ICMP;				\
  (pr)->pr_icmp_type = ICMP_TSTAMP;				\
  (pr)->pr_icmp_id = (id);					\
  (pr)->pr_icmp_seq = (seq);					\
  } while(0)

#define SCAMPER_PROBE_ICMP_PTB(pr, mtu) do {			\
  assert((pr)->pr_ip_dst != NULL);				\
  assert((pr)->pr_ip_dst->type == SCAMPER_ADDR_TYPE_IPV4 ||	\
	 (pr)->pr_ip_dst->type == SCAMPER_ADDR_TYPE_IPV6);	\
  if((pr)->pr_ip_dst->type == SCAMPER_ADDR_TYPE_IPV4)		\
    {								\
      (pr)->pr_ip_proto  = IPPROTO_ICMP;			\
      (pr)->pr_icmp_type = ICMP_UNREACH;			\
      (pr)->pr_icmp_code = ICMP_UNREACH_NEEDFRAG;		\
    }								\
  else								\
    {								\
      (pr)->pr_ip_proto  = IPPROTO_ICMPV6;			\
      (pr)->pr_icmp_type = ICMP6_PACKET_TOO_BIG;		\
    }								\
  (pr)->pr_icmp_mtu = (mtu);					\
  } while(0)

/*
 * scamper_probe_cleanup:
 * cleanup any state kept inside the scamper_probe module
 */
int scamper_probe_init(void);
void scamper_probe_cleanup(void);

#endif /* __SCAMPER_PROBE_H */
