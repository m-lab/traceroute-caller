/*
 * scamper_dl.h
 *
 * $Id: scamper_dl.h,v 1.62 2015/09/15 04:49:06 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (c) 2013-2015 The Regents of the University of California
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

#ifndef __SCAMPER_DL_H
#define __SCAMPER_DL_H

/*
 * these flags are set in scamper_dl_rec.dl_flags
 *
 * SCAMPER_DL_REC_FLAG_TIMESTAMP: if set, the datalink record has a timestamp
 * obtained from the datalink.
 *
 * SCAMPER_DL_REC_FLAG_IP: if set, the datalink record has an IP header
 * obtained from the datalink, and it is complete.
 *
 * SCAMPER_DL_REC_FLAG_TRANS: if set, the datalink record has a IP transport
 * header (ICMP, UDP, TCP) obtained from the datalink, and it is complete
 * for the purposes it is designed for.
 */
#define SCAMPER_DL_REC_FLAG_TIMESTAMP 0x01
#define SCAMPER_DL_REC_FLAG_NET       0x02
#define SCAMPER_DL_REC_FLAG_TRANS     0x04

#define SCAMPER_DL_REC_NET_TYPE_IP    0x01
#define SCAMPER_DL_REC_NET_TYPE_ARP   0x02

/*
 * these types are set in scamper_dl_rec.dl_type
 *
 * SCAMPER_DL_TYPE_RAW: datalink record off a raw interface, no L2 header
 * SCAMPER_DL_TYPE_NULL: datalink record off a null interface, no L2 recorded
 * SCAMPER_DL_TYPE_ETHERNET: datalink record off an ethernet interface
 * SCAMPER_DL_TYPE_FIREWIRE: datalink record off a firewire interface
 */
#define SCAMPER_DL_TYPE_RAW       0x01
#define SCAMPER_DL_TYPE_NULL      0x02
#define SCAMPER_DL_TYPE_ETHERNET  0x03
#define SCAMPER_DL_TYPE_FIREWIRE  0x04

#define SCAMPER_DL_IP_FLAG_DF     0x01
#define SCAMPER_DL_IP_FLAG_MF     0x02
#define SCAMPER_DL_IP_FLAG_FRAG   0x04
#define SCAMPER_DL_IP_FLAG_REASS  0x08

#define SCAMPER_DL_TCP_OPT_SACKP  0x01
#define SCAMPER_DL_TCP_OPT_TS     0x02
#define SCAMPER_DL_TCP_OPT_FO     0x04
#define SCAMPER_DL_TCP_OPT_FO_EXP 0x08

#define SCAMPER_DL_IS_IP(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP)

#define SCAMPER_DL_IS_IPV4(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (dl)->dl_af == AF_INET)

#define SCAMPER_DL_IS_IPV6(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (dl)->dl_af == AF_INET6)

#define SCAMPER_DL_IS_ICMP(dl) ( \
 ((dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP) && \
 (((dl)->dl_af == AF_INET  && (dl)->dl_ip_proto == 1) || \
  ((dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58)))

#define SCAMPER_DL_IS_UDP(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (dl)->dl_ip_proto == 17)

#define SCAMPER_DL_IS_TCP(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (dl)->dl_ip_proto == 6)

#define SCAMPER_DL_IS_TCP_SYNACK(dl) ( \
 SCAMPER_DL_IS_TCP(dl) && \
 ((dl)->dl_tcp_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))

#define SCAMPER_DL_IS_ICMPV4(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (dl)->dl_af == AF_INET && (dl)->dl_ip_proto == 1)

#define SCAMPER_DL_IS_ICMPV6(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58)

#define SCAMPER_DL_IS_ICMP_Q_ICMP(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 ((dl)->dl_af == AF_INET && (dl)->dl_ip_proto == 1 && \
  (dl)->dl_icmp_ip_proto == 1) || \
 ((dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58 && \
  (dl)->dl_icmp_ip_proto == 58)))

#define SCAMPER_DL_IS_ICMP_Q_UDP(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (((dl)->dl_af == AF_INET  && (dl)->dl_ip_proto == 1) || \
  ((dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58)) && \
 (dl)->dl_icmp_ip_proto == 17)

#define SCAMPER_DL_IS_ICMP_Q_TCP(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (((dl)->dl_af == AF_INET  && (dl)->dl_ip_proto == 1) || \
  ((dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58)) && \
 (dl)->dl_icmp_ip_proto == 6)

#define SCAMPER_DL_IS_ICMP_Q_ICMP_ECHO_REQ(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (((dl)->dl_af == AF_INET && (dl)->dl_ip_proto == 1 && \
   (dl)->dl_icmp_ip_proto == 1 && (dl)->dl_icmp_icmp_type == 8) || \
  ((dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58 && \
   (dl)->dl_icmp_ip_proto == 58 && (dl)->dl_icmp_icmp_type == 128)))

#define SCAMPER_DL_IS_ICMP_Q_ICMP_TIME_REQ(dl) (	\
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP &&	\
 (dl)->dl_af == AF_INET && (dl)->dl_ip_proto == 1 &&	\
 (dl)->dl_icmp_ip_proto == 1 && (dl)->dl_icmp_icmp_type == 13)

#define SCAMPER_DL_IS_ICMP_Q_ICMP_ECHO(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (((dl)->dl_af == AF_INET && \
   (dl)->dl_ip_proto == 1 && (dl)->dl_icmp_ip_proto == 1 && \
   ((dl)->dl_icmp_icmp_type == 8 || (dl)->dl_icmp_icmp_type == 0)) || \
  ((dl)->dl_af == AF_INET6 && \
   (dl)->dl_ip_proto == 58 && (dl)->dl_icmp_ip_proto == 58 && \
   ((dl)->dl_icmp_icmp_type == 128 || (dl)->dl_icmp_icmp_type == 129))))

#define SCAMPER_DL_IS_ICMP_ECHO_REQUEST(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (((dl)->dl_af == AF_INET && (dl)->dl_ip_proto == 1 && \
   (dl)->dl_icmp_type == 8) || \
  ((dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58 && \
   (dl)->dl_icmp_type == 128)))

#define SCAMPER_DL_IS_ICMP_ECHO_REPLY(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (((dl)->dl_af == AF_INET && (dl)->dl_ip_proto == 1 && \
   (dl)->dl_icmp_type == 0) || \
  ((dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58 && \
   (dl)->dl_icmp_type == 129)))

#define SCAMPER_DL_IS_ICMP_ECHO(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (((dl)->dl_af == AF_INET && (dl)->dl_ip_proto == 1 && \
   ((dl)->dl_icmp_type == 0 || (dl)->dl_icmp_type == 8)) || \
  ((dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58 && \
   ((dl)->dl_icmp_type == 128 || (dl)->dl_icmp_type == 129))))

#define SCAMPER_DL_IS_ICMP_TIME_REPLY(dl) (		\
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP &&	\
 (dl)->dl_af == AF_INET && (dl)->dl_ip_proto == 1 &&	\
 (dl)->dl_icmp_icmp_type == 14)

#define SCAMPER_DL_IS_ICMP_TTL_EXP(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (((dl)->dl_af == AF_INET && (dl)->dl_ip_proto == 1 && \
   (dl)->dl_icmp_type == 11) || \
  ((dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58 && \
   (dl)->dl_icmp_type == 3)))

#define SCAMPER_DL_IS_ICMP_UNREACH(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (((dl)->dl_af == AF_INET && (dl)->dl_ip_proto == 1 && \
   (dl)->dl_icmp_type == 3) || \
  ((dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58 && \
   (dl)->dl_icmp_type == 1)))

#define SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (((dl)->dl_af == AF_INET && (dl)->dl_ip_proto == 1 && \
   (dl)->dl_icmp_type == 3 && (dl)->dl_icmp_code == 4) || \
  ((dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58 && \
   (dl)->dl_icmp_type == 2)))

#define SCAMPER_DL_IS_ICMP_PARAMPROB(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (dl)->dl_af == AF_INET && (dl)->dl_ip_proto == 1 && \
 (dl)->dl_icmp_type == 12)

#define SCAMPER_DL_IS_ICMP6_ND_NADV(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58 && \
 (dl)->dl_icmp_type == 136)

#define SCAMPER_DL_IS_ICMP6_ND_NSOL(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (dl)->dl_af == AF_INET6 && (dl)->dl_ip_proto == 58 && \
 (dl)->dl_icmp_type == 135)

#define SCAMPER_DL_IS_ARP(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_ARP)

#define SCAMPER_DL_IS_ARP_OP_REQ(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_ARP && \
 (dl)->dl_arp_op == 1)

#define SCAMPER_DL_IS_ARP_OP_REPLY(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_ARP && \
 (dl)->dl_arp_op == 2)

#define SCAMPER_DL_IS_ARP_HRD_ETHERNET(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_ARP && \
 (dl)->dl_arp_hrd == 1)

#define SCAMPER_DL_IS_ARP_PRO_IPV4(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_ARP && \
 (dl)->dl_arp_pro == 0x0800)

#define SCAMPER_DL_IS_IP_DF(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 (dl)->dl_af == AF_INET && ((dl)->dl_ip_flags & SCAMPER_DL_IP_FLAG_DF) != 0)

#define SCAMPER_DL_IS_IP_MF(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 ((dl)->dl_ip_flags & SCAMPER_DL_IP_FLAG_MF) != 0)

#define SCAMPER_DL_IS_IP_FRAG(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 ((dl)->dl_ip_flags & SCAMPER_DL_IP_FLAG_FRAG) != 0)

#define SCAMPER_DL_IS_IP_REASS(dl) ( \
 (dl)->dl_net_type == SCAMPER_DL_REC_NET_TYPE_IP && \
 ((dl)->dl_ip_flags & SCAMPER_DL_IP_FLAG_REASS) != 0)

/*
 * scamper_dl_rec
 *
 * this structure summarises details provided by the datalink of packets
 * that passed the filter.
 */
typedef struct scamper_dl_rec
{
  /* flags, meanings defined above */
  uint32_t         dl_flags;

  /* type of the datalink which passed the packet */
  uint32_t         dl_type;

  /* the time that the packet was seen on the datalink */
  struct timeval   dl_tv;

  /*
   * the index assigned by the OS that identifies the interface the
   * packet was pulled off
   */
  int              dl_ifindex;

  /*
   * category 1: the datalink frame header, if any.
   *
   * scamper records the source and destination link local addresses if the
   * frame is ethernet or firewire; otherwise these fields are null;
   */
  uint8_t         *dl_lladdr_src;
  uint8_t         *dl_lladdr_dst;

  /*
   * category 2: the network layer
   *
   * scamper records the network headers found.  either IPv4/IPv6, or ARP.
   *
   */
  uint8_t          dl_net_type;
  uint8_t         *dl_net_raw;
  size_t           dl_net_rawlen;

  union
  {
    struct dl_ip
    {
      int            af;    /* AF_INET or AF_INET6 */
      uint8_t        hl;    /* header length */
      uint8_t       *src;   /* pointer to raw source IP address */
      uint8_t       *dst;   /* pointer to raw destination IP address */
      uint16_t       size;  /* size of IP packet including header */
      uint16_t       off;   /* fragment offset */
      uint16_t       ipid;  /* IPv4 IP-ID */
      uint32_t       id;    /* IPv6 frag ID */
      uint32_t       flow;  /* IPv6 flowid (20 bits) */
      uint8_t        tos;   /* 8 bits formerly known as type of service */
      uint8_t        ttl;   /* time to live */
      uint8_t        proto; /* IP protocol */
      uint8_t        flags; /* flags */
      uint8_t       *data;  /* payload after the IP header */
      uint16_t       len;   /* length of data after the IP header */
    } net_ip;

    struct dl_arp
    {
      uint16_t       hrd; /* hardware address space */
      uint16_t       pro; /* protocol address space */
      uint8_t        hln; /* hardware address length */
      uint8_t        pln; /* protocol address length */
      uint16_t       op;  /* opcode */
      uint8_t       *sha; /* hardware address of sender */
      uint8_t       *spa; /* protocol address of sender */
      uint8_t       *tha; /* hardware address of target */
      uint8_t       *tpa; /* protocol address of target */
    } net_arp;

  } dl_net_un;

  /*
   * category 3: the transport header
   *
   * scamper records the details of the datalink in the following union
   * [if it understands it]
   */
  union
  {
    struct dl_udp
    {
      uint16_t sport;
      uint16_t dport;
      uint16_t sum;
    } udp;

    struct dl_tcp
    {
      uint16_t  sport;
      uint16_t  dport;
      uint32_t  seq;
      uint32_t  ack;
      uint8_t   hl;
      uint8_t   flags;
      uint16_t  win;
      uint16_t  mss;
      uint8_t   opts;
      int8_t    sack_edgec;
      uint32_t  sack_edges[8];
      uint32_t  tsval;
      uint32_t  tsecr;
      uint8_t  *data;
      uint16_t  datalen;
      uint8_t   fo_cookie[16];
      uint8_t   fo_cookielen;
    } tcp;

    struct dl_icmp
    {
      uint8_t  type;
      uint8_t  code;

      union
      {
	struct dl_icmp6_nd
	{
	  uint8_t  *target;
	  uint8_t  *opts;
	  uint16_t  opts_len;
	} nd;

	struct dl_icmp_echo
	{
	  uint16_t  id;
	  uint16_t  seq;
	} echo;

	struct dl_icmp_err
	{
	  uint16_t  nhmtu;
	  uint8_t  *ip_src;
	  uint8_t  *ip_dst;
	  uint16_t  ip_size;
	  uint16_t  ip_id;   /* IPv4 ID */
	  uint32_t  ip_flow; /* IPv6 flow */
	  uint8_t   ip_tos;
	  uint8_t   ip_ttl;
	  uint8_t   ip_proto;

	  union
	  {
	    struct icmp_udp
	    {
	      uint16_t sport;
	      uint16_t dport;
	      uint16_t sum;
	    } udp;

	    struct icmp_tcp
	    {
	      uint16_t sport;
	      uint16_t dport;
	      uint32_t seq;
	    } tcp;

	    struct icmp_icmp
	    {
	      uint8_t  type;
	      uint8_t  code;
	      uint16_t id;
	      uint16_t seq;
	    } icmp;
	  } trans;
	} err;
      } un;
    } icmp;
  } dl_trans_un;

} scamper_dl_rec_t;

#define dl_flags              dl_flags
#define dl_ifindex            dl_ifindex
#define dl_lladdr_src         dl_lladdr_src
#define dl_lladdr_dst         dl_lladdr_dst
#define dl_net_type           dl_net_type
#define dl_net_raw            dl_net_raw
#define dl_net_rawlen         dl_net_rawlen
#define dl_arp_hrd            dl_net_un.net_arp.hrd
#define dl_arp_pro            dl_net_un.net_arp.pro
#define dl_arp_hln            dl_net_un.net_arp.hln
#define dl_arp_pln            dl_net_un.net_arp.pln
#define dl_arp_op             dl_net_un.net_arp.op
#define dl_arp_sha            dl_net_un.net_arp.sha
#define dl_arp_spa            dl_net_un.net_arp.spa
#define dl_arp_tha            dl_net_un.net_arp.tha
#define dl_arp_tpa            dl_net_un.net_arp.tpa
#define dl_af                 dl_net_un.net_ip.af
#define dl_ip_hl              dl_net_un.net_ip.hl
#define dl_ip_src             dl_net_un.net_ip.src
#define dl_ip_dst             dl_net_un.net_ip.dst
#define dl_ip_size            dl_net_un.net_ip.size
#define dl_ip_id              dl_net_un.net_ip.ipid
#define dl_ip6_id             dl_net_un.net_ip.id
#define dl_ip_off             dl_net_un.net_ip.off
#define dl_ip_tos             dl_net_un.net_ip.tos
#define dl_ip_ttl             dl_net_un.net_ip.ttl
#define dl_ip_hlim            dl_net_un.net_ip.ttl
#define dl_ip_proto           dl_net_un.net_ip.proto
#define dl_ip_flow            dl_net_un.net_ip.flow
#define dl_ip_flags           dl_net_un.net_ip.flags
#define dl_ip_data            dl_net_un.net_ip.data
#define dl_ip_datalen         dl_net_un.net_ip.len
#define dl_udp_sport          dl_trans_un.udp.sport
#define dl_udp_dport          dl_trans_un.udp.dport
#define dl_udp_sum            dl_trans_un.udp.sum
#define dl_tcp_sport          dl_trans_un.tcp.sport
#define dl_tcp_dport          dl_trans_un.tcp.dport
#define dl_tcp_seq            dl_trans_un.tcp.seq
#define dl_tcp_ack            dl_trans_un.tcp.ack
#define dl_tcp_hl             dl_trans_un.tcp.hl
#define dl_tcp_flags          dl_trans_un.tcp.flags
#define dl_tcp_win            dl_trans_un.tcp.win
#define dl_tcp_mss            dl_trans_un.tcp.mss
#define dl_tcp_opts           dl_trans_un.tcp.opts
#define dl_tcp_sack_edges     dl_trans_un.tcp.sack_edges
#define dl_tcp_sack_edgec     dl_trans_un.tcp.sack_edgec
#define dl_tcp_tsval          dl_trans_un.tcp.tsval
#define dl_tcp_tsecr          dl_trans_un.tcp.tsecr
#define dl_tcp_fo_cookie      dl_trans_un.tcp.fo_cookie
#define dl_tcp_fo_cookielen   dl_trans_un.tcp.fo_cookielen
#define dl_tcp_data           dl_trans_un.tcp.data
#define dl_tcp_datalen        dl_trans_un.tcp.datalen
#define dl_icmp_type          dl_trans_un.icmp.type
#define dl_icmp_code          dl_trans_un.icmp.code
#define dl_icmp_id            dl_trans_un.icmp.un.echo.id
#define dl_icmp_seq           dl_trans_un.icmp.un.echo.seq
#define dl_icmp_nhmtu         dl_trans_un.icmp.un.err.nhmtu
#define dl_icmp_ip_src        dl_trans_un.icmp.un.err.ip_src
#define dl_icmp_ip_dst        dl_trans_un.icmp.un.err.ip_dst
#define dl_icmp_ip_size       dl_trans_un.icmp.un.err.ip_size
#define dl_icmp_ip_id         dl_trans_un.icmp.un.err.ip_id
#define dl_icmp_ip_flow       dl_trans_un.icmp.un.err.ip_flow
#define dl_icmp_ip_tos        dl_trans_un.icmp.un.err.ip_tos
#define dl_icmp_ip_ttl        dl_trans_un.icmp.un.err.ip_ttl
#define dl_icmp_ip_hlim       dl_trans_un.icmp.un.err.ip_ttl
#define dl_icmp_ip_proto      dl_trans_un.icmp.un.err.ip_proto
#define dl_icmp_udp_sport     dl_trans_un.icmp.un.err.trans.udp.sport
#define dl_icmp_udp_dport     dl_trans_un.icmp.un.err.trans.udp.dport
#define dl_icmp_udp_sum       dl_trans_un.icmp.un.err.trans.udp.sum
#define dl_icmp_tcp_sport     dl_trans_un.icmp.un.err.trans.tcp.sport
#define dl_icmp_tcp_dport     dl_trans_un.icmp.un.err.trans.tcp.dport
#define dl_icmp_tcp_seq       dl_trans_un.icmp.un.err.trans.tcp.seq
#define dl_icmp_icmp_type     dl_trans_un.icmp.un.err.trans.icmp.type
#define dl_icmp_icmp_code     dl_trans_un.icmp.un.err.trans.icmp.code
#define dl_icmp_icmp_id       dl_trans_un.icmp.un.err.trans.icmp.id
#define dl_icmp_icmp_seq      dl_trans_un.icmp.un.err.trans.icmp.seq
#define dl_icmp6_nd_target    dl_trans_un.icmp.un.nd.target
#define dl_icmp6_nd_opts      dl_trans_un.icmp.un.nd.opts
#define dl_icmp6_nd_opts_len  dl_trans_un.icmp.un.nd.opts_len

#define SCAMPER_DL_TX_UNSUPPORTED           0x00
#define SCAMPER_DL_TX_ETHERNET              0x01
#define SCAMPER_DL_TX_NULL                  0x02
#define SCAMPER_DL_TX_RAW                   0x03
#define SCAMPER_DL_TX_ETHLOOP               0x04

typedef struct scamper_dl scamper_dl_t;

/*
 * scamper_dl_init:    initialise scamper's datalink structures
 * scamper_dl_cleanup: cleanup scamper's datalink structures
 */
int scamper_dl_init(void);
void scamper_dl_cleanup(void);

int scamper_dl_tx_type(scamper_dl_t *);

/*
 * scamper_dl_open:    open datalink interface, use privsep if required
 * scamper_dl_open_fd: open datalink interface. for the benefit of privsep code
 */
int scamper_dl_open(const int ifindex);
int scamper_dl_open_fd(const int ifindex);
void scamper_dl_close(int fd);

/*
 * scamper_dl_state_alloc: allocate state to be held with fd
 * scamper_dl_state_free:  deallocate state
 */
#ifdef __SCAMPER_FD_H
scamper_dl_t *scamper_dl_state_alloc(scamper_fd_t *fdn);
void scamper_dl_state_free(scamper_dl_t *dl);
#endif

/*
 * scamper_dl_read_cb: callback for read events
 */
void scamper_dl_read_cb(const int fd, void *param);

/*
 * scamper_dl_tx:
 * transmit the packet, including relevant headers which are included, on
 * the datalink.
 */
int scamper_dl_tx(const scamper_dl_t *dl,
		  const uint8_t *pkt, const size_t len);

#ifdef __SCAMPER_ADDR_H
int scamper_dl_rec_src(scamper_dl_rec_t *dl, scamper_addr_t *addr);
int scamper_dl_rec_icmp_ip_dst(scamper_dl_rec_t *dl, scamper_addr_t *addr);
#endif

#if !defined(NDEBUG) && !defined(WITHOUT_DEBUGFILE)
void    scamper_dl_rec_tcp_print(const scamper_dl_rec_t *dl);
void    scamper_dl_rec_udp_print(const scamper_dl_rec_t *dl);
void    scamper_dl_rec_frag_print(const scamper_dl_rec_t *dl);
void    scamper_dl_rec_icmp_print(const scamper_dl_rec_t *dl);
#else
#define scamper_dl_rec_tcp_print(dl) ((void)0)
#define scamper_dl_rec_udp_print(dl) ((void)0)
#define scamper_dl_rec_frag_print(dl) ((void)0)
#define scamper_dl_rec_icmp_print(dl) ((void)0)
#endif

#endif /* __SCAMPER_DL_H */
