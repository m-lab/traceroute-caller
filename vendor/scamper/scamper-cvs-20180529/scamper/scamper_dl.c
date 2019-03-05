/*
 * scamper_dl: manage BPF/PF_PACKET datalink instances for scamper
 *
 * $Id: scamper_dl.c,v 1.186 2017/12/03 09:54:32 mjl Exp $
 *
 *          Matthew Luckie
 *          Ben Stasiewicz added fragmentation support.
 *          Stephen Eichler added SACK support.
 *
 *          Supported by:
 *           The University of Waikato
 *           NLANR Measurement and Network Analysis
 *           CAIDA
 *           The WIDE Project
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2014-2015 The Regents of the University of California
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

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_dl.c,v 1.186 2017/12/03 09:54:32 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#if defined(HAVE_BPF) || defined(__linux__)
#define HAVE_BPF_FILTER
#endif

#include "scamper.h"
#include "scamper_debug.h"
#include "scamper_addr.h"
#include "scamper_fds.h"
#include "scamper_dl.h"
#include "scamper_privsep.h"
#include "scamper_task.h"
#include "scamper_if.h"
#include "scamper_osinfo.h"
#include "utils.h"

#if defined(HAVE_BPF) && defined(DLT_APPLE_IP_OVER_IEEE1394)
#define HAVE_FIREWIRE
#elif defined(__linux__) && defined(ARPHRD_IEEE1394)
#define HAVE_FIREWIRE
#endif

struct scamper_dl
{
  /* the file descriptor that scamper has on the datalink */
  scamper_fd_t  *fdn;

  /* the callback used to read packets off the datalink */
  int          (*dlt_cb)(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len);

  /* the underlying type of the datalink (DLT_* or ARPHDR_* values) */
  int            type;

  /* how the user should frame packet to transmit on the datalink */
  int            tx_type;

  /* if we're using BPF, then we need to use an appropriately sized buffer */
#if defined(HAVE_BPF)
  u_int          readbuf_len;
#endif

};

static uint8_t          *readbuf = NULL;
static size_t            readbuf_len = 0;

#if defined(HAVE_BPF)
static const scamper_osinfo_t *osinfo = NULL;
#endif

/*
 * dl_parse_ip
 *
 * pkt points to the beginning of an IP header.  given the length of the
 * packet, parse the contents into a datalink record structure.
 */
static int dl_parse_ip(scamper_dl_rec_t *dl, uint8_t *pktbuf, size_t pktlen)
{
  struct ip        *ip4;
  struct ip6_hdr   *ip6;
  struct ip6_ext   *ip6_exthdr;
  struct ip6_frag  *ip6_fraghdr;
  struct icmp      *icmp4;
  struct icmp6_hdr *icmp6;
  struct tcphdr    *tcp;
  struct udphdr    *udp;
  size_t            iplen;
  size_t            extlen;
  uint8_t          *pkt = pktbuf;
  size_t            len = pktlen;
  size_t            off;
  uint8_t          *tmp;
  uint16_t          u16;
  int               i;

  if((pkt[0] >> 4) == 4) /* IPv4 */
    {
      ip4 = (struct ip *)pkt;

#ifndef _WIN32
      iplen = (ip4->ip_hl << 2);
#else
      iplen = ((ip4->ip_vhl) & 0xf) << 2;
#endif

      /*
       * make sure that the captured packet has enough to cover the whole
       * of the IP header
       */
      if(iplen > len)
	return 0;

      /* figure out fragmentation details */
      u16 = ntohs(ip4->ip_off);
      dl->dl_ip_off = (u16 & IP_OFFMASK) * 8;
      if(dl->dl_ip_off != 0 || (u16 & IP_MF) != 0)
	dl->dl_ip_flags |= SCAMPER_DL_IP_FLAG_FRAG;
      if((u16 & IP_DF) != 0)
	dl->dl_ip_flags |= SCAMPER_DL_IP_FLAG_DF;
      if((u16 & IP_MF) != 0)
	dl->dl_ip_flags |= SCAMPER_DL_IP_FLAG_MF;

      dl->dl_af       = AF_INET;
      dl->dl_ip_hl    = iplen;
      dl->dl_ip_proto = ip4->ip_p;
      dl->dl_ip_size  = ntohs(ip4->ip_len);
      dl->dl_ip_id    = ntohs(ip4->ip_id);
      dl->dl_ip_tos   = ip4->ip_tos;
      dl->dl_ip_ttl   = ip4->ip_ttl;
      dl->dl_ip_src   = (uint8_t *)&ip4->ip_src;
      dl->dl_ip_dst   = (uint8_t *)&ip4->ip_dst;

      dl->dl_flags   |= SCAMPER_DL_REC_FLAG_NET;
      dl->dl_net_type = SCAMPER_DL_REC_NET_TYPE_IP;

      pkt += iplen;
      len -= iplen;
    }
  else if((pkt[0] >> 4) == 6) /* IPv6 */
    {
      ip6 = (struct ip6_hdr *)pkt;

      if((iplen = sizeof(struct ip6_hdr)) > len)
	return 0;

      dl->dl_af       = AF_INET6;
      dl->dl_ip_hl    = iplen;
      dl->dl_ip_flow  = ntohl(ip6->ip6_flow) & 0xfffff;
      dl->dl_ip_proto = ip6->ip6_nxt;
      dl->dl_ip_size  = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);
      dl->dl_ip_hlim  = ip6->ip6_hlim;
      dl->dl_ip_src   = (uint8_t *)&ip6->ip6_src;
      dl->dl_ip_dst   = (uint8_t *)&ip6->ip6_dst;
      dl->dl_flags   |= SCAMPER_DL_REC_FLAG_NET;
      dl->dl_net_type = SCAMPER_DL_REC_NET_TYPE_IP;

      pkt += iplen;
      len -= iplen;

      /* Process any IPv6 fragmentation headers */
      for(;;)
        {
	  switch(dl->dl_ip_proto)
            {
	    case IPPROTO_HOPOPTS:
	    case IPPROTO_DSTOPTS:
	    case IPPROTO_ROUTING:
	      if(sizeof(struct ip6_ext) > len)
		return 0;
	      ip6_exthdr = (struct ip6_ext *)pkt;
	      if((extlen = (ip6_exthdr->ip6e_len * 8) + 8) > len)
		return 0;
	      dl->dl_ip_proto = ip6_exthdr->ip6e_nxt;
	      break;

	    case IPPROTO_FRAGMENT:
	      if((extlen = sizeof(struct ip6_frag)) > len)
		return 0;
	      ip6_fraghdr = (struct ip6_frag *)pkt;
	      dl->dl_ip6_id = ntohl(ip6_fraghdr->ip6f_ident);
	      dl->dl_ip_off = ntohs(ip6_fraghdr->ip6f_offlg) & 0xfff8;
	      dl->dl_ip_proto = ip6_fraghdr->ip6f_nxt;
	      dl->dl_ip_flags |= SCAMPER_DL_IP_FLAG_FRAG;
	      if(ntohs(ip6_fraghdr->ip6f_offlg) & 0x1)
		dl->dl_ip_flags |= SCAMPER_DL_IP_FLAG_MF;
	      break;

	    default:
	      extlen = 0;
	      break;
            }

	  if(extlen == 0)
	    break;

	  dl->dl_ip_hl += extlen;
	  pkt += extlen;
	  len -= extlen;
        }
    }
  else
    {
      return 0;
    }

  dl->dl_ip_data    = pkt;
  dl->dl_ip_datalen = len;

  /*
   * can't do any further processing of the packet if we're seeing
   * a later fragment
   */
  if(dl->dl_ip_off != 0)
    return 1;

  if(dl->dl_ip_proto == IPPROTO_UDP)
    {
      if((int)sizeof(struct udphdr) > len)
	{
	  return 0;
	}

      udp = (struct udphdr *)pkt;
      dl->dl_udp_dport = ntohs(udp->uh_dport);
      dl->dl_udp_sport = ntohs(udp->uh_sport);
      dl->dl_udp_sum   = udp->uh_sum;
      dl->dl_flags    |= SCAMPER_DL_REC_FLAG_TRANS;
    }
  else if(dl->dl_ip_proto == IPPROTO_TCP)
    {
      if((int)sizeof(struct tcphdr) > len)
	{
	  return 0;
	}

      tcp = (struct tcphdr *)pkt;
      dl->dl_tcp_dport  = ntohs(tcp->th_dport);
      dl->dl_tcp_sport  = ntohs(tcp->th_sport);
      dl->dl_tcp_seq    = ntohl(tcp->th_seq);
      dl->dl_tcp_ack    = ntohl(tcp->th_ack);
#ifndef _WIN32
      dl->dl_tcp_hl     = tcp->th_off * 4;
#else
      dl->dl_tcp_hl     = (tcp->th_offx2 >> 4) * 4;
#endif
      dl->dl_tcp_flags  = tcp->th_flags;
      dl->dl_tcp_win    = ntohs(tcp->th_win);
      dl->dl_flags     |= SCAMPER_DL_REC_FLAG_TRANS;

      if(dl->dl_tcp_hl >= 20 && len >= dl->dl_tcp_hl)
	{
	  off = 20;
	  while(off < dl->dl_tcp_hl)
	    {
	      tmp = pkt + off;

	      if(tmp[0] == 0) /* End of option list */
		break;

	      if(tmp[0] == 1) /* no-op */
		{
		  off++;
		  continue;
		}

	      if(tmp[1] == 0)
		break;

	      /* make sure the option can be extracted */
	      if(off + tmp[1] > dl->dl_tcp_hl)
		break;

	      if(tmp[0] == 2 && tmp[1] == 4) /* mss option */
		dl->dl_tcp_mss = bytes_ntohs(tmp+2);

	      if(tmp[0] == 4 && tmp[1] == 2) /* sack permitted option */
		dl->dl_tcp_opts |= SCAMPER_DL_TCP_OPT_SACKP;

	      if(tmp[0] == 8 && tmp[1] == 10) /* timestamps */
		{
		  dl->dl_tcp_opts |= SCAMPER_DL_TCP_OPT_TS;
		  dl->dl_tcp_tsval = bytes_ntohl(tmp+2);
		  dl->dl_tcp_tsecr = bytes_ntohl(tmp+6);
		}

	      if(tmp[0] == 5)
		{
		  if(tmp[1]==10 || tmp[1]==18 || tmp[1]==26 || tmp[1]==34)
		    {
		      dl->dl_tcp_sack_edgec = (tmp[1]-2) / 4;
		      for(i=0; i<(tmp[1]-2)/4; i++)
			dl->dl_tcp_sack_edges[i] = bytes_ntohl(tmp+2 + (i*4));
		    }
		  else
		    {
		      dl->dl_tcp_sack_edgec = -1;
		    }
		}

	      if(tmp[0] == 34 && tmp[1] >= 2)
		{
		  dl->dl_tcp_opts |= SCAMPER_DL_TCP_OPT_FO;
		  dl->dl_tcp_fo_cookielen = tmp[1] - 2;
		  for(i=0; i<dl->dl_tcp_fo_cookielen; i++)
		    dl->dl_tcp_fo_cookie[i] = tmp[2+i];
		}

	      if(tmp[0] == 254 && tmp[1] >= 4 && bytes_ntohs(tmp+2) == 0xF989)
		{
		  dl->dl_tcp_opts |= SCAMPER_DL_TCP_OPT_FO_EXP;
		  dl->dl_tcp_fo_cookielen = tmp[1] - 4;
		  for(i=0; i<dl->dl_tcp_fo_cookielen; i++)
		    dl->dl_tcp_fo_cookie[i] = tmp[4+i];
		}

	      off += tmp[1];
	    }

	  dl->dl_tcp_datalen = dl->dl_ip_size - dl->dl_ip_hl - dl->dl_tcp_hl;
	  if(dl->dl_tcp_datalen > 0)
	    dl->dl_tcp_data = pkt + dl->dl_tcp_hl;
	}
    }
  else if(dl->dl_ip_proto == IPPROTO_ICMP)
    {
      /* the absolute minimum ICMP header size is 8 bytes */
      if(ICMP_MINLEN > len)
	{
	  return 0;
	}

      icmp4 = (struct icmp *)pkt;
      dl->dl_icmp_type = icmp4->icmp_type;
      dl->dl_icmp_code = icmp4->icmp_code;

      switch(dl->dl_icmp_type)
	{
	case ICMP_UNREACH:
	case ICMP_TIMXCEED:
	  if(ICMP_MINLEN + (int)sizeof(struct ip) > len)
	    {
	      return 0;
	    }

	  if(dl->dl_icmp_type == ICMP_UNREACH &&
	     dl->dl_icmp_code == ICMP_UNREACH_NEEDFRAG)
	    {
	      dl->dl_icmp_nhmtu = ntohs(icmp4->icmp_nextmtu);
	    }

	  ip4 = &icmp4->icmp_ip;

	  dl->dl_icmp_ip_proto = ip4->ip_p;
	  dl->dl_icmp_ip_size  = ntohs(ip4->ip_len);
	  dl->dl_icmp_ip_id    = ntohs(ip4->ip_id);
	  dl->dl_icmp_ip_tos   = ip4->ip_tos;
	  dl->dl_icmp_ip_ttl   = ip4->ip_ttl;
	  dl->dl_icmp_ip_src   = (uint8_t *)&ip4->ip_src;
	  dl->dl_icmp_ip_dst   = (uint8_t *)&ip4->ip_dst;

	  /*
	   * the ICMP response should include the IP header and the first
	   * 8 bytes of the transport header.
	   */
#ifndef _WIN32
	  if((size_t)(ICMP_MINLEN + (ip4->ip_hl << 2) + 8) > len)
#else
	  if((size_t)(ICMP_MINLEN + ((ip4->ip_vhl & 0xf) << 2) + 8) > len)
#endif
	    {
	      return 0;
	    }

	  pkt = (uint8_t *)ip4;

#ifndef _WIN32
	  iplen = (ip4->ip_hl << 2);
#else
	  iplen = ((ip4->ip_vhl & 0xf) << 2);
#endif

	  pkt += iplen;

	  if(dl->dl_icmp_ip_proto == IPPROTO_UDP)
	    {
	      udp = (struct udphdr *)pkt;
	      dl->dl_icmp_udp_sport = ntohs(udp->uh_sport);
	      dl->dl_icmp_udp_dport = ntohs(udp->uh_dport);
	      dl->dl_icmp_udp_sum   = udp->uh_sum;
	    }
	  else if(dl->dl_icmp_ip_proto == IPPROTO_ICMP)
	    {
	      icmp4 = (struct icmp *)pkt;
	      dl->dl_icmp_icmp_type = icmp4->icmp_type;
	      dl->dl_icmp_icmp_code = icmp4->icmp_code;
	      dl->dl_icmp_icmp_id   = ntohs(icmp4->icmp_id);
	      dl->dl_icmp_icmp_seq  = ntohs(icmp4->icmp_seq);
	    }
	  else if(dl->dl_icmp_ip_proto == IPPROTO_TCP)
	    {
	      tcp = (struct tcphdr *)pkt;
	      dl->dl_icmp_tcp_sport = ntohs(tcp->th_sport);
	      dl->dl_icmp_tcp_dport = ntohs(tcp->th_dport);
	      dl->dl_icmp_tcp_seq   = ntohl(tcp->th_seq);
	    }
	  break;

	case ICMP_ECHOREPLY:
	case ICMP_ECHO:
	case ICMP_TSTAMPREPLY:
	case ICMP_TSTAMP:
	  dl->dl_icmp_id  = ntohs(icmp4->icmp_id);
	  dl->dl_icmp_seq = ntohs(icmp4->icmp_seq);
	  break;

	default:
	  return 0;
	}

      dl->dl_flags |= SCAMPER_DL_REC_FLAG_TRANS;
    }
  else if(dl->dl_ip_proto == IPPROTO_ICMPV6)
    {
      /* the absolute minimum ICMP header size is 8 bytes */
      if((int)sizeof(struct icmp6_hdr) > len)
	{
	  return 0;
	}

      icmp6 = (struct icmp6_hdr *)pkt;
      dl->dl_icmp_type = icmp6->icmp6_type;
      dl->dl_icmp_code = icmp6->icmp6_code;
      pkt += sizeof(struct icmp6_hdr);
      len -= sizeof(struct icmp6_hdr);

      switch(dl->dl_icmp_type)
	{
	case ICMP6_TIME_EXCEEDED:
	case ICMP6_DST_UNREACH:
	case ICMP6_PACKET_TOO_BIG:
	  if((int)sizeof(struct ip6_hdr) + 8 > len)
	    {
	      return 0;
	    }

	  if(dl->dl_icmp_type == ICMP6_PACKET_TOO_BIG)
	    {
#ifndef _WIN32
	      dl->dl_icmp_nhmtu = (ntohl(icmp6->icmp6_mtu) % 0xffff);
#else
	      dl->dl_icmp_nhmtu = ntohs(icmp6->icmp6_seq);
#endif
	    }

	  ip6 = (struct ip6_hdr *)pkt;
	  pkt += sizeof(struct ip6_hdr);

	  dl->dl_icmp_ip_proto = ip6->ip6_nxt;
	  dl->dl_icmp_ip_size  = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);
	  dl->dl_icmp_ip_hlim  = ip6->ip6_hlim;
	  dl->dl_icmp_ip_flow  = ntohl(ip6->ip6_flow) & 0xfffff;
	  dl->dl_icmp_ip_src = (uint8_t *)&ip6->ip6_src;
	  dl->dl_icmp_ip_dst = (uint8_t *)&ip6->ip6_dst;

	  if(dl->dl_icmp_ip_proto == IPPROTO_UDP)
	    {
	      udp = (struct udphdr *)pkt;
	      dl->dl_icmp_udp_sport = ntohs(udp->uh_sport);
	      dl->dl_icmp_udp_dport = ntohs(udp->uh_dport);
	      dl->dl_icmp_udp_sum   = udp->uh_sum;
	    }
	  else if(dl->dl_icmp_ip_proto == IPPROTO_ICMPV6)
	    {
	      icmp6 = (struct icmp6_hdr *)pkt;
	      dl->dl_icmp_icmp_type = icmp6->icmp6_type;
	      dl->dl_icmp_icmp_code = icmp6->icmp6_code;
	      dl->dl_icmp_icmp_id   = ntohs(icmp6->icmp6_id);
	      dl->dl_icmp_icmp_seq  = ntohs(icmp6->icmp6_seq);
	    }
	  else if(dl->dl_icmp_ip_proto == IPPROTO_TCP)
	    {
	      tcp = (struct tcphdr *)pkt;
	      dl->dl_icmp_tcp_sport = ntohs(tcp->th_sport);
	      dl->dl_icmp_tcp_dport = ntohs(tcp->th_dport);
	      dl->dl_icmp_tcp_seq   = ntohl(tcp->th_seq);
	    }
	  break;

	case ICMP6_ECHO_REPLY:
	case ICMP6_ECHO_REQUEST:
	  dl->dl_icmp_id  = ntohs(icmp6->icmp6_id);
	  dl->dl_icmp_seq = ntohs(icmp6->icmp6_seq);
	  break;

	case ND_NEIGHBOR_ADVERT:
	  dl->dl_icmp6_nd_target   = pkt;
	  dl->dl_icmp6_nd_opts     = pkt + 16;
	  dl->dl_icmp6_nd_opts_len = len - 16;
	  break;

	default:
	  return 0;
	}

      dl->dl_flags |= SCAMPER_DL_REC_FLAG_TRANS;
    }
  else
    {
      return 0;
    }

  return 1;
}

/*
 * dlt_raw_cb
 *
 * handle raw IP frames.
 * i'm not sure how many of these interface types there are, but the linux
 * sit interface is an example of one that is...
 *
 */
static int dlt_raw_cb(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
{
  int ret;

  if((ret = dl_parse_ip(dl, pkt, len)) != 0)
    {
      dl->dl_type = SCAMPER_DL_TYPE_RAW;
      dl->dl_net_raw = pkt;
      dl->dl_net_rawlen = len;
    }

  return ret;
}

/*
 * dlt_null_cb
 *
 * handle the BSD loopback encapsulation.  the first 4 bytes say what protocol
 * family is used.  filter out anything that is not IPv4 / IPv6
 *
 */
#ifdef HAVE_BPF
static int dlt_null_cb(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
{
  uint32_t pf;
  int ret;

  /* ensure the packet holds at least 4 bytes for the psuedo header */
  if(len <= 4)
    {
      return 0;
    }

  memcpy(&pf, pkt, 4);
  if(pf == PF_INET || pf == PF_INET6)
    {
      if((ret = dl_parse_ip(dl, pkt+4, len-4)) != 0)
	{
	  dl->dl_type = SCAMPER_DL_TYPE_NULL;
	  dl->dl_net_raw = pkt+4;
	  dl->dl_net_rawlen = len-4;
	}

      return ret;
    }

  return 0;
}
#endif

/*
 * dlt_en10mb_cb
 *
 * handle ethernet frames.
 *
 * an ethernet frame consists of
 *   - 6 bytes dst mac
 *   - 6 bytes src mac
 *   - 2 bytes type
 *
 */
static int dlt_en10mb_cb(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
{
  uint16_t u16;
  size_t off;

  /* ensure the packet holds at least the length of the ethernet header */
  if(len <= 14)
    return 0;

  u16 = bytes_ntohs(pkt+12);
  if(u16 == ETHERTYPE_IP || u16 == ETHERTYPE_IPV6)
    {
      if(dl_parse_ip(dl, pkt+14, len-14) == 0)
	return 0;
    }
  else if(u16 == ETHERTYPE_ARP)
    {
      /* need to at least have a header */
      if(14 + 8 >= len)
	return 0;

      off = 14;
      dl->dl_arp_hrd = bytes_ntohs(pkt+off); off += 2;
      dl->dl_arp_pro = bytes_ntohs(pkt+off); off += 2;
      dl->dl_arp_hln = pkt[off++];
      dl->dl_arp_pln = pkt[off++];
      dl->dl_arp_op  = bytes_ntohs(pkt+off); off += 2;

      /* make sure all the bits are found after the arp header */
      if(14 + 8 + (dl->dl_arp_hln*2) + (dl->dl_arp_pln*2) > len)
	return 0;

      dl->dl_arp_sha = pkt+off; off += dl->dl_arp_hln;
      dl->dl_arp_spa = pkt+off; off += dl->dl_arp_pln;
      dl->dl_arp_tha = pkt+off; off += dl->dl_arp_hln;
      dl->dl_arp_tpa = pkt+off;

      /* completed record is an arp frame */
      dl->dl_net_type = SCAMPER_DL_REC_NET_TYPE_ARP;
    }
  else return 0;

  dl->dl_type       = SCAMPER_DL_TYPE_ETHERNET;
  dl->dl_lladdr_dst = pkt;
  dl->dl_lladdr_src = pkt+6;
  dl->dl_net_raw    = pkt+14;
  dl->dl_net_rawlen = len-14;

  return 1;
}

/*
 * dlt_firewire_cb
 *
 * handle IP frames on firewire devices.  a firewire layer-2 frame consists
 * of two 8 byte EUI64 addresses which represent the dst and the src
 * addresses, and a 2 byte ethertype
 */
#ifdef HAVE_FIREWIRE
static int dlt_firewire_cb(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
{
  int ret;
  uint16_t type;

  /* ensure the packet holds at least the length of the firewire header */
  if(len <= 18)
    {
      return 0;
    }

  memcpy(&type, pkt+16, 2); type = ntohs(type);
  if(type == ETHERTYPE_IP || type == ETHERTYPE_IPV6)
    {
      if((ret = dl_parse_ip(dl, pkt+18, len-18)) != 0)
	{
	  dl->dl_type = SCAMPER_DL_TYPE_FIREWIRE;
	  dl->dl_lladdr_dst = pkt;
	  dl->dl_lladdr_src = pkt + 8;
	  dl->dl_net_raw    = pkt + 18;
	  dl->dl_net_rawlen = len - 18;
	}

      return ret;
    }

  return 0;
}
#endif

#if defined(HAVE_BPF)
static int dl_bpf_open_dev(char *dev, const size_t len)
{
  int i=0, fd;

  do
    {
      snprintf(dev, len, "/dev/bpf%d", i);
      if((fd = open(dev, O_RDWR)) == -1)
	{
	  if(errno == EBUSY)
	    {
	      continue;
	    }
	  else
	    {
	      printerror(__func__, "could not open %s", dev);
	      return -1;
	    }
	}
      else break;
    }
  while(++i < 32768);

  return fd;
}

static int dl_bpf_open(const int ifindex)
{
  struct ifreq ifreq;
  char dev[16];
  u_int blen;
  int fd = -1;

  /* work out the name corresponding to the ifindex */
  memset(&ifreq, 0, sizeof(ifreq));
  if(if_indextoname((unsigned int)ifindex, ifreq.ifr_name) == NULL)
    {
      printerror(__func__, "if_indextoname failed");
      goto err;
    }

  if((fd = dl_bpf_open_dev(dev, sizeof(dev))) == -1)
    {
      goto err;
    }

  /* get the suggested read buffer size */
  if(ioctl(fd, BIOCGBLEN, &blen) == -1)
    {
      printerror(__func__, "BIOCGBLEN %s", ifreq.ifr_name);
      goto err;
    }

  /*
   * try and get the system to use a larger buffer.  need to do this
   * before the call to BIOCSETIF.
   */
  if(blen < 65536)
    {
      blen = 65536;
      if(ioctl(fd, BIOCSBLEN, &blen) == -1)
	{
	  printerror(__func__, "BIOCSBLEN %s: %d", ifreq.ifr_name, blen);
	  goto err;
	}
    }

  /* set the interface that will be sniffed */
  if(ioctl(fd, BIOCSETIF, &ifreq) == -1)
    {
      printerror(__func__, "%s BIOCSETIF %s failed", dev, ifreq.ifr_name);
      goto err;
    }

  return fd;

 err:
  if(fd != -1) close(fd);
  return -1;
}

static int dl_bpf_node_init(const scamper_fd_t *fdn, scamper_dl_t *node)
{
  char ifname[IFNAMSIZ];
  u_int tmp;
  int ifindex, fd;
  uint8_t *buf;

  /* get the file descriptor associated with the fd node */
  if((fd = scamper_fd_fd_get(fdn)) < 0)
    {
      goto err;
    }

  /* get the interface index */
  if(scamper_fd_ifindex(fdn, &ifindex) != 0)
    {
      goto err;
    }

  /* convert the interface index to a name */
  if(if_indextoname((unsigned int)ifindex, ifname) == NULL)
    {
      printerror(__func__,"if_indextoname %d failed", ifindex);
      goto err;
    }

  /* get the read buffer size */
  if(ioctl(fd, BIOCGBLEN, &node->readbuf_len) == -1)
    {
      printerror(__func__, "bpf BIOCGBLEN %s failed", ifname);
      goto err;
    }

  /* get the DLT type for the interface */
  if(ioctl(fd, BIOCGDLT, &tmp) == -1)
    {
      printerror(__func__, "bpf BIOCGDLT %s failed", ifname);
      goto err;
    }
  node->type = tmp;

  switch(node->type)
    {
    case DLT_NULL:
      node->dlt_cb = dlt_null_cb;
      if(osinfo->os_id == SCAMPER_OSINFO_OS_FREEBSD &&
	 osinfo->os_rel_dots > 0 && osinfo->os_rel[0] >= 6)
	{
	  node->tx_type = SCAMPER_DL_TX_NULL;
	}
      else
	{
	  node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
	}
      break;

    case DLT_EN10MB:
      node->dlt_cb = dlt_en10mb_cb;
      node->tx_type = SCAMPER_DL_TX_ETHERNET;
      break;

    case DLT_RAW:
      node->dlt_cb = dlt_raw_cb;
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      break;

#if defined(DLT_APPLE_IP_OVER_IEEE1394)
    case DLT_APPLE_IP_OVER_IEEE1394:
      node->dlt_cb = dlt_firewire_cb;
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      break;
#endif

    default:
      scamper_debug(__func__, "%s unhandled datalink %d", ifname, node->type);
      goto err;
    }

  scamper_debug(__func__, "bpf if %s index %d buflen %d datalink %d",
		ifname, ifindex, node->readbuf_len, node->type);

  tmp = 1;
  if(ioctl(fd, BIOCIMMEDIATE, &tmp) == -1)
    {
      printerror(__func__, "bpf BIOCIMMEDIATE failed");
      goto err;
    }

  if(readbuf_len < node->readbuf_len)
    {
      if((buf = realloc(readbuf, node->readbuf_len)) == NULL)
	{
	  printerror(__func__, "could not realloc");
	  return -1;
	}
      readbuf     = buf;
      readbuf_len = node->readbuf_len;
    }

  return 0;

 err:
  return -1;
}

static int dl_bpf_init(void)
{
  struct bpf_version bv;
  int  fd;
  char buf[16];
  int  err;

  if((fd = dl_bpf_open_dev(buf, sizeof(buf))) == -1)
    {
      if(errno == ENXIO)
	{
	  return 0;
	}
      return -1;
    }

  err = ioctl(fd, BIOCVERSION, &bv);
  close(fd);
  if(err == -1)
    {
      printerror(__func__, "BIOCVERSION failed");
      return -1;
    }

  scamper_debug(__func__, "bpf version %d.%d", bv.bv_major, bv.bv_minor);
  if(bv.bv_major != BPF_MAJOR_VERSION || bv.bv_minor < BPF_MINOR_VERSION)
    {
      printerror_msg(__func__, "bpf ver %d.%d is incompatible with %d.%d",
		     bv.bv_major, bv.bv_minor,
		     BPF_MAJOR_VERSION, BPF_MINOR_VERSION);
      return -1;
    }

  osinfo = scamper_osinfo_get();
  if(osinfo->os_id == SCAMPER_OSINFO_OS_FREEBSD &&
     osinfo->os_rel_dots >= 2 && osinfo->os_rel[0] == 4 &&
     (osinfo->os_rel[1] == 3 || osinfo->os_rel[1] == 4))
    {
      printerror_msg(__func__,
		     "BPF file descriptors do not work with "
		     "select in FreeBSD 4.3 or 4.4");
      return -1;
    }

  return 0;
}

static int dl_bpf_read(const int fd, scamper_dl_t *node)
{
  struct bpf_hdr    *bpf_hdr;
  scamper_dl_rec_t   dl;
  ssize_t            len;
  uint8_t           *buf = readbuf;

  while((len = read(fd, buf, node->readbuf_len)) == -1)
    {
      if(errno == EINTR) continue;
      if(errno == EWOULDBLOCK) return 0;
      printerror(__func__, "read %d bytes from fd %d failed",
		 node->readbuf_len, fd);
      return -1;
    }

  /* record the ifindex now, as the cb may need it */
  if(scamper_fd_ifindex(node->fdn, &dl.dl_ifindex) != 0)
    {
      return -1;
    }

  while(buf < readbuf + len)
    {
      bpf_hdr = (struct bpf_hdr *)buf;

      /* reset the datalink record */
      memset(&dl, 0, sizeof(dl));

      if(node->dlt_cb(&dl, buf + bpf_hdr->bh_hdrlen, bpf_hdr->bh_caplen))
	{
	  /* bpf always supplies a timestamp */
	  dl.dl_flags |= SCAMPER_DL_REC_FLAG_TIMESTAMP;

	  dl.dl_tv.tv_sec  = bpf_hdr->bh_tstamp.tv_sec;
	  dl.dl_tv.tv_usec = bpf_hdr->bh_tstamp.tv_usec;

	  scamper_task_handledl(&dl);
	}

      buf += BPF_WORDALIGN(bpf_hdr->bh_caplen + bpf_hdr->bh_hdrlen);
    }

  return 0;
}

static int dl_bpf_tx(const scamper_dl_t *node,
		     const uint8_t *pkt, const size_t len)
{
  ssize_t wb;

  if((wb = write(scamper_fd_fd_get(node->fdn), pkt, len)) < (ssize_t)len)
    {
      if(wb == -1)
	printerror(__func__, "%d bytes failed", len);
      else
	scamper_debug(__func__, "%d bytes sent of %d total", wb, len);
      return -1;
    }

  return 0;
}

static int dl_bpf_filter(scamper_dl_t *node, struct bpf_insn *insns, int len)
{
  struct bpf_program prog;

  prog.bf_len   = len;
  prog.bf_insns = insns;

  if(ioctl(scamper_fd_fd_get(node->fdn), BIOCSETF, (caddr_t)&prog) == -1)
    {
      printerror(__func__, "BIOCSETF failed");
      return -1;
    }

  return 0;
}

#elif defined(__linux__)

static int dl_linux_open(const int ifindex)
{
  struct sockaddr_ll sll;
  int fd;

  /* open the socket in non cooked mode for now */
  if((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    {
      printerror(__func__, "could not open PF_PACKET");
      return -1;
    }

  /* scamper only wants packets on this interface */
  memset(&sll, 0, sizeof(sll));
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifindex;
  sll.sll_protocol = htons(ETH_P_ALL);
  if(bind(fd, (struct sockaddr *)&sll, sizeof(sll)) == -1)
    {
      printerror(__func__, "could not bind to %d", ifindex);
      close(fd);
      return -1;
    }

  return fd;
}

static int dl_linux_node_init(const scamper_fd_t *fdn, scamper_dl_t *node)
{
  struct ifreq ifreq;
  char ifname[IFNAMSIZ];
  int fd, ifindex;

  if(scamper_fd_ifindex(fdn, &ifindex) != 0)
    {
      goto err;
    }

  if((fd = scamper_fd_fd_get(fdn)) < 0)
    {
      goto err;
    }

  if(if_indextoname(ifindex, ifname) == NULL)
    {
      printerror(__func__, "if_indextoname %d failed", ifindex);
      goto err;
    }

  /* find out what type of datalink the interface has */
  memcpy(ifreq.ifr_name, ifname, sizeof(ifreq.ifr_name));
  if(ioctl(fd, SIOCGIFHWADDR, &ifreq) == -1)
    {
      printerror(__func__, "%s SIOCGIFHWADDR failed", ifname);
      goto err;
    }

  node->type = ifreq.ifr_hwaddr.sa_family;

  /* scamper can only deal with ethernet datalinks at this time */
  switch(node->type)
    {
    case ARPHRD_ETHER:
      node->dlt_cb = dlt_en10mb_cb;
      node->tx_type = SCAMPER_DL_TX_ETHERNET;
      break;

    case ARPHRD_LOOPBACK:
      node->dlt_cb = dlt_en10mb_cb;
      node->tx_type = SCAMPER_DL_TX_ETHLOOP;
      break;

#if defined(ARPHRD_SIT)
    case ARPHRD_SIT:
      node->dlt_cb = dlt_raw_cb;
      node->tx_type = SCAMPER_DL_TX_RAW;
      break;
#endif

#if defined(ARPHRD_IEEE1394)
    case ARPHRD_IEEE1394:
      node->dlt_cb = dlt_firewire_cb;
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      break;
#endif

#if defined(ARPHRD_VOID)
    case ARPHRD_VOID:
      node->dlt_cb = dlt_raw_cb;
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      break;
#endif

    default:
      scamper_debug(__func__, "%s unhandled datalink %d", ifname, node->type);
      goto err;
    }

  return 0;

 err:
  return -1;
}

static int dl_linux_read(const int fd, scamper_dl_t *node)
{
  scamper_dl_rec_t   dl;
  ssize_t            len;
  struct sockaddr_ll from;
  socklen_t          fromlen;

  fromlen = sizeof(from);
  while((len = recvfrom(fd, readbuf, readbuf_len, MSG_TRUNC,
			(struct sockaddr *)&from, &fromlen)) == -1)
    {
      if(errno == EINTR)
	{
	  fromlen = sizeof(from);
	  continue;
	}
      if(errno == EAGAIN)
	{
	  return 0;
	}
      printerror(__func__, "read %d bytes from fd %d failed", readbuf_len, fd);
      return -1;
    }

  /* sanity check the packet length */
  if(len > readbuf_len) len = readbuf_len;

  /* reset the datalink record */
  memset(&dl, 0, sizeof(dl));

  /* record the ifindex now, as the cb routine may need it */
  if(scamper_fd_ifindex(node->fdn, &dl.dl_ifindex) != 0)
    {
      return -1;
    }

  /* if the packet passes the filter, we need to get the time it was rx'd */
  if(node->dlt_cb(&dl, readbuf, len))
    {
      /* scamper treats the failure of this ioctl as non-fatal */
      if(ioctl(fd, SIOCGSTAMP, &dl.dl_tv) == 0)
	{
	  dl.dl_flags |= SCAMPER_DL_REC_FLAG_TIMESTAMP;
	}
      else
	{
	  printerror(__func__, "could not SIOCGSTAMP on fd %d", fd);
	}

      scamper_task_handledl(&dl);
    }

  return 0;
}

static int dl_linux_tx(const scamper_dl_t *node,
		       const uint8_t *pkt, const size_t len)
{
  struct sockaddr_ll sll;
  struct sockaddr *sa = (struct sockaddr *)&sll;
  ssize_t wb;
  int fd, ifindex;

  if(scamper_fd_ifindex(node->fdn, &ifindex) != 0)
    {
      return -1;
    }

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifindex;

  if(node->type == ARPHRD_SIT)
    sll.sll_protocol = htons(ETH_P_IPV6);
  else
    sll.sll_protocol = htons(ETH_P_ALL);

  fd = scamper_fd_fd_get(node->fdn);

  if((wb = sendto(fd, pkt, len, 0, sa, sizeof(sll))) < (ssize_t)len)
    {
      if(wb == -1)
	printerror(__func__, "%d bytes failed", len);
      else
	scamper_debug(__func__, "%d bytes sent of %d total", wb, len);
      return -1;
    }

  return 0;
}

static int dl_linux_filter(scamper_dl_t *node,
			   struct sock_filter *insns, int len)
{
  struct sock_fprog prog;
  int i;

  for(i=0; i<len; i++)
    {
      if(insns[i].code == (BPF_RET+BPF_K) && insns[i].k > 0)
	{
	  insns[i].k = 65535;
	}
    }

  prog.len    = len;
  prog.filter = insns;

  if(setsockopt(scamper_fd_fd_get(node->fdn), SOL_SOCKET, SO_ATTACH_FILTER,
		(caddr_t)&prog, sizeof(prog)) == -1)
    {
      printerror(__func__, "SO_ATTACH_FILTER failed");
      return -1;
    }

  return 0;
}

#elif defined(HAVE_DLPI)

static int dl_dlpi_open(const int ifindex)
{
  char ifname[5+IFNAMSIZ];
  int fd;

  strncpy(ifname, "/dev/", sizeof(ifname));
  if(if_indextoname(ifindex, ifname+5) == NULL)
    {
      printerror(__func__, "if_indextoname %d failed", ifindex);
      return -1;
    }

  if((fd = open(ifname, O_RDWR)) == -1)
    {
      printerror(__func__, "could not open %s", ifname);
      return -1;
    }

  return fd;
}

static int dl_dlpi_req(const int fd, void *req, size_t len)
{
  union	DL_primitives *dlp;
  struct strbuf ctl;

  ctl.maxlen = 0;
  ctl.len = len;
  ctl.buf = (char *)req;

  if(putmsg(fd, &ctl, NULL, 0) == -1)
    {
      dlp = req;
      printerror(__func__, "could not putmsg %d", dlp->dl_primitive);
      return -1;
    }

  return 0;
}

static int dl_dlpi_ack(const int fd, void *ack, int primitive)
{
  union	DL_primitives *dlp;
  struct strbuf ctl;
  int flags;

  flags = 0;
  ctl.maxlen = MAXDLBUF;
  ctl.len = 0;
  ctl.buf = (char *)ack;
  if(getmsg(fd, &ctl, NULL, &flags) == -1)
    {
      printerror(__func__, "could not getmsg %d", primitive);
      return -1;
    }

  dlp = ack;
  if(dlp->dl_primitive != primitive)
    {
      scamper_debug(__func__,
		    "expected %d, got %d", primitive, dlp->dl_primitive);
      return -1;
    }

  return 0;
}

static int dl_dlpi_promisc(const int fd, const int level)
{
  dl_promiscon_req_t promiscon_req;
  uint32_t buf[MAXDLBUF];

  promiscon_req.dl_primitive = DL_PROMISCON_REQ;
  promiscon_req.dl_level = level;
  if(dl_dlpi_req(fd, &promiscon_req, sizeof(promiscon_req)) == -1)
    {
      return -1;
    }

  /* check for an ack to the promisc req */
  if(dl_dlpi_ack(fd, buf, DL_OK_ACK) == -1)
    {
      return -1;
    }

  return 0;
}

static int strioctl(int fd, int cmd, void *dp, int len)
{
  struct strioctl str;

  str.ic_cmd = cmd;
  str.ic_timout = -1;
  str.ic_len = len;
  str.ic_dp = (char *)dp;
  if(ioctl(fd, I_STR, &str) == -1)
    {
      return -1;
    }

  return str.ic_len;
}

static int dl_dlpi_node_init(const scamper_fd_t *fdn, scamper_dl_t *node)
{
  uint32_t         buf[MAXDLBUF];
  struct timeval   tv;
  dl_info_req_t    info_req;
  dl_info_ack_t   *info_ack;
  dl_attach_req_t  attach_req;
  dl_bind_req_t    bind_req;
  int              i, fd;

#ifndef NDEBUG
  char             ifname[IFNAMSIZ];
  int              ifindex;
#endif

  if((fd = scamper_fd_fd_get(fdn)) < 0)
    {
      return -1;
    }

  /*
   * send an information request to the datalink to determine what type
   * of packets they supply
   */
  info_req.dl_primitive = DL_INFO_REQ;
  if(dl_dlpi_req(fd, &info_req, sizeof(info_req)) == -1)
    {
      return -1;
    }

  /*
   * read the information acknowledgement, which contains details on the
   * type of the interface, etc.
   */
  if(dl_dlpi_ack(fd, buf, DL_INFO_ACK) == -1)
    {
      return -1;
    }
  info_ack = (dl_info_ack_t *)buf;

  /* record the mac type with the node */
  node->type = info_ack->dl_mac_type;

  /* determine how to handle the datalink */
  switch(node->type)
    {
    case DL_CSMACD:
    case DL_ETHER:
      node->dlt_cb = dlt_en10mb_cb;
      node->tx_type = SCAMPER_DL_TX_ETHERNET;
      break;

    default:
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      scamper_debug(__func__, "unhandled datalink %d", node->type);
      return -1;
    }

  /* attach to the interface */
  if(info_ack->dl_provider_style == DL_STYLE2)
    {
      attach_req.dl_primitive = DL_ATTACH_REQ;
      attach_req.dl_ppa = 0;
      if(dl_dlpi_req(fd, &attach_req, sizeof(attach_req)) == -1)
	{
	  return -1;
	}

      /* check for a generic ack */
      if(dl_dlpi_ack(fd, buf, DL_OK_ACK) == -1)
	{
	  return -1;
	}
    }

  /* bind the interface */
  memset(&bind_req, 0, sizeof(bind_req));
  bind_req.dl_primitive = DL_BIND_REQ;
  bind_req.dl_service_mode = DL_CLDLS;
  if(dl_dlpi_req(fd, &bind_req, sizeof(bind_req)) == -1)
    {
      return -1;
    }

  /* check for an ack to the bind */
  if(dl_dlpi_ack(fd, buf, DL_BIND_ACK) == -1)
    {
      return -1;
    }

  /*
   * turn on phys and sap promisc modes.  dlpi will not supply outbound
   * probe packets unless in phys promisc mode.
   */
  if(dl_dlpi_promisc(fd, DL_PROMISC_PHYS) == -1 ||
     dl_dlpi_promisc(fd, DL_PROMISC_SAP) == -1)
    {
      return -1;
    }

  /* get full link layer */
  if(strioctl(fd, DLIOCRAW, NULL, 0) == -1)
    {
      printerror(__func__, "could not DLIOCRAW");
      return -1;
    }

  /* push bufmod */
  if(ioctl(fd, I_PUSH, "bufmod") == -1)
    {
      printerror(__func__, "could not push bufmod");
      return -1;
    }

  /* we need the first 1500 bytes of the packet */
  i = 1500;
  if(strioctl(fd, SBIOCSSNAP, &i, sizeof(i)) == -1)
    {
      printerror(__func__, "could not SBIOCSSNAP %d", i);
      return -1;
    }

  /* send the data every 50ms */
  tv.tv_sec = 0;
  tv.tv_usec = 50000;
  if(strioctl(fd, SBIOCSTIME, &tv, sizeof(tv)) == -1)
    {
      printerror(__func__, "could not SBIOCSTIME %d.%06d",
		 tv.tv_sec, tv.tv_usec);
      return -1;
    }

  /* set the chunk length */
  i = 65535;
  if(strioctl(fd, SBIOCSCHUNK, &i, sizeof(i)) == -1)
    {
      printerror(__func__, "could not SBIOCSCHUNK %d", i);
      return -1;
    }

  if(ioctl(fd, I_FLUSH, FLUSHR) == -1)
    {
      printerror(__func__, "could not flushr");
      return -1;
    }

#ifndef NDEBUG
  if(scamper_fd_ifindex(fdn, &ifindex) != 0 ||
     if_indextoname(ifindex, ifname) == NULL)
    {
      strncpy(ifname, "<null>", sizeof(ifname)-1);
      ifname[sizeof(ifname)-1] = '\0';
    }
  scamper_debug(__func__, "dlpi if %s index %d datalink %d",
		ifname, ifindex, node->type);
#endif

  return 0;
}

static int dl_dlpi_read(const int fd, scamper_dl_t *node)
{
  scamper_dl_rec_t  dl;
  struct strbuf     data;
  struct sb_hdr    *sbh;
  uint8_t          *buf = readbuf;
  int               flags;

  flags = 0;
  data.buf = (void *)readbuf;
  data.maxlen = readbuf_len;
  data.len = 0;

  if(getmsg(fd, NULL, &data, &flags) == -1)
    {
      printerror(__func__, "could not getmsg");
      return -1;
    }

  while(buf < readbuf + data.len)
    {
      sbh = (struct sb_hdr *)buf;

      memset(&dl, 0, sizeof(dl));
      dl.dl_flags = SCAMPER_DL_REC_FLAG_TIMESTAMP;

      if(node->dlt_cb(&dl, buf + sizeof(struct sb_hdr), sbh->sbh_msglen))
	{
	  dl.dl_tv.tv_sec  = sbh->sbh_timestamp.tv_sec;
	  dl.dl_tv.tv_usec = sbh->sbh_timestamp.tv_usec;
	  scamper_task_handledl(&dl);
	}

      buf += sbh->sbh_totlen;
    }

  return -1;
}

static int dl_dlpi_tx(const scamper_dl_t *node,
		      const uint8_t *pkt, const size_t len)
{
  struct strbuf data;
  int fd;

  if((fd = scamper_fd_fd_get(node->fdn)) < 0)
    return -1;

  memset(&data, 0, sizeof(data));
  data.buf = (void *)pkt;
  data.len = len;

  if(putmsg(fd, NULL, &data, 0) != 0)
    {
      printerror(__func__, "could not putmsg");
      return -1;
    }

  return 0;
}

#endif

#if defined(HAVE_BPF_FILTER)

#if defined(HAVE_BPF)
static void bpf_stmt(struct bpf_insn *insn, uint16_t code, uint32_t k)
#else
static void bpf_stmt(struct sock_filter *insn, uint16_t code, uint32_t k)
#endif
{
  insn->code = code;
  insn->jt   = 0;
  insn->jf   = 0;
  insn->k    = k;
  return;
}

static int dl_filter(scamper_dl_t *node)
{
#if defined(HAVE_BPF)
  struct bpf_insn insns[1];
#else
  struct sock_filter insns[1];
#endif

  bpf_stmt(&insns[0], BPF_RET+BPF_K, 65535);

#if defined(HAVE_BPF)
  if(dl_bpf_filter(node, insns, 1) == -1)
#elif defined(__linux__)
  if(dl_linux_filter(node, insns, 1) == -1)
#endif
    {
      return -1;
    }

   return 0;
}
#endif

int scamper_dl_rec_src(scamper_dl_rec_t *dl, scamper_addr_t *addr)
{
  if(dl->dl_af == AF_INET)
    addr->type = SCAMPER_ADDR_TYPE_IPV4;
  else if(dl->dl_af == AF_INET6)
    addr->type = SCAMPER_ADDR_TYPE_IPV6;
  else
    return -1;

  addr->addr = dl->dl_ip_src;
  return 0;
}

int scamper_dl_rec_icmp_ip_dst(scamper_dl_rec_t *dl, scamper_addr_t *addr)
{
  if(dl->dl_af == AF_INET)
    addr->type = SCAMPER_ADDR_TYPE_IPV4;
  else if(dl->dl_af == AF_INET6)
    addr->type = SCAMPER_ADDR_TYPE_IPV6;
  else
    return -1;

  addr->addr = dl->dl_icmp_ip_dst;
  return 0;
}

#if !defined(NDEBUG) && !defined(WITHOUT_DEBUGFILE)
void scamper_dl_rec_frag_print(const scamper_dl_rec_t *dl)
{
  char addr[64];
  uint32_t id;

  assert(dl->dl_af == AF_INET || dl->dl_af == AF_INET6);

  if(dl->dl_af == AF_INET)
    id = dl->dl_ip_id;
  else
    id = dl->dl_ip6_id;

  scamper_debug(NULL, "from %s len %d ipid %u off %u",
		addr_tostr(dl->dl_af, dl->dl_ip_src, addr, sizeof(addr)),
		dl->dl_ip_size, id, dl->dl_ip_off);

  return;
}

void scamper_dl_rec_udp_print(const scamper_dl_rec_t *dl)
{
  char addr[64], ipid[16];

  assert(dl->dl_af == AF_INET || dl->dl_af == AF_INET6);
  assert(dl->dl_ip_proto == IPPROTO_UDP);

  if(dl->dl_af == AF_INET)
    snprintf(ipid, sizeof(ipid), "ipid 0x%04x ", dl->dl_ip_id);
  else
    ipid[0] = '\0';

  scamper_debug(NULL, "from %s %sudp %d:%d len %d",
		addr_tostr(dl->dl_af, dl->dl_ip_src, addr, sizeof(addr)),
		ipid, dl->dl_tcp_sport, dl->dl_tcp_dport, dl->dl_ip_size);
  return;
}

void scamper_dl_rec_tcp_print(const scamper_dl_rec_t *dl)
{
  static const char *tcpflags[] = {
    "fin",
    "syn",
    "rst",
    "psh",
    "ack",
    "urg",
    "ece",
    "cwr"
  };
  uint8_t u8;
  size_t off;
  char addr[64];
  char fbuf[32], *flags;
  char pos[32];
  char ipid[16];
  int i;

  assert(dl->dl_af == AF_INET || dl->dl_af == AF_INET6);
  assert(dl->dl_ip_proto == IPPROTO_TCP);

  if((u8 = dl->dl_tcp_flags) != 0)
    {
      flags = fbuf;
      for(i=0; i<8; i++)
	{
	  if((dl->dl_tcp_flags & (1<<i)) != 0)
	    {
	      memcpy(flags, tcpflags[i], 3); flags += 3;
	      u8 &= ~(1<<i);
	      if(u8 != 0)
		{
		  *flags = '-';
		  flags++;
		}
	      else break;
	    }
	}
      *flags = '\0';
      flags = fbuf;
    }
  else
    {
      flags = "nil";
    }

  off = 0;
  string_concat(pos, sizeof(pos), &off, "%u", dl->dl_tcp_seq);
  if(dl->dl_tcp_flags & TH_ACK)
    string_concat(pos, sizeof(pos), &off, ":%u", dl->dl_tcp_ack);

  if(dl->dl_af == AF_INET)
    snprintf(ipid, sizeof(ipid), "ipid 0x%04x ", dl->dl_ip_id);
  else
    ipid[0] = '\0';

  scamper_debug(NULL, "from %s %stcp %d:%d %s %s len %d",
		addr_tostr(dl->dl_af, dl->dl_ip_src, addr, sizeof(addr)),
		ipid, dl->dl_tcp_sport, dl->dl_tcp_dport, flags, pos,
		dl->dl_ip_size);

  return;
}

void scamper_dl_rec_icmp_print(const scamper_dl_rec_t *dl)
{
  char *t = NULL, tbuf[64];
  char *c = NULL, cbuf[64];
  char addr[64];
  char ip[256];
  char icmp[256];
  char inner_ip[256];
  char inner_transport[256];
  size_t off;

  assert(dl->dl_af == AF_INET || dl->dl_af == AF_INET6);

  if(dl->dl_af == AF_INET)
    {
      addr_tostr(AF_INET, dl->dl_ip_src, addr, sizeof(addr));
      snprintf(ip, sizeof(ip), "from %s size %d ttl %d tos 0x%02x ipid 0x%04x",
	       addr, dl->dl_ip_size, dl->dl_ip_ttl, dl->dl_ip_tos,
	       dl->dl_ip_id);

      switch(dl->dl_icmp_type)
        {
        case ICMP_UNREACH:
          t = "unreach";
          switch(dl->dl_icmp_code)
            {
            case ICMP_UNREACH_NET:           c = "net";           break;
            case ICMP_UNREACH_HOST:          c = "host";          break;
            case ICMP_UNREACH_PROTOCOL:      c = "protocol";      break;
            case ICMP_UNREACH_PORT:          c = "port";          break;
            case ICMP_UNREACH_SRCFAIL:       c = "src-rt failed"; break;
            case ICMP_UNREACH_NET_UNKNOWN:   c = "net unknown";   break;
            case ICMP_UNREACH_HOST_UNKNOWN:  c = "host unknown";  break;
            case ICMP_UNREACH_ISOLATED:      c = "isolated";      break;
            case ICMP_UNREACH_NET_PROHIB:    c = "net prohib";    break;
            case ICMP_UNREACH_HOST_PROHIB:   c = "host prohib";   break;
            case ICMP_UNREACH_TOSNET:        c = "tos net";       break;
            case ICMP_UNREACH_TOSHOST:       c = "tos host";      break;
            case ICMP_UNREACH_FILTER_PROHIB: c = "admin prohib";  break;
            case ICMP_UNREACH_NEEDFRAG:
	      /*
	       * use the type buf to be consistent with the ICMP6
	       * fragmentation required message
	       */
	      snprintf(tbuf, sizeof(tbuf), "need frag %d", dl->dl_icmp_nhmtu);
	      t = tbuf;
	      break;

            default:
	      snprintf(cbuf, sizeof(cbuf), "code %d", dl->dl_icmp_code);
	      c = cbuf;
	      break;
            }
          break;

        case ICMP_TIMXCEED:
          t = "time exceeded";
          switch(dl->dl_icmp_code)
            {
            case ICMP_TIMXCEED_INTRANS: c = "in trans"; break;
            case ICMP_TIMXCEED_REASS:   c = "in reass"; break;
            default:
	      snprintf(cbuf, sizeof(cbuf), "code %d", dl->dl_icmp_code);
	      c = cbuf;
	      break;
            }
          break;

	case ICMP_ECHOREPLY:
	  t = "echo reply";
	  snprintf(cbuf, sizeof(cbuf), "id %d seq %d",
		   dl->dl_icmp_id, dl->dl_icmp_seq);
	  c = cbuf;
	  break;

	case ICMP_TSTAMPREPLY:
	  t = "time reply";
	  snprintf(cbuf, sizeof(cbuf), "id %d seq %d",
		   dl->dl_icmp_id, dl->dl_icmp_seq);
	  c = cbuf;
	  break;
        }
    }
  else
    {
      addr_tostr(AF_INET6, dl->dl_ip_src, addr, sizeof(addr));
      off = 0;
      string_concat(ip, sizeof(ip), &off, "from %s size %d hlim %d", addr,
		    dl->dl_ip_size, dl->dl_ip_hlim);
      if(dl->dl_ip_flags & SCAMPER_DL_IP_FLAG_FRAG)
	string_concat(ip, sizeof(ip), &off, " ipid 0x%08x", dl->dl_ip6_id);

      switch(dl->dl_icmp_type)
        {
        case ICMP6_DST_UNREACH:
          t = "unreach";
          switch(dl->dl_icmp_code)
            {
            case ICMP6_DST_UNREACH_NOROUTE:     c = "no route";     break;
            case ICMP6_DST_UNREACH_ADMIN:       c = "admin prohib"; break;
            case ICMP6_DST_UNREACH_BEYONDSCOPE: c = "beyond scope"; break;
            case ICMP6_DST_UNREACH_ADDR:        c = "addr";         break;
            case ICMP6_DST_UNREACH_NOPORT:      c = "port";         break;

            default:
	      snprintf(cbuf, sizeof(cbuf), "code %d", dl->dl_icmp_code);
	      c = cbuf;
	      break;
            }
          break;

        case ICMP6_TIME_EXCEEDED:
          t = "time exceeded";
          switch(dl->dl_icmp_code)
            {
            case ICMP6_TIME_EXCEED_TRANSIT:    c = "in trans"; break;
            case ICMP6_TIME_EXCEED_REASSEMBLY: c = "in reass"; break;

            default:
	      snprintf(cbuf, sizeof(cbuf), "code %d", dl->dl_icmp_code);
	      c = cbuf;
	      break;
            }
          break;

	case ICMP6_PACKET_TOO_BIG:
	  snprintf(tbuf, sizeof(tbuf), "need frag %d", dl->dl_icmp_nhmtu);
	  t = tbuf;
	  break;

	case ICMP6_ECHO_REPLY:
	  t = "echo reply";
	  snprintf(cbuf, sizeof(cbuf), "id %d seq %d",
		   dl->dl_icmp_id, dl->dl_icmp_seq);
	  c = cbuf;
	  break;
        }
    }

  if(t == NULL)
    {
      snprintf(icmp, sizeof(icmp), "icmp %d code %d",
	       dl->dl_icmp_type, dl->dl_icmp_code);
    }
  else if(c == NULL)
    {
      snprintf(icmp, sizeof(icmp), "icmp %s", t);
    }
  else
    {
      snprintf(icmp, sizeof(icmp), "icmp %s %s", t, c);
    }

  if(dl->dl_icmp_ip_dst != NULL)
    {
      if(dl->dl_af == AF_INET)
	{
	  addr_tostr(AF_INET, dl->dl_icmp_ip_dst, addr, sizeof(addr));
	  snprintf(inner_ip, sizeof(inner_ip),
		   " to %s size %d ttl %d tos 0x%02x ipid 0x%04x",
		   addr, dl->dl_icmp_ip_size, dl->dl_icmp_ip_ttl,
		   dl->dl_icmp_ip_tos, dl->dl_icmp_ip_id);
	}
      else
	{
	  addr_tostr(AF_INET6, dl->dl_icmp_ip_dst, addr, sizeof(addr));
	  snprintf(inner_ip, sizeof(inner_ip),
		   " to %s size %d hlim %d flow 0x%05x", addr,
		   dl->dl_icmp_ip_size, dl->dl_icmp_ip_hlim,
		   dl->dl_icmp_ip_flow);
	}

      switch(dl->dl_icmp_ip_proto)
	{
	case IPPROTO_UDP:
	  snprintf(inner_transport, sizeof(inner_transport),
		   " proto UDP sport %d dport %d sum 0x%04x",
		   dl->dl_icmp_udp_sport, dl->dl_icmp_udp_dport,
		   ntohs(dl->dl_icmp_udp_sum));
	  break;

	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	  snprintf(inner_transport, sizeof(inner_transport),
		   " proto ICMP type %d code %d id %04x seq %d",
		   dl->dl_icmp_icmp_type, dl->dl_icmp_icmp_code,
		   dl->dl_icmp_icmp_id, dl->dl_icmp_icmp_seq);
	  break;

	case IPPROTO_TCP:
	  snprintf(inner_transport, sizeof(inner_transport),
		   " proto TCP sport %d dport %d seq %08x",
		   dl->dl_icmp_tcp_sport, dl->dl_icmp_tcp_dport,
		   dl->dl_icmp_tcp_seq);
	  break;

	default:
	  inner_transport[0] = '\0';
	  break;
	}
    }
  else
    {
      inner_ip[0] = '\0';
      inner_transport[0] = '\0';
    }

  scamper_debug(NULL, "%s %s%s%s", ip, icmp, inner_ip, inner_transport);
  return;
}
#endif

/*
 * dl_read_cb
 *
 * this function is called by scamper_fds when a BPF fd fires as being
 * available to read from.
 */
void scamper_dl_read_cb(const int fd, void *param)
{
  assert(param != NULL);

#if defined(HAVE_BPF)
  dl_bpf_read(fd, (scamper_dl_t *)param);
#elif defined(__linux__)
  dl_linux_read(fd, (scamper_dl_t *)param);
#elif defined(HAVE_DLPI)
  dl_dlpi_read(fd, (scamper_dl_t *)param);
#endif

  return;
}

void scamper_dl_state_free(scamper_dl_t *dl)
{
  assert(dl != NULL);
  free(dl);
  return;
}

/*
 * scamper_dl_state_alloc
 *
 * given the scamper_fd_t supplied, initialise the file descriptor and do
 * initial setup tasks, then compile and set a filter to pick up the packets
 * scamper is responsible for transmitting.
 */
scamper_dl_t *scamper_dl_state_alloc(scamper_fd_t *fdn)
{
  scamper_dl_t *dl = NULL;

  if((dl = malloc_zero(sizeof(scamper_dl_t))) == NULL)
    {
      printerror(__func__, "malloc node failed");
      goto err;
    }
  dl->fdn = fdn;

#if defined(HAVE_BPF)
  if(dl_bpf_node_init(fdn, dl) == -1)
#elif defined(__linux__)
  if(dl_linux_node_init(fdn, dl) == -1)
#elif defined(HAVE_DLPI)
  if(dl_dlpi_node_init(fdn, dl) == -1)
#endif
    {
      goto err;
    }

#if defined(HAVE_BPF_FILTER)
  dl_filter(dl);
#endif

  return dl;

 err:
  scamper_dl_state_free(dl);
  return NULL;
}

int scamper_dl_tx(const scamper_dl_t *node,
		  const uint8_t *pkt, const size_t len)
{
#if defined(HAVE_BPF)
  if(dl_bpf_tx(node, pkt, len) == -1)
#elif defined(__linux__)
  if(dl_linux_tx(node, pkt, len) == -1)
#elif defined(HAVE_DLPI)
  if(dl_dlpi_tx(node, pkt, len) == -1)
#endif
    {
      return -1;
    }

  return 0;
}

int scamper_dl_tx_type(scamper_dl_t *dl)
{
  return dl->tx_type;
}

void scamper_dl_close(int fd)
{
#ifndef _WIN32
  close(fd);
#endif
  return;
}

/*
 * scamper_dl_open_fd
 *
 * routine to actually open a datalink.  called by scamper_dl_open below,
 * as well as by the privsep code.
 */
int scamper_dl_open_fd(const int ifindex)
{
#if defined(HAVE_BPF)
  return dl_bpf_open(ifindex);
#elif defined(__linux__)
  return dl_linux_open(ifindex);
#elif defined(HAVE_DLPI)
  return dl_dlpi_open(ifindex);
#elif defined(_WIN32)
  return -1;
#endif
}

/*
 * scamper_dl_open
 *
 * return a file descriptor for the datalink for the interface specified.
 * use privilege separation if required, otherwise open fd directly.
 */
int scamper_dl_open(const int ifindex)
{
  int fd;

#if defined(WITHOUT_PRIVSEP)
  if((fd = scamper_dl_open_fd(ifindex)) == -1)
#else
  if((fd = scamper_privsep_open_datalink(ifindex)) == -1)
#endif
    {
      scamper_debug(__func__, "could not open ifindex %d", ifindex);
      return -1;
    }

  return fd;
}

void scamper_dl_cleanup()
{
  if(readbuf != NULL)
    {
      free(readbuf);
      readbuf = NULL;
    }

  return;
}

int scamper_dl_init()
{
#if defined(HAVE_BPF)
  if(dl_bpf_init() == -1)
    {
      return -1;
    }
#elif defined(__linux__)
  readbuf_len = 128;
  if((readbuf = malloc_zero(readbuf_len)) == NULL)
    {
      printerror(__func__, "could not malloc readbuf");
      readbuf_len = 0;
      return -1;
    }
#elif defined(HAVE_DLPI)
  readbuf_len = 65536; /* magic obtained from pcap-dlpi.c */
  if((readbuf = malloc_zero(readbuf_len)) == NULL)
    {
      printerror(__func__, "could not malloc readbuf");
      readbuf_len = 0;
      return -1;
    }
#endif

  return 0;
}
