/*
 * scamper_tcp6.c
 *
 * $Id: scamper_tcp6.c,v 1.34 2017/12/03 09:38:27 mjl Exp $
 *
 * Copyright (C) 2006      Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012,2015 The Regents of the University of California
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

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_tcp6.c,v 1.34 2017/12/03 09:38:27 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_ip6.h"
#include "scamper_tcp6.h"

#include "scamper_debug.h"
#include "utils.h"

static size_t tcp_mss(uint8_t *buf, uint16_t mss)
{
  buf[0] = 2;
  buf[1] = 4;
  bytes_htons(buf+2, mss);
  return 4;
}

static size_t tcp_wscale(uint8_t *buf, uint8_t wscale)
{
  buf[0] = 3;
  buf[1] = 3;
  buf[2] = wscale;
  return 3;
}

static size_t tcp_sackp(uint8_t *buf)
{
  buf[0] = 4;
  buf[1] = 2;
  return 2;
}

static size_t tcp_sack(uint8_t *buf, const scamper_probe_t *pr)
{
  size_t off = 2;
  uint8_t i;
  assert(pr->pr_tcp_sackb > 0);
  assert(pr->pr_tcp_sackb <= 4);
  buf[0] = 5;
  for(i=0; i<pr->pr_tcp_sackb * 2; i++)
    {
      bytes_htonl(buf+off, pr->pr_tcp_sack[i]);
      off += 4;
    }
  buf[1] = off;
  return off;
}

static size_t tcp_nop(uint8_t *buf)
{
  buf[0] = 1;
  return 1;
}

static size_t tcp_fo(uint8_t *buf, const scamper_probe_t *probe)
{
  buf[0] = 34;
  buf[1] = 2;
  if(probe->pr_tcp_fo_cookielen > 0)
    {
      buf[1] += probe->pr_tcp_fo_cookielen;
      memcpy(buf+2, probe->pr_tcp_fo_cookie, probe->pr_tcp_fo_cookielen);
    }
  return buf[1];
}

static size_t tcp_fo_exp(uint8_t *buf, const scamper_probe_t *probe)
{
  buf[0] = 254;
  buf[1] = 4;
  buf[2] = 0xf9;
  buf[3] = 0x89;
  if(probe->pr_tcp_fo_cookielen > 0)
    {
      buf[1] += probe->pr_tcp_fo_cookielen;
      memcpy(buf+4, probe->pr_tcp_fo_cookie, probe->pr_tcp_fo_cookielen);
    }
  return buf[1];
}

static size_t tcp_ts(uint8_t *buf, const scamper_probe_t *probe)
{
  buf[0] = 8;
  buf[1] = 10;
  bytes_htonl(buf+2, probe->pr_tcp_tsval);
  bytes_htonl(buf+6, probe->pr_tcp_tsecr);
  return 10;
}

static void tcp_cksum(struct ip6_hdr *ip6, struct tcphdr *tcp, size_t len)
{
  struct in6_addr a;
  uint16_t *w;
  int sum = 0;

  /*
   * the TCP checksum includes a checksum calculated over a psuedo header
   * that includes the src and dst IP addresses, the protocol type, and
   * the TCP length.
   */
  memcpy(&a, &ip6->ip6_src, sizeof(struct in6_addr));
  w = (uint16_t *)&a;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  memcpy(&a, &ip6->ip6_dst, sizeof(struct in6_addr));
  w = (uint16_t *)&a;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += htons(len);
  sum += htons(IPPROTO_TCP);

  /* compute the checksum over the body of the TCP message */
  w = (uint16_t *)tcp;
  while(len > 1)
    {
      sum += *w++;
      len -= 2;
    }

  if(len != 0)
    {
      sum += ((uint8_t *)w)[0];
    }

  /* fold the checksum */
  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  if((tcp->th_sum = ~sum) == 0)
    {
      tcp->th_sum = 0xffff;
    }

  return;
}

size_t scamper_tcp6_hlen(scamper_probe_t *pr)
{
  size_t tcphlen = 20;
  if(pr->pr_tcp_flags & TH_SYN)
    {
      if(pr->pr_tcp_mss != 0)
	tcphlen += 4;
      if(pr->pr_tcp_wscale != 0)
	tcphlen += 3;
      if((pr->pr_tcp_opts & SCAMPER_PROBE_TCPOPT_SACK) != 0)
	tcphlen += 2;
      if((pr->pr_tcp_opts & SCAMPER_PROBE_TCPOPT_FO) != 0)
	tcphlen += (2 + pr->pr_tcp_fo_cookielen);
      if((pr->pr_tcp_opts & SCAMPER_PROBE_TCPOPT_FO_EXP) != 0)
	tcphlen += (4 + pr->pr_tcp_fo_cookielen);
    }
  if((pr->pr_tcp_opts & SCAMPER_PROBE_TCPOPT_TS) != 0)
    {
      tcphlen += 10;
      if(pr->pr_tcp_sackb != 0)
	while((tcphlen % 4) != 0)
	  tcphlen++;
    }
  if(pr->pr_tcp_sackb != 0)
    tcphlen += ((8 * pr->pr_tcp_sackb) + 2);
  while((tcphlen % 4) != 0)
    tcphlen++;
  assert(tcphlen <= 60);
  return tcphlen;
}

int scamper_tcp6_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  struct ip6_hdr *ip6;
  struct tcphdr  *tcp;
  size_t          ip6hlen, tcphlen, req;

  /* build the IPv6 header */
  ip6hlen = *len;
  scamper_ip6_build(probe, buf, &ip6hlen);

  /* for now, we don't handle any TCP options */
  tcphlen = scamper_tcp6_hlen(probe);

  /* calculate the total number of bytes required for this packet */
  req = ip6hlen + tcphlen + probe->pr_len;

  if(req <= *len)
    {
      ip6 = (struct ip6_hdr *)buf;
      ip6->ip6_plen = htons(ip6hlen - 40 + tcphlen + probe->pr_len);

      /* build the tcp header */
      tcp = (struct tcphdr *)(buf + ip6hlen);
      tcp->th_sport = htons(probe->pr_tcp_sport);
      tcp->th_dport = htons(probe->pr_tcp_dport);
      tcp->th_seq   = htonl(probe->pr_tcp_seq);
      tcp->th_ack   = htonl(probe->pr_tcp_ack);
      tcp->th_flags = probe->pr_tcp_flags;
      tcp->th_win   = htons(probe->pr_tcp_win);
      tcp->th_sum   = 0;
      tcp->th_urp   = 0;

      tcphlen = 20;

      if(probe->pr_tcp_flags & TH_SYN)
	{
	  if(probe->pr_tcp_mss != 0)
	    tcphlen += tcp_mss(buf+ip6hlen+tcphlen, probe->pr_tcp_mss);
	  if(probe->pr_tcp_wscale != 0)
	    tcphlen += tcp_wscale(buf+ip6hlen+tcphlen, probe->pr_tcp_wscale);
	  if((probe->pr_tcp_opts & SCAMPER_PROBE_TCPOPT_SACK) != 0)
	    tcphlen += tcp_sackp(buf+ip6hlen+tcphlen);
	  if((probe->pr_tcp_opts & SCAMPER_PROBE_TCPOPT_FO) != 0)
	    tcphlen += tcp_fo(buf+tcphlen, probe);
	  if((probe->pr_tcp_opts & SCAMPER_PROBE_TCPOPT_FO_EXP) != 0)
	    tcphlen += tcp_fo_exp(buf+tcphlen, probe);
	}

      if((probe->pr_tcp_opts & SCAMPER_PROBE_TCPOPT_TS) != 0)
	{
	  tcphlen += tcp_ts(buf+ip6hlen+tcphlen, probe);
	  while((tcphlen % 4) != 0)
	    tcphlen += tcp_nop(buf+ip6hlen+tcphlen);
	}

      if(probe->pr_tcp_sackb != 0)
	tcphlen += tcp_sack(buf+ip6hlen+tcphlen, probe);

      while((tcphlen % 4) != 0)
	tcphlen += tcp_nop(buf+ip6hlen+tcphlen);

#ifndef _WIN32
      tcp->th_off   = tcphlen >> 2;
      tcp->th_x2    = 0;
#else
      tcp->th_offx2 = ((tcphlen >> 2) << 4);
#endif

      /* if there is data to include in the payload, copy it in now */
      if(probe->pr_len > 0)
	{
	  memcpy(buf + ip6hlen + tcphlen, probe->pr_data, probe->pr_len);
	}

      /* compute the checksum over the tcp portion of the probe */
      tcp_cksum(ip6, tcp, tcphlen + probe->pr_len);

      *len = req;
      return 0;
    }

  *len = req;
  return -1;
}

void scamper_tcp6_close(int fd)
{
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
  return;
}

int scamper_tcp6_open(const void *addr, int sport)
{
  struct sockaddr_in6 sin6;
  char tmp[128];
  int fd = -1;

#ifdef IPV6_V6ONLY
  int opt;
#endif

  if((fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {
      printerror(__func__, "could not open socket");
      goto err;
    }

#ifdef IPV6_V6ONLY
  opt = 1;
  if(setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY, (char *)&opt,sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set IPV6_V6ONLY");
      goto err;
    }
#endif

  sockaddr_compose((struct sockaddr *)&sin6, AF_INET6, addr, sport);
  if(bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) == -1)
    {
      if(addr == NULL || addr_tostr(AF_INET6, addr, tmp, sizeof(tmp)) == NULL)
	printerror(__func__, "could not bind port %d", sport);
      else
	printerror(__func__, "could not bind %s:%d", tmp, sport);
      goto err;
    }

  return fd;

 err:
  if(fd != -1) scamper_tcp6_close(fd);
  return -1;
}
