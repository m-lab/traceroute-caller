/*
 * scamper_udp6.c
 *
 * $Id: scamper_udp6.c,v 1.55 2017/12/03 09:38:27 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
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
  "$Id: scamper_udp6.c,v 1.55 2017/12/03 09:38:27 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_ip6.h"
#include "scamper_udp6.h"

#include "scamper_debug.h"
#include "utils.h"

uint16_t scamper_udp6_cksum(scamper_probe_t *probe)
{
  uint16_t *w, tmp;
  int i, sum = 0;

  /* compute the checksum over the psuedo header */
  w = (uint16_t *)probe->pr_ip_src->addr;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  w = (uint16_t *)probe->pr_ip_dst->addr;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += htons(probe->pr_len + 8);
  sum += htons(IPPROTO_UDP);

  /* main UDP header */
  sum += htons(probe->pr_udp_sport);
  sum += htons(probe->pr_udp_dport);
  sum += htons(probe->pr_len + 8);

  /* compute the checksum over the payload of the UDP message */
  w = (uint16_t *)probe->pr_data;
  for(i = probe->pr_len; i > 1; i -= 2)
    {
      sum += *w++;
    }
  if(i != 0)
    {
      sum += ((uint8_t *)w)[0];
    }

  /* fold the checksum */
  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  if((tmp = ~sum) == 0)
    {
      tmp = 0xffff;
    }

  return tmp;
}

int scamper_udp6_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  struct ip6_hdr *ip6;
  struct udphdr  *udp;
  size_t          ip6hlen, req;

  /* build the IPv6 header */
  ip6hlen = *len;
  scamper_ip6_build(probe, buf, &ip6hlen);

  /* calculate the total number of bytes required for this packet */
  req = ip6hlen + 8 + probe->pr_len;

  if(req <= *len)
    {
      /* calculate and record the plen value */
      ip6 = (struct ip6_hdr *)buf;
      ip6->ip6_plen = htons(ip6hlen - 40 + 8 + probe->pr_len);

      udp = (struct udphdr *)(buf + ip6hlen);
      udp->uh_sport = htons(probe->pr_udp_sport);
      udp->uh_dport = htons(probe->pr_udp_dport);
      udp->uh_ulen  = htons(sizeof(struct udphdr) + probe->pr_len);
      udp->uh_sum   = scamper_udp6_cksum(probe);

      /* if there is data to include in the payload, copy it in now */
      if(probe->pr_len != 0)
	{
	  memcpy(buf + ip6hlen + 8, probe->pr_data, probe->pr_len);
	}

      *len = req;
      return 0;
    }

  *len = req;
  return -1;
}

/*
 * scamper_udp6_probe:
 *
 * given the address, hop limit, destination UDP port number, and size, send
 * a UDP probe packet encapsulated in an IPv6 header.
 *
 * the size parameter is useful when doing path MTU discovery, and represents
 * how large the packet should be including IPv6 and UDP headers
 *
 * this function returns 0 on success, -1 otherwise
 */
int scamper_udp6_probe(scamper_probe_t *probe)
{
  struct sockaddr_in6  sin6;
  int                  i;
  char                 addr[128];

  assert(probe != NULL);
  assert(probe->pr_ip_proto == IPPROTO_UDP);
  assert(probe->pr_ip_dst != NULL);
  assert(probe->pr_ip_src != NULL);
  assert(probe->pr_len != 0 || probe->pr_data == NULL);

  i = probe->pr_ip_ttl;
  if(setsockopt(probe->pr_fd,
		IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&i, sizeof(i)) == -1)
    {
      printerror(__func__, "could not set hlim to %d", i);
      return -1;
    }

  sockaddr_compose((struct sockaddr *)&sin6, AF_INET6,
		   probe->pr_ip_dst->addr, probe->pr_udp_dport);

  /* get the transmit time immediately before we send the packet */
  gettimeofday_wrap(&probe->pr_tx);

  i = sendto(probe->pr_fd, probe->pr_data, probe->pr_len, 0,
	     (struct sockaddr *)&sin6, sizeof(struct sockaddr_in6));

  /* if we sent the probe successfully, there is nothing more to do here */
  if(i == probe->pr_len)
    {
      return 0;
    }

  /* get a copy of the errno variable as it is immediately after the sendto */
  probe->pr_errno = errno;

  /* error condition, could not send the packet at all */
  if(i == -1)
    {
      printerror(__func__, "could not send to %s (%d hlim, %d dport, %d len)",
		 scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)),
		 probe->pr_ip_ttl, probe->pr_udp_dport, probe->pr_len);
    }
  /* error condition, sent a portion of the probe */
  else
    {
      printerror_msg(__func__, "sent %d bytes of %d byte packet to %s",
		     i, (int)probe->pr_len,
		     scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)));
    }

  return -1;
}

void scamper_udp6_close(int fd)
{
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
  return;
}

int scamper_udp6_open(const void *addr, int sport)
{
  struct sockaddr_in6 sin6;
  char buf[128];
  int opt, fd = -1;

  if((fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1)
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
      if(addr == NULL || addr_tostr(AF_INET6, addr, buf, sizeof(buf)) == NULL)
	printerror(__func__, "could not bind port %d", sport);
      else
	printerror(__func__, "could not bind %s:%d", buf, sport);
      goto err;
    }

  opt = 65535 + 128;
  if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set SO_SNDBUF");
      return -1;
    }

#if defined(IPV6_DONTFRAG)
  opt = 1;
  if(setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG,
		(char *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set IPV6_DONTFRAG");
      goto err;
    }
#endif

  return fd;

 err:
  if(fd != -1) scamper_udp6_close(fd);
  return -1;
}
