/*
 * scamper_udp4.c
 *
 * $Id: scamper_udp4.c,v 1.74 2017/12/03 09:38:27 mjl Exp $
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
  "$Id: scamper_udp4.c,v 1.74 2017/12/03 09:38:27 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_ip4.h"
#include "scamper_udp4.h"
#include "scamper_privsep.h"
#include "scamper_debug.h"
#include "utils.h"

/*
 * these variables are used to store a packet buffer that is allocated
 * in the scamper_udp4_probe function large enough for the largest probe
 * the routine sends
 */
static uint8_t *pktbuf = NULL;
static size_t   pktbuf_len = 0;

uint16_t scamper_udp4_cksum(scamper_probe_t *probe)
{
  uint16_t tmp, *w;
  int i, sum = 0;

  /* compute the checksum over the psuedo header */
  w = (uint16_t *)probe->pr_ip_src->addr;
  sum += *w++; sum += *w++;
  w = (uint16_t *)probe->pr_ip_dst->addr;
  sum += *w++; sum += *w++;
  sum += htons(IPPROTO_UDP);
  sum += htons(probe->pr_len + 8);

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

static void udp4_build(scamper_probe_t *probe, uint8_t *buf)
{
  struct udphdr *udp = (struct udphdr *)buf;

  udp->uh_sport = htons(probe->pr_udp_sport);
  udp->uh_dport = htons(probe->pr_udp_dport);
  udp->uh_ulen  = htons(8 + probe->pr_len);
  udp->uh_sum = scamper_udp4_cksum(probe);

  /* if there is data to include in the payload, copy it in now */
  if(probe->pr_len > 0)
    {
      memcpy(buf + 8, probe->pr_data, probe->pr_len);
    }

  return;
}

int scamper_udp4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  size_t ip4hlen, req;
  int rc = 0;

  ip4hlen = *len;
  scamper_ip4_build(probe, buf, &ip4hlen);
  req = ip4hlen + 8 + probe->pr_len;

  if(req <= *len)
    udp4_build(probe, buf + ip4hlen);
  else
    rc = -1;

  *len = req;
  return rc;
}

int scamper_udp4_probe(scamper_probe_t *probe)
{
  struct sockaddr_in  sin4;
  int                 i;
  char                addr[128];
  size_t              ip4hlen, len, tmp;
  uint8_t            *buf;

#if !defined(IP_HDR_HTONS)
  struct ip          *ip;
#endif

  assert(probe != NULL);
  assert(probe->pr_ip_proto == IPPROTO_UDP);
  assert(probe->pr_ip_dst != NULL);
  assert(probe->pr_ip_src != NULL);
  assert(probe->pr_len > 0 || probe->pr_data == NULL);

  scamper_ip4_hlen(probe, &ip4hlen);

  /* compute length, for sake of readability */
  len = ip4hlen + sizeof(struct udphdr) + probe->pr_len;

  if(pktbuf_len < len)
    {
      if((buf = realloc(pktbuf, len)) == NULL)
	{
	  printerror(__func__, "could not realloc");
	  return -1;
	}
      pktbuf     = buf;
      pktbuf_len = len;
    }

  tmp = len;
  scamper_ip4_build(probe, pktbuf, &tmp);

#if !defined(IP_HDR_HTONS)
  ip = (struct ip *)pktbuf;
  ip->ip_len = ntohs(ip->ip_len);
  ip->ip_off = ntohs(ip->ip_off);
#endif

  udp4_build(probe, pktbuf + ip4hlen);

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET,
		   probe->pr_ip_dst->addr, probe->pr_udp_dport);

  /* get the transmit time immediately before we send the packet */
  gettimeofday_wrap(&probe->pr_tx);

  i = sendto(probe->pr_fd, pktbuf, len, 0, (struct sockaddr *)&sin4,
	     sizeof(struct sockaddr_in));

  if(i < 0)
    {
      /* error condition, could not send the packet at all */
      probe->pr_errno = errno;
      printerror(__func__, "could not send to %s (%d ttl, %d dport, %d len)",
		 scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)),
		 probe->pr_ip_ttl, probe->pr_udp_dport, len);
      return -1;
    }
  else if((size_t)i != len)
    {
      /* error condition, sent a portion of the probe */
      printerror_msg(__func__, "sent %d bytes of %d byte packet to %s",
		     i, (int)len,
		     scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)));
      return -1;
    }

  return 0;
}

void scamper_udp4_cleanup()
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  return;
}

void scamper_udp4_close(int fd)
{
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
  return;
}

int scamper_udp4_opendgram(const void *addr, int sport)
{
  struct sockaddr_in sin4;
  char tmp[32];
  int fd, opt;

  if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
      printerror(__func__, "could not open socket");
      goto err;
    }

  opt = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) != 0)
    {
      printerror(__func__, "could not set SO_REUSEADDR");
      goto err;
    }

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET, addr, sport);
  if(bind(fd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1)
    {
      printerror(__func__, "could not bind %s",
		 sockaddr_tostr((struct sockaddr *)&sin4, tmp, sizeof(tmp)));
      goto err;
    }

  return fd;

 err:
  if(fd != -1) scamper_udp4_close(fd);
  return -1;
}

int scamper_udp4_openraw_fd(const void *addr)
{
  struct sockaddr_in sin4;
  int hdr, fd;
  char tmp[32];

  if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
      printerror(__func__, "could not open socket");
      goto err;
    }
  hdr = 1;
  if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, (void *)&hdr, sizeof(hdr)) == -1)
    {
      printerror(__func__, "could not IP_HDRINCL");
      goto err;
    }
  sockaddr_compose((struct sockaddr *)&sin4, AF_INET, addr, 0);
  if(bind(fd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1)
    {
      printerror(__func__, "could not bind %s",
		 sockaddr_tostr((struct sockaddr *)&sin4, tmp, sizeof(tmp)));
      goto err;
    }

  return fd;

 err:
  if(fd != -1) scamper_udp4_close(fd);
  return -1;
}

int scamper_udp4_openraw(const void *addr)
{
  int fd, opt;

#if defined(WITHOUT_PRIVSEP)
  fd = scamper_udp4_openraw_fd(addr);
#else
  fd = scamper_privsep_open_rawudp(addr);
#endif
  if(fd == -1)
    return -1;

  opt = 65535 + 128;
  if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set SO_SNDBUF");
      goto err;
    }
  return fd;

 err:
  if(fd != -1) scamper_udp4_close(fd);
  return -1;
}
