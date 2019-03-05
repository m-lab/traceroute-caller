/*
 * scamper_ip4.c
 *
 * $Id: scamper_ip4.c,v 1.17 2017/12/03 09:38:27 mjl Exp $
 *
 * Copyright (C) 2009-2011 The University of Waikato
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
  "$Id: scamper_ip4.c,v 1.17 2017/12/03 09:38:27 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_ip4.h"
#include "scamper_tcp4.h"
#include "scamper_privsep.h"
#include "scamper_debug.h"
#include "utils.h"

void scamper_ip4_close(int fd)
{
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
  return;
}

int scamper_ip4_openraw_fd(void)
{
  int fd, hdr;
  if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
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
  return fd;

 err:
  if(fd != -1) scamper_ip4_close(fd);
  return -1;
}

int scamper_ip4_openraw(void)
{
#if defined(WITHOUT_PRIVSEP)
  return scamper_ip4_openraw_fd();
#else
  return scamper_privsep_open_rawip();
#endif
}

int scamper_ip4_hlen(scamper_probe_t *pr, size_t *hlen)
{
  size_t ip4hlen = sizeof(struct ip);
  scamper_probe_ipopt_t *opt;
  int i;

  for(i=0; i<pr->pr_ipoptc; i++)
    {
      opt = &pr->pr_ipopts[i];
      if(opt->type == SCAMPER_PROBE_IPOPTS_V4RR)
	{
	  /*
	   * want the ability to record at least one IP address otherwise
	   * the option is useless.
	   */
	  if(ip4hlen + 8 > 60)
	    goto err;

	  /* for now assume this option fills the rest of the option space */
	  ip4hlen = 60;
	}
      else if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSPS)
	{
	  if(opt->opt_v4tsps_ipc < 1 || opt->opt_v4tsps_ipc > 4)
	    goto err;

	  ip4hlen += (opt->opt_v4tsps_ipc * 4 * 2) + 4;
	  if(ip4hlen > 60)
	    goto err;
	}
      else if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSO)
	{
	  ip4hlen += 40;
	  if(ip4hlen > 60)
	    goto err;
	}
      else if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSAA)
	{
	  ip4hlen += 36;
	  if(ip4hlen > 60)
	    goto err;
	}
      else if(opt->type == SCAMPER_PROBE_IPOPTS_QUICKSTART)
	{
	  ip4hlen += 8;
	  if(ip4hlen > 60)
	    goto err;
	}
      else goto err;
    }

  *hlen = ip4hlen;
  return 0;

 err:
  scamper_debug(__func__, "invalid IPv4 header specification");
  return -1;
}

int scamper_ip4_build(scamper_probe_t *pr, uint8_t *buf, size_t *len)
{
  scamper_probe_ipopt_t *opt;
  struct ip *ip;
  size_t off, ip4hlen;
  int i, j;

  if(scamper_ip4_hlen(pr, &ip4hlen) != 0)
    return -1;

  if(ip4hlen > *len)
    {
      *len = ip4hlen;
      return -1;
    }

  ip  = (struct ip *)buf;
  off = sizeof(struct ip);

#ifndef _WIN32
  ip->ip_v   = 4;
  ip->ip_hl  = (ip4hlen / 4);
#else
  ip->ip_vhl = 0x40 | (ip4hlen / 4);
#endif

  if((pr->pr_ip_off & IP_OFFMASK) != 0)
    ip->ip_len = htons(ip4hlen + pr->pr_len);
  else if(pr->pr_ip_proto == IPPROTO_ICMP || pr->pr_ip_proto == IPPROTO_UDP)
    ip->ip_len = htons(ip4hlen + 8 + pr->pr_len);
  else if(pr->pr_ip_proto == IPPROTO_TCP)
    ip->ip_len = htons(ip4hlen + scamper_tcp4_hlen(pr) + pr->pr_len);
  else
    {
      scamper_debug(__func__, "unimplemented pr %d", pr->pr_ip_proto);
      return -1;
    }

  ip->ip_tos = pr->pr_ip_tos;
  ip->ip_id  = htons(pr->pr_ip_id);
  ip->ip_off = htons(pr->pr_ip_off);
  ip->ip_ttl = pr->pr_ip_ttl;
  ip->ip_p   = pr->pr_ip_proto;
  ip->ip_sum = 0;
  memcpy(&ip->ip_src, pr->pr_ip_src->addr, sizeof(ip->ip_src));
  memcpy(&ip->ip_dst, pr->pr_ip_dst->addr, sizeof(ip->ip_dst));

  for(i=0; i<pr->pr_ipoptc; i++)
    {
      opt = &pr->pr_ipopts[i];
      if(opt->type == SCAMPER_PROBE_IPOPTS_V4RR)
	{
	  memset(buf+off+3, 0, 37);
	  buf[off+0] = 7;
	  buf[off+1] = 39;
	  buf[off+2] = 4;
	  off = 60;
	}
      else if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSPS ||
	      opt->type == SCAMPER_PROBE_IPOPTS_V4TSO  ||
	      opt->type == SCAMPER_PROBE_IPOPTS_V4TSAA)
	{
	  buf[off+0] = 68;
	  buf[off+2] = 5;

	  if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSPS)
	    {
	      buf[off+1] = (opt->opt_v4tsps_ipc * 4 * 2) + 4;
	      buf[off+3] = 3;
	      off += 4;
	      for(j=0; j<opt->opt_v4tsps_ipc; j++)
		{
		  memcpy(buf+off, &opt->opt_v4tsps_ips[j], 4); off += 4;
		  memset(buf+off, 0, 4); off += 4;
		}
	    }
	  else if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSO)
	    {
	      buf[off+1] = 40;
	      memset(buf+off+3, 0, 41);
	      off += 40;
	    }
	  else if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSAA)
	    {
	      buf[off+1] = 36;
	      buf[off+3] = 1;
	      memset(buf+off+4, 0, 36);
	      off += 36;
	    }
	}
      else if(opt->type == SCAMPER_PROBE_IPOPTS_QUICKSTART)
	{
	  assert(opt->opt_qs_func <= 0xf);
	  assert(opt->opt_qs_rate <= 0xf);
	  buf[off+0] = 25;
	  buf[off+1] = 8;
	  buf[off+2] = (opt->opt_qs_func << 4) | opt->opt_qs_rate;
	  buf[off+3] = opt->opt_qs_ttl;
	  bytes_htonl(&buf[off+4], opt->opt_qs_nonce << 2);
	  off += 8;
	}
      else return -1;
    }

  assert(off == ip4hlen);
  ip->ip_sum = in_cksum(ip, ip4hlen);

  *len = off;
  return 0;
}

/*
 * scamper_ip4_frag_build
 *
 * given an IPv4 fragment, build it.
 */
int scamper_ip4_frag_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  size_t ip4hlen, req;
  int rc = 0;

  /* build the IPv4 header */
  ip4hlen = *len;
  scamper_ip4_build(probe, buf, &ip4hlen);

  /* calculate the total number of bytes required for this packet */
  req = ip4hlen + probe->pr_len;

  if(req > *len)
    rc = -1;
  else if(probe->pr_len != 0)
    memcpy(buf + ip4hlen, probe->pr_data, probe->pr_len);

  *len = req;
  return rc;
}
