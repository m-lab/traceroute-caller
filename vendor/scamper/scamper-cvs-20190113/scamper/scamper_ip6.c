/*
 * scamper_ip6.c
 *
 * $Id: scamper_ip6.c,v 1.19 2011/12/14 04:24:55 mjl Exp $
 *
 * Copyright (C) 2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
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
  "$Id: scamper_ip6.c,v 1.19 2011/12/14 04:24:55 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_ip6.h"

#include "scamper_debug.h"
#include "utils.h"

/*
 * ip6_ext_route0
 *
 * this function builds an IPv6 Routing Header of Type 0, as defined by
 * RFC 2460.  It does not set bytes 5-8, which were defined in RFC 1883
 * as being a loose/strict bitmap.  In RFC 2460, these bits are just set
 * to zero.
 */
static int ip6_ext_route0(struct ip6_hdr *ip6,
			  const scamper_probe_ipopt_t *opt,
			  uint8_t *buf, size_t *len)
{
  int i;
  ssize_t off;

  assert(opt->opt_v6rh0_ipc > 0);

  if(*len < (opt->opt_v6rh0_ipc * 16) + 8)
    {
      *len = (opt->opt_v6rh0_ipc * 16) + 8;
      return -1;
    }

  /*
   * the length field counts number of 8 octets, excluding the first 8 bytes
   * of routing header.
   * RFC 2460 says this value is twice the number of addresses in the header
   */
  buf[1] = opt->opt_v6rh0_ipc * 2;

  /* routing type = 0 */
  buf[2] = 0;

  /* number of segments left */
  buf[3] = opt->opt_v6rh0_ipc;

  /* set the next four bytes to zero */
  memset(buf+4, 0, 4);

  off = 8;

  /*
   * copy in addresses 1 .. N, skipping over the first address which is
   * swapped with ip6->ip6_dst after this loop
   */
  for(i=1; i<opt->opt_v6rh0_ipc; i++)
    {
      memcpy(buf+off, &opt->opt_v6rh0_ips[i], 16);
      off += 16;
    }

  /*
   * the current destination address becomes the last address in the routing
   * header
   */
  memcpy(buf+off, &ip6->ip6_dst, 16);
  off += 16;

  /* the first address in the option becomes the destination address */
  memcpy(&ip6->ip6_dst, &opt->opt_v6rh0_ips[0], 16);

  *len = off;
  return 0;
}

static int ip6_ext_frag(struct ip6_hdr *ip6,
			const scamper_probe_ipopt_t *opt,
			uint8_t *buf, size_t *len)
{
  /* make sure the pktbuf has at least enough space left for this */
  if(*len < 8)
    {
      *len = 8;
      return -1;
    }

  /* the length of this header is set to zero since it is of fixed size */
  buf[1] = 0;

  /* copy in the fragmentation value */
  bytes_htons(buf+2, opt->opt_v6frag_off);
  bytes_htonl(buf+4, opt->opt_v6frag_id);

  *len = 8;
  return 0;
}

static int ip6_ext_quickstart(struct ip6_hdr *ip6,
			      const scamper_probe_ipopt_t *opt,
			      uint8_t *buf, size_t *len)
{
  size_t off = 1;

  if(*len < 16)
    {
      *len = 16;
      return -1;
    }

  buf[off++] = 1; /* length of hop-by-hop options : 16 bytes */

  /* two Pad1 options */
  buf[off++] = 0;
  buf[off++] = 0;

  /* quickstart option */
  buf[off++] = 0x26;
  buf[off++] = 6;
  buf[off++] = (opt->opt_qs_func << 4) | opt->opt_qs_rate;
  buf[off++] = opt->opt_qs_ttl;
  bytes_htonl(&buf[off], opt->opt_qs_nonce << 2);
  off += 4;

  /* PadN option, length 4 */
  buf[off++] = 1;
  buf[off++] = 2;
  buf[off++] = 0;
  buf[off++] = 0;

  *len = off;
  return 0;
}

/*
 * scamper_ip6_build
 *
 * given a scamper probe structure, and a place in the pktbuf to dump the
 * header, write the header.
 *
 * return 0 on success, -1 on fail.
 * on entry, buflen contains the length of the pktbuf left for the header.
 * on exit, buflen contains the length of the space used if zero was returned,
 * or the space that would be necessary on fail.
 *
 * the caller is still required to set ip6->ip6_plen when it knows how much
 * payload is going to be included.
 */
int scamper_ip6_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  static int (*const func[])(struct ip6_hdr *, const scamper_probe_ipopt_t *,
			     uint8_t *, size_t *) = {
    ip6_ext_route0,     /* SCAMPER_PROBE_IPOPTS_V6ROUTE0 */
    ip6_ext_frag,       /* SCAMPER_PROBE_IPOPTS_V6FRAG */
    NULL,               /* SCAMPER_PROBE_IPOPTS_V4RR */
    NULL,               /* SCAMPER_PROBE_IPOPTS_V4TSPS */
    NULL,               /* SCAMPER_PROBE_IPOPTS_V4TSO */
    NULL,               /* SCAMPER_PROBE_IPOPTS_V4TSAA */
    ip6_ext_quickstart, /* SCAMPER_PROBE_IPOPTS_QUICKSTART */
  };

  static const int nxthdrval[] = {
    IPPROTO_ROUTING,    /* SCAMPER_PROBE_IPOPTS_V6ROUTE0 */
    IPPROTO_FRAGMENT,   /* SCAMPER_PROBE_IPOPTS_V6FRAG */
    -1,                 /* SCAMPER_PROBE_IPOPTS_V4RR */
    -1,                 /* SCAMPER_PROBE_IPOPTS_V4TSPS */
    -1,                 /* SCAMPER_PROBE_IPOPTS_V4TSO */
    -1,                 /* SCAMPER_PROBE_IPOPTS_V4TSAA */
    IPPROTO_HOPOPTS,    /* SCAMPER_PROBE_IPOPTS_QUICKSTART */
  };

  struct ip6_hdr        *ip6;
  scamper_probe_ipopt_t *opt;
  size_t                 off, tmp;
  int                    i;

  /* get a pointer to the first byte of the buf for the IPv6 header */
  ip6 = (struct ip6_hdr *)buf;
  off = sizeof(struct ip6_hdr);

  if(off <= *len)
    {
      /* build the ip6 header */
      ip6->ip6_flow = htonl(0x6<<28|probe->pr_ip_tos<<20|probe->pr_ip_flow);
      ip6->ip6_hlim = probe->pr_ip_ttl;
      memcpy(&ip6->ip6_src, probe->pr_ip_src->addr, 16);
      memcpy(&ip6->ip6_dst, probe->pr_ip_dst->addr, 16);
    }

  /*
   * if there are no IPv6 extension headers, then the ip6_nxt field is set
   * to the underlying type of the packet
   */
  if(probe->pr_ipoptc == 0)
    {
      if(off <= *len)
	{
	  ip6->ip6_nxt = probe->pr_ip_proto;
	}
      goto done;
    }

  /*
   * the next header field in the IPv6 header is set to the type of the
   * first extension header
   */
  if(off <= *len)
    {
      if(nxthdrval[probe->pr_ipopts[0].type] == -1)
	return -1;

      ip6->ip6_nxt = nxthdrval[probe->pr_ipopts[0].type];
    }

  /* build the body of the IPv6 extension headers area */
  for(i=0; i<probe->pr_ipoptc; i++)
    {
      if(off + 1 < *len)
	{
	  /* the last extension header uses the ip protocol value */
	  if(i == probe->pr_ipoptc-1)
	    {
	      buf[off] = probe->pr_ip_proto;
	    }
	  else
	    {
	      if(nxthdrval[probe->pr_ipopts[i+1].type] == -1)
		return -1;

	      buf[off] = nxthdrval[probe->pr_ipopts[i+1].type];
	    }
	}

      /* obtain a handy pointer to the current extension header */
      opt = &probe->pr_ipopts[i];

      /* work out how much space is left in the buf */
      if(*len >= off)
	tmp = *len - off;
      else
	tmp = 0;

      /* handle the extension header */
      func[opt->type](ip6, opt, buf+off, &tmp);

      off += tmp;
    }

 done:
  /*
   * figure out what to return based on if there was enough space in the
   * packet payload to compose the IPv6 header
   */
  if(off > *len)
    {
      *len = off;
      return -1;
    }

  *len = off;
  return 0;
}

/*
 * scamper_ip6_hlen
 *
 * given an IPv6 header outline in the probe structure, return how large
 * the IPv6 header length will be.
 */
int scamper_ip6_hlen(scamper_probe_t *probe, size_t *ip6hlen)
{
  *ip6hlen = 0;
  scamper_ip6_build(probe, NULL, ip6hlen);
  return 0;
}

/*
 * scamper_ip6_frag_build
 *
 * given an IPv6 fragment, build it.
 */
int scamper_ip6_frag_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  struct ip6_hdr *ip6;
  size_t ip6hlen, req;

  /* build the IPv6 header */
  ip6hlen = *len;
  scamper_ip6_build(probe, buf, &ip6hlen);

  /* calculate the total number of bytes required for this packet */
  req = ip6hlen + probe->pr_len;

  if(req > *len)
    {
      *len = req;
      return -1;
    }

  /* build the IPv6 fragment */
  ip6 = (struct ip6_hdr *)buf;
  ip6->ip6_plen = htons(ip6hlen - 40 + probe->pr_len);
  if(probe->pr_len != 0)
    memcpy(buf + ip6hlen, probe->pr_data, probe->pr_len);
  *len = req;

  return 0;
}
