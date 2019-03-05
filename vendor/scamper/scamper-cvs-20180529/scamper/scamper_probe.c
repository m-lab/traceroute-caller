/*
 * scamper_probe.c
 *
 * $Id: scamper_probe.c,v 1.74 2017/12/03 09:38:27 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2013      The Regents of the University of California
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
  "$Id: scamper_probe.c,v 1.74 2017/12/03 09:38:27 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_fds.h"
#include "scamper_rtsock.h"
#include "scamper_task.h"
#include "scamper_probe.h"
#include "scamper_udp4.h"
#include "scamper_udp6.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_tcp4.h"
#include "scamper_tcp6.h"
#include "scamper_ip4.h"
#include "scamper_ip6.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_osinfo.h"
#include "scamper_debug.h"
#include "utils.h"

/*
 * probe_state_t:
 *
 * an internal probe structure to store a built packet as it makes its
 * way into the network.  the len field is the size of the IP packet,
 * and the buf field is 16 bytes larger (at the front) to allow space for
 * layer-2 headers to be added without having to re-copy the packet.
 */
typedef struct probe_state
{
  scamper_probe_t    *pr;
  scamper_task_t     *task;
  scamper_task_anc_t *anc;
  scamper_fd_t       *rtsock;
  scamper_route_t    *rt;
  scamper_dlhdr_t    *dlhdr;
  uint8_t            *buf;
  size_t              len;
  struct timeval      tv;
  int                 mode;
  int                 error;
} probe_state_t;

#define PROBE_MODE_RT  1
#define PROBE_MODE_DL  2
#define PROBE_MODE_TX  3
#define PROBE_MODE_ERR 4

/*
 * this pad macro determines the number of extra bytes we have to allocate
 * so that the next element (the IP header) of the buffer is aligned
 * appropriately after the datalink header.
 */
#define PAD(s) ((s > 0) ? (1 + ((s - 1) | (sizeof(long) - 1)) - s) : 0)

static uint8_t *pktbuf = NULL;
static size_t   pktbuf_len = 0;
static int      ipid_dl = 0;
static int      rawtcp = 0;

#ifdef HAVE_SCAMPER_DEBUG
static char *tcp_flags(char *buf, size_t len, scamper_probe_t *probe)
{
  uint8_t flags = probe->pr_tcp_flags;
  uint8_t flag;
  size_t off;
  int i;

  buf[0] = '\0';
  if(probe->pr_len != 0)
    flags &= ~(TH_ACK);

  off = 0;
  for(i=0; i<8 && flags != 0; i++)
    {
      flag = 1 << i;

      if((flags & flag) == 0)
	continue;
      flags &= ~flag;

      switch(flag)
	{
	case TH_SYN:  string_concat(buf, len, &off, " syn"); break;
	case TH_RST:  string_concat(buf, len, &off, " rst"); break;
	case TH_FIN:  string_concat(buf, len, &off, " fin"); break;
	case TH_ACK:  string_concat(buf, len, &off, " ack"); break;
	case TH_PUSH: string_concat(buf, len, &off, " psh"); break;
	case TH_URG:  string_concat(buf, len, &off, " urg"); break;
	case TH_ECE:  string_concat(buf, len, &off, " ece"); break;
	case TH_CWR:  string_concat(buf, len, &off, " cwr"); break;
	}
    }

  return buf;
}

static char *tcp_pos(char *buf, size_t len, scamper_probe_t *probe)
{
  size_t off = 0;
  string_concat(buf, len, &off, "%u", probe->pr_tcp_seq);
  if(probe->pr_tcp_flags & TH_ACK)
    string_concat(buf, len, &off, ":%u", probe->pr_tcp_ack);
  if(probe->pr_len > 0)
    string_concat(buf, len, &off, "(%u)", probe->pr_len);
  return buf;
}

static void probe_print(scamper_probe_t *probe)
{
  size_t iphl;
  char tcp[16];
  char pos[32];
  char addr[128];
  char icmp[16];
  char tos[8];

  assert(probe->pr_ip_dst != NULL);

  scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr));

  tos[0] = '\0';
  icmp[0] = '\0';

  if(probe->pr_ip_proto == IPPROTO_TCP)
    {
      if((probe->pr_ip_tos & IPTOS_ECN_CE) == IPTOS_ECN_CE)
	snprintf(tos, sizeof(tos), ", ce");
      else if(probe->pr_ip_tos & IPTOS_ECN_ECT1)
	snprintf(tos, sizeof(tos), ", ect1");
      else if(probe->pr_ip_tos & IPTOS_ECN_ECT0)
	snprintf(tos, sizeof(tos), ", ect0");
    }

  if(probe->pr_ip_dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      if(scamper_ip4_hlen(probe, &iphl) != 0)
	return;

      if((probe->pr_ip_off & IP_OFFMASK) != 0)
	{
	  scamper_debug("tx", "frag %s %04x:%d ttl %d, len %d",
			addr, probe->pr_ip_id, probe->pr_ip_off << 3,
			probe->pr_ip_ttl, iphl + probe->pr_len);
	  return;
	}

      switch(probe->pr_ip_proto)
	{
	case IPPROTO_UDP:
	  scamper_debug("tx", "udp %s, ttl %d, %d:%d, len %d",
			addr, probe->pr_ip_ttl, probe->pr_udp_sport,
			probe->pr_udp_dport, iphl + 8 + probe->pr_len);
	  break;

	case IPPROTO_TCP:
	  scamper_debug("tx",
			"tcp %s%s, ttl %d, %d:%d%s, ipid %04x, %s, len %d",
			addr, tos, probe->pr_ip_ttl,
			probe->pr_tcp_sport, probe->pr_tcp_dport,
			tcp_flags(tcp, sizeof(tcp), probe),
			probe->pr_ip_id, tcp_pos(pos, sizeof(pos), probe),
			iphl + scamper_tcp4_hlen(probe) + probe->pr_len);
	  break;

	case IPPROTO_ICMP:
	  if(probe->pr_icmp_type == ICMP_ECHO)
	    {
	      if(probe->pr_icmp_sum != 0)
		{
		  snprintf(icmp, sizeof(icmp), ", sum %04x",
			   ntohs(probe->pr_icmp_sum));
		}
	      scamper_debug("tx", "icmp %s echo, ttl %d%s, seq %d, len %d",
			    addr, probe->pr_ip_ttl, icmp, probe->pr_icmp_seq,
			    iphl + 8 + probe->pr_len);
	    }
	  else if(probe->pr_icmp_type == ICMP_UNREACH)
	    {
	      if(probe->pr_icmp_code == ICMP_UNREACH_NEEDFRAG)
		snprintf(icmp,sizeof(icmp),"ptb %d", probe->pr_icmp_mtu);
	      else
		snprintf(icmp,sizeof(icmp),"unreach %d", probe->pr_icmp_code);
	      scamper_debug("tx", "icmp %s %s, len %d",
			    addr, icmp, iphl + 8 + probe->pr_len);
	    }
	  else if(probe->pr_icmp_type == ICMP_TSTAMP)
	    {
	      scamper_debug("tx", "icmp %s ts, ttl %d, seq %d, len %d",
			    addr, probe->pr_ip_ttl, probe->pr_icmp_seq,
			    iphl + 20);
	    }
	  else
	    {
	      scamper_debug("tx", "icmp %s type %d, code %d, len %d",
			    addr, probe->pr_icmp_type, probe->pr_icmp_code,
			    iphl + 8 + probe->pr_len);
	    }
	  break;
	}
    }
  else if(probe->pr_ip_dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      if(scamper_ip6_hlen(probe, &iphl) != 0)
	return;

      if(probe->pr_ip_off != 0)
	{
	  scamper_debug("tx", "frag %s off %04x, ttl %d, len %d",
			addr, probe->pr_ip_off, probe->pr_ip_ttl,
			iphl + probe->pr_len);
	  return;
	}

      switch(probe->pr_ip_proto)
	{
	case IPPROTO_UDP:
	  scamper_debug("tx", "udp %s, ttl %d, %d:%d, len %d",
			addr, probe->pr_ip_ttl, probe->pr_udp_sport,
			probe->pr_udp_dport, iphl + 8 + probe->pr_len);
	  break;

	case IPPROTO_TCP:
	  scamper_debug("tx", "tcp %s%s, ttl %d, %d:%d%s, %s, len %d",
			addr, tos, probe->pr_ip_ttl,
			probe->pr_tcp_sport, probe->pr_tcp_dport,
			tcp_flags(tcp, sizeof(tcp), probe),
			tcp_pos(pos, sizeof(pos), probe),
			iphl + scamper_tcp6_hlen(probe) + probe->pr_len);
	  break;

	case IPPROTO_ICMPV6:
	  if(probe->pr_icmp_type == ICMP6_ECHO_REQUEST)
	    {
	      if(probe->pr_icmp_sum != 0)
		{
		  snprintf(icmp, sizeof(icmp), ", sum %04x",
			   ntohs(probe->pr_icmp_sum));
		}
	      scamper_debug("tx", "icmp %s echo, ttl %d%s, seq %d, len %d",
			    addr, probe->pr_ip_ttl, icmp, probe->pr_icmp_seq,
			    iphl + 8 + probe->pr_len);
	    }
	  else if(probe->pr_icmp_type == ICMP6_PACKET_TOO_BIG)
	    {
	      scamper_debug("tx", "icmp %s ptb %d, len %d", addr,
			    probe->pr_icmp_mtu, iphl + 8 + probe->pr_len);
	    }
	  else if(probe->pr_icmp_type == ICMP6_DST_UNREACH)
	    {
	      scamper_debug("tx", "icmp %s unreach %d, len %d", addr,
			    probe->pr_icmp_code, iphl + 8 + probe->pr_len);
	    }
	  else
	    {
	      scamper_debug("tx", "icmp %s type %d, code %d, len %d",
			    addr, probe->pr_icmp_type, probe->pr_icmp_code,
			    iphl + 8 + probe->pr_len);
	    }
	  break;
	}
    }

  return;
}
#else
#define probe_print(probe) ((void)0)
#endif

static void probe_free(scamper_probe_t *pr)
{
  if(pr == NULL) return;
  if(pr->pr_ip_dst != NULL) scamper_addr_free(pr->pr_ip_dst);
  if(pr->pr_ip_src != NULL) scamper_addr_free(pr->pr_ip_src);
  if(pr->pr_ipopts != NULL) free(pr->pr_ipopts);
  if(pr->pr_data != NULL) free(pr->pr_data);
  free(pr);
  return;
}

static scamper_probe_t *probe_dup(scamper_probe_t *pr)
{
  scamper_probe_t *pd = NULL;
  size_t len;

  if((pd = memdup(pr, sizeof(scamper_probe_t))) == NULL)
    goto err;

  pd->pr_dl = NULL;
  pd->pr_dl_buf = NULL;
  pd->pr_dl_len = 0;
  pd->pr_ipopts = NULL;
  pd->pr_data = NULL;
  if(pr->pr_ip_src != NULL)
    pd->pr_ip_src = scamper_addr_use(pr->pr_ip_src);
  if(pr->pr_ip_dst != NULL)
    pd->pr_ip_dst = scamper_addr_use(pr->pr_ip_dst);

  if(pr->pr_ipoptc > 0)
    {
      len = pr->pr_ipoptc * sizeof(scamper_probe_ipopt_t);
      if((pd->pr_ipopts = memdup(pr->pr_ipopts, len)) == NULL)
	goto err;
    }

  if(pr->pr_len > 0)
    {
      if((pd->pr_data = memdup(pr->pr_data, pr->pr_len)) == NULL)
	goto err;
    }

  return pd;

 err:
  probe_free(pd);
  return NULL;
}

static void probe_state_free_cb(void *vpt)
{
  probe_state_t *pt = vpt;
  if(pt == NULL)
    return;
  if(pt->pr != NULL)
    probe_free(pt->pr);
  if(pt->buf != NULL && pt->buf != pktbuf)
    free(pt->buf);
  if(pt->rt != NULL)
    scamper_route_free(pt->rt);
  if(pt->dlhdr != NULL)
    scamper_dlhdr_free(pt->dlhdr);
  free(pt);
  return;
}

static void probe_state_free(probe_state_t *pt)
{
  if(pt == NULL)
    return;
  if(pt->anc != NULL)
    scamper_task_anc_del(pt->task, pt->anc);
  probe_state_free_cb(pt);
  return;
}

/*
 * probe_state_alloc
 *
 * determine how to build the packet and call the appropriate function
 * to do so.
 */
static probe_state_t *probe_state_alloc(scamper_probe_t *pr)
{
  int (*build_func)(scamper_probe_t *, uint8_t *, size_t *) = NULL;
  probe_state_t *pt = NULL;
  size_t len;

  if((pt = malloc_zero(sizeof(probe_state_t))) == NULL)
    {
      pr->pr_errno = errno;
      goto err;
    }

  if(rawtcp != 0 && pr->pr_ip_proto == IPPROTO_TCP &&
     SCAMPER_ADDR_TYPE_IS_IPV4(pr->pr_ip_dst))
    {
      if((pt->pr = probe_dup(pr)) == NULL)
	{
	  pr->pr_errno = errno;
	  goto err;
	}
      return pt;
    }

  if(SCAMPER_ADDR_TYPE_IS_IPV4(pr->pr_ip_dst))
    {
      if((pr->pr_ip_off & IP_OFFMASK) != 0)
	build_func = scamper_ip4_frag_build;
      else if(pr->pr_ip_proto == IPPROTO_UDP)
	build_func = scamper_udp4_build;
      else if(pr->pr_ip_proto == IPPROTO_ICMP)
	build_func = scamper_icmp4_build;
      else if(pr->pr_ip_proto == IPPROTO_TCP)
	build_func = scamper_tcp4_build;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(pr->pr_ip_dst))
    {
      if(pr->pr_ip_off != 0)
	build_func = scamper_ip6_frag_build;
      if(pr->pr_ip_proto == IPPROTO_UDP)
	build_func = scamper_udp6_build;
      else if(pr->pr_ip_proto == IPPROTO_ICMPV6)
	build_func = scamper_icmp6_build;
      else if(pr->pr_ip_proto == IPPROTO_TCP)
	build_func = scamper_tcp6_build;
    }

  if(build_func == NULL)
    {
      pr->pr_errno = EINVAL;
      goto err;
    }

  /* allow 16 bytes at the front of the packet for layer-2 headers */
  if(16 >= pktbuf_len)
    len = 0;
  else
    len = pktbuf_len-16;

  if(build_func(pr, pktbuf+16, &len) != 0)
    {
      /* reallocate the packet buffer */
      if(realloc_wrap((void **)&pktbuf, len+16) != 0)
	{
	  pr->pr_errno = errno;
	  goto err;
	}
      pktbuf_len = len+16;
      if(build_func(pr, pktbuf+16, &len) != 0)
	{
	  pr->pr_errno = EINVAL;
	  goto err;
	}
    }

  pt->buf = pktbuf;
  pt->len = len;
  return pt;

 err:
  if(pt != NULL) probe_state_free(pt);
  return NULL;
}

static void probe_dlhdr_cb(scamper_dlhdr_t *dlhdr)
{
  probe_state_t *pr = dlhdr->param;
  scamper_fd_t *fd = NULL;
  scamper_dl_t *dl = NULL;
  uint8_t *pkt;

  if(dlhdr->error != 0)
    {
      pr->error = dlhdr->error;
      goto err;
    }

  assert(dlhdr->len < 16);
  pkt = pr->buf+16-dlhdr->len;
  if(dlhdr->len > 0)
    memcpy(pkt, dlhdr->buf, dlhdr->len);

  if((fd = scamper_task_fd_dl(pr->task, pr->rt->ifindex)) == NULL)
    {
      pr->error = EINVAL;
      goto err;
    }

  if(pr->buf == pktbuf)
    gettimeofday_wrap(&pr->tv);
  dl = scamper_fd_dl_get(fd);
  if(scamper_dl_tx(dl, pkt, dlhdr->len + pr->len) == -1)
    {
      pr->error = errno;
      goto err;
    }
  pr->mode = PROBE_MODE_TX;
  goto done;

 err:
  pr->mode = PROBE_MODE_ERR;

 done:
  if(pr->anc != NULL)
    probe_state_free(pr);
  return;
}

static void probe_route_cb(scamper_route_t *rt)
{
  scamper_fd_t *fd = NULL;
  scamper_dl_t *dl = NULL;
  probe_state_t *pr = rt->param;

  if(rt->error != 0 || rt->ifindex < 0)
    {
      pr->error = rt->error;
      goto err;
    }
  if((fd = scamper_task_fd_dl(pr->task, rt->ifindex)) == NULL)
    {
      pr->error = errno;
      goto err;
    }

  if(rawtcp != 0 && pr->pr != NULL &&
     pr->pr->pr_ip_proto == IPPROTO_TCP &&
     SCAMPER_ADDR_TYPE_IS_IPV4(pr->pr->pr_ip_dst))
    {
      if((fd = scamper_task_fd_ip4(pr->task)) != NULL)
	{
	  pr->pr->pr_fd = scamper_fd_fd_get(fd);
	  if(scamper_tcp4_probe(pr->pr) != 0)
	    pr->mode = PROBE_MODE_ERR;
	}
      if(pr->anc != NULL)
	probe_state_free(pr);
      return;
    }

  if((pr->dlhdr = scamper_dlhdr_alloc()) == NULL)
    {
      pr->error = errno;
      goto err;
    }
  dl = scamper_fd_dl_get(fd);

  pr->dlhdr->dst     = scamper_addr_use(rt->dst);
  pr->dlhdr->gw      = rt->gw != NULL ? scamper_addr_use(rt->gw) : NULL;
  pr->dlhdr->ifindex = rt->ifindex;
  pr->dlhdr->txtype  = scamper_dl_tx_type(dl);
  pr->dlhdr->param   = pr;
  pr->dlhdr->cb      = probe_dlhdr_cb;
  pr->mode           = PROBE_MODE_DL;
  if(scamper_dlhdr_get(pr->dlhdr) != 0)
    {
      pr->error = pr->dlhdr->error;
      goto err;
    }

  return;

 err:
  pr->mode = PROBE_MODE_ERR;
  if(pr->anc != NULL)
    probe_state_free(pr);
  return;
}

static int probe_task_dl(scamper_probe_t *pr, scamper_task_t *task)
{
  probe_state_t *pt = NULL;

  if((pt = probe_state_alloc(pr)) == NULL)
    {
      pr->pr_errno = errno;
      goto err;
    }
  pt->task = task;
  pt->mode = PROBE_MODE_RT;
  if((pt->rt = scamper_route_alloc(pr->pr_ip_dst,pt,probe_route_cb)) == NULL)
    {
      pr->pr_errno = errno;
      goto err;
    }

#ifndef _WIN32
  if((pt->rtsock = scamper_task_fd_rtsock(task)) == NULL)
    {
      pr->pr_errno = errno;
      goto err;
    }
  if(scamper_rtsock_getroute(pt->rtsock, pt->rt) != 0)
    {
      pr->pr_errno = errno;
      goto err;
    }
#else
  if(scamper_rtsock_getroute(pt->rt) != 0)
    {
      pr->pr_errno = errno;
      goto err;
    }
#endif

  if(pt->mode == PROBE_MODE_ERR)
    {
      pr->pr_errno = pt->error;
      goto err;
    }

  if(pt->mode != PROBE_MODE_TX)
    {
      if(pt->len > 0 && (pt->buf = memdup(pktbuf, pt->len + 16)) == NULL)
	{
	  pr->pr_errno = errno;
	  goto err;
	}
      if((pt->anc = scamper_task_anc_add(task,pt,probe_state_free_cb)) == NULL)
	{
	  pr->pr_errno = errno;
	  goto err;
	}
      gettimeofday_wrap(&pr->pr_tx);
    }
  else
    {
      timeval_cpy(&pr->pr_tx, &pt->tv);
      probe_state_free(pt);
    }
  return 0;

 err:
  if(pt != NULL) probe_state_free(pt);
  return -1;
}

static int probe_task_ipv4(scamper_probe_t *pr, scamper_task_t *task,
			   scamper_fd_t *icmp)
{
  scamper_fd_t *fd;

  if(pr->pr_ip_proto == IPPROTO_UDP)
    {
      fd = scamper_task_fd_udp4(task, pr->pr_ip_src->addr, pr->pr_udp_sport);
      if(fd == NULL)
	{
	  pr->pr_errno = errno;
	  return -1;
	}
      pr->pr_fd = scamper_fd_fd_get(fd);
      if(scamper_udp4_probe(pr) != 0)
	{
	  pr->pr_errno = errno;
	  return -1;
	}
    }
  else if(pr->pr_ip_proto == IPPROTO_ICMP)
    {
      pr->pr_fd = scamper_fd_fd_get(icmp);
      if(scamper_icmp4_probe(pr) != 0)
	{
	  pr->pr_errno = errno;
	  return -1;
	}
    }
  else
    {
      scamper_debug(__func__, "unhandled protocol %d", pr->pr_ip_proto);
      pr->pr_errno = EINVAL; /* actually a bug in the caller */
      return -1;
    }

  return 0;
}

static int probe_task_ipv6(scamper_probe_t *pr, scamper_task_t *task,
			   scamper_fd_t *icmp)
{
  scamper_fd_t *fd;

  if(pr->pr_ip_proto == IPPROTO_UDP)
    {
      fd = scamper_task_fd_udp6(task, pr->pr_ip_src->addr, pr->pr_udp_sport);
      if(fd == NULL)
	{
	  pr->pr_errno = errno;
	  return -1;
	}
      pr->pr_fd = scamper_fd_fd_get(fd);
      if(scamper_udp6_probe(pr) != 0)
	{
	  pr->pr_errno = errno;
	  return -1;
	}
    }
  else if(pr->pr_ip_proto == IPPROTO_ICMPV6)
    {
      pr->pr_fd = scamper_fd_fd_get(icmp);
      if(scamper_icmp6_probe(pr) != 0)
	{
	  pr->pr_errno = errno;
	  return -1;
	}
    }
  else
    {
      pr->pr_errno = EINVAL; /* actually a bug in the caller */
      return -1;
    }

  return 0;
}

int scamper_probe_task(scamper_probe_t *pr, scamper_task_t *task)
{
  scamper_fd_t *icmp = NULL;
  int dl = 0;

  probe_print(pr);

  /* get an ICMP socket to listen for responses */
  if(SCAMPER_ADDR_TYPE_IS_IPV4(pr->pr_ip_dst))
    {
      if((pr->pr_flags & SCAMPER_PROBE_FLAG_SPOOF) == 0 &&
	 (icmp = scamper_task_fd_icmp4(task, pr->pr_ip_src->addr)) == NULL)
	{
	  pr->pr_errno = errno;
	  goto err;
	}
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(pr->pr_ip_dst))
    {
      if((pr->pr_flags & SCAMPER_PROBE_FLAG_SPOOF) == 0 &&
	 (icmp = scamper_task_fd_icmp6(task, pr->pr_ip_src->addr)) == NULL)
	{
	  pr->pr_errno = errno;
	  goto err;
	}
    }
  else
    {
      scamper_debug(__func__, "missing destination address");
      pr->pr_errno = EINVAL;
      goto err;
    }

  /*
   * even though many operating systems allow the use of RAW TCP sockets to
   * send TCP probes, we still need to be able to receive TCP responses.
   * so we use a datalink socket to both send and receive TCP probes rather
   * than open both a socket to send and another to receive.
   */
  if(pr->pr_ip_proto == IPPROTO_TCP ||
     (ipid_dl != 0 && SCAMPER_PROBE_IS_IPID(pr)) ||
     (pr->pr_flags & SCAMPER_PROBE_FLAG_NOFRAG) != 0 ||
     (pr->pr_flags & SCAMPER_PROBE_FLAG_SPOOF) != 0 ||
     (pr->pr_flags & SCAMPER_PROBE_FLAG_DL) != 0)
    dl = 1;

  if(dl != 0)
    {
      if(probe_task_dl(pr, task) != 0)
	goto err;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV4(pr->pr_ip_dst))
    {
      if(probe_task_ipv4(pr, task, icmp) != 0)
	goto err;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(pr->pr_ip_dst))
    {
      if(probe_task_ipv6(pr, task, icmp) != 0)
	goto err;
    }
  else
    {
      pr->pr_errno = EINVAL;
      goto err;
    }

  return 0;

 err:
  printerror_msg(__func__, "could not probe: %s", strerror(pr->pr_errno));
  return -1;
}

/*
 * scamper_probe_send
 *
 * this meta-function is responsible for
 *  1. sending a probe
 *  2. handling any error condition incurred when sending the probe
 *  3. recording details of the probe with the trace's state
 */
int scamper_probe(scamper_probe_t *probe)
{
  int (*send_func)(scamper_probe_t *) = NULL;
  int (*build_func)(scamper_probe_t *, uint8_t *, size_t *) = NULL;
  size_t pad, len;
  uint8_t *buf;

  probe->pr_errno = 0;
  probe_print(probe);

  /* determine which function scamper should use to build or send the probe */
  if(probe->pr_ip_dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      if((probe->pr_ip_off & IP_OFFMASK) != 0)
	{
	  build_func = scamper_ip4_frag_build;
	}
      else if(probe->pr_ip_proto == IPPROTO_UDP)
	{
	  send_func = scamper_udp4_probe;
	  build_func = scamper_udp4_build;
	}
      else if(probe->pr_ip_proto == IPPROTO_TCP)
	{
	  build_func = scamper_tcp4_build;
	  if(probe->pr_fd != -1)
	    send_func = scamper_tcp4_probe;
	}
      else if(probe->pr_ip_proto == IPPROTO_ICMP)
	{
	  send_func = scamper_icmp4_probe;
	  build_func = scamper_icmp4_build;
	}
    }
  else if(probe->pr_ip_dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      if(probe->pr_ip_off != 0)
	{
	  build_func = scamper_ip6_frag_build;
	}
      else if(probe->pr_ip_proto == IPPROTO_UDP)
	{
	  send_func = scamper_udp6_probe;
	  build_func = scamper_udp6_build;
	}
      else if(probe->pr_ip_proto == IPPROTO_TCP)
	{
	  build_func = scamper_tcp6_build;
	}
      else if(probe->pr_ip_proto == IPPROTO_ICMPV6)
	{
	  send_func = scamper_icmp6_probe;
	  build_func = scamper_icmp6_build;
	}
    }

  /* if we're not using the datalink to send the packet, then send it now */
  if(probe->pr_dl == NULL)
    {
      if(send_func != NULL)
	return send_func(probe);
      probe->pr_errno = EINVAL;
      return -1;
    }

  /* if the header type is not known (we cannot build it) then bail */
  if(build_func == NULL)
    {
      probe->pr_errno = EINVAL;
      return -1;
    }

  /*
   * determine a suitable value for the length parameter for passing
   * to build_func.  to do so we also need to calculate the number of pad
   * bytes to put at the front of the packet buffer so that the IP layer
   * is properly aligned for the architecture
   */
  pad = PAD(probe->pr_dl_len);
  if(pad + probe->pr_dl_len >= pktbuf_len)
    len = 0;
  else
    len = pktbuf_len - pad - probe->pr_dl_len;

  /*
   * try building the probe.  if it returns -1, then hopefully the len field
   * will supply a clue as to what it should be
   */
  if(build_func(probe, pktbuf + pad + probe->pr_dl_len, &len) != 0)
    {
      assert(pktbuf_len < pad + probe->pr_dl_len + len);

      /* reallocate the packet buffer */
      len += pad + probe->pr_dl_len;
      if((buf = realloc(pktbuf, len)) == NULL)
	{
	  probe->pr_errno = errno;
	  printerror(__func__, "could not realloc");
	  return -1;
	}
      pktbuf     = buf;
      pktbuf_len = len;

      len = pktbuf_len - pad - probe->pr_dl_len;
      if(build_func(probe, pktbuf + pad + probe->pr_dl_len, &len) != 0)
	{
	  probe->pr_errno = EINVAL;
	  return -1;
	}
    }

  /* add the datalink header size back to the length field */
  len += probe->pr_dl_len;

  /* pre-pend the datalink header, if there is one */
  if(probe->pr_dl_len > 0)
    memcpy(pktbuf+pad, probe->pr_dl_buf, probe->pr_dl_len);

  gettimeofday_wrap(&probe->pr_tx);
  if(scamper_dl_tx(probe->pr_dl, pktbuf+pad, len) == -1)
    {
      probe->pr_errno = errno;
      return -1;
    }

  probe->pr_tx_raw = pktbuf + pad + probe->pr_dl_len;
  probe->pr_tx_rawlen = len - probe->pr_dl_len;
  return 0;
}

int scamper_probe_init(void)
{
  const scamper_osinfo_t *osinfo = scamper_osinfo_get();
  if(SCAMPER_OSINFO_IS_SUNOS(osinfo))
    ipid_dl = 1;
  if(scamper_option_planetlab() || scamper_option_rawtcp())
    rawtcp = 1;
  return 0;
}

void scamper_probe_cleanup(void)
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  pktbuf_len = 0;
  return;
}
