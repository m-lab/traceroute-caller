/*
 * scamper_do_neighbourdisc
 *
 * $Id: scamper_neighbourdisc_do.c,v 1.39 2019/08/04 05:08:40 mjl Exp $
 *
 * Copyright (C) 2009-2011 Matthew Luckie
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
  "$Id: scamper_neighbourdisc_do.c,v 1.39 2019/08/04 05:08:40 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_neighbourdisc.h"
#include "scamper_dl.h"
#include "scamper_fds.h"
#include "scamper_probe.h"
#include "scamper_task.h"
#include "scamper_options.h"
#include "scamper_if.h"
#include "scamper_getsrc.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_debug.h"
#include "scamper_neighbourdisc_do.h"
#include "mjl_list.h"
#include "utils.h"

static scamper_task_funcs_t nd_funcs;
extern scamper_addrcache_t *addrcache;
static uint8_t *pktbuf;
static size_t pktbuf_len;

typedef struct nd_state
{
  scamper_fd_t   *fd;
  int             ifindex;
  int             replyc;
  dlist_t        *cbs;
} nd_state_t;

struct scamper_neighbourdisc_do
{
  scamper_task_t *task;
  void           *param;
  void          (*cb)(void *, scamper_addr_t *, scamper_addr_t *);
  dlist_node_t   *node;
};

#define ND_OPT_FIRSTRESPONSE     1
#define ND_OPT_IFNAME            2
#define ND_OPT_REPLYC            3
#define ND_OPT_ATTEMPTS          4
#define ND_OPT_ALLATTEMPTS       5
#define ND_OPT_WAIT              6
#define ND_OPT_SRCADDR           7

static const scamper_option_in_t opts[] = {
  {'F', NULL, ND_OPT_FIRSTRESPONSE, SCAMPER_OPTION_TYPE_NULL},
  {'i', NULL, ND_OPT_IFNAME,        SCAMPER_OPTION_TYPE_STR},
  {'o', NULL, ND_OPT_REPLYC,        SCAMPER_OPTION_TYPE_NUM},
  {'q', NULL, ND_OPT_ATTEMPTS,      SCAMPER_OPTION_TYPE_NUM},
  {'Q', NULL, ND_OPT_ALLATTEMPTS,   SCAMPER_OPTION_TYPE_NULL},
  {'S', NULL, ND_OPT_SRCADDR,       SCAMPER_OPTION_TYPE_STR},
  {'w', NULL, ND_OPT_WAIT,          SCAMPER_OPTION_TYPE_NUM},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_neighbourdisc_usage(void)
{
  return "neighbourdisc [-FQ] [-i if] [-o replyc] [-q attempts] [-S srcaddr] [-w wait]\n";
}

static scamper_neighbourdisc_t *nd_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static nd_state_t *nd_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static void nd_handleerror(scamper_task_t *task, int error)
{
  scamper_task_queue_done(task, 0);
  return;
}

static void nd_done(scamper_task_t *task)
{
  scamper_task_queue_done(task, 0);
  return;
}

static void nd_state_free(nd_state_t *state)
{
  if(state->fd != NULL) scamper_fd_free(state->fd);
  free(state);
  return;
}

static int nd_state_alloc(scamper_task_t *task)
{
  scamper_neighbourdisc_t *nd = nd_getdata(task);
  scamper_dl_t *dl;
  nd_state_t *state;
  uint8_t src[6];
  int i;

  assert(nd != NULL);

  gettimeofday_wrap(&nd->start);

  if((state = malloc_zero(sizeof(nd_state_t))) == NULL)
    {
      printerror(__func__, "could not malloc state");
      goto err;
    }

  if(scamper_if_getifindex(nd->ifname, &state->ifindex) != 0)
    {
      printerror(__func__, "could not get ifindex for %s", nd->ifname);
      goto err;
    }

  if(nd->src_ip == NULL &&
     (nd->src_ip = scamper_getsrc(nd->dst_ip, state->ifindex)) == NULL)
    {
      printerror(__func__, "could not get src ip");
      goto err;
    }

  if(scamper_if_getmac(state->ifindex, src) != 0)
    {
      printerror(__func__, "could not get src mac");
      goto err;
    }

  if((nd->src_mac = scamper_addrcache_get_ethernet(addrcache, src)) == NULL)
    {
      printerror(__func__, "could not get src mac");
      goto err;
    }

  if((state->fd = scamper_fd_dl(state->ifindex)) == NULL)
    {
      printerror(__func__, "could not get fd");
      goto err;
    }

  if((dl = scamper_fd_dl_get(state->fd)) == NULL)
    {
      printerror(__func__, "could not get dl");
      goto err;
    }

  if((i = scamper_dl_tx_type(dl)) != SCAMPER_DL_TX_ETHERNET)
    {
      scamper_debug(__func__, "dl type %d not ethernet", i);
      goto err;
    }

  scamper_task_setstate(task, state);
  return 0;

 err:
  if(state != NULL) nd_state_free(state);
  return -1;
}

static void do_nd_handle_timeout(scamper_task_t *task)
{
  scamper_neighbourdisc_t *nd = nd_getdata(task);
  nd_state_t *state = nd_getstate(task);

  if(((nd->flags & SCAMPER_NEIGHBOURDISC_FLAG_ALLATTEMPTS) == 0 &&
      nd->dst_mac != NULL) || nd->probec == nd->attempts ||
     (state->replyc >= nd->replyc && nd->replyc != 0))
    {
      nd_done(task);
      return;
    }

  return;
}

static void do_nd_probe_arp(scamper_task_t *task)
{
  scamper_neighbourdisc_t *nd = nd_getdata(task);
  size_t off;

  /*
   * standard 14 byte ethernet header followed by 28 byte arp request.
   *
   * 6 bytes: broadcast ethernet mac address
   * 6 bytes: src mac address
   * 2 bytes: ethernet type
   *
   * 2 bytes: ethernet address space: 0x0001
   * 2 bytes: protocol address space: 0x0800
   * 1 byte:  the length of an ethernet mac address: 6
   * 1 byte:  the length of an ip address: 4
   * 2 bytes: request packet: 0x0001
   * 6 bytes: src mac address
   * 4 bytes: src IP address
   * 6 bytes: dst mac address: all zeros in request
   * 4 bytes: dst IP address
   */
  memset(pktbuf, 0xff, 6); off = 6;

  mem_concat(pktbuf, nd->src_mac->addr, 6, &off, pktbuf_len);
  bytes_htons(pktbuf+off, ETHERTYPE_ARP); off += 2;
  bytes_htons(pktbuf+off, 0x0001); off += 2;
  bytes_htons(pktbuf+off, ETHERTYPE_IP); off += 2;
  pktbuf[off++] = 6;
  pktbuf[off++] = 4;
  bytes_htons(pktbuf+off, 0x0001); off += 2;
  mem_concat(pktbuf, nd->src_mac->addr, 6, &off, pktbuf_len);
  mem_concat(pktbuf, nd->src_ip->addr, 4, &off, pktbuf_len);
  memset(pktbuf+off, 0, 6); off += 6;
  mem_concat(pktbuf, nd->dst_ip->addr, 4, &off, pktbuf_len);

  return;
}

static void do_nd_probe_nsol(scamper_task_t *task)
{
  scamper_neighbourdisc_t *nd = nd_getdata(task);
  struct ip6_hdr *ip6;
  struct icmp6_hdr *icmp6;
  struct in6_addr a;
  uint16_t u16, *w;
  uint8_t ip6_dst[16];
  uint8_t sol[4];
  size_t off = 0, icmp_off;
  int i, sum = 0;

  /* figure out the lower 4 bytes of the solicited multicast address */
  memcpy(sol, ((uint8_t *)nd->dst_ip->addr)+12, 4);
  sol[0] = 0xff;

  /* figure out the destination IPv6 address of this message */
  ip6_dst[0] = 0xff;
  ip6_dst[1] = 0x02;
  memset(ip6_dst+2, 0, 9);
  ip6_dst[11] = 0x01;
  memcpy(ip6_dst+12, sol, 4);

  /* ethernet header: 14 bytes */
  pktbuf[off++] = 0x33;
  pktbuf[off++] = 0x33;
  mem_concat(pktbuf, sol, 4, &off, pktbuf_len);
  mem_concat(pktbuf, nd->src_mac->addr, 6, &off, pktbuf_len);
  bytes_htons(pktbuf+off, ETHERTYPE_IPV6); off += 2;

  /* IPv6 header: 40 bytes */
  ip6 = (struct ip6_hdr *)(pktbuf+off); off += sizeof(struct ip6_hdr);
  memset(ip6, 0, sizeof(struct ip6_hdr));
  ip6->ip6_vfc  = 0x60;
  ip6->ip6_plen = htons(32);
  ip6->ip6_nxt  = IPPROTO_ICMPV6;
  ip6->ip6_hlim = 255;
  memcpy(&ip6->ip6_src, nd->src_ip->addr, 16);
  memcpy(&ip6->ip6_dst, ip6_dst, 16);

  /* ICMP6 neighbour discovery: 32 bytes */
  icmp_off = off;
  icmp6 = (struct icmp6_hdr *)(pktbuf+off); off += sizeof(struct icmp6_hdr);
  icmp6->icmp6_type = ND_NEIGHBOR_SOLICIT;
  icmp6->icmp6_code = 0;
  icmp6->icmp6_data32[0] = 0;
  icmp6->icmp6_cksum = 0;

  mem_concat(pktbuf, nd->dst_ip->addr, 16, &off, pktbuf_len);
  pktbuf[off++] = 0x01;
  pktbuf[off++] = 0x01;
  mem_concat(pktbuf, nd->src_mac->addr, 6, &off, pktbuf_len);

  /* build up the ICMP6 checksum, which includes a psuedo header */
  memcpy(&a, &ip6->ip6_src, sizeof(struct in6_addr));
  w = (uint16_t *)&a;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  memcpy(&a, &ip6->ip6_dst, sizeof(struct in6_addr));
  w = (uint16_t *)&a;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += ip6->ip6_plen;
  sum += htons(IPPROTO_ICMPV6);
  w = (uint16_t *)(pktbuf + icmp_off);
  for(i = ntohs(ip6->ip6_plen); i > 1; i -= 2)
    sum += *w++;
  if(i != 0)
    sum += ((uint8_t *)w)[0];
  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  if((u16 = ~sum) == 0)
    u16 = 0xffff;
  icmp6->icmp6_cksum = u16;

  return;
}

static void do_nd_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_neighbourdisc_t *nd = nd_getdata(task);
  nd_state_t *state = nd_getstate(task);
  scamper_neighbourdisc_probe_t *probe;
  scamper_neighbourdisc_reply_t *reply;
  uint16_t opt_off;
  uint8_t *opt;
  uint8_t *mac = NULL;

#ifdef HAVE_SCAMPER_DEBUG
  char a[64], b[64];
#endif

  if(nd->probec == 0)
    return;
  probe = nd->probes[nd->probec-1];

  if(SCAMPER_DL_IS_ARP(dl))
    {
      if(nd->method != SCAMPER_NEIGHBOURDISC_METHOD_ARP ||
	 SCAMPER_DL_IS_ARP_OP_REPLY(dl) == 0 ||
	 SCAMPER_DL_IS_ARP_HRD_ETHERNET(dl) == 0 ||
	 SCAMPER_DL_IS_ARP_PRO_IPV4(dl) == 0)
	{
	  return;
	}

      mac = dl->dl_arp_sha;
    }
  else if(SCAMPER_DL_IS_ICMPV6(dl))
    {
      if(nd->method != SCAMPER_NEIGHBOURDISC_METHOD_ND_NSOL ||
	 SCAMPER_DL_IS_ICMP6_ND_NADV(dl) == 0)
	{
	  return;
	}

      /*
       * loop through the attached options, trying to find the
       * destination link-address option
       */
      opt = dl->dl_icmp6_nd_opts;
      opt_off = 0;

      while(opt_off + 8 <= dl->dl_icmp6_nd_opts_len)
	{
	  if(opt[0]==2 && opt[1]==1 && dl->dl_icmp6_nd_opts_len-opt_off >= 8)
	    {
	      mac = opt+2;
	      break;
	    }
	  if(opt[1] == 0)
	    return;
	  opt_off += (opt[1] * 8);
	  opt     += (opt[1] * 8);
	}
    }

  if(mac == NULL)
    return;

  if((reply = scamper_neighbourdisc_reply_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc reply");
      goto err;
    }
  timeval_cpy(&reply->rx, &dl->dl_tv);
  reply->mac = scamper_addrcache_get_ethernet(addrcache, mac);
  if(reply->mac == NULL)
    {
      printerror(__func__, "could not get reply->mac");
      goto err;
    }

  scamper_debug(__func__, "%s is-at %s",
		scamper_addr_tostr(nd->dst_ip, a, sizeof(a)),
		scamper_addr_tostr(reply->mac, b, sizeof(b)));

  if(scamper_neighbourdisc_reply_add(probe, reply) != 0)
    {
      printerror(__func__, "could not add reply");
      goto err;
    }

  if(nd->dst_mac == NULL)
    nd->dst_mac = scamper_addr_use(reply->mac);

  if(probe->rxc == 1)
    {
      state->replyc++;
      if((nd->flags & SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE) != 0)
	nd_done(task);
    }

  return;

 err:
  return;
}

static void do_nd_probe(scamper_task_t *task)
{
  scamper_neighbourdisc_probe_t *probe = NULL;
  scamper_neighbourdisc_t *nd = nd_getdata(task);
  nd_state_t *state = nd_getstate(task);
  scamper_dl_t *dl;
  size_t len;
  char ip[64], mac[32];

  if(state == NULL)
    {
      if(nd_state_alloc(task) != 0)
	goto err;
      state = nd_getstate(task);
    }

  /* determine the length of the packet to transmit */
  if(nd->method == SCAMPER_NEIGHBOURDISC_METHOD_ARP)
    len = 42;
  else if(nd->method == SCAMPER_NEIGHBOURDISC_METHOD_ND_NSOL)
    len = 86;
  else goto err;

  /* make sure the pktbuf is at least that size */
  if(pktbuf_len < len)
    {
      if(realloc_wrap((void **)&pktbuf, len) != 0)
	{
	  printerror(__func__, "could not realloc");
	  goto err;
	}
      pktbuf_len = len;
    }

  /* form the probe to send */
  if(nd->method == SCAMPER_NEIGHBOURDISC_METHOD_ARP)
    do_nd_probe_arp(task);
  else if(nd->method == SCAMPER_NEIGHBOURDISC_METHOD_ND_NSOL)
    do_nd_probe_nsol(task);
  else goto err;

  /* allocate a probe record to store tx time and associated replies */
  if((probe = scamper_neighbourdisc_probe_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc probe");
      goto err;
    }

  /* send the probe.  record the time it is sent */
  dl = scamper_fd_dl_get(state->fd);
  gettimeofday_wrap(&probe->tx);
  if(scamper_dl_tx(dl, pktbuf, len) == -1)
    {
      goto err;
    }

  scamper_addr_tostr(nd->dst_ip, ip, sizeof(ip));
  scamper_addr_tostr(nd->src_mac, mac, sizeof(mac));
  scamper_debug(__func__, "who-has %s tell %s", ip, mac);

  if(scamper_neighbourdisc_probe_add(nd, probe) != 0)
    {
      printerror(__func__, "could not add probe");
      goto err;
    }

  scamper_task_queue_wait(task, nd->wait);
  return;

 err:
  nd_handleerror(task, errno);
  return;
}

static void do_nd_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_file_write_neighbourdisc(sf, nd_getdata(task));
  return;
}

static void do_nd_halt(scamper_task_t *task)
{
  nd_done(task);
  return;
}

static void do_nd_free(scamper_task_t *task)
{
  scamper_neighbourdisc_do_t *nddo;
  scamper_neighbourdisc_t *nd = nd_getdata(task);
  nd_state_t *state = nd_getstate(task);
  scamper_addr_t *mac = NULL;
  scamper_addr_t *ip = NULL;

  if(state != NULL && state->cbs != NULL)
    {
      if(nd != NULL)
	{
	  ip = nd->dst_ip;
	  mac = nd->dst_mac;
	}
      while((nddo = dlist_head_pop(state->cbs)) != NULL)
	{
	  nddo->node = NULL;
	  if(ip != NULL)
	    nddo->cb(nddo->param, ip, mac);
	  free(nddo);
	}
      dlist_free(state->cbs);
      state->cbs = NULL;
    }

  if(nd != NULL)
    scamper_neighbourdisc_free(nd);

  if(state != NULL)
    nd_state_free(state);

  return;
}

static int nd_arg_param_validate(int optid, char *param, long long *out)
{
  long tmp;

  switch(optid)
    {
    case ND_OPT_IFNAME:
    case ND_OPT_ALLATTEMPTS:
    case ND_OPT_SRCADDR:
      return 0;

    case ND_OPT_ATTEMPTS:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
       return -1;
      break;

    case ND_OPT_REPLYC:
      if(string_tolong(param, &tmp) != 0 || tmp < 0 || tmp > 65535)
	return -1;
      break;

    case ND_OPT_WAIT:
      if(string_tolong(param, &tmp) != 0 || tmp < 100 || tmp > 65535)
	return -1;
      break;

    default:
      return -1;
    }

  if(out != NULL)
    *out = (long long)tmp;

  return 0;
}

int scamper_do_neighbourdisc_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  nd_arg_param_validate);
}

scamper_task_t *scamper_do_neighbourdisc_alloctask(void *data,
						   scamper_list_t *list,
						   scamper_cycle_t *cycle)
{
  scamper_neighbourdisc_t *nd = (scamper_neighbourdisc_t *)data;
  scamper_task_sig_t *sig = NULL;
  scamper_task_t *task = NULL;

  /* allocate a task structure and store the neighbourdisc with it */
  if((task = scamper_task_alloc(nd, &nd_funcs)) == NULL)
    goto err;

  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_ND)) == NULL)
    goto err;
  sig->sig_tx_nd_ip = scamper_addr_use(nd->dst_ip);
  if(scamper_task_sig_add(task, sig) != 0)
    goto err;
  sig = NULL;

  /* associate the list and cycle with the neighbourdisc */
  nd->list  = scamper_list_use(list);
  nd->cycle = scamper_cycle_use(cycle);

  return task;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  if(task != NULL)
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  return NULL;
}

void *scamper_do_neighbourdisc_alloc(char *str)
{
  scamper_neighbourdisc_t *nd = NULL;
  scamper_option_out_t *opts_out = NULL, *opt;
  char    *ifname   = NULL;
  uint16_t attempts = 1;
  uint16_t replyc   = 0;
  uint16_t wait     = 1000;
  uint8_t  flags    = 0;
  char    *dst      = NULL;
  char    *src      = NULL;
  long long tmp     = 0;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &dst) != 0)
    {
      scamper_debug(__func__, "could not parse command");
      goto err;
    }

  if(dst == NULL)
    goto err;

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 nd_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	case ND_OPT_FIRSTRESPONSE:
	  flags |= SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE;
	  break;

	case ND_OPT_IFNAME:
	  ifname = opt->str;
	  break;

	case ND_OPT_ATTEMPTS:
	  attempts = (uint16_t)tmp;
	  break;

	case ND_OPT_REPLYC:
	  replyc = (uint16_t)tmp;
	  break;

	case ND_OPT_ALLATTEMPTS:
	  flags |= SCAMPER_NEIGHBOURDISC_FLAG_ALLATTEMPTS;
	  break;

	case ND_OPT_WAIT:
	  wait = (uint16_t)tmp;
	  break;

	case ND_OPT_SRCADDR:
	  if(src != NULL)
	    goto err;
	  src = opt->str;
	  break;

	default:
	  scamper_debug(__func__, "unhandled option %d", opt->id);
	  goto err;
	}
    }

  scamper_options_free(opts_out); opts_out = NULL;

  if(ifname == NULL)
    goto err;

  if((nd = scamper_neighbourdisc_alloc()) == NULL)
    goto err;

  if((nd->dst_ip = scamper_addrcache_resolve(addrcache,AF_UNSPEC,dst)) == NULL)
    goto err;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(nd->dst_ip))
    nd->method = SCAMPER_NEIGHBOURDISC_METHOD_ARP;
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(nd->dst_ip))
    nd->method = SCAMPER_NEIGHBOURDISC_METHOD_ND_NSOL;
  else
    goto err;

  if(src != NULL)
    {
      if(SCAMPER_ADDR_TYPE_IS_IPV6(nd->dst_ip) == 0)
	goto err;
      nd->src_ip = scamper_addrcache_resolve(addrcache, AF_INET6, src);
      if(nd->src_ip == NULL)
	goto err;
    }

  if(scamper_neighbourdisc_ifname_set(nd, ifname) != 0)
    goto err;

  /*
   * if we only want the first response, then we can't want more than
   * one reply
   */
  if((flags & SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE) != 0 &&
     (replyc > 1 || (flags & SCAMPER_NEIGHBOURDISC_FLAG_ALLATTEMPTS) != 0))
    {
      scamper_debug(__func__, "invalid combination of arguments");
      goto err;
    }

  /*
   * if we have asked for all attempts to be sent, but we have limited the
   * number of replies we want to less than the number of probes we will send,
   * then these arguments are conflicting
   */
  if(replyc < attempts && replyc != 0 &&
     (flags & SCAMPER_NEIGHBOURDISC_FLAG_ALLATTEMPTS) != 0)
    {
      scamper_debug(__func__, "invalid combination of arguments");
      goto err;
    }

  nd->flags    = flags;
  nd->attempts = attempts;
  nd->replyc   = replyc;
  nd->wait     = wait;

  return nd;

 err:
  if(nd != NULL) scamper_neighbourdisc_free(nd);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

void scamper_neighbourdisc_do_free(scamper_neighbourdisc_do_t *nddo)
{
  scamper_task_t *task;
  nd_state_t *state;

  if(nddo == NULL)
    return;

  if((task = nddo->task) != NULL)
    {
      state = nd_getstate(task);
      if(state != NULL && nddo->node != NULL)
	dlist_node_pop(state->cbs, nddo->node);
    }

  free(nddo);
  return;
}

static scamper_neighbourdisc_do_t *scamper_neighbourdisc_do_add(
  scamper_task_t *task, void *param,
  void (*cb)(void *param,scamper_addr_t *ip,scamper_addr_t *dst))
{
  scamper_neighbourdisc_do_t *nddo = NULL;
  nd_state_t *state = nd_getstate(task);

  if(state->cbs == NULL && (state->cbs = dlist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc state->cbs");
      return NULL;
    }
  if((nddo = malloc_zero(sizeof(scamper_neighbourdisc_do_t))) == NULL)
    {
      printerror(__func__, "could not alloc nddo");
      return NULL;
    }
  nddo->task = task;
  nddo->cb = cb;
  nddo->param = param;
  if((nddo->node = dlist_tail_push(state->cbs, nddo)) == NULL)
    {
      printerror(__func__, "could not add nddo");
      free(nddo);
      return NULL;
    }
  return nddo;
}

scamper_neighbourdisc_do_t *scamper_do_neighbourdisc_do(
  int ifindex, scamper_addr_t *dst, void *param,
  void (*cb)(void *param,scamper_addr_t *ip,scamper_addr_t *dst))
{
  scamper_neighbourdisc_t *nd = NULL;
  scamper_task_sig_t sig;
  scamper_task_t *task = NULL;
  uint8_t method;
  char ifname[64];

  if(dst->type == SCAMPER_ADDR_TYPE_IPV4)
    method = SCAMPER_NEIGHBOURDISC_METHOD_ARP;
  else
    method = SCAMPER_NEIGHBOURDISC_METHOD_ND_NSOL;

  memset(&sig, 0, sizeof(sig));
  sig.sig_type = SCAMPER_TASK_SIG_TYPE_TX_ND;
  sig.sig_tx_nd_ip = dst;

  /* piggy back on existing nd task if there is one */
  if((task = scamper_task_find(&sig)) != NULL)
    return scamper_neighbourdisc_do_add(task, param, cb);

  if(scamper_if_getifname(ifname, sizeof(ifname), ifindex) != 0)
    goto err;

  if((nd = scamper_neighbourdisc_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc nd");
      goto err;
    }
  if(scamper_neighbourdisc_ifname_set(nd, ifname) != 0)
    {
      printerror(__func__, "could not set ifname");
      goto err;
    }

  nd->method    = method;
  nd->dst_ip    = scamper_addr_use(dst);
  nd->flags    |= SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE;
  nd->attempts  = 1;
  nd->wait      = 500;
  nd->replyc    = 1;

  if((task = scamper_do_neighbourdisc_alloctask(nd, NULL, NULL)) == NULL)
    goto err;
  nd = NULL;
  if(scamper_task_sig_install(task) != 0)
    goto err;
  if(nd_state_alloc(task) != 0)
    goto err;
  do_nd_probe(task);
  if(scamper_task_queue_isdone(task))
    goto err;
  return scamper_neighbourdisc_do_add(task, param, cb);

 err:
  if(nd != NULL) scamper_neighbourdisc_free(nd);
  return NULL;
}

void scamper_do_neighbourdisc_free(void *data)
{
  scamper_neighbourdisc_free((scamper_neighbourdisc_t *)data);
  return;
}

void scamper_do_neighbourdisc_cleanup()
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  return;
}

int scamper_do_neighbourdisc_init()
{
  nd_funcs.probe          = do_nd_probe;
  nd_funcs.handle_timeout = do_nd_handle_timeout;
  nd_funcs.write          = do_nd_write;
  nd_funcs.task_free      = do_nd_free;
  nd_funcs.handle_dl      = do_nd_handle_dl;
  nd_funcs.halt           = do_nd_halt;

  return 0;
}
