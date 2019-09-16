/*
 * scamper_do_dealias.c
 *
 * $Id: scamper_dealias_do.c,v 1.162 2019/07/12 23:37:57 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012-2013 Matthew Luckie
 * Copyright (C) 2012-2014 The Regents of the University of California
 * Copyright (C) 2016      Matthew Luckie
 * Author: Matthew Luckie
 *
 * This code implements alias resolution techniques published by others
 * which require the network to be probed; the author of each technique
 * is detailed with its data structures.
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
  "$Id: scamper_dealias_do.c,v 1.162 2019/07/12 23:37:57 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_dealias.h"
#include "scamper_task.h"
#include "scamper_icmp_resp.h"
#include "scamper_fds.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_rtsock.h"
#include "scamper_probe.h"
#include "scamper_getsrc.h"
#include "scamper_udp4.h"
#include "scamper_udp6.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_options.h"
#include "scamper_debug.h"
#include "scamper_dealias_do.h"
#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "utils.h"

static scamper_task_funcs_t funcs;

/* packet buffer for generating the payload of each packet */
static uint8_t             *pktbuf     = NULL;
static size_t               pktbuf_len = 0;

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

#define DEALIAS_OPT_DPORT        1
#define DEALIAS_OPT_FUDGE        2
#define DEALIAS_OPT_METHOD       3
#define DEALIAS_OPT_REPLYC       4
#define DEALIAS_OPT_OPTION       5
#define DEALIAS_OPT_PROBEDEF     6
#define DEALIAS_OPT_ATTEMPTS     7
#define DEALIAS_OPT_WAIT_ROUND   8
#define DEALIAS_OPT_SPORT        9
#define DEALIAS_OPT_TTL          10
#define DEALIAS_OPT_USERID       11
#define DEALIAS_OPT_WAIT_TIMEOUT 12
#define DEALIAS_OPT_WAIT_PROBE   13
#define DEALIAS_OPT_EXCLUDE      14

static const scamper_option_in_t opts[] = {
  {'d', NULL, DEALIAS_OPT_DPORT,        SCAMPER_OPTION_TYPE_NUM},
  {'f', NULL, DEALIAS_OPT_FUDGE,        SCAMPER_OPTION_TYPE_NUM},
  {'m', NULL, DEALIAS_OPT_METHOD,       SCAMPER_OPTION_TYPE_STR},
  {'o', NULL, DEALIAS_OPT_REPLYC,       SCAMPER_OPTION_TYPE_NUM},
  {'O', NULL, DEALIAS_OPT_OPTION,       SCAMPER_OPTION_TYPE_STR},
  {'p', NULL, DEALIAS_OPT_PROBEDEF,     SCAMPER_OPTION_TYPE_STR},
  {'q', NULL, DEALIAS_OPT_ATTEMPTS,     SCAMPER_OPTION_TYPE_NUM},
  {'r', NULL, DEALIAS_OPT_WAIT_ROUND,   SCAMPER_OPTION_TYPE_NUM},
  {'s', NULL, DEALIAS_OPT_SPORT,        SCAMPER_OPTION_TYPE_NUM},
  {'t', NULL, DEALIAS_OPT_TTL,          SCAMPER_OPTION_TYPE_NUM},
  {'U', NULL, DEALIAS_OPT_USERID,       SCAMPER_OPTION_TYPE_NUM},
  {'w', NULL, DEALIAS_OPT_WAIT_TIMEOUT, SCAMPER_OPTION_TYPE_NUM},
  {'W', NULL, DEALIAS_OPT_WAIT_PROBE,   SCAMPER_OPTION_TYPE_NUM},
  {'x', NULL, DEALIAS_OPT_EXCLUDE,      SCAMPER_OPTION_TYPE_STR},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

#define DEALIAS_PROBEDEF_OPT_CSUM  1
#define DEALIAS_PROBEDEF_OPT_DPORT 2
#define DEALIAS_PROBEDEF_OPT_IP    3
#define DEALIAS_PROBEDEF_OPT_PROTO 4
#define DEALIAS_PROBEDEF_OPT_SPORT 5
#define DEALIAS_PROBEDEF_OPT_TTL   6
#define DEALIAS_PROBEDEF_OPT_SIZE  7
#define DEALIAS_PROBEDEF_OPT_MTU   8

static const scamper_option_in_t probedef_opts[] = {
  {'c', NULL, DEALIAS_PROBEDEF_OPT_CSUM,  SCAMPER_OPTION_TYPE_STR},
  {'d', NULL, DEALIAS_PROBEDEF_OPT_DPORT, SCAMPER_OPTION_TYPE_NUM},
  {'F', NULL, DEALIAS_PROBEDEF_OPT_SPORT, SCAMPER_OPTION_TYPE_NUM},
  {'i', NULL, DEALIAS_PROBEDEF_OPT_IP,    SCAMPER_OPTION_TYPE_STR},
  {'P', NULL, DEALIAS_PROBEDEF_OPT_PROTO, SCAMPER_OPTION_TYPE_STR},
  {'s', NULL, DEALIAS_PROBEDEF_OPT_SIZE,  SCAMPER_OPTION_TYPE_NUM},
  {'t', NULL, DEALIAS_PROBEDEF_OPT_TTL,   SCAMPER_OPTION_TYPE_NUM},
  {'M', NULL, DEALIAS_PROBEDEF_OPT_MTU,   SCAMPER_OPTION_TYPE_NUM},
};
static const int probedef_opts_cnt = SCAMPER_OPTION_COUNT(probedef_opts);

const char *scamper_do_dealias_usage(void)
{
  return
    "dealias [-d dport] [-f fudge] [-m method] [-o replyc] [-O option]\n"
    "        [-p '[-c sum] [-d dp] [-F sp] [-i ip] [-M mtu] [-P meth] [-s size] [-t ttl]']\n"
    "        [-q attempts] [-r wait-round] [-s sport] [-t ttl]\n"
    "        [-U userid] [-w wait-timeout] [-W wait-probe] [-x exclude]\n";
}

typedef struct dealias_target
{
  scamper_addr_t              *addr;
  dlist_t                     *probes;
  uint16_t                     tcp_sport;
  uint16_t                     udp_dport;
} dealias_target_t;

typedef struct dealias_probe
{
  dealias_target_t            *target;
  scamper_dealias_probe_t     *probe;
  uint16_t                     match_field;
  dlist_node_t                *target_node;
} dealias_probe_t;

typedef struct dealias_prefixscan
{
  scamper_dealias_probedef_t  *probedefs;
  int                          probedefc;
  scamper_addr_t             **aaliases;
  int                          aaliasc;
  int                          attempt;
  int                          seq;
  int                          round0;
  int                          round;
  int                          replyc;
} dealias_prefixscan_t;

typedef struct dealias_radargun
{
  uint32_t                    *order; /* probedef order */
  uint32_t                     i;     /* index into order */
  struct timeval               next_round;
} dealias_radargun_t;

typedef struct dealias_bump
{
  uint8_t                      step;
  uint8_t                      attempt;
  uint16_t                     bump;
} dealias_bump_t;

typedef struct dealias_options
{
  char                        *addr;
  uint8_t                      attempts;
  uint8_t                      replyc;
  uint8_t                      wait_timeout;
  uint16_t                     wait_probe;
  uint32_t                     wait_round;
  uint16_t                     sport;
  uint16_t                     dport;
  uint8_t                      ttl;
  uint16_t                     fudge;
  slist_t                     *probedefs;
  slist_t                     *xs;
  int                          nobs;
  int                          shuffle;
  int                          inseq;
} dealias_options_t;

typedef struct dealias_probedef
{
  scamper_dealias_probedef_t  *def;
  dealias_target_t            *target;
  uint32_t                     tcp_seq;
  uint32_t                     tcp_ack;
  uint16_t                     pktbuf_len;
  uint8_t                      flags;
  uint8_t                      echo;
} dealias_probedef_t;

typedef struct dealias_ptb
{
  scamper_dealias_probedef_t  *def;
  uint8_t                     *quote;
  uint16_t                     quote_len;
} dealias_ptb_t;

typedef struct dealias_state
{
  uint8_t                      id;
  uint8_t                      flags;
  uint16_t                     icmpseq;
  scamper_dealias_probedef_t  *probedefs;
  uint32_t                     probedefc;
  dealias_probedef_t         **pds;
  int                          pdc;
  uint32_t                     probe;
  uint32_t                     round;
  struct timeval               last_tx;
  struct timeval               next_tx;
  struct timeval               ptb_tx;
  splaytree_t                 *targets;
  dlist_t                     *recent_probes;
  void                        *methodstate;
  slist_t                     *ptbq;
  slist_t                     *discard;
} dealias_state_t;

#define DEALIAS_STATE_FLAG_DL 0x01

#define DEALIAS_PROBEDEF_FLAG_RX_IPID 0x01
#define DEALIAS_PROBEDEF_FLAG_TX_PTB  0x02

#ifdef NDEBUG
#define dealias_state_assert(state) ((void)0)
#endif

#ifndef NDEBUG
static void dealias_state_assert(const dealias_state_t *state)
				 
{
  int i;
  for(i=0; i<state->pdc; i++)
    {
      assert(state->pds[i] != NULL);
      assert(state->pds[i]->def->id == i);
    }
  return;
}
#endif

static scamper_dealias_t *dealias_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static dealias_state_t *dealias_getstate(const scamper_task_t *task)
{
  dealias_state_t *state = scamper_task_getstate(task);
  dealias_state_assert(state);
  return state;
}

static int dealias_ally_queue(const scamper_dealias_t *dealias,
			      dealias_state_t *state,
			      const struct timeval *now, struct timeval *tv)
{
  if(state->ptb_tx.tv_sec == 0)
    return 0;
  timeval_add_s(tv, &state->ptb_tx, 1);
  if(timeval_cmp(tv, now) > 0)
    return 1;
  memset(&state->ptb_tx, 0, sizeof(struct timeval));
  return 0;
}

static void dealias_queue(scamper_task_t *task)
{
  static int (*const func[])(const scamper_dealias_t *, dealias_state_t *,
			     const struct timeval *, struct timeval *) = {
    NULL,
    dealias_ally_queue,
    NULL,
    NULL,
    NULL,
  };
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  struct timeval tv, now;
  dealias_probe_t *p;

  if(scamper_task_queue_isdone(task))
    return;

  gettimeofday_wrap(&now);

  for(;;)
    {
      if((p = dlist_head_item(state->recent_probes)) == NULL)
	break;
      timeval_add_s(&tv, &p->probe->tx, 10);
      if(timeval_cmp(&now, &tv) < 0)
	break;
      dlist_node_pop(p->target->probes, p->target_node);
      dlist_head_pop(state->recent_probes);
      free(p);
    }

  if(slist_count(state->ptbq) > 0)
    {
      scamper_task_queue_probe(task);
      return;
    }

  if(func[dealias->method-1] != NULL &&
     func[dealias->method-1](dealias, state, &now, &tv) != 0)
    {
      scamper_task_queue_wait_tv(task, &tv);
      return;
    }

  if(timeval_cmp(&state->next_tx, &now) <= 0)
    {
      scamper_task_queue_probe(task);
      return;
    }

  scamper_task_queue_wait_tv(task, &state->next_tx);
  return;
}

static void dealias_handleerror(scamper_task_t *task, int error)
{
  scamper_task_queue_done(task, 0);
  return;
}

static void dealias_result(scamper_task_t *task, uint8_t result)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
#ifdef HAVE_SCAMPER_DEBUG
  char buf[16];
#endif

  dealias->result = result;

#ifdef HAVE_SCAMPER_DEBUG
  scamper_debug(__func__, "%s",
		scamper_dealias_result_tostr(dealias, buf, sizeof(buf)));
#endif

  scamper_task_queue_done(task, 0);
  return;
}

static void dealias_ptb_free(dealias_ptb_t *ptb)
{
  if(ptb == NULL)
    return;
  if(ptb->quote != NULL)
    free(ptb->quote);
  free(ptb);
  return;
}

static int dealias_ptb_add(dealias_state_t *state, scamper_dl_rec_t *dl,
			   scamper_dealias_probedef_t *def)
{
  dealias_ptb_t *ptb;

  if((ptb = malloc_zero(sizeof(dealias_ptb_t))) == NULL)
    {
      printerror(__func__, "could not malloc ptb");
      goto err;
    }
  ptb->def = def;
  if(dl->dl_ip_size > 1280-40-8)
    ptb->quote_len = 1280-40-8;
  else
    ptb->quote_len = dl->dl_ip_size;
  if((ptb->quote = memdup(dl->dl_net_raw, ptb->quote_len)) == NULL)
    {
      printerror(__func__, "could not dup ptb quote");
      goto err;
    }

  if(slist_tail_push(state->ptbq, ptb) == NULL)
    {
      printerror(__func__, "could not queue ptb");
      goto err;
    }

  return 0;
 err:
  if(ptb != NULL) dealias_ptb_free(ptb);
  return -1;
}

static int dealias_target_cmp(const dealias_target_t *a,
			      const dealias_target_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static void dealias_target_free(dealias_target_t *tgt)
{
  if(tgt == NULL)
    return;
  if(tgt->probes != NULL)
    dlist_free_cb(tgt->probes, free);
  if(tgt->addr != NULL)
    scamper_addr_free(tgt->addr);
  free(tgt);
  return;
}

static dealias_target_t *dealias_target_find(dealias_state_t *s,
					     scamper_addr_t *addr)
{
  dealias_target_t fm;
  fm.addr = addr;
  return splaytree_find(s->targets, &fm);
}

static dealias_target_t *dealias_target_get(dealias_state_t *state,
					    scamper_addr_t *addr)
{
  dealias_target_t *tgt;
  if((tgt = dealias_target_find(state, addr)) != NULL)
    return tgt;
  if((tgt = malloc_zero(sizeof(dealias_target_t))) == NULL ||
     (tgt->probes = dlist_alloc()) == NULL)
    {
      printerror(__func__, "could not malloc tgt");
      goto err;
    }
  tgt->addr = scamper_addr_use(addr);
  if(splaytree_insert(state->targets, tgt) == NULL)
    {
      printerror(__func__, "could not add tgt to tree");
      goto err;
    }
  return tgt;

 err:
  dealias_target_free(tgt);
  return NULL;
}

static int dealias_probedef_add(dealias_state_t *state,
				scamper_dealias_probedef_t *def)
{
  dealias_probedef_t *pd = NULL;

  if((pd = malloc_zero(sizeof(dealias_probedef_t))) == NULL)
    {
      printerror(__func__, "could not malloc pd");
      goto err;
    }
  pd->def = def;
  if((pd->target = dealias_target_get(state, def->dst)) == NULL)
    goto err;

  if(def->size == 0)
    pd->pktbuf_len = 2;
  else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO)
    if(SCAMPER_ADDR_TYPE_IS_IPV4(def->dst))
      pd->pktbuf_len = def->size - 28;
    else
      pd->pktbuf_len = def->size - 48;
  else
    goto err;

  if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK &&
     (random_u32(&pd->tcp_seq) != 0 || random_u32(&pd->tcp_ack) != 0))
    goto err;

  if(array_insert((void ***)&state->pds, &state->pdc, pd, NULL) != 0)
    {
      printerror(__func__, "could not add pd");
      goto err;
    }

  return 0;

 err:
  if(pd != NULL) free(pd);
  return -1;
}

static void dealias_prefixscan_array_free(scamper_addr_t **addrs, int addrc)
{
  int i;

  if(addrs == NULL)
    return;

  for(i=0; i<addrc; i++)
    if(addrs[i] != NULL)
      scamper_addr_free(addrs[i]);

  free(addrs);
  return;
}

static int dealias_prefixscan_array_add(scamper_dealias_t *dealias,
					scamper_addr_t ***out, int *outc,
					struct in_addr *addr)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_addr_t **array = *out;
  scamper_addr_t *sa;

  /* convert the in_addr into something that scamper deals with */
  sa = scamper_addrcache_get(addrcache, SCAMPER_ADDR_TYPE_IPV4, addr);
  if(sa == NULL)
    {
      printerror(__func__, "could not get addr");
      return -1;
    }

  /*
   * don't consider this address if it is the same as the address
   * we are trying to find an alias for, or it is in the exclude list.
   */
  if(scamper_addr_cmp(prefixscan->a, sa) == 0 ||
     scamper_dealias_prefixscan_xs_in(dealias, sa) != 0)
    {
      scamper_addr_free(sa);
      return 0;
    }

  /* add the scamper address to the array */
  if(array_insert((void ***)&array, outc, sa, NULL) != 0)
    {
      printerror(__func__, "could not add addr");
      scamper_addr_free(sa);
      return -1;
    }

  *out = array;
  return 0;
}

/*
 * dealias_prefixscan_array:
 *
 * figure out what the next address to scan will be, based on what the
 * previously probed address was.  below are examples of the order in which
 * addresses should be probed given a starting address.  addresses in
 * prefixes less than /30 could be probed in random order.
 *
 * 00100111 39        00100010 34        00101001 41       00100000 32
 * 00100110 38 /31    00100001 33        00101010 42       00100001 33 /31
 * 00100101 37        00100000 32        00101000 40       00100010 34
 * 00100100 36 /30    00100011 35 /30    00101011 43 /30   00100011 35 /30
 * 00100011 35        00100100 36        00101100 44
 * 00100010 34        00100101 37        00101101 45
 * 00100001 33        00100110 38        00101110 46
 * 00100000 32 /29    00100111 39 /29    00101111 47 /29
 * 00101000 40        00101000 40        00100000 32
 * 00101001 41        00101001 41        00100001 33
 * 00101010 42        00101010 42
 * 00101011 43
 * 00101100 44
 * 00101101 45
 * 00101110 46
 * 00101111 47 /28
 *
 */
static int dealias_prefixscan_array(scamper_dealias_t *dealias,
				    scamper_addr_t ***out, int *outc)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_addr_t **array = NULL;
  uint32_t hostid, netid, mask;
  uint32_t slash30[4][3] = {{1, 2, 3}, {2, 0, 3}, {1, 0, 3}, {2, 1, 0}};
  uint32_t cnt[] = {4, 8, 16, 32, 64, 128};
  uint32_t bit;
  struct in_addr a;
  int pre, i;

  memcpy(&a, prefixscan->b->addr, sizeof(a));
  *outc = 0;

  /* if we've been instructed only to try /31 pair */
  if(prefixscan->prefix == 31)
    {
      netid  = ntohl(a.s_addr) & ~0x1;
      hostid = ntohl(a.s_addr) &  0x1;

      if(hostid == 1)
	a.s_addr = htonl(netid | 0);
      else
	a.s_addr = htonl(netid | 1);

      if(dealias_prefixscan_array_add(dealias, &array, outc, &a) != 0)
	goto err;

      *out = array;
      return 0;
    }

  /* when probing a /30 the first three probes have a particular order */
  mask   = 0x3;
  netid  = ntohl(a.s_addr) & ~mask;
  hostid = ntohl(a.s_addr) &  mask;
  for(i=0; i<3; i++)
    {
      a.s_addr = htonl(netid | slash30[hostid][i]);
      if(dealias_prefixscan_array_add(dealias, &array, outc, &a) != 0)
	goto err;
    }

  for(pre = 29; pre >= prefixscan->prefix; pre--)
    {
      bit   = (0x1 << (31-pre));
      mask |= bit;

      memcpy(&a, prefixscan->b->addr, sizeof(a));
      netid = ntohl(a.s_addr) & ~mask;

      if((ntohl(a.s_addr) & bit) != 0)
	bit = 0;

      for(hostid=0; hostid<cnt[29-pre]; hostid++)
	{
	  a.s_addr = htonl(netid | bit | hostid);
	  if(dealias_prefixscan_array_add(dealias, &array, outc, &a) != 0)
	    goto err;
	}
    }

  *out = array;
  return 0;

 err:
  dealias_prefixscan_array_free(array, *outc);
  return -1;
}

static scamper_dealias_probe_t *
dealias_probe_udp_find(dealias_state_t *state, dealias_target_t *tgt,
		       uint16_t ipid, uint16_t sport, uint16_t dport)
{
  scamper_dealias_probedef_t *def;
  dealias_probe_t *dp;
  dlist_node_t *n;

  for(n=dlist_head_node(tgt->probes); n != NULL; n = dlist_node_next(n))
    {
      dp = dlist_node_item(n); def = dp->probe->def;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def) == 0 ||
	 def->un.udp.sport != sport)
	continue;
      if(SCAMPER_ADDR_TYPE_IS_IPV4(tgt->addr) && dp->probe->ipid != ipid)
	continue;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP)
	{
	  if(def->un.udp.dport == dport)
	    return dp->probe;
	}
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)
	{
	  if(dp->match_field == dport)
	    return dp->probe;
	}
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_tcp_find2(dealias_state_t *state, dealias_target_t *tgt,
			uint16_t sport, uint16_t dport)
{
  scamper_dealias_probedef_t *def;
  dealias_probe_t *dp;
  dlist_node_t *n;

  for(n=dlist_head_node(tgt->probes); n != NULL; n = dlist_node_next(n))
    {
      dp = dlist_node_item(n); def = dp->probe->def;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def) == 0 ||
	 def->un.tcp.dport != dport)
	continue;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	{
	  if(def->un.tcp.sport == sport)
	    return dp->probe;
	}
      else if(SCAMPER_DEALIAS_PROBEDEF_VARY_TCP_SPORT(def))
	{
	  if(dp->match_field == sport)
	    return dp->probe;
	}
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_tcp_find(dealias_state_t *state, dealias_target_t *tgt,
		       uint16_t ipid, uint16_t sport, uint16_t dport)
{
  scamper_dealias_probedef_t *def;
  dealias_probe_t *dp;
  dlist_node_t *n;

  for(n=dlist_head_node(tgt->probes); n != NULL; n = dlist_node_next(n))
    {
      dp = dlist_node_item(n); def = dp->probe->def;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def) == 0 ||
	 def->un.tcp.dport != dport)
	continue;
      if(SCAMPER_ADDR_TYPE_IS_IPV4(tgt->addr) && dp->probe->ipid != ipid)
	continue;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	{
	  if(def->un.tcp.sport == sport)
	    return dp->probe;
	}
      else if(SCAMPER_DEALIAS_PROBEDEF_VARY_TCP_SPORT(def))
	{
	  if(dp->match_field == sport)
	    return dp->probe;
	}
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_icmp_find(dealias_state_t *state, dealias_target_t *tgt,
			uint16_t ipid, uint8_t type, uint8_t code,
			uint16_t id, uint16_t seq)
{
  scamper_dealias_probedef_t *def;
  dealias_probe_t *dp;
  dlist_node_t *n;
  uint8_t method;

  if((SCAMPER_ADDR_TYPE_IS_IPV4(tgt->addr) &&
      type == ICMP_ECHO && code == 0) ||
     (SCAMPER_ADDR_TYPE_IS_IPV6(tgt->addr) &&
      type == ICMP6_ECHO_REQUEST && code == 0))
    method = SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO;
  else
    return NULL;

  for(n=dlist_head_node(tgt->probes); n != NULL; n = dlist_node_next(n))
    {
      dp = dlist_node_item(n); def = dp->probe->def;
      if(SCAMPER_ADDR_TYPE_IS_IPV4(tgt->addr) && dp->probe->ipid != ipid)
	continue;
      if(def->method == method &&
	 def->un.icmp.id == id && dp->match_field == seq)
	return dp->probe;
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_echoreq_find(dealias_state_t *state, dealias_target_t *tgt,
			   uint16_t id, uint16_t seq)
{
  scamper_dealias_probedef_t *def;
  dealias_probe_t *dp;
  dlist_node_t *n;

  for(n=dlist_head_node(tgt->probes); n != NULL; n = dlist_node_next(n))
    {
      dp = dlist_node_item(n); def = dp->probe->def;
      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO &&
	 def->un.icmp.id == id && dp->match_field == seq)
	return dp->probe;
    }

  return NULL;
}

static dealias_probedef_t *
dealias_mercator_def(scamper_dealias_t *dealias, dealias_state_t *state)
{
  return state->pds[state->probe];
}

static int dealias_mercator_postprobe(scamper_dealias_t *dealias,
				      dealias_state_t *state)
{
  /* we just wait the specified number of seconds with mercator probes */
  scamper_dealias_mercator_t *mercator = dealias->data;
  timeval_add_s(&state->next_tx, &state->last_tx, mercator->wait_timeout);
  state->round++;
  return 0;
}

static void dealias_mercator_handlereply(scamper_task_t *task,
					 scamper_dealias_probe_t *probe,
					 scamper_dealias_reply_t *reply,
					 scamper_dl_rec_t *dl)
{
  if(SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT(reply) &&
     scamper_addr_cmp(probe->def->dst, reply->src) != 0)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
    }
  else
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
    }
  return;
}

static void dealias_mercator_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t          *dealias  = dealias_getdata(task);
  scamper_dealias_mercator_t *mercator = dealias->data;

  if(dealias->probec < mercator->attempts)
    dealias_queue(task);
  else
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);

  return;
}

static dealias_probedef_t *
dealias_ally_def(scamper_dealias_t *dealias, dealias_state_t *state)
{
  return state->pds[state->probe];
}

static int dealias_ally_postprobe(scamper_dealias_t *dealias,
				  dealias_state_t *state)
{
  /*
   * we wait a fixed amount of time before we send the next probe with
   * ally.  except when the last probe has been sent, where we wait for
   * some other length of time for any final replies to come in
   */
  scamper_dealias_ally_t *ally = dealias->data;
  if(dealias->probec != ally->attempts)
    timeval_add_ms(&state->next_tx, &state->last_tx, ally->wait_probe);
  else
    timeval_add_s(&state->next_tx, &state->last_tx, ally->wait_timeout);
  if(++state->probe == 2)
    {
      state->probe = 0;
      state->round++;
    }
  return 0;
}

static int dealias_ally_allzero(scamper_dealias_t *dealias)
{
  uint32_t i;
  uint16_t j;

  if(dealias->probec == 0)
    return 0;
  if(SCAMPER_ADDR_TYPE_IS_IPV4(dealias->probes[0]->def->dst) == 0)
    return 0;

  for(i=0; i<dealias->probec; i++)
    {
      assert(dealias->probes[i] != NULL);
      for(j=0; j<dealias->probes[i]->replyc; j++)
	{
	  assert(dealias->probes[i]->replies[j] != NULL);
	  if(dealias->probes[i]->replies[j]->ipid != 0)
	    return 0;
	}
    }

  return 1;
}

/*
 * dealias_ally_handlereply_v6
 *
 * process the IPv6 response and signal to the caller what to do next.
 *
 * -1: error, stop probing now.
 *  0: response is not useful, don't process the packet.
 *  1: useful response, continue processing.
 */
static int dealias_ally_handlereply_v6(scamper_task_t *task,
				       scamper_dealias_probe_t *probe,
				       scamper_dealias_reply_t *reply,
				       scamper_dl_rec_t *dl)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_probedef_t *pd = state->pds[probe->def->id];
  slist_node_t *sn;
  int ptb = 0, discard = 0;
  uint32_t i;

  /* are we in a period where we're waiting for the receiver to get the PTB? */
  if(state->ptb_tx.tv_sec != 0 || slist_count(state->ptbq) > 0)
    ptb = 1;

  /* is the probe going to be discarded? */
  for(sn=slist_head_node(state->discard); sn != NULL; sn=slist_node_next(sn))
    {
      if(slist_node_item(sn) == probe)
	{
	  discard = 1;
	  break;
	}
    }

  /* if the response contains an IP-ID, then we're good for this def */  
  if((reply->flags & SCAMPER_DEALIAS_REPLY_FLAG_IPID32) != 0)
    {
      pd->flags |= DEALIAS_PROBEDEF_FLAG_RX_IPID;
      return (discard == 0 && ptb == 0) ? 1 : 0;
    }

  /* should we send a packet too big for this packet? */
  if(probe->def->mtu != 0 && probe->def->mtu < dl->dl_ip_size &&
     (pd->flags & DEALIAS_PROBEDEF_FLAG_TX_PTB) == 0 &&
     (pd->flags & DEALIAS_PROBEDEF_FLAG_RX_IPID) == 0)
    {
      /* all prior probes are going to be discarded, so put them in the list */
      for(i=0; i<dealias->probec; i++)
	{
	  if(slist_head_push(state->discard, dealias->probes[i]) == NULL)
	    return -1;
	  dealias->probes[i] = NULL;
	}
      dealias->probec = 0;
      state->round = 0;

      /* send a PTB */
      pd->flags |= DEALIAS_PROBEDEF_FLAG_TX_PTB;
      if(dealias_ptb_add(state, dl, probe->def) != 0)
	return -1;
      dealias_queue(task);
      return 0;
    }

  /* if we're probing for real and the response is not useful, halt */
  if(ptb == 0 && discard == 0)
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);

  return 0;
}

static void dealias_ally_handlereply(scamper_task_t *task,
				     scamper_dealias_probe_t *probe,
				     scamper_dealias_reply_t *reply,
				     scamper_dl_rec_t *dl)
{
  scamper_dealias_t       *dealias = dealias_getdata(task);
  scamper_dealias_ally_t  *ally    = dealias->data;
  scamper_dealias_probe_t *probes[5];
  uint32_t k;
  int rc, probec = 0;

  /* check to see if the response could be useful for alias resolution */
  if(probe->replyc != 1 ||
     !(SCAMPER_DEALIAS_REPLY_FROM_TARGET(probe, reply) ||
       (SCAMPER_DEALIAS_REPLY_IS_ICMP_TTL_EXP(reply) &&
	probe->def->ttl != 255)))
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  if(SCAMPER_ADDR_TYPE_IS_IPV6(reply->src))
    {
      rc = dealias_ally_handlereply_v6(task, probe, reply, dl);
      if(rc == -1) goto err;
      if(rc == 0) return;
    }

  /* can't make any decision unless at least two probes have been sent */
  if(dealias->probec < 2)
    return;

  /* find the probe in its place */
  for(k=0; k<dealias->probec; k++)
    if(probe == dealias->probes[k])
      break;
  if(k == dealias->probec)
    return;

  if(k >= 1 && dealias->probes[k-1]->replyc == 1)
    {
      if(k >= 2 && dealias->probes[k-2]->replyc == 1)
	probes[probec++] = dealias->probes[k-2];
      probes[probec++] = dealias->probes[k-1];
    }
  probes[probec++] = dealias->probes[k];
  if(k+1 < dealias->probec && dealias->probes[k+1]->replyc == 1)
    {
      probes[probec++] = dealias->probes[k+1];
      if(k+2 < dealias->probec && dealias->probes[k+2]->replyc == 1)
	probes[probec++] = dealias->probes[k+2];
    }

  /* not enough adjacent responses to make a classification */
  if(probec < 2)
    return;

  /* check if the replies are in sequence */
  if(SCAMPER_DEALIAS_ALLY_IS_NOBS(dealias))
    rc = scamper_dealias_ipid_inseq(probes, probec, ally->fudge, 0);
  else
    rc = scamper_dealias_ipid_inseq(probes, probec, ally->fudge, 2);
  if(rc == 0)
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NOTALIASES);

  return;

 err:
  dealias_handleerror(task, errno);
  return;
}

static void dealias_ally_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t      *dealias = dealias_getdata(task);
  scamper_dealias_ally_t *ally    = dealias->data;
  uint32_t k;
  int rc;

  /* do a final classification */
  if(dealias->probec == ally->attempts)
    {
      for(k=0; k<dealias->probec; k++)
	if(dealias->probes[k]->replyc != 1)
	  break;

      if(k != dealias->probec)
	{
	  dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
	  return;
	}

      if(SCAMPER_DEALIAS_ALLY_IS_NOBS(dealias))
	rc = scamper_dealias_ipid_inseq(dealias->probes, k, ally->fudge, 0);
      else
	rc = scamper_dealias_ipid_inseq(dealias->probes, k, ally->fudge, 3);

      /* check if the replies are in sequence */
      if(rc == 1)
	dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
      else if(dealias_ally_allzero(dealias) != 0)
	dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      else
	dealias_result(task, SCAMPER_DEALIAS_RESULT_NOTALIASES);
    }

  return;
}

static dealias_probedef_t *
dealias_radargun_def(scamper_dealias_t *dealias, dealias_state_t *state)
{
  scamper_dealias_radargun_t *rg = dealias->data;
  dealias_radargun_t *rgstate = state->methodstate; 
  if((rg->flags & SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE) == 0)
    return state->pds[state->probe];
  return state->pds[rgstate->order[rgstate->i++]];
}

static int dealias_radargun_postprobe(scamper_dealias_t *dealias,
				      dealias_state_t *state)
{
  scamper_dealias_radargun_t *rg = dealias->data;
  dealias_radargun_t *rgstate = state->methodstate;
  struct timeval *tv = &state->last_tx;

  if(state->probe == 0)
    timeval_add_ms(&rgstate->next_round, tv, rg->wait_round);

  state->probe++;

  if(state->probe < rg->probedefc)
    {
      timeval_add_ms(&state->next_tx, tv, rg->wait_probe);
    }
  else
    {
      state->probe = 0;
      state->round++;

      if(state->round < rg->attempts)
	{
	  if(timeval_cmp(tv, &rgstate->next_round) >= 0 ||
	     timeval_diff_ms(&rgstate->next_round, tv) < rg->wait_probe)
	    {
	      timeval_add_ms(&state->next_tx, tv, rg->wait_probe);
	    }
	  else
	    {
	      timeval_cpy(&state->next_tx, &rgstate->next_round);
	    }

	  if((rg->flags & SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE) != 0)
	    {
	      if(shuffle32(rgstate->order, rg->probedefc) != 0)
		return -1;
	      rgstate->i = 0;
	    }
	}
      else
	{
	  /* we're all finished */
	  timeval_add_s(&state->next_tx, tv, rg->wait_timeout);
	}
    }
  return 0;
}

static void dealias_radargun_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t          *dealias  = dealias_getdata(task);
  dealias_state_t            *state    = dealias_getstate(task);
  scamper_dealias_radargun_t *radargun = dealias->data;

  /* check to see if we are now finished */
  if(state->round != radargun->attempts)
    dealias_queue(task);
  else
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);

  return;
}

static void dealias_radargun_handlereply(scamper_task_t *task,
					 scamper_dealias_probe_t *probe,
					 scamper_dealias_reply_t *reply,
					 scamper_dl_rec_t *dl)
{
  dealias_state_t *state = dealias_getstate(task);
  if(SCAMPER_ADDR_TYPE_IS_IPV6(probe->def->dst) &&
     (reply->flags & SCAMPER_DEALIAS_REPLY_FLAG_IPID32) == 0 &&
     probe->def->mtu != 0 && probe->def->mtu < dl->dl_ip_size)
    {
      if(dealias_ptb_add(state, dl, probe->def) != 0)
	dealias_handleerror(task, errno);
      else
	dealias_queue(task);
    }
  return;
}

static dealias_probedef_t *
dealias_prefixscan_def(scamper_dealias_t *dealias, dealias_state_t *state)
{
  return state->pds[state->probe];
}

static int dealias_prefixscan_postprobe(scamper_dealias_t *dealias,
					dealias_state_t *state)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  dealias_prefixscan_t *pfstate = state->methodstate;
  scamper_dealias_probedef_t *def = &state->probedefs[state->probe];

  if(def->id == 0)
    pfstate->round0++;
  else
    pfstate->round++;
  pfstate->attempt++;
  pfstate->replyc = 0;
  timeval_add_ms(&state->next_tx, &state->last_tx, prefixscan->wait_probe);

  return 0;
}

static int dealias_prefixscan_next(scamper_task_t *task)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_prefixscan_t *pfstate = state->methodstate;
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_dealias_probedef_t *def = &pfstate->probedefs[state->probedefc-1];
  uint32_t *defids = NULL, p;
  int q;

  /*
   * if the address we'd otherwise probe has been observed as an alias of
   * prefixscan->a, then we don't need to bother probing it.
   */
  if(array_find((void **)pfstate->aaliases, pfstate->aaliasc, def->dst,
		(array_cmp_t)scamper_addr_cmp) != NULL)
    {
      prefixscan->ab = scamper_addr_use(def->dst);
      prefixscan->flags |= SCAMPER_DEALIAS_PREFIXSCAN_FLAG_CSA;
      dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
      return 0;
    }

  /* remember the probedef used with each probe */
  if((defids = malloc_zero(sizeof(uint32_t) * dealias->probec)) == NULL)
    {
      printerror(__func__, "could not malloc defids");
      goto err;
    }
  for(p=0; p<dealias->probec; p++)
    defids[p] = dealias->probes[p]->def->id;

  /* add the probedef */
  if(scamper_dealias_prefixscan_probedef_add(dealias, def) != 0)
    {
      printerror(__func__, "could not add probedef");
      goto err;
    }

  /* re-set the pointers to the probedefs */
  for(q=0; q<state->pdc; q++)
    state->pds[q]->def = &prefixscan->probedefs[q];
  for(p=0; p<dealias->probec; p++)
    dealias->probes[p]->def = &prefixscan->probedefs[defids[p]];
  free(defids); defids = NULL;

  def = &prefixscan->probedefs[prefixscan->probedefc-1];
  if(dealias_probedef_add(state, def) != 0)
    goto err;

  state->probedefs = prefixscan->probedefs;
  state->probedefc = prefixscan->probedefc;

  return 0;

 err:
  if(defids != NULL) free(defids);
  return -1;
}

static void dealias_prefixscan_handlereply(scamper_task_t *task,
					   scamper_dealias_probe_t *probe,
					   scamper_dealias_reply_t *reply,
					   scamper_dl_rec_t *dl)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  dealias_prefixscan_t *pfstate = state->methodstate;
  scamper_dealias_probe_t **probes = NULL;
  dealias_probedef_t *pd = state->pds[probe->def->id];
  uint32_t defid;
  int p, s, seq;

  /* if the reply is not for the most recently sent probe */
  if(probe != dealias->probes[dealias->probec-1])
    return;

  /* if the reply is not the first reply for this probe */
  if(probe->replyc != 1)
    return;

  if(probe->ipid == reply->ipid && ++pd->echo >= 2)
    {
      if(probe->def->id != 0)
	goto prefixscan_next;
      dealias_result(task, SCAMPER_DEALIAS_RESULT_IPIDECHO);
      return;
    }

  /*
   * if we are currently waiting for our turn to probe, then for now
   * ignore the late response.
   */
  if(scamper_task_queue_isprobe(task))
    return;

  /* check if we should count this reply as a valid response */
  if(SCAMPER_DEALIAS_REPLY_FROM_TARGET(probe, reply))
    pfstate->replyc++;
  else
    return;

  /*
   * if we sent a UDP probe, and got a port unreachable message back from a
   * different interface, then we might be able to use that for alias
   * resolution.
   */
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(probe->def) &&
     SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT(reply) &&
     scamper_addr_cmp(probe->def->dst, reply->src) != 0)
    {
      if(probe->def->id == 0)
	{
	  /*
	   * if the reply is for prefixscan->a, then keep a record of the
	   * address of the interface used in the response.
	   */
	  if(array_find((void **)pfstate->aaliases, pfstate->aaliasc,
			reply->src, (array_cmp_t)scamper_addr_cmp) == NULL)
	    {
	      if(array_insert((void ***)&pfstate->aaliases, &pfstate->aaliasc,
			      reply->src, (array_cmp_t)scamper_addr_cmp) != 0)
		{
		  printerror(__func__, "could not add to aaliases");
		  goto err;
		}
	      scamper_addr_use(reply->src);
	    }
	}
      else
	{
	  /*
	   * if the address used to reply is probedef->a, or is one of the
	   * aliases previously observed for a, then we infer aliases.
	   */
	  if(scamper_addr_cmp(reply->src, prefixscan->a) == 0 ||
	     array_find((void **)pfstate->aaliases, pfstate->aaliasc,
			reply->src, (array_cmp_t)scamper_addr_cmp) != NULL)
	    {
	      prefixscan->ab = scamper_addr_use(probe->def->dst);
	      prefixscan->flags |= SCAMPER_DEALIAS_PREFIXSCAN_FLAG_CSA;
	      dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
	      return;
	    }
	}
    }

  /*
   * another probe received in sequence.
   * we will probably send another probe, so reset attempts
   */
  seq = ++pfstate->seq;
  pfstate->attempt = 0;

  assert(seq >= 1 && seq <= prefixscan->replyc);

  /*
   * if we don't have a reply from each IP address yet, then keep probing.
   * ideally, this could be optimised to use the previous observed IP-ID
   * for probedef zero if we have probed other probedefs in the interim and
   * have just obtained a reply.
   */
  if(seq < 2)
    {
      if(state->probe != 0)
	{
	  state->probe = 0;
	  return;
	}

      if(state->probedefc == 1)
	{
	  /* figure out what we're going to probe next */
	  if(dealias_prefixscan_next(task) != 0)
	    goto err;

	  /* if it turns out we don't need to probe, handle that */
	  if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
	    return;
	}

      state->probe = state->probedefc-1;
      dealias_queue(task);
      return;
    }

  if((probes = malloc_zero(sizeof(scamper_dealias_probe_t *) * seq)) == NULL)
    {
      printerror(__func__, "could not malloc probes");
      goto err;
    }
  probes[seq-1] = probe;

  /* if the reply was not for the first probe, then skip over earlier probes */
  p = dealias->probec-2; defid = probe->def->id;
  while(p >= 0 && dealias->probes[p]->def->id == defid)
    p--;

  for(s=seq-1; s>0; s--)
    {
      if(p < 0)
	goto err;

      if(probes[s]->def->id == 0)
	defid = state->probedefc - 1;
      else
	defid = 0;

      while(p >= 0)
	{
	  assert(defid == dealias->probes[p]->def->id);

	  /* skip over any unresponded to probes */
	  if(dealias->probes[p]->replyc == 0)
	    {
	      p--;
	      continue;
	    }

	  /* record the probe for this defid */
	  probes[s-1] = dealias->probes[p];

	  /* skip over any probes that proceeded this one with same defid */
	  while(p >= 0 && dealias->probes[p]->def->id == defid)
	    p--;

	  break;
	}
    }

  /*
   * check to see if the sequence of replies indicates an alias.  free
   * the probes array before we check the result, as it is easiest here.
   */
  if(SCAMPER_DEALIAS_PREFIXSCAN_IS_NOBS(dealias))
    p = scamper_dealias_ipid_inseq(probes, seq, prefixscan->fudge, 0);
  else
    p = scamper_dealias_ipid_inseq(probes, seq, prefixscan->fudge,
				   seq < prefixscan->replyc ? 2 : 3);
  free(probes); probes = NULL;
  if(p == -1)
    goto err;

  if(p == 1)
    {
      if(seq == prefixscan->replyc)
	{
	  p = state->probedefc-1;
	  prefixscan->ab = scamper_addr_use(prefixscan->probedefs[p].dst);
	  dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
	  return;
	}

      if(state->probe == 0)
	state->probe = state->probedefc - 1;
      else
	state->probe = 0;

      return;
    }

 prefixscan_next:
  /* if there are no other addresses to try, then finish */
  if(state->probedefc-1 == pfstate->probedefc)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  if(dealias_prefixscan_next(task) != 0)
    goto err;
  if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
    return;

  pfstate->round   = 0;
  pfstate->attempt = 0;
  state->probe     = state->probedefc-1;

  if(dealias->probes[dealias->probec-1]->def->id == 0)
    pfstate->seq = 1;
  else
    pfstate->seq = 0;

  dealias_queue(task);
  return;

 err:
  if(probes != NULL) free(probes);
  dealias_handleerror(task, errno);
  return;
}

static void dealias_prefixscan_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_prefixscan_t *pfstate = state->methodstate;
  scamper_dealias_prefixscan_t *prefixscan;
  scamper_dealias_probedef_t *def;
  scamper_dealias_probe_t *probe;

  prefixscan = dealias->data;
  probe = dealias->probes[dealias->probec-1];
  def = probe->def;

  if(pfstate->replyc == 0)
    {
      /* if we're allowed to send another attempt, then do so */
      if(pfstate->attempt < prefixscan->attempts)
	{
	  goto done;
	}

      /*
       * if the probed address is unresponsive, and it is not prefixscan->a,
       * and there are other addresses to try, then probe one now
       */
      if(def->id != 0 && state->probedefc-1 < (uint32_t)pfstate->probedefc)
	{
	  if(dealias_prefixscan_next(task) != 0)
	    goto err;

	  /* if it turns out we don't need to probe, handle that */
	  if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
	    return;

	  pfstate->round   = 0;
	  pfstate->seq     = 0;
	  pfstate->attempt = 0;
	  state->probe     = state->probedefc-1;

	  goto done;
	}

      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  /* keep going! */
 done:
  if(state->probe == 0)
    state->round = pfstate->round0;
  else
    state->round = pfstate->round;

  return;

 err:
  dealias_handleerror(task, errno);
  return;
}

static dealias_probedef_t *
dealias_bump_def(scamper_dealias_t *dealias, dealias_state_t *state)
{
  return state->pds[state->probe];
}

static int dealias_bump_postprobe(scamper_dealias_t *dealias,
				  dealias_state_t *state)
{
  scamper_dealias_bump_t *bump = dealias->data;
  timeval_add_ms(&state->next_tx, &state->last_tx, bump->wait_probe);
  return 0;
}

static void dealias_bump_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t       *dealias = dealias_getdata(task);
  dealias_state_t         *state   = dealias_getstate(task);
  dealias_bump_t          *bs      = state->methodstate;
  scamper_dealias_bump_t  *bump    = dealias->data;
  scamper_dealias_probe_t *probes[3];
  uint32_t i, x, y;

  if(bs->step < 2)
    {
      bs->step++;
    }
  else if(bs->step == 2)
    {
      /* check if the last set of probes are in sequence */
      for(i=0; i<3; i++)
	if(dealias->probes[dealias->probec-3+i]->replyc == 1)
	  probes[i] = dealias->probes[dealias->probec-3+i];
	else
	  break;

      if(i != 3)
	goto none;

      if(scamper_dealias_ipid_inseq(probes, 3, 0, 0) != 1)
	{
	  dealias_result(task, SCAMPER_DEALIAS_RESULT_NOTALIASES);
	  return;
	}

      if(bs->attempt > bump->attempts)
	{
	  dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
	  return;
	}

      x = probes[1]->replies[0]->ipid;
      y = probes[2]->replies[0]->ipid;
      if(x < y)
	i = y - x;
      else
	i = 0x10000 + y - x;

      if(i * 2 > 65535)
	goto none;

      bs->bump = i * 2;
      if(bs->bump == 2)
	bs->bump++;

      if(bs->bump > bump->bump_limit)
	goto none;

      bs->step++;
    }
  else if(bs->step == 3)
    {
      if(bs->bump != 0)
	{
	  bs->bump--;
	  return;
	}

      bs->attempt++;
      bs->step = 1;
    }

  if(state->probe == 1)
    state->probe = 0;
  else
    state->probe = 1;

  return;

 none:
  dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
  return;
}

static void dealias_bump_handlereply(scamper_task_t *task,
				     scamper_dealias_probe_t *probe,
				     scamper_dealias_reply_t *reply,
				     scamper_dl_rec_t *dl)
{
  /* check to see if the response could be useful for alias resolution */
  if(SCAMPER_DEALIAS_REPLY_FROM_TARGET(probe,reply) == 0 || probe->replyc != 1)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  return;
}

static void do_dealias_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  static void (*const func[])(scamper_task_t *, scamper_dealias_probe_t *,
			      scamper_dealias_reply_t *,
			      scamper_dl_rec_t *) = {
    dealias_mercator_handlereply,
    dealias_ally_handlereply,
    dealias_radargun_handlereply,
    dealias_prefixscan_handlereply,
    dealias_bump_handlereply,
  };
  scamper_dealias_probe_t *probe = NULL;
  scamper_dealias_reply_t *reply = NULL;
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_target_t *tgt;
  scamper_addr_t a;
  int v4 = 0;

  /* if we haven't sent a probe yet, then we have nothing to match */
  if(dealias->probec == 0)
    return;

  if(dl->dl_af == AF_INET)
    v4 = 1;
  else if(dl->dl_af != AF_INET6)
    return;

  if(v4 && SCAMPER_DL_IS_TCP(dl))
    {
      if(scamper_dl_rec_src(dl, &a) != 0 ||
	 (tgt = dealias_target_find(state, &a)) == NULL)
	return;
      probe = dealias_probe_tcp_find2(state, tgt, dl->dl_tcp_dport,
				      dl->dl_tcp_sport);
      scamper_dl_rec_tcp_print(dl);
    }
  else if(state->flags & DEALIAS_STATE_FLAG_DL && SCAMPER_DL_IS_ICMP(dl))
    {
      /* if the ICMP type is not something that we care for, then drop it */
      if(SCAMPER_DL_IS_ICMP_TTL_EXP(dl) ||
	 SCAMPER_DL_IS_ICMP_UNREACH(dl) ||
	 SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl))
	{
	  /* the IPID value used is expected to be of the form 0xabab */
	  if(v4 && (dl->dl_icmp_ip_id & 0xff) != (dl->dl_icmp_ip_id >> 8))
	    return;
	  /* get the address to match with */
	  if(scamper_dl_rec_icmp_ip_dst(dl, &a) != 0 ||
	     (tgt = dealias_target_find(state, &a)) == NULL)
	    return;

	  if(dl->dl_icmp_ip_proto == IPPROTO_UDP)
	    probe = dealias_probe_udp_find(state, tgt, dl->dl_icmp_ip_id,
					   dl->dl_icmp_udp_sport,
					   dl->dl_icmp_udp_dport);
	  else if(dl->dl_icmp_ip_proto == IPPROTO_ICMP ||
		  dl->dl_icmp_ip_proto == IPPROTO_ICMPV6)
	    probe = dealias_probe_icmp_find(state, tgt, dl->dl_icmp_ip_id,
					    dl->dl_icmp_icmp_type,
					    dl->dl_icmp_icmp_code,
					    dl->dl_icmp_icmp_id,
					    dl->dl_icmp_icmp_seq);
	  else if(dl->dl_icmp_ip_proto == IPPROTO_TCP)
	    probe = dealias_probe_tcp_find(state, tgt, dl->dl_icmp_ip_id,
					   dl->dl_icmp_tcp_sport,
					   dl->dl_icmp_tcp_dport);
	}
      else if(SCAMPER_DL_IS_ICMP_ECHO_REPLY(dl) != 0)
	{
	  if(scamper_dl_rec_src(dl, &a) != 0 ||
	     (tgt = dealias_target_find(state, &a)) == NULL)
	    return;
	  probe = dealias_probe_echoreq_find(state, tgt,
					     dl->dl_icmp_id, dl->dl_icmp_seq);
	}
      else return;

      scamper_dl_rec_icmp_print(dl);
    }

  if(probe == NULL || scamper_dl_rec_src(dl, &a) != 0)
    return;

  if((reply = scamper_dealias_reply_alloc()) == NULL)
    {
      scamper_debug(__func__, "could not alloc reply");
      goto err;
    }

  if(scamper_addr_cmp(&a, probe->def->dst) == 0)
    {
      reply->src = scamper_addr_use(probe->def->dst);
    }
  else if((reply->src=scamper_addrcache_get(addrcache,a.type,a.addr)) == NULL)
    {
      scamper_debug(__func__, "could not get address from cache");
      goto err;
    }
  timeval_cpy(&reply->rx, &dl->dl_tv);
  reply->ttl       = dl->dl_ip_ttl;
  reply->proto     = dl->dl_ip_proto;

  if(v4)
    {
      reply->ipid = dl->dl_ip_id;
    }
  else if(SCAMPER_DL_IS_IP_FRAG(dl))
    {
      reply->flags |= SCAMPER_DEALIAS_REPLY_FLAG_IPID32;
      reply->ipid32 = dl->dl_ip6_id;
    }

  if(SCAMPER_DL_IS_TCP(dl))
    {
      reply->tcp_flags = dl->dl_tcp_flags;
    }
  else
    {
      reply->icmp_type = dl->dl_icmp_type;
      reply->icmp_code = dl->dl_icmp_code;
      reply->icmp_q_ip_ttl = dl->dl_icmp_ip_ttl;
    }

  if(scamper_dealias_reply_add(probe, reply) != 0)
    {
      scamper_debug(__func__, "could not add reply to probe");
      goto err;
    }

  if(func[dealias->method-1] != NULL)
    func[dealias->method-1](task, probe, reply, dl);

  return;

 err:
  if(reply != NULL) scamper_dealias_reply_free(reply);
  dealias_handleerror(task, errno);
  return;
}

static void do_dealias_handle_icmp(scamper_task_t *task,scamper_icmp_resp_t *ir)
{
  static void (*const func[])(scamper_task_t *, scamper_dealias_probe_t *,
			      scamper_dealias_reply_t *,
			      scamper_dl_rec_t *) = {
    dealias_mercator_handlereply,
    dealias_ally_handlereply,
    NULL, /* radargun */
    dealias_prefixscan_handlereply,
    dealias_bump_handlereply,
  };
  scamper_dealias_probe_t *probe = NULL;
  scamper_dealias_reply_t *reply = NULL;
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_target_t *tgt;
  scamper_addr_t a;

  /* if we haven't sent a probe yet, then we have nothing to match */
  if(dealias->probec == 0)
    return;

  /* are we handling all responses using datalink sockets? */
  if((state->flags & DEALIAS_STATE_FLAG_DL) != 0)
    return;

  /* if the ICMP type is not something that we care for, then drop it */
  if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) ||
     SCAMPER_ICMP_RESP_IS_UNREACH(ir) ||
     SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir))
    {
      if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir) == 0 || ir->ir_inner_ip_off != 0)
	return;

      /* the IPID value used is expected to be of the form 0xabab */
      if(ir->ir_af == AF_INET &&
	 (ir->ir_inner_ip_id & 0xff) != (ir->ir_inner_ip_id >> 8))
	return;

      if(scamper_icmp_resp_inner_dst(ir, &a) != 0 ||
	 (tgt = dealias_target_find(state, &a)) == NULL)
	return;

      if(ir->ir_inner_ip_proto == IPPROTO_UDP)
	probe = dealias_probe_udp_find(state, tgt, ir->ir_inner_ip_id,
				       ir->ir_inner_udp_sport,
				       ir->ir_inner_udp_dport);
      else if(ir->ir_inner_ip_proto == IPPROTO_ICMP ||
	      ir->ir_inner_ip_proto == IPPROTO_ICMPV6)
	probe = dealias_probe_icmp_find(state, tgt, ir->ir_inner_ip_id,
					ir->ir_inner_icmp_type,
					ir->ir_inner_icmp_code,
					ir->ir_inner_icmp_id,
					ir->ir_inner_icmp_seq);
      else if(ir->ir_inner_ip_proto == IPPROTO_TCP)
	probe = dealias_probe_tcp_find(state, tgt, ir->ir_inner_ip_id,
				       ir->ir_inner_tcp_sport,
				       ir->ir_inner_tcp_dport);

      if(scamper_icmp_resp_src(ir, &a) != 0)
	return;
    }
  else if(SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir) != 0)
    {
      if(scamper_icmp_resp_src(ir, &a) != 0 ||
	 (tgt = dealias_target_find(state, &a)) == NULL)
	return;
      probe = dealias_probe_echoreq_find(state, tgt,
					 ir->ir_icmp_id, ir->ir_icmp_seq);
    }

  if(probe == NULL)
    return;

  scamper_icmp_resp_print(ir);

  if((reply = scamper_dealias_reply_alloc()) == NULL)
    {
      scamper_debug(__func__, "could not alloc reply");
      goto err;
    }
  if(scamper_addr_cmp(&a, probe->def->dst) == 0)
    {
      reply->src = scamper_addr_use(probe->def->dst);
    }
  else if((reply->src=scamper_addrcache_get(addrcache,a.type,a.addr)) == NULL)
    {
      scamper_debug(__func__, "could not get address from cache");
      goto err;
    }
  timeval_cpy(&reply->rx, &ir->ir_rx);
  reply->ttl           = (uint8_t)ir->ir_ip_ttl;
  reply->icmp_type     = ir->ir_icmp_type;
  reply->icmp_code     = ir->ir_icmp_code;
  reply->icmp_q_ip_ttl = ir->ir_inner_ip_ttl;

  if(ir->ir_af == AF_INET)
    {
      reply->ipid  = ir->ir_ip_id;
      reply->proto = IPPROTO_ICMP;
    }
  else
    {
      reply->proto = IPPROTO_ICMPV6;
    }

  if(scamper_dealias_reply_add(probe, reply) != 0)
    {
      scamper_debug(__func__, "could not add reply to probe");
      goto err;
    }

  if(func[dealias->method-1] != NULL)
    func[dealias->method-1](task, probe, reply, NULL);
  return;

 err:
  if(reply != NULL) scamper_dealias_reply_free(reply);
  dealias_handleerror(task, errno);
  return;
}

static void do_dealias_handle_timeout(scamper_task_t *task)
{
  static void (*const func[])(scamper_task_t *) = {
    dealias_mercator_handletimeout,
    dealias_ally_handletimeout,
    dealias_radargun_handletimeout,
    dealias_prefixscan_handletimeout,
    dealias_bump_handletimeout,
  };
  scamper_dealias_t *dealias = dealias_getdata(task);
  func[dealias->method-1](task);
  return;
}

/*
 * dealias_state_probe
 *
 * record the fact that a probe was sent
 */
static int dealias_state_probe(dealias_state_t *state,
			       dealias_probedef_t *pdef,
			       scamper_dealias_probe_t *probe,
			       scamper_probe_t *pr)
{
  dealias_probe_t *dp = NULL;

  /* allocate a structure to record this probe's details */
  if((dp = malloc_zero(sizeof(dealias_probe_t))) == NULL)
    {
      printerror(__func__, "could not malloc dealias_probe_t");
      goto err;
    }
  if(pdef->def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)
    dp->match_field = pr->pr_udp_dport;
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(pdef->def))
    dp->match_field = pr->pr_icmp_seq;
  else if(SCAMPER_DEALIAS_PROBEDEF_VARY_TCP_SPORT(pdef->def))
    dp->match_field = pr->pr_tcp_sport;

  dp->probe = probe;
  dp->target = pdef->target;

  if((dp->target_node = dlist_head_push(dp->target->probes, dp)) == NULL ||
     dlist_tail_push(state->recent_probes, dp) == NULL)
    {
      printerror(__func__, "could not push to lists");
      goto err;
    }

  return 0;

 err:
  if(dp != NULL) free(dp);
  return -1;
}

static void dealias_prefixscan_free(void *data)
{
  dealias_prefixscan_t *pfstate = data;
  int j;

  if(pfstate->probedefs != NULL)
    {
      for(j=0; j<pfstate->probedefc; j++)
	{
	  if(pfstate->probedefs[j].src != NULL)
	    scamper_addr_free(pfstate->probedefs[j].src);
	  if(pfstate->probedefs[j].dst != NULL)
	    scamper_addr_free(pfstate->probedefs[j].dst);
	}
      free(pfstate->probedefs);
    }
  if(pfstate->aaliases != NULL)
    {
      for(j=0; j<pfstate->aaliasc; j++)
	if(pfstate->aaliases[j] != NULL)
	  scamper_addr_free(pfstate->aaliases[j]);
      free(pfstate->aaliases);
    }
  free(pfstate);

  return;
}

static int dealias_prefixscan_alloc(scamper_dealias_t *dealias,
				    dealias_state_t *state)
{
  scamper_dealias_prefixscan_t *pfxscan = dealias->data;
  scamper_dealias_probedef_t pd;
  dealias_prefixscan_t *pfstate = NULL;
  scamper_addr_t      **addrs = NULL;
  int                   i, addrc = 0;

  /* figure out the addresses that will be probed */
  if(dealias_prefixscan_array(dealias, &addrs, &addrc) != 0)
    goto err;

  if((pfstate = malloc_zero(sizeof(dealias_prefixscan_t))) == NULL)
    {
      printerror(__func__, "could not malloc pfstate");
      goto err;
    }
  state->methodstate = pfstate;

  pfstate->probedefs = malloc_zero(addrc * sizeof(scamper_dealias_probedef_t));
  if(pfstate->probedefs == NULL)
    {
      printerror(__func__, "could not malloc probedefs");
      goto err;
    }
  pfstate->probedefc = addrc;

  for(i=0; i<addrc; i++)
    {
      memcpy(&pd, &pfxscan->probedefs[0], sizeof(pd));
      pd.dst = scamper_addr_use(addrs[i]);
      pd.src = scamper_getsrc(pd.dst, 0);
      memcpy(&pfstate->probedefs[i], &pd, sizeof(pd));
    }

  dealias_prefixscan_array_free(addrs, addrc);
  return 0;

 err:
  if(addrs != NULL) dealias_prefixscan_array_free(addrs, addrc);
  return -1;
}

static void dealias_radargun_free(void *data)
{
  dealias_radargun_t *rgstate = data;
  if(rgstate->order != NULL)
    free(rgstate->order);
  free(rgstate);
  return;
}

static int dealias_radargun_alloc(scamper_dealias_radargun_t *rg,
				  dealias_state_t *state)
{
  dealias_radargun_t *rgstate = NULL;
  uint32_t i;
  size_t size;

  if((rgstate = malloc_zero(sizeof(dealias_radargun_t))) == NULL)
    {
      printerror(__func__, "could not malloc rgstate");
      return -1;
    }
  state->methodstate = rgstate;

  /* if the probe order is to be shuffled, then shuffle it */
  if((rg->flags & SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE))
    {
      size = sizeof(uint32_t) * rg->probedefc;
      if((rgstate->order = malloc_zero(size)) == NULL)
	{
	  printerror(__func__, "could not malloc order");
	  return -1;
	}
      for(i=0; i<rg->probedefc; i++)
	rgstate->order[i] = i;
      if(shuffle32(rgstate->order, rg->probedefc) != 0)
	return -1;
    }

  return 0;
}

static int dealias_bump_alloc(dealias_state_t *state)
{
  dealias_bump_t *bstate = NULL;
  if((bstate = malloc_zero(sizeof(dealias_bump_t))) == NULL)
    {
      printerror(__func__, "could not malloc bstate");
      return -1;
    }
  state->methodstate = bstate;
  return 0;
}

static void dealias_bump_free(void *data)
{
  free(data);
  return;
}

static void dealias_state_free(scamper_dealias_t *dealias,
			       dealias_state_t *state)
{
  int j;

  if(state == NULL)
    return;

  if(state->recent_probes != NULL)
    dlist_free(state->recent_probes);

  if(state->methodstate != NULL)
    {
      if(SCAMPER_DEALIAS_METHOD_IS_PREFIXSCAN(dealias))
	dealias_prefixscan_free(state->methodstate);
      else if(SCAMPER_DEALIAS_METHOD_IS_RADARGUN(dealias))
	dealias_radargun_free(state->methodstate);
      else if(SCAMPER_DEALIAS_METHOD_IS_BUMP(dealias))
	dealias_bump_free(state->methodstate);
    }

  if(state->targets != NULL)
    splaytree_free(state->targets, (splaytree_free_t)dealias_target_free);

  if(state->pds != NULL)
    {
      for(j=0; j<state->pdc; j++)
	if(state->pds[j] != NULL)
	  free(state->pds[j]);
      free(state->pds);
    }

  if(state->ptbq != NULL)
    slist_free_cb(state->ptbq, (slist_free_t)dealias_ptb_free);

  if(state->discard != NULL)
    slist_free_cb(state->discard, (slist_free_t)scamper_dealias_probe_free);

  free(state);
  return;
}

static void do_dealias_probe(scamper_task_t *task)
{
  static int (*const postprobe_func[])(scamper_dealias_t *,
				       dealias_state_t *) = {
    dealias_mercator_postprobe,
    dealias_ally_postprobe,
    dealias_radargun_postprobe,
    dealias_prefixscan_postprobe,
    dealias_bump_postprobe,
  };
  static dealias_probedef_t *(*const def_func[])(scamper_dealias_t *,
						 dealias_state_t *) = {
    dealias_mercator_def,
    dealias_ally_def,
    dealias_radargun_def,
    dealias_prefixscan_def,
    dealias_bump_def,
  };
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_probedef_t *pdef;
  scamper_dealias_probedef_t *def;
  scamper_dealias_probe_t *dp = NULL;
  scamper_probe_t probe;
  dealias_ptb_t *ptb = NULL;
  uint16_t u16;

  if(dealias->probec == 0)
    gettimeofday_wrap(&dealias->start);
 
  memset(&probe, 0, sizeof(probe));
  if((state->flags & DEALIAS_STATE_FLAG_DL) != 0)
    probe.pr_flags |= SCAMPER_PROBE_FLAG_DL;

  if(slist_count(state->ptbq) > 0)
    {
      ptb = slist_head_pop(state->ptbq); def = ptb->def;
      probe.pr_ip_src = def->src;
      probe.pr_ip_dst = def->dst;      
      probe.pr_ip_ttl = 255;
      SCAMPER_PROBE_ICMP_PTB(&probe, def->mtu);
      probe.pr_data   = ptb->quote;
      probe.pr_len    = ptb->quote_len;
      if(scamper_probe_task(&probe, task) != 0)
	{
	  errno = probe.pr_errno;
	  goto err;
	}
      timeval_cpy(&state->ptb_tx, &probe.pr_tx);
      dealias_ptb_free(ptb);
      dealias_queue(task);
      return;
    }

  if((pdef = def_func[dealias->method-1](dealias, state)) == NULL)
    goto err;
  def = pdef->def;

  if(pktbuf_len < state->pds[def->id]->pktbuf_len)
    {
      if(realloc_wrap((void **)&pktbuf, state->pds[def->id]->pktbuf_len) != 0)
	{
	  printerror(__func__, "could not realloc pktbuf");
	  goto err;
	}
      pktbuf_len = state->pds[def->id]->pktbuf_len;
    }

  probe.pr_ip_src    = def->src;
  probe.pr_ip_dst    = def->dst;
  probe.pr_ip_ttl    = def->ttl;
  probe.pr_ip_tos    = def->tos;
  probe.pr_data      = pktbuf;
  probe.pr_len       = state->pds[def->id]->pktbuf_len;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(def->dst))
    {
      probe.pr_flags |= SCAMPER_PROBE_FLAG_IPID;
      probe.pr_ip_id  = state->id << 8 | state->id;
      probe.pr_ip_off = IP_DF;
    }

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    {
      probe.pr_ip_proto  = IPPROTO_UDP;
      probe.pr_udp_sport = def->un.udp.sport;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP)
	probe.pr_udp_dport = def->un.udp.dport;
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)
	probe.pr_udp_dport = def->un.udp.dport + pdef->target->udp_dport++;
      else
	goto err;

      /* hack to get the udp csum to be a particular value, and be valid */
      u16 = htons(dealias->probec + 1);
      memcpy(probe.pr_data, &u16, 2);
      u16 = scamper_udp4_cksum(&probe);
      memcpy(probe.pr_data, &u16, 2);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def))
    {
      SCAMPER_PROBE_ICMP_ECHO(&probe, def->un.icmp.id, state->icmpseq++);

      /* hack to get the icmp csum to be a particular value, and be valid */
      u16 = htons(def->un.icmp.csum);
      memcpy(probe.pr_data, &u16, 2);
      u16 = scamper_icmp4_cksum(&probe);
      memcpy(probe.pr_data, &u16, 2);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    {
      probe.pr_ip_proto  = IPPROTO_TCP;
      probe.pr_tcp_dport = def->un.tcp.dport;
      probe.pr_tcp_flags = def->un.tcp.flags;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	{
	  probe.pr_tcp_sport = def->un.tcp.sport;
	  probe.pr_tcp_seq   = state->pds[def->id]->tcp_seq;
	  probe.pr_tcp_ack   = state->pds[def->id]->tcp_ack;
	}
      else if(SCAMPER_DEALIAS_PROBEDEF_VARY_TCP_SPORT(def))
	{
	  probe.pr_tcp_sport = def->un.tcp.sport + pdef->target->tcp_sport++;
	  if(random_u32(&probe.pr_tcp_seq) != 0 ||
	     random_u32(&probe.pr_tcp_ack) != 0)
	    goto err;
	}
      else goto err;
    }

  /*
   * allocate a probe record before we try and send the probe as there is no
   * point sending something into the wild that we can't record
   */
  if((dp = scamper_dealias_probe_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc probe");
      goto err;
    }
  dp->def = def;
  dp->ipid = probe.pr_ip_id;
  dp->seq = state->round;

  if(dealias_state_probe(state, pdef, dp, &probe) != 0)
    goto err;

  /* send the probe */
  if(scamper_probe_task(&probe, task) != 0)
    {
      errno = probe.pr_errno;
      goto err;
    }

  /* record details of the probe in the scamper_dealias_t data structures */
  timeval_cpy(&dp->tx, &probe.pr_tx);
  if(scamper_dealias_probe_add(dealias, dp) != 0)
    {
      scamper_debug(__func__, "could not add probe to dealias data");
      goto err;
    }

  /* figure out how long to wait until sending the next probe */
  timeval_cpy(&state->last_tx, &probe.pr_tx);
  if(postprobe_func[dealias->method-1](dealias, state) != 0)
    goto err;

  assert(state->id != 0);
  if(--state->id == 0)
    state->id = 255;

  dealias_queue(task);
  return;

 err:
  if(ptb != NULL) dealias_ptb_free(ptb);
  dealias_handleerror(task, errno);
  return;
}

static void do_dealias_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_file_write_dealias(sf, dealias_getdata(task));
  return;
}

static void do_dealias_halt(scamper_task_t *task)
{
  dealias_result(task, SCAMPER_DEALIAS_RESULT_HALTED);
  return;
}

static void do_dealias_free(scamper_task_t *task)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);

  if(state != NULL)
    dealias_state_free(dealias, state);

  if(dealias != NULL)
    scamper_dealias_free(dealias);

  return;
}

static int dealias_arg_param_validate(int optid, char *param, long long *out)
{
  long tmp;

  switch(optid)
    {
    case DEALIAS_OPT_OPTION:
    case DEALIAS_OPT_PROBEDEF:
    case DEALIAS_OPT_EXCLUDE:
      tmp = 0;
      break;

    case DEALIAS_OPT_DPORT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_FUDGE:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_METHOD:
      if(strcasecmp(param, "mercator") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_MERCATOR;
      else if(strcasecmp(param, "ally") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_ALLY;
      else if(strcasecmp(param, "radargun") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_RADARGUN;
      else if(strcasecmp(param, "prefixscan") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_PREFIXSCAN;
      else if(strcasecmp(param, "bump") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_BUMP;
      else
	return -1;
      break;

    case DEALIAS_OPT_ATTEMPTS:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 500)
	return -1;
      break;

    case DEALIAS_OPT_SPORT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_TTL:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 255)
	return -1;
      break;

    case DEALIAS_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	return -1;
      break;

    case DEALIAS_OPT_WAIT_TIMEOUT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 255)
	return -1;
      break;

    case DEALIAS_OPT_WAIT_PROBE:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_WAIT_ROUND:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 180000)
	return -1;
      break;

    case DEALIAS_OPT_REPLYC:
      if(string_tolong(param, &tmp) != 0 || tmp < 3 || tmp > 255)
	return -1;
      break;

    default:
      scamper_debug(__func__, "unhandled optid %d", optid);
      return -1;
    }

  if(out != NULL)
    *out = (long long)tmp;
  return 0;
}

static int dealias_probedef_args(scamper_dealias_probedef_t *def, char *str)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  uint16_t dport = 33435;
  uint16_t sport = scamper_sport_default();
  uint16_t csum  = 0;
  uint16_t opts  = 0;
  uint8_t  ttl   = 255;
  uint8_t  tos   = 0;
  uint16_t size  = 0;
  uint16_t mtu   = 0;
  char *end;
  long tmp;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, probedef_opts, probedef_opts_cnt,
			   &opts_out, &end) != 0)
    {
      scamper_debug(__func__, "could not parse options");
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      /* check for an option being used multiple times */
      if(opts & (1<<(opt->id-1)))
	{
	  scamper_debug(__func__,"option %d specified multiple times",opt->id);
	  goto err;
	}

      opts |= (1 << (opt->id-1));

      switch(opt->id)
	{
	case DEALIAS_PROBEDEF_OPT_CSUM:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 0 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid csum %s", opt->str);
	      goto err;
	    }
	  csum = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_DPORT:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid dport %s", opt->str);
	      goto err;
	    }
	  dport = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_IP:
	  def->dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, opt->str);
	  if(def->dst == NULL)
	    {
	      scamper_debug(__func__, "invalid dst ip %s", opt->str);
	      goto err;
	    }
	  break;

	case DEALIAS_PROBEDEF_OPT_MTU:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 100 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid mtu size %s", opt->str);
	      goto err;
	    }
	  mtu = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_PROTO:
	  if(strcasecmp(opt->str, "udp") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
	  else if(strcasecmp(opt->str, "tcp-ack") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK;
	  else if(strcasecmp(opt->str, "icmp-echo") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO;
	  else if(strcasecmp(opt->str, "tcp-ack-sport") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT;
	  else if(strcasecmp(opt->str, "udp-dport") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT;
	  else if(strcasecmp(opt->str, "tcp-syn-sport") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_SYN_SPORT;
	  else
	    {
	      scamper_debug(__func__, "invalid probe type %s", opt->str);
	      goto err;
	    }
	  break;

	case DEALIAS_PROBEDEF_OPT_SIZE:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 100 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid probe size %s", opt->str);
	      goto err;
	    }
	  size = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_SPORT:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid sport %s", opt->str);
	      goto err;
	    }
	  sport = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_TTL:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 255)
	    {
	      scamper_debug(__func__, "invalid ttl %s", opt->str);
	      goto err;
	    }
	  ttl = (uint8_t)tmp;
	  break;

	default:
	  scamper_debug(__func__, "unhandled optid %d", opt->id);
	  goto err;
	}
    }

  scamper_options_free(opts_out); opts_out = NULL;

  /*
   * if there is something at the end of the option string, then this
   * probedef is not valid
   */
  if(end != NULL)
    {
      scamper_debug(__func__, "invalid option string");
      goto err;
    }

  /* record the ttl, tos, size */
  def->ttl  = ttl;
  def->tos  = tos;
  def->size = size;
  def->mtu  = mtu;

  /* if no protocol type is defined, choose UDP */
  if((opts & (1<<(DEALIAS_PROBEDEF_OPT_PROTO-1))) == 0)
    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    {
      /* don't provide the choice of the checksum value in a UDP probe */
      if(opts & (1<<(DEALIAS_PROBEDEF_OPT_CSUM-1)))
	{
	  scamper_debug(__func__, "csum option not permitted for udp");
	  goto err;
	}

      def->un.udp.dport = dport;
      def->un.udp.sport = sport;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def))
    {
      /* ICMP probes don't have source or destination ports */
      if(opts & (1<<(DEALIAS_PROBEDEF_OPT_SPORT-1)))
	{
	  scamper_debug(__func__, "sport option not permitted for icmp");
	  goto err;
	}
      if(opts & (1<<(DEALIAS_PROBEDEF_OPT_DPORT-1)))
	{
	  scamper_debug(__func__, "dport option not permitted for icmp");
	  goto err;
	}
      def->un.icmp.csum = csum;
      def->un.icmp.id   = scamper_sport_default();
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    {
      /* don't provide the choice of the checksum value in a TCP probe */
      if(opts & (1<<(DEALIAS_PROBEDEF_OPT_CSUM-1)))
	{
	  scamper_debug(__func__, "csum option not permitted for tcp");
	  goto err;
	}

      def->un.tcp.dport = dport;
      def->un.tcp.sport = sport;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP_ACK(def))
	def->un.tcp.flags = TH_ACK;
      else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP_SYN(def))
	def->un.tcp.flags = TH_SYN;
      else
	{
	  scamper_debug(__func__,"unhandled flags for method %d",def->method);
	  goto err;
	}
    }
  else
    {
      scamper_debug(__func__, "unhandled method %d", def->method);
      goto err;
    }

  return 0;

 err:
  if(opts_out != NULL) scamper_options_free(opts_out);
  if(def->dst != NULL) scamper_addr_free(def->dst);
  return -1;
}

static int dealias_alloc_mercator(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_mercator_t *mercator;
  scamper_addr_t *dst = NULL;

  /* if there is no IP address after the options string, then stop now */
  if(o->addr == NULL)
    {
      scamper_debug(__func__, "missing target address for mercator");
      goto err;
    }
  if((dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, o->addr)) == NULL)
    {
      scamper_debug(__func__, "unable to resolve address for mercator");
      goto err;
    }

  if(o->probedefs != NULL || o->xs != NULL || o->wait_probe != 0 ||
     o->fudge != 0 || o->attempts > 3 || o->nobs != 0 || o->replyc != 0 ||
     o->shuffle != 0 || o->inseq != 0)
    {
      scamper_debug(__func__, "invalid parameters for mercator");
      goto err;
    }
  if(o->attempts == 0) o->attempts = 3;
  if(o->dport == 0)    o->dport    = 33435;
  if(o->sport == 0)    o->sport    = scamper_sport_default();
  if(o->ttl == 0)      o->ttl      = 255;

  if(scamper_dealias_mercator_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc mercator structure");
      goto err;
    }
  mercator = d->data;
  mercator->attempts              = o->attempts;
  mercator->wait_timeout          = o->wait_timeout;
  mercator->probedef.id           = 0;
  mercator->probedef.dst          = dst; dst = NULL;
  mercator->probedef.ttl          = o->ttl;
  mercator->probedef.method       = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
  mercator->probedef.un.udp.sport = o->sport;
  mercator->probedef.un.udp.dport = o->dport;

  return 0;

 err:
  if(dst != NULL) scamper_addr_free(dst);
  return -1;
}

static int dealias_alloc_ally(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_ally_t *ally = NULL;
  scamper_dealias_probedef_t pd[2];
  int i, probedefc = 0;
  slist_node_t *sn;
  uint8_t flags = 0;
  char *addr2;

  memset(&pd, 0, sizeof(pd));
  
  if(o->probedefs != NULL)
    probedefc = slist_count(o->probedefs);

  if(probedefc > 2 || o->xs != NULL || o->dport != 0 || o->sport != 0 ||
     o->ttl != 0 || o->replyc != 0 || o->shuffle != 0 ||
     (o->inseq != 0 && o->fudge != 0))
    {
      scamper_debug(__func__, "invalid parameters for ally");
      goto err;
    }

  if(o->wait_probe == 0) o->wait_probe = 150;
  if(o->attempts == 0)   o->attempts   = 5;

  if(o->fudge == 0 && o->inseq == 0)
    o->fudge = 200;

  if(probedefc > 0)
    {
      i = 0;
      for(sn=slist_head_node(o->probedefs); sn != NULL; sn=slist_node_next(sn))
	{
	  if(dealias_probedef_args(&pd[i], (char *)slist_node_item(sn)) != 0)
	    {
	      scamper_debug(__func__, "could not read ally probedef %d", i);
	      goto err;
	    }
	  i++;
	}
    }

  if(probedefc == 0)
    {
      for(i=0; i<2; i++)
	{
	  pd[i].ttl          = 255;
	  pd[i].method       = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
	  pd[i].un.udp.sport = scamper_sport_default();
	  pd[i].un.udp.dport = 33435;
	}
    }
  else if(probedefc == 1)
    {
      if(pd[0].dst != NULL || o->addr == NULL)
	{
	  scamper_debug(__func__, "dst IP specified incorrectly");
	  goto err;
	}
      memcpy(&pd[1], &pd[0], sizeof(scamper_dealias_probedef_t));
    }

  if(o->addr == NULL)
    {
      if(pd[0].dst == NULL || pd[1].dst == NULL)
	{
	  scamper_debug(__func__, "missing destination IP address");
	  goto err;
	}
    }
  else
    {
      if(pd[0].dst != NULL || pd[1].dst != NULL)
	{
	  scamper_debug(__func__, "dst IP specified inconsistently");
	  goto err;
	}

      /* make sure there are two addresses specified */
      if((addr2 = string_nextword(o->addr)) == NULL)
	{
	  scamper_debug(__func__, "missing second address");
	  goto err;
	}

      /* resolve each address */
      pd[0].dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, o->addr);
      if(pd[0].dst == NULL)
	{
	  printerror(__func__, "could not resolve %s", o->addr);
	  goto err;
	}
      pd[1].dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, addr2);
      if(pd[1].dst == NULL)
	{
	  printerror(__func__, "could not resolve %s", addr2);
	  goto err;
	}
    }

  if(pd[0].dst->type != pd[1].dst->type ||
     SCAMPER_ADDR_TYPE_IS_IP(pd[0].dst) == 0 ||
     SCAMPER_ADDR_TYPE_IS_IP(pd[1].dst) == 0)
    {
      scamper_debug(__func__, "dst IP specified incorrectly");
      goto err;
    }

  if(o->nobs != 0 || SCAMPER_ADDR_TYPE_IS_IPV6(pd[0].dst))
    flags |= SCAMPER_DEALIAS_ALLY_FLAG_NOBS;

  if(scamper_dealias_ally_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc ally structure");
      goto err;
    }
  ally = d->data;

  ally->attempts     = o->attempts;
  ally->wait_probe   = o->wait_probe;
  ally->wait_timeout = o->wait_timeout;
  ally->fudge        = o->fudge;
  ally->flags        = flags;

  for(i=0; i<2; i++)
    pd[i].id = i;

  memcpy(ally->probedefs, pd, sizeof(ally->probedefs));

  return 0;

 err:
  if(pd[0].dst != NULL) scamper_addr_free(pd[0].dst);
  if(pd[1].dst != NULL) scamper_addr_free(pd[1].dst);
  return -1;
}

static int dealias_alloc_radargun(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_radargun_t *rg;
  scamper_dealias_probedef_t *pd = NULL, pd0;
  slist_t *pd_list = NULL;
  slist_node_t *sn;
  uint32_t i, probedefc;
  uint8_t flags = 0;
  char *a1, *a2;
  int j, pdc = 0;

  memset(&pd0, 0, sizeof(pd0));

  if(o->xs != NULL || o->dport != 0 || o->sport != 0 ||
     o->ttl != 0 || o->nobs != 0 || o->replyc != 0 || o->inseq != 0)
    {
      scamper_debug(__func__, "invalid parameters for radargun");
      goto err;
    }

  if(o->probedefs != NULL)
    pdc = slist_count(o->probedefs);
  if(o->wait_probe == 0) o->wait_probe   = 150;
  if(o->attempts == 0)   o->attempts     = 30;
  if(o->wait_round == 0) o->wait_round   = pdc * o->wait_probe;
  if(o->shuffle != 0)
    flags |= SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE;

  if(pdc == 0)
    {
      pd0.ttl          = 255;
      pd0.method       = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
      pd0.un.udp.sport = scamper_sport_default();
      pd0.un.udp.dport = 33435;
    }
  else if(pdc == 1)
    {
      if(dealias_probedef_args(&pd0, (char *)slist_head_item(o->probedefs))!=0)
	{
	  scamper_debug(__func__, "could not parse radargun probedef 0");
	  goto err;
	}
      if(pd0.dst != NULL || o->addr == NULL)
	{
	  scamper_debug(__func__, "dst addrs are specified after def");
	  goto err;
	}
    }

  if(pdc >= 2 && o->addr == NULL)
    {
      if((pd = malloc_zero(pdc * sizeof(scamper_dealias_probedef_t))) == NULL)
	{
	  scamper_debug(__func__, "could not malloc radargun pd");
	  goto err;
	}

      i = 0;
      for(sn=slist_head_node(o->probedefs); sn != NULL; sn=slist_node_next(sn))
	{
	  if(dealias_probedef_args(&pd[i], (char *)slist_node_item(sn)) != 0 ||
	     pd[i].dst == NULL)
	    {
	      scamper_debug(__func__, "could not parse radargun def %d", i);
	      goto err;
	    }
	  if(i != 0 && pd[0].dst->type != pd[i].dst->type)
	    {
	      scamper_debug(__func__, "mixed address families");
	      goto err;
	    }
	  pd[i].id = i;
	  i++;
	}
      probedefc = i;
    }
  else if(pdc < 2 && o->addr != NULL)
    {
      if((pd_list = slist_alloc()) == NULL)
	{
	  printerror(__func__, "could not alloc pd_list");
	  goto err;
	}
      a1 = o->addr; i = 0;
      for(;;)
	{
	  a2 = string_nextword(a1);
	  pd0.dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, a1);
	  if(pd0.dst == NULL)
	    goto err;
	  pd0.id = i++;
	  if((pd = memdup(&pd0, sizeof(pd0))) == NULL ||
	     slist_tail_push(pd_list, pd) == NULL)
	    goto err;
	  pd0.dst = NULL;
	  if(a2 == NULL)
	    break;
	  a1 = a2;
	}
      probedefc = slist_count(pd_list);
    }
  else goto err;

  if(scamper_dealias_radargun_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc radargun structure");
      goto err;
    }
  rg = d->data;

  if(scamper_dealias_radargun_probedefs_alloc(rg, probedefc) != 0)
    {
      scamper_debug(__func__, "could not alloc radargun probedefs");
      goto err;
    }

  rg->attempts     = o->attempts;
  rg->wait_probe   = o->wait_probe;
  rg->wait_timeout = o->wait_timeout;
  rg->wait_round   = o->wait_round;
  rg->probedefc    = probedefc;
  rg->flags        = flags;

  if(pd_list == NULL)
    {
      for(j=0; j<pdc; j++)
	memcpy(&rg->probedefs[j], &pd[j], sizeof(scamper_dealias_probedef_t));
    }
  else
    {
      i=0;
      while((pd = slist_head_pop(pd_list)) != NULL)
	{
	  memcpy(&rg->probedefs[i], pd, sizeof(scamper_dealias_probedef_t));
	  free(pd);
	  i++;
	}
      slist_free(pd_list); pd_list = NULL;
    }

  return 0;

 err:
  if(pd != NULL)
    {
      for(j=0; j<pdc; j++)
	if(pd[j].dst != NULL)
	  scamper_addr_free(pd[j].dst);
      free(pd);
    }
  if(pd_list != NULL)
    slist_free_cb(pd_list, (slist_free_t)scamper_dealias_probedef_free);
  if(pd0.dst != NULL)
    scamper_addr_free(pd0.dst);
  return -1;
}

static int dealias_alloc_prefixscan(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_prefixscan_t *prefixscan;
  scamper_dealias_probedef_t pd0;
  scamper_addr_t *dst = NULL;
  slist_node_t *sn;
  uint8_t flags = 0;
  uint8_t prefix;
  char *addr2 = NULL, *pfxstr, *xs;
  long tmp;
  int af;

  /* check the sanity of various parameters */
  if(slist_count(o->probedefs) != 1 || o->addr == NULL || o->dport != 0 ||
     o->sport != 0 || o->ttl != 0 || o->shuffle != 0 ||
     (o->inseq != 0 && o->fudge != 0))
    {
      scamper_debug(__func__, "invalid parameters for prefixscan");
      goto err;
    }

  if(o->ttl == 0)        o->ttl        = 255;
  if(o->wait_probe == 0) o->wait_probe = 1000;
  if(o->attempts == 0)   o->attempts   = 2;
  if(o->replyc == 0)     o->replyc     = 5;

  if(o->nobs != 0)
    flags |= SCAMPER_DEALIAS_PREFIXSCAN_FLAG_NOBS;

  if(o->fudge == 0 && o->inseq == 0)
    o->fudge = 200;

  /*
   * we need `a' and `b' to traceroute.  parse the `addr' string.
   * start by getting the second address.
   *
   * skip over the first address until we get to whitespace.
   */
  if((addr2 = string_nextword(o->addr)) == NULL)
    {
      scamper_debug(__func__, "missing second address");
      goto err;
    }

  string_nullterm_char(addr2, '/', &pfxstr);
  if(pfxstr == NULL)
    {
      scamper_debug(__func__, "missing prefix");
      goto err;
    }

  if(string_tolong(pfxstr, &tmp) != 0 || tmp < 24 || tmp >= 32)
    {
      scamper_debug(__func__, "invalid prefix %s", pfxstr);
      goto err;
    }
  prefix = (uint8_t)tmp;

  /* check the sanity of the probedef */
  memset(&pd0, 0, sizeof(pd0));
  if(dealias_probedef_args(&pd0, (char *)slist_head_item(o->probedefs)) != 0)
    {
      scamper_debug(__func__, "could not parse prefixscan probedef");
      goto err;
    }
  if(pd0.dst != NULL)
    {
      scamper_debug(__func__, "prefixscan ip address spec. in probedef");
      scamper_addr_free(pd0.dst); pd0.dst = NULL;
      goto err;
    }

  if(scamper_dealias_prefixscan_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc prefixscan structure");
      goto err;
    }
  prefixscan = d->data;

  prefixscan->attempts     = o->attempts;
  prefixscan->fudge        = o->fudge;
  prefixscan->wait_probe   = o->wait_probe;
  prefixscan->wait_timeout = o->wait_timeout;
  prefixscan->replyc       = o->replyc;
  prefixscan->prefix       = prefix;
  prefixscan->flags        = flags;

  /* resolve the two addresses now */
  prefixscan->a = scamper_addrcache_resolve(addrcache, AF_UNSPEC, o->addr);
  if(prefixscan->a == NULL)
    {
      scamper_debug(__func__, "could not resolve %s", o->addr);
      goto err;
    }
  af = scamper_addr_af(prefixscan->a);
  prefixscan->b = scamper_addrcache_resolve(addrcache, af, addr2);
  if(prefixscan->b == NULL)
    {
      scamper_debug(__func__, "could not resolve %s", addr2);
      goto err;
    }

  /* add the first probedef */
  if(scamper_dealias_prefixscan_probedefs_alloc(prefixscan, 1) != 0)
    {
      scamper_debug(__func__, "could not alloc prefixscan probedefs");
      goto err;
    }
  memcpy(prefixscan->probedefs, &pd0, sizeof(pd0));
  prefixscan->probedefs[0].dst = scamper_addr_use(prefixscan->a);
  prefixscan->probedefs[0].id  = 0;
  prefixscan->probedefc        = 1;

  /* resolve any addresses to exclude in the scan */
  if(o->xs != NULL)
    {
      for(sn = slist_head_node(o->xs); sn != NULL; sn = slist_node_next(sn))
	{
	  xs = slist_node_item(sn);
	  if((dst = scamper_addrcache_resolve(addrcache, af, xs)) == NULL)
	    {
	      scamper_debug(__func__, "could not resolve %s", xs);
	      goto err;
	    }
	  if(scamper_dealias_prefixscan_xs_add(d, dst) != 0)
	    {
	      scamper_debug(__func__, "could not add %s to xs", xs);
	      goto err;
	    }
	  scamper_addr_free(dst); dst = NULL;
	}
    }

  return 0;

 err:
  return -1;
}

static int dealias_alloc_bump(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_bump_t *bump = NULL;
  scamper_dealias_probedef_t pd[2];
  slist_node_t *sn;
  int i;

  memset(&pd, 0, sizeof(pd));

  if(slist_count(o->probedefs) != 2 || o->xs != NULL || o->dport != 0 ||
     o->sport != 0 || o->ttl != 0 || o->replyc != 0 || o->shuffle != 0 ||
     o->addr != NULL || (o->inseq != 0 && o->fudge != 0))
    {
      scamper_debug(__func__, "invalid parameters for bump");
      goto err;
    }

  if(o->wait_probe == 0) o->wait_probe = 1000;
  if(o->attempts == 0)   o->attempts   = 3;
  if(o->fudge == 0)      o->fudge      = 30; /* bump limit */

  i = 0;
  for(sn = slist_head_node(o->probedefs); sn != NULL; sn = slist_node_next(sn))
    {
      if(dealias_probedef_args(&pd[i], (char *)slist_node_item(sn)) != 0)
	{
	  scamper_debug(__func__, "could not read bump probedef %d", i);
	  goto err;
	}
      if(pd[i].dst == NULL)
	{
	  scamper_debug(__func__, "missing dst address in probedef %d", i);
	  goto err;
	}
      if(pd[i].dst->type != SCAMPER_ADDR_TYPE_IPV4)
	{
	  scamper_debug(__func__, "dst address not IPv4 in probedef %d", i);
	  goto err;
	}
      pd[i].id = i;
      i++;
    }

  if(scamper_dealias_bump_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc bump structure");
      goto err;
    }
  bump = d->data;

  bump->attempts     = o->attempts;
  bump->wait_probe   = o->wait_probe;
  bump->bump_limit   = o->fudge;
  memcpy(bump->probedefs, pd, sizeof(bump->probedefs));

  return 0;

 err:
  if(pd[0].dst != NULL) scamper_addr_free(pd[0].dst);
  if(pd[1].dst != NULL) scamper_addr_free(pd[1].dst);
  return -1;
}


/*
 * scamper_do_dealias_alloc
 *
 * given a string representing a dealias task, parse the parameters and
 * assemble a dealias.  return the dealias structure so that it is all ready
 * to go.
 */
void *scamper_do_dealias_alloc(char *str)
{
  static int (*const alloc_func[])(scamper_dealias_t *, dealias_options_t *) = {
    dealias_alloc_mercator,
    dealias_alloc_ally,
    dealias_alloc_radargun,
    dealias_alloc_prefixscan,
    dealias_alloc_bump,
  };
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_dealias_t *dealias = NULL;
  dealias_options_t o;
  uint8_t  method = SCAMPER_DEALIAS_METHOD_MERCATOR;
  uint32_t userid = 0;
  long long tmp = 0;

  memset(&o, 0, sizeof(o));

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &o.addr) != 0)
    {
      scamper_debug(__func__, "could not parse command");
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 dealias_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	case DEALIAS_OPT_METHOD:
	  method = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case DEALIAS_OPT_OPTION:
	  if(strcasecmp(opt->str, "nobs") == 0)
	    o.nobs = 1;
	  else if(strcasecmp(opt->str, "shuffle") == 0)
	    o.shuffle = 1;
	  else if(strcasecmp(opt->str, "inseq") == 0)
	    o.inseq = 1;
	  else
	    {
	      scamper_debug(__func__, "unknown option %s", opt->str);
	      goto err;
	    }
	  break;

	case DEALIAS_OPT_ATTEMPTS:
	  o.attempts = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_DPORT:
	  o.dport = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_SPORT:
	  o.sport = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_FUDGE:
	  o.fudge = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_TTL:
	  o.ttl = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_PROBEDEF:
	  if(o.probedefs == NULL && (o.probedefs = slist_alloc()) == NULL)
	    {
	      printerror(__func__, "could not alloc probedefs");
	      goto err;
	    }
	  if(slist_tail_push(o.probedefs, opt->str) == NULL)
	    {
	      printerror(__func__, "could not push probedef");
	      goto err;
	    }
	  break;

	case DEALIAS_OPT_WAIT_TIMEOUT:
	  o.wait_timeout = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_WAIT_PROBE:
	  o.wait_probe = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_WAIT_ROUND:
	  o.wait_round = (uint32_t)tmp;
	  break;

	case DEALIAS_OPT_EXCLUDE:
	  if(o.xs == NULL && (o.xs = slist_alloc()) == NULL)
	    {
	      printerror(__func__, "could not alloc xs");
	      goto err;
	    }
	  if(slist_tail_push(o.xs, opt->str) == NULL)
	    {
	      printerror(__func__, "could not push xs");
	      goto err;
	    }
	  break;

	case DEALIAS_OPT_REPLYC:
	  o.replyc = (uint8_t)tmp;
	  break;

	default:
	  scamper_debug(__func__, "unhandled option %d", opt->id);
	  goto err;
	}
    }

  scamper_options_free(opts_out);
  opts_out = NULL;

  if(o.wait_timeout == 0)
    o.wait_timeout = 5;

  if((dealias = scamper_dealias_alloc()) == NULL)
    {
      scamper_debug(__func__, "could not alloc dealias structure");
      goto err;
    }
  dealias->method = method;
  dealias->userid = userid;
  if(alloc_func[method-1](dealias, &o) != 0)
    goto err;

  if(o.probedefs != NULL)
    slist_free(o.probedefs);
  if(o.xs != NULL)
    slist_free(o.xs);

  return dealias;

 err:
  if(opts_out != NULL) scamper_options_free(opts_out);
  if(o.probedefs != NULL) free(o.probedefs);
  if(dealias != NULL) scamper_dealias_free(dealias);
  return NULL;
}

/*
 * scamper_do_dealias_arg_validate
 *
 *
 */
int scamper_do_dealias_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  dealias_arg_param_validate);
}

void scamper_do_dealias_free(void *data)
{
  scamper_dealias_free((scamper_dealias_t *)data);
  return;
}

static int probedef2sig(scamper_task_t *task, scamper_dealias_probedef_t *def)
{
  scamper_task_sig_t *sig = NULL;
  char buf[32];

  if(def->src == NULL && (def->src = scamper_getsrc(def->dst, 0)) == NULL)
    {
      printerror(__func__, "could not get src address for %s",
		 scamper_addr_tostr(def->dst, buf, sizeof(buf)));
      goto err;
    }

  /* form a signature */
  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
    goto err;
  sig->sig_tx_ip_dst = scamper_addr_use(def->dst);
  sig->sig_tx_ip_src = scamper_addr_use(def->src);

  /* add it to the task */
  if(scamper_task_sig_add(task, sig) != 0)
    goto err;

  return 0;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  return -1;
}

scamper_task_t *scamper_do_dealias_alloctask(void *data,
					     scamper_list_t *list,
					     scamper_cycle_t *cycle)
{
  scamper_dealias_t             *dealias = (scamper_dealias_t *)data;
  dealias_state_t               *state = NULL;
  scamper_task_t                *task = NULL;
  scamper_dealias_probedef_t    *def;
  scamper_dealias_prefixscan_t  *pfxscan;
  scamper_dealias_mercator_t    *mercator;
  scamper_dealias_radargun_t    *radargun;
  scamper_dealias_ally_t        *ally;
  scamper_dealias_bump_t        *bump;
  dealias_prefixscan_t          *pfstate;
  uint32_t p;
  int i;

  /* allocate a task structure and store the trace with it */
  if((task = scamper_task_alloc(dealias, &funcs)) == NULL)
    goto err;

  if((state = malloc_zero(sizeof(dealias_state_t))) == NULL ||
     (state->recent_probes = dlist_alloc()) == NULL ||
     (state->ptbq = slist_alloc()) == NULL ||
     (state->discard = slist_alloc()) == NULL ||
     (state->targets = splaytree_alloc((splaytree_cmp_t)dealias_target_cmp)) == NULL)
    {
      printerror(__func__, "could not malloc state");
      goto err;
    }
  state->id = 255;

  if(dealias->method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      mercator = dealias->data;
      if(probedef2sig(task, &mercator->probedef) != 0)
	goto err;
      state->probedefs = &mercator->probedef;
      state->probedefc = 1;
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_ALLY)
    {
      ally = dealias->data;
      for(i=0; i<2; i++)
	if(probedef2sig(task, &ally->probedefs[i]) != 0)
	  goto err;
      state->probedefs = ally->probedefs;
      state->probedefc = 2;
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    {
      radargun = dealias->data;
      for(p=0; p<radargun->probedefc; p++)
	if(probedef2sig(task, &radargun->probedefs[p]) != 0)
	  goto err;

      state->probedefs = radargun->probedefs;
      state->probedefc = radargun->probedefc;
      if(dealias_radargun_alloc(radargun, state) != 0)
	goto err;
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    {
      if(dealias_prefixscan_alloc(dealias, state) != 0)
	goto err;
      pfxscan = dealias->data;
      if(probedef2sig(task, &pfxscan->probedefs[0]) != 0)
	goto err;
      state->probedefs = pfxscan->probedefs;
      state->probedefc = pfxscan->probedefc;

      pfstate = state->methodstate;
      for(i=0; i<pfstate->probedefc; i++)
	{
	  if(probedef2sig(task, &pfstate->probedefs[i]) != 0)
	    goto err;
	}
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_BUMP)
    {
      bump = dealias->data;
      for(i=0; i<2; i++)
	if(probedef2sig(task, &bump->probedefs[i]) != 0)
	  goto err;

      state->probedefs = bump->probedefs;
      state->probedefc = 2;
      if(dealias_bump_alloc(state) != 0)
	goto err;
    }
  else goto err;

  for(p=0; p<state->probedefc; p++)
    {
      def = &state->probedefs[p];
      if(def->mtu != 0)
	state->flags |= DEALIAS_STATE_FLAG_DL;
      if(dealias_probedef_add(state, def) != 0)
	goto err;
    }

  /* associate the list and cycle with the trace */
  dealias->list  = scamper_list_use(list);
  dealias->cycle = scamper_cycle_use(cycle);

  scamper_task_setstate(task, state);
  state = NULL;

  return task;

 err:
  if(task != NULL)
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  if(state != NULL) dealias_state_free(dealias, state);
  return NULL;
}

void scamper_do_dealias_cleanup(void)
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  return;
}

int scamper_do_dealias_init(void)
{
  funcs.probe                  = do_dealias_probe;
  funcs.handle_icmp            = do_dealias_handle_icmp;
  funcs.handle_timeout         = do_dealias_handle_timeout;
  funcs.handle_dl              = do_dealias_handle_dl;
  funcs.write                  = do_dealias_write;
  funcs.task_free              = do_dealias_free;
  funcs.halt                   = do_dealias_halt;

  return 0;
}
