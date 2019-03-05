/*
 * scamper_dealias.c
 *
 * $Id: scamper_dealias.c,v 1.51 2016/11/21 04:20:47 mjl Exp $
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Copyright (C) 2012-2013 The Regents of the University of California
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
  "$Id: scamper_dealias.c,v 1.51 2016/11/21 04:20:47 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_dealias.h"
#include "utils.h"

int scamper_dealias_ipid(const scamper_dealias_probe_t **probes,
			 uint32_t probec, scamper_dealias_ipid_t *ipid)
{
  const scamper_dealias_probe_t *p;
  const scamper_dealias_reply_t *r;
  uint32_t bs_mind = 0x30000;
  uint32_t bs_maxd = 0;
  uint32_t bs_sum  = 0;
  uint32_t mind = 0x30000;
  uint32_t maxd = 0;
  uint32_t sum  = 0;
  uint32_t diff;
  uint32_t cur, prev;
  uint32_t i;
  int echo, cons;

  ipid->type = SCAMPER_DEALIAS_IPID_UNKNOWN;

  echo = 1;
  cons = 1;

  if(probec == 0 || probes[0] == NULL || probes[0]->replyc != 1)
    return 0;

  prev = probes[0]->replies[0]->ipid;
  for(i=1; i<probec; i++)
    {
      if((p = probes[i]) == NULL)
	return 0;

      if(p->replyc != 1)
	return 0;

      if((r = p->replies[0]) == NULL)
	return 0;

      /* non byteswap case */
      cur = r->ipid;
      if(cur > prev)
	diff = cur - prev;
      else if(cur < prev)
	diff = 0x10000 + cur - prev;
      else
	diff = 0;
      if(diff < mind)
	mind = diff;
      if(diff > maxd)
	maxd = diff;
      sum += diff;

      /* byteswap case */
      cur = byteswap16(r->ipid);
      prev = byteswap16(prev);
      if(cur > prev)
	diff = cur - prev;
      else if(cur < prev)
	diff = 0x10000 + cur - prev;
      else
	diff = 0;
      if(diff < bs_mind)
	bs_mind = diff;
      if(diff > maxd)
	bs_maxd = diff;
      bs_sum += diff;

      if(echo != 0 && p->ipid != r->ipid && p->ipid != byteswap16(r->ipid))
	echo = 0;
      else if(cons != 0 && probes[i-1]->replies[0]->ipid != r->ipid)
	cons = 0;

      prev = r->ipid;
    }

  if(cons == 0 && echo == 0)
    {
      /* figure out which byte ordering best explains the sequence */
      if(sum < bs_sum)
	{
	  ipid->mind = mind;
	  ipid->maxd = maxd;
	}
      else
	{
	  ipid->mind = bs_mind;
	  ipid->maxd = bs_maxd;
	}
      ipid->type = SCAMPER_DEALIAS_IPID_INCR;
    }
  else if(cons != 0)
    {
      if(probes[0]->replies[0]->ipid == 0)
	ipid->type = SCAMPER_DEALIAS_IPID_ZERO;
      else
	ipid->type = SCAMPER_DEALIAS_IPID_CONST;
    }
  else if(echo != 0)
    {
      ipid->type = SCAMPER_DEALIAS_IPID_ECHO;
    }

  return 0;
}

static void dealias_probedef_free(scamper_dealias_probedef_t *probedef)
{
  if(probedef->src != NULL)
    {
      scamper_addr_free(probedef->src);
      probedef->src = NULL;
    }
  if(probedef->dst != NULL)
    {
      scamper_addr_free(probedef->dst);
      probedef->dst = NULL;
    }
  return;
}

static void dealias_mercator_free(void *data)
{
  scamper_dealias_mercator_t *mercator = (scamper_dealias_mercator_t *)data;
  dealias_probedef_free(&mercator->probedef);
  free(mercator);
  return;
}

static void dealias_ally_free(void *data)
{
  scamper_dealias_ally_t *ally = (scamper_dealias_ally_t *)data;
  dealias_probedef_free(&ally->probedefs[0]);
  dealias_probedef_free(&ally->probedefs[1]);
  free(ally);
  return;
}

static void dealias_radargun_free(void *data)
{
  scamper_dealias_radargun_t *radargun = (scamper_dealias_radargun_t *)data;
  uint32_t i;

  if(radargun->probedefs != NULL)
    {
      for(i=0; i<radargun->probedefc; i++)
	{
	  dealias_probedef_free(&radargun->probedefs[i]);
	}
      free(radargun->probedefs);
    }
  free(radargun);
  return;
}

static void dealias_prefixscan_free(void *data)
{
  scamper_dealias_prefixscan_t *prefixscan = data;
  uint16_t i;

  if(prefixscan == NULL)
    return;

  if(prefixscan->a  != NULL) scamper_addr_free(prefixscan->a);
  if(prefixscan->b  != NULL) scamper_addr_free(prefixscan->b);
  if(prefixscan->ab != NULL) scamper_addr_free(prefixscan->ab);

  if(prefixscan->xs != NULL)
    {
      for(i=0; i<prefixscan->xc; i++)
	if(prefixscan->xs[i] != NULL)
	  scamper_addr_free(prefixscan->xs[i]);
      free(prefixscan->xs);
    }

  if(prefixscan->probedefs != NULL)
    {
      for(i=0; i<prefixscan->probedefc; i++)
	dealias_probedef_free(&prefixscan->probedefs[i]);
      free(prefixscan->probedefs);
    }

  free(prefixscan);

  return;
}

static void dealias_bump_free(void *data)
{
  scamper_dealias_bump_t *bump = (scamper_dealias_bump_t *)data;
  dealias_probedef_free(&bump->probedefs[0]);
  dealias_probedef_free(&bump->probedefs[1]);
  free(bump);
  return;
}

const char *scamper_dealias_probedef_method_tostr(const scamper_dealias_probedef_t *d,
						  char *b, size_t l)
{
  static const char *m[] = {
    NULL,
    "icmp-echo",
    "tcp-ack",
    "udp",
    "tcp-ack-sport",
    "udp-dport",
    "tcp-syn-sport",
  };
  if(d->method > sizeof(m) / sizeof(char *) || m[d->method] == NULL)
    {
      snprintf(b, l, "%d", d->method);
      return b;
    }
  return m[d->method];
}

scamper_dealias_probedef_t *scamper_dealias_probedef_alloc(void)
{
  size_t size = sizeof(scamper_dealias_probedef_t);
  return (scamper_dealias_probedef_t *)malloc_zero(size);
}

void scamper_dealias_probedef_free(scamper_dealias_probedef_t *probedef)
{
  dealias_probedef_free(probedef);
  free(probedef);
  return;
}

scamper_dealias_probe_t *scamper_dealias_probe_alloc(void)
{
  size_t size = sizeof(scamper_dealias_probe_t);
  return (scamper_dealias_probe_t *)malloc_zero(size);
}

void scamper_dealias_probe_free(scamper_dealias_probe_t *probe)
{
  uint16_t i;

  if(probe->replies != NULL)
    {
      for(i=0; i<probe->replyc; i++)
	{
	  if(probe->replies[i] != NULL)
	    scamper_dealias_reply_free(probe->replies[i]);
	}
      free(probe->replies);
    }

  free(probe);
  return;
}

scamper_dealias_reply_t *scamper_dealias_reply_alloc(void)
{
  size_t size = sizeof(scamper_dealias_reply_t);
  return (scamper_dealias_reply_t *)malloc_zero(size);
}

void scamper_dealias_reply_free(scamper_dealias_reply_t *reply)
{
  if(reply->src != NULL)
    scamper_addr_free(reply->src);
  free(reply);
  return;
}

uint32_t scamper_dealias_reply_count(const scamper_dealias_t *dealias)
{
  uint32_t rc = 0;
  uint16_t i;
  for(i=0; i<dealias->probec; i++)
    {
      if(dealias->probes[i] != NULL)
	rc += dealias->probes[i]->replyc;
    }
  return rc;
}

static int dealias_probe_tx_cmp(const scamper_dealias_probe_t *a,
				const scamper_dealias_probe_t *b)
{
  return timeval_cmp(&a->tx, &b->tx);
}

static int dealias_probe_seq_cmp(const scamper_dealias_probe_t *a,
				 const scamper_dealias_probe_t *b)
{
  if(a->seq < b->seq)
    return -1;
  if(a->seq > b->seq)
    return 1;
  if(a->def->id < b->def->id)
    return -1;
  if(a->def->id > b->def->id)
    return 1;
  return 0;
}

static int dealias_probe_def_cmp(const scamper_dealias_probe_t *a,
				 const scamper_dealias_probe_t *b)
{
  if(a->def->id < b->def->id)
    return -1;
  if(a->def->id > b->def->id)
    return 1;
  if(a->seq < b->seq)
    return -1;
  if(a->seq > b->seq)
    return 1;
  return 0;
}

void scamper_dealias_probes_sort_tx(scamper_dealias_t *dealias)
{
  array_qsort((void **)dealias->probes, dealias->probec,
	      (array_cmp_t)dealias_probe_tx_cmp);
  return;
}

void scamper_dealias_probes_sort_seq(scamper_dealias_t *dealias)
{
  array_qsort((void **)dealias->probes, dealias->probec,
	      (array_cmp_t)dealias_probe_seq_cmp);
  return;
}

void scamper_dealias_probes_sort_def(scamper_dealias_t *dealias)
{
  array_qsort((void **)dealias->probes, dealias->probec,
	      (array_cmp_t)dealias_probe_def_cmp);
  return;
}

int scamper_dealias_probe_add(scamper_dealias_t *dealias,
			      scamper_dealias_probe_t *probe)
{
  size_t size = (dealias->probec+1) * sizeof(scamper_dealias_probe_t *);
  if(realloc_wrap((void **)&dealias->probes, size) == 0)
    {
      dealias->probes[dealias->probec++] = probe;
      return 0;
    }
  return -1;
}

int scamper_dealias_reply_add(scamper_dealias_probe_t *probe,
			      scamper_dealias_reply_t *reply)
{
  size_t size = (probe->replyc+1) * sizeof(scamper_dealias_reply_t *);
  if(realloc_wrap((void **)&probe->replies, size) == 0)
    {
      probe->replies[probe->replyc++] = reply;
      return 0;
    }
  return -1;
}

int scamper_dealias_ally_alloc(scamper_dealias_t *dealias)
{
  if((dealias->data = malloc_zero(sizeof(scamper_dealias_ally_t))) != NULL)
    return 0;
  return -1;
}

int scamper_dealias_mercator_alloc(scamper_dealias_t *dealias)
{
  if((dealias->data = malloc_zero(sizeof(scamper_dealias_mercator_t))) != NULL)
    return 0;
  return -1;
}

int scamper_dealias_radargun_alloc(scamper_dealias_t *dealias)
{
  if((dealias->data = malloc_zero(sizeof(scamper_dealias_radargun_t))) != NULL)
    return 0;
  return -1;
}

int scamper_dealias_prefixscan_alloc(scamper_dealias_t *dealias)
{
  dealias->data = malloc_zero(sizeof(scamper_dealias_prefixscan_t));
  if(dealias->data != NULL)
    return 0;
  return -1;
}

int scamper_dealias_bump_alloc(scamper_dealias_t *dealias)
{
  if((dealias->data = malloc_zero(sizeof(scamper_dealias_bump_t))) != NULL)
    return 0;

  return -1;
}

static uint16_t dealias_ipid16_diff(uint16_t a, uint16_t b)
{
  if(a <= b)
    return b - a;
  return (0xFFFFUL - a) + b + 1;
}

static int dealias_ipid16_inseq2(uint16_t a, uint16_t b, uint16_t fudge)
{
  if(a == b || dealias_ipid16_diff(a, b) > fudge)
    return 0;
  return 1;
}

static int dealias_ipid16_inseq3(uint32_t a,uint32_t b,uint32_t c,uint32_t f)
{
  if(a == b || b == c || a == c)
    return 0;

  if(a > b)
    b += 0x10000;
  if(a > c)
    c += 0x10000;

  if(a > b || b > c)
    return 0;
  if(f != 0 && (b - a > f || c - b > f))
    return 0;

  return 1;
}

static uint32_t dealias_ipid32_diff(uint32_t a, uint32_t b)
{
  if(a <= b)
    return b - a;
  return (0xFFFFFFFFUL - a) + b + 1;
}

static int dealias_ipid32_inseq2(uint32_t a, uint32_t b, uint32_t fudge)
{
  if(a == b || dealias_ipid32_diff(a, b) > fudge)
    return 0;
  return 1;
}

static int dealias_ipid32_inseq3(uint64_t a,uint64_t b,uint64_t c,uint64_t f)
{
  if(a == b || b == c || a == c)
    return 0;

  if(a > b)
    b += 0x100000000ULL;
  if(a > c)
    c += 0x100000000ULL;

  if(a > b || b > c)
    return 0;
  if(f != 0 && (b - a > f || c - b > f))
    return 0;

  return 1;
}

static int dealias_ipid16_bo(scamper_dealias_probe_t **probes, int probec)
{
  scamper_dealias_probe_t **s = NULL;
  uint16_t a, b, c = 1, max_bs = 0, max_nobs = 0, u16;
  int i, rc = 2;

  if((s = memdup(probes, sizeof(scamper_dealias_probe_t *) * probec)) == NULL)
    return -1;
  array_qsort((void **)s, probec, (array_cmp_t)dealias_probe_def_cmp);

  for(i=0; i<probec; i++)
    {
      if(i+1 == probec || s[i]->def != s[i+1]->def)
	{
	  if(c >= 3)
	    {
	      if(max_nobs < max_bs)
		rc = 0;
	      else if(max_nobs > max_bs)
		rc = 1;
	      if(rc == 0)
		goto done;
	    }
	  c = 1; max_nobs = 0; max_bs = 0;
	}
      else
	{
	  a = s[i]->replies[0]->ipid; b = s[i+1]->replies[0]->ipid;
	  u16 = dealias_ipid16_diff(a, b);
	  if(u16 > max_nobs || max_nobs == 0)
	    max_nobs = u16;
	  u16 = dealias_ipid16_diff(byteswap16(a), byteswap16(b));
	  if(u16 > max_bs || max_bs == 0)
	    max_bs = u16;
	  c++;
	}
    }

 done:
  if(s != NULL) free(s);
  return rc;
}

static int dealias_ipid16_inseq(scamper_dealias_probe_t **probes,
				int probec, uint16_t fudge, int bs)
{
  uint16_t a, b, c;
  int i;

  /*
   * do a preliminary check to see if the ipids could be in sequence with
   * two samples.
   */
  if(probec == 2)
    {
      /* if it is a strict sequence check, we don't actually know */
      if(fudge == 0)
	return 1;

      a = probes[0]->replies[0]->ipid;
      b = probes[1]->replies[0]->ipid;
      if(bs != 0)
	{
	  a = byteswap16(a);
	  b = byteswap16(b);
	}
      if(dealias_ipid16_inseq2(a, b, fudge) != 0)
	return 1;
      return 0;
    }

  for(i=0; i+2<probec; i++)
    {
      a = probes[i+0]->replies[0]->ipid;
      b = probes[i+1]->replies[0]->ipid;
      c = probes[i+2]->replies[0]->ipid;
      if(bs != 0)
	{
	  a = byteswap16(a);
	  b = byteswap16(b);
	  c = byteswap16(c);
	}
      if(dealias_ipid16_inseq3(a, b, c, fudge) == 0)
	return 0;
    }

  return 1;
}

static int dealias_ipid32_bo(scamper_dealias_probe_t **probes, int probec)
{
  scamper_dealias_probe_t **s = NULL;
  uint32_t a, b, c = 1, max_bs = 0, max_nobs = 0, u32;
  int i, rc = 2;

  if((s = memdup(probes, sizeof(scamper_dealias_probe_t *) * probec)) == NULL)
    return -1;
  array_qsort((void **)s, probec, (array_cmp_t)dealias_probe_def_cmp);

  for(i=0; i<probec; i++)
    {
      if(i+1 == probec || s[i]->def != s[i+1]->def)
	{
	  if(c >= 3)
	    {
	      if(max_nobs < max_bs)
		rc = 0;
	      else if(max_nobs > max_bs)
		rc = 1;
	      if(rc == 0)
		goto done;
	    }
	  c = 1; max_nobs = 0; max_bs = 0;
	}
      else
	{
	  a = s[i]->replies[0]->ipid32; b = s[i+1]->replies[0]->ipid32;
	  u32 = dealias_ipid32_diff(a, b);
	  if(u32 > max_nobs || max_nobs == 0)
	    max_nobs = u32;
	  u32 = dealias_ipid32_diff(byteswap32(a), byteswap32(b));
	  if(u32 > max_bs || max_bs == 0)
	    max_bs = u32;
	  c++;
	}
    }

 done:
  if(s != NULL) free(s);
  return rc;
}

static int dealias_ipid32_inseq(scamper_dealias_probe_t **probes,
				int probec, uint16_t fudge, int bs)
{
  uint32_t a, b, c;
  int i;

  /*
   * do a preliminary check to see if the ipids could be in sequence with
   * two samples.
   */
  if(probec == 2)
    {
      /* if it is a strict sequence check, we don't actually know */
      if(fudge == 0)
	return 1;

      a = probes[0]->replies[0]->ipid32;
      b = probes[1]->replies[0]->ipid32;
      if(bs != 0)
	{
	  a = byteswap32(a);
	  b = byteswap32(b);
	}
      if(dealias_ipid32_inseq2(a, b, fudge) != 0)
	return 1;
      return 0;
    }

  for(i=0; i+2<probec; i++)
    {
      a = probes[i+0]->replies[0]->ipid32;
      b = probes[i+1]->replies[0]->ipid32;
      c = probes[i+2]->replies[0]->ipid32;
      if(bs != 0)
	{
	  a = byteswap32(a);
	  b = byteswap32(b);
	  c = byteswap32(c);
	}
      if(dealias_ipid32_inseq3(a, b, c, fudge) == 0)
	return 0;
    }

  return 1;
}

int scamper_dealias_ipid_inseq(scamper_dealias_probe_t **probes,
			       int probec, uint16_t fudge, int bs)
{
  static int (*const inseq[])(scamper_dealias_probe_t **,int,uint16_t,int) = {
    dealias_ipid16_inseq,
    dealias_ipid32_inseq,
  };
  static int (*const bo[])(scamper_dealias_probe_t **, int) = {
    dealias_ipid16_bo,
    dealias_ipid32_bo,
  };
  int i, x;

  if(probec < 2)
    return -1;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(probes[0]->def->dst))
    x = 0;
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(probes[0]->def->dst))
    x = 1;
  else
    return -1;

  if(bs == 3 && fudge == 0)
    {
      if((i = bo[x](probes, probec)) == -1)
	return -1;
      return inseq[x](probes, probec, fudge, i);
    }

  if(bs == 2 || bs == 3)
    {
      if(inseq[x](probes, probec, fudge, 0) == 1)
	return 1;
      return inseq[x](probes, probec, fudge, 1);
    }

  return inseq[x](probes, probec, fudge, bs);
}

int scamper_dealias_probes_alloc(scamper_dealias_t *dealias, uint32_t cnt)
{
  size_t size = cnt * sizeof(scamper_dealias_probe_t *);
  if((dealias->probes = malloc_zero(size)) == NULL)
    return -1;
  return 0;
}

int scamper_dealias_replies_alloc(scamper_dealias_probe_t *probe, uint16_t cnt)
{
  size_t size = cnt * sizeof(scamper_dealias_reply_t *);
  if((probe->replies = malloc_zero(size)) == NULL)
    return -1;
  return 0;
}

int scamper_dealias_radargun_probedefs_alloc(scamper_dealias_radargun_t *rg,
					     uint32_t probedefc)
{
  size_t len = probedefc * sizeof(scamper_dealias_probedef_t);
  if((rg->probedefs = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

typedef struct dealias_resolv
{
  scamper_dealias_probe_t **probes;
  int                       probec;
  int                       probet;
} dealias_resolv_t;

static int dealias_fudge_inseq(scamper_dealias_probe_t *pr_a,
			       scamper_dealias_probe_t *pr_b,
			       int bs, int fudge)
{
  uint32_t a = pr_a->replies[0]->ipid;
  uint32_t b = pr_b->replies[0]->ipid;

  if(bs != 0)
    {
      a = byteswap16(a);
      b = byteswap16(b);
    }

  if(a > b)
    b += 0x10000;

  if((int)(b - a) > fudge)
    return 0;

  return 1;
}

int scamper_dealias_prefixscan_xs_add(scamper_dealias_t *dealias,
				      scamper_addr_t *addr)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  int tmp;

  if(array_find((void **)prefixscan->xs, prefixscan->xc, addr,
		(array_cmp_t)scamper_addr_cmp) != NULL)
    return 0;

  if((tmp = prefixscan->xc) == 65535)
    return -1;

  if(array_insert((void ***)&prefixscan->xs, &tmp, addr,
		  (array_cmp_t)scamper_addr_cmp) != 0)
    return -1;

  scamper_addr_use(addr);
  prefixscan->xc++;
  return 0;
}

int scamper_dealias_prefixscan_xs_in(scamper_dealias_t *dealias,
				     scamper_addr_t *addr)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  if(array_find((void **)prefixscan->xs, prefixscan->xc, addr,
		(array_cmp_t)scamper_addr_cmp) != NULL)
    return 1;
  return 0;
}

int scamper_dealias_prefixscan_xs_alloc(scamper_dealias_prefixscan_t *p,
					uint16_t xc)
{
  if((p->xs = malloc_zero(sizeof(scamper_addr_t *) * xc)) != NULL)
    return 0;
  return -1;
}

int scamper_dealias_prefixscan_probedefs_alloc(scamper_dealias_prefixscan_t *p,
					       uint32_t probedefc)
{
  size_t len = probedefc * sizeof(scamper_dealias_probedef_t);
  if((p->probedefs = malloc_zero(len)) != NULL)
    return 0;
  return -1;
}

int scamper_dealias_prefixscan_probedef_add(scamper_dealias_t *dealias,
					    scamper_dealias_probedef_t *def)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  size_t size;

  /* make the probedef array one bigger */
  size = sizeof(scamper_dealias_probedef_t) * (prefixscan->probedefc+1);
  if(realloc_wrap((void **)&prefixscan->probedefs, size) != 0)
    return -1;

  /* add the probedef to the array */
  memcpy(&prefixscan->probedefs[prefixscan->probedefc],
	 def, sizeof(scamper_dealias_probedef_t));

  /* update the probedef with an id, and get references to the addresses */
  def = &prefixscan->probedefs[prefixscan->probedefc];
  def->id = prefixscan->probedefc++;
  scamper_addr_use(def->src);
  scamper_addr_use(def->dst);

  return 0;
}

int scamper_dealias_radargun_fudge(scamper_dealias_t *dealias,
				   scamper_dealias_probedef_t *def,
				   scamper_dealias_probedef_t **defs, int *cnt,
				   int fudge)
{
  scamper_dealias_radargun_t *rg = dealias->data;
  scamper_dealias_probe_t *pr, *pr_a, *pr_b;
  scamper_dealias_reply_t *re, *re_a, *re_b, *re_c;
  dealias_resolv_t *dr = NULL;
  dealias_resolv_t *drd;
  uint32_t pid, x;
  int i, j, k, bs, inseq, d = 0;

  if(dealias->method != SCAMPER_DEALIAS_METHOD_RADARGUN)
    goto err;

  if((dr = malloc_zero(sizeof(dealias_resolv_t) * rg->probedefc)) == NULL)
    goto err;

  for(x=0; x<dealias->probec; x++)
    {
      pr = dealias->probes[x];
      pid = pr->def->id;

      /*
       * if this probedef has already been determined to be useless for
       * alias resolution, skip it
       */
      if(dr[pid].probec < 0)
	continue;

      if(pr->replyc > 1)
	{
	  if(dr[pid].probes != NULL)
	    free(dr[pid].probes);
	  dr[pid].probec = -1;

	  if(pr->def == def)
	    goto done;
	  continue;
	}

      /* total number of probes transmitted */
      dr[pid].probet++;

      if(pr->replyc == 0)
	continue;

      re = pr->replies[0];

      /*
       * with three replies, do some basic checks to see if we should
       * continue considering this probedef.
       */
      if(dr[pid].probec == 2)
	{
	  pr_a = dr[pid].probes[0];
	  pr_b = dr[pid].probes[1];
	  re_a = pr_a->replies[0];
	  re_b = pr_b->replies[0];

	  if((re->ipid == pr->ipid && re_a->ipid == pr_a->ipid &&
	      re_b->ipid == pr_b->ipid) ||
	     (re->ipid == re_a->ipid && re->ipid == re_b->ipid))
	    {
	      free(dr[pid].probes);
	      dr[pid].probec = -1;

	      if(pr->def == def)
		goto done;
	      continue;
	    }
	}

      if(array_insert((void ***)&dr[pid].probes,&dr[pid].probec,pr,NULL) != 0)
	goto err;
    }

  /* figure out if we should byteswap the ipid sequence */
  if(dr[def->id].probec < 3)
    goto done;
  re_a = dr[def->id].probes[0]->replies[0];
  re_b = dr[def->id].probes[1]->replies[0];
  re_c = dr[def->id].probes[2]->replies[0];
  if(re_a->ipid < re_b->ipid)
    i = re_b->ipid - re_a->ipid;
  else
    i = 0x10000 + re_b->ipid - re_a->ipid;
  if(re_b->ipid < re_c->ipid)
    i += re_c->ipid - re_b->ipid;
  else
    i += 0x10000 + re_c->ipid - re_b->ipid;
  if(byteswap16(re_a->ipid) < byteswap16(re_b->ipid))
    j = byteswap16(re_b->ipid) - byteswap16(re_a->ipid);
  else
    j = 0x10000 + byteswap16(re_b->ipid) - byteswap16(re_a->ipid);
  if(byteswap16(re_b->ipid) < byteswap16(re_c->ipid))
    j += byteswap16(re_c->ipid) - byteswap16(re_b->ipid);
  else
    j += 0x10000 + byteswap16(re_c->ipid) - byteswap16(re_b->ipid);
  if(i < j)
    bs = 0;
  else
    bs = 1;

  /* for each probedef, consider if it could be an alias */
  drd = &dr[def->id]; d = 0;
  for(pid=0; pid<rg->probedefc; pid++)
    {
      if(&rg->probedefs[pid] == def || dr[pid].probec < 3)
	continue;

      j = 0; k = 0;

      /* get the first ipid */
      if(timeval_cmp(&drd->probes[j]->tx, &dr[pid].probes[k]->tx) < 0)
	pr_a = drd->probes[j++];
      else
	pr_a = dr[pid].probes[k++];

      for(;;)
	{
	  if(timeval_cmp(&drd->probes[j]->tx, &dr[pid].probes[k]->tx) < 0)
	    pr_b = drd->probes[j++];
	  else
	    pr_b = dr[pid].probes[k++];

	  if((inseq = dealias_fudge_inseq(pr_a, pr_b, bs, fudge)) == 0)
	    break;

	  if(j == drd->probec || k == dr[pid].probec)
	    break;
	}

      /*
       * if the pairs do not appear to have insequence IP-ID values, then
       * abandon
       */
      if(inseq == 0)
	continue;

      defs[d++] = &rg->probedefs[pid];
      if(d == *cnt)
	break;
    }

 done:
  *cnt = d;
  for(x=0; x<rg->probedefc; x++)
    if(dr[x].probec > 0)
      free(dr[x].probes);
  free(dr);
  return 0;

 err:
  if(dr != NULL)
    {
      for(x=0; x<rg->probedefc; x++)
	if(dr[x].probec > 0)
	  free(dr[x].probes);
      free(dr);
    }
  return -1;
}

const char *scamper_dealias_method_tostr(const scamper_dealias_t *d, char *b, size_t l)
{
  static const char *m[] = {
    NULL,
    "mercator",
    "ally",
    "radargun",
    "prefixscan",
    "bump",
  };
  if(d->method > sizeof(m) / sizeof(char *) || m[d->method] == NULL)
    {
      snprintf(b, l, "%d", d->method);
      return b;
    }
  return m[d->method];
}

const char *scamper_dealias_result_tostr(const scamper_dealias_t *d, char *b, size_t l)
{
  static char *t[] = {
    "none",
    "aliases",
    "not-aliases",
    "halted",
    "ipid-echo",
  };
  if(d->result > sizeof(t) / sizeof(char *) || t[d->result] == NULL)
    {
      snprintf(b, l, "%d", d->result);
      return b;
    }
  return t[d->result];
}

void scamper_dealias_free(scamper_dealias_t *dealias)
{
  static void (*const func[])(void *) = {
    dealias_mercator_free,
    dealias_ally_free,
    dealias_radargun_free,
    dealias_prefixscan_free,
    dealias_bump_free,
  };

  uint32_t i;

  if(dealias == NULL)
    return;

  if(dealias->probes != NULL)
    {
      for(i=0; i<dealias->probec; i++)
	{
	  if(dealias->probes[i] != NULL)
	    scamper_dealias_probe_free(dealias->probes[i]);
	}
      free(dealias->probes);
    }

  if(dealias->cycle != NULL) scamper_cycle_free(dealias->cycle);
  if(dealias->list != NULL)  scamper_list_free(dealias->list);

  if(dealias->data != NULL)
    {
      assert(dealias->method != 0);
      assert(dealias->method <= 5);
      func[dealias->method-1](dealias->data);
    }

  free(dealias);
  return;
}

scamper_dealias_t *scamper_dealias_alloc(void)
{
  return (scamper_dealias_t *)malloc_zero(sizeof(scamper_dealias_t));
}
