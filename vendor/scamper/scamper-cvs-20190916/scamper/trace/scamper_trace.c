/*
 * scamper_trace.c
 *
 * $Id: scamper_trace.c,v 1.96 2019/06/23 05:41:21 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2003-2011 The University of Waikato
 * Copyright (C) 2008      Alistair King
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2019      Matthew Luckie
 *
 * Authors: Matthew Luckie
 *          Doubletree implementation by Alistair King
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
  "$Id: scamper_trace.c,v 1.96 2019/06/23 05:41:21 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_trace.h"
#include "utils.h"

int scamper_trace_pmtud_alloc(scamper_trace_t *trace)
{
  if((trace->pmtud = malloc_zero(sizeof(scamper_trace_pmtud_t))) == NULL)
    return -1;
  return 0;
}

void scamper_trace_pmtud_free(scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop, *hop_next;
  uint8_t u8;

  if(trace->pmtud == NULL)
    return;

  hop = trace->pmtud->hops;
  while(hop != NULL)
    {
      hop_next = hop->hop_next;
      scamper_trace_hop_free(hop);
      hop = hop_next;
    }

  if(trace->pmtud->notes != NULL)
    {
      for(u8=0; u8<trace->pmtud->notec; u8++)
	scamper_trace_pmtud_n_free(trace->pmtud->notes[u8]);
      free(trace->pmtud->notes);
    }

  free(trace->pmtud);
  trace->pmtud = NULL;

  return;
}

int scamper_trace_pmtud_hop_count(const scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  int count = 0;
  if(trace == NULL || trace->pmtud == NULL)
    return -1;
  for(hop = trace->pmtud->hops; hop != NULL; hop = hop->hop_next)
    count++;
  return count;
}

scamper_trace_pmtud_n_t *scamper_trace_pmtud_n_alloc(void)
{
  return malloc_zero(sizeof(scamper_trace_pmtud_n_t));
}

void scamper_trace_pmtud_n_free(scamper_trace_pmtud_n_t *n)
{
  free(n);
  return;
}

int scamper_trace_pmtud_n_alloc_c(scamper_trace_pmtud_t *pmtud, uint8_t count)
{
  size_t len = count * sizeof(scamper_trace_pmtud_n_t *);
  if((pmtud->notes = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

int scamper_trace_pmtud_n_add(scamper_trace_pmtud_t *pmtud,
			      scamper_trace_pmtud_n_t *n)
{
  size_t len = (pmtud->notec + 1) * sizeof(scamper_trace_pmtud_n_t *);
  if(realloc_wrap((void **)&pmtud->notes, len) != 0)
    return -1;
  pmtud->notes[pmtud->notec] = n;
  pmtud->notec++;
  return 0;
}

int scamper_trace_lastditch_hop_count(const scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  int count = 0;
  if(trace == NULL || trace->lastditch == NULL)
    return -1;
  for(hop = trace->lastditch; hop != NULL; hop = hop->hop_next)
    count++;
  return count;
}

int scamper_trace_dtree_alloc(scamper_trace_t *trace)
{
  if((trace->dtree = malloc_zero(sizeof(scamper_trace_dtree_t))) != NULL)
    return 0;
  return -1;
}

void scamper_trace_dtree_free(scamper_trace_t *trace)
{
  uint16_t i;

  if(trace->dtree == NULL)
    return;

  if(trace->dtree->lss_stop != NULL)
    scamper_addr_free(trace->dtree->lss_stop);
  if(trace->dtree->gss_stop != NULL)
    scamper_addr_free(trace->dtree->gss_stop);
  if(trace->dtree->lss != NULL)
    free(trace->dtree->lss);

  if(trace->dtree->gss != NULL)
    {
      for(i=0; i<trace->dtree->gssc; i++)
	if(trace->dtree->gss[i] != NULL)
	  scamper_addr_free(trace->dtree->gss[i]);
      free(trace->dtree->gss);
    }

  free(trace->dtree);
  trace->dtree = NULL;
  return;
}

int scamper_trace_dtree_lss(scamper_trace_t *trace, const char *name)
{
  if(trace->dtree == NULL || (trace->dtree->lss = strdup(name)) == NULL)
    return -1;
  return 0;
}

int scamper_trace_dtree_gss_alloc(scamper_trace_t *trace, uint16_t cnt)
{
  if(trace->dtree == NULL || trace->dtree->gss != NULL)
    return -1;
  if((trace->dtree->gss = malloc_zero(sizeof(scamper_addr_t *) * cnt)) == NULL)
    return -1;
  return 0;
}

scamper_addr_t *scamper_trace_dtree_gss_find(const scamper_trace_t *trace,
                                             const scamper_addr_t *iface)
{
  if(trace->dtree == NULL)
    return NULL;
  return array_find((void **)trace->dtree->gss, trace->dtree->gssc,
                    iface, (array_cmp_t)scamper_addr_cmp);
}

void scamper_trace_dtree_gss_sort(const scamper_trace_t *trace)
{
  array_qsort((void **)trace->dtree->gss, trace->dtree->gssc,
	      (array_cmp_t)scamper_addr_cmp);
  return;
}

int scamper_trace_hops_alloc(scamper_trace_t *trace, const int hops)
{
  size_t size = sizeof(scamper_trace_hop_t *) * hops;
  scamper_trace_hop_t **h;

  if(trace->hops == NULL)
    h = (scamper_trace_hop_t **)malloc_zero(size);
  else
    h = (scamper_trace_hop_t **)realloc(trace->hops, size);

  if(h == NULL)
    return -1;
  
  trace->hops = h;
  return 0;
}

void scamper_trace_hop_free(scamper_trace_hop_t *hop)
{
  if(hop == NULL)
    return;

  scamper_icmpext_free(hop->hop_icmpext);
  scamper_addr_free(hop->hop_addr);
  free(hop);
  return;
}

scamper_trace_hop_t *scamper_trace_hop_alloc()
{
  return malloc_zero(sizeof(struct scamper_trace_hop));
}

int scamper_trace_hop_count(const scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  int hops = 0;
  uint8_t i;

  for(i=0; i<trace->hop_count; i++)
    for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
      hops++;

  return hops;
}

int scamper_trace_hop_addr_cmp(const scamper_trace_hop_t *a,
			       const scamper_trace_hop_t *b)
{
  assert(a != NULL);
  assert(b != NULL);
  return scamper_addr_cmp(a->hop_addr, b->hop_addr);
}

/*
 * scamper_trace_addr
 *
 * return the target address of the traceroute.  the caller doesn't know
 * that this is a trace structure, they merely get passed the address
 * of this function.
 */
scamper_addr_t *scamper_trace_addr(const void *va)
{
  return ((const scamper_trace_t *)va)->dst;
}

const char *scamper_trace_type_tostr(const scamper_trace_t *t, char *b, size_t l)
{
  static const char *m[] = {
    NULL,
    "icmp-echo",
    "udp",
    "tcp",
    "icmp-echo-paris",
    "udp-paris",
    "tcp-ack",
  };
  if(t->type > sizeof(m) / sizeof(char *) || m[t->type] == NULL)
    {
      snprintf(b, l, "%d", t->type);
      return b;
    }
  return m[t->type];
}

const char *scamper_trace_stop_tostr(const scamper_trace_t *t, char *b, size_t l)
{
  static const char *r[] = {
    "NONE",
    "COMPLETED",
    "UNREACH",
    "ICMP",
    "LOOP",
    "GAPLIMIT",
    "ERROR",
    "HOPLIMIT",
    "GSS",
    "HALTED",
  };
  if(t->stop_reason > sizeof(r) / sizeof(char *) || r[t->stop_reason] == NULL)
    {
      snprintf(b, l, "%d", t->stop_reason);
      return b;
    }
  return r[t->stop_reason];
}

/*
 * scamper_trace_probe_headerlen
 *
 * return the length of headers sent on probe packets with this trace
 */
int scamper_trace_probe_headerlen(const scamper_trace_t *trace)
{
  int len;

  switch(trace->dst->type)
    {
    case SCAMPER_ADDR_TYPE_IPV4:
      len = 20;
      break;

    case SCAMPER_ADDR_TYPE_IPV6:
      len = 40;
      break;

    default:
      return -1;
    }

  if(trace->offset > 0)
    return len;

  if(SCAMPER_TRACE_TYPE_IS_UDP(trace))
    len += 8;
  else if(SCAMPER_TRACE_TYPE_IS_ICMP(trace))
    len += (1 + 1 + 2 + 2 + 2);
  else if(SCAMPER_TRACE_TYPE_IS_TCP(trace))
    len += 20;
  else
    return -1;

  return len;
}

uint16_t scamper_trace_pathlength(const scamper_trace_t *trace)
{
  uint16_t i=0, max = 0;
  for(i=0; i != trace->hop_count; i++)
    {
      if(trace->hops[i] != NULL)
	max = i;
    }

  return max;
}

int scamper_trace_iscomplete(const scamper_trace_t *trace)
{
  uint8_t i;

  if(trace->stop_reason != SCAMPER_TRACE_STOP_COMPLETED)
    return 0;

  for(i=trace->firsthop-1; i<trace->hop_count; i++)
    if(trace->hops[i] == NULL)
      return 0;

  return 1;
}

int scamper_trace_dst_cmp(const scamper_trace_t *a, const scamper_trace_t *b)
{
  return scamper_addr_cmp(a->dst, b->dst);
}

/*
 * trace_hop_firstaddr
 *
 */
static int trace_hop_firstaddr(const scamper_trace_t *trace,
			       const scamper_trace_hop_t *hop)
{
  const scamper_trace_hop_t *tmp = trace->hops[hop->hop_probe_ttl-1];

  while(tmp != hop)
    {
      if(scamper_trace_hop_addr_cmp(tmp, hop) == 0)
	return 0;
      tmp = tmp->hop_next;
    }

  return 1;
}

int scamper_trace_loop(const scamper_trace_t *trace, const int n,
		       const scamper_trace_hop_t **a,
		       const scamper_trace_hop_t **b)
{
  const scamper_trace_hop_t *hop, *tmp;
  uint8_t i;
  int j, loopc = 0;

  assert(trace->firsthop != 0);

  if(b != NULL && *b != NULL)
    {
      /* to start with, make sure that the hop supplied is in the trace */
      hop = *b;
      if(hop->hop_probe_ttl >= trace->hop_count)
	{
	  return -1;
	}
      tmp = trace->hops[hop->hop_probe_ttl-1];
      while(tmp != NULL)
	{
	  if(tmp == hop) break;
	  tmp = tmp->hop_next;
	}
      if(tmp == NULL)
	{
	  return -1;
	}

      /* find the next place to consider new hop records */
      i = hop->hop_probe_ttl-1;
      if((hop = hop->hop_next) == NULL)
	{
	  i++;
	}
    }
  else
    {
      i = trace->firsthop;
      hop = NULL;
    }

  while(i<trace->hop_count)
    {
      if(hop == NULL)
	{
	  /* find the next hop record to start with, if necessary */
	  while(i<trace->hop_count)
	    {
	      if((hop = trace->hops[i]) != NULL)
		break;
	      i++;
	    }
	  if(i == trace->hop_count)
	    {
	      return 0;
	    }
	}

      /* the next loop requires hop not be null */
      assert(hop != NULL);

      do
	{
	  /*
	   * if this address was already checked for loops earlier, then
	   * continue with the next hop record
	   */
	  if(trace_hop_firstaddr(trace, hop) == 0)
	    {
	      hop = hop->hop_next;
	      continue;
	    }

	  /* check prior hop records leading up to this hop */
	  for(j=i-1; j>=trace->firsthop-1; j--)
	    {
	      /* check all hop records in this hop */
	      for(tmp = trace->hops[j]; tmp != NULL; tmp = tmp->hop_next)
		{
		  /*
		   * if there's a loop (and this is the first instance of
		   * this address in the list) then a new loop is found.
		   */
		  if(scamper_trace_hop_addr_cmp(tmp, hop) == 0 &&
		     trace_hop_firstaddr(trace, tmp) != 0)
		    {
		      if(++loopc == n)
			{
			  if(a != NULL) *a = tmp;
			  if(b != NULL) *b = hop;
			  return i-j;
			}
		    }
		}
	    }

	  hop = hop->hop_next;
	}
      while(hop != NULL);

      i++;
    }

  return 0;
}

/*
 * scamper_trace_free
 *
 */
void scamper_trace_free(scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop, *hop_next;
  uint8_t i;

  if(trace == NULL) return;

  /* free hop records */
  if(trace->hops != NULL)
    {
      for(i=0; i<trace->hop_count; i++)
	{
	  hop = trace->hops[i];
	  while(hop != NULL)
	    {
	      hop_next = hop->hop_next;
	      scamper_trace_hop_free(hop);
	      hop = hop_next;
	    }
	}
      free(trace->hops);
    }

  /* free lastditch hop records */
  hop = trace->lastditch;
  while(hop != NULL)
    {
      hop_next = hop->hop_next;
      scamper_trace_hop_free(hop);
      hop = hop_next;
    }

  if(trace->payload != NULL) free(trace->payload);

  scamper_trace_pmtud_free(trace);
  scamper_trace_dtree_free(trace);

  if(trace->dst != NULL) scamper_addr_free(trace->dst);
  if(trace->src != NULL) scamper_addr_free(trace->src);
  if(trace->rtr != NULL) scamper_addr_free(trace->rtr);

  if(trace->cycle != NULL) scamper_cycle_free(trace->cycle);
  if(trace->list != NULL) scamper_list_free(trace->list);

  free(trace);
  return;
}

/*
 * scamper_trace_alloc
 *
 * allocate the trace and all the possibly necessary data fields
 */
scamper_trace_t *scamper_trace_alloc()
{
  return (struct scamper_trace *)malloc_zero(sizeof(struct scamper_trace));
}
