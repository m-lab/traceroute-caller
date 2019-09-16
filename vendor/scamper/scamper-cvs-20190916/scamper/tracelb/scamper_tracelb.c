/*
 * scamper_tracelb.c
 *
 * $Id: scamper_tracelb.c,v 1.58 2019/01/13 07:02:07 mjl Exp $
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
 * Copyright (C) 2018-2019 Matthew Luckie
 * Author: Matthew Luckie
 *
 * Load-balancer traceroute technique authored by
 * Brice Augustin, Timur Friedman, Renata Teixeira; "Measuring Load-balanced
 *  Paths in the Internet", in Proc. Internet Measurement Conference 2007.
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
  "$Id: scamper_tracelb.c,v 1.58 2019/01/13 07:02:07 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_tracelb.h"
#include "utils.h"

typedef struct tracelb_fwdpathc
{
  int pathc;
  int pathcc;
  int loop;
} tracelb_fwdpathc_t;

void
scamper_tracelb_probeset_summary_free(scamper_tracelb_probeset_summary_t *sum)
{
  int i;
  if(sum->addrs != NULL)
    {
      for(i=0; i<sum->addrc; i++)
	if(sum->addrs[i] != NULL)
	  scamper_addr_free(sum->addrs[i]);
      free(sum->addrs);
    }
  free(sum);
  return;
}

scamper_tracelb_probeset_summary_t *
scamper_tracelb_probeset_summary_alloc(scamper_tracelb_probeset_t *set)
{
  scamper_tracelb_probeset_summary_t *sum = NULL;
  scamper_tracelb_probe_t *probe;
  scamper_addr_t *addr;
  uint16_t flowid, j;
  int i, x;

  if((sum = malloc_zero(sizeof(scamper_tracelb_probeset_summary_t))) == NULL)
    goto err;

  if(set->probec == 0)
    return sum;

  flowid = set->probes[0]->flowid;
  x = 0;
  for(i=0; i<=set->probec; i++)
    {
      if(i == set->probec)
	{
	  if(x == 0)
	    sum->nullc++;
	  break;
	}

      probe = set->probes[i];
      if(probe->flowid != flowid)
	{
	  /*
	   * if a unique flowid had no response (even with multiple
	   * attempts) then make a note of that.
	   */
	  if(x == 0)
	    sum->nullc++;

	  flowid = probe->flowid;
	  x = 0;
	}

      if(probe->rxc > 0)
	{
	  for(j=0; j<probe->rxc; j++)
	    {
	      addr = probe->rxs[j]->reply_from;
	      if(array_find((void **)sum->addrs, sum->addrc, addr,
			    (array_cmp_t)scamper_addr_cmp) != NULL)
		continue;
	      if(array_insert((void ***)&sum->addrs, &sum->addrc,
			      addr, (array_cmp_t)scamper_addr_cmp) != 0)
		goto err;
	      scamper_addr_use(addr);
	    }
	  x++;
	}
    }

  return sum;

 err:
  if(sum != NULL) scamper_tracelb_probeset_summary_free(sum);
  return NULL;
}

/*
 * scamper_tracelb_node_cmp
 *
 * function to compare two nodes, taking into account the possibility that
 * the quoted ttl field is present and has a value.
 */
int scamper_tracelb_node_cmp(const scamper_tracelb_node_t *a,
			     const scamper_tracelb_node_t *b)
{
  int i;

  if(a->addr == NULL || b->addr == NULL)
    {
      if(a->addr == NULL && b->addr == NULL)
	return 0;
      else if(a->addr == NULL)
	return -1;
      return 1;
    }

  if((i = scamper_addr_human_cmp(a->addr, b->addr)) != 0)
    return i;

  if(SCAMPER_TRACELB_NODE_QTTL(a) == SCAMPER_TRACELB_NODE_QTTL(b))
    {
      if(SCAMPER_TRACELB_NODE_QTTL(a))
	{
	  if(a->q_ttl < b->q_ttl) return -1;
	  if(a->q_ttl > b->q_ttl) return  1;
	}
      return 0;
    }
  else if(SCAMPER_TRACELB_NODE_QTTL(a))
    {
      return -1;
    }
  return 1;
}

/*
 * scamper_tracelb_link_cmp
 *
 * function to compare two links.  the comparison is based on the nodes
 * present in each link.
 */
int scamper_tracelb_link_cmp(const scamper_tracelb_link_t *a,
			     const scamper_tracelb_link_t *b)
{
  int i;

  if(a == b)
    return 0;

  if((i = scamper_tracelb_node_cmp(a->from, b->from)) != 0)
    return i;

  if(a->to != NULL && b->to != NULL)
    return scamper_tracelb_node_cmp(a->to, b->to);

  if(a->to == NULL && b->to == NULL)
    return 0;
  else if(a->to == NULL)
    return 1;
  else
    return -1;
}

/*
 * tracelb_node_link_cmp
 *
 * compare the `to' node of two links.
 * the from node is the same; this function is used to compare a set of links
 * attached to a single node and order them accordingly.
 */
static int tracelb_node_link_cmp(const scamper_tracelb_link_t *a,
				 const scamper_tracelb_link_t *b)
{
  assert(a->from == b->from);
  return scamper_tracelb_node_cmp(a->to, b->to);
}

/*
 * scamper_tracelb_nodes_extract
 *
 * function to extract a set of nodes between two points in the graph.
 */
static void tracelb_nodes_extract(const scamper_tracelb_t *trace,
				  scamper_tracelb_node_t *from,
				  scamper_tracelb_node_t *to,
				  scamper_tracelb_node_t **nodes, int *nodec)
{
  uint16_t i;

  if(array_find((void **)nodes, *nodec, from,
		(array_cmp_t)scamper_tracelb_node_cmp) != NULL)
    return;

  nodes[*nodec] = from;
  *nodec = *nodec + 1;
  array_qsort((void **)nodes, *nodec, (array_cmp_t)scamper_tracelb_node_cmp);

  if(to != NULL && from == to)
    return;

  for(i=0; i<from->linkc; i++)
    {
      tracelb_nodes_extract(trace, from->links[i]->to, to, nodes, nodec);
    }

  return;
}

/*
 * tracelb_nodes_extract
 *
 * recursive function to extract a set of nodes between two points in the
 * graph.
 */
int scamper_tracelb_nodes_extract(const scamper_tracelb_t *trace,
				  scamper_tracelb_node_t *from,
				  scamper_tracelb_node_t *to,
				  scamper_tracelb_node_t **nodes)
{
  int nodec = 0;
  tracelb_nodes_extract(trace, from, to, nodes, &nodec);
  return nodec;
}

/*
 * tracelb_node_index
 *
 * find the corresponding index for a node in the trace.
 */
static int tracelb_node_index(const scamper_tracelb_t *trace,
			      const scamper_tracelb_node_t *node)
{
  uint16_t i;
  for(i=0; i<trace->nodec; i++)
    {
      if(trace->nodes[i] == node)
	return i;
    }
  return -1;
}

int scamper_tracelb_node_convergencepoint(const scamper_tracelb_t *trace,
					  const int *fwdpathc,
					  int from, int *to)
{
  scamper_tracelb_node_t *node;
  int n, nn, rc = -1;
  int *loop;

  /* if there are no forward links, then there is no convergence point */
  if(trace->nodes[from]->linkc == 0)
    {
      *to = -1;
      return 0;
    }

  /*
   * if there is only one forward link, then the convergence point is the
   * next node
   */
  if(trace->nodes[from]->linkc == 1)
    {
      if((n=tracelb_node_index(trace, trace->nodes[from]->links[0]->to)) == -1)
	return -1;
      *to = n;
      return 0;
    }

  /*
   * allocate an array to keep track of which nodes have been visited so
   * far on this exploration
   */
  if((loop = malloc_zero(sizeof(int) * trace->nodec)) == NULL)
    return -1;
  n = nn = from;
  loop[n] = 1;

  for(;;)
    {
      node = trace->nodes[n];

      /* if there is no forward link, then there is no convergence point */
      if(node->linkc == 0)
	{
	  *to = -1; rc = 0;
	  break;
	}

      /* get the index into the node array of the next node to visit */
      if((n = tracelb_node_index(trace, node->links[0]->to)) == -1)
	break;

      /* check for loops (i.e. already visited) */
      if(loop[n] != 0)
	{
	  *to = -1; rc = 0;
	  break;
	}
      loop[n] = 1;

      /*
       * if the path converges here, then return the index into the node array
       * where it converges
       */
      if(fwdpathc[n] >= fwdpathc[nn])
	{
	  *to = n; rc = 0;
	  break;
	}
    }

  free(loop);
  return rc;
}

/*
 * tracelb_fwdpathc
 *
 * recursive function used to help determine how many unique forward
 * paths can be observed at a particular node.
 *
 */
static int tracelb_fwdpathc(const scamper_tracelb_t *trace, int n,
			    tracelb_fwdpathc_t *nodes)
{
  scamper_tracelb_link_t *link;
  scamper_tracelb_node_t *node;
  uint16_t i;
  int nn, c, t;

  if(nodes[n].pathc != 0)
    {
      /*
       * if we have already visited the nodes below this point
       * (non-zero pathc for the current node) then we increment the
       * number of paths observable going forward by the number of
       * unique paths from that point
       */
      nodes[n].pathcc += nodes[n].pathc;

      node = trace->nodes[n];
      for(i=0; i<node->linkc; i++)
	{
	  link = node->links[i];
	  nn = tracelb_node_index(trace, link->to);
	  assert(nn >= 0 && nn < trace->nodec);
	  tracelb_fwdpathc(trace, nn, nodes);
	}
    }
  else if(trace->nodes[n]->linkc > 0)
    {
      /*
       * count the number of unique paths forward from this point by visiting
       * each node forward from this point
       */
      nodes[n].loop = 1;
      c = 0;
      node = trace->nodes[n];
      for(i=0; i<node->linkc; i++)
	{
	  link = node->links[i];

	  /* get the index of the next node */
	  nn = tracelb_node_index(trace, link->to);
	  assert(nn >= 0 && nn < trace->nodec);

	  /* skip over any nodes that would cause us to get into a loop */
	  if(nodes[nn].loop != 0)
	    continue;

	  /* count the number of paths beneath it */
	  t = tracelb_fwdpathc(trace, nn, nodes);
	  assert(t > 0);

	  /* more paths! */
	  c += t;
	}

      /* at the end, we store the number of unique paths with the node */
      nodes[n].pathcc = nodes[n].pathc = c;
      nodes[n].loop = 0;
    }
  else
    {
      /*
       * can't go any further.  the first time this node has been visited.
       * it is part of one unique path so far.
       */
      nodes[n].pathcc = nodes[n].pathc = 1;
    }

  return nodes[n].pathc;
}

/*
 * scamper_tracelb_fwdpathc
 *
 * count the number of unique paths visible from one point towards a
 * destination.
 */
int scamper_tracelb_fwdpathc(const scamper_tracelb_t *trace, int *nodes)
{
  tracelb_fwdpathc_t *fwdpathc;
  uint16_t i;

  if(trace->nodec == 0)
    return 0;

  if((fwdpathc = malloc_zero(sizeof(tracelb_fwdpathc_t)*trace->nodec)) == NULL)
    return -1;

  tracelb_fwdpathc(trace, 0, fwdpathc);
  for(i=0; i<trace->nodec; i++)
    {
      nodes[i] = fwdpathc[i].pathcc;
    }
  free(fwdpathc);

  return 0;
}

scamper_tracelb_node_t *scamper_tracelb_node_alloc(scamper_addr_t *addr)
{
  scamper_tracelb_node_t *node;
  if((node = malloc_zero(sizeof(scamper_tracelb_node_t))) != NULL)
    {
      if(addr != NULL)
	node->addr = scamper_addr_use(addr);
    }
  return node;
}

void scamper_tracelb_node_free(scamper_tracelb_node_t *node)
{
  if(node == NULL)
    return;

  if(node->links != NULL)
    free(node->links);

  if(node->addr != NULL)
    scamper_addr_free(node->addr);

  if(node->name != NULL)
    free(node->name);

  free(node);
  return;
}

int scamper_tracelb_node_add(scamper_tracelb_t *trace,
			     scamper_tracelb_node_t *node)
{
  size_t len = (trace->nodec + 1) * sizeof(scamper_tracelb_node_t *);
  if(realloc_wrap((void **)&trace->nodes, len) == 0)
    {
      trace->nodes[trace->nodec++] = node;
      return 0;
    }

  return -1;
}

scamper_tracelb_node_t *scamper_tracelb_node_find(scamper_tracelb_t *trace,
						  scamper_tracelb_node_t *node)
{
  uint16_t i;

  for(i=0; i<trace->nodec; i++)
    {
      if(trace->nodes[i]->addr == NULL)
	continue;

      if(scamper_tracelb_node_cmp(trace->nodes[i], node) == 0)
	return trace->nodes[i];
    }
  return NULL;
}

scamper_tracelb_reply_t *scamper_tracelb_reply_alloc(scamper_addr_t *addr)
{
  scamper_tracelb_reply_t *reply;

  if((reply = malloc_zero(sizeof(scamper_tracelb_reply_t))) == NULL)
    return NULL;

  if(addr != NULL)
    reply->reply_from = scamper_addr_use(addr);

  return reply;
}

void scamper_tracelb_reply_free(scamper_tracelb_reply_t *reply)
{
  if(reply == NULL)
    return;

  if(reply->reply_from != NULL)
    scamper_addr_free(reply->reply_from);

  if((reply->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) == 0)
    scamper_icmpext_free(reply->reply_icmp_ext);

  free(reply);
  return;
}

scamper_tracelb_probe_t *scamper_tracelb_probe_alloc(void)
{
  scamper_tracelb_probe_t *probe;
  probe = malloc_zero(sizeof(scamper_tracelb_probe_t));
  return probe;
}

void scamper_tracelb_probe_free(scamper_tracelb_probe_t *probe)
{
  uint16_t i;

  if(probe == NULL)
    return;

  if(probe->rxs != NULL)
    {
      for(i=0; i<probe->rxc; i++)
	scamper_tracelb_reply_free(probe->rxs[i]);

      free(probe->rxs);
    }
  free(probe);
  return;
}

int scamper_tracelb_probe_reply(scamper_tracelb_probe_t *probe,
				scamper_tracelb_reply_t *reply)
{
  size_t len;

  /* extend the replies array and store the reply in it */
  len = (probe->rxc + 1) * sizeof(scamper_tracelb_reply_t *);
  if(realloc_wrap((void **)&probe->rxs, len) != 0)
    return -1;
  probe->rxs[probe->rxc++] = reply;
  return 0;
}

int scamper_tracelb_probeset_probes_alloc(scamper_tracelb_probeset_t *set,
					  uint16_t probec)
{
  size_t len = sizeof(scamper_tracelb_probe_t *) * probec;
  if((set->probes = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

int scamper_tracelb_probeset_add(scamper_tracelb_probeset_t *probeset,
				 scamper_tracelb_probe_t *probe)
{
  size_t len = (probeset->probec + 1) * sizeof(scamper_tracelb_probe_t *);
  if(realloc_wrap((void **)&probeset->probes, len) != 0)
    return -1;
  probeset->probes[probeset->probec++] = probe;
  return 0;
}

scamper_tracelb_probeset_t *scamper_tracelb_probeset_alloc(void)
{
  scamper_tracelb_probeset_t *set;
  set = malloc_zero(sizeof(scamper_tracelb_probeset_t));
  return set;
}

void scamper_tracelb_probeset_free(scamper_tracelb_probeset_t *set)
{
  uint16_t i;

  if(set == NULL)
    return;

  if(set->probes != NULL)
    {
      for(i=0; i<set->probec; i++)
	scamper_tracelb_probe_free(set->probes[i]);
      free(set->probes);
    }

  free(set);
  return;
}

scamper_tracelb_link_t *scamper_tracelb_link_find(const scamper_tracelb_t *tr,
						  scamper_tracelb_link_t *link)
{
  return array_find((void **)tr->links, tr->linkc, link,
		    (array_cmp_t)scamper_tracelb_link_cmp);
}

scamper_tracelb_link_t *scamper_tracelb_link_alloc(void)
{
  return (scamper_tracelb_link_t *)malloc_zero(sizeof(scamper_tracelb_link_t));
}

void scamper_tracelb_link_free(scamper_tracelb_link_t *link)
{
  uint8_t i;

  if(link == NULL)
    return;

  if(link->sets != NULL)
    {
      for(i=0; i<link->hopc; i++)
	scamper_tracelb_probeset_free(link->sets[i]);

      free(link->sets);
    }

  free(link);
  return;
}

int scamper_tracelb_link_add(scamper_tracelb_t *trace,
			     scamper_tracelb_link_t *link)
{
  scamper_tracelb_node_t *node = NULL;
  size_t size;
  uint16_t i;

  /*
   * to start with, find the node the link originates from, and add the link
   * to that node
   */
  for(i=0; i<trace->nodec; i++)
    {
      if((node = trace->nodes[i]) == link->from)
	break;
    }
  if(i == trace->nodec)
    return -1;
  assert(node != NULL);

  /* add the link to the node */
  size = sizeof(scamper_tracelb_link_t *) * (node->linkc+1);
  if(realloc_wrap((void **)&node->links, size) == 0)
    {
      node->links[node->linkc++] = link;
      array_qsort((void **)node->links, node->linkc,
		  (array_cmp_t)scamper_tracelb_link_cmp);
    }
  else return -1;

  /* add the link to the set of links held in the trace */
  size = sizeof(scamper_tracelb_link_t *) * (trace->linkc+1);
  if(realloc_wrap((void **)&trace->links, size) == 0)
    {
      trace->links[trace->linkc++] = link;
      array_qsort((void **)trace->links, trace->linkc,
		  (array_cmp_t)scamper_tracelb_link_cmp);
      return 0;
    }
  return -1;
}

/*
 * scamper_tracelb_link_zerottlfwd
 *
 * determine if a link is a case of zero-ttl forwarding.
 */
int scamper_tracelb_link_zerottlfwd(const scamper_tracelb_link_t *link)
{
  if(link->from->addr == NULL)
    return 0;
  if(scamper_addr_cmp(link->from->addr, link->to->addr) != 0)
    return 0;
  if(SCAMPER_TRACELB_NODE_QTTL(link->from) == 0)
    return 0;
  if(SCAMPER_TRACELB_NODE_QTTL(link->to) == 0)
    return 0;
  if(link->from->q_ttl != 0 || link->to->q_ttl != 1)
    return 0;

  return 1;
}

int scamper_tracelb_link_probesets_alloc(scamper_tracelb_link_t *link,
					 uint8_t hopc)
{
  size_t len = hopc * sizeof(scamper_tracelb_probeset_t *);
  if((link->sets = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

int scamper_tracelb_link_probeset(scamper_tracelb_link_t *link,
				  scamper_tracelb_probeset_t *set)
{
  size_t len = (link->hopc + 1) * sizeof(scamper_tracelb_probeset_t *);
  if(realloc_wrap((void **)&link->sets, len) == 0)
    {
      link->sets[link->hopc++] = set;
      return 0;
    }

  return -1;
}

int scamper_tracelb_nodes_alloc(scamper_tracelb_t *trace, uint16_t count)
{
  size_t size = sizeof(scamper_tracelb_node_t *) * count;
  if((trace->nodes = malloc_zero(size)) != NULL)
    return 0;
  return -1;
}

int scamper_tracelb_links_alloc(scamper_tracelb_t *trace, uint16_t count)
{
  size_t size = sizeof(scamper_tracelb_link_t *) * count;
  if((trace->links = malloc_zero(size)) != NULL)
    return 0;
  return -1;
}

int scamper_tracelb_node_links_alloc(scamper_tracelb_node_t *node,
				     uint16_t count)
{
  size_t size = sizeof(scamper_tracelb_link_t *) * count;
  if((node->links = malloc_zero(size)) != NULL)
    return 0;
  return -1;
}

int scamper_tracelb_probe_replies_alloc(scamper_tracelb_probe_t *probe,
					uint16_t count)
{
  size_t size = sizeof(scamper_tracelb_reply_t *) * count;
  if((probe->rxs = malloc_zero(size)) != NULL)
    return 0;
  return -1;
}

void scamper_tracelb_node_links_sort(scamper_tracelb_node_t *node)
{
  array_qsort((void **)node->links, node->linkc,
	      (array_cmp_t)tracelb_node_link_cmp);
  return;
}

scamper_addr_t *scamper_tracelb_addr(const void *va)
{
  return ((scamper_tracelb_t *)va)->dst;
}

const char *scamper_tracelb_type_tostr(const scamper_tracelb_t *trace)
{
  if(trace->type == SCAMPER_TRACELB_TYPE_UDP_DPORT)
    return "udp-dport";
  if(trace->type == SCAMPER_TRACELB_TYPE_ICMP_ECHO)
    return "icmp-echo";
  if(trace->type == SCAMPER_TRACELB_TYPE_UDP_SPORT)
    return "udp-sport";
  if(trace->type == SCAMPER_TRACELB_TYPE_TCP_SPORT)
    return "tcp-sport";
  if(trace->type == SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT)
    return "tcp-ack-sport";
  return NULL;
}

int scamper_tracelb_sort(scamper_tracelb_t *trace)
{
  scamper_tracelb_node_t **nodes = NULL;
  scamper_tracelb_node_t **nq = NULL;
  int i, k, n, q, qt;
  size_t size;
  uint16_t j;

  if(trace->nodec == 0)
    return 0;

  size = sizeof(scamper_tracelb_node_t *) * trace->nodec;
  if((nodes = malloc_zero(size)) == NULL || (nq = malloc_zero(size)) == NULL)
    goto err;

  n = 0;
  q = 0;

  nq[q++] = trace->nodes[0];

  while(q > 0)
    {
      qt = q;

      for(i=0; i<qt; i++)
	{
	  assert(n < trace->nodec);
	  nodes[n++] = nq[i];

	  for(j=0; j<nq[i]->linkc; j++)
	    {
	      for(k=0; k<q; k++)
		{
		  if(nq[i]->links[j]->to == nq[k])
		    break;
		}

	      if(k != q)
		continue;

	      for(k=0; k<n; k++)
		{
		  if(nq[i]->links[j]->to == nodes[k])
		    break;
		}

	      if(k != n)
		continue;

	      assert(q < trace->nodec);
	      nq[q++] = nq[i]->links[j]->to;
	    }
	}

      memmove(nq, nq+qt, (q-qt) * sizeof(scamper_tracelb_node_t *));
      q -= qt;
    }

  assert(n == trace->nodec);
  memcpy(trace->nodes, nodes, trace->nodec*sizeof(scamper_tracelb_node_t *));
  free(nodes);
  free(nq);
  return 0;

 err:
  if(nodes != NULL) free(nodes);
  if(nq != NULL) free(nq);
  return -1;
}

/*
 * scamper_tracelb_free
 *
 */
void scamper_tracelb_free(scamper_tracelb_t *trace)
{
  uint16_t i;

  if(trace == NULL) return;

  if(trace->links != NULL)
    {
      for(i=0; i<trace->linkc; i++)
	scamper_tracelb_link_free(trace->links[i]);
      free(trace->links);
    }

  if(trace->nodes != NULL)
    {
      for(i=0; i<trace->nodec; i++)
	scamper_tracelb_node_free(trace->nodes[i]);
      free(trace->nodes);
    }

  if(trace->dst != NULL) scamper_addr_free(trace->dst);
  if(trace->src != NULL) scamper_addr_free(trace->src);

  if(trace->cycle != NULL) scamper_cycle_free(trace->cycle);
  if(trace->list != NULL) scamper_list_free(trace->list);

  free(trace);
  return;
}

/*
 * scamper_tracelb_alloc
 *
 * allocate the trace and all the possibly necessary data fields
 */
scamper_tracelb_t *scamper_tracelb_alloc()
{
  return (scamper_tracelb_t *)malloc_zero(sizeof(scamper_tracelb_t));
}
