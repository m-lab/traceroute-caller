/*
 * scamper_tracelb_json.c
 *
 * Copyright (C) 2018 Matthew Luckie
 *
 * Authors: Matthew Luckie
 *
 * $Id: scamper_tracelb_json.c,v 1.6 2018/05/27 03:32:14 mjl Exp $
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
  "$Id: scamper_tracelb_json.c,v 1.6 2018/05/27 03:32:14 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tracelb.h"
#include "scamper_file.h"
#include "scamper_file_json.h"
#include "scamper_tracelb_json.h"
#include "utils.h"

typedef struct strlist
{
  char           *str;
  struct strlist *next;
} strlist_t;

static char *header_tostr(const scamper_tracelb_t *trace)
{
  char buf[512], tmp[128];
  size_t off = 0;
  time_t tt = trace->start.tv_sec;

  string_concat(buf, sizeof(buf), &off,
		"\"type\":\"tracelb\", \"version\":\"0.1\"");
  string_concat(buf, sizeof(buf), &off, ", \"userid\":%u", trace->userid);
  string_concat(buf, sizeof(buf), &off, ", \"method\":\"%s\"",
		scamper_tracelb_type_tostr(trace));
  if(trace->src != NULL)
    string_concat(buf, sizeof(buf), &off, ", \"src\":\"%s\"",
		  scamper_addr_tostr(trace->src, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off, ", \"dst\":\"%s\"",
		scamper_addr_tostr(trace->dst, tmp, sizeof(tmp)));
  if(SCAMPER_TRACELB_TYPE_IS_UDP(trace) || SCAMPER_TRACELB_TYPE_IS_TCP(trace))
    string_concat(buf, sizeof(buf), &off, ", \"sport\":%u, \"dport\":%u",
		  trace->sport, trace->dport);
  strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", localtime(&tt));
  string_concat(buf, sizeof(buf), &off,
		", \"start\":{\"sec\":%u, \"usec\":%u, \"ftime\":\"%s\"}",
		trace->start.tv_sec, trace->start.tv_usec, tmp);
  string_concat(buf, sizeof(buf), &off,
		", \"probe_size\":%u, \"firsthop\":%u, \"attempts\":%u",
		trace->probe_size, trace->firsthop, trace->attempts);
  string_concat(buf, sizeof(buf), &off,
		", \"confidence\":%u, \"tos\":%u, \"gaplimit\":%u",
		trace->confidence, trace->tos, trace->gaplimit);
  string_concat(buf, sizeof(buf), &off,
		", \"wait_timeout\":%u, \"wait_probe\":%u",
		trace->wait_timeout, trace->wait_probe * 10);
  string_concat(buf, sizeof(buf), &off,
		", \"probec\":%u, \"probec_max\":%u",
		trace->probec, trace->probec_max);
  string_concat(buf, sizeof(buf), &off,
		", \"nodec\":%u, \"linkc\":%u",
		trace->nodec, trace->linkc);

  return strdup(buf);
}



static char *reply_tostr(const scamper_tracelb_probe_t *probe,
			 const scamper_tracelb_reply_t *reply)
{
  char buf[2048], tmp[256];
  struct timeval rtt;
  size_t off = 0;

  timeval_diff_tv(&rtt, &probe->tx, &reply->reply_rx);
  string_concat(buf, sizeof(buf), &off,
		"{\"rx\":{\"sec\":%u, \"usec\":%u}, \"ttl\":%u, \"rtt\":%s",
		reply->reply_rx.tv_sec, reply->reply_rx.tv_usec,
		reply->reply_ttl, timeval_tostr_us(&rtt, tmp, sizeof(tmp)));

  if(SCAMPER_ADDR_TYPE_IS_IPV4(reply->reply_from))
    string_concat(buf, sizeof(buf), &off, ", \"ipid\":%u", reply->reply_ipid);

  if(SCAMPER_TRACELB_REPLY_IS_TCP(reply))
    {
      string_concat(buf, sizeof(buf), &off, ", \"tcp_flags\":%u",
		    reply->reply_tcp_flags);
    }
  else
    {
      string_concat(buf, sizeof(buf), &off,
		    ", \"icmp_type\":%u, \"icmp_code\":%u, \"icmp_q_tos\":%u",
		    reply->reply_icmp_type, reply->reply_icmp_code,
		    reply->reply_icmp_q_tos);
      if(SCAMPER_TRACELB_REPLY_IS_ICMP_UNREACH(reply) ||
	 SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(reply))
	string_concat(buf, sizeof(buf), &off,
		      ", \"icmp_q_ttl\":%u", reply->reply_icmp_q_ttl);
    }
  string_concat(buf, sizeof(buf), &off, "}");

  return strdup(buf);
}

static char *probe_tostr(const scamper_tracelb_probe_t *probe,
			 const scamper_addr_t *addr)
{
  char buf[256];
  char **rxs = NULL, *dup = NULL;
  size_t off = 0;
  size_t len = 0;
  uint32_t i, j;
  uint16_t rxc = 0;

  for(i=0; i<probe->rxc; i++)
    if(scamper_addr_cmp(addr, probe->rxs[i]->reply_from) == 0)
      rxc++;

  string_concat(buf, sizeof(buf), &off,
		"{\"tx\":{\"sec\":%u, \"usec\":%u}, \"replyc\":%u,"
		" \"ttl\":%u, \"attempt\":%u, \"flowid\":%u",
		probe->tx.tv_sec, probe->tx.tv_usec, rxc,
		probe->ttl, probe->attempt, probe->flowid);

  if(rxc == 0)
    return strdup(buf);

  /* make room for the replies array */
  string_concat(buf, sizeof(buf), &off, ", \"replies\":[");
  len += strlen(buf);

  if((rxs = malloc_zero(rxc * sizeof(char *))) == NULL)
    goto err;
  j = 0;
  for(i=0; i<probe->rxc; i++)
    {
      if(scamper_addr_cmp(addr, probe->rxs[i]->reply_from) != 0)
	continue;
      if(j > 0) len++; /* , */
      if((rxs[j] = reply_tostr(probe, probe->rxs[i])) == NULL)
	goto err;
      len += strlen(rxs[j]);
      j++;
    }
  len++; /* ] */
  len++; /* \'0' */

  if((dup = malloc(len)) == NULL)
    goto err;
  off = 0;

  string_concat(dup, len, &off, buf);
  for(i=0; i<rxc; i++)
    {
      if(i > 0) string_concat(dup, len, &off, ",");
      string_concat(dup, len, &off, "%s", rxs[i]);
      free(rxs[i]);
    }
  free(rxs);
  string_concat(dup, len, &off, "]");
  assert(off+1 == len);

  return dup;

 err:
  if(rxs != NULL)
    {
      for(i=0; i<rxc; i++)
	if(probe->rxs[i] != NULL)
	  free(rxs[i]);
      free(rxs);
    }
  if(dup != NULL) free(dup);
  return NULL;
}

static int strlist_add(strlist_t **tail, char *str, size_t *off)
{
  strlist_t *sl = NULL;

  if((sl = malloc(sizeof(strlist_t))) == NULL)
    return -1;
  sl->next = NULL;
  if((sl->str = strdup(str)) == NULL)
    {
      free(sl);
      return -1;
    }

  if(*tail != NULL)
    (*tail)->next = sl;
  *tail = sl;
  *off += strlen(str);

  return 0;
}

static char *probeset_summary_tojson(scamper_tracelb_probeset_summary_t *sum,
				     scamper_tracelb_probeset_t *set)
{
  scamper_tracelb_probe_t *probe;
  strlist_t *head = NULL, *tail = NULL, *slp, *slpn;
  char buf[128], tmp[64], *dup = NULL;
  size_t off, len = 0;
  int i, j, k;

  if(sum->nullc > 0 && sum->addrc == 0)
    return strdup("{\"addr\":\"*\"}");

  for(i=0; i<sum->addrc; i++)
    {
      off = 0;
      if(i > 0) string_concat(buf, sizeof(buf), &off, ", ");
      string_concat(buf, sizeof(buf), &off, "{\"addr\":\"%s\", \"probes\":[",
		    scamper_addr_tostr(sum->addrs[i], tmp, sizeof(tmp)));
      if(strlist_add(&tail, buf, &len) != 0)
	goto err;
      if(head == NULL)
	head = tail;

      for(j=0; j<set->probec; j++)
	{
	  probe = set->probes[j];
	  for(k=0; k<probe->rxc; k++)
	    if(scamper_addr_cmp(sum->addrs[i], probe->rxs[k]->reply_from) == 0)
	      break;
	  if(k == probe->rxc)
	    continue;
	  dup = probe_tostr(probe, sum->addrs[i]);
	  if(strlist_add(&tail, dup, &len) != 0)
	    goto err;
	  free(dup); dup = NULL;
	}

      if(strlist_add(&tail, "}", &len) != 0)
	goto err;
    }
  if(sum->nullc > 0 && strlist_add(&tail, ", {\"addr\":\"*\"}", &len) != 0)
    goto err;
  len++; /* \0 */

  if((dup = malloc(len)) == NULL)
    goto err;

  off = 0; slp = head;
  while(slp != NULL)
    {
      string_concat(dup, len, &off, "%s", slp->str);
      slpn = slp->next;
      free(slp->str);
      free(slp);
      slp = slpn;
    }

  return dup;

 err:
  slp = head;
  while(slp != NULL)
    {
      slpn = slp->next;
      free(slp->str);
      free(slp);
      slp = slpn;
    }
  if(dup != NULL) free(dup);
  return NULL;
}

static char *node_tostr(const scamper_tracelb_node_t *node)
{
  strlist_t *head = NULL, *tail = NULL, *slp, *slpn;
  scamper_tracelb_probeset_summary_t *sum = NULL;
  scamper_tracelb_probeset_t *set;
  scamper_tracelb_probe_t *probe;
  scamper_tracelb_link_t *link;
  char buf[2048], tmp[128], *dup = NULL;
  size_t off, len = 0;
  int j, k;

  assert(node->linkc >= 1);
  if(node->addr != NULL)
    scamper_addr_tostr(node->addr, tmp, sizeof(tmp));
  else
    snprintf(tmp, sizeof(tmp), "*");
  off = 0;
  string_concat(buf, sizeof(buf), &off, "{\"addr\":\"%s\"", tmp);
  if(SCAMPER_TRACELB_NODE_QTTL(node))
    string_concat(buf, sizeof(buf), &off, ", \"q_ttl\":%u", node->q_ttl);
  string_concat(buf, sizeof(buf), &off, ", \"linkc\":%u", node->linkc);
  string_concat(buf, sizeof(buf), &off, ", \"links\":[");

  if(strlist_add(&tail, buf, &len) != 0)
    goto err;
  head = tail;

  if(node->linkc > 1)
    {
      if(strlist_add(&tail, "[", &len) != 0)
	goto err;

      for(j=0; j<node->linkc; j++)
	{
	  link = node->links[j];
	  scamper_addr_tostr(link->to->addr, tmp, sizeof(tmp));
	  off = 0;
	  if(j > 0) string_concat(buf, sizeof(buf), &off, ",");
	  string_concat(buf, sizeof(buf), &off,
			"{\"addr\":\"%s\", \"probes\":[ ", tmp);
	  if(strlist_add(&tail, buf, &len) != 0)
	    goto err;

	  for(k=0; k<link->sets[0]->probec; k++)
	    {
	      if(k > 0 && strlist_add(&tail, ",", &len) != 0)
		goto err;
	      probe = link->sets[0]->probes[k];
	      dup = probe_tostr(probe, link->to->addr);
	      if(strlist_add(&tail, dup, &len) != 0)
		goto err;
	      free(dup); dup = NULL;
	      if(strlist_add(&tail, "}", &len) != 0)
		goto err;
	    }
	  if(strlist_add(&tail, "]}", &len) != 0)
	    goto err;
	}
      if(strlist_add(&tail, "]", &len) != 0)
	goto err;
    }
  else
    {
      link = node->links[0];
      for(j=0; j<link->hopc-1; j++)
	{
	  set = link->sets[j];
	  if((sum = scamper_tracelb_probeset_summary_alloc(set)) == NULL)
	    return NULL;

	  off = 0;
	  if(j > 0) string_concat(buf, sizeof(buf), &off, ",");
	  string_concat(buf, sizeof(buf), &off, "[");
	  if(strlist_add(&tail, buf, &len) != 0)
	    goto err;
	  if((dup = probeset_summary_tojson(sum, set)) == NULL)
	    goto err;
	  scamper_tracelb_probeset_summary_free(sum); sum = NULL;
	  if(strlist_add(&tail, dup, &len) != 0)
	    goto err;
	  free(dup); dup = NULL;

	  if(strlist_add(&tail, "]", &len) != 0)
	    goto err;
	}
      if(link->hopc > 1 && strlist_add(&tail, ",", &len) != 0)
	goto err;
      if(link->to != NULL)
	{
	  off = 0;
	  string_concat(buf, sizeof(buf), &off,
			"[{\"addr\":\"%s\", \"probes\":[",
			scamper_addr_tostr(link->to->addr, tmp, sizeof(tmp)));
	  if(strlist_add(&tail, buf, &len) != 0)
	    goto err;

	  for(k=0; k<link->sets[link->hopc-1]->probec; k++)
	    {
	      if(k > 0 && strlist_add(&tail, ",", &len) != 0)
		goto err;
	      probe = link->sets[link->hopc-1]->probes[k];
	      dup = probe_tostr(probe, link->to->addr);
	      if(strlist_add(&tail, dup, &len) != 0)
		goto err;
	      free(dup); dup = NULL;
	      if(strlist_add(&tail, "}", &len) != 0)
		goto err;
	    }
	  if(strlist_add(&tail, "]}]", &len) != 0)
	    goto err;
	}
    }

  if(strlist_add(&tail, "]}", &len) != 0)
    goto err;
  len++; /* \0' */

  if((dup = malloc(len)) == NULL)
    goto err;

  off = 0; slp = head;
  while(slp != NULL)
    {
      string_concat(dup, len, &off, slp->str);
      slpn = slp->next;
      free(slp->str);
      free(slp);
      slp = slpn;
    }

  return dup;

 err:
  slp = head;
  while(slp != NULL)
    {
      slpn = slp->next;
      free(slp->str);
      free(slp);
      slp = slpn;
    }
  if(dup != NULL) free(dup);
  if(sum != NULL) scamper_tracelb_probeset_summary_free(sum);
  return NULL;
}

int scamper_file_json_tracelb_write(const scamper_file_t *sf,
				    const scamper_tracelb_t *trace)
{
  char *str = NULL, *header = NULL, **nodes = NULL;
  size_t len, off = 0;
  uint16_t i, nodec;
  int rc = -1;

  if((header = header_tostr(trace)) == NULL)
    goto cleanup;
  len = strlen(header);

  nodec = 0;
  if(trace->nodec > 0)
    {
      len += 12; /* , "nodes":[] */
      if((nodes = malloc_zero(sizeof(char *) * trace->nodec)) == NULL)
	goto cleanup;
      for(i=0; i<trace->nodec; i++)
	{
	  if(trace->nodes[i]->linkc < 1)
	    continue;
	  if((nodes[nodec] = node_tostr(trace->nodes[i])) == NULL)
	    goto cleanup;
	  if(nodec > 0) len++; /* , */
	  len += strlen(nodes[nodec]);
	  nodec++;
	}
    }

  len += 4; /* {}\n\0 */
  if((str = malloc_zero(len)) == NULL)
    goto cleanup;

  string_concat(str, len, &off, "{%s", header);
  if(nodec > 0)
    {
      string_concat(str, len, &off, ", \"nodes\":[");
      for(i=0; i<nodec; i++)
	{
	  if(i > 0) string_concat(str, len, &off, ",");
	  string_concat(str, len, &off, "%s", nodes[i]);
	}
      string_concat(str, len, &off, "]");
    }
  string_concat(str, len, &off, "}\n");
  assert(off+1 == len);

  rc = json_write(sf, str, off);

 cleanup:
  if(nodes != NULL)
    {
      for(i=0; i<nodec; i++)
	if(nodes[i] != NULL)
	  free(nodes[i]);
      free(nodes);
    }
  if(header != NULL) free(header);
  if(str != NULL) free(str);
  return rc;
}
