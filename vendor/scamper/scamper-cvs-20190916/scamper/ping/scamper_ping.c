/*
 * scamper_ping.c
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Author: Matthew Luckie
 *
 * $Id: scamper_ping.c,v 1.35 2019/07/12 23:08:22 mjl Exp $
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
  "$Id: scamper_ping.c,v 1.35 2019/07/12 23:08:22 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_ping.h"

#include "utils.h"

char *scamper_ping_method2str(const scamper_ping_t *ping, char *buf, size_t len)
{
  static char *m[] = {
    "icmp-echo",
    "tcp-ack",
    "tcp-ack-sport",
    "udp",
    "udp-dport",
    "icmp-time",
    "tcp-syn",
    "tcp-synack",
    "tcp-rst",
  };

  if(ping->probe_method > sizeof(m) / sizeof(char *))
    {
      snprintf(buf, len, "%d", ping->probe_method);
      return buf;
    }

  return m[ping->probe_method];
}

int scamper_ping_stats(const scamper_ping_t *ping, scamper_ping_stats_t *stats)
{
  scamper_ping_reply_t *reply;
  uint16_t i;
  uint32_t us;
  double d, sum = 0, diff = 0, rtt;
  int first = 1;
  uint32_t n;

  memset(stats, 0, sizeof(scamper_ping_stats_t));

  for(i=0; i<ping->ping_sent; i++)
    {
      if((reply = ping->ping_replies[i]) == NULL)
	{
	  stats->nloss++;
	  continue;
	}

      stats->nreplies++;
      for(;;)
	{
	  if(first == 0)
	    {
	      if(timeval_cmp(&reply->rtt, &stats->min_rtt) < 0)
		timeval_cpy(&stats->min_rtt, &reply->rtt);
	      if(timeval_cmp(&reply->rtt, &stats->max_rtt) > 0)
		timeval_cpy(&stats->max_rtt, &reply->rtt);
	    }
	  else
	    {
	      timeval_cpy(&stats->min_rtt, &reply->rtt);
	      timeval_cpy(&stats->max_rtt, &reply->rtt);
	      first = 0;
	    }

	  sum += ((reply->rtt.tv_sec * 1000000) + reply->rtt.tv_usec);

	  if(reply->next != NULL)
	    {
	      reply = reply->next;
	      stats->ndups++;
	    }
	  else break;
	}
    }

  n = stats->nreplies + stats->ndups;

  if(n > 0)
    {
      /* compute the average */
      us = (uint32_t)(sum / n);
      stats->avg_rtt.tv_sec  = us / 1000000;
      stats->avg_rtt.tv_usec = us % 1000000;

      /* compute the standard deviation */
      d = (sum / n);
      sum = 0;
      for(i=0; i<ping->ping_sent; i++)
	{
	  for(reply=ping->ping_replies[i]; reply != NULL; reply = reply->next)
	    {
	      rtt = ((reply->rtt.tv_sec * 1000000) + reply->rtt.tv_usec);
	      diff = rtt - d;
	      sum += (diff * diff);
	    }
	}

      us = (uint32_t)sqrt(sum/n);
      stats->stddev_rtt.tv_sec  = us / 1000000;
      stats->stddev_rtt.tv_usec = us % 1000000;
    }

  return 0;
}

int scamper_ping_setdata(scamper_ping_t *ping, uint8_t *bytes, uint16_t len)
{
  uint8_t *dup;

  /* make a duplicate of the pattern bytes before freeing the old pattern */
  if(bytes != NULL && len > 0)
    {
      if((dup = memdup(bytes, len)) == NULL)
	{
	  return -1;
	}
    }
  else
    {
      dup = NULL;
      len = 0;
    }

  /* clear out anything there */
  if(ping->probe_data != NULL)
    {
      free(ping->probe_data);
    }

  /* copy in the new pattern */
  ping->probe_data    = dup;
  ping->probe_datalen = len;

  return 0;
}

scamper_addr_t *scamper_ping_addr(const void *va)
{
  return ((const scamper_ping_t *)va)->dst;
}

scamper_ping_reply_tsreply_t *scamper_ping_reply_tsreply_alloc(void)
{
  return malloc_zero(sizeof(scamper_ping_reply_tsreply_t));
}

void scamper_ping_reply_tsreply_free(scamper_ping_reply_tsreply_t *tsr)
{
  free(tsr);
  return;
}

void scamper_ping_v4ts_free(scamper_ping_v4ts_t *ts)
{
  uint8_t i;

  if(ts == NULL)
    return;

  if(ts->ips != NULL)
    {
      for(i=0; i<ts->ipc; i++)
	if(ts->ips[i] != NULL)
	  scamper_addr_free(ts->ips[i]);
      free(ts->ips);
    }

  free(ts);
  return;
}

scamper_ping_v4ts_t *scamper_ping_v4ts_alloc(uint8_t ipc)
{
  scamper_ping_v4ts_t *ts = NULL;

  if(ipc == 0)
    goto err;

  if((ts = malloc_zero(sizeof(scamper_ping_v4ts_t))) == NULL)
    goto err;
  ts->ipc = ipc;

  if((ts->ips = malloc_zero(sizeof(scamper_addr_t *) * ipc)) == NULL)
    goto err;

  return ts;

 err:
  scamper_ping_v4ts_free(ts);
  return NULL;
}

scamper_ping_t *scamper_ping_alloc()
{
  return (scamper_ping_t *)malloc_zero(sizeof(scamper_ping_t));
}

void scamper_ping_free(scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply, *reply_next;
  uint16_t i;

  if(ping == NULL) return;

  if(ping->ping_replies != NULL)
    {
      for(i=0; i<ping->ping_sent; i++)
	{
	  reply = ping->ping_replies[i];
	  while(reply != NULL)
	    {
	      reply_next = reply->next;
	      scamper_ping_reply_free(reply);
	      reply = reply_next;
	    }
	}
      free(ping->ping_replies);
    }

  if(ping->dst != NULL) scamper_addr_free(ping->dst);
  if(ping->src != NULL) scamper_addr_free(ping->src);

  if(ping->cycle != NULL) scamper_cycle_free(ping->cycle);
  if(ping->list != NULL) scamper_list_free(ping->list);

  if(ping->probe_tsps != NULL) scamper_ping_v4ts_free(ping->probe_tsps);
  if(ping->probe_data != NULL) free(ping->probe_data);

  free(ping);
  return;
}

uint32_t scamper_ping_reply_count(const scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  uint16_t i;
  uint32_t count;

  for(i=0, count=0; i<ping->ping_sent; i++)
    {
      reply = ping->ping_replies[i];

      while(reply != NULL)
	{
	  count++;
	  reply = reply->next;
	}
    }

  return count;
}

int scamper_ping_reply_append(scamper_ping_t *p, scamper_ping_reply_t *reply)
{
  scamper_ping_reply_t *replies;

  if(p == NULL || reply == NULL || reply->probe_id >= p->ping_sent)
    {
      return -1;
    }

  if((replies = p->ping_replies[reply->probe_id]) == NULL)
    {
      p->ping_replies[reply->probe_id] = reply;
    }
  else
    {
      while(replies->next != NULL)
	{
	  replies = replies->next;
	}

      replies->next = reply;
    }

  return 0;
}

int scamper_ping_replies_alloc(scamper_ping_t *ping, int count)
{
  size_t size;

  size = sizeof(scamper_ping_reply_t *) * count;
  if((ping->ping_replies = (scamper_ping_reply_t **)malloc_zero(size)) != NULL)
    {
      return 0;
    }

  return -1;
}

void scamper_ping_reply_v4ts_free(scamper_ping_reply_v4ts_t *ts)
{
  uint8_t i;

  if(ts == NULL)
    return;

  if(ts->tss != NULL)
    free(ts->tss);

  if(ts->ips != NULL)
    {
      for(i=0; i<ts->tsc; i++)
	if(ts->ips[i] != NULL)
	  scamper_addr_free(ts->ips[i]);
      free(ts->ips);
    }

  free(ts);
  return;
}

scamper_ping_reply_v4ts_t *scamper_ping_reply_v4ts_alloc(uint8_t tsc, int ip)
{
  scamper_ping_reply_v4ts_t *ts = NULL;

  if((ts = malloc_zero(sizeof(scamper_ping_reply_v4ts_t))) == NULL)
    goto err;
  ts->tsc = tsc;

  if(tsc > 0)
    {
      if((ts->tss = malloc_zero(sizeof(uint32_t) * tsc)) == NULL)
	goto err;
      if(ip != 0 &&
	 (ts->ips = malloc_zero(sizeof(scamper_addr_t *) * tsc)) == NULL)
	goto err;
    }

  return ts;

 err:
  scamper_ping_reply_v4ts_free(ts);
  return NULL;
}

void scamper_ping_reply_v4rr_free(scamper_ping_reply_v4rr_t *rr)
{
  uint8_t i;

  if(rr == NULL)
    return;

  if(rr->rr != NULL)
    {
      for(i=0; i<rr->rrc; i++)
	if(rr->rr[i] != NULL)
	  scamper_addr_free(rr->rr[i]);
      free(rr->rr);
    }

  free(rr);
  return;
}

scamper_ping_reply_v4rr_t *scamper_ping_reply_v4rr_alloc(uint8_t rrc)
{
  scamper_ping_reply_v4rr_t *rr = NULL;

  if(rrc == 0)
    goto err;

  if((rr = malloc_zero(sizeof(scamper_ping_reply_v4rr_t))) == NULL)
    goto err;
  rr->rrc = rrc;

  if((rr->rr = malloc_zero(sizeof(scamper_addr_t *) * rrc)) == NULL)
    goto err;

  return rr;

 err:
  scamper_ping_reply_v4rr_free(rr);
  return NULL;
}

scamper_ping_reply_t *scamper_ping_reply_alloc(void)
{
  return (scamper_ping_reply_t *)malloc_zero(sizeof(scamper_ping_reply_t));
}

void scamper_ping_reply_free(scamper_ping_reply_t *reply)
{
  if(reply == NULL) return;

  if(reply->addr != NULL)
    scamper_addr_free(reply->addr);

  if(reply->v4rr != NULL)
    scamper_ping_reply_v4rr_free(reply->v4rr);

  if(reply->v4ts != NULL)
    scamper_ping_reply_v4ts_free(reply->v4ts);

  if(reply->tsreply != NULL)
    scamper_ping_reply_tsreply_free(reply->tsreply);

  free(reply);
  return;
}
