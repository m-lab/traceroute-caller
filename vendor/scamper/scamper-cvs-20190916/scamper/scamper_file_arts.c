/*
 * scamper_file_arts.c
 *
 * $Id: scamper_file_arts.c,v 1.63 2016/12/09 08:42:51 mjl Exp $
 *
 * code to read the legacy arts data file format into scamper_hop structures.
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
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
  "$Id: scamper_file_arts.c,v 1.63 2016/12/09 08:42:51 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "mjl_splaytree.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "trace/scamper_trace.h"
#include "scamper_file.h"
#include "scamper_file_arts.h"
#include "utils.h"

typedef struct arts_state
{
  int          ispipe;
  splaytree_t *list_tree;
  splaytree_t *cycle_tree;
} arts_state_t;

typedef struct arts_header
{
  uint8_t  ver;
  uint32_t id;
  uint32_t flags;
  uint32_t data_length;
  uint32_t creation;
} arts_header_t;

#define ARTS_MAGIC            0xdfb0
#define ARTS_IP_PATH          0x00003000
#define ARTS_IP_PATH_RTT      0x01

#define ARTS_ATTR_CREATION    2

#define ARTS_FORMAT_UNIXDATE  13

#define ARTS_STOP_NOHALT      0x00
#define ARTS_STOP_ICMPUNREACH 0x01
#define ARTS_STOP_LOOP        0x02
#define ARTS_STOP_GAPLIMIT    0x03

/*
 * arts_read_hdr:
 *
 * read the 20 byte header that is written out before each arts object
 * and parse it into ah
 */
static int arts_read_hdr(const scamper_file_t *sf, arts_header_t *ah)
{
  int      fd = scamper_file_getfd(sf);
  uint8_t  buf[20], *tmp = buf;
  uint32_t junk32;
  uint32_t i, attr_len;
  uint16_t junk16;
  int      ret;
  size_t   rc;

  memset(ah, 0, sizeof(arts_header_t));

  /* read the arts header */
  if((ret = read_wrap(fd, buf, &rc, 20)) != 0)
    {
      /* have we hit the eof? */
      if(ret == -2 && rc == 0)
	{
	  return 0;
	}

      fprintf(stderr, "arts_read_hdr: read %d of 20 bytes\n", (int)rc);
      goto err;
    }

  /* read the magic section of the header */
  memcpy(&junk16, buf, 2);
  if((junk16 = ntohs(junk16)) != ARTS_MAGIC)
    {
      fprintf(stderr, "arts_read_hdr: expected magic 0x%02x got 0x%02x\n",
	      ARTS_MAGIC, junk16);
      goto err;
    }

  /*
   * the arts id field is stored in the upper 28 bits of the 32 bit field.
   * the arts version field takes the lower 4.
   */
  memcpy(&junk32, buf+2, 4);
  junk32  = ntohl(junk32);
  ah->id  = junk32 >> 4;
  ah->ver = junk32 & 0x0f;

  /* arts flags */
  memcpy(&junk32, buf+6, 4);
  ah->flags = ntohl(junk32);

  /* length of data in the arts record */
  memcpy(&junk32, buf+16, 4);
  ah->data_length = ntohl(junk32);

  /* figure out the length of the arts attributes */
  memcpy(&junk32, buf+12, 4);
  attr_len = ntohl(junk32);

  /* allocate a large enough buffer, if necessary */
  if(attr_len > sizeof(buf) && (tmp = malloc_zero(attr_len)) == NULL)
    goto err;

  /* read the arts attributes into a buffer */
  if(attr_len > 0 && (ret = read_wrap(fd, tmp, &rc, attr_len)) != 0)
    {
      goto err;
    }

  /* parse the buffer for recognised arts attributes */
  for(i = 0; i < attr_len; i += junk32)
    {
      /* make sure there is enough left for a complete attribute */
      if(attr_len - i < 8)
	{
	  goto err;
	}

      /* read the type / identifier field */
      memcpy(&junk32, tmp + i, 4); junk32 = ntohl(junk32);

      /* extract the identifier field */
      switch(junk32 >> 8)
	{
	case ARTS_ATTR_CREATION:
	  /* make sure the type of this field is a unix date */
	  if((junk32 & 0xff) != ARTS_FORMAT_UNIXDATE || attr_len - i < 12)
	    {
	      goto err;
	    }
	  memcpy(&junk32, tmp + i + 8, 4);
	  ah->creation = ntohl(junk32);
	  break;
	}

      /* read the length field */
      memcpy(&junk32, tmp + i + 4, 4);
      junk32 = ntohl(junk32);
      if(junk32 < 8 || attr_len - i < junk32)
	{
	  goto err;
	}
    }

  /* free the buffer allocated, if there was one */
  if(tmp != buf) free(tmp);

  return 1;

 err:
  if(tmp != NULL && tmp != buf) free(tmp);
  return -1;
}

static void arts_hop_list_free(scamper_trace_hop_t *head)
{
  scamper_trace_hop_t *hop = head;

  while(hop != NULL)
    {
      head = hop->hop_next;
      scamper_trace_hop_free(hop);
      hop = head;
    }

  return;
}

static scamper_trace_hop_t *arts_hop_reply(scamper_addr_t *addr,
					   uint32_t rtt, uint8_t distance)
{
  scamper_trace_hop_t *hop = scamper_trace_hop_alloc();

  if(hop != NULL)
    {
      hop->hop_addr        = scamper_addr_use(addr);
      hop->hop_flags       = 0;
      hop->hop_probe_id    = 0;
      hop->hop_probe_ttl   = distance;
      hop->hop_probe_size  = 0;
      hop->hop_reply_ttl   = 0;
      hop->hop_reply_size  = 0;
      hop->hop_icmp_type   = ICMP_ECHOREPLY;
      hop->hop_icmp_code   = 0;
      hop->hop_rtt.tv_sec  = rtt / 1000000;
      hop->hop_rtt.tv_usec = rtt % 1000000;
    }

  return hop;
}

static int arts_hop_read(scamper_trace_hop_t *hop, const uint8_t *buf,
			 const arts_header_t *ah)
{
  uint32_t junk32;
  int      i = 0;

  /* set defaults for data items stored with this hop */
  hop->hop_addr        = NULL;
  hop->hop_flags       = 0;
  hop->hop_probe_id    = 0;
  hop->hop_probe_ttl   = buf[i++];
  hop->hop_probe_size  = 0;
  hop->hop_reply_ttl   = 0;
  hop->hop_reply_size  = 0;
  hop->hop_icmp_type   = ICMP_TIMXCEED;
  hop->hop_icmp_code   = ICMP_TIMXCEED_INTRANS;
  hop->hop_rtt.tv_sec  = 0;
  hop->hop_rtt.tv_usec = 0;

  /* read the 1 byte hop number this path entry refers to */
  if(hop->hop_probe_ttl == 0)
    return -1;

  /* the IPv4 address of the hop that responded */
  if((hop->hop_addr = scamper_addr_alloc_ipv4(buf+i)) == NULL)
    return -1;
  i += 4;

  /* arts 1 always stores RTT per hop; arts > 1 conditionally stores it */
  if(ah->ver == 1 || (ah->flags & ARTS_IP_PATH_RTT && ah->ver > 1))
    {
      /* RTT, stored in microseconds */
      memcpy(&junk32, buf+i, 4); i += 4;
      junk32 = ntohl(junk32);
      hop->hop_rtt.tv_sec  = junk32 / 1000000;
      hop->hop_rtt.tv_usec = junk32 % 1000000;

      /* num tries */
      hop->hop_probe_id = buf[i++];
    }

  return i;
}

static scamper_trace_hop_t *arts_hops_read(const arts_header_t *ah,
					   const uint8_t *buf,
					   int count, int *off)
{
  scamper_trace_hop_t *head = NULL, *hop = NULL;
  int i = 0;
  int rc;

  if(count == 0)
    {
      return NULL;
    }

  while(count-- > 0)
    {
      if(hop != NULL)
	{
	  hop->hop_next = scamper_trace_hop_alloc();
	  hop = hop->hop_next;
	}
      else
	{
	  head = hop = scamper_trace_hop_alloc();
	}

      if(hop == NULL)
	  goto err;

      if((rc = arts_hop_read(hop, buf+i, ah)) <= 0)
	goto err;
      i += rc;
    }

  *off += i;

  return head;

 err:
  arts_hop_list_free(head);
  return NULL;
}

static int arts_list_cmp(const scamper_list_t *a, const scamper_list_t *b)
{
  if(a->id < b->id) return -1;
  if(a->id > b->id) return  1;
  return 0;
}

static scamper_list_t *arts_list_get(arts_state_t *state, uint32_t id)
{
  scamper_list_t findme, *list;

  findme.id = id;
  if((list = splaytree_find(state->list_tree, &findme)) == NULL)
    {
      if((list = scamper_list_alloc(id, NULL, NULL, NULL)) == NULL)
	return NULL;

      if(splaytree_insert(state->list_tree, list) == NULL)
	{
	  scamper_list_free(list);
	  return NULL;
	}
    }

  return list;
}

static int arts_cycle_cmp(const scamper_cycle_t *a, const scamper_cycle_t *b)
{
  int i;
  if((i = arts_list_cmp(a->list, b->list)) != 0)
    return i;
  if(a->id < b->id) return -1;
  if(a->id > b->id) return  1;
  return 0;
}

static scamper_cycle_t *arts_cycle_get(arts_state_t *state,
				       scamper_list_t *list, uint32_t id)
{
  scamper_cycle_t findme, *cycle;

  findme.list = list;
  findme.id = id;
  if((cycle = splaytree_find(state->cycle_tree, &findme)) == NULL)
    {
      if((cycle = scamper_cycle_alloc(list)) == NULL)
	return NULL;
      cycle->id = id;

      if(splaytree_insert(state->cycle_tree, cycle) == NULL)
	{
	  scamper_cycle_free(cycle);
	  return NULL;
	}
    }

  return cycle;
}

static scamper_trace_t *arts_read_trace(const scamper_file_t *sf,
					const arts_header_t *ah)
{
  int                  fd = scamper_file_getfd(sf);
  arts_state_t        *state = scamper_file_getstate(sf);
  scamper_trace_t     *trace = NULL;
  uint8_t             *buf = NULL;
  int                  i;
  uint32_t             junk32;
  uint8_t              junk8;
  uint8_t              hop_distance;
  uint8_t              halt_reason;
  uint8_t              halt_reason_data;
  uint8_t              reply_ttl = 0;
  uint32_t             rtt;
  scamper_trace_hop_t *hop, *hops = NULL;
  uint8_t              num_hop_recs;
  uint8_t              max_hop;
  uint8_t              destination_replied;
  size_t               rc;

  if((buf = malloc_zero(ah->data_length)) == NULL)
    {
      fprintf(stderr, "arts_read_trace: malloc %d for trace object failed\n",
	      ah->data_length);
      goto err;
    }

  if(read_wrap(fd, buf, &rc, ah->data_length) != 0)
    {
      fprintf(stderr, "arts_read_trace: read %d expected %d\n", (int)rc,
	      ah->data_length);
      goto err;
    }

  if((trace = scamper_trace_alloc()) == NULL)
    {
      fprintf(stderr, "arts_read_trace: scamper_trace_alloc failed\n");
      goto err;
    }

  trace->start.tv_sec = ah->creation;
  trace->type = SCAMPER_TRACE_TYPE_ICMP_ECHO;
  trace->probe_size = 20 + 8 + 12;

  i = 0;

  if((trace->src = scamper_addr_alloc_ipv4(buf+i)) == NULL)
    goto err;
  i += 4;

  if((trace->dst = scamper_addr_alloc_ipv4(buf+i)) == NULL)
    goto err;
  i += 4;

  if(ah->ver >= 3)
    {
      /* list id */
      memcpy(&junk32, buf+i, 4); i += 4; junk32 = ntohl(junk32);
      if((trace->list = arts_list_get(state, junk32)) == NULL)
	goto err;
      scamper_list_use(trace->list);

      /* cycle id */
      memcpy(&junk32, buf+i, 4); i += 4; junk32 = ntohl(junk32);
      if((trace->cycle = arts_cycle_get(state, trace->list, junk32)) == NULL)
	goto err;
      scamper_cycle_use(trace->cycle);
    }

  /*
   * read the RTT of the last hop
   * arts prior to version 2 stores a timeval struct in the file for
   * recording RTT, which is wasteful
   */
  memcpy(&junk32, buf+i, 4); i += 4;
  rtt = ntohl(junk32);
  if(ah->ver < 2)
    {
      rtt *= 1000000;
      memcpy(&junk32, buf+i, 4); i += 4;
      rtt += ntohl(junk32);
    }

  /*
   * the hop distance field tells us how many hops a packet takes to a
   * destination
   */
  hop_distance = buf[i++];

  /*
   * read the next 8 bit field.  the first bit says if the trace was
   * successful in probing to the end host, and the other 7 bits say
   * how many hops actually responded to a probe.
   */
  junk8 = buf[i++];
  destination_replied = junk8 >> 7;

  if(destination_replied != 0)
    trace->stop_reason = SCAMPER_TRACE_STOP_COMPLETED;
  num_hop_recs = junk8 & 0x7f;

  /*
   * arts versions after 1 (and arts version 1 conditionally) store
   * data that tells us why the trace stopped
   */
  if(ah->ver > 1 || (destination_replied != 0 && ah->ver == 1))
    {
      halt_reason      = buf[i++];
      halt_reason_data = buf[i++];

      switch(halt_reason)
	{
	case ARTS_STOP_NOHALT:
	  trace->stop_reason = SCAMPER_TRACE_STOP_NONE;
	  break;

	case ARTS_STOP_ICMPUNREACH:
	  trace->stop_reason = SCAMPER_TRACE_STOP_UNREACH;
	  break;

	case ARTS_STOP_LOOP:
	  trace->stop_reason = SCAMPER_TRACE_STOP_LOOP;
	  break;

	case ARTS_STOP_GAPLIMIT:
	  trace->stop_reason = SCAMPER_TRACE_STOP_GAPLIMIT;
	  break;
	}

      trace->stop_data = halt_reason_data;
    }

  if(num_hop_recs == 0 && destination_replied == 0)
    {
      free(buf);
      return trace;
    }

  /*
   * arts >= 2 stores the TTL of reply packet from a destination so we
   * can estimate the number of hops on the reverse path
   */
  if(ah->ver >= 2)
    reply_ttl = buf[i++];

  if(num_hop_recs > 0 &&
     (hops = arts_hops_read(ah, buf+i, num_hop_recs, &i)) == NULL)
    {
      fprintf(stderr, "arts_read_trace: arts_hops_read %d failed\n",
	      num_hop_recs);
      goto err;
    }

  if(destination_replied != 0)
    max_hop = hop_distance;
  else
    max_hop = 0;

  /*
   * make a pass through all ArtsIpPathEntry structures.  figure out
   * the largest probe ttl used.  if the trace stopped because an ICMP
   * unreachable was received, then associate the type/code with the last
   * structure read.
   */
  if((hop = hops) != NULL)
    {
      for(;;)
	{
	  if(max_hop < hop->hop_probe_ttl)
	    max_hop = hop->hop_probe_ttl;

	  if(hop->hop_next == NULL)
	    {
	      if(trace->stop_reason == SCAMPER_TRACE_STOP_UNREACH)
		{
		  hop->hop_icmp_type = ICMP_UNREACH;
		  hop->hop_icmp_code = trace->stop_data;
		}
	      break;
	    }

	  hop = hop->hop_next;
	}
    }

  if((uint32_t)i != ah->data_length)
    goto err;
  free(buf); buf = NULL;

  if(max_hop == 0)
    return trace;

  if(scamper_trace_hops_alloc(trace, max_hop) == -1)
    goto err;
  trace->hop_count = max_hop;

  /*
   * now loop through the hops array stored in this procedure
   * and assemble the responses into trace->hops. order them based
   * on the probe's ttl then by attempt
   */
  if(hops != NULL)
    {
      trace->hops[hops->hop_probe_ttl-1] = hop = hops;
      while(hop->hop_next != NULL)
	{
	  if(hop->hop_probe_ttl != hop->hop_next->hop_probe_ttl)
	    {
	      i = hop->hop_next->hop_probe_ttl-1;
	      trace->hops[i] = hop->hop_next;
	      hop->hop_next = NULL;
	      hop = trace->hops[i];
	    }
	  else hop = hop->hop_next;
	}
      hops = NULL;
    }

  if(destination_replied != 0)
    {
      if((hop = arts_hop_reply(trace->dst, rtt, hop_distance)) == NULL)
	goto err;

      if(ah->ver >= 2)
	{
	  hop->hop_reply_ttl = reply_ttl;
	  hop->hop_flags |= SCAMPER_TRACE_HOP_FLAG_REPLY_TTL;
	}

      hop->hop_next = trace->hops[hop->hop_probe_ttl-1];
      trace->hops[hop->hop_probe_ttl-1] = hop;
    }

  return trace;

 err:
  if(hops != NULL) arts_hop_list_free(hops);
  if(trace != NULL) scamper_trace_free(trace);
  if(buf != NULL) free(buf);
  return NULL;
}

static int arts_skip(scamper_file_t *sf, uint32_t bytes)
{
  arts_state_t *state = scamper_file_getstate(sf);
  int fd = scamper_file_getfd(sf);
  uint8_t buf[512];
  size_t len;

  if(state->ispipe == 0)
    {
      if(lseek(fd, bytes, SEEK_CUR) != -1)
	return 0;
      if(errno != ESPIPE)
	return -1;
      state->ispipe = 1;
    }

  while(bytes != 0)
    {
      len = (sizeof(buf) < bytes) ? sizeof(buf) : bytes;
      if(read_wrap(fd, buf, NULL, len) != 0)
	return -1;
      bytes -= len;
    }

  return 0;
}

/*
 * scamper_file_arts_read
 *
 * legacy arts only recognises IPv4 traces
 */
int scamper_file_arts_read(scamper_file_t *sf, scamper_file_filter_t *filter,
			   uint16_t *type, void **data)
{
  arts_header_t ah;
  int           tmp;

  for(;;)
    {
      if((tmp = arts_read_hdr(sf, &ah)) == 0)
	{
	  /* EOF */
	  *data = NULL;
	  break;
	}
      else if(tmp == -1)
	{
	  /* partial record */
	  return -1;
	}

      if(ah.data_length == 0)
	return -1;

      if(ah.id == ARTS_IP_PATH &&
	 scamper_file_filter_isset(filter, SCAMPER_FILE_OBJ_TRACE))
	{
	  if((*data = arts_read_trace(sf, &ah)) == NULL)
	    return -1;
	  *type = SCAMPER_FILE_OBJ_TRACE;
	  return 0;
	}

      /* skip over */
      if(arts_skip(sf, ah.data_length) != 0)
	return -1;
    }

  return 0;
}

int scamper_file_arts_is(const scamper_file_t *sf)
{
  uint16_t magic16;
  int fd = scamper_file_getfd(sf);

  if(lseek(fd, 0, SEEK_SET) == -1)
    return 0;

  if(read_wrap(fd, &magic16, NULL, sizeof(magic16)) != 0)
    return 0;

  if(ntohs(magic16) == ARTS_MAGIC)
    {
      if(lseek(fd, 0, SEEK_SET) == -1)
	return 0;
      return 1;
    }

  return 0;
}

static void arts_state_free(arts_state_t *state)
{
  if(state == NULL)
    return;

  if(state->list_tree != NULL)
    splaytree_free(state->list_tree, (splaytree_free_t)scamper_list_free);
  if(state->cycle_tree != NULL)
    splaytree_free(state->cycle_tree, (splaytree_free_t)scamper_cycle_free);
  free(state);
  return;
}

int scamper_file_arts_init_read(scamper_file_t *sf)
{
  arts_state_t *s;
  if((s = (arts_state_t *)malloc_zero(sizeof(arts_state_t))) == NULL ||
     (s->list_tree=splaytree_alloc((splaytree_cmp_t)arts_list_cmp)) == NULL ||
     (s->cycle_tree=splaytree_alloc((splaytree_cmp_t)arts_cycle_cmp)) == NULL)
    {
      arts_state_free(s);
      return -1;
    }
  scamper_file_setstate(sf, s);
  return 0;
}

void scamper_file_arts_free_state(scamper_file_t *sf)
{
  arts_state_free(scamper_file_getstate(sf));
  return;
}
