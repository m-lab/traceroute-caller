/*
 * scamper_ping_warts.c
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2014 The Regents of the University of California
 * Copyright (C) 2016-2019 Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_ping_warts.c,v 1.18 2019/07/12 23:08:22 mjl Exp $
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
  "$Id: scamper_ping_warts.c,v 1.18 2019/07/12 23:08:22 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_ping.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_ping_warts.h"

#include "mjl_splaytree.h"
#include "utils.h"

/*
 * the optional bits of a ping structure
 */
#define WARTS_PING_LIST_ID         1
#define WARTS_PING_CYCLE_ID        2
#define WARTS_PING_ADDR_SRC_GID    3 /* deprecated */
#define WARTS_PING_ADDR_DST_GID    4 /* deprecated */
#define WARTS_PING_START           5
#define WARTS_PING_STOP_R          6
#define WARTS_PING_STOP_D          7
#define WARTS_PING_DATA_LEN        8
#define WARTS_PING_DATA_BYTES      9
#define WARTS_PING_PROBE_COUNT    10
#define WARTS_PING_PROBE_SIZE     11
#define WARTS_PING_PROBE_WAIT     12
#define WARTS_PING_PROBE_TTL      13
#define WARTS_PING_REPLY_COUNT    14
#define WARTS_PING_PING_SENT      15
#define WARTS_PING_PROBE_METHOD   16
#define WARTS_PING_PROBE_SPORT    17
#define WARTS_PING_PROBE_DPORT    18
#define WARTS_PING_USERID         19
#define WARTS_PING_ADDR_SRC       20
#define WARTS_PING_ADDR_DST       21
#define WARTS_PING_FLAGS8         22
#define WARTS_PING_PROBE_TOS      23
#define WARTS_PING_PROBE_TSPS     24
#define WARTS_PING_PROBE_ICMPSUM  25
#define WARTS_PING_REPLY_PMTU     26
#define WARTS_PING_PROBE_TIMEOUT  27
#define WARTS_PING_PROBE_WAIT_US  28
#define WARTS_PING_PROBE_TCPACK   29
#define WARTS_PING_FLAGS          30
#define WARTS_PING_PROBE_TCPSEQ   31

static const warts_var_t ping_vars[] =
{
  {WARTS_PING_LIST_ID,        4, -1},
  {WARTS_PING_CYCLE_ID,       4, -1},
  {WARTS_PING_ADDR_SRC_GID,   4, -1},
  {WARTS_PING_ADDR_DST_GID,   4, -1},
  {WARTS_PING_START,          8, -1},
  {WARTS_PING_STOP_R,         1, -1},
  {WARTS_PING_STOP_D,         1, -1},
  {WARTS_PING_DATA_LEN,       2, -1},
  {WARTS_PING_DATA_BYTES,    -1, -1},
  {WARTS_PING_PROBE_COUNT,    2, -1},
  {WARTS_PING_PROBE_SIZE,     2, -1},
  {WARTS_PING_PROBE_WAIT,     1, -1},
  {WARTS_PING_PROBE_TTL,      1, -1},
  {WARTS_PING_REPLY_COUNT,    2, -1},
  {WARTS_PING_PING_SENT,      2, -1},
  {WARTS_PING_PROBE_METHOD,   1, -1},
  {WARTS_PING_PROBE_SPORT,    2, -1},
  {WARTS_PING_PROBE_DPORT,    2, -1},
  {WARTS_PING_USERID,         4, -1},
  {WARTS_PING_ADDR_SRC,      -1, -1},
  {WARTS_PING_ADDR_DST,      -1, -1},
  {WARTS_PING_FLAGS8,         1, -1},
  {WARTS_PING_PROBE_TOS,      1, -1},
  {WARTS_PING_PROBE_TSPS,    -1, -1},
  {WARTS_PING_PROBE_ICMPSUM,  2, -1},
  {WARTS_PING_REPLY_PMTU,     2, -1},
  {WARTS_PING_PROBE_TIMEOUT,  1, -1},
  {WARTS_PING_PROBE_WAIT_US,  4, -1},
  {WARTS_PING_PROBE_TCPACK,   4, -1},
  {WARTS_PING_FLAGS,          4, -1},
  {WARTS_PING_PROBE_TCPSEQ,   4, -1},
};
#define ping_vars_mfb WARTS_VAR_MFB(ping_vars)

#define WARTS_PING_REPLY_ADDR_GID        1 /* deprecated */
#define WARTS_PING_REPLY_FLAGS           2
#define WARTS_PING_REPLY_REPLY_TTL       3
#define WARTS_PING_REPLY_REPLY_SIZE      4
#define WARTS_PING_REPLY_ICMP_TC         5
#define WARTS_PING_REPLY_RTT             6
#define WARTS_PING_REPLY_PROBE_ID        7
#define WARTS_PING_REPLY_REPLY_IPID      8
#define WARTS_PING_REPLY_PROBE_IPID      9
#define WARTS_PING_REPLY_REPLY_PROTO     10
#define WARTS_PING_REPLY_TCP_FLAGS       11
#define WARTS_PING_REPLY_ADDR            12
#define WARTS_PING_REPLY_V4RR            13
#define WARTS_PING_REPLY_V4TS            14
#define WARTS_PING_REPLY_REPLY_IPID32    15
#define WARTS_PING_REPLY_TX              16
#define WARTS_PING_REPLY_TSREPLY         17

static const warts_var_t ping_reply_vars[] =
{
  {WARTS_PING_REPLY_ADDR_GID,        4, -1},
  {WARTS_PING_REPLY_FLAGS,           1, -1},
  {WARTS_PING_REPLY_REPLY_TTL,       1, -1},
  {WARTS_PING_REPLY_REPLY_SIZE,      2, -1},
  {WARTS_PING_REPLY_ICMP_TC,         2, -1},
  {WARTS_PING_REPLY_RTT,             4, -1},
  {WARTS_PING_REPLY_PROBE_ID,        2, -1},
  {WARTS_PING_REPLY_REPLY_IPID,      2, -1},
  {WARTS_PING_REPLY_PROBE_IPID,      2, -1},
  {WARTS_PING_REPLY_REPLY_PROTO,     1, -1},
  {WARTS_PING_REPLY_TCP_FLAGS,       1, -1},
  {WARTS_PING_REPLY_ADDR,           -1, -1},
  {WARTS_PING_REPLY_V4RR,           -1, -1},
  {WARTS_PING_REPLY_V4TS,           -1, -1},
  {WARTS_PING_REPLY_REPLY_IPID32,    4, -1},
  {WARTS_PING_REPLY_TX,              8, -1},
  {WARTS_PING_REPLY_TSREPLY,        12, -1},
};
#define ping_reply_vars_mfb WARTS_VAR_MFB(ping_reply_vars)

typedef struct warts_ping_reply
{
  scamper_ping_reply_t *reply;
  uint8_t               flags[WARTS_VAR_MFB(ping_reply_vars)];
  uint16_t              flags_len;
  uint16_t              params_len;
} warts_ping_reply_t;

static void insert_ping_reply_v4rr(uint8_t *buf, uint32_t *off,
				   const uint32_t len,
				   const scamper_ping_reply_v4rr_t *rr,
				   void *param)
{
  uint8_t i;

  assert(len - *off >= 1);
  buf[(*off)++] = rr->rrc;
  for(i=0; i<rr->rrc; i++)
    insert_addr(buf, off, len, rr->rr[i], param);

  return;
}

static int extract_ping_reply_v4rr(const uint8_t *buf, uint32_t *off,
				   const uint32_t len,
				   scamper_ping_reply_v4rr_t **out,
				   void *param)
{
  scamper_addr_t *addr;
  uint8_t i, rrc;

  if(*off >= len || len - *off < 1)
    return -1;

  rrc = buf[(*off)++];

  if((*out = scamper_ping_reply_v4rr_alloc(rrc)) == NULL)
    return -1;

  for(i=0; i<rrc; i++)
    {
      if(extract_addr(buf, off, len, &addr, param) != 0)
	return -1;
      (*out)->rr[i] = addr;
    }

  return 0;
}

static void insert_ping_reply_v4ts(uint8_t *buf, uint32_t *off,
				   const uint32_t len,
				   const scamper_ping_reply_v4ts_t *ts,
				   void *param)
{
  uint8_t i, ipc;

  ipc = (ts->ips != NULL ? ts->tsc : 0);

  assert(len - *off >= 2);
  buf[(*off)++] = ts->tsc;
  buf[(*off)++] = ipc;

  for(i=0; i<ts->tsc; i++)
    insert_uint32(buf, off, len, &ts->tss[i], NULL);

  for(i=0; i<ipc; i++)
    insert_addr(buf, off, len, ts->ips[i], param);

  return;
}

static int extract_ping_reply_v4ts(const uint8_t *buf, uint32_t *off,
				   const uint32_t len,
				   scamper_ping_reply_v4ts_t **out,
				   void *param)
{
  scamper_addr_t *addr;
  uint8_t i, tsc, ipc;
  uint32_t u32;

  if(*off >= len || len - *off < 2)
    return -1;

  /*
   * the v4ts structure will have timestamps, and sometimes IP
   * addresses.  if there are IP addresses, the number must match the
   * number of timestamp records.  the second parameter to
   * scamper_ping_reply_v4ts_alloc is a binary flag that says whether
   * or not to allocate the same number of IP addresses.  this is
   * probably a design oversight in the warts records.
   */
  tsc = buf[(*off)++];
  ipc = buf[(*off)++];
  if(ipc != 0 && ipc != tsc)
    return -1;
  if((*out = scamper_ping_reply_v4ts_alloc(tsc, ipc != 0 ? 1 : 0)) == NULL)
    return -1;

  for(i=0; i<tsc; i++)
    {
      if(extract_uint32(buf, off, len, &u32, NULL) != 0)
	return -1;
      (*out)->tss[i] = u32;
    }

  for(i=0; i<ipc; i++)
    {
      if(extract_addr(buf, off, len, &addr, param) != 0)
	return -1;
      (*out)->ips[i] = addr;
    }

  return 0;
}

static void insert_ping_reply_tsreply(uint8_t *buf, uint32_t *off,
				      const uint32_t len,
				      const scamper_ping_reply_tsreply_t *ts,
				      void *param)
{
  insert_uint32(buf, off, len, &ts->tso, NULL);
  insert_uint32(buf, off, len, &ts->tsr, NULL);
  insert_uint32(buf, off, len, &ts->tst, NULL);
  return;
}

static int extract_ping_reply_tsreply(uint8_t *buf, uint32_t *off,
				      const uint32_t len,
				      scamper_ping_reply_tsreply_t **out,
				      void *param)
{
  scamper_ping_reply_tsreply_t *tsreply;
  if(*off >= len || len - *off < 12)
    return -1;
  if((tsreply = scamper_ping_reply_tsreply_alloc()) == NULL)
    return -1;
  extract_uint32(buf, off, len, &tsreply->tso, NULL);
  extract_uint32(buf, off, len, &tsreply->tsr, NULL);
  extract_uint32(buf, off, len, &tsreply->tst, NULL);
  *out = tsreply;
  return 0;
}

static void warts_ping_reply_params(const scamper_ping_t *ping,
				    const scamper_ping_reply_t *reply,
				    warts_addrtable_t *table,
				    uint8_t *flags, uint16_t *flags_len,
				    uint16_t *params_len)
{
  const warts_var_t *var;
  int i, j, max_id = 0;

  /* unset all the flags possible */
  memset(flags, 0, ping_reply_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(ping_reply_vars)/sizeof(warts_var_t); i++)
    {
      var = &ping_reply_vars[i];

      if(var->id == WARTS_PING_REPLY_ADDR_GID ||
	 (var->id == WARTS_PING_REPLY_ADDR && reply->addr == NULL) ||
	 (var->id == WARTS_PING_REPLY_FLAGS && reply->flags == 0) ||
	 (var->id == WARTS_PING_REPLY_REPLY_PROTO &&
	  SCAMPER_PING_METHOD_IS_ICMP(ping)) ||
	 (var->id == WARTS_PING_REPLY_REPLY_TTL &&
	  (reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_TTL) == 0) ||
	 (var->id == WARTS_PING_REPLY_REPLY_IPID &&
	  SCAMPER_ADDR_TYPE_IS_IPV4(ping->dst) &&
	  (reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID) == 0) ||
	 (var->id == WARTS_PING_REPLY_REPLY_IPID32 &&
	  SCAMPER_ADDR_TYPE_IS_IPV6(ping->dst) &&
	  (reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID) == 0) ||
	 (var->id == WARTS_PING_REPLY_PROBE_IPID &&
	  SCAMPER_ADDR_TYPE_IS_IPV4(ping->dst) &&
	  (reply->flags & SCAMPER_PING_REPLY_FLAG_PROBE_IPID) == 0) ||
	 (var->id == WARTS_PING_REPLY_ICMP_TC &&
	  SCAMPER_PING_REPLY_IS_ICMP(reply) == 0) ||
	 (var->id == WARTS_PING_REPLY_TCP_FLAGS &&
	  SCAMPER_PING_REPLY_IS_TCP(reply) == 0) ||
	 (var->id == WARTS_PING_REPLY_V4RR && reply->v4rr == NULL) ||
	 (var->id == WARTS_PING_REPLY_V4TS && reply->v4ts == NULL) ||
	 (var->id == WARTS_PING_REPLY_TX && reply->tx.tv_sec == 0) ||
	 (var->id == WARTS_PING_REPLY_TSREPLY && reply->tsreply == NULL))
	{
	  continue;
	}

      flag_set(flags, var->id, &max_id);

      if(var->id == WARTS_PING_REPLY_ADDR)
	{
	  *params_len += warts_addr_size(table, reply->addr);
	}
      else if(var->id == WARTS_PING_REPLY_V4RR)
	{
	  *params_len += 1;
	  for(j=0; j<reply->v4rr->rrc; j++)
	    *params_len += warts_addr_size(table, reply->v4rr->rr[j]);
	}
      else if(var->id == WARTS_PING_REPLY_V4TS)
	{
	  assert(reply->v4ts != NULL);
	  *params_len += 2; /* one byte tsc, one byte count of v4ts->ips */
	  *params_len += (reply->v4ts->tsc * 4);
	  if(reply->v4ts->ips != NULL)
	    for(j=0; j<reply->v4ts->tsc; j++)
	      *params_len += warts_addr_size(table, reply->v4ts->ips[j]);
	}
      else
	{
	  assert(var->size >= 0);
	  *params_len += var->size;
	}
    }

  *flags_len = fold_flags(flags, max_id);

  return;
}

static int warts_ping_reply_state(const scamper_file_t *sf,
				  const scamper_ping_t *ping,
				  scamper_ping_reply_t *reply,
				  warts_ping_reply_t *state,
				  warts_addrtable_t *table,
				  uint32_t *len)
{
  warts_ping_reply_params(ping, reply, table, state->flags,
			  &state->flags_len, &state->params_len);

  state->reply = reply;

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int extract_ping_reply_icmptc(const uint8_t *buf, uint32_t *off,
				     uint32_t len, scamper_ping_reply_t *reply,
				     void *param)
{
  if(*off >= len || len - *off < 2)
    return -1;

  reply->icmp_type = buf[(*off)++];
  reply->icmp_code = buf[(*off)++];
  return 0;
}

static void insert_ping_reply_icmptc(uint8_t *buf, uint32_t *off,
				     const uint32_t len,
				     const scamper_ping_reply_t *reply,
				     void *param)
{
  assert(len - *off >= 2);

  buf[(*off)++] = reply->icmp_type;
  buf[(*off)++] = reply->icmp_code;

  return;
}

static int warts_ping_reply_read(const scamper_ping_t *ping,
				 scamper_ping_reply_t *reply,
				 warts_state_t *state,
				 warts_addrtable_t *table, const uint8_t *buf,
				 uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&reply->addr,            (wpr_t)extract_addr_gid,             state},
    {&reply->flags,           (wpr_t)extract_byte,                 NULL},
    {&reply->reply_ttl,       (wpr_t)extract_byte,                 NULL},
    {&reply->reply_size,      (wpr_t)extract_uint16,               NULL},
    {reply,                   (wpr_t)extract_ping_reply_icmptc,    NULL},
    {&reply->rtt,             (wpr_t)extract_rtt,                  NULL},
    {&reply->probe_id,        (wpr_t)extract_uint16,               NULL},
    {&reply->reply_ipid,      (wpr_t)extract_uint16,               NULL},
    {&reply->probe_ipid,      (wpr_t)extract_uint16,               NULL},
    {&reply->reply_proto,     (wpr_t)extract_byte,                 NULL},
    {&reply->tcp_flags,       (wpr_t)extract_byte,                 NULL},
    {&reply->addr,            (wpr_t)extract_addr,                 table},
    {&reply->v4rr,            (wpr_t)extract_ping_reply_v4rr,      table},
    {&reply->v4ts,            (wpr_t)extract_ping_reply_v4ts,      table},
    {&reply->reply_ipid32,    (wpr_t)extract_uint32,               NULL},
    {&reply->tx,              (wpr_t)extract_timeval,              NULL},
    {&reply->tsreply,         (wpr_t)extract_ping_reply_tsreply,   NULL},
  };
  const int handler_cnt = sizeof(handlers) / sizeof(warts_param_reader_t);
  uint32_t o = *off;
  int i;

  if((i = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0)
    return i;

  if(reply->addr == NULL)
    return -1;

  /*
   * some earlier versions of the ping reply structure did not include
   * the reply protocol field.  fill it with something valid.
   */
  if(flag_isset(&buf[o], WARTS_PING_REPLY_REPLY_PROTO) == 0)
    {
      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	reply->reply_proto = IPPROTO_ICMP;
      else
	reply->reply_proto = IPPROTO_ICMPV6;
    }

  return 0;
}

static void warts_ping_reply_write(const warts_ping_reply_t *state,
				   warts_addrtable_t *table,
				   uint8_t *buf, uint32_t *off, uint32_t len)
{
  scamper_ping_reply_t *reply = state->reply;

  warts_param_writer_t handlers[] = {
    {NULL,                    NULL,                                 NULL},
    {&reply->flags,           (wpw_t)insert_byte,                   NULL},
    {&reply->reply_ttl,       (wpw_t)insert_byte,                   NULL},
    {&reply->reply_size,      (wpw_t)insert_uint16,                 NULL},
    {reply,                   (wpw_t)insert_ping_reply_icmptc,      NULL},
    {&reply->rtt,             (wpw_t)insert_rtt,                    NULL},
    {&reply->probe_id,        (wpw_t)insert_uint16,                 NULL},
    {&reply->reply_ipid,      (wpw_t)insert_uint16,                 NULL},
    {&reply->probe_ipid,      (wpw_t)insert_uint16,                 NULL},
    {&reply->reply_proto,     (wpw_t)insert_byte,                   NULL},
    {&reply->tcp_flags,       (wpw_t)insert_byte,                   NULL},
    {reply->addr,             (wpw_t)insert_addr,                   table},
    {reply->v4rr,             (wpw_t)insert_ping_reply_v4rr,        table},
    {reply->v4ts,             (wpw_t)insert_ping_reply_v4ts,        table},
    {&reply->reply_ipid32,    (wpw_t)insert_uint32,                 NULL},
    {&reply->tx,              (wpw_t)insert_timeval,                NULL},
    {reply->tsreply,          (wpw_t)insert_ping_reply_tsreply,     NULL},
  };
  const int handler_cnt = sizeof(handlers) / sizeof(warts_param_writer_t);

  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static void warts_ping_params(const scamper_ping_t *ping,
			      warts_addrtable_t *table, uint8_t *flags,
			      uint16_t *flags_len, uint16_t *params_len)
{
  const warts_var_t *var;
  int i, j, max_id = 0;

  /* unset all the flags possible */
  memset(flags, 0, ping_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(ping_vars)/sizeof(warts_var_t); i++)
    {
      var = &ping_vars[i];

      if(var->id == WARTS_PING_ADDR_SRC_GID ||
	 var->id == WARTS_PING_ADDR_DST_GID ||
	 (var->id == WARTS_PING_ADDR_SRC      && ping->src == NULL) ||
	 (var->id == WARTS_PING_ADDR_DST      && ping->dst == NULL) ||
	 (var->id == WARTS_PING_LIST_ID       && ping->list == NULL) ||
	 (var->id == WARTS_PING_CYCLE_ID      && ping->cycle == NULL) ||
	 (var->id == WARTS_PING_USERID        && ping->userid == 0) ||
	 (var->id == WARTS_PING_DATA_LEN      && ping->probe_datalen == 0) ||
	 (var->id == WARTS_PING_PROBE_METHOD  && ping->probe_method == 0) ||
	 (var->id == WARTS_PING_PROBE_TOS     && ping->probe_tos == 0) ||
	 (var->id == WARTS_PING_PROBE_SPORT   && ping->probe_sport == 0) ||
	 (var->id == WARTS_PING_PROBE_DPORT   && ping->probe_dport == 0) ||
	 (var->id == WARTS_PING_FLAGS8        && (ping->flags & 0xFF) == 0) ||
	 (var->id == WARTS_PING_FLAGS         && (ping->flags & ~0xFF) == 0) ||
	 (var->id == WARTS_PING_REPLY_PMTU    && ping->reply_pmtu == 0) ||
	 (var->id == WARTS_PING_PROBE_TIMEOUT && ping->probe_timeout == ping->probe_wait) ||
	 (var->id == WARTS_PING_PROBE_WAIT_US && ping->probe_wait_us == 0) ||
	 (var->id == WARTS_PING_PROBE_TCPACK  && ping->probe_tcpack == 0) ||
	 (var->id == WARTS_PING_PROBE_TCPSEQ  && ping->probe_tcpseq == 0))
	{
	  continue;
	}

      if(var->id == WARTS_PING_PROBE_ICMPSUM)
	{
	  if(ping->probe_icmpsum == 0 ||
	     (ping->flags & SCAMPER_PING_FLAG_ICMPSUM) == 0)
	    continue;
	}

      if(var->id == WARTS_PING_DATA_BYTES)
	{
	  if(ping->probe_datalen != 0)
	    {
	      flag_set(flags, WARTS_PING_DATA_BYTES, &max_id);
	      *params_len += ping->probe_datalen;
	    }
	  continue;
	}

      if(var->id == WARTS_PING_PROBE_TSPS)
	{
	  if(ping->probe_tsps != NULL)
	    {
	      flag_set(flags, WARTS_PING_PROBE_TSPS, &max_id);
	      *params_len += 1;
	      for(j=0; j<ping->probe_tsps->ipc; j++)
		*params_len += warts_addr_size(table,ping->probe_tsps->ips[j]);
	    }
	  continue;
	}

      flag_set(flags, var->id, &max_id);

      if(var->id == WARTS_PING_ADDR_SRC)
	{
	  *params_len += warts_addr_size(table, ping->src);
	  continue;
	}
      else if(var->id == WARTS_PING_ADDR_DST)
	{
	  *params_len += warts_addr_size(table, ping->dst);
	  continue;
	}

      assert(var->size >= 0);
      *params_len += var->size;
    }

  *flags_len = fold_flags(flags, max_id);

  return;
}

static void insert_ping_probe_tsps(uint8_t *buf, uint32_t *off,
				   const uint32_t len,
				   const scamper_ping_v4ts_t *ts, void *param)
{
  uint8_t i;

  assert(len - *off >= 1);
  buf[(*off)++] = ts->ipc;
  for(i=0; i<ts->ipc; i++)
    insert_addr(buf, off, len, ts->ips[i], param);

  return;
}

static int extract_ping_probe_tsps(const uint8_t *buf, uint32_t *off,
				   const uint32_t len,
				   scamper_ping_v4ts_t **out, void *param)
{
  scamper_addr_t *addr;
  uint8_t i, ipc;

  /* make sure there is room for the ip count */
  if(*off >= len || len - *off < 1)
    return -1;

  ipc = buf[(*off)++];

  if((*out = scamper_ping_v4ts_alloc(ipc)) == NULL)
    return -1;

  for(i=0; i<ipc; i++)
    {
      if(extract_addr(buf, off, len, &addr, param) != 0)
	return -1;
      (*out)->ips[i] = addr;
    }

  return 0;
}

static int warts_ping_params_read(scamper_ping_t *ping, warts_state_t *state,
				  warts_addrtable_t *table,
				  uint8_t *buf, uint32_t *off, uint32_t len)
{
  uint8_t flags8 = 0;
  warts_param_reader_t handlers[] = {
    {&ping->list,          (wpr_t)extract_list,            state},
    {&ping->cycle,         (wpr_t)extract_cycle,           state},
    {&ping->src,           (wpr_t)extract_addr_gid,        state},
    {&ping->dst,           (wpr_t)extract_addr_gid,        state},
    {&ping->start,         (wpr_t)extract_timeval,         NULL},
    {&ping->stop_reason,   (wpr_t)extract_byte,            NULL},
    {&ping->stop_data,     (wpr_t)extract_byte,            NULL},
    {&ping->probe_datalen, (wpr_t)extract_uint16,          NULL},
    {&ping->probe_data,    (wpr_t)extract_bytes_alloc,   &ping->probe_datalen},
    {&ping->probe_count,   (wpr_t)extract_uint16,          NULL},
    {&ping->probe_size,    (wpr_t)extract_uint16,          NULL},
    {&ping->probe_wait,    (wpr_t)extract_byte,            NULL},
    {&ping->probe_ttl,     (wpr_t)extract_byte,            NULL},
    {&ping->reply_count,   (wpr_t)extract_uint16,          NULL},
    {&ping->ping_sent,     (wpr_t)extract_uint16,          NULL},
    {&ping->probe_method,  (wpr_t)extract_byte,            NULL},
    {&ping->probe_sport,   (wpr_t)extract_uint16,          NULL},
    {&ping->probe_dport,   (wpr_t)extract_uint16,          NULL},
    {&ping->userid,        (wpr_t)extract_uint32,          NULL},
    {&ping->src,           (wpr_t)extract_addr,            table},
    {&ping->dst,           (wpr_t)extract_addr,            table},
    {&flags8,              (wpr_t)extract_byte,            NULL},
    {&ping->probe_tos,     (wpr_t)extract_byte,            NULL},
    {&ping->probe_tsps,    (wpr_t)extract_ping_probe_tsps, table},
    {&ping->probe_icmpsum, (wpr_t)extract_uint16,          NULL},
    {&ping->reply_pmtu,    (wpr_t)extract_uint16,          NULL},
    {&ping->probe_timeout, (wpr_t)extract_byte,            NULL},
    {&ping->probe_wait_us, (wpr_t)extract_uint32,          NULL},
    {&ping->probe_tcpack,  (wpr_t)extract_uint32,          NULL},
    {&ping->flags,         (wpr_t)extract_uint32,          NULL},
    {&ping->probe_tcpseq,  (wpr_t)extract_uint32,          NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  uint32_t o = *off;
  int rc;

  if((rc = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0)
    return rc;
  if(ping->src == NULL || ping->dst == NULL)
    return -1;
  if(flag_isset(&buf[o], WARTS_PING_PROBE_TIMEOUT) == 0)
    ping->probe_timeout = ping->probe_wait;
  if(flag_isset(&buf[o], WARTS_PING_FLAGS) == 0 &&
     flag_isset(&buf[o], WARTS_PING_FLAGS8) != 0)
    ping->flags = flags8;
  return 0;
}

static int warts_ping_params_write(const scamper_ping_t *ping,
				   const scamper_file_t *sf,
				   warts_addrtable_t *table,
				   uint8_t *buf, uint32_t *off,
				   const uint32_t len,
				   const uint8_t *flags,
				   const uint16_t flags_len,
				   const uint16_t params_len)
{
  uint32_t list_id, cycle_id;
  uint16_t pad_len = ping->probe_datalen;
  uint8_t flags8 = ping->flags & 0xFF;
  warts_param_writer_t handlers[] = {
    {&list_id,             (wpw_t)insert_uint32,          NULL},
    {&cycle_id,            (wpw_t)insert_uint32,          NULL},
    {NULL,                 NULL,                          NULL},
    {NULL,                 NULL,                          NULL},
    {&ping->start,         (wpw_t)insert_timeval,         NULL},
    {&ping->stop_reason,   (wpw_t)insert_byte,            NULL},
    {&ping->stop_data,     (wpw_t)insert_byte,            NULL},
    {&ping->probe_datalen, (wpw_t)insert_uint16,          NULL},
    {ping->probe_data,     (wpw_t)insert_bytes_uint16,    &pad_len},
    {&ping->probe_count,   (wpw_t)insert_uint16,          NULL},
    {&ping->probe_size,    (wpw_t)insert_uint16,          NULL},
    {&ping->probe_wait,    (wpw_t)insert_byte,            NULL},
    {&ping->probe_ttl,     (wpw_t)insert_byte,            NULL},
    {&ping->reply_count,   (wpw_t)insert_uint16,          NULL},
    {&ping->ping_sent,     (wpw_t)insert_uint16,          NULL},
    {&ping->probe_method,  (wpw_t)insert_byte,            NULL},
    {&ping->probe_sport,   (wpw_t)insert_uint16,          NULL},
    {&ping->probe_dport,   (wpw_t)insert_uint16,          NULL},
    {&ping->userid,        (wpw_t)insert_uint32,          NULL},
    {ping->src,            (wpw_t)insert_addr,            table},
    {ping->dst,            (wpw_t)insert_addr,            table},
    {&flags8,              (wpw_t)insert_byte,            NULL},
    {&ping->probe_tos,     (wpw_t)insert_byte,            NULL},
    {ping->probe_tsps,     (wpw_t)insert_ping_probe_tsps, table},
    {&ping->probe_icmpsum, (wpw_t)insert_uint16,          NULL},
    {&ping->reply_pmtu,    (wpw_t)insert_uint16,          NULL},
    {&ping->probe_timeout, (wpw_t)insert_byte,            NULL},
    {&ping->probe_wait_us, (wpw_t)insert_uint32,          NULL},
    {&ping->probe_tcpack,  (wpw_t)insert_uint32,          NULL},
    {&ping->flags,         (wpw_t)insert_uint32,          NULL},
    {&ping->probe_tcpseq,  (wpw_t)insert_uint32,          NULL},
  };

  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  ping->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, ping->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return 0;
}

int scamper_file_warts_ping_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_ping_t **ping_out)
{
  warts_state_t *state = scamper_file_getstate(sf);
  scamper_ping_t *ping = NULL;
  uint8_t *buf = NULL;
  uint32_t off = 0;
  uint16_t i;
  scamper_ping_reply_t *reply;
  uint16_t reply_count;
  warts_addrtable_t *table = NULL;

  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      *ping_out = NULL;
      return 0;
    }

  if((ping = scamper_ping_alloc()) == NULL)
    {
      goto err;
    }

  if((table = warts_addrtable_alloc_byid()) == NULL)
    goto err;

  if(warts_ping_params_read(ping, state, table, buf, &off, hdr->len) != 0)
    {
      goto err;
    }

  /* determine how many replies to read */
  if(extract_uint16(buf, &off, hdr->len, &reply_count, NULL) != 0)
    {
      goto err;
    }

  /* allocate the ping_replies array */
  if(scamper_ping_replies_alloc(ping, ping->ping_sent) != 0)
    {
      goto err;
    }

  /* if there are no replies, then we are done */
  if(reply_count == 0)
    {
      goto done;
    }

  /* for each reply, read it and insert it into the ping structure */
  for(i=0; i<reply_count; i++)
    {
      if((reply = scamper_ping_reply_alloc()) == NULL)
	{
	  goto err;
	}

      if(warts_ping_reply_read(ping,reply,state,table,buf,&off,hdr->len) != 0)
	{
	  goto err;
	}

      if(scamper_ping_reply_append(ping, reply) != 0)
	{
	  goto err;
	}
    }

 done:
  warts_addrtable_free(table);
  *ping_out = ping;
  free(buf);
  return 0;

 err:
  if(table != NULL) warts_addrtable_free(table);
  if(buf != NULL) free(buf);
  if(ping != NULL) scamper_ping_free(ping);
  return -1;
}

int scamper_file_warts_ping_write(const scamper_file_t *sf,
				  const scamper_ping_t *ping)
{
  warts_addrtable_t *table = NULL;
  warts_ping_reply_t *reply_state = NULL;
  scamper_ping_reply_t *reply;
  uint8_t *buf = NULL;
  uint8_t  flags[ping_vars_mfb];
  uint16_t flags_len, params_len;
  uint32_t len, off = 0;
  uint16_t reply_count;
  size_t   size;
  int      i, j;

  if((table = warts_addrtable_alloc_byaddr()) == NULL)
    goto err;

  /* figure out which ping data items we'll store in this record */
  warts_ping_params(ping, table, flags, &flags_len, &params_len);

  /* length of the ping's flags, parameters, and number of reply records */
  len = 8 + flags_len + 2 + params_len + 2;

  if((reply_count = scamper_ping_reply_count(ping)) > 0)
    {
      size = reply_count * sizeof(warts_ping_reply_t);
      if((reply_state = (warts_ping_reply_t *)malloc_zero(size)) == NULL)
	{
	  goto err;
	}

      for(i=0, j=0; i<ping->ping_sent; i++)
	{
	  for(reply=ping->ping_replies[i]; reply != NULL; reply = reply->next)
	    {
	      if(warts_ping_reply_state(sf, ping, reply, &reply_state[j++],
					table, &len) == -1)
		{
		  goto err;
		}
	    }
	}
    }

  if((buf = malloc_zero(len)) == NULL)
    {
      goto err;
    }

  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_PING);

  if(warts_ping_params_write(ping, sf, table, buf, &off, len,
			     flags, flags_len, params_len) == -1)
    {
      goto err;
    }

  /* reply record count */
  insert_uint16(buf, &off, len, &reply_count, NULL);

  /* write each ping reply record */
  for(i=0; i<reply_count; i++)
    {
      warts_ping_reply_write(&reply_state[i], table, buf, &off, len);
    }
  if(reply_state != NULL)
    {
      free(reply_state);
      reply_state = NULL;
    }

  assert(off == len);

  if(warts_write(sf, buf, len) == -1)
    {
      goto err;
    }

  warts_addrtable_free(table);
  free(buf);
  return 0;

 err:
  if(table != NULL) warts_addrtable_free(table);
  if(reply_state != NULL) free(reply_state);
  if(buf != NULL) free(buf);
  return -1;
}

