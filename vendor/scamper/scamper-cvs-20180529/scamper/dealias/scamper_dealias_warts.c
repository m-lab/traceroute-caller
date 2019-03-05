/*
 * scamper_dealias_warts.c
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2012-2014 The Regents of the University of California
 * Copyright (C) 2015-2016 Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_dealias_warts.c,v 1.16 2016/12/09 08:42:51 mjl Exp $
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
  "$Id: scamper_dealias_warts.c,v 1.16 2016/12/09 08:42:51 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_dealias.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_dealias_warts.h"

#include "mjl_splaytree.h"
#include "utils.h"

#define WARTS_DEALIAS_LIST_ID  1
#define WARTS_DEALIAS_CYCLE_ID 2
#define WARTS_DEALIAS_START    3
#define WARTS_DEALIAS_METHOD   4
#define WARTS_DEALIAS_RESULT   5
#define WARTS_DEALIAS_PROBEC   6
#define WARTS_DEALIAS_USERID   7

static const warts_var_t dealias_vars[] =
{
  {WARTS_DEALIAS_LIST_ID,  4, -1},
  {WARTS_DEALIAS_CYCLE_ID, 4, -1},
  {WARTS_DEALIAS_START,    8, -1},
  {WARTS_DEALIAS_METHOD,   1, -1},
  {WARTS_DEALIAS_RESULT,   1, -1},
  {WARTS_DEALIAS_PROBEC,   4, -1},
  {WARTS_DEALIAS_USERID,   4, -1},
};
#define dealias_vars_mfb WARTS_VAR_MFB(dealias_vars)

#define WARTS_DEALIAS_ALLY_WAIT_PROBE   1
#define WARTS_DEALIAS_ALLY_WAIT_TIMEOUT 2
#define WARTS_DEALIAS_ALLY_ATTEMPTS     3
#define WARTS_DEALIAS_ALLY_FUDGE        4
#define WARTS_DEALIAS_ALLY_FLAGS        5

static const warts_var_t dealias_ally_vars[] =
{
  {WARTS_DEALIAS_ALLY_WAIT_PROBE,    2, -1},
  {WARTS_DEALIAS_ALLY_WAIT_TIMEOUT,  1, -1},
  {WARTS_DEALIAS_ALLY_ATTEMPTS,      1, -1},
  {WARTS_DEALIAS_ALLY_FUDGE,         2, -1},
  {WARTS_DEALIAS_ALLY_FLAGS,         1, -1},
};
#define dealias_ally_vars_mfb WARTS_VAR_MFB(dealias_ally_vars)

#define WARTS_DEALIAS_MERCATOR_ATTEMPTS     1
#define WARTS_DEALIAS_MERCATOR_WAIT_TIMEOUT 2

static const warts_var_t dealias_mercator_vars[] =
{
  {WARTS_DEALIAS_MERCATOR_ATTEMPTS,     1, -1},
  {WARTS_DEALIAS_MERCATOR_WAIT_TIMEOUT, 1, -1},
};
#define dealias_mercator_vars_mfb WARTS_VAR_MFB(dealias_mercator_vars)

#define WARTS_DEALIAS_RADARGUN_PROBEDEFC    1
#define WARTS_DEALIAS_RADARGUN_ATTEMPTS     2
#define WARTS_DEALIAS_RADARGUN_WAIT_PROBE   3
#define WARTS_DEALIAS_RADARGUN_WAIT_ROUND   4
#define WARTS_DEALIAS_RADARGUN_WAIT_TIMEOUT 5
#define WARTS_DEALIAS_RADARGUN_FLAGS        6

static const warts_var_t dealias_radargun_vars[] =
{
  {WARTS_DEALIAS_RADARGUN_PROBEDEFC,    4, -1},
  {WARTS_DEALIAS_RADARGUN_ATTEMPTS,     2, -1},
  {WARTS_DEALIAS_RADARGUN_WAIT_PROBE,   2, -1},
  {WARTS_DEALIAS_RADARGUN_WAIT_ROUND,   4, -1},
  {WARTS_DEALIAS_RADARGUN_WAIT_TIMEOUT, 1, -1},
  {WARTS_DEALIAS_RADARGUN_FLAGS,        1, -1},
};
#define dealias_radargun_vars_mfb WARTS_VAR_MFB(dealias_radargun_vars)

#define WARTS_DEALIAS_PREFIXSCAN_A            1
#define WARTS_DEALIAS_PREFIXSCAN_B            2
#define WARTS_DEALIAS_PREFIXSCAN_AB           3
#define WARTS_DEALIAS_PREFIXSCAN_XS           4
#define WARTS_DEALIAS_PREFIXSCAN_PREFIX       5
#define WARTS_DEALIAS_PREFIXSCAN_ATTEMPTS     6
#define WARTS_DEALIAS_PREFIXSCAN_FUDGE        7
#define WARTS_DEALIAS_PREFIXSCAN_WAIT_PROBE   8
#define WARTS_DEALIAS_PREFIXSCAN_WAIT_TIMEOUT 9
#define WARTS_DEALIAS_PREFIXSCAN_PROBEDEFC    10
#define WARTS_DEALIAS_PREFIXSCAN_FLAGS        11
#define WARTS_DEALIAS_PREFIXSCAN_REPLYC       12

static const warts_var_t dealias_prefixscan_vars[] =
{
  {WARTS_DEALIAS_PREFIXSCAN_A,            -1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_B,            -1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_AB,           -1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_XS,           -1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_PREFIX,        1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_ATTEMPTS,      1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_FUDGE,         2, -1},
  {WARTS_DEALIAS_PREFIXSCAN_WAIT_PROBE,    2, -1},
  {WARTS_DEALIAS_PREFIXSCAN_WAIT_TIMEOUT,  1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_PROBEDEFC,     2, -1},
  {WARTS_DEALIAS_PREFIXSCAN_FLAGS,         1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_REPLYC,        1, -1},
};
#define dealias_prefixscan_vars_mfb WARTS_VAR_MFB(dealias_prefixscan_vars)

#define WARTS_DEALIAS_BUMP_WAIT_PROBE   1
#define WARTS_DEALIAS_BUMP_BUMP_LIMIT   2
#define WARTS_DEALIAS_BUMP_ATTEMPTS     3

static const warts_var_t dealias_bump_vars[] =
{
  {WARTS_DEALIAS_BUMP_WAIT_PROBE, 2, -1},
  {WARTS_DEALIAS_BUMP_BUMP_LIMIT, 2, -1},
  {WARTS_DEALIAS_BUMP_ATTEMPTS,   1, -1},
};
#define dealias_bump_vars_mfb WARTS_VAR_MFB(dealias_bump_vars)

#define WARTS_DEALIAS_PROBEDEF_DST_GID    1
#define WARTS_DEALIAS_PROBEDEF_SRC_GID    2
#define WARTS_DEALIAS_PROBEDEF_ID         3
#define WARTS_DEALIAS_PROBEDEF_METHOD     4
#define WARTS_DEALIAS_PROBEDEF_TTL        5
#define WARTS_DEALIAS_PROBEDEF_TOS        6
#define WARTS_DEALIAS_PROBEDEF_4BYTES     7
#define WARTS_DEALIAS_PROBEDEF_TCP_FLAGS  8
#define WARTS_DEALIAS_PROBEDEF_ICMP_ID    9
#define WARTS_DEALIAS_PROBEDEF_DST        10
#define WARTS_DEALIAS_PROBEDEF_SRC        11
#define WARTS_DEALIAS_PROBEDEF_SIZE       12
#define WARTS_DEALIAS_PROBEDEF_MTU        13
#define WARTS_DEALIAS_PROBEDEF_ICMP_CSUM  14

static const warts_var_t dealias_probedef_vars[] =
{
  {WARTS_DEALIAS_PROBEDEF_DST_GID,    4, -1},
  {WARTS_DEALIAS_PROBEDEF_SRC_GID,    4, -1},
  {WARTS_DEALIAS_PROBEDEF_ID,         4, -1},
  {WARTS_DEALIAS_PROBEDEF_METHOD,     1, -1},
  {WARTS_DEALIAS_PROBEDEF_TTL,        1, -1},
  {WARTS_DEALIAS_PROBEDEF_TOS,        1, -1},
  {WARTS_DEALIAS_PROBEDEF_4BYTES,     4, -1},
  {WARTS_DEALIAS_PROBEDEF_TCP_FLAGS,  1, -1},
  {WARTS_DEALIAS_PROBEDEF_ICMP_ID,    2, -1},
  {WARTS_DEALIAS_PROBEDEF_DST,       -1, -1},
  {WARTS_DEALIAS_PROBEDEF_SRC,       -1, -1},
  {WARTS_DEALIAS_PROBEDEF_SIZE,       2, -1},
  {WARTS_DEALIAS_PROBEDEF_MTU,        2, -1},
  {WARTS_DEALIAS_PROBEDEF_ICMP_CSUM,  2, -1},
};
#define dealias_probedef_vars_mfb WARTS_VAR_MFB(dealias_probedef_vars)

#define WARTS_DEALIAS_PROBE_DEF    1
#define WARTS_DEALIAS_PROBE_TX     2
#define WARTS_DEALIAS_PROBE_REPLYC 3
#define WARTS_DEALIAS_PROBE_IPID   4
#define WARTS_DEALIAS_PROBE_SEQ    5

static const warts_var_t dealias_probe_vars[] =
{
  {WARTS_DEALIAS_PROBE_DEF,    4, -1},
  {WARTS_DEALIAS_PROBE_TX,     8, -1},
  {WARTS_DEALIAS_PROBE_REPLYC, 2, -1},
  {WARTS_DEALIAS_PROBE_IPID,   2, -1},
  {WARTS_DEALIAS_PROBE_SEQ,    4, -1},
};
#define dealias_probe_vars_mfb WARTS_VAR_MFB(dealias_probe_vars)

#define WARTS_DEALIAS_REPLY_SRC_GID    1
#define WARTS_DEALIAS_REPLY_RX         2
#define WARTS_DEALIAS_REPLY_IPID       3
#define WARTS_DEALIAS_REPLY_TTL        4
#define WARTS_DEALIAS_REPLY_ICMP_TC    5
#define WARTS_DEALIAS_REPLY_ICMP_Q_TTL 6
#define WARTS_DEALIAS_REPLY_ICMP_EXT   7
#define WARTS_DEALIAS_REPLY_PROTO      8
#define WARTS_DEALIAS_REPLY_TCP_FLAGS  9
#define WARTS_DEALIAS_REPLY_SRC        10
#define WARTS_DEALIAS_REPLY_IPID32     11
#define WARTS_DEALIAS_REPLY_FLAG       12

static const warts_var_t dealias_reply_vars[] =
{
  {WARTS_DEALIAS_REPLY_SRC_GID,     4, -1},
  {WARTS_DEALIAS_REPLY_RX,          8, -1},
  {WARTS_DEALIAS_REPLY_IPID,        2, -1},
  {WARTS_DEALIAS_REPLY_TTL,         1, -1},
  {WARTS_DEALIAS_REPLY_ICMP_TC,     2, -1},
  {WARTS_DEALIAS_REPLY_ICMP_Q_TTL,  1, -1},
  {WARTS_DEALIAS_REPLY_ICMP_EXT,   -1, -1},
  {WARTS_DEALIAS_REPLY_PROTO,       1, -1},
  {WARTS_DEALIAS_REPLY_TCP_FLAGS,   1, -1},
  {WARTS_DEALIAS_REPLY_SRC,        -1, -1},
  {WARTS_DEALIAS_REPLY_IPID32,      4, -1},
  {WARTS_DEALIAS_REPLY_FLAG,        1, -1},
};
#define dealias_reply_vars_mfb WARTS_VAR_MFB(dealias_reply_vars)

typedef struct warts_dealias_probedef
{
  uint8_t                 flags[WARTS_VAR_MFB(dealias_probedef_vars)];
  uint16_t                flags_len;
  uint16_t                params_len;
} warts_dealias_probedef_t;

typedef struct warts_dealias_data
{
  warts_dealias_probedef_t *probedefs;
  uint32_t                  probedefc;
  uint8_t                   flags[2];
  uint16_t                  flags_len;
  uint16_t                  params_len;
} warts_dealias_data_t;

typedef struct warts_dealias_reply
{
  uint8_t                 flags[WARTS_VAR_MFB(dealias_reply_vars)];
  uint16_t                flags_len;
  uint16_t                params_len;
} warts_dealias_reply_t;

typedef struct warts_dealias_probe
{
  uint8_t                 flags[WARTS_VAR_MFB(dealias_probe_vars)];
  uint16_t                flags_len;
  uint16_t                params_len;
  warts_dealias_reply_t  *replies;
} warts_dealias_probe_t;


static void warts_dealias_params(const scamper_dealias_t *dealias,
				 uint8_t *flags, uint16_t *flags_len,
				 uint16_t *params_len)
{
  const warts_var_t *var;
  int i, max_id = 0;

  memset(flags, 0, dealias_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(dealias_vars)/sizeof(warts_var_t); i++)
    {
      var = &dealias_vars[i];
      if((var->id == WARTS_DEALIAS_USERID && dealias->userid == 0) ||
	 (var->id == WARTS_DEALIAS_RESULT && dealias->result == 0) ||
	 (var->id == WARTS_DEALIAS_PROBEC && dealias->probec == 0))
	continue;

      flag_set(flags, var->id, &max_id);
      assert(var->size != -1);
      *params_len += var->size;
    }

  *flags_len = fold_flags(flags, max_id);
  return;
}

static int warts_dealias_params_read(scamper_dealias_t *dealias,
				     warts_state_t *state,
				     uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&dealias->list,    (wpr_t)extract_list,    state},
    {&dealias->cycle,   (wpr_t)extract_cycle,   state},
    {&dealias->start,   (wpr_t)extract_timeval, NULL},
    {&dealias->method,  (wpr_t)extract_byte,    NULL},
    {&dealias->result,  (wpr_t)extract_byte,    NULL},
    {&dealias->probec,  (wpr_t)extract_uint32,  NULL},
    {&dealias->userid,  (wpr_t)extract_uint32,  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static int warts_dealias_params_write(const scamper_dealias_t *dealias,
				      const scamper_file_t *sf,
				      uint8_t *buf, uint32_t *off,
				      const uint32_t len,
				      const uint8_t *flags,
				      const uint16_t flags_len,
				      const uint16_t params_len)
{
  uint32_t list_id, cycle_id;
  warts_param_writer_t handlers[] = {
    {&list_id,          (wpw_t)insert_uint32,       NULL},
    {&cycle_id,         (wpw_t)insert_uint32,       NULL},
    {&dealias->start,   (wpw_t)insert_timeval,      NULL},
    {&dealias->method,  (wpw_t)insert_byte,         NULL},
    {&dealias->result,  (wpw_t)insert_byte,         NULL},
    {&dealias->probec,  (wpw_t)insert_uint32,       NULL},
    {&dealias->userid,  (wpw_t)insert_uint32,       NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  dealias->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, dealias->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return 0;
}

static int warts_dealias_probedef_params(const scamper_file_t *sf,
					 const scamper_dealias_probedef_t *p,
					 warts_dealias_probedef_t *state,
					 warts_addrtable_t *table,
					 uint32_t *len)
{
  const warts_var_t *var;
  int i, max_id = 0;

  memset(state->flags, 0, dealias_probedef_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(dealias_probedef_vars)/sizeof(warts_var_t); i++)
    {
      var = &dealias_probedef_vars[i];
      if(var->id == WARTS_DEALIAS_PROBEDEF_DST_GID ||
	 var->id == WARTS_DEALIAS_PROBEDEF_SRC_GID)
	continue;

      if((var->id == WARTS_DEALIAS_PROBEDEF_SIZE && p->size == 0) ||
	 (var->id == WARTS_DEALIAS_PROBEDEF_MTU && p->mtu == 0)   ||
	 (var->id == WARTS_DEALIAS_PROBEDEF_TOS && p->tos == 0)   ||
	 (var->id == WARTS_DEALIAS_PROBEDEF_ID  && p->id == 0)    ||
	 (var->id == WARTS_DEALIAS_PROBEDEF_4BYTES &&
	  SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(p) == 0 &&
	  SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(p) == 0)          ||
	 (var->id == WARTS_DEALIAS_PROBEDEF_ICMP_ID &&
	  SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(p) == 0)         ||
	 (var->id == WARTS_DEALIAS_PROBEDEF_ICMP_CSUM &&
	  (SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(p) == 0 ||
	   p->un.icmp.csum == 0))                                 ||
	 (var->id == WARTS_DEALIAS_PROBEDEF_TCP_FLAGS &&
	  SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(p) == 0))
	continue;

      flag_set(state->flags, var->id, &max_id);

      if(var->id == WARTS_DEALIAS_PROBEDEF_DST)
	{
	  flag_set(state->flags, WARTS_DEALIAS_PROBEDEF_DST, &max_id);
	  state->params_len += warts_addr_size(table, p->dst);
	}
      else if(var->id == WARTS_DEALIAS_PROBEDEF_SRC)
	{
	  flag_set(state->flags, WARTS_DEALIAS_PROBEDEF_SRC, &max_id);
	  state->params_len += warts_addr_size(table, p->src);
	}
      else
	{
	  assert(var->size != -1);
	  state->params_len += var->size;
	}
    }

  state->flags_len = fold_flags(state->flags, max_id);

  /* increase length for the probedef record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_probedef_read(scamper_dealias_probedef_t *p,
				       warts_state_t *state,
				       warts_addrtable_t *table,
				       uint8_t *buf,uint32_t *off,uint32_t len)
{
  uint8_t bytes[4]; uint16_t bytes_len = 4;
  uint8_t tcp_flags = 0;
  uint16_t icmpid = 0, csum = 0;
  warts_param_reader_t handlers[] = {
    {&p->dst,    (wpr_t)extract_addr_gid,  state},
    {&p->src,    (wpr_t)extract_addr_gid,  state},
    {&p->id,     (wpr_t)extract_uint32,    NULL},
    {&p->method, (wpr_t)extract_byte,      NULL},
    {&p->ttl,    (wpr_t)extract_byte,      NULL},
    {&p->tos,    (wpr_t)extract_byte,      NULL},
    {bytes,      (wpr_t)extract_bytes,     &bytes_len},
    {&tcp_flags, (wpr_t)extract_byte,      NULL},
    {&icmpid,    (wpr_t)extract_uint16,    NULL},
    {&p->dst,    (wpr_t)extract_addr,      table},
    {&p->src,    (wpr_t)extract_addr,      table},
    {&p->size,   (wpr_t)extract_uint16,    NULL},
    {&p->mtu,    (wpr_t)extract_uint16,    NULL},
    {&csum,      (wpr_t)extract_uint16,    NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  uint32_t o = *off;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(p->src == NULL || p->dst == NULL)
    return -1;

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(p))
    {
      if(flag_isset(&buf[o], WARTS_DEALIAS_PROBEDEF_4BYTES))
	p->un.icmp.csum = bytes_ntohs(bytes+2);
      else
	p->un.icmp.csum = csum;
      p->un.icmp.id = icmpid;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(p))
    {
      p->un.tcp.sport = bytes_ntohs(bytes+0);
      p->un.tcp.dport = bytes_ntohs(bytes+2);
      p->un.tcp.flags = tcp_flags;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(p))
    {
      p->un.udp.sport = bytes_ntohs(bytes+0);
      p->un.udp.dport = bytes_ntohs(bytes+2);
    }
  else
    {
      return -1;
    }

  return 0;
}

static void warts_dealias_probedef_write(const scamper_dealias_probedef_t *p,
					 warts_dealias_probedef_t *state,
					 const scamper_file_t *sf,
					 warts_addrtable_t *table,
					 uint8_t *buf, uint32_t *off,
					 const uint32_t len)
{
  uint8_t bytes[4]; uint16_t bytes_len = 4;
  uint8_t tcp_flags;
  uint16_t icmpid, csum;
  uint16_t u16;

  warts_param_writer_t handlers[] = {
    {NULL,         NULL,                        NULL},
    {NULL,         NULL,                        NULL},
    {&p->id,       (wpw_t)insert_uint32,        NULL},
    {&p->method,   (wpw_t)insert_byte,          NULL},
    {&p->ttl,      (wpw_t)insert_byte,          NULL},
    {&p->tos,      (wpw_t)insert_byte,          NULL},
    {bytes,        (wpw_t)insert_bytes_uint16, &bytes_len},
    {&tcp_flags,   (wpw_t)insert_byte,          NULL},
    {&icmpid,      (wpw_t)insert_uint16,        NULL},
    {p->dst,       (wpw_t)insert_addr,          table},
    {p->src,       (wpw_t)insert_addr,          table},
    {&p->size,     (wpw_t)insert_uint16,        NULL},
    {&p->mtu,      (wpw_t)insert_uint16,        NULL},
    {&csum,        (wpw_t)insert_uint16,        NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(p))
    {
      icmpid = p->un.icmp.id;
      csum   = p->un.icmp.csum;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(p))
    {
      u16 = htons(p->un.udp.sport);
      memcpy(bytes+0, &u16, 2);
      u16 = htons(p->un.udp.dport);
      memcpy(bytes+2, &u16, 2);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(p))
    {
      u16 = htons(p->un.tcp.sport);
      memcpy(bytes+0, &u16, 2);
      u16 = htons(p->un.tcp.dport);
      memcpy(bytes+2, &u16, 2);
      tcp_flags = p->un.tcp.flags;
    }

  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);

  return;
}

static int extract_dealias_prefixscan_xs(const uint8_t *buf, uint32_t *off,
					 const uint32_t len,
					 scamper_dealias_prefixscan_t *pfs,
					 void *param)
{
  scamper_addr_t **xs;
  uint16_t xc, i;

  if(extract_uint16(buf, off, len, &xc, NULL) != 0)
    return -1;

  if(scamper_dealias_prefixscan_xs_alloc(pfs, xc) != 0)
    return -1;

  xs = pfs->xs;
  for(i=0; i<xc; i++)
    {
      if(extract_addr(buf, off, len, &xs[i], param) != 0)
	return -1;
    }

  pfs->xs = xs;
  pfs->xc = xc;

  return 0;
}

static void insert_dealias_prefixscan_xs(uint8_t *buf, uint32_t *off,
					 const uint32_t len,
					 const scamper_dealias_prefixscan_t *p,
					 void *param)
{
  uint16_t i;

  i = htons(p->xc);
  insert_uint16(buf, off, len, &i, NULL);

  for(i=0; i<p->xc; i++)
    insert_addr(buf, off, len, p->xs[i], param);

  return;
}

static int warts_dealias_prefixscan_state(const scamper_file_t *sf,
					  const void *data,
					  warts_dealias_data_t *state,
					  warts_addrtable_t *table,
					  uint32_t *len)
{
  const scamper_dealias_prefixscan_t *p = data;
  const warts_var_t *var;
  int max_id = 0;
  uint16_t i, j;
  size_t size;

  if(p->probedefc > 0)
    {
      size = p->probedefc * sizeof(warts_dealias_probedef_t);
      if((state->probedefs = malloc_zero(size)) == NULL)
	return -1;
    }

  memset(state->flags, 0, dealias_prefixscan_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(dealias_prefixscan_vars)/sizeof(warts_var_t); i++)
    {
      var = &dealias_prefixscan_vars[i];

      if(var->id == WARTS_DEALIAS_PREFIXSCAN_A)
	{
	  if(p->a != NULL)
	    {
	      flag_set(state->flags, var->id, &max_id);
	      state->params_len += warts_addr_size(table, p->a);
	    }
	  continue;
	}
      else if(var->id == WARTS_DEALIAS_PREFIXSCAN_B)
	{
	  if(p->b != NULL)
	    {
	      flag_set(state->flags, var->id, &max_id);
	      state->params_len += warts_addr_size(table, p->b);
	    }
	  continue;
	}
      else if(var->id == WARTS_DEALIAS_PREFIXSCAN_AB)
	{
	  if(p->ab != NULL)
	    {
	      flag_set(state->flags, var->id, &max_id);
	      state->params_len += warts_addr_size(table, p->ab);
	    }
	  continue;
	}
      else if(var->id == WARTS_DEALIAS_PREFIXSCAN_XS)
	{
	  if(p->xc > 0)
	    {
	      flag_set(state->flags, var->id, &max_id);
	      state->params_len += 2;
	      for(j=0; j<p->xc; j++)
		state->params_len += warts_addr_size(table, p->xs[j]);
	    }
	  continue;
	}
      else if(var->id == WARTS_DEALIAS_PREFIXSCAN_PROBEDEFC)
	{
	  if(p->probedefc == 0)
	    continue;
	}
      else if(var->id == WARTS_DEALIAS_PREFIXSCAN_FLAGS)
	{
	  if(p->flags == 0)
	    continue;
	}
      else if(var->id == WARTS_DEALIAS_PREFIXSCAN_REPLYC)
	{
	  if(p->replyc == 5)
	    continue;
	}

      flag_set(state->flags, var->id, &max_id);
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  for(i=0; i<p->probedefc; i++)
    {
      if(warts_dealias_probedef_params(sf, &p->probedefs[i],
				       &state->probedefs[i], table, len) != 0)
	{
	  return -1;
	}
    }

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_prefixscan_read(scamper_dealias_t *dealias,
					 warts_state_t *state,
					 warts_addrtable_t *table,
					 scamper_dealias_probedef_t **defs,
					 uint32_t *defc,
					 uint8_t *buf, uint32_t *off,
					 uint32_t len)
{
  scamper_dealias_prefixscan_t pfs, *p;
  warts_param_reader_t handlers[] = {
    {&pfs.a,            (wpr_t)extract_addr,                  table},
    {&pfs.b,            (wpr_t)extract_addr,                  table},
    {&pfs.ab,           (wpr_t)extract_addr,                  table},
    {&pfs,              (wpr_t)extract_dealias_prefixscan_xs, table},
    {&pfs.prefix,       (wpr_t)extract_byte,                  NULL},
    {&pfs.attempts,     (wpr_t)extract_byte,                  NULL},
    {&pfs.fudge,        (wpr_t)extract_uint16,                NULL},
    {&pfs.wait_probe,   (wpr_t)extract_uint16,                NULL},
    {&pfs.wait_timeout, (wpr_t)extract_byte,                  NULL},
    {&pfs.probedefc,    (wpr_t)extract_uint16,                NULL},
    {&pfs.flags,        (wpr_t)extract_byte,                  NULL},
    {&pfs.replyc,       (wpr_t)extract_byte,                  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  uint32_t o = *off;
  uint16_t i;

  memset(&pfs, 0, sizeof(pfs));
  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;
  if(pfs.a == NULL || pfs.b == NULL)
    return -1;

  if(scamper_dealias_prefixscan_alloc(dealias) != 0)
    return -1;

  p = dealias->data;
  memcpy(p, &pfs, sizeof(pfs));

  /* by default we require five replies before inferring an alias */
  if(flag_isset(&buf[o], WARTS_DEALIAS_PREFIXSCAN_REPLYC) == 0)
    p->replyc = 5;

  if(p->probedefc > 0)
    {
      if(scamper_dealias_prefixscan_probedefs_alloc(p, p->probedefc) != 0)
	return -1;

      for(i=0; i<p->probedefc; i++)
	{
	  if(warts_dealias_probedef_read(&p->probedefs[i], state, table,
					 buf, off, len) != 0)
	    return -1;
	}
    }

  *defs = p->probedefs;
  *defc = p->probedefc;
  return 0;
}

static void warts_dealias_prefixscan_write(const void *data,
					   const scamper_file_t *sf,
					   warts_addrtable_t *table,
					   uint8_t *buf, uint32_t *off,
					   const uint32_t len,
					   warts_dealias_data_t *state)
{
  const scamper_dealias_prefixscan_t *prefixscan = data;
  warts_param_writer_t handlers[] = {
    {prefixscan->a,             (wpw_t)insert_addr,                  table},
    {prefixscan->b,             (wpw_t)insert_addr,                  table},
    {prefixscan->ab,            (wpw_t)insert_addr,                  table},
    {prefixscan,                (wpw_t)insert_dealias_prefixscan_xs, table},
    {&prefixscan->prefix,       (wpw_t)insert_byte,                  NULL},
    {&prefixscan->attempts,     (wpw_t)insert_byte,                  NULL},
    {&prefixscan->fudge,        (wpw_t)insert_uint16,                NULL},
    {&prefixscan->wait_probe,   (wpw_t)insert_uint16,                NULL},
    {&prefixscan->wait_timeout, (wpw_t)insert_byte,                  NULL},
    {&prefixscan->probedefc,    (wpw_t)insert_uint16,                NULL},
    {&prefixscan->flags,        (wpw_t)insert_byte,                  NULL},
    {&prefixscan->replyc,       (wpw_t)insert_byte,                  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  uint32_t i;

  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);

  for(i=0; i<prefixscan->probedefc; i++)
    {
      warts_dealias_probedef_write(&prefixscan->probedefs[i],
				   &state->probedefs[i],
				   sf, table, buf, off, len);
    }

  return;
}

static int warts_dealias_radargun_state(const scamper_file_t *sf,
					const void *data,
					warts_dealias_data_t *state,
					warts_addrtable_t *table, uint32_t *len)
{
  const scamper_dealias_radargun_t *rg = data;
  const warts_var_t *var;
  int max_id = 0;
  size_t size;
  uint32_t i;

  if(rg->probedefc == 0)
    return -1;

  size = rg->probedefc * sizeof(warts_dealias_probedef_t);
  if((state->probedefs = malloc_zero(size)) == NULL)
    return -1;

  memset(state->flags, 0, dealias_radargun_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(dealias_radargun_vars)/sizeof(warts_var_t); i++)
    {
      var = &dealias_radargun_vars[i];

      if(var->id == WARTS_DEALIAS_RADARGUN_FLAGS)
	{
	  if(rg->flags == 0)
	    continue;
	}

      flag_set(state->flags, var->id, &max_id);
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  for(i=0; i<rg->probedefc; i++)
    {
      if(warts_dealias_probedef_params(sf, &rg->probedefs[i],
				       &state->probedefs[i], table, len) != 0)
	{
	  return -1;
	}
    }

  /* increase length required for the radargun record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_radargun_read(scamper_dealias_t *dealias,
				       warts_state_t *state,
				       warts_addrtable_t *table,
				       scamper_dealias_probedef_t **defs,
				       uint32_t *defc,
				       uint8_t *buf,uint32_t *off,uint32_t len)
{
  scamper_dealias_radargun_t *rg;
  uint32_t probedefc = 0;
  uint16_t attempts = 0;
  uint16_t wait_probe = 0;
  uint32_t wait_round = 0;
  uint8_t  wait_timeout = 0;
  uint8_t  flags = 0;
  uint32_t i;
  warts_param_reader_t handlers[] = {
    {&probedefc,    (wpr_t)extract_uint32, NULL},
    {&attempts,     (wpr_t)extract_uint16, NULL},
    {&wait_probe,   (wpr_t)extract_uint16, NULL},
    {&wait_round,   (wpr_t)extract_uint32, NULL},
    {&wait_timeout, (wpr_t)extract_byte,   NULL},
    {&flags,        (wpr_t)extract_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(scamper_dealias_radargun_alloc(dealias) != 0)
    return -1;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;
  if(probedefc == 0)
    return -1;

  rg = dealias->data;
  if(scamper_dealias_radargun_probedefs_alloc(rg, probedefc) != 0)
    return -1;

  rg->probedefc    = probedefc;
  rg->attempts     = attempts;
  rg->wait_probe   = wait_probe;
  rg->wait_round   = wait_round;
  rg->wait_timeout = wait_timeout;
  rg->flags        = flags;

  for(i=0; i<probedefc; i++)
    {
      if(warts_dealias_probedef_read(&rg->probedefs[i], state, table,
				     buf, off, len) != 0)
	return -1;
    }

  *defs = rg->probedefs;
  *defc = rg->probedefc;
  return 0;
}

static void warts_dealias_radargun_write(const void *data,
					 const scamper_file_t *sf,
					 warts_addrtable_t *table,
					 uint8_t *buf, uint32_t *off,
					 const uint32_t len,
					 warts_dealias_data_t *state)
{
  const scamper_dealias_radargun_t *rg = data;
  warts_param_writer_t handlers[] = {
    {&rg->probedefc,    (wpw_t)insert_uint32, NULL},
    {&rg->attempts,     (wpw_t)insert_uint16, NULL},
    {&rg->wait_probe,   (wpw_t)insert_uint16, NULL},
    {&rg->wait_round,   (wpw_t)insert_uint32, NULL},
    {&rg->wait_timeout, (wpw_t)insert_byte,   NULL},
    {&rg->flags,        (wpw_t)insert_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  uint32_t i;

  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);

  for(i=0; i<rg->probedefc; i++)
    {
      warts_dealias_probedef_write(&rg->probedefs[i], &state->probedefs[i],
				   sf, table, buf, off, len);
    }

  return;
}

static int warts_dealias_bump_state(const scamper_file_t *sf, const void *data,
				    warts_dealias_data_t *state,
				    warts_addrtable_t *table, uint32_t *len)
{
  const scamper_dealias_bump_t *bump = data;
  const warts_var_t *var;
  int i, max_id = 0;
  size_t size = sizeof(warts_dealias_probedef_t) * 2;

  if((state->probedefs = malloc_zero(size)) == NULL)
    return -1;

  memset(state->flags, 0, dealias_bump_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(dealias_bump_vars)/sizeof(warts_var_t); i++)
    {
      var = &dealias_bump_vars[i];
      flag_set(state->flags, var->id, &max_id);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  if(warts_dealias_probedef_params(sf, &bump->probedefs[0],
				   &state->probedefs[0], table, len) != 0 ||
     warts_dealias_probedef_params(sf, &bump->probedefs[1],
				   &state->probedefs[1], table, len) != 0)
    {
      return -1;
    }

  /* increase length required for the ally record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_bump_read(scamper_dealias_t *dealias,
				   warts_state_t *state,
				   warts_addrtable_t *table,
				   scamper_dealias_probedef_t **defs,
				   uint32_t *defc,
				   uint8_t *buf, uint32_t *off, uint32_t len)
{
  scamper_dealias_bump_t *bump;
  uint16_t wait_probe = 0;
  uint16_t bump_limit = 0;
  uint8_t  attempts = 0;
  warts_param_reader_t handlers[] = {
    {&wait_probe,   (wpr_t)extract_uint16, NULL},
    {&bump_limit,   (wpr_t)extract_uint16, NULL},
    {&attempts,     (wpr_t)extract_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(scamper_dealias_bump_alloc(dealias) != 0)
    return -1;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  bump = dealias->data;
  bump->wait_probe   = wait_probe;
  bump->bump_limit   = bump_limit;
  bump->attempts     = attempts;

  if(warts_dealias_probedef_read(&bump->probedefs[0], state, table,
				 buf, off, len) != 0 ||
     warts_dealias_probedef_read(&bump->probedefs[1], state, table,
				 buf, off, len) != 0)
    {
      return -1;
    }

  *defs = bump->probedefs;
  *defc = 2;
  return 0;
}

static void warts_dealias_bump_write(const void *data,
				     const scamper_file_t *sf,
				     warts_addrtable_t *table,
				     uint8_t *buf, uint32_t *off,
				     const uint32_t len,
				     warts_dealias_data_t *state)
{
  const scamper_dealias_bump_t *bump = data;
  warts_param_writer_t handlers[] = {
    {&bump->wait_probe,   (wpw_t)insert_uint16, NULL},
    {&bump->bump_limit,   (wpw_t)insert_uint16, NULL},
    {&bump->attempts,     (wpw_t)insert_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);
  warts_dealias_probedef_write(&bump->probedefs[0], &state->probedefs[0],
			       sf, table, buf, off, len);
  warts_dealias_probedef_write(&bump->probedefs[1], &state->probedefs[1],
			       sf, table, buf, off, len);
  return;
}

static int warts_dealias_ally_state(const scamper_file_t *sf, const void *data,
				    warts_dealias_data_t *state,
				    warts_addrtable_t *table, uint32_t *len)
{
  const scamper_dealias_ally_t *ally = data;
  const warts_var_t *var;
  int i, max_id = 0;
  size_t size = sizeof(warts_dealias_probedef_t) * 2;

  if((state->probedefs = malloc_zero(size)) == NULL)
    return -1;

  memset(state->flags, 0, dealias_ally_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(dealias_ally_vars)/sizeof(warts_var_t); i++)
    {
      var = &dealias_ally_vars[i];
      if((var->id == WARTS_DEALIAS_ALLY_FUDGE && ally->fudge == 0) ||
	 (var->id == WARTS_DEALIAS_ALLY_FLAGS && ally->flags == 0))
	continue;
      flag_set(state->flags, var->id, &max_id);
      assert(var->size != -1);
      state->params_len += var->size;
    }
  state->flags_len = fold_flags(state->flags, max_id);

  if(warts_dealias_probedef_params(sf, &ally->probedefs[0],
				   &state->probedefs[0], table, len) != 0 ||
     warts_dealias_probedef_params(sf, &ally->probedefs[1],
				   &state->probedefs[1], table, len) != 0)
    {
      return -1;
    }

  /* increase length required for the ally record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_ally_read(scamper_dealias_t *dealias,
				   warts_state_t *state,
				   warts_addrtable_t *table,
				   scamper_dealias_probedef_t **defs,
				   uint32_t *defc,
				   uint8_t *buf, uint32_t *off, uint32_t len)
{
  scamper_dealias_ally_t *ally;
  uint16_t wait_probe = 0;
  uint8_t  wait_timeout = 0;
  uint8_t  attempts = 0;
  uint16_t fudge = 0;
  uint8_t  flags = 0;
  warts_param_reader_t handlers[] = {
    {&wait_probe,   (wpr_t)extract_uint16, NULL},
    {&wait_timeout, (wpr_t)extract_byte,   NULL},
    {&attempts,     (wpr_t)extract_byte,   NULL},
    {&fudge,        (wpr_t)extract_uint16, NULL},
    {&flags,        (wpr_t)extract_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(scamper_dealias_ally_alloc(dealias) != 0)
    return -1;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  ally = dealias->data;
  ally->wait_probe   = wait_probe;
  ally->wait_timeout = wait_timeout;
  ally->attempts     = attempts;
  ally->fudge        = fudge;
  ally->flags        = flags;

  if(warts_dealias_probedef_read(&ally->probedefs[0], state, table,
				 buf, off, len) != 0 ||
     warts_dealias_probedef_read(&ally->probedefs[1], state, table,
				 buf, off, len) != 0)
    {
      return -1;
    }

  *defs = ally->probedefs;
  *defc = 2;
  return 0;
}

static void warts_dealias_ally_write(const void *data,
				     const scamper_file_t *sf,
				     warts_addrtable_t *table,
				     uint8_t *buf, uint32_t *off,
				     const uint32_t len,
				     warts_dealias_data_t *state)
{
  const scamper_dealias_ally_t *ally = data;
  warts_param_writer_t handlers[] = {
    {&ally->wait_probe,   (wpw_t)insert_uint16, NULL},
    {&ally->wait_timeout, (wpw_t)insert_byte,   NULL},
    {&ally->attempts,     (wpw_t)insert_byte,   NULL},
    {&ally->fudge,        (wpw_t)insert_uint16, NULL},
    {&ally->flags,        (wpw_t)insert_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);
  warts_dealias_probedef_write(&ally->probedefs[0], &state->probedefs[0],
			       sf, table, buf, off, len);
  warts_dealias_probedef_write(&ally->probedefs[1], &state->probedefs[1],
			       sf, table, buf, off, len);
  return;
}

static int warts_dealias_mercator_state(const scamper_file_t *sf,
					const void *data,
					warts_dealias_data_t *state,
					warts_addrtable_t *table,uint32_t *len)
{
  const scamper_dealias_mercator_t *m = data;
  const warts_var_t *var;
  int i, max_id = 0;
  size_t size = sizeof(warts_dealias_probedef_t);

  if((state->probedefs = malloc_zero(size)) == NULL)
    return -1;

  assert(sizeof(state->flags) >= dealias_mercator_vars_mfb);

  memset(state->flags, 0, dealias_mercator_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(dealias_mercator_vars)/sizeof(warts_var_t); i++)
    {
      var = &dealias_mercator_vars[i];
      flag_set(state->flags, var->id, &max_id);
      assert(var->size != -1);
      state->params_len += var->size;
    }
  state->flags_len = fold_flags(state->flags, max_id);

  if(warts_dealias_probedef_params(sf, &m->probedef, &state->probedefs[0],
				   table, len) != 0)
    {
      return -1;
    }

  /* increase length required for the mercator record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_mercator_read(scamper_dealias_t *dealias,
				       warts_state_t *state,
				       warts_addrtable_t *table,
				       scamper_dealias_probedef_t **def,
				       uint32_t *defc,
				       uint8_t *buf, uint32_t *off,
				       uint32_t len)
{
  scamper_dealias_mercator_t *mercator;
  uint8_t attempts = 0;
  uint8_t wait_timeout = 0;
  warts_param_reader_t handlers[] = {
    {&attempts,     (wpr_t)extract_byte,   NULL},
    {&wait_timeout, (wpr_t)extract_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(scamper_dealias_mercator_alloc(dealias) != 0)
    return -1;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  mercator = dealias->data;
  mercator->attempts     = attempts;
  mercator->wait_timeout = wait_timeout;

  if(warts_dealias_probedef_read(&mercator->probedef, state, table,
				 buf, off, len) != 0)
    {
      return -1;
    }

  *def = &mercator->probedef;
  *defc = 1;
  return 0;
}

static void warts_dealias_mercator_write(const void *data,
					 const scamper_file_t *sf,
					 warts_addrtable_t *table,
					 uint8_t *buf, uint32_t *off,
					 const uint32_t len,
					 warts_dealias_data_t *state)
{
  const scamper_dealias_mercator_t *m = data;
  warts_param_writer_t handlers[] = {
    {&m->attempts,     (wpw_t)insert_byte,   NULL},
    {&m->wait_timeout, (wpw_t)insert_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);
  warts_dealias_probedef_write(&m->probedef, &state->probedefs[0], sf, table,
			       buf, off, len);
  return;
}

static int extract_dealias_reply_icmptc(const uint8_t *buf, uint32_t *off,
					uint32_t len,
					scamper_dealias_reply_t *reply,
					void *param)
{
  if(len - *off < 2)
    {
      return -1;
    }
  reply->icmp_type = buf[(*off)++];
  reply->icmp_code = buf[(*off)++];
  return 0;
}

static void insert_dealias_reply_icmptc(uint8_t *buf, uint32_t *off,
					const uint32_t len,
					const scamper_dealias_reply_t *reply,
					void *param)
{
  assert(len - *off >= 2);
  buf[(*off)++] = reply->icmp_type;
  buf[(*off)++] = reply->icmp_code;
  return;
}

static int extract_dealias_reply_icmpext(const uint8_t *buf, uint32_t *off,
					 uint32_t len,
					 scamper_dealias_reply_t *reply,
					 void *param)
{
  return warts_icmpext_read(buf, off, len, &reply->icmp_ext);
}

static void insert_dealias_reply_icmpext(uint8_t *buf, uint32_t *off,
					 const uint32_t len,
					 const scamper_dealias_reply_t *reply,
					 void *param)
{
  warts_icmpext_write(buf, off, len, reply->icmp_ext);
  return;
}

static int warts_dealias_reply_state(const scamper_dealias_reply_t *reply,
				     warts_dealias_reply_t *state,
				     const scamper_file_t *sf,
				     warts_addrtable_t *table, uint32_t *len)
{
  const warts_var_t *var;
  scamper_icmpext_t *ie;
  int i, max_id = 0;

  memset(state->flags, 0, dealias_reply_vars_mfb);
  state->params_len = 0;

  /* encode any icmp extensions included */
  if(SCAMPER_DEALIAS_REPLY_IS_ICMP(reply) && reply->icmp_ext != NULL)
    {
      flag_set(state->flags, WARTS_DEALIAS_REPLY_ICMP_EXT, &max_id);
      state->params_len += 2;

      for(ie = reply->icmp_ext; ie != NULL; ie = ie->ie_next)
	{
	  state->params_len += (2 + 1 + 1 + ie->ie_dl);
	}
    }

  for(i=0; i<sizeof(dealias_reply_vars)/sizeof(warts_var_t); i++)
    {
      var = &dealias_reply_vars[i];

      if(var->id == WARTS_DEALIAS_REPLY_SRC_GID)
	{
	  continue;
	}
      else if(var->id == WARTS_DEALIAS_REPLY_ICMP_TC)
	{
	  if(SCAMPER_DEALIAS_REPLY_IS_ICMP(reply) == 0)
	    continue;
	}
      else if(var->id == WARTS_DEALIAS_REPLY_ICMP_Q_TTL)
	{
	  if(SCAMPER_DEALIAS_REPLY_IS_ICMP(reply) == 0)
	    continue;
	}
      else if(var->id == WARTS_DEALIAS_REPLY_ICMP_EXT)
	{
	  continue;
	}
      else if(var->id == WARTS_DEALIAS_REPLY_PROTO)
	{
	  if(SCAMPER_DEALIAS_REPLY_IS_ICMP(reply))
	    continue;
	}
      else if(var->id == WARTS_DEALIAS_REPLY_TCP_FLAGS)
	{
	  if(SCAMPER_DEALIAS_REPLY_IS_TCP(reply) == 0)
	    continue;
	}
      else if(var->id == WARTS_DEALIAS_REPLY_IPID)
	{
	  if(!SCAMPER_ADDR_TYPE_IS_IPV4(reply->src) || reply->ipid == 0)
	    continue;
	}
      else if(var->id == WARTS_DEALIAS_REPLY_IPID32)
	{
	  if(!SCAMPER_ADDR_TYPE_IS_IPV6(reply->src) || reply->ipid32 == 0)
	    continue;
	}
      else if(var->id == WARTS_DEALIAS_REPLY_FLAG)
	{
	  if(reply->flags == 0)
	    continue;
	}

      flag_set(state->flags, var->id, &max_id);

      if(var->id == WARTS_DEALIAS_REPLY_SRC)
	{
	  state->params_len += warts_addr_size(table, reply->src);
	  continue;
	}

      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  /* increase length required for the dealias reply record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_reply_read(scamper_dealias_reply_t *reply,
				    warts_state_t *state,
				    warts_addrtable_t *table,
				    uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&reply->src,           (wpr_t)extract_addr_gid,              state},
    {&reply->rx,            (wpr_t)extract_timeval,               NULL},
    {&reply->ipid,          (wpr_t)extract_uint16,                NULL},
    {&reply->ttl,           (wpr_t)extract_byte,                  NULL},
    {reply,                 (wpr_t)extract_dealias_reply_icmptc,  NULL},
    {&reply->icmp_q_ip_ttl, (wpr_t)extract_byte,                  NULL},
    {reply,                 (wpr_t)extract_dealias_reply_icmpext, NULL},
    {&reply->proto,         (wpr_t)extract_byte,                  NULL},
    {&reply->tcp_flags,     (wpr_t)extract_byte,                  NULL},
    {&reply->src,           (wpr_t)extract_addr,                  table},
    {&reply->ipid32,        (wpr_t)extract_uint32,                NULL},
    {&reply->flags,         (wpr_t)extract_byte,                  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  uint32_t o = *off;
  int i;

  if((i = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0)
    return i;

  if(flag_isset(&buf[o], WARTS_DEALIAS_REPLY_PROTO) == 0)
    {
      if(reply->src->type == SCAMPER_ADDR_TYPE_IPV4)
	reply->proto = IPPROTO_ICMP;
      else
	reply->proto = IPPROTO_ICMPV6;
    }

  return i;
}

static int warts_dealias_reply_write(const scamper_dealias_reply_t *r,
				     const scamper_file_t *sf,
				     warts_addrtable_t *table,
				     uint8_t *buf, uint32_t *off,
				     const uint32_t len,
				     warts_dealias_reply_t *state)
{
  warts_param_writer_t handlers[] = {
    {NULL,              NULL,                                NULL},
    {&r->rx,            (wpw_t)insert_timeval,               NULL},
    {&r->ipid,          (wpw_t)insert_uint16,                NULL},
    {&r->ttl,           (wpw_t)insert_byte,                  NULL},
    {r,                 (wpw_t)insert_dealias_reply_icmptc,  NULL},
    {&r->icmp_q_ip_ttl, (wpw_t)insert_byte,                  NULL},
    {r,                 (wpw_t)insert_dealias_reply_icmpext, NULL},
    {&r->proto,         (wpw_t)insert_byte,                  NULL},
    {&r->tcp_flags,     (wpw_t)insert_byte,                  NULL},
    {r->src,            (wpw_t)insert_addr,                  table},
    {&r->ipid32,        (wpw_t)insert_uint32,                NULL},
    {&r->flags,         (wpw_t)insert_byte,                  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);
  return 0;
}

static int warts_dealias_probe_state(const scamper_file_t *sf,
				     const scamper_dealias_probe_t *probe,
				     warts_dealias_probe_t *state,
				     warts_addrtable_t *table, uint32_t *len)
{
  const warts_var_t *var;
  int i, max_id = 0;
  size_t size;

  memset(state->flags, 0, dealias_probe_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(dealias_probe_vars)/sizeof(warts_var_t); i++)
    {
      var = &dealias_probe_vars[i];
      if((var->id == WARTS_DEALIAS_PROBE_DEF && probe->def->id == 0) ||
	 (var->id == WARTS_DEALIAS_PROBE_REPLYC && probe->replyc == 0) ||
	 (var->id == WARTS_DEALIAS_PROBE_SEQ && probe->seq == 0) ||
	 (var->id == WARTS_DEALIAS_PROBE_IPID &&
	  SCAMPER_ADDR_TYPE_IS_IPV4(probe->def->dst) == 0))
	continue;

      flag_set(state->flags, var->id, &max_id);
      assert(var->size != -1);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);
  state->replies = NULL;

  if(probe->replyc > 0)
    {
      size = sizeof(warts_dealias_reply_t) * probe->replyc;
      if((state->replies = malloc_zero(size)) == NULL)
	return -1;

      for(i=0; i<probe->replyc; i++)
	{
	  if(warts_dealias_reply_state(probe->replies[i], &state->replies[i],
				       sf, table, len) != 0)
	    {
	      free(state->replies);
	      state->replies = NULL;
	      return -1;
	    }
	}
    }

  /* increase length required for the probe record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_probe_read(scamper_dealias_probe_t *probe,
				    warts_state_t *state,
				    scamper_dealias_probedef_t *defs,
				    uint32_t defc,
				    warts_addrtable_t *table,
				    uint8_t *buf, uint32_t *off, uint32_t len)
{
  uint32_t probedef_id = 0;
  warts_param_reader_t handlers[] = {
    {&probedef_id,   (wpr_t)extract_uint32,  NULL},
    {&probe->tx,     (wpr_t)extract_timeval, NULL},
    {&probe->replyc, (wpr_t)extract_uint16,  NULL},
    {&probe->ipid,   (wpr_t)extract_uint16,  NULL},
    {&probe->seq,    (wpr_t)extract_uint32,  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  scamper_dealias_reply_t *reply;
  int i;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    {
      return -1;
    }

  if(probedef_id >= defc)
    return -1;

  probe->def = defs + probedef_id;

  if(probe->replyc == 0)
    return 0;

  if(scamper_dealias_replies_alloc(probe, probe->replyc) != 0)
    {
      return -1;
    }

  for(i=0; i<probe->replyc; i++)
    {
      if((reply = scamper_dealias_reply_alloc()) == NULL)
	{
	  return -1;
	}
      probe->replies[i] = reply;

      if(warts_dealias_reply_read(reply, state, table, buf, off, len) != 0)
	{
	  return -1;
	}
    }

  return 0;
}

static void warts_dealias_probe_write(const scamper_dealias_probe_t *probe,
				      const scamper_file_t *sf,
				      warts_addrtable_t *table,
				      uint8_t *buf, uint32_t *off,
				      const uint32_t len,
				      warts_dealias_probe_t *state)
{
  int i;
  warts_param_writer_t handlers[] = {
    {&probe->def->id,      (wpw_t)insert_uint32,  NULL},
    {&probe->tx,           (wpw_t)insert_timeval, NULL},
    {&probe->replyc,       (wpw_t)insert_uint16,  NULL},
    {&probe->ipid,         (wpw_t)insert_uint16,  NULL},
    {&probe->seq,          (wpw_t)insert_uint32,  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);

  for(i=0; i<probe->replyc; i++)
    {
      warts_dealias_reply_write(probe->replies[i], sf, table, buf, off, len,
				&state->replies[i]);
    }

  return;
}

int scamper_file_warts_dealias_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				    scamper_dealias_t **dealias_out)
{
  static int (*const read[])(scamper_dealias_t *,warts_state_t *,
			     warts_addrtable_t *,scamper_dealias_probedef_t **,
			     uint32_t *, uint8_t *, uint32_t *, uint32_t) = {
    warts_dealias_mercator_read,
    warts_dealias_ally_read,
    warts_dealias_radargun_read,
    warts_dealias_prefixscan_read,
    warts_dealias_bump_read,
  };
  scamper_dealias_t *dealias = NULL;
  scamper_dealias_probedef_t *defs;
  scamper_dealias_probe_t *probe;
  warts_addrtable_t *table = NULL;
  warts_state_t *state = scamper_file_getstate(sf);
  uint8_t *buf = NULL;
  uint32_t defc = 0;
  uint32_t off = 0;
  uint32_t i;

  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      *dealias_out = NULL;
      return 0;
    }

  if((dealias = scamper_dealias_alloc()) == NULL)
    {
      goto err;
    }

  if(warts_dealias_params_read(dealias, state, buf, &off, hdr->len) != 0)
    goto err;
  if(dealias->method == 0)
    goto err;

  /* bounds check the type, can only read types we know about */
  if(dealias->method > 5)
    {
      scamper_dealias_free(dealias);
      *dealias_out = NULL;
      return 0;
    }

  if((table = warts_addrtable_alloc_byid()) == NULL)
    goto err;

  if(read[dealias->method-1](dealias, state, table, &defs, &defc,
			     buf, &off, hdr->len) != 0)
    goto err;

  if(dealias->probec == 0)
    goto done;

  if(scamper_dealias_probes_alloc(dealias, dealias->probec) != 0)
    {
      goto err;
    }

  for(i=0; i<dealias->probec; i++)
    {
      if((probe = scamper_dealias_probe_alloc()) == NULL)
	{
	  goto err;
	}
      dealias->probes[i] = probe;

      if(warts_dealias_probe_read(probe, state, defs, defc, table,
				  buf, &off, hdr->len) != 0)
	{
	  goto err;
	}
    }

 done:
  warts_addrtable_free(table);
  *dealias_out = dealias;
  free(buf);
  return 0;

 err:
  if(table != NULL) warts_addrtable_free(table);
  if(buf != NULL) free(buf);
  if(dealias != NULL) scamper_dealias_free(dealias);
  return -1;
}

static void warts_dealias_probes_free(warts_dealias_probe_t *probes,
				      uint32_t cnt)
{
  uint32_t i;

  if(probes != NULL)
    {
      for(i=0; i<cnt; i++)
	if(probes[i].replies != NULL)
	  free(probes[i].replies);
      free(probes);
    }

  return;
}

int scamper_file_warts_dealias_write(const scamper_file_t *sf,
				     const scamper_dealias_t *dealias)
{
  static int (*const state[])(const scamper_file_t *, const void *,
			      warts_dealias_data_t *, warts_addrtable_t *,
			      uint32_t *) = {
    warts_dealias_mercator_state,
    warts_dealias_ally_state,
    warts_dealias_radargun_state,
    warts_dealias_prefixscan_state,
    warts_dealias_bump_state,
  };
  static void (*const write[])(const void *, const scamper_file_t *,
			       warts_addrtable_t *, uint8_t *, uint32_t *,
			       const uint32_t, warts_dealias_data_t *) = {
    warts_dealias_mercator_write,
    warts_dealias_ally_write,
    warts_dealias_radargun_write,
    warts_dealias_prefixscan_write,
    warts_dealias_bump_write,
  };
  uint8_t                 *buf = NULL;
  uint8_t                  flags[dealias_vars_mfb];
  uint16_t                 flags_len, params_len;
  scamper_dealias_probe_t *probe;
  warts_dealias_data_t     data;
  warts_dealias_probe_t   *probes = NULL;
  uint32_t                 len, len2, off = 0;
  size_t                   size;
  uint32_t                 i;
  warts_addrtable_t       *table = NULL;

  memset(&data, 0, sizeof(data));

  /* figure out which dealias data items we'll store in this record */
  warts_dealias_params(dealias, flags, &flags_len, &params_len);
  len = 8 + flags_len + params_len + 2;

  if((table = warts_addrtable_alloc_byaddr()) == NULL)
    goto err;

  /* figure out the state that we have to allocate */
  if(state[dealias->method-1](sf, dealias->data, &data, table, &len) != 0)
     {
       goto err;
     }

  /*
   * figure out the state that we have to allocate to store the
   * probes sent (and their responses)
   */
  if(dealias->probec > 0)
    {
      size = dealias->probec * sizeof(warts_dealias_probe_t);
      if((probes = (warts_dealias_probe_t *)malloc_zero(size)) == NULL)
	{
	  goto err;
	}

      for(i=0; i<dealias->probec; i++)
	{
	  probe = dealias->probes[i];
	  len2 = len;
	  if(warts_dealias_probe_state(sf,probe,&probes[i],table,&len2) != 0)
	    goto err;
	  if(len2 < len)
	    goto err;
	  len = len2;
	}
    }

  if((buf = malloc_zero(len)) == NULL)
    goto err;
  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_DEALIAS);

  if(warts_dealias_params_write(dealias, sf, buf, &off, len,
				flags, flags_len, params_len) != 0)
    {
      goto err;
    }

  write[dealias->method-1](dealias->data, sf, table, buf, &off, len, &data);

  if(data.probedefs != NULL)
    free(data.probedefs);
  data.probedefs = NULL;

  if(dealias->probec > 0)
    {
      for(i=0; i<dealias->probec; i++)
	{
	  probe = dealias->probes[i];
	  warts_dealias_probe_write(probe,sf,table,buf,&off, len, &probes[i]);
	}
    }

  warts_dealias_probes_free(probes, dealias->probec);
  probes = NULL;

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
  if(probes != NULL) warts_dealias_probes_free(probes, dealias->probec);
  if(data.probedefs != NULL) free(data.probedefs);
  if(buf != NULL) free(buf);
  return -1;
}
