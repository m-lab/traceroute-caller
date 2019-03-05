/*
 * scamper_tracelb_warts.c
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2016      Matthew Luckie
 * Copyright (C) 2019      Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_tracelb_warts.c,v 1.8 2019/01/13 07:02:08 mjl Exp $
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
  "$Id: scamper_tracelb_warts.c,v 1.8 2019/01/13 07:02:08 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_tracelb.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_tracelb_warts.h"
#include "mjl_splaytree.h"
#include "utils.h"

/*
 * the optional bits of a tracelb structure
 */
#define WARTS_TRACELB_LIST_ID      1        /* list id assigned by warts */
#define WARTS_TRACELB_CYCLE_ID     2        /* cycle id assigned by warts */
#define WARTS_TRACELB_ADDR_SRC_GID 3        /* src address key, deprecated */
#define WARTS_TRACELB_ADDR_DST_GID 4        /* dst address key, deprecated */
#define WARTS_TRACELB_START        5        /* start timestamp */
#define WARTS_TRACELB_SPORT        6        /* source port */
#define WARTS_TRACELB_DPORT        7        /* destination port */
#define WARTS_TRACELB_PROBE_SIZE   8        /* probe size */
#define WARTS_TRACELB_TYPE         9        /* type */
#define WARTS_TRACELB_FIRSTHOP     10       /* first hop */
#define WARTS_TRACELB_WAIT_TIMEOUT 11       /* wait before probe timeout */
#define WARTS_TRACELB_WAIT_PROBE   12       /* minimum wait between probes */
#define WARTS_TRACELB_ATTEMPTS     13       /* attempts */
#define WARTS_TRACELB_CONFIDENCE   14       /* confidence level to attain */
#define WARTS_TRACELB_TOS          15       /* type of service bits */
#define WARTS_TRACELB_NODEC        16       /* the number of nodes found */
#define WARTS_TRACELB_LINKC        17       /* the number of links found */
#define WARTS_TRACELB_PROBEC       18       /* number of probes sent */
#define WARTS_TRACELB_PROBECMAX    19       /* max number of probes to send */
#define WARTS_TRACELB_GAPLIMIT     20       /* gaplimit */
#define WARTS_TRACELB_ADDR_SRC     21       /* src address */
#define WARTS_TRACELB_ADDR_DST     22       /* dst address */
#define WARTS_TRACELB_USERID       23       /* user id */
#define WARTS_TRACELB_FLAGS        24       /* flags */

static const warts_var_t tracelb_vars[] =
{
  {WARTS_TRACELB_LIST_ID,      4, -1},
  {WARTS_TRACELB_CYCLE_ID,     4, -1},
  {WARTS_TRACELB_ADDR_SRC_GID, 4, -1},
  {WARTS_TRACELB_ADDR_DST_GID, 4, -1},
  {WARTS_TRACELB_START,        8, -1},
  {WARTS_TRACELB_SPORT,        2, -1},
  {WARTS_TRACELB_DPORT,        2, -1},
  {WARTS_TRACELB_PROBE_SIZE,   2, -1},
  {WARTS_TRACELB_TYPE,         1, -1},
  {WARTS_TRACELB_FIRSTHOP,     1, -1},
  {WARTS_TRACELB_WAIT_TIMEOUT, 1, -1},
  {WARTS_TRACELB_WAIT_PROBE,   1, -1},
  {WARTS_TRACELB_ATTEMPTS,     1, -1},
  {WARTS_TRACELB_CONFIDENCE,   1, -1},
  {WARTS_TRACELB_TOS,          1, -1},
  {WARTS_TRACELB_NODEC,        2, -1},
  {WARTS_TRACELB_LINKC,        2, -1},
  {WARTS_TRACELB_PROBEC,       4, -1},
  {WARTS_TRACELB_PROBECMAX,    4, -1},
  {WARTS_TRACELB_GAPLIMIT,     1, -1},
  {WARTS_TRACELB_ADDR_SRC,    -1, -1},
  {WARTS_TRACELB_ADDR_DST,    -1, -1},
  {WARTS_TRACELB_USERID,       4, -1},
  {WARTS_TRACELB_FLAGS,        1, -1},
};
#define tracelb_vars_mfb WARTS_VAR_MFB(tracelb_vars)

#define WARTS_TRACELB_NODE_ADDR_GID  1
#define WARTS_TRACELB_NODE_FLAGS     2
#define WARTS_TRACELB_NODE_LINKC     3
#define WARTS_TRACELB_NODE_QTTL      4
#define WARTS_TRACELB_NODE_ADDR      5
#define WARTS_TRACELB_NODE_NAME      6

static const warts_var_t tracelb_node_vars[] =
{
  {WARTS_TRACELB_NODE_ADDR_GID, 4, -1}, /* deprecated */
  {WARTS_TRACELB_NODE_FLAGS,    1, -1},
  {WARTS_TRACELB_NODE_LINKC,    2, -1},
  {WARTS_TRACELB_NODE_QTTL,     1, -1},
  {WARTS_TRACELB_NODE_ADDR,    -1, -1},
  {WARTS_TRACELB_NODE_NAME,    -1, -1},
};
#define tracelb_node_vars_mfb WARTS_VAR_MFB(tracelb_node_vars)

#define WARTS_TRACELB_LINK_FROM    1
#define WARTS_TRACELB_LINK_TO      2
#define WARTS_TRACELB_LINK_HOPC    3

static const warts_var_t tracelb_link_vars[] =
{
  {WARTS_TRACELB_LINK_FROM,   2, -1},
  {WARTS_TRACELB_LINK_TO,     2, -1},
  {WARTS_TRACELB_LINK_HOPC,   1, -1},
};
#define tracelb_link_vars_mfb WARTS_VAR_MFB(tracelb_link_vars)

#define WARTS_TRACELB_PROBE_TX         1
#define WARTS_TRACELB_PROBE_FLOWID     2
#define WARTS_TRACELB_PROBE_TTL        3
#define WARTS_TRACELB_PROBE_ATTEMPT    4
#define WARTS_TRACELB_PROBE_RXC        5

static const warts_var_t tracelb_probe_vars[] =
{
  {WARTS_TRACELB_PROBE_TX,      8, -1},
  {WARTS_TRACELB_PROBE_FLOWID,  2, -1},
  {WARTS_TRACELB_PROBE_TTL,     1, -1},
  {WARTS_TRACELB_PROBE_ATTEMPT, 1, -1},
  {WARTS_TRACELB_PROBE_RXC,     2, -1},
};
#define tracelb_probe_vars_mfb WARTS_VAR_MFB(tracelb_probe_vars)

#define WARTS_TRACELB_REPLY_RX         1
#define WARTS_TRACELB_REPLY_IPID       2
#define WARTS_TRACELB_REPLY_TTL        3
#define WARTS_TRACELB_REPLY_FLAGS      4
#define WARTS_TRACELB_REPLY_ICMP_TC    5
#define WARTS_TRACELB_REPLY_TCP_FLAGS  6
#define WARTS_TRACELB_REPLY_ICMP_EXT   7
#define WARTS_TRACELB_REPLY_ICMP_Q_TTL 8
#define WARTS_TRACELB_REPLY_ICMP_Q_TOS 9
#define WARTS_TRACELB_REPLY_FROM_GID   10 /* deprecated */
#define WARTS_TRACELB_REPLY_FROM       11

static const warts_var_t tracelb_reply_vars[] =
{
  {WARTS_TRACELB_REPLY_RX,         8, -1},
  {WARTS_TRACELB_REPLY_IPID,       2, -1},
  {WARTS_TRACELB_REPLY_TTL,        1, -1},
  {WARTS_TRACELB_REPLY_FLAGS,      1, -1},
  {WARTS_TRACELB_REPLY_ICMP_TC,    2, -1},
  {WARTS_TRACELB_REPLY_TCP_FLAGS,  1, -1},
  {WARTS_TRACELB_REPLY_ICMP_EXT,  -1, -1},
  {WARTS_TRACELB_REPLY_ICMP_Q_TTL, 1, -1},
  {WARTS_TRACELB_REPLY_ICMP_Q_TOS, 1, -1},
  {WARTS_TRACELB_REPLY_FROM_GID,   4, -1},
  {WARTS_TRACELB_REPLY_FROM,      -1, -1},
};
#define tracelb_reply_vars_mfb WARTS_VAR_MFB(tracelb_reply_vars)

#define WARTS_TRACELB_PROBESET_PROBEC 1

static const warts_var_t tracelb_probeset_vars[] =
{
  {WARTS_TRACELB_PROBESET_PROBEC, 2, -1},
};
#define tracelb_probeset_vars_mfb WARTS_VAR_MFB(tracelb_probeset_vars)


typedef struct warts_tracelb_node
{
  uint8_t               flags[WARTS_VAR_MFB(tracelb_node_vars)];
  uint16_t              flags_len;
  uint16_t              params_len;
} warts_tracelb_node_t;

typedef struct warts_tracelb_reply
{
  uint8_t                 flags[WARTS_VAR_MFB(tracelb_reply_vars)];
  uint16_t                flags_len;
  uint16_t                params_len;
} warts_tracelb_reply_t;

typedef struct warts_tracelb_probe
{
  uint8_t                 flags[WARTS_VAR_MFB(tracelb_probe_vars)];
  uint16_t                flags_len;
  uint16_t                params_len;
  warts_tracelb_reply_t  *replies;
} warts_tracelb_probe_t;

typedef struct warts_tracelb_probeset
{
  uint8_t                 flags[WARTS_VAR_MFB(tracelb_probeset_vars)];
  uint16_t                flags_len;
  uint16_t                params_len;
  warts_tracelb_probe_t  *probes;
  uint16_t                probec;
} warts_tracelb_probeset_t;

typedef struct warts_tracelb_link
{
  uint16_t                  from;
  uint16_t                  to;
  uint8_t                   flags[WARTS_VAR_MFB(tracelb_link_vars)];
  uint16_t                  flags_len;
  uint16_t                  params_len;
  warts_tracelb_probeset_t *sets;
  uint8_t                   hopc;
} warts_tracelb_link_t;


static void warts_tracelb_params(const scamper_tracelb_t *trace,
				 warts_addrtable_t *table, uint8_t *flags,
				 uint16_t *flags_len, uint16_t *params_len)
{
  int i, max_id = 0;
  const warts_var_t *var;

  /* unset all the flags possible */
  memset(flags, 0, tracelb_vars_mfb);
  *params_len = 0;

  /* for now, we include the base data items */
  for(i=0; i<sizeof(tracelb_vars)/sizeof(warts_var_t); i++)
    {
      var = &tracelb_vars[i];

      if(var->id == WARTS_TRACELB_ADDR_SRC_GID ||
	 var->id == WARTS_TRACELB_ADDR_DST_GID)
	{
	  continue;
	}
      else if(var->id == WARTS_TRACELB_USERID)
	{
	  if(trace->userid == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACELB_FLAGS)
	{
	  if(trace->flags == 0)
	    continue;
	}

      flag_set(flags, var->id, &max_id);

      if(var->id == WARTS_TRACELB_ADDR_SRC)
	{
	  *params_len += warts_addr_size(table, trace->src);
	  continue;
	}
      else if(var->id == WARTS_TRACELB_ADDR_DST)
	{
	  *params_len += warts_addr_size(table, trace->dst);
	  continue;
	}

      assert(var->size >= 0);
      *params_len += var->size;
    }

  *flags_len = fold_flags(flags, max_id);
  return;
}

static int warts_tracelb_params_read(scamper_tracelb_t *trace,
				     warts_state_t *state,
				     warts_addrtable_t *table, uint8_t *buf,
				     uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&trace->list,         (wpr_t)extract_list,      state},
    {&trace->cycle,        (wpr_t)extract_cycle,     state},
    {&trace->src,          (wpr_t)extract_addr_gid,  state},
    {&trace->dst,          (wpr_t)extract_addr_gid,  state},
    {&trace->start,        (wpr_t)extract_timeval,   NULL},
    {&trace->sport,        (wpr_t)extract_uint16,    NULL},
    {&trace->dport,        (wpr_t)extract_uint16,    NULL},
    {&trace->probe_size,   (wpr_t)extract_uint16,    NULL},
    {&trace->type,         (wpr_t)extract_byte,      NULL},
    {&trace->firsthop,     (wpr_t)extract_byte,      NULL},
    {&trace->wait_timeout, (wpr_t)extract_byte,      NULL},
    {&trace->wait_probe,   (wpr_t)extract_byte,      NULL},
    {&trace->attempts,     (wpr_t)extract_byte,      NULL},
    {&trace->confidence,   (wpr_t)extract_byte,      NULL},
    {&trace->tos,          (wpr_t)extract_byte,      NULL},
    {&trace->nodec,        (wpr_t)extract_uint16,    NULL},
    {&trace->linkc,        (wpr_t)extract_uint16,    NULL},
    {&trace->probec,       (wpr_t)extract_uint32,    NULL},
    {&trace->probec_max,   (wpr_t)extract_uint32,    NULL},
    {&trace->gaplimit,     (wpr_t)extract_byte,      NULL},
    {&trace->src,          (wpr_t)extract_addr,      table},
    {&trace->dst,          (wpr_t)extract_addr,      table},
    {&trace->userid,       (wpr_t)extract_uint32,    NULL},
    {&trace->flags,        (wpr_t)extract_byte,      NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  int rc;

  if((rc = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0)
    return rc;
  if(trace->src == NULL || trace->dst == NULL)
    return -1;
  return 0;
}

static int warts_tracelb_params_write(const scamper_tracelb_t *trace,
				      const scamper_file_t *sf,
				      warts_addrtable_t *table,
				      uint8_t *buf, uint32_t *off,
				      const uint32_t len,
				      const uint8_t *flags,
				      const uint16_t flags_len,
				      const uint16_t params_len)
{
  uint32_t list_id, cycle_id;
  warts_param_writer_t handlers[] = {
    {&list_id,             (wpw_t)insert_uint32,  NULL},
    {&cycle_id,            (wpw_t)insert_uint32,  NULL},
    {NULL,                 NULL,                  NULL},
    {NULL,                 NULL,                  NULL},
    {&trace->start,        (wpw_t)insert_timeval, NULL},
    {&trace->sport,        (wpw_t)insert_uint16,  NULL},
    {&trace->dport,        (wpw_t)insert_uint16,  NULL},
    {&trace->probe_size,   (wpw_t)insert_uint16,  NULL},
    {&trace->type,         (wpw_t)insert_byte,    NULL},
    {&trace->firsthop,     (wpw_t)insert_byte,    NULL},
    {&trace->wait_timeout, (wpw_t)insert_byte,    NULL},
    {&trace->wait_probe,   (wpw_t)insert_byte,    NULL},
    {&trace->attempts,     (wpw_t)insert_byte,    NULL},
    {&trace->confidence,   (wpw_t)insert_byte,    NULL},
    {&trace->tos,          (wpw_t)insert_byte,    NULL},
    {&trace->nodec,        (wpw_t)insert_uint16,  NULL},
    {&trace->linkc,        (wpw_t)insert_uint16,  NULL},
    {&trace->probec,       (wpw_t)insert_uint32,  NULL},
    {&trace->probec_max,   (wpw_t)insert_uint32,  NULL},
    {&trace->gaplimit,     (wpw_t)insert_byte,    NULL},
    {trace->src,           (wpw_t)insert_addr,    table},
    {trace->dst,           (wpw_t)insert_addr,    table},
    {&trace->userid,       (wpw_t)insert_uint32,  NULL},
    {&trace->flags,        (wpw_t)insert_byte,    NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  trace->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, trace->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return 0;
}

static int warts_tracelb_node_state(const scamper_file_t *sf,
				    const scamper_tracelb_node_t *node,
				    warts_addrtable_t *table,
				    warts_tracelb_node_t *state, uint32_t *len)
{
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(state->flags, 0, tracelb_node_vars_mfb);
  state->params_len = 0;

  /* for now, we include the base data items */
  for(i=0; i<sizeof(tracelb_node_vars)/sizeof(warts_var_t); i++)
    {
      var = &tracelb_node_vars[i];

      if(var->id == WARTS_TRACELB_NODE_ADDR_GID)
	{
	  continue;
	}
      else if(var->id == WARTS_TRACELB_NODE_QTTL)
	{
	  /* don't include the qttl field if it isn't used */
	  if(SCAMPER_TRACELB_NODE_QTTL(node) == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACELB_NODE_ADDR)
	{
	  if(node->addr != NULL)
	    {
	      flag_set(state->flags, var->id, &max_id);
	      state->params_len += warts_addr_size(table, node->addr);
	    }
	  continue;
	}
      else if(var->id == WARTS_TRACELB_NODE_NAME)
	{
	  if(node->name == NULL)
	    continue;
	}

      flag_set(state->flags, var->id, &max_id);

      if(var->size < 0)
	{
	  if(var->id == WARTS_TRACELB_NODE_NAME)
	    state->params_len += warts_str_size(node->name);
	  continue;
	}

      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_tracelb_node_read(scamper_tracelb_node_t *node,
				   warts_state_t *state,
				   warts_addrtable_t *table,const uint8_t *buf,
				   uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&node->addr,  (wpr_t)extract_addr_gid,  state},
    {&node->flags, (wpr_t)extract_byte,      NULL},
    {&node->linkc, (wpr_t)extract_uint16,    NULL},
    {&node->q_ttl, (wpr_t)extract_byte,      NULL},
    {&node->addr,  (wpr_t)extract_addr,      table},
    {&node->name,  (wpr_t)extract_string,    NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;
  if(node->addr == NULL)
    return -1;

  return 0;
}

static void warts_tracelb_node_write(const scamper_tracelb_node_t *node,
				     const warts_tracelb_node_t *state,
				     warts_addrtable_t *table,
				     uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_writer_t handlers[] = {
    {NULL,         NULL,                 NULL},
    {&node->flags, (wpw_t)insert_byte,   NULL},
    {&node->linkc, (wpw_t)insert_uint16, NULL},
    {&node->q_ttl, (wpw_t)insert_byte,   NULL},
    {node->addr,   (wpw_t)insert_addr,   table},
    {node->name,   (wpw_t)insert_string, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
                     state->params_len, handlers, handler_cnt);
  return;
}

static int extract_tracelb_reply_icmp_tc(const uint8_t *buf, uint32_t *off,
					 uint32_t len,
					 scamper_tracelb_reply_t *reply,
					 void *param)
{
  if(*off >= len || len - *off < 2)
    return -1;
  reply->reply_icmp_type = buf[(*off)++];
  reply->reply_icmp_code = buf[(*off)++];
  return 0;
}

static void insert_tracelb_reply_icmp_tc(uint8_t *buf, uint32_t *off,
					 const uint32_t len,
					 const scamper_tracelb_reply_t *reply,
					 void *param)
{
  assert(len - *off >= 2);
  buf[(*off)++] = reply->reply_icmp_type;
  buf[(*off)++] = reply->reply_icmp_code;
  return;
}

static int extract_tracelb_reply_icmp_ext(const uint8_t *buf, uint32_t *off,
					  uint32_t len,
					  scamper_tracelb_reply_t *reply,
					  void *param)
{
  return warts_icmpext_read(buf, off, len, &reply->reply_icmp_ext);
}

static void insert_tracelb_reply_icmp_ext(uint8_t *buf, uint32_t *off,
					  const uint32_t len,
					  const scamper_tracelb_reply_t *reply,
					  void *param)
{
  warts_icmpext_write(buf, off, len, reply->reply_icmp_ext);
  return;
}

static int warts_tracelb_reply_state(const scamper_file_t *sf,
				     const scamper_tracelb_reply_t *reply,
				     warts_tracelb_reply_t *state,
				     warts_addrtable_t *table, uint32_t *len)
{
  const warts_var_t *var;
  scamper_icmpext_t *ie;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(state->flags, 0, tracelb_reply_vars_mfb);
  state->params_len = 0;

  /* figure out what to include */
  for(i=0; i<sizeof(tracelb_reply_vars)/sizeof(warts_var_t); i++)
    {
      var = &tracelb_reply_vars[i];

      if(var->id == WARTS_TRACELB_REPLY_FROM_GID)
	{
	  continue;
	}
      else if(var->id == WARTS_TRACELB_REPLY_TTL)
	{
	  if((reply->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_REPLY_TTL) == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACELB_REPLY_ICMP_TC ||
	      var->id == WARTS_TRACELB_REPLY_ICMP_Q_TTL ||
	      var->id == WARTS_TRACELB_REPLY_ICMP_Q_TOS)
	{
	  if((reply->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) != 0)
	    continue;
	}
      else if(var->id == WARTS_TRACELB_REPLY_TCP_FLAGS)
	{
	  if((reply->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACELB_REPLY_ICMP_EXT)
	{
	  if((reply->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) != 0 ||
	     reply->reply_icmp_ext == NULL)
	    continue;

	  state->params_len += 2;
	  for(ie = reply->reply_icmp_ext; ie != NULL; ie = ie->ie_next)
	    {
	      state->params_len += (2 + 1 + 1 + ie->ie_dl);
	    }
	}
      else if(var->id == WARTS_TRACELB_REPLY_FROM)
	{
	  state->params_len += warts_addr_size(table, reply->reply_from);
	}

      flag_set(state->flags, var->id, &max_id);

      if(var->size > 0)
	{
	  state->params_len += var->size;
	}
    }

  state->flags_len = fold_flags(state->flags, max_id);

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_tracelb_reply_read(scamper_tracelb_reply_t *reply,
				    warts_state_t *state,
				    warts_addrtable_t *table,
				    const uint8_t *buf,
				    uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&reply->reply_rx,         (wpr_t)extract_timeval,                NULL},
    {&reply->reply_ipid,       (wpr_t)extract_uint16,                 NULL},
    {&reply->reply_ttl,        (wpr_t)extract_byte,                   NULL},
    {&reply->reply_flags,      (wpr_t)extract_byte,                   NULL},
    {reply,                    (wpr_t)extract_tracelb_reply_icmp_tc,  NULL},
    {&reply->reply_tcp_flags,  (wpr_t)extract_byte,                   NULL},
    {reply,                    (wpr_t)extract_tracelb_reply_icmp_ext, NULL},
    {&reply->reply_icmp_q_ttl, (wpr_t)extract_byte,                   NULL},
    {&reply->reply_icmp_q_tos, (wpr_t)extract_byte,                   NULL},
    {&reply->reply_from,       (wpr_t)extract_addr_gid,               state},
    {&reply->reply_from,       (wpr_t)extract_addr,                   table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static void warts_tracelb_reply_write(const scamper_tracelb_reply_t *reply,
				      const warts_tracelb_reply_t *state,
				      warts_addrtable_t *table,
				      uint8_t *buf,uint32_t *off,uint32_t len)
{
  warts_param_writer_t handlers[] = {
    {&reply->reply_rx,         (wpw_t)insert_timeval,                NULL},
    {&reply->reply_ipid,       (wpw_t)insert_uint16,                 NULL},
    {&reply->reply_ttl,        (wpw_t)insert_byte,                   NULL},
    {&reply->reply_flags,      (wpw_t)insert_byte,                   NULL},
    {reply,                    (wpw_t)insert_tracelb_reply_icmp_tc,  NULL},
    {&reply->reply_tcp_flags,  (wpw_t)insert_byte,                   NULL},
    {reply,                    (wpw_t)insert_tracelb_reply_icmp_ext, NULL},
    {&reply->reply_icmp_q_ttl, (wpw_t)insert_byte,                   NULL},
    {&reply->reply_icmp_q_tos, (wpw_t)insert_byte,                   NULL},
    {NULL,                     NULL,                                 NULL},
    {reply->reply_from,        (wpw_t)insert_addr,                   table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
                     state->params_len, handlers, handler_cnt);
  return;
}

static void warts_tracelb_probe_free(warts_tracelb_probe_t *state)
{
  if(state->replies != NULL)
    {
      free(state->replies);
      state->replies = NULL;
    }
  return;
}

static int warts_tracelb_probe_state(const scamper_file_t *sf,
				     const scamper_tracelb_probe_t *probe,
				     warts_tracelb_probe_t *state,
				     warts_addrtable_t *table,
				     uint32_t *len)
{
  const warts_var_t *var;
  int i, max_id = 0;
  size_t size;

  memset(state->flags, 0, tracelb_probe_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tracelb_probe_vars)/sizeof(warts_var_t); i++)
    {
      var = &tracelb_probe_vars[i];
      flag_set(state->flags, var->id, &max_id);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  if(probe->rxc > 0)
    {
      size = sizeof(warts_tracelb_reply_t) * probe->rxc;
      if((state->replies = malloc_zero(size)) == NULL)
	{
	  return -1;
	}

      for(i=0; i<probe->rxc; i++)
	{
	  if(warts_tracelb_reply_state(sf, probe->rxs[i], &state->replies[i],
				       table, len) != 0)
	    return -1;
	}
    }

  return 0;
}

static int warts_tracelb_probe_read(scamper_tracelb_probe_t *probe,
				    warts_state_t *state,
				    warts_addrtable_t *table,
				    const uint8_t *buf,
				    uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&probe->tx,         (wpr_t)extract_timeval,                NULL},
    {&probe->flowid,     (wpr_t)extract_uint16,                 NULL},
    {&probe->ttl,        (wpr_t)extract_byte,                   NULL},
    {&probe->attempt,    (wpr_t)extract_byte,                   NULL},
    {&probe->rxc,        (wpr_t)extract_uint16,                 NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  scamper_tracelb_reply_t *reply;
  uint16_t i;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(probe->rxc > 0)
    {
      if(scamper_tracelb_probe_replies_alloc(probe, probe->rxc) != 0)
	return -1;

      for(i=0; i<probe->rxc; i++)
	{
	  if((reply = scamper_tracelb_reply_alloc(NULL)) == NULL)
	    return -1;
	  probe->rxs[i] = reply;

	  if(warts_tracelb_reply_read(reply, state, table, buf, off, len) != 0)
	    return -1;
	}
    }

  return 0;
}

static void warts_tracelb_probe_write(const scamper_tracelb_probe_t *probe,
				      const warts_tracelb_probe_t *state,
				      warts_addrtable_t *table,
				      uint8_t *buf,uint32_t *off,uint32_t len)
{
  warts_param_writer_t handlers[] = {
    {&probe->tx,         (wpw_t)insert_timeval,                NULL},
    {&probe->flowid,     (wpw_t)insert_uint16,                 NULL},
    {&probe->ttl,        (wpw_t)insert_byte,                   NULL},
    {&probe->attempt,    (wpw_t)insert_byte,                   NULL},
    {&probe->rxc,        (wpw_t)insert_uint16,                 NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  uint16_t i;

  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);

  for(i=0; i<probe->rxc; i++)
    {
      warts_tracelb_reply_write(probe->rxs[i], &state->replies[i], table,
				buf, off, len);
    }

  return;
}

static void warts_tracelb_probeset_free(warts_tracelb_probeset_t *state)
{
  uint16_t i;

  if(state->probes != NULL)
    {
      for(i=0; i<state->probec; i++)
	warts_tracelb_probe_free(&state->probes[i]);
      free(state->probes);
      state->probes = NULL;
    }

  return;
}

static int warts_tracelb_probeset_state(const scamper_file_t *sf,
					const scamper_tracelb_probeset_t *set,
					warts_tracelb_probeset_t *state,
					warts_addrtable_t *table,
					uint32_t *len)
{
  const warts_var_t *var;
  int i, max_id = 0;
  size_t size;

  state->probec = set->probec;

  memset(state->flags, 0, tracelb_probeset_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tracelb_probeset_vars)/sizeof(warts_var_t); i++)
    {
      var = &tracelb_probeset_vars[i];
      flag_set(state->flags, var->id, &max_id);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  if(set->probec > 0)
    {
      size = sizeof(warts_tracelb_probe_t) * set->probec;
      if((state->probes = malloc_zero(size)) == NULL)
	{
	  return -1;
	}

      for(i=0; i<set->probec; i++)
	{
	  if(warts_tracelb_probe_state(sf, set->probes[i], &state->probes[i],
				       table, len) != 0)
	    return -1;
	}
    }

  return 0;
}

static int warts_tracelb_probeset_read(scamper_tracelb_probeset_t *set,
				       warts_state_t *state,
				       warts_addrtable_t *table,
				       const uint8_t *buf, uint32_t *off,
				       uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&set->probec, (wpr_t)extract_uint16, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  uint16_t i;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(set->probec > 0)
    {
      if(scamper_tracelb_probeset_probes_alloc(set, set->probec) != 0)
	return -1;

      for(i=0; i<set->probec; i++)
	{
	  if((set->probes[i] = scamper_tracelb_probe_alloc()) == NULL ||
	     warts_tracelb_probe_read(set->probes[i], state, table,
				      buf, off, len) != 0)
	    {
	      return -1;
	    }
	}
    }

  return 0;
}

static void warts_tracelb_probeset_write(const scamper_tracelb_probeset_t *set,
					 const warts_tracelb_probeset_t *state,
					 warts_addrtable_t *table,
					 uint8_t *buf, uint32_t *off,
					 uint32_t len)
{
  warts_param_writer_t handlers[] = {
    {&set->probec, (wpw_t)insert_uint16, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  uint16_t i;

  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);

  for(i=0; i<set->probec; i++)
    {
      warts_tracelb_probe_write(set->probes[i], &state->probes[i], table,
				buf, off, len);
    }

  return;
}

static void warts_tracelb_link_free(warts_tracelb_link_t *state)
{
  uint8_t i;
  if(state->sets != NULL)
    {
      for(i=0; i<state->hopc; i++)
	warts_tracelb_probeset_free(&state->sets[i]);
      free(state->sets);
      state->sets = NULL;
    }
  return;
}

static int warts_tracelb_link_state(const scamper_file_t *sf,
				    const scamper_tracelb_t *trace,
				    const scamper_tracelb_link_t *link,
				    warts_tracelb_link_t *state,
				    warts_addrtable_t *table, uint32_t *len)
{
  const warts_var_t *var;
  size_t size;
  int i, j, max_id = 0;
  uint8_t s;

  state->hopc = link->hopc;

  /*
   * get the index into the nodes array for each of the nodes represented
   * in the link.  the loop finishes when j reaches 2, i.e. both nodes have
   * been identified.
   */
  for(i=0, j=0; i<trace->nodec; i++)
    {
      if(link->from == trace->nodes[i])
	{
	  state->from = i;
	  j++;
	}
      if(link->to == trace->nodes[i])
	{
	  state->to = i;
	  j++;
	}

      if(j == 2 || (link->to == NULL && j == 1))
	break;
    }

  /* unset all the flags possible */
  memset(state->flags, 0, tracelb_link_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tracelb_link_vars)/sizeof(warts_var_t); i++)
    {
      var = &tracelb_link_vars[i];

      /* if the link does not include a `to' node, skip it */
      if(var->id == WARTS_TRACELB_LINK_TO && link->to == NULL)
	continue;

      flag_set(state->flags, var->id, &max_id);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  if(link->hopc > 0)
    {
      size = sizeof(warts_tracelb_probeset_t) * link->hopc;
      if((state->sets = malloc_zero(size)) == NULL)
	{
	  return -1;
	}

      for(s=0; s<link->hopc; s++)
	{
	  if(warts_tracelb_probeset_state(sf, link->sets[s], &state->sets[s],
					  table, len) != 0)
	    return -1;
	}
    }

  return 0;
}

static int warts_tracelb_link_read(scamper_tracelb_t *trace,
				   scamper_tracelb_link_t *link,
				   warts_state_t *state,
				   warts_addrtable_t *table,
				   const uint8_t *buf,
				   uint32_t *off, uint32_t len)
{
  uint16_t from, to;
  warts_param_reader_t handlers[] = {
    {&from,         (wpr_t)extract_uint16, NULL},
    {&to,           (wpr_t)extract_uint16, NULL},
    {&link->hopc,   (wpr_t)extract_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  scamper_tracelb_probeset_t *set;
  uint8_t i;
  uint32_t o = *off;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    {
      return -1;
    }

  if(from >= trace->nodec)
    return -1;
  link->from = trace->nodes[from];

  if(flag_isset(&buf[o], WARTS_TRACELB_LINK_TO) != 0)
    link->to = trace->nodes[to];
  else
    link->to = NULL;

  if(link->hopc > 0)
    {
      if(scamper_tracelb_link_probesets_alloc(link, link->hopc) != 0)
	return -1;

      for(i=0; i<link->hopc; i++)
	{
	  if((set = scamper_tracelb_probeset_alloc()) == NULL)
	    return -1;
	  link->sets[i] = set;

	  if(warts_tracelb_probeset_read(set, state, table, buf, off, len) != 0)
	    return -1;
	}
    }

  return 0;
}

static void warts_tracelb_link_write(const scamper_tracelb_link_t *link,
				     const warts_tracelb_link_t *state,
				     warts_addrtable_t *table,
				     uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_writer_t handlers[] = {
    {&state->from,          (wpw_t)insert_uint16,   NULL},
    {&state->to,            (wpw_t)insert_uint16,   NULL},
    {&link->hopc,           (wpw_t)insert_byte,     NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  uint32_t i;

  warts_params_write(buf, off, len, state->flags, state->flags_len,
                     state->params_len, handlers, handler_cnt);

  for(i=0; i<link->hopc; i++)
    {
      warts_tracelb_probeset_write(link->sets[i], &state->sets[i], table,
				   buf, off, len);
    }

  return;
}

/*
 * warts_tracelb_read
 *
 */
int scamper_file_warts_tracelb_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				    scamper_tracelb_t **trace_out)
{
  warts_state_t          *state = scamper_file_getstate(sf);
  scamper_tracelb_t      *trace = NULL;
  uint8_t                *buf = NULL;
  uint32_t                i, off = 0;
  uint16_t               *nlc = NULL, j;
  scamper_tracelb_node_t *node;
  warts_addrtable_t      *table = NULL;

  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      *trace_out = NULL;
      return 0;
    }

  if((trace = scamper_tracelb_alloc()) == NULL)
    {
      goto err;
    }

  if((table = warts_addrtable_alloc_byid()) == NULL)
    goto err;

  /* read the trace's parameters */
  if(warts_tracelb_params_read(trace, state, table, buf, &off, hdr->len) != 0)
    {
      goto err;
    }

  /* read the nodes */
  if(trace->nodec > 0)
    {
      if(scamper_tracelb_nodes_alloc(trace, trace->nodec) != 0)
	{
	  goto err;
	}
      for(i=0; i<trace->nodec; i++)
	{
	  if((trace->nodes[i] = scamper_tracelb_node_alloc(NULL)) == NULL)
	    goto err;

	  if(warts_tracelb_node_read(trace->nodes[i], state, table,
				     buf, &off, hdr->len) != 0)
	    goto err;
	}
    }

  /* read the links */
  if(trace->linkc > 0)
    {
      if(scamper_tracelb_links_alloc(trace, trace->linkc) != 0)
	{
	  goto err;
	}
      for(i=0; i<trace->linkc; i++)
	{
	  if((trace->links[i] = scamper_tracelb_link_alloc()) == NULL)
	    goto err;

	  if(warts_tracelb_link_read(trace, trace->links[i], state, table,
				     buf, &off, hdr->len) != 0)
	    goto err;
	}
    }

  /* don't need the buf any more */
  free(buf); buf = NULL;

  /*
   * add the links to their respective nodes.
   */
  if(trace->nodec > 0)
    {
      if((nlc = malloc_zero(sizeof(uint16_t) * trace->nodec)) == NULL)
	{
	  goto err;
	}
      for(i=0; i<trace->linkc; i++)
	{
	  for(j=0; j<trace->nodec; j++)
	    {
	      if(trace->links[i]->from == trace->nodes[j])
		break;
	    }

	  if(j == trace->nodec)
	    goto err;

	  node = trace->nodes[j];

	  if(node->links == NULL &&
	     scamper_tracelb_node_links_alloc(node, node->linkc) != 0)
	    goto err;

	  if(nlc[j] == node->linkc)
	    goto err;

	  node->links[nlc[j]++] = trace->links[i];
	}

      for(i=0; i<trace->nodec; i++)
	{
	  if(nlc[i] != trace->nodes[i]->linkc)
	    goto err;
	}

      free(nlc); nlc = NULL;
    }

  warts_addrtable_free(table);
  *trace_out = trace;
  return 0;

 err:
  if(table != NULL) warts_addrtable_free(table);
  if(buf != NULL) free(buf);
  if(nlc != NULL) free(nlc);
  if(trace != NULL) scamper_tracelb_free(trace);
  return -1;
}

int scamper_file_warts_tracelb_write(const scamper_file_t *sf,
				     const scamper_tracelb_t *trace)
{
  const scamper_tracelb_node_t *node;
  const scamper_tracelb_link_t *link;
  uint8_t                      *buf = NULL;
  uint32_t                      off = 0, len, len2;
  uint8_t                       trace_flags[tracelb_vars_mfb];
  uint16_t                      trace_flags_len, trace_params_len;
  warts_tracelb_node_t         *node_state = NULL;
  warts_tracelb_link_t         *link_state = NULL;
  size_t                        size;
  int                           i;
  warts_addrtable_t            *table = NULL;

  /* make sure the table is nulled out */
  if((table = warts_addrtable_alloc_byaddr()) == NULL)
    goto err;

  /* figure out which tracelb data items we'll store in this record */
  warts_tracelb_params(trace, table, trace_flags, &trace_flags_len,
		       &trace_params_len);

  /* this represents the length of the trace's flags and parameters */
  len = 8 + trace_flags_len + trace_params_len;
  if(trace_params_len != 0) len += 2;

  /* record the node records */
  if(trace->nodec > 0)
    {
      size = trace->nodec * sizeof(warts_tracelb_node_t);
      if((node_state = (warts_tracelb_node_t *)malloc_zero(size)) == NULL)
	{
	  goto err;
	}

      for(i=0; i<trace->nodec; i++)
	{
	  len2 = len;
	  node = trace->nodes[i];
	  if(warts_tracelb_node_state(sf, node, table, &node_state[i],
				      &len2) != 0)
	    {
	      goto err;
	    }

	  /* check for wrapping */
	  if(len2 < len)
	    goto err;
	  len = len2;
	}
    }

  /* record the link records */
  if(trace->linkc > 0)
    {
      size = trace->linkc * sizeof(warts_tracelb_link_t);
      if((link_state = (warts_tracelb_link_t *)malloc_zero(size)) == NULL)
	{
	  goto err;
	}

      for(i=0; i<trace->linkc; i++)
	{
	  len2 = len;
	  link = trace->links[i];
	  if(warts_tracelb_link_state(sf, trace, link, &link_state[i],
				      table, &len2) != 0)
	    {
	      goto err;
	    }

	  /* check for wrapping */
	  if(len2 < len)
	    goto err;
	  len = len2;
	}
    }

  if((buf = malloc_zero(len)) == NULL)
    {
      goto err;
    }

  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_TRACELB);

  /* write trace params */
  if(warts_tracelb_params_write(trace, sf, table, buf, &off, len, trace_flags,
				trace_flags_len, trace_params_len) != 0)
    {
      goto err;
    }

  /* write trace nodes */
  for(i=0; i<trace->nodec; i++)
    {
      warts_tracelb_node_write(trace->nodes[i], &node_state[i], table,
			       buf, &off, len);
    }
  if(node_state != NULL)
    {
      free(node_state);
      node_state = NULL;
    }

  /* write trace links */
  for(i=0; i<trace->linkc; i++)
    {
      link = trace->links[i];
      warts_tracelb_link_write(link, &link_state[i], table, buf, &off, len);
      warts_tracelb_link_free(&link_state[i]);
    }
  if(link_state != NULL)
    {
      free(link_state);
      link_state = NULL;
    }

  assert(off == len);

  if(warts_write(sf, buf, off) == -1)
    {
      goto err;
    }

  warts_addrtable_free(table);
  free(buf);
  return 0;

 err:
  if(table != NULL) warts_addrtable_free(table);
  if(node_state != NULL) free(node_state);
  if(link_state != NULL) free(link_state);
  if(buf != NULL) free(buf);
  return -1;
}


