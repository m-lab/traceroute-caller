/*
 * scamper_trace_warts.c
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
 * Copyright (C) 2015      The University of Waikato
 * Copyright (C) 2015-2016 Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_trace_warts.c,v 1.23 2018/05/03 19:17:08 mjl Exp $
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
  "$Id: scamper_trace_warts.c,v 1.23 2018/05/03 19:17:08 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_trace.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_trace_warts.h"

#include "mjl_splaytree.h"
#include "utils.h"

/*
 * trace attributes: 2 bytes each.
 * the first 4 bits are the type, the second 12 bits are the length
 */
#define WARTS_TRACE_ATTR_HDR(type, len) ((type << 12) | len)
#define WARTS_TRACE_ATTR_HDR_TYPE(hdr)  ((hdr >> 12) & 0xf)
#define WARTS_TRACE_ATTR_HDR_LEN(hdr)    (hdr & 0x0fff)
#define WARTS_TRACE_ATTR_EOF       0x0000
#define WARTS_TRACE_ATTR_PMTUD     0x1
#define WARTS_TRACE_ATTR_LASTDITCH 0x2
#define WARTS_TRACE_ATTR_DTREE     0x3

/*
 * the optional bits of a trace structure
 */
#define WARTS_TRACE_LIST_ID        1   /* list id assigned by warts */
#define WARTS_TRACE_CYCLE_ID       2   /* cycle id assigned by warts */
#define WARTS_TRACE_ADDR_SRC_GID   3   /* src address key, deprecated */
#define WARTS_TRACE_ADDR_DST_GID   4   /* dst address key, deprecated */
#define WARTS_TRACE_START          5   /* start timestamp */
#define WARTS_TRACE_STOP_R         6   /* stop reason */
#define WARTS_TRACE_STOP_D         7   /* stop data */
#define WARTS_TRACE_FLAGS          8   /* flags */
#define WARTS_TRACE_ATTEMPTS       9   /* attempts */
#define WARTS_TRACE_HOPLIMIT       10  /* hoplimit */
#define WARTS_TRACE_TYPE           11  /* type */
#define WARTS_TRACE_PROBE_S        12  /* probe size */
#define WARTS_TRACE_PORT_SRC       13  /* source port */
#define WARTS_TRACE_PORT_DST       14  /* destination port */
#define WARTS_TRACE_FIRSTHOP       15  /* first hop */
#define WARTS_TRACE_TOS            16  /* type of service bits */
#define WARTS_TRACE_WAIT           17  /* how long to wait per probe */
#define WARTS_TRACE_LOOPS          18  /* max loops before stopping */
#define WARTS_TRACE_HOPCOUNT       19  /* hop count */
#define WARTS_TRACE_GAPLIMIT       20  /* gap limit */
#define WARTS_TRACE_GAPACTION      21  /* gap action */
#define WARTS_TRACE_LOOPACTION     22  /* loop action */
#define WARTS_TRACE_PROBEC         23  /* probe count */
#define WARTS_TRACE_WAITPROBE      24  /* min wait between probes */
#define WARTS_TRACE_CONFIDENCE     25  /* confidence level to attain */
#define WARTS_TRACE_ADDR_SRC       26  /* source address key */
#define WARTS_TRACE_ADDR_DST       27  /* destination address key */
#define WARTS_TRACE_USERID         28  /* user id */
#define WARTS_TRACE_OFFSET         29  /* IP offset to use in fragments */

static const warts_var_t trace_vars[] =
{
  {WARTS_TRACE_LIST_ID,      4, -1},
  {WARTS_TRACE_CYCLE_ID,     4, -1},
  {WARTS_TRACE_ADDR_SRC_GID, 4, -1},
  {WARTS_TRACE_ADDR_DST_GID, 4, -1},
  {WARTS_TRACE_START,        8, -1},
  {WARTS_TRACE_STOP_R,       1, -1},
  {WARTS_TRACE_STOP_D,       1, -1},
  {WARTS_TRACE_FLAGS,        1, -1},
  {WARTS_TRACE_ATTEMPTS,     1, -1},
  {WARTS_TRACE_HOPLIMIT,     1, -1},
  {WARTS_TRACE_TYPE,         1, -1},
  {WARTS_TRACE_PROBE_S,      2, -1},
  {WARTS_TRACE_PORT_SRC,     2, -1},
  {WARTS_TRACE_PORT_DST,     2, -1},
  {WARTS_TRACE_FIRSTHOP,     1, -1},
  {WARTS_TRACE_TOS,          1, -1},
  {WARTS_TRACE_WAIT,         1, -1},
  {WARTS_TRACE_LOOPS,        1, -1},
  {WARTS_TRACE_HOPCOUNT,     2, -1},
  {WARTS_TRACE_GAPLIMIT,     1, -1},
  {WARTS_TRACE_GAPACTION,    1, -1},
  {WARTS_TRACE_LOOPACTION,   1, -1},
  {WARTS_TRACE_PROBEC,       2, -1},
  {WARTS_TRACE_WAITPROBE,    1, -1},
  {WARTS_TRACE_CONFIDENCE,   1, -1},
  {WARTS_TRACE_ADDR_SRC,    -1, -1},
  {WARTS_TRACE_ADDR_DST,    -1, -1},
  {WARTS_TRACE_USERID,       4, -1},
  {WARTS_TRACE_OFFSET,       2, -1},
};
#define trace_vars_mfb WARTS_VAR_MFB(trace_vars)

/*
 * the optional bits of a trace pmtud structure
 */
#define WARTS_TRACE_PMTUD_IFMTU  1       /* interface mtu */
#define WARTS_TRACE_PMTUD_PMTU   2       /* path mtu */
#define WARTS_TRACE_PMTUD_OUTMTU 3       /* mtu to gateway */
#define WARTS_TRACE_PMTUD_VER    4       /* version of data collection */
#define WARTS_TRACE_PMTUD_NOTEC  5       /* number of notes attached */
static const warts_var_t pmtud_vars[] =
{
  {WARTS_TRACE_PMTUD_IFMTU,  2, -1},
  {WARTS_TRACE_PMTUD_PMTU,   2, -1},
  {WARTS_TRACE_PMTUD_OUTMTU, 2, -1},
  {WARTS_TRACE_PMTUD_VER,    1, -1},
  {WARTS_TRACE_PMTUD_NOTEC,  1, -1},
};
#define pmtud_vars_mfb WARTS_VAR_MFB(pmtud_vars)

#define WARTS_TRACE_PMTUD_N_TYPE  1      /* type of note */
#define WARTS_TRACE_PMTUD_N_NHMTU 2      /* nhmtu measured */
#define WARTS_TRACE_PMTUD_N_HOP   3      /* hop record; index into hops */
static const warts_var_t pmtud_n_vars[] =
{
  {WARTS_TRACE_PMTUD_N_TYPE,  1, -1},
  {WARTS_TRACE_PMTUD_N_NHMTU, 2, -1},
  {WARTS_TRACE_PMTUD_N_HOP,   2, -1},
};
#define pmtud_n_vars_mfb WARTS_VAR_MFB(pmtud_n_vars)

/*
 * the optional bits of a trace dtree structure
 */
#define WARTS_TRACE_DTREE_LSS_STOP_GID 1 /* deprecated */
#define WARTS_TRACE_DTREE_GSS_STOP_GID 2 /* deprecated */
#define WARTS_TRACE_DTREE_FIRSTHOP     3 /* firsthop */
#define WARTS_TRACE_DTREE_LSS_STOP     4 /* lss stop address */
#define WARTS_TRACE_DTREE_GSS_STOP     5 /* gss stop address */
#define WARTS_TRACE_DTREE_LSS_NAME     6 /* lss name */
#define WARTS_TRACE_DTREE_FLAGS        7 /* flags */
static const warts_var_t trace_dtree_vars[] =
{
  {WARTS_TRACE_DTREE_LSS_STOP_GID,  4, -1},
  {WARTS_TRACE_DTREE_GSS_STOP_GID,  4, -1},
  {WARTS_TRACE_DTREE_FIRSTHOP,      1, -1},
  {WARTS_TRACE_DTREE_LSS_STOP,     -1, -1},
  {WARTS_TRACE_DTREE_GSS_STOP,     -1, -1},
  {WARTS_TRACE_DTREE_LSS_NAME,     -1, -1},
  {WARTS_TRACE_DTREE_FLAGS,         1, -1},
};
#define trace_dtree_vars_mfb WARTS_VAR_MFB(trace_dtree_vars)

/*
 * the optional bits of a trace hop structure
 */
#define WARTS_TRACE_HOP_ADDR_GID     1       /* address id, deprecated */
#define WARTS_TRACE_HOP_PROBE_TTL    2       /* probe ttl */
#define WARTS_TRACE_HOP_REPLY_TTL    3       /* reply ttl */
#define WARTS_TRACE_HOP_FLAGS        4       /* flags */
#define WARTS_TRACE_HOP_PROBE_ID     5       /* probe id */
#define WARTS_TRACE_HOP_RTT          6       /* round trip time */
#define WARTS_TRACE_HOP_ICMP_TC      7       /* icmp type / code */
#define WARTS_TRACE_HOP_PROBE_SIZE   8       /* probe size */
#define WARTS_TRACE_HOP_REPLY_SIZE   9       /* reply size */
#define WARTS_TRACE_HOP_REPLY_IPID   10      /* ipid of reply packet */
#define WARTS_TRACE_HOP_REPLY_IPTOS  11      /* tos bits of reply packet */
#define WARTS_TRACE_HOP_NHMTU        12      /* next hop mtu in ptb message */
#define WARTS_TRACE_HOP_Q_IPLEN      13      /* ip->len from inside icmp */
#define WARTS_TRACE_HOP_Q_IPTTL      14      /* ip->ttl from inside icmp */
#define WARTS_TRACE_HOP_TCP_FLAGS    15      /* tcp->flags of reply packet */
#define WARTS_TRACE_HOP_Q_IPTOS      16      /* ip->tos byte inside icmp */
#define WARTS_TRACE_HOP_ICMPEXT      17      /* RFC 4884 icmp extension data */
#define WARTS_TRACE_HOP_ADDR         18      /* address */
#define WARTS_TRACE_HOP_TX           19      /* transmit time */
static const warts_var_t hop_vars[] =
{
  {WARTS_TRACE_HOP_ADDR_GID,     4, -1},
  {WARTS_TRACE_HOP_PROBE_TTL,    1, -1},
  {WARTS_TRACE_HOP_REPLY_TTL,    1, -1},
  {WARTS_TRACE_HOP_FLAGS,        1, -1},
  {WARTS_TRACE_HOP_PROBE_ID,     1, -1},
  {WARTS_TRACE_HOP_RTT,          4, -1},
  {WARTS_TRACE_HOP_ICMP_TC,      2, -1},
  {WARTS_TRACE_HOP_PROBE_SIZE,   2, -1},
  {WARTS_TRACE_HOP_REPLY_SIZE,   2, -1},
  {WARTS_TRACE_HOP_REPLY_IPID,   2, -1},
  {WARTS_TRACE_HOP_REPLY_IPTOS,  1, -1},
  {WARTS_TRACE_HOP_NHMTU,        2, -1},
  {WARTS_TRACE_HOP_Q_IPLEN,      2, -1},
  {WARTS_TRACE_HOP_Q_IPTTL,      1, -1},
  {WARTS_TRACE_HOP_TCP_FLAGS,    1, -1},
  {WARTS_TRACE_HOP_Q_IPTOS,      1, -1},
  {WARTS_TRACE_HOP_ICMPEXT,     -1, -1},
  {WARTS_TRACE_HOP_ADDR,        -1, -1},
  {WARTS_TRACE_HOP_TX,           8, -1},
};
#define hop_vars_mfb WARTS_VAR_MFB(hop_vars)

typedef struct warts_trace_hop
{
  scamper_trace_hop_t *hop;
  uint8_t              flags[WARTS_VAR_MFB(hop_vars)];
  uint16_t             flags_len;
  uint16_t             params_len;
} warts_trace_hop_t;

typedef struct warts_trace_dtree
{
  uint8_t              flags[WARTS_VAR_MFB(trace_dtree_vars)];
  uint16_t             flags_len;
  uint16_t             params_len;
  uint32_t             len;
} warts_trace_dtree_t;

typedef struct warts_trace_pmtud_n
{
  uint8_t              flags[pmtud_n_vars_mfb];
  uint16_t             flags_len;
  uint16_t             params_len;
  uint16_t             hop;
} warts_trace_pmtud_n_t;

typedef struct warts_trace_pmtud
{
  uint8_t                flags[pmtud_vars_mfb];
  uint16_t               flags_len;
  uint16_t               params_len;
  warts_trace_hop_t     *hops;
  uint16_t               hopc;
  warts_trace_pmtud_n_t *notes;
  uint32_t               len;
} warts_trace_pmtud_t;

static void warts_trace_params(const scamper_trace_t *trace,
			       warts_addrtable_t *table, uint8_t *flags,
			       uint16_t *flags_len, uint16_t *params_len)
{
  int max_id = 0;
  const warts_var_t *var;
  size_t i;

  /* unset all the flags possible */
  memset(flags, 0, trace_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(trace_vars)/sizeof(warts_var_t); i++)
    {
      var = &trace_vars[i];

      if(var->id == WARTS_TRACE_ADDR_SRC_GID ||
	 var->id == WARTS_TRACE_ADDR_DST_GID)
	{
	  continue;
	}

      if(var->id == WARTS_TRACE_USERID)
	{
	  if(trace->userid == 0)
	    continue;
	}

      if(var->id == WARTS_TRACE_OFFSET)
	{
	  if(trace->offset == 0)
	    continue;
	}

      flag_set(flags, var->id, &max_id);

      if(var->id == WARTS_TRACE_ADDR_SRC)
	{
	  *params_len += warts_addr_size(table, trace->src);
	  continue;
	}
      else if(var->id == WARTS_TRACE_ADDR_DST)
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

static int warts_trace_params_read(scamper_trace_t *trace,warts_state_t *state,
				   warts_addrtable_t *table,
				   uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&trace->list,        (wpr_t)extract_list,     state},
    {&trace->cycle,       (wpr_t)extract_cycle,    state},
    {&trace->src,         (wpr_t)extract_addr_gid, state},
    {&trace->dst,         (wpr_t)extract_addr_gid, state},
    {&trace->start,       (wpr_t)extract_timeval,  NULL},
    {&trace->stop_reason, (wpr_t)extract_byte,     NULL},
    {&trace->stop_data,   (wpr_t)extract_byte,     NULL},
    {&trace->flags,       (wpr_t)extract_byte,     NULL},
    {&trace->attempts,    (wpr_t)extract_byte,     NULL},
    {&trace->hoplimit,    (wpr_t)extract_byte,     NULL},
    {&trace->type,        (wpr_t)extract_byte,     NULL},
    {&trace->probe_size,  (wpr_t)extract_uint16,   NULL},
    {&trace->sport,       (wpr_t)extract_uint16,   NULL},
    {&trace->dport,       (wpr_t)extract_uint16,   NULL},
    {&trace->firsthop,    (wpr_t)extract_byte,     NULL},
    {&trace->tos,         (wpr_t)extract_byte,     NULL},
    {&trace->wait,        (wpr_t)extract_byte,     NULL},
    {&trace->loops,       (wpr_t)extract_byte,     NULL},
    {&trace->hop_count,   (wpr_t)extract_uint16,   NULL},
    {&trace->gaplimit,    (wpr_t)extract_byte,     NULL},
    {&trace->gapaction,   (wpr_t)extract_byte,     NULL},
    {&trace->loopaction,  (wpr_t)extract_byte,     NULL},
    {&trace->probec,      (wpr_t)extract_uint16,   NULL},
    {&trace->wait_probe,  (wpr_t)extract_byte,     NULL},
    {&trace->confidence,  (wpr_t)extract_byte,     NULL},
    {&trace->src,         (wpr_t)extract_addr,     table},
    {&trace->dst,         (wpr_t)extract_addr,     table},
    {&trace->userid,      (wpr_t)extract_uint32,   NULL},
    {&trace->offset,      (wpr_t)extract_uint16,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  int rc;

  if((rc = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0)
    return rc;
  if(trace->dst == NULL)
    return -1;
  if(trace->firsthop == 0)
    trace->firsthop = 1;

  return 0;
}

static int warts_trace_params_write(const scamper_trace_t *trace,
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
    {&list_id,            (wpw_t)insert_uint32,  NULL},
    {&cycle_id,           (wpw_t)insert_uint32,  NULL},
    {NULL,                NULL,                  NULL},
    {NULL,                NULL,                  NULL},
    {&trace->start,       (wpw_t)insert_timeval, NULL},
    {&trace->stop_reason, (wpw_t)insert_byte,    NULL},
    {&trace->stop_data,   (wpw_t)insert_byte,    NULL},
    {&trace->flags,       (wpw_t)insert_byte,    NULL},
    {&trace->attempts,    (wpw_t)insert_byte,    NULL},
    {&trace->hoplimit,    (wpw_t)insert_byte,    NULL},
    {&trace->type,        (wpw_t)insert_byte,    NULL},
    {&trace->probe_size,  (wpw_t)insert_uint16,  NULL},
    {&trace->sport,       (wpw_t)insert_uint16,  NULL},
    {&trace->dport,       (wpw_t)insert_uint16,  NULL},
    {&trace->firsthop,    (wpw_t)insert_byte,    NULL},
    {&trace->tos,         (wpw_t)insert_byte,    NULL},
    {&trace->wait,        (wpw_t)insert_byte,    NULL},
    {&trace->loops,       (wpw_t)insert_byte,    NULL},
    {&trace->hop_count,   (wpw_t)insert_uint16,  NULL},
    {&trace->gaplimit,    (wpw_t)insert_byte,    NULL},
    {&trace->gapaction,   (wpw_t)insert_byte,    NULL},
    {&trace->loopaction,  (wpw_t)insert_byte,    NULL},
    {&trace->probec,      (wpw_t)insert_uint16,  NULL},
    {&trace->wait_probe,  (wpw_t)insert_byte,    NULL},
    {&trace->confidence,  (wpw_t)insert_byte,    NULL},
    {trace->src,          (wpw_t)insert_addr,    table},
    {trace->dst,          (wpw_t)insert_addr,    table},
    {&trace->userid,      (wpw_t)insert_uint32,  NULL},
    {&trace->offset,      (wpw_t)insert_uint16,  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  trace->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, trace->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return 0;
}

static int warts_trace_hop_read_icmp_tc(const uint8_t *buf, uint32_t *off,
					uint32_t len, scamper_trace_hop_t *hop,
					void *param)
{
  if(len - *off < 2)
    return -1;
  hop->hop_icmp_type = buf[(*off)++];
  hop->hop_icmp_code = buf[(*off)++];
  return 0;
}

static void warts_trace_hop_write_icmp_tc(uint8_t *buf, uint32_t *off,
					  const uint32_t len,
					  const scamper_trace_hop_t *hop,
					  void *param)
{
  assert(len - *off >= 2);
  buf[(*off)++] = hop->hop_icmp_type;
  buf[(*off)++] = hop->hop_icmp_code;
  return;
}

static int warts_trace_hop_read_probe_id(const uint8_t *buf, uint32_t *off,
					 uint32_t len, uint8_t *out,
					 void *param)
{
  if(len - *off < 1)
    {
      return -1;
    }
  *out = buf[(*off)++] + 1;
  return 0;
}

static void warts_trace_hop_write_probe_id(uint8_t *buf, uint32_t *off,
					   const uint32_t len,
					   const uint8_t *in, void *param)
{
  assert(len - *off >= 1);
  buf[(*off)++] = *in - 1;
  return;
}

static int warts_trace_hop_read_icmpext(const uint8_t *buf, uint32_t *off,
					uint32_t len, scamper_trace_hop_t *hop,
					void *param)
{
  return warts_icmpext_read(buf, off, len, &hop->hop_icmpext);
}

static void warts_trace_hop_write_icmpext(uint8_t *buf, uint32_t *off,
					  const uint32_t len,
					  const scamper_trace_hop_t *hop,
					  void *param)
{
  warts_icmpext_write(buf, off, len, hop->hop_icmpext);
  return;
}

static void warts_trace_hop_params(const scamper_trace_t *trace,
				   const scamper_trace_hop_t *hop,
				   warts_addrtable_t *table, uint8_t *flags,
				   uint16_t *flags_len, uint16_t *params_len)
{
  scamper_icmpext_t *ie;
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(flags, 0, hop_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(hop_vars)/sizeof(warts_var_t); i++)
    {
      var = &hop_vars[i];

      /* not used any more */
      if(var->id == WARTS_TRACE_HOP_ADDR_GID)
	continue;

      if(var->id == WARTS_TRACE_HOP_ADDR)
	{
	  if(hop->hop_addr == NULL)
	    continue;
	}
      else if(var->id == WARTS_TRACE_HOP_TCP_FLAGS)
	{
	  if(SCAMPER_TRACE_HOP_IS_TCP(hop) == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACE_HOP_ICMP_TC)
	{
	  if(SCAMPER_TRACE_HOP_IS_ICMP(hop) == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACE_HOP_Q_IPLEN)
	{
	  if(SCAMPER_TRACE_HOP_IS_ICMP_Q(hop) == 0)
	    continue;
	  if(hop->hop_icmp_q_ipl == trace->probe_size)
	    continue;
	}
      else if(var->id == WARTS_TRACE_HOP_Q_IPTTL)
	{
	  if(SCAMPER_TRACE_HOP_IS_ICMP_Q(hop) == 0)
	    continue;
	  if(hop->hop_icmp_q_ttl == 1)
	    continue;
	}
      else if(var->id == WARTS_TRACE_HOP_Q_IPTOS)
	{
	  if(SCAMPER_TRACE_HOP_IS_ICMP_Q(hop) == 0)
	    continue;
	  if(hop->hop_addr->type != SCAMPER_ADDR_TYPE_IPV4)
	    continue;
	}
      else if(var->id == WARTS_TRACE_HOP_NHMTU)
	{
	  if(SCAMPER_TRACE_HOP_IS_ICMP_PTB(hop) == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACE_HOP_ICMPEXT)
	{
	  if(hop->hop_icmpext == NULL)
	    continue;
	}
      else if(var->id == WARTS_TRACE_HOP_REPLY_IPID)
	{
	  if(hop->hop_reply_ipid == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACE_HOP_TX)
	{
	  if(hop->hop_tx.tv_sec == 0)
	    continue;
	}

      flag_set(flags, var->id, &max_id);

      if(var->id == WARTS_TRACE_HOP_ADDR)
	{
	  *params_len += warts_addr_size(table, hop->hop_addr);
	}
      else if(var->id == WARTS_TRACE_HOP_ICMPEXT)
	{
	  *params_len += 2;
	  for(ie = hop->hop_icmpext; ie != NULL; ie = ie->ie_next)
	    *params_len += (2 + 1 + 1 + ie->ie_dl);
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

static void warts_trace_hop_state(const scamper_trace_t *trace,
				  scamper_trace_hop_t *hop,
				  warts_trace_hop_t *state,
				  warts_addrtable_t *table, uint32_t *len)
{
  /* for each hop, figure out how much space it will take up */
  warts_trace_hop_params(trace, hop, table, state->flags, &state->flags_len,
			 &state->params_len);

  /* store the actual hop record with the state structure too */
  state->hop = hop;

  /* increase length required for the trace record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0)
    *len += 2;

  return;
}

static int warts_trace_hop_read(scamper_trace_hop_t *hop, warts_state_t *state,
				warts_addrtable_t *table,
				const uint8_t *buf,uint32_t *off,uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&hop->hop_addr,       (wpr_t)extract_addr_gid,              state},
    {&hop->hop_probe_ttl,  (wpr_t)extract_byte,                  NULL},
    {&hop->hop_reply_ttl,  (wpr_t)extract_byte,                  NULL},
    {&hop->hop_flags,      (wpr_t)extract_byte,                  NULL},
    {&hop->hop_probe_id,   (wpr_t)warts_trace_hop_read_probe_id, NULL},
    {&hop->hop_rtt,        (wpr_t)extract_rtt,                   NULL},
    {hop,                  (wpr_t)warts_trace_hop_read_icmp_tc,  NULL},
    {&hop->hop_probe_size, (wpr_t)extract_uint16,                NULL},
    {&hop->hop_reply_size, (wpr_t)extract_uint16,                NULL},
    {&hop->hop_reply_ipid, (wpr_t)extract_uint16,                NULL},
    {&hop->hop_reply_tos,  (wpr_t)extract_byte,                  NULL},
    {&hop->hop_icmp_nhmtu, (wpr_t)extract_uint16,                NULL},
    {&hop->hop_icmp_q_ipl, (wpr_t)extract_uint16,                NULL},
    {&hop->hop_icmp_q_ttl, (wpr_t)extract_byte,                  NULL},
    {&hop->hop_tcp_flags,  (wpr_t)extract_byte,                  NULL},
    {&hop->hop_icmp_q_tos, (wpr_t)extract_byte,                  NULL},
    {hop,                  (wpr_t)warts_trace_hop_read_icmpext,  NULL},
    {&hop->hop_addr,       (wpr_t)extract_addr,                  table},
    {&hop->hop_tx,         (wpr_t)extract_timeval,               NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  uint32_t o = *off;
  int rc;

  if((rc = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0)
    return rc;

  if(hop->hop_addr == NULL)
    return -1;
  if(hop->hop_probe_ttl == 0)
    return -1;

  if(SCAMPER_TRACE_HOP_IS_ICMP_Q(hop))
    {
      if(flag_isset(&buf[o], WARTS_TRACE_HOP_Q_IPTTL) == 0)
	hop->hop_icmp_q_ttl = 1;
      if(flag_isset(&buf[o], WARTS_TRACE_HOP_Q_IPLEN) == 0)
	hop->hop_icmp_q_ipl = hop->hop_probe_size;
    }

  return 0;
}

static void warts_trace_hop_write(const warts_trace_hop_t *state,
				  warts_addrtable_t *table,
				  uint8_t *buf, uint32_t *off, uint32_t len)
{
  scamper_trace_hop_t *hop = state->hop;
  warts_param_writer_t handlers[] = {
    {NULL,                 NULL,                                  NULL},
    {&hop->hop_probe_ttl,  (wpw_t)insert_byte,                    NULL},
    {&hop->hop_reply_ttl,  (wpw_t)insert_byte,                    NULL},
    {&hop->hop_flags,      (wpw_t)insert_byte,                    NULL},
    {&hop->hop_probe_id,   (wpw_t)warts_trace_hop_write_probe_id, NULL},
    {&hop->hop_rtt,        (wpw_t)insert_rtt,                     NULL},
    {hop,                  (wpw_t)warts_trace_hop_write_icmp_tc,  NULL},
    {&hop->hop_probe_size, (wpw_t)insert_uint16,                  NULL},
    {&hop->hop_reply_size, (wpw_t)insert_uint16,                  NULL},
    {&hop->hop_reply_ipid, (wpw_t)insert_uint16,                  NULL},
    {&hop->hop_reply_tos,  (wpw_t)insert_byte,                    NULL},
    {&hop->hop_icmp_nhmtu, (wpw_t)insert_uint16,                  NULL},
    {&hop->hop_icmp_q_ipl, (wpw_t)insert_uint16,                  NULL},
    {&hop->hop_icmp_q_ttl, (wpw_t)insert_byte,                    NULL},
    {&hop->hop_tcp_flags,  (wpw_t)insert_byte,                    NULL},
    {&hop->hop_icmp_q_tos, (wpw_t)insert_byte,                    NULL},
    {hop,                  (wpw_t)warts_trace_hop_write_icmpext,  NULL},
    {hop->hop_addr,        (wpw_t)insert_addr,                    table},
    {&hop->hop_tx,         (wpw_t)insert_timeval,                 NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int warts_trace_hops_read(scamper_trace_hop_t **hops,
				 warts_state_t *state,
				 warts_addrtable_t *table, const uint8_t *buf,
				 uint32_t *off, uint32_t len, uint16_t count)
{
  scamper_trace_hop_t *head = NULL, *hop = NULL;
  uint16_t i;

  for(i=0; i<count; i++)
    {
      /*
       * the hop list is stored in a linked list; add each new hop to the
       * end of the list
       */
      if(hop != NULL)
	{
	  hop->hop_next = scamper_trace_hop_alloc();
	  hop = hop->hop_next;
	}
      else
	{
	  head = hop = scamper_trace_hop_alloc();
	}

      /* could not allocate an empty hop structure ... */
      if(hop == NULL)
	goto err;

      if(warts_trace_hop_read(hop, state, table, buf, off, len) != 0)
	goto err;
    }

  *hops = head;
  return 0;

 err:
  while(head != NULL)
    {
      hop = head;
      head = head->hop_next;
      scamper_trace_hop_free(hop);
    }
  return -1;
}

static void warts_trace_pmtud_n_params(const scamper_trace_pmtud_t *pmtud,
				       const scamper_trace_pmtud_n_t *n,
				       warts_trace_pmtud_n_t *state)
{
  const scamper_trace_hop_t *hop;
  const warts_var_t *var;
  uint16_t u16;
  int i, max_id = 0;

  memset(state->flags, 0, pmtud_n_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(pmtud_n_vars)/sizeof(warts_var_t); i++)
    {
      var = &pmtud_n_vars[i];
      if(var->id == WARTS_TRACE_PMTUD_N_TYPE)
	{
	  if(n->type == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACE_PMTUD_N_NHMTU)
	{
	  if(n->nhmtu == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACE_PMTUD_N_HOP)
	{
	  if(n->hop == NULL)
	    continue;

	  u16 = 0;
	  for(hop = pmtud->hops; hop != NULL; hop = hop->hop_next)
	    {
	      if(hop == n->hop)
		break;
	      u16++;
	    }
	  assert(hop != NULL);
	  state->hop = u16;
	}

      flag_set(state->flags, var->id, &max_id);
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);
  return;
}

static void warts_trace_pmtud_n_write(const scamper_trace_pmtud_n_t *note,
				      uint8_t *buf, uint32_t *off, uint32_t len,
				      warts_trace_pmtud_n_t *state)
{
  warts_param_writer_t handlers[] = {
    {&note->type,           (wpw_t)insert_byte,   NULL},
    {&note->nhmtu,          (wpw_t)insert_uint16, NULL},
    {&state->hop,           (wpw_t)insert_uint16, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int warts_trace_pmtud_n_read(const scamper_trace_pmtud_t *pmtud,
				    scamper_trace_pmtud_n_t *note,
				    const uint8_t *buf, uint32_t *off,
				    uint32_t len)
{
  scamper_trace_hop_t *hop;
  uint16_t u16 = 0;
  warts_param_reader_t handlers[] = {
    {&note->type,  (wpr_t)extract_byte,   NULL},
    {&note->nhmtu, (wpr_t)extract_uint16, NULL},
    {&u16,         (wpr_t)extract_uint16, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  uint32_t o = *off;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(flag_isset(&buf[o], WARTS_TRACE_PMTUD_N_HOP))
    {
      hop = pmtud->hops;
      while(u16 > 0)
	{
	  if(hop == NULL)
	    break;
	  hop = hop->hop_next;
	  u16--;
	}
      if(hop == NULL)
	return -1;
      note->hop = hop;
    }

  return 0;
}

static void warts_trace_pmtud_params(const scamper_trace_t *trace,
				     warts_trace_pmtud_t *state)
{
  const scamper_trace_pmtud_t *pmtud = trace->pmtud;
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(state->flags, 0, pmtud_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(pmtud_vars)/sizeof(warts_var_t); i++)
    {
      var = &pmtud_vars[i];
      if(var->id == WARTS_TRACE_PMTUD_IFMTU)
	{
	  if(pmtud->ifmtu == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACE_PMTUD_PMTU)
	{
	  if(pmtud->pmtu == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACE_PMTUD_OUTMTU)
	{
	  if(pmtud->outmtu == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACE_PMTUD_NOTEC)
	{
	  if(pmtud->notec == 0)
	    continue;
	}

      flag_set(state->flags, var->id, &max_id);
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);
  return;
}

static int warts_trace_pmtud_state(const scamper_trace_t *trace,
				   warts_trace_pmtud_t *state,
				   warts_addrtable_t *table)
{
  warts_trace_pmtud_n_t *note;
  scamper_trace_hop_t *hop;
  uint8_t i;
  size_t size;
  int j;

  /* figure out what the structure of the pmtud header looks like */
  warts_trace_pmtud_params(trace, state);

  /* flags + params + number of hop records for pmtud structure */
  state->len = state->flags_len + state->params_len + 2;
  if(state->params_len != 0)
    state->len += 2;

  /* count the number of hop records */
  state->hopc = scamper_trace_pmtud_hop_count(trace);
  if(state->hopc > 0)
    {
      /* allocate an array of address indexes for the pmtud hop addresses */
      size = state->hopc * sizeof(warts_trace_hop_t);
      if((state->hops = (warts_trace_hop_t *)malloc_zero(size)) == NULL)
	return -1;

      /* record hop state for each pmtud hop */
      for(hop = trace->pmtud->hops, j=0; hop != NULL; hop = hop->hop_next)
	warts_trace_hop_state(trace,hop,&state->hops[j++],table,&state->len);
    }

  /* record state for each pmtud note */
  if(trace->pmtud->notec > 0)
    {
      size = trace->pmtud->notec * sizeof(warts_trace_pmtud_n_t);
      if((state->notes = (warts_trace_pmtud_n_t *)malloc_zero(size)) == NULL)
	return -1;
      for(i=0; i<trace->pmtud->notec; i++)
	{
	  note = &state->notes[i];
	  warts_trace_pmtud_n_params(trace->pmtud,trace->pmtud->notes[i],note);

	  /* increase length required for the trace record */
	  state->len += note->flags_len + note->params_len;
	  if(note->params_len != 0)
	    state->len += 2;
	}
    }

  return 0;
}

static int warts_trace_pmtud_read(scamper_trace_t *trace, warts_state_t *state,
				  warts_addrtable_t *table, const uint8_t *buf,
				  uint32_t *off, uint32_t len)
{
  uint16_t ifmtu = 0, pmtu = 0, outmtu = 0;
  uint8_t  ver = 1, notec = 0;
  warts_param_reader_t handlers[] = {
    {&ifmtu,  (wpr_t)extract_uint16, NULL},
    {&pmtu,   (wpr_t)extract_uint16, NULL},
    {&outmtu, (wpr_t)extract_uint16, NULL},
    {&ver,    (wpr_t)extract_byte,   NULL},
    {&notec,  (wpr_t)extract_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  scamper_trace_pmtud_n_t *n = NULL;
  scamper_trace_hop_t *hops;
  uint16_t count;
  uint8_t u8;

  if(scamper_trace_pmtud_alloc(trace) != 0)
    goto err;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto err;
  trace->pmtud->ifmtu  = ifmtu;
  trace->pmtud->pmtu   = pmtu;
  trace->pmtud->outmtu = outmtu;
  trace->pmtud->ver    = ver;
  trace->pmtud->notec  = notec;

  /* the number of hop records that follow */
  if(extract_uint16(buf, off, len, &count, NULL) != 0)
    goto err;
  if(count != 0)
    {
      if(warts_trace_hops_read(&hops,state,table,buf,off,len,count) != 0)
	goto err;
      trace->pmtud->hops = hops;
    }

  if(trace->pmtud->notec != 0)
    {
      if(scamper_trace_pmtud_n_alloc_c(trace->pmtud, trace->pmtud->notec) != 0)
	goto err;

      for(u8=0; u8<trace->pmtud->notec; u8++)
	{
	  if((n = scamper_trace_pmtud_n_alloc()) == NULL)
	    goto err;
	  if(warts_trace_pmtud_n_read(trace->pmtud, n, buf, off, len) != 0)
	    goto err;
	  trace->pmtud->notes[u8] = n; n = NULL;
	}
    }

  return 0;

 err:
  if(n != NULL) scamper_trace_pmtud_n_free(n);
  return -1;
}

static void warts_trace_pmtud_write(const scamper_trace_t *trace,
				    uint8_t *buf, uint32_t *off, uint32_t len,
				    warts_trace_pmtud_t *state,
				    warts_addrtable_t *table)
{
  warts_param_writer_t handlers[] = {
    {&trace->pmtud->ifmtu,  (wpw_t)insert_uint16, NULL},
    {&trace->pmtud->pmtu,   (wpw_t)insert_uint16, NULL},
    {&trace->pmtud->outmtu, (wpw_t)insert_uint16, NULL},
    {&trace->pmtud->ver,    (wpw_t)insert_byte,   NULL},
    {&trace->pmtud->notec,  (wpw_t)insert_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  uint16_t u16;
  uint8_t u8;

  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);

  /* write the number of hop records */
  insert_uint16(buf, off, len, &state->hopc, NULL);

  /* write the hop records */
  for(u16=0; u16<state->hopc; u16++)
    warts_trace_hop_write(&state->hops[u16], table, buf, off, len);

  /* write the notes */
  for(u8=0; u8<trace->pmtud->notec; u8++)
    warts_trace_pmtud_n_write(trace->pmtud->notes[u8], buf, off, len,
			      &state->notes[u8]);

  return;
}

static void warts_trace_pmtud_free(warts_trace_pmtud_t *state)
{
  if(state == NULL)
    return;
  if(state->hops != NULL) free(state->hops);
  free(state);
  return;
}

static int warts_trace_lastditch_read(scamper_trace_t *trace,
				      warts_state_t *state,
				      warts_addrtable_t *table,
				      const uint8_t *buf,
				      uint32_t *off, uint32_t len)
{
  scamper_trace_hop_t *hops;
  uint16_t count;

  if(warts_params_read(buf, off, len, NULL, 0) != 0)
    goto err;

  if(extract_uint16(buf, off, len, &count, NULL) != 0)
    goto err;

  if(count != 0)
    {
      if(warts_trace_hops_read(&hops,state,table,buf,off,len,count) != 0)
	goto err;
      trace->lastditch = hops;
    }

  return 0;

 err:
  return -1;
}

static int warts_trace_dtree_params(const scamper_file_t *sf,
				    const scamper_trace_t *trace,
				    warts_addrtable_t *table,
				    warts_trace_dtree_t *state)
{
  scamper_trace_dtree_t *dtree = trace->dtree;
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(state->flags, 0, trace_dtree_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(trace_dtree_vars)/sizeof(warts_var_t); i++)
    {
      var = &trace_dtree_vars[i];

      /* not used any more */
      if(var->id == WARTS_TRACE_DTREE_LSS_STOP_GID ||
	 var->id == WARTS_TRACE_DTREE_GSS_STOP_GID)
	continue;

      if((var->id == WARTS_TRACE_DTREE_LSS_STOP && dtree->lss_stop == NULL) ||
	 (var->id == WARTS_TRACE_DTREE_LSS_NAME && dtree->lss == NULL) ||
	 (var->id == WARTS_TRACE_DTREE_GSS_STOP && dtree->gss_stop == NULL) ||
	 (var->id == WARTS_TRACE_DTREE_FLAGS    && dtree->flags == 0))
	continue;

      flag_set(state->flags, var->id, &max_id);

      /* variables that don't have a fixed size */
      if(var->id == WARTS_TRACE_DTREE_LSS_STOP)
	{
	  state->params_len += warts_addr_size(table, dtree->lss_stop);
	  continue;
	}
      else if(var->id == WARTS_TRACE_DTREE_LSS_NAME)
	{
	  state->params_len += warts_str_size(dtree->lss);
	  continue;
	}
      else if(var->id == WARTS_TRACE_DTREE_GSS_STOP)
	{
	  state->params_len += warts_addr_size(table, dtree->gss_stop);
	  continue;
	}

      assert(var->size != -1);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2 ;

  return 0;
}

static void warts_trace_dtree_write(const scamper_trace_t *trace,
				    warts_addrtable_t *table,
				    uint8_t *buf, uint32_t *off, uint32_t len,
				    warts_trace_dtree_t *state)
{
  warts_param_writer_t handlers[] = {
    {NULL,                    NULL,                 NULL},
    {NULL,                    NULL,                 NULL},
    {&trace->dtree->firsthop, (wpw_t)insert_byte,   NULL},
    {trace->dtree->lss_stop,  (wpw_t)insert_addr,   table},
    {trace->dtree->gss_stop,  (wpw_t)insert_addr,   table},
    {trace->dtree->lss,       (wpw_t)insert_string, NULL},
    {&trace->dtree->flags,    (wpw_t)insert_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);
  return;
}

static int warts_trace_dtree_read(scamper_trace_t *trace, warts_state_t *state,
				  warts_addrtable_t *table, const uint8_t *buf,
				  uint32_t *off, uint32_t len)
{
  scamper_addr_t *lss_stop = NULL, *gss_stop = NULL;
  uint8_t firsthop = 0, flags = 0;
  char *lss = NULL;

  warts_param_reader_t handlers[] = {
    {&lss_stop, (wpr_t)extract_addr_gid, state},
    {&gss_stop, (wpr_t)extract_addr_gid, state},
    {&firsthop, (wpr_t)extract_byte,     NULL},
    {&lss_stop, (wpr_t)extract_addr,     table},
    {&gss_stop, (wpr_t)extract_addr,     table},
    {&lss,      (wpr_t)extract_string,   NULL},
    {&flags,    (wpr_t)extract_byte,     NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(scamper_trace_dtree_alloc(trace) != 0 ||
     warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    {
      if(lss_stop != NULL) scamper_addr_free(lss_stop);
      if(gss_stop != NULL) scamper_addr_free(gss_stop);
      if(lss != NULL) free(lss);
      return -1;
    }

  trace->dtree->lss_stop = lss_stop;
  trace->dtree->gss_stop = gss_stop;
  trace->dtree->firsthop = firsthop;
  trace->dtree->lss      = lss;
  trace->dtree->flags    = flags;
  return 0;
}

/*
 * warts_trace_read
 *
 */
int scamper_file_warts_trace_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				  scamper_trace_t **trace_out)
{
  warts_state_t       *state = scamper_file_getstate(sf);
  scamper_trace_t     *trace = NULL;
  uint8_t             *buf = NULL;
  uint32_t             i, off = 0;
  scamper_trace_hop_t *hops = NULL;
  scamper_trace_hop_t *hop;
  uint16_t             count;
  uint8_t              max_ttl;
  uint8_t              type;
  uint16_t             len;
  uint16_t             u16;
  warts_addrtable_t   *table = NULL;

  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      *trace_out = NULL;
      return 0;
    }

  if((trace = scamper_trace_alloc()) == NULL)
    {
      goto err;
    }

  if((table = warts_addrtable_alloc_byid()) == NULL)
    goto err;

  /* read the trace's parameters */
  if(warts_trace_params_read(trace, state, table, buf, &off, hdr->len) != 0)
    {
      goto err;
    }

  /*
   * the next two bytes tell us how many scamper_hops to read out of trace
   * if we did not get any responses, we are done.
   */
  if(extract_uint16(buf, &off, hdr->len, &count, NULL) != 0)
    {
      goto err;
    }

  /* read all the hop records */
  if(warts_trace_hops_read(&hops,state,table,buf,&off,hdr->len,count) != 0)
    goto err;

  /* work out the maximum ttl probed with that got a response */
  max_ttl = 0;
  for(i=0, hop = hops; i < count; i++)
    {
      if(hop->hop_probe_ttl > max_ttl)
	max_ttl = hop->hop_probe_ttl;
      hop = hop->hop_next;
    }

  /*
   * if the hop_count field was provided in the file, then
   * make sure it makes sense based on the hop data we've just scanned
   */
  if(trace->hop_count != 0)
    {
      if(trace->hop_count < max_ttl)
	goto err;
      if(trace->hop_count > 255)
	goto err;
    }
  else
    {
      trace->hop_count = max_ttl;
    }

  /* allocate enough hops to string the trace together */
  if(scamper_trace_hops_alloc(trace, trace->hop_count) == -1)
    {
      goto err;
    }

  if(hops == NULL)
    {
      assert(count == 0);
      goto done;
    }

  /*
   * now loop through the hops array stored in this procedure
   * and assemble the responses into trace->hops.
   */
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

  for(;;)
    {
      if(extract_uint16(buf, &off, hdr->len, &u16, NULL) != 0)
	goto err;
      if(u16 == WARTS_TRACE_ATTR_EOF)
	break;

      type = WARTS_TRACE_ATTR_HDR_TYPE(u16);
      len  = WARTS_TRACE_ATTR_HDR_LEN(u16);

      if(type == WARTS_TRACE_ATTR_PMTUD)
	{
	  i = off;
	  if(warts_trace_pmtud_read(trace,state,table,buf,&i,hdr->len) != 0)
	    goto err;
	}
      else if(type == WARTS_TRACE_ATTR_LASTDITCH)
	{
	  i = off;
	  if(warts_trace_lastditch_read(trace, state, table,
 					buf, &i, hdr->len) != 0)
	    goto err;
	}
      else if(type == WARTS_TRACE_ATTR_DTREE)
	{
	  i = off;
	  if(warts_trace_dtree_read(trace,state,table,buf,&i,hdr->len) != 0)
	    goto err;
	}

      off += len;
    }

 done:
  warts_addrtable_free(table);
  free(buf);
  *trace_out = trace;
  return 0;

 err:
  if(table != NULL) warts_addrtable_free(table);
  if(hops != NULL) free(hops);
  if(buf != NULL) free(buf);
  if(trace != NULL) scamper_trace_free(trace);
  return -1;
}

int scamper_file_warts_trace_write(const scamper_file_t *sf,
				   const scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  uint8_t             *buf = NULL;
  uint8_t              trace_flags[trace_vars_mfb];
  uint16_t             trace_flags_len, trace_params_len;
  warts_trace_hop_t   *hop_state = NULL;
  uint16_t             hop_recs;
  warts_trace_pmtud_t *pmtud = NULL;
  warts_trace_hop_t   *ld_state = NULL;
  uint16_t             ld_recs = 0;
  uint32_t             ld_len = 0;
  warts_trace_dtree_t  dtree_state;
  uint16_t             u16;
  uint8_t              u8;
  uint32_t             off = 0, len, len2;
  size_t               size;
  int                  i, j;
  warts_addrtable_t   *table = NULL;

  memset(&dtree_state, 0, sizeof(dtree_state));

  if((table = warts_addrtable_alloc_byaddr()) == NULL)
    goto err;

  /* figure out which trace data items we'll store in this record */
  warts_trace_params(trace, table,
		     trace_flags, &trace_flags_len, &trace_params_len);

  /*
   * this represents the length of the trace's flags and parameters, and the
   * 2-byte field that records the number of hop records that follow
   */
  len = 8 + trace_flags_len + trace_params_len + 2;
  if(trace_params_len != 0) len += 2;

  /* for each hop, figure out what is going to be stored in this record */
  if((hop_recs = scamper_trace_hop_count(trace)) > 0)
    {
      size = hop_recs * sizeof(warts_trace_hop_t);
      if((hop_state = (warts_trace_hop_t *)malloc_zero(size)) == NULL)
	{
	  goto err;
	}

      for(i=0, j=0; i<trace->hop_count; i++)
	{
	  for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
	    {
	      /* record basic hop state */
	      len2 = len;
	      warts_trace_hop_state(trace,hop,&hop_state[j++],table,&len2);
	      if(len2 < len)
		goto err;
	      len = len2;
	    }
	}
    }

  /* figure out how much space we need for PMTUD data, if we have it */
  if(trace->pmtud != NULL)
    {
      if((pmtud = malloc_zero(sizeof(warts_trace_pmtud_t))) == NULL)
	goto err;

      if(warts_trace_pmtud_state(trace, pmtud, table) != 0)
	goto err;

      len += (2 + pmtud->len); /* 2 = size of attribute header */
    }

  if(trace->lastditch != NULL)
    {
      /* count the number of last-ditch hop records */
      ld_recs = scamper_trace_lastditch_hop_count(trace);

      /* allocate an array of hop state structs for the lastditch hops */
      size = ld_recs * sizeof(warts_trace_hop_t);
      if((ld_state = (warts_trace_hop_t *)malloc_zero(size)) == NULL)
	goto err;

      /* need to record count of lastditch hops and a single zero flags byte */
      ld_len = 3;

      /* record hop state for each lastditch reply */
      for(hop = trace->lastditch, j=0; hop != NULL; hop = hop->hop_next)
	warts_trace_hop_state(trace, hop, &ld_state[j++], table, &ld_len);

      len += (2 + ld_len); /* 2 = size of attribute header */
    }

  if(trace->dtree != NULL)
    {
      /* figure out what the structure of the dtree header looks like */
      if(warts_trace_dtree_params(sf, trace, table, &dtree_state) != 0)
	goto err;

      /* 2 = size of attribute header */
      len += (2 + dtree_state.len);
    }

  len += 2; /* EOF */

  if((buf = malloc_zero(len)) == NULL)
    {
      goto err;
    }

  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_TRACE);

  /* write trace parameters */
  if(warts_trace_params_write(trace, sf, table, buf, &off, len, trace_flags,
			      trace_flags_len, trace_params_len) == -1)
    {
      goto err;
    }

  /* hop record count */
  insert_uint16(buf, &off, len, &hop_recs, NULL);

  /* write each traceroute hop record */
  for(i=0; i<hop_recs; i++)
    warts_trace_hop_write(&hop_state[i], table, buf, &off, len);
  if(hop_state != NULL)
    free(hop_state);
  hop_state = NULL;

  /* write the PMTUD data */
  if(pmtud != NULL)
    {
      /* write the attribute header */
      u16 = WARTS_TRACE_ATTR_HDR(WARTS_TRACE_ATTR_PMTUD, pmtud->len);
      insert_uint16(buf, &off, len, &u16, NULL);

      /* write details of the pmtud measurement */
      warts_trace_pmtud_write(trace, buf, &off, len, pmtud, table);

      warts_trace_pmtud_free(pmtud);
      pmtud = NULL;
    }

  /* write the last-ditch data */
  if(trace->lastditch != NULL)
    {
      /* write the attribute header */
      u16 = WARTS_TRACE_ATTR_HDR(WARTS_TRACE_ATTR_LASTDITCH, ld_len);
      insert_uint16(buf, &off, len, &u16, NULL);

      /* write the last-ditch flags: currently zero */
      u8 = 0;
      insert_byte(buf, &off, len, &u8, NULL);

      /* write the number of hop records */
      insert_uint16(buf, &off, len, &ld_recs, NULL);

      for(i=0; i<ld_recs; i++)
	warts_trace_hop_write(&ld_state[i], table, buf, &off, len);

      free(ld_state);
      ld_state = NULL;
    }

  /* write doubletree data */
  if(trace->dtree != NULL)
    {
      u16 = WARTS_TRACE_ATTR_HDR(WARTS_TRACE_ATTR_DTREE, dtree_state.len);
      insert_uint16(buf, &off, len, &u16, NULL);

      /* write details of the pmtud measurement */
      warts_trace_dtree_write(trace, table, buf, &off, len, &dtree_state);
    }

  /* write the end of trace attributes header */
  u16 = WARTS_TRACE_ATTR_EOF;
  insert_uint16(buf, &off, len, &u16, NULL);

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
  if(buf != NULL) free(buf);
  if(hop_state != NULL) free(hop_state);
  if(pmtud != NULL) warts_trace_pmtud_free(pmtud);
  if(ld_state != NULL) free(ld_state);
  return -1;
}
