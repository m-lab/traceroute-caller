/*
 * scamper_neighbourdisc_warts.h
 *
 * $Id: scamper_neighbourdisc_warts.c,v 1.7 2016/12/02 09:13:42 mjl Exp $
 *
 * Copyright (C) 2009-2016 Matthew Luckie
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
  "$Id: scamper_neighbourdisc_warts.c,v 1.7 2016/12/02 09:13:42 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_neighbourdisc.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_neighbourdisc_warts.h"

#include "mjl_splaytree.h"
#include "utils.h"

#define WARTS_NEIGHBOURDISC_LIST     1
#define WARTS_NEIGHBOURDISC_CYCLE    2
#define WARTS_NEIGHBOURDISC_USERID   3
#define WARTS_NEIGHBOURDISC_IFNAME   4
#define WARTS_NEIGHBOURDISC_START    5
#define WARTS_NEIGHBOURDISC_METHOD   6
#define WARTS_NEIGHBOURDISC_WAIT     7
#define WARTS_NEIGHBOURDISC_FLAGS    8
#define WARTS_NEIGHBOURDISC_ATTEMPTS 9
#define WARTS_NEIGHBOURDISC_REPLYC   10
#define WARTS_NEIGHBOURDISC_SRC_IP   11
#define WARTS_NEIGHBOURDISC_SRC_MAC  12
#define WARTS_NEIGHBOURDISC_DST_IP   13
#define WARTS_NEIGHBOURDISC_DST_MAC  14
#define WARTS_NEIGHBOURDISC_PROBEC   15

static const warts_var_t neighbourdisc_vars[] =
{
  {WARTS_NEIGHBOURDISC_LIST,      4, -1},
  {WARTS_NEIGHBOURDISC_CYCLE,     4, -1},
  {WARTS_NEIGHBOURDISC_USERID,    4, -1},
  {WARTS_NEIGHBOURDISC_IFNAME,   -1, -1},
  {WARTS_NEIGHBOURDISC_START,     8, -1},
  {WARTS_NEIGHBOURDISC_METHOD,    1, -1},
  {WARTS_NEIGHBOURDISC_WAIT,      2, -1},
  {WARTS_NEIGHBOURDISC_FLAGS,     1, -1},
  {WARTS_NEIGHBOURDISC_ATTEMPTS,  2, -1},
  {WARTS_NEIGHBOURDISC_REPLYC,    2, -1},
  {WARTS_NEIGHBOURDISC_SRC_IP,   -1, -1},
  {WARTS_NEIGHBOURDISC_SRC_MAC,  -1, -1},
  {WARTS_NEIGHBOURDISC_DST_IP,   -1, -1},
  {WARTS_NEIGHBOURDISC_DST_MAC,  -1, -1},
  {WARTS_NEIGHBOURDISC_PROBEC,    2, -1},
};
#define neighbourdisc_vars_mfb WARTS_VAR_MFB(neighbourdisc_vars)

#define WARTS_NEIGHBOURDISC_PROBE_TX  1
#define WARTS_NEIGHBOURDISC_PROBE_RXC 2
static const warts_var_t neighbourdisc_probe_vars[] =
{
  {WARTS_NEIGHBOURDISC_PROBE_TX,  8, -1},
  {WARTS_NEIGHBOURDISC_PROBE_RXC, 4, -1},
};
#define neighbourdisc_probe_vars_mfb WARTS_VAR_MFB(neighbourdisc_probe_vars)

#define WARTS_NEIGHBOURDISC_REPLY_RX  1
#define WARTS_NEIGHBOURDISC_REPLY_MAC 2
static const warts_var_t neighbourdisc_reply_vars[] =
{
  {WARTS_NEIGHBOURDISC_REPLY_RX,   8, -1},
  {WARTS_NEIGHBOURDISC_REPLY_MAC, -1, -1},
};
#define neighbourdisc_reply_vars_mfb WARTS_VAR_MFB(neighbourdisc_reply_vars)


typedef struct warts_neighbourdisc_reply
{
  uint8_t                      flags[WARTS_VAR_MFB(neighbourdisc_reply_vars)];
  uint16_t                     flags_len;
  uint16_t                     params_len;
} warts_neighbourdisc_reply_t;

typedef struct warts_neighbourdisc_probe
{
  uint8_t                      flags[WARTS_VAR_MFB(neighbourdisc_probe_vars)];
  uint16_t                     flags_len;
  uint16_t                     params_len;
  warts_neighbourdisc_reply_t *rxs;
} warts_neighbourdisc_probe_t;


static int warts_neighbourdisc_reply_state(scamper_neighbourdisc_reply_t *reply,
					   warts_neighbourdisc_reply_t *state,
					   warts_addrtable_t *table,
					   uint32_t *len)
{
  const warts_var_t *var;
  int i, max_id = 0;

  memset(state->flags, 0, neighbourdisc_reply_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(neighbourdisc_reply_vars)/sizeof(warts_var_t); i++)
    {
      var = &neighbourdisc_reply_vars[i];
      flag_set(state->flags, var->id, &max_id);
      if(var->id == WARTS_NEIGHBOURDISC_REPLY_MAC)
	{
	  state->params_len += warts_addr_size(table, reply->mac);
	  continue;
	}
      assert(var->size != -1);
      state->params_len += var->size;
    }
  state->flags_len = fold_flags(state->flags, max_id);

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_neighbourdisc_reply_write(const scamper_neighbourdisc_reply_t *reply,
					   const scamper_file_t *sf,
					   warts_addrtable_t *table,
					   uint8_t *buf, uint32_t *off,
					   const uint32_t len,
					   warts_neighbourdisc_reply_t *state)
{
  warts_param_writer_t handlers[] = {
    {&reply->rx,   (wpw_t)insert_timeval, NULL},
    {reply->mac,   (wpw_t)insert_addr,    table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);
  return 0;
}

static int warts_neighbourdisc_reply_read(scamper_neighbourdisc_reply_t *reply,
					  warts_state_t *state,
					  warts_addrtable_t *table,
					  uint8_t *buf, uint32_t *off,
					  uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&reply->rx,  (wpr_t)extract_timeval, NULL},
    {&reply->mac, (wpr_t)extract_addr,    table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static int warts_neighbourdisc_probe_state(const scamper_file_t *sf,
					   scamper_neighbourdisc_probe_t *probe,
					   warts_neighbourdisc_probe_t *state,
					   warts_addrtable_t *table,
					   uint32_t *len)
{
  const warts_var_t *var;
  int i, max_id = 0;
  size_t size;

  memset(state->flags, 0, neighbourdisc_probe_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(neighbourdisc_probe_vars)/sizeof(warts_var_t); i++)
    {
      var = &neighbourdisc_probe_vars[i];
      if(var->id == WARTS_NEIGHBOURDISC_PROBE_RXC && probe->rxc == 0)
	continue;

      flag_set(state->flags, var->id, &max_id);
      assert(var->size != -1);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);
  state->rxs = NULL;

  if(probe->rxc > 0)
    {
      size = sizeof(warts_neighbourdisc_reply_t) * probe->rxc;
      if((state->rxs = malloc_zero(size)) == NULL)
	return -1;

      for(i=0; i<probe->rxc; i++)
	{
	  if(warts_neighbourdisc_reply_state(probe->rxs[i], &state->rxs[i],
					     table, len) != 0)
	    {
	      free(state->rxs);
	      state->rxs = NULL;
	      return -1;
	    }
	}
    }

  /* increase length required for the probe record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_neighbourdisc_probe_write(const scamper_neighbourdisc_probe_t *probe,
					   const scamper_file_t *sf,
					   warts_addrtable_t *table,
					   uint8_t *buf, uint32_t *off,
					   const uint32_t len,
					   warts_neighbourdisc_probe_t *state)
{
  uint16_t i;
  warts_param_writer_t handlers[] = {
    {&probe->tx,  (wpw_t)insert_timeval, NULL},
    {&probe->rxc, (wpw_t)insert_uint16,  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);

  for(i=0; i<probe->rxc; i++)
    {
      warts_neighbourdisc_reply_write(probe->rxs[i], sf, table, buf, off, len,
				      &state->rxs[i]);
    }

  return 0;
}

static int warts_neighbourdisc_probe_read(scamper_neighbourdisc_probe_t *pr,
					  warts_state_t *state,
					  warts_addrtable_t *table,
					  uint8_t *buf, uint32_t *off,
					  uint32_t len)
{
  scamper_neighbourdisc_reply_t *reply;
  uint16_t i;
  warts_param_reader_t handlers[] = {
    {&pr->tx,  (wpr_t)extract_timeval, NULL},
    {&pr->rxc, (wpr_t)extract_uint16,  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(pr->rxc == 0)
    return 0;

  if(scamper_neighbourdisc_replies_alloc(pr, pr->rxc) != 0)
    return -1;

  for(i=0; i<pr->rxc; i++)
    {
      if((reply = scamper_neighbourdisc_reply_alloc()) == NULL)
	return -1;
      pr->rxs[i] = reply;

      if(warts_neighbourdisc_reply_read(reply,state,table,buf,off,len) != 0)
	return -1;
    }

  return 0;
}

static void warts_neighbourdisc_params(const scamper_neighbourdisc_t *nd,
				       warts_addrtable_t *table,
				       uint8_t *flags, uint16_t *flags_len,
				       uint16_t *params_len)
{
  int i, max_id = 0;
  const warts_var_t *var;

  memset(flags, 0, neighbourdisc_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(neighbourdisc_vars)/sizeof(warts_var_t); i++)
    {
      var = &neighbourdisc_vars[i];
      if((var->id == WARTS_NEIGHBOURDISC_LIST && nd->list == NULL) ||
	 (var->id == WARTS_NEIGHBOURDISC_CYCLE && nd->cycle == NULL) ||
	 (var->id == WARTS_NEIGHBOURDISC_USERID && nd->userid == 0) ||
	 (var->id == WARTS_NEIGHBOURDISC_IFNAME && nd->ifname == NULL) ||
	 (var->id == WARTS_NEIGHBOURDISC_SRC_IP && nd->src_ip == NULL) ||
	 (var->id == WARTS_NEIGHBOURDISC_SRC_MAC && nd->src_mac == NULL) ||
	 (var->id == WARTS_NEIGHBOURDISC_DST_IP && nd->dst_ip == NULL) ||
	 (var->id == WARTS_NEIGHBOURDISC_DST_MAC && nd->dst_mac == NULL) ||
	 (var->id == WARTS_NEIGHBOURDISC_PROBEC && nd->probec == 0))
	continue;
      flag_set(flags, var->id, &max_id);

      if(var->size < 0)
	{
	  if(var->id == WARTS_NEIGHBOURDISC_SRC_IP)
	    *params_len += warts_addr_size(table, nd->src_ip);
	  else if(var->id == WARTS_NEIGHBOURDISC_SRC_MAC)
	    *params_len += warts_addr_size(table, nd->src_mac);
	  else if(var->id == WARTS_NEIGHBOURDISC_DST_IP)
	    *params_len += warts_addr_size(table, nd->dst_ip);
	  else if(var->id == WARTS_NEIGHBOURDISC_DST_MAC)
	    *params_len += warts_addr_size(table, nd->dst_mac);
	  else if(var->id == WARTS_NEIGHBOURDISC_IFNAME)
	    *params_len += warts_str_size(nd->ifname);
	  continue;
	}

      assert(var->size >= 0);
      *params_len += var->size;
    }

  *flags_len = fold_flags(flags, max_id);
  return;
}

static int warts_neighbourdisc_params_write(const scamper_neighbourdisc_t *nd,
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
    {&list_id,      (wpw_t)insert_uint32,  NULL},
    {&cycle_id,     (wpw_t)insert_uint32,  NULL},
    {&nd->userid,   (wpw_t)insert_uint32,  NULL},
    {nd->ifname,    (wpw_t)insert_string,  NULL},
    {&nd->start,    (wpw_t)insert_timeval, NULL},
    {&nd->method,   (wpw_t)insert_byte,    NULL},
    {&nd->wait,     (wpw_t)insert_uint16,  NULL},
    {&nd->flags,    (wpw_t)insert_byte,    NULL},
    {&nd->attempts, (wpw_t)insert_uint16,  NULL},
    {&nd->replyc,   (wpw_t)insert_uint16,  NULL},
    {nd->src_ip,    (wpw_t)insert_addr,    table},
    {nd->src_mac,   (wpw_t)insert_addr,    table},
    {nd->dst_ip,    (wpw_t)insert_addr,    table},
    {nd->dst_mac,   (wpw_t)insert_addr,    table},
    {&nd->probec,   (wpw_t)insert_uint16,  table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  nd->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, nd->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len,
		     handlers, handler_cnt);

  return 0;
}

static int warts_neighbourdisc_params_read(scamper_neighbourdisc_t *nd,
					   warts_addrtable_t *table,
					   warts_state_t *state,
					   uint8_t *buf, uint32_t *off,
					   uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&nd->list,     (wpr_t)extract_list,    state},
    {&nd->cycle,    (wpr_t)extract_cycle,   state},
    {&nd->userid,   (wpr_t)extract_uint32,  NULL},
    {&nd->ifname,   (wpr_t)extract_string,  NULL},
    {&nd->start,    (wpr_t)extract_timeval, NULL},
    {&nd->method,   (wpr_t)extract_byte,    NULL},
    {&nd->wait,     (wpr_t)extract_uint16,  NULL},
    {&nd->flags,    (wpr_t)extract_byte,    NULL},
    {&nd->attempts, (wpr_t)extract_uint16,  NULL},
    {&nd->replyc,   (wpr_t)extract_uint16,  NULL},
    {&nd->src_ip,   (wpr_t)extract_addr,    table},
    {&nd->src_mac,  (wpr_t)extract_addr,    table},
    {&nd->dst_ip,   (wpr_t)extract_addr,    table},
    {&nd->dst_mac,  (wpr_t)extract_addr,    table},
    {&nd->probec,   (wpr_t)extract_uint16,  NULL},
  };
  const int handler_cnt = sizeof(handlers) / sizeof(warts_param_reader_t);
  int rc;

  if((rc = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0)
    return rc;

  if(nd->src_mac == NULL)
    return -1;

  return 0;
}

static void warts_neighbourdisc_probes_free(warts_neighbourdisc_probe_t *ps,
					    uint32_t cnt)
{
  uint16_t i;

  if(ps != NULL)
    {
      for(i=0; i<cnt; i++)
	{
	  free(ps[i].rxs);
	}
      free(ps);
    }

  return;
}

int scamper_file_warts_neighbourdisc_write(const scamper_file_t *sf,
					   const scamper_neighbourdisc_t *nd)
{
  warts_addrtable_t *table = NULL;
  warts_neighbourdisc_probe_t *probes = NULL;
  scamper_neighbourdisc_probe_t *probe;
  uint8_t *buf = NULL;
  uint8_t  flags[neighbourdisc_vars_mfb];
  uint16_t flags_len, params_len;
  uint32_t len, len2, off = 0;
  size_t   size;
  int      i;

  if((table = warts_addrtable_alloc_byaddr()) == NULL)
    goto err;

  /* figure out which neighbourdisc items we'll store in this record */
  warts_neighbourdisc_params(nd, table, flags, &flags_len, &params_len);
  len = 8 + flags_len + params_len + 2;

  if(nd->probec > 0)
    {
      size = nd->probec * sizeof(warts_neighbourdisc_probe_t);
      if((probes = (warts_neighbourdisc_probe_t *)malloc_zero(size)) == NULL)
	goto err;

      for(i=0; i<nd->probec; i++)
	{
	  probe = nd->probes[i];
	  len2 = len;
	  if(warts_neighbourdisc_probe_state(sf, probe, &probes[i], table,
					     &len2) != 0)
	    goto err;
	  if(len2 < len)
	    goto err;
	  len = len2;
	}
    }

  if((buf = malloc_zero(len)) == NULL)
    goto err;
  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_NEIGHBOURDISC);

  if(warts_neighbourdisc_params_write(nd, sf, table, buf, &off, len,
				      flags, flags_len, params_len) != 0)
    {
      goto err;
    }

  if(nd->probec > 0)
    {
      for(i=0; i<nd->probec; i++)
	{
	  probe = nd->probes[i];
	  warts_neighbourdisc_probe_write(probe, sf, table, buf, &off, len,
					  &probes[i]);
	}
    }

  warts_neighbourdisc_probes_free(probes, nd->probec);
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
  if(probes != NULL) warts_neighbourdisc_probes_free(probes, nd->probec);
  if(buf != NULL) free(buf);
  return -1;
}

int scamper_file_warts_neighbourdisc_read(scamper_file_t *sf,
					  const warts_hdr_t *hdr,
					  scamper_neighbourdisc_t **nd_out)
{
  scamper_neighbourdisc_t *nd = NULL;
  scamper_neighbourdisc_probe_t *probe;
  warts_addrtable_t *table = NULL;
  warts_state_t *state = scamper_file_getstate(sf);
  uint8_t *buf = NULL;
  uint32_t off = 0;
  uint16_t i;

  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      *nd_out = NULL;
      return 0;
    }

  if((nd = scamper_neighbourdisc_alloc()) == NULL)
    {
      goto err;
    }

  if((table = warts_addrtable_alloc_byid()) == NULL)
    goto err;

  if(warts_neighbourdisc_params_read(nd,table,state,buf,&off,hdr->len) != 0)
    {
      goto err;
    }

  if(nd->probec == 0)
    goto done;

  if(scamper_neighbourdisc_probes_alloc(nd, nd->probec) != 0)
    {
      goto err;
    }

  for(i=0; i<nd->probec; i++)
    {
      if((probe = scamper_neighbourdisc_probe_alloc()) == NULL)
	{
	  goto err;
	}
      nd->probes[i] = probe;

      if(warts_neighbourdisc_probe_read(probe, state, table,
					buf, &off, hdr->len) != 0)
	{
	  goto err;
	}
    }

 done:
  warts_addrtable_free(table);
  *nd_out = nd;
  free(buf);
  return 0;

 err:
  if(table != NULL) warts_addrtable_free(table);
  if(buf != NULL) free(buf);
  if(nd != NULL) scamper_neighbourdisc_free(nd);
  return -1;
}
