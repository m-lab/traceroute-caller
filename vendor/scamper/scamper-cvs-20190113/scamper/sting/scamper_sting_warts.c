/*
 * scamper_sting_warts.c
 *
 * Copyright (C) 2010-2011 The University of Waikato
 * Copyright (C) 2012-2014 The Regents of the University of California
 * Copyright (C) 2016      Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_sting_warts.c,v 1.9 2016/12/02 09:13:42 mjl Exp $
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
  "$Id: scamper_sting_warts.c,v 1.9 2016/12/02 09:13:42 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_sting.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_sting_warts.h"
#include "utils.h"

#define WARTS_STING_LIST      1
#define WARTS_STING_CYCLE     2
#define WARTS_STING_USERID    3
#define WARTS_STING_SRC       4
#define WARTS_STING_DST       5
#define WARTS_STING_SPORT     6
#define WARTS_STING_DPORT     7
#define WARTS_STING_COUNT     8
#define WARTS_STING_MEAN      9
#define WARTS_STING_INTER     10
#define WARTS_STING_DIST      11
#define WARTS_STING_SYNRETX   12
#define WARTS_STING_DATARETX  13
#define WARTS_STING_SEQSKIP   14
#define WARTS_STING_DATALEN   15
#define WARTS_STING_DATA      16
#define WARTS_STING_START     17
#define WARTS_STING_HSRTT     18
#define WARTS_STING_DATAACKC  19
#define WARTS_STING_HOLEC     20
#define WARTS_STING_PKTC      21
#define WARTS_STING_RESULT    22

static const warts_var_t sting_vars[] =
{
  {WARTS_STING_LIST,     4, -1},
  {WARTS_STING_CYCLE,    4, -1},
  {WARTS_STING_USERID,   4, -1},
  {WARTS_STING_SRC,     -1, -1},
  {WARTS_STING_DST,     -1, -1},
  {WARTS_STING_SPORT,    2, -1},
  {WARTS_STING_DPORT,    2, -1},
  {WARTS_STING_COUNT,    2, -1},
  {WARTS_STING_MEAN,     2, -1},
  {WARTS_STING_INTER,    2, -1},
  {WARTS_STING_DIST,     1, -1},
  {WARTS_STING_SYNRETX,  1, -1},
  {WARTS_STING_DATARETX, 1, -1},
  {WARTS_STING_SEQSKIP,  1, -1},
  {WARTS_STING_DATALEN,  2, -1},
  {WARTS_STING_DATA,    -1, -1},
  {WARTS_STING_START,    8, -1},
  {WARTS_STING_HSRTT,    8, -1},
  {WARTS_STING_DATAACKC, 2, -1},
  {WARTS_STING_HOLEC,    2, -1},
  {WARTS_STING_PKTC,     4, -1},
  {WARTS_STING_RESULT,   1, -1},
};
#define sting_vars_mfb WARTS_VAR_MFB(sting_vars)

#define WARTS_STING_PKT_FLAGS    1
#define WARTS_STING_PKT_TIME     2
#define WARTS_STING_PKT_DATALEN  3
#define WARTS_STING_PKT_DATA     4

static const warts_var_t sting_pkt_vars[] =
{
  {WARTS_STING_PKT_FLAGS,           1, -1},
  {WARTS_STING_PKT_TIME,            8, -1},
  {WARTS_STING_PKT_DATALEN,         2, -1},
  {WARTS_STING_PKT_DATA,           -1, -1},
};
#define sting_pkt_vars_mfb WARTS_VAR_MFB(sting_pkt_vars)

typedef struct warts_sting_pkt
{
  uint8_t               flags[sting_pkt_vars_mfb];
  uint16_t              flags_len;
  uint16_t              params_len;
} warts_sting_pkt_t;

static void warts_sting_pkt_params(const scamper_sting_pkt_t *pkt,
				   warts_sting_pkt_t *state, uint32_t *len)
{
  const warts_var_t *var;
  int max_id = 0;
  uint16_t i;

  memset(state->flags, 0, sting_pkt_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(sting_pkt_vars) / sizeof(warts_var_t); i++)
    {
      var = &sting_pkt_vars[i];

      if(var->id == WARTS_STING_PKT_DATA)
        {
	  if(pkt->len == 0)
	    continue;

	  state->params_len += pkt->len;
	  flag_set(state->flags, var->id, &max_id);
	  continue;
        }

      assert(var->size >= 0);
      state->params_len += var->size;
      flag_set(state->flags, var->id, &max_id);
    }

  state->flags_len = fold_flags(state->flags, max_id);

  *len += state->flags_len + state->params_len;

  if(state->params_len != 0)
    *len += 2;

  return;
}

static scamper_sting_pkt_t *warts_sting_pkt_read(warts_state_t *state,
						 uint8_t *buf, uint32_t *off,
						 uint32_t len)
{
  scamper_sting_pkt_t *pkt = NULL;
  uint8_t flags, *data = NULL;
  struct timeval tv;
  uint16_t plen;
  warts_param_reader_t handlers[] = {
    {&flags, (wpr_t)extract_byte,         NULL},
    {&tv,    (wpr_t)extract_timeval,      NULL},
    {&plen,  (wpr_t)extract_uint16,       NULL},
    {&data,  (wpr_t)extract_bytes_ptr,   &plen},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0 ||
     (pkt = scamper_sting_pkt_alloc(flags, data, plen, &tv)) == NULL)
    goto err;

  return pkt;

 err:
  if(pkt != NULL) scamper_sting_pkt_free(pkt);
  return NULL;
}

static int warts_sting_pkt_write(const scamper_sting_pkt_t *pkt,
				 const scamper_file_t *sf, uint8_t *buf,
				 uint32_t *off, const uint32_t len,
				 warts_sting_pkt_t *state)
{
  uint16_t dl = pkt->len;
  warts_param_writer_t handlers[] = {
    {&pkt->flags, (wpw_t)insert_byte,          NULL},
    {&pkt->tv,    (wpw_t)insert_timeval,       NULL},
    {&pkt->len,   (wpw_t)insert_uint16,        NULL},
    {pkt->data,   (wpw_t)insert_bytes_uint16, &dl},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return 0;
}

static void warts_sting_params(const scamper_sting_t *sting,
			       warts_addrtable_t *table, uint8_t *flags,
			       uint16_t *flags_len, uint16_t *params_len)
{
  const warts_var_t *var;
  int i, max_id = 0;

  /* Unset all flags */
  memset(flags, 0, sting_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(sting_vars)/sizeof(warts_var_t); i++)
    {
      var = &sting_vars[i];

      /* Skip the variables for which we have no data */
      if(var->id == WARTS_STING_LIST && sting->list == NULL)
	continue;
      else if(var->id == WARTS_STING_CYCLE && sting->cycle == NULL)
	continue;
      else if(var->id == WARTS_STING_USERID && sting->userid == 0)
	continue;
      else if(var->id == WARTS_STING_SRC && sting->src == NULL)
	continue;
      else if(var->id == WARTS_STING_DST && sting->dst == NULL)
	continue;
      else if(var->id == WARTS_STING_DATA && sting->datalen == 0)
	continue;
      else if(var->id == WARTS_STING_RESULT && sting->result == 0)
	continue;

      /* Set the flag for the rest of the variables */
      flag_set(flags, var->id, &max_id);

      /* Variables that don't have a fixed size */
      if(var->id == WARTS_STING_SRC)
        {
	  *params_len += warts_addr_size(table, sting->src);
	  continue;
        }
      else if(var->id == WARTS_STING_DST)
        {
	  *params_len += warts_addr_size(table, sting->dst);
	  continue;
        }
      else if(var->id == WARTS_STING_DATA)
	{
	  *params_len += sting->datalen;
	  continue;
	}

      /* The rest of the variables have a fixed size */
      *params_len += var->size;
    }

  *flags_len = fold_flags(flags, max_id);
  return;
}

static int warts_sting_params_read(scamper_sting_t *sting,
				   warts_addrtable_t *table,
				   warts_state_t *state,
				   uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&sting->list,         (wpr_t)extract_list,         state},
    {&sting->cycle,        (wpr_t)extract_cycle,        state},
    {&sting->userid,       (wpr_t)extract_uint32,       NULL},
    {&sting->src,          (wpr_t)extract_addr,         table},
    {&sting->dst,          (wpr_t)extract_addr,         table},
    {&sting->sport,        (wpr_t)extract_uint16,       NULL},
    {&sting->dport,        (wpr_t)extract_uint16,       NULL},
    {&sting->count,        (wpr_t)extract_uint16,       NULL},
    {&sting->mean,         (wpr_t)extract_uint16,       NULL},
    {&sting->inter,        (wpr_t)extract_uint16,       NULL},
    {&sting->dist,         (wpr_t)extract_byte,         NULL},
    {&sting->synretx,      (wpr_t)extract_byte,         NULL},
    {&sting->dataretx,     (wpr_t)extract_byte,         NULL},
    {&sting->seqskip,      (wpr_t)extract_byte,         NULL},
    {&sting->datalen,      (wpr_t)extract_uint16,       NULL},
    {&sting->data,         (wpr_t)extract_bytes_alloc,  &sting->datalen},
    {&sting->start,        (wpr_t)extract_timeval,      NULL},
    {&sting->hsrtt,        (wpr_t)extract_timeval,      NULL},
    {&sting->dataackc,     (wpr_t)extract_uint16,       NULL},
    {&sting->holec,        (wpr_t)extract_uint16,       NULL},
    {&sting->pktc,         (wpr_t)extract_uint32,       NULL},
    {&sting->result,       (wpr_t)extract_byte,         NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  int rc;
  if((rc = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0)
    return rc;
  if(sting->src == NULL || sting->dst == NULL)
    return -1;
  return 0;
}

static int warts_sting_params_write(const scamper_sting_t *sting,
				    const scamper_file_t *sf,
				    warts_addrtable_t *table,
				    uint8_t *buf, uint32_t *off,
				    const uint32_t len, const uint8_t *flags,
				    const uint16_t flags_len,
				    const uint16_t params_len)
{
  uint32_t list_id, cycle_id;
  uint16_t dl = sting->datalen;

  /* Specifies how to write each variable to the warts file. */
  warts_param_writer_t handlers[] = {
    {&list_id,             (wpw_t)insert_uint32,       NULL},
    {&cycle_id,            (wpw_t)insert_uint32,       NULL},
    {&sting->userid,       (wpw_t)insert_uint32,       NULL},
    {sting->src,           (wpw_t)insert_addr,         table},
    {sting->dst,           (wpw_t)insert_addr,         table},
    {&sting->sport,        (wpw_t)insert_uint16,       NULL},
    {&sting->dport,        (wpw_t)insert_uint16,       NULL},
    {&sting->count,        (wpw_t)insert_uint16,       NULL},
    {&sting->mean,         (wpw_t)insert_uint16,       NULL},
    {&sting->inter,        (wpw_t)insert_uint16,       NULL},
    {&sting->dist,         (wpw_t)insert_byte,         NULL},
    {&sting->synretx,      (wpw_t)insert_byte,         NULL},
    {&sting->dataretx,     (wpw_t)insert_byte,         NULL},
    {&sting->seqskip,      (wpw_t)insert_byte,         NULL},
    {&sting->datalen,      (wpw_t)insert_uint16,       NULL},
    {&sting->data,         (wpw_t)insert_bytes_uint16, &dl},
    {&sting->start,        (wpw_t)insert_timeval,      NULL},
    {&sting->hsrtt,        (wpw_t)insert_timeval,      NULL},
    {&sting->dataackc,     (wpw_t)insert_uint16,       NULL},
    {&sting->holec,        (wpw_t)insert_uint16,       NULL},
    {&sting->pktc,         (wpw_t)insert_uint32,       NULL},
    {&sting->result,       (wpw_t)insert_byte,         NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  sting->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, sting->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len,
		     handlers, handler_cnt);

  return 0;
}

int scamper_file_warts_sting_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_sting_t **sting_out)
{
  scamper_sting_t *sting = NULL;
  warts_addrtable_t *table = NULL;
  warts_state_t *state = scamper_file_getstate(sf);
  uint8_t *buf = NULL;
  uint32_t off = 0;
  uint32_t i;

  /* Read in the header */
  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }

  if(buf == NULL)
    {
      *sting_out = NULL;
      return 0;
    }

  /* Allocate space for a sting object */
  if((sting = scamper_sting_alloc()) == NULL)
    {
      goto err;
    }

  if((table = warts_addrtable_alloc_byid()) == NULL)
    goto err;

  /* Read in the sting data from the warts file */
  if(warts_sting_params_read(sting, table, state, buf, &off, hdr->len) != 0)
    {
      goto err;
    }

  /* Determine how many sting pkts to read */
  if(sting->pktc > 0)
    {
      /* Allocate the sting pkts array */
      if(scamper_sting_pkts_alloc(sting, sting->pktc) != 0)
	{
	  goto err;
	}

      /*
       * for each sting packet, read it and insert it into the sting
       * structure
       */
      for(i=0; i<sting->pktc; i++)
        {
	  sting->pkts[i] = warts_sting_pkt_read(state, buf, &off, hdr->len);
	  if(sting->pkts[i] == NULL)
	    {
	      goto err;
	    }
        }
    }

  warts_addrtable_free(table);
  *sting_out = sting;
  free(buf);
  return 0;

 err:
  if(table != NULL) warts_addrtable_free(table);
  if(buf != NULL) free(buf);
  if(sting != NULL) scamper_sting_free(sting);
  return -1;
}

/* Write data from a scamper sting object to a warts file */
int scamper_file_warts_sting_write(const scamper_file_t *sf,
				   const scamper_sting_t *sting)
{
  warts_addrtable_t *table = NULL;
  warts_sting_pkt_t *pkts = NULL;
  uint8_t *buf = NULL;
  uint8_t  flags[sting_vars_mfb];
  uint16_t flags_len, params_len;
  uint32_t len, i, off = 0;
  size_t size;

  if((table = warts_addrtable_alloc_byaddr()) == NULL)
    goto err;

  /* Set the sting data (not including the packets) */
  warts_sting_params(sting, table, flags, &flags_len, &params_len);
  len = 8 + flags_len + params_len + 2;

  if(sting->pktc > 0)
    {
      /* Allocate memory for the state */
      size = sting->pktc * sizeof(warts_sting_pkt_t);
      if((pkts = (warts_sting_pkt_t *)malloc_zero(size)) == NULL)
	goto err;

      for(i=0; i<sting->pktc; i++)
	warts_sting_pkt_params(sting->pkts[i], &pkts[i], &len);
    }

  /* Allocate memory to store all of the data (including packets) */
  if((buf = malloc_zero(len)) == NULL)
    goto err;
  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_STING);

  /* Write the sting data (excluding packets) to the buffer */
  if(warts_sting_params_write(sting, sf, table, buf, &off, len,
			      flags, flags_len, params_len) != 0)
    {
      goto err;
    }

  if(sting->pktc > 0)
    {
      for(i=0; i<sting->pktc; i++)
	warts_sting_pkt_write(sting->pkts[i], sf, buf, &off, len, &pkts[i]);
      free(pkts); pkts = NULL;
    }

  assert(off == len);

  /* Write the whole buffer to a warts file */
  if(warts_write(sf, buf, len) == -1)
    goto err;

  warts_addrtable_free(table);
  free(buf);
  return 0;

err:
  if(table != NULL) warts_addrtable_free(table);
  if(pkts != NULL) free(pkts);
  if(buf != NULL) free(buf);
  return -1;
}
