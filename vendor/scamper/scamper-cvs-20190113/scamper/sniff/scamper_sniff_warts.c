/*
 * scamper_sniff_warts.c
 *
 * Copyright (C) 2011 The University of Waikato
 * Copyright (C) 2014 The Regents of the University of California
 * Copyright (C) 2016 Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_sniff_warts.c,v 1.9 2016/12/09 08:42:51 mjl Exp $
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
  "$Id: scamper_sniff_warts.c,v 1.9 2016/12/09 08:42:51 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_sniff.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_sniff_warts.h"
#include "utils.h"

#define WARTS_SNIFF_LIST        1
#define WARTS_SNIFF_CYCLE       2
#define WARTS_SNIFF_USERID      3
#define WARTS_SNIFF_SRC         4
#define WARTS_SNIFF_START       5
#define WARTS_SNIFF_FINISH      6
#define WARTS_SNIFF_STOP_REASON 7
#define WARTS_SNIFF_LIMIT_PKTC  8
#define WARTS_SNIFF_LIMIT_TIME  9
#define WARTS_SNIFF_PKTC        10
#define WARTS_SNIFF_ICMPID      11

static const warts_var_t sniff_vars[] =
{
  {WARTS_SNIFF_LIST,         4, -1},
  {WARTS_SNIFF_CYCLE,        4, -1},
  {WARTS_SNIFF_USERID,       4, -1},
  {WARTS_SNIFF_SRC,         -1, -1},
  {WARTS_SNIFF_START,        8, -1},
  {WARTS_SNIFF_FINISH,       8, -1},
  {WARTS_SNIFF_STOP_REASON,  1, -1},
  {WARTS_SNIFF_LIMIT_PKTC,   4, -1},
  {WARTS_SNIFF_LIMIT_TIME,   2, -1},
  {WARTS_SNIFF_PKTC,         4, -1},
  {WARTS_SNIFF_ICMPID,       2, -1},
};
#define sniff_vars_mfb WARTS_VAR_MFB(sniff_vars)

#define WARTS_SNIFF_PKT_TIME     1
#define WARTS_SNIFF_PKT_DATALEN  2
#define WARTS_SNIFF_PKT_DATA     3

static const warts_var_t sniff_pkt_vars[] =
{
  {WARTS_SNIFF_PKT_TIME,            8, -1},
  {WARTS_SNIFF_PKT_DATALEN,         2, -1},
  {WARTS_SNIFF_PKT_DATA,           -1, -1},
};
#define sniff_pkt_vars_mfb WARTS_VAR_MFB(sniff_pkt_vars)

typedef struct warts_sniff_pkt
{
  uint8_t               flags[sniff_pkt_vars_mfb];
  uint16_t              flags_len;
  uint16_t              params_len;
} warts_sniff_pkt_t;

static void warts_sniff_pkt_params(const scamper_sniff_pkt_t *pkt,
				   warts_sniff_pkt_t *state, uint32_t *len)
{
  const warts_var_t *var;
  int max_id = 0;
  uint16_t i;

  memset(state->flags, 0, sniff_pkt_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(sniff_pkt_vars) / sizeof(warts_var_t); i++)
    {
      var = &sniff_pkt_vars[i];

      if(var->id == WARTS_SNIFF_PKT_DATA)
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

static scamper_sniff_pkt_t *warts_sniff_pkt_read(warts_state_t *state,
						 uint8_t *buf, uint32_t *off,
						 uint32_t len)
{
  scamper_sniff_pkt_t *pkt = NULL;
  uint8_t *data = NULL;
  struct timeval tv;
  uint16_t plen;
  warts_param_reader_t handlers[] = {
    {&tv,    (wpr_t)extract_timeval,      NULL},
    {&plen,  (wpr_t)extract_uint16,       NULL},
    {&data,  (wpr_t)extract_bytes_ptr,   &plen},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0 ||
     plen == 0 || data == NULL ||
     (pkt = scamper_sniff_pkt_alloc(data, plen, &tv)) == NULL)
    goto err;

  return pkt;

 err:
  if(pkt != NULL) scamper_sniff_pkt_free(pkt);
  return NULL;
}

static int warts_sniff_pkt_write(const scamper_sniff_pkt_t *pkt,
				 const scamper_file_t *sf, uint8_t *buf,
				 uint32_t *off, const uint32_t len,
				 warts_sniff_pkt_t *state)
{
  uint16_t dl = pkt->len;
  warts_param_writer_t handlers[] = {
    {&pkt->tv,    (wpw_t)insert_timeval,       NULL},
    {&pkt->len,   (wpw_t)insert_uint16,        NULL},
    {pkt->data,   (wpw_t)insert_bytes_uint16, &dl},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return 0;
}

static void warts_sniff_params(const scamper_sniff_t *sniff,
			       warts_addrtable_t *table, uint8_t *flags,
			       uint16_t *flags_len, uint16_t *params_len)
{
  const warts_var_t *var;
  int i, max_id = 0;

  /* Unset all flags */
  memset(flags, 0, sniff_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(sniff_vars)/sizeof(warts_var_t); i++)
    {
      var = &sniff_vars[i];

      /* Skip the variables for which we have no data */
      if(var->id == WARTS_SNIFF_LIST && sniff->list == NULL)
	continue;
      else if(var->id == WARTS_SNIFF_CYCLE && sniff->cycle == NULL)
	continue;
      else if(var->id == WARTS_SNIFF_USERID && sniff->userid == 0)
	continue;
      else if(var->id == WARTS_SNIFF_SRC && sniff->src == NULL)
	continue;

      /* Set the flag for the rest of the variables */
      flag_set(flags, var->id, &max_id);

      /* Variables that don't have a fixed size */
      if(var->id == WARTS_SNIFF_SRC)
        {
	  *params_len += warts_addr_size(table, sniff->src);
	  continue;
        }

      /* The rest of the variables have a fixed size */
      *params_len += var->size;
    }

  *flags_len = fold_flags(flags, max_id);
  return;
}

static int warts_sniff_params_read(scamper_sniff_t *sniff,
				   warts_addrtable_t *table,
				   warts_state_t *state,
				   uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&sniff->list,         (wpr_t)extract_list,         state},
    {&sniff->cycle,        (wpr_t)extract_cycle,        state},
    {&sniff->userid,       (wpr_t)extract_uint32,       NULL},
    {&sniff->src,          (wpr_t)extract_addr,         table},
    {&sniff->start,        (wpr_t)extract_timeval,      NULL},
    {&sniff->finish,       (wpr_t)extract_timeval,      NULL},
    {&sniff->stop_reason,  (wpr_t)extract_byte,         NULL},
    {&sniff->limit_pktc,   (wpr_t)extract_uint32,       NULL},
    {&sniff->limit_time,   (wpr_t)extract_uint16,       NULL},
    {&sniff->pktc,         (wpr_t)extract_uint32,       NULL},
    {&sniff->icmpid,       (wpr_t)extract_uint16,       NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  int rc;
  if((rc = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0)
    return rc;
  if(sniff->src == NULL)
    return -1;
  return 0;
}

static int warts_sniff_params_write(const scamper_sniff_t *sniff,
				    const scamper_file_t *sf,
				    warts_addrtable_t *table,
				    uint8_t *buf, uint32_t *off,
				    const uint32_t len, const uint8_t *flags,
				    const uint16_t flags_len,
				    const uint16_t params_len)
{
  uint32_t list_id, cycle_id;

  /* Specifies how to write each variable to the warts file. */
  warts_param_writer_t handlers[] = {
    {&list_id,             (wpw_t)insert_uint32,       NULL},
    {&cycle_id,            (wpw_t)insert_uint32,       NULL},
    {&sniff->userid,       (wpw_t)insert_uint32,       NULL},
    {sniff->src,           (wpw_t)insert_addr,         table},
    {&sniff->start,        (wpw_t)insert_timeval,      NULL},
    {&sniff->finish,       (wpw_t)insert_timeval,      NULL},
    {&sniff->stop_reason,  (wpw_t)insert_byte,         NULL},
    {&sniff->limit_pktc,   (wpw_t)insert_uint32,       NULL},
    {&sniff->limit_time,   (wpw_t)insert_uint16,       NULL},
    {&sniff->pktc,         (wpw_t)insert_uint32,       NULL},
    {&sniff->icmpid,       (wpw_t)insert_uint16,       NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  sniff->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, sniff->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len,
		     handlers, handler_cnt);

  return 0;
}

int scamper_file_warts_sniff_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_sniff_t **sniff_out)
{
  scamper_sniff_t *sniff = NULL;
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
      *sniff_out = NULL;
      return 0;
    }

  /* Allocate space for a sniff object */
  if((sniff = scamper_sniff_alloc()) == NULL)
    {
      goto err;
    }

  if((table = warts_addrtable_alloc_byid()) == NULL)
    goto err;

  /* Read in the sniff data from the warts file */
  if(warts_sniff_params_read(sniff, table, state, buf, &off, hdr->len) != 0)
    {
      goto err;
    }

  /* Determine how many sniff pkts to read */
  if(sniff->pktc > 0)
    {
      /* Allocate the sniff pkts array */
      if(scamper_sniff_pkts_alloc(sniff, sniff->pktc) != 0)
	{
	  goto err;
	}

      /*
       * for each sniff packet, read it and insert it into the sniff
       * structure
       */
      for(i=0; i<sniff->pktc; i++)
        {
	  sniff->pkts[i] = warts_sniff_pkt_read(state, buf, &off, hdr->len);
	  if(sniff->pkts[i] == NULL)
	    {
	      goto err;
	    }
        }
    }

  warts_addrtable_free(table);
  *sniff_out = sniff;
  free(buf);
  return 0;

 err:
  if(table != NULL) warts_addrtable_free(table);
  if(buf != NULL) free(buf);
  if(sniff != NULL) scamper_sniff_free(sniff);
  return -1;
}

/* Write data from a scamper sniff object to a warts file */
int scamper_file_warts_sniff_write(const scamper_file_t *sf,
				   const scamper_sniff_t *sniff)
{
  warts_addrtable_t *table = NULL;
  warts_sniff_pkt_t *pkts = NULL;
  uint8_t *buf = NULL;
  uint8_t  flags[sniff_vars_mfb];
  uint16_t flags_len, params_len;
  uint32_t len, i, off = 0;
  size_t size;

  if((table = warts_addrtable_alloc_byaddr()) == NULL)
    goto err;

  /* Set the sniff data (not including the packets) */
  warts_sniff_params(sniff, table, flags, &flags_len, &params_len);
  len = 8 + flags_len + params_len + 2;

  if(sniff->pktc > 0)
    {
      /* Allocate memory for the state */
      size = sniff->pktc * sizeof(warts_sniff_pkt_t);
      if((pkts = (warts_sniff_pkt_t *)malloc_zero(size)) == NULL)
	goto err;

      for(i=0; i<sniff->pktc; i++)
	warts_sniff_pkt_params(sniff->pkts[i], &pkts[i], &len);
    }

  /* Allocate memory to store all of the data (including packets) */
  if((buf = malloc_zero(len)) == NULL)
    goto err;
  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_SNIFF);

  /* Write the sniff data (excluding packets) to the buffer */
  if(warts_sniff_params_write(sniff, sf, table, buf, &off, len,
			      flags, flags_len, params_len) != 0)
    {
      goto err;
    }

  if(sniff->pktc > 0)
    {
      for(i=0; i<sniff->pktc; i++)
	warts_sniff_pkt_write(sniff->pkts[i], sf, buf, &off, len, &pkts[i]);
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
