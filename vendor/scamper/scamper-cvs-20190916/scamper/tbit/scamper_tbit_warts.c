/*
 * scamper_tbit_warts.c
 *
 * Copyright (C) 2009-2010 Ben Stasiewicz
 * Copyright (C) 2010-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2016      Matthew Luckie
 * Authors: Matthew Luckie, Ben Stasiewicz
 *
 * $Id: scamper_tbit_warts.c,v 1.28 2017/09/27 01:54:18 mjl Exp $
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
  "$Id: scamper_tbit_warts.c,v 1.28 2017/09/27 01:54:18 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_tbit.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_tbit_warts.h"
#include "utils.h"

/*
 * tbit structures conditionally included.
 * the first 2 bytes are the type, the second 2 bytes are the length
 */
#define WARTS_TBIT_STRUCT_EOF   0x0000
#define WARTS_TBIT_STRUCT_TYPE  0x0001
#define WARTS_TBIT_STRUCT_APP   0x0002

#define WARTS_TBIT_LIST      1
#define WARTS_TBIT_CYCLE     2
#define WARTS_TBIT_USERID    3
#define WARTS_TBIT_SRC       4
#define WARTS_TBIT_DST       5
#define WARTS_TBIT_SPORT     6
#define WARTS_TBIT_DPORT     7
#define WARTS_TBIT_START     8
#define WARTS_TBIT_RESULT    9
#define WARTS_TBIT_TYPE      10
#define WARTS_TBIT_APPPROTO  11
#define WARTS_TBIT_CMSS      12
#define WARTS_TBIT_SMSS      13
#define WARTS_TBIT_SYNRETX   14
#define WARTS_TBIT_DATARETX  15
#define WARTS_TBIT_PKTC16    16
#define WARTS_TBIT_PKTC      17
#define WARTS_TBIT_COOKIE    18
#define WARTS_TBIT_WSCALE    19
#define WARTS_TBIT_OPTIONS   20
#define WARTS_TBIT_TTL       21

static const warts_var_t tbit_vars[] =
{
  {WARTS_TBIT_LIST,                  4, -1},
  {WARTS_TBIT_CYCLE,                 4, -1},
  {WARTS_TBIT_USERID,                4, -1},
  {WARTS_TBIT_SRC,                  -1, -1},
  {WARTS_TBIT_DST,                  -1, -1},
  {WARTS_TBIT_SPORT,                 2, -1},
  {WARTS_TBIT_DPORT,                 2, -1},
  {WARTS_TBIT_START,                 8, -1},
  {WARTS_TBIT_RESULT,                2, -1},
  {WARTS_TBIT_TYPE,                  1, -1},
  {WARTS_TBIT_APPPROTO,              1, -1},
  {WARTS_TBIT_CMSS,                  2, -1},
  {WARTS_TBIT_SMSS,                  2, -1},
  {WARTS_TBIT_SYNRETX,               1, -1},
  {WARTS_TBIT_DATARETX,              1, -1},
  {WARTS_TBIT_PKTC16,                2, -1},
  {WARTS_TBIT_PKTC,                  4, -1},
  {WARTS_TBIT_COOKIE,               -1, -1},
  {WARTS_TBIT_WSCALE,                1, -1},
  {WARTS_TBIT_OPTIONS,               4, -1},
  {WARTS_TBIT_TTL,                   1, -1},
};
#define tbit_vars_mfb WARTS_VAR_MFB(tbit_vars)

#define WARTS_TBIT_PKT_DIR      1
#define WARTS_TBIT_PKT_TIME     2
#define WARTS_TBIT_PKT_DATALEN  3
#define WARTS_TBIT_PKT_DATA     4

static const warts_var_t tbit_pkt_vars[] =
{
  {WARTS_TBIT_PKT_DIR,             1, -1},
  {WARTS_TBIT_PKT_TIME,            8, -1},
  {WARTS_TBIT_PKT_DATALEN,         2, -1},
  {WARTS_TBIT_PKT_DATA,           -1, -1},
};
#define tbit_pkt_vars_mfb WARTS_VAR_MFB(tbit_pkt_vars)

#define WARTS_TBIT_PMTUD_MTU     1
#define WARTS_TBIT_PMTUD_PTBRETX 2
#define WARTS_TBIT_PMTUD_OPTIONS 3
#define WARTS_TBIT_PMTUD_PTBSRC  4

static const warts_var_t tbit_pmtud_vars[] =
{
  {WARTS_TBIT_PMTUD_MTU,     2, -1},
  {WARTS_TBIT_PMTUD_PTBRETX, 1, -1},
  {WARTS_TBIT_PMTUD_OPTIONS, 1, -1},
  {WARTS_TBIT_PMTUD_PTBSRC, -1, -1},
};
#define tbit_pmtud_vars_mfb WARTS_VAR_MFB(tbit_pmtud_vars)

#define WARTS_TBIT_NULL_OPTIONS 1
#define WARTS_TBIT_NULL_RESULTS 2

static const warts_var_t tbit_null_vars[] =
{
  {WARTS_TBIT_NULL_OPTIONS, 2, -1},
  {WARTS_TBIT_NULL_RESULTS, 2, -1},
};
#define tbit_null_vars_mfb WARTS_VAR_MFB(tbit_null_vars)

#define WARTS_TBIT_ICW_FIRSTSEQ 1

static const warts_var_t tbit_icw_vars[] =
{
  {WARTS_TBIT_ICW_FIRSTSEQ, 4, -1},
};
#define tbit_icw_vars_mfb WARTS_VAR_MFB(tbit_icw_vars)

#define WARTS_TBIT_BLIND_OFF     1
#define WARTS_TBIT_BLIND_RETX    2

static const warts_var_t tbit_blind_vars[]  =
{
  {WARTS_TBIT_BLIND_OFF,   4, -1},
  {WARTS_TBIT_BLIND_RETX,  1, -1},
};
#define tbit_blind_vars_mfb WARTS_VAR_MFB(tbit_blind_vars)

#define WARTS_TBIT_APP_HTTP_HOST 1
#define WARTS_TBIT_APP_HTTP_FILE 2
#define WARTS_TBIT_APP_HTTP_TYPE 3

static const warts_var_t tbit_app_http_vars[] =
{
  {WARTS_TBIT_APP_HTTP_HOST, -1, -1},
  {WARTS_TBIT_APP_HTTP_FILE, -1, -1},
  {WARTS_TBIT_APP_HTTP_TYPE,  1, -1},
};
#define tbit_app_http_vars_mfb WARTS_VAR_MFB(tbit_app_http_vars)

#define WARTS_TBIT_APP_BGP_ASN 1

static const warts_var_t tbit_app_bgp_vars[] =
{
  {WARTS_TBIT_APP_BGP_ASN,    4, -1},
};
#define tbit_app_bgp_vars_mfb WARTS_VAR_MFB(tbit_app_bgp_vars)

typedef struct warts_tbit_pkt
{
  uint8_t               flags[tbit_pkt_vars_mfb];
  uint16_t              flags_len;
  uint16_t              params_len;
} warts_tbit_pkt_t;

typedef struct warts_tbit_pmtud
{
  uint8_t               flags[WARTS_VAR_MFB(tbit_pmtud_vars)];
  uint16_t              flags_len;
  uint16_t              params_len;
  uint32_t              len;
} warts_tbit_pmtud_t;

typedef struct warts_tbit_null
{
  uint8_t               flags[WARTS_VAR_MFB(tbit_null_vars)];
  uint16_t              flags_len;
  uint16_t              params_len;
  uint32_t              len;
} warts_tbit_null_t;

typedef struct warts_tbit_icw
{
  uint8_t               flags[WARTS_VAR_MFB(tbit_icw_vars)];
  uint16_t              flags_len;
  uint16_t              params_len;
  uint32_t              len;
} warts_tbit_icw_t;

typedef struct warts_tbit_blind
{
  uint8_t               flags[WARTS_VAR_MFB(tbit_blind_vars)];
  uint16_t              flags_len;
  uint16_t              params_len;
  uint32_t              len;
} warts_tbit_blind_t;

typedef struct warts_tbit_app_http
{
  uint8_t               flags[WARTS_VAR_MFB(tbit_app_http_vars)];
  uint16_t              flags_len;
  uint16_t              params_len;
  uint32_t              len;
} warts_tbit_app_http_t;

typedef struct warts_tbit_app_bgp
{
  uint8_t               flags[WARTS_VAR_MFB(tbit_app_bgp_vars)];
  uint16_t              flags_len;
  uint16_t              params_len;
  uint32_t              len;
} warts_tbit_app_bgp_t;

static void warts_tbit_blind_params(const scamper_tbit_t *tbit,
				    warts_tbit_blind_t *state)
{
  scamper_tbit_blind_t *blind = tbit->data;
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(state->flags, 0, tbit_blind_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tbit_blind_vars)/sizeof(warts_var_t); i++)
    {
      var = &tbit_blind_vars[i];
      if((var->id == WARTS_TBIT_BLIND_OFF && blind->off == 0) ||
	 (var->id == WARTS_TBIT_BLIND_RETX && blind->retx == 0))
	continue;
      flag_set(state->flags, var->id, &max_id);
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;

  return;
}

static void warts_tbit_icw_params(const scamper_tbit_t *tbit,
				  warts_tbit_icw_t *state)
{
  scamper_tbit_icw_t *icw = tbit->data;
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(state->flags, 0, tbit_icw_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tbit_icw_vars)/sizeof(warts_var_t); i++)
    {
      var = &tbit_icw_vars[i];
      if(var->id == WARTS_TBIT_ICW_FIRSTSEQ && icw->start_seq == 0)
	continue;
      flag_set(state->flags, var->id, &max_id);
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;

  return;
}

static void warts_tbit_null_params(const scamper_tbit_t *tbit,
				   warts_tbit_null_t *state)
{
  scamper_tbit_null_t *null = tbit->data;
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(state->flags, 0, tbit_null_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tbit_null_vars)/sizeof(warts_var_t); i++)
    {
      var = &tbit_null_vars[i];
      if(var->id == WARTS_TBIT_NULL_OPTIONS && null->options == 0)
	continue;
      if(var->id == WARTS_TBIT_NULL_RESULTS && null->results == 0)
	continue;

      flag_set(state->flags, var->id, &max_id);
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;

  return;
}

static void warts_tbit_pmtud_params(const scamper_tbit_t *tbit,
				    warts_addrtable_t *table,
				    warts_tbit_pmtud_t *state)
{
  scamper_tbit_pmtud_t *pmtud = tbit->data;
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(state->flags, 0, tbit_pmtud_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tbit_pmtud_vars)/sizeof(warts_var_t); i++)
    {
      var = &tbit_pmtud_vars[i];
      if(var->id == WARTS_TBIT_PMTUD_MTU && pmtud->mtu == 0)
	continue;
      if(var->id == WARTS_TBIT_PMTUD_PTBRETX && pmtud->ptb_retx == 0)
	continue;
      if(var->id == WARTS_TBIT_PMTUD_OPTIONS && pmtud->options == 0)
	continue;
      if(var->id == WARTS_TBIT_PMTUD_PTBSRC && pmtud->ptbsrc == NULL)
	continue;

      flag_set(state->flags, var->id, &max_id);

      if(var->id == WARTS_TBIT_PMTUD_PTBSRC)
        {
	  state->params_len += warts_addr_size(table, pmtud->ptbsrc);
	  continue;
        }

      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;

  return;
}

static int warts_tbit_null_read(scamper_tbit_t *tbit, const uint8_t *buf,
				uint32_t *off, uint32_t len)
{
  scamper_tbit_null_t *null = tbit->data;
  uint16_t options = 0;
  uint16_t results = 0;
  warts_param_reader_t handlers[] = {
    {&options, (wpr_t)extract_uint16, NULL},
    {&results, (wpr_t)extract_uint16, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto err;
  null->options = options;
  null->results = results;
  return 0;

 err:
  return -1;
}

static void warts_tbit_null_write(const scamper_tbit_t *tbit, uint8_t *buf,
				  uint32_t *off, uint32_t len,
				  warts_tbit_null_t *state)
{
  scamper_tbit_null_t *null = tbit->data;
  warts_param_writer_t handlers[] = {
    {&null->options, (wpw_t)insert_uint16, NULL},
    {&null->results, (wpw_t)insert_uint16, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int warts_tbit_pmtud_read(scamper_tbit_t *tbit,
				 warts_addrtable_t *table, const uint8_t *buf,
				 uint32_t *off, uint32_t len)
{
  scamper_tbit_pmtud_t *pmtud = tbit->data;
  scamper_addr_t *ptbsrc = NULL;
  uint16_t mtu = 0;
  uint8_t ptb_retx = 0;
  uint8_t options = 0;
  warts_param_reader_t handlers[] = {
    {&mtu,      (wpr_t)extract_uint16, NULL},
    {&ptb_retx, (wpr_t)extract_byte,   NULL},
    {&options,  (wpr_t)extract_byte,   NULL},
    {&ptbsrc,   (wpr_t)extract_addr,   table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto err;

  pmtud->mtu      = mtu;
  pmtud->ptb_retx = ptb_retx;
  pmtud->options  = options;
  pmtud->ptbsrc   = ptbsrc;

  return 0;

 err:
  return -1;
}

static void warts_tbit_pmtud_write(const scamper_tbit_t *tbit, uint8_t *buf,
				   uint32_t *off, uint32_t len,
				   warts_addrtable_t *table,
				   warts_tbit_pmtud_t *state)
{
  scamper_tbit_pmtud_t *pmtud = tbit->data;
  warts_param_writer_t handlers[] = {
    {&pmtud->mtu,      (wpw_t)insert_uint16, NULL},
    {&pmtud->ptb_retx, (wpw_t)insert_byte,   NULL},
    {&pmtud->options,  (wpw_t)insert_byte,   NULL},
    {pmtud->ptbsrc,    (wpw_t)insert_addr,   table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int warts_tbit_icw_read(scamper_tbit_t *tbit, const uint8_t *buf,
			       uint32_t *off, uint32_t len)
{
  scamper_tbit_icw_t *icw = tbit->data;
  warts_param_reader_t handlers[] = {
    {&icw->start_seq, (wpr_t)extract_uint32, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static void warts_tbit_icw_write(const scamper_tbit_t *tbit, uint8_t *buf,
				 uint32_t *off, uint32_t len,
				 warts_tbit_icw_t *state)
{
  scamper_tbit_icw_t *icw = tbit->data;
  warts_param_writer_t handlers[] = {
    {&icw->start_seq, (wpw_t)insert_uint32, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int warts_tbit_blind_read(scamper_tbit_t *tbit, const uint8_t *buf,
				 uint32_t *off, uint32_t len)
{
  scamper_tbit_blind_t *blind = tbit->data;
  warts_param_reader_t handlers[] = {
    {&blind->off,     (wpr_t)extract_int32,    NULL},
    {&blind->retx,    (wpr_t)extract_byte,     NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static void warts_tbit_blind_write(const scamper_tbit_t *tbit, uint8_t *buf,
				   uint32_t *off, uint32_t len,
				   warts_tbit_blind_t *state)
{
  scamper_tbit_blind_t *blind = tbit->data;
  warts_param_writer_t handlers[] = {
    {&blind->off,     (wpw_t)insert_int32,     NULL},
    {&blind->retx,    (wpw_t)insert_byte,      NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static void warts_tbit_app_http_params(const scamper_tbit_t *tbit,
				       warts_tbit_app_http_t *state)
{
  scamper_tbit_app_http_t *http = tbit->app_data;
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(state->flags, 0, tbit_app_http_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tbit_app_http_vars)/sizeof(warts_var_t); i++)
    {
      var = &tbit_app_http_vars[i];
      if(var->id == WARTS_TBIT_APP_HTTP_HOST && http->host == NULL)
	continue;
      if(var->id == WARTS_TBIT_APP_HTTP_FILE && http->file == NULL)
	continue;
      if(var->id == WARTS_TBIT_APP_HTTP_TYPE && http->type == 0)
	continue;

      flag_set(state->flags, var->id, &max_id);

      if(var->size < 0)
	{
	  if(var->id == WARTS_TBIT_APP_HTTP_HOST)
	    state->params_len += warts_str_size(http->host);
	  else if(var->id == WARTS_TBIT_APP_HTTP_FILE)
	    state->params_len += warts_str_size(http->file);
	  continue;
	}

      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;

  return;
}

static int warts_tbit_app_http_read(scamper_tbit_t *tbit, const uint8_t *buf,
				    uint32_t *off, uint32_t len)
{
  scamper_tbit_app_http_t *http;
  char *host = NULL, *file = NULL;
  uint8_t type = SCAMPER_TBIT_APP_HTTP_TYPE_HTTP;
  warts_param_reader_t handlers[] = {
    {&host,     (wpr_t)extract_string, NULL},
    {&file,     (wpr_t)extract_string, NULL},
    {&type,     (wpr_t)extract_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto err;

  if((http = scamper_tbit_app_http_alloc(type, host, file)) == NULL)
    goto err;
  if(host != NULL) { free(host); host = NULL; }
  if(file != NULL) { free(file); file = NULL; }
  tbit->app_data = http;
  return 0;

 err:
  if(host != NULL) free(host);
  if(file != NULL) free(file);
  return -1;
}

static void warts_tbit_app_http_write(const scamper_tbit_t *tbit, uint8_t *buf,
				      uint32_t *off, uint32_t len,
				      warts_tbit_app_http_t *state)
{
  scamper_tbit_app_http_t *http = tbit->app_data;
  warts_param_writer_t handlers[] = {
    {http->host,      (wpw_t)insert_string,   NULL},
    {http->file,      (wpw_t)insert_string,   NULL},
    {&http->type,     (wpw_t)insert_byte,     NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static void warts_tbit_app_bgp_params(const scamper_tbit_t *tbit,
				      warts_tbit_app_bgp_t *state)
{
  scamper_tbit_app_bgp_t *bgp = tbit->app_data;
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(state->flags, 0, tbit_app_bgp_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tbit_app_bgp_vars)/sizeof(warts_var_t); i++)
    {
      var = &tbit_app_bgp_vars[i];
      if(var->id == WARTS_TBIT_APP_BGP_ASN && bgp->asn == 0)
	continue;

      flag_set(state->flags, var->id, &max_id);
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;

  return;
}

static int warts_tbit_app_bgp_read(scamper_tbit_t *tbit, const uint8_t *buf,
				    uint32_t *off, uint32_t len)
{
  scamper_tbit_app_bgp_t *bgp;
  uint32_t asn = 0;
  warts_param_reader_t handlers[] = {
    {&asn,     (wpr_t)extract_uint32, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;
  if((bgp = scamper_tbit_app_bgp_alloc()) == NULL)
    return -1;
  bgp->asn = asn;
  tbit->app_data = bgp;
  return 0;
}

static void warts_tbit_app_bgp_write(const scamper_tbit_t *tbit, uint8_t *buf,
				     uint32_t *off, uint32_t len,
				     warts_tbit_app_bgp_t *state)
{
  scamper_tbit_app_bgp_t *bgp = tbit->app_data;
  warts_param_writer_t handlers[] = {
    {&bgp->asn,     (wpw_t)insert_uint32,     NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static void warts_tbit_pkt_params(const scamper_tbit_pkt_t *pkt,
				  warts_tbit_pkt_t *state, uint32_t *len)
{
  const warts_var_t *var;
  int max_id = 0;
  uint16_t i;

  memset(state->flags, 0, tbit_pkt_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tbit_pkt_vars) / sizeof(warts_var_t); i++)
    {
      var = &tbit_pkt_vars[i];

      if(var->id == WARTS_TBIT_PKT_DATA)
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

static scamper_tbit_pkt_t *warts_tbit_pkt_read(warts_state_t *state,
					       uint8_t *buf, uint32_t *off,
					       uint32_t len)
{
  scamper_tbit_pkt_t *pkt = NULL;
  uint8_t dir, *data = NULL;
  struct timeval tv;
  uint16_t plen;
  warts_param_reader_t handlers[] = {
    {&dir,  (wpr_t)extract_byte,         NULL},
    {&tv,   (wpr_t)extract_timeval,      NULL},
    {&plen, (wpr_t)extract_uint16,       NULL},
    {&data, (wpr_t)extract_bytes_ptr,   &plen},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0 ||
     (pkt = scamper_tbit_pkt_alloc(dir, data, plen, &tv)) == NULL)
    goto err;

  return pkt;

 err:
  if(pkt != NULL) scamper_tbit_pkt_free(pkt);
  return NULL;
}

static int warts_tbit_pkt_write(const scamper_tbit_pkt_t *pkt,
				const scamper_file_t *sf,
				uint8_t *buf,uint32_t *off,const uint32_t len,
				warts_tbit_pkt_t *state)
{
  uint16_t dl = pkt->len;
  warts_param_writer_t handlers[] = {
    {&pkt->dir, (wpw_t)insert_byte,          NULL},
    {&pkt->tv,  (wpw_t)insert_timeval,       NULL},
    {&pkt->len, (wpw_t)insert_uint16,        NULL},
    {pkt->data, (wpw_t)insert_bytes_uint16, &dl},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return 0;
}

void insert_cookie(uint8_t *buf, uint32_t *off, const uint32_t len,
		   const uint8_t *cookie, uint8_t *count)
{
  assert(len - *off >= ((*count) + 1));
  buf[(*off)++] = *count;
  memcpy(buf + *off, cookie, *count);
  *off += *count;
  return;
}

int extract_cookie(const uint8_t *buf, uint32_t *off,
		   const uint32_t len, uint8_t *out, void *param)
{
  uint8_t cookielen;
  if(*off >= len || len - *off < 1)
    return -1;
  out[0] = cookielen = buf[(*off)++];
  if(cookielen > 16 || cookielen > len - *off)
    return -1;
  memcpy(out+1, buf + *off, cookielen);
  *off += cookielen;
  return 0;
}

static void warts_tbit_params(const scamper_tbit_t *tbit,
			      warts_addrtable_t *table, uint8_t *flags,
			      uint16_t *flags_len, uint16_t *params_len)
{
  const warts_var_t *var;
  int i, max_id = 0;

  /* Unset all flags */
  memset(flags, 0, tbit_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(tbit_vars)/sizeof(warts_var_t); i++)
    {
      var = &tbit_vars[i];

      /* Skip the variables for which we have no data */
      if(var->id == WARTS_TBIT_PKTC16 ||
	 (var->id == WARTS_TBIT_LIST && tbit->list == NULL)   ||
	 (var->id == WARTS_TBIT_CYCLE && tbit->cycle == NULL) ||
	 (var->id == WARTS_TBIT_USERID && tbit->userid == 0)  ||
	 (var->id == WARTS_TBIT_SRC && tbit->src == NULL)     ||
	 (var->id == WARTS_TBIT_DST && tbit->dst == NULL)     ||
	 (var->id == WARTS_TBIT_COOKIE && tbit->fo_cookielen == 0) ||
	 (var->id == WARTS_TBIT_WSCALE && tbit->wscale == 0) ||
	 (var->id == WARTS_TBIT_OPTIONS && tbit->options == 0) ||
	 (var->id == WARTS_TBIT_TTL && tbit->ttl == 255))
	continue;

      /* Set the flag for the rest of the variables */
      flag_set(flags, var->id, &max_id);

      /* Variables that don't have a fixed size */
      if(var->id == WARTS_TBIT_SRC)
        {
	  *params_len += warts_addr_size(table, tbit->src);
	  continue;
        }
      else if(var->id == WARTS_TBIT_DST)
        {
	  *params_len += warts_addr_size(table, tbit->dst);
	  continue;
        }
      else if(var->id == WARTS_TBIT_COOKIE)
	{
	  *params_len += (1 + tbit->fo_cookielen);
	  continue;
	}

      /* The rest of the variables have a fixed size */
      *params_len += var->size;
    }

  *flags_len = fold_flags(flags, max_id);
  return;
}

static int warts_tbit_params_read(scamper_tbit_t *tbit,
				  warts_addrtable_t *table,
				  warts_state_t *state,
				  uint8_t *buf, uint32_t *off, uint32_t len)
{
  uint16_t pktc16 = 0;
  uint32_t pktc32 = 0;
  uint8_t cookie[17];
  uint32_t o = *off;

  warts_param_reader_t handlers[] = {
    {&tbit->list,         (wpr_t)extract_list,    state},
    {&tbit->cycle,        (wpr_t)extract_cycle,   state},
    {&tbit->userid,       (wpr_t)extract_uint32,  NULL},
    {&tbit->src,          (wpr_t)extract_addr,    table},
    {&tbit->dst,          (wpr_t)extract_addr,    table},
    {&tbit->sport,        (wpr_t)extract_uint16,  NULL},
    {&tbit->dport,        (wpr_t)extract_uint16,  NULL},
    {&tbit->start,        (wpr_t)extract_timeval, NULL},
    {&tbit->result,       (wpr_t)extract_uint16,  NULL},
    {&tbit->type,         (wpr_t)extract_byte,    NULL},
    {&tbit->app_proto,    (wpr_t)extract_byte,    NULL},
    {&tbit->client_mss,   (wpr_t)extract_uint16,  NULL},
    {&tbit->server_mss,   (wpr_t)extract_uint16,  NULL},
    {&tbit->syn_retx,     (wpr_t)extract_byte,    NULL},
    {&tbit->dat_retx,     (wpr_t)extract_byte,    NULL},
    {&pktc16,             (wpr_t)extract_uint16,  NULL},
    {&pktc32,             (wpr_t)extract_uint32,  NULL},
    {cookie,              (wpr_t)extract_cookie,  NULL},
    {&tbit->wscale,       (wpr_t)extract_byte,    NULL},
    {&tbit->options,      (wpr_t)extract_uint32,  NULL},
    {&tbit->ttl,          (wpr_t)extract_byte,    NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(tbit->src == NULL || tbit->dst == NULL)
    return -1;

  /* handle the fact the pktc param changed from 16 to 32 bits */
  if(pktc32 != 0)
    tbit->pktc = pktc32;
  else if(pktc16 != 0)
    tbit->pktc = pktc16;

  if(flag_isset(&buf[o], WARTS_TBIT_COOKIE) &&
     scamper_tbit_fo_setcookie(tbit, cookie+1, cookie[0]) != 0)
    return -1;

  if(flag_isset(&buf[o], WARTS_TBIT_TTL) == 0)
    tbit->ttl = 255;
  
  return 0;
}

static int warts_tbit_params_write(const scamper_tbit_t *tbit,
				   const scamper_file_t *sf,
				   warts_addrtable_t *table,
				   uint8_t *buf, uint32_t *off,
				   const uint32_t len, const uint8_t *flags,
				   const uint16_t flags_len,
				   const uint16_t params_len)
{
  uint32_t list_id, cycle_id;
  uint8_t cookielen = tbit->fo_cookielen;

  /* Specifies how to write each variable to the warts file. */
  warts_param_writer_t handlers[] = {
    {&list_id,            (wpw_t)insert_uint32,  NULL},
    {&cycle_id,           (wpw_t)insert_uint32,  NULL},
    {&tbit->userid,       (wpw_t)insert_uint32,  NULL},
    {tbit->src,           (wpw_t)insert_addr,    table},
    {tbit->dst,           (wpw_t)insert_addr,    table},
    {&tbit->sport,        (wpw_t)insert_uint16,  NULL},
    {&tbit->dport,        (wpw_t)insert_uint16,  NULL},
    {&tbit->start,        (wpw_t)insert_timeval, NULL},
    {&tbit->result,       (wpw_t)insert_uint16,  NULL},
    {&tbit->type,         (wpw_t)insert_byte,    NULL},
    {&tbit->app_proto,    (wpw_t)insert_byte,    NULL},
    {&tbit->client_mss,   (wpw_t)insert_uint16,  NULL},
    {&tbit->server_mss,   (wpw_t)insert_uint16,  NULL},
    {&tbit->syn_retx,     (wpw_t)insert_byte,    NULL},
    {&tbit->dat_retx,     (wpw_t)insert_byte,    NULL},
    {NULL,                NULL,                  NULL}, /* PKTC16 */
    {&tbit->pktc,         (wpw_t)insert_uint32,  NULL},
    {tbit->fo_cookie,     (wpw_t)insert_cookie,  &cookielen},
    {&tbit->wscale,       (wpw_t)insert_byte,    NULL},
    {&tbit->options,      (wpw_t)insert_uint32,  NULL},
    {&tbit->ttl,          (wpw_t)insert_byte,    NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  tbit->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, tbit->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len,
		     handlers, handler_cnt);

  return 0;
}

int scamper_file_warts_tbit_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_tbit_t **tbit_out)
{
  scamper_tbit_t *tbit = NULL;
  warts_addrtable_t *table = NULL;
  warts_state_t *state = scamper_file_getstate(sf);
  uint8_t *buf = NULL;
  uint16_t junk16;
  uint32_t junk32;
  uint32_t off = 0;
  uint32_t i;

  /* Read in the header */
  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }

  if(buf == NULL)
    {
      *tbit_out = NULL;
      return 0;
    }

  /* Allocate space for a tbit object */
  if((tbit = scamper_tbit_alloc()) == NULL)
    {
      goto err;
    }

  if((table = warts_addrtable_alloc_byid()) == NULL)
    goto err;

  /* Read in the tbit data from the warts file */
  if(warts_tbit_params_read(tbit, table, state, buf, &off, hdr->len) != 0)
    {
      goto err;
    }

  switch(tbit->type)
    {
    case SCAMPER_TBIT_TYPE_PMTUD:
      if((tbit->data = scamper_tbit_pmtud_alloc()) == NULL)
	goto err;
      break;

    case SCAMPER_TBIT_TYPE_NULL:
      if((tbit->data = scamper_tbit_null_alloc()) == NULL)
	goto err;
      break;

    case SCAMPER_TBIT_TYPE_ICW:
      if((tbit->data = scamper_tbit_icw_alloc()) == NULL)
	goto err;
      break;

    case SCAMPER_TBIT_TYPE_BLIND_RST:
    case SCAMPER_TBIT_TYPE_BLIND_SYN:
    case SCAMPER_TBIT_TYPE_BLIND_DATA:
    case SCAMPER_TBIT_TYPE_BLIND_FIN:
      if((tbit->data = scamper_tbit_blind_alloc()) == NULL)
	goto err;
      break;      
    }

  /* Determine how many tbit_pkts to read */
  if(tbit->pktc > 0)
    {
      /* Allocate the tbit_pkts array */
      if(scamper_tbit_pkts_alloc(tbit, tbit->pktc) != 0)
	goto err;

      /* For each tbit packet, read it and insert it into the tbit structure */
      for(i=0; i<tbit->pktc; i++)
        {
	  tbit->pkts[i] = warts_tbit_pkt_read(state, buf, &off, hdr->len);
	  if(tbit->pkts[i] == NULL)
	    goto err;
        }
    }

  for(;;)
    {
      if(extract_uint16(buf, &off, hdr->len, &junk16, NULL) != 0)
	goto err;
      if(junk16 == WARTS_TBIT_STRUCT_EOF)
	break;
      if(extract_uint32(buf, &off, hdr->len, &junk32, NULL) != 0)
	goto err;

      i = off;
      if(junk16 == WARTS_TBIT_STRUCT_TYPE)
	{
	  switch(tbit->type)
	    {
	    case SCAMPER_TBIT_TYPE_PMTUD:
	      if(warts_tbit_pmtud_read(tbit, table, buf, &i, hdr->len) != 0)
		goto err;
	      break;

	    case SCAMPER_TBIT_TYPE_NULL:
	      if(warts_tbit_null_read(tbit, buf, &i, hdr->len) != 0)
		goto err;
	      break;

	    case SCAMPER_TBIT_TYPE_ICW:
	      if(warts_tbit_icw_read(tbit, buf, &i, hdr->len) != 0)
		goto err;
	      break;
	      
	    case SCAMPER_TBIT_TYPE_BLIND_RST:
	    case SCAMPER_TBIT_TYPE_BLIND_SYN:
	    case SCAMPER_TBIT_TYPE_BLIND_DATA:
	    case SCAMPER_TBIT_TYPE_BLIND_FIN:
	      if(warts_tbit_blind_read(tbit, buf, &i, hdr->len) != 0)
		goto err;
	      break;
	    }
	}
      else if(junk16 == WARTS_TBIT_STRUCT_APP)
	{
	  if(tbit->app_proto == SCAMPER_TBIT_APP_HTTP)
	    {
	      if(warts_tbit_app_http_read(tbit, buf, &i, hdr->len) != 0)
		goto err;
	    }
	  else if(tbit->app_proto == SCAMPER_TBIT_APP_BGP)
	    {
	      if(warts_tbit_app_bgp_read(tbit, buf, &i, hdr->len) != 0)
		goto err;
	    }
	}

      off += junk32;
    }

  warts_addrtable_free(table);
  *tbit_out = tbit;
  free(buf);
  return 0;

 err:
  if(table != NULL) warts_addrtable_free(table);
  if(buf != NULL) free(buf);
  if(tbit != NULL) scamper_tbit_free(tbit);
  return -1;
}

/* Write data from a scamper tbit object to a warts file */
int scamper_file_warts_tbit_write(const scamper_file_t *sf,
				  const scamper_tbit_t *tbit)
{
  warts_addrtable_t *table = NULL;
  warts_tbit_pkt_t *pkts = NULL;
  warts_tbit_pmtud_t pmtud;
  warts_tbit_null_t null;
  warts_tbit_icw_t icw;
  warts_tbit_blind_t blind;
  warts_tbit_app_http_t http;
  warts_tbit_app_bgp_t bgp;
  uint8_t *buf = NULL;
  uint8_t  flags[tbit_vars_mfb];
  uint16_t junk16;
  uint16_t flags_len, params_len;
  uint32_t len, i, off = 0;
  size_t size;

  if((table = warts_addrtable_alloc_byaddr()) == NULL)
    goto err;

  /* Set the tbit data (not including the packets) */
  warts_tbit_params(tbit, table, flags, &flags_len, &params_len);
  len = 8 + flags_len + params_len + 2;

  if(tbit->pktc > 0)
    {
      /* Allocate memory for the state */
      size = tbit->pktc * sizeof(warts_tbit_pkt_t);
      if((pkts = (warts_tbit_pkt_t *)malloc_zero(size)) == NULL)
	goto err;

      for(i=0; i<tbit->pktc; i++)
	warts_tbit_pkt_params(tbit->pkts[i], &pkts[i], &len);
    }

  if(tbit->data != NULL)
    {
      switch(tbit->type)
	{
	case SCAMPER_TBIT_TYPE_PMTUD:
	  warts_tbit_pmtud_params(tbit, table, &pmtud);
	  len += (2 + 4 + pmtud.len);
	  break;

	case SCAMPER_TBIT_TYPE_NULL:
	  warts_tbit_null_params(tbit, &null);
	  len += (2 + 4 + null.len);
	  break;

	case SCAMPER_TBIT_TYPE_ICW:
	  warts_tbit_icw_params(tbit, &icw);
	  len += (2 + 4 + icw.len);
	  break;
	  
	case SCAMPER_TBIT_TYPE_BLIND_RST:
	case SCAMPER_TBIT_TYPE_BLIND_SYN:
	case SCAMPER_TBIT_TYPE_BLIND_DATA:
	case SCAMPER_TBIT_TYPE_BLIND_FIN:
	  warts_tbit_blind_params(tbit, &blind);
	  len += (2 + 4 + blind.len);
	  break;

	default:
	  goto err;
	}
    }

  if(tbit->app_data != NULL)
    {
      if(tbit->app_proto == SCAMPER_TBIT_APP_HTTP)
	{
	  warts_tbit_app_http_params(tbit, &http);
	  len += (2 + 4 + http.len);
	}
      else if(tbit->app_proto == SCAMPER_TBIT_APP_BGP)
	{
	  warts_tbit_app_bgp_params(tbit, &bgp);
	  len += (2 + 4 + bgp.len);
	}
      else goto err;
    }

  /* struct eof */
  len += 2;

  /* Allocate memory to store all of the data (including packets) */
  if((buf = malloc_zero(len)) == NULL)
    goto err;
  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_TBIT);

  /* Write the tbit data (excluding packets) to the buffer */
  if(warts_tbit_params_write(tbit, sf, table, buf, &off, len,
			     flags, flags_len, params_len) != 0)
    {
      goto err;
    }

  if(tbit->pktc > 0)
    {
      for(i=0; i<tbit->pktc; i++)
	warts_tbit_pkt_write(tbit->pkts[i], sf, buf, &off, len, &pkts[i]);
      free(pkts); pkts = NULL;
    }

  if(tbit->data != NULL)
    {
      junk16 = WARTS_TBIT_STRUCT_TYPE;
      insert_uint16(buf, &off, len, &junk16, NULL);

      switch(tbit->type)
	{
	case SCAMPER_TBIT_TYPE_PMTUD:
	  insert_uint32(buf, &off, len, &pmtud.len, NULL);
	  warts_tbit_pmtud_write(tbit, buf, &off, len, table, &pmtud);
	  break;

	case SCAMPER_TBIT_TYPE_NULL:
	  insert_uint32(buf, &off, len, &null.len, NULL);
	  warts_tbit_null_write(tbit, buf, &off, len, &null);
	  break;

	case SCAMPER_TBIT_TYPE_ICW:
	  insert_uint32(buf, &off, len, &icw.len, NULL);
	  warts_tbit_icw_write(tbit, buf, &off, len, &icw);
	  break;
	  
	case SCAMPER_TBIT_TYPE_BLIND_RST:
	case SCAMPER_TBIT_TYPE_BLIND_SYN:
	case SCAMPER_TBIT_TYPE_BLIND_DATA:
	case SCAMPER_TBIT_TYPE_BLIND_FIN:
	  insert_uint32(buf, &off, len, &blind.len, NULL);
	  warts_tbit_blind_write(tbit, buf, &off, len, &blind);
	  break;

	default:
	  goto err;
	}
    }

  if(tbit->app_data != NULL)
    {
      junk16 = WARTS_TBIT_STRUCT_APP;
      insert_uint16(buf, &off, len, &junk16, NULL);

      if(tbit->app_proto == SCAMPER_TBIT_APP_HTTP)
	{
	  insert_uint32(buf, &off, len, &http.len, NULL);
	  warts_tbit_app_http_write(tbit, buf, &off, len, &http);
	}
      else if(tbit->app_proto == SCAMPER_TBIT_APP_BGP)
	{
	  insert_uint32(buf, &off, len, &bgp.len, NULL);
	  warts_tbit_app_bgp_write(tbit, buf, &off, len, &bgp);
	}
      else goto err;
    }

  junk16 = WARTS_TBIT_STRUCT_EOF;
  insert_uint16(buf, &off, len, &junk16, NULL);

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
