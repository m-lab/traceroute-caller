/*
 * scamper_host_warts.c
 *
 * Copyright (C) 2019      Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_host_warts.c,v 1.2 2019/08/04 09:33:06 mjl Exp $
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
  "$Id: scamper_host_warts.c,v 1.2 2019/08/04 09:33:06 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_host.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_host_warts.h"

#include "mjl_splaytree.h"
#include "utils.h"

/*
 * the bits of a host structure
 */
#define WARTS_HOST_LIST            1
#define WARTS_HOST_CYCLE           2
#define WARTS_HOST_USERID          3
#define WARTS_HOST_SRC             4
#define WARTS_HOST_DST             5
#define WARTS_HOST_START           6
#define WARTS_HOST_FLAGS           7
#define WARTS_HOST_WAIT            8
#define WARTS_HOST_STOP            9
#define WARTS_HOST_RETRIES         10
#define WARTS_HOST_QTYPE           11
#define WARTS_HOST_QCLASS          12
#define WARTS_HOST_QNAME           13
#define WARTS_HOST_QCOUNT          14

static const warts_var_t host_vars[] =
{
  {WARTS_HOST_LIST,            4, -1},
  {WARTS_HOST_CYCLE,           4, -1},
  {WARTS_HOST_USERID,          4, -1},
  {WARTS_HOST_SRC,            -1, -1},
  {WARTS_HOST_DST,            -1, -1},
  {WARTS_HOST_START,           8, -1},
  {WARTS_HOST_FLAGS,           2, -1},
  {WARTS_HOST_WAIT,            2, -1},
  {WARTS_HOST_STOP,            1, -1},
  {WARTS_HOST_RETRIES,         1, -1},
  {WARTS_HOST_QTYPE,           2, -1},
  {WARTS_HOST_QCLASS,          2, -1},
  {WARTS_HOST_QNAME,          -1, -1},
  {WARTS_HOST_QCOUNT,          1, -1},
};
#define host_vars_mfb WARTS_VAR_MFB(host_vars)

/*
 * the bits of a host query structure
 */
#define WARTS_HOST_QUERY_TX        1
#define WARTS_HOST_QUERY_RX        2
#define WARTS_HOST_QUERY_ID        3
#define WARTS_HOST_QUERY_ANCOUNT   4
#define WARTS_HOST_QUERY_NSCOUNT   5
#define WARTS_HOST_QUERY_ARCOUNT   6

static const warts_var_t host_query_vars[] =
{
 {WARTS_HOST_QUERY_TX,        8, -1},
 {WARTS_HOST_QUERY_RX,        8, -1},
 {WARTS_HOST_QUERY_ID,        2, -1},
 {WARTS_HOST_QUERY_ANCOUNT,   2, -1},
 {WARTS_HOST_QUERY_NSCOUNT,   2, -1},
 {WARTS_HOST_QUERY_ARCOUNT,   2, -1},
};
#define host_query_vars_mfb WARTS_VAR_MFB(host_query_vars)

/*
 * the bits of a host rr structure
 */
#define WARTS_HOST_RR_CLASS         1
#define WARTS_HOST_RR_TYPE          2
#define WARTS_HOST_RR_NAME          3
#define WARTS_HOST_RR_TTL           4
#define WARTS_HOST_RR_DATA          5

static const warts_var_t host_rr_vars[] =
{
 {WARTS_HOST_RR_CLASS,        2, -1},
 {WARTS_HOST_RR_TYPE,         2, -1},
 {WARTS_HOST_RR_NAME,        -1, -1},
 {WARTS_HOST_RR_TTL,          4, -1},
 {WARTS_HOST_RR_DATA,        -1, -1},
};
#define host_rr_vars_mfb WARTS_VAR_MFB(host_rr_vars)

/*
 * the bits of a rr_mx structure
 */
#define WARTS_HOST_RR_MX_PREFERENCE 1
#define WARTS_HOST_RR_MX_EXCHANGE   2

static const warts_var_t host_rr_mx_vars[] =
{
 {WARTS_HOST_RR_MX_PREFERENCE,  2, -1},
 {WARTS_HOST_RR_MX_EXCHANGE,   -1, -1},
};
#define host_rr_mx_vars_mfb WARTS_VAR_MFB(host_rr_mx_vars)

/*
 * the bits of a rr_soa structure
 */
#define WARTS_HOST_RR_SOA_MNAME     1
#define WARTS_HOST_RR_SOA_RNAME     2
#define WARTS_HOST_RR_SOA_SERIAL    3
#define WARTS_HOST_RR_SOA_REFRESH   4
#define WARTS_HOST_RR_SOA_RETRY     5
#define WARTS_HOST_RR_SOA_EXPIRE    6
#define WARTS_HOST_RR_SOA_MINIMUM   7

static const warts_var_t host_rr_soa_vars[] =
{
 {WARTS_HOST_RR_SOA_MNAME,   -1, -1},
 {WARTS_HOST_RR_SOA_RNAME,   -1, -1},
 {WARTS_HOST_RR_SOA_SERIAL,   4, -1},
 {WARTS_HOST_RR_SOA_REFRESH,  4, -1},
 {WARTS_HOST_RR_SOA_RETRY,    4, -1},
 {WARTS_HOST_RR_SOA_EXPIRE,   4, -1},
 {WARTS_HOST_RR_SOA_MINIMUM,  4, -1},
};
#define host_rr_soa_vars_mfb WARTS_VAR_MFB(host_rr_soa_vars)

typedef struct warts_host_query
{
  uint8_t   flags[WARTS_VAR_MFB(host_query_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint32_t  len;
} warts_host_query_t;

typedef struct warts_host_rr_mx
{
  uint8_t   flags[WARTS_VAR_MFB(host_rr_mx_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint32_t  len;
} warts_host_rr_mx_t;

typedef struct warts_host_rr_soa
{
  uint8_t   flags[WARTS_VAR_MFB(host_rr_soa_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint32_t  len;
} warts_host_rr_soa_t;

typedef struct warts_host_rr
{
  uint8_t   flags[WARTS_VAR_MFB(host_rr_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint32_t  len;

  scamper_host_rr_t *rr;
  uint16_t  data_type;
  union
  {
    warts_host_rr_soa_t *soa;
    warts_host_rr_mx_t *mx;
  } data_un;
} warts_host_rr_t;

static void warts_host_query_params(const scamper_host_query_t *query,
				    warts_host_query_t *state)
{
  const warts_var_t *var;
  int i, max_id = 0;

  memset(state->flags, 0, host_query_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(host_query_vars)/sizeof(warts_var_t); i++)
    {
      var = &host_query_vars[i];
      if((var->id == WARTS_HOST_QUERY_ID      && query->id == 0) ||
	 (var->id == WARTS_HOST_QUERY_ANCOUNT && query->ancount == 0) ||
	 (var->id == WARTS_HOST_QUERY_NSCOUNT && query->nscount == 0) ||
	 (var->id == WARTS_HOST_QUERY_ARCOUNT && query->arcount == 0))
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

static int warts_host_query_read(scamper_host_query_t *query,
				 const uint8_t *buf, uint32_t *off,
				 uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&query->tx,      (wpr_t)extract_timeval, NULL},
    {&query->rx,      (wpr_t)extract_timeval, NULL},
    {&query->id,      (wpr_t)extract_uint16,  NULL},
    {&query->ancount, (wpr_t)extract_uint16,  NULL},
    {&query->nscount, (wpr_t)extract_uint16,  NULL},
    {&query->arcount, (wpr_t)extract_uint16,  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto err;
  return 0;

 err:
  return -1;
}

static void warts_host_query_write(const scamper_host_query_t *query,
				   uint8_t *buf, uint32_t *off, uint32_t len,
				   warts_host_query_t *state)
{
  warts_param_writer_t handlers[] = {
    {&query->tx,      (wpw_t)insert_timeval, NULL},
    {&query->tx,      (wpw_t)insert_timeval, NULL},
    {&query->id,      (wpw_t)insert_uint16,  NULL},
    {&query->ancount, (wpw_t)insert_uint16,  NULL},
    {&query->nscount, (wpw_t)insert_uint16,  NULL},
    {&query->arcount, (wpw_t)insert_uint16,  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static void warts_host_rr_mx_params(const scamper_host_rr_mx_t *mx,
				    warts_host_rr_mx_t *state)
{
  const warts_var_t *var;
  int i, max_id = 0;

  memset(state->flags, 0, host_rr_mx_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(host_rr_mx_vars)/sizeof(warts_var_t); i++)
    {
      var = &host_rr_mx_vars[i];
      if((var->id == WARTS_HOST_RR_MX_PREFERENCE && mx->preference == 0) ||
	 (var->id == WARTS_HOST_RR_MX_EXCHANGE && mx->exchange == NULL))
	continue;
      flag_set(state->flags, var->id, &max_id);

      if(var->id == WARTS_HOST_RR_MX_EXCHANGE)
	{
	  state->params_len += warts_str_size(mx->exchange);
	  continue;
	}
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len += fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;
  return;
}

static int warts_host_rr_mx_read(void **data, const uint8_t *buf,
				 uint32_t *off, uint32_t len)
{
  scamper_host_rr_mx_t *mx = NULL;
  uint16_t preference = 0;
  char *exchange = NULL;
  warts_param_reader_t handlers[] = {
    {&preference, (wpr_t)extract_uint16, NULL},
    {&exchange,   (wpr_t)extract_string, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto err;
  if((mx = scamper_host_rr_mx_alloc(preference, exchange)) == NULL)
    goto err;
  if(exchange != NULL) free(exchange);
  *data = mx;
  return 0;

 err:
  if(exchange != NULL) free(exchange);
  return -1;
}

static void warts_host_rr_mx_write(scamper_host_rr_mx_t *mx, uint8_t *buf,
				   uint32_t *off, uint32_t len,
				   warts_host_rr_mx_t *state)
{
  warts_param_writer_t handlers[] = {
    {&mx->preference, (wpw_t)insert_uint16, NULL},
    {mx->exchange,    (wpw_t)insert_string, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static void warts_host_rr_soa_params(const scamper_host_rr_soa_t *soa,
				     warts_host_rr_soa_t *state)
{
  const warts_var_t *var;
  int i, max_id = 0;

  memset(state->flags, 0, host_rr_soa_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(host_rr_soa_vars)/sizeof(warts_var_t); i++)
    {
      var = &host_rr_soa_vars[i];
      if((var->id == WARTS_HOST_RR_SOA_MNAME   && soa->mname == NULL) ||
	 (var->id == WARTS_HOST_RR_SOA_RNAME   && soa->mname == NULL) ||
	 (var->id == WARTS_HOST_RR_SOA_SERIAL  && soa->serial == 0) ||
	 (var->id == WARTS_HOST_RR_SOA_REFRESH && soa->refresh == 0) ||
	 (var->id == WARTS_HOST_RR_SOA_RETRY   && soa->retry == 0) ||
	 (var->id == WARTS_HOST_RR_SOA_EXPIRE  && soa->expire == 0) ||
	 (var->id == WARTS_HOST_RR_SOA_MINIMUM && soa->minimum == 0))
	continue;

      flag_set(state->flags, var->id, &max_id);
      if(var->id == WARTS_HOST_RR_SOA_MNAME)
	{
	  state->params_len += warts_str_size(soa->mname);
	  continue;
	}
      else if(var->id == WARTS_HOST_RR_SOA_RNAME)
	{
	  state->params_len += warts_str_size(soa->rname);
	  continue;
	}
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len += fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;
  return;
}

static int warts_host_rr_soa_read(void **data,
				  const uint8_t *buf, uint32_t *off,
				  uint32_t len)
{
  scamper_host_rr_soa_t *soa = NULL;
  char *mname = NULL, *rname = NULL;
  uint32_t serial = 0, refresh = 0, retry = 0, expire = 0, minimum = 0;
  warts_param_reader_t handlers[] = {
    {&mname,   (wpr_t)extract_string, NULL},
    {&rname,   (wpr_t)extract_string, NULL},
    {&serial,  (wpr_t)extract_uint32, NULL},
    {&refresh, (wpr_t)extract_uint32, NULL},
    {&retry,   (wpr_t)extract_uint32, NULL},
    {&expire,  (wpr_t)extract_uint32, NULL},
    {&minimum, (wpr_t)extract_uint32, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto err;
  if((soa = scamper_host_rr_soa_alloc(mname, rname)) == NULL)
    goto err;
  soa->serial = serial;
  soa->refresh = refresh;
  soa->retry = retry;
  soa->expire = expire;
  soa->minimum = minimum;
  *data = soa;
  if(mname != NULL) free(mname);
  if(rname != NULL) free(rname);
  return 0;

 err:
  if(mname != NULL) free(mname);
  if(rname != NULL) free(rname);
  return -1;
}

static void warts_host_rr_soa_write(scamper_host_rr_soa_t *soa,
				    uint8_t *buf, uint32_t *off, uint32_t len,
				    warts_host_rr_soa_t *state)
{
  warts_param_writer_t handlers[] = {
    {soa->mname,    (wpw_t)insert_string, NULL},
    {soa->rname,    (wpw_t)insert_string, NULL},
    {&soa->serial,  (wpw_t)insert_uint32, NULL},
    {&soa->refresh, (wpw_t)insert_uint32, NULL},
    {&soa->retry,   (wpw_t)insert_uint32, NULL},
    {&soa->expire,  (wpw_t)insert_uint32, NULL},
    {&soa->minimum, (wpw_t)insert_uint32, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int extract_rrdata(const uint8_t *buf, uint32_t *off, uint32_t len,
			  void **data, warts_addrtable_t *table)
{
  uint16_t type;

  if(extract_uint16(buf, off, len, &type, NULL) != 0)
    return -1;

  if(type == SCAMPER_HOST_RR_DATA_TYPE_ADDR)
    {
      if(extract_addr(buf, off, len, (scamper_addr_t **)data, table) != 0)
	return -1;
      return 0;
    }
  else if(type == SCAMPER_HOST_RR_DATA_TYPE_STR)
    {
      if(extract_string(buf, off, len, (char **)data, NULL) != 0)
	return -1;
      return 0;
    }
  else if(type == SCAMPER_HOST_RR_DATA_TYPE_SOA)
    {
      if(warts_host_rr_soa_read(data, buf, off, len) != 0)
	return -1;
      return 0;
    }
  else if(type == SCAMPER_HOST_RR_DATA_TYPE_MX)
    {
      if(warts_host_rr_mx_read(data, buf, off, len) != 0)
	return -1;
      return 0;
    }
  return -1;
}

static void insert_rrdata(uint8_t *buf, uint32_t *off, const uint32_t len,
			  const warts_host_rr_t *rr,
			  warts_addrtable_t *table)
{
  insert_uint16(buf, off, len, &rr->data_type, NULL);

  if(rr->data_type == SCAMPER_HOST_RR_DATA_TYPE_ADDR)
    {
      insert_addr(buf, off, len, rr->rr->un.addr, table);
    }
  else if(rr->data_type == SCAMPER_HOST_RR_DATA_TYPE_STR)
    {
      insert_string(buf, off, len, rr->rr->un.str, NULL);
    }
  else if(rr->data_type == SCAMPER_HOST_RR_DATA_TYPE_SOA)
    {
      warts_host_rr_soa_write(rr->rr->un.soa, buf, off, len, rr->data_un.soa);
    }
  else if(rr->data_type == SCAMPER_HOST_RR_DATA_TYPE_MX)
    {
      warts_host_rr_mx_write(rr->rr->un.mx, buf, off, len, rr->data_un.mx);
    }
  return;
}

static int warts_host_rr_data_len(const scamper_host_rr_t *rr,
				  warts_host_rr_t *state,
				  warts_addrtable_t *table)
{
  int len = 2;
  int x;

  x = scamper_host_rr_data_type(rr);
  assert(x == SCAMPER_HOST_RR_DATA_TYPE_ADDR ||
	 x == SCAMPER_HOST_RR_DATA_TYPE_STR ||
	 x == SCAMPER_HOST_RR_DATA_TYPE_SOA ||
	 x == SCAMPER_HOST_RR_DATA_TYPE_MX);

  state->data_type = (uint16_t)x;
  state->rr = (scamper_host_rr_t*)rr;
  if(state->data_type == SCAMPER_HOST_RR_DATA_TYPE_ADDR)
    {
      len += warts_addr_size(table, rr->un.addr);
      return len;
    }
  else if(state->data_type == SCAMPER_HOST_RR_DATA_TYPE_STR)
    {
      len += warts_str_size(rr->un.str);
      return len;
    }
  else if(state->data_type == SCAMPER_HOST_RR_DATA_TYPE_SOA)
    {
      if((state->data_un.soa=malloc_zero(sizeof(warts_host_rr_soa_t))) == NULL)
	return -1;
      warts_host_rr_soa_params(rr->un.soa, state->data_un.soa);
      len += state->data_un.soa->len;
    }
  else if(state->data_type == SCAMPER_HOST_RR_DATA_TYPE_MX)
    {
      if((state->data_un.mx=malloc_zero(sizeof(warts_host_rr_mx_t))) == NULL)
	return -1;
      warts_host_rr_mx_params(rr->un.mx, state->data_un.mx);
      len += state->data_un.mx->len;
    }
  else return -1;
  return len;
}

static void warts_host_rr_params(const scamper_host_rr_t *rr,
				 warts_host_rr_t *state,
				 warts_addrtable_t *table)
{
  const warts_var_t *var;
  int i, max_id = 0;

  memset(state->flags, 0, host_rr_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(host_rr_vars)/sizeof(warts_var_t); i++)
    {
      var = &host_rr_vars[i];
      if((var->id == WARTS_HOST_RR_CLASS && rr->class == 0) ||
	 (var->id == WARTS_HOST_RR_TYPE  && rr->type == 0) ||
	 (var->id == WARTS_HOST_RR_NAME  && rr->name == NULL) ||
	 (var->id == WARTS_HOST_RR_TTL   && rr->ttl == 0) ||
	 (var->id == WARTS_HOST_RR_DATA  && rr->un.v == NULL))
	continue;

      flag_set(state->flags, var->id, &max_id);
      if(var->id == WARTS_HOST_RR_NAME)
	state->params_len += warts_str_size(rr->name);
      else if(var->id == WARTS_HOST_RR_DATA)
	state->params_len += warts_host_rr_data_len(rr, state, table);
      else
	state->params_len += var->size;
    }

  state->flags_len += fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;
  return;
}

static int warts_host_rr_read(scamper_host_rr_t **rr, int i,
			      const uint8_t *buf, uint32_t *off,
			      uint32_t len, warts_addrtable_t *table)
{
  uint16_t class, type;
  uint32_t ttl;
  char *name = NULL;
  void *data = NULL;
  warts_param_reader_t handlers[] = {
    {&class, (wpr_t)extract_uint16, NULL},
    {&type,  (wpr_t)extract_uint16, NULL},
    {&name,  (wpr_t)extract_string, NULL},
    {&ttl,   (wpr_t)extract_uint32, NULL},
    {&data,  (wpr_t)extract_rrdata, table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto err;
  if((rr[i] = scamper_host_rr_alloc(name, class, type, ttl)) == NULL)
    goto err;
  rr[i]->un.v = data;
  if(name != NULL) free(name);
  return 0;

 err:
  if(name != NULL) free(name);
  return -1;
}

static void warts_host_rr_write(scamper_host_rr_t *rr, uint8_t *buf,
				uint32_t *off, uint32_t len,
				warts_host_rr_t *state,
				warts_addrtable_t *table)
{
   warts_param_writer_t handlers[] = {
     {&rr->class, (wpw_t)insert_uint16, NULL},
     {&rr->type,  (wpw_t)insert_uint16, NULL},
     {rr->name,   (wpw_t)insert_string, NULL},
     {&rr->ttl,   (wpw_t)insert_uint32, NULL},
     {state,      (wpw_t)insert_rrdata, table},
   };
   const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
   warts_params_write(buf, off, len, state->flags, state->flags_len,
		      state->params_len, handlers, handler_cnt);
   return;
}

static void warts_host_params(const scamper_host_t *host,
			      warts_addrtable_t *table, uint8_t *flags,
			      uint16_t *flags_len, uint16_t *params_len)
{
  const warts_var_t *var;
  int i, max_id = 0;

  /* Unset all flags */
  memset(flags, 0, host_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(host_vars)/sizeof(warts_var_t); i++)
    {
      var = &host_vars[i];

      if((var->id == WARTS_HOST_LIST    && host->list == NULL) ||
	 (var->id == WARTS_HOST_CYCLE   && host->cycle == NULL) ||
	 (var->id == WARTS_HOST_USERID  && host->userid == 0) ||
	 (var->id == WARTS_HOST_SRC     && host->src == NULL) ||
	 (var->id == WARTS_HOST_DST     && host->dst == NULL) ||
	 (var->id == WARTS_HOST_FLAGS   && host->flags == 0) ||
	 (var->id == WARTS_HOST_WAIT    && host->wait == 0) ||
	 (var->id == WARTS_HOST_STOP    && host->stop == 0) ||
	 (var->id == WARTS_HOST_RETRIES && host->retries == 0) ||
	 (var->id == WARTS_HOST_QTYPE   && host->qtype == 0) ||
	 (var->id == WARTS_HOST_QCLASS  && host->qclass == 0) ||
	 (var->id == WARTS_HOST_QNAME   && host->qname == NULL) ||
	 (var->id == WARTS_HOST_QCOUNT  && host->qcount == 0))
	continue;

      /* Set the flag for the rest of the variables */
      flag_set(flags, var->id, &max_id);

      /* Variables that don't have a fixed size */
      if(var->id == WARTS_HOST_SRC)
	{
	  *params_len += warts_addr_size(table, host->src);
	  continue;
	}
      else if(var->id == WARTS_HOST_DST)
	{
	  *params_len += warts_addr_size(table, host->dst);
	  continue;
	}
      else if(var->id == WARTS_HOST_QNAME)
	{
	  *params_len += warts_str_size(host->qname);
	  continue;
	}

      assert(var->size >= 0);
      *params_len += var->size;
    }

  *flags_len = fold_flags(flags, max_id);
  return;
}

static int warts_host_params_read(scamper_host_t *host,
				  warts_addrtable_t *table,
				  warts_state_t *state,
				  uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&host->list,         (wpr_t)extract_list,    state},
    {&host->cycle,        (wpr_t)extract_cycle,   state},
    {&host->userid,       (wpr_t)extract_uint32,  NULL},
    {&host->src,          (wpr_t)extract_addr,    table},
    {&host->dst,          (wpr_t)extract_addr,    table},
    {&host->start,        (wpr_t)extract_timeval, NULL},
    {&host->flags,        (wpr_t)extract_uint16,  NULL},
    {&host->wait,         (wpr_t)extract_uint16,  NULL},
    {&host->stop,         (wpr_t)extract_byte,    NULL},
    {&host->retries,      (wpr_t)extract_byte,    NULL},
    {&host->qtype,        (wpr_t)extract_uint16,  NULL},
    {&host->qclass,       (wpr_t)extract_uint16,  NULL},
    {&host->qname,        (wpr_t)extract_string,  NULL},
    {&host->qcount,       (wpr_t)extract_byte,    NULL},
  };
  const int handler_cnt = sizeof(handlers) / sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  return 0;
}

static int warts_host_params_write(const scamper_host_t *host,
				   const scamper_file_t *sf,
				   warts_addrtable_t *table,
				   uint8_t *buf, uint32_t *off,
				   const uint32_t len, const uint8_t *flags,
				   const uint16_t flags_len,
				   const uint16_t params_len)
{
  uint32_t list_id, cycle_id;
  warts_param_writer_t handlers[] = {
    {&list_id,            (wpw_t)insert_uint32,   NULL},
    {&cycle_id,           (wpw_t)insert_uint32,   NULL},
    {&host->userid,       (wpw_t)insert_uint32,   NULL},
    {host->src,           (wpw_t)insert_addr,     table},
    {host->dst,           (wpw_t)insert_addr,     table},
    {&host->start,        (wpw_t)insert_timeval,  NULL},
    {&host->flags,        (wpw_t)insert_uint16,   NULL},
    {&host->wait,         (wpw_t)insert_uint16,   NULL},
    {&host->stop,         (wpw_t)insert_byte,     NULL},
    {&host->retries,      (wpw_t)insert_byte,     NULL},
    {&host->qtype,        (wpw_t)insert_uint16,   NULL},
    {&host->qclass,       (wpw_t)insert_uint16,   NULL},
    {host->qname,         (wpw_t)insert_string,   NULL},
    {&host->qcount,       (wpw_t)insert_byte,     NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  host->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, host->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len,
		     handlers, handler_cnt);

  return 0;
}

int scamper_file_warts_host_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_host_t **host_out)
{
  scamper_host_t *host = NULL;
  scamper_host_query_t *query;
  warts_addrtable_t *table = NULL;
  warts_state_t *state = scamper_file_getstate(sf);
  uint8_t *buf = NULL;
  uint32_t off = 0, i, j;

  if(warts_read(sf, &buf, hdr->len) != 0)
    goto err;

  if(buf == NULL)
    {
      *host_out = NULL;
      return 0;
    }

  if((host = scamper_host_alloc()) == NULL)
    goto err;

  if((table = warts_addrtable_alloc_byid()) == NULL)
    goto err;

  if(warts_host_params_read(host, table, state, buf, &off, hdr->len) != 0)
    goto err;

  if(host->qcount > 0)
    {
      if(scamper_host_queries_alloc(host, host->qcount) != 0)
	goto err;
      for(i=0; i<host->qcount; i++)
	{
	  if((host->queries[i] = query = scamper_host_query_alloc()) == NULL)
	    goto err;
	  if(warts_host_query_read(query, buf, &off, hdr->len) != 0)
	    goto err;
	  if(scamper_host_query_rr_alloc(query) != 0)
	    goto err;
	  for(j=0; j<query->ancount; j++)
	    if(warts_host_rr_read(query->an, j, buf,&off,hdr->len, table) != 0)
	      goto err;
	  for(j=0; j<query->nscount; j++)
	    if(warts_host_rr_read(query->ns, j, buf,&off,hdr->len, table) != 0)
	      goto err;
	  for(j=0; j<query->arcount; j++)
	    if(warts_host_rr_read(query->ar, j, buf,&off,hdr->len, table) != 0)
	      goto err;
	}
    }

  warts_addrtable_free(table);
  *host_out = host;
  free(buf);
  return 0;

 err:
  if(table != NULL) warts_addrtable_free(table);
  if(buf != NULL) free(buf);
  if(host != NULL) scamper_host_free(host);
  return -1;
}

int scamper_file_warts_host_write(const scamper_file_t *sf,
				  const scamper_host_t *host)
{
  scamper_host_query_t *query;
  warts_addrtable_t *table = NULL;
  warts_host_query_t *query_state = NULL;
  warts_host_rr_t *rr_state = NULL;
  uint8_t *buf = NULL;
  uint8_t  flags[host_vars_mfb];
  uint16_t flags_len, params_len;
  uint32_t len, i, j, r = 0, rrc = 0, off = 0;
  size_t size;

  if((table = warts_addrtable_alloc_byaddr()) == NULL)
    goto err;

  warts_host_params(host, table, flags, &flags_len, &params_len);
  len = 8 + flags_len + params_len + 2;

  if(host->qcount > 0)
    {
      /* figure out how many resource records there are */
      for(i=0; i<host->qcount; i++)
	{
	  query = host->queries[i];
	  rrc += (query->ancount + query->nscount + query->arcount);
	}

      size = host->qcount * sizeof(warts_host_query_t);
      if((query_state = (warts_host_query_t *)malloc_zero(size)) == NULL)
	goto err;

      if(rrc > 0)
	{
	  size = rrc * sizeof(warts_host_rr_t);
	  if((rr_state = (warts_host_rr_t *)malloc_zero(size)) == NULL)
	    goto err;
	}

      for(i=0; i<host->qcount; i++)
	{
	  query = host->queries[i];
	  warts_host_query_params(query, &query_state[i]);
	  len += query_state[i].len;
	  for(j=0; j<query->ancount; j++)
	    {
	      warts_host_rr_params(query->an[j], &rr_state[r], table);
	      len += rr_state[r].len;
	      r++;
	    }
	  for(j=0; j<query->nscount; j++)
	    {
	      warts_host_rr_params(query->ns[j], &rr_state[r], table);
	      len += rr_state[r].len;
	      r++;
	    }
	  for(j=0; j<query->arcount; j++)
	    {
	      warts_host_rr_params(query->ar[j], &rr_state[r], table);
	      len += rr_state[r].len;
	      r++;
	    }
	}
      assert(r == rrc);
    }

  /* Allocate memory to store all of the data (including packets) */
  if((buf = malloc_zero(len)) == NULL)
    goto err;
  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_HOST);

  if(warts_host_params_write(host, sf, table, buf, &off, len,
			     flags, flags_len, params_len) != 0)
    {
      goto err;
    }

  if(host->qcount > 0)
    {
      r = 0;
      for(i=0; i<host->qcount; i++)
	{
	  query = host->queries[i];
	  warts_host_query_write(query, buf, &off, len, &query_state[i]);
	  for(j=0; j<query->ancount; j++)
	    warts_host_rr_write(query->an[j], buf, &off, len,
				&rr_state[r++], table);
	  for(j=0; j<query->nscount; j++)
	    warts_host_rr_write(query->ns[j], buf, &off, len,
				&rr_state[r++], table);
	  for(j=0; j<query->arcount; j++)
	    warts_host_rr_write(query->ar[j], buf, &off, len,
				&rr_state[r++], table);
	}
      free(query_state); query_state = NULL;
      free(rr_state); rr_state = NULL;
    }

  assert(off == len);

  /* Write the whole buffer to a warts file */
  if(warts_write(sf, buf, len) == -1)
    goto err;

  warts_addrtable_free(table);
  free(buf);
  return 0;

err:
  if(query_state != NULL) free(query_state);
  if(rr_state != NULL) free(rr_state);
  if(table != NULL) warts_addrtable_free(table);
  if(buf != NULL) free(buf);
  return -1;
}
