/*
 * scamper_file_warts.c
 *
 * the warts file format
 *
 * $Id: scamper_file_warts.c,v 1.254 2019/07/28 09:24:53 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2015-2016 Matthew Luckie
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
  "$Id: scamper_file_warts.c,v 1.254 2019/07/28 09:24:53 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "trace/scamper_trace.h"
#include "trace/scamper_trace_warts.h"
#include "ping/scamper_ping.h"
#include "ping/scamper_ping_warts.h"
#include "tracelb/scamper_tracelb.h"
#include "tracelb/scamper_tracelb_warts.h"
#include "dealias/scamper_dealias.h"
#include "dealias/scamper_dealias_warts.h"
#include "neighbourdisc/scamper_neighbourdisc.h"
#include "neighbourdisc/scamper_neighbourdisc_warts.h"
#include "tbit/scamper_tbit.h"
#include "tbit/scamper_tbit_warts.h"
#include "sting/scamper_sting.h"
#include "sting/scamper_sting_warts.h"
#include "sniff/scamper_sniff.h"
#include "sniff/scamper_sniff_warts.h"
#include "host/scamper_host.h"
#include "host/scamper_host_warts.h"

#include "mjl_splaytree.h"
#include "utils.h"

#define WARTS_MAGIC 0x1205
#define WARTS_HDRLEN 8

/* how many entries to grow the table by each time */
#define WARTS_ADDR_TABLEGROW  1000
#define WARTS_LIST_TABLEGROW  1
#define WARTS_CYCLE_TABLEGROW 1

/*
 * the optional bits of a list structure
 */
#define WARTS_LIST_DESCR      1              /* description of list */
#define WARTS_LIST_MONITOR    2              /* canonical name of monitor */
static const warts_var_t list_vars[] =
{
  {WARTS_LIST_DESCR,   -1, -1},
  {WARTS_LIST_MONITOR, -1, -1},
};
#define list_vars_mfb WARTS_VAR_MFB(list_vars)

/*
 * the optional bits of a cycle start structure
 */
#define WARTS_CYCLE_STOP_TIME 1              /* time at which cycle ended */
#define WARTS_CYCLE_HOSTNAME  2              /* hostname at cycle point */
static const warts_var_t cycle_vars[] =
{
  {WARTS_CYCLE_STOP_TIME,  4, -1},
  {WARTS_CYCLE_HOSTNAME,  -1, -1},
};
#define cycle_vars_mfb WARTS_VAR_MFB(cycle_vars)

typedef int (*warts_obj_read_t)(scamper_file_t *,const warts_hdr_t *,void **);

struct warts_addrtable
{
  splaytree_t   *tree;
  warts_addr_t **addrs;
  int            addrc;
};

void flag_ij(const int id, int *i, int *j)
{
  int x = id - 1;
  *i = (x / 7);
  *j = id - (*i * 7);
  return;
}

/*
 * flag_set
 *
 * small routine to set a flag bit.  this exists because the 8th bit of
 * each byte used for flags is used to indicate when another set of flags
 * follows the byte.
 */
void flag_set(uint8_t *flags, const int id, int *max_id)
{
  int i, j;

  assert(id > 0);
  flag_ij(id, &i, &j);
  flags[i] |= (0x1 << (j-1));

  if(max_id != NULL && *max_id < id)
    *max_id = id;

  return;
}

int flag_isset(const uint8_t *flags, const int id)
{
  int i, j;

  assert(id > 0);
  flag_ij(id, &i, &j);

  if((flags[i] & (0x1 << (j-1))) == 0)
    return 0;

  return 1;
}

/*
 * fold_flags
 *
 * go through and set each link bit in the flag set, as appropriate.
 * conveniently return the count of the number of bytes required to store
 * the flags.
 */
uint16_t fold_flags(uint8_t *flags, const int max_id)
{
  uint16_t i, j, k;

  /* if no flags are set, it is still a requirement to include a zero byte */
  if(max_id == 0)
    {
      return 1;
    }

  /* figure out how many bytes have been used */
  j = max_id / 7;
  if((max_id % 7) != 0) j++;

  /*
   * j has to be greater than zero by the above logic.  however, the for
   * loop below will go bananas if it is not
   */
  assert(j > 0);

  /* skip through and set the 'more flags' bit for all flag bytes necessary */
  k = j-1;
  for(i=0; i<k; i++)
    {
      flags[i] |= 0x80;
    }

  return j;
}

int warts_str_size(const char *str)
{
  return strlen(str) + 1;
}

static int warts_addr_cmp(const warts_addr_t *a, const warts_addr_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static warts_addr_t *warts_addr_alloc(scamper_addr_t *addr, uint32_t id)
{
  warts_addr_t *wa;
  if((wa = malloc(sizeof(warts_addr_t))) == NULL)
    return NULL;
  wa->addr = scamper_addr_use(addr);
  wa->id = id;
  wa->ondisk = 0;
  return wa;
}

static void warts_addr_free(warts_addr_t *wa)
{
  if(wa == NULL)
    return;
  if(wa->addr != NULL) scamper_addr_free(wa->addr);
  free(wa);
  return;
}

uint32_t warts_addr_size(warts_addrtable_t *t, scamper_addr_t *addr)
{
  warts_addr_t fm, *wa;

  fm.addr = addr;
  if(splaytree_find(t->tree, &fm) != NULL)
    return 1 + 4;

  if((wa = warts_addr_alloc(addr, splaytree_count(t->tree))) != NULL &&
     splaytree_insert(t->tree, wa) == NULL)
    warts_addr_free(wa);

  return 1 + 1 + scamper_addr_size(addr);
}

warts_addrtable_t *warts_addrtable_alloc_byaddr(void)
{
  warts_addrtable_t *table;
  if((table = malloc(sizeof(warts_addrtable_t))) == NULL)
    return NULL;
  table->addrs = NULL;
  table->addrc = 0;
  if((table->tree = splaytree_alloc((splaytree_cmp_t)warts_addr_cmp))==NULL)
    {
      free(table);
      return NULL;
    }
  return table;
}

warts_addrtable_t *warts_addrtable_alloc_byid(void)
{
  warts_addrtable_t *table;
  if((table = malloc(sizeof(warts_addrtable_t))) == NULL)
    return NULL;
  table->addrs = NULL;
  table->addrc = 0;
  table->tree = NULL;
  return table;
}

void warts_addrtable_free(warts_addrtable_t *table)
{
  int i;
  if(table == NULL)
    return;
  if(table->tree != NULL)
    {
      splaytree_free(table->tree, (splaytree_free_t)warts_addr_free);
    }
  if(table->addrs != NULL)
    {
      for(i=0; i<table->addrc; i++)
	warts_addr_free(table->addrs[i]);
      free(table->addrs);
    }
  free(table);
  return;
}

void insert_addr(uint8_t *buf, uint32_t *off, const uint32_t len,
		 const scamper_addr_t *addr, void *param)
{
  warts_addrtable_t *table = param;
  warts_addr_t *wa, f;
  uint32_t id;
  size_t size;

  assert(table != NULL);
  assert(len - *off >= 1 + 1);

  f.addr = (scamper_addr_t *)addr;
  wa = splaytree_find(table->tree, &f);
  assert(wa != NULL);

  if(wa->ondisk == 0)
    {
      size = scamper_addr_size(addr);
      buf[(*off)++] = (uint8_t)size;
      buf[(*off)++] = addr->type;
      memcpy(&buf[*off], addr->addr, size);

      /* make a record to say this address is now recorded */
      if(wa != NULL)
	wa->ondisk = 1;
    }
  else
    {
      size = 4;
      id = htonl(wa->id);
      buf[(*off)++] = 0;
      memcpy(&buf[*off], &id, size);
    }

  *off += size;
  return;
}

void insert_uint16(uint8_t *buf, uint32_t *off, const uint32_t len,
		   const uint16_t *in, void *param)
{
  uint16_t tmp = htons(*in);
  assert(len - *off >= 2);
  memcpy(&buf[*off], &tmp, 2);
  *off += 2;
  return;
}

void insert_uint32(uint8_t *buf, uint32_t *off, const uint32_t len,
		   const uint32_t *in, void *param)
{
  uint32_t tmp = htonl(*in);
  assert(len - *off >= 4);
  memcpy(&buf[*off], &tmp, 4);
  *off += 4;
  return;
}

void insert_int32(uint8_t *buf, uint32_t *off, const uint32_t len,
		  const int32_t *in, void *param)
{
  uint32_t tmp = htonl((uint32_t)*in);
  assert(len - *off >= 4);
  memcpy(&buf[*off], &tmp, 4);
  *off += 4;
  return;
}

void insert_wartshdr(uint8_t *buf, uint32_t *off, uint32_t len,
		     uint16_t hdr_type)
{
  const uint16_t hdr_magic = WARTS_MAGIC;
  uint32_t hdr_len = len - 8;
  assert(len - *off >= 8);
  insert_uint16(buf, off, len, &hdr_magic, NULL);
  insert_uint16(buf, off, len, &hdr_type, NULL);
  insert_uint32(buf, off, len, &hdr_len, NULL);
  return;
}

void insert_byte(uint8_t *buf, uint32_t *off, const uint32_t len,
		 const uint8_t *in, void *param)
{
  assert(len - *off >= 1);
  buf[(*off)++] = *in;
  return;
}

void insert_bytes_uint16(uint8_t *buf,uint32_t *off,const uint32_t len,
			 const void *vin, uint16_t *count)
{
  assert(len - *off >= *count);
  memcpy(buf + *off, vin, *count);
  *off += *count;
  return;
}

void insert_string(uint8_t *buf, uint32_t *off, const uint32_t len,
		   const char *in, void *param)
{
  uint8_t c;
  int i = 0;

  do
    {
      assert(len - *off > 0);
      assert(in != NULL);
      buf[(*off)++] = c = in[i++];
    }
  while(c != '\0');

  return;
}

/*
 * insert_timeval
 *
 * this function may cause trouble in the future with timeval struct members
 * changing types and so on.
 */
void insert_timeval(uint8_t *buf, uint32_t *off, const uint32_t len,
			   const struct timeval *in, void *param)
{
  uint32_t t32;

  assert(len - *off >= 8);

  t32 = htonl(in->tv_sec);
  memcpy(buf + *off, &t32, 4); *off += 4;

  t32 = htonl(in->tv_usec);
  memcpy(buf + *off, &t32, 4); *off += 4;

  return;
}

void insert_rtt(uint8_t *buf, uint32_t *off, const uint32_t len,
		       const struct timeval *tv, void *param)
{
  uint32_t t32 = (tv->tv_sec * 1000000) + tv->tv_usec;
  insert_uint32(buf, off, len, &t32, NULL);
  return;
}

int extract_addr(const uint8_t *buf, uint32_t *off,
		 const uint32_t len, scamper_addr_t **out, void *param)
{
  warts_addrtable_t *table = param;
  warts_addr_t *wa;
  uint32_t u32;
  uint8_t size;
  uint8_t type;

  assert(table != NULL);

  /* make sure the offset is sane */
  if(*off >= len)
    return -1;

  /* make sure there is enough data left for the address header */
  if(len - *off < 1)
    return -1;

  /* get the byte saying how large the record is */
  size = buf[(*off)++];

  /*
   * if the address length field is zero, then we have a 4 byte index value
   * following.
   */
  if(size == 0)
    {
      if(len - *off < 4)
	return -1;

      /* load the index value out, and sanity check it */
      memcpy(&u32, &buf[*off], 4); u32 = ntohl(u32);
      if(u32 >= table->addrc)
	return -1;

      *out = scamper_addr_use(table->addrs[u32]->addr);
      *off += 4;
      return 0;
    }

  /*
   * we have an address defined inline.  extract the address out and store
   * it in a table, incase it is referenced shortly.  sanity check the type
   * of address
   */
  type = buf[(*off)++];
  if(type == 0 || type > SCAMPER_ADDR_TYPE_MAX)
    return -1;
  if((wa = malloc_zero(sizeof(warts_addr_t))) == NULL ||
     (wa->addr = scamper_addr_alloc(type, &buf[*off])) == NULL ||
     array_insert((void ***)&table->addrs, &table->addrc, wa, NULL) != 0)
    {
      goto err;
    }

  *out = scamper_addr_use(wa->addr);
  *off += size;
  return 0;

 err:
  if(wa != NULL)
    {
      if(wa->addr != NULL) scamper_addr_free(wa->addr);
      free(wa);
    }
  return -1;
}

int extract_string(const uint8_t *buf, uint32_t *off,
			  const uint32_t len, char **out, void *param)
{
  uint32_t i;

  for(i=*off; i<len; i++)
    {
      /* scan for the null terminator */
      if(buf[i] == '\0')
	{
	  if((*out = memdup(buf+*off, (size_t)(i-*off+1))) == NULL)
	    {
	      return -1;
	    }

	  *off = i+1;
	  return 0;
	}
    }

  return -1;
}

int extract_uint16(const uint8_t *buf, uint32_t *off,
		   const uint32_t len, uint16_t *out, void *param)
{
  if(*off >= len || len - *off < 2)
    return -1;
  memcpy(out, buf + *off, 2); *off += 2;
  *out = ntohs(*out);
  return 0;
}

int extract_uint32(const uint8_t *buf, uint32_t *off,
		   const uint32_t len, uint32_t *out, void *param)
{
  if(*off >= len || len - *off < 4)
    return -1;
  memcpy(out, buf + *off, 4); *off += 4;
  *out = ntohl(*out);
  return 0;
}

int extract_int32(const uint8_t *buf, uint32_t *off,
		  const uint32_t len, int32_t *out, void *param)
{
  uint32_t u32;
  if(*off >= len || len - *off < 4)
    return -1;
  memcpy(&u32, buf + *off, 4); *off += 4;
  *out = (int32_t)ntohl(u32);
  return 0;
}

int extract_byte(const uint8_t *buf, uint32_t *off,
			const uint32_t len, uint8_t *out, void *param)
{
  if(*off >= len || len - *off < 1)
    return -1;
  *out = buf[(*off)++];
  return 0;
}

int extract_bytes_ptr(const uint8_t *buf, uint32_t *off,
			     const uint32_t len, const uint8_t **out,
			     uint16_t *req)
{
  if(*off >= len || len - *off < *req)
    return -1;

  if(*req > 0)
    *out = buf + *off;
  else
    *out = NULL;
  *off += *req;

  return 0;
}

int extract_bytes_alloc(const uint8_t *buf, uint32_t *off,
			       const uint32_t len, uint8_t **out,
			       uint16_t *req)
{
  if(*off >= len || len - *off < *req)
    return -1;

  if(*req == 0)
    {
      *out = NULL;
    }
  else
    {
      if((*out = malloc_zero(*req)) == NULL)
	return -1;
      memcpy(*out, buf + *off, *req);
      *off += *req;
    }

  return 0;
}

/*
 * extract_bytes
 *
 * copy the number of requested bytes into the specified array
 */
int extract_bytes(const uint8_t *buf, uint32_t *off, const uint32_t len,
			 uint8_t *out, uint16_t *req)
{
  if(*off >= len || len - *off < *req)
    return -1;

  if(req == 0)
    return 0;

  memcpy(out, buf + *off, *req);
  *off += *req;

  return 0;
}

int extract_addr_gid(const uint8_t *buf, uint32_t *off,
			    const uint32_t len,
			    scamper_addr_t **addr, warts_state_t *state)
{
  uint32_t id;

  if(extract_uint32(buf, off, len, &id, NULL) != 0)
    {
      return -1;
    }

  if(id >= state->addr_count)
    {
      return -1;
    }

  *addr = scamper_addr_use(state->addr_table[id]);
  return 0;
}

int extract_list(const uint8_t *buf, uint32_t *off,
			const uint32_t len,
			scamper_list_t **list, warts_state_t *state)
{
  uint32_t id;

  if(extract_uint32(buf, off, len, &id, NULL) != 0)
    {
      return -1;
    }

  if(id >= state->list_count)
    {
      return -1;
    }

  *list = scamper_list_use(state->list_table[id]->list);
  return 0;
}

int extract_cycle(const uint8_t *buf, uint32_t *off,
			 const uint32_t len,
			 scamper_cycle_t **cycle, warts_state_t *state)
{
  uint32_t id;

  if(extract_uint32(buf, off, len, &id, NULL) != 0)
    return -1;

  if(id >= state->cycle_count || state->cycle_table[id] == NULL)
    return -1;
  *cycle = scamper_cycle_use(state->cycle_table[id]->cycle);

  return 0;
}

int extract_timeval(const uint8_t *buf, uint32_t *off,
			   const uint32_t len, struct timeval *tv, void *param)
{
  uint32_t t32;

  if(extract_uint32(buf, off, len, &t32, NULL) != 0)
    {
      return -1;
    }
  tv->tv_sec = t32;

  if(extract_uint32(buf, off, len, &t32, NULL) != 0)
    {
      return -1;
    }
  tv->tv_usec = t32;

  return 0;
}

int extract_rtt(const uint8_t *buf, uint32_t *off, const uint32_t len,
		       struct timeval *tv, void *param)
{
  uint32_t t32;

  if(extract_uint32(buf, off, len, &t32, NULL) != 0)
    {
      return -1;
    }

  tv->tv_sec  = t32 / 1000000;
  tv->tv_usec = t32 % 1000000;
  return 0;
}

int warts_params_read(const uint8_t *buf, uint32_t *off, uint32_t len,
			     warts_param_reader_t *handlers, int handler_cnt)
{
  warts_param_reader_t *handler;
  const uint8_t *flags = &buf[*off];
  uint16_t flags_len, params_len;
  uint32_t final_off;
  uint16_t i, j;
  int      id;

  /* if there are no flags set at all, then there's nothing left to do */
  if(flags[0] == 0)
    {
      (*off)++;
      return 0;
    }

  /* figure out how long the flags block is */
  flags_len = 0;
  while((buf[*off] & 0x80) != 0 && *off < len)
    {
      (*off)++; flags_len++;
    }
  flags_len++; (*off)++;
  if(*off > len)
    {
      goto err;
    }

  /* the length field */
  if(extract_uint16(buf, off, len, &params_len, NULL) != 0)
    {
      goto err;
    }

  /*
   * this calculation is required so we handle the case where we have
   * new parameters that we don't know how to handle (i.e. so we can skip
   * over them)
   */
  final_off = *off + params_len;

  /* read all flag bytes */
  for(i=0; i<flags_len; i++)
    {
      /* if no flags are set in this byte, then skip over it */
      if((flags[i] & 0x7f) == 0)
	{
	  continue;
	}

      /* try each bit in this byte */
      for(j=0; j<7; j++)
	{
	  /* if this flag is unset, then skip the rest of the loop */
	  if((flags[i] & (0x1 << j)) == 0)
	    {
	      continue;
	    }

	  /*
	   * if the id is greater than we have handlers for, then we've
	   * got to the end of what we can parse.
	   */
	  if((id = (i*7)+j) >= handler_cnt)
	    {
	      goto done;
	    }

	  handler = &handlers[id]; assert(handler->read != NULL);
	  if(handler->read(buf, off, len, handler->data, handler->param) == -1)
	    {
	      goto err;
	    }
	}
    }

 done:
  *off = final_off;
  return 0;

 err:
  return -1;
}

void warts_params_write(uint8_t *buf, uint32_t *off,
			       const uint32_t len,
			       const uint8_t *flags,
			       const uint16_t flags_len,
			       const uint16_t params_len,
			       const warts_param_writer_t *handlers,
			       const int handler_cnt)
{
  uint16_t i, j, tmp;
  int id;

  /* write the flag bytes out */
  tmp = flags_len;
  insert_bytes_uint16(buf, off, len, flags, &tmp);

  /*
   * if there are flags specified, then write the parameter length out.
   * otherwise, there are no parameters to write, so we are done.
   */
  if(flags[0] != 0)
    {
      insert_uint16(buf, off, len, &params_len, NULL);
    }
  else
    {
      assert(params_len == 0);
      return;
    }

  /* handle writing the parameter for each flight out */
  for(i=0; i<flags_len; i++)
    {
      /* skip flag bytes where no flags are set */
      if((flags[i] & 0x7f) == 0)
	{
	  continue;
	}

      /* try each flag bit in the byte */
      for(j=0; j<7; j++)
	{
	  /* skip over unset flags */
	  if((flags[i] & (0x1 << j)) == 0)
	    {
	      continue;
	    }

	  /* this is the parameter id for the flag */
	  id = (i*7)+j;

	  /*
	   * if the id is greater than we have handlers for, then either there
	   * is some code missing, or there is a bug.
	   */
	  assert(id < handler_cnt);
	  assert(handlers[id].write != NULL);

	  /* actually write the data out */
	  handlers[id].write(buf,off,len,handlers[id].data,handlers[id].param);
	}
    }

  return;
}

/*
 * warts_read
 *
 * this function reads the requested number of bytes into a new piece of
 * memory returned in *buf.  as the underlying file descriptor may be
 * set O_NONBLOCK, most of this code is spent dealing with partial reads.
 */
int warts_read(scamper_file_t *sf, uint8_t **buf, size_t len)
{
  scamper_file_readfunc_t rf = scamper_file_getreadfunc(sf);
  warts_state_t *state = scamper_file_getstate(sf);
  int            fd    = scamper_file_getfd(sf);
  uint8_t       *tmp   = NULL;
  int            ret;
  size_t         rc;

  *buf = NULL;
  if(len == 0)
    return -1;

  if(rf != NULL)
    {
      if((ret = rf(scamper_file_getreadparam(sf), buf, len)) == 0 || ret == -2)
	{
	  if(ret == -2)
	    scamper_file_seteof(sf);
	  return 0;
	}
      return -1;
    }

  /* if there is data left over from a prior read, then append to it. */
  if(state->readbuf != NULL)
    {
      assert(state->readbuf_len == len);

      /* read */
      if((ret = read_wrap(fd, state->readbuf + state->readlen, &rc,
			  len - state->readlen)) != 0)
	{
	  /* rc will be zero if nothing was read, so safe to use */
	  state->readlen += rc;

	  /*
	   * we got an error (or EOF) without successfully reading whatever
	   * was left over.
	   */
	  if((ret == -1 && errno != EAGAIN) || ret == -2)
	    {
	      if(ret == -2)
		scamper_file_seteof(sf);
	      return -1;
	    }

	  /*
	   * read has not completed yet, but we haven't got a failure
	   * condition either.
	   */
	  return 0;
	}

      *buf = state->readbuf;
      state->readlen = 0;
      state->readbuf = NULL;
      state->readbuf_len = 0;
      state->off += len;
      return 0;
    }

  /* no data left over, reading from scratch */
  if((tmp = malloc_zero(len)) == NULL)
    return -1;

  /* try and read.  if we read the whole amount, everything is good */
  if((ret = read_wrap(fd, tmp, &rc, len)) == 0)
    {
      *buf = tmp;
      state->off += len;
      return 0;
    }

  /* if a partial read occured, then record the partial read in state */
  if(rc != 0)
    {
      state->readlen = rc;
      state->readbuf = tmp;
      state->readbuf_len = len;
    }
  else
    {
      free(tmp);
    }

  /* if we got eof and we had a partial read, then we've got a problem */
  if(ret == -2)
    {
      /* got eof */
      scamper_file_seteof(sf);

      /* partial read, so error condition */
      if(rc != 0)
	return -1;

      return 0;
    }

  /* if the read would block, then there's no problem */
  if(ret == -1 && errno == EAGAIN)
    return 0;

  return -1;
}

/*
 * warts_write
 *
 * this function will write a record to disk, appending a warts_header
 * on the way out to the disk.  if the write fails for whatever reason
 * (as in the disk is full and only a partial recrd can be written), then
 * the write will be retracted in its entirety.
 */
int warts_write(const scamper_file_t *sf, const void *buf, size_t len)
{
  scamper_file_writefunc_t wf = scamper_file_getwritefunc(sf);
  warts_state_t *state = scamper_file_getstate(sf);
  void *param;
  off_t off = 0;
  int fd;

  if(wf == NULL)
    {
      fd = scamper_file_getfd(sf);

      if(state->isreg && (off = lseek(fd, 0, SEEK_CUR)) == (off_t)-1)
	return -1;

      if(write_wrap(fd, buf, NULL, len) != 0)
	{
	  /*
	   * if we could not write the buf out, then truncate the warts file
	   * at the hdr we just wrote out above.
	   */
	  if(state->isreg)
	    {
	      if(ftruncate(fd, off) != 0)
		return -1;
	    }
	  return -1;
	}
    }
  else
    {
      param = scamper_file_getwriteparam(sf);
      return wf(param, buf, len);
    }

  return 0;
}

/*
 * warts_hdr_read
 *
 */
int warts_hdr_read(scamper_file_t *sf, warts_hdr_t *hdr)
{
  const uint32_t len = 8;
  uint8_t  *buf = NULL;
  uint32_t  off = 0;

  if(warts_read(sf, &buf, len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      return 0;
    }

  /* these three statements are guaranteed not to fail... */
  extract_uint16(buf, &off, len, &hdr->magic, NULL);
  extract_uint16(buf, &off, len, &hdr->type, NULL);
  extract_uint32(buf, &off, len, &hdr->len, NULL);
  free(buf);

  assert(off == len);
  return 1;

 err:
  return -1;
}

/*
 * warts_addr_read
 *
 * read an address structure out of the file and record it in the splay
 * tree of addresses.
 *
 * each address record consists of
 *   - an id assigned to the address, modulo 255
 *   - the address family the address belongs to
 *   - the address [length determined by record length]
 */
int warts_addr_read(scamper_file_t *sf, const warts_hdr_t *hdr,
			   scamper_addr_t **addr_out)
{
  warts_state_t  *state = scamper_file_getstate(sf);
  scamper_addr_t *addr = NULL, **table;
  uint8_t        *buf = NULL;
  size_t          size;

  /* the data has to be at least 3 bytes long to be valid */
  assert(hdr->len > 2);

  if((state->addr_count % WARTS_ADDR_TABLEGROW) == 0)
    {
      size = sizeof(scamper_addr_t *)*(state->addr_count+WARTS_ADDR_TABLEGROW);
      if((table = realloc(state->addr_table, size)) == NULL)
	{
	  goto err;
	}
      state->addr_table = table;
    }

  /* read the address record from the file */
  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      if(addr_out != NULL)
	*addr_out = NULL;
      return 0;
    }

  /*
   * sanity check that the warts id recorded in the file matches what we
   * think it should be.
   */
  if(state->addr_count % 255 != buf[0])
    goto err;

  /* sanity check the type of address */
  if(buf[1] == 0 || buf[1] > SCAMPER_ADDR_TYPE_MAX)
    goto err;
  
  /* allocate a scamper address using the record read from disk */
  if((addr = scamper_addr_alloc(buf[1], buf+2)) == NULL)
    goto err;

  state->addr_table[state->addr_count++] = addr;
  free(buf);

  if(addr_out != NULL)
    *addr_out = addr;

  return 0;

 err:
  if(addr != NULL) scamper_addr_free(addr);
  if(buf != NULL) free(buf);
  return -1;
}

static int warts_list_cmp(const warts_list_t *wa, const warts_list_t *wb)
{
  return scamper_list_cmp(wa->list, wb->list);
}

warts_list_t *warts_list_alloc(scamper_list_t *list, uint32_t id)
{
  warts_list_t *wl;
  if((wl = malloc_zero(sizeof(warts_list_t))) != NULL)
    {
      wl->list = scamper_list_use(list);
      wl->id = id;
    }
  return wl;
}

void warts_list_free(warts_list_t *wl)
{
  if(wl->list != NULL) scamper_list_free(wl->list);
  free(wl);
  return;
}

/*
 * warts_list_params
 *
 * put together an outline of the optional bits for a list structure,
 * including the flags structure that sits at the front, and the size (in
 * bytes) of the various parameters that will be optionally included in the
 * file.
 */
void warts_list_params(const scamper_list_t *list, uint8_t *flags,
		       uint16_t *flags_len, uint16_t *params_len)
{
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags */
  memset(flags, 0, list_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(list_vars)/sizeof(warts_var_t); i++)
    {
      var = &list_vars[i];
      if(var->id == WARTS_LIST_DESCR && list->descr != NULL)
	{
	  flag_set(flags, WARTS_LIST_DESCR, &max_id);
	  *params_len += warts_str_size(list->descr);
	}
      else if(var->id == WARTS_LIST_MONITOR && list->monitor != NULL)
	{
	  flag_set(flags, WARTS_LIST_MONITOR, &max_id);
	  *params_len += warts_str_size(list->monitor);
	}
    }

  *flags_len = fold_flags(flags, max_id);
  return;
}

/*
 * warts_list_params_read
 *
 */
int warts_list_params_read(scamper_list_t *list,
				  uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&list->descr,   (wpr_t)extract_string, NULL}, /* WARTS_LIST_DESCR   */
    {&list->monitor, (wpr_t)extract_string, NULL}, /* WARTS_LIST_MONITOR */
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

void warts_list_params_write(const scamper_list_t *list,
				    uint8_t *buf, uint32_t *off,
				    const uint32_t len,
				    const uint8_t *flags,
				    const uint16_t flags_len,
				    const uint16_t params_len)
{
  warts_param_writer_t handlers[] = {
    {list->descr,   (wpw_t)insert_string, NULL}, /* WARTS_LIST_DESCR */
    {list->monitor, (wpw_t)insert_string, NULL}, /* WARTS_LIST_MONITOR */
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return;
}

/*
 * warts_list_read
 *
 * each list record consists of
 *   - a 4 byte id assigned to the list by warts
 *   - a 4 byte list id assigned by a human
 *   - the name of the list
 *   - optional parameters (e.g. list description, monitor)
 */
int warts_list_read(scamper_file_t *sf, const warts_hdr_t *hdr,
			   scamper_list_t **list_out)
{
  warts_state_t *state = scamper_file_getstate(sf);
  scamper_list_t *list = NULL;
  warts_list_t *wl = NULL, **table;
  uint8_t  *buf = NULL;
  size_t    size;
  uint32_t  i = 0;
  uint32_t  id;

  /*
   * must at least include the warts list id, the human-assigned list-id,
   * a name, and some amount of flags + parameters
   */
  if(hdr->len < 4 + 4 + 2 + 1)
    {
      goto err;
    }

  if((state->list_count % WARTS_LIST_TABLEGROW) == 0)
    {
      size = sizeof(warts_list_t *)*(state->list_count + WARTS_LIST_TABLEGROW);
      if((table = realloc(state->list_table, size)) == NULL)
	{
	  goto err;
	}
      state->list_table = table;
    }

  /* read the list record from the file */
  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      if(list_out != NULL)
	{
	  *list_out = NULL;
	}
      return 0;
    }

  /* preallocate an empty list structure */
  if((list = malloc_zero(sizeof(scamper_list_t))) == NULL)
    {
      goto err;
    }
  list->refcnt = 1;

  /*
   * sanity check that the warts id recorded in the file matches what we
   * think it should be.
   */
  if(extract_uint32(buf, &i, hdr->len, &id, NULL) != 0 ||
     id != state->list_count)
    {
      goto err;
    }

  /* get the list id (assigned by a human) and name */
  if(extract_uint32(buf, &i, hdr->len, &list->id, NULL) != 0 ||
     extract_string(buf, &i, hdr->len, &list->name, NULL) != 0)
    {
      goto err;
    }

  if(warts_list_params_read(list, buf, &i, hdr->len) != 0)
    {
      goto err;
    }

  if((wl = warts_list_alloc(list, state->list_count)) == NULL)
    {
      goto err;
    }

  state->list_table[state->list_count++] = wl;
  scamper_list_free(list);
  free(buf);

  if(list_out != NULL)
    {
      *list_out = list;
    }
  return 0;

 err:
  if(list != NULL) scamper_list_free(list);
  if(wl != NULL)   warts_list_free(wl);
  if(buf != NULL)  free(buf);
  return -1;
}

/*
 * warts_list_write
 *
 * take a list structure and write it to disk.  update the state held, too
 */
int warts_list_write(const scamper_file_t *sf, scamper_list_t *list,
			    uint32_t *id)
{
  warts_state_t *state = scamper_file_getstate(sf);
  warts_list_t *wl = NULL;
  uint8_t  *buf = NULL;
  uint8_t   flags[list_vars_mfb];
  uint32_t  off = 0, len;
  uint16_t  name_len, flags_len, params_len;

  /* we require a list name */
  if(list->name == NULL)
    {
      goto err;
    }

  /* allocate a warts wrapping structure for the list */
  if((wl = warts_list_alloc(list, state->list_count)) == NULL)
    {
      goto err;
    }

  /* figure out how large the record will be */
  name_len = strlen(list->name) + 1;
  warts_list_params(list, flags, &flags_len, &params_len);
  len = 8 + 4 + 4 + name_len + flags_len + params_len;
  if(params_len != 0) len += 2;

  /* allocate the record */
  if((buf = malloc_zero(len)) == NULL)
    {
      goto err;
    }

  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_LIST);

  /* list id assigned by warts */
  insert_uint32(buf, &off, len, &wl->id, NULL);

  /* list id assigned by a person */
  insert_uint32(buf, &off, len, &list->id, NULL);

  /* list name */
  insert_bytes_uint16(buf, &off, len, list->name, &name_len);

  /* copy in the flags for any parameters */
  warts_list_params_write(list, buf, &off, len, flags, flags_len, params_len);

  assert(off == len);

  if(splaytree_insert(state->list_tree, wl) == NULL)
    {
      goto err;
    }

  /* write the list record to disk */
  if(warts_write(sf, buf, len) == -1)
    {
      goto err;
    }

  state->list_count++;
  *id = wl->id;
  free(buf);
  return 0;

 err:
  if(wl != NULL)
    {
      splaytree_remove_item(state->list_tree, wl);
      warts_list_free(wl);
    }
  if(buf != NULL) free(buf);
  return -1;
}

/*
 * warts_list_getid
 *
 * given a scamper_list structure, return the id to use internally to
 * uniquely identify it.  allocate the id if necessary.
 */
int warts_list_getid(const scamper_file_t *sf, scamper_list_t *list,
			    uint32_t *id)
{
  warts_state_t *state = scamper_file_getstate(sf);
  warts_list_t findme, *wl;

  if(list == NULL)
    {
      *id = 0;
      return 0;
    }

  /* see if there is a tree entry for this list */
  findme.list = list;
  if((wl = splaytree_find(state->list_tree, &findme)) != NULL)
    {
      *id = wl->id;
      return 0;
    }

  /* no tree entry, so write it to a file and return the assigned id */
  if(warts_list_write(sf, list, id) == 0)
    {
      return 0;
    }

  return -1;
}

static int warts_cycle_cmp(const warts_cycle_t *a, const warts_cycle_t *b)
{
  return scamper_cycle_cmp(a->cycle, b->cycle);
}

warts_cycle_t *warts_cycle_alloc(scamper_cycle_t *cycle, uint32_t id)
{
  warts_cycle_t *wc;
  if((wc = malloc_zero(sizeof(warts_cycle_t))) != NULL)
    {
      wc->cycle = scamper_cycle_use(cycle);
      wc->id = id;
    }
  return wc;
}

void warts_cycle_free(warts_cycle_t *cycle)
{
  if(cycle->cycle != NULL) scamper_cycle_free(cycle->cycle);
  free(cycle);
  return;
}

void warts_cycle_params(const scamper_cycle_t *cycle, uint8_t *flags,
			       uint16_t *flags_len, uint16_t *params_len)
{
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags, reset max_id */
  memset(flags, 0, cycle_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(cycle_vars)/sizeof(warts_var_t); i++)
    {
      var = &cycle_vars[i];
      if(var->id == WARTS_CYCLE_HOSTNAME && cycle->hostname != NULL)
	{
	  flag_set(flags, WARTS_CYCLE_HOSTNAME, &max_id);
	  *params_len += warts_str_size(cycle->hostname);
	}
      else if(var->id == WARTS_CYCLE_STOP_TIME && cycle->stop_time != 0)
	{
	  flag_set(flags, WARTS_CYCLE_STOP_TIME, &max_id);
	  *params_len += 4;
	}
    }

  *flags_len = fold_flags(flags, max_id);
  return;
}

void warts_cycle_params_write(const scamper_cycle_t *cycle,
				     uint8_t *buf, uint32_t *off,
				     const uint32_t len,
				     const uint8_t *flags,
				     const uint16_t flags_len,
				     const uint16_t params_len)
{
  warts_param_writer_t handlers[] = {
    {&cycle->stop_time, (wpw_t)insert_uint32, NULL},
    {cycle->hostname,   (wpw_t)insert_string, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return;
}

int warts_cycle_params_read(scamper_cycle_t *cycle,
				   uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&cycle->stop_time, (wpr_t)extract_uint32, NULL},
    {&cycle->hostname,  (wpr_t)extract_string, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

/*
 * warts_cycle_read
 *
 * 4 byte cycle id (assigned by warts from counter)
 * 4 byte list id (assigned by warts)
 * 4 byte cycle id (assigned by human)
 * 4 byte time since the epoch, representing start time of the cycle
 * 1 byte flags (followed by optional data items)
 */
int warts_cycle_read(scamper_file_t *sf, const warts_hdr_t *hdr,
			    scamper_cycle_t **cycle_out)
{
  warts_state_t *state = scamper_file_getstate(sf);
  scamper_cycle_t *cycle = NULL;
  warts_cycle_t *wc = NULL, **table;
  size_t   size;
  uint8_t *buf = NULL;
  uint32_t id;
  uint32_t off = 0;

  /* ensure the cycle_start object is large enough to be valid */
  if(hdr->len < 4 + 4 + 4 + 4 + 1)
    {
      goto err;
    }

  if((state->cycle_count % WARTS_CYCLE_TABLEGROW) == 0)
    {
      size = sizeof(warts_list_t *)*(state->cycle_count+WARTS_CYCLE_TABLEGROW);
      if((table = realloc(state->cycle_table, size)) == NULL)
	{
	  goto err;
	}
      state->cycle_table = table;
    }

  /* read the cycle_start structure out of the file */
  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      if(cycle_out != NULL)
	{
	  *cycle_out = NULL;
	}
      return 0;
    }

  /*
   * sanity check that the warts id recorded in the file matches what we
   * think it should be.
   */
  if(extract_uint32(buf, &off, hdr->len, &id, NULL) != 0 ||
     id != state->cycle_count)
    {
      goto err;
    }

  /* the _warts_ list id for the cycle */
  if(extract_uint32(buf, &off, hdr->len, &id, NULL) != 0 ||
     id >= state->list_count)
    {
      goto err;
    }

  if((cycle = scamper_cycle_alloc(state->list_table[id]->list)) == NULL)
    {
      goto err;
    }

  /*
   * the second 4 bytes is the actual cycle id assigned by a human.
   * the third 4 bytes is seconds since the epoch.
   */
  if(extract_uint32(buf, &off, hdr->len, &cycle->id, NULL) != 0 ||
     extract_uint32(buf, &off, hdr->len, &cycle->start_time, NULL) != 0)
    {
      goto err;
    }

  if(warts_cycle_params_read(cycle, buf, &off, hdr->len) != 0)
    {
      goto err;
    }

  if((wc = warts_cycle_alloc(cycle, state->cycle_count)) == NULL)
    {
      goto err;
    }

  state->cycle_table[state->cycle_count++] = wc;
  scamper_cycle_free(cycle);
  free(buf);

  if(cycle_out != NULL)
    {
      *cycle_out = cycle;
    }

  return 0;

 err:
  if(cycle != NULL)
    {
      if(cycle->list != NULL) scamper_list_free(cycle->list);
      free(cycle);
    }
  if(buf != NULL) free(buf);
  return -1;
}

/*
 * warts_cycle_write
 *
 * write out a cycle record.  depending on whether the type is a start point,
 * or a cycle definition, some
 *
 * 4 byte cycle id (assigned by warts from counter)
 * 4 byte list id (assigned by warts)
 * 4 byte cycle id (assigned by human)
 * 4 byte time since the epoch, representing start time of the cycle
 * 1 byte flags (followed by optional data items)
 */
int warts_cycle_write(const scamper_file_t *sf, scamper_cycle_t *cycle,
			     const int type, uint32_t *id)
{
  warts_state_t *state = scamper_file_getstate(sf);
  warts_cycle_t *wc = NULL;
  uint32_t warts_list_id;
  uint8_t *buf = NULL;
  uint8_t  flags[cycle_vars_mfb];
  uint16_t flags_len, params_len;
  uint32_t off = 0, len;

  /* find the list associated w/ the cycle, as we require the warts list id */
  if(warts_list_getid(sf, cycle->list, &warts_list_id) == -1)
    {
      goto err;
    }

  /* allocate warts_cycle wrapping struct to associate a warts-assigned id */
  if((wc = warts_cycle_alloc(cycle, state->cycle_count)) == NULL)
    {
      goto err;
    }

  /* figure out the shape the optional parameters will take */
  warts_cycle_params(cycle, flags, &flags_len, &params_len);

  /* allocate a temporary buf for recording the cycle */
  len = 8 + 4 + 4 + 4 + 4 + flags_len + params_len;
  if(params_len != 0) len += 2;
  if((buf = malloc_zero(len)) == NULL)
    {
      goto err;
    }

  /* insert the warts header */
  insert_wartshdr(buf, &off, len, type);

  /* cycle and list ids, assigned by warts from counters */
  insert_uint32(buf, &off, len, &wc->id, NULL);
  insert_uint32(buf, &off, len, &warts_list_id, NULL);

  /* human cycle id, timestamp */
  insert_uint32(buf, &off, len, &cycle->id, NULL);
  insert_uint32(buf, &off, len, &cycle->start_time, NULL);

  /* copy in the optionally-included parameters */
  warts_cycle_params_write(cycle, buf,&off,len, flags, flags_len, params_len);

  assert(off == len);

  if(splaytree_insert(state->cycle_tree, wc) == NULL)
    {
      goto err;
    }

  if(warts_write(sf, buf, len) == -1)
    {
      goto err;
    }

  if(id != NULL) *id = wc->id;
  state->cycle_count++;
  free(buf);

  return 0;

 err:
  if(wc != NULL)
    {
      splaytree_remove_item(state->cycle_tree, wc);
      warts_cycle_free(wc);
    }
  if(buf != NULL) free(buf);
  return -1;
}

/*
 * warts_cycle_stop_read
 *
 * a cycle_stop record consists of the cycle id (assigned by warts from a
 * counter), a timestamp, and some optional parameters.
 */
int warts_cycle_stop_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_cycle_t **cycle_out)
{
  warts_state_t *state = scamper_file_getstate(sf);
  scamper_cycle_t *cycle;
  uint32_t  off = 0;
  uint32_t  id;
  uint8_t  *buf = NULL;

  if(hdr->len < 4 + 4 + 1)
    {
      goto err;
    }

  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      if(cycle_out != NULL)
	{
	  *cycle_out = NULL;
	}
      return 0;
    }

  /*
   * get an index into the stored cycles.
   *
   * if the id does not make sense (is larger than any cycle currently
   * defined, or is the null cycle entry, or there is no current cycle
   * for this id) then we have a problem...
   */
  if(extract_uint32(buf, &off, hdr->len, &id, NULL) != 0 ||
     id >= state->cycle_count || id == 0 || state->cycle_table[id] == NULL)
    {
      goto err;
    }

  /* embed the stop timestamp with the cycle object */
  cycle = state->cycle_table[id]->cycle;
  if(extract_uint32(buf, &off, hdr->len, &cycle->stop_time, NULL) != 0)
    {
      goto err;
    }

  /*
   * if the caller wants the cycle record, then get a reference to it.
   * don't need the cycle in the array any longer, though.
   */
  if(cycle_out != NULL)
    {
      *cycle_out = scamper_cycle_use(cycle);
    }
  warts_cycle_free(state->cycle_table[id]);
  state->cycle_table[id] = NULL;

  free(buf);

  return 0;

 err:
  if(buf != NULL) free(buf);
  return -1;
}

int warts_cycle_getid(const scamper_file_t *sf, scamper_cycle_t *cycle,
			     uint32_t *id)
{
  warts_state_t *state = scamper_file_getstate(sf);
  warts_cycle_t findme, *wc;

  /* if no cycle is specified, we use the special value zero */
  if(cycle == NULL)
    {
      *id = 0;
      return 0;
    }

  /* see if there is an entry for this cycle */
  findme.cycle = cycle;
  if((wc = splaytree_find(state->cycle_tree, &findme)) != NULL)
    {
      *id = wc->id;
      return 0;
    }

  if(warts_cycle_write(sf, cycle, SCAMPER_FILE_OBJ_CYCLE_DEF, id) == 0)
    {
      return 0;
    }

  return -1;
}

/*
 * warts_cycle_stop_write
 *
 * this function writes a record denoting the end of the cycle pointed to
 * by the cycle parameter.
 * it writes
 *  the 4 byte cycle id assigned by warts
 *  the 4 byte stop time
 *  where applicable, additional parameters
 */
int warts_cycle_stop_write(const scamper_file_t *sf,
				  scamper_cycle_t *cycle)
{
  uint32_t wc_id;
  uint8_t *buf = NULL;
  uint32_t off = 0, len;
  uint8_t  flag = 0;

  assert(cycle != NULL);

  if(warts_cycle_getid(sf, cycle, &wc_id) != 0)
    {
      goto err;
    }

  len = 8 + 4 + 4 + 1;
  if((buf = malloc_zero(len)) == NULL)
    {
      goto err;
    }

  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_CYCLE_STOP);
  insert_uint32(buf, &off, len, &wc_id, NULL);
  insert_uint32(buf, &off, len, &cycle->stop_time, NULL);
  insert_byte(buf, &off, len, &flag, NULL);

  assert(off == len);

  if(warts_write(sf, buf, len) == -1)
    {
      goto err;
    }

  free(buf);
  return 0;

 err:
  if(buf != NULL) free(buf);
  return -1;
}

int warts_icmpext_read(const uint8_t *buf, uint32_t *off, uint32_t len,
			      scamper_icmpext_t **exts)
{
  scamper_icmpext_t *ie, *next = NULL;
  uint16_t tmp;
  uint16_t u16;
  uint8_t cn, ct;

  /* make sure there's enough left for the length field */
  if(len - *off < 2)
    {
      return -1;
    }

  /* extract the length field that says how much data is left past it */
  memcpy(&tmp, &buf[*off], 2);
  tmp = ntohs(tmp);

  *off += 2;

  /* the length value must be greater than zero */
  if(tmp == 0)
    return -1;

  /* make sure there's enough left for the extension data */
  if(len - *off < tmp)
    return -1;

  while(tmp >= 4)
    {
      memcpy(&u16, &buf[*off], 2); u16 = ntohs(u16);
      if(len - *off < (uint32_t)(u16 + 2 + 1 + 1))
	{
	  return -1;
	}
      cn = buf[*off+2];
      ct = buf[*off+3];

      if((ie = scamper_icmpext_alloc(cn, ct, u16, &buf[*off+4])) == NULL)
	{
	  return -1;
	}

      if(next == NULL)
	{
	  *exts = ie;
	}
      else
	{
	  next->ie_next = ie;
	}
      next = ie;

      *off += (2 + 1 + 1 + u16);
      tmp  -= (2 + 1 + 1 + u16);
    }

  if(tmp != 0)
    return -1;

  return 0;
}

void warts_icmpext_write(uint8_t *buf,uint32_t *off,const uint32_t len,
				const scamper_icmpext_t *exts)
{
  const scamper_icmpext_t *ie;
  uint16_t tmp = 0;
  uint16_t u16;

  for(ie=exts; ie != NULL; ie = ie->ie_next)
    {
      assert(*off + tmp + 1 + 1 + 2 + ie->ie_dl <= len);

      /* convert the data length field to network byte order and write */
      u16 = htons(ie->ie_dl);
      memcpy(&buf[*off + 2 + tmp], &u16, 2); tmp += 2;

      /* write the class num/type fields */
      buf[*off + 2 + tmp] = ie->ie_cn; tmp++;
      buf[*off + 2 + tmp] = ie->ie_ct; tmp++;

      /* write any data */
      if(ie->ie_dl != 0)
	{
	  memcpy(&buf[*off + 2 + tmp], ie->ie_data, ie->ie_dl);
	  tmp += ie->ie_dl;
	}
    }

  /* write, at the start of the data, the length of the icmp extension data */
  u16 = htons(tmp);
  memcpy(&buf[*off], &u16, 2);
  *off = *off + 2 + tmp;

  return;
}

/*
 * scamper_file_warts_read
 *
 */
int scamper_file_warts_read(scamper_file_t *sf, scamper_file_filter_t *filter,
			    uint16_t *type, void **data)
{
  static const warts_obj_read_t objread[] =
  {
    NULL,
    (warts_obj_read_t)warts_list_read,
    (warts_obj_read_t)warts_cycle_read,
    (warts_obj_read_t)warts_cycle_read,
    (warts_obj_read_t)warts_cycle_stop_read,
    (warts_obj_read_t)warts_addr_read,
    (warts_obj_read_t)scamper_file_warts_trace_read,
    (warts_obj_read_t)scamper_file_warts_ping_read,
    (warts_obj_read_t)scamper_file_warts_tracelb_read,
    (warts_obj_read_t)scamper_file_warts_dealias_read,
    (warts_obj_read_t)scamper_file_warts_neighbourdisc_read,
    (warts_obj_read_t)scamper_file_warts_tbit_read,
    (warts_obj_read_t)scamper_file_warts_sting_read,
    (warts_obj_read_t)scamper_file_warts_sniff_read,
    (warts_obj_read_t)scamper_file_warts_host_read,
  };
  warts_state_t   *state = scamper_file_getstate(sf);
  warts_hdr_t      hdr;
  int              isfilter;
  int              tmp;
  uint8_t         *buf;
  void            *ptr;
  char             offs[16];

  for(;;)
    {
      /*
       * check to see if the previous read got a warts header but not
       * the payload
       */
      if(state->hdr.type == 0)
	{
	  /* read the header for the next record from the file */
	  if((tmp = warts_hdr_read(sf, &hdr)) == 0)
	    {
	      *data = NULL;
	      return 0;
	    }

	  /* if the header does not pass a basic sanity check, then give up */
	  if(tmp == -1 || hdr.magic != WARTS_MAGIC || hdr.type == 0)
	    goto err;
	}
      else
	{
	  hdr = state->hdr;
	}

      /*
       * does the caller want to know about this type?
       * if they do, tell them what type of object (might be) returned.
       */
      if((isfilter = scamper_file_filter_isset(filter, hdr.type)) == 1)
	*type = hdr.type;
      *data = NULL;

      if(hdr.type == SCAMPER_FILE_OBJ_ADDR        ||
	 hdr.type == SCAMPER_FILE_OBJ_LIST        ||
	 hdr.type == SCAMPER_FILE_OBJ_CYCLE_DEF   ||
	 hdr.type == SCAMPER_FILE_OBJ_CYCLE_START ||
	 hdr.type == SCAMPER_FILE_OBJ_CYCLE_STOP)
	{
	  if(objread[hdr.type](sf, &hdr, &ptr) != 0)
	    goto err;

	  if(ptr == NULL)
	    {
	      /* partial read.  return for now */
	      state->hdr = hdr;
	      return 0;
	    }

	  memset(&state->hdr, 0, sizeof(state->hdr));

	  if(isfilter != 0)
	    {
	      switch(hdr.type)
		{
		case SCAMPER_FILE_OBJ_ADDR:
		  *data = scamper_addr_use((scamper_addr_t *)ptr);
		  break;
		case SCAMPER_FILE_OBJ_LIST:
		  *data = scamper_list_use((scamper_list_t *)ptr);
		  break;
		case SCAMPER_FILE_OBJ_CYCLE_DEF:
		case SCAMPER_FILE_OBJ_CYCLE_START:
		  *data = scamper_cycle_use((scamper_cycle_t *)ptr);
		  break;
		case SCAMPER_FILE_OBJ_CYCLE_STOP:
		  *data = ptr;
		  break;
		}
	      return 0;
	    }

	  if(hdr.type == SCAMPER_FILE_OBJ_CYCLE_STOP)
	    scamper_cycle_free((scamper_cycle_t *)ptr);
	}
      else if(isfilter == 0)
	{
	  /* reader doesn't care what the data is, and neither do we */
	  buf = NULL;
	  if(warts_read(sf, &buf, hdr.len) != 0)
	    goto err;
	  if(buf == NULL)
	    {
	      /* partial read.  return for now */
	      state->hdr = hdr;
	      return 0;
	    }
	  free(buf);
	  memset(&state->hdr, 0, sizeof(state->hdr));
	}
      else
	{
	  if(hdr.type >= sizeof(objread)/sizeof(warts_obj_read_t) ||
	     objread[hdr.type] == NULL ||
	     objread[hdr.type](sf, &hdr, data) != 0)
	    goto err;

	  if(*data != NULL)
	    memset(&state->hdr, 0, sizeof(state->hdr));
	  else
	    state->hdr = hdr;
	  break;
	}
    }

  return 0;

 err:
  fprintf(stderr,
	  "off 0x%s magic 0x%04x type 0x%04x len 0x%08x\n",
	  offt_tostr(offs, sizeof(offs), state->off - hdr.len, 8, 'x'),
	  hdr.magic, hdr.type, hdr.len);
  return -1;
}

int scamper_file_warts_cyclestart_write(const scamper_file_t *sf,
					scamper_cycle_t *c)
{
  return warts_cycle_write(sf, c, SCAMPER_FILE_OBJ_CYCLE_START, NULL);
}

int scamper_file_warts_cyclestop_write(const scamper_file_t *sf,
				       scamper_cycle_t *c)
{
  return warts_cycle_stop_write(sf, c);
}

/*
 * scamper_file_warts_init_read
 *
 * initialise the scamper_file_t's state structure so that it is all set
 * for reading.  the first entry of the list and cycle tables is pre-set
 * to be null for data objects that don't have associated list/cycle
 * objects.
 */
int scamper_file_warts_init_read(scamper_file_t *sf)
{
  warts_state_t *state;
  size_t size;

  if((state = (warts_state_t *)malloc_zero(sizeof(warts_state_t))) == NULL)
    {
      goto err;
    }

  size = sizeof(scamper_addr_t *) * WARTS_ADDR_TABLEGROW;
  if((state->addr_table = malloc_zero(size)) == NULL)
    {
      goto err;
    }
  state->addr_table[0] = NULL;
  state->addr_count = 1;

  size = sizeof(warts_list_t *) * WARTS_LIST_TABLEGROW;
  if((state->list_table = malloc_zero(size)) == NULL)
    {
      goto err;
    }
  state->list_table[0] = &state->list_null;
  state->list_count = 1;

  size = sizeof(warts_cycle_t *) * WARTS_CYCLE_TABLEGROW;
  if((state->cycle_table = malloc_zero(size)) == NULL)
    {
      goto err;
    }
  state->cycle_table[0] = &state->cycle_null;
  state->cycle_count = 1;

  scamper_file_setstate(sf, state);
  return 0;

 err:
  if(state != NULL)
    {
      if(state->addr_table != NULL) free(state->addr_table);
      if(state->list_table != NULL) free(state->list_table);
      if(state->cycle_table != NULL) free(state->cycle_table);
      free(state);
    }
  return -1;
}

/*
 * scamper_file_warts_init_write
 *
 * get the scamper_file_t object ready to write warts objects and keep state
 */
int scamper_file_warts_init_write(scamper_file_t *sf)
{
  warts_state_t *s = NULL;
  int fd = scamper_file_getfd(sf);
  struct stat sb;

  if((s = (warts_state_t *)malloc_zero(sizeof(warts_state_t))) == NULL)
    goto err;

  if(fd != -1)
    {
      if(fstat(fd, &sb) != 0)
	goto err;
      if(S_ISREG(sb.st_mode))
	s->isreg = 1;
    }

  if((s->list_tree=splaytree_alloc((splaytree_cmp_t)warts_list_cmp)) == NULL)
    goto err;
  s->list_count = 1;

  if((s->cycle_tree=splaytree_alloc((splaytree_cmp_t)warts_cycle_cmp)) == NULL)
    goto err;
  s->cycle_count = 1;

  scamper_file_setstate(sf, s);

  return 0;

 err:
  if(s != NULL)
    {
      if(s->list_tree != NULL)  splaytree_free(s->list_tree, NULL);
      if(s->cycle_tree != NULL) splaytree_free(s->cycle_tree, NULL);
      free(s);
    }
  return -1;
}

/*
 * scamper_file_warts_init_append
 *
 * go through the file and form the address, list, and cycle dictionaries
 */
int scamper_file_warts_init_append(scamper_file_t *sf)
{
  warts_state_t   *s;
  warts_hdr_t      hdr;
  int              i, fd;
  uint32_t         j;
  scamper_addr_t  *addr;
  scamper_list_t  *list;
  scamper_cycle_t *cycle;

  /* init the warts structures as if we were reading the file */
  if(scamper_file_warts_init_read(sf) == -1)
    {
      return -1;
    }

  fd = scamper_file_getfd(sf);

  for(;;)
    {
      /* read the header for the next record from the file */
      if((i = warts_hdr_read(sf, &hdr)) == 0)
	{
	  /* EOF */
	  break;
	}
      else if(i == -1)
	{
	  /* partial record */
	  return -1;
	}

      if(hdr.magic != WARTS_MAGIC || hdr.type == 0)
	{
	  return -1;
	}

      switch(hdr.type)
	{
	case SCAMPER_FILE_OBJ_ADDR:
	  if(warts_addr_read(sf, &hdr, &addr) != 0 || addr == NULL)
	    return -1;
	  break;

	case SCAMPER_FILE_OBJ_LIST:
	  if(warts_list_read(sf, &hdr, &list) != 0 || list == NULL)
	    return -1;
	  break;

	case SCAMPER_FILE_OBJ_CYCLE_START:
	case SCAMPER_FILE_OBJ_CYCLE_DEF:
	  if(warts_cycle_read(sf, &hdr, &cycle) != 0 || cycle == NULL)
	    return -1;
	  break;

	case SCAMPER_FILE_OBJ_CYCLE_STOP:
	  if(warts_cycle_stop_read(sf, &hdr, &cycle) != 0 || cycle == NULL)
	    return -1;
	  scamper_cycle_free(cycle);
	  break;

	default:
	  if(lseek(fd, hdr.len, SEEK_CUR) == -1)
	    {
	      return -1;
	    }
	  break;
	}
    }

  /* get the state structure created in init_read */
  s = scamper_file_getstate(sf);

  /*
   * all the lists are in a table.  put them into a splay tree so we can
   * find them quickly, and then trash the list table
   */
  if((s->list_tree = splaytree_alloc((splaytree_cmp_t)warts_list_cmp)) == NULL)
    return -1;
  for(j=1; j<s->list_count; j++)
    if(splaytree_insert(s->list_tree, s->list_table[j]) == NULL)
      return -1;
  free(s->list_table); s->list_table = NULL;

  if((s->cycle_tree=splaytree_alloc((splaytree_cmp_t)warts_cycle_cmp)) == NULL)
    return -1;
  for(j=1; j<s->cycle_count; j++)
    {
      /* don't install finished cycles into the splaytree */
      if(s->cycle_table[j] == NULL)
	continue;
      if(splaytree_insert(s->cycle_tree, s->cycle_table[j]) == NULL)
	return -1;
    }
  free(s->cycle_table); s->cycle_table = NULL;

  return 0;
}

int scamper_file_warts_is(const scamper_file_t *sf)
{
  uint16_t magic16;
  int fd = scamper_file_getfd(sf);

  if(lseek(fd, 0, SEEK_SET) == -1)
    {
      return 0;
    }

  if(read_wrap(fd, &magic16, NULL, sizeof(magic16)) != 0)
    {
      return 0;
    }

  if(ntohs(magic16) == WARTS_MAGIC)
    {
      if(lseek(fd, 0, SEEK_SET) == -1)
	{
	  return 0;
	}
      return 1;
    }

  return 0;
}

static void warts_free_state(splaytree_t *tree, void **table,
			     unsigned int count, splaytree_free_t free_cb)
{
  unsigned int i;

  if(table != NULL)
    {
      for(i=1; i<count; i++)
	{
	  if(table[i] != NULL)
	    {
	      free_cb(table[i]);
	    }
	}
      free(table);
    }
  if(tree != NULL)
    {
      splaytree_free(tree, free_cb);
    }

  return;
}

void scamper_file_warts_free_state(scamper_file_t *sf)
{
  warts_state_t *state;
  uint32_t i;

  /* there may not actually be state allocated with the file ... */
  if((state = scamper_file_getstate(sf)) == NULL)
    {
      return;
    }

  if(state->readbuf != NULL)
    {
      free(state->readbuf);
    }

  warts_free_state(state->list_tree,
		   (void **)state->list_table, state->list_count,
		   (splaytree_free_t)warts_list_free);

  warts_free_state(state->cycle_tree,
		   (void **)state->cycle_table, state->cycle_count,
		   (splaytree_free_t)warts_cycle_free);

  if(state->addr_table != NULL)
    {
      for(i=1; i<state->addr_count; i++)
	if(state->addr_table[i] != NULL)
	  scamper_addr_free(state->addr_table[i]);
      free(state->addr_table);
    }

  free(state);

  return;
}
