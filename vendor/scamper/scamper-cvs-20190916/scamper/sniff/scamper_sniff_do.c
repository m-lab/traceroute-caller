/*
 * scamper_sniff_do.c
 *
 * $Id: scamper_sniff_do.c,v 1.15 2019/07/12 23:37:57 mjl Exp $
 *
 * Copyright (C) 2011 The University of Waikato
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
  "$Id: scamper_sniff_do.c,v 1.15 2019/07/12 23:37:57 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_sniff.h"
#include "scamper_fds.h"
#include "scamper_dl.h"
#include "scamper_task.h"
#include "scamper_options.h"
#include "scamper_if.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_debug.h"
#include "scamper_sniff_do.h"
#include "mjl_list.h"
#include "utils.h"

typedef struct sniff_state
{
  scamper_fd_t *fd;
  slist_t      *list;
} sniff_state_t;

/* the callback functions registered with the sniff task */
static scamper_task_funcs_t sniff_funcs;

/* Address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

#define SNIFF_OPT_LIMIT_PKTC   1
#define SNIFF_OPT_LIMIT_TIME   2
#define SNIFF_OPT_SRCADDR      3
#define SNIFF_OPT_USERID       4

static const scamper_option_in_t opts[] = {
  {'c', NULL, SNIFF_OPT_LIMIT_PKTC, SCAMPER_OPTION_TYPE_NUM},
  {'G', NULL, SNIFF_OPT_LIMIT_TIME, SCAMPER_OPTION_TYPE_NUM},
  {'S', NULL, SNIFF_OPT_SRCADDR,    SCAMPER_OPTION_TYPE_STR},
  {'U', NULL, SNIFF_OPT_USERID,     SCAMPER_OPTION_TYPE_NUM},
};

static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_sniff_usage(void)
{
  return "sniff [-c limit-pktc] [-G limit-time] [-S ipaddr] [-U userid] <expression>\n";
}

static scamper_sniff_t *sniff_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static sniff_state_t *sniff_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static void sniff_finish(scamper_task_t *task, int reason)
{
  scamper_sniff_t *sniff = sniff_getdata(task);
  sniff_state_t *state = sniff_getstate(task);
  scamper_sniff_pkt_t *pkt;
  int i, rc;

  gettimeofday_wrap(&sniff->finish);

  if(state != NULL && state->list != NULL && (rc=slist_count(state->list)) > 0)
    {
      if(scamper_sniff_pkts_alloc(sniff, rc) != 0)
	{
	  sniff->stop_reason = SCAMPER_SNIFF_STOP_ERROR;
	  scamper_task_queue_done(task, 0);
	  return;
	}

      i = 0;
      while((pkt = slist_head_pop(state->list)) != NULL)
	sniff->pkts[i++] = pkt;
      assert(i == rc);
    }

  sniff->stop_reason = reason;
  scamper_task_queue_done(task, 0);
  return;
}

static void do_sniff_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_sniff_t *sniff = sniff_getdata(task);
  sniff_state_t *state = sniff_getstate(task);
  scamper_sniff_pkt_t *pkt;
  int cap = 0;

  if(SCAMPER_DL_IS_ICMP(dl))
    {
      if((SCAMPER_DL_IS_ICMP_ECHO(dl) &&
	  dl->dl_icmp_id == sniff->icmpid &&
	  scamper_addr_raw_cmp(sniff->src, dl->dl_ip_dst) == 0) ||
	 (SCAMPER_DL_IS_ICMP_Q_ICMP_ECHO(dl) &&
	  dl->dl_icmp_icmp_id == sniff->icmpid &&
	  scamper_addr_raw_cmp(sniff->src, dl->dl_icmp_ip_src) == 0))
	cap = 1;
    }

  if(cap == 0)
    return;

  pkt = scamper_sniff_pkt_alloc(dl->dl_net_raw, dl->dl_ip_size, &dl->dl_tv);
  if(pkt == NULL)
    {
      printerror(__func__, "could not alloc pkt");
      goto err;
    }

  if(slist_tail_push(state->list, pkt) == NULL)
    {
      printerror(__func__, "could not push pkt");
      goto err;
    }

  if(slist_count(state->list) >= sniff->limit_pktc)
    sniff_finish(task, SCAMPER_SNIFF_STOP_LIMIT_PKTC);

  return;

 err:
  sniff_finish(task, SCAMPER_SNIFF_STOP_ERROR);
  return;
}

static void do_sniff_handle_timeout(scamper_task_t *task)
{
  sniff_finish(task, SCAMPER_SNIFF_STOP_LIMIT_TIME);
  return;
}

static void sniff_state_free(sniff_state_t *state)
{
  if(state == NULL)
    return;

  if(state->fd != NULL)
    scamper_fd_free(state->fd);
  if(state->list != NULL)
    slist_free(state->list);

  free(state);
  return;
}

static int sniff_state_alloc(scamper_task_t *task)
{
  scamper_sniff_t *sniff = sniff_getdata(task);
  sniff_state_t *state = NULL;
  struct sockaddr_storage sas;
  int ifindex;

  assert(sniff->src != NULL);

  if(sniff->src->type == SCAMPER_ADDR_TYPE_IPV4)
    sockaddr_compose((struct sockaddr *)&sas, AF_INET, sniff->src->addr, 0);
  else if(sniff->src->type == SCAMPER_ADDR_TYPE_IPV6)
    sockaddr_compose((struct sockaddr *)&sas, AF_INET6, sniff->src->addr, 0);
  else
    goto err;

  if(scamper_if_getifindex_byaddr((struct sockaddr *)&sas, &ifindex) != 0)
    goto err;

  if((state = malloc_zero(sizeof(sniff_state_t))) == NULL)
    goto err;

  if((state->list = slist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc list");
      goto err;
    }

  if((state->fd = scamper_fd_dl(ifindex)) == NULL)
    {
      printerror(__func__, "could not get dl");
      goto err;
    }

  scamper_task_setstate(task, state);
  return 0;

 err:
  if(state != NULL) sniff_state_free(state);
  return -1;
}

static void do_sniff_probe(scamper_task_t *task)
{
  scamper_sniff_t *sniff = sniff_getdata(task);
  struct timeval tv;

  assert(sniff_getstate(task) == NULL);

  gettimeofday_wrap(&sniff->start);
  if(sniff_state_alloc(task) != 0)
    {
      sniff_finish(task, SCAMPER_SNIFF_STOP_ERROR);
      return;
    }

  timeval_add_s(&tv, &sniff->start, sniff->limit_time);
  scamper_task_queue_wait_tv(task, &tv);
  return;
}

static void do_sniff_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_file_write_sniff(sf, sniff_getdata(task));
  return;
}

static int sniff_arg_param_validate(int optid, char *param, long long *out)
{
  long tmp = 0;

  switch(optid)
    {
    case SNIFF_OPT_SRCADDR:
      break;

    case SNIFF_OPT_LIMIT_PKTC:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 5000)
	goto err;
      break;

    case SNIFF_OPT_LIMIT_TIME:
      if(string_tolong(param, &tmp) != 0 || tmp < 0 || tmp > 1200)
	goto err;
      break;

    case SNIFF_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	goto err;
      break;

    default:
      return -1;
    }

  if(out != NULL)
    *out = (long long)tmp;
  return 0;

 err:
  return -1;
}

int scamper_do_sniff_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  sniff_arg_param_validate);
}

void *scamper_do_sniff_alloc(char *str)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_sniff_t *sniff = NULL;
  uint32_t userid = 0;
  uint32_t limit_pktc = 100;
  uint16_t limit_time = 60;
  long icmpid = -1;
  char *expr = NULL;
  char *src = NULL;
  long long tmp = 0;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &expr) != 0)
    goto err;

  if(expr == NULL)
    goto err;

  if(strncasecmp(expr, "icmp[icmpid] == ", 16) != 0 ||
     string_isnumber(expr+16) == 0 ||
     string_tolong(expr+16, &icmpid) != 0 ||
     icmpid < 0 || icmpid > 65535)
    {
      scamper_debug(__func__, "icmp[icmpid] not supplied");
      goto err;
    }

  /* parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 sniff_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	case SNIFF_OPT_SRCADDR:
	  src = opt->str;
	  break;

	case SNIFF_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case SNIFF_OPT_LIMIT_TIME:
	  limit_time = (uint16_t)tmp;
	  break;

	case SNIFF_OPT_LIMIT_PKTC:
	  limit_pktc = (uint32_t)tmp;
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if(src == NULL)
    {
      printerror(__func__, "missing -S parameter");
      goto err;
    }

  if((sniff = scamper_sniff_alloc()) == NULL)
    goto err;

  if((sniff->src = scamper_addrcache_resolve(addrcache,AF_UNSPEC,src)) == NULL)
    {
      printerror(__func__, "could not resolve %s", src);
      goto err;
    }

  sniff->limit_pktc = limit_pktc;
  sniff->limit_time = limit_time;
  sniff->userid     = userid;
  sniff->icmpid     = (uint16_t)icmpid;

  return sniff;

 err:
  if(sniff != NULL) scamper_sniff_free(sniff);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

static void do_sniff_halt(scamper_task_t *task)
{
  sniff_finish(task, SCAMPER_SNIFF_STOP_HALTED);
  return;
}

static void do_sniff_free(scamper_task_t *task)
{
  scamper_sniff_t *sniff;
  sniff_state_t *state;

  if((sniff = sniff_getdata(task)) != NULL)
    scamper_sniff_free(sniff);

  if((state = sniff_getstate(task)) != NULL)
    sniff_state_free(state);

  return;
}

scamper_task_t *scamper_do_sniff_alloctask(void *data, scamper_list_t *list,
					  scamper_cycle_t *cycle)
{
  scamper_sniff_t *sniff = (scamper_sniff_t *)data;
  scamper_task_t *task = NULL;
  scamper_task_sig_t *sig = NULL;

  /* allocate a task structure and store the sniff with it */
  if((task = scamper_task_alloc(sniff, &sniff_funcs)) == NULL)
    goto err;

  /* task signature */
  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_SNIFF)) == NULL)
    goto err;
  sig->sig_sniff_src = scamper_addr_use(sniff->src);
  sig->sig_sniff_icmp_id = sniff->icmpid;
  if(scamper_task_sig_add(task, sig) != 0)
    goto err;
  sig = NULL;

  /* associate the list and cycle with the sniff */
  sniff->list  = scamper_list_use(list);
  sniff->cycle = scamper_cycle_use(cycle);

  return task;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  if(task != NULL)
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  return NULL;
}

void scamper_do_sniff_free(void *data)
{
  scamper_sniff_free((scamper_sniff_t *)data);
  return;
}

void scamper_do_sniff_cleanup()
{
  return;
}

int scamper_do_sniff_init()
{
  sniff_funcs.probe          = do_sniff_probe;
  sniff_funcs.handle_timeout = do_sniff_handle_timeout;
  sniff_funcs.handle_dl      = do_sniff_handle_dl;
  sniff_funcs.write          = do_sniff_write;
  sniff_funcs.task_free      = do_sniff_free;
  sniff_funcs.halt           = do_sniff_halt;

  return 0;
}
