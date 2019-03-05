/*
 * sc_ipiddump
 *
 * $Id: sc_ipiddump.c,v 1.13 2015/10/21 06:07:56 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2013 The Regents of the University of California
 * Copyright (C) 2015 The University of Waikato
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
  "$Id: sc_ipiddump.c,v 1.13 2015/10/21 06:07:56 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_file.h"
#include "ping/scamper_ping.h"
#include "dealias/scamper_dealias.h"
#include "trace/scamper_trace.h"
#include "mjl_list.h"
#include "utils.h"

typedef struct ipid_sample
{
  scamper_addr_t *probe_src;
  scamper_addr_t *addr;
  struct timeval  tx;
  struct timeval  rx;
  uint32_t        ipid;
} ipid_sample_t;

/* file filter */
static scamper_file_filter_t *filter;

/* the input warts files */
static char **filelist = NULL;
static int    filelist_len = 0;

/* the list of ipid samples to record */
static slist_t *list = NULL;

/* the userids to select on */
static uint32_t *userids = 0;
static int       useridc = 0;

/* the IPs to select on */
static scamper_addr_t **ips = NULL;
static int              ipc = 0;

static uint8_t flags = 0;

#define FLAG_NOTRACE 0x01

#define OPT_USERID  0x0001
#define OPT_IP      0x0002
#define OPT_OPTIONS 0x0004

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
	  "usage: sc_ipiddump [-?] [-i ips] [-O options] [-U userids]\n"
	  "          <file.warts>\n");
  if(opt_mask & OPT_IP)
    fprintf(stderr, "      -i IP address to filter\n");
  if(opt_mask & OPT_OPTIONS)
    fprintf(stderr, "      -O options [notrace]\n");
  if(opt_mask & OPT_USERID)
    fprintf(stderr, "      -U userid to filter\n");
  return;
}

static int uint32_cmp(const void *va, const void *vb)
{
  const uint32_t a = *((uint32_t *)va);
  const uint32_t b = *((uint32_t *)vb);
  if(a < b) return -1;
  if(a > b) return  1;
  return 0;
}

static int uint32_find(uint32_t *a, size_t len, uint32_t u32)
{
  if(bsearch(&u32, a, len, sizeof(uint32_t), uint32_cmp) != NULL)
    return 1;
  return 0;
}

static int ip_cmp(const void *va, const void *vb)
{
  const scamper_addr_t *a = *((const scamper_addr_t **)va);
  const scamper_addr_t *b = *((const scamper_addr_t **)vb);
  return scamper_addr_cmp(a, b);
}

static int ip_find(scamper_addr_t **set, size_t len, scamper_addr_t *a)
{
  if(bsearch(&a, set, len, sizeof(scamper_addr_t *), ip_cmp) != NULL)
    return 1;
  return 0;
}

static int check_options(int argc, char *argv[])
{
  scamper_addr_t *addr_a[256], *addr;
  uint32_t u32_a[256];
  int ch; long lo;
  char *opts = "?i:O:U:";
  char *opt_userid = NULL, *opt_ips = NULL;
  char *str, *next;
  int i, x;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'i':
	  opt_ips = strdup(optarg);
	  break;

	case 'O':
	  if(strcasecmp(optarg, "notrace") == 0)
	    flags |= FLAG_NOTRACE;
	  else
	    {
	      usage(OPT_OPTIONS);
	      goto err;
	    }
	  break;

	case 'U':
	  opt_userid = strdup(optarg);
	  break;

	case '?':
	default:
	  usage(0xffffffff);
	  goto err;
	}
    }

  if((str = opt_userid) != NULL)
    {
      x = 0;
      do
	{
	  if(x >= sizeof(u32_a) / sizeof(uint32_t))
	    {
	      usage(OPT_USERID);
	      goto err;
	    }
	  string_nullterm_char(str, ',', &next);
	  if(string_tolong(str, &lo) != 0 || lo < 0 || lo > 65535)
	    {
	      usage(OPT_USERID);
	      goto err;
	    }
	  u32_a[x++] = lo;
	  str = next;
	}
      while(str != NULL);
      if((userids = malloc(sizeof(uint32_t) * x)) == NULL)
	goto err;
      for(i=0; i<x; i++)
	userids[i] = u32_a[i];
      useridc = x;
      qsort(userids, useridc, sizeof(uint32_t), uint32_cmp);
      free(opt_userid); opt_userid = NULL;
    }

  if((str = opt_ips) != NULL)
    {
      x = 0;
      do
	{
	  if(x >= sizeof(addr_a) / sizeof(scamper_addr_t *))
	    {
	      usage(OPT_IP);
	      goto err;
	    }
	  string_nullterm_char(str, ',', &next);
	  if((addr = scamper_addr_resolve(AF_UNSPEC, str)) == NULL)
	    {
	      usage(OPT_IP);
	      goto err;
	    }
	  addr_a[x++] = addr;
	  str = next;
	}
      while(str != NULL);
      if((ips = malloc(sizeof(scamper_addr_t *) * x)) == NULL)
	goto err;
      for(i=0; i<x; i++)
	ips[i] = addr_a[i];
      ipc = x;
      qsort(ips, ipc, sizeof(scamper_addr_t *), ip_cmp);
      free(opt_ips); opt_ips = NULL;
    }

  filelist     = argv+optind;
  filelist_len = argc-optind;

  if(filelist_len == 0)
    {
      usage(0xffffffff);
      goto err;
    }

  return 0;

 err:
  if(opt_userid != NULL) free(opt_userid);
  if(opt_ips != NULL) free(opt_ips);
  return -1;
}

static int ipid_sample_cmp(const ipid_sample_t *a, const ipid_sample_t *b)
{
  return timeval_cmp(&a->tx, &b->tx);
}

static char *ipid_sample_ipid(const ipid_sample_t *sample,char *buf,size_t len)
{
  if(SCAMPER_ADDR_TYPE_IS_IPV4(sample->addr))
    snprintf(buf, len, "%04x", sample->ipid);
  else
    snprintf(buf, len, "%08x", sample->ipid);
  return buf;
}

static void ipid_sample_free(ipid_sample_t *sample)
{
  if(sample == NULL)
    return;
  if(sample->addr != NULL)
    scamper_addr_free(sample->addr);
  if(sample->probe_src != NULL)
    scamper_addr_free(sample->probe_src);
  free(sample);
  return;
}

static int process_dealias(scamper_dealias_t *dealias)
{
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply;
  ipid_sample_t *sample;
  uint32_t i, u32;
  uint16_t j;

  if(useridc > 0 && uint32_find(userids, useridc, dealias->userid) == 0)
    goto done;

  for(i=0; i<dealias->probec; i++)
    {
      probe = dealias->probes[i];
      for(j=0; j<probe->replyc; j++)
	{
	  reply = probe->replies[j];
	  if(ipc > 0 && ip_find(ips, ipc, reply->src) == 0)
	    continue;

	  if(SCAMPER_ADDR_TYPE_IS_IPV4(reply->src))
	    u32 = reply->ipid;
	  else if(reply->flags & SCAMPER_DEALIAS_REPLY_FLAG_IPID32)
	    u32 = reply->ipid32;
	  else
	    continue;

	  if((sample = malloc_zero(sizeof(ipid_sample_t))) == NULL)
	    goto err;
	  sample->probe_src = scamper_addr_use(probe->def->src);
	  sample->addr = scamper_addr_use(reply->src);
	  sample->ipid = u32;
	  timeval_cpy(&sample->tx, &probe->tx);
	  timeval_cpy(&sample->rx, &reply->rx);

	  if(slist_tail_push(list, sample) == NULL)
	    goto err;
	}
    }

 done:
  scamper_dealias_free(dealias);
  return 0;

 err:
  scamper_dealias_free(dealias);
  return -1;
}

static int process_ping(scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  ipid_sample_t *sample;
  uint16_t i;
  uint32_t u32;

  if(useridc > 0 && uint32_find(userids, useridc, ping->userid) == 0)
    goto done;

  for(i=0; i<ping->ping_sent; i++)
    {
      for(reply = ping->ping_replies[i]; reply != NULL; reply = reply->next)
	{
	  if(reply->tx.tv_sec == 0)
	    continue;
	  if(ipc > 0 && ip_find(ips, ipc, reply->addr) == 0)
	    continue;

	  if(SCAMPER_ADDR_TYPE_IS_IPV4(reply->addr))
	    u32 = reply->reply_ipid;
	  else if(reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID)
	    u32 = reply->reply_ipid32;
	  else
	    continue;

	  if((sample = malloc_zero(sizeof(ipid_sample_t))) == NULL)
	    goto err;
	  sample->probe_src = scamper_addr_use(ping->src);
	  sample->addr = scamper_addr_use(reply->addr);
	  sample->ipid = u32;
	  timeval_cpy(&sample->tx, &reply->tx);
	  timeval_add_tv3(&sample->rx, &reply->tx, &reply->rtt);

	  if(slist_tail_push(list, sample) == NULL)
	    goto err;
	}
    }

 done:
  scamper_ping_free(ping);
  return 0;

 err:
  scamper_ping_free(ping);
  return -1;
}

static int process_trace(scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  ipid_sample_t *sample;
  uint16_t u16;

  /* only grab IPID values from IPv4 traceroutes */
  if(trace->dst->type != SCAMPER_ADDR_TYPE_IPV4)
    goto done;

  /* only include traceroutes for specified userids */
  if(useridc > 0 && uint32_find(userids, useridc, trace->userid) == 0)
    goto done;

  for(u16=trace->firsthop-1; u16<trace->hop_count; u16++)
    {
      for(hop = trace->hops[u16]; hop != NULL; hop = hop->hop_next)
	{      
	  if(hop->hop_tx.tv_sec == 0)
	    continue;
	  if(ipc > 0 && ip_find(ips, ipc, hop->hop_addr) == 0)
	    continue;

	  if((sample = malloc_zero(sizeof(ipid_sample_t))) == NULL)
	    goto err;
	  sample->probe_src = scamper_addr_use(trace->src);
	  sample->addr = scamper_addr_use(hop->hop_addr);
	  sample->ipid = hop->hop_reply_ipid;
	  timeval_cpy(&sample->tx, &hop->hop_tx);
	  timeval_add_tv3(&sample->rx, &hop->hop_tx, &hop->hop_rtt);

	  if(slist_tail_push(list, sample) == NULL)
	    goto err;
	}
    }

 done:
  scamper_trace_free(trace);
  return 0;

 err:
  scamper_trace_free(trace);
  return -1;
}

static void process(scamper_file_t *file)
{
  void *data;
  uint16_t type;

  while(scamper_file_read(file, filter, &type, &data) == 0)
    {
      if(data == NULL) break; /* EOF */
      if(type == SCAMPER_FILE_OBJ_PING)
	process_ping(data);
      else if(type == SCAMPER_FILE_OBJ_DEALIAS)
	process_dealias(data);
      else if(type == SCAMPER_FILE_OBJ_TRACE)
	process_trace(data);
    }
  scamper_file_close(file);
  return;
}

static void cleanup(void)
{
  int i;

  if(list != NULL)
    {
      slist_free_cb(list, (slist_free_t)ipid_sample_free);
      list = NULL;
    }

  if(userids != NULL)
    {
      free(userids);
      userids = NULL;
    }

  if(ips != NULL)
    {
      for(i=0; i<ipc; i++)
	if(ips[i] != NULL)
	  scamper_addr_free(ips[i]);
      free(ips);
      ips = NULL;
    }

  return;
}

int main(int argc, char *argv[])
{
  scamper_file_t *file;
  ipid_sample_t *sample;
  uint16_t types[3];
  char probe_src[128], addr[128], ipid[10];
  int i, typec, stdin_used = 0;

#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2,2), &wsaData);
#endif

  if(check_options(argc, argv) != 0)
    return -1;

  /* ask for specific measurement types */
  typec = 0;
  types[typec++] = SCAMPER_FILE_OBJ_PING;
  types[typec++] = SCAMPER_FILE_OBJ_DEALIAS;
  if((flags & FLAG_NOTRACE) == 0)
    types[typec++] = SCAMPER_FILE_OBJ_TRACE;

  if((filter = scamper_file_filter_alloc(types, typec)) == NULL)
    return -1;

  if((list = slist_alloc()) == NULL)
    return -1;

  for(i=0; i<filelist_len; i++)
    {
      if(strcmp(filelist[i], "-") == 0)
	{
	  if(stdin_used == 1)
	    {
	      fprintf(stderr, "stdin already used\n");
	      return -1;
	    }
	  stdin_used++;
	  file = scamper_file_openfd(STDIN_FILENO, "-", 'r', "warts");
	}
      else
	{
	  file = scamper_file_open(filelist[i], 'r', NULL);
	}

      if(file == NULL)
	fprintf(stderr, "unable to open %s\n", filelist[i]);
      else
	process(file);
    }

  scamper_file_filter_free(filter);

  slist_qsort(list, (slist_cmp_t)ipid_sample_cmp);
  while((sample = slist_head_pop(list)) != NULL)
    {
      printf("%d.%06d %d.%06d %s %s %s\n",
	     (int)sample->tx.tv_sec, (int)sample->tx.tv_usec,
	     (int)sample->rx.tv_sec, (int)sample->rx.tv_usec,
	     scamper_addr_tostr(sample->probe_src,probe_src,sizeof(probe_src)),
	     scamper_addr_tostr(sample->addr, addr, sizeof(addr)),
	     ipid_sample_ipid(sample, ipid, sizeof(ipid)));
      ipid_sample_free(sample);
    }
  slist_free(list); list = NULL;

  return 0;
}
