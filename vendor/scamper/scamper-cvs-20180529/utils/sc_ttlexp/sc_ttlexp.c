/*
 * sc_ttlexp: dump all unique source IP addresses in TTL expired messages
 *
 * $Id: sc_ttlexp.c,v 1.5 2018/03/08 08:02:10 mjl Exp $
 *
 *         Matthew Luckie
 *         mjl@luckie.org.nz
 *
 * Copyright (C) 2017-2018 Matthew Luckie
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
  "$Id: sc_ttlexp.c,v 1.5 2018/03/08 08:02:10 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "trace/scamper_trace.h"
#include "tracelb/scamper_tracelb.h"
#include "scamper_file.h"
#include "mjl_patricia.h"

static patricia_t *pt_ip4 = NULL;
static patricia_t *pt_ip6 = NULL;
static int         no_dst = 0;

static void usage(void)
{
  fprintf(stderr, "usage: sc_ttlexp [-O options] file1 .. fileN\n");
  return;
}

static int check_options(int argc, char *argv[])
{
  int ch;
  char *opts = "?O:";

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'O':
	  if(strcasecmp(optarg, "nodst") == 0)
	    no_dst = 1;
	  else
	    return -1;
	  break;

	case '?':
	  usage();
	  return -1;

	default:
	  return -1;
	}
    }

  return 0;
}

static int dump_addr(scamper_addr_t *addr)
{
  scamper_addr_t *a = NULL;
  char b[128];
  int rc = -1;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(addr))
    {
      if(patricia_find(pt_ip4, addr) != NULL)
	return 0;
      printf("%s\n", scamper_addr_tostr(addr, b, sizeof(b)));
      a = scamper_addr_use(addr);
      if(patricia_insert(pt_ip4, a) == NULL)
	goto done;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(addr))
    {
      if(patricia_find(pt_ip6, addr) != NULL)
	return 0;
      printf("%s\n", scamper_addr_tostr(addr, b, sizeof(b)));
      a = scamper_addr_use(addr);
      if(patricia_insert(pt_ip6, a) == NULL)
	goto done;
    }
  rc = 0;

 done:
  if(rc != 0 && a != NULL) scamper_addr_free(a);
  return rc;
}

static int dump_tracelb(scamper_tracelb_t *trace)
{
  scamper_tracelb_link_t *link;
  scamper_tracelb_node_t *node;
  scamper_tracelb_probe_t *probe;
  scamper_tracelb_reply_t *reply;
  scamper_tracelb_probeset_t *set;
  uint16_t i, j, k, l, m;
  int rc = -1;

  for(i=0; i<trace->nodec; i++)
    {
      node = trace->nodes[i];
      for(j=0; j<node->linkc; j++)
	{
	  link = node->links[j];
	  for(k=0; k<link->hopc; k++)
	    {
	      set = link->sets[k];
	      for(l=0; l<set->probec; l++)
		{
		  probe = set->probes[l];
		  for(m=0; m<probe->rxc; m++)
		    {
		      reply = set->probes[l]->rxs[m];
		      if(SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(reply) == 0 ||
			 (no_dst != 0 &&
			  scamper_addr_cmp(reply->reply_from,trace->dst) == 0))
			continue;
		      if(dump_addr(reply->reply_from) != 0)
			goto done;
		    }
		}
	    }
	}
    }
  rc = 0;

 done:
  scamper_tracelb_free(trace);
  return rc;
}

static int dump_trace(scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  uint16_t u16;
  int rc = -1;

  for(u16=0; u16<trace->hop_count; u16++)
    {
      for(hop = trace->hops[u16]; hop != NULL; hop = hop->hop_next)
	{
	  if(SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(hop) == 0 ||
	     (no_dst != 0 &&
	      scamper_addr_cmp(hop->hop_addr, trace->dst) == 0))
	    continue;
	  if(dump_addr(hop->hop_addr) != 0)
	    goto done;
	}
    }
  rc = 0;

 done:
  scamper_trace_free(trace);
  return rc;
}

static void cleanup(void)
{
  if(pt_ip4 != NULL)
    {
      patricia_free_cb(pt_ip4, (patricia_free_t)scamper_addr_free);
      pt_ip4 = NULL;
    }

  if(pt_ip6 != NULL)
    {
      patricia_free_cb(pt_ip6, (patricia_free_t)scamper_addr_free);
      pt_ip6 = NULL;
    }

  return;
}

int main(int argc, char *argv[])
{
  scamper_file_t        *file;
  scamper_file_filter_t *filter;
  uint16_t filter_types[] = {
    SCAMPER_FILE_OBJ_TRACE,
    SCAMPER_FILE_OBJ_TRACELB,
  };
  uint16_t filter_cnt = sizeof(filter_types)/sizeof(uint16_t);

  void     *data;
  uint16_t  type;
  int       f;

#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2,2), &wsaData);
#endif

#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

  if((pt_ip4 = patricia_alloc((patricia_bit_t)scamper_addr_bit,
			      (patricia_cmp_t)scamper_addr_cmp,
			      (patricia_fbd_t)scamper_addr_fbd)) == NULL ||
     (pt_ip6 = patricia_alloc((patricia_bit_t)scamper_addr_bit,
			      (patricia_cmp_t)scamper_addr_cmp,
			      (patricia_fbd_t)scamper_addr_fbd)) == NULL)
    return -1;

  if((filter = scamper_file_filter_alloc(filter_types, filter_cnt)) == NULL)
    {
      fprintf(stderr, "could not alloc filter\n");
      return -1;
    }

  for(f=0; f<argc; f++)
    {
      if(f == 0)
	{
	  if(argc > 1)
	    continue;

	  if((file=scamper_file_openfd(STDIN_FILENO,"-",'r',"warts")) == NULL)
	    {
	      usage();
	      fprintf(stderr, "could not use stdin\n");
	      return -1;
	    }
	}
      else
	{
	  if((file = scamper_file_open(argv[f], 'r', NULL)) == NULL)
	    {
	      usage();
	      fprintf(stderr, "could not open %s\n", argv[f]);
	      return -1;
	    }
	}

      while(scamper_file_read(file, filter, &type, &data) == 0)
	{
	  /* hit eof */
	  if(data == NULL)
	    goto done;

	  switch(type)
	    {
	    case SCAMPER_FILE_OBJ_TRACE:
	      dump_trace(data);
	      break;

	    case SCAMPER_FILE_OBJ_TRACELB:
	      dump_tracelb(data);
	      break;
	    }
	}

    done:
      scamper_file_close(file);

      if(argc == 1)
	break;
    }

  scamper_file_filter_free(filter);
  return 0;
}
