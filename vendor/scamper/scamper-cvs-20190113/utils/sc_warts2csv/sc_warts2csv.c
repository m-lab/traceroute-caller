/*
 * sc_warts2csv.c
 *
 * Copyright (C) 2014 The Regents of the University of California
 *
 * $Id: sc_warts2csv.c,v 1.3 2017/07/12 07:34:02 mjl Exp $
 *
 * Authors: Vaibhav Bajpai, Matthew Luckie
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
  "$Id: sc_warts2csv.c,v 1.3 2017/07/12 07:34:02 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_file.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "trace/scamper_trace.h"
#include "utils.h"

static void csv_trace(scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  int i, hopc = 0;
  char src[128], dst[128], addr[128], rtt[32], type[32], stop[32];
  const char *tptr, *sptr;

  for(i=trace->firsthop-1; i<trace->hop_count; i++)
    {
      for(hop=trace->hops[i]; hop != NULL; hop = hop->hop_next)
	{
	  hopc++;
	  break;
	}
    }

  if(hopc == 0)
    goto done;

  printf("version;userID;timestamp;src;dst;method;stop;ttl;hopaddr;rtt\n");

  scamper_addr_tostr(trace->dst, dst, sizeof(dst));
  scamper_addr_tostr(trace->src, src, sizeof(src));
  tptr = scamper_trace_type_tostr(trace, type, sizeof(type));
  sptr = scamper_trace_stop_tostr(trace, stop, sizeof(stop));

  for(i=trace->firsthop-1; i<trace->hop_count; i++)
    {
      for(hop=trace->hops[i]; hop != NULL; hop=hop->hop_next)
	{
	  printf("scamper.%s;%u;%d;%s;%s;%s;%s;%u;%s;%s\n", PACKAGE_VERSION,
		 trace->userid, (int)trace->start.tv_sec, src, dst, tptr,
		 sptr, hop->hop_probe_ttl,
		 scamper_addr_tostr(hop->hop_addr,addr,sizeof(addr)),
		 timeval_tostr_us(&hop->hop_rtt, rtt, sizeof(addr)));
	}
    }

 done:
  scamper_trace_free(trace);
  return;
}

int main(int argc, char *argv[])
{
  uint16_t types[] = {
    SCAMPER_FILE_OBJ_TRACE,
  };
  scamper_file_t *in;
  scamper_file_filter_t *filter;
  char **files = NULL;
  int filec;
  uint16_t type;
  void *data;
  int i;

  filter = scamper_file_filter_alloc(types, sizeof(types)/sizeof(uint16_t));
  if(filter == NULL)
    {
      fprintf(stderr, "could not allocate filter\n");
      return -1;
    }

  filec = argc - 1;
  if(filec > 0)
    files = argv + 1;

  for(i=0; i<=filec; i++)
    {
      if(filec == 0)
	{
	  if((in = scamper_file_openfd(STDIN_FILENO,"-",'r',"warts")) == NULL)
	    {
	      fprintf(stderr, "could not use stdin\n");
	      return -1;
	    }
	}
      else if(i < filec)
	{
	  if((in = scamper_file_open(files[i], 'r', NULL)) == NULL)
	    {
	      fprintf(stderr, "could not open %s: %s\n",
		      files[i], strerror(errno));
	      return -1;
	    }
	}
      else break;

      while(scamper_file_read(in, filter, &type, (void *)&data) == 0)
	{
	  if(data == NULL)
	    break; /* EOF */
	  if(type == SCAMPER_FILE_OBJ_TRACE)
	    csv_trace(data);
	}

      scamper_file_close(in);
    }

  scamper_file_filter_free(filter);
  return 0;
}
