/*
 * scamper_trace_json.c
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2011-2013 Internap Network Services Corporation
 * Copyright (C) 2013-2014 The Regents of the University of California
 * Copyright (C) 2015      The University of Waikato
 * Copyright (C) 2016      Matthew Luckie
 *
 * Authors: Brian Hammond, Matthew Luckie
 *
 * $Id: scamper_trace_json.c,v 1.17 2018/05/03 20:44:52 mjl Exp $
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
  "$Id: scamper_trace_json.c,v 1.17 2018/05/03 20:44:52 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_trace.h"
#include "scamper_icmpext.h"
#include "scamper_file.h"
#include "scamper_file_json.h"
#include "scamper_trace_json.h"
#include "utils.h"

static char *hop_tostr(scamper_trace_hop_t *hop)
{
  char buf[1024], tmp[128];
  scamper_icmpext_t *ie;
  size_t off = 0;
  uint32_t u32;
  int i;

  string_concat(buf, sizeof(buf), &off,	"{\"addr\":\"%s\"",
		scamper_addr_tostr(hop->hop_addr, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off,
		", \"probe_ttl\":%u, \"probe_id\":%u, \"probe_size\":%u",
		hop->hop_probe_ttl, hop->hop_probe_id, hop->hop_probe_size);
  if(hop->hop_tx.tv_sec != 0)
    string_concat(buf, sizeof(buf), &off,
		  ", \"tx\":{\"sec\":%u, \"usec\":%u}",
		  hop->hop_tx.tv_sec, hop->hop_tx.tv_usec);
  string_concat(buf, sizeof(buf), &off, ", \"rtt\":%s",
		timeval_tostr_us(&hop->hop_rtt, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off,
		", \"reply_ttl\":%u, \"reply_tos\":%u, \"reply_size\":%u",
		hop->hop_reply_ttl, hop->hop_reply_tos, hop->hop_reply_size);
  string_concat(buf, sizeof(buf), &off,	", \"reply_ipid\":%u",
		hop->hop_reply_ipid);

  if(SCAMPER_TRACE_HOP_IS_ICMP(hop))
    {
      string_concat(buf, sizeof(buf), &off,
		    ", \"icmp_type\":%u, \"icmp_code\":%u",
		    hop->hop_icmp_type, hop->hop_icmp_code);
      if(SCAMPER_TRACE_HOP_IS_ICMP_Q(hop))
	{
	  string_concat(buf, sizeof(buf), &off,
			", \"icmp_q_ttl\":%u, \"icmp_q_ipl\":%u",
			hop->hop_icmp_q_ttl, hop->hop_icmp_q_ipl);
	  if(SCAMPER_ADDR_TYPE_IS_IPV4(hop->hop_addr))
	    string_concat(buf, sizeof(buf), &off, ", \"icmp_q_tos\":%u",
			  hop->hop_icmp_q_tos);
	}
      if(SCAMPER_TRACE_HOP_IS_ICMP_PTB(hop))
	string_concat(buf, sizeof(buf), &off, ", \"icmp_nhmtu:\":%u",
		      hop->hop_icmp_nhmtu);
    }
  else if(SCAMPER_TRACE_HOP_IS_TCP(hop))
    {
      string_concat(buf, sizeof(buf), &off,
		    ", \"tcp_flags\":%u", hop->hop_tcp_flags);
    }

  if(hop->hop_icmpext != NULL)
    {
      string_concat(buf, sizeof(buf), &off, ", \"icmpext\":[");
      for(ie=hop->hop_icmpext; ie != NULL; ie=ie->ie_next)
	{
	  if(ie != hop->hop_icmpext)
	    string_concat(buf, sizeof(buf), &off, ",");
	  string_concat(buf, sizeof(buf), &off,
			"{\"ie_cn\":%u,\"ie_ct\":%u,\"ie_dl\":%u",
			ie->ie_cn, ie->ie_ct, ie->ie_dl);
	  if(SCAMPER_ICMPEXT_IS_MPLS(ie))
	    {
	      string_concat(buf, sizeof(buf), &off,
			    ",\"mpls_labels\":[");
	      for(i=0; i<SCAMPER_ICMPEXT_MPLS_COUNT(ie); i++)
		{
		  u32 = SCAMPER_ICMPEXT_MPLS_LABEL(ie, i);
		  if(i > 0)
		    string_concat(buf, sizeof(buf), &off, ",");
		  string_concat(buf, sizeof(buf), &off,
				"{\"mpls_ttl\":%u,\"mpls_s\":%u,"
				"\"mpls_exp\":%u,\"mpls_label\":%u}",
				SCAMPER_ICMPEXT_MPLS_TTL(ie, i),
				SCAMPER_ICMPEXT_MPLS_S(ie, i),
				SCAMPER_ICMPEXT_MPLS_EXP(ie, i), u32);
		}
	      string_concat(buf, sizeof(buf), &off, "]");
	    }
	  string_concat(buf, sizeof(buf), &off, "}");
	}
      string_concat(buf, sizeof(buf), &off, "]");
    }

  string_concat(buf, sizeof(buf), &off, "}");
  return strdup(buf);
}

static char *header_tostr(const scamper_trace_t *trace)
{
  char buf[512], tmp[64];
  size_t off = 0;
  time_t tt = trace->start.tv_sec;

  string_concat(buf,sizeof(buf),&off,"\"type\":\"trace\",\"version\":\"0.1\"");
  string_concat(buf, sizeof(buf), &off, ", \"userid\":%u", trace->userid);
  string_concat(buf, sizeof(buf), &off, ", \"method\":\"%s\"",
		scamper_trace_type_tostr(trace, tmp, sizeof(tmp)));
  if(trace->src != NULL)
    string_concat(buf, sizeof(buf), &off, ", \"src\":\"%s\"",
		  scamper_addr_tostr(trace->src, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off, ", \"dst\":\"%s\"",
		scamper_addr_tostr(trace->dst, tmp, sizeof(tmp)));
  if(SCAMPER_TRACE_TYPE_IS_UDP(trace) || SCAMPER_TRACE_TYPE_IS_TCP(trace))
    string_concat(buf, sizeof(buf), &off, ", \"sport\":%u, \"dport\":%u",
		  trace->sport, trace->dport);
  else if(trace->flags & SCAMPER_TRACE_FLAG_ICMPCSUMDP)
    string_concat(buf, sizeof(buf), &off, ", \"icmp_sum\":%u", trace->dport);
  string_concat(buf, sizeof(buf), &off,
		", \"stop_reason\":\"%s\", \"stop_data\":%u",
		scamper_trace_stop_tostr(trace, tmp, sizeof(tmp)),
		trace->stop_data);
  strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", localtime(&tt));
  string_concat(buf, sizeof(buf), &off,
		", \"start\":{\"sec\":%u, \"usec\":%u, \"ftime\":\"%s\"}",
		trace->start.tv_sec, trace->start.tv_usec, tmp);
  string_concat(buf, sizeof(buf), &off,
		", \"hop_count\":%u, \"attempts\":%u, \"hoplimit\":%u",
		trace->hop_count, trace->attempts, trace->hoplimit);
  string_concat(buf, sizeof(buf), &off,
		", \"firsthop\":%u, \"wait\":%u, \"wait_probe\":%u",
		trace->firsthop, trace->wait, trace->wait_probe);
  string_concat(buf, sizeof(buf), &off,
		", \"tos\":%u, \"probe_size\":%u, \"probe_count\":%u",
		trace->tos, trace->probe_size, trace->probec);

  return strdup(buf);
}

int scamper_file_json_trace_write(const scamper_file_t *sf,
				  const scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  size_t len, off = 0;
  char *str = NULL, *header = NULL, **hops = NULL;
  int i, j, hopc = 0, rc = -1;

  if((header = header_tostr(trace)) == NULL)
    goto cleanup;
  len = strlen(header);

  for(i=trace->firsthop-1; i<trace->hop_count; i++)
    for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
      hopc++;
  if(hopc > 0)
    {
      len += 11; /* , "hops":[] */
      if((hops = malloc_zero(sizeof(char *) * hopc)) == NULL)
	goto cleanup;
      for(i=trace->firsthop-1, j=0; i<trace->hop_count; i++)
	{
	  for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
	    {
	      if(j > 0) len++; /* , */
	      if((hops[j] = hop_tostr(hop)) == NULL)
		goto cleanup;
	      len += strlen(hops[j]);
	      j++;
	    }
	}
    }
  len += 4; /* {}\n\0 */

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;

  string_concat(str, len, &off, "{%s", header);
  if(hopc > 0)
    {
      string_concat(str, len, &off, ", \"hops\":[");
      for(j=0; j<hopc; j++)
	{
	  if(j > 0) string_concat(str, len, &off, ",");
	  string_concat(str, len, &off, "%s", hops[j]);
	}
      string_concat(str, len, &off, "]");
    }
  string_concat(str, len, &off, "}\n");
  assert(off+1 == len);

  rc = json_write(sf, str, off);

 cleanup:
  if(hops != NULL)
    {
      for(i=0; i<hopc; i++)
	if(hops[i] != NULL)
	  free(hops[i]);
      free(hops);
    }
  if(header != NULL) free(header);
  if(str != NULL) free(str);

  return rc;
}
