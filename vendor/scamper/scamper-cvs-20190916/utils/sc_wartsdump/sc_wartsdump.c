/*
 * sc_wartsdump
 *
 * $Id: sc_wartsdump.c,v 1.221 2019/07/28 09:24:53 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2019      Matthew Luckie
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
  "$Id: sc_wartsdump.c,v 1.221 2019/07/28 09:24:53 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "trace/scamper_trace.h"
#include "ping/scamper_ping.h"
#include "tracelb/scamper_tracelb.h"
#include "dealias/scamper_dealias.h"
#include "neighbourdisc/scamper_neighbourdisc.h"
#include "tbit/scamper_tbit.h"
#include "sting/scamper_sting.h"
#include "sniff/scamper_sniff.h"
#include "host/scamper_host.h"
#include "scamper_file.h"
#include "utils.h"

static void usage()
{
  fprintf(stderr, "usage: sc_wartsdump <file>\n");
  return;
}

static char *icmp_unreach_tostr(char *buf, size_t len, int at, uint8_t co)
{
  char *p = NULL;

  if(at == SCAMPER_ADDR_TYPE_IPV4)
    {
      switch(co)
	{
	case ICMP_UNREACH_NET:           p = "net";           break;
	case ICMP_UNREACH_HOST:          p = "host";          break;
	case ICMP_UNREACH_PROTOCOL:      p = "protocol";      break;
	case ICMP_UNREACH_PORT:          p = "port";          break;
	case ICMP_UNREACH_SRCFAIL:       p = "src-rt failed"; break;
	case ICMP_UNREACH_NET_UNKNOWN:   p = "net unknown";   break;
	case ICMP_UNREACH_HOST_UNKNOWN:  p = "host unknown";  break;
	case ICMP_UNREACH_ISOLATED:      p = "isolated";      break;
	case ICMP_UNREACH_NET_PROHIB:    p = "net prohib";    break;
	case ICMP_UNREACH_HOST_PROHIB:   p = "host prohib";   break;
	case ICMP_UNREACH_TOSNET:        p = "tos net";       break;
	case ICMP_UNREACH_TOSHOST:       p = "tos host";      break;
	case ICMP_UNREACH_FILTER_PROHIB: p = "admin prohib";  break;
	case ICMP_UNREACH_NEEDFRAG:      p = "need frag";     break;
	}
    }
  else
    {
      switch(co)
	{
	case ICMP6_DST_UNREACH_NOROUTE:     p = "no route";     break;
	case ICMP6_DST_UNREACH_ADMIN:       p = "admin prohib"; break;
	case ICMP6_DST_UNREACH_BEYONDSCOPE: p = "beyond scope"; break;
	case ICMP6_DST_UNREACH_ADDR:        p = "addr"; break;
	case ICMP6_DST_UNREACH_NOPORT:      p = "port"; break;
	}
    }

  if(p != NULL)
    snprintf(buf, len, "%s", p);
  else
    snprintf(buf, len, "%d", co);

  return buf;
}

static void dump_list_summary(scamper_list_t *list)
{
  if(list != NULL)
    {
      printf(" list id: %d", list->id);
      if(list->name != NULL)
	printf(", name: %s", list->name);
      if(list->monitor != NULL)
	printf(", monitor: %s", list->monitor);
      printf("\n");
    }
  return;
}

static void dump_cycle_summary(scamper_cycle_t *cycle)
{
  if(cycle != NULL)
    printf(" cycle id: %d\n", cycle->id);
  return;
}

static void dump_tcp_flags(uint8_t flags)
{
  if(flags != 0)
    {
      printf(" (%s%s%s%s%s%s%s%s )",
	     (flags & 0x01) ? " fin" : "",
	     (flags & 0x02) ? " syn" : "",
	     (flags & 0x04) ? " rst" : "",
	     (flags & 0x08) ? " psh" : "",
	     (flags & 0x10) ? " ack" : "",
	     (flags & 0x20) ? " urg" : "",
	     (flags & 0x40) ? " ece" : "",
	     (flags & 0x80) ? " cwr" : "");
    }
  return;
}

static void dump_timeval(const char *label, struct timeval *start)
{
  time_t tt = start->tv_sec;
  char buf[32];
  memcpy(buf, ctime(&tt), 24); buf[24] = '\0';
  printf(" %s: %s %06d\n", label, buf, (int)start->tv_usec);
  return;
}

static void dump_trace_hop(const scamper_trace_t *trace,
			   scamper_trace_hop_t *hop)
{
  struct timeval tv;
  scamper_icmpext_t *ie;
  uint32_t u32;
  char addr[256];
  int i;

  printf("hop %2d  %s\n",
	 hop->hop_probe_ttl,
	 scamper_addr_tostr(hop->hop_addr, addr, sizeof(addr)));

  printf(" attempt: %d", hop->hop_probe_id);
  if(hop->hop_tx.tv_sec != 0)
    {
      timeval_diff_tv(&tv, &trace->start, &hop->hop_tx);
      printf(", tx: %d.%06ds", (int)tv.tv_sec, (int)tv.tv_usec);
    }
  printf(", rtt: %d.%06ds, probe-size: %d\n",
	 (int)hop->hop_rtt.tv_sec, (int)hop->hop_rtt.tv_usec,
	 hop->hop_probe_size);

  printf(" reply-size: %d", hop->hop_reply_size);
  if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_REPLY_TTL)
    printf(", reply-ttl: %d", hop->hop_reply_ttl);
  if(hop->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4)
    printf(", reply-ipid: 0x%04x, reply-tos 0x%02x",
	   hop->hop_reply_ipid, hop->hop_reply_tos);
  printf("\n");

  if(SCAMPER_TRACE_HOP_IS_ICMP(hop))
    {
      printf(" icmp-type: %d, icmp-code: %d",
	     hop->hop_icmp_type, hop->hop_icmp_code);
      if(SCAMPER_TRACE_HOP_IS_ICMP_Q(hop))
	{
	  printf(", q-ttl: %d, q-len: %d",
		 hop->hop_icmp_q_ttl, hop->hop_icmp_q_ipl);
	  if(hop->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4)
	    printf(", q-tos %d", hop->hop_icmp_q_tos);
	}
      if(SCAMPER_TRACE_HOP_IS_ICMP_PTB(hop))
	printf(", nhmtu: %d", hop->hop_icmp_nhmtu);
      printf("\n");
    }
  else if(SCAMPER_TRACE_HOP_IS_TCP(hop))
    {
      printf(" tcp-flags: 0x%02x", hop->hop_tcp_flags);
      dump_tcp_flags(hop->hop_tcp_flags);
      printf("\n");
    }

  printf(" flags: 0x%02x", hop->hop_flags);
  if(hop->hop_flags != 0)
    {
      printf(" (");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_SOCK_RX)
	printf(" sockrxts");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_TX)
	printf(" dltxts");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_RX)
	printf(" dlrxts");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_TSC)
	printf(" tscrtt");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_REPLY_TTL)
	printf(" replyttl");
      printf(" )");
    }
  printf("\n");

  for(ie = hop->hop_icmpext; ie != NULL; ie = ie->ie_next)
    {
      if(SCAMPER_ICMPEXT_IS_MPLS(ie))
	{
	  for(i=0; i<SCAMPER_ICMPEXT_MPLS_COUNT(ie); i++)
	    {
	      u32 = SCAMPER_ICMPEXT_MPLS_LABEL(ie, i);
	      printf("%9s ttl: %d, s: %d, exp: %d, label: %d\n",
		     (i == 0) ? "mpls ext" : "",
		     SCAMPER_ICMPEXT_MPLS_TTL(ie, i),
		     SCAMPER_ICMPEXT_MPLS_S(ie, i),
		     SCAMPER_ICMPEXT_MPLS_EXP(ie, i), u32);
	    }
	}
    }

  return;
}

static void dump_trace(scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  scamper_trace_pmtud_t *pmtud;
  scamper_trace_pmtud_n_t *n;
  uint16_t u16;
  uint8_t u8;
  char buf[256];
  int i;

  if(trace->src != NULL)
    {
      scamper_addr_tostr(trace->src, buf, sizeof(buf));
      printf("traceroute from %s to ", buf);
      scamper_addr_tostr(trace->dst, buf, sizeof(buf));
      printf("%s\n", buf);
    }
  else
    {
      printf("traceroute to %s\n",
	     scamper_addr_tostr(trace->dst, buf, sizeof(buf)));
    }

  dump_list_summary(trace->list);
  dump_cycle_summary(trace->cycle);
  printf(" user-id: %d\n", trace->userid);
  dump_timeval("start", &trace->start);

  printf(" type: ");
  switch(trace->type)
    {
    case SCAMPER_TRACE_TYPE_ICMP_ECHO:
      printf("icmp, echo id: %d", trace->sport);
      break;

    case SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS:
      /*
       * if the byte ordering of the trace->sport used in the icmp csum
       * is unknown -- that is, not known to be correct, print that detail
       */
      printf("icmp paris, echo id: %d", trace->sport);
      if(SCAMPER_TRACE_IS_ICMPCSUMDP(trace))
	printf(", csum: 0x%04x", trace->dport);
      break;

    case SCAMPER_TRACE_TYPE_UDP:
      printf("udp, sport: %d, base dport: %d",
	     trace->sport, trace->dport);
      break;

    case SCAMPER_TRACE_TYPE_UDP_PARIS:
      printf("udp paris, sport: %d, dport: %d",
	     trace->sport, trace->dport);
      break;

    case SCAMPER_TRACE_TYPE_TCP:
      printf("tcp, sport: %d, dport: %d", trace->sport, trace->dport);
      break;

    case SCAMPER_TRACE_TYPE_TCP_ACK:
      printf("tcp-ack, sport: %d, dport: %d",
	     trace->sport, trace->dport);
      break;

    default:
      printf("%d", trace->type);
      break;
    }
  if(trace->offset != 0)
    printf(", offset %d", trace->offset);
  printf("\n");

  if(trace->dtree != NULL)
    {
      printf(" doubletree firsthop: %d", trace->dtree->firsthop);
      if(trace->dtree->lss != NULL)
	printf(", lss-name: %s", trace->dtree->lss);
      if(trace->dtree->lss_stop != NULL)
	printf(", lss-stop: %s",
	       scamper_addr_tostr(trace->dtree->lss_stop, buf, sizeof(buf)));
      if(trace->dtree->gss_stop != NULL)
	printf(", gss-stop: %s",
	       scamper_addr_tostr(trace->dtree->gss_stop, buf, sizeof(buf)));
      printf("\n");
    }

  printf(" attempts: %d, hoplimit: %d, loops: %d, probec: %d\n",
	 trace->attempts, trace->hoplimit, trace->loops, trace->probec);
  printf(" gaplimit: %d, gapaction: ", trace->gaplimit);
  if(trace->gapaction == SCAMPER_TRACE_GAPACTION_STOP)
    printf("stop");
  else if(trace->gapaction == SCAMPER_TRACE_GAPACTION_LASTDITCH)
    printf("lastditch");
  else
    printf("0x%02x", trace->gapaction);
  printf("\n");

  printf(" wait-timeout: %ds", trace->wait);
  if(trace->wait_probe != 0)
    printf(", wait-probe: %dms", trace->wait_probe * 10);
  if(trace->confidence != 0)
    printf(", confidence: %d%%", trace->confidence);
  printf("\n");

  printf(" flags: 0x%02x", trace->flags);
  if(trace->flags != 0)
    {
      printf(" (");
      if(trace->flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS)
	printf(" all-attempts");
      if(trace->flags & SCAMPER_TRACE_FLAG_PMTUD)
	printf(" pmtud");
      if(trace->flags & SCAMPER_TRACE_FLAG_DL)
	printf(" dl");
      if(trace->flags & SCAMPER_TRACE_FLAG_IGNORETTLDST)
	printf(" ignorettldst");
      if(trace->flags & SCAMPER_TRACE_FLAG_DOUBLETREE)
	printf(" doubletree");
      if(trace->flags & SCAMPER_TRACE_FLAG_ICMPCSUMDP)
	printf(" icmp-csum-dport");
      if(trace->flags & SCAMPER_TRACE_FLAG_CONSTPAYLOAD)
	printf(" const-payload");
      printf(" )");
    }
  printf("\n");

  printf(" stop reason: ");
  switch(trace->stop_reason)
    {
    case SCAMPER_TRACE_STOP_NONE:
      printf("none");
      break;

    case SCAMPER_TRACE_STOP_COMPLETED:
      printf("done");
      break;

    case SCAMPER_TRACE_STOP_UNREACH:
      i = trace->dst->type;
      printf("icmp unreach %s",
	     icmp_unreach_tostr(buf, sizeof(buf), i, trace->stop_data));
      break;

    case SCAMPER_TRACE_STOP_ICMP:
      printf("icmp type %d", trace->stop_data);
      break;

    case SCAMPER_TRACE_STOP_LOOP:
      printf("loop");
      break;

    case SCAMPER_TRACE_STOP_GAPLIMIT:
      printf("gaplimit");
      break;

    case SCAMPER_TRACE_STOP_ERROR:
      printf("errno %d", trace->stop_data);
      break;

    case SCAMPER_TRACE_STOP_HOPLIMIT:
      printf("hoplimit");
      break;

    case SCAMPER_TRACE_STOP_GSS:
      printf("dtree-gss");
      break;

    case SCAMPER_TRACE_STOP_HALTED:
      printf("halted");
      break;

    default:
      printf("reason 0x%02x data 0x%02x",trace->stop_reason,trace->stop_data);
      break;
    }
  printf("\n");

  for(u16=0; u16<trace->hop_count; u16++)
    for(hop = trace->hops[u16]; hop != NULL; hop = hop->hop_next)
      dump_trace_hop(trace, hop);

  /* dump any last-ditch probing hops */
  for(hop = trace->lastditch; hop != NULL; hop = hop->hop_next)
    dump_trace_hop(trace, hop);

  if((pmtud = trace->pmtud) != NULL)
    {
      printf("pmtud: ver %d ifmtu %d, pmtu %d", pmtud->ver, pmtud->ifmtu,
	     pmtud->pmtu);
      if(pmtud->outmtu != 0)
	printf(", outmtu %d", pmtud->outmtu);
      if(pmtud->notec != 0)
	printf(", notec %d", pmtud->notec);
      printf("\n");
      for(u8=0; u8<pmtud->notec; u8++)
	{
	  n = pmtud->notes[u8];
	  hop = n->hop;
	  printf(" note %d: nhmtu %d, ", u8, n->nhmtu);

	  if(hop != NULL)
	    scamper_addr_tostr(hop->hop_addr, buf, sizeof(buf));
	  else
	    buf[0] = '\0';

	  if(n->type == SCAMPER_TRACE_PMTUD_N_TYPE_PTB)
	    printf("ptb %s", buf);
	  else if(n->type == SCAMPER_TRACE_PMTUD_N_TYPE_PTB_BAD && hop != NULL)
	    printf("ptb-bad %s mtu %d", buf, hop->hop_icmp_nhmtu);
	  else if(n->type == SCAMPER_TRACE_PMTUD_N_TYPE_SILENCE)
	    printf("silence > ttl %d", hop != NULL ? hop->hop_probe_ttl : 0);
	  else
	    printf("type-%d", n->type);
	  printf("\n");
	}
      for(hop = trace->pmtud->hops; hop != NULL; hop = hop->hop_next)
	dump_trace_hop(trace, hop);
    }

  printf("\n");

  scamper_trace_free(trace);

  return;
}

static void dump_tracelb_reply(scamper_tracelb_probe_t *probe,
			       scamper_tracelb_reply_t *reply)
{
  scamper_icmpext_t *ie;
  struct timeval rtt;
  char from[32];
  uint32_t u32;
  uint16_t m;

  timeval_diff_tv(&rtt, &probe->tx, &reply->reply_rx);
  scamper_addr_tostr(reply->reply_from, from, sizeof(from));

  printf("   reply from: %s, rtt: %d.%06d, ttl: %d",
	 from, (int)rtt.tv_sec, (int)rtt.tv_usec, reply->reply_ttl);

  if(reply->reply_from->type == SCAMPER_ADDR_TYPE_IPV4)
    printf(", ipid: 0x%04x", reply->reply_ipid);
  printf("\n     ");

  if(reply->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP)
    {
      printf("tcp flags 0x%02x", reply->reply_tcp_flags);
      dump_tcp_flags(reply->reply_tcp_flags);
      printf("\n");
    }
  else
    {
      printf("icmp: %d/%d, q-tos: 0x%02x",
	     reply->reply_icmp_type, reply->reply_icmp_code,
	     reply->reply_icmp_q_tos);
      if(SCAMPER_TRACELB_REPLY_IS_ICMP_UNREACH(reply) ||
	 SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(reply))
	{
	  printf(", q-ttl: %d", reply->reply_icmp_q_ttl);
	}
      printf("\n");

      for(ie = reply->reply_icmp_ext; ie != NULL; ie = ie->ie_next)
	{
	  if(SCAMPER_ICMPEXT_IS_MPLS(ie))
	    {
	      for(m=0; m<SCAMPER_ICMPEXT_MPLS_COUNT(ie); m++)
		{
		  u32 = SCAMPER_ICMPEXT_MPLS_LABEL(ie, m);
		  printf("   %9s: label %d exp %d s %d ttl %d\n",
			 (m == 0) ? "  icmp-ext mpls" : "", u32,
			 SCAMPER_ICMPEXT_MPLS_EXP(ie, m),
			 SCAMPER_ICMPEXT_MPLS_S(ie, m),
			 SCAMPER_ICMPEXT_MPLS_TTL(ie, m));
		}
	    }
	}
    }

  return;
}

static void dump_tracelb_probe(scamper_tracelb_t *trace,
			       scamper_tracelb_probe_t *probe)
{
  uint32_t i;

  printf("  probe flowid: %d, ttl: %d, attempt: %d, tx: %d.%06d\n",
	 probe->flowid, probe->ttl, probe->attempt,
	 (int)probe->tx.tv_sec, (int)probe->tx.tv_usec);

  for(i=0; i<probe->rxc; i++)
    {
      dump_tracelb_reply(probe, probe->rxs[i]);
    }

  return;
}

static void dump_tracelb(scamper_tracelb_t *trace)
{
  static const char *flags[] = {
    "ptr"
  };
  scamper_tracelb_link_t *link;
  scamper_tracelb_node_t *node;
  scamper_tracelb_probeset_t *set;
  char src[256], dst[256];
  uint16_t i, j, k, l;

  if(trace->src != NULL)
    {
      printf("tracelb from %s to %s\n",
	     scamper_addr_tostr(trace->src, src, sizeof(src)),
	     scamper_addr_tostr(trace->dst, dst, sizeof(dst)));
    }
  else
    {
      printf("tracelb to %s\n",
	     scamper_addr_tostr(trace->dst, dst, sizeof(dst)));
    }

  dump_list_summary(trace->list);
  dump_cycle_summary(trace->cycle);
  printf(" user-id: %d\n", trace->userid);
  dump_timeval("start", &trace->start);

  printf(" type: ");
  switch(trace->type)
    {
    case SCAMPER_TRACELB_TYPE_ICMP_ECHO:
      printf("icmp-echo id: %d", trace->sport);
      break;

    case SCAMPER_TRACELB_TYPE_UDP_DPORT:
      printf("udp-dport %d:%d", trace->sport, trace->dport);
      break;

    case SCAMPER_TRACELB_TYPE_UDP_SPORT:
      printf("udp-sport %d:%d", trace->sport, trace->dport);
      break;

    case SCAMPER_TRACELB_TYPE_TCP_SPORT:
      printf("tcp-sport %d:%d", trace->sport, trace->dport);
      break;

    case SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT:
      printf("tcp-ack-sport %d:%d", trace->sport, trace->dport);
      break;

    default:
      printf("%d", trace->type);
      break;
    }
  printf(", tos: 0x%02x\n", trace->tos);

  printf(" firsthop: %d, attempts: %d, confidence: %d\n",
	 trace->firsthop, trace->attempts, trace->confidence);
  printf(" probe-size: %d, wait-probe: %dms, wait-timeout %ds\n",
	 trace->probe_size, trace->wait_probe * 10, trace->wait_timeout);
  printf(" nodec: %d, linkc: %d, probec: %d, probec_max: %d\n",
	 trace->nodec, trace->linkc, trace->probec, trace->probec_max);
  if(trace->flags != 0)
    {
      printf(" flags:");
      l = 0;
      for(i=0; i<1; i++)
	{
	  if((trace->flags & (0x1 << i)) == 0)
	    continue;
	  if(l > 0)
	    printf(",");
	  printf(" %s", flags[i]);
	  l++;
	}
      printf("\n");
    }

  for(i=0; i<trace->nodec; i++)
    {
      node = trace->nodes[i];

      if(node->addr != NULL)
	scamper_addr_tostr(node->addr, src, sizeof(src));
      else
	snprintf(src, sizeof(src), "*");

      printf("node %d %s", i, src);
      if(SCAMPER_TRACELB_NODE_QTTL(node) != 0)
	printf(", q-ttl %d", node->q_ttl);
      if(node->name != NULL)
	printf(", name %s", node->name);
      printf("\n");

      for(j=0; j<node->linkc; j++)
	{
	  link = node->links[j];
	  if(link->from->addr != NULL)
	    scamper_addr_tostr(link->from->addr, src, sizeof(src));
	  else
	    snprintf(src, sizeof(src), "*");
	  if(link->to != NULL)
	    scamper_addr_tostr(link->to->addr, dst, sizeof(dst));
	  else
	    snprintf(dst, sizeof(dst), "*");
	  printf(" link %s -> %s hopc %d\n", src, dst, link->hopc);

	  for(k=0; k<link->hopc; k++)
	    {
	      set = link->sets[k];
	      for(l=0; l<set->probec; l++)
		dump_tracelb_probe(trace, set->probes[l]);
	    }
	}
    }

  printf("\n");

  scamper_tracelb_free(trace);
  return;
}

static char *ping_tsreply_tostr(char *buf, size_t len, uint32_t val)
{
  uint32_t hh, mm, ss, ms;
  ms = val % 1000;
  ss = val / 1000;
  hh = ss / 3600; ss -= (hh * 3600);
  mm = ss / 60; ss -= (mm * 60);
  snprintf(buf, len, "%02d:%02d:%02d.%03d", hh, mm, ss, ms);
  return buf;
}

static void dump_ping_reply(const scamper_ping_t *ping,
			    const scamper_ping_reply_t *reply)
{
  scamper_ping_reply_v4rr_t *v4rr;
  scamper_ping_reply_v4ts_t *v4ts;
  scamper_ping_reply_tsreply_t *tsreply;
  uint8_t i;
  char buf[256];
  struct timeval txoff;

  printf("reply from %s, attempt: %d",
	 scamper_addr_tostr(reply->addr, buf, sizeof(buf)), reply->probe_id+1);
  if(timeval_cmp(&reply->tx, &ping->start) >= 0)
    {
      timeval_diff_tv(&txoff, &ping->start, &reply->tx);
      printf(", tx: %d.%06ds", (int)txoff.tv_sec, (int)txoff.tv_usec);
    }
  printf(", rtt: %d.%06ds\n", (int)reply->rtt.tv_sec, (int)reply->rtt.tv_usec);

  printf(" size: %d", reply->reply_size);
  if(reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_TTL)
    printf(", ttl: %d", reply->reply_ttl);
  if(reply->flags & SCAMPER_PING_REPLY_FLAG_PROBE_IPID)
    printf(", probe-ipid: 0x%04x", reply->probe_ipid);
  if(reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID)
    {
      if(SCAMPER_ADDR_TYPE_IS_IPV4(reply->addr))
	printf(", reply-ipid: 0x%04x", reply->reply_ipid);
      else
	printf(", reply-ipid32: 0x%08x", reply->reply_ipid32);
    }
  printf("\n");

  if(SCAMPER_PING_REPLY_IS_ICMP(reply))
    {
      printf(" icmp type: %d, code: %d\n", reply->icmp_type, reply->icmp_code);
    }
  else if(SCAMPER_PING_REPLY_IS_TCP(reply))
    {
      printf(" tcp flags: %02x", reply->tcp_flags);
      dump_tcp_flags(reply->tcp_flags);
      printf("\n");
    }

  if((tsreply = reply->tsreply) != NULL)
    {
      printf(" icmp-tsreply:");
      printf(" tso=%s", ping_tsreply_tostr(buf, sizeof(buf), tsreply->tso));
      printf(" tsr=%s", ping_tsreply_tostr(buf, sizeof(buf), tsreply->tsr));
      printf(" tst=%s\n", ping_tsreply_tostr(buf, sizeof(buf), tsreply->tst));
    }

  if((v4rr = reply->v4rr) != NULL)
    {
      printf(" record route:");
      for(i=0; i<v4rr->rrc; i++)
	{
	  if((i % 3) == 0 && i != 0)
	    printf("\n              ");

	  printf(" %-15s",
		 scamper_addr_tostr(v4rr->rr[i],buf,sizeof(buf)));
	}
      printf("\n");
    }

  if((v4ts = reply->v4ts) != NULL)
    {
      printf(" IP timestamp option: tsc %d", v4ts->tsc);
      if(v4ts->ips != NULL)
	{
	  for(i=0; i<v4ts->tsc; i++)
	    {
	      if((i % 2) == 0)
		printf("\n  ");
	      else if(i != 0)
		printf("    ");

	      printf("%-15s 0x%08x",
		     scamper_addr_tostr(v4ts->ips[i], buf, sizeof(buf)),
		     v4ts->tss[i]);
	    }
	}
      else
	{
	  for(i=0; i<v4ts->tsc; i++)
	    {
	      if((i % 3) == 0)
		printf("\n  ");
	      printf(" 0x%08x", v4ts->tss[i]);
	    }
	}
      printf("\n");
    }

  return;
}

static void dump_ping(scamper_ping_t *ping)
{
  static const char *flags[] = {
    "v4rr", "spoof", "payload", "tsonly", "tsandaddr", "icmpsum", "dl", "tbt",
    "nosrc",
  };
  scamper_ping_reply_t *reply;
  char buf[256];
  uint32_t u32;
  int i;

  scamper_addr_tostr(ping->src, buf, sizeof(buf));
  printf("ping from %s", buf);
  if(ping->flags & SCAMPER_PING_FLAG_SPOOF)
    printf(" (spoofed)");
  scamper_addr_tostr(ping->dst, buf, sizeof(buf));
  printf(" to %s\n", buf);

  dump_list_summary(ping->list);
  dump_cycle_summary(ping->cycle);
  printf(" user-id: %d\n", ping->userid);
  dump_timeval("start", &ping->start);

  printf(" probe-count: %d", ping->probe_count);
  if(ping->reply_count > 0)
    printf(", replies-req: %d", ping->reply_count);
  printf(", size: %d", ping->probe_size);
  if(ping->reply_pmtu > 0)
    printf(", reply-pmtu: %d", ping->reply_pmtu);
  printf(", wait: %u", ping->probe_wait);
  if(ping->probe_wait_us > 0)
    {
      u32 = ping->probe_wait_us;
      while((u32 % 10) == 0)
	u32 /= 10;
      printf(".%u", u32);
    }
  printf(", timeout: %u, ttl: %u", ping->probe_timeout, ping->probe_ttl);
  printf("\n");

  if(ping->flags != 0)
    {
      printf(" flags:");
      u32 = 0;
      for(i=0; i<9; i++)
	{
	  if((ping->flags & (0x1 << i)) == 0)
	    continue;
	  if(u32 > 0)
	    printf(",");
	  printf(" %s", flags[i]);
	  u32++;
	}
      printf("\n");
    }

  printf(" method: %s", scamper_ping_method2str(ping, buf, sizeof(buf)));
  switch(ping->probe_method)
    {
    case SCAMPER_PING_METHOD_ICMP_ECHO:
    case SCAMPER_PING_METHOD_ICMP_TIME:
      if((ping->flags & SCAMPER_PING_FLAG_ICMPSUM) != 0)
	printf(", icmp-csum: %04x", ping->probe_icmpsum);
      break;

    case SCAMPER_PING_METHOD_UDP:
    case SCAMPER_PING_METHOD_TCP_ACK:
    case SCAMPER_PING_METHOD_TCP_SYN:
    case SCAMPER_PING_METHOD_TCP_RST:
    case SCAMPER_PING_METHOD_TCP_SYNACK:
      printf(", sport: %d, dport: %d", ping->probe_sport, ping->probe_dport);
      break;

    case SCAMPER_PING_METHOD_TCP_ACK_SPORT:
      printf(", base-sport: %d, dport: %d",
	     ping->probe_sport, ping->probe_dport);
      break;

    case SCAMPER_PING_METHOD_UDP_DPORT:
      printf(", sport: %d, base-dport %d",
	     ping->probe_sport, ping->probe_dport);
      break;
    }

  if(SCAMPER_PING_METHOD_IS_TCP(ping))
    printf(", seq: %u, ack: %u", ping->probe_tcpseq, ping->probe_tcpack);

  printf("\n");

  if(ping->probe_tsps != NULL)
    {
      printf(" timestamp-prespec:");
      for(i=0; i<ping->probe_tsps->ipc; i++)
	printf(" %s",
	       scamper_addr_tostr(ping->probe_tsps->ips[i],buf,sizeof(buf)));
      printf("\n");
    }

  /* dump pad bytes, if used */
  if(ping->probe_datalen > 0 && ping->probe_data != NULL)
    {
      if((ping->flags & SCAMPER_PING_FLAG_PAYLOAD) != 0)
	printf(" payload");
      else
	printf(" pattern");
      printf(" bytes (%d): ", ping->probe_datalen);
      for(i=0; i<ping->probe_datalen; i++)
	printf("%02x", ping->probe_data[i]);
      printf("\n");
    }

  printf(" probes-sent: %d, stop-reason: ", ping->ping_sent);
  switch(ping->stop_reason)
    {
    case SCAMPER_PING_STOP_NONE:
      printf("none"); break;

    case SCAMPER_PING_STOP_COMPLETED:
      printf("done"); break;

    case SCAMPER_PING_STOP_ERROR:
      printf("sendto errno %d", ping->stop_data); break;

    case SCAMPER_PING_STOP_HALTED:
      printf("halted"); break;

    default:
      printf("reason 0x%02x data 0x%02x",
	      ping->stop_reason, ping->stop_data);
      break;
    }
  printf("\n");

  for(i=0; i<ping->ping_sent; i++)
    {
      for(reply = ping->ping_replies[i]; reply != NULL; reply = reply->next)
	{
	  dump_ping_reply(ping, reply);
	}
    }

  printf("\n");

  scamper_ping_free(ping);

  return;
}

static void dump_dealias_probedef(scamper_dealias_probedef_t *def)
{
  scamper_dealias_probedef_icmp_t *icmp;
  char dst[128], src[128];

  printf(" probedef %d: dst: %s, ttl: %d, tos: 0x%02x\n  src: %s",
	 def->id,
	 scamper_addr_tostr(def->dst, dst, sizeof(dst)),
	 def->ttl, def->tos,
	 scamper_addr_tostr(def->src, src, sizeof(src)));
  if(def->size > 0)
    printf(", size: %d", def->size);
  if(def->mtu > 0)
    printf(", mtu: %d", def->mtu);
  printf("\n");

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def))
    {
      icmp = &def->un.icmp;
      printf("  icmp-echo csum: %04x, id: %04x\n", icmp->csum, icmp->id);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    {
      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP)
	printf("  udp");
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)
	printf("  udp-dport");
      else
	printf("  udp-%d", def->method);
      printf(" %d:%d\n", def->un.udp.sport, def->un.udp.dport);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    {
      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	printf("  tcp-ack");
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT)
	printf("  tcp-ack-sport");
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_SYN_SPORT)
	printf("  tcp-syn-sport");
      else
	printf("  tcp-%d", def->method);
      printf(" %d:%d ", def->un.tcp.sport, def->un.tcp.dport);
      dump_tcp_flags(def->un.tcp.flags);
      printf("\n");
    }
  else
    {
      printf("%d\n", def->method);
    }
  return;
}

static void dump_dealias(scamper_dealias_t *dealias)
{
  scamper_dealias_prefixscan_t *ps = dealias->data;
  scamper_dealias_mercator_t *mercator = dealias->data;
  scamper_dealias_radargun_t *radargun = dealias->data;
  scamper_dealias_ally_t *ally = dealias->data;
  scamper_dealias_bump_t *bump = dealias->data;
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply;
  struct timeval rtt;
  uint32_t i;
  uint16_t u16;
  uint8_t u8;
  char buf[256];
  int j;

  /* first line: dealias */
  printf("dealias");
  if(dealias->method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      scamper_addr_tostr(mercator->probedef.src, buf, sizeof(buf));
      printf(" from %s", buf);
      scamper_addr_tostr(mercator->probedef.dst, buf, sizeof(buf));
      printf(" to %s", buf);
    }
  printf("\n");

  /* dump list, cycle, start time */
  dump_list_summary(dealias->list);
  dump_cycle_summary(dealias->cycle);
  printf(" user-id: %d\n", dealias->userid);
  dump_timeval("start", &dealias->start);

  /* method headers */
  printf(" method: ");
  if(dealias->method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      printf("mercator, attempts: %d, timeout: %ds\n",
	     mercator->attempts, mercator->wait_timeout);
      dump_dealias_probedef(&mercator->probedef);
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_ALLY)
    {
      printf("ally, attempts: %d, fudge: %d, "
	     "wait-probe: %dms, wait-timeout: %ds",
	     ally->attempts,ally->fudge,ally->wait_probe,ally->wait_timeout);
      if(SCAMPER_DEALIAS_ALLY_IS_NOBS(dealias))
	printf(", nobs");
      printf("\n");

      dump_dealias_probedef(&ally->probedefs[0]);
      dump_dealias_probedef(&ally->probedefs[1]);
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_BUMP)
    {
      printf("bump, attempts: %d, wait-probe: %dms, bump-limit: %d\n",
	     bump->attempts, bump->wait_probe, bump->bump_limit);
      dump_dealias_probedef(&bump->probedefs[0]);
      dump_dealias_probedef(&bump->probedefs[1]);
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    {
      printf("radargun, wait-probe: %dms, wait-round: %dms\n"
	     "  wait-timeout: %ds, attempts: %d, probedefc: %d\n",
	     radargun->wait_probe, radargun->wait_round,
	     radargun->wait_timeout, radargun->attempts, radargun->probedefc);
      if((u8 = radargun->flags) != 0)
	{
	  printf("  flags: ");
	  for(i=0; i<8; i++)
	    {
	      if((u8 & (1 << i)) == 0)
		continue;
	      switch(1 << i)
		{
		case SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE:
		  printf("shuffle");
		  break;

		default:
		  printf("0x%02x", 1<<i);
		  break;
		}

	      u8 &= ~(1 << i);
	      if(u8 != 0)
		printf(", ");
	      else
		break;
	    }
	  printf("\n");
	}
      for(i=0; i<radargun->probedefc; i++)
	dump_dealias_probedef(&radargun->probedefs[i]);
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    {
      printf("prefixscan, %s:",
	     scamper_addr_tostr(ps->a, buf, sizeof(buf)));
      printf("%s/%d",
	     scamper_addr_tostr(ps->b, buf, sizeof(buf)), ps->prefix);
      if(ps->ab != NULL)
	printf(", alias: %s/%d",
	       scamper_addr_tostr(ps->ab, buf, sizeof(buf)),
	       scamper_addr_prefixhosts(ps->b, ps->ab));
      printf("\n");

      printf("  attempts: %d, replyc: %d, fudge: %d, wait-probe: %dms, "
	     "wait-timeout: %ds", ps->attempts, ps->replyc, ps->fudge,
	     ps->wait_probe, ps->wait_timeout);
      if(SCAMPER_DEALIAS_PREFIXSCAN_IS_NOBS(dealias))
	printf(", nobs");
      printf("\n");
      if(ps->xc > 0)
	{
	  printf("  exclude:");
	  for(u16=0; u16<ps->xc; u16++)
	    printf(" %s", scamper_addr_tostr(ps->xs[u16], buf, sizeof(buf)));
	  printf("\n");
	}
      for(i=0; i<ps->probedefc; i++)
	dump_dealias_probedef(&ps->probedefs[i]);
    }
  else
    {
      printf("%d\n", dealias->method);
    }

  printf(" probes: %d, result: %s", dealias->probec,
	 scamper_dealias_result_tostr(dealias, buf, sizeof(buf)));

  if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN &&
     ps->flags & SCAMPER_DEALIAS_PREFIXSCAN_FLAG_CSA)
    printf(", csa");
  printf("\n");

  for(i=0; i<dealias->probec; i++)
    {
      probe = dealias->probes[i];
      printf(" probe: %d, def: %d, seq: %d, tx: %d.%06d",
	     i, probe->def->id, probe->seq,
	     (int)probe->tx.tv_sec, (int)probe->tx.tv_usec);
      if(SCAMPER_ADDR_TYPE_IS_IPV4(probe->def->dst))
	printf(", ipid: %04x", probe->ipid);
      printf("\n");

      for(j=0; j<probe->replyc; j++)
	{
	  reply = probe->replies[j];
	  timeval_diff_tv(&rtt, &probe->tx, &reply->rx);
	  printf("  reply: %d, src: %s, ttl: %d, rtt: %d.%06d",
		 j, scamper_addr_tostr(reply->src, buf, sizeof(buf)),
		 reply->ttl, (int)rtt.tv_sec, (int)rtt.tv_usec);
	  if(SCAMPER_ADDR_TYPE_IS_IPV4(reply->src))
	    printf(", ipid: %04x", reply->ipid);
	  else if(reply->flags & SCAMPER_DEALIAS_REPLY_FLAG_IPID32)
	    printf(", ipid32: %08x", reply->ipid32);
	  printf("\n");

	  if(SCAMPER_DEALIAS_REPLY_IS_ICMP(reply))
	    {
	      printf("  icmp-type: %d, icmp-code: %d",
		     reply->icmp_type, reply->icmp_code);

	      if(SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH(reply) ||
		 SCAMPER_DEALIAS_REPLY_IS_ICMP_TTL_EXP(reply))
		{
		  printf(", icmp-q-ttl: %d", reply->icmp_q_ip_ttl);
		}
	      printf("\n");
	    }
	  else if(SCAMPER_DEALIAS_REPLY_IS_TCP(reply))
	    {
	      printf("   tcp flags:");
	      dump_tcp_flags(reply->tcp_flags);
	      printf("\n");
	    }
	  else
	    {
	      printf("  reply proto %d\n", reply->proto);
	    }
	}
    }

  printf("\n");

  scamper_dealias_free(dealias);
  return;
}

static void dump_neighbourdisc(scamper_neighbourdisc_t *nd)
{
  scamper_neighbourdisc_probe_t *probe;
  scamper_neighbourdisc_reply_t *reply;
  struct timeval rtt;
  uint16_t i, j;
  char a[64], b[64];

  printf("neighbourdisc\n");
  dump_list_summary(nd->list);
  dump_cycle_summary(nd->cycle);
  printf(" user-id: %d\n", nd->userid);
  dump_timeval("start", &nd->start);

  if(nd->method == SCAMPER_NEIGHBOURDISC_METHOD_ARP ||
     nd->method == SCAMPER_NEIGHBOURDISC_METHOD_ND_NSOL)
    {
      if(nd->method == SCAMPER_NEIGHBOURDISC_METHOD_ARP)
	printf(" method: arp");
      else
	printf(" method: ipv6 nsol");

      printf(", attempts: %d, wait: %ds, replyc: %d, iface: %s\n",
	     nd->attempts, nd->wait, nd->replyc, nd->ifname);
      printf(" our-mac: %s\n",
	     scamper_addr_tostr(nd->src_mac, a, sizeof(a)));
      printf(" flags: 0x%02x", nd->flags);
      if(nd->flags != 0)
	{
	  printf(" (");
	  if(nd->flags & SCAMPER_NEIGHBOURDISC_FLAG_ALLATTEMPTS)
	    printf(" all-attempts");
	  if(nd->flags & SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE)
	    printf(" first-response");
	  printf(" )");
	}
      printf("\n");
      printf(" query:  who-has %s tell %s\n",
	     scamper_addr_tostr(nd->dst_ip,  a, sizeof(a)),
	     scamper_addr_tostr(nd->src_ip,  b, sizeof(b)));
      printf(" result: %s is-at %s\n", a,
	     scamper_addr_tostr(nd->dst_mac, b, sizeof(b)));
    }

  for(i=0; i<nd->probec; i++)
    {
      probe = nd->probes[i];
      printf(" probe: %d, tx: %d.%06d\n",
	     i, (int)probe->tx.tv_sec, (int)probe->tx.tv_usec);

      for(j=0; j<probe->rxc; j++)
	{
	  reply = probe->rxs[j];
	  timeval_diff_tv(&rtt, &probe->tx, &reply->rx);
	  printf("  reply: %d, rtt: %d.%06d, mac: %s\n",
		 i, (int)rtt.tv_sec, (int)rtt.tv_usec,
		 scamper_addr_tostr(reply->mac, a, sizeof(a)));
	}
    }

  printf("\n");

  scamper_neighbourdisc_free(nd);
  return;
}

static void tbit_bits_print(uint32_t flags,int bits, const char **f2s,int f2sc)
{
  int i, f = 0;
  uint32_t u32;

  if(flags == 0)
    return;
  for(i=0; i<bits; i++)
    {
      if((u32 = flags & (0x1 << i)) == 0) continue;
      if(f > 0) printf(",");
      if(i < f2sc)
	printf(" %s", f2s[i]);
      else
	printf(" 0x%x", u32);
      f++;
    }
  return;
}

static uint32_t tbit_isnoff(uint32_t isn, uint32_t seq)
{
  if(seq >= isn)
    return seq - isn;
  return TCP_MAX_SEQNUM - isn + seq + 1;
}

static void dump_tbit(scamper_tbit_t *tbit)
{
  static const char *tbit_options[] = {"tcpts", "sack"};
  static const char *null_options[] = {"tcpts", "ipts-syn", "iprr-syn",
				       "ipqs-syn", "sack", "fo", "fo-exp"};
  static const char *null_results[] = {"tcpts-ok", "sack-ok", "fo-ok"};
  scamper_tbit_pmtud_t *pmtud;
  scamper_tbit_null_t *null;
  scamper_tbit_icw_t *icw;
  scamper_tbit_blind_t *blind;
  scamper_tbit_app_http_t *http;
  scamper_tbit_app_bgp_t *bgp;
  scamper_tbit_pkt_t *pkt;
  struct timeval diff;
  uint32_t i;
  uint16_t len, u16, datalen;
  uint8_t proto, flags, iphlen, tcphlen, mf, ecn, u8, *tmp, txsyn, rxsyn;
  uint32_t seq, ack, server_isn, client_isn, off, u32;
  char src[64], dst[64], buf[128], ipid[12], fstr[32], tfstr[32], sack[64];
  uint8_t cookie[16];
  char *str;
  size_t soff;
  int frag;

  /* Start dumping the tbit test information */
  printf("tbit from %s to %s\n",
	 scamper_addr_tostr(tbit->src, src, sizeof(src)),
	 scamper_addr_tostr(tbit->dst, dst, sizeof(dst)));

  dump_list_summary(tbit->list);
  dump_cycle_summary(tbit->cycle);
  printf(" user-id: %d\n", tbit->userid);
  dump_timeval("start", &tbit->start);

  printf(" sport: %d, dport: %d\n", tbit->sport, tbit->dport);
  printf(" client-mss: %d, server-mss: %d, ttl: %u",
	 tbit->client_mss, tbit->server_mss, tbit->ttl);
  if(tbit->wscale > 0)
    printf(", wscale: %u", tbit->wscale);
  printf("\n");
  printf(" type: %s,", scamper_tbit_type2str(tbit, buf, sizeof(buf)));
  printf(" result: %s\n", scamper_tbit_res2str(tbit, buf, sizeof(buf)));
  if(tbit->options != 0)
    {
      printf(" options:");
      tbit_bits_print(tbit->options, 32, tbit_options,
		      sizeof(tbit_options) / sizeof(char *));
      printf("\n");
    }

  if(tbit->fo_cookielen > 0)
    {
      printf(" fo-cookie: ");
      for(u8=0; u8<tbit->fo_cookielen; u8++)
	printf("%02x", tbit->fo_cookie[u8]);
      printf("\n");
    }

  if(tbit->type == SCAMPER_TBIT_TYPE_PMTUD && tbit->data != NULL)
    {
      pmtud = tbit->data;
      printf(" mtu: %d, ptb-retx: %d", pmtud->mtu, pmtud->ptb_retx);
      if(pmtud->ptbsrc != NULL)
	printf(", ptb-src: %s",
	       scamper_addr_tostr(pmtud->ptbsrc, src, sizeof(src)));
      if(pmtud->options & SCAMPER_TBIT_PMTUD_OPTION_BLACKHOLE)
	printf(", blackhole");
      printf("\n");
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_NULL && tbit->data != NULL)
    {
      null = tbit->data;
      if(null->options != 0)
	{
	  printf(" null-options:");
	  tbit_bits_print(null->options, 16, null_options,
			  sizeof(null_options) / sizeof(char *));
	  printf("\n");
	}
      if(null->results != 0)
	{
	  printf(" results:");
	  tbit_bits_print(null->results, 16, null_results,
			  sizeof(null_results) / sizeof(char *));
	  printf("\n");

	  if((null->results & SCAMPER_TBIT_NULL_RESULT_FO) &&
	     scamper_tbit_fo_getcookie(tbit, cookie, &u8) != 0)
	    {
	      printf(" fo-cookie: ");
	      for(i=0; i<u8; i++)
		printf("%02x", cookie[i]);
	      printf("\n");
	    }
	}
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_ICW &&
	  tbit->result == SCAMPER_TBIT_RESULT_ICW_SUCCESS)
    {
      icw = tbit->data;
      printf(" icw-start-seq: %u", icw->start_seq);
      if(scamper_tbit_icw_size(tbit, &u32) == 0)
	printf(", icw-size: %u bytes", u32);
      printf("\n");
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_RST ||
	  tbit->type == SCAMPER_TBIT_TYPE_BLIND_SYN ||
	  tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA)
    {
      blind = tbit->data;
      printf(" blind: offset %d, retx %u\n", blind->off, blind->retx);
    }

  if(tbit->app_proto == SCAMPER_TBIT_APP_HTTP && tbit->app_data != NULL)
    {
      http = tbit->app_data;
      printf(" app: http");
      if(http->type == SCAMPER_TBIT_APP_HTTP_TYPE_HTTPS)
	str = "https";
      else
	str = "http";

      if(http->host != NULL && http->file != NULL)
	printf(", url: %s://%s%s", str, http->host, http->file);
      else if(http->host != NULL)
	printf(", url: %s://%s", str, http->host);
      else
	printf(", file: %s", http->file);
      printf("\n");
    }
  else if(tbit->app_proto == SCAMPER_TBIT_APP_BGP && tbit->app_data != NULL)
    {
      bgp = tbit->app_data;
      printf(" app: bgp, asn: %u\n", bgp->asn);
    }

  client_isn = 0;
  server_isn = 0;
  txsyn      = 0;
  rxsyn      = 0;

  for(i=0; i<tbit->pktc; i++)
    {
      pkt = tbit->pkts[i];
      frag = 0; mf = 0; off = 0;
      ipid[0] = '\0';

      if((pkt->data[0] >> 4) == 4)
        {
	  iphlen = (pkt->data[0] & 0xf) * 4;
	  len = bytes_ntohs(pkt->data+2);
	  proto = pkt->data[9];
	  ecn = pkt->data[1] & 0x3;
	  if(pkt->data[6] & 0x20)
	    mf = 1;
	  off = (bytes_ntohs(pkt->data+6) & 0x1fff) * 8;
	  if(mf != 0 || off != 0)
	    frag = 1;
	  snprintf(ipid, sizeof(ipid), "%04x", bytes_ntohs(pkt->data+4));
        }
      else if((pkt->data[0] >> 4) == 6)
        {
	  iphlen = 40;
	  len = bytes_ntohs(pkt->data+4) + iphlen;
	  proto = pkt->data[6];
	  ecn = (pkt->data[1] & 0x30) >> 4;

	  for(;;)
            {
	      switch(proto)
                {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		  proto = pkt->data[iphlen+0];
		  iphlen += (pkt->data[iphlen+1] * 8) + 8;
		  continue;

		case IPPROTO_FRAGMENT:
		  if(pkt->data[iphlen+3] & 0x1)
		    mf = 1;
		  off = (bytes_ntohs(pkt->data+iphlen+2) & 0xfff8);
		  snprintf(ipid, sizeof(ipid), "%x",
			   bytes_ntohl(pkt->data+iphlen+4));
		  proto = pkt->data[iphlen+0];
		  iphlen += 8;
		  frag = 1;
		  continue;
                }
	      break;
            }
        }
      else
	{
	  continue;
	}

      timeval_diff_tv(&diff, &tbit->start, &pkt->tv);
      printf(" [%3d.%03d] %s ", (int)diff.tv_sec, (int)(diff.tv_usec / 1000),
	     pkt->dir == SCAMPER_TBIT_PKT_DIR_TX ? "TX" : "RX");

      if(frag != 0)
	snprintf(fstr,sizeof(fstr),":%u%s", off, mf != 0 ? " MF" : "");
      else
	fstr[0] = '\0';

      if(off != 0)
	{
	  printf("%13s %4dF%17s%s%s", "", len, "", ipid, fstr);
	}
      else if(proto == IPPROTO_TCP)
        {
	  seq     = bytes_ntohl(pkt->data+iphlen+4);
	  ack     = bytes_ntohl(pkt->data+iphlen+8);
	  flags   = pkt->data[iphlen+13];
	  tcphlen = ((pkt->data[iphlen+12] & 0xf0) >> 4) * 4;

	  soff = 0; tfstr[0] = '\0';
	  if(flags & 0x2)
            {
	      if(flags & 0x10)
                {
		  if(rxsyn == 0)
		    {
		      server_isn = seq;
		      rxsyn = 1;
		    }
		  string_concat(tfstr, sizeof(tfstr), &soff, "SYN/ACK");
                }
	      else
                {
		  if(txsyn == 0)
		    {
		      client_isn = seq;
		      txsyn = 1;
		    }
		  string_concat(tfstr, sizeof(tfstr), &soff, "SYN");
                }
            }
	  else if(flags & 0x1)
	    string_concat(tfstr, sizeof(tfstr), &soff, "FIN");
	  else if(flags & 0x4)
	    string_concat(tfstr, sizeof(tfstr), &soff, "RST");

	  if(flags & 0x40)
	    string_concat(tfstr, sizeof(tfstr), &soff, "%sECE",
			  soff != 0 ? "/" : "");
	  if(flags & 0x80)
	    string_concat(tfstr, sizeof(tfstr), &soff, "%sCWR",
			  soff != 0 ? "/" : "");

	  /* parse TCP options for sack blocks */
	  u8 = 20; soff = 0; sack[0] = '\0';
	  while(u8 < tcphlen)
	    {
	      tmp = pkt->data + iphlen + u8;

	      if(tmp[0] == 0) /* end of option list */
		break;

	      if(tmp[0] == 1) /* nop */
		{
		  u8++;
		  continue;
		}

	      if(tmp[1] == 0 || u8 + tmp[1] > tcphlen)
		break;

	      /* sack edges */
	      if(tmp[0] == 5 &&
		 (tmp[1]==10 || tmp[1]==18 || tmp[1]==26 || tmp[1]==34))
		{
		  if(pkt->dir == SCAMPER_TBIT_PKT_DIR_TX)
		    u32 = server_isn;
		  else
		    u32 = client_isn;

		  string_concat(sack, sizeof(sack), &soff, " {");
		  for(u16=0; u16<(tmp[1]-2)/8; u16++)
		    string_concat(sack, sizeof(sack), &soff, "%s%u:%u",
				  u16 != 0 ? "," : "",
				  bytes_ntohl(tmp+2+(u16*8)) - u32,
				  bytes_ntohl(tmp+2+(u16*8)+4) - u32);
		  string_concat(sack, sizeof(sack), &soff, "}");
		}

	      u8 += tmp[1];
	    }

	  if(pkt->dir == SCAMPER_TBIT_PKT_DIR_TX)
            {
	      seq = tbit_isnoff(client_isn, seq);
	      ack = tbit_isnoff(server_isn, ack);
            }
	  else
            {
	      if(!(seq == 0 && (flags & TH_RST) != 0))
		seq = tbit_isnoff(server_isn, seq);
	      ack = tbit_isnoff(client_isn, ack);
            }

	  datalen = len - iphlen - tcphlen;

	  printf("%-13s %4d%s", tfstr, len, frag != 0 ? "F" : " ");
	  soff = 0;
	  string_concat(buf, sizeof(buf), &soff, " %u", seq);
	  if(flags & TH_ACK)
	    string_concat(buf, sizeof(buf), &soff, ":%u", ack);
	  if(datalen != 0)
	    string_concat(buf, sizeof(buf), &soff, "(%d)", datalen);
	  printf("%-17s%s", buf, ipid);
	  if(frag != 0) printf("%s", fstr);
	  if(datalen > 0 && (pkt->data[0] >> 4) == 4 && pkt->data[6] & 0x40)
	    printf(" DF");
	  if(ecn == 3)      printf(" CE");
	  else if(ecn != 0) printf(" ECT");
	  printf("%s", sack);
        }
      else if(proto == IPPROTO_ICMP)
        {
	  if(pkt->data[iphlen+0] == 3 && pkt->data[iphlen+1] == 4)
	    {
	      u16 = bytes_ntohs(pkt->data+iphlen+6);
	      printf("%-13s %4d  mtu = %d", "PTB", len, u16);
	    }
        }
      else if(proto == IPPROTO_ICMPV6)
        {
	  if(pkt->data[iphlen+0] == 2)
	    {
	      u32 = bytes_ntohl(pkt->data+iphlen+4);
	      printf("%-13s %4d  mtu = %d", "PTB", len, u32);
	    }
	}

      printf("\n");
    }

  fprintf(stdout,"\n");

  scamper_tbit_free(tbit);
  return;
}

static void dump_sting(scamper_sting_t *sting)
{
  scamper_sting_pkt_t *pkt;
  struct timeval diff;
  char src[64], dst[64], buf[32], ipid[12], tfstr[32], *dir;
  uint32_t i, seq, ack, server_isn, client_isn;
  uint16_t len, datalen;
  uint8_t proto, flags, iphlen, tcphlen;
  size_t tfoff;

  printf("sting from %s to %s\n",
	 scamper_addr_tostr(sting->src, src, sizeof(src)),
	 scamper_addr_tostr(sting->dst, dst, sizeof(dst)));

  dump_list_summary(sting->list);
  dump_cycle_summary(sting->cycle);
  printf(" user-id: %d\n", sting->userid);
  dump_timeval("start", &sting->start);
  printf(" sport: %d, dport: %d\n", sting->sport, sting->dport);
  printf(" count: %d, mean: %dus, inter: %dus, seqskip %d\n",
	 sting->count, sting->mean, sting->inter, sting->seqskip);
  printf(" synretx: %d, dataretx: %d\n", sting->synretx, sting->dataretx);
  printf(" dataackc: %d, holec: %d\n", sting->dataackc, sting->holec);
  printf(" hs-rtt: %d.%06d\n",
	 (int)sting->hsrtt.tv_sec, (int)sting->hsrtt.tv_usec);

  printf(" result: ");
  if(sting->result == SCAMPER_STING_RESULT_NONE)
    printf("none");
  else if(sting->result == SCAMPER_STING_RESULT_COMPLETED)
    printf("completed");
  else
    printf("0x%02x", sting->result);
  printf("\n");

  client_isn = 0;
  server_isn = 0;

  for(i=0; i<sting->pktc; i++)
    {
      pkt = sting->pkts[i];

      if((pkt->data[0] >> 4) == 4)
        {
	  iphlen = (pkt->data[0] & 0xf) * 4;
	  len = bytes_ntohs(pkt->data+2);
	  proto = pkt->data[9];
	  snprintf(ipid, sizeof(ipid), " %04x", bytes_ntohs(pkt->data+4));
	}
      else if((pkt->data[0] >> 4) == 6)
        {
	  iphlen = 40;
	  len = bytes_ntohs(pkt->data+4) + iphlen;
	  proto = pkt->data[6];
	  ipid[0] = '\0';

	  for(;;)
            {
	      switch(proto)
                {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		  proto = pkt->data[iphlen+0];
		  iphlen += (pkt->data[iphlen+1] * 8) + 8;
		  continue;

		case IPPROTO_FRAGMENT:
		  proto = pkt->data[iphlen+0];
		  iphlen += 8;
		  continue;
                }
	      break;
            }
        }
      else continue;

      if(proto != IPPROTO_TCP)
	continue;

      timeval_diff_tv(&diff, &sting->start, &pkt->tv);
      if(pkt->flags & SCAMPER_STING_PKT_FLAG_TX) dir = "TX";
      else if(pkt->flags & SCAMPER_STING_PKT_FLAG_RX) dir = "RX";
      else dir = "??";

      printf(" [%3d.%03d] %s ",(int)diff.tv_sec,(int)(diff.tv_usec/1000),dir);

      seq     = bytes_ntohl(pkt->data+iphlen+4);
      ack     = bytes_ntohl(pkt->data+iphlen+8);
      flags   = pkt->data[iphlen+13];
      tcphlen = ((pkt->data[iphlen+12] & 0xf0) >> 4) * 4;

      tfoff = 0;
      if(flags & 0x2)
	{
	  if(flags & 0x10)
	    {
	      server_isn = seq;
	      string_concat(tfstr, sizeof(tfstr), &tfoff, "SYN/ACK");
	    }
	  else
	    {
	      client_isn = seq;
	      string_concat(tfstr, sizeof(tfstr), &tfoff, "SYN");
	    }
	}
      else if(flags & 0x1)
	string_concat(tfstr, sizeof(tfstr), &tfoff, "FIN");
      else if(flags & 0x4)
	string_concat(tfstr, sizeof(tfstr), &tfoff, "RST");

      if(flags & 0x40)
	string_concat(tfstr, sizeof(tfstr), &tfoff, "%sECE",
		      tfoff != 0 ? "/" : "");
      if(flags & 0x80)
	string_concat(tfstr, sizeof(tfstr), &tfoff, "%sCWR",
		      tfoff != 0 ? "/" : "");
      if(tfoff == 0)
	tfstr[0] = '\0';

      if(pkt->flags & SCAMPER_STING_PKT_FLAG_TX)
	{
	  seq = tbit_isnoff(client_isn, seq);
	  ack = tbit_isnoff(server_isn, ack);
	}
      else
	{
	  seq = tbit_isnoff(server_isn, seq);
	  ack = tbit_isnoff(client_isn, ack);
	}

      datalen = len - iphlen - tcphlen;

      printf("%-13s %4d", tfstr, len);
      if(datalen != 0)
	snprintf(buf, sizeof(buf), " seq = %u:%u(%d)", seq, ack, datalen);
      else
	snprintf(buf, sizeof(buf), " seq = %u:%u", seq, ack);
      printf("%-23s%s\n", buf, ipid);
    }

  scamper_sting_free(sting);
  return;
}

static void dump_sniff(scamper_sniff_t *sniff)
{
  scamper_sniff_pkt_t *pkt;
  struct timeval tv;
  uint8_t u8, *ptr;
  uint32_t i, j;
  int k;
  char src[64], dst[64], buf[32], *str;

  printf("sniff %s\n", scamper_addr_tostr(sniff->src, src, sizeof(src)));
  dump_list_summary(sniff->list);
  dump_cycle_summary(sniff->cycle);
  printf(" user-id: %d\n", sniff->userid);
  dump_timeval("start", &sniff->start);
  dump_timeval("finish", &sniff->finish);
  printf(" limit-pktc: %d, limit-time: %d, icmp-id %d\n",
	 sniff->limit_pktc, sniff->limit_time, sniff->icmpid);
  switch(sniff->stop_reason)
    {
    case SCAMPER_SNIFF_STOP_NONE: str = "none"; break;
    case SCAMPER_SNIFF_STOP_ERROR: str = "error"; break;
    case SCAMPER_SNIFF_STOP_LIMIT_TIME: str = "limit-time"; break;
    case SCAMPER_SNIFF_STOP_LIMIT_PKTC: str = "limit-pktc"; break;
    case SCAMPER_SNIFF_STOP_HALTED: str = "halted"; break;
    default:
      snprintf(buf, sizeof(buf), "%d", sniff->stop_reason);
      str = buf;
      break;
    }
  printf(" result: %s, pktc: %d\n", str, sniff->pktc);

  for(i=0; i<sniff->pktc; i++)
    {
      pkt = sniff->pkts[i];
      timeval_diff_tv(&tv, &sniff->start, &pkt->tv);
      printf(" %3d %d.%06d", i, (int)tv.tv_sec, (int)tv.tv_usec);
      u8 = (pkt->data[0] & 0xf0) >> 4;
      if(u8 == 4)
	{
	  printf(" %s -> %s",
		 inet_ntop(AF_INET, pkt->data+12, src, sizeof(src)),
		 inet_ntop(AF_INET, pkt->data+16, dst, sizeof(dst)));
	}
      else if(u8 == 6)
	{
	  printf(" %s -> %s",
		 inet_ntop(AF_INET6, pkt->data+8,  src, sizeof(src)),
		 inet_ntop(AF_INET6, pkt->data+24, dst, sizeof(dst)));
	}
      printf("\n");

      ptr = pkt->data;
      for(j=0; j+16<=pkt->len; j+=16)
	{
	  printf("     0x%04x: ", j);
	  for(k=0; k<8; k++)
	    {
	      printf(" %02x%02x", ptr[0], ptr[1]);
	      ptr += 2;
	    }
	  printf("\n");
	}
      if(pkt->len - j != 0)
	{
	  printf("     0x%04x: ", j);
	  while(j<pkt->len)
	    {
	      if((j % 2) == 0)
		printf(" ");
	      printf("%02x", *ptr);
	      ptr++;
	      j++;
	    }
	  printf("\n");
	}
    }

  return;
}

static void dump_host_rr(scamper_host_rr_t *rr, const char *section)
{
  char buf[256];

  printf("  %s: %s %u ", section,
	 rr->name != NULL ? rr->name : "<null>", rr->ttl);

  if(rr->class == SCAMPER_HOST_CLASS_IN)
    printf("IN");
  else
    printf("%d", rr->class);
  printf(" ");
  switch(rr->type)
    {
    case SCAMPER_HOST_TYPE_A: printf("A"); break;
    case SCAMPER_HOST_TYPE_NS: printf("NS"); break;
    case SCAMPER_HOST_TYPE_CNAME: printf("CNAME"); break;
    case SCAMPER_HOST_TYPE_SOA: printf("SOA"); break;
    case SCAMPER_HOST_TYPE_PTR: printf("PTR"); break;
    case SCAMPER_HOST_TYPE_MX: printf("MX"); break;
    case SCAMPER_HOST_TYPE_TXT: printf("TXT"); break;
    case SCAMPER_HOST_TYPE_AAAA: printf("AAAA"); break;
    case SCAMPER_HOST_TYPE_DS: printf("DS"); break;
    case SCAMPER_HOST_TYPE_SSHFP: printf("SSHFP"); break;
    case SCAMPER_HOST_TYPE_RRSIG: printf("RRISG"); break;
    case SCAMPER_HOST_TYPE_NSEC: printf("NSEC"); break;
    case SCAMPER_HOST_TYPE_DNSKEY: printf("DNSKEY"); break;
    default: printf("%d", rr->type); break;
    }

  switch(scamper_host_rr_data_type(rr))
    {
    case SCAMPER_HOST_RR_DATA_TYPE_ADDR:
      printf(" %s", scamper_addr_tostr(rr->un.addr, buf, sizeof(buf)));
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_STR:
      printf(" %s", rr->un.str);
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_MX:
      printf(" %d %s", rr->un.mx->preference, rr->un.mx->exchange);
      break;
    }

  printf("\n");
  return;
}

static void dump_host(scamper_host_t *host)
{
  scamper_host_query_t *query;
  struct timeval tv;
  char buf[256];
  uint32_t i, j;

  printf("host from %s", scamper_addr_tostr(host->src, buf, sizeof(buf)));
  printf(" to %s\n", scamper_addr_tostr(host->dst, buf, sizeof(buf)));
  dump_list_summary(host->list);
  dump_cycle_summary(host->cycle);
  printf(" user-id: %d\n", host->userid);
  dump_timeval("start", &host->start);

  if(host->flags != 0)
    {
      printf(" flags: ");
      if(host->flags & SCAMPER_HOST_FLAG_NORECURSE)
	printf("norecurse");
      printf("\n");	
    }

  printf(" wait: %ums, retries: %u\n", host->wait, host->retries);
  printf(" stop: ");
  switch(host->stop)
    {
    case SCAMPER_HOST_STOP_NONE: printf("none"); break;
    case SCAMPER_HOST_STOP_DONE: printf("done"); break;
    case SCAMPER_HOST_STOP_TIMEOUT: printf("timeout"); break;
    case SCAMPER_HOST_STOP_HALTED: printf("halted"); break;
    case SCAMPER_HOST_STOP_ERROR: printf("error"); break;
    default: printf("%04x", host->stop); break;
    }
  printf("\n");

  printf(" qname: %s, qclass: %d, qtype: ", host->qname, host->qclass);
  switch(host->qtype)
    {
    case SCAMPER_HOST_TYPE_A: printf("A"); break;
    case SCAMPER_HOST_TYPE_NS: printf("NS"); break;
    case SCAMPER_HOST_TYPE_CNAME: printf("CNAME"); break;
    case SCAMPER_HOST_TYPE_SOA: printf("SOA"); break;
    case SCAMPER_HOST_TYPE_PTR: printf("PTR"); break;
    case SCAMPER_HOST_TYPE_MX: printf("MX"); break;
    case SCAMPER_HOST_TYPE_TXT: printf("TXT"); break;
    case SCAMPER_HOST_TYPE_AAAA: printf("AAAA"); break;
    case SCAMPER_HOST_TYPE_DS: printf("DS"); break;
    case SCAMPER_HOST_TYPE_SSHFP: printf("SSHFP"); break;
    case SCAMPER_HOST_TYPE_RRSIG: printf("RRSIG"); break;
    case SCAMPER_HOST_TYPE_NSEC: printf("NSEC"); break;
    case SCAMPER_HOST_TYPE_DNSKEY: printf("DNSKEY"); break;
    default: printf("%04x", host->qtype); break;
    }
  printf("\n");
  printf(" qcount: %d\n", host->qcount);

  for(i=0; i<host->qcount; i++)
    {
      query = host->queries[i];
      timeval_diff_tv(&tv, &host->start, &query->tx);
      printf(" query: %u, id: %u, tx: %d.%06d", i, query->id,
	     (int)tv.tv_sec, (int)tv.tv_usec);
      timeval_diff_tv(&tv, &query->tx, &query->rx);
      printf(", rtt: %d.%06d", (int)tv.tv_sec, (int)tv.tv_usec);
      printf(", an: %u, ns: %u, ar: %u", query->ancount, query->nscount,
	     query->arcount);
      printf("\n");

      for(j=0; j<query->ancount; j++)
	dump_host_rr(query->an[j], "an");
      for(j=0; j<query->nscount; j++)
	dump_host_rr(query->ns[j], "ns");
      for(j=0; j<query->arcount; j++)
	dump_host_rr(query->ar[j], "ar");
    }

  printf("\n");
  return;
}

static void dump_cycle(scamper_cycle_t *cycle, const char *type)
{
  time_t tt;
  char buf[32];

  if(strcmp(type, "start") == 0 || strcmp(type, "def") == 0)
    tt = cycle->start_time;
  else
    tt = cycle->stop_time;

  memcpy(buf, ctime(&tt), 24); buf[24] = '\0';

  printf("cycle %s, list %s %d, cycle %d, time %s\n",
	 type, cycle->list->name, cycle->list->id, cycle->id, buf);
  scamper_cycle_free(cycle);
  return;
}

static void dump_list(scamper_list_t *list)
{
  printf("list id %d, name %s", list->id, list->name);
  if(list->descr != NULL) printf(", descr \"%s\"", list->descr);
  printf("\n");
  scamper_list_free(list);
  return;
}

static void dump_addr(scamper_addr_t *addr)
{
  char buf[128];
  printf("addr %s\n", scamper_addr_tostr(addr, buf, sizeof(buf)));
  scamper_addr_free(addr);
  return;
}

int main(int argc, char *argv[])
{
  scamper_file_t        *file;
  scamper_file_filter_t *filter;
  uint16_t filter_types[] = {
    SCAMPER_FILE_OBJ_LIST,
    SCAMPER_FILE_OBJ_CYCLE_START,
    SCAMPER_FILE_OBJ_CYCLE_DEF,
    SCAMPER_FILE_OBJ_CYCLE_STOP,
    SCAMPER_FILE_OBJ_TRACE,
    SCAMPER_FILE_OBJ_PING,
    SCAMPER_FILE_OBJ_TRACELB,
    SCAMPER_FILE_OBJ_DEALIAS,
    SCAMPER_FILE_OBJ_NEIGHBOURDISC,
    SCAMPER_FILE_OBJ_TBIT,
    SCAMPER_FILE_OBJ_STING,
    SCAMPER_FILE_OBJ_SNIFF,
    SCAMPER_FILE_OBJ_HOST,
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

  if((filter = scamper_file_filter_alloc(filter_types, filter_cnt)) == NULL)
    {
      usage();
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
	    case SCAMPER_FILE_OBJ_ADDR:
	      dump_addr(data);
	      break;

	    case SCAMPER_FILE_OBJ_TRACE:
	      dump_trace(data);
	      break;

	    case SCAMPER_FILE_OBJ_PING:
	      dump_ping(data);
	      break;

	    case SCAMPER_FILE_OBJ_TRACELB:
	      dump_tracelb(data);
	      break;

	    case SCAMPER_FILE_OBJ_DEALIAS:
	      dump_dealias(data);
	      break;

	    case SCAMPER_FILE_OBJ_NEIGHBOURDISC:
	      dump_neighbourdisc(data);
	      break;

	    case SCAMPER_FILE_OBJ_TBIT:
	      dump_tbit(data);
	      break;

	    case SCAMPER_FILE_OBJ_STING:
	      dump_sting(data);
	      break;

	    case SCAMPER_FILE_OBJ_SNIFF:
	      dump_sniff(data);
	      break;

	    case SCAMPER_FILE_OBJ_HOST:
	      dump_host(data);
	      break;

	    case SCAMPER_FILE_OBJ_LIST:
	      dump_list(data);
	      break;

	    case SCAMPER_FILE_OBJ_CYCLE_START:
	      dump_cycle(data, "start");
	      break;

	    case SCAMPER_FILE_OBJ_CYCLE_STOP:
	      dump_cycle(data, "stop");
	      break;

	    case SCAMPER_FILE_OBJ_CYCLE_DEF:
	      dump_cycle(data, "def");
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
