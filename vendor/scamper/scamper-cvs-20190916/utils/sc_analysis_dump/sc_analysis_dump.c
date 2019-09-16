/*
 * sc_analysis_dump
 *
 * $Id: sc_analysis_dump.c,v 1.60 2019/01/13 07:35:11 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2013 The Regents of the University of California
 * Copyright (C) 2012      Matthew Luckie
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
  "$Id: sc_analysis_dump.c,v 1.60 2019/01/13 07:35:11 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_file.h"
#include "scamper_icmpext.h"
#include "trace/scamper_trace.h"
#include "mjl_splaytree.h"
#include "utils.h"

#define OPT_SKIP          0x00001
#define OPT_DEBUG         0x00002
#define OPT_DSTEND        0x00004
#define OPT_OLDFORMAT     0x00008
#define OPT_HIDECOMMENTS  0x00010
#define OPT_HIDESRC       0x00020
#define OPT_HIDEDST       0x00040
#define OPT_HIDELIST      0x00080
#define OPT_HIDECYCLE     0x00100
#define OPT_HIDETIME      0x00200
#define OPT_HIDEREPLY     0x00400
#define OPT_HIDEHALT      0x00800
#define OPT_HIDEPATH      0x01000
#define OPT_HIDEIRTT      0x02000
#define OPT_HELP          0x04000
#define OPT_SHOWUSERID    0x08000
#define OPT_SHOWQTTL      0x10000
#define OPT_SHOWMPLS      0x20000
#define OPT_SHOWIPTTL     0x40000

static uint32_t options = 0;

static int skip_numlines = 0;
static int debug_numlines = 0;

/* the input warts files */
static char **filelist = NULL;
static int    filelist_len = 0;

/* where the output goes.  stdout by default */
static FILE *out = NULL;

#ifdef HAVE_NETACUITY
#define OPT_GEO           0x08000
#define OPT_GEOSERV       0x10000
static char               *geo_serv = NULL;
static struct splaytree_t *geo_seen = NULL;
#endif

static void usage(void)
{
  fprintf(stderr,
	  "usage: sc_analysis_dump [-oeCsdlctrHpighUQMT]\n"
	  "                        [-S skip count] [-D debug count]\n"
	  "                        [-G geo server] [file1 file2 ... fileN]\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  int i, ch;
  char opts[48];
  snprintf(opts, sizeof(opts), "oeCsdlctrHpiS:D:?UQMT");

#ifdef HAVE_NETACUITY
  strcat(opts, "gG:");
#endif

  while((i = getopt(argc, argv, opts)) != -1)
    {
      ch = (char)i;
      switch(ch)
	{
	case 'S':
	  options |= OPT_SKIP;
	  skip_numlines = atoi(optarg);
	  break;

	case 'D':
	  options |= OPT_DEBUG;
	  debug_numlines = atoi(optarg);
	  break;

	case 'e':
	  options |= OPT_DSTEND;
	  break;

	case 'o':
	  options |= OPT_OLDFORMAT;
	  break;

	case 'C':
	  options |= OPT_HIDECOMMENTS;
	  break;

	case 's':
	  options |= OPT_HIDESRC;
	  break;

	case 'd':
	  options |= OPT_HIDEDST;
	  break;

	case 'l':
	  options |= OPT_HIDELIST;
	  break;

	case 'c':
	  options |= OPT_HIDECYCLE;
	  break;

	case 't':
	  options |= OPT_HIDETIME;
	  break;

	case 'r':
	  options |= OPT_HIDEREPLY;
	  break;

	case 'H':
	  options |= OPT_HIDEHALT;
	  break;

	case 'p':
	  options |= OPT_HIDEPATH;
	  break;

	case 'i':
	  options |= OPT_HIDEIRTT;
	  break;

	case 'U':
	  options |= OPT_SHOWUSERID;
	  break;

	case 'Q':
	  options |= OPT_SHOWQTTL;
	  break;

	case 'M':
	  options |= OPT_SHOWMPLS;
	  break;

	case 'T':
	  options |= OPT_SHOWIPTTL;
	  break;

#ifdef HAVE_NETACUITY
	case 'g':
	  options |= OPT_GEO;
	  break;

	case 'G':
	  options |= OPT_GEOSERV;
	  geo_serv = optarg;
	  break;
#endif

	case '?':
	  options |= OPT_HELP;
	  break;

	default:
	  usage();
	  return -1;
	}
    }

  filelist = argv + optind;
  filelist_len = argc - optind;

  return 0;
}

static char *rtt_tostr(char *str, const size_t len, const struct timeval *rtt)
{
  if(rtt != NULL)
    {
      snprintf(str, len, "%ld.%03d",
	       (long)((rtt->tv_sec * 1000) + (rtt->tv_usec / 1000)),
	       (int)(rtt->tv_usec % 1000));
    }
  else
    {
      str[0] = '\0';
    }

  return str;
}

static void print_help()
{
  usage();
  fprintf(stderr,
  "  This program prints out scamper warts and skitter arts traces.\n"
  "  C - hide comments\n"
  "  o - old format version 1.0\n"
  "  s - hide Source \n"
  "  d - hide Destination \n"
  "  l - hide list number\n"
  "  c - hide cycle number\n"
  "  U - show userid number\n"
  "  t - hide Timestamp \n"
  "  r - hide Reply Fields\n"
  "     DestReplied, DestRTT, RequestTTL, ReplyTTL \n"
  "  H - hide Halt Fields \n"
  "      HaltReason, HaltReasonData\n"
  "  p - hide Path Fields \n"
  "      PathComplete, PerHopData\n"
  "  i - hides hop non IP data\n"
  "      HopRTT, HopNumTries\n"
  "  M - show MPLS headers recorded in ICMP extension headers\n"
  "  Q - show quoted IP-TTL in response\n"
  "  T - show IP-TTL in response\n"
  "\n"
  "  e - add Destination to Ending\n"
  "\n"
  "  D numline - debug mode that only reads the first numline objects\n"
  "  S numline - skips first numline objects in the file\n"
  "\n"
#ifdef HAVE_NETACUITY
  "  g - print out geographical information\n"
  "      assuming that environmental variable NETACUITY_SERVER is set\n"
  "      to the NETACUITY server\n"
  "  G servername - the same as g except it uses the servername\n"
  "      given on the command line.\n"
  " \n"
#endif
  "  ? - prints this message\n"
  " \n"
 );

  return;
}


static void print_header_comments(void)
{
  uint32_t u32;
  int i = 1;
  char buf[64], buf2[64], buf3[256];
  size_t off;

  printf(
 "# =======================================================================\n"
 "# This file contains an ASCII representation of the IP paths stored in\n"
 "# the binary skitter arts++ and scamper warts file formats.\n"
 "#\n"
 "# This ASCII file format is in the sk_analysis_dump text output\n"
 "# format: imdc.datcat.org/format/1-003W-7\n"
 "#\n"
 "# =======================================================================\n"
 "# There is one trace per line, with the following tab-separated fields:\n"
 "#\n"
 "#\n");

  if((options & OPT_OLDFORMAT) == 0)
    {
      printf(
 "# %2d. Key -- Indicates the type of line and determines the meaning of the\n"
 "#            remaining fields.  This will always be 'T' for an IP trace.\n"
 "#\n", i++);

      u32 = (OPT_HIDESRC|OPT_HIDEDST|OPT_HIDELIST|OPT_HIDECYCLE|OPT_HIDETIME);
      if((options & u32) != u32 || (options & OPT_SHOWUSERID) != 0)
	printf(
 "# -------------------- Header Fields ------------------\n"
 "#\n");

      if((options & OPT_HIDESRC) == 0)
	printf(
 "# %2d. Source -- Source IP of skitter/scamper monitor performing the trace.\n"
 "#\n", i++);

      if((options & OPT_HIDEDST) == 0)
	printf(
 "# %2d. Destination -- Destination IP being traced.\n"
 "#\n", i++);

      if((options & OPT_HIDELIST) == 0)
	printf(
 "# %2d. ListId -- ID of the list containing this destination address.\n"
 "#\n"
 "#        This value will be zero if no list ID was provided.  (uint32_t)\n"
 "#\n", i++);

      if((options & OPT_HIDECYCLE) == 0)
	printf(
 "# %2d. CycleId -- ID of current probing cycle (a cycle is a single run\n"
 "#                through a given list).  For skitter traces, cycle IDs\n"
 "#                will be equal to or slightly earlier than the timestamp\n"
 "#                of the first trace in each cycle. There is no standard\n"
 "#                interpretation for scamper cycle IDs.\n"
 "#\n"
 "#        This value will be zero if no cycle ID was provided.  (uint32_t)\n"
 "#\n", i++);

      if((options & OPT_SHOWUSERID) != 0)
	printf(
 "# %2d. UserId -- ID provided by the user for this trace.\n"
 "#\n"
 "#        This value will be zero if no user ID was provided.  (uint32_t)\n"
 "#\n", i++);

      if((options & OPT_HIDETIME) == 0)
	printf(
 "# %2d. Timestamp -- Timestamp when trace began to this destination.\n"
 "#\n", i++);

      if((options & OPT_HIDEREPLY) == 0)
	{
	  printf(
 "# -------------------- Reply Fields ------------------\n"
 "#\n"
 "# %2d. DestReplied -- Whether a response from the destination was received.\n"
 "#\n"
 "#        R - Replied, reply was received\n"
 "#        N - Not-replied, no reply was received;\n"
 "#            Since skitter sends a packet with a TTL of 255 when it halts\n"
 "#            probing, it is still possible for the final destination to\n"
 "#            send a reply and for the HaltReasonData (see below) to not\n"
 "#            equal no_halt.  Note: scamper does not perform last-ditch\n"
 "#            probing at TTL 255 by default.\n"
 "#\n", i++);

	  printf(
 "# %2d. DestRTT -- RTT (ms) of first response packet from destination.\n"
 "#        0 if DestReplied is N.\n"
 "#\n", i++);

	  printf(
 "# %2d. RequestTTL -- TTL set in request packet which elicited a response\n"
 "#      (echo reply) from the destination.\n"
 "#        0 if DestReplied is N.\n"
 "#\n", i++);

	  printf(
 "# %2d. ReplyTTL -- TTL found in reply packet from destination;\n"
 "#        0 if DestReplied is N.\n"
 "#\n", i++);
	}

      if((options & OPT_HIDEHALT) == 0)
	{
	  printf(
 "# -------------------- Halt Fields ------------------\n"
 "#\n"
 "# %2d. HaltReason -- The reason, if any, why incremental probing stopped.\n"
 "#\n", i++);

	  printf(
 "# %2d. HaltReasonData -- Extra data about why probing halted.\n"
 "#\n"
 "#        HaltReason            HaltReasonData\n"
 "#        ------------------------------------\n"
 "#        S (success/no_halt)    0\n"
 "#        U (icmp_unreachable)   icmp_code\n"
 "#        L (loop_detected)      loop_length\n"
 "#        G (gap_detected)       gap_limit\n"
 "#\n", i++);
	}
    }

  if((options & OPT_HIDEPATH) == 0)
    {
      printf(
 "# -------------------- Path Fields ------------------\n"
 "#\n"
 "# %2d. PathComplete -- Whether all hops to destination were found.\n"
 "#\n"
 "#        C - Complete, all hops found\n"
 "#        I - Incomplete, at least one hop is missing (i.e., did not\n"
 "#            respond)\n"
 "#\n", i++);

      printf(
 "# %2d. PerHopData -- Response data for the first hop.\n"
 "#\n"
 "#       If multiple IP addresses respond at the same hop, response data\n"
 "#       for each IP address are separated by semicolons:\n"
 "#\n", i++);

      off = 0;
      string_concat(buf, sizeof(buf), &off, "IP");
      if((options & OPT_HIDEIRTT) == 0)
	string_concat(buf, sizeof(buf), &off, ",RTT,nTries");
      if((options & OPT_SHOWQTTL) != 0)
	string_concat(buf, sizeof(buf), &off, ",Q|quoted-TTL");
      if((options & OPT_SHOWMPLS) != 0)
	string_concat(buf, sizeof(buf), &off, ",M|ttl|label|exp|s");
      if((options & OPT_SHOWIPTTL) != 0)
	string_concat(buf, sizeof(buf), &off, ",T|IP-TTL");

      snprintf(buf2, sizeof(buf2),
	       "#       %%-%ds %%s\n", (int)((off*2) + 5));
      printf(buf2, buf, "(for only one responding IP)");

      snprintf(buf3, sizeof(buf3), "%s;%s;...", buf, buf);
      printf(buf2, buf3, "(for multiple responding IPs)");

      printf(
 "#\n"
 "#         where\n"
 "#\n"
 "#       IP -- IP address which sent a TTL expired packet\n");
      if((options & OPT_HIDEIRTT) == 0)
	{
	  printf(
 "#       RTT -- RTT of the TTL expired packet\n"
 "#       nTries -- number of tries before response received from hop\n");
	}
      if((options & OPT_SHOWQTTL) != 0)
	{
	  printf(
 "#       qTTL -- the IP-TTL in the quoted packet ('-' if not present)\n");
	}
      if((options & OPT_SHOWMPLS) != 0)
	{
	  printf(
 "#       ttl   -- the TTL in the MPLS header\n"
 "#       label -- the label in the MPLS header\n"
 "#       exp   -- the value of the 3 Exp bits in the MPLS header\n"
 "#       s     -- the value of the 'S' bit in the MPLS header\n");
	}

      printf(
 "#\n"
 "#       This field will have the value 'q' if there was no response at\n"
 "#       this hop.\n"
 "#\n");

      printf(
 "# %2d. PerHopData -- Response data for the second hop in the same format\n"
 "#       as field %d.\n", i, i-1);

      printf(
 "#\n"
 "# ...\n"
 "#\n");

      if(options & OPT_DSTEND)
	{
	  printf(
 "#  N. PerHopData -- Response data for the destination\n"
 "#       (if destination replied).\n"
 "#\n"
		 );
	}
    }

  return;
}

static void print_header_fields(const scamper_trace_t *trace)
{
  char  buf[256];

  if((options & OPT_HIDESRC) == 0)
    fprintf(out, "\t%s", scamper_addr_tostr(trace->src, buf, sizeof(buf)));

  if((options & OPT_HIDEDST) == 0)
    fprintf(out, "\t%s", scamper_addr_tostr(trace->dst, buf, sizeof(buf)));

  if((options & OPT_HIDELIST) == 0)
    fprintf(out, "\t%d", (trace->list != NULL) ? trace->list->id : 0);

  if((options & OPT_HIDECYCLE) == 0)
    fprintf(out, "\t%d", (trace->cycle != NULL) ? trace->cycle->id : 0);

  if((options & OPT_SHOWUSERID) != 0)
    fprintf(out, "\t%d", trace->userid);

  if((options & OPT_HIDETIME) == 0)
    fprintf(out, "\t%ld", (long)trace->start.tv_sec);

  return;
}

static void print_reply_fields(const scamper_trace_hop_t *dst)
{
  char rtt[64];

  if(dst != NULL)
    {
      rtt_tostr(rtt, sizeof(rtt), &dst->hop_rtt);
      fprintf(out, "\tR\t%s\t%d\t%d",
	      rtt, dst->hop_probe_ttl, dst->hop_reply_ttl);
    }
  else
    {
      fprintf(out, "\tN\t0\t0\t0");
    }

  return;
}

static void print_halt_fields(const scamper_trace_t *trace)
{
  int l;

  switch(trace->stop_reason)
    {
    case SCAMPER_TRACE_STOP_COMPLETED:
    case SCAMPER_TRACE_STOP_NONE:
      fprintf(out, "\tS\t0");
      break;

    case SCAMPER_TRACE_STOP_UNREACH:
      fprintf(out, "\tU\t%d", trace->stop_data);
      break;

    case SCAMPER_TRACE_STOP_LOOP:
      if((l = trace->stop_data) == 0)
	{
	  l = scamper_trace_loop(trace, 1, NULL, NULL);
	}
      fprintf(out, "\tL\t%d", l);
      break;

    case SCAMPER_TRACE_STOP_GAPLIMIT:
      fprintf(out, "\tG\t%d", trace->stop_data);
      break;

    default:
      fprintf(out, "\t?\t0");
      break;
    }
  return;
}

static void print_old_fields(const scamper_trace_t *trace,
			     const scamper_trace_hop_t *hop)
{
  char src[256], dst[256], rtt[256];

  fprintf(out, " %s %s %ld %s %d",
	  scamper_addr_tostr(trace->src, src, sizeof(src)),
	  scamper_addr_tostr(trace->dst, dst, sizeof(dst)),
	  (long)trace->start.tv_sec,
	  rtt_tostr(rtt, sizeof(rtt), (hop != NULL) ? &hop->hop_rtt : NULL),
	  trace->hop_count);

  return;
}

static char *hop_tostr(const scamper_trace_hop_t *hop, char *buf, size_t len)
{
  const scamper_icmpext_t *ie;
  char rtt[128], addr[128];
  size_t off = 0;
  int i;

  string_concat(buf, len, &off, "%s",
		scamper_addr_tostr(hop->hop_addr, addr, sizeof(addr)));

  if((options & OPT_HIDEIRTT) == 0)
    string_concat(buf, len, &off, ",%s,%d",
		  rtt_tostr(rtt, sizeof(rtt), &hop->hop_rtt),
		  hop->hop_probe_id);

  if((options & OPT_SHOWQTTL) != 0 && SCAMPER_TRACE_HOP_IS_ICMP_Q(hop))
    string_concat(buf, len, &off, ",Q|%d", hop->hop_icmp_q_ttl);

  if((options & OPT_SHOWIPTTL) != 0)
    string_concat(buf, len, &off, ",T|%d", hop->hop_reply_ttl);

  if((options & OPT_SHOWMPLS) != 0)
    {
      for(ie=hop->hop_icmpext; ie != NULL; ie = ie->ie_next)
	{
	  if(SCAMPER_ICMPEXT_IS_MPLS(ie))
	    {
	      for(i=0; i<SCAMPER_ICMPEXT_MPLS_COUNT(ie); i++)
		{
		  string_concat(buf, len, &off, ",M|%d|%d|%d|%d",
				SCAMPER_ICMPEXT_MPLS_TTL(ie, i),
				SCAMPER_ICMPEXT_MPLS_LABEL(ie, i),
				SCAMPER_ICMPEXT_MPLS_EXP(ie, i),
				SCAMPER_ICMPEXT_MPLS_S(ie, i));
		}
	    }
	}
    }

  return buf;
}

static void print_path_fields(const scamper_trace_t *trace,
			      const scamper_trace_hop_t *dst)
{
  scamper_trace_hop_t *hop;
  char buf[256], path_complete;
  int i, unresponsive = 0;

#ifdef HAVE_NETACUITY
  if((options & OPT_GEO) != 0 && trace->hop_count != 0)
    {
      for(i=0; i<trace->hop_count; i++)
	{
	  for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
	    print_geo_info(hop->hop_addr);
	}
    }
#endif

  /*
   * decide what the path_complete flag should be set to.  if we reached
   * the destination then the path_complete flag == 'C' (for complete).
   * otherwise the path_complete flag == 'I' (incomplete) or 'N' if
   * using the old sk_analysis_dump output format.
   */
  path_complete = 'I';
  if(dst != NULL)
    {
      for(i=0; i<dst->hop_probe_ttl; i++)
	if(trace->hops[i] == NULL)
	  break;

      if(i == dst->hop_probe_ttl && (options & OPT_OLDFORMAT) == 0)
	path_complete = 'C';
    }
  else if(options & OPT_OLDFORMAT)
    {
      path_complete = 'N';
    }

  /*
   * actually output the path complete flag, and some extra old fields
   * if requested
   */
  if((options & OPT_OLDFORMAT) == 0)
    {
      fprintf(out, "\t%c", path_complete);
    }
  else
    {
      fprintf(out, "%c", path_complete);
      print_old_fields(trace, dst);
    }

  for(i=0; i<trace->hop_count; i++)
    {
      if((hop = trace->hops[i]) != NULL)
	{
	  /* don't print out the hop corresponding to the destination */
	  if(hop == dst)
	    {
	      if(hop->hop_next == NULL)
		break;
	      else
		hop = hop->hop_next;
	    }

	  while(unresponsive > 0)
	    {
	      fprintf(out, "%c", options & OPT_OLDFORMAT ? ' ' : '\t');
	      fprintf(out, "q");
	      unresponsive--;
	    }

	  fprintf(out, "%c", options & OPT_OLDFORMAT ? ' ' : '\t');

	  for(;;)
	    {
	      if((options & OPT_OLDFORMAT) == 0)
		fprintf(out, "%s", hop_tostr(hop, buf, sizeof(buf)));

	      if((hop = hop->hop_next) != NULL && hop != dst)
		{
		  if((options & OPT_OLDFORMAT) == 0)
		    fprintf(out, ";");
		  else
		    fprintf(out, ",");
		}
	      else break;
	    }
	}
      else
	{
	  unresponsive++;
	}
    }

  if(dst != NULL && options & OPT_DSTEND)
    {
      while (i < dst->hop_probe_ttl-1)
        {
	  i++;
          fprintf(out, "\tq");
	}

      fprintf(out, "\t%s", hop_tostr(dst, buf, sizeof(buf)));
    }

  return;
}

#ifdef HAVE_NETACUITY
static int print_geo_info(scamper_addr_t *addr)
{
  na_geo_struct answer;
  char buf[256];

  if(splaytree_find(geo_seen, addr) != NULL)
    {
      return 0;
    }

  if(splaytree_insert(geo_seen, scamper_addr_use(addr)) != 1)
    {
      return -1;
    }

  if(scamper_addr_tostr(addr, buf, sizeof(buf)) == NULL)
    {
      return -1;
    }

  if(na_query_geo(buf, &answer))
    {
      fprintf(out, "G\t%s\t%s=%d\t%s=%d\t%s=%d\t%s\t%d\t%.3f\t%.3f\n",
	      buf,
	      answer.country, answer.country_c,
	      answer.region, answer.region_c,
	      answer.city, answer.city_c,
	      answer.speed,
	      answer.metro_code,
	      answer.latitude, answer.longitude);
    }
  else
    {
      fprintf(stderr, "Error in na_query_geo(%s)\n", buf);
    }

  return 0;
}

static void print_path_geo_info(const scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  int i;

  for(i=0; i<trace->hop_count; i++)
    {
      for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
	{
	  print_geo_info(hop->hop_addr);
	}
    }

  return;
}

static int setup_netacuity_server(char *server)
{
  struct addrinfo hints, *res, *res0;
  char buf[256];
  int set = 0;

  memset(&hints, 0, sizeof(hints));

  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_family   = AF_INET;

  if((error = getaddrinfo(ipstr, NULL, &hints, &res0)) != 0 || res0 == NULL)
    {
      fprintf(stderr, "could not resolve %s: %s", server, gai_strerror(error));
      return -1;
    }

  for(res = res0; res != NULL; res = res->ai_next)
    {
      if(res->ai_family == PF_INET)
	{
	  inet_ntop(res->ai_family,
		    &((struct sockaddr_in *)ai_list->ai_addr)->sin_addr,
		    buf, sizeof(buf));

	  if(na_api_set_server_addr(buf))
	    {
	      set = 1;
	      break;
	    }
	  else
	    {
	      fprintf(stderr, "Error in setting server addr %s", buf);
	    }
	}
    }

  freeaddrinfo(res0);

  if(set == 1)
    {
      geo_seen = splaytree_alloc((splaytree_cmp_t)scamper_addr_cmp);
      if(geo_seen == NULL)
	{
	  return -1;
	}

      return 0;
    }

  return -1;
}

#endif /* HAVE_NETACUITY */

static void print_trace(const scamper_trace_t *trace)
{
  scamper_trace_hop_t *dst = NULL, *hop;
  int i;

  if(trace->hop_count == 0 &&
     trace->stop_reason == SCAMPER_TRACE_STOP_ERROR)
    {
      return;
    }

  /* try and determine the hop that corresponds to the destination */
  if(trace->hop_count > 0 &&
     trace->stop_reason != SCAMPER_TRACE_STOP_ERROR)
    {
      for(i=trace->hop_count-1; i>=0 && dst == NULL; i--)
	{
	  for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
	    {
	      if(SCAMPER_TRACE_HOP_IS_ICMP_UNREACH_PORT(hop))
		{
		  if(SCAMPER_TRACE_TYPE_IS_UDP(trace) ||
		     SCAMPER_TRACE_TYPE_IS_TCP(trace))
		    {
		      dst = hop;
		      break;
		    }
		}

	      if(SCAMPER_TRACE_HOP_IS_ICMP_ECHO_REPLY(hop))
		{
		  if(SCAMPER_TRACE_TYPE_IS_ICMP(trace))
		    {
		      dst = hop;
		      break;
		    }
		}

	      if((hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) != 0 &&
		 SCAMPER_TRACE_TYPE_IS_TCP(trace))
		{
		  dst = hop;
		  break;
		}

	    }
	}
    }

#ifdef HAVE_NETACUITY
  if(options & OPT_GEO)
    {
      if((options & OPT_HIDESRC) == 0)
	{
	  print_geo_info(trace->src);
	}
      if((options & OPT_HIDEDST) == 0)
	{
	  print_geo_info(trace->dst);
	}
      if((options & OPT_HIDEPATH) == 0)
	{
	  print_path_geo_info(trace);
	}
    }
#endif

  if((options & OPT_OLDFORMAT) == 0)
    {
      fprintf(out, "T");
      print_header_fields(trace);

      if((options & OPT_HIDEREPLY) == 0)
	{
	  print_reply_fields(dst);
	}

      if((options & OPT_HIDEHALT) == 0)
	{
	  print_halt_fields(trace);
	}
    }

  if((options & OPT_HIDEPATH) == 0 || (options & OPT_OLDFORMAT))
    {
      print_path_fields(trace, dst);
    }

  fprintf(out, "\n");
  fflush(out);

  return;
}

static void process(scamper_file_t *file, scamper_file_filter_t *filter)
{
  scamper_trace_t *trace;
  uint16_t type;
  int n = 0;

  while(scamper_file_read(file, filter, &type, (void *)&trace) == 0)
    {
      if(trace == NULL) break; /* EOF */

      if((options & OPT_DEBUG) && n == debug_numlines)
	{
	  scamper_trace_free(trace);
	  break;
	}

      n++;

      if(n > skip_numlines)
	{
	  print_trace(trace);
	}

      scamper_trace_free(trace);
    }

  scamper_file_close(file);

  return;
}

int main(int argc, char *argv[])
{
  scamper_file_t *file;
  scamper_file_filter_t *filter;
  uint16_t type = SCAMPER_FILE_OBJ_TRACE;
  int i;

#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2,2), &wsaData);
#endif

  out = stdout;

  if(check_options(argc, argv) == -1)
    {
      return -1;
    }
  if(options & OPT_HELP)
    {
      print_help();
      return 0;
    }

  if((filter = scamper_file_filter_alloc(&type, 1)) == NULL)
    {
      return -1;
    }

  if((options & OPT_HIDECOMMENTS) == 0)
    {
      print_header_comments();
    }

  if(filelist_len != 0)
    {
      for(i=0; i<filelist_len; i++)
	{
	  if((file = scamper_file_open(filelist[i], 'r', NULL)) == NULL)
	    {
	      fprintf(stderr, "unable to open %s\n", filelist[i]);
	      if((options & OPT_HIDECOMMENTS) == 0)
		{
		  fprintf(out, "# unable to open %s\n", filelist[i]);
		}

	      continue;
	    }

	  process(file, filter);
	}
    }
  else
    {
      if((file = scamper_file_openfd(STDIN_FILENO, "-", 'r', "warts")) == NULL)
	{
	  fprintf(stderr, "unable to open stdin\n");
	  if((options & OPT_HIDECOMMENTS) == 0)
	    {
	      fprintf(out, "# unable to open stdin\n");
	    }
	}
      else process(file, filter);
    }

  scamper_file_filter_free(filter);

  return 0;
}
