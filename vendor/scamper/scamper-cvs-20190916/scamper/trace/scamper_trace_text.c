/*
 * scamper_trace_text.c
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
 * Author: Matthew Luckie
 *
 * $Id: scamper_trace_text.c,v 1.25 2019/01/13 07:30:21 mjl Exp $
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
  "$Id: scamper_trace_text.c,v 1.25 2019/01/13 07:30:21 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_trace.h"
#include "scamper_file.h"
#include "scamper_trace_text.h"
#include "utils.h"

static char *addr_str(const scamper_addr_t *addr,char *buf,const size_t len)
{
  if(addr != NULL)
    scamper_addr_tostr(addr, buf, len);
  else
    snprintf(buf, len, "*");

  return buf;
}

/*
 * icmp_tostr
 *
 * the caller must pass a pointer to a str buffer at least 14 chars in length
 * to be safe.
 */
static char *icmp_tostr(const scamper_trace_hop_t *hop,
			char *str, const size_t len)
{
  if((hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) != 0)
    {
      if((hop->hop_tcp_flags & TH_RST) != 0)
	{
	  snprintf(str, len, " [closed]");
	}
      else if((hop->hop_tcp_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
	{
	  if((hop->hop_tcp_flags & TH_ECE) != 0)
	    snprintf(str, len, " [open, ecn]");
	  else
	    snprintf(str, len, " [open]");
	}
      else
	{
	  if(hop->hop_tcp_flags == 0)
	    snprintf(str, len, " [unknown, no flags]");
	  else
	    snprintf(str, len, " [unknown,%s%s%s%s%s%s%s%s]",
		     (hop->hop_tcp_flags & TH_RST)  ? " RST" : "",
		     (hop->hop_tcp_flags & TH_SYN)  ? " SYN" : "",
		     (hop->hop_tcp_flags & TH_ACK)  ? " ACK" : "",
		     (hop->hop_tcp_flags & TH_PUSH) ? " PSH" : "",
		     (hop->hop_tcp_flags & TH_FIN)  ? " FIN" : "",
		     (hop->hop_tcp_flags & TH_URG)  ? " URG" : "",
		     (hop->hop_tcp_flags & TH_CWR)  ? " CWR" : "",
		     (hop->hop_tcp_flags & TH_ECE)  ? " ECE" : "");
	}
    }
  else if(SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(hop) ||
	  SCAMPER_TRACE_HOP_IS_ICMP_ECHO_REPLY(hop))
    {
      str[0] = '\0';
    }
  else if(SCAMPER_TRACE_HOP_IS_ICMP(hop) &&
	  hop->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      if(hop->hop_icmp_type == ICMP_UNREACH)
	{
	  switch(hop->hop_icmp_code)
	    {
	    case ICMP_UNREACH_FILTER_PROHIB:
	      snprintf(str, len, " !X");
	      break;

	    case ICMP_UNREACH_HOST:
	      snprintf(str, len, " !H");
	      break;

	    case ICMP_UNREACH_NEEDFRAG:
	      snprintf(str, len, " !F");
	      break;

	    case ICMP_UNREACH_SRCFAIL:
	      snprintf(str, len, " !S");
	      break;

	    case ICMP_UNREACH_PROTOCOL:
	      snprintf(str, len, " !P");
	      break;

	    case ICMP_UNREACH_NET:
	      snprintf(str, len, " !N");
	      break;

	    case ICMP_UNREACH_PORT:
	      str[0] = '\0';
	      break;

	    default:
	      snprintf(str, len, " !<%d>", hop->hop_icmp_code);
	      break;
	    }
	}
      else
	{
	  snprintf(str,len," !<%d,%d>",hop->hop_icmp_type,hop->hop_icmp_code);
	}
    }
  else if(SCAMPER_TRACE_HOP_IS_ICMP(hop) &&
	  hop->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      if(hop->hop_icmp_type == ICMP6_DST_UNREACH)
	{
	  switch(hop->hop_icmp_code)
	    {
	    case ICMP6_DST_UNREACH_ADDR:
	      snprintf(str, len," !A");
	      break;

	    case ICMP6_DST_UNREACH_BEYONDSCOPE:
	      snprintf(str, len," !S");
	      break;

	    case ICMP6_DST_UNREACH_ADMIN:
	      snprintf(str, len," !P");
	      break;

	    case ICMP6_DST_UNREACH_NOROUTE:
	      snprintf(str, len," !N");
	      break;

	    case ICMP6_DST_UNREACH_NOPORT:
	      str[0] = '\0';
	      break;

	    default:
	      snprintf(str, len, " !<%d>", hop->hop_icmp_code);
	      break;
	    }
	}
      else if(hop->hop_icmp_type == ICMP6_PACKET_TOO_BIG)
	{
	  snprintf(str,len," !F");
	}
      else
	{
	  snprintf(str,len," !<%d,%d>",hop->hop_icmp_type,hop->hop_icmp_code);
	}
    }

  return str;
}

/*
 * header_tostr
 *
 */
static char *header_tostr(const scamper_trace_t *trace)
{
  char src[64], dst[64], header[192];

  if(trace->dst == NULL)
    return NULL;
  scamper_addr_tostr(trace->dst, dst, sizeof(dst));

  if(trace->src != NULL)
    {
      scamper_addr_tostr(trace->src, src, sizeof(src));
      snprintf(header, sizeof(header), "traceroute from %s to %s", src, dst);
    }
  else
    {
      snprintf(header, sizeof(header), "traceroute to %s", dst);
    }

  return strdup(header);
}

/*
 * hop_to_str
 *
 * given a hop (with other hops possibly linked to it) create a string that
 * holds the hop.
 */
static char *hop_tostr(const scamper_trace_t *trace, const int h)
{
  scamper_trace_hop_t *hop;
  char    *str = NULL;
  char   **str_addrs = NULL;
  size_t  *len_addrs = NULL;
  char   **str_rtts = NULL;
  size_t  *len_rtts = NULL;
  size_t   len;
  int      i;
  char     str_hop[256];
  char     str_addr[64];
  char     str_rtt[24];
  char     str_icmp[128];
  int      spare;
  int      replyc;

  replyc = 0;
  for(hop=trace->hops[h]; hop != NULL; hop = hop->hop_next)
    replyc++;

  /* if we got no responses at all for this hop */
  if(replyc == 0)
    {
      if((trace->flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS) == 0)
	{
	  snprintf(str_hop, sizeof(str_hop), "%2d  *", h+1);
	  str = strdup(str_hop);
	}
      else if((str = malloc_zero((len = 4 + (2 * trace->attempts)))) != NULL)
	{
	  snprintf(str, len, "%2d  ", h+1);
	  for(i=0; i<trace->attempts; i++)
	    {
	      str[4+(i*2)]   = '*';
	      str[4+(i*2)+1] = ' ';
	    }
	  str[4+((i-1)*2)+1] = '\0';
	}
      return str;
    }
  
  if(replyc == 1)
    {
      hop = trace->hops[h];
      scamper_addr_tostr(hop->hop_addr, str_addr, sizeof(str_addr));
      timeval_tostr_us(&hop->hop_rtt, str_rtt, sizeof(str_rtt));
      icmp_tostr(hop, str_icmp, sizeof(str_icmp));

      snprintf(str_hop, sizeof(str_hop),
	       "%2d  %s  %s ms%s", h+1, str_addr, str_rtt, str_icmp);
      return strdup(str_hop);
    }

  /* we have to print out all of the replies */
  len = sizeof(char *) * replyc;
  if((str_addrs = malloc_zero(len)) == NULL)
    goto out;
  if((str_rtts = malloc_zero(len)) == NULL)
    goto out;

  /* keep track of the length of each string in the arrays */
  len = sizeof(size_t) * replyc;
  if((len_addrs = malloc_zero(len)) == NULL)
    goto out;
  if((len_rtts = malloc_zero(len)) == NULL)
    goto out;

  /* for each response we have, record an entry in the array */
  i = 0;
  for(hop = trace->hops[h]; hop != NULL; hop = hop->hop_next)
    {
      /*
       * calculate the length of the address to record for this hop probe,
       * and then generate and store the string
       */
      addr_str(hop->hop_addr, str_addr, sizeof(str_addr));
      len = strlen(str_addr);
      if((str_addrs[i] = malloc_zero(len+1)) == NULL)
	goto out;
      memcpy(str_addrs[i], str_addr, len+1);
      len_addrs[i] = len;

      /*
       * calculate the length of the rtt and icmp data for this hop probe,
       * and then generate and store the string
       */
      timeval_tostr_us(&hop->hop_rtt, str_rtt, sizeof(str_rtt));
      icmp_tostr(hop, str_icmp, sizeof(str_icmp));
      len = strlen(str_rtt) + 3 + strlen(str_icmp);
      if((str_rtts[i] = malloc_zero(len+1)) == NULL)
	goto out;
      snprintf(str_rtts[i],len+1,"%s ms%s",str_rtt,str_icmp);
      len_rtts[i] = len;

      i++;
    }

  /*
   * go through and figure how long our string should be
   * we reserve 5 characters to start with so that we can print 3 digits
   * hop number + 2 digits space ahead of the hop information.
   */
  len = 5; spare = -1;
  for(i=0; i<replyc; i++)
    {
      /* if no data for this probe, then print '* ' */
      if(str_addrs[i] == NULL)
	{
	  len += 2;
	}
      /*
       * if we've printed an address before, check to see if it is the same
       * as the previous address printed.  if so, we just have to print the
       * rtt and be done
       */
      else if(spare != -1 && strcmp(str_addrs[spare], str_addrs[i]) == 0)
	{
	  len += len_rtts[i] + 2;
	}
      /* print out the IP address and the RTT to the hop */
      else
	{
	  spare = i;
	  len += len_addrs[i] + 2 + len_rtts[i] + 2;
	}
    }

  /* allocate a string long enough to store the hop data */
  if((str = malloc_zero(len)) == NULL)
    goto out;

  /* build the string up */
  snprintf(str, len, "%2d  ", h+1);
  len = strlen(str); spare = -1;
  for(i=0; i<replyc; i++)
    {
      if(str_addrs[i] == NULL)
	{
	  str[len++] = '*'; str[len++] = ' ';
	}
      else if(spare != -1 && strcmp(str_addrs[spare], str_addrs[i]) == 0)
	{
	  memcpy(str+len, str_rtts[i], len_rtts[i]);
	  len += len_rtts[i];
	  str[len++] = ' '; str[len++] = ' ';
	}
      else
	{
	  spare = i;
	  memcpy(str+len, str_addrs[i], len_addrs[i]);
	  len += len_addrs[i];
	  str[len++] = ' '; str[len++] = ' ';
	  memcpy(str+len, str_rtts[i], len_rtts[i]);
	  len += len_rtts[i];
	  str[len++] = ' '; str[len++] = ' ';
	}
    }

  /* cut off the unnecessary trailing white space */
  while(str[len-1] == ' ') len--;
  str[len] = '\0';

 out:

  /* clean up */
  if(str_addrs != NULL)
    {
      for(i=0; i<replyc; i++)
	if(str_addrs[i] != NULL)
	  free(str_addrs[i]);
      free(str_addrs);
    }
  if(str_rtts != NULL)
    {
      for(i=0; i<replyc; i++)
	if(str_rtts[i] != NULL)
	  free(str_rtts[i]);
      free(str_rtts);
    }
  if(len_addrs != NULL) free(len_addrs);
  if(len_rtts != NULL) free(len_rtts);

  return str;
}

static char *mtu_tostr(const int mtu, const int size)
{
  char str[24];
  if(mtu != size)
    snprintf(str, sizeof(str), " [*mtu: %d]", size);
  else
    snprintf(str, sizeof(str), " [mtu: %d]", mtu);
  return strdup(str);
}

static int pmtud_ver1(const scamper_trace_t *trace, char **mtus)
{
  scamper_trace_hop_t *hop;
  uint16_t mtu, size;
  int i;

  /*
   * if we did not get any responses from the path, then the path MTU
   * is zero
   */
  if((hop = trace->pmtud->hops) == NULL)
    {
      mtu = size = trace->pmtud->pmtu;
    }
  else
    {
      mtu = size = trace->pmtud->ifmtu;
      if(trace->pmtud->outmtu != 0)
	size = trace->pmtud->outmtu;
    }

  for(i=0; i<trace->hop_count; i++)
    {
      /* no response for this hop */
      if(trace->hops[i] == NULL)
	{
	  if(mtus[i] != NULL)
	    free(mtus[i]);
	  mtus[i] = NULL;
	  continue;
	}

      /* if there is no pmtud data then skip this bit */
      if(hop == NULL)
	continue;

      /*
       * if this hop has the same address as an ICMP message, then
       * change the MTU to reach the next hop after recording the size
       * of the packet that reached this hop successfully
       */
      if(scamper_addr_cmp(hop->hop_addr, trace->hops[i]->hop_addr) == 0)
	{
	  if((mtus[i] = mtu_tostr(mtu, size)) == NULL)
	    return -1;

	  if(SCAMPER_TRACE_HOP_IS_ICMP_PTB(hop))
	    mtu = hop->hop_icmp_nhmtu;

	  hop = hop->hop_next;
	  if(hop == NULL)
	    size = trace->pmtud->pmtu;
	  else
	    size = hop->hop_probe_size;

	  continue;
	}

      /*
       * if this hop has the same ttl as the probe packet, then the
       * egress interface returned the frag required message.  record
       * the MTU for the current working hop
       */
      if(i >= hop->hop_probe_ttl - hop->hop_icmp_q_ttl)
	{
	  if(SCAMPER_TRACE_HOP_IS_ICMP_PTB(hop))
	    size = mtu = hop->hop_icmp_nhmtu;

	  if((mtus[i] = mtu_tostr(mtu, size)) == NULL)
	    return -1;

	  hop = hop->hop_next;
	  if(hop == NULL)
	    size = trace->pmtud->pmtu;
	  else
	    size = hop->hop_probe_size;

	  continue;
	}

      if((mtus[i] = mtu_tostr(mtu, size)) == NULL)
	return -1;
    }

  return 0;
}

static int pmtud_ver2(const scamper_trace_t *trace, char **mtus)
{
  const scamper_trace_pmtud_t *pmtud = trace->pmtud;
  const scamper_trace_pmtud_n_t *note;
  const scamper_trace_hop_t *hop;
  const scamper_addr_t *ha;
  char buf[256], addr[128];
  size_t off;
  uint16_t mtu, size;
  uint8_t n = 0;
  uint8_t h = 0;
  int i;

  mtu = size = pmtud->ifmtu;

  if(pmtud->outmtu != 0)
    {
      /* the first note should be for a silent first hop */
      assert(pmtud->notec > 0);
      assert(pmtud->notes[0]->hop == NULL);
      assert(pmtud->notes[0]->type == SCAMPER_TRACE_PMTUD_N_TYPE_SILENCE);
      size = pmtud->outmtu;
      n++;
    }

  if(n == pmtud->notec)
    {
      for(h=0; h<trace->hop_count; h++)
	if(trace->hops[h] != NULL && (mtus[h] = mtu_tostr(mtu,size)) == NULL)
	  return -1;

      return 0;
    }

  while(n < pmtud->notec)
    {
      note = pmtud->notes[n]; n++;
      if((hop = note->hop) == NULL)
	{
	  size = note->nhmtu;
	  continue;
	}

      if(note->type == SCAMPER_TRACE_PMTUD_N_TYPE_SILENCE)
	{
	  i = hop->hop_probe_ttl - 1;
	}
      else
	{
	  ha = hop->hop_addr;

	  for(i=h; i<trace->hop_count; i++)
	    {
	      if(trace->hops[i] == NULL)
		continue;
	      if(scamper_addr_cmp(trace->hops[i]->hop_addr, ha) == 0)
		break;
	    }

	  /* kludge to try and figure out which hop to put the PTB on */
	  if(i == trace->hop_count)
	    {
	      i = hop->hop_probe_ttl - hop->hop_icmp_q_ttl;

	      /*
	       * shift the predicted hop back one if the alignment is
	       * analytically unlikely.
	       */
	      if(trace->hops[i] != NULL &&
		 ((ha->type == SCAMPER_ADDR_TYPE_IPV4 &&
		   scamper_addr_prefix(trace->hops[i]->hop_addr,ha) >= 30) ||
		  (ha->type == SCAMPER_ADDR_TYPE_IPV6 &&
		   scamper_addr_prefix(trace->hops[i]->hop_addr,ha) >= 126)))
		i--;

	      /* handle wrap */
	      if(i >= (trace->hop_count-1))
		i = trace->hop_count-2;
	      if(i < 0)
		i = 0;
	    }
	}

      while(h <= i)
	{
	  if(trace->hops[h] != NULL && (mtus[h] = mtu_tostr(mtu,size)) == NULL)
	    return -1;
	  h++;
	}

      if(SCAMPER_TRACE_HOP_IS_ICMP_PTB(hop))
	{
	  if(trace->hops[i] == NULL && (mtus[i] = mtu_tostr(mtu,size)) == NULL)
	    return -1;

	  if(trace->hops[i] == NULL ||
	     scamper_addr_cmp(trace->hops[i]->hop_addr, hop->hop_addr) != 0)
	    scamper_addr_tostr(hop->hop_addr, addr, sizeof(addr));
	  else
	    addr[0] = '\0';

	  if(addr[0] != '\0' || note->nhmtu != hop->hop_icmp_nhmtu)
	    {
	      off = 0;
	      string_concat(buf, sizeof(buf), &off, "%s", mtus[i]);
	      if(addr[0] != '\0')
		string_concat(buf, sizeof(buf), &off, " ptb %s", addr);
	      if(note->nhmtu != hop->hop_icmp_nhmtu)
		string_concat(buf, sizeof(buf), &off, " nhmtu %d!",
			      hop->hop_icmp_nhmtu);

	      free(mtus[i]);
	      if((mtus[i] = strdup(buf)) == NULL)
		return -1;
	    }

	  mtu = hop->hop_icmp_nhmtu;
	}

      size = note->nhmtu;
    }

  while(h < trace->hop_count)
    {
      if(trace->hops[h] != NULL && (mtus[h] = mtu_tostr(mtu,size)) == NULL)
	return -1;
      h++;
    }

  return 0;
}

/*
 * scamper_file_text_trace_write
 *
 * return 0 on successful write, -1 otherwise.
 */
int scamper_file_text_trace_write(const scamper_file_t *sf,
				  const scamper_trace_t *trace)
{
  static int (*const pmtud_tostr[])(const scamper_trace_t *, char **) = {
    NULL,
    pmtud_ver1,
    pmtud_ver2,
  };

  /* current return code */
  int rc = -1;

  /* variables for creating the string representing the trace */
  int      i;
  size_t   off, len;
  char    *str      = NULL;
  char    *header   = NULL;
  char   **hops     = NULL;
  char   **mtus     = NULL;

  /* variables for writing to the file */
  off_t  foff = 0;
  int    fd;
  size_t wc;

  /*
   * get the current offset into the file, incase the write fails and a
   * truncation is required
   */
  fd = scamper_file_getfd(sf);
  if(fd != STDOUT_FILENO && (foff = lseek(fd, 0, SEEK_CUR)) == -1)
    goto cleanup;

  /* get a string that specifies the source and destination of the trace */
  header = header_tostr(trace);
  len = strlen(header) + 2;

  if(trace->hop_count > 0)
    {
      if((hops = malloc_zero(sizeof(char *) * trace->hop_count)) == NULL)
	goto cleanup;

      for(i=0; i < trace->hop_count; i++)
	{
	  if((hops[i] = hop_tostr(trace, i)) == NULL)
	    goto cleanup;
	  len += strlen(hops[i]);
	}

      /* if we have PMTU data to print for the trace, then write it too */
      if(trace->pmtud != NULL &&
	 trace->pmtud->ver >= 1 && trace->pmtud->ver <= 2)
	{
	  if((mtus = malloc_zero(sizeof(char *) * trace->hop_count)) == NULL)
	    goto cleanup;

	  if(pmtud_tostr[trace->pmtud->ver](trace, mtus) != 0)
	    goto cleanup;

	  for(i=0; i<trace->hop_count; i++)
	    if(mtus[i] != NULL)
	      len += strlen(mtus[i]);
	}

      len += trace->hop_count; /* \n on each line */
    }

  len += 1; /* final \0 */

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;

  off = 0;
  string_concat(str, len, &off, "%s\n", header);

  if(hops != NULL)
    {
      for(i=0; i < trace->hop_count; i++)
	{
	  string_concat(str, len, &off, "%s", hops[i]);
	  if(mtus != NULL && mtus[i] != NULL)
	    string_concat(str, len, &off, "%s", mtus[i]);
	  string_concat(str, len, &off, "\n");
	}
    }

  /*
   * try and write the string to disk.  if it fails, then truncate the
   * write and fail
   */
  if(write_wrap(fd, str, &wc, off) != 0)
    {
      if(fd != STDOUT_FILENO)
	{
	  if(ftruncate(fd, foff) != 0)
	    goto cleanup;
	}
      goto cleanup;
    }

  rc = 0; /* we succeeded */

 cleanup:
  if(hops != NULL)
    {
      for(i=0; i<trace->hop_count; i++)
	if(hops[i] != NULL)
	  free(hops[i]);
      free(hops);
    }
  if(mtus != NULL)
    {
      for(i=0; i<trace->hop_count; i++)
	if(mtus[i] != NULL)
	  free(mtus[i]);
      free(mtus);
    }
  if(header != NULL) free(header);
  if(str != NULL) free(str);

  return rc;
}
