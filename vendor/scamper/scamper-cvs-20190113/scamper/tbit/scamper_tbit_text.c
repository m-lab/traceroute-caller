/*
 * scamper_file_text_tbit.c
 *
 * Copyright (C) 2009-2011 The University of Waikato
 * Authors: Ben Stasiewicz, Matthew Luckie
 *
 * $Id: scamper_tbit_text.c,v 1.16 2016/09/17 08:40:13 mjl Exp $
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
  "$Id";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_file.h"
#include "scamper_tbit.h"
#include "scamper_tbit_text.h"
#include "utils.h"

static uint32_t tbit_isnoff(uint32_t isn, uint32_t seq)
{
  if(seq >= isn)
    return seq - isn;
  return TCP_MAX_SEQNUM - isn + seq + 1;
}

int scamper_file_text_tbit_write(const scamper_file_t *sf,
				 const scamper_tbit_t *tbit)
{
  scamper_tbit_pkt_t *pkt;
  scamper_tbit_app_http_t *http;
  char buf[131072], *str;
  char src[64], dst[64], tmp[256], ipid[12], fstr[32], tfstr[32], sack[128];
  struct timeval diff;
  uint32_t i;
  uint32_t seq, ack, server_isn, client_isn, off, u32;
  uint16_t len, u16, datalen;
  uint8_t proto, flags, iphlen, tcphlen, mf, ecn, u8, *ptr;
  size_t soff = 0, toff;
  int frag;
  int fd = scamper_file_getfd(sf);

  string_concat(buf, sizeof(buf), &soff,
		"tbit from %s to %s\n server-mss %d, result: %s\n",
		scamper_addr_tostr(tbit->src, src, sizeof(src)),
		scamper_addr_tostr(tbit->dst, dst, sizeof(dst)),
		tbit->server_mss,
		scamper_tbit_res2str(tbit, tmp, sizeof(tmp)));

  if(tbit->app_proto == SCAMPER_TBIT_APP_HTTP && tbit->app_data != NULL)
    {
      http = tbit->app_data;
      string_concat(buf, sizeof(buf), &soff, " app: http");
      if(http->type == SCAMPER_TBIT_APP_HTTP_TYPE_HTTPS)
	str = "https";
      else
	str = "http";
      if(http->host != NULL && http->file != NULL)
	string_concat(buf, sizeof(buf), &soff, ", url: %s://%s%s",
		      str, http->host, http->file);
      else if(http->host != NULL)
	string_concat(buf, sizeof(buf), &soff, ", url: %s://%s",
		      str, http->host);
      else
	string_concat(buf, sizeof(buf), &soff, ", file: %s", http->file);
      string_concat(buf, sizeof(buf), &soff, "\n");
    }

  client_isn = 0;
  server_isn = 0;

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
	  snprintf(ipid, sizeof(ipid), " %04x", bytes_ntohs(pkt->data+4));
	  off = (bytes_ntohs(pkt->data+6) & 0x1fff) * 8;
	  if(mf != 0 || off != 0)
	    frag = 1;
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
		  snprintf(ipid, sizeof(ipid), "%x",
			   bytes_ntohl(pkt->data+iphlen+4));
		  off = (bytes_ntohs(pkt->data+iphlen+2) & 0xfff8);
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
      string_concat(buf, sizeof(buf), &soff, " [%3d.%03d] %s ",
		    (int)diff.tv_sec, (int)(diff.tv_usec / 1000),
		    pkt->dir == SCAMPER_TBIT_PKT_DIR_TX ? "TX" : "RX");

      if(frag != 0)
	snprintf(fstr,sizeof(fstr),":%u%s", off, mf != 0 ? " MF" : "");
      else
	fstr[0] = '\0';

      if(off != 0)
	{
	  string_concat(buf, sizeof(buf), &soff,
			"%-13s %4dF%22s %s%s", "", len, "", ipid, fstr);
	}
      else if(proto == IPPROTO_TCP)
        {
	  seq     = bytes_ntohl(pkt->data+iphlen+4);
	  ack     = bytes_ntohl(pkt->data+iphlen+8);
	  flags   = pkt->data[iphlen+13];
	  tcphlen = ((pkt->data[iphlen+12] & 0xf0) >> 4) * 4;

	  toff = 0; tfstr[0] = '\0';
	  if(flags & 0x2)
            {
	      if(flags & 0x10)
                {
		  server_isn = seq;
		  string_concat(tfstr, sizeof(tfstr), &toff, "SYN/ACK");
                }
	      else
                {
		  client_isn = seq;
		  string_concat(tfstr, sizeof(tfstr), &toff, "SYN");
                }
            }
	  else if(flags & 0x1)
	    string_concat(tfstr, sizeof(tfstr), &toff, "FIN");
	  else if(flags & 0x4)
	    string_concat(tfstr, sizeof(tfstr), &toff, "RST");
	  if(flags & 0x40)
	    string_concat(tfstr, sizeof(tfstr), &toff, "%sECE",
			  toff != 0 ? "/" : "");
	  if(flags & 0x80)
	    string_concat(tfstr, sizeof(tfstr), &toff, "%sCWR",
			  toff != 0 ? "/" : "");

	  /* parse TCP options for sack blocks */
	  u8 = 20; toff = 0; sack[0] = '\0';
	  while(u8 < tcphlen)
	    {
	      ptr = pkt->data + iphlen + u8;

	      if(ptr[0] == 0) /* end of option list */
		break;

	      if(ptr[0] == 1) /* nop */
		{
		  u8++;
		  continue;
		}

	      if(ptr[1] == 0 || u8 + ptr[1] > tcphlen)
		break;

	      /* sack edges */
	      if(ptr[0] == 5 &&
		 (ptr[1]==10 || ptr[1]==18 || ptr[1]==26 || ptr[1]==34))
		{
		  if(pkt->dir == SCAMPER_TBIT_PKT_DIR_TX)
		    u32 = server_isn;
		  else
		    u32 = client_isn;

		  string_concat(sack, sizeof(sack), &toff, " {");
		  for(u16=0; u16<(ptr[1]-2)/8; u16++)
		    string_concat(sack, sizeof(sack), &toff, "%s%u:%u",
				  u16 != 0 ? "," : "",
				  bytes_ntohl(ptr+2+(u16*8)) - u32,
				  bytes_ntohl(ptr+2+(u16*8)+4) - u32);
		  string_concat(sack, sizeof(sack), &toff, "}");
		}

	      u8 += ptr[1];
	    }

	  if(pkt->dir == SCAMPER_TBIT_PKT_DIR_TX)
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

	  string_concat(buf, sizeof(buf), &soff, "%-13s %4d%s",
			tfstr, len, frag != 0 ? "F" : " ");

	  toff = 0;
	  string_concat(tmp, sizeof(tmp), &toff, " seq = %u:%u", seq, ack);
	  if(datalen != 0)
	    string_concat(tmp, sizeof(tmp), &toff, "(%d)", datalen);
	  string_concat(tmp, sizeof(tmp), &toff, sack);
	  string_concat(buf, sizeof(buf), &soff, "%-23s%s", tmp, ipid);
	  if(frag != 0) string_concat(buf, sizeof(buf), &soff, "%s", fstr);
	  if(datalen > 0 && (pkt->data[0] >> 4) == 4 && pkt->data[6] & 0x40)
	    string_concat(buf, sizeof(buf), &soff, " DF");
	  if(ecn == 3)      string_concat(buf, sizeof(buf), &soff, " CE");
	  else if(ecn != 0) string_concat(buf, sizeof(buf), &soff, " ECT");
        }
      else if(proto == IPPROTO_ICMP)
        {
	  if(pkt->data[iphlen+0] == 3 && pkt->data[iphlen+1] == 4)
	    {
	      u16 = bytes_ntohs(pkt->data+iphlen+6);
	      string_concat(buf, sizeof(buf), &soff,
			    "%-13s %4d  mtu = %d", "PTB", len, u16);
	    }
        }
      else if(proto == IPPROTO_ICMPV6)
        {
	  if(pkt->data[iphlen+0] == 2)
	    {
	      u32 = bytes_ntohl(pkt->data+iphlen+4);
	      string_concat(buf, sizeof(buf), &soff,
			    "%-13s %4d  mtu = %d", "PTB", len, u32);
	    }
	}

      string_concat(buf, sizeof(buf), &soff, "\n");
    }

  write_wrap(fd, buf, NULL, soff);
  return 0;
}
