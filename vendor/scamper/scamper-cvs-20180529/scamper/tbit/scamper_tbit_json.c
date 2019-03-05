/*
 * scamper_tbit_json.c
 *
 * Copyright (c) 2014 Matthew Luckie
 * Copyright (C) 2015 The Regents of the University of California
 *
 * Author: Matthew Luckie
 *
 * $Id: scamper_tbit_json.c,v 1.25 2017/09/27 01:54:18 mjl Exp $
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
  "$Id: scamper_tbit_json.c,v 1.25 2017/09/27 01:54:18 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tbit.h"
#include "scamper_file.h"
#include "scamper_file_json.h"
#include "scamper_tbit_json.h"

#include "utils.h"

typedef struct tbit_state
{
  uint8_t  flags;
  uint32_t client_isn;
  uint32_t server_isn;
} tbit_state_t;

#define TBIT_STATE_FLAG_CISN 0x01
#define TBIT_STATE_FLAG_SISN 0x02

static char *tbit_bits_encode(char *buf, size_t len, uint32_t flags, int bits,
			      const char **f2s, int f2sc)
{
  size_t off =  0;
  int i, f = 0;
  uint32_t u32;

  if(flags == 0)
    return "";
  for(i=0; i<bits; i++)
    {
      if((u32 = flags & (0x1 << i)) == 0) continue;
      if(f > 0) string_concat(buf, len, &off, ",");
      if(i < f2sc)
	string_concat(buf, len, &off, "\"%s\"", f2s[i]);
      else
	string_concat(buf, len, &off, "%u", u32);
      f++;
    }
  return buf;
}

static uint32_t tbit_isnoff(uint32_t isn, uint32_t seq)
{
  if(seq >= isn)
    return seq - isn;
  return TCP_MAX_SEQNUM - isn + seq + 1;
}

static char *tbit_header_tostr(const scamper_tbit_t *tbit,
			       const tbit_state_t *state)
{
  static const char *tbit_options[] = {"tcpts", "sack"};
  static const char *pmtud_options[] = {"blackhole"};
  static const char *null_options[] = {"tcpts", "ipts-syn", "iprr-syn",
				       "ipqs-syn", "sack", "fo", "fo-exp"};
  static const char *null_results[] = {"tcpts-ok", "sack-ok", "fo-ok"};
  char buf[1024], tmp[128], *str;
  size_t off = 0;
  scamper_tbit_pmtud_t *pmtud;
  scamper_tbit_null_t *null;
  scamper_tbit_blind_t *blind;
  scamper_tbit_app_http_t *http;
  scamper_tbit_app_bgp_t *bgp;
  uint32_t u32;
  uint8_t u8;

  string_concat(buf, sizeof(buf), &off,
		"{\"type\":\"tbit\", \"tbit_type\":\"%s\", \"userid\":%u",
		scamper_tbit_type2str(tbit, tmp, sizeof(tmp)),
		tbit->userid);
  string_concat(buf, sizeof(buf), &off, ", \"src\":\"%s\"",
		scamper_addr_tostr(tbit->src, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off, ", \"dst\":\"%s\"",
		scamper_addr_tostr(tbit->dst, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off, ", \"sport\":%u, \"dport\":%u",
		tbit->sport, tbit->dport);
  string_concat(buf, sizeof(buf), &off, ", \"start\":{\"sec\":%u,\"usec\":%u}",
		tbit->start.tv_sec, tbit->start.tv_usec);
  string_concat(buf, sizeof(buf), &off,
		", \"client_mss\":%u, \"server_mss\":%u, \"ttl\":%u",
		tbit->client_mss, tbit->server_mss, tbit->ttl);
  string_concat(buf, sizeof(buf), &off, ", \"result\":\"%s\"",
		scamper_tbit_res2str(tbit, tmp, sizeof(tmp)));
  if(tbit->options != 0)
    string_concat(buf, sizeof(buf), &off, ", \"options\":[%s]",
		  tbit_bits_encode(tmp, sizeof(tmp), tbit->options, 16,
				   tbit_options,
				   sizeof(tbit_options) / sizeof(char *)));

  if(tbit->wscale > 0)
    string_concat(buf, sizeof(buf), &off, ", \"wscale\":%u", tbit->wscale);

  if(tbit->fo_cookielen > 0)
    {
      string_concat(buf, sizeof(buf), &off, ", \"fo_cookie\":\"");
      for(u8=0; u8<tbit->fo_cookielen; u8++)
	string_concat(buf, sizeof(buf), &off, "%02x", tbit->fo_cookie[u8]);
      string_concat(buf, sizeof(buf), &off, "\"");
    }

  if(state->flags & TBIT_STATE_FLAG_CISN)
    string_concat(buf, sizeof(buf), &off,
		  ", \"client_isn\":%u", state->client_isn);
  if(state->flags & TBIT_STATE_FLAG_SISN)
    string_concat(buf, sizeof(buf), &off,
		  ", \"server_isn\":%u", state->server_isn);

  if(tbit->type == SCAMPER_TBIT_TYPE_PMTUD)
    {
      pmtud = tbit->data;
      string_concat(buf, sizeof(buf), &off,
		    ", \"mtu\":%u, \"ptb_retx\":%u",
		    pmtud->mtu, pmtud->ptb_retx);
      if(pmtud->ptbsrc != NULL)
	string_concat(buf, sizeof(buf), &off,
		      ", \"ptbsrc\":\"%s\"",
		      scamper_addr_tostr(pmtud->ptbsrc, tmp, sizeof(tmp)));
      string_concat(buf, sizeof(buf), &off, ", \"pmtud_options\":[%s]",
		    tbit_bits_encode(tmp, sizeof(tmp), pmtud->options, 8,
				     pmtud_options,
				     sizeof(pmtud_options) / sizeof(char *)));
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_NULL)
    {
      null = tbit->data;
      string_concat(buf, sizeof(buf), &off, ", \"null_options\":[%s]",
		    tbit_bits_encode(tmp, sizeof(tmp), null->options, 16,
				     null_options,
				     sizeof(null_options) / sizeof(char *)));
      string_concat(buf, sizeof(buf), &off, ", \"null_results\":[%s]",
		    tbit_bits_encode(tmp, sizeof(tmp), null->results, 16,
				     null_results,
				     sizeof(null_results) / sizeof(char *)));
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_ICW)
    {
      if(tbit->result == SCAMPER_TBIT_RESULT_ICW_SUCCESS &&
	 scamper_tbit_icw_size(tbit, &u32) == 0)
	string_concat(buf, sizeof(buf), &off, ", \"icw_bytes\":%u", u32);
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_RST ||
	  tbit->type == SCAMPER_TBIT_TYPE_BLIND_SYN ||
	  tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA ||
	  tbit->type == SCAMPER_TBIT_TYPE_BLIND_FIN)
    {
      blind = tbit->data;
      string_concat(buf, sizeof(buf), &off,
		    ", \"blind_off\":%d, \"blind_retx\":%u",
		    blind->off, blind->retx);
    }

  if(tbit->app_proto == SCAMPER_TBIT_APP_HTTP && tbit->app_data != NULL)
    {
      http = tbit->app_data;
      string_concat(buf, sizeof(buf), &off, ", \"app\":\"http\"");
      if(http->type == SCAMPER_TBIT_APP_HTTP_TYPE_HTTPS)
	str = "https";
      else
	str = "http";
      if(http->host != NULL && http->file != NULL)
	string_concat(buf, sizeof(buf), &off, ", \"http_url\":\"%s://%s%s\"",
		      str, http->host, http->file);
      else if(http->host != NULL)
	string_concat(buf, sizeof(buf), &off, ", \"http_url\":\"%s://%s\"",
		      str, http->host);
    }
  else if(tbit->app_proto == SCAMPER_TBIT_APP_BGP && tbit->app_data != NULL)
    {
      bgp = tbit->app_data;
      string_concat(buf, sizeof(buf), &off,
		    ", \"app\":\"bgp\", \"bgp_asn\":%u", bgp->asn);
    }

  return strdup(buf);
}

static char *tbit_pkt_tostr(const scamper_tbit_t *tbit,
			    const scamper_tbit_pkt_t *pkt, tbit_state_t *state)
{
  static const char *tcpflags_str[] = {"fin", "syn", "rst", "psh", "ack",
				       "urg", "ece", "cwr"};
  struct timeval tv;
  char buf[1024], tmp[128];
  size_t off = 0;
  int frag = 0;
  uint32_t frag_off = 0, frag_id = 0;
  uint8_t frag_mf = 0;
  uint8_t u8, proto, tcpoptc, tcpflags, iphlen, tcphlen, v, ecn, ttl, *pp;
  uint16_t u16, len, win;
  uint32_t u32, seq, ack;

  if(pkt->dir == SCAMPER_TBIT_PKT_DIR_TX)
    snprintf(tmp, sizeof(tmp), "\"tx\"");
  else if(pkt->dir == SCAMPER_TBIT_PKT_DIR_RX)
    snprintf(tmp, sizeof(tmp), "\"rx\"");
  else
    snprintf(tmp, sizeof(tmp), "%u", pkt->dir);

  timeval_diff_tv(&tv, &tbit->start, &pkt->tv);
  string_concat(buf, sizeof(buf), &off,
		"{\"dir\":%s, \"tv_sec\":%u, \"tv_usec\":%u, \"len\":%u",
		tmp, tv.tv_sec, tv.tv_usec, pkt->len);

  v = (pkt->data[0] >> 4);

  if(v == 4)
    {
      iphlen = (pkt->data[0] & 0xf) * 4;
      len = bytes_ntohs(pkt->data+2);
      proto = pkt->data[9];
      ecn = pkt->data[1] & 0x3;
      ttl = pkt->data[8];
      if(pkt->data[6] & 0x20)
	frag_mf = 1;
      frag_id  = bytes_ntohs(pkt->data+4);
      frag_off = (bytes_ntohs(pkt->data+6) & 0x1fff) * 8;
      if(frag_mf != 0 || frag_off != 0)
	frag = 1;
    }
  else if(v == 6)
    {
      iphlen = 40;
      len = bytes_ntohs(pkt->data+4) + iphlen;
      proto = pkt->data[6];
      ecn = (pkt->data[1] & 0x30) >> 4;
      ttl = pkt->data[7];

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
		frag_mf = 1;
	      frag_off = (bytes_ntohs(pkt->data+iphlen+2) & 0xfff8);
	      frag_id = bytes_ntohl(pkt->data+iphlen+4);
	      proto = pkt->data[iphlen+0];
	      iphlen += 8;
	      frag = 1;
	      continue;
	    }
	  break;
	}
    }
  else goto done; /* not v4 or v6 */

  string_concat(buf, sizeof(buf), &off,
		", \"ip_hlen\":%u, \"ip_ecn\":%u, \"ip_ttl\":%u",
		iphlen, ecn, ttl);

  if(v == 4 || (v == 6 && frag != 0))
    string_concat(buf, sizeof(buf), &off,
		  ", \"frag_id\":%u, \"frag_off\":%u, \"frag_mf\":%u",
		  frag_id, frag_off, frag_mf);
  if(v == 4)
    string_concat(buf, sizeof(buf), &off, ", \"frag_df\":%u",
		  (pkt->data[6] & 0x40) >> 7);

  if(frag_off != 0)
    goto done;

  if(proto == IPPROTO_TCP)
    {
      seq      = bytes_ntohl(pkt->data+iphlen+4);
      ack      = bytes_ntohl(pkt->data+iphlen+8);
      win      = bytes_ntohs(pkt->data+iphlen+14);
      tcpflags = pkt->data[iphlen+13];
      tcphlen  = ((pkt->data[iphlen+12] & 0xf0) >> 4) * 4;

      if((tcpflags & (TH_SYN|TH_ACK)) == TH_SYN &&
	 (state->flags & TBIT_STATE_FLAG_CISN) == 0)
	{
	  state->client_isn = seq;
	  state->flags |= TBIT_STATE_FLAG_CISN;
	}
      else if((tcpflags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK) &&
	      (state->flags & TBIT_STATE_FLAG_SISN) == 0)
	{
	  state->server_isn = seq;
	  state->flags |= TBIT_STATE_FLAG_SISN;
	}

      string_concat(buf, sizeof(buf), &off,
		    ", \"tcp_hlen\": %u, \"tcp_flags\":[%s]", tcphlen,
		    tbit_bits_encode(tmp, sizeof(tmp), tcpflags, 8,
				     tcpflags_str,
				     sizeof(tcpflags_str) / sizeof(char *)));

      /* parse TCP header for options */
      string_concat(buf, sizeof(buf), &off, ", \"tcp_options\":[");
      u8 = 20; tcpoptc = 0;
      while(u8 < tcphlen)
	{
	  pp = pkt->data + iphlen + u8;
	  if(pp[0] == 0)
	    {
	      string_concat(buf, sizeof(buf), &off, "%s{\"kind\":\"eol\"}",
			    tcpoptc > 0 ? ", " : "");
	      break;
	    }
	  if(pp[0] == 1)
	    {
	      string_concat(buf, sizeof(buf), &off, "%s{\"kind\":\"nop\"}",
			    tcpoptc > 0 ? ", " : "");
	      tcpoptc++; u8++;
	      continue;
	    }
	  if(pp[1] == 0 || u8 + pp[1] > tcphlen)
	    break;
	  if(pp[0] == 3 && pp[1] == 3)
	    {
	      string_concat(buf, sizeof(buf), &off,
			    "%s{\"kind\":\"wscale\", \"shift\":%u}",
			    tcpoptc > 0 ? ", " : "", pp[2]);
	      tcpoptc++;
	    }
	  if(pp[0] == 4 && pp[1] == 2)
	    {
	      string_concat(buf, sizeof(buf), &off, "%s{\"kind\":\"sack-ok\"}",
			    tcpoptc > 0 ? ", " : "");
	      tcpoptc++;
	    }
	  if(pp[0] == 5 && (pp[1]==10 || pp[1]==18 || pp[1]==26 || pp[1]==34))
	    {
	      if(pkt->dir == SCAMPER_TBIT_PKT_DIR_TX)
		u32 = state->server_isn;
	      else
		u32 = state->client_isn;
	      string_concat(buf, sizeof(buf), &off,
			    "%s{\"kind\":\"sack\", \"blocks\":[",
			    tcpoptc > 0 ? ", " : "");
	      for(u16=0; u16<(pp[1]-2)/8; u16++)
		string_concat(buf, sizeof(buf), &off,
			      "%s{\"left\":%u, \"right\":%u}",
			      u16 != 0 ? ", " : "",
			      bytes_ntohl(pp+2+(u16*8)) - u32,
			      bytes_ntohl(pp+2+(u16*8)+4) - u32);
	      string_concat(buf, sizeof(buf), &off, "]}");
	      tcpoptc++;
	    }
	  if(pp[0] == 8 && pp[1] == 10)
	    {
	      string_concat(buf, sizeof(buf), &off,
			    "%s{\"kind\":\"ts\", \"val\":%u, \"ecr\":%u}",
			    tcpoptc > 0 ? ", " : "",
			    bytes_ntohl(pp+2), bytes_ntohl(pp+6));
	      tcpoptc++;
	    }
	  if(pp[0] == 34 && pp[1] >= 2)
	    {
	      string_concat(buf, sizeof(buf), &off, "%s{\"kind\":\"fo\"",
			    tcpoptc > 0 ? ", " : "");
	      if(pp[1] > 2)
		{
		  string_concat(buf, sizeof(buf), &off, ", \"cookie\":\"");
		  for(u16=0; u16<pp[1]-2; u16++)
		    string_concat(buf, sizeof(buf), &off, "%02x",
				  pp[2+u16]);
		  string_concat(buf, sizeof(buf), &off, "\"}");
		}
	      tcpoptc++;
	    }
	  if(pp[0] == 254 && pp[1] >= 4 && pp[2] == 0xF9 && pp[3] == 0x89)
	    {
	      string_concat(buf, sizeof(buf), &off, "%s{\"kind\":\"fo-exp\"",
			    tcpoptc > 0 ? ", " : "");
	      if(pp[1] > 4)
		{
		  string_concat(buf, sizeof(buf), &off, ", \"cookie\":\"");
		  for(u16=0; u16<pp[1]-4; u16++)
		    string_concat(buf, sizeof(buf), &off, "%02x",
				  pp[4+u16]);
		  string_concat(buf, sizeof(buf), &off, "\"}");
		}
	      tcpoptc++;
	    }

	  u8 += pp[1];
	}
      string_concat(buf, sizeof(buf), &off, "]");

      if(pkt->dir == SCAMPER_TBIT_PKT_DIR_TX)
	{
	  seq = tbit_isnoff(state->client_isn, seq);
	  ack = tbit_isnoff(state->server_isn, ack);
	}
      else
	{
	  if(!(seq == 0 && (tcpflags & TH_RST) != 0))
	    seq = tbit_isnoff(state->server_isn, seq);
	  ack = tbit_isnoff(state->client_isn, ack);
	}

      string_concat(buf, sizeof(buf), &off, ", \"tcp_seq\":%u", seq);
      if(tcpflags & TH_ACK)
	string_concat(buf, sizeof(buf), &off, ", \"tcp_ack\":%u", ack);
      string_concat(buf, sizeof(buf), &off, ", \"tcp_datalen\":%u",
		    len - iphlen - tcphlen);
      string_concat(buf, sizeof(buf), &off, ", \"tcp_win\":%u", win);
    }

 done:
  string_concat(buf, sizeof(buf), &off, "}");
  return strdup(buf);
}

int scamper_file_json_tbit_write(const scamper_file_t *sf,
				 const scamper_tbit_t *tbit)
{
  tbit_state_t state;
  char *str = NULL, *header = NULL, **pkts = NULL;
  size_t header_len = 0, len = 0, wc = 0, *pkt_lens = NULL;
  int rc = -1;
  uint32_t i;

  memset(&state, 0, sizeof(state)); 

  /* put together packet strings, done first to get state for header string */
  len += 11; /* , "pkts":[] */
  if(tbit->pktc > 0 &&
     ((pkts = malloc_zero(sizeof(char *) * tbit->pktc)) == NULL ||
      ((pkt_lens = malloc_zero(sizeof(size_t) * tbit->pktc)) == NULL)))
    goto cleanup;
  for(i=0; i<tbit->pktc; i++)
    {
      if(i > 0) len += 2; /* , */
      if((pkts[i] = tbit_pkt_tostr(tbit, tbit->pkts[i], &state)) == NULL)
	goto cleanup;
      pkt_lens[i] = strlen(pkts[i]);
      len += pkt_lens[i];
    }

  /* get the header string */
  if((header = tbit_header_tostr(tbit, &state)) == NULL)
    goto cleanup;
  len += (header_len = strlen(header));
  len += 2; /* }\n" */

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;
  memcpy(str+wc, header, header_len); wc += header_len;
  memcpy(str+wc, ", \"pkts\":[", 10); wc += 10;
  for(i=0; i<tbit->pktc; i++)
    {
      if(i > 0)
	{
	  memcpy(str+wc, ", ", 2);
	  wc += 2;
	}
      memcpy(str+wc, pkts[i], pkt_lens[i]);
      wc += pkt_lens[i];
    }
  memcpy(str+wc, "]}\n", 3); wc += 3;

  assert(wc == len);

  rc = json_write(sf, str, len);

 cleanup:
  if(str != NULL) free(str);
  if(header != NULL) free(header);
  if(pkt_lens != NULL) free(pkt_lens);
  if(pkts != NULL)
    {
      for(i=0; i<tbit->pktc; i++)
	if(pkts[i] != NULL)
	  free(pkts[i]);
      free(pkts);
    }
  return rc;
}
