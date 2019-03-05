/*
 * scamper_tbit.c
 *
 * Copyright (C) 2009-2010 Ben Stasiewicz
 * Copyright (C) 2010-2011 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2012,2015 The Regents of the University of California
 * Authors: Ben Stasiewicz, Matthew Luckie
 *
 * $Id: scamper_tbit.c,v 1.48 2017/09/27 01:54:17 mjl Exp $
 *
 * This file implements algorithms described in the tbit-1.0 source code,
 * as well as the papers:
 *
 *  "On Inferring TCP Behaviour"
 *      by Jitendra Padhye and Sally Floyd
 *  "Measuring the Evolution of Transport Protocols in the Internet"
 *      by Alberto Medina, Mark Allman, and Sally Floyd.
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
  "$Id: scamper_tbit.c,v 1.48 2017/09/27 01:54:17 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tbit.h"
#include "utils.h"

typedef struct tqe
{
  int                   off;
  scamper_tbit_tcpqe_t *qe;
} tqe_t;

struct scamper_tbit_tcpq
{
  uint32_t   seq;
  tqe_t    **tqes;
  int        tqec;
};

int scamper_tbit_data_seqoff(uint32_t rcv_nxt, uint32_t seq)
{
  if(seq >= rcv_nxt)
    return seq - rcv_nxt;
  return TCP_MAX_SEQNUM - rcv_nxt + seq + 1;
}

static int tqe_cmp(const tqe_t *a, const tqe_t *b)
{
  if(a->off < b->off)         return -1;
  if(a->off > b->off)         return  1;
  if(a->qe->len < b->qe->len) return -1;
  if(a->qe->len > b->qe->len) return  1;
  return 0;
}

int scamper_tbit_fo_setcookie(scamper_tbit_t *tbit,uint8_t *cookie,uint8_t len)
{
  if((tbit->fo_cookie = memdup(cookie, len)) == NULL)
    return -1;
  tbit->fo_cookielen = len;
  return 0;
}

int scamper_tbit_fo_getcookie(scamper_tbit_t *tbit, uint8_t *c, uint8_t *l)
{
  uint8_t u8, v, iphlen, tcphlen, *pktptr;
  scamper_tbit_pkt_t *pkt;
  uint32_t i;

  for(i=0; i<tbit->pktc; i++)
    {
      pkt = tbit->pkts[i];
      if(pkt->dir != SCAMPER_TBIT_PKT_DIR_RX)
	continue;

      v = (pkt->data[0] >> 4);
      if(v == 4)
	{
	  iphlen = (pkt->data[0] & 0xf) * 4;
	  if(pkt->data[9] != IPPROTO_TCP)
	    continue;
	  if((bytes_ntohs(pkt->data+6) & 0x1fff) != 0)
	    continue;
	}
      else if(v == 6)
	{
	  iphlen = 40;
	  u8 = pkt->data[6];
	  for(;;)
	    {
	      switch(u8)
		{
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		  u8 = pkt->data[iphlen+0];
		  iphlen += (pkt->data[iphlen+1] * 8) + 8;
		  continue;

		case IPPROTO_FRAGMENT:
		  if((bytes_ntohs(pkt->data+iphlen+2) & 0xfff8) != 0)
		    break;
		  u8 = pkt->data[iphlen+0];
		  iphlen += 8;
		  continue;
		}
	      break;
	    }
	  if(u8 != IPPROTO_TCP)
	    continue;
	}
      else continue;

      if((pkt->data[iphlen+13] & (TH_SYN|TH_ACK)) != (TH_SYN|TH_ACK))
	continue;

      tcphlen = ((pkt->data[iphlen+12] & 0xf0) >> 4) * 4;
      u8 = 20;
      while(u8 < tcphlen)
	{
	  pktptr = pkt->data + iphlen + u8;
	  if(pktptr[0] == 0)
	    break;
	  if(pktptr[1] == 1) {
	    u8++; continue;
	  }

	  if(pktptr[1] == 0 || u8 + pktptr[1] > tcphlen)
	    break;

	  if(pktptr[0] == 34 && pktptr[1] > 2 && pktptr[1] <= 18)
	    {
	      *l = pktptr[1] - 2;
	      memcpy(c, pktptr+2, *l);
	      return 1;
	    }
	  else if(pktptr[0] == 254  && pktptr[1] > 4 && pktptr[1] <= 20 &&
		  pktptr[2] == 0xF9 && pktptr[3] == 0x89)
	    {
	      *l = pktptr[1] - 4;
	      memcpy(c, pktptr+4, *l);
	      return 1;
	    }
	  u8 += pktptr[1];
	}
    }

  return 0;
}

void scamper_tbit_tcpqe_free(scamper_tbit_tcpqe_t *qe, void (*ff)(void *))
{
  if(qe == NULL) return;
  if(ff != NULL && qe->data != NULL)
    ff(qe->data);
  free(qe);
  return;
}

/*
 * scamper_tbit_tcpq_tail
 *
 * returns the sequence number at the tail of the tcpq, even if there
 * are gaps in the tcpq.
 */
uint32_t scamper_tbit_tcpq_tail(const scamper_tbit_tcpq_t *tcpq)
{
  uint32_t range = 0, edge, u32;
  scamper_tbit_tcpqe_t *qe;
  int i;

  for(i=0; i<tcpq->tqec; i++)
    {
      qe = tcpq->tqes[i]->qe;
      edge = qe->seq + qe->len;
      if((u32 = scamper_tbit_data_seqoff(tcpq->seq, edge)) > range)
	range = u32;
    }

  return tcpq->seq + range;
}

scamper_tbit_tcpq_t *scamper_tbit_tcpq_alloc(uint32_t isn)
{
  scamper_tbit_tcpq_t *q;
  if((q = malloc_zero(sizeof(scamper_tbit_tcpq_t))) == NULL)
    goto err;
  q->seq = isn;
  return q;
 err:
  scamper_tbit_tcpq_free(q, NULL);
  return NULL;
}

void scamper_tbit_tcpq_flush(scamper_tbit_tcpq_t *q, void (*ff)(void *))
{
  tqe_t *tqe;
  int i;

  if(q->tqes == NULL)
    return;

  for(i=0; i<q->tqec; i++)
    {
      tqe = q->tqes[i];
      scamper_tbit_tcpqe_free(tqe->qe, ff);
      free(tqe);
    }
  free(q->tqes);
  q->tqes = NULL;
  q->tqec = 0;
  return;
}

void scamper_tbit_tcpq_free(scamper_tbit_tcpq_t *q, void (*ff)(void *))
{
  if(q == NULL)
    return;
  if(q->tqes != NULL)
    scamper_tbit_tcpq_flush(q, ff);
  free(q);
  return;
}

int scamper_tbit_tcpq_seg(scamper_tbit_tcpq_t *q, uint32_t *seq, uint16_t *len)
{
  tqe_t *tqe;
  assert(q->tqec >= 0);
  if(q->tqec == 0)
    return -1;
  tqe = q->tqes[0];
  assert(q->seq + tqe->off == tqe->qe->seq);
  *seq = tqe->qe->seq;
  *len = tqe->qe->len;
  return 0;
}

scamper_tbit_tcpqe_t *scamper_tbit_tcpq_pop(scamper_tbit_tcpq_t *q)
{
  scamper_tbit_tcpqe_t *qe;
  uint16_t len;
  tqe_t *tqe;
  int i, off;

  if(q->tqec == 0)
    return NULL;

  tqe = q->tqes[0];
  qe = tqe->qe;
  free(tqe);

  if(--q->tqec > 0)
    memmove(q->tqes, q->tqes+1, sizeof(tqe_t *) * q->tqec);

  off = scamper_tbit_data_seqoff(q->seq, qe->seq);
  if(off < 0 && off + qe->len <= 0)
    return qe;

  len = qe->len + off;
  for(i=0; i<q->tqec; i++)
    q->tqes[i]->off -= len;
  q->seq += len;

  return qe;
}

int scamper_tbit_tcpq_add(scamper_tbit_tcpq_t *q, uint32_t seq,
			  uint8_t flags, uint16_t len, uint8_t *data)
{
  tqe_t *tqe;

  assert(scamper_tbit_data_inrange(q->seq, seq, len) != 0);
  if((tqe = malloc_zero(sizeof(tqe_t))) == NULL)
    goto err;
  if((tqe->qe = malloc_zero(sizeof(scamper_tbit_tcpqe_t))) == NULL)
    goto err;
  tqe->off = scamper_tbit_data_seqoff(q->seq, seq);
  tqe->qe->seq   = seq;
  tqe->qe->flags = flags;
  tqe->qe->len   = len;
  tqe->qe->data  = data;
  if(array_insert((void ***)&q->tqes,&q->tqec,tqe,(array_cmp_t)tqe_cmp) != 0)
    goto err;
  return 0;

 err:
  if(tqe != NULL)
    {
      scamper_tbit_tcpqe_free(tqe->qe, NULL);
      free(tqe);
    }
  return -1;
}

int scamper_tbit_tcpq_sack(scamper_tbit_tcpq_t *q, uint32_t *sack, int count)
{
  uint32_t left, right;
  scamper_tbit_tcpqe_t *qe;
  int i, off, c = 0;

  assert(q->tqec >= 0);
  if(q->tqec == 0)
    return 0;

  qe = q->tqes[0]->qe;
  if(qe->len == 0)
    return 0;

  left = qe->seq;
  right = qe->seq + qe->len;
  assert(scamper_tbit_data_seqoff(q->seq, left) > 0);

  for(i=1; i<q->tqec && c < count; i++)
    {
      qe = q->tqes[i]->qe;
      if(qe->len == 0)
	continue;
      if((off = scamper_tbit_data_seqoff(right, qe->seq)) <= 0)
	{
	  off = abs(off);
	  if(qe->len > off)
	    right = right + qe->len - off;
	  continue;
	}

      sack[c*2]     = left;
      sack[(c*2)+1] = right;
      c++;

      left  = qe->seq;
      right = qe->seq + qe->len;
    }

  if(c < count)
    {
      sack[c*2]     = left;
      sack[(c*2)+1] = right;
      c++;
    }

  return c;
}

/*
 * scamper_tbit_data_inrange:
 *
 * rcv_nxt <= beginning sequence number of segment < rcv_nxt + rcv_wnd OR
 * rcv_nxt <= ending sequence number of segment < rcv_nxt + rcv_wnd
 */
int scamper_tbit_data_inrange(uint32_t rcv_nxt, uint32_t seq, uint16_t len)
{
  if((SEQ_LEQ(rcv_nxt, seq) && SEQ_LT(seq, rcv_nxt + 65535)) ||
     (SEQ_LEQ(rcv_nxt, seq+len-1) && SEQ_LT(seq+len-1, rcv_nxt + 65535)))
    return 1;
  return 0;
}

int scamper_tbit_pkt_iplen(const scamper_tbit_pkt_t *pkt)
{
  uint8_t v = pkt->data[0] >> 4;
  int rc = -1;

  if(v == 4)
    rc = bytes_ntohs(pkt->data+2);
  else if(v == 6)
    rc = bytes_ntohs(pkt->data+4) + 40;

  return rc;
}

int scamper_tbit_pkt_iph(const scamper_tbit_pkt_t *pkt,
			 uint8_t *proto, uint8_t *iphlen, uint16_t *iplen)
{
  uint8_t v = pkt->data[0] >> 4;

  if(v == 4)
    {
      *iphlen = (pkt->data[0] & 0xf) * 4;
      *iplen = bytes_ntohs(pkt->data+2);
      *proto = pkt->data[9];
      return 0;
    }

  if(v == 6)
    {
      *iphlen = 40;
      *iplen = bytes_ntohs(pkt->data+4) + 40;
      *proto = pkt->data[6];
      for(;;)
	{
	  switch(*proto)
	    {
	    case IPPROTO_HOPOPTS:
	    case IPPROTO_DSTOPTS:
	    case IPPROTO_ROUTING:
	      *proto = pkt->data[*iphlen];
	      *iphlen += (pkt->data[(*iphlen)+1] * 8) + 8;
	      continue;
	    case IPPROTO_FRAGMENT:
	      *proto = pkt->data[*iphlen];
	      if((bytes_ntohs(pkt->data+(*iphlen)+2) & 0xfff8) != 0) /* off */
		return -1;
	      if((pkt->data[(*iphlen)+3] & 0x1) != 0) /* mf */
		return -1;
	      *iphlen += 8;
	      continue;
	    }
	  break;
	}
      return 0;
    }

  return -1;
}

int scamper_tbit_pkt_tcpdatabytes(const scamper_tbit_pkt_t *pkt, uint16_t *bc)
{
  uint8_t iphlen, tcphlen, proto;
  uint16_t iplen;

  if(scamper_tbit_pkt_iph(pkt, &proto, &iphlen, &iplen) != 0)
    return -1;
  if(proto != IPPROTO_TCP)
    return -1;
  tcphlen = ((pkt->data[iphlen+12] & 0xf0) >> 4) * 4;
  *bc = iplen - iphlen - tcphlen;
  return 0;
}

int scamper_tbit_pkt_tcpack(const scamper_tbit_pkt_t *pkt, uint32_t *ack)
{
  uint8_t iphlen, proto;
  uint16_t iplen;
  if(scamper_tbit_pkt_iph(pkt, &proto, &iphlen, &iplen) != 0)
    return -1;
  if(proto != IPPROTO_TCP || (pkt->data[iphlen+13] & TH_ACK) == 0)
    return -1;
  *ack = bytes_ntohl(pkt->data+iphlen+8);
  return 0;
}

int scamper_tbit_icw_size(const scamper_tbit_t *tbit, uint32_t *icw_out)
{
  const scamper_tbit_icw_t *icw = tbit->data;
  const scamper_tbit_pkt_t *pkt;
  scamper_tbit_tcpq_t *q = NULL;
  uint32_t i, u32, seq, start_seq;
  uint16_t iplen, datalen;
  uint8_t proto, iphlen, tcphlen, flags, start_seq_c = 0;
  int rc = -1;

  if(tbit->result != SCAMPER_TBIT_RESULT_ICW_SUCCESS ||
     tbit->pktc < 1)
    goto done;

  for(i=1; i<tbit->pktc; i++)
    {
      pkt = tbit->pkts[i];
      if(pkt->dir == SCAMPER_TBIT_PKT_DIR_RX)
	break;
    }
  if(i == tbit->pktc ||
     scamper_tbit_pkt_iph(pkt, &proto, &iphlen, &iplen) != 0 ||
     proto != IPPROTO_TCP ||
     (pkt->data[iphlen+13] & (TH_SYN|TH_ACK)) != (TH_SYN|TH_ACK))
    goto done;

  start_seq = bytes_ntohl(pkt->data+iphlen+4) + icw->start_seq;
  if((q = scamper_tbit_tcpq_alloc(start_seq)) == NULL)
    goto done;

  for(i++; i<tbit->pktc; i++)
    {
      pkt = tbit->pkts[i];
      if(pkt->dir != SCAMPER_TBIT_PKT_DIR_RX)
	continue;
      if(scamper_tbit_pkt_iph(pkt, &proto, &iphlen, &iplen) != 0)
	break;
      if(proto != IPPROTO_TCP)
	break;
      seq     = bytes_ntohl(pkt->data+iphlen+4);
      tcphlen = ((pkt->data[iphlen+12] & 0xf0) >> 4) * 4;
      flags   = pkt->data[iphlen+13];

      if((datalen = iplen - iphlen - tcphlen) == 0 && (flags & TH_FIN) == 0)
	continue;
      if(scamper_tbit_data_inrange(start_seq, seq, datalen) == 0)
	continue;

      if(seq == start_seq)
	{
	  start_seq_c++;
	  if(start_seq_c == 2)
	    {
	      u32 = scamper_tbit_tcpq_tail(q);
	      *icw_out = scamper_tbit_data_seqoff(start_seq, u32);
	      rc = 0;
	      break;
	    }
	}

      if(scamper_tbit_tcpq_add(q, seq, flags, datalen, NULL) != 0)
	break;
    }

 done:
  scamper_tbit_tcpq_free(q, NULL);
  return rc;
}

int scamper_tbit_stats(const scamper_tbit_t *tbit, scamper_tbit_stats_t *stats)
{
  const scamper_tbit_pkt_t *pkt, *syn;
  scamper_tbit_tcpq_t *q = NULL;
  scamper_tbit_tcpqe_t *qe;
  uint32_t rcv_nxt, seq;
  uint16_t iplen, datalen, len;
  uint8_t proto, iphlen, tcphlen, flags;
  uint32_t i;
  int off, seenfin = 0;

  memset(stats, 0, sizeof(scamper_tbit_stats_t));
  if(tbit->pktc < 1)
    return 0;

  /* to begin with, look for a SYN/ACK */
  syn = tbit->pkts[0];
  for(i=1; i<tbit->pktc; i++)
    {
      pkt = tbit->pkts[i];
      if(pkt->dir == SCAMPER_TBIT_PKT_DIR_RX)
	break;
    }
  if(i == tbit->pktc)
    return 0;

  if(scamper_tbit_pkt_iph(pkt, &proto, &iphlen, &iplen) != 0)
    goto err;
  if(proto != IPPROTO_TCP)
    goto err;
  if((pkt->data[iphlen+13] & (TH_SYN|TH_ACK)) != (TH_SYN|TH_ACK))
    goto err;

  timeval_diff_tv(&stats->synack_rtt, &syn->tv, &pkt->tv);
  rcv_nxt = bytes_ntohl(pkt->data+iphlen+4) + 1;

  if((q = scamper_tbit_tcpq_alloc(rcv_nxt)) == NULL)
    goto err;

  for(i++; i<tbit->pktc; i++)
    {
      pkt = tbit->pkts[i];
      if(pkt->dir != SCAMPER_TBIT_PKT_DIR_RX)
	continue;
      if(scamper_tbit_pkt_iph(pkt, &proto, &iphlen, &iplen) != 0)
	goto err;
      if(proto != IPPROTO_TCP)
	goto err;
      seq     = bytes_ntohl(pkt->data+iphlen+4);
      tcphlen = ((pkt->data[iphlen+12] & 0xf0) >> 4) * 4;
      flags   = pkt->data[iphlen+13];
      if((datalen = iplen - iphlen - tcphlen) == 0 && (flags & TH_FIN) == 0)
	continue;

      stats->rx_totalsize += (iplen - iphlen - tcphlen);

      /* skip over a packet out of range */
      if(scamper_tbit_data_inrange(rcv_nxt, seq, datalen) == 0)
	continue;

      if(scamper_tbit_tcpq_add(q, seq, flags, datalen, NULL) != 0)
	goto err;

      while(scamper_tbit_tcpq_seg(q, &seq, &datalen) == 0)
	{
	  if(scamper_tbit_data_inrange(rcv_nxt, seq, datalen) == 0)
	    {
	      scamper_tbit_tcpqe_free(scamper_tbit_tcpq_pop(q), NULL);
	      continue;
	    }

	  /* can't process this packet yet */
	  if((off = scamper_tbit_data_seqoff(rcv_nxt, seq)) > 0)
	    break;

	  qe = scamper_tbit_tcpq_pop(q);
	  flags = qe->flags;
	  scamper_tbit_tcpqe_free(qe, NULL);
	  len = datalen + off;
	  rcv_nxt += len;
	  stats->rx_xfersize += len;

	  if((flags & TH_FIN) != 0)
	    {
	      timeval_diff_tv(&stats->xfertime, &syn->tv, &pkt->tv);
	      seenfin = 1;
	    }
	}
    }

  if(seenfin == 0)
    goto err;

  scamper_tbit_tcpq_free(q, NULL);
  return 0;

 err:
  scamper_tbit_tcpq_free(q, NULL);
  return -1;
}

char *scamper_tbit_type2str(const scamper_tbit_t *tbit, char *buf, size_t len)
{
  static char *t[] = {
    NULL,
    "pmtud",
    "ecn",
    "null",
    "sack-rcvr",
    "icw",
    "abc",
    "blind-data",
    "blind-rst",
    "blind-syn",
    "blind-fin",
  };

  if(tbit->type > sizeof(t) / sizeof(char *) || t[tbit->type] == NULL)
    {
      snprintf(buf, len, "%d", tbit->type);
      return buf;
    }

  return t[tbit->type];
}

char *scamper_tbit_res2str(const scamper_tbit_t *tbit, char *buf, size_t len)
{
  static char *t[] = {
    "none",                /* 0 */
    "tcp-noconn",
    "tcp-rst",
    "tcp-error",
    "sys-error",
    "aborted",
    "tcp-noconn-rst",
    "halted",
    "tcp-badopt",
    "tcp-fin",
    "tcp-zerowin",         /* 10 */
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "pmtud-noack",         /* 20 */
    "pmtud-nodata",
    "pmtud-toosmall",
    "pmtud-nodf",
    "pmtud-fail",
    "pmtud-success",
    "pmtud-cleardf",
    NULL,
    NULL,
    NULL,
    "ecn-success",         /* 30 */
    "ecn-incapable",
    "ecn-badsynack",
    "ecn-noece",
    "ecn-noack",
    "ecn-nodata",
    NULL,
    NULL,
    NULL,
    NULL,
    "null-success",        /* 40 */
    "null-nodata",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "sack-incapable",      /* 50 */
    "sack-rcvr-success",
    "sack-rcvr-shifted",
    "sack-rcvr-timeout",
    "sack-rcvr-nosack",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "icw-success",         /* 60 */
    "icw-tooshort",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "abc-success",         /* 70 */
    "abc-tooshort",
    "abc-badicw",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "blind-accepted",      /* 80 */
    "blind-challenge",
    "blind-ignored",
    "blind-rst",
    "blind-synnew",
  };

  if(tbit->result > sizeof(t) / sizeof(char *) || t[tbit->result] == NULL)
    {
      snprintf(buf, len, "%d", tbit->result);
      return buf;
    }

  return t[tbit->result];
}

scamper_tbit_pkt_t *scamper_tbit_pkt_alloc(uint8_t dir, uint8_t *data,
					   uint16_t len, struct timeval *tv)
{
  scamper_tbit_pkt_t *pkt;

  if((pkt = malloc_zero(sizeof(scamper_tbit_pkt_t))) == NULL)
    goto err;

  pkt->dir = dir;
  if(len != 0 && data != NULL)
    {
      if((pkt->data = memdup(data, len)) == NULL)
	goto err;
      pkt->len = len;
    }
  if(tv != NULL) timeval_cpy(&pkt->tv, tv);
  return pkt;

 err:
  free(pkt);
  return NULL;
}

void scamper_tbit_pkt_free(scamper_tbit_pkt_t *pkt)
{
  if(pkt == NULL)
    return;
  if(pkt->data != NULL) free(pkt->data);
  free(pkt);
  return;
}

int scamper_tbit_pkts_alloc(scamper_tbit_t *tbit, uint32_t count)
{
  size_t size = count * sizeof(scamper_tbit_pkt_t *);
  if((tbit->pkts = (scamper_tbit_pkt_t **)malloc_zero(size)) == NULL)
    return -1;
  return 0;
}

int scamper_tbit_record_pkt(scamper_tbit_t *tbit, scamper_tbit_pkt_t *pkt)
{
  size_t len = (tbit->pktc + 1) * sizeof(scamper_tbit_pkt_t *);

  /* Add a new element to the pkts array */
  if(realloc_wrap((void**)&tbit->pkts, len) != 0)
    return -1;

  tbit->pkts[tbit->pktc++] = pkt;
  return 0;
}

scamper_tbit_app_http_t *scamper_tbit_app_http_alloc(uint8_t type,
						     char *host, char *file)
{
  scamper_tbit_app_http_t *http;

  if((http = malloc_zero(sizeof(scamper_tbit_app_http_t))) == NULL ||
     (host != NULL && (http->host = strdup(host)) == NULL) ||
     (file != NULL && (http->file = strdup(file)) == NULL))
    {
      if(http == NULL) return NULL;
      if(http->host != NULL) free(http->host);
      if(http->file != NULL) free(http->file);
      free(http);
      return NULL;
    }

  http->type = type;
  return http;
}

void scamper_tbit_app_http_free(scamper_tbit_app_http_t *http)
{
  if(http == NULL)
    return;
  if(http->host != NULL) free(http->host);
  if(http->file != NULL) free(http->file);
  free(http);
  return;
}

scamper_tbit_app_bgp_t *scamper_tbit_app_bgp_alloc(void)
{
  return malloc_zero(sizeof(scamper_tbit_app_bgp_t));
}

void scamper_tbit_app_bgp_free(scamper_tbit_app_bgp_t *bgp)
{
  if(bgp == NULL)
    return;
  free(bgp);
  return;
}

scamper_tbit_pmtud_t *scamper_tbit_pmtud_alloc(void)
{
  return malloc_zero(sizeof(scamper_tbit_pmtud_t));
}

void scamper_tbit_pmtud_free(scamper_tbit_pmtud_t *pmtud)
{
  if(pmtud == NULL)
    return;
  if(pmtud->ptbsrc != NULL)
    scamper_addr_free(pmtud->ptbsrc);
  free(pmtud);
  return;
}

scamper_tbit_null_t *scamper_tbit_null_alloc(void)
{
  return malloc_zero(sizeof(scamper_tbit_null_t));
}

void scamper_tbit_null_free(scamper_tbit_null_t *null)
{
  if(null == NULL)
    return;
  free(null);
  return;
}

scamper_tbit_icw_t *scamper_tbit_icw_alloc(void)
{
  return malloc_zero(sizeof(scamper_tbit_icw_t));
}

void scamper_tbit_icw_free(scamper_tbit_icw_t *icw)
{
  free(icw);
  return;
}

scamper_tbit_blind_t *scamper_tbit_blind_alloc(void)
{
  return malloc_zero(sizeof(scamper_tbit_blind_t));
}

void scamper_tbit_blind_free(scamper_tbit_blind_t *blind)
{
  if(blind == NULL)
    return;
  free(blind);
  return;
}

/* Free the tbit object. */
void scamper_tbit_free(scamper_tbit_t *tbit)
{
  uint32_t i;

  if(tbit == NULL)
    return;

  if(tbit->src != NULL)   scamper_addr_free(tbit->src);
  if(tbit->dst != NULL)   scamper_addr_free(tbit->dst);
  if(tbit->list != NULL)  scamper_list_free(tbit->list);
  if(tbit->cycle != NULL) scamper_cycle_free(tbit->cycle);

  if(tbit->fo_cookie != NULL) free(tbit->fo_cookie);

  /* Free the recorded packets */
  if(tbit->pkts != NULL)
    {
      for(i=0; i<tbit->pktc; i++)
	scamper_tbit_pkt_free(tbit->pkts[i]);
      free(tbit->pkts);
    }

  /* Free protocol specific data */
  if(tbit->app_data != NULL)
    {
      if(tbit->app_proto == SCAMPER_TBIT_APP_HTTP)
	scamper_tbit_app_http_free(tbit->app_data);
    }

  /* Free test-specific data */
  if(tbit->data != NULL)
    {
      if(tbit->type == SCAMPER_TBIT_TYPE_PMTUD)
	scamper_tbit_pmtud_free(tbit->data);
      else if(tbit->type == SCAMPER_TBIT_TYPE_NULL)
	scamper_tbit_null_free(tbit->data);
      else if(tbit->type == SCAMPER_TBIT_TYPE_ICW)
	scamper_tbit_icw_free(tbit->data);
      else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_RST ||
	      tbit->type == SCAMPER_TBIT_TYPE_BLIND_SYN ||
	      tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA ||
	      tbit->type == SCAMPER_TBIT_TYPE_BLIND_FIN)
	scamper_tbit_blind_free(tbit->data);
    }

  free(tbit);
  return;
}

scamper_tbit_t *scamper_tbit_alloc(void)
{
  return (scamper_tbit_t *)malloc_zero(sizeof(scamper_tbit_t));
}
