/*
 * scamper_do_tbit.c
 *
 * $Id: scamper_tbit_do.c,v 1.183 2019/07/12 23:37:57 mjl Exp $
 *
 * Copyright (C) 2009-2010 Ben Stasiewicz
 * Copyright (C) 2009-2010 Stephen Eichler
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2010-2011 University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2017      University of Waikato
 *
 * Authors: Matthew Luckie, Ben Stasiewicz, Stephen Eichler, Tiange Wu,
 *          Robert Beverly
 *
 * Some of the algorithms implemented in this file are described in the
 * tbit-1.0 source code, as well as the papers:
 *
 *  "On Inferring TCP Behaviour"
 *      by Jitendra Padhye and Sally Floyd
 *  "Measuring the Evolution of Transport Protocols in the Internet" by
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
  "$Id: scamper_tbit_do.c,v 1.183 2019/07/12 23:37:57 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_task.h"
#include "scamper_dl.h"
#include "scamper_fds.h"
#include "scamper_dlhdr.h"
#include "scamper_firewall.h"
#include "scamper_rtsock.h"
#include "scamper_if.h"
#include "scamper_probe.h"
#include "scamper_getsrc.h"
#include "scamper_tcp4.h"
#include "scamper_tcp6.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_options.h"
#include "scamper_debug.h"
#include "utils.h"
#include "mjl_list.h"
#include "scamper_tbit.h"
#include "scamper_tbit_do.h"

/* Default test parameters */
#define TBIT_RETX_DEFAULT         3
#define TBIT_TIMEOUT_DEFAULT      10000
#define TBIT_TIMEOUT_LONG         70000
#define TBIT_TIMEOUT_SACK         2000
#define TBIT_TIMEOUT_BLINDDATA    2000

typedef struct tbit_options
{
  uint8_t   app;
  uint8_t   type;
  uint8_t   syn_retx;
  uint8_t   dat_retx;
  uint8_t   attempts;
  uint8_t   fo_cookielen;
  uint8_t   fo_cookie[16];
  uint16_t  options;
  uint16_t  mss;
  uint16_t  mtu;
  uint16_t  sport;
  uint16_t  dport;
  char     *url;
  char     *ptbsrc;
  char     *src;
  int32_t   offset;
  uint16_t  asn;
} tbit_options_t;

typedef struct tbit_segment
{
  uint8_t        *data;
  uint16_t        len;
} tbit_segment_t;

typedef struct tbit_frag
{
  uint16_t         off;
  uint8_t         *data;
  uint16_t         datalen;
} tbit_frag_t;

typedef struct tbit_frags
{
  struct timeval   tv;
  uint32_t         id;
  tbit_frag_t    **frags;
  int              fragc;
  uint8_t          gotlast;
} tbit_frags_t;

typedef struct tbit_probe
{
  uint8_t type;
  int     wait;
  union
  {
    struct tp_tcp
    {
      uint16_t len;
      uint8_t  flags;
      uint8_t  sackb;
      uint32_t seq;
      uint32_t ack;
      uint32_t sack[8];
    } tcp;
  } un;
} tbit_probe_t;

#define tp_len   un.tcp.len
#define tp_flags un.tcp.flags
#define tp_sackb un.tcp.sackb
#define tp_seq   un.tcp.seq
#define tp_ack   un.tcp.ack
#define tp_sack  un.tcp.sack

typedef struct tbit_state
{
#ifndef _WIN32
  scamper_fd_t               *rtsock;
#endif
  scamper_fd_t               *dl;
  scamper_dlhdr_t            *dlhdr;
  scamper_route_t            *route;
  scamper_firewall_entry_t   *fw;
  uint8_t                     mode;
  uint8_t                     attempt;
  uint16_t                    flags;
  struct timeval              timeout;
  uint16_t                    ipid;

  slist_t                    *tx;
  slist_t                    *segments;
  scamper_tbit_tcpq_t        *rxq;
  uint32_t                    sa_seq;
  uint32_t                    snd_nxt;
  uint32_t                    rcv_nxt;

  tbit_frags_t              **frags;
  int                         fragc;

  uint32_t                    ts_recent;
  uint32_t                    ts_lastack;
  uint32_t                    qs_nonce;
  uint8_t                     qs_ttl;

#if defined(HAVE_OPENSSL)
  int                         ssl_mode;
  SSL                        *ssl;
  BIO                        *rbio;
  BIO                        *wbio;
#endif

  union
  {
    struct tbit_pmtud
    {
      uint8_t                *ptb_data;
      uint16_t                ptb_datalen;
      uint16_t                ptb_c;
    } pmtud;

    struct tbit_sackr
    {
      uint8_t                 rx[7]; /* pkts received */
      uint8_t                 x;
      uint8_t                 flags;
      uint8_t                 timeout;
    } sackr;

    struct tbit_ecn
    {
      uint8_t                 flags;
    } ecn;

    struct tbit_icw
    {
      uint32_t                seq;
      uint32_t                tail;
      uint8_t                 count;
      uint8_t                 flags;
    } icw;

    struct tbit_blind
    {
      uint8_t                 flags;
      uint8_t                 c;       /* the number of blind packets sent */
      uint8_t                 sent;    /* sent blind packet for this data */
      uint8_t                 ignored; /* how many times sender ignored */
      uint8_t                 step;    /* what step in blind data */
      uint16_t                part1;
      uint16_t                part2;
      uint16_t                part3;
      uint32_t                ack;
    } blind;

  } un;
} tbit_state_t;

#define pmtud_ptb_data        un.pmtud.ptb_data
#define pmtud_ptb_datalen     un.pmtud.ptb_datalen
#define pmtud_ptb_c           un.pmtud.ptb_c
#define sackr_rx              un.sackr.rx
#define sackr_x               un.sackr.x
#define sackr_flags           un.sackr.flags
#define sackr_timeout         un.sackr.timeout
#define ecn_flags             un.ecn.flags
#define icw_seq               un.icw.seq
#define icw_count             un.icw.count
#define icw_tail              un.icw.tail
#define icw_flags             un.icw.flags
#define blind_flags           un.blind.flags
#define blind_c               un.blind.c
#define blind_sent            un.blind.sent
#define blind_ignored         un.blind.ignored
#define blind_part1           un.blind.part1
#define blind_part2           un.blind.part2
#define blind_part3           un.blind.part3
#define blind_step            un.blind.step
#define blind_ack             un.blind.ack

/* The callback functions registered with the tbit task */
static scamper_task_funcs_t tbit_funcs;

/* Address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

#define TBIT_STATE_FLAG_FIN_SEEN      0x0001
#define TBIT_STATE_FLAG_FIN_ACKED     0x0002
#define TBIT_STATE_FLAG_SEEN_DATA     0x0004
#define TBIT_STATE_FLAG_SEEN_220      0x0008
#define TBIT_STATE_FLAG_NODF          0x0010
#define TBIT_STATE_FLAG_RST_SEEN      0x0020
#define TBIT_STATE_FLAG_NOMOREDATA    0x0040
#define TBIT_STATE_FLAG_NORESET       0x1000
#define TBIT_STATE_FLAG_TCPTS         0x2000
#define TBIT_STATE_FLAG_SACK          0x4000

/* flags specific to the ecn test */
#define TBIT_STATE_ECN_FLAG_ECT         0x01
#define TBIT_STATE_ECN_FLAG_CE_SET      0x02
#define TBIT_STATE_ECN_FLAG_CE_SENT     0x04
#define TBIT_STATE_ECN_FLAG_CWR_SET     0x08
#define TBIT_STATE_ECN_FLAG_CWR_SENT    0x10
#define TBIT_STATE_ECN_FLAG_ECE_SEEN    0x20

/* flags specific to the sackr test */
#define TBIT_STATE_SACKR_FLAG_INCAPABLE 0x01
#define TBIT_STATE_SACKR_FLAG_SHIFTED   0x02
#define TBIT_STATE_SACKR_FLAG_BADOPT    0x04

/* flags specific to the icw test */
#define TBIT_STATE_ICW_FLAG_SEQ         0x01

/* flags specific to the blind tests */
#define TBIT_STATE_BLIND_FLAG_CHALLENGE 0x01
#define TBIT_STATE_BLIND_FLAG_ACCEPTED  0x02
#define TBIT_STATE_BLIND_FLAG_SILENCE   0x04
#define TBIT_STATE_BLIND_FLAG_RST       0x08
#define TBIT_STATE_BLIND_FLAG_FIN       0x10
#define TBIT_STATE_BLIND_FLAG_SPLIT     0x20

#if defined(HAVE_OPENSSL)
/* ssl modes */
#define TBIT_STATE_SSL_MODE_HANDSHAKE   0x00
#define TBIT_STATE_SSL_MODE_ESTABLISHED 0x01
#define TBIT_STATE_SSL_MODE_SHUTDOWN    0x02
#endif

/* Options that tbit supports */
#define TBIT_OPT_DPORT       1
#define TBIT_OPT_MSS         2
#define TBIT_OPT_MTU         3
#define TBIT_OPT_OPTION      4
#define TBIT_OPT_APP         5
#define TBIT_OPT_PTBSRC      6
#define TBIT_OPT_SPORT       7
#define TBIT_OPT_TYPE        8
#define TBIT_OPT_URL         9
#define TBIT_OPT_USERID      10
#define TBIT_OPT_SRCADDR     11
#define TBIT_OPT_FO          12
#define TBIT_OPT_WSCALE      17
#define TBIT_OPT_ATTEMPTS    18
#define TBIT_OPT_OFFSET      19
#define TBIT_OPT_ASN         20
#define TBIT_OPT_TTL         21

/* bits for the tbit_option.options field */
#define TBIT_OPT_OPTION_BLACKHOLE  0x0001
#define TBIT_OPT_OPTION_TCPTS      0x0002
#define TBIT_OPT_OPTION_IPTS_SYN   0x0004
#define TBIT_OPT_OPTION_IPRR_SYN   0x0008
#define TBIT_OPT_OPTION_IPQS_SYN   0x0010
#define TBIT_OPT_OPTION_SACK       0x0020
#define TBIT_OPT_OPTION_FO         0x0040
#define TBIT_OPT_OPTION_FO_EXP     0x0080

/* we only support one IP option on a SYN packet */
#define TBIT_OPT_OPTION_IPOPT_SYN_MASK \
 (TBIT_OPT_OPTION_IPTS_SYN | TBIT_OPT_OPTION_IPRR_SYN | \
  TBIT_OPT_OPTION_IPQS_SYN)

/* types of tbit probe packets */
#define TBIT_PROBE_TYPE_TCP 1
#define TBIT_PROBE_TYPE_PTB 2

static const scamper_option_in_t opts[] = {
  {'b', NULL, TBIT_OPT_ASN,      SCAMPER_OPTION_TYPE_NUM},
  {'d', NULL, TBIT_OPT_DPORT,    SCAMPER_OPTION_TYPE_NUM},
  {'f', NULL, TBIT_OPT_FO,       SCAMPER_OPTION_TYPE_STR},
  {'m', NULL, TBIT_OPT_MSS,      SCAMPER_OPTION_TYPE_NUM},
  {'M', NULL, TBIT_OPT_MTU,      SCAMPER_OPTION_TYPE_NUM},
  {'o', NULL, TBIT_OPT_OFFSET,   SCAMPER_OPTION_TYPE_NUM},
  {'O', NULL, TBIT_OPT_OPTION,   SCAMPER_OPTION_TYPE_STR},
  {'p', NULL, TBIT_OPT_APP,      SCAMPER_OPTION_TYPE_STR},
  {'P', NULL, TBIT_OPT_PTBSRC,   SCAMPER_OPTION_TYPE_STR},
  {'q', NULL, TBIT_OPT_ATTEMPTS, SCAMPER_OPTION_TYPE_NUM},
  {'s', NULL, TBIT_OPT_SPORT,    SCAMPER_OPTION_TYPE_NUM},
  {'S', NULL, TBIT_OPT_SRCADDR,  SCAMPER_OPTION_TYPE_STR},
  {'t', NULL, TBIT_OPT_TYPE,     SCAMPER_OPTION_TYPE_STR},
  {'T', NULL, TBIT_OPT_TTL,      SCAMPER_OPTION_TYPE_NUM},
  {'u', NULL, TBIT_OPT_URL,      SCAMPER_OPTION_TYPE_STR},
  {'U', NULL, TBIT_OPT_USERID,   SCAMPER_OPTION_TYPE_NUM},
  {'w', NULL, TBIT_OPT_WSCALE,   SCAMPER_OPTION_TYPE_NUM},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

static const uint8_t MODE_RTSOCK    =  1; /* waiting for rtsock */
static const uint8_t MODE_DLHDR     =  2; /* waiting for dlhdr to use */
static const uint8_t MODE_FIREWALL  =  3; /* insert firewall rule */
static const uint8_t MODE_DONE      =  4; /* test finished */
static const uint8_t MODE_SYN       =  5; /* waiting for syn/ack */
static const uint8_t MODE_FIN       =  6; /* send fin, wait for ack */
static const uint8_t MODE_DATA      =  7; /* connection established */
static const uint8_t MODE_PMTUD     =  8; /* sending PTBs */
static const uint8_t MODE_BLACKHOLE =  9; /* don't send PTBs */
static const uint8_t MODE_ZEROWIN   = 10; /* wait for window update */
static const uint8_t MODE_MOREDATA  = 11; /* wait for new data beyond tail */
static const uint8_t MODE_BLIND     = 12; /* in process of blind packets */

#if defined(HAVE_OPENSSL)
static SSL_CTX *ssl_ctx = NULL;
#endif

/* Note : URL is only valid for HTTP tests. */
const char *scamper_do_tbit_usage(void)
{
  return
    "tbit [-t type] [-p app] [-d dport] [-s sport] [-b asn] [-f cookie]\n"
    "     [-m mss] [-M mtu] [-o offset] [-O option]\n"
    "     [-P ptbsrc] [-q attempts] [-S srcaddr] [-T ttl] [-u url]";
}

static scamper_tbit_t *tbit_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static tbit_state_t *tbit_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static void tbit_queue(scamper_task_t *task)
{
  tbit_state_t *state = tbit_getstate(task);

  if(slist_count(state->tx) > 0)
    scamper_task_queue_probe(task);
  else if(state->mode == MODE_DONE)
    scamper_task_queue_done(task, 0);
  else
    scamper_task_queue_wait_tv(task, &state->timeout);

  return;
}

/*
 * tbit_result:
 *
 * record the result, and then begin to gracefully end the connection.
 */
static void tbit_result(scamper_task_t *task, uint8_t result)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  int d = 0;

#ifdef HAVE_SCAMPER_DEBUG
  char addr[64], buf[16];
#endif

  switch(result)
    {
    case SCAMPER_TBIT_RESULT_NONE:
    case SCAMPER_TBIT_RESULT_TCP_NOCONN:
    case SCAMPER_TBIT_RESULT_TCP_NOCONN_RST:
    case SCAMPER_TBIT_RESULT_TCP_ERROR:
    case SCAMPER_TBIT_RESULT_TCP_RST:
    case SCAMPER_TBIT_RESULT_TCP_BADOPT:
    case SCAMPER_TBIT_RESULT_TCP_FIN:
    case SCAMPER_TBIT_RESULT_TCP_ZEROWIN:
    case SCAMPER_TBIT_RESULT_ERROR:
    case SCAMPER_TBIT_RESULT_ABORTED:
    case SCAMPER_TBIT_RESULT_HALTED:
    case SCAMPER_TBIT_RESULT_PMTUD_NOACK:
    case SCAMPER_TBIT_RESULT_PMTUD_FAIL:
    case SCAMPER_TBIT_RESULT_SACK_INCAPABLE:
    case SCAMPER_TBIT_RESULT_SACK_RCVR_SUCCESS:
    case SCAMPER_TBIT_RESULT_SACK_RCVR_SHIFTED:
    case SCAMPER_TBIT_RESULT_SACK_RCVR_TIMEOUT:
    case SCAMPER_TBIT_RESULT_SACK_RCVR_NOSACK:
    case SCAMPER_TBIT_RESULT_BLIND_RST:
    case SCAMPER_TBIT_RESULT_BLIND_ACCEPTED:
      d = 1;
      break;
    }

  if(state->flags & TBIT_STATE_FLAG_RST_SEEN)
    d = 1;

  if(tbit->result == SCAMPER_TBIT_RESULT_NONE)
    {
      tbit->result = result;
#ifdef HAVE_SCAMPER_DEBUG
      scamper_debug(__func__, "%s %s",
		    scamper_addr_tostr(tbit->dst, addr, sizeof(addr)),
		    scamper_tbit_res2str(tbit, buf, sizeof(buf)));
#endif
    }

  if(d == 0)
    {
      /* only set MODE_FIN if we are out of the SYN mode */
      if(state->mode != MODE_SYN)
	{
	  state->mode = MODE_FIN;
	  scamper_task_queue_probe(task);
	}
    }
  else
    {
      state->mode = MODE_DONE;
      scamper_task_queue_done(task, 0);
    }

  return;
}

static void tbit_classify(scamper_task_t *task)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_pmtud_t *pmtud;
  scamper_tbit_blind_t *blind;
  int ipv6 = SCAMPER_ADDR_TYPE_IS_IPV6(tbit->dst) ? 1 : 0;
  int bh = 0;

  if(tbit->result != SCAMPER_TBIT_RESULT_NONE)
    {
      if(state->flags & TBIT_STATE_FLAG_RST_SEEN)
	{
	  state->mode = MODE_DONE;
	  scamper_task_queue_done(task, 0);
	}
      return;
    }

  if(tbit->type == SCAMPER_TBIT_TYPE_PMTUD)
    {
      pmtud = tbit->data;
      if(pmtud->options & SCAMPER_TBIT_PMTUD_OPTION_BLACKHOLE)
	bh = 1;

      /*
       * if we receive a reset, then the measurement is finished.
       * if we have sent two PTBs, we class it as a failure.
       */
      if(state->flags & TBIT_STATE_FLAG_RST_SEEN)
	{
	  if(state->pmtud_ptb_c >= 2)
	    tbit_result(task, SCAMPER_TBIT_RESULT_PMTUD_FAIL);
	  else
	    tbit_result(task, SCAMPER_TBIT_RESULT_TCP_RST);
	}
      else if(state->mode == MODE_ZEROWIN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_ZEROWIN);
      /* if we haven't seen any data */
      else if((state->flags & TBIT_STATE_FLAG_SEEN_DATA) == 0)
	tbit_result(task, SCAMPER_TBIT_RESULT_PMTUD_NODATA);
      /* if we were trying to solicit a fragmentation header but couldn't */
      else if(state->pmtud_ptb_c == 0 && ipv6 && bh == 0 && pmtud->mtu < 1280)
	tbit_result(task, SCAMPER_TBIT_RESULT_NONE);
      /* if we sent any PTBs but didn't see an appropriate reduction, fail */
      else if(state->pmtud_ptb_c > 0)
	tbit_result(task, SCAMPER_TBIT_RESULT_PMTUD_FAIL);
      /* if the IP DF was not set on sufficiently large packets */
      else if(ipv6 == 0 && state->flags & TBIT_STATE_FLAG_NODF)
	tbit_result(task, SCAMPER_TBIT_RESULT_PMTUD_NODF);
      /* faking a blackhole */
      else if(state->mode == MODE_BLACKHOLE)
	tbit_result(task, SCAMPER_TBIT_RESULT_PMTUD_FAIL);
      /* otherwise, we just didn't see a sufficiently large packet */
      else
	tbit_result(task, SCAMPER_TBIT_RESULT_PMTUD_TOOSMALL);
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_ECN)
    {
      if(state->ecn_flags & TBIT_STATE_ECN_FLAG_ECE_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_ECN_SUCCESS);
      else if(state->flags & TBIT_STATE_FLAG_RST_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_RST);
      else if(state->mode == MODE_ZEROWIN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_ZEROWIN);
      else if(state->ecn_flags & TBIT_STATE_ECN_FLAG_CE_SENT)
	tbit_result(task, SCAMPER_TBIT_RESULT_ECN_NOECE);
      else if((state->flags & TBIT_STATE_FLAG_SEEN_DATA) == 0)
	tbit_result(task, SCAMPER_TBIT_RESULT_ECN_NODATA);
      return;
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_NULL)
    {
      if(state->flags & TBIT_STATE_FLAG_RST_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_RST);
      else if(state->mode == MODE_ZEROWIN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_ZEROWIN);
      else if((state->flags & TBIT_STATE_FLAG_SEEN_DATA) == 0)
	tbit_result(task, SCAMPER_TBIT_RESULT_NULL_NODATA);
      else
	tbit_result(task, SCAMPER_TBIT_RESULT_NULL_SUCCESS);
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_SACK_RCVR)
    {
      if(state->sackr_flags & TBIT_STATE_SACKR_FLAG_INCAPABLE)
	tbit_result(task, SCAMPER_TBIT_RESULT_SACK_INCAPABLE);
      else if(state->sackr_flags & TBIT_STATE_SACKR_FLAG_SHIFTED)
	tbit_result(task, SCAMPER_TBIT_RESULT_SACK_RCVR_SHIFTED);
      else if(state->flags & TBIT_STATE_FLAG_RST_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_RST);
      else if(state->mode == MODE_ZEROWIN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_ZEROWIN);
      else if(state->flags & TBIT_STATE_FLAG_FIN_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_FIN);
      else if(state->sackr_rx[0] > 3)
	tbit_result(task, SCAMPER_TBIT_RESULT_SACK_RCVR_NOSACK);
      else if(state->sackr_flags & TBIT_STATE_SACKR_FLAG_BADOPT)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_BADOPT);
      else if(state->sackr_timeout > 2)
	tbit_result(task, SCAMPER_TBIT_RESULT_SACK_RCVR_TIMEOUT);
      else
	tbit_result(task, SCAMPER_TBIT_RESULT_SACK_RCVR_SUCCESS);
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_ICW)
    {
      if(state->flags & TBIT_STATE_FLAG_RST_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_RST);
      else if(state->flags & TBIT_STATE_FLAG_FIN_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_FIN);
      else
	tbit_result(task, SCAMPER_TBIT_RESULT_NONE);
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA ||
	  tbit->type == SCAMPER_TBIT_TYPE_BLIND_FIN)
    {
      if(state->blind_flags & TBIT_STATE_BLIND_FLAG_ACCEPTED)
	tbit_result(task, SCAMPER_TBIT_RESULT_BLIND_ACCEPTED);
      else if(state->blind_flags & TBIT_STATE_BLIND_FLAG_CHALLENGE)
	tbit_result(task, SCAMPER_TBIT_RESULT_BLIND_CHALLENGE);
      else if(state->blind_flags & TBIT_STATE_BLIND_FLAG_SILENCE)
	tbit_result(task, SCAMPER_TBIT_RESULT_BLIND_IGNORED);
      else if(state->blind_flags & TBIT_STATE_BLIND_FLAG_RST)
	tbit_result(task, SCAMPER_TBIT_RESULT_BLIND_RST);
      else if(state->flags & TBIT_STATE_FLAG_RST_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_RST);
      else if(state->flags & TBIT_STATE_FLAG_FIN_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_FIN);
      else
	tbit_result(task, SCAMPER_TBIT_RESULT_NONE);
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_RST)
    {
      blind = tbit->data;
      if(state->blind_flags & TBIT_STATE_BLIND_FLAG_CHALLENGE)
	tbit_result(task, SCAMPER_TBIT_RESULT_BLIND_CHALLENGE);
      else if(state->blind_c >= blind->retx)
	tbit_result(task, SCAMPER_TBIT_RESULT_BLIND_IGNORED);
      else if(state->blind_flags & TBIT_STATE_BLIND_FLAG_FIN ||
	      state->flags & TBIT_STATE_FLAG_FIN_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_FIN);
      else if(state->flags & TBIT_STATE_FLAG_RST_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_RST);
      else if(state->blind_c == 1 && state->blind_ignored == 0)
	tbit_result(task, SCAMPER_TBIT_RESULT_BLIND_ACCEPTED);
      else
	tbit_result(task, SCAMPER_TBIT_RESULT_NONE);
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_SYN)
    {
      blind = tbit->data;
      if(state->blind_flags & TBIT_STATE_BLIND_FLAG_RST)
	tbit_result(task, SCAMPER_TBIT_RESULT_BLIND_RST);
      else if(state->blind_flags & TBIT_STATE_BLIND_FLAG_CHALLENGE)
	tbit_result(task, SCAMPER_TBIT_RESULT_BLIND_CHALLENGE);
      else if(state->blind_c >= blind->retx)
	tbit_result(task, SCAMPER_TBIT_RESULT_BLIND_IGNORED);
      else if(state->blind_flags & TBIT_STATE_BLIND_FLAG_FIN ||
	      state->flags & TBIT_STATE_FLAG_FIN_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_FIN);
      else if(state->flags & TBIT_STATE_FLAG_RST_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_RST);
      else if(state->flags & TBIT_STATE_FLAG_FIN_SEEN)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_FIN);
      else
	tbit_result(task, SCAMPER_TBIT_RESULT_NONE);
    }
  else
    {
      scamper_debug(__func__, "unhandled type %d", tbit->type);
      tbit_result(task, SCAMPER_TBIT_RESULT_NONE);
    }

  return;
}

/*
 * tbit_tcpclosed
 *
 * function to see if both ends have exchanged fins.
 */
static int tbit_tcpclosed(tbit_state_t *state)
{
  if((state->flags & TBIT_STATE_FLAG_FIN_SEEN) != 0 &&
     (state->flags & TBIT_STATE_FLAG_FIN_ACKED) != 0)
    return 1;
  return 0;
}

static void tbit_handleerror(scamper_task_t *task, int error)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  tbit->result = SCAMPER_TBIT_RESULT_ERROR;
  if(state != NULL) state->mode = MODE_DONE;
  scamper_task_queue_done(task, 0);
  return;
}

static void tbit_frags_free(tbit_frags_t *frags)
{
  int i;

  if(frags == NULL)
    return;

  if(frags->frags != NULL)
    {
      for(i=0; i<frags->fragc; i++)
	{
	  free(frags->frags[i]->data);
	  free(frags->frags[i]);
	}
      free(frags->frags);
    }
  free(frags);
  return;
}

static int tbit_frags_cmp(const tbit_frags_t *a, const tbit_frags_t *b)
{
  if(a->id < b->id) return -1;
  if(a->id > b->id) return  1;
  return 0;
}

static int tbit_frag_cmp(const tbit_frag_t *a, const tbit_frag_t *b)
{
  if(a->off < b->off) return -1;
  if(a->off > b->off) return  1;
  return 0;
}

static int tbit_reassemble(scamper_task_t *task, scamper_dl_rec_t **out,
			   scamper_dl_rec_t *dl)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_pmtud_t *pmtud;
  scamper_dl_rec_t *newp = NULL;
  tbit_frags_t fmfs, *frags;
  tbit_frag_t fmf, *frag, *next;
  uint8_t *data = NULL;
  size_t off;
  uint16_t mtu;
  int i, rc, pos, ipv4 = 0, ipv6 = 0;

  /* empty fragment? */
  if(dl->dl_ip_datalen == 0 || dl->dl_ip_proto != IPPROTO_TCP)
    {
      scamper_debug(__func__, "ignoring fragment %d %d",
		    dl->dl_ip_datalen, dl->dl_ip_proto);
      return 0;
    }

  if(dl->dl_af == AF_INET)
    ipv4 = 1;
  else
    ipv6 = 1;

  /* if we are doing path mtu discovery, the fragment might not be accepted */
  if(tbit->type == SCAMPER_TBIT_TYPE_PMTUD)
    {
      pmtud = tbit->data;

      if(ipv4 || pmtud->mtu > 1280)
	mtu = pmtud->mtu;
      else
	mtu = 1280;

      /*
       * if the packet is larger than the psuedo mtu, we can't reassemble
       * it since in theory we didn't receive it.
       * if the fragment offset is zero, pass it back to trigger a PTB.
       */
      if((ipv6 || SCAMPER_DL_IS_IP_DF(dl)) && dl->dl_ip_size > mtu)
	{
	  if(dl->dl_ip_off == 0)
	    *out = dl;
	  return 0;
	}
    }

  /* see if we have other fragments for this packet. if not, create new rec */
  if(ipv4)
    fmfs.id = dl->dl_ip_id;
  else
    fmfs.id = dl->dl_ip6_id;
  pos = array_findpos((void **)state->frags, state->fragc, &fmfs,
		      (array_cmp_t)tbit_frags_cmp);
  if(pos >= 0)
    {
      frags = state->frags[pos];
    }
  else
    {
      if((frags = malloc_zero(sizeof(tbit_frags_t))) == NULL)
	{
	  printerror(__func__, "could not malloc frags");
	  goto err;
	}
      frags->id = fmfs.id;
      rc=array_insert((void ***)&state->frags, &state->fragc, frags,
		      (array_cmp_t)tbit_frags_cmp);
      if(rc != 0)
	{
	  printerror(__func__, "could not insert frags");
	  goto err;
	}
      pos = array_findpos((void **)state->frags, state->fragc, frags,
			  (array_cmp_t)tbit_frags_cmp);
      assert(pos != -1);
    }

  /* add the fragment to the collection */
  fmf.off = dl->dl_ip_off;
  frag = array_find((void **)frags->frags, frags->fragc, &fmf,
		    (array_cmp_t)tbit_frag_cmp);
  if(frag == NULL)
    {
      if((frag = malloc_zero(sizeof(tbit_frag_t))) == NULL)
	{
	  printerror(__func__, "could not malloc frag");
	  goto err;
	}
      frag->off = fmf.off;

      if((frag->data = memdup(dl->dl_ip_data, dl->dl_ip_datalen)) == NULL)
	{
	  printerror(__func__, "could not dup %d", dl->dl_ip_datalen);
	  goto err;
	}
      frag->datalen = dl->dl_ip_datalen;

      if(array_insert((void ***)&frags->frags, &frags->fragc, frag,
		      (array_cmp_t)tbit_frag_cmp) != 0)
	{
	  printerror(__func__, "could not add frag");
	  goto err;
	}

      if(SCAMPER_DL_IS_IP_MF(dl) == 0)
	frags->gotlast = 1;
    }

  /* can't reassemble a packet without the last fragment */
  if(frags->gotlast == 0 || frags->fragc < 2)
    {
      return 0;
    }

  for(i=0; i<frags->fragc-1; i++)
    {
      frag = frags->frags[i];
      next = frags->frags[i+1];

      if(frag->off + frag->datalen != next->off)
	{
	  return 0;
	}
    }

  frag = frags->frags[frags->fragc-1];
  if((data = malloc_zero(frag->off + frag->datalen)) == NULL)
    {
      printerror(__func__, "could not malloc data");
      goto err;
    }
  for(i=0, off=0; i<frags->fragc; i++)
    {
      frag = frags->frags[i];
      memcpy(data+off, frag->data, frag->datalen);
      off += frag->datalen;
    }
  array_remove((void **)state->frags, &state->fragc, pos);
  tbit_frags_free(frags);

  if((newp = malloc_zero(sizeof(scamper_dl_rec_t))) == NULL)
    {
      printerror(__func__, "could not malloc newp");
      goto err;
    }

  timeval_cpy(&newp->dl_tv, &dl->dl_tv);
  newp->dl_type       = SCAMPER_DL_TYPE_RAW;
  newp->dl_net_type   = SCAMPER_DL_REC_NET_TYPE_IP;
  newp->dl_ifindex    = dl->dl_ifindex;
  newp->dl_af         = dl->dl_af;
  newp->dl_ip_hl      = dl->dl_ip_hl;
  newp->dl_ip_proto   = dl->dl_ip_proto;
  newp->dl_ip_size    = dl->dl_ip_hl + off;
  newp->dl_ip_id      = dl->dl_ip_id;
  newp->dl_ip6_id     = dl->dl_ip6_id;
  newp->dl_ip_tos     = dl->dl_ip_tos;
  newp->dl_ip_ttl     = dl->dl_ip_ttl;
  newp->dl_ip_src     = dl->dl_ip_src;
  newp->dl_ip_dst     = dl->dl_ip_dst;
  newp->dl_ip_flow    = dl->dl_ip_flow;
  newp->dl_ip_data    = data;
  newp->dl_ip_datalen = off;
  newp->dl_ip_flags   = SCAMPER_DL_IP_FLAG_REASS;

  if(sizeof(struct tcphdr) > newp->dl_ip_datalen)
    {
      free(newp);
      free(data);
      return 0;
    }

  newp->dl_tcp_sport   = bytes_ntohs(data+0);
  newp->dl_tcp_dport   = bytes_ntohs(data+2);
  newp->dl_tcp_seq     = bytes_ntohl(data+4);
  newp->dl_tcp_ack     = bytes_ntohl(data+8);
  newp->dl_tcp_hl      = (data[12] >> 4) * 4;
  newp->dl_tcp_flags   = data[13];
  newp->dl_tcp_win     = bytes_ntohs(data+14);
  newp->dl_tcp_datalen = newp->dl_ip_datalen - newp->dl_tcp_hl;
  if(newp->dl_tcp_datalen > 0)
    newp->dl_tcp_data  = data + newp->dl_tcp_hl;

  *out = newp;
  return 0;

 err:
  if(newp != NULL) free(newp);
  if(data != NULL) free(data);
  return -1;
}

static void tp_free(tbit_probe_t *tp)
{
  if(tp == NULL)
    return;
  free(tp);
  return;
}

static tbit_probe_t *tp_alloc(tbit_state_t *state, uint8_t type)
{
  tbit_probe_t *tp;
  if((tp = malloc_zero(sizeof(tbit_probe_t))) == NULL)
    {
      printerror(__func__, "could not malloc tp");
      return NULL;
    }
  if(slist_tail_push(state->tx, tp) == NULL)
    {
      printerror(__func__, "could not queue tp");
      free(tp);
      return NULL;
    }
  tp->type = type;
  return tp;
}

static tbit_probe_t *tp_tcp(tbit_state_t *state)
{
  tbit_probe_t *tp;
  if((tp = tp_alloc(state, TBIT_PROBE_TYPE_TCP)) == NULL)
    return NULL;
  tp->tp_flags = TH_ACK;
  tp->tp_seq   = state->snd_nxt;
  tp->tp_ack   = state->rcv_nxt;
  return tp;
}

static tbit_probe_t *tp_ptb(tbit_state_t *state)
{
  return tp_alloc(state, TBIT_PROBE_TYPE_PTB);
}

static void tp_flush(tbit_state_t *state, tbit_probe_t *tp_stop)
{
  tbit_probe_t *tp;
  for(;;)
    {
      if((tp = slist_head_item(state->tx)) == NULL || tp == tp_stop)
	break;
      slist_head_pop(state->tx);
      tp_free(tp);
    }
  return;
}

static void tbit_segment_free(tbit_segment_t *seg)
{
  if(seg == NULL)
    return;
  if(seg->data != NULL)
    free(seg->data);
  free(seg);
  return;
}

static int tbit_segment(tbit_state_t *state, const uint8_t *data, uint16_t len)
{
  tbit_segment_t *seg = NULL;

  if((seg = malloc_zero(sizeof(tbit_segment_t))) == NULL)
    {
      printerror(__func__, "could not malloc seg");
      goto err;
    }
  if((seg->data = memdup(data, len)) == NULL)
    {
      printerror(__func__, "could not malloc seg->data");
      goto err;
    }
  seg->len = len;
  if(slist_tail_push(state->segments, seg) == NULL)
    {
      printerror(__func__, "could not add seg");
      goto err;
    }

  return 0;

 err:
  tbit_segment_free(seg);
  return -1;
}

static int tbit_data_inrange(tbit_state_t *state, uint32_t seq, uint32_t len)
{
  if(scamper_tbit_data_inrange(state->rcv_nxt, seq, len) != 0)
    return 1;
  scamper_debug(__func__, "out of sequence");
  return 0;
}

static int tbit_rxq(tbit_state_t *state, const scamper_dl_rec_t *dl)
{
  void *data = NULL;

  assert(dl->dl_ip_proto == IPPROTO_TCP);
  assert(dl->dl_tcp_datalen > 0 || (dl->dl_tcp_flags & TH_FIN) != 0);

  if(state->rxq == NULL &&
     (state->rxq = scamper_tbit_tcpq_alloc(state->rcv_nxt)) == NULL)
    {
      printerror(__func__, "could not alloc tcpq");
      goto err;
    }

  if(dl->dl_tcp_datalen > 0 &&
     (data = memdup(dl->dl_tcp_data, dl->dl_tcp_datalen)) == NULL)
    {
      printerror(__func__, "could not dup %d bytes", dl->dl_tcp_datalen);
      goto err;
    }

  if(scamper_tbit_tcpq_add(state->rxq, dl->dl_tcp_seq, dl->dl_tcp_flags,
			   dl->dl_tcp_datalen, data) != 0)
    {
      printerror(__func__, "could not add %u/%2x/%u",
		 dl->dl_tcp_seq, dl->dl_tcp_flags, dl->dl_tcp_datalen);
      goto err;
    }

  return 0;

 err:
  if(data != NULL) free(data);
  return -1;
}

#if defined(HAVE_OPENSSL)
static int tbit_ssl_wbio_write(tbit_state_t *state)
{
  uint8_t buf[1024];
  int pending, rc, size, off = 0;

  if((pending = BIO_pending(state->wbio)) < 0)
    return -1;

  while(off < pending)
    {
      if(pending - off > sizeof(buf))
	size = sizeof(buf);
      else
	size = pending - off;

      if((rc = BIO_read(state->wbio, buf, size)) <= 0)
	{
	  if(BIO_should_retry(state->wbio) == 0)
	    scamper_debug(__func__, "BIO_read should not retry");
	  else
	    scamper_debug(__func__, "BIO_read returned %d", rc);
	  return -1;
	}
      off += rc;

      if(tbit_segment(state, buf, rc) != 0)
	return -1;
    }

  return pending;
}

static ssize_t tbit_ssl_write(tbit_state_t *state, uint8_t *buf, size_t len)
{
  SSL_write(state->ssl, buf, len);
  return tbit_ssl_wbio_write(state);
}

static ssize_t tbit_ssl_init(tbit_state_t *state, char *name)
{
  int rc;

  /*
   * the order is important because once the BIOs are associated with
   * the ssl structure, SSL_free will clean them up.
   */
  if((state->wbio = BIO_new(BIO_s_mem())) == NULL ||
     (state->rbio = BIO_new(BIO_s_mem())) == NULL ||
     (state->ssl = SSL_new(ssl_ctx)) == NULL)
    return -1;

  SSL_set_bio(state->ssl, state->rbio, state->wbio);
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
  if(name != NULL) SSL_set_tlsext_host_name(state->ssl, name);
#endif
  SSL_set_connect_state(state->ssl);

  rc = SSL_do_handshake(state->ssl);
  assert(rc <= 0);

  if((rc = SSL_get_error(state->ssl, rc)) == SSL_ERROR_WANT_READ)
    return tbit_ssl_wbio_write(state);

  scamper_debug(__func__, "SSL_do_handshake error %d", rc);
  return -1;
}
#endif

static int tbit_app_http_req(scamper_task_t *task)
{
  static const char *http_ua =
    "Mozilla/5.0 (X11; U; FreeBSD i386; en-US; rv:1.9.1.2) "
    "Gecko/20090806 Firefox/3.5.2";
  scamper_tbit_t *tbit = tbit_getdata(task);
  scamper_tbit_app_http_t *http = tbit->app_data;
  tbit_state_t *state = tbit_getstate(task);
  char buf[512];
  size_t off = 0;

  string_concat(buf, sizeof(buf), &off, "GET %s HTTP/1.0\r\n", http->file);
  if(http->host != NULL)
    string_concat(buf, sizeof(buf), &off, "Host: %s\r\n", http->host);
  string_concat(buf, sizeof(buf), &off,
		"Connection: Keep-Alive\r\n"
		"Accept: */*\r\n"
		"User-Agent: %s\r\n\r\n", http_ua);

#if defined(HAVE_OPENSSL)
  if(state->ssl != NULL)
    return tbit_ssl_write(state, (uint8_t *)buf, off);
#endif

  if(tbit_segment(state, (uint8_t *)buf, off) != 0)
    return -1;
  return off;
}

static int tbit_app_http_rx(scamper_task_t *task, uint8_t *data, uint16_t dlen)
{
  tbit_state_t *state = tbit_getstate(task);
  int rc;

#if defined(HAVE_OPENSSL)
  scamper_tbit_t *tbit = tbit_getdata(task);
  scamper_tbit_app_http_t *http = tbit->app_data;
  char buf[4096];
#endif

  if(state->flags & TBIT_STATE_FLAG_NOMOREDATA)
    return 0;

  if(state->mode == MODE_SYN || state->mode == MODE_RTSOCK)
    {
#if defined(HAVE_OPENSSL)
      if(http->type == SCAMPER_TBIT_APP_HTTP_TYPE_HTTPS)
	return tbit_ssl_init(state, http->host);
#endif
      if((rc = tbit_app_http_req(task)) < 0)
	return -1;
      state->flags |= TBIT_STATE_FLAG_NOMOREDATA;
      return rc;
    }

#if defined(HAVE_OPENSSL)
  if(dlen > 0 && state->ssl != NULL)
    {
      BIO_write(state->rbio, data, dlen);
      if(state->ssl_mode == TBIT_STATE_SSL_MODE_HANDSHAKE)
	{
	  if(SSL_is_init_finished(state->ssl) != 0 ||
	     (rc = SSL_do_handshake(state->ssl)) > 0)
	    {
	      state->ssl_mode = TBIT_STATE_SSL_MODE_ESTABLISHED;
	      state->flags |= TBIT_STATE_FLAG_NOMOREDATA;
	      return tbit_app_http_req(task);
	    }
	  return tbit_ssl_wbio_write(state);
	}
      else if(state->ssl_mode == TBIT_STATE_SSL_MODE_ESTABLISHED)
	{
	  while((rc = SSL_read(state->ssl, buf, sizeof(buf))) > 0);
	  return tbit_ssl_wbio_write(state);
	}
    }
#endif

  return 0;
}

static int tbit_app_bgp_req(scamper_task_t *task)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_app_bgp_t *bgp = tbit->app_data;
  uint8_t buf[29]; /* BGP 20B header + 9B OPEN w/o options */
  size_t off = 0;

  /* bgp header */
  for(off=0; off<16; off++)
    buf[off] = 0xff;
  bytes_htons(buf+off, 29); off += 2; /* length */
  buf[off++] = 1; /* type = BGP_OPEN */
  buf[off++] = 4; /* version = 4 */

  /* bgp open */
  bytes_htons(buf+off, (uint16_t)bgp->asn); off += 2;
  bytes_htons(buf+off, 180); off += 2; /* hold time */
  bytes_htonl(buf+off, 12345); off += 4; /* id */
  buf[off++] = 0; /* options length */

  if(tbit_segment(state, (uint8_t *)buf, off) != 0)
    return -1;
  return off;
}

static int tbit_app_bgp_rx(scamper_task_t *task, uint8_t *data, uint16_t dlen)
{
  tbit_state_t *state = tbit_getstate(task);
  int rc;

  if(state->flags & TBIT_STATE_FLAG_NOMOREDATA)
    return 0;

  if(state->mode == MODE_SYN || state->mode == MODE_RTSOCK)
    {
      if((rc = tbit_app_bgp_req(task)) < 0)
	return -1;
      state->flags |= TBIT_STATE_FLAG_NOMOREDATA;
      return rc;
    }

  return 0;
}

static int tbit_app_rx(scamper_task_t *task, uint8_t *data, uint16_t len)
{
  static int (* const func[])(scamper_task_t *, uint8_t *, uint16_t) = {
    NULL,
    tbit_app_http_rx,
    NULL,
    NULL,
    NULL,
    tbit_app_bgp_rx,
  };
  scamper_tbit_t *tbit = tbit_getdata(task);

  assert(tbit->app_proto == SCAMPER_TBIT_APP_HTTP ||
         tbit->app_proto == SCAMPER_TBIT_APP_BGP);

  return func[tbit->app_proto](task, data, len);
}

static void timeout_generic_error(scamper_task_t *task)
{
  tbit_result(task, SCAMPER_TBIT_RESULT_ERROR);
  return;
}

/*
 * dl_syn:
 *
 * handles the response to a SYN - It should be a SYN/ACK.
 */
static void dl_syn(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_null_t *null;
  tbit_segment_t *seg = slist_head_item(state->segments);
  tbit_probe_t *tp = NULL;
  uint32_t ab;
  uint8_t mode = MODE_DATA;
  int rc;

  if(SCAMPER_DL_IS_TCP_SYNACK(dl) == 0 || dl->dl_tcp_ack <= state->snd_nxt)
    {
      if(dl->dl_tcp_flags & TH_RST)
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_NOCONN_RST);
      else
	tbit_result(task, SCAMPER_TBIT_RESULT_TCP_NOCONN);
      return;
    }

  /* increment our sequence number, and remember the seq we expect from them */
  state->snd_nxt++;
  state->sa_seq = dl->dl_tcp_seq;
  state->rcv_nxt = dl->dl_tcp_seq + 1;

  /*
   * if the sender appears to be acking data, it might be because we used
   * TCP fast open
   */
  if((ab = dl->dl_tcp_ack - state->snd_nxt) > 0)
    {
      if(seg == NULL || ab > seg->len)
	{
	  tbit_result(task, SCAMPER_TBIT_RESULT_TCP_NOCONN);
	  return;
	}
      if(ab == seg->len)
	{
	  slist_head_pop(state->segments);
	  tbit_segment_free(seg);
	}
      else
	{
	  memmove(seg->data, seg->data+ab, seg->len-ab);
	  seg->len -= ab;
	}
      state->snd_nxt += ab;
    }

  if((tbit->options & SCAMPER_TBIT_OPTION_TCPTS) &&
     (dl->dl_tcp_opts & SCAMPER_DL_TCP_OPT_TS) != 0)
    {
      state->flags |= TBIT_STATE_FLAG_TCPTS;
      state->ts_recent = dl->dl_tcp_tsval;
    }

  /* check if we got the expected response to an ECN-syn */
  if(tbit->type == SCAMPER_TBIT_TYPE_ECN)
    {
      if((dl->dl_tcp_flags & (TH_ECE|TH_CWR)) != TH_ECE)
	{
	  if((dl->dl_tcp_flags & (TH_ECE|TH_CWR)) == 0)
	    tbit_result(task, SCAMPER_TBIT_RESULT_ECN_INCAPABLE);
	  else
	    tbit_result(task, SCAMPER_TBIT_RESULT_ECN_BADSYNACK);
	}
      else
	{
	  state->ecn_flags |= TBIT_STATE_ECN_FLAG_ECT;
	  state->ecn_flags |= TBIT_STATE_ECN_FLAG_CE_SET;
	}
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_SACK_RCVR)
    {
      if((dl->dl_tcp_opts & SCAMPER_DL_TCP_OPT_SACKP) == 0)
	state->sackr_flags |= TBIT_STATE_SACKR_FLAG_INCAPABLE;
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_NULL)
    {
      null = tbit->data;
      if((tbit->options & SCAMPER_TBIT_OPTION_TCPTS) != 0 &&
	 (dl->dl_tcp_opts & SCAMPER_DL_TCP_OPT_TS) != 0)
	{
	  null->results |= SCAMPER_TBIT_NULL_RESULT_TCPTS;
	}
      if((tbit->options & SCAMPER_TBIT_OPTION_SACK) != 0 &&
	 (dl->dl_tcp_opts & SCAMPER_DL_TCP_OPT_SACKP) != 0)
	{
	  null->results |= SCAMPER_TBIT_NULL_RESULT_SACK;
	  state->flags |= TBIT_STATE_FLAG_SACK;
	}
      if((((null->options & SCAMPER_TBIT_NULL_OPTION_FO) != 0 &&
	   (dl->dl_tcp_opts & SCAMPER_DL_TCP_OPT_FO) != 0) ||
	  ((null->options & SCAMPER_TBIT_NULL_OPTION_FO_EXP) != 0 &&
	   (dl->dl_tcp_opts & SCAMPER_DL_TCP_OPT_FO_EXP) != 0)) &&
	 dl->dl_tcp_fo_cookielen > 0 && tbit->fo_cookielen == 0)
	{
	  null->results |= SCAMPER_TBIT_NULL_RESULT_FO;
	}
    }

  tbit->server_mss = dl->dl_tcp_mss;

  if(tbit->fo_cookie != NULL)
    {
      rc = 0;
      if(dl->dl_tcp_datalen > 0)
	{
	  if((rc = tbit_app_rx(task, dl->dl_tcp_data, dl->dl_tcp_datalen)) < 0)
	    goto err;
	  state->rcv_nxt += dl->dl_tcp_datalen;
	}
    }
  else
    {
      if((rc = tbit_app_rx(task, NULL, 0)) < 0)
	goto err;
    }

  /* send a pure ack to their data */
  if((tp = tp_tcp(state)) == NULL)
    goto err;

  /* send our request if there is one */
  if(rc > 0)
    {
      /*
       * handle receivers who advertise a zero window in a syn/ack and
       * expect the sender to wait until it has issued a window update
       */
      if(dl->dl_tcp_win == 0)
	{
	  tp->wait = TBIT_TIMEOUT_DEFAULT;
  	  state->mode = MODE_ZEROWIN;
	  tbit_queue(task);
	  return;
	}

      if((tp = tp_tcp(state)) == NULL)
	goto err;
      tp->tp_len = rc;

      if(tbit->type == SCAMPER_TBIT_TYPE_SACK_RCVR)
	{
	  /* send one byte of the data in the SACK test */
	  tp->tp_len = 1;
	  tp->wait = TBIT_TIMEOUT_SACK;
	}
      else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA ||
	      tbit->type == SCAMPER_TBIT_TYPE_BLIND_FIN)
	{
	  state->blind_part1 = rc / 3;
	  if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA)
	    {
	      state->blind_part2 = state->blind_part1;
	      state->blind_part3 = rc - state->blind_part1 - state->blind_part2;
	    }
	  else
	    {
	      state->blind_part2 = rc - state->blind_part1;
	      state->blind_ack = state->snd_nxt + rc;
	    }
	  tp->tp_len = state->blind_part1;
	  tp->wait = TBIT_TIMEOUT_BLINDDATA;
	}
      else
	{
	  tp->wait = TBIT_TIMEOUT_DEFAULT;
	}

      if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_RST ||
	 tbit->type == SCAMPER_TBIT_TYPE_BLIND_SYN ||
	 tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA ||
	 tbit->type == SCAMPER_TBIT_TYPE_BLIND_FIN)
	mode = MODE_BLIND;

      state->attempt = 0;
    }

  state->mode = mode;
  tbit_queue(task);
  return;

 err:
  tbit_handleerror(task, errno);
  return;
}

static void timeout_syn(scamper_task_t *task)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  if(state->attempt >= tbit->syn_retx)
    tbit_result(task, SCAMPER_TBIT_RESULT_TCP_NOCONN);
  return;
}

static void dl_fin(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_tcpqe_t *qe;
  tbit_probe_t *tp;
  uint32_t seq;
  uint16_t datalen;
  uint8_t flags;
  int x;

  timeval_add_ms(&state->timeout, &dl->dl_tv, TBIT_TIMEOUT_LONG);

  /* see if the remote host has acked our fin */
  if(dl->dl_tcp_ack == state->snd_nxt + 1 &&
     (state->flags & TBIT_STATE_FLAG_FIN_ACKED) == 0)
    {
      state->flags |= TBIT_STATE_FLAG_FIN_ACKED;
      state->snd_nxt++;
    }

  /* check if the remote host has received our ack to their fin */
  if((state->flags & TBIT_STATE_FLAG_FIN_SEEN) &&
     dl->dl_tcp_seq == state->rcv_nxt)
    {
      if(tbit_tcpclosed(state))
	{
	  if(tbit->result == SCAMPER_TBIT_RESULT_NONE)
	    tbit_classify(task);
	  state->mode = MODE_DONE;
	  tbit_queue(task);
	}
      return;
    }

  /* if there is nothing to ack, then don't generate an ack */
  if(dl->dl_tcp_datalen == 0 && (dl->dl_tcp_flags & TH_FIN) == 0)
    return;

  if((tp = tp_tcp(state)) == NULL)
    goto err;

  /* is the data in range? */
  if(tbit_data_inrange(state, dl->dl_tcp_seq, dl->dl_tcp_datalen) == 0)
    goto ack;

  if(tbit_rxq(state, dl) != 0)
    goto err;

  while(scamper_tbit_tcpq_seg(state->rxq, &seq, &datalen) == 0)
    {
      if(scamper_tbit_data_inrange(state->rcv_nxt, seq, datalen) == 0)
	{
	  scamper_tbit_tcpqe_free(scamper_tbit_tcpq_pop(state->rxq), free);
	  continue;
	}

      /* send an ack for the next packet we want */
      if((x = scamper_tbit_data_seqoff(state->rcv_nxt, seq)) > 0)
	break;

      qe = scamper_tbit_tcpq_pop(state->rxq);
      flags = qe->flags;
      scamper_tbit_tcpqe_free(qe, free);
      state->rcv_nxt += (datalen - abs(x));

      if((flags & TH_FIN) != 0)
	{
	  state->flags |= TBIT_STATE_FLAG_FIN_SEEN;
	  state->rcv_nxt++;
	}

      if((state->flags & TBIT_STATE_FLAG_FIN_ACKED) == 0)
	tp->tp_flags |= TH_FIN;

      if(tbit_tcpclosed(state))
	{
	  if(tbit->result == SCAMPER_TBIT_RESULT_NONE)
	    tbit_classify(task);
	  state->mode = MODE_DONE;
	  break;
	}
    }

 ack:
  tp->tp_ack = state->rcv_nxt;
  if(state->mode != MODE_DONE && (state->flags & TBIT_STATE_FLAG_SACK) != 0)
    {
      x = 4;
      if((state->flags & TBIT_STATE_FLAG_TCPTS) != 0)
	x--;
      tp->tp_sackb = scamper_tbit_tcpq_sack(state->rxq, tp->tp_sack, x);
    }

  tbit_queue(task);
  return;

 err:
  tbit_handleerror(task, errno);
  return;
}

static void timeout_fin(scamper_task_t *task)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);

  if(tbit->result == SCAMPER_TBIT_RESULT_NONE)
    tbit_classify(task);
  state->mode = MODE_DONE;
  tbit_queue(task);
  return;
}

/*
 * dl_data_pmtud
 *
 * this function is tasked with reading data from the end host until
 * it sends a packet that we can send a PTB for.  when that happens,
 * we send the PTB and then go into a mode where this function will never
 * be called again.
 */
static int dl_data_pmtud(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_pmtud_t *pmtud = tbit->data;
  tbit_probe_t *tp;
  int rc, bh = 0, ipv4 = 0, ipv6 = 0, skip = 0, frag = 0;
  uint16_t size;

  /* if it is out of sequence, then send an ack for what we want */
  if(dl->dl_tcp_seq != state->rcv_nxt)
    {
      if(tp_tcp(state) == NULL)
	goto err;
      return 0;
    }

  if(dl->dl_af == AF_INET)
    ipv4 = 1;
  else
    ipv6 = 1;

  if(SCAMPER_DL_IS_IP_FRAG(dl) != 0)
    frag = 1;

  if(pmtud->options & SCAMPER_TBIT_PMTUD_OPTION_BLACKHOLE)
    bh = 1;

  size = dl->dl_ip_size;

  /*
   * skip over tcp packets without data, packets that were allowed to be
   * reassembled, data packets without the DF bit set, data packets below
   * the MTU, and ipv6 packets with the fragmentation header set
   */
  if(dl->dl_tcp_datalen == 0 || SCAMPER_DL_IS_IP_REASS(dl) != 0)
    skip = 1;
  else if(ipv4 && SCAMPER_DL_IS_IP_DF(dl) == 0)
    skip = 1;
  else if((ipv4 || pmtud->mtu >= 1280) && size <= pmtud->mtu)
    skip = 1;
  else if(ipv6 && bh == 0 && pmtud->mtu < 1280 && frag != 0 && size <= 1280)
    skip = 1;
  else if(ipv6 && bh == 1 && size <= pmtud->mtu)
    skip = 1;

  if(dl->dl_tcp_datalen > 0)
    state->flags |= TBIT_STATE_FLAG_SEEN_DATA;

  if(skip)
    {
      if(dl->dl_tcp_datalen > 0)
	{
	  state->rcv_nxt += dl->dl_tcp_datalen;

	  if(ipv4 && SCAMPER_DL_IS_IP_DF(dl) == 0 &&
	     size > pmtud->mtu && SCAMPER_DL_IS_IP_REASS(dl) == 0)
	    state->flags |= TBIT_STATE_FLAG_NODF;
	}

      if(dl->dl_tcp_datalen > 0 || (dl->dl_tcp_flags & TH_FIN) != 0)
	{
	  if((rc = tbit_app_rx(task, dl->dl_tcp_data, dl->dl_tcp_datalen)) < 0)
	    goto err;
	  if((tp = tp_tcp(state)) == NULL)
	    goto err;
	  if(rc > 0)
            {
	      tp->tp_len = rc;
	      tp->wait = TBIT_TIMEOUT_DEFAULT;
	      state->attempt = 0;
            }

	  if((dl->dl_tcp_flags & TH_FIN) != 0)
	    {
	      tp->tp_flags |= TH_FIN;
	      tp->tp_ack++;
	      state->rcv_nxt++;
	      state->mode = MODE_FIN;
	      state->flags |= TBIT_STATE_FLAG_FIN_SEEN;
	    }
	}

      return 0;
    }

  /*
   * we've received a large frame, but we're not sending PTB.  see how
   * the remote host copes.
   */
  if(bh != 0)
    {
      state->mode = MODE_BLACKHOLE;
      return 0;
    }

  state->mode = MODE_PMTUD;

  if(dl->dl_af == AF_INET)
    state->pmtud_ptb_datalen = dl->dl_ip_hl + 8;
  else if(size >= 1280-40-8)
    state->pmtud_ptb_datalen = 1280 - 40 - 8;
  else
    state->pmtud_ptb_datalen = size;

  state->pmtud_ptb_data = memdup(dl->dl_net_raw, state->pmtud_ptb_datalen);
  if(state->pmtud_ptb_data == NULL)
    {
      printerror(__func__, "could not dup quote");
      goto err;
    }

  if(tp_ptb(state) == NULL)
    goto err;
  state->attempt = 0;

  return 0;

 err:
  tbit_handleerror(task, errno);
  return -1;
}

static void timeout_data_pmtud(scamper_task_t *task)
{
  tbit_result(task, SCAMPER_TBIT_RESULT_PMTUD_NODATA);
  return;
}

/*
 * dl_data_ecn
 *
 * read packets until we get an ECN-echo for our CE packet.
 */
static int dl_data_ecn(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  tbit_state_t *state = tbit_getstate(task);
  tbit_probe_t *tp = NULL;
  int rc, fin = 0;

  /*
   * look for the ECN echo bit in the TCP header.
   * if it is set, then we should set CWR until the host stops sending ECE.
   */
  if(dl->dl_tcp_flags & TH_ECE)
    {
      if((state->ecn_flags & TBIT_STATE_ECN_FLAG_ECE_SEEN) == 0)
	{
	  state->ecn_flags |= TBIT_STATE_ECN_FLAG_ECE_SEEN;
	  if((state->ecn_flags & TBIT_STATE_ECN_FLAG_CWR_SET) == 0)
	    state->ecn_flags |= TBIT_STATE_ECN_FLAG_CWR_SET;
	}
    }
  else
    {
      if(state->ecn_flags & TBIT_STATE_ECN_FLAG_CWR_SET)
	{
	  state->ecn_flags &= ~TBIT_STATE_ECN_FLAG_CWR_SET;
	  state->ecn_flags |= TBIT_STATE_ECN_FLAG_CWR_SENT;
	}
    }

  /* if it is out of sequence, then send an ack for what we want */
  if(dl->dl_tcp_seq != state->rcv_nxt)
    {
      if(tp_tcp(state) == NULL)
	goto err;
      return 0;
    }

  /*
   * if we were sending CE then we can stop now, because they have
   * received the packet we sent with CE marked.
   */
  if(state->ecn_flags & TBIT_STATE_ECN_FLAG_CE_SET)
    {
      state->ecn_flags &= ~TBIT_STATE_ECN_FLAG_CE_SET;
      state->ecn_flags |=  TBIT_STATE_ECN_FLAG_CE_SENT;
    }

  if((dl->dl_tcp_flags & TH_FIN) != 0)
    fin = 1;

  if(dl->dl_tcp_datalen > 0)
    {
      state->flags |= TBIT_STATE_FLAG_SEEN_DATA;
      state->rcv_nxt += dl->dl_tcp_datalen;
    }

  if(dl->dl_tcp_datalen > 0 || fin != 0)
    {
      if((rc = tbit_app_rx(task, dl->dl_tcp_data, dl->dl_tcp_datalen)) < 0)
	goto err;
      if((tp = tp_tcp(state)) == NULL)
	goto err;
      if(rc > 0)
	{
	  tp->tp_len = rc;
	  tp->wait = TBIT_TIMEOUT_DEFAULT;
	  state->attempt = 0;
	}
      if(fin != 0 || (state->ecn_flags & TBIT_STATE_ECN_FLAG_ECT) == 0)
	{
	  tp->tp_flags |= TH_FIN;
	  state->mode = MODE_FIN;
	  if(fin != 0)
	    {
	      state->flags |= TBIT_STATE_FLAG_FIN_SEEN;
	      state->rcv_nxt++;
	      tp->tp_ack++;
	    }
	}
    }

  return 0;

 err:
  tbit_handleerror(task, errno);
  return -1;
}

static void timeout_data_generic(scamper_task_t *task)
{
  tbit_state_t *state = tbit_getstate(task);
  tbit_classify(task);
  if(state->mode != MODE_FIN)
    {
      state->mode = MODE_FIN;
      scamper_task_queue_probe(task);
    }
  return;
}

/*
 * dl_data_null
 *
 * read packets until FIN.
 */
static int dl_data_null(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  tbit_state_t *state = tbit_getstate(task);
  tbit_probe_t *tp = NULL;
  scamper_tbit_tcpqe_t *qe = NULL;
  uint32_t seq;
  uint16_t datalen;
  int off, rc, fin, tx_fin = 0;

  /* if we've got no more data to send, transmit a fin */
  if((state->flags & TBIT_STATE_FLAG_NOMOREDATA) != 0 &&
     slist_count(state->segments) == 0)
    tx_fin = 1;

  /* skip over non-data packets unless we are ready to send a fin */
  if(dl->dl_tcp_datalen == 0 && (dl->dl_tcp_flags & TH_FIN) == 0)
    {
      if(tx_fin != 0 && (state->flags & TBIT_STATE_FLAG_SEEN_DATA) != 0)
	{
	  if((tp = tp_tcp(state)) == NULL)
	    goto err;
	  tp->tp_flags |= TH_FIN;
	  state->mode = MODE_FIN;
	}
      return 0;
    }

  if(tbit_data_inrange(state, dl->dl_tcp_seq, dl->dl_tcp_datalen) == 0)
    return 0;
  if(tbit_rxq(state, dl) != 0)
    goto err;

  while(scamper_tbit_tcpq_seg(state->rxq, &seq, &datalen) == 0)
    {
      if(scamper_tbit_data_inrange(state->rcv_nxt, seq, datalen) == 0)
	{
	  scamper_tbit_tcpqe_free(scamper_tbit_tcpq_pop(state->rxq), free);
	  continue;
	}

      if(datalen > 0)
	state->flags |= TBIT_STATE_FLAG_SEEN_DATA;

      /* send an ack for the next packet we want */
      if((off = scamper_tbit_data_seqoff(state->rcv_nxt, seq)) > 0)
	{
	  if((tp = tp_tcp(state)) == NULL)
	    goto err;
	  if(tx_fin != 0)
	    {
	      tp->tp_flags |= TH_FIN;
	      state->mode = MODE_FIN;
	    }
	  return 0;
	}

      /*
       * remove the segment from the list; we will process it.
       * check if the fin bit is set for later processing.
       * determine if we have already received a portion of this segment.
       * move rcv_nxt along by the amount of new data.
       * pass the new data up to the application.
       * free the segment once it is no longer required.
       */
      qe = scamper_tbit_tcpq_pop(state->rxq);
      off = abs(off);
      fin = (qe->flags & TH_FIN) != 0 ? 1 : 0;
      if(qe->len > 0)
	state->rcv_nxt += (qe->len - off);
      if((rc = tbit_app_rx(task, qe->data+off, qe->len-off)) < 0)
	goto err;
      scamper_tbit_tcpqe_free(qe, free); qe = NULL;

      if((tp = tp_tcp(state)) == NULL)
	goto err;
      if(rc > 0)
	{
	  tp->tp_len = rc;
	  tp->wait = TBIT_TIMEOUT_DEFAULT;
	  state->attempt = 0;
	}
      if(tx_fin != 0 || fin != 0)
	{
	  tp->tp_flags |= TH_FIN;
	  state->mode = MODE_FIN;
	  if(fin != 0)
	    {
	      state->flags |= TBIT_STATE_FLAG_FIN_SEEN;
	      state->rcv_nxt++;
	      tp->tp_ack++;
	      break;
	    }
	}
    }

  return 0;

 err:
  if(qe != NULL) scamper_tbit_tcpqe_free(qe, free);
  tbit_handleerror(task, errno);
  return -1;
}

static int sack_rcvr_next(scamper_task_t *task)
{
  tbit_state_t *state = tbit_getstate(task);
  tbit_probe_t *tp;

  /* after six sacks, we classify */
  if(state->sackr_x == 6)
    {
      tbit_classify(task);
      return 0;
    }

  /* send the next out of sequence packet */
  if((tp = tp_tcp(state)) == NULL)
    return -1;
  tp->tp_len = 1;
  tp->tp_seq += 1 + (state->sackr_x * 2);
  tp->wait = TBIT_TIMEOUT_SACK;
  state->attempt = 0;
  state->sackr_x++;

  tbit_queue(task);
  return 0;
}

/*
 * dl_data_sack_rcvr
 *
 * send sequence of six packets that are out of sequence to solict SACK
 * blocks, each time an ack is received.
 */
static int dl_data_sack_rcvr(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  tbit_state_t *state = tbit_getstate(task);
  uint32_t edge;
  int i, x = -1;

  if(dl->dl_tcp_seq != state->rcv_nxt)
    return 0;

  /* if we get an early fin, abort */
  if((dl->dl_tcp_flags & TH_FIN) != 0)
    {
      state->flags |= TBIT_STATE_FLAG_FIN_SEEN;
      tbit_classify(task);
      return 0;
    }

  if(dl->dl_tcp_sack_edgec == -1)
    {
      state->sackr_flags |= TBIT_STATE_SACKR_FLAG_BADOPT;
      return 0;
    }
  else if(dl->dl_tcp_sack_edgec == 0)
    {
      x = 0;
    }
  else if(dl->dl_tcp_sack_edgec > 0)
    {
      assert(dl->dl_tcp_sack_edgec > 1);
      edge = dl->dl_tcp_sack_edges[1] - state->snd_nxt;
      if((edge & 0x1) == 0 && edge != 0 && edge / 2 <= state->sackr_x)
	x = edge / 2;

      /* check if any of the edges in the sack block are out of range */
      for(i=0; i<dl->dl_tcp_sack_edgec; i++)
	{
	  edge = dl->dl_tcp_sack_edges[0] - state->snd_nxt;
	  if(edge == 0 || edge / 2 > state->sackr_x)
	    {
	      state->sackr_flags |= TBIT_STATE_SACKR_FLAG_SHIFTED;
	      break;
	    }
	}
    }

  /*
   * if we were able to identify the likely probe this is a reply for,
   * then send the next one only if we haven't already.
   */
  if(x != -1)
    {
      state->sackr_rx[x]++;
      if(state->sackr_rx[x] > 1 && x == 0 &&
	 (state->sackr_flags & TBIT_STATE_SACKR_FLAG_INCAPABLE) == 0)
	return 0;
    }

  if(sack_rcvr_next(task) != 0)
    goto err;

  return 0;

 err:
  tbit_handleerror(task, errno);
  return -1;
}

static void timeout_data_sack_rcvr(scamper_task_t *task)
{
  tbit_state_t *state = tbit_getstate(task);

  state->sackr_timeout++;
  if(sack_rcvr_next(task) != 0)
    tbit_handleerror(task, errno);

  return;
}

/*
 * dl_data_icw
 *
 * this function reads from the stream until the first segment is seen
 * again.  at that point, the function sends a FIN to accelerate a
 * classification.  a successful classification is made in dl_icw.
 *
 */
static int dl_data_icw(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_tcpqe_t *qe;
  scamper_tbit_icw_t *icw;
  tbit_probe_t *tp = NULL;
  uint32_t seq;
  uint16_t datalen;
  int rc, off, fin = 0;

  assert(state->icw_count <= 2);

  if((dl->dl_tcp_flags & TH_FIN) != 0)
    {
      state->flags |= TBIT_STATE_FLAG_FIN_SEEN;
      fin = 1;
    }

  if(tbit_data_inrange(state, dl->dl_tcp_seq, dl->dl_tcp_datalen) == 0)
    goto done;

  /* if the packet contains data or is a fin, fail if we cannot queue it */
  if((dl->dl_tcp_datalen != 0 || fin) && tbit_rxq(state, dl) != 0)
    {
      printerror(__func__, "could not queue packet");
      goto err;
    }

  if(state->flags & TBIT_STATE_FLAG_NOMOREDATA)
    {
      if((state->icw_flags & TBIT_STATE_ICW_FLAG_SEQ) == 0)
	{
	  icw = tbit->data;
	  icw->start_seq = scamper_tbit_data_seqoff(state->sa_seq,
						    state->rcv_nxt);
	  state->icw_flags |= TBIT_STATE_ICW_FLAG_SEQ;
	  state->icw_seq = state->rcv_nxt;
	}

      /*
       * count the number of times the first segment is seen (with data)
       * so that we know when the second retransmission is made.
       */
      if(dl->dl_tcp_seq == state->icw_seq && dl->dl_tcp_datalen > 0)
	state->icw_count++;

      if(state->icw_count < 2)
	{
	  /* we're done for now unless the packet is a fin */
	  if(fin == 0)
	    goto done;

	  /*
	   * if the packet is a fin, we do not have a retransmission
	   * that would allow an ICW to be inferred.
	   */
	  tbit_result(task, SCAMPER_TBIT_RESULT_ICW_TOOSHORT);
	  state->mode = MODE_FIN;
	}
      else
	{
	  /*
	   * got a second retransmission.  make a note of the sequence
	   * number we need to see to be sure we are seeing new data after
	   * the initial flight.  shift to MODE_MOREDATA after we have
	   * processed the packets in the rxq.
	   */
	  state->icw_tail = scamper_tbit_tcpq_tail(state->rxq);
	  state->mode = MODE_MOREDATA;
	}
    }

  if(state->rxq == NULL)
    goto done;

  while(scamper_tbit_tcpq_seg(state->rxq, &seq, &datalen) == 0)
    {
      /* skip if not in range */
      if(scamper_tbit_data_inrange(state->rcv_nxt, seq, datalen) == 0)
	{
	  scamper_tbit_tcpqe_free(scamper_tbit_tcpq_pop(state->rxq), free);
	  continue;
	}

      /* if we have a gap in the rxq, stop processing stream for now */
      if((off = scamper_tbit_data_seqoff(state->rcv_nxt, seq)) > 0)
	{
	  if((tp = tp_tcp(state)) == NULL)
	    goto err;
	  if(state->mode == MODE_MOREDATA)
	    tp->tp_flags |= TH_FIN;
	  break;
	}

      /* process the data and free it */
      qe = scamper_tbit_tcpq_pop(state->rxq);
      off = abs(off);
      fin = (qe->flags & TH_FIN) != 0 ? 1 : 0;
      if(qe->len > 0)
	state->rcv_nxt += (qe->len - off);
      if((rc = tbit_app_rx(task, qe->data+off, qe->len-off)) < 0)
	goto err;
      scamper_tbit_tcpqe_free(qe, free); qe = NULL;

      if((tp = tp_tcp(state)) == NULL)
	goto err;
      tp->tp_len = rc;
      if(state->mode == MODE_MOREDATA)
	tp->tp_flags |= TH_FIN;
      if(fin != 0)
	{
	  tp->tp_ack++;
	  state->rcv_nxt++;
	  break;
	}
    }

 done:
  tbit_queue(task);
  return 0;

 err:
  tbit_handleerror(task, errno);
  tbit_queue(task);
  return -1;
}

static int dl_data_blinddata(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_blind_t *blind = tbit->data;
  tbit_segment_t *seg;
  tbit_probe_t *tp;

  if(state->mode == MODE_DATA)
    return dl_data_null(task, dl);
  if(state->mode != MODE_BLIND)
    return 0;

  /*
   * if we got some data, or the packet is an ack that indicates the
   * blind data was accepted, then we're done
   */
  if(dl->dl_tcp_datalen > 0 || slist_count(state->segments) == 0)
    {
      if(state->blind_step == 2 && slist_count(state->segments) == 0)
	state->blind_flags |= TBIT_STATE_BLIND_FLAG_ACCEPTED;
      state->mode = MODE_DATA;
      tp_flush(state, NULL);
      return dl_data_null(task, dl);
    }

  /* skip over unexpected data */
  if(dl->dl_tcp_seq != state->rcv_nxt)
    return 0;

  /* if we got a fin while trying to do the measurement, stop */
  if((dl->dl_tcp_flags & TH_FIN) != 0)
    {
      tbit_result(task, SCAMPER_TBIT_RESULT_TCP_FIN);
      return 0;
    }

  seg = slist_head_item(state->segments);

  if(state->blind_step == 0)
    {
      if(seg->len != state->blind_part2 + state->blind_part3)
	return 0;
      state->blind_step++;
      state->attempt = 0;

      /* in step 1, we send third segment with wrong ack */
      if((tp = tp_tcp(state)) == NULL)
	goto err;
      tp->tp_seq += state->blind_part2;
      tp->tp_len = state->blind_part3;
      tp->tp_ack += blind->off;
      tp->wait = TBIT_TIMEOUT_BLINDDATA;
    }
  else if(state->blind_step == 1)
    {
      state->blind_flags |= TBIT_STATE_BLIND_FLAG_CHALLENGE;
      if(state->attempt >= blind->retx)
	{
	  state->blind_step++;
	  state->attempt = 0;
	}
    }
  else if(state->blind_step == 2)
    {
      if(seg->len != state->blind_part3)
	return 0;
      state->blind_step++;
      state->attempt = 0;
      tp_flush(state, NULL);

      /* in step 3, we send the third segment with correct ack */
      if((tp = tp_tcp(state)) == NULL)
	goto err;
      tp->tp_len = seg->len;
      tp->wait = TBIT_TIMEOUT_BLINDDATA;
    }

  return 0;

 err:
  tbit_handleerror(task, errno);
  return -1;
}

/*
 * dl_data_blindfin
 *
 * step 0: send the first part
 * step 1: send a fin, leaving a hole in receiver's window
 * step 2: fill the hole
 * step 3: wait to see if the server ack's the FIN beyond acking the data
 */
static int dl_data_blindfin(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_blind_t *blind = tbit->data;
  tbit_segment_t *seg;
  tbit_probe_t *tp;

  if(state->mode == MODE_DATA)
    return dl_data_null(task, dl);
  if(state->mode != MODE_BLIND)
    return 0;

  /*
   * if the packet does not contain the expected sequence number, but we're in
   * step 2, we need to check the ack incase it covers the data we've sent
   */
  if(slist_count(state->segments) == 0 && state->blind_step == 2 &&
     dl->dl_tcp_seq != state->rcv_nxt)
    {
      /* got an ack covering the request without the FIN */
      if(dl->dl_tcp_ack == state->blind_ack)
	{
	  state->blind_step = 3;
	  return 0;
	}

      /* ack indicates the blind FIN was accepted */
      if(dl->dl_tcp_ack == state->blind_ack + 1 &&
	 (state->flags & TBIT_STATE_FLAG_FIN_ACKED) == 0)
	{
	  state->blind_flags |= TBIT_STATE_BLIND_FLAG_ACCEPTED;
	  state->flags |= TBIT_STATE_FLAG_FIN_ACKED;
	  state->snd_nxt++;
	  state->mode = MODE_FIN;
	  tp_flush(state, NULL);
	}
      return 0;
    }

  /* skip over unexpected data */
  if(dl->dl_tcp_seq != state->rcv_nxt)
    {
      scamper_debug(__func__, "skip %u %u", dl->dl_tcp_seq, state->rcv_nxt);
      return 0;
    }

  seg = slist_head_item(state->segments);

  if(state->blind_step == 0)
    {
      if(seg->len != state->blind_part2)
	return 0;
      state->blind_step++;
      state->attempt = 0;

      /* in step 1, we send the FIN with wrong ack */
      if((tp = tp_tcp(state)) == NULL)
	goto err;
      tp->tp_seq += state->blind_part2;
      tp->tp_ack += blind->off;
      tp->tp_flags |= TH_FIN;
      tp->wait = TBIT_TIMEOUT_BLINDDATA;
    }
  else if(state->blind_step == 1)
    {
      /* if we get an ack in this stage, classify as a challenge ack */
      if(dl->dl_tcp_datalen == 0 && (dl->dl_tcp_flags & TH_FIN) == 0)
	state->blind_flags |= TBIT_STATE_BLIND_FLAG_CHALLENGE;
      if(state->attempt >= blind->retx)
	{
	  state->blind_step++;
	  state->attempt = 0;
	}
    }
  else if(state->blind_step == 2 || state->blind_step == 3)
    {
      /* waiting for an ACK covering the data we sent */
      if(dl->dl_tcp_ack < state->blind_ack)
	{
	  scamper_debug(__func__, "old ack %u %u", dl->dl_tcp_ack, state->blind_ack);
	  return 0;
	}
      //if(state->blind_step == 2)
      //{
      //timeval_add_ms(&state->timeout, &dl->dl_tv, TBIT_TIMEOUT_BLINDDATA);
      //state->flags |= TBIT_STATE_FLAG_NORESET;
      //}
      state->blind_step = 3;

      /* make sure the ack is one of two possible values */
      if(dl->dl_tcp_ack > state->blind_ack + 1)
	{
	  errno = 0;
	  goto err;
	}

      /* pass data up to the application and send an ack for it */
      if(dl->dl_tcp_datalen > 0)
	{
	  if(tbit_app_rx(task, dl->dl_tcp_data, dl->dl_tcp_datalen) < 0)
	    goto err;
	  state->rcv_nxt += dl->dl_tcp_datalen;
	  if((tp = tp_tcp(state)) == NULL)
	    goto err;
	}

      /*
       * if the packet is an ack that indicates the blind fin was accepted,
       * then we're done
       */
      if(dl->dl_tcp_ack == state->blind_ack + 1 &&
	 (state->flags & TBIT_STATE_FLAG_FIN_ACKED) == 0)
	{
	  state->blind_flags |= TBIT_STATE_BLIND_FLAG_ACCEPTED;
	  state->flags |= TBIT_STATE_FLAG_FIN_ACKED;
	  state->snd_nxt++;
	  state->mode = MODE_FIN;
	  tp_flush(state, NULL);
	}
    }

  return 0;

 err:
  tbit_handleerror(task, errno);
  return -1;
}

/*
 * dl_data_blindrst:
 *
 * try and reset the connection three times for the first three data packets,
 * by sending blinded syn/rst.
 */
static int dl_data_blindrst(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_blind_t *blind = tbit->data;
  tbit_probe_t *tp;

  assert(tbit->type == SCAMPER_TBIT_TYPE_BLIND_RST ||
	 tbit->type == SCAMPER_TBIT_TYPE_BLIND_SYN);

  if((state->flags & TBIT_STATE_FLAG_NOMOREDATA) != 0 &&
     state->mode == MODE_BLIND)
    {
      /* we do not use the rxq through this stage */
      if(state->rxq != NULL)
	{
	  scamper_tbit_tcpq_free(state->rxq, free);
	  state->rxq = NULL;
	}

      if(dl->dl_tcp_datalen == 0 && (dl->dl_tcp_flags & TH_FIN) == 0)
	{
	  /* infer if the ack could be a challenge ack */
	  if(state->blind_c > 0 && dl->dl_tcp_ack == state->snd_nxt)
	    state->blind_flags |= TBIT_STATE_BLIND_FLAG_CHALLENGE;
	  return 0;
	}

      /* if it is out of sequence, then send an ack for what we want */
      if(dl->dl_tcp_seq != state->rcv_nxt)
	{
	  if(tp_tcp(state) == NULL)
	    goto err;
	  return 0;
	}

      /*
       * make a note that we saw a fin (or data) at some point to help
       * classify later
       */
      if(dl->dl_tcp_flags & TH_FIN)
	state->blind_flags |= TBIT_STATE_BLIND_FLAG_FIN;
      if(dl->dl_tcp_datalen > 0)
	state->flags |= TBIT_STATE_FLAG_SEEN_DATA;

      /*
       * if we've already sent a rst/syn for this packet, accept the data so
       * we can move on to the next one
       */
      if(state->blind_sent == 1 && dl->dl_tcp_datalen > 0)
	{
	  state->rcv_nxt += dl->dl_tcp_datalen;
	  if(tbit_app_rx(task, dl->dl_tcp_data, dl->dl_tcp_datalen) < 0)
	    goto err;
	}
      if((tp = tp_tcp(state)) == NULL)
	goto err;

      /* if the packet is a pure fin, then stop now */
      if((dl->dl_tcp_flags & TH_FIN) != 0 && dl->dl_tcp_datalen == 0)
	{
	  tp->tp_flags |= TH_FIN;
	  tp->tp_ack++;
	  state->rcv_nxt++;
	  state->mode = MODE_FIN;
	  state->flags |= TBIT_STATE_FLAG_FIN_SEEN;
	  return 0;
	}

      if(state->blind_sent == 0)
	{
	  /*
	   * if we haven't sent a blinded rst/syn packet for this piece of
	   * data yet, then send one now
	   */
	  if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_RST)
	    tp->tp_flags = TH_RST;
	  else
	    tp->tp_flags = TH_SYN;
	  tp->tp_seq += blind->off;
	  state->blind_sent = 1;
	  state->blind_c++;
	}
      else
	{
	  /*
	   * move on to the next piece of data.  if we've sent enough
	   * blinded rst/syn packets, then let the connection complete and
	   * move on.
	   */
	  state->blind_sent = 0;
	  state->blind_ignored++;
	  if(state->blind_c >= blind->retx)
	    state->mode = MODE_DATA;
	  else
	    tp_flush(state, tp);

	  if((dl->dl_tcp_flags & TH_FIN) != 0)
	    {
	      tp->tp_flags |= TH_FIN;
	      tp->tp_ack++;
	      state->rcv_nxt++;
	      state->mode = MODE_FIN;
	      state->flags |= TBIT_STATE_FLAG_FIN_SEEN;
	    }
	}
      tp->wait = TBIT_TIMEOUT_LONG;
      state->attempt = 0;
    }
  else if((state->flags & TBIT_STATE_FLAG_NOMOREDATA) == 0 ||
	  state->mode == MODE_DATA)
    {
      return dl_data_null(task, dl);
    }

  return 0;

 err:
  tbit_handleerror(task, errno);
  return -1;
}

static void dl_data(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  static int (* const func[])(scamper_task_t *, scamper_dl_rec_t *) =
    {
      NULL,
      dl_data_pmtud,
      dl_data_ecn,
      dl_data_null,
      dl_data_sack_rcvr,
      dl_data_icw,
      NULL,
      dl_data_blinddata,
      dl_data_blindrst,
      dl_data_blindrst,
      dl_data_blindfin,
    };
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  tbit_segment_t *seg;
  uint32_t ab;
  int timeout = TBIT_TIMEOUT_LONG;

  if((tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA ||
      tbit->type == SCAMPER_TBIT_TYPE_BLIND_FIN) &&
     state->mode == MODE_BLIND)
    timeout = TBIT_TIMEOUT_BLINDDATA;

  if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_SYN &&
     (dl->dl_tcp_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK) &&
     dl->dl_tcp_seq != state->sa_seq)
    {
      tbit_result(task, SCAMPER_TBIT_RESULT_BLIND_SYNNEW);
      return;
    }

  if((state->flags & TBIT_STATE_FLAG_NORESET) == 0)
    timeval_add_ms(&state->timeout, &dl->dl_tv, timeout);

  /* is the data in range? */
  if(tbit_data_inrange(state, dl->dl_tcp_seq, dl->dl_tcp_datalen) == 0)
    return;

  /* remove segment data from the send queue */
  if(dl->dl_tcp_ack > state->snd_nxt)
    {
      if((seg = slist_head_item(state->segments)) == NULL)
	return;

      ab = dl->dl_tcp_ack - state->snd_nxt;
      if(ab >= seg->len)
	{
	  ab = seg->len;
	  slist_head_pop(state->segments);
	  tbit_segment_free(seg);
	}
      else
	{
	  memmove(seg->data, seg->data+ab, seg->len-ab);
	  seg->len -= ab;
	}
      state->snd_nxt += ab;
    }

  func[tbit->type](task, dl);
  tbit_queue(task);
  return;
}

static void timeout_data(scamper_task_t *task)
{
  static void (* const func[])(scamper_task_t *) =
    {
      NULL,
      timeout_data_pmtud,
      timeout_data_generic, /* ecn */
      timeout_data_generic, /* null */
      timeout_data_sack_rcvr,
      timeout_data_generic, /* icw */
      NULL,                 /* abc */
      timeout_data_generic, /* blind-data */
      timeout_data_generic, /* blind-rst */
      timeout_data_generic, /* blind-syn */
      timeout_data_generic, /* blind-fin */
    };
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  tbit_segment_t *seg;
  tbit_probe_t *tp;

  if((seg = slist_head_item(state->segments)) != NULL)
    {
      if(state->attempt >= tbit->dat_retx)
	{
	  func[tbit->type](task);
	  return;
	}
      if((tp=tp_tcp(state)) == NULL)
	goto err;
      tp->tp_len = seg->len;
      tp->wait = TBIT_TIMEOUT_DEFAULT;
      tbit_queue(task);
    }
  else
    {
      tbit_classify(task);
      if(tbit->result != SCAMPER_TBIT_RESULT_NONE && state->mode != MODE_FIN)
	{
	  state->mode = MODE_FIN;
	  scamper_task_queue_probe(task);
	}
    }

  return;

 err:
  tbit_handleerror(task, errno);
  return;
}

/*
 * timeout_pmtud
 *
 * did not observe remote TCP changing behaviour.
 */
static void timeout_pmtud(scamper_task_t *task)
{
  tbit_classify(task);
  return;
}

/*
 * Checks the response to a PTB message.
 */
static void dl_pmtud(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_pmtud_t *pmtud = tbit->data;
  tbit_probe_t *tp;
  uint16_t mtu = pmtud->mtu;
  int ipv4 = SCAMPER_ADDR_TYPE_IS_IPV4(tbit->dst) ? 1 : 0;
  int success = 0;

  /* no packet size restriction for IPv6 fragmentation header technique */
  if(SCAMPER_ADDR_TYPE_IS_IPV6(tbit->dst) && pmtud->mtu < 1280)
    mtu = 0;

  /* if an out of sequence packet is received, ack it */
  if(dl->dl_tcp_seq != state->rcv_nxt)
    {
      if(dl->dl_ip_size > mtu)
	return;
      if(tp_tcp(state) == NULL)
	goto err;
      tbit_queue(task);
      return;
    }

  if(mtu != 0)
    {
      if(SCAMPER_DL_IS_IP_REASS(dl) || dl->dl_ip_size <= mtu ||
	 (ipv4 && SCAMPER_DL_IS_IP_DF(dl) == 0))
	success = 1;
    }
  else
    {
      if(SCAMPER_DL_IS_IP_FRAG(dl) || SCAMPER_DL_IS_IP_REASS(dl))
	success = 1;
    }

  if(success)
    {
      state->rcv_nxt += dl->dl_tcp_datalen;

      if(ipv4 && SCAMPER_DL_IS_IP_DF(dl) == 0)
	tbit_result(task, SCAMPER_TBIT_RESULT_PMTUD_CLEARDF);
      else
	tbit_result(task, SCAMPER_TBIT_RESULT_PMTUD_SUCCESS);

      if((tp = tp_tcp(state)) == NULL)
	{
	  tbit_handleerror(task, errno);
	  return;
	}
      if((dl->dl_tcp_flags & TH_FIN) != 0)
	{
	  tp->tp_flags |= TH_FIN;
	  tp->tp_ack++;
	  state->flags |= TBIT_STATE_FLAG_FIN_SEEN;
	  state->rcv_nxt++;
	}

      tbit_queue(task);
      return;
    }

  if(pmtud->ptb_retx != 0 && state->attempt >= pmtud->ptb_retx)
    {
      tbit_result(task, SCAMPER_TBIT_RESULT_PMTUD_FAIL);
      return;
    }

  /* send another PTB */
  if(tp_ptb(state) == NULL)
    goto err;

  tbit_queue(task);
  return;

 err:
  tbit_handleerror(task, errno);
  return;
}

static void dl_blackhole(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_pmtud_t *pmtud = tbit->data;
  tbit_probe_t *tp;
  uint16_t mtu = pmtud->mtu;
  int ipv4 = SCAMPER_ADDR_TYPE_IS_IPV4(tbit->dst) ? 1 : 0;
  int ack = 0;

  /* if an out of sequence packet is received, ack it */
  if(dl->dl_tcp_seq != state->rcv_nxt)
    {
      if(dl->dl_ip_size > mtu)
	return;
      if(tp_tcp(state) == NULL)
	goto err;
      tbit_queue(task);
      return;
    }

  if(mtu != 0)
    {
      if(dl->dl_ip_size <= mtu || (ipv4 && SCAMPER_DL_IS_IP_DF(dl) == 0))
	ack = 1;
    }
  else
    {
      if(SCAMPER_DL_IS_IP_FRAG(dl) || SCAMPER_DL_IS_IP_REASS(dl))
	ack = 1;
    }

  if(ack != 0)
    {
      state->rcv_nxt += dl->dl_tcp_datalen;

      if((tp = tp_tcp(state)) == NULL)
	{
	  tbit_handleerror(task, errno);
	  return;
	}

      /*
       * if we've received the packet and its a fin, then the remote host
       * might have completed blackhole detection or some similar process.
       */
      if((dl->dl_tcp_flags & TH_FIN) != 0)
	{
	  tp->tp_flags |= TH_FIN;
	  tp->tp_ack++;
	  state->flags |= TBIT_STATE_FLAG_FIN_SEEN;
	  state->rcv_nxt++;
	  tbit_result(task, SCAMPER_TBIT_RESULT_PMTUD_SUCCESS);
	}

      /* reset the timeout */
      timeval_add_ms(&state->timeout, &dl->dl_tv, TBIT_TIMEOUT_LONG);
    }

  tbit_queue(task);
  return;

 err:
  tbit_handleerror(task, errno);
  return;
}

static void timeout_zerowin(scamper_task_t *task)
{
  tbit_classify(task);
  return;
}

/*
 * dl_zerowin:
 *
 * packet received, hopefully advertising a receive window sufficient
 * to send our data.
 */
static void dl_zerowin(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  tbit_segment_t *seg;
  tbit_probe_t *tp;

  if(dl->dl_tcp_win == 0)
    return;

  seg = slist_head_item(state->segments); assert(seg != NULL);
  if((tp = tp_tcp(state)) == NULL)
    goto err;

  if(tbit->type == SCAMPER_TBIT_TYPE_SACK_RCVR)
    tp->tp_len = 1;
  else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA ||
	  tbit->type == SCAMPER_TBIT_TYPE_BLIND_FIN)
    tp->tp_len = state->blind_part1;
  else
    tp->tp_len = seg->len;

  if(tbit->type == SCAMPER_TBIT_TYPE_SACK_RCVR)
    {
      tp->wait = TBIT_TIMEOUT_SACK;
      state->mode = MODE_DATA;
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA ||
	  tbit->type == SCAMPER_TBIT_TYPE_BLIND_FIN)
    {
      tp->wait = TBIT_TIMEOUT_BLINDDATA;
      state->mode = MODE_BLIND;
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_RST ||
	  tbit->type == SCAMPER_TBIT_TYPE_BLIND_SYN)
    {
      tp->wait = TBIT_TIMEOUT_DEFAULT;
      state->mode = MODE_BLIND;
    }
  else
    {
      tp->wait = TBIT_TIMEOUT_DEFAULT;
      state->mode = MODE_DATA;
    }

  state->attempt = 0;
  tbit_queue(task);
  return;

 err:
  tbit_handleerror(task, errno);
  return;
}

static void timeout_moredata(scamper_task_t *task)
{
  tbit_classify(task);
  return;
}

/*
 * dl_moredata
 *
 * this function exists to make note of when a new data packet arrives
 * from beyond the last flight.  dl_data_icw has previously sent
 * FIN-ack packets to encourage a fast resolution to the measurement.
 */
static void dl_moredata(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_tcpqe_t *qe;
  tbit_probe_t *tp = NULL;
  uint32_t seq;
  uint16_t datalen;
  int off, fin = 0;

  assert(tbit->type == SCAMPER_TBIT_TYPE_ICW);

  if(tbit->type == SCAMPER_TBIT_TYPE_ICW)
    assert(state->icw_count == 2);

  /* see if the remote host has acked our fin */
  if(dl->dl_tcp_ack == state->snd_nxt + 1 &&
     (state->flags & TBIT_STATE_FLAG_FIN_ACKED) == 0)
    {
      state->flags |= TBIT_STATE_FLAG_FIN_ACKED;
      state->snd_nxt++;
    }

  /* skip over packets that do not occupy sequence number space */
  if(dl->dl_tcp_datalen == 0 && (dl->dl_tcp_flags & TH_FIN) == 0)
    return;

  /* skip over data that is out of range */
  if(tbit_data_inrange(state, dl->dl_tcp_seq, dl->dl_tcp_datalen) == 0)
    return;

  /* fail if we cannot queue packet */
  if(tbit_rxq(state, dl) != 0)
    {
      printerror(__func__, "could not queue packet");
      goto err;
    }

  while(scamper_tbit_tcpq_seg(state->rxq, &seq, &datalen) == 0)
    {
      if(scamper_tbit_data_inrange(state->rcv_nxt, seq, datalen) == 0)
	{
	  scamper_tbit_tcpqe_free(scamper_tbit_tcpq_pop(state->rxq), free);
	  continue;
	}

      if(datalen > 0)
	{
	  if(tbit->type == SCAMPER_TBIT_TYPE_ICW &&
	     scamper_tbit_data_seqoff(state->icw_tail, seq+datalen) >= 0)
	    {
	      state->mode = MODE_FIN;
	      tbit_result(task, SCAMPER_TBIT_RESULT_ICW_SUCCESS);
	    }
	}
      else
	{
	  if(tbit->type == SCAMPER_TBIT_TYPE_ICW &&
	     scamper_tbit_data_seqoff(state->icw_tail, seq) == 0)
	    {
	      state->mode = MODE_FIN;
	      tbit_result(task, SCAMPER_TBIT_RESULT_ICW_TOOSHORT);
	    }
	}

      if((off = scamper_tbit_data_seqoff(state->rcv_nxt, seq)) > 0)
	{
	  if((tp = tp_tcp(state)) == NULL)
	    goto err;
	  if((state->flags & TBIT_STATE_FLAG_FIN_ACKED) == 0)
	    tp->tp_flags |= TH_FIN;
	  break;
	}

      qe = scamper_tbit_tcpq_pop(state->rxq);
      off = abs(off);
      fin = (qe->flags & TH_FIN) != 0 ? 1 : 0;
      if(qe->len > 0)
	state->rcv_nxt += (qe->len - off);
      if(tbit_app_rx(task, qe->data+off, qe->len-off) < 0)
	goto err;
      scamper_tbit_tcpqe_free(qe, free); qe = NULL;

      if((tp = tp_tcp(state)) == NULL)
	goto err;
      if((state->flags & TBIT_STATE_FLAG_FIN_ACKED) == 0)
	tp->tp_flags |= TH_FIN;
      if(fin != 0)
	{
	  tp->tp_ack++;
	  state->flags |= TBIT_STATE_FLAG_FIN_SEEN;
	  state->rcv_nxt++;
	  break;
	}
    }

  if(tbit_tcpclosed(state))
    {
      if(tbit->result == SCAMPER_TBIT_RESULT_NONE)
	tbit_classify(task);
      state->mode = MODE_DONE;
    }

  tbit_queue(task);
  return;

 err:
  tbit_handleerror(task, errno);
  tbit_queue(task);
  return;
}

static void timeout_blinddata(scamper_task_t *task)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_blind_t *blind = tbit->data;
  tbit_segment_t *seg;
  tbit_probe_t *tp;

  seg = slist_head_item(state->segments); assert(seg != NULL);

  if(state->blind_step == 0 || state->blind_step == 3)
    {
      if(state->attempt >= blind->retx)
	{
	  tbit_result(task, SCAMPER_TBIT_RESULT_NONE);
	  return;
	}
      if((tp = tp_tcp(state)) == NULL)
	goto err;
      if(state->blind_step == 0)
	tp->tp_len = state->blind_part1;
      else
	tp->tp_len = seg->len;
      tp->wait = TBIT_TIMEOUT_BLINDDATA;
      tbit_queue(task);
      return;
    }

  if((tp = tp_tcp(state)) == NULL)
    goto err;
  tp->tp_len = seg->len;
  tp->wait = TBIT_TIMEOUT_BLINDDATA;

  if(state->attempt >= blind->retx)
    {
      if(state->blind_step == 1)
	{
	  /*
	   * if we did not get a challenge ack during the process of
	   * sending the first packet, then record silence.
	   */
	  if((state->blind_flags & TBIT_STATE_BLIND_FLAG_CHALLENGE) == 0)
	    state->blind_flags |= TBIT_STATE_BLIND_FLAG_SILENCE;
	}
      state->attempt = 0;
      state->blind_step++;
    }

  if(state->blind_step == 1)
    {
      /*
       * if we are still in the process of re-trying data packet
       * with offset ack field, keep trying
       */
      tp->tp_ack += blind->off;
      tp->tp_seq += state->blind_part2;
      tp->tp_len  = state->blind_part3;
    }
  else
    {
      tp->tp_len  = state->blind_part2;
    }

  tbit_queue(task);
  return;

 err:
  tbit_handleerror(task, errno);
  return;
}

/*
 * timeout_blindfin
 *
 * step 0: send the first part
 * step 1: send a fin, leaving a hole in receiver's window
 * step 2: fill the hole
 * step 3: wait to see if the server ack's the FIN beyond acking the data
 */
static void timeout_blindfin(scamper_task_t *task)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_blind_t *blind = tbit->data;
  tbit_segment_t *seg = slist_head_item(state->segments);
  tbit_probe_t *tp;

  if(state->blind_step == 0)
    {
      if(state->attempt >= blind->retx)
	{
	  tbit_result(task, SCAMPER_TBIT_RESULT_NONE);
	  return;
	}
      if((tp = tp_tcp(state)) == NULL)
	goto err;
      tp->tp_len = state->blind_part1;
      tp->wait = TBIT_TIMEOUT_BLINDDATA;
    }
  else if(state->blind_step == 3)
    {
      tp_flush(state, NULL);
      state->flags &= (~TBIT_STATE_FLAG_NORESET);
      state->mode = MODE_DATA;
    }
  else
    {
      if((tp = tp_tcp(state)) == NULL)
	goto err;
      tp->tp_len = seg->len;
      tp->wait = TBIT_TIMEOUT_BLINDDATA;

      if(state->attempt >= blind->retx)
	{
	  if(state->blind_step == 1)
	    {
	      /*
	       * if we did not get a challenge ack during the process of
	       * sending the first packet, then record silence.
	       */
	      if((state->blind_flags & TBIT_STATE_BLIND_FLAG_CHALLENGE) == 0)
		state->blind_flags |= TBIT_STATE_BLIND_FLAG_SILENCE;
	    }
	  state->attempt = 0;
	  state->blind_step++;
	}

      if(state->blind_step == 1)
	{
	  /*
	   * if we are still in the process of re-trying packet
	   * with offset ack field, keep trying
	   */
	  tp->tp_ack += blind->off;
	  tp->tp_seq += state->blind_part2;
	  tp->tp_len = 0;
	  tp->tp_flags |= TH_FIN;
	}
      else
	{
	  tp->tp_len = state->blind_part2;
	  state->flags |= TBIT_STATE_FLAG_NORESET;
	}
    }

  tbit_queue(task);
  return;

 err:
  tbit_handleerror(task, errno);
  return;
}

/*
 * timeout_blind
 *
 * a timeout has occured doing a blind-test.  figure out which blind
 * test this corresponds to and take the appropriate action
 */
static void timeout_blind(scamper_task_t *task)
{
  scamper_tbit_t *tbit = tbit_getdata(task);

  /* if the timeout is for the reset or syn tests, we're done */
  if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_RST ||
     tbit->type == SCAMPER_TBIT_TYPE_BLIND_SYN)
    {
      tbit_classify(task);
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA)
    {
      timeout_blinddata(task);
    }
  else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_FIN)
    {
      timeout_blindfin(task);
    }
  return;
}

static int blind_check_rst(const scamper_task_t *t, const scamper_dl_rec_t *dl)
{
  scamper_tbit_t *tbit = tbit_getdata(t);
  tbit_state_t *state = tbit_getstate(t);
  scamper_tbit_blind_t *blind = tbit->data;

  if(((tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA &&
       dl->dl_tcp_seq == state->rcv_nxt + blind->off) ||
      (tbit->type == SCAMPER_TBIT_TYPE_BLIND_FIN &&
       dl->dl_tcp_seq == state->rcv_nxt + blind->off) ||
      (tbit->type == SCAMPER_TBIT_TYPE_BLIND_SYN &&
       dl->dl_tcp_ack == state->snd_nxt + blind->off + 1)))
    return 1;

  return 0;
}

/*
 * do_tbit_handle_dl
 *
 * for each packet received, check that the addresses and ports make sense,
 * and that the packet is not a reset.
 */
static void do_tbit_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  static void (* const func[])(scamper_task_t *, scamper_dl_rec_t *) =
    {
      NULL,
      NULL,          /* MODE_RTSOCK */
      NULL,          /* MODE_DLHDR */
      NULL,          /* MODE_FIREWALL */
      NULL,          /* MODE_DONE */
      dl_syn,        /* MODE_SYN */
      dl_fin,        /* MODE_FIN */
      dl_data,       /* MODE_DATA */
      dl_pmtud,      /* MODE_PMTUD */
      dl_blackhole,  /* MODE_BLACKHOLE */
      dl_zerowin,    /* MODE_ZEROWIN */
      dl_moredata,   /* MODE_MOREDATA */
      dl_data,       /* MODE_BLIND */
    };

  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_tbit_pkt_t *pkt = NULL;
  scamper_dl_rec_t *newp = NULL;

  /*
   * handle packets that arrive in fragments.  fall through if it is able
   * to be reassembled.
   */
  if(dl->dl_ip_off != 0 || SCAMPER_DL_IS_IP_MF(dl))
    {
      scamper_dl_rec_frag_print(dl);
      pkt = scamper_tbit_pkt_alloc(SCAMPER_TBIT_PKT_DIR_RX, dl->dl_net_raw,
				   dl->dl_ip_size, &dl->dl_tv);
      if(pkt == NULL || scamper_tbit_record_pkt(tbit, pkt) != 0)
	goto err;
      if(tbit_reassemble(task, &newp, dl) != 0)
	goto err;
      if(newp == NULL)
	return;
      dl = newp;
    }

  /* Unless it is an inbound TCP packet for the flow, ignore it */
  if(SCAMPER_DL_IS_TCP(dl) == 0 ||
     dl->dl_tcp_sport != tbit->dport || dl->dl_tcp_dport != tbit->sport ||
     scamper_addr_raw_cmp(tbit->dst, dl->dl_ip_src) != 0 ||
     scamper_addr_raw_cmp(tbit->src, dl->dl_ip_dst) != 0)
    {
      goto done;
    }

  /*
   * only record the packet if it was not reassembled.  If it was reassembled
   * from fragments, we have already recorded all the fragments.
   */
  if(newp == NULL)
    {
      scamper_dl_rec_tcp_print(dl);
      pkt = scamper_tbit_pkt_alloc(SCAMPER_TBIT_PKT_DIR_RX, dl->dl_net_raw,
				   dl->dl_ip_size, &dl->dl_tv);
      if(pkt == NULL || scamper_tbit_record_pkt(tbit, pkt) != 0)
	{
	  if(pkt != NULL) scamper_tbit_pkt_free(pkt);
	  goto err;
	}
    }

  /* only continue if we process TCP packets in this mode */
  if(func[state->mode] == NULL)
    goto done;

  if(state->mode != MODE_SYN)
    {
      /* If a reset packet is received, abandon the measurement */
      if((dl->dl_tcp_flags & TH_RST) != 0)
	{
	  if(state->mode == MODE_BLIND && blind_check_rst(task, dl) == 1)
	    state->blind_flags |= TBIT_STATE_BLIND_FLAG_RST;

	  state->flags |= TBIT_STATE_FLAG_RST_SEEN;
	  tbit_classify(task);
	  return;
	}

      /* the ACK flag should be set on all packets */
      if((dl->dl_tcp_flags & TH_ACK) == 0)
	goto done;
    }

  /* update the timestamp record */
  if((state->flags & TBIT_STATE_FLAG_TCPTS) != 0 &&
     dl->dl_tcp_seq <= state->ts_lastack &&
     state->ts_lastack < dl->dl_tcp_seq + dl->dl_tcp_datalen)
    {
      state->ts_recent = dl->dl_tcp_tsval;
    }

  func[state->mode](task, dl);

 done:
  if(newp != NULL && newp != dl)
    {
      if(newp->dl_ip_data != NULL)
	free(newp->dl_ip_data);
      free(newp);
    }
  return;

 err:
  tbit_handleerror(task, errno);
  return;
}

static void do_tbit_handle_timeout(scamper_task_t *task)
{
  /* Array of timeout functions */
  static void (* const func[])(scamper_task_t *) =
    {
      NULL,
      timeout_generic_error, /* MODE_RTSOCK */
      timeout_generic_error, /* MODE_DLHDR */
      NULL,               /* MODE_FIREWALL */
      NULL,               /* MODE_DONE */
      timeout_syn,        /* MODE_SYN */
      timeout_fin,        /* MODE_FIN */
      timeout_data,       /* MODE_DATA */
      timeout_pmtud,      /* MODE_PMTUD */
      timeout_pmtud,      /* MODE_BLACKHOLE */
      timeout_zerowin,    /* MODE_ZEROWIN */
      timeout_moredata,   /* MODE_MOREDATA */
      timeout_blind,      /* MODE_BLIND */
    };
  tbit_state_t *state = tbit_getstate(task);

  /* Call the appropriate timeout function */
  if(func[state->mode] != NULL)
    func[state->mode](task);

  return;
}

static void tbit_handle_dlhdr(scamper_dlhdr_t *dlhdr)
{
  scamper_task_t *task = dlhdr->param;
  tbit_state_t *state = tbit_getstate(task);

  if(dlhdr->error != 0)
    {
      scamper_task_queue_done(task, 0);
      return;
    }

  state->mode = MODE_FIREWALL;
  scamper_task_queue_probe(task);
  return;
}

static void tbit_handle_rt(scamper_route_t *rt)
{
  scamper_task_t *task = rt->param;
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  scamper_dl_t *dl;
  uint16_t mtu;

  if(state->mode != MODE_RTSOCK || state->route != rt)
    goto done;

#ifndef _WIN32
  if(state->rtsock != NULL)
    {
      scamper_fd_free(state->rtsock);
      state->rtsock = NULL;
    }
#endif

  if(rt->error != 0 || rt->ifindex < 0)
    {
      printerror(__func__, "could not get ifindex");
      tbit_handleerror(task, errno);
      goto done;
    }

  /*
   * scamper needs the datalink to transmit packets; try and get a
   * datalink on the ifindex specified.
   */
  if((state->dl = scamper_fd_dl(rt->ifindex)) == NULL)
    {
      scamper_debug(__func__, "could not get dl for %d", rt->ifindex);
      tbit_handleerror(task, errno);
      goto done;
    }

  /* Calculate the MSS to advertise */
  if(tbit->client_mss == 0)
    {
      if(scamper_if_getmtu(rt->ifindex, &mtu) != 0)
        {
	  scamper_debug(__func__, "could not get the interface mtu");
	  tbit_handleerror(task, errno);
	  goto done;
        }

      if(tbit->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	tbit->client_mss = mtu - 40;
      else if(tbit->dst->type == SCAMPER_ADDR_TYPE_IPV6)
	tbit->client_mss = mtu - 60;

      scamper_debug(__func__, "using client mss = %hu", tbit->client_mss);
    }

  /*
   * determine the underlying framing to use with each probe packet that will
   * be sent on the datalink.
   */
  state->mode = MODE_DLHDR;
  if((state->dlhdr = scamper_dlhdr_alloc()) == NULL)
    {
      tbit_handleerror(task, errno);
      goto done;
    }
  dl = scamper_fd_dl_get(state->dl);
  state->dlhdr->dst = scamper_addr_use(tbit->dst);
  state->dlhdr->gw = rt->gw != NULL ? scamper_addr_use(rt->gw) : NULL;
  state->dlhdr->ifindex = rt->ifindex;
  state->dlhdr->txtype = scamper_dl_tx_type(dl);
  state->dlhdr->param = task;
  state->dlhdr->cb = tbit_handle_dlhdr;
  if(scamper_dlhdr_get(state->dlhdr) != 0)
    {
      tbit_handleerror(task, errno);
      goto done;
    }

  if(state->mode != MODE_FIREWALL && scamper_task_queue_isdone(task) == 0)
    scamper_task_queue_wait(task, 1000);

 done:
  scamper_route_free(rt);
  if(state->route == rt)
    state->route = NULL;
  return;
}

static void do_tbit_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_file_write_tbit(sf, tbit_getdata(task));
  return;
}

static void tbit_state_free(scamper_task_t *task)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  tbit_state_t *state = tbit_getstate(task);
  int i;

  if(state == NULL)
    return;
  assert(tbit != NULL);

  if(state->fw != NULL)
    scamper_firewall_entry_free(state->fw);

#ifndef _WIN32
  if(state->rtsock != NULL)
    scamper_fd_free(state->rtsock);
#endif

  if(state->dl != NULL)
    scamper_fd_free(state->dl);

  if(state->dlhdr != NULL)
    scamper_dlhdr_free(state->dlhdr);

  if(state->route != NULL)
    scamper_route_free(state->route);

  if(tbit->type == SCAMPER_TBIT_TYPE_PMTUD)
    {
      if(state->pmtud_ptb_data != NULL)
	free(state->pmtud_ptb_data);
    }

  if(state->segments != NULL)
    slist_free_cb(state->segments, (slist_free_t)tbit_segment_free);

  if(state->tx != NULL)
    slist_free_cb(state->tx, (slist_free_t)tp_free);

  if(state->rxq != NULL)
    scamper_tbit_tcpq_free(state->rxq, free);

  if(state->frags != NULL)
    {
      for(i=0; i<state->fragc; i++)
	tbit_frags_free(state->frags[i]);
      free(state->frags);
    }

#if defined(HAVE_OPENSSL)
  if(state->ssl != NULL)
    {
      SSL_free(state->ssl);
    }
  else
    {
      if(state->wbio != NULL)
	BIO_free(state->wbio);
      if(state->rbio != NULL)
	BIO_free(state->rbio);
    }
#endif

  free(state);
  return;
}

static int tbit_state_alloc(scamper_task_t *task)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  scamper_tbit_null_t *null;
  tbit_state_t *state;
  uint16_t seq;

  if((state = malloc_zero(sizeof(tbit_state_t))) == NULL)
    {
      printerror(__func__, "could not malloc state");
      goto err;
    }
  state->mode = MODE_RTSOCK;
  scamper_task_setstate(task, state);

  if((state->segments = slist_alloc()) == NULL)
    {
      printerror(__func__, "could not create segments list");
      goto err;
    }
  if((state->tx = slist_alloc()) == NULL)
    {
      printerror(__func__, "could not create tx list");
      goto err;
    }

  /*
   * generate a random 16 bit sequence number so we don't have to deal
   * with sequence number wrapping for now.
   */
  if(random_u16(&seq) != 0)
    {
      printerror(__func__, "could not get random isn");
      goto err;
    }
  state->snd_nxt = seq;

  if(tbit->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    random_u16(&state->ipid);

#ifndef _WIN32
  if((state->rtsock = scamper_fd_rtsock()) == NULL)
    {
      printerror(__func__, "could not get rtsock");
      goto err;
    }
#endif

  if(tbit->type == SCAMPER_TBIT_TYPE_SACK_RCVR)
    state->flags |= TBIT_STATE_FLAG_NORESET;

  if(tbit->type == SCAMPER_TBIT_TYPE_NULL)
    {
      null = tbit->data;
      if(null->options & SCAMPER_TBIT_NULL_OPTION_IPQS_SYN)
	{
	  random_u32(&state->qs_nonce);
	  state->qs_nonce &= 0x3fffffff; /* 30 bit value */
	  random_u8(&state->qs_ttl);
	}

      /* if we are using the fast-open cookie, get the payload to include */
      if(tbit->fo_cookielen > 0 && tbit_app_rx(task, NULL, 0) <= 0)
	{
	  scamper_debug(__func__, "could not get payload");
	  goto err;
	}
    }

  return 0;

err:
  return -1;
}

static void do_tbit_halt(scamper_task_t *task)
{
  tbit_result(task, SCAMPER_TBIT_RESULT_HALTED);
  return;
}

static void do_tbit_free(scamper_task_t *task)
{
  scamper_tbit_t *tbit = tbit_getdata(task);
  if(tbit == NULL)
    return;
  tbit_state_free(task);
  scamper_tbit_free(tbit);
  return;
}

static int tbit_tx_tcp(scamper_task_t *task, scamper_probe_t *pr,
		       tbit_probe_t *tp)
{
  static scamper_probe_ipopt_t opt;
  scamper_tbit_t *tbit  = tbit_getdata(task);
  tbit_state_t   *state = tbit_getstate(task);
  scamper_tbit_null_t *null;
  struct timeval tv;
  tbit_segment_t *seg;

  pr->pr_ip_proto  = IPPROTO_TCP;
  pr->pr_tcp_sport = tbit->sport;
  pr->pr_tcp_dport = tbit->dport;
  pr->pr_tcp_seq   = state->snd_nxt;
  pr->pr_tcp_win   = 65535;

  if(state->mode == MODE_SYN)
    {
      pr->pr_tcp_flags = TH_SYN;
      pr->pr_tcp_mss   = tbit->client_mss;
      pr->pr_tcp_wscale = tbit->wscale;

      if(tbit->options & SCAMPER_TBIT_OPTION_TCPTS)
	{
	  gettimeofday_wrap(&tv);
	  pr->pr_tcp_opts |= SCAMPER_PROBE_TCPOPT_TS;
	  pr->pr_tcp_tsval = timeval_diff_ms(&tv, &tbit->start);
	}

      if(tbit->options & SCAMPER_TBIT_OPTION_SACK)
	pr->pr_tcp_opts |= SCAMPER_PROBE_TCPOPT_SACK;

      switch(tbit->type)
	{
	case SCAMPER_TBIT_TYPE_ECN:
	  pr->pr_tcp_flags |= (TH_ECE|TH_CWR);
	  break;

	case SCAMPER_TBIT_TYPE_SACK_RCVR:
	  pr->pr_tcp_opts |= SCAMPER_PROBE_TCPOPT_SACK;
	  break;

	case SCAMPER_TBIT_TYPE_NULL:
	  null = tbit->data;
	  if((null->options & SCAMPER_TBIT_NULL_OPTION_FO) ||
	     (null->options & SCAMPER_TBIT_NULL_OPTION_FO_EXP))
	    {
	      if(null->options & SCAMPER_TBIT_NULL_OPTION_FO)
		pr->pr_tcp_opts |= SCAMPER_PROBE_TCPOPT_FO;
	      else
		pr->pr_tcp_opts |= SCAMPER_PROBE_TCPOPT_FO_EXP;
	      pr->pr_tcp_fo_cookielen = tbit->fo_cookielen;
	      if(tbit->fo_cookielen > 0)
		{
		  pr->pr_tcp_fo_cookie = tbit->fo_cookie;
		  if((seg = slist_head_item(state->segments)) != NULL)
		    {
		      pr->pr_data = seg->data;
		      pr->pr_len = seg->len;
		    }
		}
	    }
	  if(null->options & SCAMPER_TBIT_NULL_OPTION_IPTS_SYN)
	    {
	      opt.type = SCAMPER_PROBE_IPOPTS_V4TSO;
	      pr->pr_ipopts = &opt;
	      pr->pr_ipoptc = 1;
	    }
	  if(null->options & SCAMPER_TBIT_NULL_OPTION_IPRR_SYN)
	    {
	      opt.type = SCAMPER_PROBE_IPOPTS_V4RR;
	      pr->pr_ipopts = &opt;
	      pr->pr_ipoptc = 1;
	    }
	  if(null->options & SCAMPER_TBIT_NULL_OPTION_IPQS_SYN)
	    {
	      opt.type = SCAMPER_PROBE_IPOPTS_QUICKSTART;
	      opt.opt_qs_func = 0;
	      opt.opt_qs_rate = 2;
	      opt.opt_qs_ttl = state->qs_ttl;
	      opt.opt_qs_nonce = state->qs_nonce;
	      pr->pr_ipopts = &opt;
	      pr->pr_ipoptc = 1;
	    }
	  break;
	}

      state->attempt++;
      return 1;
    }

  if(tp != NULL)
    {
      if(tp->tp_len > 0)
	{
	  if((seg = slist_head_item(state->segments)) == NULL)
	    return 0;

	  pr->pr_data = seg->data + (tp->tp_seq - state->snd_nxt);
	  pr->pr_len  = tp->tp_len;
	  state->attempt++;
	}
      else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_FIN &&
	      state->mode == MODE_BLIND && state->blind_step == 1 &&
	      (tp->tp_flags & TH_FIN) != 0)
	{
	  state->attempt++;
	}
      pr->pr_tcp_seq = tp->tp_seq;
      pr->pr_tcp_ack = tp->tp_ack;
      pr->pr_tcp_flags = tp->tp_flags;

      if(tp->tp_sackb > 0)
	{
	  pr->pr_tcp_sackb = tp->tp_sackb;
	  memcpy(pr->pr_tcp_sack, tp->tp_sack, 32);
	}
    }
  else
    {
      pr->pr_tcp_ack = state->rcv_nxt;
      pr->pr_tcp_flags = TH_ACK;
      if(state->mode == MODE_FIN)
	pr->pr_tcp_flags |= TH_FIN;
    }

  if(state->flags & TBIT_STATE_FLAG_TCPTS)
    {
      gettimeofday_wrap(&tv);
      pr->pr_tcp_opts |= SCAMPER_PROBE_TCPOPT_TS;
      pr->pr_tcp_tsval = timeval_diff_ms(&tv, &tbit->start);
      pr->pr_tcp_tsecr = state->ts_recent;
      state->ts_lastack = pr->pr_tcp_ack;
    }

  /* only set ECN bits on data packets */
  if(tbit->type == SCAMPER_TBIT_TYPE_ECN &&
     (pr->pr_tcp_flags & TH_FIN) == 0 && pr->pr_len > 0)
    {
      if((state->ecn_flags & TBIT_STATE_ECN_FLAG_CE_SET) != 0)
	pr->pr_ip_tos = IPTOS_ECN_CE;
      else if((state->ecn_flags & TBIT_STATE_ECN_FLAG_ECT) != 0)
	pr->pr_ip_tos = IPTOS_ECN_ECT1;

      if(state->ecn_flags & TBIT_STATE_ECN_FLAG_CWR_SET)
	pr->pr_tcp_flags |= TH_CWR;
    }

  return 1;
}

static int tbit_tx_ptb(scamper_task_t *task, scamper_probe_t *pr,
		       tbit_probe_t *tp)
{
  scamper_tbit_t       *tbit  = tbit_getdata(task);
  tbit_state_t         *state = tbit_getstate(task);
  scamper_tbit_pmtud_t *pmtud = tbit->data;

  SCAMPER_PROBE_ICMP_PTB(pr, pmtud->mtu);

  if(pmtud->ptbsrc != NULL)
    pr->pr_ip_src = pmtud->ptbsrc;

  pr->pr_data      = state->pmtud_ptb_data;
  pr->pr_len       = state->pmtud_ptb_datalen;
  state->attempt++;
  state->pmtud_ptb_c++;

  return 1;
}

static void do_tbit_probe(scamper_task_t *task)
{
  scamper_firewall_rule_t sfw;
  scamper_tbit_t     *tbit = tbit_getdata(task);
  tbit_state_t       *state = tbit_getstate(task);
  scamper_tbit_pkt_t *pkt;
  scamper_probe_t     probe;
  tbit_probe_t       *tp;
  int                 wait, rc;

  if(state == NULL)
    {
      /* Fill in the test start time */
      gettimeofday_wrap(&tbit->start);

      /* Allocate space to store task state */
      if(tbit_state_alloc(task) != 0)
	goto err;

      state = tbit_getstate(task);
    }

  if(state->mode == MODE_RTSOCK)
    {
      state->route = scamper_route_alloc(tbit->dst, task, tbit_handle_rt);
      if(state->route == NULL)
	goto err;

#ifndef _WIN32
      if(scamper_rtsock_getroute(state->rtsock, state->route) != 0)
	goto err;
#else
      if(scamper_rtsock_getroute(state->route) != 0)
	goto err;
#endif

      if(scamper_task_queue_isdone(task))
	return;

      if(state->mode != MODE_FIREWALL)
        {
	  scamper_task_queue_wait(task, 1000);
	  return;
        }
    }

  if(state->mode == MODE_FIREWALL)
    {
      sfw.type = SCAMPER_FIREWALL_RULE_TYPE_5TUPLE;
      sfw.sfw_5tuple_proto = IPPROTO_TCP;
      sfw.sfw_5tuple_src   = tbit->dst;
      sfw.sfw_5tuple_dst   = tbit->src;
      sfw.sfw_5tuple_sport = tbit->dport;
      sfw.sfw_5tuple_dport = tbit->sport;

      if((state->fw = scamper_firewall_entry_get(&sfw)) == NULL)
	{
	  scamper_debug(__func__, "could not get firewall entry");
	  goto err;
	}

      state->mode = MODE_SYN;
    }

  memset(&probe, 0, sizeof(probe));

  /* Common to all probes */
  probe.pr_dl     = scamper_fd_dl_get(state->dl);
  probe.pr_dl_buf = state->dlhdr->buf;
  probe.pr_dl_len = state->dlhdr->len;
  probe.pr_ip_src = tbit->src;
  probe.pr_ip_dst = tbit->dst;
  probe.pr_ip_ttl = tbit->ttl;

  if(tbit->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      probe.pr_ip_id = state->ipid++;
      probe.pr_ip_off = IP_DF;
    }

  /* if there are specific packets to be sent, then do so */
  if((tp = slist_head_pop(state->tx)) != NULL)
    {
      if(tp->type == TBIT_PROBE_TYPE_TCP)
	rc = tbit_tx_tcp(task, &probe, tp);
      else if(tp->type == TBIT_PROBE_TYPE_PTB)
	rc = tbit_tx_ptb(task, &probe, tp);
      else
	rc = 0;
      wait = tp->wait;
      tp_free(tp);
    }
  else
    {
      rc = tbit_tx_tcp(task, &probe, NULL);
      wait = TBIT_TIMEOUT_DEFAULT;
    }

  if(rc == 0)
    {
      tbit_queue(task);
      return;
    }

  /* Send the probe */
  if(scamper_probe(&probe) != 0)
    {
      errno = probe.pr_errno;
      printerror(__func__, "could not send probe");
      goto err;
    }

  if((pkt = scamper_tbit_pkt_alloc(SCAMPER_TBIT_PKT_DIR_TX, probe.pr_tx_raw,
				   probe.pr_tx_rawlen, &probe.pr_tx))==NULL ||
     scamper_tbit_record_pkt(tbit, pkt) != 0)
    {
      printerror(__func__, "could not record packet");
      goto err;
    }

  if(wait > 0)
    timeval_add_ms(&state->timeout, &probe.pr_tx, wait);

  tbit_queue(task);
  return;

err:
  tbit_handleerror(task, errno);
  return;
}

static int tbit_arg_param_validate(int optid, char *param, long long *out)
{
  long tmp;

  switch(optid)
    {
    case TBIT_OPT_TYPE:
      if(strcasecmp(param, "pmtud") == 0)
	tmp = SCAMPER_TBIT_TYPE_PMTUD;
      else if(strcasecmp(param, "ecn") == 0)
	tmp = SCAMPER_TBIT_TYPE_ECN;
      else if(strcasecmp(param, "null") == 0)
	tmp = SCAMPER_TBIT_TYPE_NULL;
      else if(strcasecmp(param, "sack-rcvr") == 0)
	tmp = SCAMPER_TBIT_TYPE_SACK_RCVR;
      else if(strcasecmp(param, "icw") == 0)
	tmp = SCAMPER_TBIT_TYPE_ICW;
      else if(strcasecmp(param, "blind-data") == 0)
	tmp = SCAMPER_TBIT_TYPE_BLIND_DATA;
      else if(strcasecmp(param, "blind-rst") == 0)
	tmp = SCAMPER_TBIT_TYPE_BLIND_RST;
      else if(strcasecmp(param, "blind-syn") == 0)
	tmp = SCAMPER_TBIT_TYPE_BLIND_SYN;
      else if(strcasecmp(param, "blind-fin") == 0)
	tmp = SCAMPER_TBIT_TYPE_BLIND_FIN;
      else
	goto err;
      break;

    case TBIT_OPT_APP:
      if(strcasecmp(param, "http") == 0)
	tmp = SCAMPER_TBIT_APP_HTTP;
      else if(strcasecmp(param, "bgp") == 0)
	tmp = SCAMPER_TBIT_APP_BGP;
      else
	goto err;
      break;

    case TBIT_OPT_SPORT:
    case TBIT_OPT_DPORT:
    case TBIT_OPT_MSS:
    case TBIT_OPT_MTU:
    case TBIT_OPT_ASN:
      if(string_tolong(param, &tmp) != 0 || tmp < 0 || tmp > 65535)
	goto err;
      break;

    case TBIT_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	goto err;
      break;

    case TBIT_OPT_FO:
      tmp = strlen(param);
      if((tmp % 8) != 0)
	return -1;
      tmp = tmp / 2;
      if(tmp < 4 || tmp > 16)
	return -1;
      break;

    case TBIT_OPT_WSCALE:
      if(string_tolong(param, &tmp) != 0 || tmp > 14 || tmp < 0)
	goto err;
      break;

    case TBIT_OPT_ATTEMPTS:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 4)
	goto err;
      break;

    case TBIT_OPT_OFFSET:
      if(string_tolong(param, &tmp) != 0)
	goto err;
#if SIZEOF_LONG > 4
      if(tmp > 2147483647 || tmp < -2147483647)
	goto err;
#endif
      break;

    case TBIT_OPT_TTL:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 255)
	goto err;
      break;

    case TBIT_OPT_PTBSRC:
    case TBIT_OPT_OPTION:
    case TBIT_OPT_URL:
    case TBIT_OPT_SRCADDR:
      tmp = 0;
      break;

    default:
      return -1;
    }

  /* valid parameter */
  if(out != NULL)
    *out = (long long)tmp;
  return 0;

 err:
  return -1;
}

int scamper_do_tbit_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  tbit_arg_param_validate);
}

static int tbit_app_smtp(scamper_tbit_t *tbit, tbit_options_t *o)
{
  if(tbit->dport == 0)
    tbit->dport = 25;
  return 0;
}

static int tbit_app_dns(scamper_tbit_t *tbit, tbit_options_t *o)
{
  if(tbit->dport == 0)
    tbit->dport = 53;
  return 0;
}

static int tbit_app_ftp(scamper_tbit_t *tbit, tbit_options_t *o)
{
  if(tbit->dport == 0)
    tbit->dport = 21;
  return 0;
}

static int tbit_app_bgp(scamper_tbit_t *tbit, tbit_options_t *o)
{
  scamper_tbit_app_bgp_t *bgp;
  if(tbit->dport == 0)
    tbit->dport = 179;
  if((bgp = scamper_tbit_app_bgp_alloc()) == NULL)
    return -1;
  if(o->asn == 0)
    bgp->asn = 1;
  else
    bgp->asn = o->asn;
  tbit->app_data = bgp;
  return 0;
}

static int tbit_app_http(scamper_tbit_t *tbit, tbit_options_t *o)
{
  uint8_t type = SCAMPER_TBIT_APP_HTTP_TYPE_HTTP;
  char *file = NULL, *host, *port, *ptr;
  uint16_t dport = 80;
  long lo;

  if(o->url == NULL)
    {
      host = NULL; file = "/";
      goto done;
    }

  if(strncasecmp(o->url, "http://", 7) == 0)
    {
      host = o->url+7;
    }
#if defined(HAVE_OPENSSL)
  else if(strncasecmp(o->url, "https://", 8) == 0)
    {
      if(scamper_option_notls() != 0)
	return -1;
      dport = 443;
      host = o->url+8;
      type = SCAMPER_TBIT_APP_HTTP_TYPE_HTTPS;
    }
#endif
  else
    {
      return -1;
    }

  /* extract the domain */
  ptr = host;
  while(*ptr != '\0')
    {
      if(*ptr == '/' || *ptr == ':') break;
      if(isalnum((int)*ptr) == 0 && *ptr != '-' && *ptr != '.') return -1;
      ptr++;
    }
  if(ptr == host)
    return -1;

  if(*ptr == '\0')
    goto done;

  if(*ptr == ':')
    {
      *ptr = '\0';
      ptr++; port = ptr;
      while(*ptr != '\0')
	{
	  if(*ptr == '/') break;
	  ptr++;
	}

      if(*ptr == '\0')
	goto done;
      *ptr = '\0';

      if(string_tolong(port, &lo) != 0 || lo < 1 || lo > 65535)
	return -1;
      dport = (uint16_t)lo;
      *ptr = '/';
    }

  memmove(host-1, host, ptr-host);
  host--;
  *(ptr-1) = '\0';
  file = ptr;

 done:
  if(file == NULL)
    file = "/";
  if(tbit->dport == 0)
    tbit->dport = dport;
  if((tbit->app_data = scamper_tbit_app_http_alloc(type, host, file)) == NULL)
    return -1;
  return 0;
}

static int tbit_alloc_pmtud(scamper_tbit_t *tbit, tbit_options_t *o)
{
  scamper_tbit_pmtud_t *pmtud;
  int af;

  if((pmtud = scamper_tbit_pmtud_alloc()) == NULL)
    return -1;
  tbit->data = pmtud;

  if(o->mtu == 0)
    pmtud->mtu = 1280;
  else
    pmtud->mtu = o->mtu;

  if(o->ptbsrc != NULL)
    {
      af = scamper_addr_af(tbit->dst);
      if(af != AF_INET && af != AF_INET6)
	return -1;
      pmtud->ptbsrc = scamper_addrcache_resolve(addrcache, af, o->ptbsrc);
      if(pmtud->ptbsrc == NULL || pmtud->ptbsrc->type != tbit->dst->type)
	return -1;
    }

  /* if we're in blackhole mode, we don't send PTB messages */
  if(o->options & TBIT_OPT_OPTION_BLACKHOLE)
    pmtud->options |= SCAMPER_TBIT_PMTUD_OPTION_BLACKHOLE;
  else if(o->attempts == 0)
    pmtud->ptb_retx = 4;
  else
    pmtud->ptb_retx = o->attempts;

  return 0;
}

static int tbit_alloc_icw(scamper_tbit_t *tbit, tbit_options_t *o)
{
  if((tbit->data = scamper_tbit_icw_alloc()) == NULL)
    return -1;
  if(o->options & TBIT_OPT_OPTION_TCPTS)
    tbit->options |= SCAMPER_TBIT_OPTION_TCPTS;
  if(o->options & TBIT_OPT_OPTION_SACK)
    tbit->options |= SCAMPER_TBIT_OPTION_SACK;
  return 0;
}

static int tbit_alloc_blind(scamper_tbit_t *tbit, tbit_options_t *o)
{
  scamper_tbit_blind_t *blind;

  if((blind = scamper_tbit_blind_alloc()) == NULL)
    return -1;
  tbit->data = blind;

  if(o->attempts == 0)
    blind->retx = 3;
  else
    blind->retx = o->attempts;

  if(o->offset == 0)
    {
      if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_SYN ||
	 tbit->type == SCAMPER_TBIT_TYPE_BLIND_RST)
	blind->off = 10;
      else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA ||
	      tbit->type == SCAMPER_TBIT_TYPE_BLIND_FIN)
	blind->off = -70000;
      else
	return -1;
    }
  else
    blind->off = o->offset;

  return 0;
}

static int tbit_alloc_null(scamper_tbit_t *tbit, tbit_options_t *o)
{
  scamper_tbit_null_t *null;
  uint16_t u;

  /* ensure that only one IP option is set on the SYN packet */
  u = (o->options & TBIT_OPT_OPTION_IPOPT_SYN_MASK);
  if(u != 0 && countbits32(u) != 1)
    return -1;

  if((null = scamper_tbit_null_alloc()) == NULL)
    return -1;
  tbit->data = null;

  if(o->options & TBIT_OPT_OPTION_TCPTS)
    tbit->options |= SCAMPER_TBIT_OPTION_TCPTS;
  if(o->options & TBIT_OPT_OPTION_SACK)
    tbit->options |= SCAMPER_TBIT_OPTION_SACK;
  if(o->options & TBIT_OPT_OPTION_IPQS_SYN)
    null->options |= SCAMPER_TBIT_NULL_OPTION_IPQS_SYN;

  if(o->options & TBIT_OPT_OPTION_FO)
    null->options |= SCAMPER_TBIT_NULL_OPTION_FO;
  else if(o->options & TBIT_OPT_OPTION_FO_EXP)
    null->options |= SCAMPER_TBIT_NULL_OPTION_FO_EXP;

  if(o->fo_cookielen > 0)
    {
      if(scamper_tbit_fo_setcookie(tbit, o->fo_cookie, o->fo_cookielen) != 0)
	return -1;
      if((o->options & (TBIT_OPT_OPTION_FO|TBIT_OPT_OPTION_FO_EXP)) == 0)
	null->options = SCAMPER_TBIT_NULL_OPTION_FO;
    }

  if(o->options & (TBIT_OPT_OPTION_IPTS_SYN | TBIT_OPT_OPTION_IPRR_SYN))
    {
      if(SCAMPER_ADDR_TYPE_IS_IPV4(tbit->dst) == 0)
	return -1;

      if(o->options & TBIT_OPT_OPTION_IPTS_SYN)
	null->options |= SCAMPER_TBIT_NULL_OPTION_IPTS_SYN;
      if(o->options & TBIT_OPT_OPTION_IPRR_SYN)
	null->options |= SCAMPER_TBIT_NULL_OPTION_IPRR_SYN;
    }

  return 0;
}

/*
 * scamper_do_tbit_alloc
 *
 * Given a string representing a tbit task, parse the parameters and assemble
 * a tbit. Return the tbit structure so that it is all ready to go.
 */
void *scamper_do_tbit_alloc(char *str)
{
  static int (* const type_func[])(scamper_tbit_t *, tbit_options_t *) = {
    NULL,
    tbit_alloc_pmtud, /* pmtud */
    NULL,             /* ecn */
    tbit_alloc_null,  /* null */
    NULL,             /* sack-rcvr */
    tbit_alloc_icw,   /* icw */
    NULL,             /* abc */
    tbit_alloc_blind, /* blind-data */
    tbit_alloc_blind, /* blind-rst */
    tbit_alloc_blind, /* blind-syn */
    tbit_alloc_blind, /* blind-fin */
  };
  static int (* const app_func[])(scamper_tbit_t *, tbit_options_t *) = {
    NULL,
    tbit_app_http,
    tbit_app_smtp,
    tbit_app_dns,
    tbit_app_ftp,
    tbit_app_bgp,
  };
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_tbit_t *tbit = NULL;
  tbit_options_t o;
  uint8_t type = SCAMPER_TBIT_TYPE_NULL;
  uint8_t wscale = 0;
  uint8_t ttl = 255;
  uint32_t userid = 0;
  char *addr;
  long long tmp = 0;
  int i;

  memset(&o, 0, sizeof(o));

  /* Parse the options */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      scamper_debug(__func__, "could not parse options");
      goto err;
    }

  /* If there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      scamper_debug(__func__, "no address parameter");
      goto err;
    }

  /* Parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 tbit_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
        {
	case TBIT_OPT_TYPE:
	  type = (uint8_t)tmp;
	  break;

	case TBIT_OPT_APP:
	  o.app = (uint8_t)tmp;
	  break;

	case TBIT_OPT_DPORT:
	  o.dport = (uint16_t)tmp;
	  break;

	case TBIT_OPT_SPORT:
	  o.sport = (uint16_t)tmp;
	  break;

	case TBIT_OPT_MSS:
	  o.mss = (uint16_t)tmp;
	  break;

	case TBIT_OPT_MTU:
	  o.mtu = (uint16_t)tmp;
	  break;

	case TBIT_OPT_SRCADDR:
	  o.src = opt->str;
	  break;

	case TBIT_OPT_URL:
	  o.url = opt->str;
	  break;

	case TBIT_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case TBIT_OPT_PTBSRC:
	  o.ptbsrc = opt->str;
	  break;

	case TBIT_OPT_FO:
	  for(i=0; i<tmp; i++)
	    o.fo_cookie[i] = hex2byte(opt->str[i*2], opt->str[(i*2)+1]);
	  o.fo_cookielen = (uint8_t)tmp;
	  break;

	case TBIT_OPT_WSCALE:
	  wscale = (uint8_t)tmp;
	  break;

	case TBIT_OPT_ATTEMPTS:
	  o.attempts = (uint8_t)tmp;
	  break;

	case TBIT_OPT_OFFSET:
	  o.offset = (int32_t)tmp;
	  break;

	case TBIT_OPT_ASN:
	  o.asn = (uint16_t)tmp;
	  break;

	case TBIT_OPT_TTL:
	  ttl = (uint8_t)tmp;
	  break;

	case TBIT_OPT_OPTION:
	  if(strcasecmp(opt->str, "blackhole") == 0)
	    o.options |= TBIT_OPT_OPTION_BLACKHOLE;
	  else if(strcasecmp(opt->str, "tcpts") == 0)
	    o.options |= TBIT_OPT_OPTION_TCPTS;
	  else if(strcasecmp(opt->str, "ipts-syn") == 0)
	    o.options |= TBIT_OPT_OPTION_IPTS_SYN;
	  else if(strcasecmp(opt->str, "iprr-syn") == 0)
	    o.options |= TBIT_OPT_OPTION_IPRR_SYN;
	  else if(strcasecmp(opt->str, "ipqs-syn") == 0)
	    o.options |= TBIT_OPT_OPTION_IPQS_SYN;
	  else if(strcasecmp(opt->str, "sack") == 0)
	    o.options |= TBIT_OPT_OPTION_SACK;
	  else if(strcasecmp(opt->str, "fo") == 0)
	    o.options |= TBIT_OPT_OPTION_FO;
	  else if(strcasecmp(opt->str, "fo-exp") == 0)
	    o.options |= TBIT_OPT_OPTION_FO_EXP;
	  else
	    goto err;
	  break;
        }
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if(type == SCAMPER_TBIT_TYPE_SACK_RCVR)
    {
      if(o.dat_retx != 0 && o.dat_retx != 1)
	goto err;
      if(o.dat_retx == 0)
	o.dat_retx = 1;
    }

  if((tbit = scamper_tbit_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc tbit");
      goto err;
    }
  if((tbit->dst = scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr)) == NULL)
    {
      printerror(__func__, "could not resolve %s", addr);
      goto err;
    }
  tbit->type       = type;
  tbit->userid     = userid;
  tbit->wscale     = wscale;
  tbit->ttl        = ttl;
  tbit->client_mss = o.mss;
  tbit->dport      = o.dport;
  tbit->sport      = (o.sport != 0)    ? o.sport    : scamper_sport_default();
  tbit->syn_retx   = (o.syn_retx != 0) ? o.syn_retx : TBIT_RETX_DEFAULT;
  tbit->dat_retx   = (o.dat_retx != 0) ? o.dat_retx : TBIT_RETX_DEFAULT;

  if(o.src != NULL)
    {
      i = scamper_addr_af(tbit->dst);
      if(i != AF_INET && i != AF_INET6)
	goto err;
      if((tbit->src = scamper_addrcache_resolve(addrcache, i, o.src)) == NULL)
	goto err;
    }

  if(o.app == 0) o.app = SCAMPER_TBIT_APP_HTTP;
  tbit->app_proto = o.app;
  if(app_func[o.app] != NULL && app_func[o.app](tbit, &o) != 0)
    goto err;

  if(type_func[type] != NULL && type_func[type](tbit, &o) != 0)
    goto err;

  return tbit;

err:
  if(tbit != NULL) scamper_tbit_free(tbit);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

void scamper_do_tbit_free(void *data)
{
  scamper_tbit_t *tbit = (scamper_tbit_t *)data;
  scamper_tbit_free(tbit);
  return;
}

scamper_task_t *scamper_do_tbit_alloctask(void *data, scamper_list_t *list,
					  scamper_cycle_t *cycle)
{
  scamper_tbit_t *tbit = (scamper_tbit_t *)data;
  scamper_task_sig_t *sig = NULL;
  scamper_task_t *task = NULL;

  /* allocate a task structure and store the tbit with it */
  if((task = scamper_task_alloc(data, &tbit_funcs)) == NULL)
    goto err;

  /* declare the signature of the tbit task */
  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
    goto err;
  sig->sig_tx_ip_dst = scamper_addr_use(tbit->dst);
  if(tbit->src == NULL && (tbit->src = scamper_getsrc(tbit->dst,0)) == NULL)
    goto err;
  sig->sig_tx_ip_src = scamper_addr_use(tbit->src);
  if(scamper_task_sig_add(task, sig) != 0)
    goto err;
  sig = NULL;

  /* associate the list and cycle with the tbit */
  tbit->list  = scamper_list_use(list);
  tbit->cycle = scamper_cycle_use(cycle);

  return task;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  if(task != NULL)
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  return NULL;
}

void scamper_do_tbit_cleanup(void)
{
#if defined(HAVE_OPENSSL)
  if(ssl_ctx != NULL)
    {
      SSL_CTX_free(ssl_ctx);
      ssl_ctx = NULL;
    }
#endif
  return;
}

int scamper_do_tbit_init(void)
{
#if defined(HAVE_OPENSSL)
  if(scamper_option_notls() == 0)
    {
      if((ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
	return -1;
      SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    }
#endif

  tbit_funcs.probe          = do_tbit_probe;
  tbit_funcs.handle_icmp    = NULL;
  tbit_funcs.handle_dl      = do_tbit_handle_dl;
  tbit_funcs.handle_timeout = do_tbit_handle_timeout;
  tbit_funcs.write          = do_tbit_write;
  tbit_funcs.task_free      = do_tbit_free;
  tbit_funcs.halt           = do_tbit_halt;

  return 0;
}
