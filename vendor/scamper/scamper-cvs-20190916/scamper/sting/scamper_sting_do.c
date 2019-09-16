/*
 * scamper_do_sting.c
 *
 * $Id: scamper_sting_do.c,v 1.48 2019/07/12 23:37:57 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
 * Author: Matthew Luckie
 *
 * This file implements algorithms described in the sting-0.7 source code,
 * as well as the paper:
 *
 *  Sting: a TCP-based Network Measurement Tool
 *  by Stefan Savage
 *  1999 USENIX Symposium on Internet Technologies and Systems
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
  "$Id: scamper_sting_do.c,v 1.48 2019/07/12 23:37:57 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_sting.h"
#include "scamper_task.h"
#include "scamper_dl.h"
#include "scamper_fds.h"
#include "scamper_dlhdr.h"
#include "scamper_firewall.h"
#include "scamper_rtsock.h"
#include "scamper_probe.h"
#include "scamper_getsrc.h"
#include "scamper_tcp4.h"
#include "scamper_tcp6.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_options.h"
#include "scamper_debug.h"
#include "scamper_sting_do.h"
#include "utils.h"
#include "mjl_list.h"

/*
 * how many packets to send in data phase:
 *   freebsd net.inet.tcp.reass.maxqlen = 48
 *   note that this value is different to the hard-coded sting-0.7 default
 *   of 100.
 */
#define SCAMPER_DO_STING_COUNT_MIN 2
#define SCAMPER_DO_STING_COUNT_DEF 48
#define SCAMPER_DO_STING_COUNT_MAX 65535

/*
 * mean rate at which to send packets in data phase:
 *   100ms is the hard-coded number in sting-0.7
 */
#define SCAMPER_DO_STING_MEAN_MIN  1
#define SCAMPER_DO_STING_MEAN_DEF  100
#define SCAMPER_DO_STING_MEAN_MAX  1000

/*
 * inter-phase delay between data seeding and hole filling.
 *   2000ms is the hard-coded number in sting-0.7
 */
#define SCAMPER_DO_STING_INTER_MIN  1
#define SCAMPER_DO_STING_INTER_DEF  2000
#define SCAMPER_DO_STING_INTER_MAX  10000

/*
 * distribution to apply when determining when to send the next packet
 *  3 corresponds to uniform distribution
 */
#define SCAMPER_DO_STING_DIST_MIN  1
#define SCAMPER_DO_STING_DIST_DEF  3
#define SCAMPER_DO_STING_DIST_MAX  3

/*
 * how many times to retransmit a syn packet before deciding the host is down
 *  3 is the hard-coded number in sting-0.7
 */
#define SCAMPER_DO_STING_SYNRETX_MIN 0
#define SCAMPER_DO_STING_SYNRETX_DEF 3
#define SCAMPER_DO_STING_SYNRETX_MAX 5

/*
 * number of times to retransmit data packets
 *  5 is the default number in sting-0.7
 */
#define SCAMPER_DO_STING_DATARETX_MIN 0
#define SCAMPER_DO_STING_DATARETX_DEF 5
#define SCAMPER_DO_STING_DATARETX_MAX 10

/*
 * size of the first hole in the sequence number space
 *  3 is the default number in sting-0.7
 */
#define SCAMPER_DO_STING_SEQSKIP_MIN 1
#define SCAMPER_DO_STING_SEQSKIP_DEF 3
#define SCAMPER_DO_STING_SEQSKIP_MAX 255

typedef struct sting_state
{
  uint8_t                   mode;
  struct timeval            next_tx;

#ifndef _WIN32
  scamper_fd_t             *rtsock;
#endif

  scamper_fd_t             *dl;
  scamper_firewall_entry_t *fw;
  scamper_route_t          *route;
  scamper_dlhdr_t          *dlhdr;
  uint32_t                  isn;     /* initial sequence number */
  uint32_t                  ack;     /* acknowledgement number to use */
  uint32_t                  off;     /* which byte to tx next */
  uint8_t                   attempt;
  scamper_sting_pkt_t     **probes;
  uint16_t                  probec;
} sting_state_t;

static const uint8_t MODE_RTSOCK = 0;
static const uint8_t MODE_DLHDR  = 1;
static const uint8_t MODE_SYN    = 2;
static const uint8_t MODE_ACK    = 3;
static const uint8_t MODE_DATA   = 4;
static const uint8_t MODE_INTER  = 5;
static const uint8_t MODE_HOLE   = 6;
static const uint8_t MODE_RST    = 7;

/* the callback functions registered with the sting task */
static scamper_task_funcs_t sting_funcs;

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

#define STING_OPT_COUNT  1
#define STING_OPT_DPORT  2
#define STING_OPT_DIST   3
#define STING_OPT_REQ    4
#define STING_OPT_HOLE   5
#define STING_OPT_INTER  6
#define STING_OPT_MEAN   7
#define STING_OPT_SPORT  8
#define STING_OPT_USERID 9

static const scamper_option_in_t opts[] = {
  {'c', NULL, STING_OPT_COUNT,  SCAMPER_OPTION_TYPE_NUM},
  {'d', NULL, STING_OPT_DPORT,  SCAMPER_OPTION_TYPE_NUM},
  {'f', NULL, STING_OPT_DIST,   SCAMPER_OPTION_TYPE_STR},
  {'h', NULL, STING_OPT_REQ,    SCAMPER_OPTION_TYPE_STR},
  {'H', NULL, STING_OPT_HOLE,   SCAMPER_OPTION_TYPE_NUM},
  {'i', NULL, STING_OPT_INTER,  SCAMPER_OPTION_TYPE_NUM},
  {'m', NULL, STING_OPT_MEAN,   SCAMPER_OPTION_TYPE_STR},
  {'s', NULL, STING_OPT_SPORT,  SCAMPER_OPTION_TYPE_NUM},
  {'U', NULL, STING_OPT_USERID, SCAMPER_OPTION_TYPE_NUM},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_sting_usage(void)
{
  return "sting [-c count] [-d dport] [-f distribution] [-h request]\n"
         "      [-H hole] [-i inter] [-m mean] [-s sport] [-U userid]";
}

/*
 * this is the default request used when none is specified.  it is the same
 * default request found in sting-0.7, except it uses <CR><LF> not
 * just <LF> as per the HTTP specification.
 */
static const char *defaultrequest =
  "GET / HTTP/1.0\r\n"
  "Accept: text/plain\r\n"
  "Accept: */*\r\n"
  "User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; Sting)\r\n"
  "\r\n";

static scamper_sting_t *sting_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static sting_state_t *sting_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static void sting_handleerror(scamper_task_t *task, int error)
{
  scamper_task_queue_done(task, 0);
  return;
}

/*
 * handletimeout_syn
 *
 * retransmit a syn up to a specified number of times.
 */
static void handletimeout_syn(scamper_task_t *task)
{
  scamper_sting_t *sting = sting_getdata(task);
  sting_state_t *state = sting_getstate(task);

  if(state->attempt == sting->synretx)
    scamper_task_queue_done(task, 0);
  else
    scamper_task_queue_probe(task);

  return;
}

/*
 * handletimeout_inter
 *
 * this function is called to signal the end of the inter-phase wait time.
 * the only point of this function is to shift the sting into the hole-filling
 * phase.
 */
static void handletimeout_inter(scamper_task_t *task)
{
  sting_state_t *state = sting_getstate(task);
  state->attempt = 0;
  state->off     = 0;
  state->mode    = MODE_HOLE;
  scamper_task_queue_probe(task);
  return;
}

/*
 * handletimeout_hole
 *
 * this function is called when a timeout occurs when in the hole-filling
 * state.  it allows a packet in a hole to be retransmitted a number of times
 * before giving up.
 */
static void handletimeout_hole(scamper_task_t *task)
{
  scamper_sting_t *sting = sting_getdata(task);
  sting_state_t *state = sting_getstate(task);

  /*
   * when we reach the maximum number of retranmissions, send a reset
   * and give up
   */
  if(state->attempt == sting->dataretx)
    state->mode = MODE_RST;

  scamper_task_queue_probe(task);
  return;
}

/*
 * handletimeout_rst
 *
 * this function exists solely to ensure a task makes its way into the
 * done queue after a reset has been transmitted.
 */
static void handletimeout_rst(scamper_task_t *task)
{
  scamper_task_queue_done(task, 0);
  return;
}

/*
 * do_sting_handle_timeout
 *
 * this function ensures an appropriate action is taken when a timeout
 * occurs.
 */
static void do_sting_handle_timeout(scamper_task_t *task)
{
  static void (* const func[])(scamper_task_t *) =
  {
    NULL,                /* MODE_RTSOCK */
    NULL,                /* MODE_DLHDR */
    handletimeout_syn,   /* MODE_SYN */
    NULL,                /* MODE_ACK */
    NULL,                /* MODE_DATA */
    handletimeout_inter, /* MODE_INTER */
    handletimeout_hole,  /* MODE_HOLE */
    handletimeout_rst,   /* MODE_RST */
  };
  sting_state_t *state = sting_getstate(task);

  if(func[state->mode] != NULL)
    {
      func[state->mode](task);
    }

  return;
}

/*
 * handletcp_syn
 *
 * this function checks the response to a syn
 */
static void handletcp_syn(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_sting_t *sting = sting_getdata(task);
  sting_state_t *state = sting_getstate(task);
  struct timeval tv;

  /*
   * wait for the SYN/ACK to come in; make a note of the sequence number
   * used by the receiver, and take an RTT measurement if possible.
   */
  if((dl->dl_tcp_flags & (TH_SYN|TH_ACK)) != (TH_SYN|TH_ACK))
    {
      /* we got a reply, but it was not a SYN/ACK; halt the measurement */
      scamper_task_queue_done(task, 0);
      return;
    }

  /*
   * the initial syn occupies one byte in the sequence space; data is
   * going to have this offset
   */
  state->isn++;

  /* if the sequence number in response did not make sense, abandon */
  if(dl->dl_tcp_ack != state->isn)
    {
      scamper_task_queue_done(task, 0);
      return;
    }

  /* if we get a syn/ack on the first probe, take an RTT measurement */
  if(state->attempt == 1)
    {
      tv.tv_sec  = state->next_tx.tv_sec - 5;
      tv.tv_usec = state->next_tx.tv_usec;
      timeval_diff_tv(&sting->hsrtt, &tv, &dl->dl_tv);
    }

  /* send a token acknowledgement */
  state->ack  = dl->dl_tcp_seq + 1;
  state->mode = MODE_ACK;

  /* leave a hole in the sequence space */
  state->off  = sting->seqskip;

  scamper_task_queue_probe(task);
  return;
}

/*
 * handletcp_data
 *
 * for each acknowledgement received, check that it makes sense.
 * count the number of acknowledgements received in the data phase
 */
static void handletcp_data(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_sting_t *sting = sting_getdata(task);
  sting_state_t *state = sting_getstate(task);

  /* if the acknowledgement number is not what is expected, abandon */
  if(dl->dl_tcp_ack != state->isn)
    {
      scamper_task_queue_done(task, 0);
      return;
    }

  sting->dataackc++;
  return;
}

/*
 * handletcp_hole
 *
 * for each acknowledgement received in the hole-filling phase, figure out
 * if all probes have been accounted for
 */
static void handletcp_hole(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_sting_t *sting = sting_getdata(task);
  sting_state_t *state = sting_getstate(task);
  uint16_t u16;

  /*
   * this handles the case where the receiver lost our ACK to
   * their SYN/ACK and the data request.
   */
  if(state->isn >= dl->dl_tcp_ack)
    goto err;

  /* check to see if all holes are now full */
  if(state->isn + sting->seqskip + sting->count == dl->dl_tcp_ack)
    {
      state->off  = sting->seqskip + sting->count - 1;
      state->mode = MODE_RST;
      sting->result = SCAMPER_STING_RESULT_COMPLETED;
      scamper_task_queue_probe(task);
      return;
    }

  state->off = dl->dl_tcp_ack - state->isn;
  u16 = state->off - sting->seqskip;
  if(u16 >= state->probec)
    goto err;

  state->probes[u16]->flags |= SCAMPER_STING_PKT_FLAG_HOLE;
  sting->holec++;
  state->attempt = 0;
  scamper_task_queue_probe(task);
  return;

 err:
  state->mode = MODE_RST;
  scamper_task_queue_probe(task);
  return;
}

/*
 * do_sting_handle_dl
 *
 * for each packet received, check that the addresses and ports make sense,
 * and that the packet is not a reset
 */
static void do_sting_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  static void (* const func[])(scamper_task_t *, scamper_dl_rec_t *) =
  {
    NULL,           /* MODE_RTSOCK */
    NULL,           /* MODE_DLHDR */
    handletcp_syn,  /* MODE_SYN */
    NULL,           /* MODE_ACK */
    handletcp_data, /* MODE_DATA */
    handletcp_data, /* MODE_INTER */
    handletcp_hole, /* MODE_HOLE */
    NULL,           /* MODE_RST */
  };
  scamper_sting_t *sting = sting_getdata(task);
  sting_state_t *state = sting_getstate(task);
  scamper_sting_pkt_t *pkt;

  /* unless the packet is an inbound TCP packet for the flow, ignore it */
  if(SCAMPER_DL_IS_TCP(dl) == 0 ||
     dl->dl_tcp_sport != sting->dport ||
     dl->dl_tcp_dport != sting->sport ||
     scamper_addr_raw_cmp(sting->src, dl->dl_ip_dst) != 0 ||
     scamper_addr_raw_cmp(sting->dst, dl->dl_ip_src) != 0)
    {
      return;
    }

  scamper_dl_rec_tcp_print(dl);

  pkt = scamper_sting_pkt_alloc(SCAMPER_STING_PKT_FLAG_RX, dl->dl_net_raw,
				dl->dl_ip_size, &dl->dl_tv);
  if(pkt == NULL || scamper_sting_pkt_record(sting, pkt) != 0)
    {
      if(pkt != NULL) scamper_sting_pkt_free(pkt);
      sting_handleerror(task, errno);
      return;
    }

  /* if a reset packet is received, abandon the measurement */
  if((dl->dl_tcp_flags & TH_RST) != 0)
    {
      scamper_task_queue_done(task, 0);
      return;
    }

  if(func[state->mode] != NULL)
    {
      func[state->mode](task, dl);
    }
  return;
}

static void sting_handle_dlhdr(scamper_dlhdr_t *dlhdr)
{
  scamper_task_t *task = dlhdr->param;
  sting_state_t *state = sting_getstate(task);

  if(dlhdr->error != 0)
    {
      scamper_task_queue_done(task, 0);
      return;
    }

  state->mode = MODE_SYN;
  scamper_task_queue_probe(task);
  return;
}

static void sting_handle_rt(scamper_route_t *rt)
{
  scamper_task_t *task = rt->param;
  scamper_sting_t *sting = sting_getdata(task);
  sting_state_t *state = sting_getstate(task);
  scamper_dl_t *dl;

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
      sting_handleerror(task, errno);
      goto done;
    }

  if((state->dl = scamper_fd_dl(rt->ifindex)) == NULL)
    {
      scamper_debug(__func__, "could not get dl for %d", rt->ifindex);
      sting_handleerror(task, errno);
      goto done;
    }

  /*
   * determine the underlying framing to use with each probe packet that will
   * be sent on the datalink.
   */
  state->mode = MODE_DLHDR;
  if((state->dlhdr = scamper_dlhdr_alloc()) == NULL)
    {
      sting_handleerror(task, errno);
      goto done;
    }
  dl = scamper_fd_dl_get(state->dl);
  state->dlhdr->dst = scamper_addr_use(sting->dst);
  state->dlhdr->gw = rt->gw != NULL ? scamper_addr_use(rt->gw) : NULL;
  state->dlhdr->ifindex = rt->ifindex;
  state->dlhdr->txtype = scamper_dl_tx_type(dl);
  state->dlhdr->param = task;
  state->dlhdr->cb = sting_handle_dlhdr;
  if(scamper_dlhdr_get(state->dlhdr) != 0)
    {
      sting_handleerror(task, errno);
      goto done;
    }

  if(state->mode != MODE_SYN && scamper_task_queue_isdone(task) == 0)
    scamper_task_queue_wait(task, 1000);

 done:
  scamper_route_free(rt);
  if(state->route == rt)
    state->route = NULL;
  return;
}

static void do_sting_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_file_write_sting(sf, sting_getdata(task));
  return;
}

static void sting_state_free(sting_state_t *state)
{
  if(state == NULL)
    return;

  if(state->fw != NULL)     scamper_firewall_entry_free(state->fw);
#ifndef _WIN32
  if(state->rtsock != NULL) scamper_fd_free(state->rtsock);
#endif
  if(state->dl != NULL)     scamper_fd_free(state->dl);
  if(state->dlhdr != NULL)  scamper_dlhdr_free(state->dlhdr);
  if(state->route != NULL)  scamper_route_free(state->route);
  free(state);

  return;
}

static int sting_state_alloc(scamper_task_t *task)
{
  scamper_sting_t *sting = sting_getdata(task);
  sting_state_t *state;
  uint16_t u16;
  size_t size;

  if((state = malloc_zero(sizeof(sting_state_t))) == NULL)
    {
      printerror(__func__, "could not malloc state");
      goto err;
    }
  scamper_task_setstate(task, state);

  size = (sting->seqskip + sting->count) * sizeof(scamper_sting_pkt_t *);
  if((state->probes = malloc_zero(size)) == NULL)
    goto err;

  if(random_u16(&u16) != 0)
    {
      printerror(__func__, "could not get random isn");
      goto err;
    }
  state->isn = u16;

#ifndef _WIN32
  if((state->rtsock = scamper_fd_rtsock()) == NULL)
    {
      goto err;
    }
#endif

  state->mode = MODE_RTSOCK;
  return 0;

 err:
  return -1;
}

static void do_sting_halt(scamper_task_t *task)
{
  scamper_task_queue_done(task, 0);
  return;
}

static void do_sting_free(scamper_task_t *task)
{
  scamper_sting_t *sting;
  sting_state_t *state;

  /* free any state kept */
  if((state = sting_getstate(task)) != NULL)
    {
      sting_state_free(state);
    }

  /* free any sting data collected */
  if((sting = sting_getdata(task)) != NULL)
    {
      scamper_sting_free(sting);
    }

  return;
}

static void do_sting_probe(scamper_task_t *task)
{
  scamper_firewall_rule_t sfw;
  scamper_sting_pkt_t *pkt;
  scamper_sting_t *sting = sting_getdata(task);
  sting_state_t   *state = sting_getstate(task);
  scamper_probe_t  probe;
  uint32_t         wait;
  uint8_t          data[3];

  if(state == NULL)
    {
      gettimeofday_wrap(&sting->start);

      if(sting_state_alloc(task) != 0)
	goto err;

      state = sting_getstate(task);
    }

  if(state->mode == MODE_RTSOCK)
    {
      state->route = scamper_route_alloc(sting->dst, task, sting_handle_rt);
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

      if(state->mode != MODE_SYN)
	{
	  scamper_task_queue_wait(task, 1000);
	  return;
	}
    }

  memset(&probe, 0, sizeof(probe));
  probe.pr_dl        = scamper_fd_dl_get(state->dl);
  probe.pr_dl_buf    = state->dlhdr->buf;
  probe.pr_dl_len    = state->dlhdr->len;
  probe.pr_ip_src    = sting->src;
  probe.pr_ip_dst    = sting->dst;
  probe.pr_ip_ttl    = 255;
  probe.pr_ip_proto  = IPPROTO_TCP;
  probe.pr_tcp_sport = sting->sport;
  probe.pr_tcp_dport = sting->dport;

  if(state->mode == MODE_SYN)
    {
      if(state->attempt == 0)
	{
	  /*
	   * add a firewall rule to block the kernel from interfering with
	   * the measurement
	   */
	  sfw.type = SCAMPER_FIREWALL_RULE_TYPE_5TUPLE;
	  sfw.sfw_5tuple_proto = IPPROTO_TCP;
	  sfw.sfw_5tuple_src   = sting->dst;
	  sfw.sfw_5tuple_dst   = sting->src;
	  sfw.sfw_5tuple_sport = sting->dport;
	  sfw.sfw_5tuple_dport = sting->sport;
	  if((state->fw = scamper_firewall_entry_get(&sfw)) == NULL)
	    {
	      goto err;
	    }
	}

      probe.pr_tcp_seq   = state->isn;
      probe.pr_tcp_ack   = 0;
      probe.pr_tcp_flags = TH_SYN;
      probe.pr_tcp_win   = 0;
      probe.pr_len       = 0;

      /* wait five seconds */
      wait = 5000;
    }
  else if(state->mode == MODE_ACK)
    {
      probe.pr_tcp_seq   = state->isn;
      probe.pr_tcp_ack   = state->ack;
      probe.pr_tcp_flags = TH_ACK;
      probe.pr_tcp_win   = 0;
      probe.pr_len       = 0;

      /* wait for 50 msec until sending the first data probe */
      wait = 50;
      state->mode = MODE_DATA;
    }
  else if(state->mode == MODE_DATA)
    {
      data[0] = sting->data[state->off];

      probe.pr_tcp_seq   = state->isn + state->off;
      probe.pr_tcp_ack   = state->ack;
      probe.pr_tcp_flags = TH_PUSH | TH_ACK;
      probe.pr_tcp_win   = 0;
      probe.pr_len       = 1;
      probe.pr_data      = data;

      state->off++;

      wait = sting->mean;
    }
  else if(state->mode == MODE_HOLE)
    {
      data[0] = sting->data[state->off];

      probe.pr_tcp_seq   = state->isn + state->off;
      probe.pr_tcp_ack   = state->ack;
      probe.pr_tcp_flags = TH_PUSH | TH_ACK;
      probe.pr_tcp_win   = 0;
      probe.pr_data      = data;

      if(state->off == 0)
	{
	  data[1]      = sting->data[1];
	  data[2]      = sting->data[2];
	  probe.pr_len = 3;
	}
      else
	{
	  probe.pr_len = 1;
	}

      /* wait 2 seconds before trying to retransmit */
      wait = 2000;
    }
  else if(state->mode == MODE_RST)
    {
      probe.pr_tcp_seq   = state->isn + state->off;
      probe.pr_tcp_ack   = state->ack;
      probe.pr_tcp_flags = TH_RST;
      probe.pr_tcp_win   = 0;
      probe.pr_len       = 0;

      /* wait a second */
      wait = 1000;
    }
  else
    {
      goto err;
    }

  /* send the probe */
  if(scamper_probe(&probe) == -1)
    {
      errno = probe.pr_errno;
      printerror(__func__, "could not send probe");
      goto err;
    }

  if((pkt = scamper_sting_pkt_alloc(SCAMPER_STING_PKT_FLAG_TX,
				    probe.pr_tx_raw, probe.pr_tx_rawlen,
				    &probe.pr_tx)) == NULL ||
     scamper_sting_pkt_record(sting, pkt) != 0)
    {
      printerror(__func__, "could not record packet");
      goto err;
    }

  if(state->mode == MODE_DATA)
    {
      pkt->flags |= SCAMPER_STING_PKT_FLAG_DATA;
      state->probes[state->probec] = pkt;
      if(state->probec == sting->count)
	{
	  /* wait 2 seconds */
	  wait = sting->inter;
	  state->mode = MODE_INTER;
	}
      state->probec++;
    }

  /* figure out when the next probe may be sent */
  timeval_add_ms(&state->next_tx, &probe.pr_tx, wait);

  /* put in the queue for waiting */
  scamper_task_queue_wait(task, wait);

  state->attempt++;
  return;

 err:
  scamper_debug(__func__, "error mode %d", state != NULL ? state->mode : -1);
  sting_handleerror(task, errno);
  return;
}

static int sting_arg_param_validate(int optid, char *param, long long *out)
{
  long tmp;

  switch(optid)
    {
    case STING_OPT_COUNT:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_STING_COUNT_MIN ||
	 tmp > SCAMPER_DO_STING_COUNT_MAX)
	{
	  goto err;
	}
      break;

    case STING_OPT_SPORT:
    case STING_OPT_DPORT:
      if(string_tolong(param, &tmp) != 0 || tmp < 0 || tmp > 65535)
	goto err;
      break;

    case STING_OPT_DIST:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_STING_DIST_MIN ||
	 tmp > SCAMPER_DO_STING_DIST_MAX)
	goto err;
      break;

    case STING_OPT_REQ:
      return -1;

    case STING_OPT_MEAN:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_STING_MEAN_MIN ||
	 tmp > SCAMPER_DO_STING_MEAN_MAX)
	goto err;
      break;

    case STING_OPT_HOLE:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_STING_SEQSKIP_MIN ||
	 tmp > SCAMPER_DO_STING_SEQSKIP_MAX)
	goto err;
      break;

    case STING_OPT_INTER:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_STING_INTER_MIN ||
	 tmp > SCAMPER_DO_STING_INTER_MAX)
	goto err;
      break;

    case STING_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	goto err;
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

/*
 * scamper_do_sting_alloc
 *
 * given a string representing a sting task, parse the parameters and
 * assemble a sting.  return the sting structure so that it is all ready to
 * go.
 */
void *scamper_do_sting_alloc(char *str)
{
  uint16_t sport    = scamper_sport_default();
  uint16_t dport    = 80;
  uint16_t count    = SCAMPER_DO_STING_COUNT_DEF;
  uint16_t mean     = SCAMPER_DO_STING_MEAN_DEF;
  uint16_t inter    = SCAMPER_DO_STING_INTER_DEF;
  uint8_t  seqskip  = SCAMPER_DO_STING_SEQSKIP_DEF;
  uint8_t  dist     = SCAMPER_DO_STING_DIST_DEF;
  uint8_t  synretx  = SCAMPER_DO_STING_SYNRETX_DEF;
  uint8_t  dataretx = SCAMPER_DO_STING_DATARETX_DEF;
  uint32_t userid   = 0;
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_sting_t *sting = NULL;
  char *addr;
  long long tmp = 0;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      scamper_debug(__func__, "could not parse options");
      goto err;
    }

  /* if there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      scamper_debug(__func__, "no address parameter");
      goto err;
    }

  /* parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 sting_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	case STING_OPT_DPORT:
	  dport = (uint16_t)tmp;
	  break;

	case STING_OPT_SPORT:
	  sport = (uint16_t)tmp;
	  break;

	case STING_OPT_COUNT:
	  count = (uint16_t)tmp;
	  break;

	case STING_OPT_MEAN:
	  mean = (uint16_t)tmp;
	  break;

	case STING_OPT_DIST:
	  dist = (uint8_t)tmp;
	  break;

	case STING_OPT_HOLE:
	  seqskip = (uint8_t)tmp;
	  break;

	case STING_OPT_INTER:
	  inter = (uint16_t)tmp;
	  break;

	case STING_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if((sting = scamper_sting_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc sting");
      goto err;
    }
  if((sting->dst=scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr)) == NULL)
    {
      printerror(__func__, "could not resolve %s", addr);
      goto err;
    }

  sting->sport    = sport;
  sting->dport    = dport;
  sting->count    = count;
  sting->mean     = mean;
  sting->inter    = inter;
  sting->dist     = dist;
  sting->synretx  = synretx;
  sting->dataretx = dataretx;
  sting->seqskip  = seqskip;
  sting->userid   = userid;

  /* take a copy of the data to be used in the measurement */
  if(scamper_sting_data(sting, (const uint8_t *)defaultrequest,
			seqskip + count) != 0)
    {
      goto err;
    }

  return sting;

 err:
  if(sting != NULL) scamper_sting_free(sting);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

/*
 * scamper_do_sting_arg_validate
 *
 *
 */
int scamper_do_sting_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  sting_arg_param_validate);
}

void scamper_do_sting_free(void *data)
{
  scamper_sting_free((scamper_sting_t *)data);
  return;
}

/*
 * scamper_do_sting_alloctask
 *
 */
scamper_task_t *scamper_do_sting_alloctask(void *data,
					   scamper_list_t *list,
					   scamper_cycle_t *cycle)
{
  scamper_sting_t *sting = (scamper_sting_t *)data;
  scamper_task_sig_t *sig = NULL;
  scamper_task_t *task = NULL;

  /* allocate a task structure and store the sting with it */
  if((task = scamper_task_alloc(sting, &sting_funcs)) == NULL)
    goto err;

  /* declare the signature of the sting task */
  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
    goto err;
  sig->sig_tx_ip_dst = scamper_addr_use(sting->dst);
  if(sting->src == NULL && (sting->src = scamper_getsrc(sting->dst,0)) == NULL)
    goto err;
  sig->sig_tx_ip_src = scamper_addr_use(sting->src);
  if(scamper_task_sig_add(task, sig) != 0)
    goto err;
  sig = NULL;

  /* associate the list and cycle with the sting */
  sting->list  = scamper_list_use(list);
  sting->cycle = scamper_cycle_use(cycle);

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

void scamper_do_sting_cleanup(void)
{
  return;
}

int scamper_do_sting_init(void)
{
  sting_funcs.probe          = do_sting_probe;
  sting_funcs.handle_icmp    = NULL;
  sting_funcs.handle_dl      = do_sting_handle_dl;
  sting_funcs.handle_timeout = do_sting_handle_timeout;
  sting_funcs.write          = do_sting_write;
  sting_funcs.task_free      = do_sting_free;
  sting_funcs.halt           = do_sting_halt;

  return 0;
}
