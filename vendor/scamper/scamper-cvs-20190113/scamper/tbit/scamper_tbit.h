/*
 * scamper_tbit.h
 *
 * $Id: scamper_tbit.h,v 1.55 2017/09/27 01:54:17 mjl Exp $
 *
 * Copyright (C) 2009-2010 Ben Stasiewicz
 * Copyright (C) 2010-2011 University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2012,2015 The Regents of the University of California
 *
 * This file implements algorithms described in the tbit-1.0 source code,
 * as well as the papers:
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

#ifndef __SCAMPER_TBIT_H
#define __SCAMPER_TBIT_H

/* types of tbit tests */
#define SCAMPER_TBIT_TYPE_PMTUD              1
#define SCAMPER_TBIT_TYPE_ECN                2
#define SCAMPER_TBIT_TYPE_NULL               3
#define SCAMPER_TBIT_TYPE_SACK_RCVR          4
#define SCAMPER_TBIT_TYPE_ICW                5
#define SCAMPER_TBIT_TYPE_ABC                6
#define SCAMPER_TBIT_TYPE_BLIND_DATA         7
#define SCAMPER_TBIT_TYPE_BLIND_RST          8
#define SCAMPER_TBIT_TYPE_BLIND_SYN          9
#define SCAMPER_TBIT_TYPE_BLIND_FIN          10

/* tbit options */
#define SCAMPER_TBIT_OPTION_TCPTS            0x01 /* tcp timestamps */
#define SCAMPER_TBIT_OPTION_SACK             0x02 /* offer use of TCP SACK */

/* application layer protocols supported by the tbit test */
#define SCAMPER_TBIT_APP_HTTP                1
#define SCAMPER_TBIT_APP_SMTP                2
#define SCAMPER_TBIT_APP_DNS                 3
#define SCAMPER_TBIT_APP_FTP                 4
#define SCAMPER_TBIT_APP_BGP                 5

/* for http, either http or https */
#define SCAMPER_TBIT_APP_HTTP_TYPE_HTTP      0
#define SCAMPER_TBIT_APP_HTTP_TYPE_HTTPS     1

/* generic tbit results */
#define SCAMPER_TBIT_RESULT_NONE             0 /* no result */
#define SCAMPER_TBIT_RESULT_TCP_NOCONN       1 /* no connection */
#define SCAMPER_TBIT_RESULT_TCP_RST          2 /* Early reset */
#define SCAMPER_TBIT_RESULT_TCP_ERROR        3 /* TCP Error */
#define SCAMPER_TBIT_RESULT_ERROR            4 /* System error */
#define SCAMPER_TBIT_RESULT_ABORTED          5 /* Test aborted */
#define SCAMPER_TBIT_RESULT_TCP_NOCONN_RST   6 /* no connection: rst rx */
#define SCAMPER_TBIT_RESULT_HALTED           7 /* halted */
#define SCAMPER_TBIT_RESULT_TCP_BADOPT       8 /* bad TCP option */
#define SCAMPER_TBIT_RESULT_TCP_FIN          9 /* early fin */
#define SCAMPER_TBIT_RESULT_TCP_ZEROWIN      10 /* zero window */

/* possible PMTUD test results */
#define SCAMPER_TBIT_RESULT_PMTUD_NOACK      20 /* no ACK of request */
#define SCAMPER_TBIT_RESULT_PMTUD_NODATA     21 /* no data received */
#define SCAMPER_TBIT_RESULT_PMTUD_TOOSMALL   22 /* packets too small */
#define SCAMPER_TBIT_RESULT_PMTUD_NODF       23 /* DF not set (IPv4 only) */
#define SCAMPER_TBIT_RESULT_PMTUD_FAIL       24 /* did not reduce pkt size */
#define SCAMPER_TBIT_RESULT_PMTUD_SUCCESS    25 /* responded correctly */
#define SCAMPER_TBIT_RESULT_PMTUD_CLEARDF    26 /* cleared DF in response */

/* possible ECN test results */
#define SCAMPER_TBIT_RESULT_ECN_SUCCESS      30 /* responded correctly */
#define SCAMPER_TBIT_RESULT_ECN_INCAPABLE    31 /* no ece on syn/ack */
#define SCAMPER_TBIT_RESULT_ECN_BADSYNACK    32 /* bad syn/ack */
#define SCAMPER_TBIT_RESULT_ECN_NOECE        33 /* no ECN echo */
#define SCAMPER_TBIT_RESULT_ECN_NOACK        34 /* no ack of request */
#define SCAMPER_TBIT_RESULT_ECN_NODATA       35 /* no data received */

/* possible NULL test results */
#define SCAMPER_TBIT_RESULT_NULL_SUCCESS     40 /* responded correctly */
#define SCAMPER_TBIT_RESULT_NULL_NODATA      41 /* no data received */

/* possible SACK-RCVR test results */
#define SCAMPER_TBIT_RESULT_SACK_INCAPABLE      50 /* not capable of SACK */
#define SCAMPER_TBIT_RESULT_SACK_RCVR_SUCCESS   51 /* responded correctly */
#define SCAMPER_TBIT_RESULT_SACK_RCVR_SHIFTED   52 /* shifted sack blocks */
#define SCAMPER_TBIT_RESULT_SACK_RCVR_TIMEOUT   53 /* missing ack */
#define SCAMPER_TBIT_RESULT_SACK_RCVR_NOSACK    54 /* missing sack blocks */

/* possible ICW test results */
#define SCAMPER_TBIT_RESULT_ICW_SUCCESS      60 /* estimate of ICW */
#define SCAMPER_TBIT_RESULT_ICW_TOOSHORT     61 /* not enough data to infer */

/* possible ABC test results */
#define SCAMPER_TBIT_RESULT_ABC_SUCCESS      70 /* ABC test successful */
#define SCAMPER_TBIT_RESULT_ABC_TOOSHORT     71 /* not enough data to infer */
#define SCAMPER_TBIT_RESULT_ABC_BADICW       72 /* apparent bad ICW */

/* possible blind test results */
#define SCAMPER_TBIT_RESULT_BLIND_ACCEPTED   80 /* blind packet accepted */
#define SCAMPER_TBIT_RESULT_BLIND_CHALLENGE  81 /* challenge ack */
#define SCAMPER_TBIT_RESULT_BLIND_IGNORED    82 /* no effect */
#define SCAMPER_TBIT_RESULT_BLIND_RST        83 /* reset for blinded packet */
#define SCAMPER_TBIT_RESULT_BLIND_SYNNEW     84 /* new S/A for blinded syn */

/* direction of recorded packet */
#define SCAMPER_TBIT_PKT_DIR_TX              1
#define SCAMPER_TBIT_PKT_DIR_RX              2

/* pmtud options */
#define SCAMPER_TBIT_PMTUD_OPTION_BLACKHOLE  0x1 /* test blackhole behaviour */

/* null options */
#define SCAMPER_TBIT_NULL_OPTION_TCPTS       0x01 /* tcp timestamps */
#define SCAMPER_TBIT_NULL_OPTION_IPTS_SYN    0x02 /* IP TS option on SYN */
#define SCAMPER_TBIT_NULL_OPTION_IPRR_SYN    0x04 /* IP RR option on SYN */
#define SCAMPER_TBIT_NULL_OPTION_IPQS_SYN    0x08 /* IP QS option on SYN */
#define SCAMPER_TBIT_NULL_OPTION_SACK        0x10 /* offer use of TCP SACK */
#define SCAMPER_TBIT_NULL_OPTION_FO          0x20 /* offer use of TCP FO */
#define SCAMPER_TBIT_NULL_OPTION_FO_EXP      0x40 /* offer use of TCP FO-exp */

/* null results */
#define SCAMPER_TBIT_NULL_RESULT_TCPTS       0x01 /* TCP timestamps OK */
#define SCAMPER_TBIT_NULL_RESULT_SACK        0x02 /* use of TCP SACK OK */
#define SCAMPER_TBIT_NULL_RESULT_FO          0x04 /* use of TCP FO OK */

typedef struct scamper_tbit_pkt
{
  struct timeval       tv;
  uint8_t              dir;
  uint16_t             len;
  uint8_t             *data;
} scamper_tbit_pkt_t;

typedef struct scamper_tbit_app_http
{
  uint8_t              type;
  char                *host;
  char                *file;
} scamper_tbit_app_http_t;

typedef struct scamper_tbit_app_bgp
{
  uint32_t             asn;
} scamper_tbit_app_bgp_t;

typedef struct scamper_tbit_pmtud
{
  uint16_t             mtu;
  uint8_t              ptb_retx;
  uint8_t              options;
  scamper_addr_t      *ptbsrc;
} scamper_tbit_pmtud_t;

typedef struct scamper_tbit_null
{
  uint16_t             options;
  uint16_t             results;
} scamper_tbit_null_t;

typedef struct scamper_tbit_icw
{
  uint32_t             start_seq;
} scamper_tbit_icw_t;

typedef struct scamper_tbit_blind
{
  int32_t              off;
  uint8_t              retx;
} scamper_tbit_blind_t;

/*
 * scamper_tbit
 *
 * parameters and results of a measurement conducted with tbit.
 */
typedef struct scamper_tbit
{
  scamper_list_t      *list;
  scamper_cycle_t     *cycle;
  uint32_t             userid;

  scamper_addr_t      *src;
  scamper_addr_t      *dst;
  uint16_t             sport;
  uint16_t             dport;
  struct timeval       start;

  /* outcome of test */
  uint16_t             result;

  /* type of tbit test and data specific to that test */
  uint8_t              type;
  void                *data;

  /* details of application protocol used */
  uint8_t              app_proto;
  void                *app_data;

  /* client and server mss values advertised */
  uint32_t             options;
  uint16_t             client_mss;
  uint16_t             server_mss;
  uint8_t             *fo_cookie;
  uint8_t              fo_cookielen;
  uint8_t              wscale;
  uint8_t              ttl;

  /* various generic retransmit values */
  uint8_t              syn_retx;
  uint8_t              dat_retx;

  /* packets collected as part of this test */
  scamper_tbit_pkt_t **pkts;
  uint32_t             pktc;
} scamper_tbit_t;

scamper_tbit_t *scamper_tbit_alloc(void);
void scamper_tbit_free(scamper_tbit_t *tbit);

char *scamper_tbit_res2str(const scamper_tbit_t *tbit, char *buf, size_t len);
char *scamper_tbit_type2str(const scamper_tbit_t *tbit, char *buf, size_t len);

scamper_tbit_pkt_t *scamper_tbit_pkt_alloc(uint8_t dir, uint8_t *data,
					   uint16_t len, struct timeval *tv);
void scamper_tbit_pkt_free(scamper_tbit_pkt_t *pkt);
int scamper_tbit_pkt_tcpdatabytes(const scamper_tbit_pkt_t *pkt, uint16_t *bc);
int scamper_tbit_pkt_tcpack(const scamper_tbit_pkt_t *pkt, uint32_t *ack);

scamper_tbit_pmtud_t *scamper_tbit_pmtud_alloc(void);
void scamper_tbit_pmtud_free(scamper_tbit_pmtud_t *pmtud);

scamper_tbit_icw_t *scamper_tbit_icw_alloc(void);
int scamper_tbit_icw_size(const scamper_tbit_t *tbit, uint32_t *size);
void scamper_tbit_icw_free(scamper_tbit_icw_t *icw);

scamper_tbit_null_t *scamper_tbit_null_alloc(void);
void scamper_tbit_null_free(scamper_tbit_null_t *null);

scamper_tbit_blind_t *scamper_tbit_blind_alloc(void);
void scamper_tbit_blind_free(scamper_tbit_blind_t *blind);

scamper_tbit_app_http_t *scamper_tbit_app_http_alloc(uint8_t type,
						     char *host, char *file);
int scamper_tbit_app_http_host(scamper_tbit_app_http_t *http, const char *h);
int scamper_tbit_app_http_file(scamper_tbit_app_http_t *http, const char *f);
void scamper_tbit_app_http_free(scamper_tbit_app_http_t *http);

scamper_tbit_app_bgp_t *scamper_tbit_app_bgp_alloc(void);
void scamper_tbit_app_bgp_free(scamper_tbit_app_bgp_t *bgp);

int scamper_tbit_pkts_alloc(scamper_tbit_t *tbit, uint32_t count);
int scamper_tbit_record_pkt(scamper_tbit_t *tbit, scamper_tbit_pkt_t *pkt);

int scamper_tbit_fo_getcookie(scamper_tbit_t *tbit, uint8_t *c, uint8_t *l);
int scamper_tbit_fo_setcookie(scamper_tbit_t *tbit, uint8_t *c, uint8_t l);

/*
 * scamper_tbit_tcpq functions.
 *
 * these functions are used to maintain in-order processing of TCP packets
 * when the packets are received out of order.  for these routines to work
 * correctly, all TCP packets that are received in range must be processed
 * through the queue so that the queue knows what sequence number is
 * expected.
 *
 * scamper_tbit_tcpq_alloc: allocate a new tcp data queue with an initial
 *  sequence number seeding the queue.
 *
 * scamper_tbit_tcpq_free: free the tcp data queue.  the ff parameter is an
 *  optional free() function that can be called on all queue entry param
 *  fields.
 *
 * scamper_tbit_tcpq_add: add a new segment to the queue.  the seq, flags,
 *  and length must be supplied.  the param field is an optional field that
 *  will be returned with the queue entry when the segment is returned in
 *  order.
 *
 * scamper_tbit_tcpq_seg: return the sequence number and payload length of
 *  the next packet in line to be returned.  the segment remains in the queue.
 *  returns -1 if there is no segment in the queue, zero otherwise.
 *
 * scamper_tbit_tcpq_pop: return the next queue entry that is next in line
 *  to be returned.  the segment is now the responsibility of the caller.
 *
 * scamper_tbit_tcpq_sack: return a set of sack blocks that specify the
 *  state of the tcpq.  the caller must pass a pointer to an array of
 *  (c*2) uint32_t.  the routine returns the number of sack blocks
 *  computed given the constraint of c and the state of the queue.
 *
 * scamper_tbit_tcpq_tail: returns the sequence number at the tail of the
 *  tcp, even if there are gaps in the tcpq.
 *
 * scamper_tbit_tcpqe_free: free the queue entry passed in.  ff is an
 *  optional free() function that will be called on the param if not null.
 *
 */
typedef struct scamper_tbit_tcpq scamper_tbit_tcpq_t;
typedef struct scamper_tbit_tcpqe
{
  uint32_t seq;
  uint16_t len;
  uint8_t  flags;
  uint8_t *data;
} scamper_tbit_tcpqe_t;
scamper_tbit_tcpq_t *scamper_tbit_tcpq_alloc(uint32_t isn);
void scamper_tbit_tcpq_free(scamper_tbit_tcpq_t *q, void (*ff)(void *));
void scamper_tbit_tcpq_flush(scamper_tbit_tcpq_t *q, void (*ff)(void *));
int scamper_tbit_tcpq_add(scamper_tbit_tcpq_t *q, uint32_t seq,
			  uint8_t flags, uint16_t len, uint8_t *data);
int scamper_tbit_tcpq_seg(scamper_tbit_tcpq_t *q,uint32_t *seq,uint16_t *len);
scamper_tbit_tcpqe_t *scamper_tbit_tcpq_pop(scamper_tbit_tcpq_t *q);
int scamper_tbit_tcpq_sack(scamper_tbit_tcpq_t *q, uint32_t *blocks, int c);
uint32_t scamper_tbit_tcpq_tail(const scamper_tbit_tcpq_t *q);
void scamper_tbit_tcpqe_free(scamper_tbit_tcpqe_t *qe, void (*ff)(void *));

/*
 * convenience functions.
 *
 * scamper_tbit_data_inrange: determine if a particular packet and length
 *  are in range or not.
 *
 * scamper_tbit_data_seqoff: determine the difference in sequence number
 *  space between a and b handling wrapping.  this function assumes that
 *  the caller has used scamper_tbit_data_inrange first to determine
 *  the packet is in the current window.
 *
 */
int scamper_tbit_data_inrange(uint32_t rcv_nxt, uint32_t seq, uint16_t len);
int scamper_tbit_data_seqoff(uint32_t rcv_nxt, uint32_t seq);

/*
 * scamper_tbit_stats
 *
 * give some idea about what took place during the tbit measurement.
 */
typedef struct scamper_tbit_stats
{
  struct timeval synack_rtt;
  uint32_t       rx_xfersize;
  uint32_t       rx_totalsize;
  struct timeval xfertime;
} scamper_tbit_stats_t;

int scamper_tbit_stats(const scamper_tbit_t *tbit,scamper_tbit_stats_t *stats);

#endif /* __SCAMPER_TBIT_H */
