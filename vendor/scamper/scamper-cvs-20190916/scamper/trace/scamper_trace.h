/*
 * scamper_trace.h
 *
 * $Id: scamper_trace.h,v 1.138 2019/06/23 05:41:21 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2008      Alistair King
 * Copyright (C) 2015      The Regents of the University of California
 * Copyright (C) 2015      The University of Waikato
 * Copyright (C) 2019      Matthew Luckie
 * Authors: Matthew Luckie
 *          Doubletree implementation by Alistair King
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

#ifndef __SCAMPER_TRACE_H
#define __SCAMPER_TRACE_H

/* forward declare some important structures */
struct scamper_icmpext;
struct scamper_list;
struct scamper_cycle;
struct scamper_addr;

#define SCAMPER_TRACE_STOP_NONE      0x00 /* null reason */
#define SCAMPER_TRACE_STOP_COMPLETED 0x01 /* got an ICMP port unreach */
#define SCAMPER_TRACE_STOP_UNREACH   0x02 /* got an other ICMP unreach code */
#define SCAMPER_TRACE_STOP_ICMP      0x03 /* got an ICMP msg, not unreach */
#define SCAMPER_TRACE_STOP_LOOP      0x04 /* loop detected */
#define SCAMPER_TRACE_STOP_GAPLIMIT  0x05 /* gaplimit reached */
#define SCAMPER_TRACE_STOP_ERROR     0x06 /* sendto error */
#define SCAMPER_TRACE_STOP_HOPLIMIT  0x07 /* hoplimit reached */
#define SCAMPER_TRACE_STOP_GSS       0x08 /* found hop in global stop set */
#define SCAMPER_TRACE_STOP_HALTED    0x09 /* halted */

#define SCAMPER_TRACE_FLAG_ALLATTEMPTS  0x01 /* send all allotted attempts */
#define SCAMPER_TRACE_FLAG_PMTUD        0x02 /* conduct PMTU discovery */
#define SCAMPER_TRACE_FLAG_DL           0x04 /* datalink for TX timestamps */
#define SCAMPER_TRACE_FLAG_IGNORETTLDST 0x08 /* ignore ttl exp. rx f/ dst */
#define SCAMPER_TRACE_FLAG_DOUBLETREE   0x10 /* doubletree */
#define SCAMPER_TRACE_FLAG_ICMPCSUMDP   0x20 /* icmp csum found in dport */
#define SCAMPER_TRACE_FLAG_CONSTPAYLOAD 0x40 /* do not hack payload for csum */

#define SCAMPER_TRACE_TYPE_ICMP_ECHO       0x01 /* ICMP echo requests */
#define SCAMPER_TRACE_TYPE_UDP             0x02 /* UDP to unused ports */
#define SCAMPER_TRACE_TYPE_TCP             0x03 /* TCP SYN packets */
#define SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS 0x04 /* paris traceroute */
#define SCAMPER_TRACE_TYPE_UDP_PARIS       0x05 /* paris traceroute */
#define SCAMPER_TRACE_TYPE_TCP_ACK         0x06 /* TCP ACK packets */

#define SCAMPER_TRACE_GAPACTION_STOP      0x01 /* stop when gaplimit reached */
#define SCAMPER_TRACE_GAPACTION_LASTDITCH 0x02 /* send TTL-255 probes */

#define SCAMPER_TRACE_HOP_IS_TCP(hop) (                         \
 (hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) != 0)

#define SCAMPER_TRACE_HOP_IS_UDP(hop) (				\
 (hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_UDP) != 0)

#define SCAMPER_TRACE_HOP_IS_ICMP(hop) (                        \
 (hop->hop_flags & (SCAMPER_TRACE_HOP_FLAG_TCP|			\
		    SCAMPER_TRACE_HOP_FLAG_UDP)) == 0)

#define SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(hop) (		\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 11) ||				\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 3)))

#define SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP_TRANS(hop) (		\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 11 && (hop)->hop_icmp_code == 0) ||	\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 3 && (hop)->hop_icmp_code == 0)))

#define SCAMPER_TRACE_HOP_IS_ICMP_PTB(hop) (			\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 3 && (hop)->hop_icmp_code == 4) ||	\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 2)))

#define SCAMPER_TRACE_HOP_IS_ICMP_PTB_BADSUGG(hop) (		\
 SCAMPER_TRACE_HOP_IS_ICMP_PTB((hop)) &&			\
 (hop)->hop_probe_size <= (hop)->hop_icmp_nhmtu)

#define SCAMPER_TRACE_HOP_IS_ICMP_UNREACH(hop) (		\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 3) ||				\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 1)))

#define SCAMPER_TRACE_HOP_IS_ICMP_UNREACH_PORT(hop) (		\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 3 && (hop)->hop_icmp_code == 3) ||	\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 1 && (hop)->hop_icmp_code == 4)))

#define SCAMPER_TRACE_HOP_IS_ICMP_ECHO_REPLY(hop) (		\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 0) ||				\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 129)))

#define SCAMPER_TRACE_HOP_IS_ICMP_Q(hop) (			\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   ((hop)->hop_icmp_type == 3 || (hop)->hop_icmp_type == 11)) ||\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   ((hop)->hop_icmp_type >= 1 && (hop)->hop_icmp_type <= 3))))

#define SCAMPER_TRACE_TYPE_IS_ICMP(trace) (			\
 (trace)->type == SCAMPER_TRACE_TYPE_ICMP_ECHO ||		\
 (trace)->type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS)

#define SCAMPER_TRACE_TYPE_IS_UDP(trace) (			\
 (trace)->type == SCAMPER_TRACE_TYPE_UDP ||			\
 (trace)->type == SCAMPER_TRACE_TYPE_UDP_PARIS)

#define SCAMPER_TRACE_TYPE_IS_TCP(trace) (			\
 (trace)->type == SCAMPER_TRACE_TYPE_TCP ||			\
 (trace)->type == SCAMPER_TRACE_TYPE_TCP_ACK)

#define SCAMPER_TRACE_TYPE_IS_UDP_PARIS(trace) (		\
 (trace)->type == SCAMPER_TRACE_TYPE_UDP_PARIS)

/*
 * macros for dealing with scamper trace flags.
 */
#define SCAMPER_TRACE_IS_ICMPCSUMDP(trace) (			\
 (trace)->flags & SCAMPER_TRACE_FLAG_ICMPCSUMDP)

#define SCAMPER_TRACE_IS_PMTUD(trace) (				\
 (trace)->flags & SCAMPER_TRACE_FLAG_PMTUD)

#define SCAMPER_TRACE_IS_DOUBLETREE(trace) (			\
 (trace)->flags & SCAMPER_TRACE_FLAG_DOUBLETREE)

#define SCAMPER_TRACE_IS_DL(trace) (				\
 (trace)->flags & SCAMPER_TRACE_FLAG_DL)

#define SCAMPER_TRACE_IS_IGNORETTLDST(trace) (			\
 (trace)->flags & SCAMPER_TRACE_FLAG_IGNORETTLDST)

#define SCAMPER_TRACE_IS_ALLATTEMPTS(trace) (			\
 (trace)->flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS)

#define SCAMPER_TRACE_IS_CONSTPAYLOAD(trace)(			\
 (trace)->flags & SCAMPER_TRACE_FLAG_CONSTPAYLOAD)

/*
 * scamper hop flags:
 * these flags give extra meaning to fields found in the hop structure
 * by default.
 */
#define SCAMPER_TRACE_HOP_FLAG_TS_SOCK_RX 0x01 /* socket rx timestamp */
#define SCAMPER_TRACE_HOP_FLAG_TS_DL_TX   0x02 /* datalink tx timestamp */
#define SCAMPER_TRACE_HOP_FLAG_TS_DL_RX   0x04 /* datalink rx timestamp */
#define SCAMPER_TRACE_HOP_FLAG_TS_TSC     0x08 /* rtt computed w/ tsc clock */
#define SCAMPER_TRACE_HOP_FLAG_REPLY_TTL  0x10 /* reply ttl included */
#define SCAMPER_TRACE_HOP_FLAG_TCP        0x20 /* reply is TCP */
#define SCAMPER_TRACE_HOP_FLAG_UDP        0x40 /* reply is UDP */

/*
 * this macro is a more convenient way to check that the hop record
 * has both the tx and rx timestamps from the datalink for computing the
 * RTT
 */
#define SCAMPER_TRACE_HOP_FLAG_DL_RTT(hop)			\
 ((hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_TX) &&		\
  (hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_RX))

/*
 * scamper_trace_hop:
 *
 * hold data on each response received as part of a traceroute.
 */
typedef struct scamper_trace_hop
{
  /* the address of the hop that responded */
  scamper_addr_t              *hop_addr;

  /* flags defined by SCAMPER_TRACE_HOP_FLAG_* */
  uint8_t                      hop_flags;

  /*
   * probe_id:   the attempt # this probe is in response to [count from 0]
   * probe_ttl:  the ttl that we sent to the trace->dst
   * probe_size: the size of the probe we sent
   * reply_ttl:  the ttl of the reply packet
   * reply_tos:  the TOS of the reply packet
   * reply_size: the size of the icmp response we received
   * reply_ipid: the IPID value in the response
   */
  uint8_t                      hop_probe_id;
  uint8_t                      hop_probe_ttl;
  uint16_t                     hop_probe_size;
  uint8_t                      hop_reply_ttl;
  uint8_t                      hop_reply_tos;
  uint16_t                     hop_reply_size;
  uint16_t                     hop_reply_ipid;

  /* icmp type / code returned by this hop */
  union
  {
    struct hop_icmp
    {
      uint8_t                  hop_icmp_type;
      uint8_t                  hop_icmp_code;
      uint8_t                  hop_icmp_q_ttl;
      uint8_t                  hop_icmp_q_tos;
      uint16_t                 hop_icmp_q_ipl;
      uint16_t                 hop_icmp_nhmtu;
    } icmp;
    struct hop_tcp
    {
      uint8_t                  hop_tcp_flags;
    } tcp;
  } hop_un;

  /* time elapsed between sending the probe and receiving this resp */
  struct timeval               hop_tx;
  struct timeval               hop_rtt;

  /* ICMP extensions */
  struct scamper_icmpext      *hop_icmpext;

  struct scamper_trace_hop    *hop_next;
} scamper_trace_hop_t;

#define hop_icmp_type  hop_un.icmp.hop_icmp_type
#define hop_icmp_code  hop_un.icmp.hop_icmp_code
#define hop_icmp_q_ttl hop_un.icmp.hop_icmp_q_ttl
#define hop_icmp_q_ipl hop_un.icmp.hop_icmp_q_ipl
#define hop_icmp_q_tos hop_un.icmp.hop_icmp_q_tos
#define hop_icmp_nhmtu hop_un.icmp.hop_icmp_nhmtu
#define hop_tcp_flags  hop_un.tcp.hop_tcp_flags

/*
 * scamper_trace_pmtud_n_t
 *
 * notes about PMTUD process; the record says the behaviour that was deduced,
 * what the next-hop MTU is, and which hop it corresponds to.  The hop
 * record is one of those listed in the parent scamper_trace_pmtud_t
 * structure.
 */
typedef struct scamper_trace_pmtud_n
{
  uint8_t              type;
  uint16_t             nhmtu;
  scamper_trace_hop_t *hop;
} scamper_trace_pmtud_n_t;

#define SCAMPER_TRACE_PMTUD_N_TYPE_PTB      1
#define SCAMPER_TRACE_PMTUD_N_TYPE_PTB_BAD  2
#define SCAMPER_TRACE_PMTUD_N_TYPE_SILENCE  3

/*
 * scamper_trace_pmtud_t
 *
 * container for data collected.
 *
 * version 1 has ifmtu, outmtu, pmtu, and a list of hops from which it must
 * be deduced what the behaviours observed are.
 * version 2 has ifmtu, outmtu, pmtu, all responses received during pmtud
 * process, and a set of annotations about what was inferred.
 */
typedef struct scamper_trace_pmtud
{
  uint8_t                   ver;    /* version of data-storing method */
  uint16_t                  ifmtu;  /* the outgoing interface's MTU */
  uint16_t                  outmtu; /* MTU to first hop, if diff from ifmtu */
  uint16_t                  pmtu;   /* packet size that reached target */
  scamper_trace_hop_t      *hops;   /* icmp messages */
  scamper_trace_pmtud_n_t **notes;  /* annotations about pmtud */
  uint8_t                   notec;  /* number of annotations */
} scamper_trace_pmtud_t;

typedef struct scamper_trace_dtree
{
  char            *lss;
  uint8_t          firsthop;
  uint8_t          flags;
  uint16_t         gssc;
  scamper_addr_t **gss;
  scamper_addr_t  *gss_stop;
  scamper_addr_t  *lss_stop;
} scamper_trace_dtree_t;

#define SCAMPER_TRACE_DTREE_FLAG_NOBACK 0x01

/*
 * scamper_trace:
 * a trace structure contains enough state for scamper to probe a series
 * of traces concurrently.
 */
typedef struct scamper_trace
{
  /* the current list, cycle, and defaults */
  struct scamper_list   *list;
  struct scamper_cycle  *cycle;
  uint32_t               userid;

  /* source and destination addresses of the trace */
  struct scamper_addr   *src;
  struct scamper_addr   *dst;
  struct scamper_addr   *rtr;

  /* when the trace commenced */
  struct timeval         start;

  /* hops array, number of valid hops specified by hop_count */
  scamper_trace_hop_t  **hops;
  uint16_t               hop_count;

  /* number of probes sent for this traceroute */
  uint16_t               probec;

  /* why the trace finished */
  uint8_t                stop_reason;
  uint8_t                stop_data;

  /* trace parameters */
  uint8_t                type;
  uint8_t                flags;
  uint8_t                attempts;
  uint8_t                hoplimit;
  uint8_t                gaplimit;
  uint8_t                gapaction;
  uint8_t                firsthop;
  uint8_t                tos;
  uint8_t                wait;
  uint8_t                wait_probe;
  uint8_t                loops;
  uint8_t                loopaction;
  uint8_t                confidence;
  uint16_t               probe_size;
  uint16_t               sport;
  uint16_t               dport;
  uint16_t               offset;

  /* payload */
  uint8_t               *payload;
  uint16_t               payload_len;

  /* if we perform PMTU discovery on the trace, then record the data here */
  scamper_trace_pmtud_t *pmtud;

  /* if we perform last ditch probing, then record any responses here */
  scamper_trace_hop_t   *lastditch;

  /* if we perform doubletree, record doubletree parameters and data here */
  scamper_trace_dtree_t *dtree;

} scamper_trace_t;

/*
 * scamper_trace_alloc:
 *  allocate a brand new scamper trace object, empty of any data
 *
 * scamper_trace_hops_alloc:
 *  allocate an array of hop records to the trace object
 *
 * scamper_trace_free:
 *  free the memory used by this trace object.
 *  this function assumes that any memory that would be dynamically
 *  allocated can be freed with free()
 *
 * scamper_trace_probe_headerlen:
 *  return the size of headers sent with each probe for the trace
 *
 * scamper_trace_addr:
 *  return the address of the trace -- caller doesn't know that it is a trace.
 */
scamper_trace_t *scamper_trace_alloc(void);
int scamper_trace_hops_alloc(scamper_trace_t *trace, const int hops);
void scamper_trace_free(scamper_trace_t *trace);
uint16_t scamper_trace_pathlength(const scamper_trace_t *trace);
int scamper_trace_probe_headerlen(const scamper_trace_t *trace);
scamper_addr_t *scamper_trace_addr(const void *va);
int scamper_trace_iscomplete(const scamper_trace_t *trace);
int scamper_trace_dst_cmp(const scamper_trace_t *a, const scamper_trace_t *b);

const char *scamper_trace_type_tostr(const scamper_trace_t *t, char *b, size_t l);
const char *scamper_trace_stop_tostr(const scamper_trace_t *t, char *b, size_t l);

/*
 * scamper_trace_loop:
 *
 * find the nth instance of a loop in the trace.  if 'a' or 'b' are non-null,
 * on exit they hold the start and end of the loop.  if '*b' is non-null on
 * entry, it specifies the hop at which to commence looking for the next
 * instance of a loop.
 */
int scamper_trace_loop(const scamper_trace_t *trace, const int n,
		       const scamper_trace_hop_t **a,
		       const scamper_trace_hop_t **b);

/*
 * scamper_trace_hop_alloc:
 *  allocate a blank hop record
 *
 * scamper_trace_hop_free:
 *  free the memory used by a hop structure
 *
 * scamper_trace_hop_count:
 *  return the total number of hops attached to the trace structure
 */
scamper_trace_hop_t *scamper_trace_hop_alloc(void);
void scamper_trace_hop_free(scamper_trace_hop_t *hop);
int scamper_trace_hop_count(const scamper_trace_t *trace);

int scamper_trace_hop_addr_cmp(const scamper_trace_hop_t *a,
			       const scamper_trace_hop_t *b);

/*
 * scamper_trace_pmtud_alloc:
 *  allocate a blank pmtud record for the trace structure
 *
 * scamper_trace_pmtud_free:
 *  free the attached pmtud record from the trace structure
 *
 * scamper_trace_pmtud_hop_count:
 *  return the total number of hops attached to the pmtud structure
 */
int scamper_trace_pmtud_alloc(scamper_trace_t *trace);
void scamper_trace_pmtud_free(scamper_trace_t *trace);
int scamper_trace_pmtud_hop_count(const scamper_trace_t *trace);
scamper_trace_pmtud_n_t *scamper_trace_pmtud_n_alloc(void);
void scamper_trace_pmtud_n_free(scamper_trace_pmtud_n_t *n);
int scamper_trace_pmtud_n_alloc_c(scamper_trace_pmtud_t *pmtud, uint8_t c);
int scamper_trace_pmtud_n_add(scamper_trace_pmtud_t *pmtud,
			      scamper_trace_pmtud_n_t *n);

int scamper_trace_lastditch_hop_count(const scamper_trace_t *trace);

/*
 * functions for helping with doubletree
 */
int scamper_trace_dtree_alloc(scamper_trace_t *trace);
void scamper_trace_dtree_free(scamper_trace_t *trace);
int scamper_trace_dtree_lss(scamper_trace_t *trace, const char *lss);

int scamper_trace_dtree_gss_alloc(scamper_trace_t *trace, uint16_t cnt);
void scamper_trace_dtree_gss_sort(const scamper_trace_t *trace);
scamper_addr_t *scamper_trace_dtree_gss_find(const scamper_trace_t *trace,
                                             const scamper_addr_t *iface);

#endif /* __SCAMPER_TRACE_H */
