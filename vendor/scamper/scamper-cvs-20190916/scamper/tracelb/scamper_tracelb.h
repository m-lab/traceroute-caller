/*
 * scamper_tracelb.h
 *
 * $Id: scamper_tracelb.h,v 1.60 2019/01/13 07:02:07 mjl Exp $
 *
 * Copyright (C) 2008-2009 The University of Waikato
 * Copyright (C) 2018-2019 Matthew Luckie
 * Author: Matthew Luckie
 *
 * Load-balancer traceroute technique authored by
 * Brice Augustin, Timur Friedman, Renata Teixeira; "Measuring Load-balanced
 *  Paths in the Internet", in Proc. Internet Measurement Conference 2007.
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

#ifndef __SCAMPER_TRACELB_H
#define __SCAMPER_TRACELB_H

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"

/* forward declare some important structures */
typedef struct scamper_tracelb_node scamper_tracelb_node_t;
typedef struct scamper_tracelb_link scamper_tracelb_link_t;
typedef struct scamper_tracelb_probe scamper_tracelb_probe_t;
typedef struct scamper_tracelb_reply scamper_tracelb_reply_t;
typedef struct scamper_tracelb_probeset scamper_tracelb_probeset_t;
typedef struct scamper_tracelb_probeset_summary scamper_tracelb_probeset_summary_t;

/*
 * these values give the 'type' member of a scamper_tracelb_t structure
 * some meaning.
 */
#define SCAMPER_TRACELB_TYPE_UDP_DPORT      0x01 /* vary udp-dport */
#define SCAMPER_TRACELB_TYPE_ICMP_ECHO      0x02 /* vary icmp checksum */
#define SCAMPER_TRACELB_TYPE_UDP_SPORT      0x03 /* vary udp-sport */
#define SCAMPER_TRACELB_TYPE_TCP_SPORT      0x04 /* vary tcp-sport */
#define SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT  0x05 /* tcp-ack, vary sport */

/*
 * these values give the 'flags' member of a scamper_tracelb_t structure
 * some meaning.
 */
#define SCAMPER_TRACELB_FLAG_PTR            0x01 /* do ptr lookups */

/*
 * these values give the 'flags' member of a scamper_tracelb_node_t
 * structure some meaning.
 */
#define SCAMPER_TRACELB_NODE_FLAG_QTTL      0x01

#define SCAMPER_TRACELB_NODE_QTTL(node) \
 ((node)->flags & SCAMPER_TRACELB_NODE_FLAG_QTTL)

#define SCAMPER_TRACELB_REPLY_FLAG_REPLY_TTL  0x01 /* reply ttl included */
#define SCAMPER_TRACELB_REPLY_FLAG_TCP        0x02 /* reply is TCP */

#define SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(reply) (			\
 ((reply)->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) == 0 &&	\
 (((reply)->reply_from->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (reply)->reply_icmp_type == 11) ||					\
  ((reply)->reply_from->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (reply)->reply_icmp_type == 3)))

#define SCAMPER_TRACELB_REPLY_IS_ICMP_UNREACH(reply) (			\
 ((reply)->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) == 0 &&	\
 (((reply)->reply_from->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (reply)->reply_icmp_type == 3) ||					\
  ((reply)->reply_from->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (reply)->reply_icmp_type == 1)))

#define SCAMPER_TRACELB_REPLY_IS_ICMP_UNREACH_PORT(reply) (		\
 ((reply)->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) == 0 &&	\
 (((reply)->reply_from->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (reply)->reply_icmp_type == 3 && (reply)->reply_icmp_code == 3) ||	\
  ((reply)->reply_from->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (reply)->reply_icmp_type == 1 && (reply)->reply_icmp_code == 4)))

#define SCAMPER_TRACELB_REPLY_IS_TCP(reply) (				\
 ((reply)->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) != 0)

#define SCAMPER_TRACELB_TYPE_IS_TCP(trace) (				\
 ((trace)->type == SCAMPER_TRACELB_TYPE_TCP_SPORT ||			\
  (trace)->type == SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT))

#define SCAMPER_TRACELB_TYPE_IS_UDP(trace) (				\
 ((trace)->type == SCAMPER_TRACELB_TYPE_UDP_SPORT ||			\
  (trace)->type == SCAMPER_TRACELB_TYPE_UDP_DPORT))

#define SCAMPER_TRACELB_TYPE_IS_ICMP(trace) (				\
 ((trace)->type == SCAMPER_TRACELB_TYPE_ICMP_ECHO))

#define SCAMPER_TRACELB_TYPE_VARY_SPORT(trace) (			\
 ((trace)->type == SCAMPER_TRACELB_TYPE_UDP_SPORT ||			\
  (trace)->type == SCAMPER_TRACELB_TYPE_TCP_SPORT ||			\
  (trace)->type == SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT))

/*
 * scamper_tracelb_reply_t
 *
 * record details of each reply received.
 */
struct scamper_tracelb_reply
{
  scamper_addr_t        *reply_from;       /* source of response */
  struct timeval         reply_rx;         /* receive time */
  uint16_t               reply_ipid;       /* IP ID of reply packet */
  uint8_t                reply_ttl;        /* ttl of the reply packet */
  uint8_t                reply_flags;      /* reply flags */

  union
  {
    struct scamper_tracelb_reply_icmp
    {
      uint8_t            reply_icmp_type;  /* icmp type of the reply */
      uint8_t            reply_icmp_code;  /* icmp code of the reply */
      uint8_t            reply_icmp_q_tos; /* tos byte in quote */
      uint8_t            reply_icmp_q_ttl; /* ttl byte in quote */
      scamper_icmpext_t *reply_icmp_ext;   /* icmp extensions included */
    } icmp;
    struct scamper_tracelb_reply_tcp
    {
      uint8_t            reply_tcp_flags;  /* tcp flags of the reply */
    } tcp;
  } reply_un;
};

#define reply_icmp_type  reply_un.icmp.reply_icmp_type
#define reply_icmp_code  reply_un.icmp.reply_icmp_code
#define reply_icmp_ext   reply_un.icmp.reply_icmp_ext
#define reply_icmp_q_ttl reply_un.icmp.reply_icmp_q_ttl
#define reply_icmp_q_tos reply_un.icmp.reply_icmp_q_tos
#define reply_tcp_flags  reply_un.tcp.reply_tcp_flags

/*
 * scamper_tracelb_probe_t
 *
 * record details of each probe sent, and any replies received.
 */
struct scamper_tracelb_probe
{
  struct timeval                tx;
  uint16_t                      flowid;
  uint8_t                       ttl;
  uint8_t                       attempt;
  scamper_tracelb_reply_t     **rxs;
  uint16_t                      rxc;
};

/*
 * scamper_tracelb_probeset_t
 *
 * record details of each probe sent in a particular set.
 */
struct scamper_tracelb_probeset
{
  scamper_tracelb_probe_t     **probes; /* array of probes sent */
  uint16_t                      probec; /* number of probes sent */
};

struct scamper_tracelb_probeset_summary
{
  scamper_addr_t              **addrs;
  int                           addrc;
  int                           nullc;
};

/*
 * scamper_tracelb_node_t
 *
 * record details of each node encountered
 */
struct scamper_tracelb_node
{
  scamper_addr_t               *addr;  /* address of the node */
  char                         *name;  /* PTR for the addr */
  uint8_t                       flags; /* associated flags */
  uint8_t                       q_ttl; /* quoted ttl */
  scamper_tracelb_link_t      **links; /* links */
  uint16_t                      linkc; /* number of links */
};

/*
 * scamper_tracelb_link_t
 *
 * record probe details of each link encountered
 */
struct scamper_tracelb_link
{
  scamper_tracelb_node_t       *from;  /* link from */
  scamper_tracelb_node_t       *to;    /* link to */
  uint8_t                       hopc;  /* distance between the nodes */
  scamper_tracelb_probeset_t  **sets;  /* array of probesets, for each hop */
};

/*
 * scamper_tracelb_t
 *
 * structure containing the results of probing to enumerate all load balanced
 * paths towards a destination
 */
typedef struct scamper_tracelb
{
  /* the current list, cycle, and defaults */
  scamper_list_t            *list;
  scamper_cycle_t           *cycle;
  uint32_t                   userid;

  /* source and destination addresses of the load balancer trace */
  scamper_addr_t            *src;
  scamper_addr_t            *dst;

  /* when the load balancer trace commenced */
  struct timeval             start;

  /* load balancer traceroute parameters */
  uint16_t                   sport;        /* base source port */
  uint16_t                   dport;        /* base destination port */
  uint16_t                   probe_size;   /* size of probe to send */
  uint8_t                    type;         /* probe type to use */
  uint8_t                    firsthop;     /* where to start probing */
  uint8_t                    wait_timeout; /* seconds to wait before timeout */
  uint8_t                    wait_probe;   /* min. inter-probe time per ttl */
  uint8_t                    attempts;     /* number of attempts per probe */
  uint8_t                    confidence;   /* confidence level to attain */
  uint8_t                    tos;          /* type-of-service byte to use */
  uint8_t                    gaplimit;     /* max consecutive unresp. hops */
  uint8_t                    flags;        /* flags */
  uint32_t                   probec_max;   /* max number of probes to send */

  /*
   * data collected:
   *
   * nodes:
   *  an IP address from each node inferred between the source and the
   *  destination, recorded in the order they were discovered in
   *
   * links:
   *  all links between the source and destination, sorted numerically by
   *  from address and then by to address; each link contains the replies
   *  collected for it
   *
   * probec:
   *  count of probes sent.  includes retries.
   *
   * error:
   *  if non-zero, something went wrong.
   */
  scamper_tracelb_node_t   **nodes;
  uint16_t                   nodec;
  scamper_tracelb_link_t   **links;
  uint16_t                   linkc;
  uint32_t                   probec;
  uint8_t                    error;
} scamper_tracelb_t;

/*
 * basic scamper_tracelb_t routines:
 *
 *  scamper_tracelb_alloc: allocate a scamper_tracelb_t structure
 *  scamper_tracelb_free:  free a scamper_tracelb_t and contents
 *  scamper_tracelb_addr:  return destination address of the scamper_tracelb_t
 *  scamper_tracelb_type_tostr: return a string specifying the trace type
 *  scamper_tracelb_sort:  sort nodes and links in a deterministic manner
 */
scamper_tracelb_t *scamper_tracelb_alloc(void);
void               scamper_tracelb_free(scamper_tracelb_t *);
scamper_addr_t    *scamper_tracelb_addr(const void *);
const char        *scamper_tracelb_type_tostr(const scamper_tracelb_t *trace);
int                scamper_tracelb_sort(scamper_tracelb_t *);

/*
 * basic scamper_tracelb_node_t routines:
 *
 *  scamper_tracelb_node_alloc: allocate a scamper_tracelb_node_t structure
 *  scamper_tracelb_node_free:  free a scamper_tracelb_node_t and contents
 *  scamper_tracelb_node_add:   add a node to a scamper_tracelb_t structure
 *  scamper_tracelb_node_find:  find a node structure by address
 *  scamper_tracelb_node_cmp:   comparison function for comparing nodes
 */
scamper_tracelb_node_t *scamper_tracelb_node_alloc(scamper_addr_t *);
void                    scamper_tracelb_node_free(scamper_tracelb_node_t *);
int                     scamper_tracelb_node_add(scamper_tracelb_t *,
						 scamper_tracelb_node_t *);
scamper_tracelb_node_t *scamper_tracelb_node_find(scamper_tracelb_t *,
						  scamper_tracelb_node_t *);
int scamper_tracelb_node_cmp(const scamper_tracelb_node_t *,
			     const scamper_tracelb_node_t *);
int scamper_tracelb_node_links_alloc(scamper_tracelb_node_t *, uint16_t);
void scamper_tracelb_node_links_sort(scamper_tracelb_node_t *);

/*
 * basic scamper_tracelb_reply_t routines:
 *
 *  scamper_tracelb_reply_alloc: allocate a scamper_tracelb_reply_t structure
 *  scamper_tracelb_reply_free:  free a reply structure
 */
scamper_tracelb_reply_t *scamper_tracelb_reply_alloc(scamper_addr_t *);
void scamper_tracelb_reply_free(scamper_tracelb_reply_t *);

/*
 * basic scamper_tracelb_probe_t routines:
 *
 */
scamper_tracelb_probe_t *scamper_tracelb_probe_alloc(void);
void scamper_tracelb_probe_free(scamper_tracelb_probe_t *);
int scamper_tracelb_probe_reply(scamper_tracelb_probe_t *probe,
				scamper_tracelb_reply_t *reply);
int scamper_tracelb_probe_replies_alloc(scamper_tracelb_probe_t *, uint16_t);

/*
 * basic scamper_tracelb_link_t routines:
 *
 *  scamper_tracelb_link_alloc: allocate a scamper_tracelb_link_t structure
 *  scamper_tracelb_link_free:  free a scamper_tracelb_link_t and contents
 *  scamper_tracelb_link_cmp:   convenient function to compare links with
 *  scamper_tracelb_link_find:  convenient function to find a link in a trace
 *  scamper_tracelb_link_add:   add a link to a scamper_tracelb_t structure
 */
scamper_tracelb_link_t *scamper_tracelb_link_alloc(void);
scamper_tracelb_link_t *scamper_tracelb_link_find(const scamper_tracelb_t *,
						  scamper_tracelb_link_t *);
void scamper_tracelb_link_free(scamper_tracelb_link_t *);
int scamper_tracelb_link_cmp(const scamper_tracelb_link_t *,
			     const scamper_tracelb_link_t *);
int scamper_tracelb_link_add(scamper_tracelb_t *, scamper_tracelb_link_t *);
int scamper_tracelb_link_zerottlfwd(const scamper_tracelb_link_t *);
int scamper_tracelb_link_probeset(scamper_tracelb_link_t *,
				  scamper_tracelb_probeset_t *);
int scamper_tracelb_link_probesets_alloc(scamper_tracelb_link_t *, uint8_t);

/*
 * basic scamper_tracelb_probeset_t routines:
 *
 */
scamper_tracelb_probeset_t *scamper_tracelb_probeset_alloc(void);
void scamper_tracelb_probeset_free(scamper_tracelb_probeset_t *);
int scamper_tracelb_probeset_add(scamper_tracelb_probeset_t *,
				 scamper_tracelb_probe_t *);
int scamper_tracelb_probeset_probes_alloc(scamper_tracelb_probeset_t *,
					  uint16_t);

/*
 * routines to summarise a set of probes beyond a specific node
 *
 */
scamper_tracelb_probeset_summary_t *
  scamper_tracelb_probeset_summary_alloc(scamper_tracelb_probeset_t *);
void
  scamper_tracelb_probeset_summary_free(scamper_tracelb_probeset_summary_t *);

/*
 * these functions allocate arrays of appropriate size, all elements
 * initialised to null.
 */
int scamper_tracelb_nodes_alloc(scamper_tracelb_t *, uint16_t);
int scamper_tracelb_links_alloc(scamper_tracelb_t *, uint16_t);

/*
 * scamper_tracelb_fwdpathc
 *
 * this function determines the number of unique forward paths, counted
 * in IP-links, observed from each node in the trace structure.  this
 * data is useful to then pull out redundant sections in the path.
 * returns zero on success.
 */
int scamper_tracelb_fwdpathc(const scamper_tracelb_t *trace, int *fwdpathc);

/*
 * scamper_tracelb_node_convergencepoint
 *
 * this function determines the index (if any) into the trace at which
 * the path converges to a single node.  the caller should pass the array
 *
 * if the path does not reconverge, -1 is passed back in the to variable.
 * returns zero on success, or -1 if an error occurs.
 */
int scamper_tracelb_node_convergencepoint(const scamper_tracelb_t *trace,
					  const int *fwdpathc,
					  int from, int *to);

/*
 * scamper_tracelb_nodes_extract
 *
 * this function supplies all nodes between two points in the graph in the
 * nodes parameter.  the caller therefore should pass a nodes array with
 * enough space to store trace->nodec items.
 * this function returns the number of nodes extracted, or -1 in an
 * error.
 */
int scamper_tracelb_nodes_extract(const scamper_tracelb_t *trace,
				  scamper_tracelb_node_t *from,
				  scamper_tracelb_node_t *to,
				  scamper_tracelb_node_t **nodes);

#endif /* __SCAMPER_TRACELB_H */
