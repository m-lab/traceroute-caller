/*
 * scamper_do_tracelb.c
 *
 * $Id: scamper_tracelb_do.c,v 1.279 2019/07/12 23:37:58 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
 * Copyright (C) 2016,2019 Matthew Luckie
 * Author: Matthew Luckie
 *
 * MDA traceroute technique authored by
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

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_tracelb_do.c,v 1.279 2019/07/12 23:37:58 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_tracelb.h"
#include "scamper_task.h"
#include "scamper_icmp_resp.h"
#include "scamper_dl.h"
#include "scamper_fds.h"
#include "scamper_dlhdr.h"
#include "scamper_rtsock.h"
#include "scamper_probe.h"
#include "scamper_getsrc.h"
#include "scamper_udp4.h"
#include "scamper_udp6.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_options.h"
#include "scamper_debug.h"
#include "host/scamper_host_do.h"
#include "scamper_tracelb_do.h"
#include "utils.h"
#include "mjl_list.h"
#include "mjl_heap.h"
#include "mjl_splaytree.h"

#define SCAMPER_DO_TRACELB_ATTEMPTS_MIN    1
#define SCAMPER_DO_TRACELB_ATTEMPTS_DEF    2
#define SCAMPER_DO_TRACELB_ATTEMPTS_MAX    5

#define SCAMPER_DO_TRACELB_PORT_MIN        1
#define SCAMPER_DO_TRACELB_PORT_MAX        65535

#define SCAMPER_DO_TRACELB_DPORT_DEF       (32768+666+1)

#define SCAMPER_DO_TRACELB_FIRSTHOP_MIN    1
#define SCAMPER_DO_TRACELB_FIRSTHOP_DEF    1
#define SCAMPER_DO_TRACELB_FIRSTHOP_MAX    254

#define SCAMPER_DO_TRACELB_GAPLIMIT_MIN    1
#define SCAMPER_DO_TRACELB_GAPLIMIT_DEF    3
#define SCAMPER_DO_TRACELB_GAPLIMIT_MAX    5

#define SCAMPER_DO_TRACELB_PROBECMAX_MIN   50
#define SCAMPER_DO_TRACELB_PROBECMAX_DEF   3000
#define SCAMPER_DO_TRACELB_PROBECMAX_MAX   65535

#define SCAMPER_DO_TRACELB_TOS_MIN         0
#define SCAMPER_DO_TRACELB_TOS_DEF         0
#define SCAMPER_DO_TRACELB_TOS_MAX         255

#define SCAMPER_DO_TRACELB_WAITPROBE_MIN   15
#define SCAMPER_DO_TRACELB_WAITPROBE_DEF   25
#define SCAMPER_DO_TRACELB_WAITPROBE_MAX   200

#define SCAMPER_DO_TRACELB_WAITTIMEOUT_MIN 1
#define SCAMPER_DO_TRACELB_WAITTIMEOUT_DEF 5
#define SCAMPER_DO_TRACELB_WAITTIMEOUT_MAX 10

static const uint8_t MODE_RTSOCK     = 0; /* need to determine outgoing if */
static const uint8_t MODE_DLHDR      = 1; /* need to determine datalink hdr */
static const uint8_t MODE_FIRSTADDR  = 2; /* probing for the first address */
static const uint8_t MODE_FIRSTHOP   = 3; /* probing for the first hop */
static const uint8_t MODE_HOPPROBE   = 4; /* probing a hop for lb paths */
static const uint8_t MODE_PERPACKET  = 5; /* determine if router lb per pkt */
static const uint8_t MODE_BRINGFWD   = 6; /* need more flowids for hop-probe */
static const uint8_t MODE_BRINGFWD0  = 7; /* when first addr branches */
static const uint8_t MODE_CLUMP      = 8; /* clump of nodes */

/* forward declare some structs that are used to keep state */
typedef struct tracelb_link  tracelb_link_t;
typedef struct tracelb_path  tracelb_path_t;
typedef struct tracelb_probe tracelb_probe_t;

/*
 * tracelb_link
 *
 * keep track of links discovered, the probes that discovered them, and
 * where in the path they are.
 */
struct tracelb_link
{
  scamper_tracelb_link_t  *link;
  slist_t                 *flowids;
  struct tracelb_path     *path;
};

/*
 * tracelb_path
 *
 * keep track of unique paths to probe and the probes which find them.
 *
 */
struct tracelb_path
{
  /*
   * these fields maintain a graph structure
   *
   * the 'back' fields keep track of the paths that lead up to this path.
   * the 'fwd' fields keep track of the paths that follow on from this path.
   * the 'link' fields keep track of the links discovered in this path segment.
   */
  tracelb_path_t         **back;
  int                      backc;
  tracelb_link_t         **links;
  int                      linkc;
  tracelb_path_t         **fwd;
  int                      fwdc;

  /*
   * these fields maintain other useful items of state
   *
   * the 'visited' field says whether or not the path has been visited in DFS
   * the 'distance' field records the maximum distance from the root
   */
  int                      visited;
  int                      distance;
};

/*
 * tracelb_bringfwd
 *
 * this structure keeps track at the number of times a particular subpath has
 * been probed when attempting to bring a particular flowid forward through a
 * path so it can be used to probe a latter portion of the path.
 *
 * when k reaches the corresponding value in the confidence table, the attempt
 * to bring a flowid forward for the path ceases.
 */
typedef struct tracelb_bringfwd
{
  tracelb_path_t          *path;
  int                      k;
} tracelb_bringfwd_t;

/*
 * tracelb_flowid
 *
 * keep track of the flowid values known to be useful in probing a path.
 */
typedef struct tracelb_flowid
{
  uint16_t                 id;
  uint8_t                  ttl;
} tracelb_flowid_t;


typedef struct tracelb_newnode
{
  scamper_tracelb_node_t  *node;
  scamper_tracelb_probe_t *probe;
} tracelb_newnode_t;

/*
 * tracelb_branch
 *
 * state to keep while probing a branch in the path.
 */
typedef struct tracelb_branch
{
  tracelb_path_t          *path;         /* path being probed forward */
  struct timeval           last_tx;      /* time last probe sent */
  struct timeval           next_tx;      /* when to next probe */
  uint8_t                  mode;         /* mode this branch is in */
  int                      k;            /* # of probes replied to */
  int                      l;            /* # of lost probes */
  int                      n;            /* # of loadbal paths to rule out */
  tracelb_bringfwd_t     **bringfwd;     /* paths leading to this path */
  int                      bringfwdc;    /* # of paths in subset */
  int                      bringfwd0;    /* number of probes in this state */
  heap_node_t             *heapnode;     /* corresponding node in heap */
  tracelb_newnode_t      **newnodes;
  int                      newnodec;
  tracelb_probe_t        **probes;
  int                      probec;
} tracelb_branch_t;

/*
 * tracelb_probe
 *
 * keep track of probes and the paths they probe.  the tracelb_state structure
 * holds an array of these probe structures indexed by probe id.
 */
struct tracelb_probe
{
  tracelb_link_t          *link;     /* the link found one ttl earlier */
  tracelb_branch_t        *branch;   /* which branch is being probed */
  scamper_tracelb_probe_t *probe;    /* probe record to be held as data */
  uint16_t                 id;       /* id of the probe */
  uint8_t                  mode;     /* mode the probe was sent in */
};

typedef struct tracelb_host
{
  scamper_task_t          *task;
  scamper_host_do_t       *hostdo;
  scamper_tracelb_node_t  *node;
  dlist_node_t            *dn;
} tracelb_host_t;

/*
 * tracelb_state
 *
 * this keeps state for the load-balancer traceroute process.
 */
typedef struct tracelb_state
{
  uint8_t                  confidence;   /* index into k[] */
  scamper_fd_t            *icmp;         /* fd to listen to icmp packets */
  scamper_fd_t            *probe;        /* fd to probe with */
  scamper_fd_t            *dl;           /* datalink fd to tx on */
  splaytree_t             *addrs;        /* set of addresses */

#ifndef _WIN32
  scamper_fd_t            *rtsock;       /* route socket */
#endif

  scamper_route_t         *route;
  scamper_dlhdr_t         *dlhdr;        /* datalink header to prepend on tx */
  struct timeval           next_tx;      /* time to send the next probe */
  uint16_t                 payload_size; /* size of the probe packet payload */
  tracelb_probe_t        **probes;       /* probes sent so far */
  uint16_t                 id_next;      /* next id to use in a probe */
  uint16_t                 flowid_next;  /* next flow-id to use in a probe */
  heap_t                  *active;       /* heap of active branches */
  heap_t                  *waiting;      /* heap of queued branches */
  tracelb_link_t         **links;        /* links established */
  int                      linkc;        /* count of links */
  tracelb_path_t         **paths;        /* paths established */
  int                      pathc;        /* count of paths */
  dlist_t                 *ths;          /* tracelb_host_t */
} tracelb_state_t;

/* temporary buffer shared amongst traceroutes */
static uint8_t             *pktbuf     = NULL;
static size_t               pktbuf_len = 0;

/* the callback functions registered with the tracelb task */
static scamper_task_funcs_t funcs;

#define TRACE_OPT_CONFIDENCE   1
#define TRACE_OPT_DPORT        2
#define TRACE_OPT_FIRSTHOP     3
#define TRACE_OPT_GAPLIMIT     4
#define TRACE_OPT_OPTION       5
#define TRACE_OPT_PROTOCOL     6
#define TRACE_OPT_ATTEMPTS     7
#define TRACE_OPT_PROBECMAX    8
#define TRACE_OPT_SPORT        9
#define TRACE_OPT_TOS          10
#define TRACE_OPT_USERID       11
#define TRACE_OPT_WAITTIMEOUT  12
#define TRACE_OPT_WAITPROBE    13

static const scamper_option_in_t opts[] = {
  {'c', NULL, TRACE_OPT_CONFIDENCE,  SCAMPER_OPTION_TYPE_NUM},
  {'d', NULL, TRACE_OPT_DPORT,       SCAMPER_OPTION_TYPE_NUM},
  {'f', NULL, TRACE_OPT_FIRSTHOP,    SCAMPER_OPTION_TYPE_NUM},
  {'g', NULL, TRACE_OPT_GAPLIMIT,    SCAMPER_OPTION_TYPE_NUM},
  {'O', NULL, TRACE_OPT_OPTION,      SCAMPER_OPTION_TYPE_STR},
  {'P', NULL, TRACE_OPT_PROTOCOL,    SCAMPER_OPTION_TYPE_STR},
  {'q', NULL, TRACE_OPT_ATTEMPTS,    SCAMPER_OPTION_TYPE_NUM},
  {'Q', NULL, TRACE_OPT_PROBECMAX,   SCAMPER_OPTION_TYPE_NUM},
  {'s', NULL, TRACE_OPT_SPORT,       SCAMPER_OPTION_TYPE_NUM},
  {'t', NULL, TRACE_OPT_TOS,         SCAMPER_OPTION_TYPE_NUM},
  {'U', NULL, TRACE_OPT_USERID,      SCAMPER_OPTION_TYPE_NUM},
  {'w', NULL, TRACE_OPT_WAITTIMEOUT, SCAMPER_OPTION_TYPE_NUM},
  {'W', NULL, TRACE_OPT_WAITPROBE,   SCAMPER_OPTION_TYPE_NUM},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_tracelb_usage(void)
{
  return "tracelb [-c confidence] [-d dport] [-f firsthop] [-g gaplimit]\n"
         "        [-O option] [-P method] [-q attempts] [-Q maxprobec]\n"
         "        [-s sport] [-t tos] [-U userid] [-w wait-timeout]\n"
         "        [-W wait-probe]";
}

static tracelb_state_t *tracelb_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static scamper_tracelb_t *tracelb_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static int k(tracelb_state_t *state, int n)
{
  /*
   * number of probes (k) to send to rule out a load-balancer having n hops;
   * 95% confidence level first from 823-augustin-e2emon.pdf, then extended
   * with gmp-based code.
   * 99% confidence derived with gmp-based code.
   */
  static const int k[][2] = {
    {   0,   0 }, {   0,   0 }, {   6,   8 }, {  11,  15 }, {  16,  21 },
    {  21,  28 }, {  27,  36 }, {  33,  43 }, {  38,  51 }, {  44,  58 },
    {  51,  66 }, {  57,  74 }, {  63,  82 }, {  70,  90 }, {  76,  98 },
    {  83, 106 }, {  90, 115 }, {  96, 123 }, { 103, 132 }, { 110, 140 },
    { 117, 149 }, { 124, 157 }, { 131, 166 }, { 138, 175 }, { 145, 183 },
    { 152, 192 }, { 159, 201 }, { 167, 210 }, { 174, 219 }, { 181, 228 },
    { 189, 237 }, { 196, 246 }, { 203, 255 }, { 211, 264 }, { 218, 273 },
    { 226, 282 }, { 233, 291 }, { 241, 300 }, { 248, 309 }, { 256, 319 },
    { 264, 328 }, { 271, 337 }, { 279, 347 }, { 287, 356 }, { 294, 365 },
    { 302, 375 }, { 310, 384 }, { 318, 393 }, { 326, 403 }, { 333, 412 },
    { 341, 422 }, { 349, 431 }, { 357, 441 }, { 365, 450 }, { 373, 460 },
    { 381, 470 }, { 389, 479 }, { 397, 489 }, { 405, 499 }, { 413, 508 },
    { 421, 518 }, { 429, 528 }, { 437, 537 }, { 445, 547 }, { 453, 557 },
    { 462, 566 }, { 470, 576 }, { 478, 586 }, { 486, 596 }, { 494, 606 },
    { 502, 616 }, { 511, 625 }, { 519, 635 }, { 527, 645 }, { 535, 655 },
    { 544, 665 }, { 552, 675 }, { 560, 685 }, { 569, 695 }, { 577, 705 },
    { 585, 715 }, { 594, 725 }, { 602, 735 }, { 610, 745 }, { 619, 755 },
    { 627, 765 }, { 635, 775 }, { 644, 785 }, { 652, 795 }, { 661, 805 },
    { 669, 815 }, { 678, 825 }, { 686, 835 }, { 695, 845 }, { 703, 855 },
    { 712, 866 }, { 720, 876 }, { 729, 886 }, { 737, 896 }, { 746, 906 },
  };

#define TRACELB_CONFIDENCE_MAX_N 99
#define TRACELB_CONFIDENCE_NLIMIT(v) \
  ((v) <= TRACELB_CONFIDENCE_MAX_N ? (v) : TRACELB_CONFIDENCE_MAX_N)

  assert(state->confidence < 2);
  assert(n >= 2);
  assert(n <= TRACELB_CONFIDENCE_MAX_N);

  return k[n][state->confidence];
}

static void tracelb_handleerror(scamper_task_t *task, int err)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  trace->error = err;
  scamper_debug(__func__, "%d", err);
  scamper_task_queue_done(task, 0);
  return;
}

#ifdef NDEBUG
#define tracelb_paths_assert(state) ((void)0)
#define tracelb_paths_dump(state) ((void)0)
#define tracelb_links_dump(state) ((void)0)
#endif

#ifndef NDEBUG
static int tracelb_paths_loop_fwd(tracelb_path_t *path, tracelb_path_t *node)
{
  int i;
  for(i=0; i<path->fwdc; i++)
    {
      if(path->fwd[i] == node)
	return 1;
      if(tracelb_paths_loop_fwd(path->fwd[i], node) != 0)
	return 1;
    }
  return 0;
}

static int tracelb_paths_loop_back(tracelb_path_t *path, tracelb_path_t *node)
{
  int i;
  for(i=0; i<path->backc; i++)
    {
      if(path->back[i] == node)
	return 1;
      if(tracelb_paths_loop_back(path->back[i], node) != 0)
	return 1;
    }
  return 0;
}

static void tracelb_paths_assert(tracelb_state_t *state)
{
  tracelb_path_t *path;
  int i, j, d, p;

  for(p=0; p<state->pathc; p++)
    {
      path = state->paths[p];

      assert(path->linkc >= 0);
      if(path->linkc == 0)
	assert(path->links == NULL);
      else
	assert(path->links != NULL);

      assert(path->fwdc >= 0);
      if(path->fwdc == 0)
	assert(path->fwd == NULL);
      else
	assert(path->fwd != NULL);

      assert(path->backc >= 0);
      if(path->backc == 0)
	assert(path->back == NULL);
      else
	assert(path->back != NULL);

      if(path->linkc == 0 && path->backc > 0)
	{
	  for(i=0; i<path->backc; i++)
	    assert(path->back[i]->linkc > 0);
	}

      for(i=0; i<path->linkc; i++)
	{
	  assert(path->links[i]->path == path);
	  assert(path->links[i]->link != NULL);
	  assert(path->links[i]->link->from != NULL);
	  if(i+1 != path->linkc || path->fwdc > 0)
	    assert(path->links[i]->link->to != NULL);
	}

      d = 0;
      for(i=0; i<path->backc; i++)
	{
	  assert(path->back[i]->fwdc > 0);

	  if(path->back[i]->distance > d)
	    d = path->back[i]->distance;

	  for(j=0; j<path->back[i]->fwdc; j++)
	    {
	      assert(path->distance > path->back[i]->distance);
	      if(path->back[i]->fwd[j] == path)
		break;
	    }

	  assert(j != path->back[i]->fwdc);
	}

      if(path->backc > 0)
	assert(d + 1 == path->distance);

      for(i=0; i<path->fwdc; i++)
	{
	  assert(path->fwd[i]->backc > 0);
	  for(j=0; j<path->fwd[i]->backc; j++)
	    {
	      if(path->fwd[i]->back[j] == path)
		break;
	    }
	  assert(j != path->fwd[i]->backc);
	}

      assert(tracelb_paths_loop_fwd(path, path) == 0);
      assert(tracelb_paths_loop_back(path, path) == 0);
    }

  return;
}

static void tracelb_paths_dump(tracelb_state_t *state)
{
  tracelb_path_t *path;
  tracelb_link_t *link;
  char buf[4096], addr[64];
  size_t off;
  int i, c, p;

  for(p=0; p<state->pathc; p++)
    {
      path = state->paths[p];
      off  = 0;

      string_concat(buf, sizeof(buf), &off, "%p: %d %d %d %d", path,
		    path->distance, path->backc, path->linkc, path->fwdc);
      if(path->linkc > 0)
	{
	  if(path->links[0]->link->from->addr != NULL)
	    {
	      scamper_addr_tostr(path->links[0]->link->from->addr,
				 addr, sizeof(addr));
	      string_concat(buf, sizeof(buf), &off, " %s", addr);
	    }
	  else
	    {
	      string_concat(buf, sizeof(buf), &off, " +");
	    }

	  for(i=0; i<path->linkc; i++)
	    {
	      link = path->links[i];

	      if(link->link->to == NULL)
		{
		  for(c=0; c<link->link->hopc; c++)
		    string_concat(buf, sizeof(buf), &off, " +");
		}
	      else
		{
		  for(c=1; c<link->link->hopc; c++)
		    string_concat(buf, sizeof(buf), &off, " +");
		  scamper_addr_tostr(link->link->to->addr, addr, sizeof(addr));
		  string_concat(buf, sizeof(buf), &off, " %s", addr);
		}

	      if(link->flowids != NULL && (c=slist_count(link->flowids)) != 0)
		string_concat(buf, sizeof(buf), &off, " (%d)", c);
	    }
	}

      for(i=0; i<path->fwdc; i++)
	string_concat(buf, sizeof(buf), &off, " %p", path->fwd[i]);

      scamper_debug(__func__, "%s", buf);
    }

  return;
}

static void tracelb_links_dump(tracelb_state_t *state)
{
  scamper_tracelb_link_t *link;
  scamper_tracelb_node_t *node;
  tracelb_link_t *tlbl;
  char buf[256], addr[64];
  size_t off;
  int i, j;

  for(i=0; i<state->linkc; i++)
    {
      tlbl = state->links[i];
      link = tlbl->link;
      off = 0;

      node = link->from;
      if(node->addr != NULL)
	{
	  scamper_addr_tostr(node->addr, addr, sizeof(addr));
	  string_concat(buf, sizeof(buf), &off, "%s", addr);
	  if(SCAMPER_TRACELB_NODE_QTTL(node))
	    string_concat(buf, sizeof(buf), &off, ",%d", node->q_ttl);
	}
      else
	string_concat(buf, sizeof(buf), &off, "*");

      for(j=1; j<link->hopc; j++)
	string_concat(buf, sizeof(buf), &off, " +");

      if(link->to == NULL)
	{
	  string_concat(buf, sizeof(buf), &off, " *");
	}
      else
	{
	  node = link->to;
	  scamper_addr_tostr(node->addr, addr, sizeof(addr));
	  string_concat(buf, sizeof(buf), &off, " %s", addr);
	  if(SCAMPER_TRACELB_NODE_QTTL(node))
	    string_concat(buf, sizeof(buf), &off, ",%d", node->q_ttl);
	}

      scamper_debug(__func__, "%s", buf);
    }

  return;
}

#endif

/*
 * tracelb_isloop_addr
 *
 * small utility function to determine if a loop exists.
 * called by tracelb_isloop.
 * this function does not have to do the zero-ttl check that trace_isloop
 * does and so should be faster.
 */
static tracelb_link_t *tracelb_isloop_addr(const tracelb_path_t *path,
					   const scamper_addr_t *addr)
{
  scamper_tracelb_probeset_t *set;
  scamper_tracelb_probe_t *probe;
  scamper_tracelb_link_t *link;
  tracelb_link_t *tlbl;
  int i, j;
  uint16_t k, l;

  for(i=path->linkc-1; i>=0; i--)
    {
      /* a tracelb_link_t state is required at each spot in the array */
      tlbl = path->links[i]; assert(tlbl != NULL);

      /* but there does not have to be an actual link with the state */
      if((link = tlbl->link) == NULL)
	continue;

      if(link->from->addr == NULL)
	continue;

      /* if the from address is the same, then we have a loop */
      if(scamper_addr_cmp(link->from->addr, addr) == 0)
	return tlbl;

      /* if the link includes a clump, then check the replies in the clump */
      for(j=0; j<link->hopc-1; j++)
	{
	  set = link->sets[j];
	  for(k=0; k<set->probec; k++)
	    {
	      probe = set->probes[k];
	      for(l=0; l<probe->rxc; l++)
		if(scamper_addr_cmp(probe->rxs[l]->reply_from, addr) == 0)
		  return tlbl;
	    }
	}
    }

  for(i=0; i<path->backc; i++)
    {
      if((tlbl = tracelb_isloop_addr(path->back[i], addr)) != NULL)
	{
	  return tlbl;
	}
    }

  return NULL;
}

/*
 * tracelb_isloop
 *
 * check to see if the link that has just been added to the path has an
 * inferred loop.
 */
static tracelb_link_t *tracelb_isloop(const tracelb_path_t *path)
{
  /*
   * the link has been added to this path before calling, so there should
   * be at least one link here
   */
  assert(path->linkc > 0);

  /*
   * if the link is a case of zero-ttl forwarding, then there is no loop
   * at this link, or in any prior part, as the link->from address has
   * already been tested for a loop.
   */
  if(scamper_tracelb_link_zerottlfwd(path->links[path->linkc-1]->link) != 0)
    {
      return 0;
    }

  return tracelb_isloop_addr(path, path->links[path->linkc-1]->link->to->addr);
}

/*
 * tracelb_link_continue
 *
 * iterate through the replies for the link.  if any of the replies indicates
 * that the router won't forward packets any further, tell the caller not
 * to continue probing the path.
 */
static int tracelb_link_continue(const scamper_tracelb_t *trace,
				 const tracelb_path_t *path,
				 const scamper_tracelb_link_t *link)
{
  scamper_tracelb_probeset_t *set;
  scamper_tracelb_probe_t *probe;
  scamper_tracelb_reply_t *reply;
  uint16_t i, j;

  /* don't continue probing if the destination address has been reached */
  if(link->to != NULL && scamper_addr_cmp(trace->dst, link->to->addr) == 0)
    {
      scamper_debug(__func__, "reached destination");
      return 0;
    }

  /* if any of the replies are not time exceeded, don't continue probing */
  set = link->sets[link->hopc-1];
  for(i=0; i<set->probec; i++)
    {
      probe = set->probes[i];
      for(j=0; j<probe->rxc; j++)
	{
	  reply = probe->rxs[j];
	  if(SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(reply) == 0)
	    {
	      scamper_debug(__func__, "%d/%d not time exceeded", i, j);
	      return 0;
	    }
	}
    }

  /* if a loop is encountered, then don't continue probing */
  if(tracelb_isloop(path) != NULL)
    {
      scamper_debug(__func__, "loop encountered");
      return 0;
    }

  return 1;
}

/*
 * tracelb_addr
 *
 * keep a per-tracelb cache of addresses to avoid unnecessary malloc
 * of addresses.
 */
static scamper_addr_t *tracelb_addr(tracelb_state_t *state,int type,void *addr)
{
  scamper_addr_t *a, fm;

  fm.type = type;
  fm.addr = addr;
  if((a = splaytree_find(state->addrs, &fm)) != NULL)
    return a;

  if((a = scamper_addr_alloc(type, addr)) == NULL)
    {
      printerror(__func__, "could not alloc addr");
      return NULL;
    }

  if(splaytree_insert(state->addrs, a) == NULL)
    {
      printerror(__func__, "could not insert addr");
      scamper_addr_free(a);
      return NULL;
    }

  return a;
}

/*
 * tracelb_set_visited0
 *
 * set the visited field of all tracelb_path_t structures to zero
 */
static void tracelb_set_visited0(tracelb_state_t *state)
{
  int i;
  for(i=0; i<state->pathc; i++)
    state->paths[i]->visited = 0;
  return;
}

static void tracelb_bringfwd_free(tracelb_branch_t *br)
{
  int i;
  if(br->bringfwd != NULL)
    {
      for(i=0; i<br->bringfwdc; i++)
	if(br->bringfwd[i] != NULL)
	  free(br->bringfwd[i]);
      free(br->bringfwd);
      br->bringfwd = NULL;
    }
  br->bringfwdc = 0;
  return;
}

static int tracelb_bringfwd_add(tracelb_branch_t *br, tracelb_path_t *path)
{
  tracelb_bringfwd_t *bf;
  if((bf = malloc_zero(sizeof(tracelb_bringfwd_t))) == NULL)
    {
      printerror(__func__, "could not malloc");
      return -1;
    }
  bf->path = path;
  br->bringfwd[br->bringfwdc++] = bf;
  return 0;
}

/*
 * tracelb_bringfwd_dft
 *
 * depth-first traversal of the paths leading to the specified path, for the
 * purposes of bring a flowid forward through the path to path[0].
 */
static int tracelb_bringfwd_dft(tracelb_branch_t *branch, tracelb_path_t *path)
{
  int i, x, rc = 0;

  assert(path != NULL);

  if(path->visited != 0)
    return 1;

  if(path->backc == 0)
    {
      if(tracelb_bringfwd_add(branch, path) != 0)
	return -1;
      path->visited = 1;
      return 1;
    }

  for(i=0; i<path->backc; i++)
    {
      if((x = tracelb_bringfwd_dft(branch, path->back[i])) == 1)
	rc = 1;
      else if(x == -1)
	return -1;
    }

  if(rc != 0)
    {
      if(tracelb_bringfwd_add(branch, path) != 0)
	return -1;
      path->visited = 1;
    }

  return rc;
}

/*
 * tracelb_bringfwd_set
 *
 *
 */
static int tracelb_bringfwd_set(tracelb_state_t *state, tracelb_branch_t *br,
				tracelb_link_t *tlbl, int set)
{
  tracelb_path_t *path;
  int i, n;

  for(i=0; i<br->bringfwdc; i++)
    {
      path = br->bringfwd[i]->path;
      if(path == tlbl->path)
	{
	  assert(path->links[path->linkc-1] == tlbl);
	  n = TRACELB_CONFIDENCE_NLIMIT(path->fwdc+2);

	  if(set != 0)
	    {
	      br->bringfwd[i]->k++;
	      if(br->bringfwd[i]->k >= k(state, n))
		{
		  return 1;
		}
	    }
	  else
	    br->bringfwd[i]->k = 0;

	  scamper_debug(__func__, "set %d i %d k %d < %d",
			set, i, br->bringfwd[i]->k, k(state, n));
	  break;
	}
    }

  assert(i != br->bringfwdc);

  return 0;
}

static int tracelb_flowids_list_add(slist_t *list, tracelb_probe_t *pr)
{
  tracelb_flowid_t *tf;

  assert(pr->mode != MODE_PERPACKET);
  assert(pr->mode != MODE_BRINGFWD0);
  assert(pr->mode != MODE_BRINGFWD);

  if((tf = malloc_zero(sizeof(tracelb_flowid_t))) == NULL)
    {
      printerror(__func__, "could not malloc flowid");
      return -1;
    }
  tf->id  = pr->probe->flowid;
  tf->ttl = pr->probe->ttl;

  if(slist_tail_push(list, tf) == NULL)
    {
      free(tf);
      printerror(__func__, "could not slist_tail_push");
      return -1;
    }

  return 0;
}

/*
 * tracelb_link_flowid_get
 *
 * return a flowid from the link, if there is one.  when returning the last
 * flowid free the list structure.
 */
static tracelb_flowid_t *tracelb_link_flowid_get(tracelb_link_t *link)
{
  tracelb_flowid_t *tf;

  if(link->flowids == NULL)
    return NULL;

  tf = slist_head_pop(link->flowids);

  if(slist_count(link->flowids) == 0)
    {
      slist_free(link->flowids);
      link->flowids = NULL;
    }

  return tf;
}

/*
 * tracelb_link_cmp
 *
 * useful for providing as a sort callback method for qsort on state->links
 */
static int tracelb_link_cmp(const tracelb_link_t *a, const tracelb_link_t *b)
{
  assert(a != NULL); assert(a->link != NULL);
  assert(b != NULL); assert(b->link != NULL);
  return scamper_tracelb_link_cmp(a->link, b->link);
}

/*
 * tracelb_cmp_node2reply
 *
 * determine if a reply could be matched against a node.
 */
static int tracelb_cmp_node2reply(const scamper_tracelb_node_t *node,
				  const scamper_tracelb_reply_t *reply)
{
  scamper_tracelb_node_t cmp;

  memset(&cmp, 0, sizeof(cmp));
  cmp.addr = reply->reply_from;
  if(SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(reply) ||
     SCAMPER_TRACELB_REPLY_IS_ICMP_UNREACH(reply))
    {
      cmp.q_ttl  = reply->reply_icmp_q_ttl;
      cmp.flags |= SCAMPER_TRACELB_NODE_FLAG_QTTL;
    }

  return scamper_tracelb_node_cmp(node, &cmp);
}

static int tracelb_newnode_cmp(const tracelb_newnode_t *a,
			       const tracelb_newnode_t *b)
{
  return scamper_tracelb_node_cmp(a->node, b->node);
}

static tracelb_newnode_t *tracelb_newnode_find(tracelb_branch_t *br,
					       scamper_tracelb_reply_t *reply)
{
  tracelb_newnode_t findme;
  scamper_tracelb_node_t node;

  memset(&node, 0, sizeof(node));
  findme.node = &node;

  if(SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(reply) ||
     SCAMPER_TRACELB_REPLY_IS_ICMP_UNREACH(reply))
    {
      node.q_ttl  = reply->reply_icmp_q_ttl;
      node.flags |= SCAMPER_TRACELB_NODE_FLAG_QTTL;
    }
  node.addr = reply->reply_from;

  return array_find((void **)br->newnodes, br->newnodec, &findme,
		    (array_cmp_t)tracelb_newnode_cmp);
}

static int tracelb_newnode_add(tracelb_branch_t *br,
			       scamper_tracelb_probe_t *probe)
{
  scamper_tracelb_reply_t *reply;
  tracelb_newnode_t *newnode;

  assert(probe->rxc == 1);

  if((newnode = malloc_zero(sizeof(tracelb_newnode_t))) == NULL)
    {
      printerror(__func__, "could not alloc newnode");
      goto err;
    }
  newnode->probe = probe;

  reply = probe->rxs[0];
  if((newnode->node = scamper_tracelb_node_alloc(reply->reply_from)) == NULL)
    {
      printerror(__func__, "could not alloc node");
      goto err;
    }
  if(SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(reply) ||
     SCAMPER_TRACELB_REPLY_IS_ICMP_UNREACH(reply))
    {
      newnode->node->q_ttl  = reply->reply_icmp_q_ttl;
      newnode->node->flags |= SCAMPER_TRACELB_NODE_FLAG_QTTL;
    }

  if(array_insert((void ***)&br->newnodes, &br->newnodec, newnode,
		  (array_cmp_t)tracelb_newnode_cmp) != 0)
    {
      printerror(__func__, "could not add node to branch");
      goto err;
    }

  return 0;

 err:
  if(newnode != NULL)
    {
      if(newnode->node != NULL)
	scamper_tracelb_node_free(newnode->node);
      free(newnode);
    }
  return -1;
}

/*
 * tracelb_link_alloc
 *
 * simple function to allocate a new link.
 */
static tracelb_link_t *tracelb_link_alloc(tracelb_state_t *state,
					  scamper_tracelb_link_t *link,
					  tracelb_path_t *path)
{
  tracelb_link_t *tlbl;

  if((tlbl = malloc_zero(sizeof(tracelb_link_t))) == NULL)
    {
      printerror(__func__, "could not alloc tlbl");
      return NULL;
    }
  tlbl->link = link;
  tlbl->path = path;

  if(array_insert((void ***)&state->links, &state->linkc, tlbl,
		  (array_cmp_t)tracelb_link_cmp) != 0)
    {
      printerror(__func__, "could not insert tlbl");
      free(tlbl);
      return NULL;;
    }

  return tlbl;
}

static tracelb_link_t *tracelb_link_find(tracelb_state_t *state,
					 scamper_tracelb_link_t *link)
{
  tracelb_link_t findme;
  findme.link = link;
  return (tracelb_link_t *)array_find((void **)state->links, state->linkc,
				      &findme, (array_cmp_t)tracelb_link_cmp);
}

/*
 * tracelb_link_free
 *
 * free up a tracelb_link structure.
 */
static void tracelb_link_free(tracelb_link_t *link)
{
  tracelb_flowid_t *tf;
  while((tf = tracelb_link_flowid_get(link)) != NULL)
    {
      free(tf);
    }
  free(link);
  return;
}

/*
 * tracelb_link_flowid_add_tail
 *
 * record probe flowid/ttl details of a reply with a link
 */
static int tracelb_link_flowid_add_tail(tracelb_link_t *link,
					scamper_tracelb_probe_t *probe)
{
  tracelb_flowid_t *tf;

  /* allocate a list structure, if necessary, to store the flowids */
  if(link->flowids == NULL && (link->flowids = slist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc flowids list");
      return -1;
    }

  if((tf = malloc_zero(sizeof(tracelb_flowid_t))) == NULL)
    {
      printerror(__func__, "could not malloc flowid");
      return -1;
    }
  tf->id  = probe->flowid;
  tf->ttl = probe->ttl;

  if(slist_tail_push(link->flowids, tf) == NULL)
    {
      free(tf);
      printerror(__func__, "could not slist_tail_push");
      return -1;
    }

  return 0;
}

static void tracelb_link_flowids_inc(tracelb_link_t *tlbl)
{
  tracelb_flowid_t *tf;
  slist_node_t *node;

  if(tlbl->flowids == NULL)
    return;

  node = slist_head_node(tlbl->flowids);
  while(node != NULL)
    {
      tf = slist_node_item(node);
      tf->ttl++;
      node = slist_node_next(node);
    }

  return;
}

/*
 * tracelb_link_flowids_add_list
 *
 */
static void tracelb_link_flowids_add_list(tracelb_link_t *tlbl, slist_t *list)
{
  /* allocate a list structure, if necessary, to store the flowids */
  if(tlbl->flowids == NULL)
    {
      tlbl->flowids = list;
    }
  else
    {
      slist_concat(list, tlbl->flowids);
      slist_free(tlbl->flowids);
      tlbl->flowids = list;
    }
  return;
}

/*
 * tracelb_probe_add
 *
 * simple function to add a probe to the array of probes sent
 */
static int tracelb_probe_add(tracelb_state_t *state, tracelb_branch_t *br,
			     tracelb_probe_t *pr)
{
  size_t len = sizeof(tracelb_probe_t *) * (state->id_next + 1);
  if(realloc_wrap((void **)&state->probes, len) != 0)
    {
      printerror(__func__, "could not realloc %d bytes", len);
      return -1;
    }
  pr->id = state->id_next;

  state->probes[state->id_next] = pr;
  state->id_next++;

  if(array_insert((void ***)&br->probes, &br->probec, pr, NULL) != 0)
    {
      printerror(__func__, "could not add probe to branch");
      return -1;
    }
  pr->branch = br;

  return 0;
}

/*
 * tracelb_path_length
 *
 * return the length of the shortest sequence of path lengths back to the head
 */
static uint8_t tracelb_path_length(const tracelb_path_t *path)
{
  const tracelb_path_t *shortest;
  uint8_t len = path->linkc;
  int i;

  while(path->backc > 0)
    {
      shortest = path->back[0];
      for(i=1; i<path->backc; i++)
	{
	  if(shortest->linkc > path->back[i]->linkc)
	    shortest = path->back[i];
	}
      len += shortest->linkc;
      path = shortest;
    }

  return len;
}

/*
 * tracelb_path_add_link
 *
 * simple function to add a link to an existing path
 */
static int tracelb_path_add_link(tracelb_path_t *path, tracelb_link_t *link)
{
  if(array_insert((void ***)&path->links, &path->linkc, link, NULL) != 0)
    {
      printerror(__func__, "could not add link");
      return -1;
    }
  return 0;
}

/*
 * tracelb_path_add_fwd
 *
 * simple function to add a forward path to another path.
 */
static int tracelb_path_add_fwd(tracelb_path_t *path, tracelb_path_t *fwd)
{
  if(array_insert((void ***)&path->fwd, &path->fwdc, fwd, NULL) != 0)
    {
      printerror(__func__, "could not add fwd");
      return -1;
    }
  return 0;
}

/*
 * tracelb_path_add_back
 *
 * simple function to add a back path to another path.
 */
static int tracelb_path_add_back(tracelb_path_t *path, tracelb_path_t *back)
{
  if(array_insert((void ***)&path->back, &path->backc, back, NULL) != 0)
    {
      printerror(__func__, "could not add back");
      return -1;
    }

  return tracelb_path_add_fwd(back, path);
}

static void tracelb_path_free(tracelb_path_t *path)
{
  if(path == NULL)
    return;

  if(path->back  != NULL) free(path->back);
  if(path->fwd   != NULL) free(path->fwd);
  if(path->links != NULL) free(path->links);
  free(path);

  return;
}

/*
 * tracelb_path_alloc
 *
 * allocate a new path structure; advise how many backc/linkc entries
 * to pre-allocate, if any.
 */
static tracelb_path_t *tracelb_path_alloc(tracelb_state_t *state, int linkc)
{
  tracelb_path_t *path;
  size_t len;

  assert(linkc >= 0);

  if((path = malloc_zero(sizeof(tracelb_path_t))) == NULL)
    {
      printerror(__func__, "could not malloc path");
      goto err;
    }

  len = sizeof(scamper_tracelb_link_t *) * linkc;
  if(linkc != 0 && (path->links = malloc_zero(len)) == NULL)
    {
      printerror(__func__, "could not malloc path->links");
      goto err;
    }

  if(array_insert((void ***)&state->paths, &state->pathc, path, NULL) != 0)
    {
      printerror(__func__, "could not insert path");
      goto err;
    }

  return path;

 err:
  tracelb_path_free(path);
  return NULL;
}

/*
 * tracelb_bringfwd_cmp
 *
 * callback sort function used to sort the paths by distance (in branches)
 * from the top of the tree.
 */
static int tracelb_bringfwd_cmp(const tracelb_bringfwd_t *a,
				const tracelb_bringfwd_t *b)
{
  if(a->path->distance < b->path->distance)
    return 1;
  if(a->path->distance > b->path->distance)
    return -1;
  return 0;
}

/*
 * tracelb_branch_active_cmp
 *
 * this function is used to sort the state->active heap so that the branch
 * due to be probed next is at the top of the heap.
 */
static int tracelb_branch_active_cmp(const tracelb_branch_t *a,
				     const tracelb_branch_t *b)
{
  return timeval_cmp(&b->next_tx, &a->next_tx);
}

static int tracelb_branch_active(tracelb_state_t *state, tracelb_branch_t *br)
{
  assert(heap_count(state->active) == 0);
  assert(br->probec > 0 || br->mode == MODE_RTSOCK || br->mode == MODE_DLHDR);
  if((br->heapnode = heap_insert(state->active, br)) != NULL)
    {
      return 0;
    }
  printerror(__func__, "could not insert branch on active");
  return -1;
}

/*
 * tracelb_branch_waiting_cmp
 *
 * this function is used to sort the state->branch heap so that next the
 * branch introduced to active probing is the one closest to the root, in
 * ttl terms.
 */
static int tracelb_branch_waiting_cmp(const tracelb_branch_t *a,
				      const tracelb_branch_t *b)
{
  return tracelb_path_length(b->path) - tracelb_path_length(a->path);
}

static int tracelb_branch_waiting(tracelb_state_t *state, tracelb_branch_t *br)
{
  if((br->heapnode = heap_insert(state->waiting, br)) != NULL)
    {
      return 0;
    }
  printerror(__func__, "could not insert branch on waiting");
  return -1;
}

/*
 * tracelb_branch_reset
 *
 * reset probing state on the branch, but do not reset the links/nodes
 * inferred so far.  this allows us to determine per-packet load balancing
 * details for a set of
 */
static void tracelb_branch_reset(tracelb_branch_t *branch)
{
  int i;

  branch->l = 0;
  branch->k = 0;
  branch->n = 2;

  if(branch->mode != MODE_PERPACKET)
    {
      /* don't want the probes */
      if(branch->probes != NULL)
	{
	  for(i=0; i<branch->probec; i++)
	    branch->probes[i]->branch = NULL;
	  free(branch->probes);
	  branch->probes = NULL;
	}
      branch->probec = 0;
    }

  /* won't need any state associated with bringing probes forward */
  tracelb_bringfwd_free(branch);

  return;
}

static void tracelb_branch_free(tracelb_state_t *state, tracelb_branch_t *br)
{
  int i;

  if(br->probes != NULL)
    {
      for(i=0; i<br->probec; i++)
	br->probes[i]->branch = NULL;
      free(br->probes);
    }

  tracelb_bringfwd_free(br);

  if(br->newnodes != NULL)
    free(br->newnodes);

  free(br);
  return;
}

/*
 * tracelb_path_add
 *
 * add a path to the heap of currently traced paths.
 */
static int tracelb_path_add(tracelb_state_t *state, tracelb_path_t *path)
{
  tracelb_branch_t *branch = NULL;

  if((branch = malloc_zero(sizeof(tracelb_branch_t))) == NULL)
    {
      printerror(__func__, "could not alloc branch");
      goto err;
    }
  branch->mode = MODE_HOPPROBE;
  branch->path = path;
  tracelb_branch_reset(branch);
  if(tracelb_branch_waiting(state, branch) != 0)
    goto err;

  return 0;

 err:
  if(branch != NULL) tracelb_branch_free(state, branch);
  return -1;
}

/*
 * tracelb_path_distance_1
 *
 * recursive function to add a particular value to the distance field of
 * all paths ahead of a particular path.
 */
static void tracelb_path_distance_1(tracelb_path_t *path, int distance)
{
  int i;

  scamper_debug(__func__, "path %p,%d %d->%d", path, path->visited,
		path->distance, distance);

  path->visited++;
  if(path->distance >= distance)
    return;

  path->distance = distance;

  for(i=0; i<path->fwdc; i++)
    {
      assert(path != path->fwd[i]);
      tracelb_path_distance_1(path->fwd[i], distance+1);
    }

  return;
}

static int tracelb_path_cmp(const tracelb_path_t *a, const tracelb_path_t *b)
{
  if(a->distance < b->distance)
    return -1;
  if(a->distance > b->distance)
    return 1;
  return 0;
}

static void tracelb_paths_sort(tracelb_state_t *state)
{
  array_qsort((void **)state->paths, state->pathc,
	      (array_cmp_t)tracelb_path_cmp);
  return;
}

/*
 * tracelb_path_distance
 *
 * function to add a particular value to the distance field of all paths
 * ahead of a particular path.  uses the tracelb_path_distance_1 function
 * above, but first sets all of the visited values to zero so loops can
 * be detected when built with debugging.
 */
static void tracelb_path_distance(tracelb_state_t *state,
				  tracelb_path_t *path, int distance)
{
  tracelb_set_visited0(state);
  tracelb_path_distance_1(path, distance);
  heap_remake(state->waiting);
  tracelb_paths_sort(state);
  return;
}

/*
 * tracelb_paths_splice
 *
 * `path0' shares a link or node in common with `path'.  take path, split
 * it into two parts.
 */
static int tracelb_paths_splice(tracelb_state_t *state, tracelb_path_t *path0,
				tracelb_path_t *path, int linkc)
{
  tracelb_path_t *newp;
  int i, j, d;

  /*
   * allocate a new path.  the new path will have the first half of `path'
   * by the end of this routine
   */
  if((newp = tracelb_path_alloc(state, linkc)) == NULL)
    {
      return -1;
    }

  /* the new path inherits the back paths from the existing `path' */
  newp->back  = path->back;
  newp->backc = path->backc;
  path->back  = NULL;
  path->backc = 0;
  for(i=0; i<newp->backc; i++)
    {
      for(j=0; j<newp->back[i]->fwdc; j++)
	{
	  if(newp->back[i]->fwd[j] == path)
	    newp->back[i]->fwd[j] = newp;
	}
    }

  /* the new path inherits the first portion of the links in the old path */
  for(newp->linkc=0; newp->linkc < linkc; newp->linkc++)
    {
      newp->links[newp->linkc] = path->links[newp->linkc];
      newp->links[newp->linkc]->path = newp;
    }

  /* shift the links in the second portion into place */
  if(path->linkc - linkc > 0)
    {
      for(i=0; i<path->linkc-linkc; i++)
	{
	  path->links[i] = path->links[linkc+i];
	}
      path->linkc = path->linkc - linkc;
    }
  else
    {
      assert(path->linkc - linkc == 0);
      free(path->links);
      path->links = NULL;
      path->linkc = 0;
    }

  /* the path now has two back pointers; add them */
  if(tracelb_path_add_back(path, newp)  != 0 ||
     tracelb_path_add_back(path, path0) != 0)
    {
      return -1;
    }

  /* make sure the measure of distance for path segments are correct */
  newp->distance = path->distance;
  if(path0->distance > path->distance)
    d = path0->distance + 1;
  else
    d = path->distance + 1;
  tracelb_path_distance(state, path, d);

  return 0;
}

/*
 * tracelb_paths_splice_bynode
 *
 *
 */
static int tracelb_paths_splice_bynode(tracelb_state_t *state,
				       tracelb_path_t *path0)
{
  scamper_tracelb_link_t *link;
  tracelb_path_t *path;
  tracelb_link_t *tlbl;
  int i, j;

  tracelb_paths_assert(state);

  /*
   * find a link where this node is found.
   * this is done before the link below is added, since we don't want to
   * find the new link we are adding, nor do we want the index value to be
   * changed by a new link being added (and sorted) into the array.
   */
  tlbl = path0->links[path0->linkc-1];
  link = tlbl->link;
  for(i=0; i<state->linkc; i++)
    {
      if(state->links[i] != tlbl &&
	 state->links[i]->link->to != NULL &&
	 scamper_tracelb_node_cmp(state->links[i]->link->to, link->to) == 0)
	{
	  break;
	}
    }
  assert(i != state->linkc);

  /* find where abouts in the path segment the node is found */
  tlbl = state->links[i];
  path = tlbl->path;
  for(i=0; i<path->linkc; i++)
    {
      if(path->links[i] == tlbl)
	break;
    }
  assert(i != path->linkc);

  if(i+1 == path->linkc && path->fwdc != 0)
    {
      for(j=0; j<path->fwdc; j++)
	{
	  tracelb_path_add_back(path->fwd[j], path0);
	  tracelb_path_distance(state, path->fwd[j], path0->distance + 1);
	}
    }
  else
    {
      tracelb_paths_splice(state, path0, path, i+1);
    }

  tracelb_paths_assert(state);
  return 0;
}

/*
 * tracelb_queue
 *
 * the task is ready to be probed again.  put it in a queue to wait a little
 * longer, or put it into the queue to be probed asap.
 */
static void tracelb_queue(scamper_task_t *task)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);
  tracelb_branch_t *branch;
  struct timeval now, next_tx;

  if(scamper_task_queue_isdone(task))
    return;

  /* if there are no branches to probe, then we're done */
  if(heap_count(state->active) == 0 && heap_count(state->waiting) == 0)
    {
      scamper_task_queue_done(task, 0);
      return;
    }

  if((branch = heap_head_item(state->active)) != NULL)
    {
      timeval_cpy(&next_tx, &branch->next_tx);
    }
  else
    {
      timeval_cpy(&next_tx, &state->next_tx);
    }

  /* get the current time */
  gettimeofday_wrap(&now);

  /* if the time to probe has already passed, queue it up */
  if(timeval_cmp(&next_tx, &now) <= 0)
    {
      /* check to see if we're permitted to send another probe */
      if(trace->probec >= trace->probec_max)
	{
	  scamper_task_queue_done(task, 0);
	  return;
	}

      scamper_task_queue_probe(task);
      return;
    }

  scamper_task_queue_wait_tv(task, &next_tx);
  return;
}

static void tracelb_host_free(tracelb_state_t *state, tracelb_host_t *th)
{
  if(th->dn != NULL) dlist_node_pop(state->ths, th->dn);
  if(th->hostdo != NULL) scamper_host_do_free(th->hostdo);
  free(th);
  return;
}

static void tracelb_node_ptr_cb(void *param, const char *name)
{
  tracelb_host_t *th = param;
  scamper_task_t *task = th->task;
  tracelb_state_t *state = tracelb_getstate(task);

  th->hostdo = NULL;

  if(name != NULL)
    th->node->name = strdup(name);

  tracelb_host_free(state, th);

  return;
}

static int tracelb_node_ptr(scamper_task_t *task, scamper_tracelb_node_t *node)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);
  tracelb_host_t *th = NULL;

  if((trace->flags & SCAMPER_TRACELB_FLAG_PTR) == 0)
    return 0;

  if((state->ths == NULL && (state->ths = dlist_alloc()) == NULL))
    {
      printerror(__func__, "could not alloc ths");
      goto err;
    }
  if((th = malloc_zero(sizeof(tracelb_host_t))) == NULL)
    {
      printerror(__func__, "could not alloc th");
      goto err;
    }
  th->node = node;
  th->task = task;
  th->hostdo = scamper_do_host_do_ptr(node->addr, th, tracelb_node_ptr_cb);
  if(th->hostdo == NULL)
    {
      printerror(__func__, "could not scamper_do_host_do_ptr");
      goto err;
    }
  if((th->dn = dlist_tail_push(state->ths, th)) == NULL)
    {
      printerror(__func__, "could not push th");
      goto err;
    }
  return 0;

 err:
  if(th != NULL) tracelb_host_free(state, th);
  return -1;
}

static int tracelb_process_hops(scamper_task_t *task, tracelb_branch_t *br)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);
  tracelb_path_t *path0 = br->path;
  scamper_tracelb_probeset_t *set;
  scamper_tracelb_probe_t *probe;
  scamper_tracelb_node_t *from, *to;
  scamper_tracelb_link_t *link;
  tracelb_link_t *tlbl;
  tracelb_path_t *newp;
  tracelb_probe_t *pr;
  uint16_t flowid;
  slist_t *flowids = NULL;
  int i, j, k, splice, record, timxceed;

  assert(br->probec > 0);

  /*
   * get the from node.  the algorithm to obtain it depends on exactly what
   * happened prior to reaching here.
   */
  if(br->mode == MODE_FIRSTHOP)
    from = trace->nodes[0];
  else if(br->mode == MODE_CLUMP)
    from = NULL;
  else if(path0->linkc > 0)
    from = path0->links[path0->linkc-1]->link->to;
  else
    from = path0->back[0]->links[path0->back[0]->linkc-1]->link->to;

  for(i=0; i<br->newnodec; i++)
    {
      /* get details about the far end of the link */
      to = scamper_tracelb_node_find(trace, br->newnodes[i]->node);
      if(to == NULL)
	{
	  to = br->newnodes[i]->node;
	  if(tracelb_node_ptr(task, to) != 0 ||
	     scamper_tracelb_node_add(trace, to) != 0)
	    goto err;
	  splice = 0;
	}
      else
	{
	  scamper_tracelb_node_free(br->newnodes[i]->node);
	  splice = 1;
	}
      free(br->newnodes[i]);
      br->newnodes[i] = NULL;

      /* create a link to store in the trace */
      if(br->mode != MODE_CLUMP)
	{
	  assert(from != NULL);
	  if((link = scamper_tracelb_link_alloc()) == NULL)
	    {
	      goto err;
	    }
	  link->from = from;
	  link->to   = to;
	}
      else
	{
	  link = path0->links[path0->linkc-1]->link;
	  assert(link->to == NULL);
	  link->to = to;
	}

      /*
       * try and allocate a probeset to record details of probes.
       * if it fails, then we have to free the link allocated above
       */
      if((set = scamper_tracelb_probeset_alloc()) == NULL ||
	 (flowids = slist_alloc()) == NULL)
	{
	  if(br->mode != MODE_CLUMP)
	    scamper_tracelb_link_free(link);
	  goto err;
	}

      /*
       * record responses with each link.  the code is relatively complicated
       * as we want to record all relevant probes with the link (some of which
       * did not obtain a response) and also figure out which flowids to use
       * probing forward.
       */
      flowid = br->probes[0]->probe->flowid;
      k = 0; record = 0; timxceed = 1;
      for(j=0; j<=br->probec; j++)
	{
	  /*
	   * when we've got to the end of a sequence of probes with the same
	   * flowid, look to record that sequence if applicable.
	   *
	   * the j == br->probec is a hack to make sure the last probe is
	   * counted when processing all probes.
	   */
	  if(j == br->probec || br->probes[j]->probe->flowid != flowid)
	    {
	      /*
	       * record only if the response(s) came from the node we are
	       * recording to
	       */
	      if(record != 0)
		{
		  /*
		   * record the flowid for further use if we have only
		   * received time exceeded responses when probing
		   */
		  if(timxceed != 0 && br->probes[k]->mode != MODE_PERPACKET)
		    {
		      pr = br->probes[k];
		      if(tracelb_flowids_list_add(flowids, pr) != 0)
			goto err;
		    }

		  /*
		   * record all attempts with a particular flowid/ttl
		   * combination
		   */
		  while(k<j)
		    {
		      pr = br->probes[k];
		      if(scamper_tracelb_probeset_add(set, pr->probe) != 0)
			goto err;
		      k++;
		    }
		}

	      if(j == br->probec)
		break;

	      /* moving onto the next flowid now.  reset variables */
	      timxceed = 1;
	      record = 0;
	      flowid = br->probes[j]->probe->flowid;
	      k = j;
	    }

	  pr = br->probes[j];
	  probe = pr->probe;

	  /* if this probe is one which was brought forward, then skip it */
	  if(pr->mode == MODE_BRINGFWD || pr->mode == MODE_BRINGFWD0)
	    {
	      k++;
	      continue;
	    }

	  /* check to see if this probe got any responses. */
	  if(probe->rxc == 0)
	    continue;

	  /*
	   * if we're in this function, it is because no probe got more than
	   * a single response
	   */
	  assert(probe->rxc == 1 || pr->mode == MODE_PERPACKET);

	  /*
	   * if this reply matches the node we're processing, then set a
	   * variable to say that we want to record this set of probes.
	   */
	  if(tracelb_cmp_node2reply(to, probe->rxs[0]) == 0)
	    {
	      record = 1;
	      if(SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(probe->rxs[0]) == 0)
		timxceed = 0;
	    }
	}

      /* record the probeset with the link */
      if(scamper_tracelb_link_probeset(link, set) != 0)
	{
	  printerror(__func__, "could not add probeset");
	  goto err;
	}

      /* record the link in the trace */
      if(link->hopc == 1 && scamper_tracelb_link_add(trace, link) != 0)
	{
	  printerror(__func__, "could not add new link");
	  goto err;
	}

      if(br->mode == MODE_FIRSTHOP)
	{
	  assert(splice == 0 || link->from == link->to);
	  if((newp = tracelb_path_alloc(state, 0)) == NULL ||
	     (tlbl = tracelb_link_alloc(state, link, newp)) == NULL ||
	     tracelb_path_add_link(newp, tlbl) != 0)
	    {
	      goto err;
	    }
	}
      else if(br->mode == MODE_CLUMP)
	{
	  tlbl = path0->links[path0->linkc-1];
	  tracelb_link_flowids_inc(tlbl);
	  newp = path0;
	}
      else if(br->newnodec == 1)
	{
	  /*
	   * (1) allocate a tracelb_link_t structure to keep link state with
	   * (2) add the link to the path being probed
	   * (3) note the successful probes with the link state
	   */
	  if((tlbl = tracelb_link_alloc(state, link, path0)) == NULL ||
	     tracelb_path_add_link(path0, tlbl) != 0)
	    {
	      goto err;
	    }
	  newp = path0;
	}
      else
	{
	  if((newp = tracelb_path_alloc(state, 0)) == NULL ||
	     (tlbl = tracelb_link_alloc(state, link, newp)) == NULL ||
	     tracelb_path_add_link(newp, tlbl) != 0 ||
	     tracelb_path_add_back(newp, path0) != 0)
	    {
	      goto err;
	    }

	  /* the distance to the root is one more than the last path segment */
	  newp->distance = path0->distance + 1;
	  tracelb_paths_sort(state);
	}

      tracelb_link_flowids_add_list(tlbl, flowids);
      flowids = NULL;

      if(tracelb_link_continue(trace, newp, link) == 0)
	continue;

      if(splice == 0)
	{
	  if(tracelb_path_add(state, newp) != 0)
	    {
	      goto err;
	    }
	}
      else
	{
	  if(tracelb_paths_splice_bynode(state, newp) != 0)
	    {
	      goto err;
	    }
	}
    }

  tracelb_branch_free(state, br);
  tracelb_paths_assert(state);
  return 0;

 err:
  return -1;
}

static int tracelb_process_clump(scamper_task_t *task, tracelb_branch_t *br)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);
  tracelb_path_t *path0 = br->path;
  scamper_tracelb_probe_t *probe;
  scamper_tracelb_node_t *node;
  scamper_tracelb_link_t *link;
  scamper_tracelb_probeset_t *set = NULL;
  tracelb_probe_t *pr;
  tracelb_link_t *tlbl = NULL;
  slist_t *flowids = NULL;
  uint16_t flowid;
  int i, j, k, halt = 0;

  tracelb_paths_dump(state);

  if(path0 == NULL)
    {
      assert(trace->nodec == 1);
      for(i=0; i<br->newnodec; i++)
	{
	  node = br->newnodes[i]->node;
	  if(scamper_tracelb_node_cmp(trace->nodes[0], node) == 0)
	    {
	      scamper_debug(__func__, "node %d loop", i);
	      halt = 1;
	    }
	  scamper_tracelb_node_free(br->newnodes[i]->node);
	  free(br->newnodes[i]); br->newnodes[i] = NULL;
	}
      free(br->newnodes);
      br->newnodes = NULL;
      br->newnodec = 0;

      if((path0 = tracelb_path_alloc(state, 0)) == NULL)
	goto err;
      br->path = path0;
    }
  else if(br->newnodec > 0)
    {
      /*
       * check if any of the nodes would indicate a loop.  this is the only
       * thing we use the nodes for, so free them as we go.
       */
      for(i=0; i<br->newnodec; i++)
	{
	  node = br->newnodes[i]->node;
	  if(halt == 0 && tracelb_isloop_addr(path0, node->addr) != NULL)
	    {
	      scamper_debug(__func__, "node %d loop", i);
	      halt = 1;
	    }
	  scamper_tracelb_node_free(br->newnodes[i]->node);
	  free(br->newnodes[i]); br->newnodes[i] = NULL;
	}
      free(br->newnodes);
      br->newnodes = NULL;
      br->newnodec = 0;
    }
  else if(path0->linkc > 0)
    {
      link = path0->links[path0->linkc-1]->link;
      if(trace->gaplimit < 2)
	{
	  halt = 1;
	}
      else if(link->to == NULL && link->hopc+1 >= trace->gaplimit)
	{
	  k = 1;
	  for(i=link->hopc-1; i>=0; i--)
	    {
	      if(k == trace->gaplimit)
		break;

	      set = link->sets[i];
	      for(j=0; j<set->probec; j++)
		if(set->probes[j]->rxc > 0)
		  break;

	      if(j == set->probec)
		k++;
	    }
	  if(k == trace->gaplimit)
	    halt = 1;
	}
    }

  /* allocate a list to store flowids in */
  if((flowids = slist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc list");
      goto err;
    }

  /* allocate a probeset and add all probes sent in the round */
  if((set = scamper_tracelb_probeset_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc probeset");
      goto err;
    }

  flowid = br->probes[0]->probe->flowid; k = 0;
  for(i=0; i<=br->probec; i++)
    {
      /*
       * record the flowid in the branch so it will be used for further
       * probing, unless its already been noted the branch will not be
       * probed further.
       */
      if(i == br->probec || flowid != br->probes[i]->probe->flowid)
	{
	  if(halt == 0 && k<i)
	    {
	      pr = br->probes[k];
	      if(pr->mode != MODE_PERPACKET &&
		 tracelb_flowids_list_add(flowids, pr) != 0)
		goto err;
	    }
	  if(i == br->probec)
	    break;

	  flowid = br->probes[i]->probe->flowid;
	  k = i;
	}

      pr = br->probes[i];
      if(pr->mode == MODE_BRINGFWD || pr->mode == MODE_BRINGFWD0)
	{
	  k++;
	  continue;
	}

      probe = pr->probe;
      if(scamper_tracelb_probeset_add(set, probe) != 0)
	{
	  printerror(__func__, "could not add probe %d", i);
	  goto err;
	}

      /*
       * if any of the responses observed are not a time exceeded message,
       * then halt this branch of probing
       */
      if(halt != 0)
	continue;
      for(j=0; j<probe->rxc; j++)
	{
	  if(SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(probe->rxs[j]) == 0)
	    halt = 1;
	}
    }

  /*
   * determine if we have to create a new link or if the clump merely extends
   * an earlier one
   */
  if(path0->linkc == 0 || path0->links[path0->linkc-1]->link->to != NULL)
    {
      if((link = scamper_tracelb_link_alloc()) == NULL)
	{
	  printerror(__func__, "could not alloc link");
	  goto err;
	}

      if(path0->linkc > 0)
	link->from = path0->links[path0->linkc-1]->link->to;
      else if(path0->backc > 0)
	link->from = path0->back[0]->links[path0->back[0]->linkc-1]->link->to;
      else
	link->from = trace->nodes[0];
    }
  else
    {
      tlbl = path0->links[path0->linkc-1];
      link = tlbl->link;
      tracelb_link_flowids_inc(tlbl);
    }

  /* add the probeset to the link */
  if(scamper_tracelb_link_probeset(link, set) != 0)
    {
      printerror(__func__, "could not add probeset");
      goto err;
    }

  /* if this is the first probeset to be added, then record the link */
  if(link->hopc == 1)
    {
      if(scamper_tracelb_link_add(trace, link) != 0)
	{
	  printerror(__func__, "could not add new link");
	  goto err;
	}

      if((tlbl = tracelb_link_alloc(state, link, path0)) == NULL ||
	 tracelb_path_add_link(path0, tlbl) != 0)
	{
	  goto err;
	}
    }

  if(halt == 0)
    {
      tracelb_link_flowids_add_list(tlbl, flowids);

      /* put the branch back in for probing */
      br->mode = MODE_CLUMP;
      tracelb_branch_reset(br);
      timeval_add_cs(&br->next_tx, &br->last_tx, trace->wait_probe);
      if(tracelb_branch_waiting(state, br) != 0)
	goto err;
    }
  else
    {
      if(flowids != NULL) slist_free_cb(flowids, free);
      tracelb_branch_free(state, br);
    }

  return 0;

 err:
  return -1;
}

static int tracelb_process_perpacket(scamper_task_t *task,tracelb_branch_t *br)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);

  br->mode = MODE_PERPACKET;
  tracelb_branch_reset(br);
  timeval_add_cs(&br->next_tx, &br->last_tx, trace->wait_probe);
  if(tracelb_branch_active(state, br) != 0)
    return -1;

  return 0;
}

static void tracelb_process_probes(scamper_task_t *task, tracelb_branch_t *br)
{
  tracelb_state_t *state = tracelb_getstate(task);
  tracelb_probe_t *pr;
  scamper_addr_t *addr = NULL;
  scamper_tracelb_probe_t *probe;
  scamper_tracelb_reply_t *reply;
  uint16_t flowid;
  uint8_t mode;
  int i, n = 0, c = 0, x = 0, hopprobe = 0;

#ifndef NDEBUG
  char *ms;
  for(i=0; i<br->probec; i++)
    {
      pr = br->probes[i]; probe = pr->probe;
      if(pr->mode == MODE_FIRSTADDR)      ms = "firstaddr";
      else if(pr->mode == MODE_FIRSTHOP)  ms = "firsthop";
      else if(pr->mode == MODE_HOPPROBE)  ms = "hopprobe";
      else if(pr->mode == MODE_BRINGFWD)  ms = "bringfwd";
      else if(pr->mode == MODE_BRINGFWD0) ms = "bringfwd0";
      else if(pr->mode == MODE_CLUMP)     ms = "clump";
      else if(pr->mode == MODE_PERPACKET) ms = "perpacket";
      else                                ms = "???";
      scamper_debug(__func__, "flow %d ttl %d rx %d %s",
		    probe->flowid, probe->ttl, probe->rxc, ms);
    }
#endif

  /* remove the branch from the active heap, if it is not already removed */
  if(br->heapnode != NULL)
    heap_delete(state->active, br->heapnode);

  assert(br->mode == MODE_FIRSTHOP  || br->mode == MODE_HOPPROBE ||
	 br->mode == MODE_PERPACKET || br->mode == MODE_CLUMP);

  /*
   * first, check the nature of the replies received; i.e. count the
   * number of probes which solicited multiple responses, and count the
   * number of probes which solicited no response.
   *
   * we will do this step twice in the face of a branch where we also
   * check for per-packet forwarding.  this is because a second
   * response may arrive to the last probe (but not any earlier ones)
   * but the decision about checking for per-packet behaviour is done
   * before the second response arrives.
   */
  flowid = br->probes[0]->probe->flowid;
  for(i=0; i<=br->probec; i++)
    {
      if(i == br->probec)
	{
	  if(x == 0 && hopprobe != 0)
	    n++;
	  break;
	}

      pr    = br->probes[i];
      probe = pr->probe;

      if(probe->flowid != flowid)
	{
	  /*
	   * if a unique flowid had no response (even with multiple
	   * attempts) then make a note of that.
	   */
	  if(x == 0 && hopprobe != 0)
	    n++;

	  flowid = probe->flowid;
	  x = 0; hopprobe = 0; addr = NULL;
	}

      /*
       * ignore what happened to probes if it isn't a probe that was
       * trying to enumerate hops.
       */
      if(pr->mode == MODE_HOPPROBE || pr->mode == MODE_FIRSTHOP ||
	 pr->mode == MODE_CLUMP)
	{
	  hopprobe = 1;

	  /* make a note that this probe got a response */
	  if(probe->rxc > 0)
	    x++;

	  /* make a note that this probe got multiple responses */
	  if(probe->rxc > 1)
	    c++;

	  /*
	   * check if probes with the same flowid got responses
	   * from different addresses.
	   */
	  if(probe->rxc == 1)
	    {
	      reply = probe->rxs[0];
	      if(addr == NULL)
		addr = reply->reply_from;
	      else if(scamper_addr_cmp(addr, reply->reply_from) != 0)
		c++;
	    }
	}
    }

  if(br->mode == MODE_PERPACKET)
    {
      if(br->k <= k(state, 2) || c > 0 || n > 0)
	mode = MODE_CLUMP;
      else
	mode = MODE_HOPPROBE;
    }
  else
    {
      if(c > 0 || n > 0)
	{
	  mode = MODE_CLUMP;
	}
      else if(br->newnodec > 1)
	{
	  if(br->mode == MODE_HOPPROBE)
	    mode = MODE_PERPACKET;
	  else
	    mode = MODE_CLUMP;
	}
      else
	{
	  mode = MODE_HOPPROBE;
	}
    }

  if(mode == MODE_HOPPROBE)
    tracelb_process_hops(task, br);
  else if(mode == MODE_CLUMP)
    tracelb_process_clump(task, br);
  else
    tracelb_process_perpacket(task, br);

  tracelb_paths_dump(state);
  tracelb_queue(task);
  return;
}

/*
 * tracelb_path_flowid
 *
 * determine if the path has a usable flowid that does not need to be
 * brought forward.
 */
static int tracelb_path_flowid(tracelb_path_t *path,
			       scamper_tracelb_probe_t *probe)
{
  tracelb_flowid_t *flowid;
  int i;

  /* check the path for a flow-id */
  for(i=path->linkc-1; i>=0; i--)
    {
      if((flowid = tracelb_link_flowid_get(path->links[i])) == NULL)
	continue;

      probe->flowid = flowid->id;
      probe->ttl    = flowid->ttl + 1;
      free(flowid);

      for(i=i+1; i<path->linkc; i++)
	probe->ttl += path->links[i]->link->hopc;

      return 1;
    }

  /*
   * if the path does not have a flow-id, descend through any prior paths
   * that only have one forward branch (to this path) for a usable flowid.
   * if one is found, then as the recursive function unwinds, the ttl is
   * incremented by the ttl of each path segment leading to it.
   */
  for(i=0; i<path->backc; i++)
    {
      if(path->back[i]->fwdc == 1 &&
	 tracelb_path_flowid(path->back[i], probe) != 0)
	{
	  for(i=0; i<path->linkc; i++)
	    probe->ttl += path->links[i]->link->hopc;

	  return 1;
	}
    }

  return 0;
}

/*
 * tracelb_probe_vals
 *
 * for the current path being traced, determine the flowid and
 * ttl values to use next.
 *
 */
static int tracelb_probe_vals(scamper_task_t *task, tracelb_branch_t *branch,
			      tracelb_probe_t *pr)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);
  tracelb_path_t *path0, *path;
  size_t len;
  int i;

#ifndef NDEBUG
  scamper_tracelb_node_t *node;
  char from[64], to[64];
#endif

  tracelb_paths_assert(state);

  /* the current path being traced is found in position zero */
  path0 = branch->path;

  /* this will be the first attempt made */
  pr->mode = branch->mode;
  pr->probe->attempt = 0;

  /*
   * look through the links traced so far in this path, starting at the most
   * recent link prior to the current link.  if a flow-id is found in
   * this link sequence then we can just probe with that at the current TTL
   * as there is some confidence there are no branches in this sequence.
   */
  if(tracelb_path_flowid(path0, pr->probe) != 0)
    {
      /* this flowid has been brought all the way forward */
      for(i=0; i<branch->bringfwdc; i++)
	branch->bringfwd[i]->k = 0;

      if(path0->linkc > 0)
	pr->link = path0->links[path0->linkc-1];
      else if(path0->backc > 0)
	pr->link = path0->back[0]->links[path0->back[0]->linkc-1];
      else
	return -1;
      return 0;
    }

  assert(trace->nodec > 0);
  assert(trace->nodes[0] != NULL);
  assert(trace->nodes[0]->linkc > 0);

  /*
   * if there are no prior path segments, then the probe is going to have
   * a brand new flowid
   */
  if(path0->back == NULL && trace->nodes[0]->linkc == 1)
    {
      pr->probe->ttl = trace->firsthop + 1;
      for(i=0; i<path0->linkc; i++)
	pr->probe->ttl += path0->links[i]->link->hopc;

      pr->probe->flowid = state->flowid_next++;
      pr->link          = path0->links[path0->linkc-1];
      return 0;
    }

  /* build the set of paths leading to the current path, if necessary */
  if(branch->bringfwd == NULL || branch->bringfwd[0]->path != path0)
    {
      /* make sure any existing state is removed */
      tracelb_bringfwd_free(branch);

      /* allocate enough entries to record all segments, if necessary */
      len = sizeof(tracelb_bringfwd_t *) * state->pathc;
      if((branch->bringfwd = malloc_zero(len)) == NULL)
	{
	  printerror(__func__, "could not malloc set");
	  return -1;
	}

      /*
       * do a depth-first traversal of the path, figuring out what sequence
       * of path segments are visited on the way up.  sort the sequence
       * into the distance from the root of the tree, so that the root of
       * the tree is the last item in the array, and the current path is
       * found at the head.
       */
      tracelb_set_visited0(state);
      if(tracelb_bringfwd_dft(branch, path0) == -1)
	return -1;
      array_qsort((void **)branch->bringfwd, branch->bringfwdc,
		  (array_cmp_t)tracelb_bringfwd_cmp);

#ifndef NDEBUG
      for(i=branch->bringfwdc-1; i>=0; i--)
	{
	  path = branch->bringfwd[i]->path;

	  if(path->linkc == 0)
	    continue;

	  node = path->links[0]->link->from;
	  if(node->addr != NULL)
	    scamper_addr_tostr(node->addr, from, sizeof(from));
	  else
	    snprintf(from, sizeof(from), "*");
	  if((node = path->links[path->linkc-1]->link->to) != NULL)
	    scamper_addr_tostr(node->addr, to, sizeof(to));
	  else
	    snprintf(to, sizeof(to), "*");

	  scamper_debug(__func__, "%d %s %s", path->distance, from, to);
	}
#endif
    }

  /*
   * sanity check that the table starts with the current path being probed
   * and extends back to the first path segment
   */
  assert(branch->bringfwd[0]->path == path0);
  assert(branch->bringfwd[branch->bringfwdc-1]->path->backc == 0);

  /* reset the visited members to zero */
  for(i=0; i<branch->bringfwdc; i++)
    branch->bringfwd[i]->path->visited = 0;

  /* we now have to bring a flowid forward through the path to probe a hop */
  pr->mode = MODE_BRINGFWD;

  /*
   * descend through the table of paths, checking to see if there is any
   * flowid available for use
   */
  for(i=1; i<branch->bringfwdc; i++)
    {
      path = branch->bringfwd[i]->path;
      if(path->visited != 0)
	{
	  continue;
	}

      if(tracelb_path_flowid(path, pr->probe) != 0)
	{
	  if(path->linkc != 0)
	    pr->link = path->links[path->linkc-1];
	  else
	    pr->link = path->back[0]->links[path->back[0]->linkc-1];
	  goto done;
	}
    }

  /*
   * there is no flowid available for use.
   * create a new one to bring forward
   */
  pr->probe->flowid = state->flowid_next++;
  pr->probe->ttl = trace->firsthop + 1;

  if(trace->nodes[0]->linkc == 1)
    {
      path = branch->bringfwd[branch->bringfwdc-1]->path;
      pr->link = path->links[path->linkc-1];

      for(i=0; i<path->linkc; i++)
	pr->probe->ttl += path->links[i]->link->hopc;
    }
  else
    {
      pr->mode = MODE_BRINGFWD0;
      pr->link = NULL;
    }

 done:
  scamper_debug(__func__, "bringfwd: ttl %d flowid %d",
		pr->probe->ttl, pr->probe->flowid);
  return 0;
}

static void tracelb_branch_cancel(scamper_task_t *task, tracelb_branch_t *br)
{
  scamper_debug(__func__, "cancelling path %p", br->path);
  tracelb_process_probes(task, br);
  return;
}

/*
 * handleicmp_reply
 *
 * add details of the reply to the link
 */
static scamper_tracelb_reply_t *handleicmp_reply(const scamper_icmp_resp_t *ir,
						 scamper_addr_t *from)
{
  scamper_tracelb_reply_t *reply;

  if((reply = scamper_tracelb_reply_alloc(from)) == NULL)
    {
      printerror(__func__, "could not allocate reply");
      return NULL;
    }

  timeval_cpy(&reply->reply_rx, &ir->ir_rx);
  reply->reply_ipid       = ir->ir_ip_id;
  reply->reply_icmp_type  = ir->ir_icmp_type;
  reply->reply_icmp_code  = ir->ir_icmp_code;
  reply->reply_icmp_q_ttl = ir->ir_inner_ip_ttl;
  reply->reply_icmp_q_tos = ir->ir_inner_ip_tos;

  if(ir->ir_ip_ttl >= 0)
    {
      reply->reply_ttl    = (uint8_t)ir->ir_ip_ttl;
      reply->reply_flags |= SCAMPER_TRACELB_REPLY_FLAG_REPLY_TTL;
    }

  if(ir->ir_ext != NULL &&
     scamper_icmpext_parse(&reply->reply_icmp_ext,
			   ir->ir_ext, ir->ir_extlen) != 0)
    {
      scamper_debug(__func__, "could not include icmp extension data");
      scamper_tracelb_reply_free(reply);
      return NULL;
    }

  return reply;
}

static scamper_tracelb_reply_t *handletcp_reply(const scamper_dl_rec_t *dl,
						scamper_addr_t *from)
{
  scamper_tracelb_reply_t *reply;

  if((reply = scamper_tracelb_reply_alloc(from)) == NULL)
    {
      printerror(__func__, "could not allocate reply");
      return NULL;
    }

  timeval_cpy(&reply->reply_rx, &dl->dl_tv);
  reply->reply_flags      = SCAMPER_TRACELB_REPLY_FLAG_TCP;
  reply->reply_flags     |= SCAMPER_TRACELB_REPLY_FLAG_REPLY_TTL;
  reply->reply_ttl        = dl->dl_ip_ttl;
  reply->reply_tcp_flags  = dl->dl_tcp_flags;
  reply->reply_ipid       = dl->dl_ip_id;

  return reply;
}

/*
 * handleicmp_firstaddr
 *
 * handle recording the first address discovered in the IP path.
 */
static void handleicmp_firstaddr(scamper_task_t *task, scamper_icmp_resp_t *ir,
				 tracelb_probe_t *pr, scamper_addr_t *from)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);
  tracelb_branch_t *branch = pr->branch;
  scamper_tracelb_node_t *node = NULL;

  assert(pr->probe->ttl == trace->firsthop);
  assert(trace->nodes == NULL);

  heap_delete(state->active, branch->heapnode);

  /* record the details of the first hop */
  if((node = scamper_tracelb_node_alloc(from)) == NULL ||
     tracelb_node_ptr(task, node) != 0 ||
     scamper_tracelb_node_add(trace, node) != 0)
    {
      printerror(__func__, "could not alloc node");
      goto err;
    }
  if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) || SCAMPER_ICMP_RESP_IS_UNREACH(ir))
    {
      node->flags |= SCAMPER_TRACELB_NODE_FLAG_QTTL;
      node->q_ttl  = ir->ir_inner_ip_ttl;
    }
  node = NULL;

  /* if we can't probe on, then we're done */
  if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) == 0 ||
     scamper_addr_cmp(trace->dst, from) == 0)
    {
      tracelb_branch_free(state, branch);
      tracelb_queue(task);
      return;
    }

  /* we've got the first address; now probe active branches from here */
  branch->mode = MODE_FIRSTHOP;
  tracelb_branch_reset(branch);
  timeval_add_cs(&branch->next_tx, &branch->last_tx, trace->wait_probe);
  if(tracelb_branch_waiting(state, branch) != 0)
    goto err;

  tracelb_queue(task);
  return;

 err:
  scamper_tracelb_node_free(node);
  tracelb_branch_free(state, branch);
  tracelb_handleerror(task, errno);
  return;
}

static int hopprobe_handlereply(scamper_task_t *task, tracelb_probe_t *pr,
				scamper_tracelb_reply_t *reply)
{
  tracelb_branch_t *branch = pr->branch;
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);

  if(scamper_tracelb_probe_reply(pr->probe, reply) != 0)
    {
      printerror(__func__, "could not add reply to probe");
      scamper_tracelb_reply_free(reply);
      return -1;
    }

  /*
   * if this was not the most recent probe to be sent, or it was not the first
   * response to the probe, we're done.
   */
  if(branch->probes[branch->probec-1] != pr || pr->probe->rxc > 1)
    {
      return 0;
    }

  if(tracelb_newnode_find(branch, reply) == NULL)
    {
      if(tracelb_newnode_add(branch, pr->probe) != 0)
	return -1;

      if(branch->n == branch->newnodec)
	{
	  scamper_debug(__func__, "branch->n %d", branch->n);
	  branch->n++;
	}
    }

  heap_delete(state->active, branch->heapnode);
  branch->k++;

  /*
   * if a reply from the destination is received, assume that there is only
   * one link used to forward to the destination (in this case the directly
   * connected interface) and process that link now.
   *
   * otherwise, if the hop has been probed enough to the appropriate level
   * of confidence, process the links discovered.
   */
  if(branch->n >= TRACELB_CONFIDENCE_MAX_N ||
     (scamper_addr_cmp(reply->reply_from, trace->dst) == 0 &&
      branch->newnodec < 2) ||
     branch->k >= k(state, branch->n))
    {
      tracelb_process_probes(task, branch);
    }
  else
    {
      timeval_add_cs(&branch->next_tx, &branch->last_tx, trace->wait_probe);
      if(tracelb_branch_active(state, branch) != 0)
	return -1;

      tracelb_queue(task);
    }

  return 0;
}

/*
 * handleicmp_hopprobe
 *
 * handle processing a reply, including recording details of the reply and
 * deciding what to do next
 */
static void handleicmp_hopprobe(scamper_task_t *task, scamper_icmp_resp_t *ir,
				tracelb_probe_t *pr, scamper_addr_t *irfrom)
{
  scamper_tracelb_reply_t *reply;

  if(pr->branch == NULL)
    return;

  /*
   * generate a reply to store with the probe, and then record the reply with
   * the probe
   */
  if((reply = handleicmp_reply(ir, irfrom)) == NULL ||
     hopprobe_handlereply(task, pr, reply) != 0)
    {
      tracelb_handleerror(task, errno);
    }

  return;
}

/*
 * handleicmp_perpacket
 *
 * this routine is used to check if a load balancing router at a particular
 * hop forwards on a per-packet basis.
 */
static void handleicmp_perpacket(scamper_task_t *task, scamper_icmp_resp_t *ir,
				 tracelb_probe_t *pr, scamper_addr_t *from)
{
  scamper_tracelb_t *trace     = tracelb_getdata(task);
  tracelb_state_t   *state     = tracelb_getstate(task);
  tracelb_branch_t  *branch    = pr->branch;
  scamper_tracelb_node_t *node = branch->newnodes[0]->node;
  scamper_tracelb_reply_t *reply;
  int process = 0;

  if(pr->branch == NULL)
    return;

  assert(branch->newnodec > 1);

  if((reply = handleicmp_reply(ir, from)) == NULL)
    {
      goto err;
    }
  if(scamper_tracelb_probe_reply(pr->probe, reply) != 0)
    {
      scamper_tracelb_reply_free(reply);
      goto err;
    }

  if(pr->probe->rxc == 1)
    branch->k++;

  if(tracelb_cmp_node2reply(node, reply) != 0)
    {
      process = 1;
    }
  else if(pr->probe->rxc == 1 && branch->k == k(state, 2))
    {
      process = 1;
      branch->k++;
    }

  if(process == 0)
    {
      heap_delete(state->active, branch->heapnode);
      timeval_add_cs(&branch->next_tx, &branch->last_tx, trace->wait_probe);
      if(tracelb_branch_active(state, branch) != 0)
	goto err;
      tracelb_queue(task);
    }
  else
    {
      tracelb_process_probes(task, pr->branch);
    }

  return;

 err:
  tracelb_handleerror(task, errno);
  return;
}

/*
 * handleicmp_bringfwd
 *
 * handle an ICMP reply in the bringfwd mode.
 */
static void handleicmp_bringfwd(scamper_task_t *task, scamper_icmp_resp_t *ir,
				tracelb_probe_t *pr, scamper_addr_t *from)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);
  tracelb_branch_t *branch = pr->branch;
  tracelb_probe_t *cpr;
  scamper_tracelb_reply_t *reply;
  scamper_tracelb_link_t findme;
  scamper_tracelb_node_t node;
  tracelb_link_t *tlbl;
  int i, rx, set, n;

#ifdef HAVE_SCAMPER_DEBUG
  char f[64], t[64];
#endif

  if((reply = handleicmp_reply(ir, from)) == NULL)
    {
      goto err;
    }
  if(scamper_tracelb_probe_reply(pr->probe, reply) != 0)
    {
      scamper_tracelb_reply_free(reply);
      goto err;
    }

  /*
   * check that the reply is for the current flowid/ttl combination, and
   * that the reply is the first reply for this flowid/ttl combination
   */
  cpr = branch->probes[branch->probec-1];
  if(pr->mode != cpr->mode ||
     pr->probe->flowid != cpr->probe->flowid ||
     pr->probe->ttl != cpr->probe->ttl)
    {
      return;
    }
  for(i=0, rx=0; i<=cpr->probe->attempt; i++)
    {
      rx += branch->probes[branch->probec-1-i]->probe->rxc;
    }
  if(rx != 1)
    {
      return;
    }

  memset(&node, 0, sizeof(node));
  if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) || SCAMPER_ICMP_RESP_IS_UNREACH(ir))
    {
      node.q_ttl |= ir->ir_inner_ip_ttl;
      node.flags  = SCAMPER_TRACELB_NODE_FLAG_QTTL;
    }
  node.addr = from;
  findme.to = &node;

  assert(pr->mode == MODE_BRINGFWD || pr->mode == MODE_BRINGFWD0);
  if(pr->mode == MODE_BRINGFWD)
    findme.from = pr->link->link->to;
  else
    findme.from = trace->nodes[0];

  scamper_debug(__func__, "reply link %s %s",
		scamper_addr_tostr(findme.from->addr, f, sizeof(f)),
		scamper_addr_tostr(findme.to->addr, t, sizeof(t)));

  if((tlbl = tracelb_link_find(state, &findme)) == NULL)
    {
      scamper_debug(__func__, "no matching link in trace");
      set = 1;
    }
  else
    {
      if(tracelb_link_flowid_add_tail(tlbl, pr->probe) != 0)
	goto err;

      for(i=0; i<branch->bringfwdc; i++)
	{
	  if(branch->bringfwd[i]->path->linkc == 0)
	    continue;

	  if(branch->bringfwd[i]->path->links[0] == tlbl)
	    break;
	}

      if(i != branch->bringfwdc)
	set = 0;
      else
	set = 1;
    }

  /*
   * if after trying to bring a flowid past a particular router we can't,
   * stop trying
   */
  if(pr->mode == MODE_BRINGFWD)
    {
      if(tracelb_bringfwd_set(state, branch, pr->link, set) != 0)
	{
	  tracelb_branch_cancel(task, branch);
	  branch = NULL;
	}
    }
  else
    {
      assert(pr->mode == MODE_BRINGFWD0);
      n = TRACELB_CONFIDENCE_NLIMIT(trace->nodes[0]->linkc+2);

      if(set == 0)
	branch->bringfwd0 = 0;
      else
	branch->bringfwd0++;

      scamper_debug(__func__, "i 0 k %d : %d", branch->bringfwd0, k(state, n));

      if(branch->bringfwd0 >= k(state, n))
	{
	  tracelb_branch_cancel(task, branch);
	  branch = NULL;
	}
    }

  if(branch != NULL)
    {
      heap_delete(state->active, branch->heapnode);
      timeval_add_cs(&branch->next_tx, &branch->last_tx, trace->wait_probe);
      if(tracelb_branch_active(state, branch) != 0)
	goto err;
    }

  tracelb_paths_dump(state);
  tracelb_queue(task);
  return;

 err:
  tracelb_handleerror(task, errno);
  return;
}

static void do_tracelb_handle_icmp(scamper_task_t *task,
				   scamper_icmp_resp_t *ir)
{
  static void (*const func[])(scamper_task_t *, scamper_icmp_resp_t *,
			      tracelb_probe_t *, scamper_addr_t *) = {
    NULL,                 /* MODE_RTSOCK    */
    NULL,                 /* MODE_DLHDR     */
    handleicmp_firstaddr, /* MODE_FIRSTADDR */
    handleicmp_hopprobe,  /* MODE_FIRSTHOP  */
    handleicmp_hopprobe,  /* MODE_HOPPROBE  */
    handleicmp_perpacket, /* MODE_PERPACKET */
    handleicmp_bringfwd,  /* MODE_BRINGFWD  */
    handleicmp_bringfwd,  /* MODE_BRINGFWD0 */
    handleicmp_hopprobe,  /* MODE_CLUMP     */
  };
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);
  tracelb_probe_t *pr;
  scamper_addr_t *icmpfrom = NULL;
  uint16_t id;
  uint8_t proto;
  void *addr;
  int type;

  assert(ir->ir_af == AF_INET || ir->ir_af == AF_INET6);

  /*
   * if the first probe has not been sent yet, then this cannot be a reply
   * for anything we sent.
   */
  if(state->id_next == 0)
    return;

  /*
   * ignore the message if it is received on an fd that we didn't use to send
   * it.  this is to avoid recording duplicate replies if an unbound socket
   * is in use.
   */
  if(ir->ir_fd != scamper_fd_fd_get(state->icmp))
    return;

  scamper_icmp_resp_print(ir);

  /* if the ICMP type is not something that we care for, then drop it */
  if(!((SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) ||
	SCAMPER_ICMP_RESP_IS_UNREACH(ir) ||
	SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir)) &&
       SCAMPER_ICMP_RESP_INNER_IS_SET(ir) && ir->ir_inner_ip_off == 0) &&
     !(SCAMPER_TRACELB_TYPE_IS_ICMP(trace) &&
       SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir)))
    {
      return;
    }

  if(SCAMPER_TRACELB_TYPE_IS_UDP(trace))
    {
      /*
       * if the ICMP response does not reference a UDP probe sent from our
       * source port to a destination probe we're likely to have probed, then
       * ignore the packet
       */
      if(ir->ir_inner_ip_proto != IPPROTO_UDP)
	return;

      if(trace->type == SCAMPER_TRACELB_TYPE_UDP_DPORT)
	{
	  /* if the dport varies, the sport should match */
	  if(ir->ir_inner_udp_sport != trace->sport)
	    return;
	}
      else
	{
	  /* if the sport varies, the dport should match */
	  if(ir->ir_inner_udp_dport != trace->dport)
	    return;
	}

      /* extract the id of the probe */
      if(ir->ir_af == AF_INET)
	{
	  if(ntohs(ir->ir_inner_udp_sum) == ir->ir_inner_ip_id &&
	     ir->ir_inner_udp_sum != 0)
	    {
	      id = ntohs(ir->ir_inner_udp_sum) - 1;
	    }
	  else if(ir->ir_inner_ip_id != 0)
	    {
	      id = ir->ir_inner_ip_id - 1;
	    }
	  else
	    {
	      return;
	    }
	}
      else if(ir->ir_af == AF_INET6)
	{
	  if(ir->ir_inner_udp_sum == 0)
	    return;
	  id = ntohs(ir->ir_inner_udp_sum) - 1;
	}
      else return;
    }
  else if(SCAMPER_TRACELB_TYPE_IS_ICMP(trace))
    {
      if(SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir) == 0)
	{
	  if(ir->ir_af == AF_INET) proto = IPPROTO_ICMP;
	  else if(ir->ir_af == AF_INET6) proto = IPPROTO_ICMPV6;
	  else return;

	  if(ir->ir_inner_ip_proto != proto          ||
	     ir->ir_inner_icmp_id  != trace->sport   ||
	     ir->ir_inner_icmp_seq >= state->id_next)
	    {
	      return;
	    }

	  id = ir->ir_inner_icmp_seq;
	}
      else
	{
	  if(ir->ir_icmp_id  != trace->sport ||
	     ir->ir_icmp_seq >= state->id_next)
	    {
	      return;
	    }

	  id = ir->ir_icmp_seq;
	}
    }
  else if(SCAMPER_TRACELB_TYPE_IS_TCP(trace))
    {
      /*
       * if the ICMP response does not reference a UDP probe sent from our
       * source port to a destination probe we're likely to have probed, then
       * ignore the packet
       */
      if(ir->ir_inner_ip_proto != IPPROTO_TCP ||
	 ir->ir_inner_tcp_dport != trace->dport)
	{
	  return;
	}

      if(ir->ir_inner_ip_id != 0)
	id = ir->ir_inner_ip_id - 1;
      else
	return;
    }
  else return;

  /* make sure the id is in range */
  if(id >= state->id_next)
    {
      return;
    }
  pr = state->probes[id];

  if(pr->branch == NULL)
    {
      scamper_debug(__func__, "pr->branch is null");
      return;
    }

  /* get the address of the icmp response */
  if(ir->ir_af == AF_INET)
    {
      type = SCAMPER_ADDR_TYPE_IPV4;
      addr = &ir->ir_ip_src.v4;
    }
  else
    {
      type = SCAMPER_ADDR_TYPE_IPV6;
      addr = &ir->ir_ip_src.v6;
    }

  if((icmpfrom = tracelb_addr(state, type, addr)) == NULL)
    {
      tracelb_handleerror(task, errno);
      return;
    }

  func[pr->mode](task, ir, pr, icmpfrom);
  return;
}

/*
 * handletimeout_firstaddr
 *
 * if a reply for the first set of probes sent into the network is not
 * received, then abandon
 */
static void handletimeout_firstaddr(scamper_task_t *task, tracelb_branch_t *br)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);
  scamper_tracelb_node_t *node = NULL;

  heap_delete(state->active, br->heapnode);

  if((node = scamper_tracelb_node_alloc(NULL)) == NULL ||
     tracelb_node_ptr(task, node) != 0 ||
     scamper_tracelb_node_add(trace, node) != 0)
    {
      printerror(__func__, "could not alloc node");
      goto err;
    }
  node = NULL;

  br->mode = MODE_FIRSTHOP;
  tracelb_branch_reset(br);
  timeval_add_cs(&br->next_tx, &br->last_tx, trace->wait_probe);
  if(tracelb_branch_waiting(state, br) != 0)
    goto err;

  tracelb_queue(task);
  return;

 err:
  scamper_tracelb_node_free(node);
  tracelb_branch_free(state, br);
  tracelb_handleerror(task, errno);
  return;
}

/*
 * handletimeout_abandon
 *
 * if no route is received in response to a route socket query or datalink
 * header request, then abandon
 */
static void handletimeout_abandon(scamper_task_t *task, tracelb_branch_t *br)
{
  tracelb_state_t *state = tracelb_getstate(task);
  heap_delete(state->active, br->heapnode);
  tracelb_branch_free(state, br);
  tracelb_queue(task);
  return;
}

/*
 * handletimeout_hopprobe
 *
 * if a reply for a probe is not received, record that fact with a null
 * record.  if the number of lost probes now takes us to the confidence level
 * required, then halt further probing of this particular hop.
 */
static void handletimeout_hopprobe(scamper_task_t *task, tracelb_branch_t *br)
{
  tracelb_state_t *state = tracelb_getstate(task);

  br->l++;

  assert(br->mode == MODE_FIRSTHOP || br->mode == MODE_HOPPROBE ||
	 br->mode == MODE_CLUMP);

  /*
   * stop probing the link when the number of replies and the number of
   * lost probes reach the required confidence level
   */
  if((br->k + br->l) >= k(state, br->n))
    {
      tracelb_process_probes(task, br);
    }
  else
    {
      tracelb_queue(task);
    }
  return;
}

/*
 * handletimeout_perpacket
 *
 */
static void handletimeout_perpacket(scamper_task_t *task, tracelb_branch_t *br)
{
  assert(br->newnodec > 1);
  tracelb_process_probes(task, br);
  return;
}

static void handletimeout_bringfwd(scamper_task_t *task, tracelb_branch_t *br)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);
  tracelb_probe_t *pr = br->probes[br->probec-1];
  int cancel = 0, n;

  assert(pr->mode == MODE_BRINGFWD || pr->mode == MODE_BRINGFWD0);

  /*
   * if after trying to bring a flowid past a particular router we can't,
   * stop trying
   */
  if(pr->mode == MODE_BRINGFWD)
    {
      if(tracelb_bringfwd_set(state, br, pr->link, 1) != 0)
	{
	  cancel = 1;
	}
    }
  else
    {
      br->bringfwd0++;

      n = TRACELB_CONFIDENCE_NLIMIT(trace->nodes[0]->linkc+2);
      if(br->bringfwd0 >= k(state, n))
	{
	  cancel = 1;
	}
    }

  if(cancel != 0)
    {
      tracelb_branch_cancel(task, br);
    }

  tracelb_queue(task);
  return;
}

/*
 * do_tracelb_handle_timeout
 *
 *
 */
static void do_tracelb_handle_timeout(scamper_task_t *task)
{
  static void (*const func[])(scamper_task_t *, tracelb_branch_t *) = {
    NULL,                    /* MODE_RTSOCK    */
    NULL,                    /* MODE_DLHDR     */
    handletimeout_firstaddr, /* MODE_FIRSTADDR */
    handletimeout_hopprobe,  /* MODE_FIRSTHOP  */
    handletimeout_hopprobe,  /* MODE_HOPPROBE  */
    handletimeout_perpacket, /* MODE_PERPACKET */
    handletimeout_bringfwd,  /* MODE_BRINGFWD  */
    handletimeout_bringfwd,  /* MODE_BRINGFWD0 */
    handletimeout_hopprobe,  /* MODE_CLUMP     */
  };
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);
  tracelb_branch_t *br;
  tracelb_probe_t *pr;

  assert(heap_count(state->active) > 0 || heap_count(state->waiting) > 0);

  /*
   * if there is nothing in the active heap, then its time to try something
   * from the waiting heap.
   */
  if((br = heap_head_item(state->active)) == NULL)
    {
      tracelb_queue(task);
      return;
    }

  if(br->mode == MODE_RTSOCK || br->mode == MODE_DLHDR)
    {
      handletimeout_abandon(task, br);
      return;
    }

  /*
   * check to see if the last probe received any replies.  if it did not,
   * then we leave the decision about what to do next to other code
   */
  assert(br->probec > 0);
  pr = br->probes[br->probec-1];
  if(pr->probe->rxc == 0 && pr->probe->attempt + 1 >= trace->attempts)
    {
      func[pr->mode](task, br);
      return;
    }

  tracelb_queue(task);
  return;
}

static void handletcp_firstaddr(scamper_task_t *task, scamper_dl_rec_t *dl,
				tracelb_probe_t *pr, scamper_addr_t *from)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);
  scamper_tracelb_node_t *node = NULL;
  tracelb_branch_t *br = pr->branch;

  assert(pr->probe->ttl == trace->firsthop);
  assert(trace->nodes == NULL);

  /* don't need the branch any more */
  if(br->heapnode != NULL)
    heap_delete(state->active, br->heapnode);
  tracelb_branch_free(state, br);

  /* record the details of the first hop */
  if((node = scamper_tracelb_node_alloc(from)) == NULL ||
     tracelb_node_ptr(task, node) != 0 ||
     scamper_tracelb_node_add(trace, node) != 0)
    {
      printerror(__func__, "could not alloc node");
      goto err;
    }
  node = NULL;

  tracelb_paths_assert(state);
  tracelb_queue(task);
  return;

 err:
  scamper_tracelb_node_free(node);
  tracelb_handleerror(task, errno);
  return;
}

static void handletcp_hopprobe(scamper_task_t *task, scamper_dl_rec_t *dl,
			       tracelb_probe_t *pr, scamper_addr_t *tcpfrom)
{
  scamper_tracelb_reply_t *reply;

  if(pr->branch == NULL)
    return;

  if((reply = handletcp_reply(dl, tcpfrom)) == NULL ||
     hopprobe_handlereply(task, pr, reply) != 0)
    {
      tracelb_handleerror(task, errno);
    }

  return;
}

/*
 * handletcp_perpacket
 *
 * got a TCP response when doing the per-packet test.  this is unexpected
 * because we would have been obtaining ICMP time exceeded messages before
 * we did this test.  ignore response for now, but this should probably be
 * revised.
 */
static void handletcp_perpacket(scamper_task_t *task, scamper_dl_rec_t *dl,
				tracelb_probe_t *probe, scamper_addr_t *from)
{
  return;
}

static void do_tracelb_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  static void (* const handletcp_func[])(scamper_task_t *, scamper_dl_rec_t *,
					 tracelb_probe_t *, scamper_addr_t *) =
  {
    NULL,                /* MODE_RTSOCK    */
    NULL,                /* MODE_DLHDR     */
    handletcp_firstaddr, /* MODE_FIRSTADDR */
    handletcp_hopprobe,  /* MODE_FIRSTHOP  */
    handletcp_hopprobe,  /* MODE_HOPPROBE  */
    handletcp_perpacket, /* MODE_PERPACKET */
    NULL,                /* MODE_BRINGFWD  */
    NULL,                /* MODE_BRINGFWD0 */
    handletcp_hopprobe,  /* MODE_CLUMP     */
  };

  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t   *state = tracelb_getstate(task);
  scamper_addr_t    *from;
  tracelb_probe_t   *pr;

  if(SCAMPER_DL_IS_TCP(dl) == 0)
    return;

  /* ignore outgoing probes observed on the datalink socket */
  if(trace->type == SCAMPER_TRACELB_TYPE_TCP_SPORT)
    {
      /*
       * if the syn flag (and only the syn flag is set) then the probe
       * is probably an outgoing one
       */
      if(dl->dl_tcp_flags == TH_SYN)
	return;
    }
  else if(trace->type == SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT)
    {
      /*
       * if the ack flag (and only the ack flag is set) then the probe
       * is probably an outgoing one
       */
      if(dl->dl_tcp_flags == TH_ACK)
	return;
    }

  scamper_dl_rec_tcp_print(dl);

  if(dl->dl_tcp_sport != trace->dport)
    {
      scamper_debug(__func__, "ignoring reply sport %d dport %d",
		    dl->dl_tcp_sport, trace->dport);
      return;
    }

  /*
   * there is no easy way to determine which probe the reply is
   * for, so assume it was for the last one
   */
  assert(state->id_next > 0);
  pr = state->probes[state->id_next-1];

  if(pr->branch == NULL)
    {
      scamper_debug(__func__, "pr->branch is null");
      return;
    }

  /* if the port doesn't match the flowid sent to, ignore */
  if(pr->probe->flowid != dl->dl_tcp_dport)
    {
      scamper_debug(__func__, "ignoring reply flowid %d dport %d",
		    pr->probe->flowid, dl->dl_tcp_dport);
      return;
    }

  /* if this is an inbound packet with a timestamp attached */
  if(handletcp_func[pr->mode] != NULL)
    {
      if((from = tracelb_addr(state, trace->dst->type, dl->dl_ip_src)) == NULL)
	goto err;
      handletcp_func[pr->mode](task, dl, pr, from);
    }

  return;

 err:
  tracelb_handleerror(task, errno);
  return;
}

/*
 * tracelb_handle_dlhdr
 *
 * a datalink header has come in.  now move into probing.
 */
static void tracelb_handle_dlhdr(scamper_dlhdr_t *dlhdr)
{
  scamper_task_t *task = dlhdr->param;
  tracelb_state_t *state = tracelb_getstate(task);
  tracelb_branch_t *br;

  if(dlhdr->error != 0)
    {
      scamper_task_queue_done(task, 0);
      return;
    }

  /* there is one head item, and it is in datalink header mode */
  assert(heap_count(state->active) == 1);
  br = heap_head_item(state->active);
  assert(br->mode == MODE_DLHDR);

  /* move into probing */
  br->mode = MODE_FIRSTADDR;
  tracelb_branch_reset(br);
  scamper_task_queue_probe(task);

  return;
}

/*
 * tracelb_handle_rt
 *
 * process a route record: open the appropriate interface and determine
 * the appropriate datalink header to use when transmitting a frame
 */
static void tracelb_handle_rt(scamper_route_t *rt)
{
  scamper_task_t *task = rt->param;
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);
  tracelb_branch_t *br;
  scamper_dl_t *dl;

#ifndef _WIN32
  if(state->rtsock == NULL)
    goto done;
#endif

  if(state->route != rt)
    goto done;

  assert(heap_count(state->active) == 1);
  br = heap_head_item(state->active);
  assert(br->mode == MODE_RTSOCK);

#ifndef _WIN32
  scamper_fd_free(state->rtsock);
  state->rtsock = NULL;
#endif

  /* if there was a problem getting the ifindex, handle that */
  if(rt->error != 0 || rt->ifindex < 0)
    {
      printerror(__func__, "could not get ifindex");
      tracelb_handleerror(task, errno);
      goto done;
    }

  if((state->dl = scamper_fd_dl(rt->ifindex)) == NULL)
    {
      scamper_debug(__func__, "could not get dl for %d", rt->ifindex);
      tracelb_handleerror(task, errno);
      goto done;
    }

  /*
   * determine the underlying framing to use with each probe packet that will
   * be sent on the datalink.
   */
  br->mode = MODE_DLHDR;
  if((state->dlhdr = scamper_dlhdr_alloc()) == NULL)
    {
      tracelb_handleerror(task, errno);
      goto done;
    }
  dl = scamper_fd_dl_get(state->dl);
  state->dlhdr->dst = scamper_addr_use(trace->dst);
  state->dlhdr->gw = rt->gw != NULL ? scamper_addr_use(rt->gw) : NULL;
  state->dlhdr->ifindex = rt->ifindex;
  state->dlhdr->txtype = scamper_dl_tx_type(dl);
  state->dlhdr->param = task;
  state->dlhdr->cb = tracelb_handle_dlhdr;
  if(scamper_dlhdr_get(state->dlhdr) != 0)
    {
      tracelb_handleerror(task, errno);
      goto done;
    }

  /* we are ready to probe, so do so */
  if(br->mode == MODE_FIRSTADDR)
    {
      timeval_cpy(&state->next_tx, &br->last_tx);
      timeval_cpy(&br->next_tx, &br->last_tx);
    }

  tracelb_queue(task);

 done:
  scamper_route_free(rt);
  if(state->route == rt)
    state->route = NULL;
  return;
}

static void do_tracelb_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  scamper_file_write_tracelb(sf, trace);
  return;
}

static void tracelb_state_free(scamper_tracelb_t *trace,tracelb_state_t *state)
{
  tracelb_branch_t *br;
  tracelb_probe_t *pr;
  tracelb_host_t *th;
  int i;

  tracelb_paths_dump(state);
  tracelb_links_dump(state);

  /* free the address tree */
  if(state->addrs != NULL)
    splaytree_free(state->addrs, (splaytree_free_t)scamper_addr_free);

  /* free any outstanding ptr requests */
  if(state->ths != NULL)
    {
      while((th = dlist_head_pop(state->ths)) != NULL)
	{
	  th->dn = NULL;
	  tracelb_host_free(state, th);
	}
      dlist_free(state->ths);
    }

  /* free the active branch records */
  if(state->active != NULL)
    {
      while((br = heap_remove(state->active)) != NULL)
	tracelb_branch_free(state, br);
      heap_free(state->active, NULL);
    }

  /* free the waiting branch records */
  if(state->waiting != NULL)
    {
      while((br = heap_remove(state->waiting)) != NULL)
	tracelb_branch_free(state, br);
      heap_free(state->waiting, NULL);
    }

  /* free the probe records */
  if(state->probes != NULL)
    {
      for(i=0; i<state->id_next; i++)
	{
	  pr = state->probes[i];
	  if(pr->mode == MODE_FIRSTADDR || pr->mode == MODE_BRINGFWD ||
	     pr->mode == MODE_BRINGFWD0)
	    {
	      scamper_tracelb_probe_free(pr->probe);
	    }
	  free(pr);
	}
      free(state->probes);
    }

  /* free the path segments built up as the tracelb progressed */
  if(state->paths != NULL)
    {
      for(i=0; i<state->pathc; i++)
	tracelb_path_free(state->paths[i]);
      free(state->paths);
    }

  /* free the link records */
  if(state->links != NULL)
    {
      for(i=0; i<state->linkc; i++)
	tracelb_link_free(state->links[i]);
      free(state->links);
    }

  if(state->icmp != NULL)     scamper_fd_free(state->icmp);
  if(state->dl != NULL)       scamper_fd_free(state->dl);
#ifndef _WIN32
  if(state->rtsock != NULL)   scamper_fd_free(state->rtsock);
#endif
  if(state->dlhdr != NULL)    scamper_dlhdr_free(state->dlhdr);
  if(state->route != NULL)    scamper_route_free(state->route);

  switch(trace->type)
    {
    case SCAMPER_TRACELB_TYPE_UDP_DPORT:
    case SCAMPER_TRACELB_TYPE_ICMP_ECHO:
      if(state->probe != NULL)
	scamper_fd_free(state->probe);
      break;

    case SCAMPER_TRACELB_TYPE_UDP_SPORT:
    case SCAMPER_TRACELB_TYPE_TCP_SPORT:
    case SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT:
      break;
    }

  free(state);
  return;
}

static void do_tracelb_halt(scamper_task_t *task)
{
  scamper_task_queue_done(task, 0);
  return;
}

static void do_tracelb_free(scamper_task_t *task)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t *state = tracelb_getstate(task);

  if(trace == NULL)
    {
      assert(state == NULL);
      return;
    }

  /* free any state kept */
  if(state != NULL)
    tracelb_state_free(trace, state);

  /* free trace data collected */
  scamper_tracelb_free(trace);

  return;
}

static void tracelb_branch_onremove(void *item)
{
  ((tracelb_branch_t *)item)->heapnode = NULL;
  return;
}

/*
 * tracelb_state_alloc
 *
 * allocate the per-tracelb state data structures to be kept.
 * also decide on where to start.
 */
static int tracelb_state_alloc(scamper_task_t *task)
{
  scamper_tracelb_t *trace  = tracelb_getdata(task);
  tracelb_state_t   *state  = NULL;
  void              *addr   = trace->src->addr;
  tracelb_branch_t  *branch;

  assert(trace != NULL);

  if((state = malloc_zero(sizeof(tracelb_state_t))) == NULL)
    {
      printerror(__func__, "could not malloc state");
      goto err;
    }

  switch(trace->confidence)
    {
    case 95:
      state->confidence = 0;
      break;

    case 99:
      state->confidence = 1;
      break;

    default:
      goto err;
    }

  if((state->addrs = splaytree_alloc((splaytree_cmp_t)scamper_addr_cmp))==NULL)
    {
      printerror(__func__, "could not alloc addr tree");
      goto err;
    }

  if((state->active = heap_alloc((heap_cmp_t)tracelb_branch_active_cmp))==NULL)
    {
      printerror(__func__, "could not alloc active heap");
      goto err;
    }
  heap_onremove(state->active, tracelb_branch_onremove);
  if((state->waiting=heap_alloc((heap_cmp_t)tracelb_branch_waiting_cmp))==NULL)
    {
      printerror(__func__, "could not alloc waiting heap");
      goto err;
    }
  heap_onremove(state->waiting, tracelb_branch_onremove);

  if((branch = malloc_zero(sizeof(tracelb_branch_t))) == NULL)
    {
      printerror(__func__, "could not alloc branch");
      goto err;
    }

  if(SCAMPER_TRACELB_TYPE_VARY_SPORT(trace))
    {
      branch->mode = MODE_RTSOCK;

#ifndef _WIN32
      if((state->rtsock = scamper_fd_rtsock()) == NULL)
	{
	  goto err;
	}
#endif
    }
  else
    {
      branch->mode = MODE_FIRSTADDR;
    }
  tracelb_branch_reset(branch);
  if(tracelb_branch_waiting(state, branch) != 0)
    goto err;

  /* get the fds to probe and listen with */
  if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      if(trace->type == SCAMPER_TRACELB_TYPE_UDP_DPORT)
	{
	  if((state->probe = scamper_fd_udp4(addr, trace->sport)) == NULL)
	    goto err;
	}
      else if(trace->type == SCAMPER_TRACELB_TYPE_ICMP_ECHO)
	{
	  if((state->probe = scamper_fd_icmp4(addr)) == NULL)
	    goto err;
	}
      else if(SCAMPER_TRACELB_TYPE_VARY_SPORT(trace) == 0)
	{
	  goto err;
	}

      if(SCAMPER_TRACELB_TYPE_IS_TCP(trace))
	state->payload_size = 0;
      else
	state->payload_size = trace->probe_size - 28;

      state->icmp = scamper_fd_icmp4(addr);
    }
  else if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      if(trace->type == SCAMPER_TRACELB_TYPE_UDP_DPORT)
	{
	  if((state->probe = scamper_fd_udp6(addr, trace->sport)) == NULL)
	    goto err;
	}
      else if(trace->type == SCAMPER_TRACELB_TYPE_ICMP_ECHO)
	{
	  if((state->probe = scamper_fd_icmp6(addr)) == NULL)
	    goto err;
	}
      else if(trace->type != SCAMPER_TRACELB_TYPE_UDP_SPORT)
	{
	  goto err;
	}

      state->icmp         = scamper_fd_icmp6(addr);
      state->payload_size = trace->probe_size - 48;
    }
  else goto err;

  /* allocate a larger global pktbuf if needed */
  if(pktbuf_len < state->payload_size)
    {
      if(realloc_wrap((void **)&pktbuf, state->payload_size) != 0)
	{
	  printerror(__func__, "could not realloc");
	  goto err;
	}
      pktbuf_len = state->payload_size;
    }

  if(state->icmp == NULL)
    {
      goto err;
    }

  switch(trace->type)
    {
    case SCAMPER_TRACELB_TYPE_UDP_DPORT:
      state->flowid_next = trace->dport;
      break;

    case SCAMPER_TRACELB_TYPE_ICMP_ECHO:
      state->flowid_next = 1;
      break;

    case SCAMPER_TRACELB_TYPE_UDP_SPORT:
    case SCAMPER_TRACELB_TYPE_TCP_SPORT:
    case SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT:
      state->flowid_next = trace->sport;
      break;

    default:
      goto err;
    }

  scamper_task_setstate(task, state);
  return 0;

 err:
  tracelb_state_free(trace, state);
  return -1;
}

static void do_tracelb_probe(scamper_task_t *task)
{
  scamper_tracelb_t *trace = tracelb_getdata(task);
  tracelb_state_t   *state = tracelb_getstate(task);
  tracelb_branch_t  *branch;
  tracelb_probe_t   *tp = NULL;
  tracelb_probe_t   *tpl;
  scamper_probe_t    probe;
  uint16_t           u16;

  assert(trace != NULL);

  if(state == NULL)
    {
      /* timestamp when the trace began */
      gettimeofday_wrap(&trace->start);

      /* allocate state and store it with the task */
      if(tracelb_state_alloc(task) != 0)
	goto err;

      state = tracelb_getstate(task);
    }

  /* select an appropriate branch to probe */
  if((branch = heap_remove(state->active)) == NULL)
    {
      branch = heap_remove(state->waiting);
    }
  assert(branch != NULL);

  if(branch->mode == MODE_RTSOCK)
    {
      state->route = scamper_route_alloc(trace->dst, task, tracelb_handle_rt);
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
	{
	  tracelb_branch_free(state, branch);
	  return;
	}

      if(branch->mode == MODE_RTSOCK || branch->mode == MODE_DLHDR)
	{
	  /*
	   * re-queue the tracelb. have to setup the time values in the
	   * branch and state structs as part of this.
	   */
	  gettimeofday_wrap(&branch->last_tx);
	  timeval_add_cs(&state->next_tx,&branch->last_tx,trace->wait_probe);
	  timeval_add_s(&branch->next_tx,&branch->last_tx,trace->wait_timeout);
	  if(tracelb_branch_active(state, branch) != 0)
	    goto err;
	  tracelb_queue(task);
	  return;
	}
    }

  /* get a reference to the previous probe sent, if there is one */
  if(branch->probec > 0)
    {
      tpl = branch->probes[branch->probec-1];
    }
  else tpl = NULL;

  /* allocate a probe structure to record state of the probe to be sent */
  if((tp = malloc_zero(sizeof(tracelb_probe_t))) == NULL ||
     (tp->probe = scamper_tracelb_probe_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc probe");
      goto err;
    }

  assert((tpl != NULL && tpl->probe->rxc == 0 &&
	  tpl->probe->attempt+1 < trace->attempts) ||
	 branch->mode == MODE_FIRSTADDR || branch->mode == MODE_FIRSTHOP ||
	 branch->mode == MODE_HOPPROBE  || branch->mode == MODE_PERPACKET ||
	 branch->mode == MODE_CLUMP);

  /* default mode, can be changed to something more specific if appropriate */
  tp->mode = branch->mode;

  if(tpl != NULL && tpl->probe->rxc == 0 &&
     tpl->probe->attempt+1 < trace->attempts)
    {
      /*
       * if a reply to the previous probe was not received and the allotted
       * number of attempts is not yet reached, retransmit
       */
      tp->probe->flowid  = tpl->probe->flowid;
      tp->probe->ttl     = tpl->probe->ttl;
      tp->probe->attempt = tpl->probe->attempt + 1;
      tp->link           = tpl->link;
      tp->mode           = tpl->mode;
    }
  else if(branch->mode == MODE_FIRSTADDR)
    {
      /* probe to determine the address of the first hop. */
      assert(trace->nodec == 0);
      tp->probe->flowid  = state->flowid_next;
      tp->probe->ttl     = trace->firsthop;
      tp->probe->attempt = 0;
    }
  else if(branch->mode == MODE_FIRSTHOP)
    {
      /* still enumerating the first set of links */
      assert(trace->nodec > 0);
      tp->probe->flowid  = state->flowid_next++;
      tp->probe->ttl     = trace->firsthop + 1;
      tp->probe->attempt = 0;
    }
  else if(branch->mode == MODE_HOPPROBE || branch->mode == MODE_CLUMP)
    {
      /*
       * call a function that can deal with the possibly complex details of
       * selecting a flowid/ttl to probe with
       */
      if(tracelb_probe_vals(task, branch, tp) < 0)
	goto err;
    }
  else if(branch->mode == MODE_PERPACKET)
    {
      assert(branch->newnodec > 1);
      tp->probe->flowid  = branch->newnodes[0]->probe->flowid;
      tp->probe->ttl     = branch->newnodes[0]->probe->ttl;
      tp->probe->attempt = 0;
    }

  memset(&probe, 0, sizeof(probe));
  probe.pr_ip_src    = trace->src;
  probe.pr_ip_dst    = trace->dst;
  probe.pr_ip_tos    = trace->tos;
  probe.pr_data      = pktbuf;
  probe.pr_len       = state->payload_size;
  probe.pr_ip_ttl    = tp->probe->ttl;

  if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    probe.pr_ip_off  = IP_DF;

  /* reset the payload of the packet */
  memset(probe.pr_data, 0, probe.pr_len);

  if(SCAMPER_TRACELB_TYPE_IS_UDP(trace))
    {
      probe.pr_ip_proto = IPPROTO_UDP;
      probe.pr_ip_id    = state->id_next + 1;

      if(trace->type == SCAMPER_TRACELB_TYPE_UDP_DPORT)
	{
	  probe.pr_fd        = scamper_fd_fd_get(state->probe);
	  probe.pr_udp_sport = trace->sport;
	  probe.pr_udp_dport = tp->probe->flowid;
	}
      else
	{
	  probe.pr_udp_dport = trace->dport;
	  probe.pr_udp_sport = tp->probe->flowid;
	}

      /*
       * fudge it so the probe id goes into the checksum field.
       * the probe id also goes in the IP-ID field to guard against FreeBSD
       * systems that munge the checksum on rx when checking the packet.
       */
      u16 = htons(state->id_next + 1);
      memcpy(probe.pr_data, &u16, 2);
      if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	{
	  probe.pr_ip_id = state->id_next + 1;
	  u16 = scamper_udp4_cksum(&probe);
	}
      else
	{
	  u16 = scamper_udp6_cksum(&probe);
	}
      memcpy(probe.pr_data, &u16, 2);
    }
  else if(SCAMPER_TRACELB_TYPE_IS_ICMP(trace))
    {
      probe.pr_fd = scamper_fd_fd_get(state->probe);
      SCAMPER_PROBE_ICMP_ECHO(&probe, trace->sport, state->id_next);

      /* this is the flow-id to use -- the ICMP checksum */
      u16 = htons(tp->probe->flowid);
      probe.pr_icmp_sum = u16;

      /* fudge the checksum field so it is used as the flow id */
      memcpy(probe.pr_data, &u16, 2);
      if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	u16 = scamper_icmp4_cksum(&probe);
      else
	u16 = scamper_icmp6_cksum(&probe);
      memcpy(probe.pr_data, &u16, 2);
    }
  else
    {
      assert(SCAMPER_TRACELB_TYPE_IS_TCP(trace));

      probe.pr_ip_proto  = IPPROTO_TCP;
      probe.pr_tcp_dport = trace->dport;
      probe.pr_tcp_sport = tp->probe->flowid;
      probe.pr_tcp_seq   = 0;
      probe.pr_tcp_ack   = 0;
      probe.pr_tcp_win   = 0;
      probe.pr_ip_id     = state->id_next + 1;

      if(trace->type == SCAMPER_TRACELB_TYPE_TCP_SPORT)
	probe.pr_tcp_flags = TH_SYN;
      else
	probe.pr_tcp_flags = TH_ACK;
    }

  if(SCAMPER_TRACELB_TYPE_VARY_SPORT(trace))
    {
      probe.pr_dl        = scamper_fd_dl_get(state->dl);
      probe.pr_dl_buf    = state->dlhdr->buf;
      probe.pr_dl_len    = state->dlhdr->len;
    }

  if(scamper_probe(&probe) == -1)
    {
      errno = probe.pr_errno;
      goto err;
    }

  /* another probe sent */
  trace->probec++;

  /* make a note that the probe was sent */
  timeval_cpy(&tp->probe->tx, &probe.pr_tx);

  /* record the probe in state */
  if(tracelb_probe_add(state, branch, tp) != 0)
    goto err;

  /* figure out when the next probe may be sent */
  timeval_add_cs(&state->next_tx, &probe.pr_tx, trace->wait_probe);

  /*
   * put the branch back in the heap structure, but with appropriate
   * timestamps
   */
  timeval_cpy(&branch->last_tx, &probe.pr_tx);
  branch->next_tx.tv_sec  = probe.pr_tx.tv_sec + trace->wait_timeout;
  branch->next_tx.tv_usec = probe.pr_tx.tv_usec;
  if(tracelb_branch_active(state, branch) != 0)
    goto err;

  tracelb_queue(task);
  return;

 err:
  if(tp != NULL) free(tp);
  tracelb_handleerror(task, errno);
  return;
}

static int tracelb_arg_param_validate(int optid, char *param, long long *out)
{
  long tmp;

  switch(optid)
    {
    case TRACE_OPT_CONFIDENCE:
      if(string_tolong(param, &tmp) != 0 || (tmp != 95 && tmp != 99))
	{
	  goto err;
	}
      break;

    case TRACE_OPT_SPORT:
    case TRACE_OPT_DPORT:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_PORT_MIN ||
	 tmp > SCAMPER_DO_TRACELB_PORT_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_FIRSTHOP:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_FIRSTHOP_MIN ||
	 tmp > SCAMPER_DO_TRACELB_FIRSTHOP_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_GAPLIMIT:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_GAPLIMIT_MIN ||
	 tmp > SCAMPER_DO_TRACELB_GAPLIMIT_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_OPTION:
      tmp = 0;
      if(strcasecmp(param, "ptr") != 0)
	goto err;
      break;

    case TRACE_OPT_PROTOCOL:
      if(strcasecmp(param, "udp-dport") == 0)
	tmp = SCAMPER_TRACELB_TYPE_UDP_DPORT;
      else if(strcasecmp(param, "icmp-echo") == 0)
	tmp = SCAMPER_TRACELB_TYPE_ICMP_ECHO;
      else if(strcasecmp(param, "udp-sport") == 0)
	tmp = SCAMPER_TRACELB_TYPE_UDP_SPORT;
      else if(strcasecmp(param, "tcp-sport") == 0)
	tmp = SCAMPER_TRACELB_TYPE_TCP_SPORT;
      else if(strcasecmp(param, "tcp-ack-sport") == 0)
	tmp = SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT;
      else
	goto err;
      break;

    case TRACE_OPT_TOS:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_TOS_MIN || tmp > SCAMPER_DO_TRACELB_TOS_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_ATTEMPTS:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_ATTEMPTS_MIN ||
	 tmp > SCAMPER_DO_TRACELB_ATTEMPTS_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_PROBECMAX:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_PROBECMAX_MIN ||
	 tmp > SCAMPER_DO_TRACELB_PROBECMAX_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_WAITPROBE:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_WAITPROBE_MIN ||
	 tmp > SCAMPER_DO_TRACELB_WAITPROBE_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_WAITTIMEOUT:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_WAITTIMEOUT_MIN ||
	 tmp > SCAMPER_DO_TRACELB_WAITTIMEOUT_MAX)
	{
	  goto err;
	}
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
 * scamper_do_tracelb_alloc
 *
 * given a string representing a traceroute task, parse the parameters and
 * assemble a trace.  return the trace structure so that it is all ready to
 * go.
 */
void *scamper_do_tracelb_alloc(char *str)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_tracelb_t *trace = NULL;
  uint8_t  type         = SCAMPER_TRACELB_TYPE_UDP_DPORT;
  uint16_t sport        = scamper_sport_default();
  uint8_t  confidence   = 95;
  uint16_t dport        = SCAMPER_DO_TRACELB_DPORT_DEF;
  uint8_t  attempts     = SCAMPER_DO_TRACELB_ATTEMPTS_DEF;
  uint8_t  firsthop     = SCAMPER_DO_TRACELB_FIRSTHOP_DEF;
  uint8_t  wait_timeout = SCAMPER_DO_TRACELB_WAITTIMEOUT_DEF;
  uint8_t  wait_probe   = SCAMPER_DO_TRACELB_WAITPROBE_DEF;
  uint8_t  tos          = SCAMPER_DO_TRACELB_TOS_DEF;
  uint32_t probec_max   = SCAMPER_DO_TRACELB_PROBECMAX_DEF;
  uint8_t  gaplimit     = SCAMPER_DO_TRACELB_GAPLIMIT_DEF;
  uint32_t userid       = 0;
  uint8_t  flags        = 0;
  char *addr;
  long long tmp = 0;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      goto err;
    }

  /* if there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 tracelb_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	case TRACE_OPT_CONFIDENCE:
	  confidence = (uint8_t)tmp;
	  break;

	case TRACE_OPT_DPORT:
	  dport = (uint16_t)tmp;
	  break;

	case TRACE_OPT_FIRSTHOP:
	  firsthop = (uint8_t)tmp;
	  break;

	case TRACE_OPT_GAPLIMIT:
	  gaplimit = (uint8_t)tmp;
	  break;

	case TRACE_OPT_OPTION:
	  if(strcasecmp(opt->str, "ptr") == 0)
	    flags |= SCAMPER_TRACELB_FLAG_PTR;
	  else
	    {
	      scamper_debug(__func__, "unknown option %s", opt->str);
	      goto err;
	    }
	  break;

	case TRACE_OPT_PROTOCOL:
	  type = (uint8_t)tmp;
	  break;

	case TRACE_OPT_TOS:
	  tos = (uint8_t)tmp;
	  break;

	case TRACE_OPT_ATTEMPTS:
	  attempts = (uint8_t)tmp;
	  break;

	case TRACE_OPT_PROBECMAX:
	  probec_max = (uint32_t)tmp;
	  break;

	case TRACE_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case TRACE_OPT_WAITPROBE:
	  wait_probe = (uint8_t)tmp;
	  break;

	case TRACE_OPT_WAITTIMEOUT:
	  wait_timeout = (uint8_t)tmp;
	  break;
	}
    }

  scamper_options_free(opts_out); opts_out = NULL;

  if((trace = scamper_tracelb_alloc()) == NULL)
    {
      goto err;
    }

  if((trace->dst = scamper_addr_resolve(AF_UNSPEC, addr)) == NULL)
    {
      goto err;
    }

  if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV6 &&
     SCAMPER_TRACELB_TYPE_IS_TCP(trace))
    {
      goto err;
    }

  trace->sport        = sport;
  trace->dport        = dport;
  trace->tos          = tos;
  trace->firsthop     = firsthop;
  trace->wait_timeout = wait_timeout;
  trace->wait_probe   = wait_probe;
  trace->attempts     = attempts;
  trace->confidence   = confidence;
  trace->type         = type;
  trace->probec_max   = probec_max;
  trace->gaplimit     = gaplimit;
  trace->userid       = userid;
  trace->flags        = flags;

  switch(trace->dst->type)
    {
    case SCAMPER_ADDR_TYPE_IPV4:
      if(SCAMPER_TRACELB_TYPE_IS_TCP(trace))
	trace->probe_size = 40;
      else
	trace->probe_size = 44;
      break;

    case SCAMPER_ADDR_TYPE_IPV6:
      trace->probe_size = 60;
      break;

    default:
      goto err;
    }

  return trace;

 err:
  if(trace != NULL) scamper_tracelb_free(trace);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

scamper_task_t *scamper_do_tracelb_alloctask(void *data,
					     scamper_list_t *list,
					     scamper_cycle_t *cycle)
{
  scamper_tracelb_t *trace = (scamper_tracelb_t *)data;
  scamper_task_sig_t *sig = NULL;
  scamper_task_t *task = NULL;

  /* allocate a task structure and store the trace with it */
  if((task = scamper_task_alloc(trace, &funcs)) == NULL)
    goto err;

  /* declare the signature of the task */
  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
    goto err;
  sig->sig_tx_ip_dst = scamper_addr_use(trace->dst);
  if(trace->src == NULL && (trace->src = scamper_getsrc(trace->dst,0)) == NULL)
    goto err;
  sig->sig_tx_ip_src = scamper_addr_use(trace->src);
  if(scamper_task_sig_add(task, sig) != 0)
    goto err;
  sig = NULL;

  /* associate the list and cycle with the trace */
  trace->list  = scamper_list_use(list);
  trace->cycle = scamper_cycle_use(cycle);

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

/*
 * scamper_do_tracelb_arg_validate
 *
 *
 */
int scamper_do_tracelb_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  tracelb_arg_param_validate);
}

void scamper_do_tracelb_free(void *data)
{
  scamper_tracelb_free((scamper_tracelb_t *)data);
  return;
}

void scamper_do_tracelb_cleanup(void)
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  return;
}

int scamper_do_tracelb_init(void)
{
  funcs.probe          = do_tracelb_probe;
  funcs.handle_icmp    = do_tracelb_handle_icmp;
  funcs.handle_dl      = do_tracelb_handle_dl;
  funcs.handle_timeout = do_tracelb_handle_timeout;
  funcs.write          = do_tracelb_write;
  funcs.task_free      = do_tracelb_free;
  funcs.halt           = do_tracelb_halt;

  return 0;
}
