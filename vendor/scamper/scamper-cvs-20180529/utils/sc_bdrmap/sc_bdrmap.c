/*
 * sc_bdrmap: driver to map first hop border routers of networks
 *
 * $Id: sc_bdrmap.c,v 1.12 2018/03/16 05:45:28 mjl Exp $
 *
 *         Matthew Luckie
 *         mjl@caida.org / mjl@wand.net.nz
 *
 * Copyright (C) 2014-2015 The Regents of the University of California
 * Copyright (C) 2015-2016 The University of Waikato
 * Copyright (C) 2017      The Regents of the University of California
 * Copyright (C) 2018      The University of Waikato
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
  "$Id: sc_bdrmap.c,v 1.12 2018/03/16 05:45:28 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "ping/scamper_ping.h"
#include "trace/scamper_trace.h"
#include "dealias/scamper_dealias.h"
#include "scamper_file.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "mjl_heap.h"
#include "mjl_prefixtree.h"
#include "utils.h"

/*
 * sc_test_t
 *
 * generic structure that can map an individual test structure to its
 * type.
 */
typedef struct sc_test
{
  int                type;
  void              *data;
} sc_test_t;

/*
 * sc_target_t
 *
 * map an address that is currently being probed to a test.  record other
 * tests that are blocked because of this test in the list.
 */
typedef struct sc_target
{
  scamper_addr_t    *addr;
  sc_test_t         *test;
  slist_t           *blocked;
  splaytree_node_t  *node;
} sc_target_t;

/*
 * sc_waittest_t
 *
 * wait some time between running the specified test
 */
typedef struct sc_waittest
{
  struct timeval    tv;
  sc_test_t        *test;
} sc_waittest_t;

/*
 * sc_stree
 *
 * a tree and singly linked list, holding the same items.  used for
 * AS counts.
 */
typedef struct sc_stree
{
  splaytree_t      *tree;
  slist_t          *list;
} sc_stree_t;

/*
 * sc_router_t
 *
 * collect a set of interfaces mapped to a router and assigned an owner
 */
typedef struct sc_router
{
  uint32_t          owner_as;
  uint8_t           owner_reason;
  uint8_t           ttl;     /* earliest ttl router was observed */
  uint8_t           flags;   /* annotations on the router */
  slist_t          *addrs;   /* sc_addr2router_t belonging to this router */
  dlist_t          *adj;     /* sc_router_t that are adjacent */
  dlist_t          *prev;    /* sc_router_t that are backwards adjacent */
  sc_stree_t       *dstases; /* downstream Ases */
  sc_stree_t       *adjases; /* adjacent hops when addrs are not VP */
  sc_stree_t       *gapases; /* ASes seen after gap */
  dlist_node_t     *node;
} sc_router_t;

/*
 * sc_addr2router_t
 *
 * map an address to a router.
 */
typedef struct sc_addr2router
{
  scamper_addr_t   *addr;
  sc_router_t      *router;
  void             *data;
  uint8_t           ttlexp;
} sc_addr2router_t;

/*
 * sc_routerset_t
 *
 * hold a collection of routers in the list, and a collection of
 * addresses in the set in the tree.
 */
typedef struct sc_routerset
{
  dlist_t         *list;
  splaytree_t     *tree;
} sc_routerset_t;

/*
 * sc_asmap_t
 *
 * record all the ASes a prefix is mapped to.
 */
typedef struct sc_asmap
{
  uint32_t         *ases;
  int               asc;
} sc_asmap_t;

/*
 * sc_prefix_t
 *
 * map an individual prefix to an AS or set of ASes.
 */
typedef struct sc_prefix
{
  union
  {
    prefix4_t      *v4;
    prefix6_t      *v6;
  } pfx;
  sc_asmap_t       *asmap;
} sc_prefix_t;

/*
 * sc_prefix_nest_t
 *
 * data structure to organise nested prefixes so that the gaps in
 * the prefixes can be found.
 */
typedef struct sc_prefix_nest
{
  sc_prefix_t      *pfx;
  prefixtree_t     *pt;
  slist_t          *list;
} sc_prefix_nest_t;

/*
 * sc_astraces_t
 *
 * do all traceroutes towards a given AS at approximately the same time
 * so that we can use a global stop set to prevent traceroute continuing
 * beyond the same interdomain link in subsequent traceroutes.
 */
typedef struct sc_astraces
{
  sc_asmap_t       *asmap;
  sc_stree_t       *gss;
  slist_t          *dsts;
  sc_stree_t       *links;
} sc_astraces_t;

/*
 * sc_link_t
 *
 * a representation of an individual link between A and B.
 * The link may have arbitrary additional data attached.
 */
typedef struct sc_link
{
  scamper_addr_t   *a;
  scamper_addr_t   *b;
  void             *data;
} sc_link_t;

/*
 * sc_indir_t
 *
 * this structure is attached to structures that want to obtain responses
 * from an address X with TTL-limited probes to a given destination.
 */
typedef struct sc_indir
{
  scamper_addr_t *dst;
  uint8_t         ttl;
  uint16_t        csum;
} sc_indir_t;

/*
 * sc_linktest_t
 *
 * this data structure is used to
 * - complete a prefixscan test of a given link, trying different probe
 *   methods until it gets a useful response.
 * - complete a ping record route test, to see if the packet seems to
 *   come back via the same router
 * - complete a ping with pre-specified timestamps, trying to get a or
 *   ab to embed a timestamp when it returns the packet.
 *
 * the step field determines which of these three things is currently
 * being worked on.  the method says which probe method (an index into
 * the probedef_str array) is currently used, and the attempt says
 * how many times we've tried.
 */
typedef struct sc_linktest
{
  sc_link_t        *link;
  sc_target_t      *ta, *tb; /* addresses A and B for the link */
  scamper_addr_t   *ab;      /* address that makes link pt2pt */
  int               step;    /* step through the link test process */
  int               method;
  int               attempt;
} sc_linktest_t;

/*
 * sc_ping_t
 *
 * for a given address, record the useful methods for extracting
 * an incrementing IPID value.
 */
typedef struct sc_ping
{
  scamper_addr_t   *addr;
  uint8_t           methods[4];
  sc_indir_t        indir;
} sc_ping_t;

/*
 * sc_pingtest_t
 *
 */
typedef struct sc_pingtest
{
  sc_target_t      *target; /* target for ping->addr */
  sc_target_t      *t2;     /* target for ping->indir.dst */
  sc_ping_t        *ping;
  int               method;
} sc_pingtest_t;

typedef struct sc_ally
{
  scamper_addr_t   *a, *b;
  uint8_t           result;
} sc_ally_t;

/*
 * sc_allytest_t
 *
 * given a set of addresses that might be aliases (based on an IP graph)
 * test addresses for aliases.
 */
typedef struct sc_allytest
{
  sc_target_t      *a, *b;
  int               method;
  int               attempt;
  slist_t          *addr_list;
  slist_node_t     *s1, *s2;
  sc_routerset_t   *routers;
} sc_allytest_t;

/*
 * sc_allyconftest_t
 *
 * given a pair of addresses that resolved for aliases, periodically
 * check if their counters have diverged (until count reaches zero)
 */
typedef struct sc_allyconftest
{
  sc_target_t      *a, *b;
  sc_ally_t        *ally;
  int               method;
  int               count;
} sc_allyconftest_t;

/*
 * sc_tracetest_t
 *
 * this data structure is used to coordinate traceroutes towards a
 * a given AS as the traceroute for each prefix in the AS completes.
 */
typedef struct sc_tracetest
{
  sc_target_t      *target;
  sc_astraces_t    *astraces;
} sc_tracetest_t;

/*
 * sc_traceset_t
 *
 * this data structure is used to record traceroutes that might not have
 * crossed into a customer network
 */
typedef struct sc_traceset
{
  uint32_t         asn;
  slist_t         *list;
} sc_traceset_t;

/*
 * sc_asrel_t
 *
 * record the AS relationship between a and b.  -1 cust, 0 peer, 1 provider.
 * the relationship is stored so that the value of A is less than B.
 */
typedef struct sc_asrel
{
  uint32_t          a, b;
  int               r;
} sc_asrel_t;

/*
 * sc_asc_t
 *
 * utility structure to help count the number of times something mapping
 * to an ASN is seen
 */
typedef struct sc_asc
{
  uint32_t          as;
  int               c;
} sc_asc_t;

/*
 * sc_asmapc_t
 *
 * utility structure to count the number of times an ASMAP is seen.
 */
typedef struct sc_asmapc
{
  sc_asmap_t       *asmap;
  int               c;
} sc_asmapc_t;

/*
 * sc_ixpc_t
 *
 * utility structure to count the number of times an IXP prefix is seen.
 * useful for counting neighbors at an IXP.
 */
typedef struct sc_ixpc
{
  union
  {
    prefix4_t      *v4;
    prefix6_t      *v6;
    void           *ptr;
  } pfx;
  int               c;
} sc_ixpc_t;

/*
 * sc_prov_t
 *
 * record the providers of a given AS in a data structure so they can be
 * found quickly to help apply various router mapping heuristics.
 */
typedef struct sc_prov
{
  uint32_t          as;
  uint32_t         *provs;
  int               provc;
} sc_prov_t;

/*
 * sc_linkprobe_t
 *
 * this structure supplies the address, ttl, and checksum (the flow) to use
 * to find a given hop.
 */
typedef struct sc_linkprobe
{
  scamper_addr_t   *dst;
  uint8_t           ttl;
  uint16_t          csum;
} sc_linkprobe_t;

/*
 * sc_addr2name_t
 *
 * associate an IP address with a name
 */
typedef struct sc_addr2name
{
  scamper_addr_t   *addr;
  char             *name;
} sc_addr2name_t;

/*
 * sc_delegated_t
 *
 * record entry from the set of RIR files
 */
typedef struct sc_delegated
{
  struct in_addr    x;
  struct in_addr    y;
} sc_delegated_t;

/*
 * sc_addr2adj_t
 *
 * which addresses are adjacent to the specified address
 */
typedef struct sc_addr2adj
{
  scamper_addr_t   *addr;
  slist_t          *list[2];
} sc_addr2adj_t;

/*
 * sc_farrouter_t
 *
 * try and assemble likely aliases among the routers found in "nears"
 * based on inferred far routers observed in traceroute.
 */
typedef struct sc_farrouter
{
  sc_router_t      *far;
  slist_t          *nears;
} sc_farrouter_t;

typedef struct sc_dump
{
  char  *descr;
  char  *label;
  int  (*init)(void);
  int  (*proc_trace)(scamper_trace_t *trace);
  int  (*proc_ping)(scamper_ping_t *ping);
  int  (*proc_dealias)(scamper_dealias_t *dealias);
  void (*finish)(void);
} sc_dump_t;

static int init_1(void);
static int process_1_trace(scamper_trace_t *);
static int process_1_dealias(scamper_dealias_t *);
static int process_1_ping(scamper_ping_t *);
static void finish_1(void);

static int process_2_trace(scamper_trace_t *);

#define SC_ROUTER_OWNER_NONE       0
#define SC_ROUTER_OWNER_FIRST      1
#define SC_ROUTER_OWNER_TRACESET   2
#define SC_ROUTER_OWNER_PROVIDER   3
#define SC_ROUTER_OWNER_PEER       4
#define SC_ROUTER_OWNER_CUSTOMER   5
#define SC_ROUTER_OWNER_IP2AS      6
#define SC_ROUTER_OWNER_HIDDENPEER 7
#define SC_ROUTER_OWNER_COUNT      8
#define SC_ROUTER_OWNER_GRAPH      9
#define SC_ROUTER_OWNER_NOIP2AS    10
#define SC_ROUTER_OWNER_THIRDPARTY 11
#define SC_ROUTER_OWNER_IXP        12
#define SC_ROUTER_OWNER_ONENET     13
#define SC_ROUTER_OWNER_MISSING    14
#define SC_ROUTER_OWNER_FIRST2     15
#define SC_ROUTER_OWNER_COUNT2     16
#define SC_ROUTER_OWNER_COUNT3     17
#define SC_ROUTER_OWNER_THIRDPARTY2 18
#define SC_ROUTER_OWNER_ONENET2     19
#define SC_ROUTER_OWNER_SILENT      20
#define SC_ROUTER_OWNER_ICMP        21

#define SC_ROUTER_FLAG_FIRST       0x01
#define SC_ROUTER_FLAG_MERGED      0x02
#define SC_ROUTER_FLAG_VISITED     0x04

static const char *owner_reasonstr[] = {
  "none",
  "first",
  "traceset",
  "provider",
  "peer",
  "customer",
  "ip2as",
  "hidden-peer",
  "count",
  "graph",
  "noip2as",
  "thirdparty",
  "ixp",
  "onenet",
  "missing",
  "first2",
  "count2",
  "count3",
  "thirdparty2",
  "onenet2",
  "silent",
  "icmp",
};

static uint32_t               options       = 0;
static char                  *unix_name     = NULL;
static unsigned int           port          = 0;
static uint8_t                firsthop      = 1;
static uint16_t               csum          = 0x420;
static prefixtree_t          *ip2as_pt      = NULL;
static char                  *ip2as_fn      = NULL;
static splaytree_t           *ip2name_tree  = NULL;
static char                  *ip2name_fn    = NULL;
static prefixtree_t          *ixp_pt        = NULL;
static char                  *ixp_fn        = NULL;
static char                  *outfile_fn    = NULL;
static char                  *relfile_fn    = NULL;
static char                  *logfile_fn    = NULL;
static FILE                  *logfile       = NULL;
static slist_t               *prefixes      = NULL;
static scamper_file_filter_t *ffilter       = NULL;
static scamper_file_t        *outfile       = NULL;
static splaytree_t           *targets       = NULL;
static splaytree_t           *links         = NULL;
static splaytree_t           *pings         = NULL;
static splaytree_t           *allys         = NULL;
static splaytree_t           *tracesets     = NULL;
static slist_t               *virgin        = NULL;
static heap_t                *waiting       = NULL;
static splaytree_t           *asmaptree     = NULL;
static splaytree_t           *reltree       = NULL;
static splaytree_t           *provtree      = NULL;
static char                  *delegated_fn  = NULL;
static slist_t               *delegated     = NULL;
static slist_t               *held          = NULL;
static sc_routerset_t        *rtrset        = NULL;
static uint32_t              *vpas          = NULL;
static int                    vpasc         = 0;
static uint32_t              *targetas      = NULL;
static int                    targetasc     = 0;
static char                 **opt_args      = NULL;
static int                    opt_argc      = 0;
static int                    scamper_fd    = -1;
static char                  *readbuf       = NULL;
static size_t                 readbuf_len   = 0;
static int                    data_left     = 0;
static scamper_file_t        *decode_in     = NULL;
static int                    decode_in_fd  = -1;
static int                    decode_out_fd = -1;
static int                    more          = 0;
static int                    probing       = 0;
static int                    waittime      = 0;
static int                    attempts      = 5;
static int                    random_dst    = 0;
static int                    impatient     = 0;
static int                    allyconf      = 5;
static int                    allyconf_wait = 60 * 5;
static int                    dump_borders  = 0;
static int                    dump_onedsts  = 0;
static int                    dump_tracesets = 0;
static int                    no_ipopts     = 0;
static int                    no_gss        = 0;
static int                    no_self       = 0;
static int                    no_merge      = 0;
static int                    fudge         = 5000;
static int                    af            = AF_INET;
static struct timeval         now;
static char                   cmd[32768];
static int                    dump_id       = 0;
static const sc_dump_t        dump_funcs[]  = {
  {NULL, NULL, NULL, NULL},
  {"infer border routers", "routers",
   init_1, process_1_trace, process_1_ping, process_1_dealias, finish_1},
  {"dump annotated traceroutes", "traces",
   NULL,   process_2_trace, NULL,           NULL,              NULL},
};
static int dump_funcc = sizeof(dump_funcs) / sizeof(sc_dump_t);

typedef void (*sc_stree_free_t)(void *ptr);

#define OPT_IP2AS       0x000001
#define OPT_OUTFILE     0x000002
#define OPT_LOGFILE     0x000004
#define OPT_PORT        0x000008
#define OPT_UNIX        0x000010
#define OPT_DAEMON      0x000020
#define OPT_VPASES      0x000040
#define OPT_RELFILE     0x000080
#define OPT_FIRSTHOP    0x000100
#define OPT_IPV6        0x000200
#define OPT_DUMP        0x000400
#define OPT_OPTIONS     0x000800
#define OPT_IXPFILE     0x001000
#define OPT_HELP        0x002000
#define OPT_NAMEFILE    0x004000
#define OPT_TARGETIPS   0x008000
#define OPT_TARGETASES  0x010000
#define OPT_REMOTE      0x020000
#define OPT_ALLYCONF    0x040000
#define OPT_DELEGATED   0x080000
#define OPT_CSUM        0x100000

#define TEST_TRACE      0x00
#define TEST_LINK       0x01
#define TEST_PING       0x02
#define TEST_ALLY       0x03
#define TEST_ALLYCONF   0x04

#define TEST_LINK_PREFIXSCAN 0x00
#define TEST_LINK_RR         0x01
#define TEST_LINK_PSTS       0x02

/*
 * types of IPID behavior classified
 */
#define IPID_NONE   0
#define IPID_INCR   1
#define IPID_RAND   2
#define IPID_ECHO   3
#define IPID_CONST  4
#define IPID_UNRESP 5

/*
 * alias resolution probe types and their preference.
 * prefer icmp echo because it is benign.
 * prefer tcp to udp because it returns fewer false negatives --shared
 * counter held centrally (TCP) vs held on line card (UDP) on some routers.
 */
#define METHOD_ICMP  0
#define METHOD_TCP   1
#define METHOD_UDP   2
#define METHOD_INDIR 3

#define METHOD_PFXS_LAST METHOD_UDP
#define METHOD_ALLY_LAST METHOD_INDIR

/*
 * the prefix size ranges that are allowed.  in v4, we consider a prefix
 * valid if it is >= 8 && <= 24.  in v6, >= 19 && <= 48.
 */
#define IPV4_PREFIX_MIN 8
#define IPV4_PREFIX_MAX 24
#define IPV6_PREFIX_MIN 19
#define IPV6_PREFIX_MAX 48

static void usage(uint32_t opts)
{
  int i;

  fprintf(stderr,
    "usage: sc_bdrmap [-6Di] [-a ip2as] [-A targetases] [-c allyconf]\n"
    "                 [-C csum] [-f firsthop] [-l log] [-o warts]\n"
    "                 [-O option] [-p port] [-U unix] [-R unix] [-v vpases]\n"
    "                 [-x ixps]\n"
    "\n"
    "       sc_bdrmap [-6] [-a ip2as] [-A targetases] [-d dump]\n"
    "                 [-g delegated] [-n names] [-r rels] [-v vpases]\n"
    "                 [-x ixps] file1 .. fileN\n");

  if(opts == 0)
    {
      fprintf(stderr, "\n       sc_bdrmap -?\n\n");
      return;
    }
  fprintf(stderr, "\n");

  if(opts & OPT_DAEMON)
    fprintf(stderr, "       -D: become a daemon\n");
  if(opts & OPT_IPV6)
    fprintf(stderr, "       -6: input files are IPv6\n");
  if(opts & OPT_IP2AS)
    fprintf(stderr, "       -a: ip2as file\n");
  if(opts & OPT_TARGETASES)
    fprintf(stderr, "       -A: map interconnections towards specified ASes\n");
  if(opts & OPT_ALLYCONF)
    fprintf(stderr, "       -c: how many times to confirm alias inference\n");
  if(opts & OPT_CSUM)
    fprintf(stderr, "       -C: ICMP csum for Paris traceroute\n");
  if(opts & OPT_DUMP)
    {
      fprintf(stderr, "       -d: dump id\n");
      for(i=1; i<dump_funcc; i++)
	{
	  fprintf(stderr, "           %d", i);
	  if(dump_funcs[i].label != NULL)
	    fprintf(stderr, " / %s", dump_funcs[i].label);
	  fprintf(stderr, ": %s\n", dump_funcs[i].descr);
	}
    }
  if(opts & OPT_FIRSTHOP)
    fprintf(stderr, "       -f: first IP hop to probe in traceroute\n");
  if(opts & OPT_DELEGATED)
    fprintf(stderr, "       -g: delegated file\n");
  if(opts & OPT_TARGETIPS)
    fprintf(stderr, "       -i: map interconnections towards specified IPs\n");
  if(opts & OPT_LOGFILE)
    fprintf(stderr, "       -l: log activity to specified file\n");
  if(opts & OPT_NAMEFILE)
    fprintf(stderr, "       -n: IP to name file\n");
  if(opts & OPT_OUTFILE)
    fprintf(stderr, "       -o: write raw data to specified file\n");
  if(opts & OPT_OPTIONS)
    {
      fprintf(stderr, "       -O: options\n");
      fprintf(stderr, "           randomdst: probe random IPs in prefixes\n");
      fprintf(stderr, "           impatient: probe large sets first\n");
      fprintf(stderr, "           dumpborders: dump only border routers\n");
      fprintf(stderr, "           dumponedsts: annotate onedst routers\n");
      fprintf(stderr, "           dumptracesets: dump unused tracesets\n");
      fprintf(stderr, "           noipopts: do not tx probes with options\n");
      fprintf(stderr, "           nogss: do not use global stop set\n");
      fprintf(stderr, "           noself: do not print adjacent VP routers\n");
      fprintf(stderr, "           nomerge: do not analytically merge routers\n");
    }
  if(opts & OPT_PORT)
    fprintf(stderr, "       -p: find local scamper process on local port\n");
  if(opts & OPT_RELFILE)
    fprintf(stderr, "       -r: use AS relationships in specified file\n");
  if(opts & OPT_REMOTE)
    fprintf(stderr, "       -R: find remote scamper process on unix socket\n");
  if(opts & OPT_UNIX)
    fprintf(stderr, "       -U: find local scamper process on unix socket\n");
  if(opts & OPT_VPASES)
    fprintf(stderr, "       -v: ASNs that represent local network\n");
  if(opts & OPT_IXPFILE)
    fprintf(stderr, "       -x: ixp prefix file\n");

  return;
}

static int uint32_find(const uint32_t *ptr, int c, uint32_t x)
{
  int i;
  for(i=0; i<c; i++)
    if(ptr[i] == x)
      return i;
  return -1;
}

static int uint32_add(uint32_t **ptr, int *c, uint32_t x)
{
  uint32_t *a = *ptr;

  if(uint32_find(a, *c, x) >= 0)
    return 0;

  if(realloc_wrap((void **)&a, sizeof(uint32_t) * (*c + 1)) != 0)
    return -1;

  a[*c] = x;
  *ptr = a;
  *c = *c + 1;

  return 0;
}

static int uint32_cmp(const void *va, const void *vb)
{
  const uint32_t a = *((const uint32_t *)va);
  const uint32_t b = *((const uint32_t *)vb);
  if(a < b) return -1;
  if(a > b) return  1;
  return 0;
}

static int check_options_once(char ch, uint32_t flag)
{
  if((options & flag) == 0)
    return 0;

  fprintf(stderr, "-%c specified twice\n", ch);
  usage(flag);
  return -1;
}

static int vpas_line(char *line, void *param)
{
  long lo;
  if(line[0] == '\0' || line[0] == '#')
    return 0;
  if(string_tolong(line, &lo) != 0 || lo < 1 ||
     uint32_add(&vpas, &vpasc, lo) != 0)
    return -1;
  return 0;
}

static int check_options_vpas(const char *vpas_str)
{
  struct stat sb;
  char *vp = NULL, *cur, *next;
  long lo;

  if(stat(vpas_str, &sb) == 0)
    {
      if(file_lines(vpas_str, vpas_line, NULL) != 0)
	{
	  fprintf(stderr, "could not read file %s\n", vpas_str);
	  goto err;
	}
    }
  else
    {
      if((vp = strdup(vpas_str)) == NULL)
	{
	  fprintf(stderr, "could not dup vpas_str: %s\n", strerror(errno));
	  goto err;
	}
      cur = vp;
      while(cur != NULL)
	{
	  string_nullterm_char(cur, ',', &next);
	  if(string_tolong(cur, &lo) != 0 || lo < 1 ||
	     uint32_add(&vpas, &vpasc, lo) != 0)
	    {
	      fprintf(stderr, "malformed -v %s: not a file or set of ASes\n",
		      vpas_str);
	      goto err;
	    }
	  cur = next;
	}
      free(vp); vp = NULL;
    }

  return 0;

 err:
  if(vp != NULL) free(vp);
  return -1;
}

static int check_options_targetases(slist_t *list)
{
  char *opt;
  long lo;

  while((opt = slist_head_pop(list)) != NULL)
    {
      if(string_tolong(opt, &lo) != 0 || lo < 1)
	{
	  fprintf(stderr, "%s is not a valid ASN\n", opt);
	  return -1;
	}
      if(uint32_find(vpas, vpasc, lo) >= 0)
	{
	  fprintf(stderr, "%ld is also a VP ASN\n", lo);
	  return -1;
	}
      if(uint32_add(&targetas, &targetasc, lo) != 0)
	{
	  fprintf(stderr, "could not add %ld to targetas set\n", lo);
	  return -1;
	}
    }

  qsort(targetas, targetasc, sizeof(uint32_t), uint32_cmp);
  return 0;
}

static int check_options(int argc, char *argv[])
{
  int rc = -1, x = 0, ch; long lo;
  char *opts = "?6a:A:c:C:d:Df:g:il:n:o:O:p:r:R:U:v:x:";
  char *opt_port = NULL, *opt_firsthop = NULL, *opt_dumpid = NULL;
  char *opt_unix = NULL, *opt_allyconf = NULL, *opt_vpases = NULL;
  char *opt_csum = NULL;
  slist_t *opt_targetases = NULL;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      x++;
      switch(ch)
	{
	case '?':
	  options |= OPT_HELP;
	  usage(0xffffffff);
	  rc = 0;
	  goto done;

	case '6':
	  if(check_options_once(ch, OPT_IPV6) != 0)
	    goto done;
	  options |= OPT_IPV6;
	  af = AF_INET6;
	  break;

	case 'a':
	  if(check_options_once(ch, OPT_IP2AS) != 0)
	    goto done;
	  options |= OPT_IP2AS;
	  ip2as_fn = optarg;
	  break;

	case 'C':
	  if(check_options_once(ch, OPT_CSUM) != 0)
	    goto done;
	  options |= OPT_CSUM;
	  opt_csum = optarg;
	  break;

	case 'A':
	  options |= OPT_TARGETASES;
	  if(opt_targetases == NULL && (opt_targetases=slist_alloc()) == NULL)
	    goto done;
	  if(slist_tail_push(opt_targetases, optarg) == NULL)
	    goto done;
	  break;

	case 'c':
	  if(check_options_once(ch, OPT_ALLYCONF) != 0)
	    goto done;
	  options |= OPT_ALLYCONF;
	  opt_allyconf = optarg;
	  break;

	case 'd':
	  if(check_options_once(ch, OPT_DUMP) != 0)
	    goto done;
	  options |= OPT_DUMP;
	  opt_dumpid = optarg;
	  break;

	case 'D':
	  if(check_options_once(ch, OPT_DAEMON) != 0)
	    goto done;
	  options |= OPT_DAEMON;
	  break;

	case 'f':
	  if(check_options_once(ch, OPT_FIRSTHOP) != 0)
	    goto done;
	  options |= OPT_FIRSTHOP;
	  opt_firsthop = optarg;
	  break;

	case 'g':
	  if(check_options_once(ch, OPT_DELEGATED) != 0)
	    goto done;
	  options |= OPT_DELEGATED;
	  delegated_fn = optarg;
	  break;

	case 'i':
	  if(check_options_once(ch, OPT_TARGETIPS) != 0)
	    goto done;
	  options |= OPT_TARGETIPS;
	  break;

	case 'l':
	  if(check_options_once(ch, OPT_LOGFILE) != 0)
	    goto done;
	  options |= OPT_LOGFILE;
	  logfile_fn = optarg;
	  break;

	case 'o':
	  if(check_options_once(ch, OPT_OUTFILE) != 0)
	    goto done;
	  options |= OPT_OUTFILE;
	  outfile_fn = optarg;
	  break;

	case 'O':
	  options |= OPT_OPTIONS;
	  if(strcasecmp(optarg, "dumpborders") == 0)
	    dump_borders = 1;
	  else if(strcasecmp(optarg, "dumponedsts") == 0)
	    dump_onedsts = 1;
	  else if(strcasecmp(optarg, "dumptracesets") == 0)
	    dump_tracesets = 1;
	  else if(strcasecmp(optarg, "impatient") == 0)
	    impatient = 1;
	  else if(strcasecmp(optarg, "nogss") == 0)
	    no_gss = 1;
	  else if(strcasecmp(optarg, "noipopts") == 0)
	    no_ipopts = 1;
	  else if(strcasecmp(optarg, "nomerge") == 0)
	    no_merge = 1;
	  else if(strcasecmp(optarg, "noself") == 0)
	    no_self = 1;
	  else if(strcasecmp(optarg, "randomdst") == 0)
	    random_dst = 1;
	  else
	    {
	      fprintf(stderr, "unknown option %s\n", optarg);
	      goto done;
	    }
	  break;

	case 'n':
	  if(check_options_once(ch, OPT_NAMEFILE) != 0)
	    goto done;
	  options |= OPT_NAMEFILE;
	  ip2name_fn = optarg;
	  break;

	case 'p':
	  if(check_options_once(ch, OPT_PORT) != 0)
	    goto done;
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case 'r':
	  if(check_options_once(ch, OPT_RELFILE) != 0)
	    goto done;
	  options |= OPT_RELFILE;
	  relfile_fn = optarg;
	  break;

	case 'R':
	  if(check_options_once(ch, OPT_REMOTE) != 0)
	    goto done;
	  options |= OPT_REMOTE;
	  opt_unix = optarg;
	  break;

	case 'U':
	  if(check_options_once(ch, OPT_UNIX) != 0)
	    goto done;
	  options |= OPT_UNIX;
	  opt_unix = optarg;
	  break;

	case 'x':
	  if(check_options_once(ch, OPT_IXPFILE) != 0)
	    goto done;
	  options |= OPT_IXPFILE;
	  ixp_fn = optarg;
	  break;

	case 'v':
	  if(check_options_once(ch, OPT_VPASES) != 0)
	    goto done;
	  options |= OPT_VPASES;
	  opt_vpases = optarg;
	  break;
	}
    }

  if(x == 0)
    {
      usage(0);
      goto done;
    }

  opt_args = argv + optind;
  opt_argc = argc - optind;

  if((options & OPT_VPASES) == 0)
    {
      usage(OPT_VPASES);
      goto done;
    }
  if((options & OPT_IP2AS) == 0)
    {
      usage(OPT_IP2AS);
      goto done;
    }

  if(check_options_vpas(opt_vpases) != 0)
    goto done;

  if((options & (OPT_TARGETIPS|OPT_TARGETASES))==(OPT_TARGETIPS|OPT_TARGETASES))
    {
      usage(OPT_TARGETIPS|OPT_TARGETASES);
      goto done;
    }
  if(options & OPT_TARGETASES && check_options_targetases(opt_targetases) != 0)
    goto done;

  if(options & OPT_DUMP)
    {
      if(string_isnumber(opt_dumpid) != 0)
	{
	  if(string_tolong(opt_dumpid, &lo) != 0 || lo < 1 || lo > dump_funcc)
	    {
	      usage(OPT_DUMP);
	      goto done;
	    }
	  dump_id = lo;
	}
      else
	{
	  for(x=1; x<dump_funcc; x++)
	    {
	      if(dump_funcs[x].label == NULL)
		continue;
	      if(strcasecmp(dump_funcs[x].label, opt_dumpid) == 0)
		break;
	    }
	  if(x == dump_funcc)
	    {
	      usage(OPT_DUMP);
	      goto done;
	    }
	  dump_id = x;
	}

      if(opt_argc < 1)
	{
	  usage(0);
	  goto done;
	}
      rc = 0;
      goto done;
    }

  if(options & OPT_ALLYCONF)
    {
      if(string_tolong(opt_allyconf, &lo) != 0 || lo < 0 || lo > 10)
	{
	  usage(OPT_ALLYCONF);
	  goto done;
	}
      allyconf = lo;
    }

  if(options & OPT_FIRSTHOP)
    {
      if(string_tolong(opt_firsthop, &lo) != 0 || lo < 1 || lo > 4)
	{
	  usage(OPT_FIRSTHOP);
	  goto done;
	}
      firsthop = lo;
    }

  if(options & OPT_CSUM)
    {
      if(string_tolong(opt_csum, &lo) != 0 || lo < 1 || lo > 65535)
	{
	  usage(OPT_CSUM);
	  return -1;
	}
      csum = lo;
    }

  if(options & OPT_TARGETIPS)
    {
      if(opt_argc < 1)
	{
	  usage(OPT_TARGETIPS);
	  goto done;
	}
    }

  if((options & OPT_OUTFILE) == 0)
    {
      usage(OPT_OUTFILE);
      goto done;
    }
  if((options & (OPT_PORT|OPT_REMOTE|OPT_UNIX)) == 0 ||
     ((options & (OPT_PORT|OPT_REMOTE|OPT_UNIX)) != OPT_PORT &&
      (options & (OPT_PORT|OPT_REMOTE|OPT_UNIX)) != OPT_REMOTE &&
      (options & (OPT_PORT|OPT_REMOTE|OPT_UNIX)) != OPT_UNIX))
    {
      usage(OPT_PORT|OPT_REMOTE|OPT_UNIX);
      goto done;
    }

  if(options & OPT_PORT)
    {
      if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
	{
	  usage(OPT_PORT);
	  goto done;
	}
      port = lo;
    }
  else
    {
      unix_name = opt_unix;
    }

  if(logfile_fn != NULL && (logfile = fopen(logfile_fn, "w")) == NULL)
    {
      usage(OPT_LOGFILE);
      fprintf(stderr, "could not open %s\n", logfile_fn);
      goto done;
    }

  rc = 0;

 done:
  if(opt_targetases != NULL) slist_free(opt_targetases);
  return rc;
}

static int tree_to_slist(void *ptr, void *entry)
{
  if(slist_tail_push((slist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

static void logerr(char *format, ...)
{
  va_list ap;
  char msg[131072];

  if((options & OPT_DAEMON) && logfile == NULL)
    return;

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  if((options & OPT_DAEMON) == 0)
    fprintf(stderr, "%s", msg);

  if(logfile != NULL)
    {
      fprintf(logfile, "%ld: %s", (long int)now.tv_sec, msg);
      fflush(logfile);
    }

  return;
}

static void logprint(char *format, ...)
{
  va_list ap;
  char msg[131072];

  if((options & OPT_DAEMON) && logfile == NULL)
    return;

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  if((options & OPT_DAEMON) == 0)
    printf("%s", msg);

  if(logfile != NULL)
    {
      fprintf(logfile, "%ld: %s", (long int)now.tv_sec, msg);
      fflush(logfile);
    }

  return;
}

static char *class_tostr(char *str, size_t len, uint8_t class)
{
  char *ptr;

  switch(class)
    {
    case IPID_NONE:   ptr = "none"; break;
    case IPID_INCR:   ptr = "incr"; break;
    case IPID_RAND:   ptr = "rand"; break;
    case IPID_ECHO:   ptr = "echo"; break;
    case IPID_CONST:  ptr = "const"; break;
    case IPID_UNRESP: ptr = "unresp"; break;
    default:
      snprintf(str, len, "class %d", class);
      return str;
    }

  snprintf(str, len, "%s", ptr);
  return str;
}

static void *pt_find(prefixtree_t *pt, scamper_addr_t *addr)
{
  prefix4_t *p4; prefix6_t *p6;
  if(addr->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      if((p4 = prefixtree_find_ip4(pt, addr->addr)) == NULL)
	return NULL;
      return p4->ptr;
    }
  else if(addr->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      if((p6 = prefixtree_find_ip6(pt, addr->addr)) == NULL)
	return NULL;
      return p6->ptr;
    }
  return NULL;
}

static int is_ixp(scamper_addr_t *addr)
{
  if(ixp_pt != NULL && pt_find(ixp_pt, addr) != NULL)
    return 1;
  return 0;
}

static int is_reserved(scamper_addr_t *addr)
{
  return scamper_addr_isreserved(addr);
}

static int is_vpas(uint32_t as)
{
  int i;
  for(i=0; i<vpasc; i++)
    if(as == vpas[i])
      return 1;
  return 0;
}

static sc_indir_t *sc_indir_alloc(void)
{
  return malloc_zero(sizeof(sc_indir_t));
}

static void sc_indir_free(sc_indir_t *indir)
{
  if(indir == NULL)
    return;
  if(indir->dst != NULL) scamper_addr_free(indir->dst);
  free(indir);
  return;
}

static int sc_ally_cmp(const sc_ally_t *a, const sc_ally_t *b)
{
  int rc;
  if((rc = scamper_addr_cmp(a->a, b->a)) != 0)
    return rc;
  return scamper_addr_cmp(a->b, b->b);
}

static void sc_ally_free(sc_ally_t *a)
{
  if(a == NULL)
    return;
  if(a->a != NULL) scamper_addr_free(a->a);
  if(a->b != NULL) scamper_addr_free(a->b);
  free(a);
  return;
}

static sc_ally_t *sc_ally_find(scamper_addr_t *a, scamper_addr_t *b)
{
  sc_ally_t fm; int rc;
  rc = scamper_addr_cmp(a, b); assert(rc != 0);
  if(rc < 0)
    {
      fm.a = a;
      fm.b = b;
    }
  else
    {
      fm.a = b;
      fm.b = a;
    }
  return splaytree_find(allys, &fm);
}

static sc_ally_t *sc_ally_get(scamper_addr_t *a, scamper_addr_t *b)
{
  sc_ally_t *ally;
  int rc;

  if((ally = sc_ally_find(a, b)) != NULL)
    return ally;
  if((ally = malloc_zero(sizeof(sc_ally_t))) == NULL)
    return NULL;

  rc = scamper_addr_cmp(a, b);
  if(rc < 0)
    {
      ally->a = scamper_addr_use(a);
      ally->b = scamper_addr_use(b);
    }
  else
    {
      ally->a = scamper_addr_use(b);
      ally->b = scamper_addr_use(a);
    }
  if(splaytree_insert(allys, ally) == NULL)
    {
      sc_ally_free(ally);
      return NULL;
    }

  return ally;
}

static int sc_link_cmp(const sc_link_t *a, const sc_link_t *b)
{
  int rc;
  if((rc = scamper_addr_cmp(a->a, b->a)) != 0)
    return rc;
  return scamper_addr_cmp(a->b, b->b);
}

static sc_link_t *sc_link_find(scamper_addr_t *a, scamper_addr_t *b)
{
  sc_link_t fm;
  fm.a = a; fm.b = b;
  return splaytree_find(links, &fm);
}

static void sc_link_free(sc_link_t *link)
{
  if(link == NULL) return;
  if(link->a != NULL) scamper_addr_free(link->a);
  if(link->b != NULL) scamper_addr_free(link->b);
  free(link);
  return;
}

static sc_link_t *sc_link_alloc(scamper_addr_t *a, scamper_addr_t *b)
{
  sc_link_t *link;
  if((link = malloc_zero(sizeof(sc_link_t))) == NULL)
    return NULL;
  link->a = scamper_addr_use(a);
  link->b = scamper_addr_use(b);
  return link;
}

static sc_link_t *sc_link_get(scamper_addr_t *a, scamper_addr_t *b)
{
  sc_link_t *link;
  if((link = sc_link_find(a, b)) != NULL)
    return link;
  if((link = sc_link_alloc(a, b)) == NULL ||
     splaytree_insert(links, link) == NULL)
    {
      if(link != NULL) sc_link_free(link);
      return NULL;
    }
  return link;
}

static void *sc_stree_find(sc_stree_t *set, void *item)
{
  return splaytree_find(set->tree, item);
}

static int sc_stree_add(sc_stree_t *set, void *item)
{
  assert(splaytree_find(set->tree, item) == NULL);
  if(slist_head_push(set->list, item) == NULL)
    return -1;
  if(splaytree_insert(set->tree, item) == NULL)
    {
      slist_head_pop(set->list);
      return -1;
    }
  return 0;
}

static void sc_stree_free(sc_stree_t *set, void (*free_func)(void *))
{
  if(set == NULL)
    return;
  if(set->tree != NULL) splaytree_free(set->tree, NULL);
  if(set->list != NULL) slist_free_cb(set->list, free_func);
  free(set);
  return;
}

static sc_stree_t *sc_stree_alloc(splaytree_cmp_t cmp)
{
  sc_stree_t *set = NULL;
  if((set = malloc_zero(sizeof(sc_stree_t))) == NULL ||
     (set->tree = splaytree_alloc(cmp)) == NULL ||
     (set->list = slist_alloc()) == NULL)
    {
      sc_stree_free(set, NULL);
      return NULL;
    }
  return set;
}

static char *sc_asmap_tostr(const sc_asmap_t *asmap, char *buf, size_t len)
{
  size_t off = 0;
  int i;
  string_concat(buf, len, &off, "%u", asmap->ases[0]);
  for(i=1; i<asmap->asc; i++)
    string_concat(buf, len, &off, "_%u", asmap->ases[i]);
  return buf;
}

static void sc_asmap_free(sc_asmap_t *asmap)
{
  if(asmap == NULL)
    return;
  if(asmap->ases != NULL)
    free(asmap->ases);
  free(asmap);
  return;
}

static int sc_asmap_cmp(const sc_asmap_t *a, const sc_asmap_t *b)
{
  int i, m = a->asc < b->asc ? a->asc : b->asc;
  if(a == b) return 0;
  for(i=0; i<m; i++)
    {
      if(a->ases[i] < b->ases[i]) return -1;
      if(a->ases[i] > b->ases[i]) return  1;
    }
  if(a->asc < b->asc) return -1;
  if(a->asc > b->asc) return  1;
  return 0;
}

static sc_asmap_t *sc_asmap_find(uint32_t *ases, int asc)
{
  sc_asmap_t fm; fm.ases = ases; fm.asc = asc;
  return splaytree_find(asmaptree, &fm);
}

static sc_asmap_t *sc_asmap_get(uint32_t *ases, int asc)
{
  sc_asmap_t *map = NULL;

  if((map = sc_asmap_find(ases, asc)) != NULL)
    return map;
  if((map = malloc_zero(sizeof(sc_asmap_t))) == NULL ||
     (map->ases = memdup(ases, sizeof(uint32_t) * asc)) == NULL)
    goto err;
  map->asc = asc;
  if(splaytree_insert(asmaptree, map) == NULL)
    goto err;

  return map;

 err:
  if(map != NULL) sc_asmap_free(map);
  return NULL;
}

static int sc_asmap_isvp(sc_asmap_t *asmap)
{
  int i, vppref = 0;
  for(i=0; i<asmap->asc; i++)
    if(is_vpas(asmap->ases[i]))
      vppref++;
  if(vppref == asmap->asc)
    return 1;
  return 0;
}

static void sc_asrel_free(sc_asrel_t *a)
{
  if(a == NULL)
    return;
  free(a);
  return;
}

static int sc_asrel_cmp(const sc_asrel_t *a, const sc_asrel_t *b)
{
  if(a->a < b->a) return -1;
  if(a->a > b->a) return  1;
  if(a->b < b->b) return -1;
  if(a->b > b->b) return  1;
  return 0;
}

static sc_asrel_t *sc_asrel_find(uint32_t a, uint32_t b)
{
  sc_asrel_t fm;
  if(a < b) { fm.a = a; fm.b = b; }
  else      { fm.a = b; fm.b = a; }
  return splaytree_find(reltree, &fm);
}

static int sc_asrel_r(uint32_t a, uint32_t b, int *r)
{
  sc_asrel_t *asr;
  if((asr = sc_asrel_find(a, b)) == NULL)
    return -1;
  if(a < b) *r = asr->r;
  else      *r = asr->r * -1;
  return 0;
}

static int sc_asrel_add(uint32_t a, uint32_t b, int r)
{
  sc_asrel_t *asr;
  if((asr = sc_asrel_find(a, b)) != NULL)
    {
      if(a < b && asr->r != r)
	return -1;
      else if(a > b && asr->r != r * -1)
	return -1;
      return 0;
    }
  if((asr = malloc_zero(sizeof(sc_asrel_t))) == NULL)
    return -1;
  if(a < b) { asr->a = a; asr->b = b; asr->r = r; }
  else      { asr->a = b; asr->b = a; asr->r = r * -1; }
  if(splaytree_insert(reltree, asr) == NULL)
    return -1;
  return 0;
}

static int sc_prov_cmp(const sc_prov_t *a, const sc_prov_t *b)
{
  if(a->as < b->as) return -1;
  if(a->as > b->as) return  1;
  return 0;
}

static void sc_prov_free(sc_prov_t *p)
{
  if(p == NULL)
    return;
  if(p->provs != NULL) free(p->provs);
  free(p);
  return;
}

static sc_prov_t *sc_prov_find(uint32_t as)
{
  sc_prov_t fm;
  fm.as = as;
  return splaytree_find(provtree, &fm);
}

static sc_prov_t *sc_prov_get(uint32_t as)
{
  sc_prov_t *p;
  if((p = sc_prov_find(as)) != NULL)
    return p;
  if((p = malloc_zero(sizeof(sc_prov_t))) == NULL)
    return NULL;
  p->as = as;
  if(splaytree_insert(provtree, p) == NULL)
    {
      free(p);
      return NULL;
    }
  return p;
}

/*
 * sc_prov_add
 *
 * B is a provider for A.  make a note of that.
 */
static int sc_prov_add(uint32_t a, uint32_t b)
{
  sc_prov_t *p;
  if((p = sc_prov_get(a)) == NULL)
    return -1;
  if(uint32_add(&p->provs, &p->provc, b) != 0)
    return -1;
  return 0;
}

static int vp_r(uint32_t peer, uint32_t *sib_as, int *r)
{
  int custc = 0, peerc = 0, provc = 0;
  uint32_t custas, peeras, provas;
  int i, rl;

  for(i=0; i<vpasc; i++)
    {
      if(sc_asrel_r(vpas[i], peer, &rl) != 0)
	continue;
      if(rl == -1)
	{
	  if(custc == 0) custas = vpas[i];
	  custc++;
	}
      else if(rl == 0)
	{
	  if(peerc == 0) peeras = vpas[i];
	  peerc++;
	}
      else
	{
	  if(provc == 0) provas = vpas[i];
	  provc++;
	}
    }

  if(provc > 0)
    {
      *r = 1;
      if(sib_as != NULL) *sib_as = provas;
      return 0;
    }
  else if(peerc > 0 && custc == 0)
    {
      *r = 0;
      if(sib_as != NULL) *sib_as = peeras;
      return 0;
    }
  else if(custc > 0 && peerc == 0)
    {
      *r = -1;
      if(sib_as != NULL) *sib_as = custas;
      return 0;
    }

  return -1;
}

static int asmap_r(sc_asmap_t *peer, uint32_t *sib, uint32_t *neigh, int *r)
{
  int custc = 0, peerc = 0, provc = 0;
  uint32_t cust_sib, cust_neigh, peer_sib, peer_neigh, prov_sib, prov_neigh;
  int i, j, rl;

  if(peer->asc == 1)
    {
      if(is_vpas(peer->ases[0]))
	return -1;
      for(i=0; i<vpasc; i++)
	{
	  if(sc_asrel_r(vpas[i], peer->ases[0], r) == 0)
	    {
	      *sib = vpas[i];
	      *neigh = peer->ases[0];
	      return 0;
	    }
	}
    }
  else
    {
      for(i=0; i<vpasc; i++)
	{
	  for(j=0; j<peer->asc; j++)
	    {
	      if(is_vpas(peer->ases[j]))
		continue;
	      if(sc_asrel_r(vpas[i], peer->ases[j], &rl) != 0)
		continue;
	      if(rl == -1)
		{
		  if(custc == 0)
		    {
		      cust_sib = vpas[i];
		      cust_neigh = peer->ases[j];
		    }
		  custc++;
		}
	      else if(rl == 0)
		{
		  if(peerc == 0)
		    {
		      peer_sib = vpas[i];
		      peer_neigh = peer->ases[j];
		    }
		  peerc++;
		}
	      else
		{
		  if(provc == 0)
		    {
		      prov_sib = vpas[i];
		      prov_neigh = peer->ases[j];
		    }
		  provc++;
		}
	    }
	}

      if(provc > 0)
	{
	  *r = 1; *sib = prov_sib; *neigh = prov_neigh;
	  return 0;
	}
      else if(peerc > 0 && custc == 0)
	{
	  *r = 0; *sib = peer_sib; *neigh = peer_neigh;
	  return 0;
	}
      else if(custc > 0 && peerc == 0)
	{
	  *r = -1; *sib = cust_sib; *neigh = cust_neigh;
	  return 0;
	}
    }

  return -1;
}

static sc_test_t *sc_test_alloc(int type, void *data)
{
  sc_test_t *test;

  if((test = malloc_zero(sizeof(sc_test_t))) == NULL)
    {
      fprintf(stderr, "could not malloc test\n");
      return NULL;
    }

  test->type = type;
  test->data = data;
  return test;
}

static void sc_test_free(sc_test_t *test)
{
  if(test != NULL) free(test);
  return;
}

static int sc_waittest_cmp(const void *va, const void *vb)
{
  const sc_waittest_t *a = va;
  const sc_waittest_t *b = vb;
  return timeval_cmp(&b->tv, &a->tv);
}

static int sc_waittest_sec(sc_test_t *test, int sec)
{
  sc_waittest_t *wt;
  if((wt = malloc_zero(sizeof(sc_waittest_t))) == NULL)
    return -1;
  timeval_add_s(&wt->tv, &now, sec);
  wt->test = test;
  if(heap_insert(waiting, wt) == NULL)
    {
      free(wt);
      return -1;
    }
  return 0;
}

static int sc_waittest(sc_test_t *test)
{
  return sc_waittest_sec(test, waittime);
}

static void sc_target_detach(sc_target_t *tg)
{
  sc_test_t *test;
  char buf[128];

  if(tg == NULL)
    return;

  if(tg->node != NULL)
    {
      if(splaytree_remove_node(targets, tg->node) != 0)
	{
	  logerr("%s: could not remove %s from tree\n", __func__,
		 scamper_addr_tostr(tg->addr, buf, sizeof(buf)));
	}
      tg->node = NULL;
    }

  if(tg->blocked != NULL)
    {
      while((test = slist_head_pop(tg->blocked)) != NULL)
	sc_waittest(test);
      slist_free(tg->blocked);
      tg->blocked = NULL;
    }

  return;
}

static void sc_target_free(sc_target_t *tg)
{
  if(tg == NULL)
    return;
  sc_target_detach(tg);
  if(tg->addr != NULL)
    scamper_addr_free(tg->addr);
  free(tg);
  return;
}

static int sc_target_cmp(const sc_target_t *a, const sc_target_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static sc_target_t *sc_target_alloc(scamper_addr_t *addr)
{
  sc_target_t *tg = NULL;
  if((tg = malloc_zero(sizeof(sc_target_t))) == NULL)
    {
      fprintf(stderr, "could not malloc target\n");
      return NULL;
    }
  tg->addr = scamper_addr_use(addr);
  return tg;
}

static int sc_target_block(sc_target_t *target, sc_test_t *block)
{
  if(target->blocked == NULL && (target->blocked = slist_alloc()) == NULL)
    {
      fprintf(stderr, "could not alloc target->blocked list\n");
      return -1;
    }

  if(slist_tail_push(target->blocked, block) == NULL)
    {
      fprintf(stderr, "could not add test to blocked list\n");
      return -1;
    }

  return 0;
}

static sc_target_t *sc_target_find(sc_target_t *target)
{
  return splaytree_find(targets, target);
}

static sc_target_t *sc_target_findaddr(scamper_addr_t *addr)
{
  sc_target_t findme;
  findme.addr = addr;
  return sc_target_find(&findme);
}

static int sc_target_add(sc_target_t *target)
{
  char buf[128];

  assert(target->node == NULL);
  assert(target->test != NULL);

  if((target->node = splaytree_insert(targets, target)) == NULL)
    {
      logerr("%s: could not add %s to tree\n", __func__,
	     scamper_addr_tostr(target->addr, buf, sizeof(buf)));
      return -1;
    }
  return 0;
}

static int sc_prefix_cmp(const sc_prefix_t *a, const sc_prefix_t *b)
{
  if(a == b)
    return 0;
  if(af == AF_INET)
    return prefix4_cmp(a->pfx.v4, b->pfx.v4);
  return prefix6_cmp(a->pfx.v6, b->pfx.v6);
}

static void sc_prefix_free(sc_prefix_t *p)
{
  if(p == NULL)
    return;
  if(af == AF_INET)
    {
      if(p->pfx.v4 != NULL)
	prefix4_free(p->pfx.v4);
    }
  else
    {
      if(p->pfx.v6 != NULL)
	prefix6_free(p->pfx.v6);
    }
  free(p);
  return;
}

static sc_prefix_t *sc_prefix_alloc(void *net, int len)
{
  sc_prefix_t *p;

  if((p = malloc_zero(sizeof(sc_prefix_t))) == NULL)
    goto err;
  if(af == AF_INET)
    {
      if((p->pfx.v4 = prefix4_alloc(net, len, p)) == NULL)
	goto err;
    }
  else
    {
      if((p->pfx.v6 = prefix6_alloc(net, len, p)) == NULL)
	goto err;
    }
  return p;

 err:
  sc_prefix_free(p);
  return NULL;
}

static sc_prefix_t *sc_prefix_find_in(void *addr)
{
  prefix4_t *p4; prefix6_t *p6;

  if(af == AF_INET)
    {
      if((p4 = prefixtree_find_ip4(ip2as_pt, addr)) != NULL)
	return p4->ptr;
    }
  else if(af == AF_INET6)
    {
      if((p6 = prefixtree_find_ip6(ip2as_pt, addr)) != NULL)
	return p6->ptr;
    }
  return NULL;
}

static sc_prefix_t *sc_prefix_find(scamper_addr_t *addr)
{
  if(scamper_addr_isreserved(addr) != 0)
    return NULL;
  if(ixp_pt != NULL && pt_find(ixp_pt, addr) != NULL)
    return NULL;
  return pt_find(ip2as_pt, addr);
}

static void sc_prefix_nest_free(sc_prefix_nest_t *nest)
{
  if(nest == NULL)
    return;
  if(nest->list != NULL)
    slist_free_cb(nest->list, (slist_free_t)sc_prefix_nest_free);
  if(nest->pt != NULL)
    {
      if(af == AF_INET)
	prefixtree_free_cb(nest->pt, (prefix_free_t)prefix4_free);
      else
	prefixtree_free_cb(nest->pt, (prefix_free_t)prefix6_free);
    }
  free(nest);
  return;
}

static sc_prefix_nest_t *sc_prefix_nest_alloc(sc_prefix_t *pfx)
{
  sc_prefix_nest_t *nest;
  if((nest = malloc_zero(sizeof(sc_prefix_nest_t))) == NULL)
    return NULL;
  nest->pfx = pfx;
  return nest;
}

static int sc_prefix_nest_cmp(const sc_prefix_nest_t *a,
			      const sc_prefix_nest_t *b)
{
  return sc_prefix_cmp(a->pfx, b->pfx);
}

static int sc_ixpc_pfx_cmp(const sc_ixpc_t *a, const sc_ixpc_t *b)
{
  if(af == AF_INET)
    return prefix4_cmp(a->pfx.v4, b->pfx.v4);
  return prefix6_cmp(a->pfx.v6, b->pfx.v6);
}

static int sc_ixpc_c_cmp(const sc_ixpc_t *a, const sc_ixpc_t *b)
{
  if(a->c > b->c) return -1;
  if(a->c < b->c) return  1;
  return 0;
}

static sc_ixpc_t *sc_ixpc_find(sc_stree_t *set, scamper_addr_t *addr)
{
  sc_ixpc_t fm;
  if(ixp_pt == NULL)
    return NULL;
  fm.pfx.ptr = pt_find(ixp_pt, addr);
  assert(fm.pfx.ptr != NULL);
  return sc_stree_find(set, &fm);
}

static sc_ixpc_t *sc_ixpc_get(sc_stree_t *set, scamper_addr_t *addr)
{
  sc_ixpc_t *pfxc;
  if(ixp_pt == NULL)
    return NULL;
  if((pfxc = sc_ixpc_find(set, addr)) != NULL)
    return pfxc;
  if((pfxc = malloc_zero(sizeof(sc_ixpc_t))) == NULL)
    return NULL;
  pfxc->pfx.ptr = pt_find(ixp_pt, addr);
  if(sc_stree_add(set, pfxc) != 0)
    {
      free(pfxc);
      return NULL;
    }
  return pfxc;
}

/*
 * is_vp:
 *
 * infer if the address belongs to the VP.
 * return 0 if it does not, 1 if it does, and 2 if we don't know.
 */
static int is_vp(scamper_addr_t *addr)
{
  sc_prefix_t *pfx;
  if(is_ixp(addr) != 0 || (pfx = sc_prefix_find(addr)) == NULL)
    return 2;
  return sc_asmap_isvp(pfx->asmap);
}

static void sc_tracetest_free(sc_tracetest_t *tt)
{
  if(tt == NULL)
    return;
  if(tt->target != NULL)
    sc_target_free(tt->target);
  free(tt);
  return;
}

static sc_tracetest_t *sc_tracetest_alloc(scamper_addr_t *addr)
{
  sc_tracetest_t *tt;
  sc_test_t *test;

  if((tt = malloc_zero(sizeof(sc_tracetest_t))) == NULL ||
     (tt->target = sc_target_alloc(addr)) == NULL ||
     (test = sc_test_alloc(TEST_TRACE, tt)) == NULL)
    goto err;
  tt->target->test = test;
  return tt;

 err:
  if(tt != NULL) sc_tracetest_free(tt);
  return NULL;
}

static void sc_linktest_free(sc_linktest_t *lt)
{
  if(lt == NULL)
    return;
  if(lt->ta != NULL)
    sc_target_free(lt->ta);
  if(lt->tb != NULL)
    sc_target_free(lt->tb);
  if(lt->ab != NULL)
    scamper_addr_free(lt->ab);

  free(lt);
  return;
}

static int sc_linktest_alloc(scamper_addr_t *a, scamper_addr_t *b)
{
  sc_link_t *link;
  sc_linktest_t *lt;
  sc_test_t *test;

  /* the two addresses should not be the same */
  assert(scamper_addr_cmp(a, b) != 0);

  /* if the link has already been tested, there is nothing more to be done */
  if(sc_link_find(a, b) != NULL)
    return 0;

  if((link = sc_link_get(a, b)) == NULL ||
     (lt = malloc_zero(sizeof(sc_linktest_t))) == NULL ||
     (lt->ta = sc_target_alloc(a)) == NULL ||
     (lt->tb = sc_target_alloc(b)) == NULL)
    return -1;
  lt->link = link;

  if((test = sc_test_alloc(TEST_LINK, lt)) == NULL || sc_waittest(test) != 0)
    {
      sc_linktest_free(lt);
      if(test != NULL) sc_test_free(test);
      return -1;
    }
  lt->ta->test = test;
  lt->tb->test = test;

  return 0;
}

/*
 * sc_ping_method
 *
 * prefer icmp echo because it is benign.
 * prefer tcp to udp because it returns fewer false negatives --shared
 * counter held centrally (TCP) vs held on line card (UDP) on some routers.
 */
static int sc_ping_method(const sc_ping_t *a, const sc_ping_t *b, int *meth)
{
  int i;
  for(i=0; i<4; i++)
    {
      if(a->methods[i] == IPID_INCR && b->methods[i] == IPID_INCR)
	{
	  *meth = i;
	  return 0;
	}
    }
  return -1;
}

static int sc_ping_cmp(const sc_ping_t *a, const sc_ping_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static sc_ping_t *sc_ping_find(scamper_addr_t *addr)
{
  sc_ping_t fm;
  fm.addr = addr;
  return splaytree_find(pings, &fm);
}

static sc_ping_t *sc_ping_alloc(scamper_addr_t *addr)
{
  sc_ping_t *ping;
  if((ping = malloc_zero(sizeof(sc_ping_t))) == NULL)
    return NULL;
  ping->addr = scamper_addr_use(addr);
  return ping;
}

static void sc_ping_free(sc_ping_t *ping)
{
  if(ping == NULL) return;
  if(ping->addr != NULL) scamper_addr_free(ping->addr);
  if(ping->indir.dst != NULL) scamper_addr_free(ping->indir.dst);
  free(ping);
  return;
}

static void sc_pingtest_free(sc_pingtest_t *pt)
{
  if(pt == NULL)
    return;
  if(pt->target != NULL)
    sc_target_free(pt->target);
  if(pt->t2 != NULL)
    sc_target_free(pt->t2);
  free(pt);
  return;
}

static sc_test_t *sc_pingtest_alloc(scamper_addr_t *addr)
{
  sc_pingtest_t *pt;
  sc_ping_t *ping;
  sc_test_t *test;

  if((ping = sc_ping_find(addr)) == NULL)
    {
      if((ping = sc_ping_alloc(addr)) == NULL)
	return NULL;
      if(splaytree_insert(pings, ping) == NULL)
	{
	  sc_ping_free(ping);
	  return NULL;
	}
    }

  if((pt = malloc_zero(sizeof(sc_pingtest_t))) == NULL ||
     (pt->target = sc_target_alloc(addr)) == NULL)
    {
      if(pt != NULL) sc_pingtest_free(pt);
      return NULL;
    }
  pt->ping = ping;

  if((test = sc_test_alloc(TEST_PING, pt)) == NULL)
    {
      sc_pingtest_free(pt);
      return NULL;
    }
  pt->target->test = test;

  return test;
}

static void sc_asmapc_free(sc_asmapc_t *a)
{
  if(a == NULL)
    return;
  free(a);
  return;
}

static int sc_asmapc_as_cmp(const sc_asmapc_t *a, const sc_asmapc_t *b)
{
  return sc_asmap_cmp(a->asmap, b->asmap);
}

static int sc_asmapc_c_cmp(const sc_asmapc_t *a, const sc_asmapc_t *b)
{
  if(a->c > b->c) return -1;
  if(a->c < b->c) return  1;
  return 0;
}

static sc_asmapc_t *sc_asmapc_find(sc_stree_t *set, sc_asmap_t *asmap)
{
  sc_asmapc_t fm; fm.asmap = asmap;
  return sc_stree_find(set, &fm);
}

#ifndef DMALLOC
static sc_asmapc_t *sc_asmapc_get(sc_stree_t *set, sc_asmap_t *asmap)
#else
#define sc_asmapc_get(set,asmap) sc_asmapc_get_dm((set),(asmap),__FILE__,__LINE__)
static sc_asmapc_t *sc_asmapc_get_dm(sc_stree_t *set, sc_asmap_t *asmap,
				     const char *file, const int line)
#endif
{
  sc_asmapc_t *asmapc;
  if((asmapc = sc_asmapc_find(set, asmap)) != NULL)
    return asmapc;
#ifndef DMALLOC
  if((asmapc = malloc_zero(sizeof(sc_asmapc_t))) == NULL)
    return NULL;
#else
  if((asmapc = malloc_zero_dm(sizeof(sc_asmapc_t), file, line)) == NULL)
    return NULL;
#endif
  asmapc->asmap = asmap;
  if(sc_stree_add(set, asmapc) != 0)
    {
      free(asmapc);
      return NULL;
    }
  return asmapc;
}

static void sc_asc_free(sc_asc_t *asc)
{
  if(asc == NULL)
    return;
  free(asc);
  return;
}

static int sc_asc_as_cmp(const sc_asc_t *a, const sc_asc_t *b)
{
  if(a->as < b->as) return -1;
  if(a->as > b->as) return  1;
  return 0;
}

static int sc_asc_c_cmp(const sc_asc_t *a, const sc_asc_t *b)
{
  if(a->c > b->c) return -1;
  if(a->c < b->c) return  1;
  return 0;
}

static sc_asc_t *sc_asc_find(sc_stree_t *set, uint32_t as)
{
  sc_asc_t fm; fm.as = as;
  return sc_stree_find(set, &fm);
}

static sc_asc_t *sc_asc_get(sc_stree_t *set, uint32_t as)
{
  sc_asc_t *asc;
  if((asc = sc_asc_find(set, as)) != NULL)
    return asc;
  if((asc = malloc_zero(sizeof(sc_asc_t))) == NULL)
    return NULL;
  asc->as = as;
  if(sc_stree_add(set, asc) != 0)
    {
      free(asc);
      return NULL;
    }
  return asc;
}

static int sc_addr2router_ttlexp_cmp(const sc_addr2router_t *a,
				     const sc_addr2router_t *b)
{
  if(a->ttlexp > b->ttlexp) return -1;
  if(a->ttlexp < b->ttlexp) return  1;
  return scamper_addr_human_cmp(a->addr, b->addr);
}

static int sc_addr2router_addr_cmp(const sc_addr2router_t *a,
				   const sc_addr2router_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static int sc_addr2router_free_ping(void *ptr, void *entry)
{
  sc_addr2router_t *a2r = entry;
  sc_ping_free(a2r->data);
  return 0;
}

static void sc_addr2router_free(sc_addr2router_t *a2r)
{
  if(a2r == NULL)
    return;
  if(a2r->addr != NULL)
    scamper_addr_free(a2r->addr);
  free(a2r);
  return;
}

static int sc_router_p_cmp(const sc_router_t *a, const sc_router_t *b)
{
  if(a < b) return -1;
  if(a > b) return  1;
  return 0;
}

static int sc_router_ttl_cmp(const sc_router_t *a, const sc_router_t *b)
{
  if(a->ttl < b->ttl) return -1;
  if(a->ttl > b->ttl) return  1;
  return 0;
}

static sc_asmapc_t *sc_router_dstases_get(sc_router_t *rtr, sc_asmap_t *asmap)
{
  if(rtr->dstases == NULL &&
     (rtr->dstases = sc_stree_alloc((splaytree_cmp_t)sc_asmapc_as_cmp)) == NULL)
    return NULL;
  return sc_asmapc_get(rtr->dstases, asmap);
}

/*
 * sc_router_adj_add
 *
 * add an adjacency between two routers (if the adjacency is not
 * already recorded)
 */
static int sc_router_adj_add(sc_router_t *rtr, sc_router_t *adj)
{
  dlist_node_t *dn;
  if(rtr->adj == NULL && (rtr->adj = dlist_alloc()) == NULL)
    return -1;
  for(dn=dlist_head_node(rtr->adj); dn != NULL; dn=dlist_node_next(dn))
    if(dlist_node_item(dn) == adj)
      return 0;
  if(dlist_tail_push(rtr->adj, adj) == NULL)
    return -1;
  return 0;
}

/*
 * sc_router_prev_add
 *
 * add a backwards adjacency between two routers (if the adjacency is
 * not already recorded)
 */
static int sc_router_prev_add(sc_router_t *rtr, sc_router_t *prev)
{
  dlist_node_t *dn;
  if(rtr->prev == NULL && (rtr->prev = dlist_alloc()) == NULL)
    return -1;
  for(dn=dlist_head_node(rtr->prev); dn != NULL; dn=dlist_node_next(dn))
    if(dlist_node_item(dn) == prev)
      return 0;
  if(dlist_tail_push(rtr->prev, prev) == NULL)
    return -1;
  return 0;
}

/*
 * sc_router_free
 *
 */
static void sc_router_free(sc_router_t *rtr)
{
  if(rtr == NULL)
    return;
  if(rtr->addrs != NULL) slist_free(rtr->addrs);
  if(rtr->adj != NULL) dlist_free(rtr->adj);
  if(rtr->prev != NULL) dlist_free(rtr->prev);
  if(rtr->dstases != NULL)
    sc_stree_free(rtr->dstases, (sc_stree_free_t)sc_asmapc_free);
  if(rtr->adjases != NULL)
    sc_stree_free(rtr->adjases, (sc_stree_free_t)sc_asmapc_free);
  if(rtr->gapases != NULL)
    sc_stree_free(rtr->gapases, (sc_stree_free_t)sc_asmapc_free);
  free(rtr);
  return;
}

static sc_router_t *sc_router_alloc(void)
{
  sc_router_t *rtr;
  if((rtr = malloc_zero(sizeof(sc_router_t))) == NULL ||
     (rtr->addrs = slist_alloc()) == NULL)
    {
      sc_router_free(rtr);
      return NULL;
    }
  return rtr;
}

static sc_addr2router_t *sc_routerset_a2r_find(sc_routerset_t *set,
					       scamper_addr_t *a)
{
  sc_addr2router_t fm; fm.addr = a;
  assert(a != NULL);
  return splaytree_find(set->tree, &fm);
}

/*
 * sc_routerset_a2r_add:
 *
 * given an existing router, add an interface to it.  the interface
 * is not already associated with a router in the set.
 */
static sc_addr2router_t *sc_routerset_a2r_add(sc_routerset_t *set,
					      sc_router_t *rtr,
					      scamper_addr_t *addr)
{
  sc_addr2router_t *a2r;
  if((a2r = malloc_zero(sizeof(sc_addr2router_t))) == NULL)
    return NULL;
  a2r->router = rtr;
  a2r->addr   = scamper_addr_use(addr);
  if(splaytree_insert(set->tree, a2r) == NULL)
    {
      sc_addr2router_free(a2r);
      return NULL;
    }
  if(slist_tail_push(rtr->addrs, a2r) == NULL)
    return NULL;
  return a2r;
}

static sc_addr2router_t *sc_routerset_a2r_get(sc_routerset_t *set,
					      scamper_addr_t *addr)
{
  sc_router_t *rtr = NULL;
  sc_addr2router_t *a2r;
  if((a2r = sc_routerset_a2r_find(set, addr)) != NULL)
    return a2r;
  if((rtr = sc_router_alloc()) == NULL ||
     (rtr->node = dlist_tail_push(set->list, rtr)) == NULL)
    {
      if(rtr != NULL) sc_router_free(rtr);
      return NULL;
    }
  if((a2r = sc_routerset_a2r_add(set, rtr, addr)) == NULL)
    return NULL;
  return a2r;
}

static sc_router_t *sc_routerset_find(sc_routerset_t *set, scamper_addr_t *a)
{
  sc_addr2router_t *a2r;
  if((a2r = sc_routerset_a2r_find(set, a)) == NULL)
    return NULL;
  return a2r->router;
}

static sc_router_t *sc_routerset_get(sc_routerset_t *set, scamper_addr_t *a)
{
  sc_addr2router_t *a2r;
  if((a2r = sc_routerset_a2r_find(set, a)) != NULL)
    return a2r->router;
  if((a2r = sc_routerset_a2r_get(set, a)) != NULL)
    return a2r->router;
  return NULL;
}

static sc_router_t *sc_routerset_getnull(sc_routerset_t *set)
{
  sc_router_t *rtr = NULL;
  if((rtr = sc_router_alloc()) == NULL ||
     (rtr->node = dlist_tail_push(set->list, rtr)) == NULL)
    goto err;
  return rtr;
 err:
  if(rtr != NULL) sc_router_free(rtr);
  return NULL;
}

static void sc_routerset_pop(sc_routerset_t *set, sc_router_t *r)
{
  dlist_node_pop(set->list, r->node);
  r->node = NULL;
  return;
}

static void sc_routerset_free(sc_routerset_t *set)
{
  if(set == NULL)
    return;
  if(set->list != NULL)
    dlist_free_cb(set->list, (dlist_free_t)sc_router_free);
  if(set->tree != NULL)
    splaytree_free(set->tree, (splaytree_free_t)sc_addr2router_free);
  free(set);
  return;
}

static sc_routerset_t *sc_routerset_alloc(void)
{
  sc_routerset_t *set;
  if((set = malloc_zero(sizeof(sc_routerset_t))) == NULL ||
     (set->list = dlist_alloc()) == NULL ||
     (set->tree = splaytree_alloc((splaytree_cmp_t)sc_addr2router_addr_cmp)) == NULL)
    {
      sc_routerset_free(set);
      return NULL;
    }
  return set;
}

/*
 * sc_routerset_merge:
 *
 * merge two routers.  shift all the addresses, adjacent hops, and
 * associated data from b to a.
 */
static int sc_routerset_merge(sc_routerset_t *set,
			      sc_router_t *a, sc_router_t *b)
{
  sc_addr2router_t *a2r;
  sc_router_t *x;
  dlist_node_t *dn, *dn2;

  /*
   * update the earliest ttl the router was observed, and annotations
   * on the router.
   */
  if(b->ttl != 0 && (b->ttl < a->ttl || a->ttl == 0))
    a->ttl = b->ttl;
  a->flags |= b->flags;
  a->flags |= SC_ROUTER_FLAG_MERGED;

  /*
   * shift the addresses from router b to router a.  the addresses
   * are distinct to each router
   */
  while((a2r = slist_head_pop(b->addrs)) != NULL)
    {
      a2r->router = a;
      if(slist_tail_push(a->addrs, a2r) == NULL)
	return -1;
    }

  /*
   * shift adjacent routers from b to a, ensuring that the router
   * was not already recorded as adjacent on router a.
   */
  while((x = dlist_head_pop(b->adj)) != NULL)
    {
      for(dn = dlist_head_node(a->adj); dn != NULL; dn = dlist_node_next(dn))
	if(dlist_node_item(dn) == x)
	  break;
      if(dn == NULL && dlist_tail_push(a->adj, x) == NULL)
	return -1;
    }
  if(b->prev != NULL)
    {
      while((x = dlist_head_pop(b->prev)) != NULL)
	{
	  if(sc_router_prev_add(a, x) != 0)
	    return -1;
	}
    }

  /*
   * go through other routers that have a pointer to the router about
   * to be removed
   */
  for(dn = dlist_head_node(set->list); dn != NULL; dn = dlist_node_next(dn))
    {
      x = dlist_node_item(dn);
      if(x->adj != NULL)
	{
	  dn2 = dlist_head_node(x->adj);
	  while(dn2 != NULL)
	    {
	      if(dlist_node_item(dn2) == b)
		{
		  dlist_node_pop(x->adj, dn2);
		  break;
		}
	      dn2 = dlist_node_next(dn2);
	    }
	}
      if(x->prev != NULL)
	{
	  dn2 = dlist_head_node(x->prev);
	  while(dn2 != NULL)
	    {
	      if(dlist_node_item(dn2) == b)
		{
		  dlist_node_pop(x->prev, dn2);
		  break;
		}
	      dn2 = dlist_node_next(dn2);
	    }
	}
    }

  sc_routerset_pop(set, b);
  sc_router_free(b);
  return 0;
}

static sc_router_t *sc_routerset_getpair(sc_routerset_t *set,
					 scamper_addr_t *a, scamper_addr_t *b)
{
  sc_addr2router_t *a2r_a, *a2r_b;
  sc_router_t *rtr;

  a2r_a = sc_routerset_a2r_find(set, a);
  a2r_b = sc_routerset_a2r_find(set, b);
  if(a2r_a == NULL && a2r_b == NULL)
    {
      if((rtr = sc_routerset_get(set, a)) == NULL ||
	 sc_routerset_a2r_add(set, rtr, b) == NULL)
	return NULL;
    }
  else if(a2r_a != NULL && a2r_b != NULL)
    {
      rtr = a2r_a->router;
      if(a2r_a->router != a2r_b->router)
	{
	  while((a2r_a = slist_head_pop(rtr->addrs)) != NULL)
	    {
	      a2r_a->router = a2r_b->router;
	      if(slist_tail_push(a2r_b->router->addrs, a2r_a) == NULL)
		return NULL;
	    }
	  sc_routerset_pop(set, rtr);
	  sc_router_free(rtr);
	  rtr = a2r_b->router;
	}
    }
  else if(a2r_a != NULL)
    {
      rtr = a2r_a->router;
      if(sc_routerset_a2r_add(set, rtr, b) == NULL)
	return NULL;
    }
  else
    {
      rtr = a2r_b->router;
      if(sc_routerset_a2r_add(set, rtr, a) == NULL)
	return NULL;
    }

  return rtr;
}

static int sc_router_ttlexp_count(const sc_router_t *rtr)
{
  sc_addr2router_t *a2r;
  slist_node_t *sn;
  int ttlexpc = 0;

  for(sn=slist_head_node(rtr->addrs); sn != NULL; sn=slist_node_next(sn))
    {
      a2r = slist_node_item(sn);
      if(a2r->ttlexp != 0)
	ttlexpc++;
    }

  return ttlexpc;
}

static int sc_router_isvp(const sc_router_t *rtr)
{
  sc_addr2router_t *a2r;
  slist_node_t *sn;
  int vpc = 0;

  for(sn=slist_head_node(rtr->addrs); sn != NULL; sn=slist_node_next(sn))
    {
      a2r = slist_node_item(sn);
      if(a2r->ttlexp == 0)
	continue;
      if(is_vp(a2r->addr) == 1)
	vpc++;
      else
	return 0;
    }

  if(vpc == 0)
    return 0;
  return 1;
}

static int sc_router_isborder(const sc_router_t *rtr)
{
  sc_router_t *adj;
  dlist_node_t *dn;
  if(rtr->owner_as == 0 || rtr->owner_as != vpas[0] || rtr->adj == NULL)
    return 0;
  for(dn = dlist_head_node(rtr->adj); dn != NULL; dn = dlist_node_next(dn))
    {
      adj = dlist_node_item(dn);
      if(adj->owner_as == 0 || adj->owner_as != vpas[0])
	return 1;
    }
  return 0;
}

static int sc_router_owner_cmp(const sc_router_t *a, const sc_router_t *b)
{
  const sc_addr2router_t *a2ra, *a2rb;
  int oa, ob;

  if(a->owner_as != b->owner_as)
    {
      if(a->owner_as == vpas[0] || b->owner_as == vpas[0])
	{
	  if(a->owner_as == vpas[0]) return -1;
	  if(b->owner_as == vpas[0]) return  1;
	}
      else
	{
	  if(a->owner_as < b->owner_as) return -1;
	  if(a->owner_as > b->owner_as) return  1;
	}
    }
  else if(a->owner_as == vpas[0] && b->owner_as == vpas[0])
    {
      oa = sc_router_isborder(a);
      ob = sc_router_isborder(b);
      if(oa == 1 && ob == 0) return -1;
      if(oa == 0 && ob == 1) return  1;
    }

  a2ra = slist_head_item(a->addrs);
  a2rb = slist_head_item(b->addrs);
  if(a2ra != NULL && a2rb != NULL)
    return scamper_addr_human_cmp(a2ra->addr, a2rb->addr);
  if(a2ra != NULL && a2rb == NULL)
    return -1;
  if(a2ra == NULL && a2rb != NULL)
    return 1;

  if(a < b) return -1;
  if(a > b) return  1;
  return 0;
}

static void sc_router_setowner(sc_router_t *r, uint32_t as, uint8_t reason)
{
  assert(as != 0); assert(reason != SC_ROUTER_OWNER_NONE);
  r->owner_as = as;
  r->owner_reason = reason;
  return;
}

static void sc_allyconftest_free(sc_allyconftest_t *act)
{
  if(act == NULL)
    return;
  if(act->a != NULL) sc_target_free(act->a);
  if(act->b != NULL) sc_target_free(act->b);
  free(act);
  return;
}

static sc_allyconftest_t *sc_allyconftest_alloc(sc_ally_t *ally, int method)
{
  sc_allyconftest_t *act;
  sc_test_t *test;

  if((act = malloc_zero(sizeof(sc_allyconftest_t))) == NULL)
    return NULL;
  act->ally = ally;
  act->count = allyconf;
  act->method = method;

  if((test = sc_test_alloc(TEST_ALLYCONF, act)) == NULL ||
     sc_waittest_sec(test, allyconf_wait) != 0)
    {
      sc_allyconftest_free(act);
      if(test != NULL) sc_test_free(test);
      return NULL;
    }

  return act;
}

static void sc_allytest_free(sc_allytest_t *at)
{
  if(at == NULL)
    return;
  if(at->addr_list != NULL)
    slist_free_cb(at->addr_list, (slist_free_t)sc_ping_free);
  if(at->routers != NULL)
    sc_routerset_free(at->routers);
  if(at->a != NULL) sc_target_free(at->a);
  if(at->b != NULL) sc_target_free(at->b);
  free(at);

  return;
}

static sc_allytest_t *sc_allytest_alloc(void)
{
  sc_allytest_t *at = NULL;
  if((at = malloc_zero(sizeof(sc_allytest_t))) == NULL ||
     (at->addr_list = slist_alloc()) == NULL ||
     (at->routers = sc_routerset_alloc()) == NULL)
    goto err;
  return at;
 err:
  if(at != NULL) sc_allytest_free(at);
  return NULL;
}

/*
 * sc_allytest_next
 *
 * figure out the next pair of IP addresses that should be tested.  the
 * function works by iterating through the addresses in the list,
 * only testing the addresses that do not belong to the same router
 */
static void sc_allytest_next(sc_allytest_t *at)
{
  sc_ping_t *aseq, *bseq, *a, *b;
  int m;

  if(at->a != NULL)
    {
      sc_target_free(at->a);
      at->a = NULL;
    }
  if(at->b != NULL)
    {
      sc_target_free(at->b);
      at->b = NULL;
    }
  at->method  = 0;
  at->attempt = 0;

  for(;;)
    {
      if((at->s2 = slist_node_next(at->s2)) == NULL &&
	 ((at->s1 = slist_node_next(at->s1)) == NULL ||
	  (at->s2 = slist_node_next(at->s1)) == NULL))
	{
	  at->s1 = at->s2 = NULL;
	  break;
	}

      a = slist_node_item(at->s1);
      b = slist_node_item(at->s2);

      /*
       * if these addresses have been assigned to routers already, we
       * don't need to probe them
       */
      if(sc_routerset_a2r_find(at->routers, a->addr) != NULL &&
	 sc_routerset_a2r_find(at->routers, b->addr) != NULL)
	continue;

      /* if we have already tried these addresses with ally, then skip */
      if(sc_ally_find(a->addr, b->addr) != NULL)
	continue;

      /*
       * if we cannot probe them because they do not have a common
       * probe method to use, then skip them, though this could be
       * relaxed in the future to use different probe methods if we
       * assume a single shared counter.
       */
      if((aseq = sc_ping_find(a->addr)) != NULL &&
	 (bseq = sc_ping_find(b->addr)) != NULL &&
	 sc_ping_method(aseq, bseq, &m) != 0)
	continue;

      break;
    }

  return;
}

static void sc_addr2name_free(sc_addr2name_t *a2n)
{
  if(a2n == NULL)
    return;
  if(a2n->addr != NULL) scamper_addr_free(a2n->addr);
  if(a2n->name != NULL) free(a2n->name);
  free(a2n);
  return;
}

static int sc_addr2name_cmp(const sc_addr2name_t *a, const sc_addr2name_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static sc_addr2name_t *sc_addr2name_find(scamper_addr_t *addr)
{
  sc_addr2name_t fm;
  if(ip2name_tree == NULL)
    return NULL;
  fm.addr = addr;
  return splaytree_find(ip2name_tree, &fm);
}

static void sc_addr2adj_free(sc_addr2adj_t *a2a)
{
  int i;
  if(a2a == NULL)
    return;
  if(a2a->addr != NULL) scamper_addr_free(a2a->addr);
  for(i=0; i<2; i++)
    if(a2a->list[i] != NULL)
      slist_free_cb(a2a->list[i], (slist_free_t)sc_ping_free);
  free(a2a);
  return;
}

static sc_addr2adj_t *sc_addr2adj_alloc(scamper_addr_t *addr)
{
  sc_addr2adj_t *a2a = NULL;
  if((a2a = malloc_zero(sizeof(sc_addr2adj_t))) == NULL ||
     (a2a->list[0] = slist_alloc()) == NULL ||
     (a2a->list[1] = slist_alloc()) == NULL)
    {
      sc_addr2adj_free(a2a);
      return NULL;
    }
  a2a->addr = scamper_addr_use(addr);
  return a2a;
}

static int sc_addr2adj_cmp(const sc_addr2adj_t *a, const sc_addr2adj_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static sc_addr2adj_t *sc_addr2adj_find(sc_stree_t *set, scamper_addr_t *addr)
{
  sc_addr2adj_t fm; fm.addr = addr;
  return sc_stree_find(set, &fm);
}

static sc_addr2adj_t *sc_addr2adj_get(sc_stree_t *set, scamper_addr_t *addr)
{
  sc_addr2adj_t *a2a;
  if((a2a = sc_addr2adj_find(set, addr)) != NULL)
    return a2a;
  if((a2a = sc_addr2adj_alloc(addr)) == NULL)
    return NULL;
  if(sc_stree_add(set, a2a) != 0)
    {
      sc_addr2adj_free(a2a);
      return NULL;
    }
  return a2a;
}

static int sc_farrouter_addnear(sc_farrouter_t *fr, sc_router_t *near)
{
  if(slist_tail_push(fr->nears, near) == NULL)
    return -1;
  return 0;
}

static void sc_farrouter_free(sc_farrouter_t *fr)
{
  if(fr == NULL)
    return;
  if(fr->nears != NULL)
    slist_free(fr->nears);
  free(fr);
  return;
}

static sc_farrouter_t *sc_farrouter_alloc(sc_router_t *far)
{
  sc_farrouter_t *fr = NULL;
  if((fr = malloc_zero(sizeof(sc_farrouter_t))) == NULL ||
     (fr->nears = slist_alloc()) == NULL)
    {
      sc_farrouter_free(fr);
      return NULL;
    }
  fr->far = far;
  return fr;
}

static int sc_farrouter_far_cmp(const sc_farrouter_t *a,
				const sc_farrouter_t *b)
{
  if(a->far < b->far) return -1;
  if(a->far > b->far) return  1;
  return 0;
}

static int sc_farrouter_nears_cmp(const sc_farrouter_t *a,
				  const sc_farrouter_t *b)
{
  int ac = slist_count(a->nears);
  int bc = slist_count(b->nears);
  if(ac > bc) return -1;
  if(ac < bc) return  1;
  return 0;
}

static sc_farrouter_t *sc_farrouter_find(sc_stree_t *set, sc_router_t *far)
{
  sc_farrouter_t fm; fm.far = far;
  return sc_stree_find(set, &fm);
}

static sc_farrouter_t *sc_farrouter_get(sc_stree_t *set, sc_router_t *far)
{
  sc_farrouter_t *fr;
  if((fr = sc_farrouter_find(set, far)) != NULL)
    return fr;
  if((fr = sc_farrouter_alloc(far)) == NULL)
    return NULL;
  if(sc_stree_add(set, fr) != 0)
    {
      sc_farrouter_free(fr);
      return NULL;
    }
  return fr;
}

/*
 * sc_astraces_plus1
 *
 * the previous traceroute did not help find an interdomain link that
 * we might trust.  try a different address in the same IPv4 /24 or
 * IPv6 /120.  The default is to try up to five consecutive addresses,
 * but that can be varied to a random address in each /26 or /122 if
 * -O randomdst is used.
 */
static int sc_astraces_plus1(sc_astraces_t *traces, scamper_addr_t *addr)
{
  struct in6_addr in6;
  struct in_addr in;
  uint32_t x;
  uint8_t r;

  if(af == AF_INET)
    {
      memcpy(&in, addr->addr, sizeof(in));
      x = ntohl(in.s_addr);
      if(random_dst != 0)
	{
	  if((x & 0xC0) == 0xC0)
	    return 0;
	  random_u8(&r);
	  x = (x & 0xFFFFFF00) | ((((x & 0xC0) >> 6) + 1) << 6) | (r & 0x3F);
	}
      else
	{
	  if((x & 0xff) >= 5)
	    return 0;
	  x++;
	}
      in.s_addr = htonl(x);
      if((addr = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4, &in)) == NULL)
	return -1;
    }
  else
    {
      memcpy(&in6, addr->addr, sizeof(in6));
      if(random_dst != 0)
	{
	  x = in6.s6_addr[15];
	  if((x & 0xC0) == 0xC0)
	    return 0;
	  random_u8(&r);
	  in6.s6_addr[15] = ((((x & 0xC0) >> 6) + 1) << 6) | (r & 0x3F);
	}
      else
	{
	  if(in6.s6_addr[15] >= 5)
	    return 0;
	  in6.s6_addr[15]++;
	}
      if((addr = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6, &in6)) == NULL)
	return -1;
    }

  if(slist_head_push(traces->dsts, addr) == NULL)
    {
      scamper_addr_free(addr);
      return -1;
    }

  return 0;
}

static int sc_astraces_aliases_procset(slist_t *list)
{
  sc_allytest_t *at = NULL;
  sc_test_t *test = NULL;
  sc_addr2router_t *a2r;
  sc_ping_t *a, *b;
  slist_node_t *sn, *sn2;
  sc_ally_t *ar;
  int total = 0, done = 0;

  /* all pairs for sets <= 10 is 55 worst case */
  if(list == NULL || slist_count(list) < 2 || slist_count(list) > 10)
    return 0;

  if((at = sc_allytest_alloc()) == NULL)
    {
      logerr("%s: could not alloc allytest\n", __func__);
      goto err;
    }

  for(sn = slist_head_node(list); sn != NULL; sn = slist_node_next(sn))
    {
      a2r = slist_node_item(sn);
      if(slist_tail_push(at->addr_list, a2r->data) == NULL)
	{
	  logerr("%s: could not push addr on list\n", __func__);
	  goto err;
	}
      a2r->data = NULL;
    }
  for(sn=slist_head_node(at->addr_list); sn != NULL; sn = slist_node_next(sn))
    {
      a = slist_node_item(sn);
      for(sn2 = slist_node_next(sn); sn2 != NULL; sn2 = slist_node_next(sn2))
	{
	  b = slist_node_item(sn2);
	  total++;
	  if((ar = sc_ally_find(a->addr, b->addr)) != NULL)
	    {
	      done++;
	      if(ar->result == SCAMPER_DEALIAS_RESULT_ALIASES &&
		 sc_routerset_getpair(at->routers, a->addr, b->addr) == NULL)
		{
		  logerr("%s: could not add pair\n", __func__);
		  goto err;
		}
	    }
	  else if(at->s1 == NULL)
	    {
	      at->s1 = sn;
	      at->s2 = sn2;
	    }
	}
    }
  logprint("%s: %u %u\n", __func__, done, total);
  if(done == total)
    {
      sc_allytest_free(at);
      return 0;
    }

  if((test = sc_test_alloc(TEST_ALLY, at)) == NULL || sc_waittest(test) != 0)
    {
      logerr("%s: could not schedule test\n", __func__);
      goto err;
    }

  return 0;

 err:
  if(at != NULL) sc_allytest_free(at);
  if(test != NULL) sc_test_free(test);
  return -1;
}

static int sc_astraces_aliases(sc_astraces_t *traces)
{
  sc_routerset_t *rs = NULL;
  sc_addr2router_t *a2r;
  sc_stree_t *set = NULL;
  char buf[64], buf2[64];
  slist_node_t *sn;
  dlist_node_t *dn;
  sc_ping_t *a, *b;
  sc_addr2adj_t *a2a;
  sc_router_t *ra, *rb;
  sc_indir_t *indir;
  sc_link_t *link;
  int i;

  if(traces->links == NULL)
    return 0;

  if((set = sc_stree_alloc((splaytree_cmp_t)sc_addr2adj_cmp)) == NULL)
    return -1;

  for(sn = slist_head_node(traces->links->list);
      sn != NULL; sn = slist_node_next(sn))
    {
      link = slist_node_item(sn);
      indir = link->data;
      printf("%s %s\n",
	     scamper_addr_tostr(link->a, buf, sizeof(buf)),
	     scamper_addr_tostr(link->b, buf2, sizeof(buf2)));

      /* don't test aliases for outside routers more than one hop away */
      if(is_vp(link->a) != 1)
	{
	  if((a2a = sc_addr2adj_get(set, link->a)) == NULL ||
	     (b = sc_ping_alloc(link->b)) == NULL)
	    goto err;
	  b->indir.dst = scamper_addr_use(indir->dst);
	  b->indir.csum = indir->csum;
	  b->indir.ttl = indir->ttl+1;
	  if(slist_tail_push(a2a->list[0], b) == NULL)
	    goto err;
	}

      if((a2a = sc_addr2adj_get(set, link->b)) == NULL ||
	 (a = sc_ping_alloc(link->a)) == NULL)
	goto err;
      a->indir.dst = scamper_addr_use(indir->dst);
      a->indir.csum = indir->csum;
      a->indir.ttl = indir->ttl;
      if(slist_tail_push(a2a->list[1], a) == NULL)
	goto err;
    }

  if((rs = sc_routerset_alloc()) == NULL)
    goto err;

  for(sn = slist_head_node(set->list); sn != NULL; sn = slist_node_next(sn))
    {
      a2a = slist_node_item(sn);
      for(i=0; i<2; i++)
	{
	  if(a2a->list[i] == NULL || slist_count(a2a->list[i]) < 2)
	    continue;

	  /* get a pointer to a router object representing address A */
	  a = slist_head_pop(a2a->list[i]);
	  if((a2r = sc_routerset_a2r_find(rs, a->addr)) != NULL)
	    {
	      sc_ping_free(a);
	    }
	  else
	    {
	      if((a2r = sc_routerset_a2r_get(rs, a->addr)) == NULL)
		goto err;
	      a2r->data = a;
	    }
	  ra = a2r->router;

	  /* go through all other addresses in the set B */
	  while((b = slist_head_pop(a2a->list[i])) != NULL)
	    {
	      if((a2r = sc_routerset_a2r_find(rs, b->addr)) == NULL)
		{
		  if((a2r = sc_routerset_a2r_add(rs, ra, b->addr)) == NULL)
		    goto err;
		  a2r->data = b;
		  continue;
		}

	      if((rb = a2r->router) != ra)
		{
		  while((a2r = slist_head_pop(rb->addrs)) != NULL)
		    {
		      a2r->router = ra;
		      if(slist_tail_push(ra->addrs, a2r) == NULL)
			goto err;
		    }
		  sc_routerset_pop(rs, rb);
		  sc_router_free(rb);
		}
	      sc_ping_free(b);
	    }
	}
    }

  for(dn = dlist_head_node(rs->list); dn != NULL; dn = dlist_node_next(dn))
    {
      ra = dlist_node_item(dn);
      if(sc_astraces_aliases_procset(ra->addrs) != 0)
	{
	  logerr("procset\n");
	  goto err;
	}
    }

  splaytree_inorder(rs->tree, sc_addr2router_free_ping, NULL);
  sc_routerset_free(rs);
  sc_stree_free(set, (slist_free_t)sc_addr2adj_free);
  return 0;

 err:
  logerr("%s: %s\n", __func__, strerror(errno));
  if(set != NULL)
    sc_stree_free(set, (slist_free_t)sc_addr2adj_free);
  if(rs != NULL)
    sc_routerset_free(rs);
  return -1;
}

static void sc_astraces_link_free(sc_link_t *link)
{
  if(link == NULL)
    return;
  if(link->data != NULL)
    sc_indir_free(link->data);
  sc_link_free(link);
  return;
}

static int sc_astraces_link_add(sc_astraces_t *traces, scamper_addr_t *a,
				scamper_addr_t *b, const sc_indir_t *indir_in)
{
  sc_link_t fm, *link = NULL;
  sc_indir_t *indir = NULL;

  if(traces->links == NULL &&
     (traces->links = sc_stree_alloc((splaytree_cmp_t)sc_link_cmp)) == NULL)
    {
      logerr("%s: traces->links: %s\n", __func__, strerror(errno));
      goto err;
    }

  fm.a = a; fm.b = b;
  if(sc_stree_find(traces->links, &fm) != NULL)
    return 0;

  if((link = sc_link_alloc(a, b)) == NULL)
    {
      logerr("%s: link alloc: %s\n", __func__, strerror(errno));
      goto err;
    }

  if((indir = sc_indir_alloc()) == NULL)
    {
      logerr("%s: indir alloc: %s\n", __func__, strerror(errno));
      goto err;
    }
  indir->dst  = scamper_addr_use(indir_in->dst);
  indir->ttl  = indir_in->ttl;
  indir->csum = indir_in->csum;

  if(sc_stree_add(traces->links, link) != 0)
    {
      logerr("%s: link add: %s\n", __func__, strerror(errno));
      goto err;
    }
  link->data = indir;

  return 0;

 err:
  if(link != NULL) sc_link_free(link);
  if(indir != NULL) sc_indir_free(indir);
  return -1;
}

static int sc_astraces_gss_add(sc_astraces_t *traces, scamper_addr_t *addr)
{
  if(no_gss != 0)
    return 0;
  if(traces->gss == NULL &&
     (traces->gss = sc_stree_alloc((splaytree_cmp_t)scamper_addr_cmp)) == NULL)
    return -1;
  if(sc_stree_find(traces->gss, addr) != NULL)
    return 0;
  if(sc_stree_add(traces->gss, addr) != 0)
    return -1;
  scamper_addr_use(addr);
  return 0;
}

static int sc_astraces_dst_add(sc_astraces_t *traces, void *addr)
{
  scamper_addr_t *sa = NULL;
  int type;
  if(af == AF_INET)
    type = SCAMPER_ADDR_TYPE_IPV4;
  else
    type = SCAMPER_ADDR_TYPE_IPV6;
  if((sa = scamper_addr_alloc(type, addr)) == NULL ||
     slist_tail_push(traces->dsts, sa) == NULL)
    goto err;
  return 0;
 err:
  if(sa != NULL) scamper_addr_free(sa);
  return -1;
}

static void sc_astraces_free(sc_astraces_t *traces)
{
  if(traces == NULL)
    return;
  if(traces->dsts != NULL)
    slist_free(traces->dsts);
  if(traces->gss != NULL)
    sc_stree_free(traces->gss, (sc_stree_free_t)scamper_addr_free);
  if(traces->links != NULL)
    sc_stree_free(traces->links, (sc_stree_free_t)sc_astraces_link_free);
  free(traces);
  return;
}

static sc_astraces_t *sc_astraces_alloc(void)
{
  sc_astraces_t *traces = NULL;
  if((traces = malloc_zero(sizeof(sc_astraces_t))) == NULL ||
     (traces->dsts = slist_alloc()) == NULL)
    goto err;
  return traces;
 err:
  if(traces != NULL) sc_astraces_free(traces);
  return NULL;
}

static int sc_astraces_count(sc_astraces_t *a, int *count)
{
  *count += slist_count(a->dsts);
  return 0;
}

/*
 * sc_astraces_count_cmp
 *
 * sort function to put large astraces first, to hopefully encourage
 * bdrmap to complete faster, rather than schedule large sets for the end.
 * used by -O impatient.
 */
static int sc_astraces_count_cmp(const sc_astraces_t *a, const sc_astraces_t *b)
{
  int ac = slist_count(a->dsts);
  int bc = slist_count(b->dsts);
  if(ac > bc) return -1;
  if(ac < bc) return  1;
  return 0;
}

static int sc_astraces_shuffle(sc_astraces_t *traces, void *param)
{
  slist_shuffle(traces->dsts);
  return 0;
}

static int sc_astraces_cmp(const sc_astraces_t *a, const sc_astraces_t *b)
{
  return sc_asmap_cmp(a->asmap, b->asmap);
}

static sc_astraces_t *sc_astraces_get(splaytree_t *tree, sc_asmap_t *asmap)
{
  sc_astraces_t fm, *traces;
  fm.asmap = asmap;
  if((traces = splaytree_find(tree, &fm)) != NULL)
    return traces;
  if((traces = sc_astraces_alloc()) == NULL)
    return NULL;
  traces->asmap = asmap;
  if(splaytree_insert(tree, traces) == NULL)
    goto err;
  return traces;
 err:
  if(traces != NULL) sc_astraces_free(traces);
  return NULL;
}

static int sc_traceset_cmp(const sc_traceset_t *a, const sc_traceset_t *b)
{
  if(a->asn < b->asn) return -1;
  if(a->asn > b->asn) return  1;
  return 0;
}

static void sc_traceset_free(sc_traceset_t *ts)
{
  if(ts == NULL)
    return;
  if(ts->list != NULL)
    slist_free_cb(ts->list, (slist_free_t)scamper_trace_free);
  free(ts);
  return;
}

static sc_traceset_t *sc_traceset_alloc(uint32_t asn)
{
  sc_traceset_t *ts = NULL;
  if((ts = malloc_zero(sizeof(sc_traceset_t))) == NULL ||
     (ts->list = slist_alloc()) == NULL)
    goto err;
  ts->asn = asn;
  return ts;

 err:
  if(ts != NULL) sc_traceset_free(ts);
  return NULL;
}

static sc_traceset_t *sc_traceset_find(uint32_t asn)
{
  sc_traceset_t fm;
  fm.asn = asn;
  return splaytree_find(tracesets, &fm);
}

static sc_traceset_t *sc_traceset_get(uint32_t asn)
{
  sc_traceset_t *ts = NULL;
  if((ts = sc_traceset_find(asn)) != NULL)
    return ts;
  if((ts = sc_traceset_alloc(asn)) == NULL ||
     splaytree_insert(tracesets, ts) == NULL)
    goto err;
  return ts;

 err:
  if(ts != NULL) sc_traceset_free(ts);
  return NULL;
}

static int sc_delegated_cmp(const sc_delegated_t *a, const sc_delegated_t *b)
{
  uint32_t sa, sb;
  sa = ntohl(a->y.s_addr) - ntohl(a->x.s_addr);
  sb = ntohl(b->y.s_addr) - ntohl(b->x.s_addr);
  if(sa > sb) return -1;
  if(sa < sb) return 1;
  return 0;
}

static sc_delegated_t *sc_delegated_find(scamper_addr_t *addr)
{
  sc_delegated_t *dg;
  slist_node_t *sn;
  struct in_addr in;

  if(delegated == NULL)
    return NULL;

  memcpy(&in, addr->addr, sizeof(in));
  in.s_addr = ntohl(in.s_addr);
  for(sn=slist_head_node(delegated); sn != NULL; sn=slist_node_next(sn))
    {
      dg = slist_node_item(sn);
      if(in.s_addr >= ntohl(dg->x.s_addr) && in.s_addr <= ntohl(dg->y.s_addr))
	break;
    }
  if(sn == NULL)
    return NULL;
  return slist_node_item(sn);
}

static uint8_t sc_delegated_netlen(sc_delegated_t *dg)
{
  uint32_t size = ntohl(dg->y.s_addr) - ntohl(dg->x.s_addr);
  switch(size)
    {
    case 256: return 24;
    case 512: return 23;
    case 1024: return 22;
    case 2048: return 21;
    case 4096: return 20;
    case 8192: return 19;
    case 16384: return 18;
    case 32768: return 17;
    case 65536: return 16;
    case 131072: return 15;
    case 262144: return 14;
    case 524288: return 13;
    case 1048576: return 12;
    case 2097152: return 11;
    case 4194304: return 10;
    case 8388608: return  9;
    case 16777216: return 8;
    }
  return 0;
}

static void trace_dump(const scamper_trace_t *trace, sc_routerset_t *rtrset)
{
  scamper_trace_hop_t *hop;
  sc_prefix_t *pfx;
  sc_router_t *rtr;
  char buf[128];
  int i;

  /* dump the traceroute output */
  printf("trace to %s", scamper_addr_tostr(trace->dst, buf, sizeof(buf)));
  if((pfx = sc_prefix_find(trace->dst)) != NULL)
    printf(" %s", sc_asmap_tostr(pfx->asmap, buf, sizeof(buf)));
  printf("\n");

  for(i=trace->firsthop-1; i<trace->hop_count; i++)
    {
      printf("%2d ", i+1);
      if((hop = trace->hops[i]) == NULL)
	{
	  printf("*\n");
	  continue;
	}
      printf("%s <%u,%u> %d",
	     scamper_addr_tostr(hop->hop_addr, buf, sizeof(buf)),
	     hop->hop_icmp_type, hop->hop_icmp_code,
	     is_vp(hop->hop_addr));
      if(is_ixp(hop->hop_addr) != 0)
	printf(" ixp");
      else if((pfx = sc_prefix_find(hop->hop_addr)) != NULL)
	printf(" %s", sc_asmap_tostr(pfx->asmap, buf, sizeof(buf)));
      else
	printf(" null");

      if(rtrset != NULL &&
	 (rtr = sc_routerset_find(rtrset, hop->hop_addr)) != NULL)
	printf(" %u:%s", rtr->owner_as, owner_reasonstr[rtr->owner_reason]);

      printf("\n");
    }

  return;
}

static void traceset_dump(const sc_traceset_t *ts, sc_routerset_t *rtrset)
{
  slist_node_t *sn;
  for(sn=slist_head_node(ts->list); sn != NULL; sn=slist_node_next(sn))
    trace_dump(slist_node_item(sn), rtrset);
  printf("\n");
  return;
}

static int do_method_trace(sc_test_t *test, char *cmd, size_t len)
{
  sc_tracetest_t *tt = test->data;
  scamper_addr_t *addr;
  sc_target_t *found;
  slist_node_t *sn;
  size_t off = 0;
  char buf[128];

  /* first, check to see if the test is runnable. if not block */
  if((found = sc_target_find(tt->target)) != NULL && found->test != test)
    {
      if(sc_target_block(found, test) != 0)
	return -1;
      return 0;
    }
  else if(found == NULL)
    {
      /* add the test to the blocked list */
      if(sc_target_add(tt->target) != 0)
	return -1;
    }

  string_concat(cmd, len, &off, "trace -w 1 -P icmp-paris -d %u", csum);
  if(firsthop > 1)
    string_concat(cmd, len, &off, " -f %u", firsthop);
  if(no_gss == 0 && tt->astraces->gss != NULL)
    {
      if(firsthop > 1)
	string_concat(cmd, len, &off, " -O dtree-noback");
      sn = slist_head_node(tt->astraces->gss->list);
      while(sn != NULL)
	{
	  addr = slist_node_item(sn);
	  string_concat(cmd, len, &off, " -z %s",
			scamper_addr_tostr(addr,buf,sizeof(buf)));
	  sn = slist_node_next(sn);
	}
    }
  string_concat(cmd, len, &off, " %s\n",
		scamper_addr_tostr(tt->target->addr, buf, sizeof(buf)));

  return off;
}

static int do_method_ping(sc_test_t *test, char *cmd, size_t len)
{
  static const char *method[] = {"icmp-echo", "tcp-ack-sport",
				 "udp-dport", "icmp-echo"};
  static const char *wait[] = {"0.3", "0.5", "1", "0.5"};
  sc_pingtest_t *pt = test->data;
  sc_ping_t *ping = pt->ping;
  size_t off = 0;
  char buf[128];

  assert(pt->method >= 0);
  assert(pt->method < 4);
  assert(pt->method < 3 || ping->indir.dst != NULL);

  string_concat(cmd, len, &off, "ping -P %s -i %s -c %u -o %u",
		method[pt->method], wait[pt->method], attempts + 2, attempts);

  if(pt->method == METHOD_INDIR)
    string_concat(cmd, len, &off, " -m %u -C %u %s", ping->indir.ttl,
		  ping->indir.csum,
		  scamper_addr_tostr(ping->indir.dst, buf, sizeof(buf)));
  else
    string_concat(cmd, len, &off, " %s",
		  scamper_addr_tostr(ping->addr, buf, sizeof(buf)));
  string_concat(cmd, len, &off, "\n");

  return off;
}

/*
 * do_method_ipidseq_addr
 *
 * this function
 */
static int do_method_ipidseq_addr(sc_test_t *test, scamper_addr_t *addr,
				  char *cmd, size_t len)
{
  sc_pingtest_t *pt;
  sc_target_t *found;
  sc_test_t *tt;

  if((found = sc_target_findaddr(addr)) != NULL)
    {
      logprint("%s: ipidseq found %p\n", __func__, found);
      if(sc_target_block(found, test) != 0)
	return -1;
      return 0;
    }

  if((tt = sc_pingtest_alloc(addr)) == NULL)
    return -1;
  pt = tt->data;
  if(sc_target_block(pt->target, test) != 0)
    return -1;
  if(sc_target_add(pt->target) != 0)
    {
      logerr("%s: could not add target\n", __func__);
      return -1;
    }
  return do_method_ping(tt, cmd, len);
}

/*
 * do_method_ipidseq_ping
 *
 * this function is a hack function to use when we first need to determine
 * which probe methods might be able to get an incrementing IPID.  The
 * ping structure is filled out with an indirect probing method.
 */
static int do_method_ipidseq_ping(sc_test_t *test, sc_ping_t *ping,
				  char *cmd, size_t len)
{
  sc_pingtest_t *pt;
  sc_target_t *found;
  sc_test_t *tt;

  if((found = sc_target_findaddr(ping->addr)) != NULL ||
     (found = sc_target_findaddr(ping->indir.dst)) != NULL)
    {
      logprint("%s: ipidseq found %p\n", __func__, found);
      if(sc_target_block(found, test) != 0)
	return -1;
      return 0;
    }

  if((tt = sc_pingtest_alloc(ping->addr)) == NULL)
    return -1;
  pt = tt->data;
  if(sc_target_block(pt->target, test) != 0)
    return -1;
  if(sc_target_add(pt->target) != 0)
    {
      logerr("%s: could not add target\n", __func__);
      return -1;
    }

  /* set up the indirect probing */
  pt->ping->indir.dst = scamper_addr_use(ping->indir.dst);
  pt->ping->indir.csum = ping->indir.csum;
  pt->ping->indir.ttl = ping->indir.ttl;

  /* only try and add t2 if we're probing a different address */
  if(scamper_addr_cmp(ping->indir.dst, ping->addr) != 0)
    {
      if((pt->t2 = sc_target_alloc(ping->indir.dst)) == NULL)
	return -1;
      pt->t2->test = tt;
      if(sc_target_add(pt->t2) != 0)
	{
	  logerr("%s: could not add t2\n", __func__);
	  return -1;
	}
    }

  /*
   * if we have already probed this address before, and just need indirect
   * probing, then skip to that now
   */
  if(pt->ping->methods[0] != IPID_NONE)
    pt->method = METHOD_INDIR;

  return do_method_ping(tt, cmd, len);
}

static int do_method_link(sc_test_t *test, char *cmd, size_t len)
{
  static const char *method[] = {"icmp-echo", "tcp-ack", "udp-dport"};
  static const uint16_t wait[] = {300, 500, 1000};
  sc_linktest_t *lt = test->data;
  sc_link_t *link = lt->link;
  char a[128], b[128];
  sc_target_t *found;
  sc_ping_t *ping;
  size_t off = 0;

  if(lt->step == TEST_LINK_PREFIXSCAN)
    {
      if((ping = sc_ping_find(link->a)) == NULL)
	return do_method_ipidseq_addr(test, link->a, cmd, len);
      while(ping->methods[lt->method] != IPID_INCR && lt->method < METHOD_UDP)
	lt->method++;
      if(ping->methods[lt->method] == IPID_INCR ||
	 (lt->method == METHOD_UDP && ping->methods[lt->method] != IPID_UNRESP))
	{
	  string_concat(cmd, len, &off, "dealias -m prefixscan");
	  if(fudge == 0)
	    string_concat(cmd, len, &off, " -O inseq");
	  else
	    string_concat(cmd, len, &off, " -f %u", fudge);
	  string_concat(cmd, len, &off, " -W %u -p '-P %s' %s %s/30\n",
			wait[lt->method], method[lt->method],
			scamper_addr_tostr(link->a, a, sizeof(a)),
			scamper_addr_tostr(link->b, b, sizeof(b)));
	  goto done;
	}

      lt->method = 0;
      if(no_ipopts != 0)
	{
	  sc_linktest_free(lt);
	  sc_test_free(test);
	  goto done;
	}
      lt->step = TEST_LINK_RR;
    }

  if(lt->step == TEST_LINK_RR)
    {
      string_concat(cmd, len, &off, "ping -R %s\n",
		    scamper_addr_tostr(link->b, b, sizeof(b)));
    }
  else if(lt->step == TEST_LINK_PSTS)
    {
      if(lt->method == 0)
	scamper_addr_tostr(link->a, a, sizeof(a));
      else
	scamper_addr_tostr(lt->ab, a, sizeof(a));
      scamper_addr_tostr(link->b, b, sizeof(b));
      string_concat(cmd, len, &off, "ping -T tsprespec=%s,%s %s\n", b, a, b);
    }

 done:
  if(off == 0)
    return 0;

  if(((found = sc_target_find(lt->ta)) != NULL && found->test != test) ||
     ((found = sc_target_find(lt->tb)) != NULL && found->test != test))
    {
      if(sc_target_block(found, test) != 0)
	return -1;
      return 0;
    }
  if((sc_target_find(lt->ta) == NULL && sc_target_add(lt->ta) != 0) ||
     (sc_target_find(lt->tb) == NULL && sc_target_add(lt->tb) != 0))
    return -1;

  return off;
}

static int do_method_ally(sc_test_t *test, char *cmd, size_t len)
{
  static const char *method[] = {"icmp-echo", "tcp-ack-sport",
				 "udp-dport", "icmp-echo"};
  static const uint16_t wait[] = {300, 500, 1000, 500};
  sc_allytest_t *at = test->data;
  sc_ping_t *aseq = NULL, *bseq = NULL, *a, *b;
  sc_target_t *found;
  char ab[64], bb[64];
  size_t off = 0;

  for(;;)
    {
      a = slist_node_item(at->s1);
      b = slist_node_item(at->s2);
      if((aseq = sc_ping_find(a->addr)) == NULL ||
	 (aseq->indir.dst == NULL && a->indir.dst != NULL))
	return do_method_ipidseq_ping(test, a, cmd, len);
      if((bseq = sc_ping_find(b->addr)) == NULL ||
	 (bseq->indir.dst == NULL && b->indir.dst != NULL))
	return do_method_ipidseq_ping(test, b, cmd, len);
      if(sc_ping_method(aseq, bseq, &at->method) != 0)
	{
	  sc_allytest_next(at);
	  if(at->s1 == NULL)
	    {
	      sc_allytest_free(at);
	      sc_test_free(test);
	      return 0;
	    }
	  continue;
	}
      break;
    }

  if(at->a == NULL)
    {
      if(at->method != METHOD_INDIR)
	at->a = sc_target_alloc(aseq->addr);
      else
	at->a = sc_target_alloc(aseq->indir.dst);
      if(at->a == NULL)
	return -1;
      at->a->test = test;
    }
  if(at->b == NULL)
    {
      if(at->method != METHOD_INDIR)
	at->b = sc_target_alloc(bseq->addr);
      else
	at->b = sc_target_alloc(bseq->indir.dst);
      if(at->b == NULL)
	return -1;
      at->b->test = test;
    }

  if(((found = sc_target_find(at->a)) != NULL && found->test != test) ||
     ((found = sc_target_find(at->b)) != NULL && found->test != test))
    {
      if(sc_target_block(found, test) != 0)
	return -1;
      return 0;
    }

  if((sc_target_find(at->a) == NULL && sc_target_add(at->a) != 0) ||
     (sc_target_find(at->b) == NULL && sc_target_add(at->b) != 0))
    {
      logerr("%s: could not add target %d\n", __func__, at->method);
      return -1;
    }

  string_concat(cmd, len, &off,
		"dealias -m ally -W %u -q %u", wait[at->method], attempts);
  if(fudge == 0)
    string_concat(cmd, len, &off, " -O inseq");
  else
    string_concat(cmd, len, &off, " -f %d", fudge);

  if(at->method != METHOD_INDIR)
    {
      string_concat(cmd, len, &off, " -p '-P %s' %s %s",
		    method[at->method],
		    scamper_addr_tostr(aseq->addr, ab, sizeof(ab)),
		    scamper_addr_tostr(bseq->addr, bb, sizeof(bb)));
    }
  else
    {
      string_concat(cmd, len, &off, " -p '-P %s -c %u -t %u -i %s'",
		    method[at->method], aseq->indir.csum, aseq->indir.ttl,
		    scamper_addr_tostr(aseq->indir.dst, ab, sizeof(ab)));
      string_concat(cmd, len, &off, " -p '-P %s -c %u -t %u -i %s'",
		    method[at->method], bseq->indir.csum, bseq->indir.ttl,
		    scamper_addr_tostr(bseq->indir.dst, bb, sizeof(bb)));
    }
  string_concat(cmd, len, &off, "\n");

  return off;
}

static int do_method_allyconf(sc_test_t *test, char *cmd, size_t len)
{
  static const char *method[] = {"icmp-echo", "tcp-ack-sport",
				 "udp-dport", "icmp-echo"};
  static const uint16_t wait[] = {300, 500, 1000, 500};
  sc_allyconftest_t *act = test->data;
  sc_ping_t *aseq = NULL, *bseq = NULL;
  scamper_addr_t *a, *b;
  sc_target_t *found;
  char ab[64], bb[64];
  size_t off = 0;

  assert(act->a == NULL);
  assert(act->b == NULL);

  if(act->method != METHOD_INDIR)
    {
      a = act->ally->a;
      b = act->ally->b;
    }
  else
    {
      if((aseq = sc_ping_find(act->ally->a)) == NULL ||
	 (bseq = sc_ping_find(act->ally->b)) == NULL)
	{
	  logerr("%s: could not find ipidseq\n");
	  return -1;
	}
      a = aseq->indir.dst;
      b = aseq->indir.dst;
    }

  if(((found = sc_target_findaddr(a)) != NULL && found->test != test) ||
     ((found = sc_target_findaddr(b)) != NULL && found->test != test))
    {
      if(sc_target_block(found, test) != 0)
	{
	  logerr("%s: could not block\n", __func__);
	  return -1;
	}
      return 0;
    }
  if((act->a = sc_target_alloc(a)) == NULL ||
     (act->b = sc_target_alloc(b)) == NULL)
    {
      logerr("%s: could not alloc target\n", __func__);
      return -1;
    }
  act->a->test = test;
  act->b->test = test;

  if((sc_target_find(act->a) == NULL && sc_target_add(act->a) != 0) ||
     (sc_target_find(act->b) == NULL && sc_target_add(act->b) != 0))
    {
      logerr("%s: could not add target %d\n", __func__, act->method);
      return -1;
    }

  string_concat(cmd, len, &off, "dealias -m ally -W %u -q %u -O inseq",
		wait[act->method], attempts+2);
  if(act->method != METHOD_INDIR)
    {
      string_concat(cmd, len, &off, " -p '-P %s' %s %s",
		    method[act->method],
		    scamper_addr_tostr(a, ab, sizeof(ab)),
		    scamper_addr_tostr(b, bb, sizeof(bb)));
    }
  else
    {
      string_concat(cmd, len, &off, " -p '-P %s -c %u -t %u -i %s'",
		    method[act->method], aseq->indir.csum, aseq->indir.ttl,
		    scamper_addr_tostr(aseq->indir.dst, ab, sizeof(ab)));
      string_concat(cmd, len, &off, " -p '-P %s -c %u -t %u -i %s'",
		    method[act->method], bseq->indir.csum, bseq->indir.ttl,
		    scamper_addr_tostr(bseq->indir.dst, bb, sizeof(bb)));
    }
  string_concat(cmd, len, &off, "\n");

  return off;
}

static int virgin_pop(sc_test_t **out)
{
  scamper_addr_t *addr = NULL;
  sc_tracetest_t *tt;
  sc_astraces_t *traces;

  if((traces = slist_head_pop(virgin)) == NULL)
    {
      *out = NULL;
      return 0;
    }
  addr = slist_head_pop(traces->dsts);
  if((tt = sc_tracetest_alloc(addr)) == NULL)
    goto err;
  scamper_addr_free(addr); addr = NULL;
  tt->astraces = traces;
  *out = tt->target->test;
  return 0;

 err:
  return -1;
}

static int do_method(void)
{
  static int (*const func[])(sc_test_t *, char *, size_t) = {
    do_method_trace,
    do_method_link,
    do_method_ping,
    do_method_ally,
    do_method_allyconf,
  };
  sc_waittest_t *wt;
  sc_test_t *test;
  int off;

  if(more < 1)
    return 0;

  for(;;)
    {
      if((wt = heap_head_item(waiting)) != NULL &&
	 timeval_cmp(&now, &wt->tv) >= 0)
	{
	  test = wt->test;
	  heap_remove(waiting);
	  free(wt);
	}
      else
	{
	  if(virgin_pop(&test) != 0)
	    return -1;
	  if(test == NULL)
	    return 0;
	}

      if((off = func[test->type](test, cmd, sizeof(cmd))) == -1)
	{
	  logerr("%s: something went wrong, type %d\n", __func__, test->type);
	  return -1;
	}

      /* got a command, send it */
      if(off != 0)
	{
	  write_wrap(scamper_fd, cmd, NULL, off);
	  probing++;
	  more--;

	  logprint("p %d, w %d, v %d : %s", probing, heap_count(waiting),
		   slist_count(virgin), cmd);

	  break;
	}
    }

  return 0;
}

static int do_decoderead_dealias_pfxscan(scamper_dealias_t *dealias)
{
  scamper_dealias_prefixscan_t *pfs = dealias->data;
  sc_linktest_t *lt;
  sc_target_t *tg;
  sc_test_t *test;
  sc_ally_t *ar;
  char a[32], b[32], ab[32];

  scamper_addr_tostr(pfs->a, a, sizeof(a));
  scamper_addr_tostr(pfs->b, b, sizeof(b));

  if((tg = sc_target_findaddr(pfs->a)) == NULL)
    {
      logerr("%s: could not find %s:%s\n", __func__, a, b);
      return -1;
    }
  test = tg->test;
  assert(test->type == TEST_LINK);
  lt = test->data;

  if((pfs->ab == NULL || scamper_addr_prefixhosts(pfs->b, pfs->ab) < 30) &&
     lt->method != METHOD_PFXS_LAST)
    {
      lt->method++;
    }
  else
    {
      if(pfs->ab != NULL)
	{
	  /*
	   * if we inferred a /30 mate, and not with the common-source-address
	   * technique (i.e., it was derived from IP-ID) then record an
	   * alias (if one does not already exist), and schedule a confirmation
	   * sequence.
	   */
	  if((pfs->flags & SCAMPER_DEALIAS_PREFIXSCAN_FLAG_CSA) == 0)
	    {
	      if(sc_ally_find(pfs->a, pfs->ab) == NULL)
		{
		  if((ar = sc_ally_get(pfs->a, pfs->ab)) == NULL)
		    {
		      logerr("%s: could not get ally %s:%s: %s\n", __func__,
			     a, scamper_addr_tostr(pfs->ab,b,sizeof(b)),
			     strerror(errno));
		      return -1;
		    }
		  if(allyconf > 0 &&
		     sc_allyconftest_alloc(ar, lt->method) == NULL)
		    {
		      logerr("%s: could not add allyconftest: %s",
			     __func__, strerror(errno));
		      return -1;
		    }
		}
	    }

	  lt->ab = scamper_addr_use(pfs->ab);
	  logprint("pfxscan %s %s finished: %s/%d\n", a, b,
		   scamper_addr_tostr(pfs->ab, ab, sizeof(ab)),
		   scamper_addr_prefixhosts(pfs->b, pfs->ab));
	}
      else
	{
	  logprint("pfxscan %s %s finished\n", a, b);
	}
      lt->method = 0;
      if(no_ipopts != 0)
	{
	  sc_linktest_free(lt);
	  sc_test_free(test);
	  return 0;
	}
      lt->step = TEST_LINK_RR;
    }

  if(sc_waittest(test) != 0)
    {
      logerr("%s: could not waittest\n", __func__);
      return -1;
    }

  return 0;
}

static int do_decoderead_dealias_ally(scamper_dealias_t *dealias)
{
  scamper_dealias_ally_t *ally = dealias->data;
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply;
  char buf[384], ab[32], bb[32];
  sc_allytest_t *at = NULL;
  sc_allyconftest_t *act = NULL;
  sc_test_t *test = NULL;
  scamper_addr_t *p[2];
  sc_target_t *tg;
  sc_ally_t *ar;
  size_t off = 0;
  uint32_t i;

  if((tg = sc_target_findaddr(ally->probedefs[0].dst)) == NULL)
    {
      logerr("%s: could not find %s\n", __func__,
	     scamper_addr_tostr(ally->probedefs[0].dst, ab, sizeof(ab)));
      return -1;
    }
  test = tg->test;

  if(test->type == TEST_ALLY)
    {
      at = test->data;
      at->attempt++;
      p[0] = ((sc_ping_t *)slist_node_item(at->s1))->addr;
      p[1] = ((sc_ping_t *)slist_node_item(at->s2))->addr;
    }
  else if(test->type == TEST_ALLYCONF)
    {
      act = test->data;
      act->count--;
      p[0] = act->ally->a;
      p[1] = act->ally->b;
    }
  else
    {
      logerr("%s: unexpected test type %d\n", __func__, test->type);
      goto err;
    }

  string_concat(buf, sizeof(buf), &off, "ally %s:%s",
		scamper_addr_tostr(p[0], ab, sizeof(ab)),
		scamper_addr_tostr(p[1], bb, sizeof(bb)));

  /* check for indirect probing */
  if(scamper_addr_cmp(p[0], ally->probedefs[0].dst) != 0)
    {
      string_concat(buf, sizeof(buf), &off, " indir %s:%s",
		    scamper_addr_tostr(ally->probedefs[0].dst, ab, sizeof(ab)),
		    scamper_addr_tostr(ally->probedefs[1].dst, bb, sizeof(bb)));

      /* if we inferred aliases, check the addresses returned */
      if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
	{
	  for(i=0; i<dealias->probec; i++)
	    {
	      probe = dealias->probes[i];
	      reply = probe->replies[0];
	      if(scamper_addr_cmp(reply->src, p[probe->def->id]) != 0)
		break;
	    }
	  if(i != dealias->probec)
	    dealias->result = SCAMPER_DEALIAS_RESULT_NONE;
	}
    }
  string_concat(buf, sizeof(buf), &off, " %s",
		scamper_dealias_result_tostr(dealias, ab, sizeof(ab)));
  logprint("%s\n", buf);

  if(at != NULL)
    {
      /* if we already have an ally record, skip over this test */
      if(sc_ally_find(p[0], p[1]) != NULL)
	{
	  sc_allytest_next(at);
	  if(at->s1 == NULL)
	    {
	      sc_allytest_free(at); at = NULL;
	      sc_test_free(test); test = NULL;
	    }
	  else if(sc_waittest(test) != 0)
	    {
	      logerr("%s: could not waittest\n", __func__);
	      goto err;
	    }
	  return 0;
	}

      /* if we didn't get a result, do we try again? */
      if(dealias->result == SCAMPER_DEALIAS_RESULT_NONE && at->attempt <= 4)
	{
	  if(sc_waittest(test) != 0)
	    {
	      logerr("%s: could not waittest\n", __func__);
	      goto err;
	    }
	  return 0;
	}
      else
	{
	  /* we got a result, cache it so we don't try again */
	  if((ar = sc_ally_get(p[0], p[1])) == NULL)
	    {
	      logerr("%s: could not get ally\n", __func__);
	      goto err;
	    }
	  ar->result = dealias->result;

	  /* if we inferred aliases, try and confirm */
	  if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
	    {
	      if(sc_routerset_getpair(at->routers, p[0], p[1]) == NULL)
		{
		  logerr("%s: could not getpair\n", __func__);
		  goto err;
		}

	      if(allyconf > 0 && sc_allyconftest_alloc(ar, at->method) == NULL)
		{
		  logerr("%s: could not add alloc allyconf\n", __func__);
		  goto err;
		}
	    }
	}

      /* move onto the next test pair */
      sc_allytest_next(at);
      if(at->s1 == NULL)
	{
	  sc_allytest_free(at); at = NULL;
	  sc_test_free(test); test = NULL;
	}
      else if(sc_waittest(test) != 0)
	{
	  logerr("%s: could not waittest\n", __func__);
	  goto err;
	}
    }
  else if(act != NULL)
    {
      if(dealias->result == SCAMPER_DEALIAS_RESULT_NOTALIASES)
	act->ally->result = dealias->result;

      if(act->count > 0)
	{
	  sc_target_free(act->a); act->a = NULL;
	  sc_target_free(act->b); act->b = NULL;
	  if(sc_waittest_sec(test, allyconf_wait) != 0)
	    {
	      logerr("%s: could not waittest_sec\n", __func__);
	      goto err;
	    }
	}
      else
	{
	  sc_allyconftest_free(act); act = NULL;
	  sc_test_free(test); test = NULL;
	}
    }

  return 0;

 err:
  if(act != NULL) sc_allyconftest_free(act);
  if(at != NULL) sc_allytest_free(at);
  if(test != NULL) sc_test_free(test);
  return -1;
}

static int do_decoderead_dealias(scamper_dealias_t *dealias)
{
  if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    return do_decoderead_dealias_pfxscan(dealias);
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_ALLY)
    return do_decoderead_dealias_ally(dealias);
  return -1;
}

static int do_decoderead_ping_link(sc_test_t *test, scamper_ping_t *ping)
{
  sc_linktest_t *lt = test->data;
  if(lt->step == TEST_LINK_PSTS)
    {
      if(lt->method == 0 && lt->ab != NULL)
	{
	  lt->method++;
	  if(sc_waittest(test) != 0)
	    return -1;
	  return 0;
	}
      sc_linktest_free(lt); lt = NULL;
      sc_test_free(test); test = NULL;
    }
  else
    {
      lt->step = TEST_LINK_PSTS;
      if(sc_waittest(test) != 0)
	return -1;
    }
  return 0;
}

static int ping_classify(const scamper_addr_t *dst, const scamper_ping_t *ping)
{
  scamper_ping_reply_t *rx;
  int rc = -1, echo = 0, bs = 0, nobs = 0;
  int i, samples[65536];
  uint32_t u32, f, n0, n1;
  slist_t *list = NULL;
  slist_node_t *ln0, *ln1;

  if(ping->stop_reason == SCAMPER_PING_STOP_NONE ||
     ping->stop_reason == SCAMPER_PING_STOP_ERROR)
    return IPID_UNRESP;

  if((list = slist_alloc()) == NULL)
    goto done;

  memset(samples, 0, sizeof(samples));
  for(i=0; i<ping->ping_sent; i++)
    {
      if((rx = ping->ping_replies[i]) != NULL &&
	 (SCAMPER_PING_REPLY_FROM_TARGET(ping, rx) ||
	  (SCAMPER_PING_REPLY_IS_ICMP_TTL_EXP(rx) &&
	   scamper_addr_cmp(dst, rx->addr) == 0)))
	{
	  /*
	   * if at least two of four samples have the same ipid as what was
	   * sent, then declare it echos.  this handles the observed case
	   * where some responses echo but others increment.
	   */
	  if(rx->probe_ipid == rx->reply_ipid && ++echo > 1)
	    {
	      rc = IPID_ECHO;
	      goto done;
	    }

	  /*
	   * if two responses have the same IPID value, declare that it
	   * replies with a constant IPID
	   */
	  if(++samples[rx->reply_ipid] > 1)
	    {
	      rc = IPID_CONST;
	      goto done;
	    }

	  if(slist_tail_push(list, rx) == NULL)
	    goto done;
	}
    }
  if(slist_count(list) < attempts)
    {
      rc = IPID_UNRESP;
      goto done;
    }

  f = (fudge == 0) ? 5000 : fudge;

  ln0 = slist_head_node(list);
  ln1 = slist_node_next(ln0);
  while(ln1 != NULL)
    {
      rx = slist_node_item(ln0); n0 = rx->reply_ipid;
      rx = slist_node_item(ln1); n1 = rx->reply_ipid;

      if(n0 < n1)
	u32 = n1 - n0;
      else
	u32 = (n1 + 0x10000) - n0;
      if(u32 <= f)
	nobs++;

      n0 = byteswap16(n0);
      n1 = byteswap16(n1);
      if(n0 < n1)
	u32 = n1 - n0;
      else
	u32 = (n1 + 0x10000) - n0;
      if(u32 <= f)
	bs++;

      ln0 = ln1;
      ln1 = slist_node_next(ln0);
    }

  if(nobs != attempts-1 && bs != attempts-1)
    rc = IPID_RAND;
  else
    rc = IPID_INCR;

 done:
  if(list != NULL) slist_free(list);
  return rc;
}

/*
 * trace_lasthop
 *
 * process the traceroute, returning the last hop that can be trusted
 * in this traceroute.  in this case, we are looking at looking for the
 * first repeated address in the traceroute, where the repeated address
 * is more than one hop away.
 */
static int trace_lasthop(scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  int i, j, v, L = 0, V = 0;

  /*
   * if there is an address from outside of the network in amongst
   * addresses within the the network, then ignore this traceroute
   * entirely.
   */
  for(i=trace->firsthop-1; i<trace->hop_count; i++)
    {
      if((hop = trace->hops[i]) == NULL)
	continue;
      v = is_vp(hop->hop_addr);
      if(v == 0)
	V = 1;
      else if(v == 1 && V == 1)
	return 0;
    }

  for(i=trace->firsthop-1; i<trace->hop_count; i++)
    {
      if((hop = trace->hops[i]) == NULL)
	continue;
      for(j=i+1; j<trace->hop_count; j++)
	{
	  if(trace->hops[j] == NULL)
	    continue;

	  if(scamper_addr_cmp(hop->hop_addr, trace->hops[j]->hop_addr) != 0)
	    continue;
	  if(i + 1 == j)
	    {
	      if(L > 0)
		return i + 1;
	      L++;
	      continue;
	    }
	  else
	    {
	      return i + 1;
	    }
	}
    }

  return trace->hop_count;
}

static int do_decoderead_ping_ping(sc_test_t *test, scamper_ping_t *ping)
{
  sc_pingtest_t *pt = test->data;
  int class = ping_classify(pt->ping->addr, ping);
  char msg[256], buf[128];
  size_t off;
  int i;

  if(class == -1)
    return -1;

  if(pt->method == METHOD_ICMP || pt->method == METHOD_INDIR)
    assert(SCAMPER_PING_METHOD_IS_ICMP(ping));
  else if(pt->method == METHOD_TCP)
    assert(SCAMPER_PING_METHOD_IS_TCP(ping));
  else if(pt->method == METHOD_UDP)
    assert(SCAMPER_PING_METHOD_IS_UDP(ping));
  else
    return -1;

  pt->ping->methods[pt->method] = class;
  pt->method++;
  if(pt->method < 3 || (pt->method == 3 && pt->ping->indir.dst != NULL))
    {
      if(sc_waittest(test) != 0)
	return -1;
    }
  else
    {
      off = 0;
      string_concat(msg, sizeof(msg), &off, "ping %s:",
		    scamper_addr_tostr(pt->ping->addr, buf, sizeof(buf)));
      for(i=0; i<pt->method; i++)
	string_concat(msg, sizeof(msg), &off, " %s",
		      class_tostr(buf, sizeof(buf), pt->ping->methods[i]));
      logprint("%s\n", msg);
      sc_pingtest_free(pt);
      sc_test_free(test);
    }
  return 0;
}

static int do_decoderead_ping(scamper_ping_t *ping)
{
  sc_target_t *target;
  sc_test_t *test;
  char buf[128];

  if((target = sc_target_findaddr(ping->dst)) == NULL)
    {
      fprintf(stderr, "%s: could not find %s\n", __func__,
	      scamper_addr_tostr(ping->dst, buf, sizeof(buf)));
      return -1;
    }
  test = target->test;
  assert(test != NULL);

  if(test->type == TEST_LINK)
    return do_decoderead_ping_link(test, ping);
  else if(test->type == TEST_PING)
    return do_decoderead_ping_ping(test, ping);

  return -1;
}

static int do_decoderead_trace(scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop, *x, *y;
  scamper_addr_t *addr;
  sc_tracetest_t *tt;
  sc_astraces_t *astraces;
  sc_target_t *target;
  sc_indir_t indir;
  sc_test_t *test;
  char buf[128];
  int i, p1, zttl, lh, lv;

  logprint("trace %s finished\n",
	   scamper_addr_tostr(trace->dst, buf, sizeof(buf)));

  if((target = sc_target_findaddr(trace->dst)) == NULL)
    goto err;

  test = target->test;
  tt = test->data;
  astraces = tt->astraces;

  /* don't need the test anymore */
  sc_tracetest_free(tt); tt = NULL;
  sc_test_free(test); test = NULL;

  /* dump the traceroute output */
  trace_dump(trace, NULL);

  /* figure out how far in the trace we should consider processing */
  if((lh = trace_lasthop(trace)) == 0)
    goto done;

  /* make a note of the last hop mapped to the VP */
  lv = -1;
  for(i=trace->firsthop-1; i<lh; i++)
    if((hop = trace->hops[i]) != NULL && is_vp(hop->hop_addr) == 1)
      lv = i;

  /* figure out if we need to probe another address in the same subnet */
  p1 = 1;
  if(lv != -1)
    i = lv + 1;
  else
    i = trace->firsthop-1;
  while(i < lh)
    {
      if((hop = trace->hops[i]) != NULL && is_vp(hop->hop_addr) == 0)
	{
	  if(scamper_addr_cmp(trace->dst, hop->hop_addr) != 0)
	    p1 = 0;
	  break;
	}
      i++;
    }
  if(p1 != 0 && sc_astraces_plus1(astraces, trace->dst) != 0)
    goto err;

  /* if we never found a VP address, we're done for now */
  if(lv < 0)
    goto done;

  /* these fields do not change for this traceroute, so set them now */
  indir.dst = trace->dst;
  indir.csum = trace->dport;

  for(i=trace->firsthop-1; i<=lv; i++)
    {
      if((hop = trace->hops[i]) == NULL)
	continue;

      /*
       * check if the hop being examined might be a fake hop caused by
       * zero-ttl forwarding
       */
      if(i+1 < lh && (y = trace->hops[i+1]) != NULL &&
	 scamper_addr_cmp(hop->hop_addr, y->hop_addr) == 0)
	zttl = 1;
      else
	zttl = 0;

      /*
       * keep track of links seen towards the neighbor network that we
       * will test for aliases.  do not test links where the hop being
       * examined might not be adjacent to X because of zero-ttl
       * forwarding
       */
      if(i-1 >= trace->firsthop-1 && (x = trace->hops[i-1]) != NULL &&
	 scamper_addr_cmp(x->hop_addr, hop->hop_addr) != 0 && zttl == 0)
	{
	  indir.ttl = x->hop_probe_ttl;
	  if(sc_astraces_link_add(astraces, x->hop_addr, hop->hop_addr,
				  &indir) != 0)
	    goto err;
	}
    }

  /* linktest the apparent last hop in the VP network */
  if(af == AF_INET && lv-1 >= trace->firsthop-1 &&
     (x = trace->hops[lv-1]) != NULL &&
     scamper_addr_cmp(x->hop_addr, trace->hops[lv]->hop_addr) != 0 &&
     sc_linktest_alloc(x->hop_addr, trace->hops[lv]->hop_addr) != 0)
    goto err;

  if(lv+1 < lh && (x = trace->hops[lv+1]) != NULL)
    {
      assert(scamper_addr_cmp(trace->hops[lv]->hop_addr, x->hop_addr) != 0);
      if(lv+2 < lh)
	y = trace->hops[lv+2];
      else
	y = NULL;

      if(y == NULL || scamper_addr_cmp(x->hop_addr, y->hop_addr) != 0)
	{
	  /* linktest the apparent first hop in the neighbor network */
	  if(af == AF_INET &&
	     sc_linktest_alloc(trace->hops[lv]->hop_addr, x->hop_addr) != 0)
	    goto err;

	  /* make note of apparent links to help with alias resolution */
	  indir.ttl = trace->hops[lv]->hop_probe_ttl;
	  if(sc_astraces_link_add(astraces, trace->hops[lv]->hop_addr,
				  x->hop_addr, &indir) != 0)
	    goto err;

	  /*
	   * also make note of links after first VP hop, to help with
	   * resolving aliases for routers with neighbor address space.
	   */
	  if(y != NULL)
	    {
	      indir.ttl = x->hop_probe_ttl;
	      if(sc_astraces_link_add(astraces, x->hop_addr, y->hop_addr,
				      &indir) != 0)
		goto err;
	    }
	}

      /* add the second hop past the last VP address to the GSS */
      if(y != NULL && SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(y) &&
	 scamper_addr_cmp(trace->dst, y->hop_addr) != 0 &&
	 slist_count(astraces->dsts) > 0 && is_vp(y->hop_addr) != 1 &&
	 sc_astraces_gss_add(astraces, y->hop_addr) != 0)
	goto err;
    }

 done:
  if((addr = slist_head_pop(astraces->dsts)) == NULL)
    {
      /* figure out aliases to test for */
      if(sc_astraces_aliases(astraces) != 0)
	goto err;
      sc_astraces_free(astraces);
      return 0;
    }

  if((tt = sc_tracetest_alloc(addr)) == NULL)
    goto err;
  scamper_addr_free(addr); addr = NULL;
  tt->astraces = astraces;
  if(sc_waittest(tt->target->test) != 0)
    goto err;

  return 0;

 err:
  printf("do_decoderead_trace: error\n");
  return -1;
}

static int do_decoderead(void)
{
  void     *data;
  uint16_t  type;
  int       rc = -1;

  /* try and read a traceroute from the warts decoder */
  if(scamper_file_read(decode_in, ffilter, &type, &data) != 0)
    {
      logerr("%s: scamper_file_read errno %d\n", __func__, errno);
      return -1;
    }
  if(data == NULL)
    {
      if(scamper_file_geteof(decode_in) != 0)
	{
	  scamper_file_close(decode_in);
	  decode_in = NULL;
	  decode_in_fd = -1;
	}
      return 0;
    }
  probing--;

  if(scamper_file_write_obj(outfile, type, data) != 0)
    {
      logerr("%s: could not write obj %d\n", __func__, type);
      /* XXX: free data */
      return -1;
    }

  if(type == SCAMPER_FILE_OBJ_PING)
    {
      rc = do_decoderead_ping(data);
      scamper_ping_free(data);
    }
  else if(type == SCAMPER_FILE_OBJ_TRACE)
    {
      rc = do_decoderead_trace(data);
      scamper_trace_free(data);
    }
  else if(type == SCAMPER_FILE_OBJ_DEALIAS)
    {
      rc = do_decoderead_dealias(data);
      scamper_dealias_free(data);
    }

  return rc;
}

static int do_scamperread(void)
{
  ssize_t rc;
  uint8_t uu[64];
  char   *ptr, *head;
  char    buf[512];
  void   *tmp;
  long    l;
  size_t  i, uus, linelen;

  if((rc = read(scamper_fd, buf, sizeof(buf))) > 0)
    {
      if(readbuf_len == 0)
	{
	  if((readbuf = memdup(buf, rc)) == NULL)
	    {
	      logerr("%s: could not memdup %d bytes", __func__, rc);
	      return -1;
	    }
	  readbuf_len = rc;
	}
      else
	{
	  if((tmp = realloc(readbuf, readbuf_len + rc)) != NULL)
	    {
	      readbuf = tmp;
	      memcpy(readbuf+readbuf_len, buf, rc);
	      readbuf_len += rc;
	    }
	  else
	    {
	      logerr("%s: could not realloc %d bytes",__func__,readbuf_len+rc);
	      return -1;
	    }
	}
    }
  else if(rc == 0)
    {
      logprint("disconnected\n");
      close(scamper_fd); scamper_fd = -1;
      close(decode_out_fd); decode_out_fd = -1;
      return 0;
    }
  else if(errno == EINTR || errno == EAGAIN)
    {
      return 0;
    }
  else
    {
      logerr("could not read: errno %d\n", errno);
      return -1;
    }

  /* process whatever is in the readbuf */
  if(readbuf_len == 0)
    return 0;

  head = readbuf;
  for(i=0; i<readbuf_len; i++)
    {
      if(readbuf[i] == '\n')
	{
	  /* skip empty lines */
	  if(head == &readbuf[i])
	    {
	      head = &readbuf[i+1];
	      continue;
	    }

	  /* calculate the length of the line, excluding newline */
	  linelen = &readbuf[i] - head;

	  /* if currently decoding data, then pass it to uudecode */
	  if(data_left > 0)
	    {
	      uus = sizeof(uu);
	      if(uudecode_line(head, linelen, uu, &uus) != 0)
		{
		  logerr("could not uudecode_line\n");
		  return -1;
		}

	      if(uus != 0)
		write_wrap(decode_out_fd, uu, NULL, uus);

	      data_left -= (linelen + 1);
	    }
	  /* if the scamper process is asking for more tasks, give it more */
	  else if(linelen == 4 && strncasecmp(head, "MORE", linelen) == 0)
	    {
	      more++;
	      if(do_method() != 0)
		return -1;
	    }
	  /* new piece of data */
	  else if(linelen > 5 && strncasecmp(head, "DATA ", 5) == 0)
	    {
	      l = strtol(head+5, &ptr, 10);
	      if(*ptr != '\n' || l < 1)
		{
		  head[linelen] = '\0';
		  logerr("could not parse %s\n", head);
		  return -1;
		}

	      data_left = l;
	    }
	  /* feedback letting us know that the command was accepted */
	  else if(linelen >= 2 && strncasecmp(head, "OK", 2) == 0)
	    {
	      /* nothing to do */
	    }
	  /* feedback letting us know that the command was not accepted */
	  else if(linelen >= 3 && strncasecmp(head, "ERR", 3) == 0)
	    {
	      logerr("got error\n");
	      return -1;
	    }
	  else
	    {
	      head[linelen] = '\0';
	      logerr("unknown response '%s'\n", head);
	      return -1;
	    }

	  head = &readbuf[i+1];
	}
    }

  if(head != &readbuf[readbuf_len])
    {
      readbuf_len = &readbuf[readbuf_len] - head;
      ptr = memdup(head, readbuf_len);
      free(readbuf);
      readbuf = ptr;
    }
  else
    {
      readbuf_len = 0;
      free(readbuf);
      readbuf = NULL;
    }

  return 0;
}

static int do_scamperconnect(void)
{
  struct sockaddr_un sun;
  struct sockaddr_in sin;
  struct in_addr in;

  if(options & OPT_PORT)
    {
      inet_aton("127.0.0.1", &in);
      sockaddr_compose((struct sockaddr *)&sin, AF_INET, &in, port);
      if((scamper_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
	  logerr("%s: could not inet socket: %s\n", __func__, strerror(errno));
	  return -1;
	}
      if(connect(scamper_fd, (const struct sockaddr *)&sin, sizeof(sin)) != 0)
	{
	  logerr("%s: could not inet connect: %s\n", __func__, strerror(errno));
	  return -1;
	}
      return 0;
    }
  else if(options & (OPT_UNIX | OPT_REMOTE))
    {
      if(sockaddr_compose_un((struct sockaddr *)&sun, unix_name) != 0)
	{
	  logerr("could not build sockaddr_un\n");
	  return -1;
	}
      if((scamper_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
	  logerr("%s: could not unix socket: %s\n", __func__, strerror(errno));
	  return -1;
	}
      if(connect(scamper_fd, (const struct sockaddr *)&sun, sizeof(sun)) != 0)
	{
	  logerr("%s: could not unix connect: %s\n", __func__, strerror(errno));
	  return -1;
	}
      return 0;
    }

  return -1;
}

static int delegated_line(char *line, void *param)
{
  sc_delegated_t *del = NULL;
  char *ptr, *net, *size;
  long lo;

  if(line[0] == '\0' || line[0] == '#')
    return 0;

  /* skip over RIR label */
  ptr = line;
  while(*ptr != '|' && *ptr != '\0') ptr++;
  if(*ptr == '\0') return -1;
  ptr++;

  /* skip over country label */
  while(*ptr != '|' && *ptr != '\0') ptr++;
  if(*ptr == '\0') return -1;
  ptr++;

  /* make sure this is an IPv4 record */
  if(strncasecmp(ptr, "ipv4|", 5) != 0)
    return 0;
  ptr += 5;

  /* got to the network part.  null terminate at the | */
  net = ptr;
  while(*ptr != '|' && *ptr != '\0') ptr++;
  if(*ptr == '\0') return -1;
  *ptr = '\0';
  ptr++;

  /* got to the size part.  null terminate at the | */
  size = ptr;
  while(*ptr != '|' && *ptr != '\0') ptr++;
  if(*ptr == '\0') return -1;
  *ptr = '\0';
  ptr++;
  if(string_tolong(size, &lo) != 0)
    return -1;

  /* skip over date part */
  while(*ptr != '|' && *ptr != '\0') ptr++;
  if(*ptr == '\0') return -1;
  ptr++;

  /* ensure the block is either allocated or assigned */
  if(strncasecmp(ptr,"allocated",9) != 0 && strncasecmp(ptr,"assigned",8) != 0)
    return 0;

  if((del = malloc(sizeof(sc_delegated_t))) == NULL)
    return -1;

  if(inet_pton(AF_INET, net, &del->x) != 1)
    goto err;
  del->y.s_addr = htonl(ntohl(del->x.s_addr) + lo);
  if(slist_tail_push(delegated, del) == NULL)
    goto err;

  return 0;

 err:
  if(del != NULL) free(del);
  return -1;
}

static int ip2name_line(char *line, void *param)
{
  scamper_addr_t sa;
  sc_addr2name_t *a2n;
  struct in_addr in;
  struct in6_addr in6;
  char *ip, *name;

  if(line[0] == '\0' || line[0] == '#')
    return 0;

  ip = line;
  name = line;
  while(isspace(*name) == 0 && *name != '\0')
    name++;
  if(*name == '\0')
    return 0;
  *name = '\0'; name++;
  while(isspace(*name) != 0)
    name++;

  if(af == AF_INET)
    {
      if(inet_pton(AF_INET, ip, &in) != 1)
	return -1;
      sa.type = SCAMPER_ADDR_TYPE_IPV4;
      sa.addr = &in;
      if(scamper_addr_isreserved(&sa))
	return 0;
    }
  else
    {
      if(inet_pton(AF_INET6, ip, &in6) != 1)
	return -1;
      sa.type = SCAMPER_ADDR_TYPE_IPV6;
      sa.addr = &in6;
      if(scamper_addr_isreserved(&sa))
	return 0;
    }

  /* skip over duplicate entry */
  if(sc_addr2name_find(&sa) != NULL)
    return 0;

  if((a2n = malloc_zero(sizeof(sc_addr2name_t))) == NULL ||
     (a2n->addr = scamper_addr_alloc(sa.type, sa.addr)) == NULL ||
     (a2n->name = strdup(name)) == NULL ||
     splaytree_insert(ip2name_tree, a2n) == NULL)
    {
      if(a2n != NULL) sc_addr2name_free(a2n);
      return -1;
    }

  return 0;
}

static int ip2as_line(char *line, void *param)
{
  slist_t **lists = param;
  scamper_addr_t sa;
  sc_prefix_t *p = NULL;
  char *n, *m, *a, *at;
  struct in_addr in;
  struct in6_addr in6;
  uint32_t u32, *ases = NULL;
  int asc = 0, last = 0;
  long lo;

  if(line[0] == '\0' || line[0] == '#')
    return 0;

  n = line;

  m = line;
  while(isspace(*m) == 0 && *m != '\0')
    m++;
  if(*m == '\0')
    return -1;
  *m = '\0'; m++;
  while(isspace(*m) != 0)
    m++;
  if(string_tolong(m, &lo) != 0)
    return -1;

  a = m;
  while(isspace(*a) == 0 && *a != '\0')
    a++;
  if(*a == '\0')
    return -1;
  *a = '\0'; a++;
  while(isspace(*a) != 0)
    a++;

  if(af == AF_INET)
    {
      if(lo < IPV4_PREFIX_MIN || lo > IPV4_PREFIX_MAX)
	return 0;
      if(inet_pton(AF_INET, n, &in) != 1)
	return -1;
      sa.type = SCAMPER_ADDR_TYPE_IPV4;
      sa.addr = &in;
      if(scamper_addr_isreserved(&sa))
	return 0;
      if((p = sc_prefix_alloc(&in, lo)) == NULL)
	goto err;
    }
  else
    {
      if(lo < IPV6_PREFIX_MIN || lo > IPV6_PREFIX_MAX)
	return 0;
      if(inet_pton(AF_INET6, n, &in6) != 1)
	return -1;
      sa.type = SCAMPER_ADDR_TYPE_IPV6;
      sa.addr = &in6;
      if(scamper_addr_isreserved(&sa))
	return 0;
      if((p = sc_prefix_alloc(&in6, lo)) == NULL)
	goto err;
    }

  for(at = a; last == 0; at++)
    {
      if(*at != '_' && *at != ',' && *at != ' ' && *at != '\0')
	continue;
      if(*at == ' ' || *at == '\0') last = 1;
      *at = '\0';
      u32 = atoi(a);
      /* skip over private / reserved ASNs */
      if(u32 == 0 || u32 == 23456 ||
	 (u32 >= 64512 && u32 <= 65535) || u32 >= 4200000000)
	continue;
      if(uint32_add(&ases, &asc, u32) != 0)
	goto err;
      a = at + 1;
    }

  /* if the prefix was only announced by a private ASN, skip over it */
  if(asc == 0)
    {
      sc_prefix_free(p);
      return 0;
    }

  if((af == AF_INET  && slist_tail_push(lists[lo-IPV4_PREFIX_MIN],p) == NULL) ||
     (af == AF_INET6 && slist_tail_push(lists[lo-IPV6_PREFIX_MIN],p) == NULL))
    goto err;

  qsort(ases, asc, sizeof(uint32_t), uint32_cmp);
  if((p->asmap = sc_asmap_get(ases, asc)) == NULL)
    goto err;

  free(ases);
  return 0;

 err:
  if(ases != NULL) free(ases);
  if(p != NULL) sc_prefix_free(p);
  return -1;
}

static int relfile_line(char *line, void *param)
{
  static int linec = 0;
  char *as, *bs, *rs;
  long a, b, r;

  linec++;

  if(line[0] == '\0' || line[0] == '#')
    return 0;

  as = line;
  string_nullterm_char(as, '|', &bs);
  if(bs == NULL)
    {
      printf("line %d malformed\n", linec);
      return -1;
    }
  string_nullterm_char(bs, '|', &rs);
  if(rs == NULL)
    {
      printf("line %d malformed\n", linec);
      return -1;
    }

  if(string_isnumber(as) == 0 || string_isnumber(bs) == 0 ||
     string_isnumber(rs) == 0 ||
     string_tolong(as, &a) != 0 || a < 1 ||
     string_tolong(bs, &b) != 0 || b < 1 ||
     string_tolong(rs, &r) != 0 || r < -1 || r > 1)
    {
      printf("line %d %s %s %s\n", linec, as, bs, rs);
      return -1;
    }

  if(sc_asrel_add(a, b, r) != 0)
    {
      printf("line %d %u %u %d\n", linec, (uint32_t)a, (uint32_t)b, (int)r);
      return -1;
    }

  if(r == -1)
    {
      if(sc_prov_add(b, a) != 0)
	return -1;
    }
  else if(r == 1)
    {
      if(sc_prov_add(a, b) != 0)
	return -1;
    }

  return 0;
}

static int do_targetips(void)
{
  splaytree_t *astraces = NULL;
  sc_astraces_t *traces = NULL;
  struct in6_addr in6;
  struct in_addr in;
  sc_prefix_t *pfx;
  void *addr;
  int i, rc;

  if((astraces = splaytree_alloc((splaytree_cmp_t)sc_astraces_cmp)) == NULL)
    goto err;

  for(i=0; i<opt_argc; i++)
    {
      if(af == AF_INET)
	{
	  rc = inet_pton(AF_INET, opt_args[i], &in);
	  addr = &in;
	}
      else
	{
	  rc = inet_pton(AF_INET6, opt_args[i], &in6);
	  addr = &in6;
	}
      if(rc != 1)
	{
	  fprintf(stderr, "could not resolve %s\n", opt_args[i]);
	  goto err;
	}

      if((pfx = sc_prefix_find_in(addr)) == NULL)
	{
	  fprintf(stderr, "no matching prefix for %s\n", opt_args[i]);
	  goto err;
	}

      if(sc_asmap_isvp(pfx->asmap))
	{
	  fprintf(stderr, "address %s is announced by the VP\n", opt_args[i]);
	  goto err;
	}

      if((traces = sc_astraces_get(astraces, pfx->asmap)) == NULL)
	goto err;
      sc_astraces_dst_add(traces, addr);
    }

  splaytree_inorder(astraces, tree_to_slist, virgin);
  splaytree_free(astraces, NULL);

  return 0;

 err:
  if(astraces != NULL) splaytree_free(astraces, NULL);
  return -1;
}

static int do_targetases(void)
{


  return 0;
}

static int rec_target_4(sc_prefix_nest_t *nest, struct in_addr *in)
{
  static const uint32_t add[] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 8388608, 4194304, 2097152, 1048576, 524288, 262144, 131072, 65536,
    32768, 16384, 8192, 4096, 2048, 1024, 512, 256,
  };
  sc_prefix_nest_t *nest2;
  slist_node_t *sn;
  uint32_t x, y, f = ntohl(nest->pfx->pfx.v4->net.s_addr);

  /* if there are no nested prefixes, pick the first address in the prefix */
  if(nest->list == NULL)
    {
      in->s_addr = htonl(f+1);
      return 1;
    }

  /* find address in the prefix not covered by a more specific */
  x = f; slist_qsort(nest->list, (slist_cmp_t)sc_prefix_nest_cmp);
  for(sn = slist_head_node(nest->list); sn != NULL; sn = slist_node_next(sn))
    {
      nest2 = slist_node_item(sn);
      y = ntohl(nest2->pfx->pfx.v4->net.s_addr);
      if(y != x)
	{
	  in->s_addr = htonl(x+1);
	  return 1;
	}
      x += add[nest2->pfx->pfx.v4->len];
    }

  /* if there is uncovered space at the top of the prefix then use that */
  if(sn == NULL && x < f + add[nest->pfx->pfx.v4->len])
    {
      in->s_addr = htonl(x+1);
      return 1;
    }

  return 0;
}

static int add6(struct in6_addr *in, int bitlen)
{
  static const uint8_t add[] = {0x80,0x40,0x20,0x10,0x08,0x04,0x02,0x01};
  int j = (bitlen-1) / 8;
  int k = (bitlen-1) % 8;

  if(((int)in->s6_addr[j]) + add[k] <= 255)
    {
      in->s6_addr[j] += add[k];
      return 0;
    }

  in->s6_addr[j--] = 0;
  while(j >= 0)
    {
      if(in->s6_addr[j] < 255)
	break;
      in->s6_addr[j--] = 0;
    }

  if(j < 0)
    return -1;

  in->s6_addr[j]++;
  return 0;
}

static int rec_target_6(sc_prefix_nest_t *nest, struct in6_addr *in)
{
  sc_prefix_nest_t *nest2;
  struct in6_addr f, x, y;
  slist_node_t *sn;

  /* if there are no nested prefixes, pick the first address in the prefix */
  if(nest->list == NULL)
    {
      memcpy(in, &nest->pfx->pfx.v6->net, sizeof(struct in6_addr));
      in->s6_addr[15] = 1;
      return 1;
    }

  /* find address in the prefix not covered by a more specific */
  memcpy(&x, &nest->pfx->pfx.v6->net, sizeof(struct in6_addr));
  slist_qsort(nest->list, (slist_cmp_t)sc_prefix_nest_cmp);
  for(sn = slist_head_node(nest->list); sn != NULL; sn = slist_node_next(sn))
    {
      nest2 = slist_node_item(sn);
      memcpy(&y, &nest2->pfx->pfx.v6->net, sizeof(struct in6_addr));
      if(memcmp(&x, &y, sizeof(struct in6_addr)) != 0)
	{
	  memcpy(in, &x, sizeof(struct in6_addr));
	  in->s6_addr[15] = 1;
	  return 1;
	}
      add6(&x, nest2->pfx->pfx.v6->len);
    }

  /* if there is uncovered space at the top of the prefix then use that */
  memcpy(&f, &nest->pfx->pfx.v6->net, sizeof(struct in6_addr));
  add6(&f, nest->pfx->pfx.v6->len);
  if(sn == NULL && addr6_cmp(&x, &f) < 0)
    {
      memcpy(in, &x, sizeof(struct in6_addr));
      in->s6_addr[15] = 1;
      return 1;
    }

  return 0;
}

static int do_targets_rec(slist_t *list, splaytree_t *astraces)
{
  int i, j, probe;
  sc_prefix_nest_t *nest;
  sc_astraces_t *traces;
  struct in_addr in;
  struct in6_addr in6;
  slist_node_t *sn;
  void *ptr;

  for(sn = slist_head_node(list); sn != NULL; sn = slist_node_next(sn))
    {
      nest = slist_node_item(sn);
      ptr = NULL;
      if(af == AF_INET)
	{
	  if(rec_target_4(nest, &in) == 1)
	    ptr = &in;
	}
      else
	{
	  if(rec_target_6(nest, &in6) == 1)
	    ptr = &in6;
	}

      if(ptr != NULL)
	{
	  probe = 0;
	  if(targetasc > 0)
	    {
	      for(i=0; i<targetasc && probe == 0; i++)
		for(j=0; j<nest->pfx->asmap->asc && probe == 0; j++)
		  if(targetas[i] == nest->pfx->asmap->ases[j])
		    probe = 1;
	    }
	  else
	    {
	      if(sc_asmap_isvp(nest->pfx->asmap) == 0)
		{
		  assert(nest->pfx == sc_prefix_find_in(ptr));
		  probe = 1;
		}
	    }

	  if(probe != 0)
	    {
	      if((traces = sc_astraces_get(astraces, nest->pfx->asmap)) == NULL)
		return -1;
	      sc_astraces_dst_add(traces, ptr);
	    }
	}

      if(nest->list != NULL)
	do_targets_rec(nest->list, astraces);
    }

  return 0;
}

/*
 * do_targets
 *
 * go through the list of prefixes nesting prefixes enclosed in a less
 * specific prefix.  the prefixes list is sorted from less to more
 * specific prefix.  the actual target list creation is done in
 * do_targets_rec, which recurses through the nested prefixes.
 *
 */
static int do_targets(void)
{
  splaytree_t *astracestree = NULL;
  sc_prefix_nest_t *nest;
  prefixtree_t *tree = NULL;
  prefix4_t *p4; prefix6_t *p6;
  slist_node_t *sn;
  sc_prefix_t *pfx;
  slist_t *root = NULL;
  int count = 0;

  if((tree = prefixtree_alloc(af)) == NULL || (root = slist_alloc()) == NULL)
    goto err;

  for(sn = slist_head_node(prefixes); sn != NULL; sn = slist_node_next(sn))
    {
      pfx = slist_node_item(sn);

      if(af == AF_INET)
	{
	  /* if there is no enclosing prefix, this is a root prefix */
	  if((p4 = prefixtree_find_best4(tree, pfx->pfx.v4)) == NULL)
	    {
	      if((p4 = prefix4_dup(pfx->pfx.v4)) == NULL ||
		 prefixtree_insert4(tree, p4) == NULL ||
		 (p4->ptr = sc_prefix_nest_alloc(pfx)) == NULL ||
		 slist_tail_push(root, p4->ptr) == NULL)
		goto err;
	      continue;
	    }
	  nest = p4->ptr;
	}
      else
	{
	  if((p6 = prefixtree_find_best6(tree, pfx->pfx.v6)) == NULL)
	    {
	      if((p6 = prefix6_dup(pfx->pfx.v6)) == NULL ||
		 prefixtree_insert6(tree, p6) == NULL ||
		 (p6->ptr = sc_prefix_nest_alloc(pfx)) == NULL ||
		 slist_tail_push(root, p6->ptr) == NULL)
		goto err;
	      continue;
	    }
	  nest = p6->ptr;
	}

      /* go through all nested prefixes until we get to the last one */
      while(nest != NULL)
	{
	  /* create a prefixtree as needed */
	  if(nest->pt == NULL)
	    {
	      if((nest->pt = prefixtree_alloc(af)) == NULL ||
		 (nest->list = slist_alloc()) == NULL)
		goto err;
	    }

	  if(af == AF_INET)
	    {
	      if((p4 = prefixtree_find_best4(nest->pt, pfx->pfx.v4)) == NULL)
		break;
	      nest = p4->ptr;
	    }
	  else
	    {
	      if((p6 = prefixtree_find_best6(nest->pt, pfx->pfx.v6)) == NULL)
		break;
	      nest = p6->ptr;
	    }
	}

      if(af == AF_INET)
	{
	  if((p4 = prefix4_dup(pfx->pfx.v4)) == NULL ||
	     prefixtree_insert4(nest->pt, p4) == NULL ||
	     (p4->ptr = sc_prefix_nest_alloc(pfx)) == NULL ||
	     slist_tail_push(nest->list, p4->ptr) == NULL)
	    goto err;
	}
      else
	{
	  if((p6 = prefix6_dup(pfx->pfx.v6)) == NULL ||
	     prefixtree_insert6(nest->pt, p6) == NULL ||
	     (p6->ptr = sc_prefix_nest_alloc(pfx)) == NULL ||
	     slist_tail_push(nest->list, p6->ptr) == NULL)
	    goto err;
	}
    }

  if((astracestree = splaytree_alloc((splaytree_cmp_t)sc_astraces_cmp)) == NULL)
    goto err;

  do_targets_rec(root, astracestree);

  while((nest = slist_head_pop(root)) != NULL)
    sc_prefix_nest_free(nest);
  slist_free(root); root = NULL;

  if(af == AF_INET)
    prefixtree_free_cb(tree, (prefix_free_t)prefix4_free);
  else
    prefixtree_free_cb(tree, (prefix_free_t)prefix6_free);
  tree = NULL;

  splaytree_inorder(astracestree, tree_to_slist, virgin);
  splaytree_free(astracestree, NULL); astracestree = NULL;

  slist_foreach(virgin, (slist_foreach_t)sc_astraces_count, &count);
  printf("count %d\n", count);

  if(impatient)
    slist_qsort(virgin, (slist_cmp_t)sc_astraces_count_cmp);
  else
    slist_shuffle(virgin);
  slist_foreach(virgin, (slist_foreach_t)sc_astraces_shuffle, NULL);

  return 0;

 err:
  return -1;
}

static int do_ip2as(void)
{
  slist_node_t *sn;
  sc_prefix_t *p;
  slist_t **lists;
  int i, j;

  if((asmaptree = splaytree_alloc((splaytree_cmp_t)sc_asmap_cmp)) == NULL)
    goto err;

  if(af == AF_INET)
    j = IPV4_PREFIX_MAX - IPV4_PREFIX_MIN + 1;
  else
    j = IPV6_PREFIX_MAX - IPV6_PREFIX_MIN + 1;
  if((lists = malloc_zero(sizeof(slist_t *) * j)) == NULL)
    goto err;
  for(i=0; i<j; i++)
    if((lists[i] = slist_alloc()) == NULL)
      goto err;

  if(file_lines(ip2as_fn, ip2as_line, lists) != 0)
    {
      logerr("%s: could not read %s: %s\n",__func__,ip2as_fn,strerror(errno));
      goto err;
    }

  if((prefixes = slist_alloc()) == NULL)
    goto err;
  for(i=0; i<j; i++)
    {
      slist_concat(prefixes, lists[i]);
      slist_free(lists[i]); lists[i] = NULL;
    }
  free(lists); lists = NULL;

  if((ip2as_pt = prefixtree_alloc(af)) == NULL)
    goto err;

  for(sn = slist_head_node(prefixes); sn != NULL; sn = slist_node_next(sn))
    {
      p = slist_node_item(sn);
      if((af == AF_INET  && prefixtree_insert4(ip2as_pt,p->pfx.v4) == NULL) ||
	 (af == AF_INET6 && prefixtree_insert6(ip2as_pt,p->pfx.v6) == NULL))
	goto err;
    }

  return 0;

 err:
  fprintf(stderr, "could not load ip2as\n");
  return -1;
}

static int ixp_line(char *line, void *param)
{
  struct addrinfo hints, *res, *res0;
  prefix4_t *p4; prefix6_t *p6;
  char *pf;
  void *va;
  long lo;

  if(line[0] == '\0' || line[0] == '#')
    return 0;

  string_nullterm_char(line, '/', &pf);
  if(pf == NULL)
    return -1;
  string_nullterm_char(pf, ' ', NULL);

  if(string_tolong(pf, &lo) != 0 || lo < 0)
    return -1;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags    = AI_NUMERICHOST;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_family   = AF_UNSPEC;

  if(getaddrinfo(line, NULL, &hints, &res0) != 0 || res0 == NULL)
    return -1;

  for(res = res0; res != NULL; res = res->ai_next)
    {
      if(res->ai_family == PF_INET)
	{
	  if(af != AF_INET) break;
	  va = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
	  if((p4 = prefix4_alloc(va, lo, NULL)) == NULL)
	    return -1;
	  p4->ptr = p4;
	  if(prefixtree_insert4(ixp_pt, p4) == NULL)
	    return -1;
	  break;
	}
      else if(res->ai_family == PF_INET6)
	{
	  if(af != AF_INET6) break;
	  va = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
	  if((p6 = prefix6_alloc(va, lo, NULL)) == NULL)
	    return -1;
	  p6->ptr = p6;
	  if(prefixtree_insert6(ixp_pt, p6) == NULL)
	    return -1;
	  break;
	}
    }
  freeaddrinfo(res0);
  return 0;
}

static int do_ixp(void)
{
  if((ixp_pt = prefixtree_alloc(af)) == NULL)
    return -1;
  if(file_lines(ixp_fn, ixp_line, NULL) != 0)
    {
      logerr("could not read %s\n", ixp_fn);
      return -1;
    }
  return 0;
}

static int bdrmap_data(void)
{
  struct timeval tv, *tv_ptr;
  sc_waittest_t *wait;
  sc_test_t *test;
  fd_set rfds;
  int pair[2];
  int nfds, rc = -1;

  gettimeofday_wrap(&tv);
  srandom(tv.tv_usec);

  if((targets = splaytree_alloc((splaytree_cmp_t)sc_target_cmp)) == NULL ||
     (links = splaytree_alloc((splaytree_cmp_t)sc_link_cmp)) == NULL ||
     (pings = splaytree_alloc((splaytree_cmp_t)sc_ping_cmp)) == NULL ||
     (virgin = slist_alloc()) == NULL ||
     (waiting = heap_alloc(sc_waittest_cmp)) == NULL)
    goto done;

  if(options & OPT_TARGETIPS)
    {
      if(do_targetips() != 0)
	goto done;
    }
  else
    {
      if((options & OPT_TARGETASES) && do_targetases() != 0)
	goto done;
      if(do_targets() != 0)
	goto done;
    }

  if(do_scamperconnect() != 0 ||
     (outfile = scamper_file_open(outfile_fn, 'w', "warts")) == NULL ||
     socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
    goto done;
  decode_in_fd  = pair[0];
  decode_out_fd = pair[1];
  decode_in = scamper_file_openfd(decode_in_fd, NULL, 'r', "warts");
  if(decode_in == NULL)
    goto done;
  if(fcntl_set(decode_in_fd, O_NONBLOCK) == -1)
    goto done;

  if((options & OPT_REMOTE) == 0 &&
     write_wrap(scamper_fd, "attach\n", NULL, 7) != 0)
    {
      logerr("could not attach to scamper process\n");
      goto done;
    }

  for(;;)
    {
      nfds = 0;
      FD_ZERO(&rfds);

      if(scamper_fd < 0 && decode_in_fd < 0)
	{
	  rc = 0;
	  break;
	}

      if(scamper_fd >= 0)
	{
	  FD_SET(scamper_fd, &rfds);
	  if(nfds < scamper_fd) nfds = scamper_fd;
	}

      if(decode_in_fd >= 0)
	{
	  FD_SET(decode_in_fd, &rfds);
	  if(nfds < decode_in_fd) nfds = decode_in_fd;
	}

      /*
       * need to set a timeout on select if scamper's processing window is
       * not full and there is a trace in the waiting queue.
       */
      tv_ptr = NULL;
      if(more > 0)
	{
	  gettimeofday_wrap(&now);

	  /*
	   * if there is something ready to probe now, then try and
	   * do it.
	   */
	  wait = heap_head_item(waiting);
	  if(slist_count(virgin) > 0 ||
	     (wait != NULL && timeval_cmp(&wait->tv, &now) <= 0))
	    {
	      if(do_method() != 0)
		break;
	    }

	  /*
	   * if we could not send a new command just yet, but scamper
	   * wants one, then wait for an appropriate length of time.
	   */
	  wait = heap_head_item(waiting);
	  if(more > 0 && tv_ptr == NULL && wait != NULL)
	    {
	      tv_ptr = &tv;
	      if(timeval_cmp(&wait->tv, &now) > 0)
		timeval_diff_tv(&tv, &now, &wait->tv);
	      else
		memset(&tv, 0, sizeof(tv));
	    }
	}

      if(splaytree_count(targets) == 0 &&
	 slist_count(virgin) == 0 && heap_count(waiting) == 0)
	{
	  logprint("done\n");
	  rc = 0; break;
	}

      if(select(nfds+1, &rfds, NULL, NULL, tv_ptr) < 0)
	{
	  if(errno == EINTR) continue;
	  logerr("select error\n");
	  break;
	}

      gettimeofday_wrap(&now);

      if(more > 0 && do_method() != 0)
	break;

      if(scamper_fd >= 0 && FD_ISSET(scamper_fd, &rfds))
	{
	  if(do_scamperread() != 0)
	    break;
	}

      if(decode_in_fd >= 0 && FD_ISSET(decode_in_fd, &rfds))
	{
	  if(do_decoderead() != 0)
	    break;
	}
    }

 done:
  if(targetas != NULL) free(targetas);
  if(targets != NULL) splaytree_free(targets, NULL);
  if(virgin != NULL)
    {
      while((test = slist_head_pop(virgin)) != NULL)
	{
	  sc_tracetest_free(test->data);
	  sc_test_free(test);
	}
      slist_free(virgin);
    }
  if(waiting != NULL) heap_free(waiting, NULL);
  if(outfile != NULL) scamper_file_close(outfile);
  if(decode_in != NULL) scamper_file_close(decode_in);
  if(logfile != NULL) fclose(logfile);

  return rc;
}

typedef struct sc_link4
{
  uint8_t     ttl;      /* minimum distance in path link was observed */
  sc_stree_t *dstases;  /* ASes link was seen in path towards */
  sc_stree_t *adjases;  /* ASes for next hops when Y is unannounced space */
  sc_stree_t *gapases;  /* ASes for next hops when gap after Y */
} sc_link4_t;

static sc_link4_t *sc_link4_alloc(void)
{
  sc_link4_t *l4 = NULL;
  if((l4 = malloc_zero(sizeof(sc_link4_t))) == NULL ||
     (l4->dstases=sc_stree_alloc((splaytree_cmp_t)sc_asmapc_as_cmp)) == NULL)
    return NULL;
  return l4;
}

static void sc_link4_free(sc_link4_t *l4)
{
  if(l4 == NULL)
    return;
  if(l4->dstases != NULL)
    sc_stree_free(l4->dstases, (sc_stree_free_t)sc_asmapc_free);
  if(l4->adjases != NULL)
    sc_stree_free(l4->adjases, (sc_stree_free_t)sc_asmapc_free);
  if(l4->gapases != NULL)
    sc_stree_free(l4->gapases, (sc_stree_free_t)sc_asmapc_free);
  free(l4);
  return;
}

static void sc_link_free_link4(sc_link_t *link)
{
  if(link == NULL)
    return;
  if(link->data != NULL) sc_link4_free(link->data);
  sc_link_free(link);
  return;
}

static int sc_link4_addadj(sc_link4_t *l4, sc_prefix_t *pfx)
{
  sc_asmapc_t *asmapc;
  if(l4->adjases == NULL &&
     (l4->adjases = sc_stree_alloc((splaytree_cmp_t)sc_asmapc_as_cmp)) == NULL)
    return -1;
  if((asmapc = sc_asmapc_get(l4->adjases, pfx->asmap)) == NULL)
    return -1;
  asmapc->c++;
  return 0;
}

static int sc_link4_addgap(sc_link4_t *l4, sc_prefix_t *pfx)
{
  sc_asmapc_t *asmapc;
  if(l4->gapases == NULL &&
     (l4->gapases = sc_stree_alloc((splaytree_cmp_t)sc_asmapc_as_cmp)) == NULL)
    return -1;
  if((asmapc = sc_asmapc_get(l4->gapases, pfx->asmap)) == NULL)
    return -1;
  asmapc->c++;
  return 0;
}

static int init_1(void)
{
  rtrset = sc_routerset_alloc();
  links = splaytree_alloc((splaytree_cmp_t)sc_link_cmp);
  tracesets = splaytree_alloc((splaytree_cmp_t)sc_traceset_cmp);
  held = slist_alloc();
  return 0;
}

static int process_1_dealias(scamper_dealias_t *dealias)
{
  scamper_dealias_prefixscan_t *pfs;
  scamper_dealias_ally_t *ally;
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply;
  scamper_addr_t *a, *b;
  sc_link_t *link;
  sc_ally_t *ar;
  uint32_t i;
  int ok, rc = -1;

  if(SCAMPER_DEALIAS_METHOD_IS_PREFIXSCAN(dealias))
    {
      pfs = dealias->data;
      if(pfs->ab != NULL && scamper_addr_prefixhosts(pfs->b, pfs->ab) >= 30)
	{
	  if((link = sc_link_get(pfs->a, pfs->b)) == NULL)
	    goto done;
	  if((pfs->flags & SCAMPER_DEALIAS_PREFIXSCAN_FLAG_CSA) != 0)
	    {
	      if(sc_routerset_getpair(rtrset, pfs->a, pfs->ab) == NULL)
		goto done;
	    }
	  else
	    {
	      if((ar = sc_ally_get(pfs->a, pfs->ab)) == NULL)
		goto done;
	      if(ar->result != SCAMPER_DEALIAS_RESULT_NOTALIASES)
		ar->result = SCAMPER_DEALIAS_RESULT_ALIASES;
	    }
	}

      /*
       * check for unreachable port responses that suggest might be useful
       * to build routers with using CSA.
       */
      if(pfs->probedefc > 0 &&
	 SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(&pfs->probedefs[0]))
	{
	  for(i=0; i<dealias->probec; i++)
	    {
	      probe = dealias->probes[i];
	      if(probe->replyc == 0)
		continue;
	      reply = probe->replies[0];
	      if(SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT(reply) == 0 ||
		 scamper_addr_cmp(reply->src, probe->def->dst) == 0 ||
		 scamper_addr_isreserved(reply->src) != 0 ||
		 sc_link_find(probe->def->dst, reply->src) != NULL ||
		 sc_link_find(reply->src, probe->def->dst) != NULL)
		continue;
	      if((scamper_addr_cmp(probe->def->dst, pfs->a) == 0 ||
		  scamper_addr_prefixhosts(pfs->b, probe->def->dst) >= 30) &&
		 sc_routerset_getpair(rtrset,probe->def->dst,reply->src) == NULL)
		goto done;
	    }
	}

      rc = 0;
    }
  else if(SCAMPER_DEALIAS_METHOD_IS_ALLY(dealias))
    {
      ally = dealias->data; ok = 0; ar = NULL;
      if(ally->probedefs[0].ttl == 255)
	{
	  a = ally->probedefs[0].dst;
	  b = ally->probedefs[1].dst;
	  ok = 1;
	}
      else
	{
	  for(i=0; i<dealias->probec; i++)
	    {
	      if(dealias->probes[i] == NULL || dealias->probes[i]->replyc == 0)
		break;
	      if(scamper_addr_cmp(dealias->probes[i%2]->replies[0]->src,
				  dealias->probes[i]->replies[0]->src) != 0)
		break;
	    }
	  if(i == dealias->probec && i >= 2 &&
	     scamper_addr_cmp(dealias->probes[0]->replies[0]->src,
			      dealias->probes[1]->replies[0]->src) != 0)
	    {
	      ok = 1;
	      a = dealias->probes[0]->replies[0]->src;
	      b = dealias->probes[1]->replies[0]->src;
	    }
	}

      if(ok && (ar = sc_ally_get(a, b)) == NULL)
	goto done;
      if(ar != NULL &&
	 (ar->result == SCAMPER_DEALIAS_RESULT_NONE ||
	  dealias->result == SCAMPER_DEALIAS_RESULT_NOTALIASES))
	ar->result = dealias->result;
      rc = 0;
    }
  else
    {
      rc = 0;
    }

 done:
  scamper_dealias_free(dealias);
  return rc;
}

static sc_link_t *process_1_link(scamper_trace_hop_t *x,
				 scamper_trace_hop_t *y, sc_asmap_t *dst)
{
  sc_link_t *link;
  sc_link4_t *link4;
  sc_asmapc_t *asmapc;

  /* get a link for this hop, to be further annotated */
  if((link = sc_link_get(x->hop_addr, y->hop_addr)) == NULL)
    return NULL;
  if((link4 = link->data) == NULL)
    {
      if((link4 = sc_link4_alloc()) == NULL)
	return NULL;
      link->data = link4;
      link4->ttl = x->hop_probe_ttl;
    }

  /*
   * record the earliest distance in a path the link was seen,
   * to help with later processing the links in topological order
   */
  if(link4->ttl > x->hop_probe_ttl)
    link4->ttl = x->hop_probe_ttl;

  /*
   * keep a track of which networks were seen when tracing through
   * this link
   */
  if((asmapc = sc_asmapc_get(link4->dstases, dst)) == NULL)
    return NULL;
  asmapc->c++;

  return link;
}

/*
 * process_1_trace_unrouted
 *
 * take a pass through the traceroute, marking unrouted address space
 * as belonging to the VP if it is found in a path ahead of other VP
 * address space.
 *
 * -1: error condition, sc_bdrmap should halt.
 *  0: no unrouted address space, process the trace.
 *  1: unrouted address space, but origin not determined yet.
 *  2: inferred some address space was announced by VP.
 */
static int process_1_trace_unrouted(scamper_trace_t *trace, int lh)
{
  scamper_trace_hop_t *x;
  scamper_addr_t *addr;
  sc_delegated_t *dg;
  slist_t *list = NULL;
  sc_prefix_t *pfx;
  uint32_t as = vpas[0];
  int i, vp, modified = 0, rc = -1;
  uint8_t netlen;

  /*
   * make an initial pass through to flag any unrouted addresses with
   * an inferred AS if they are internal VP addresses
   */
  if((list = slist_alloc()) == NULL)
    goto done;
  for(i=trace->firsthop-1; i<lh; i++)
    {
      /* if there is no address at this hop, skip */
      if((x = trace->hops[i]) == NULL)
	continue;
      /* if we have come to an external hop, stop */
      if((vp = is_vp(x->hop_addr)) == 0)
	break;

      /*
       * if this is a VP hop, and there are unrouted addresses in previous
       * hops, then manually create a prefix for them now
       */
      if(vp == 1 && slist_count(list) > 0)
	{
	  while((addr = slist_head_pop(list)) != NULL)
	    {
	      if(sc_prefix_find_in(addr->addr) != NULL)
		continue;
	      if((dg = sc_delegated_find(addr)) != NULL &&
		 (netlen = sc_delegated_netlen(dg)) != 0)
		{
		  pfx = sc_prefix_alloc(&dg->x, netlen);
		}
	      else
		{
		  pfx = sc_prefix_alloc(addr->addr, af == AF_INET ? 32 : 128);
		}
	      if(pfx == NULL)
		goto done;
	      if((pfx->asmap = sc_asmap_get(&as, 1)) == NULL)
		goto done;
	      if(af == AF_INET)
		{
		  if(prefixtree_insert4(ip2as_pt, pfx->pfx.v4) == NULL)
		    goto done;
		}
	      else
		{
		  if(prefixtree_insert6(ip2as_pt, pfx->pfx.v6) == NULL)
		    goto done;
		}
	      if(slist_tail_push(prefixes, pfx) == NULL)
		goto done;
	      modified = 1;
	    }
	  slist_empty(list);
	}
      else
	{
	  /*
	   * we do not know if this is a VP hop, but we know that it is not
	   * an IXP hop or using reserved IP addresses, so infer that it
	   * is
	   */
	  if(is_ixp(x->hop_addr) == 0 && is_reserved(x->hop_addr) == 0 &&
	     slist_tail_push(list, x->hop_addr) == NULL)
	    goto done;
	}
    }

  if(modified != 0)
    rc = 2;
  else if(slist_count(list) > 0)
    rc = 1;
  else
    rc = 0;

 done:
  slist_free(list); list = NULL;
  return rc;
}

static int process_1_trace_work(scamper_trace_t *trace, int lh)
{
  scamper_trace_hop_t *x, *y, *z;
  sc_traceset_t *ts;
  sc_link_t *link;
  sc_link4_t *link4;
  sc_prefix_t *dst, *pfx;
  int i, j, r, vp, ttlnn = 0;
  uint32_t asn, sib;

  /* get the target prefix to annotate links with */
  if((dst = sc_prefix_find(trace->dst)) == NULL)
    return 0;

  for(i=trace->firsthop-1; i<lh-1; i++)
    {
      if((x = trace->hops[i]) == NULL || (y = trace->hops[i+1]) == NULL ||
	 scamper_addr_cmp(x->hop_addr, y->hop_addr) == 0 ||
	 SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(x) == 0 ||
	 SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(y) == 0 ||
	 scamper_addr_cmp(y->hop_addr, trace->dst) == 0 ||
	 scamper_addr_isreserved(x->hop_addr) ||
	 scamper_addr_isreserved(y->hop_addr))
	continue;

      /*
       * do not form a link between X and Y if Y and Z are the same
       * address as that implies X and Y are not adjacent, because of
       * zero-ttl forwarding or similar at the hop for Y.  note that
       * we do not check quoted TTL values as we see these cases where
       * the TTL is not zero at hop Z.
       */
      if(i < lh-2 && (z = trace->hops[i+2]) != NULL &&
	 scamper_addr_cmp(y->hop_addr, z->hop_addr) == 0 &&
	 SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(z))
	continue;

      /*
       * stop as soon as we encounter an address from outside of this
       * network's address space.
       */
      if(is_vp(x->hop_addr) == 0)
	{
	  ttlnn = 1;
	  break;
	}

      /* get a link for the hop, annotated with the destinations probed */
      if((link = process_1_link(x, y, dst->asmap)) == NULL)
	return -1;
      link4 = link->data;

      /*
       * if Y is not announced by the VP, or is unannounced/reserved
       * address space, then annotate the link with information on the
       * first hop past the address space that is announced by some
       * network
       */
      vp = is_vp(y->hop_addr);
      if(vp == 0 || (vp == 2 && is_ixp(y->hop_addr) == 0))
	{
	  for(j=i+2; j<lh; j++)
	    {
	      if((z = trace->hops[j]) == NULL ||
		 SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(z) == 0 ||
		 scamper_addr_isreserved(z->hop_addr) ||
		 (pfx = sc_prefix_find(z->hop_addr)) == NULL)
		continue;
	      if(sc_link4_addadj(link4, pfx) != 0)
		return -1;
	      break;
	    }
	  if(vp == 0)
	    {
	      ttlnn = 1;
	      break;
	    }
	}

      /*
       * if there is a gap in this trace at the next hop, make a note
       * of the AS seen next
       */
      if(i+2 < lh && trace->hops[i+2] == NULL)
	{
	  for(j = i+2; j < lh; j++)
	    {
	      if((z = trace->hops[j]) != NULL)
		{
		  if((pfx = sc_prefix_find(z->hop_addr)) != NULL &&
		     sc_link4_addgap(link4, pfx) != 0)
		    return -1;
		  break;
		}
	    }
	}
    }

  /*
   * if there was no TTL expired message in the neighbor network,
   * and the traceroute was towards a known peer or customer, then
   * save the trace for possible use later
   */
  if(ttlnn == 0 && asmap_r(dst->asmap, &sib, &asn, &r) == 0 && r != 1)
    {
      if((ts = sc_traceset_get(asn)) == NULL)
	return -1;
      if(slist_tail_push(ts->list, trace) == NULL)
	return -1;
      return 1;
    }

  return 0;
}

static int process_1_trace(scamper_trace_t *trace)
{
  slist_t *tmp;
  int rc, lh;

  /*
   * check to see if this traceroute should be included in border map
   * construction: i.e. make sure the traceroute is not towards an address
   * in the VP's network, and the path is trustworthy
   */
  if(is_vp(trace->dst) != 0 || (lh = trace_lasthop(trace)) == 0)
    {
      scamper_trace_free(trace);
      return 0;
    }

  /*
   * ensure any unrouted address space is handled early.
   * if there is no unrouted space to take care of (rc == 0) then
   * process the trace and be done.  otherwise, put it on a list
   * to process later.
   */
  if((rc = process_1_trace_unrouted(trace, lh)) < 0)
    {
      scamper_trace_free(trace);
      return -1;
    }
  if(rc != 0)
    {
      /* process the trace later */
      if(slist_tail_push(held, trace) == NULL)
	{
	  scamper_trace_free(trace);
	  return -1;
	}

      /* if the address space was not modified, continue onwards */
      if(rc == 1)
	return 0;
      if((tmp = slist_alloc()) == NULL)
	return -1;

      while((trace = slist_head_pop(held)) != NULL)
	{
	  if((lh = trace_lasthop(trace)) == 0)
	    {
	      scamper_trace_free(trace);
	      continue;
	    }

	  if((rc = process_1_trace_unrouted(trace, lh)) < 0)
	    {
	      scamper_trace_free(trace);
	      return -1;
	    }

	  if(rc == 0)
	    {
	      if((rc = process_1_trace_work(trace, lh)) < 0)
		{
		  scamper_trace_free(trace);
		  return -1;
		}
	      if(rc == 0)
		scamper_trace_free(trace);
	      continue;
	    }

	  slist_tail_push(tmp, trace);
	  if(rc == 2)
	    slist_concat(held, tmp);
	}

      slist_concat(held, tmp);
      slist_free(tmp);
      return 0;
    }

  if((rc = process_1_trace_work(trace, lh)) < 0)
    {
      scamper_trace_free(trace);
      return -1;
    }
  if(rc == 1)
    return 0;

  scamper_trace_free(trace);
  return 0;
}

/*
 * process_1_ping
 *
 * for the pings we sent to test IPID behavior, check if there are
 * different source addresses used to respond for a cheap alias
 * resolution
 *
 */
static int process_1_ping(scamper_ping_t *ping)
{
  scamper_ping_reply_t *r;
  uint16_t i;

  if(SCAMPER_PING_METHOD_IS_UDP(ping) == 0)
    goto done;

  for(i=0; i<ping->ping_sent; i++)
    {
      r = ping->ping_replies[i];
      while(r != NULL)
	{
	  if(SCAMPER_PING_REPLY_IS_ICMP_UNREACH_PORT(r) &&
	     scamper_addr_cmp(r->addr, ping->dst) != 0 &&
	     scamper_addr_isreserved(r->addr) == 0 &&
	     sc_link_find(ping->dst, r->addr) == NULL &&
	     sc_link_find(r->addr, ping->dst) == NULL &&
	     sc_routerset_getpair(rtrset, ping->dst, r->addr) == NULL)
	    goto err;
	  r = r->next;
	}
    }

 done:
  scamper_ping_free(ping);
  return 0;

 err:
  scamper_ping_free(ping);
  return -1;
}

/*
 * sc_asrel_to_vpasc
 *
 * if the relationship involves a VP ASN, put it in the neighs structure
 * as an sc_asc_t.
 */
static int sc_asrel_to_vpasc(sc_stree_t *neighs, sc_asrel_t *r)
{
  uint32_t as;

  if(is_vpas(r->a))
    {
      if(is_vpas(r->b))
	return 0;
      as = r->b;
    }
  else if(is_vpas(r->b))
    {
      as = r->a;
    }
  else return 0;

  if(sc_asc_get(neighs, as) == NULL)
    return -1;

  return 0;
}

static sc_stree_t *asmap_to_asset(sc_stree_t *set)
{
  sc_asmapc_t *asmapc;
  sc_stree_t *asset;
  slist_node_t *sn;
  sc_asc_t *asc;
  int i;

  if((asset = sc_stree_alloc((splaytree_cmp_t)sc_asc_as_cmp)) == NULL)
    return NULL;

  for(sn=slist_head_node(set->list); sn != NULL; sn=slist_node_next(sn))
    {
      asmapc = slist_node_item(sn);
      for(i=0; i<asmapc->asmap->asc; i++)
	{
	  if(is_vpas(asmapc->asmap->ases[i]))
	    continue;
	  if((asc = sc_asc_get(asset, asmapc->asmap->ases[i])) == NULL)
	    {
	      sc_stree_free(asset, free);
	      return NULL;
	    }
	  asc->c++;
	}
    }

  return asset;
}

/*
 * owner_1_graph:
 *
 * given a set of ASes, observed at a given hop, infer who might
 * be the provider involved based on inferred AS relationships.
 */
static int owner_1_graph(sc_stree_t *set, uint32_t *as)
{
  sc_stree_t *asset = NULL;
  slist_node_t *sn, *sn2;
  sc_asc_t *asc, *asc2;
  sc_asmap_t *asmap;
  uint32_t u32;
  int i, r;

  /*
   * if the set contains one asmap, and that asmap is a MOAS of size 2,
   * then try and reason about who the owning AS might be.
   */
  if(slist_count(set->list) == 1 &&
     ((sc_asmapc_t *)slist_head_item(set->list))->asmap->asc == 2)
    {
      asmap = ((sc_asmapc_t *)slist_head_item(set->list))->asmap;

      /* if one of the two ASes is a customer of the VP, pick that one */
      for(i=0; i<2; i++)
	{
	  if(is_vpas(asmap->ases[i]))
	    continue;
	  if(vp_r(asmap->ases[i], &u32, &r) == 0 && r == -1)
	    {
	      *as = asmap->ases[i];
	      return 0;
	    }
	}

      /* if one of the two ASes is a customer of the other, pick that one */
      u32 = 0;
      if(sc_asrel_r(asmap->ases[0], asmap->ases[1], &r) == 0)
	{
	  if(r == -1)
	    u32 = asmap->ases[1];
	  else if(r == 1)
	    u32 = asmap->ases[0];
	}
      if(u32 != 0 && is_vpas(u32) == 0)
	{
	  *as = u32;
	  return 0;
	}
    }

  if((asset = asmap_to_asset(set)) == NULL)
    return -1;
  if(slist_count(asset->list) == 0)
    {
      *as = 0;
      goto done;
    }

  /*
   * if the set had more than one ASN in it, but that ASN was in every
   * prefix, then choose that ASN.
   */
  slist_qsort(asset->list, (slist_cmp_t)sc_asc_c_cmp);
  asc = slist_head_item(asset->list);
  if(asc->c == slist_count(set->list))
    {
      *as = asc->as;
      goto done;
    }

  /* reset the count per AS, because we are going to use it next */
  for(sn=slist_head_node(asset->list); sn != NULL; sn=slist_node_next(sn))
    {
      asc = slist_node_item(sn);
      asc->c = 0;
    }

  /*
   * the AS with the most customers in the set is inferred to be the owner
   * by graph
   */
  for(sn=slist_head_node(asset->list); sn != NULL; sn=slist_node_next(sn))
    {
      asc = slist_node_item(sn);
      for(sn2=slist_node_next(sn); sn2 != NULL; sn2=slist_node_next(sn2))
	{
	  asc2 = slist_node_item(sn2);
	  if(sc_asrel_r(asc->as, asc2->as, &r) == 0)
	    {
	      if(r == -1)
		asc->c++;
	      else if(r == 1)
		asc2->c++;
	    }
	}
    }

  slist_qsort(asset->list, (slist_cmp_t)sc_asc_c_cmp);
  asc = slist_head_item(asset->list);
  *as = asc->as;

 done:
  if(asset != NULL) sc_stree_free(asset, (sc_stree_free_t)sc_asc_free);
  return 0;
}

static int owner_1_asmap(sc_router_t *y, sc_asmap_t **asmap)
{
  sc_stree_t *yas_set = NULL;
  sc_asmapc_t *asmapc;
  sc_addr2router_t *a2r;
  sc_prefix_t *pfx;
  slist_node_t *sn;
  int rc = -1;

  *asmap = NULL;
  if((yas_set = sc_stree_alloc((splaytree_cmp_t)sc_asmapc_as_cmp)) == NULL)
    goto done;

  for(sn=slist_head_node(y->addrs); sn != NULL; sn=slist_node_next(sn))
    {
      a2r = slist_node_item(sn);
      if(a2r->ttlexp == 0 || is_vp(a2r->addr) == 1 || is_ixp(a2r->addr) == 1)
	continue;

      /* assemble list of ASes that announce prefixes seen for this router */
      if((pfx = sc_prefix_find(a2r->addr)) != NULL)
	{
	  if((asmapc = sc_asmapc_get(yas_set, pfx->asmap)) == NULL)
	    goto done;
	  asmapc->c++;
	}
    }

  if(slist_count(yas_set->list) == 0)
    {
      rc = 0;
      goto done;
    }

  slist_qsort(yas_set->list, (slist_cmp_t)sc_asmapc_c_cmp);
  asmapc = slist_head_item(yas_set->list);
  *asmap = asmapc->asmap;
  rc = 1;

 done:
  if(yas_set != NULL) sc_stree_free(yas_set, (sc_stree_free_t)sc_asmapc_free);
  return rc;
}

/*
 * owner_1_thirdparty:
 *
 * infer if the thirdparty heuristic applies to this router
 */
static int owner_1_thirdparty(sc_router_t *y, uint32_t *owner, uint32_t *tp)
{
  sc_stree_t *yas_set = NULL;
  uint32_t y_asn, dst_asn;
  sc_addr2router_t *a2r;
  sc_asmapc_t *asmapc;
  sc_prefix_t *pfx;
  slist_node_t *sn;
  sc_asmap_t *yas;
  int i, j, r, rc = -1;

  if(y->dstases == NULL || slist_count(y->dstases->list) != 1)
    return 0;

  if((yas_set = sc_stree_alloc((splaytree_cmp_t)sc_asmapc_as_cmp)) == NULL)
    goto done;
  for(sn=slist_head_node(y->addrs); sn != NULL; sn=slist_node_next(sn))
    {
      a2r = slist_node_item(sn);
      if(a2r->ttlexp == 0 || is_vp(a2r->addr) == 1 || is_ixp(a2r->addr) == 1)
	continue;

      /* assemble list of ASes that announce prefixes seen for this router */
      if((pfx = sc_prefix_find(a2r->addr)) != NULL &&
	 sc_asmapc_get(yas_set, pfx->asmap) == NULL)
	goto done;
    }
  if(slist_count(yas_set->list) != 1)
    {
      rc = 0;
      goto done;
    }

  yas = ((sc_asmapc_t *)slist_head_item(yas_set->list))->asmap;
  asmapc = slist_head_item(y->dstases->list);
  for(i=0; i<yas->asc; i++)
    {
      y_asn = yas->ases[i];
      if(is_vpas(y_asn))
	continue;
      for(j=0; j<asmapc->asmap->asc; j++)
	{
	  dst_asn = asmapc->asmap->ases[j];
	  if(is_vpas(dst_asn))
	    continue;
	  if(sc_asrel_r(dst_asn, y_asn, &r) == 0 && r == 1)
	    {
	      *owner = dst_asn;
	      *tp = y_asn;
	      rc = 1;
	      goto done;
	    }
	}
    }

 done:
  if(yas_set != NULL) sc_stree_free(yas_set, (slist_free_t)sc_asmapc_free);
  return rc;
}

/*
 * owner_1_traceset:
 *
 * infer the near router involved in an interdomain interconnection where
 * the far router is unresponsive, or might send an ICMP echo or unreach.
 */
static int owner_1_traceset(sc_routerset_t *set, sc_traceset_t *ts)
{
  sc_router_t *near_rtr = NULL, *last_rtr, *rtr;
  scamper_trace_hop_t *far_hop = NULL, *hop;
  scamper_trace_t *trace;
  slist_t *fars = NULL;
  slist_node_t *sn;
  uint16_t i;

  if((fars = slist_alloc()) == NULL)
    return -1;

  for(sn = slist_head_node(ts->list); sn != NULL; sn = slist_node_next(sn))
    {
      trace = slist_node_item(sn);
      last_rtr = NULL;
      for(i=0; i<trace->hop_count; i++)
	{
	  if((hop = trace->hops[i]) == NULL)
	    continue;
	  if(SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(hop) == 0)
	    {
	      if(i > 0 && trace->hops[i-1] != NULL &&
		 sc_routerset_find(set,trace->hops[i-1]->hop_addr) == last_rtr)
		slist_tail_push(fars, hop);
	      break;
	    }
	  if((rtr = sc_routerset_find(set, hop->hop_addr)) == NULL)
	    continue;
	  if(is_vpas(rtr->owner_as))
	    last_rtr = rtr;
	}

      if(near_rtr == NULL)
	near_rtr = last_rtr;
      else if(near_rtr != last_rtr)
	goto done;
    }

  if(near_rtr == NULL)
    goto done;

  /* if there is no set of adjacent routers, then build a fake adjacency */
  if(slist_count(fars) == 0)
    {
      slist_free(fars); fars = NULL;
      if((rtr = sc_routerset_getnull(set)) == NULL)
	goto err;
      rtr->owner_as = ts->asn;
      rtr->ttl = near_rtr->ttl + 1;
      rtr->owner_reason = SC_ROUTER_OWNER_SILENT;
      if(sc_router_adj_add(near_rtr, rtr) != 0)
	goto err;
      return 1;
    }

  for(sn=slist_head_node(fars); sn != NULL; sn=slist_node_next(sn))
    {
      hop = slist_node_item(sn);
      if(far_hop == NULL)
	far_hop = hop;
      else if(scamper_addr_cmp(far_hop->hop_addr, hop->hop_addr) != 0)
	break;
    }
  if(sn != NULL || far_hop == NULL)
    goto done;
  if((rtr = sc_routerset_find(set, far_hop->hop_addr)) != NULL)
    {
      if(rtr->owner_as != 0)
	goto done;
    }
  else
    {
      if((rtr = sc_routerset_get(set, far_hop->hop_addr)) == NULL)
	goto err;
      rtr->ttl = near_rtr->ttl + 1;
    }
  rtr->owner_reason = SC_ROUTER_OWNER_ICMP;
  rtr->owner_as = ts->asn;
  if(sc_router_adj_add(near_rtr, rtr) != 0)
    goto err;

  return 1;

 done:
  if(fars != NULL) slist_free(fars);
  return 0;

 err:
  if(fars != NULL) slist_free(fars);
  return -1;
}

/*
 * owner_1:
 *
 * infer ownership for router Y.
 *
 * ixpc:     the number of IXP ttlexp interfaces on router Y
 * vpc:      the number of VP ttlexp interfaces on router Y
 * yas_set:  networks announcing ttlexp interfaces on router Y
 * a2r_list: the ttlexp interfaces on router Y
 */
static int owner_1(sc_router_t *y, uint32_t *owner_as, uint8_t *owner_reason)
{
  sc_stree_t *yas_set = NULL, *zas_set = NULL, *zas2_set = NULL;
  sc_stree_t *adj_set = NULL, *ixp_set = NULL, *tp_set = NULL;
  slist_t *a2r_list = NULL;
  sc_addr2router_t *a2r;
  dlist_node_t *dn;
  slist_node_t *sn, *sn2;
  sc_asmap_t *yas, *zas;
  sc_asmapc_t *asmapc, *asmapc2, *asmapc3;
  sc_asc_t *asc;
  sc_ixpc_t *ixppfxc;
  sc_prefix_t *pfx;
  sc_router_t *z;
  sc_prov_t *prov;
  uint32_t y_asn, dst_asn, z_asn, sib, neigh;
  uint32_t y_dstases_owner = 0, zas_set_owner = 0;
  int i, j, r, ixpc, vpc, rc = -1;
  int a2r_count, yas_count, zas_count, y_dstases_count;
  uint8_t u8;

  *owner_as = 0;
  *owner_reason = SC_ROUTER_OWNER_NONE;

  if(y->owner_as != 0)
    goto done;

  if((a2r_list = slist_alloc()) == NULL ||
     (yas_set = sc_stree_alloc((splaytree_cmp_t)sc_asmapc_as_cmp)) == NULL ||
     (zas_set = sc_stree_alloc((splaytree_cmp_t)sc_asmapc_as_cmp)) == NULL ||
     (ixp_set = sc_stree_alloc((splaytree_cmp_t)sc_ixpc_pfx_cmp)) == NULL)
    goto done;

  /*
   * assemble the list of IP addresses seen in traceroutes for this router,
   * counting the number originated by the VP's network, and who announces
   * the router's address space in BGP.
   */
  vpc = 0; ixpc = 0;
  for(sn=slist_head_node(y->addrs); sn != NULL; sn=slist_node_next(sn))
    {
      a2r = slist_node_item(sn);
      if(a2r->ttlexp == 0)
	continue;
      if(slist_tail_push(a2r_list, a2r) == NULL)
	goto done;
      if(is_vp(a2r->addr) == 1)
	vpc++;
      else if(is_ixp(a2r->addr) == 1)
	ixpc++;

      /* assemble list of ASes that announce prefixes seen for this router */
      if((pfx = sc_prefix_find(a2r->addr)) != NULL &&
	 sc_asmapc_get(yas_set, pfx->asmap) == NULL)
	goto done;
    }
  if(slist_count(a2r_list) == 0)
    {
      rc = 0;
      goto done;
    }

  /*
   * assemble the list of neighboring prefixes covering addresses seen
   * in traceroutes to neighboring routers
   */
  for(dn = (y->adj != NULL) ? dlist_head_node(y->adj) : NULL;
      dn != NULL; dn = dlist_node_next(dn))
    {
      z = dlist_node_item(dn);
      for(sn2=slist_head_node(z->addrs); sn2 != NULL; sn2=slist_node_next(sn2))
	{
	  a2r = slist_node_item(sn2);
	  if(a2r->ttlexp == 0)
	    continue;
	  if(is_ixp(a2r->addr))
	    {
	      if((ixppfxc = sc_ixpc_get(ixp_set, a2r->addr)) == NULL)
		goto done;
	      ixppfxc->c++;
	    }
	  else if((pfx = sc_prefix_find(a2r->addr)) != NULL &&
		  sc_asmap_isvp(pfx->asmap) == 0)
	    {
	      if((asmapc = sc_asmapc_get(zas_set, pfx->asmap)) == NULL)
		goto done;
	      asmapc->c++;
	    }
	}
    }

  /*
   * sort the list of adjacent ASes so that the AS with the most
   * adjacent interfaces is found first.
   *
   * sort the IXP prefixes so that the prefix with the most IP addresses
   * observed is found first
   */
  slist_qsort(zas_set->list, (slist_cmp_t)sc_asmapc_c_cmp);
  slist_qsort(ixp_set->list, (slist_cmp_t)sc_ixpc_c_cmp);

  /* get a bunch of count values now that the lists have settled */
  zas_count = slist_count(zas_set->list);
  yas_count = slist_count(yas_set->list);
  a2r_count = slist_count(a2r_list);
  y_dstases_count = y->dstases != NULL ? slist_count(y->dstases->list) : 0;

  /*
   * if there are addresses announced by the VP observed adjacent to this
   * router and observed in an IP-level link, then try and determine if
   * the router belongs to this network, or an adjacent network.
   */
  if(y->flags & SC_ROUTER_FLAG_FIRST)
    {
      if(y->adj != NULL && slist_count(zas_set->list) > 0)
	{
	  if((zas2_set =
	      sc_stree_alloc((splaytree_cmp_t)sc_asmapc_as_cmp)) == NULL ||
	     (tp_set=sc_stree_alloc((splaytree_cmp_t)sc_asc_as_cmp)) == NULL)
	    goto done;

	  for(dn=dlist_head_node(y->adj); dn != NULL; dn=dlist_node_next(dn))
	    {
	      z = dlist_node_item(dn);
	      if(owner_1_thirdparty(z, &dst_asn, &y_asn) == 1)
		{
		  if((asc = sc_asc_get(tp_set, y_asn)) == NULL)
		    goto done;
		  asc->c++;
		}
	      else if(owner_1_asmap(z, &zas) == 1)
		{
		  if((asmapc = sc_asmapc_get(zas2_set, zas)) == NULL)
		    goto done;
		  asmapc->c++;
		}
	    }

	  slist_qsort(tp_set->list, (slist_cmp_t)sc_asc_c_cmp);
	  slist_qsort(zas2_set->list, (slist_cmp_t)sc_asmapc_c_cmp);
	  if(slist_count(tp_set->list) > 0 &&
	     slist_count(zas2_set->list) > 0 &&
	     (asc = slist_head_item(tp_set->list)) != NULL &&
	     is_vpas(asc->as) == 0 && asc->c >= 2)
	    {
	      asmapc = slist_head_item(zas2_set->list);
	      for(i=0; i<asmapc->asmap->asc; i++)
		{
		  z_asn = asmapc->asmap->ases[i];
		  if(asc->as == z_asn)
		    {
		      *owner_as = z_asn;
		      *owner_reason = SC_ROUTER_OWNER_FIRST2;
		      rc = 1;
		      goto done;
		    }
		}
	    }

	  sc_stree_free(zas2_set, (sc_stree_free_t)sc_asmapc_free);
	  zas2_set = NULL;
	  sc_stree_free(tp_set, (sc_stree_free_t)sc_asc_free); tp_set = NULL;
	}

      if(zas_count > 0 && y_dstases_count > 0 && y_dstases_count < 100)
	{
	  /*
	   * figure out who might own the router, based on the
	   * destination ASes probed
	   */
	  if(owner_1_graph(y->dstases, &y_dstases_owner) != 0)
	    goto done;
	  zas = ((sc_asmapc_t *)slist_head_item(zas_set->list))->asmap;
	  for(i=0; i<zas->asc; i++)
	    if(zas->ases[i] == y_dstases_owner)
	      break;

	  /*
	   * possible first2 candidate.  do some extra sanity checks
	   * on adjacent routers: if at least one of them would have
	   * an owner AS inferred, and is a customer of the VP, and
	   * has no known relationship with the candidate AS, then
	   * don't infer the owner as the candidate AS, fall through
	   * and use the first heuristic
	   */
	  if(i != zas->asc && y->adj != NULL)
	    {
	      for(dn = dlist_head_node(y->adj); dn != NULL;
		  dn = dlist_node_next(dn))
		{
		  z = dlist_node_item(dn);
		  if(z->owner_as != 0)
		    z_asn = z->owner_as;
		  else if(owner_1(z, &z_asn, &u8) != 1)
		    continue;

		  if(is_vpas(z_asn) || z_asn == y_dstases_owner || z_asn == 0)
		    continue;
		  if(vp_r(z_asn, &sib, &r) == 0 && r == -1 &&
		     sc_asrel_find(y_dstases_owner, z_asn) == NULL)
		    break;
		}

	      if(dn == NULL)
		{
		  *owner_as = y_dstases_owner;
		  *owner_reason = SC_ROUTER_OWNER_FIRST2;
		  rc = 1;
		  goto done;
		}
	    }
	}

      *owner_as = vpas[0];
      *owner_reason = SC_ROUTER_OWNER_FIRST;
      rc = 1;
      goto done;
    }

  /*
   * if we do not observe anything adjacent to this router, but we
   * have seen other addresses after the gap, then look to see if
   * we saw an address announced by the VP's network.
   */
  if(vpc == a2r_count && y->adj == NULL && y->gapases != NULL)
    {
      sn = slist_head_node(y->gapases->list);
      while(sn != NULL)
	{
	  asmapc = slist_node_item(sn);
	  if(sc_asmap_isvp(asmapc->asmap))
	    {
	      *owner_reason = SC_ROUTER_OWNER_FIRST;
	      *owner_as = vpas[0];
	      rc = 1;
	      goto done;
	    }
	  sn = slist_node_next(sn);
	}
    }

  /*
   * if this router only has address space from the VP network,
   * and there are IXP addresses adjacent suggesting the router is
   * close to an IXP
   */
  if(vpc == a2r_count &&
     (ixppfxc = slist_head_item(ixp_set->list)) != NULL && ixppfxc->c >= 2)
    {
      /*
       * if there are no routers adjacent with publicly routed address
       * space, then infer the router is owned by the VP's network
       * and represents a router colocated at an IXP
       */
      if(zas_count == 0)
	{
	  *owner_reason = SC_ROUTER_OWNER_IXP;
	  *owner_as = vpas[0];
	  rc = 1;
	  goto done;
	}
    }

  if(y->dstases != NULL && owner_1_graph(y->dstases, &y_dstases_owner) != 0)
    goto done;

  if(vpc+ixpc == a2r_count)
    {
      /*
       * if we do not observe anything after this router, then reason
       * about who might own the router based on the destination ASes
       * probed.  if we have no inference (y_dstases_owner == 0) then
       * there is no other source of information that would allow us
       * to make a better decision so we're done.
       */
      if(y->adj == NULL)
	{
	  if(y_dstases_owner != 0)
	    {
	      *owner_reason = SC_ROUTER_OWNER_TRACESET;
	      *owner_as = y_dstases_owner;
	      rc = 1;
	    }
	  goto done;
	}

      /*
       * if this router only has IXP addresses, and subsequent routers
       * are in the same IXP subnet as this router, then infer the router
       * belongs to the VP.
       */
      if(ixpc == a2r_count)
	{
	  for(sn=slist_head_node(y->addrs); sn != NULL; sn=slist_node_next(sn))
	    {
	      a2r = slist_node_item(sn);
	      if(a2r->ttlexp == 0)
		continue;
	      if((ixppfxc = sc_ixpc_find(ixp_set, a2r->addr)) != NULL)
		break;
	    }
	  if(sn != NULL)
	    {
	      *owner_reason = SC_ROUTER_OWNER_IXP;
	      *owner_as = vpas[0];
	      rc = 1;
	      goto done;
	    }
	}

      /*
       * if the adjacent router has no addresses routed in BGP,
       * then infer who might own that address space.
       */
      if(zas_count == 0 && y_dstases_owner != 0)
	{
	  *owner_reason = SC_ROUTER_OWNER_NOIP2AS;
	  *owner_as = y_dstases_owner;
	  rc = 1;
	  goto done;
	}
    }

  /*
   * if the router's addresses are not announced in BGP, then try
   * and deduce who might operate it.
   */
  if(yas_count == 0 && ixpc == 0)
    {
      if((y->adjases != NULL && owner_1_graph(y->adjases, &y_asn) != 0) ||
	 (y_asn = y_dstases_owner) != 0)
	{
	  *owner_reason = SC_ROUTER_OWNER_NOIP2AS;
	  *owner_as = y_asn;
	  rc = 1;
	}
      goto done;
    }

  if(yas_count == 1)
    {
      yas = ((sc_asmapc_t *)slist_head_item(yas_set->list))->asmap;

      /*
       * if one of the adjacent routers is also in external address space,
       * then mark Y as owned by yas.
       */
      if(y->adjases != NULL && (adj_set = asmap_to_asset(y->adjases)) == NULL)
	goto done;
      if(adj_set != NULL)
	{
	  for(i=0; i<yas->asc; i++)
	    {
	      y_asn = yas->ases[i];
	      if(is_vpas(y_asn) == 0 && sc_asc_find(adj_set, y_asn) != NULL)
		{
		  *owner_reason = SC_ROUTER_OWNER_ONENET;
		  *owner_as = y_asn;
		  rc = 1;
		  goto done;
		}
	    }
	  sc_stree_free(adj_set, (sc_stree_free_t)sc_asc_free);
	  adj_set = NULL;
	}

      /* check for third party addresses */
      if(owner_1_thirdparty(y, &dst_asn, &y_asn) == 1)
	{
	  *owner_reason = SC_ROUTER_OWNER_THIRDPARTY;
	  *owner_as = dst_asn;
	  rc = 1;
	  goto done;
	}
    }

  if(zas_count == 1)
    {
      zas = ((sc_asmapc_t *)slist_head_item(zas_set->list))->asmap;

      /*
       * go through the adjacent routers (z).  if one of the routers adjacent
       * to z (z', z'', etc) are in the same AS as z, then infer that router
       * Y is operated by the network announcing z.
       */
      for(dn=dlist_head_node(y->adj); dn != NULL; dn=dlist_node_next(dn))
	{
	  z = dlist_node_item(dn);
	  if(z->adjases == NULL)
	    continue;
	  if((adj_set = asmap_to_asset(z->adjases)) == NULL)
	    goto done;
	  for(i=0; i<zas->asc; i++)
	    {
	      z_asn = zas->ases[i];
	      if(is_vpas(z_asn))
		continue;
	      if(sc_asc_find(adj_set, z_asn) != NULL)
		{
		  *owner_reason = SC_ROUTER_OWNER_ONENET2;
		  *owner_as = z_asn;
		  rc = 1;
		  goto done;
		}
	    }
	  sc_stree_free(adj_set, (sc_stree_free_t)sc_asc_free);
	  adj_set = NULL;
	}
    }

  /*
   * if router Y was observed on the path to one network, do special
   * casing to try and avoid bad inferences caused by third party
   * addresses at a subsequent hop that will otherwise use to infer
   * Y's ownership.
   */
  if(y_dstases_count == 1 && zas_count == 1)
    {
      asmapc = slist_head_item(y->dstases->list);
      zas = ((sc_asmapc_t *)slist_head_item(zas_set->list))->asmap;

      for(i=0; i<zas->asc; i++)
	{
	  z_asn = zas->ases[i];
	  if(is_vpas(z_asn))
	    continue;
	  for(j=0; j<asmapc->asmap->asc; j++)
	    {
	      dst_asn = asmapc->asmap->ases[j];
	      if(is_vpas(dst_asn))
		continue;
	      if(sc_asrel_r(dst_asn, z_asn, &r) == 0 && r == 1)
		{
		  *owner_reason = SC_ROUTER_OWNER_THIRDPARTY2;
		  *owner_as = dst_asn;
		  rc = 1;
		  goto done;
		}
	    }
	}

      for(i=0; i<asmapc->asmap->asc; i++)
	{
	  dst_asn = asmapc->asmap->ases[i];
	  if(is_vpas(dst_asn))
	    continue;
	  if(vp_r(dst_asn, &sib, &r) == 0 && r == -1)
	    {
	      *owner_reason = SC_ROUTER_OWNER_CUSTOMER;
	      *owner_as = dst_asn;
	      rc = 1;
	      goto done;
	    }
	}
    }

  /*
   * if the neighbour router(s) are announced by one AS,
   * then assign ownership according to that AS.
   */
  if(zas_count == 1)
    {
      zas = ((sc_asmapc_t *)slist_head_item(zas_set->list))->asmap;
      if(asmap_r(zas, &sib, &neigh, &r) == 0 && (r == -1 || r == 0))
	{
	  if(r == 0)
	    *owner_reason = SC_ROUTER_OWNER_PEER;
	  else if(r == -1)
	    *owner_reason = SC_ROUTER_OWNER_CUSTOMER;
	  *owner_as = neigh;
	  rc = 1;
	  goto done;
	}

      for(i=0; i<zas->asc; i++)
	{
	  if((prov = sc_prov_find(zas->ases[i])) != NULL)
	    {
	      for(i=0; i<prov->provc; i++)
		{
		  y_asn = prov->provs[i];
		  if(vp_r(y_asn, &sib, &r) == 0 && r == -1)
		    {
		      *owner_reason = SC_ROUTER_OWNER_MISSING;
		      *owner_as = y_asn;
		      rc = 1;
		      goto done;
		    }
		}
	    }
	}

      *owner_reason = SC_ROUTER_OWNER_HIDDENPEER;
      *owner_as = zas->ases[0];
      rc = 1;
      goto done;
    }
  else if(zas_count >= 2)
    {
      sn  = slist_head_node(zas_set->list); asmapc = slist_node_item(sn);
      sn2 = slist_node_next(sn); asmapc2 = slist_node_item(sn2);
      if(asmapc->c == asmapc2->c)
	{
	  asmapc3 = NULL;
	  while(sn != NULL)
	    {
	      asmapc2 = slist_node_item(sn);
	      if(asmapc->c != asmapc2->c)
		break;
	      if(asmap_r(asmapc2->asmap, &sib, &neigh, &r) == 0)
		{
		  if(asmapc3 != NULL)
		    {
		      asmapc3 = NULL;
		      break;
		    }
		  asmapc3 = asmapc2;
		}
	      sn = slist_node_next(sn);
	    }
	  if(asmapc3 != NULL)
	    asmapc = asmapc3;
	  else
	    asmapc = NULL;
	}

      if(asmapc != NULL)
	{
	  if(asmap_r(asmapc->asmap, &sib, &neigh, &r) != 0)
	    {
	      if(is_vpas(asmapc->asmap->ases[0]) == 0)
		{
		  *owner_as = asmapc->asmap->ases[0];
		  *owner_reason = SC_ROUTER_OWNER_COUNT2;
		}
	      else
		{
		  if(owner_1_graph(zas_set, &zas_set_owner) == 0)
		    goto done;
		  if(zas_set_owner != 0)
		    neigh = zas_set_owner;
		  *owner_as = neigh;
		  *owner_reason = SC_ROUTER_OWNER_COUNT3;
		}
	    }
	  else
	    {
	      *owner_as = asmapc->asmap->ases[0];
	      *owner_reason = SC_ROUTER_OWNER_COUNT;
	    }
	  rc = 1;
	  goto done;
	}
    }

  if(vpc > 0 && a2r_count != vpc)
    {
      for(sn=slist_head_node(yas_set->list); sn != NULL; sn=slist_node_next(sn))
	{
	  yas = ((sc_asmapc_t *)slist_node_item(sn))->asmap;
	  for(i=0; i<yas->asc; i++)
	    {
	      if(is_vpas(yas->ases[i]))
		continue;
	      *owner_as = yas->ases[i];
	      *owner_reason = SC_ROUTER_OWNER_IP2AS;
	      rc = 1;
	      goto done;
	    }
	}
    }

  if(yas_count == 1)
    {
      yas = ((sc_asmapc_t *)slist_head_item(yas_set->list))->asmap;
      for(i=0; i<yas->asc; i++)
	{
	  if(is_vpas(yas->ases[i]))
	    continue;
	  *owner_as = yas->ases[i];
	  *owner_reason = SC_ROUTER_OWNER_IP2AS;
	  rc = 1;
	  goto done;
	}
    }

  rc = 0;

 done:
  if(yas_set != NULL) sc_stree_free(yas_set, (sc_stree_free_t)sc_asmapc_free);
  if(zas_set != NULL) sc_stree_free(zas_set, (sc_stree_free_t)sc_asmapc_free);
  if(zas2_set != NULL) sc_stree_free(zas2_set,(sc_stree_free_t)sc_asmapc_free);
  if(adj_set != NULL) sc_stree_free(adj_set, (sc_stree_free_t)sc_asc_free);
  if(ixp_set != NULL) sc_stree_free(ixp_set, (sc_stree_free_t)sc_asc_free);
  if(tp_set != NULL) sc_stree_free(tp_set, (sc_stree_free_t)sc_asc_free);
  if(a2r_list != NULL) slist_free(a2r_list);
  return rc;
}

static void finish_1(void)
{
  scamper_trace_t *trace;
  sc_stree_t *fars = NULL;
  sc_stree_t *neighs = NULL;
  slist_t *list = NULL;
  sc_addr2router_t *a2r;
  sc_router_t *x, *y, *z;
  sc_traceset_t *ts;
  sc_addr2name_t *a2n;
  slist_node_t *sn, *sn2;
  dlist_node_t *dn, *dn2;
  sc_link_t *link;
  sc_ally_t *ar;
  sc_link4_t *link4;
  sc_asmapc_t *asmapc, *asmapc2;
  sc_asmap_t *asmap;
  sc_farrouter_t *fr;
  sc_prefix_t *pfx;
  int r, lh, rc, owned, changed;
  sc_asc_t *asc;
  uint32_t u32, owner_as;
  uint8_t owner_reason;
  char buf[128];

  while((trace = slist_head_pop(held)) != NULL)
    {
      if((lh = trace_lasthop(trace)) == 0)
	{
	  scamper_trace_free(trace);
	  continue;
	}
      if((rc = process_1_trace_work(trace, lh)) < 0)
	{
	  scamper_trace_free(trace);
	  goto done;
	}
      if(rc == 0)
	scamper_trace_free(trace);
    }
  slist_free(held); held = NULL;

  if((list = slist_alloc()) == NULL)
    goto done;

  splaytree_inorder(allys, tree_to_slist, list);
  while((ar = slist_head_pop(list)) != NULL)
    {
      if(ar->result == SCAMPER_DEALIAS_RESULT_ALIASES &&
	 sc_routerset_getpair(rtrset, ar->a, ar->b) == NULL)
	goto done;
    }

  /*
   * build a simplified graph of routers represented in
   * the set of links, and begin to annotate routers with ownership.
   */
  splaytree_inorder(links, tree_to_slist, list);
  while((link = slist_head_pop(list)) != NULL)
    {
      /* skip over links not seen in the traceroutes we use */
      if((link4 = link->data) == NULL)
	continue;

      /* build links between routers */
      if((y = sc_routerset_get(rtrset, link->a)) == NULL ||
	 (z = sc_routerset_get(rtrset, link->b)) == NULL ||
	 sc_router_adj_add(y, z) != 0 || sc_router_prev_add(z, y) != 0)
	goto done;

      /*
       * set the earliest distance in a path each of these routers was
       * observed
       */
      if(y->ttl == 0 || y->ttl > link4->ttl)
	y->ttl = link4->ttl;
      if(z->ttl == 0 || z->ttl > link4->ttl + 1)
	z->ttl = link4->ttl + 1;

      /* figure out where the traceroutes for this router end up */
      sn = slist_head_node(link4->dstases->list);
      while(sn != NULL)
	{
	  asmapc = slist_node_item(sn);
	  if((asmapc2 = sc_router_dstases_get(z, asmapc->asmap)) == NULL)
	    goto done;
	  asmapc2->c += asmapc->c;
	  sn = slist_node_next(sn);
	}

      /*
       * get additional information, if available, on adjacent networks
       * to this router.
       */
      if(link4->adjases != NULL)
	{
	  if(z->adjases == NULL)
	    z->adjases = sc_stree_alloc((splaytree_cmp_t)sc_asmapc_as_cmp);
	  if(z->adjases == NULL)
	    goto done;
	  sn = slist_head_node(link4->adjases->list);
	  while(sn != NULL)
	    {
	      asmapc = slist_node_item(sn);
	      if((asmapc2 = sc_asmapc_get(z->adjases, asmapc->asmap)) == NULL)
		goto done;
	      asmapc2->c += asmapc->c;
	      sn = slist_node_next(sn);
	    }
	}

      /*
       * get additional information, if available, on what is seen after
       * a gap from this router
       */
      if(link4->gapases != NULL)
	{
	  if(z->gapases == NULL)
	    z->gapases = sc_stree_alloc((splaytree_cmp_t)sc_asmapc_as_cmp);
	  if(z->gapases == NULL)
	    goto done;
	  sn = slist_head_node(link4->gapases->list);
	  while(sn != NULL)
	    {
	      asmapc = slist_node_item(sn);
	      if((asmapc2 = sc_asmapc_get(z->gapases, asmapc->asmap)) == NULL)
		goto done;
	      asmapc2->c += asmapc->c;
	      sn = slist_node_next(sn);
	    }
	}

      /* mark the interfaces that are ttl-expired */
      if((a2r = sc_routerset_a2r_find(rtrset, link->a)) == NULL)
	goto done;
      a2r->ttlexp = 1;
      if((a2r = sc_routerset_a2r_find(rtrset, link->b)) == NULL)
	goto done;
      a2r->ttlexp = 1;

      /* begin to assign ownership */
      if(is_vp(link->b) == 1)
	y->flags |= SC_ROUTER_FLAG_FIRST;
    }

  dlist_qsort(rtrset->list, (dlist_cmp_t)sc_router_ttl_cmp);

  /* assign owners! */
  do
    {
      for(dn=dlist_head_node(rtrset->list); dn != NULL; dn=dlist_node_next(dn))
	{
	  x = dlist_node_item(dn);
	  x->flags &= (~SC_ROUTER_FLAG_VISITED);
	}

      /*
       * we assign owners iteratively, and continue to assign owners
       * provided we assigned an owner to at least one router in the
       * set
       */
      changed = 0;
      for(dn=dlist_head_node(rtrset->list); dn != NULL; dn=dlist_node_next(dn))
	{
	  /*
	   * we try and infer border routers involving the VP, so we
	   * look and links adjacent to a router we have inferred to
	   * be owned by the VP.
	   */
	  x = dlist_node_item(dn);
	  if(x->owner_as != vpas[0])
	    continue;
	  if(x->adj == NULL)
	    continue;
	  for(dn2=dlist_head_node(x->adj);dn2 != NULL;dn2=dlist_node_next(dn2))
	    {
	      /* skip over routers that have been assigned an owner */
	      y = dlist_node_item(dn2);
	      if(y->owner_reason != SC_ROUTER_OWNER_NONE)
		continue;
	      if(y->flags & SC_ROUTER_FLAG_VISITED)
		continue;
	      y->flags |= SC_ROUTER_FLAG_VISITED;

	      /* if we have an error, break out */
	      if((rc = owner_1(y, &owner_as, &owner_reason)) < 0)
		goto done;

	      /* if we assign an owner, then make a note */
	      if(rc > 0)
		{
		  sc_router_setowner(y, owner_as, owner_reason);
		  changed++;
		}
	    }
	}

      /*
       * if we haven't assigned any owners in the past sequence, then
       * we try new routers in the set.
       */
      if(changed > 0)
	continue;
      for(dn=dlist_head_node(rtrset->list); dn != NULL; dn=dlist_node_next(dn))
	{
	  /*
	   * we only focus on routers that have no inferred owner but
	   * could belong to the VP.  the router has to have at least one
	   * interface that responded with a TTL-expired message that maps
	   * to the VP's network.
	   */
	  x = dlist_node_item(dn);
	  if(x->owner_reason != SC_ROUTER_OWNER_NONE || sc_router_isvp(x) == 0)
	    continue;
	  if(x->flags & SC_ROUTER_FLAG_VISITED)
	    continue;
	  x->flags |= SC_ROUTER_FLAG_VISITED;
	  if((rc = owner_1(x, &owner_as, &owner_reason)) < 0)
	    goto done;
	  if(rc > 0)
	    {
	      sc_router_setowner(x, owner_as, owner_reason);
	      changed++;
	    }
	}
    }
  while(changed > 0);

  /*
   * the next step is to analytically reduce interfaces to routers
   * where we observe multiple border links X1-Y, X2-Y, X3-Y, and
   * the Xes are all single interface routers.
   */
  do
    {
      if(no_merge)
	break;

      /*
       * figure out all the far border routers, and relate them back to
       * observed near border routers.
       */
      changed = 0;
      if((fars = sc_stree_alloc((splaytree_cmp_t)sc_farrouter_far_cmp)) == NULL)
	goto done;
      for(dn=dlist_head_node(rtrset->list); dn != NULL; dn=dlist_node_next(dn))
	{
	  /* we are only interested in near routers owned by the VP network */
	  x = dlist_node_item(dn);
	  if(x->owner_as == 0 || x->owner_as != vpas[0] ||
	     sc_router_isborder(x) == 0)
	    continue;
	  for(dn2 = (x->adj != NULL) ? dlist_head_node(x->adj) : NULL;
	      dn2 != NULL; dn2 = dlist_node_next(dn2))
	    {
	      /* we want the far routers owned by other networks */
	      y = dlist_node_item(dn2);
	      if(y->owner_as == vpas[0] || y->owner_as == 0)
		continue;
	      if((fr = sc_farrouter_get(fars, y)) == NULL)
		goto done;
	      if(sc_farrouter_addnear(fr, x) != 0)
		goto done;
	    }
	}
      if(slist_count(fars->list) == 0)
	break;
      slist_qsort(fars->list, (slist_cmp_t)sc_farrouter_nears_cmp);
      for(sn=slist_head_node(fars->list); sn != NULL; sn = slist_node_next(sn))
	{
	  fr = slist_node_item(sn);
	  if(slist_count(fr->nears) <= 1)
	    break;
	  rc = 1;
	  slist_qsort(fr->nears, (slist_cmp_t)sc_router_p_cmp);
	  sn2 = slist_head_node(fr->nears);
	  while(sn2 != NULL)
	    {
	      y = slist_node_item(sn2); sn2 = slist_node_next(sn2);
	      if(sc_router_ttlexp_count(y) != 1 &&
		 (y->flags & SC_ROUTER_FLAG_MERGED) == 0)
		rc = 0;
	    }

	  /* if this node can be merged, process it */
	  if(rc != 0)
	    {
	      x = slist_head_item(fr->nears);
	      sn2 = slist_node_next(slist_head_node(fr->nears));
	      while(sn2 != NULL)
		{
		  sc_routerset_merge(rtrset, x, slist_node_item(sn2));
		  sn2 = slist_node_next(sn2);
		}
	      changed = 1;
	      break;
	    }
	}

      sc_stree_free(fars, (slist_free_t)sc_farrouter_free);
      fars = NULL;
    }
  while(changed > 0);

  /*
   * go through the list of relationships to obtain the ones involving
   * the VP
   */
  if((neighs = sc_stree_alloc((splaytree_cmp_t)sc_asc_as_cmp)) == NULL)
    goto done;
  splaytree_inorder(reltree, (splaytree_inorder_t)sc_asrel_to_vpasc, neighs);
  for(dn=dlist_head_node(rtrset->list); dn != NULL; dn = dlist_node_next(dn))
    {
      x = dlist_node_item(dn);
      if(is_vpas(x->owner_as) == 0)
	continue;

      for(dn2 = (x->adj != NULL) ? dlist_head_node(x->adj) : NULL;
	  dn2 != NULL; dn2 = dlist_node_next(dn2))
	{
	  y = dlist_node_item(dn2);
	  if(y->owner_as == 0 || is_vpas(y->owner_as) != 0)
	    continue;
	  if((asc = sc_asc_find(neighs, y->owner_as)) != NULL)
	    asc->c++;
	}
    }
  splaytree_inorder(tracesets, tree_to_slist, list);
  splaytree_free(tracesets, NULL); tracesets = NULL;
  while((ts = slist_head_pop(list)) != NULL)
    {
      if((asc = sc_asc_find(neighs, ts->asn)) != NULL && asc->c == 0)
	{
	  if((rc = owner_1_traceset(rtrset, ts)) < 0)
	    return;
	  if(rc == 0 && dump_tracesets)
	    traceset_dump(ts, rtrset);
	}
      sc_traceset_free(ts);
    }

  /* enforce a deterministic ordering */
  for(dn=dlist_head_node(rtrset->list); dn != NULL; dn = dlist_node_next(dn))
    {
      x = dlist_node_item(dn);
      slist_qsort(x->addrs, (slist_cmp_t)sc_addr2router_ttlexp_cmp);
    }
  for(dn=dlist_head_node(rtrset->list); dn != NULL; dn = dlist_node_next(dn))
    {
      x = dlist_node_item(dn);
      if(x->adj != NULL)
	dlist_qsort(x->adj, (dlist_cmp_t)sc_router_owner_cmp);
    }
  dlist_qsort(rtrset->list, (dlist_cmp_t)sc_router_owner_cmp);

  owned = 0;
  for(dn=dlist_head_node(rtrset->list); dn != NULL; dn = dlist_node_next(dn))
    {
      x = dlist_node_item(dn);
      if(x->owner_as != 0)
	owned++;
      if(x->owner_as != 0 && x->owner_as != vpas[0])
	continue;
      if(dump_borders != 0 && sc_router_isborder(x) == 0)
	continue;

      printf("owner %u (%s", x->owner_as, owner_reasonstr[x->owner_reason]);
      if(x->flags & SC_ROUTER_FLAG_MERGED)
	printf(",merged");
      printf(")\n");
      for(sn = slist_head_node(x->addrs); sn != NULL; sn = slist_node_next(sn))
	{
	  a2r = slist_node_item(sn);
	  printf("%s", scamper_addr_tostr(a2r->addr, buf, sizeof(buf)));
	  if(a2r->ttlexp != 0)
	    printf("*");
	  if((a2n = sc_addr2name_find(a2r->addr)) != NULL)
	    printf(" %s", a2n->name);
	  printf("\n");
	}
      for(dn2 = (x->adj != NULL) ? dlist_head_node(x->adj) : NULL;
	  dn2 != NULL; dn2 = dlist_node_next(dn2))
	{
	  y = dlist_node_item(dn2);
	  if(y->owner_as == vpas[0] && no_self != 0)
	    continue;
	  printf(" %u", y->owner_as);
	  if(dump_onedsts && y->dstases != NULL &&
	     slist_count(y->dstases->list) == 1)
	    {
	      asmapc = slist_head_item(y->dstases->list);
	      asmap = asmapc->asmap;
	      for(u32=0; u32 < asmap->asc; u32++)
		if(asmap->ases[u32] == y->owner_as)
		  break;
	      if(u32 == asmap->asc)
		printf(":%s", sc_asmap_tostr(asmap, buf, sizeof(buf)));
	    }

	  if(y->owner_as == vpas[0])
	    {
	      printf(" self");
	    }
	  else if(y->owner_as != 0 && vp_r(y->owner_as, &u32, &r) == 0)
	    {
	      if(r == 1)      printf(" prov");
	      else if(r == 0) printf(" peer");
	      else            printf(" cust");
	    }
	  else
	    {
	      printf(" ????");
	    }
	  printf(" %s", owner_reasonstr[y->owner_reason]);

	  slist_qsort(y->addrs, (slist_cmp_t)sc_addr2router_ttlexp_cmp);
	  for(sn2 = slist_head_node(y->addrs); sn2 != NULL;
	      sn2 = slist_node_next(sn2))
	    {
	      a2r = slist_node_item(sn2);
	      printf(" %s", scamper_addr_tostr(a2r->addr, buf, sizeof(buf)));
	      if(a2r->ttlexp != 0)
		{
		  printf("*");
		  if(x->owner_as == 0 &&
		     (pfx = sc_prefix_find(a2r->addr)) != NULL)
		    printf(" %s", sc_asmap_tostr(pfx->asmap,buf,sizeof(buf)));
		}
	      if((a2n = sc_addr2name_find(a2r->addr)) != NULL)
		printf(" %s", a2n->name);
	    }

	  printf("\n");
	}

      printf("\n");
    }
  printf("%d/%d owned\n", owned, dlist_count(rtrset->list));

 done:
  if(list != NULL) slist_free(list);
  if(tracesets != NULL)
    {
      splaytree_free(tracesets, (splaytree_free_t)sc_traceset_free);
      tracesets = NULL;
    }
  if(links != NULL)
    {
      splaytree_free(links, (splaytree_free_t)sc_link_free_link4);
      links = NULL;
    }
  return;
}

static int process_2_trace(scamper_trace_t *trace)
{
  sc_prefix_t *pfx;
  int i, j;

  /*
   * if ASes are specified on the command line, filter the traceroutes
   * so that only traceroutes towards a specific AS are dumped
   */
  if(targetasc > 0)
    {
      if((pfx = sc_prefix_find(trace->dst)) == NULL)
	return 0;
      for(i=0; i<pfx->asmap->asc; i++)
	{
	  for(j=0; j<targetasc; j++)
	    if(pfx->asmap->ases[i] == targetas[j])
	      break;
	  if(j != targetasc)
	    break;
	}
      if(i == pfx->asmap->asc)
	return 0;
    }

  trace_dump(trace, NULL);
  printf("\n");
  scamper_trace_free(trace);
  return 0;
}

static int bdrmap_dump(void)
{
  scamper_file_t *in;
  char *filename;
  uint16_t type;
  void *data;
  int i, stdin_used=0;

  if(ip2name_fn != NULL)
    {
      ip2name_tree = splaytree_alloc((splaytree_cmp_t)sc_addr2name_cmp);
      if(ip2name_tree == NULL)
	return -1;
      if(file_lines(ip2name_fn, ip2name_line, NULL) != 0)
	return -1;
    }

  if(delegated_fn != NULL)
    {
      if((delegated = slist_alloc()) == NULL)
	return -1;
      if(file_lines(delegated_fn, delegated_line, NULL) != 0)
	return -1;
      if(slist_qsort(delegated, (slist_cmp_t)sc_delegated_cmp) != 0)
	return -1;
    }

  if(dump_funcs[dump_id].init != NULL)
    dump_funcs[dump_id].init();

  for(i=0; i<opt_argc; i++)
    {
      filename = opt_args[i];
      if(strcmp(filename, "-") == 0)
	{
	  if(stdin_used == 1)
	    {
	      fprintf(stderr, "stdin already used\n");
	      return -1;
	    }
	  stdin_used++;
	  in = scamper_file_openfd(STDIN_FILENO, "-", 'r', "warts");
	}
      else
	{
	  in = scamper_file_open(filename, 'r', NULL);
	}

      if(in == NULL)
	{
	  fprintf(stderr,"could not open %s: %s\n", filename, strerror(errno));
	  return -1;
	}

      while(scamper_file_read(in, ffilter, &type, &data) == 0)
	{
	  /* EOF */
	  if(data == NULL)
	    break;

	  if(type == SCAMPER_FILE_OBJ_TRACE)
	    {
	      if(dump_funcs[dump_id].proc_trace != NULL)
		dump_funcs[dump_id].proc_trace(data);
	      else
		scamper_trace_free(data);
	    }
	  else if(type == SCAMPER_FILE_OBJ_PING)
	    {
	      if(dump_funcs[dump_id].proc_ping != NULL)
		dump_funcs[dump_id].proc_ping(data);
	      else
		scamper_ping_free(data);
	    }
	  else if(type == SCAMPER_FILE_OBJ_DEALIAS)
	    {
	      if(dump_funcs[dump_id].proc_dealias != NULL)
		dump_funcs[dump_id].proc_dealias(data);
	      else
		scamper_dealias_free(data);
	    }
	}

      scamper_file_close(in);
    }

  if(dump_funcs[dump_id].finish != NULL)
    dump_funcs[dump_id].finish();

  if(ip2name_tree != NULL)
    splaytree_free(ip2name_tree, (splaytree_free_t)sc_addr2name_free);

  return 0;
}

static int bdrmap_init(void)
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_PING,
		      SCAMPER_FILE_OBJ_TRACE,
		      SCAMPER_FILE_OBJ_DEALIAS,
  };
  int typec = sizeof(types) / sizeof(uint16_t);

  if((ffilter = scamper_file_filter_alloc(types, typec)) == NULL)
    {
      fprintf(stderr, "could not alloc file filter\n");
      return -1;
    }

  if(ip2as_fn != NULL && do_ip2as() != 0)
    return -1;

  if(ixp_fn != NULL && do_ixp() != 0)
    {
      fprintf(stderr, "could not load IXP prefixes\n");
      return -1;
    }

  if(relfile_fn != NULL)
    {
      if((reltree = splaytree_alloc((splaytree_cmp_t)sc_asrel_cmp)) == NULL ||
	 (provtree = splaytree_alloc((splaytree_cmp_t)sc_prov_cmp)) == NULL)
	return -1;
      if(file_lines(relfile_fn, relfile_line, NULL) != 0)
	return -1;
    }

  if((allys = splaytree_alloc((splaytree_cmp_t)sc_ally_cmp)) == NULL)
    return -1;

  return 0;
}

static void cleanup(void)
{
  if(rtrset != NULL)
    {
      sc_routerset_free(rtrset);
      rtrset = NULL;
    }

  if(vpas != NULL)
    {
      free(vpas);
      vpas = NULL;
    }

  if(ip2as_pt != NULL)
    {
      prefixtree_free(ip2as_pt);
      ip2as_pt = NULL;
    }

  if(ixp_pt != NULL)
    {
      if(af == AF_INET)
	prefixtree_free_cb(ixp_pt, (prefix_free_t)prefix4_free);
      else
	prefixtree_free_cb(ixp_pt, (prefix_free_t)prefix6_free);
      ixp_pt = NULL;
    }

  if(prefixes != NULL)
    {
      slist_free_cb(prefixes, (slist_free_t)sc_prefix_free);
      prefixes = NULL;
    }

  if(delegated != NULL)
    {
      slist_free_cb(delegated, (slist_free_t)free);
      delegated = NULL;
    }

  if(held != NULL)
    {
      slist_free_cb(held, (slist_free_t)scamper_trace_free);
      held = NULL;
    }

  if(asmaptree != NULL)
    {
      splaytree_free(asmaptree, (splaytree_free_t)sc_asmap_free);
      asmaptree = NULL;
    }

  if(provtree != NULL)
    {
      splaytree_free(provtree, (splaytree_free_t)sc_prov_free);
      provtree = NULL;
    }

  if(reltree != NULL)
    {
      splaytree_free(reltree, (splaytree_free_t)sc_asrel_free);
      reltree = NULL;
    }

  if(links != NULL)
    {
      splaytree_free(links, (splaytree_free_t)sc_link_free);
      links = NULL;
    }

  if(allys != NULL)
    {
      splaytree_free(allys, (splaytree_free_t)sc_ally_free);
      allys = NULL;
    }

  if(pings != NULL)
    {
      splaytree_free(pings, (splaytree_free_t)sc_ping_free);
      pings = NULL;
    }

  if(ffilter != NULL)
    {
      scamper_file_filter_free(ffilter);
      ffilter = NULL;
    }

  return;
}

int main(int argc, char *argv[])
{
#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

  /* if we were asked to print usage information, stop now */
  if(options & OPT_HELP)
    return 0;

  /* start a daemon if asked to */
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    return -1;

  if(bdrmap_init() != 0)
    return -1;

  if(options & OPT_DUMP)
    return bdrmap_dump();

  return bdrmap_data();
}
