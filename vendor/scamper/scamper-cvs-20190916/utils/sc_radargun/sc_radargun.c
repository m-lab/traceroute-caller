/*
 * sc_radargun : scamper driver to do radargun-style probing.
 *
 * $Id: sc_radargun.c,v 1.9 2019/07/12 21:40:13 mjl Exp $
 *
 * Copyright (C) 2014 The Regents of the University of California
 * Copyright (C) 2016 The University of Waikato
 * Author: Matthew Luckie
 *
 * Radargun technique authored by:
 * A. Bender, R. Sherwood, N. Spring; "Fixing Ally's growing pains with
 * velocity modeling", in Proc. Internet Measurement Conference 2008.
 *
 * MIDAR technique authored by:
 * K. Keys, Y. Hyun, M. Luckie, k claffy; "Internet-scale IPv4 alias
 * resolution with MIDAR", in IEEE/ACM Transaction on Networking, 2013.
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
  "$Id: sc_radargun.c,v 1.9 2019/07/12 21:40:13 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "ping/scamper_ping.h"
#include "dealias/scamper_dealias.h"
#include "scamper_file.h"
#include "mjl_list.h"
#include "mjl_heap.h"
#include "mjl_splaytree.h"
#include "utils.h"

typedef struct sc_ipid
{
  scamper_dealias_probedef_t *def;
  uint32_t                    seq;
  struct timeval              tx;
  struct timeval              rx;
  uint32_t                    ipid;
} sc_ipid_t;

/*
 * sc_addrset
 *
 */
typedef struct sc_addrset
{
  slist_t          *addrs;
  dlist_node_t     *node;
} sc_addrset_t;

/*
 * sc_addr2set_t
 *
 */
typedef struct sc_addr2set
{
  scamper_addr_t   *addr;
  sc_addrset_t     *set;
} sc_addr2set_t;

typedef struct sc_ping
{
  scamper_addr_t   *addr;
  uint8_t           method;
  uint8_t           class;
} sc_ping_t;

typedef struct sc_test
{
  int               type;
  void             *data;
} sc_test_t;

typedef struct sc_target
{
  scamper_addr_t   *addr;
  sc_test_t        *test;
  slist_t          *blocked;
  splaytree_node_t *node;
} sc_target_t;

typedef struct sc_waittest
{
  struct timeval   tv;
  sc_test_t       *test;
} sc_waittest_t;

typedef struct sc_pingtest
{
  sc_test_t        *test;
  sc_ping_t        *ping;
  sc_target_t      *target;
} sc_pingtest_t;

typedef struct sc_radargun
{
  sc_test_t        *test;
  slist_t          *targets;
  dlist_t          *addrs;
  dlist_node_t     *addrs_dn;
  clist_node_t     *rglist_cn;
} sc_radargun_t;

typedef struct sc_dump
{
  char  *descr;
  int  (*init)(void);
  int  (*proc_ping)(scamper_ping_t *ping);
  int  (*proc_dealias)(scamper_dealias_t *dealias);
  void (*finish)(void);
} sc_dump_t;

static int process_dealias_1(scamper_dealias_t *);
static int init_2(void);
static int process_ping_2(scamper_ping_t *);
static void finish_2(void);

static uint32_t               options       = 0;
static uint32_t               flags         = 0;
static int                    scamper_fd    = -1;
static char                  *readbuf       = NULL;
static size_t                 readbuf_len   = 0;
static int                    port          = 31337;
static char                  *unix_name     = NULL;
static char                  *addrfile      = NULL;
static char                  *outfile_name  = NULL;
static int                    outfile_fd    = -1;
static scamper_file_filter_t *ffilter       = NULL;
static scamper_file_t        *decode_in     = NULL;
static int                    decode_in_fd  = -1;
static int                    decode_out_fd = -1;
static int                    data_left     = 0;
static int                    more          = 0;
static int                    probing       = 0;
static int                    attempts      = 5;
static int                    pps           = 20;
static int                    round_count   = 30;
static int                    wait_probe    = 1000;
static int                    fudge         = 0;
static int                    wait_round    = 0;
static splaytree_t           *pingtree      = NULL;
static clist_t               *rglist        = NULL;
static clist_node_t          *rglist_cn     = NULL;
static splaytree_t           *targets       = NULL;
static heap_t                *waiting       = NULL;
static int                    waittime      = 5;
static struct timeval         now;
static FILE                  *logfile       = NULL;
static int                    dump_id       = 0;
static char                  *dump_file     = NULL;
static const sc_dump_t        dump_funcs[]  = {
  {NULL, NULL, NULL},
  {"dump inferred aliases", NULL, NULL, process_dealias_1, NULL},
  {"dump interface classifications", init_2, process_ping_2, NULL, finish_2},
};
static int dump_funcc = sizeof(dump_funcs) / sizeof(sc_dump_t);

#define OPT_HELP        0x000001
#define OPT_ADDRFILE    0x000002
#define OPT_OUTFILE     0x000004
#define OPT_PORT        0x000008
#define OPT_LOGFILE     0x000010
#define OPT_UNIX        0x000020
#define OPT_FUDGE       0x000040
#define OPT_OPTIONS     0x000080
#define OPT_ATTEMPTS    0x000200
#define OPT_ROUNDCOUNT  0x000400
#define OPT_DAEMON      0x000800
#define OPT_PPS         0x001000
#define OPT_WAITROUND   0x002000
#define OPT_DUMP        0x020000

#define FLAG_NOBS        0x0001
#define FLAG_NORESERVED  0x0002
#define FLAG_ROWS        0x0004
#define FLAG_NOBUDGET    0x0008
#define FLAG_TC          0x0010

#define IPID_NONE   0
#define IPID_INCR   1
#define IPID_RAND   2
#define IPID_ECHO   3
#define IPID_CONST  4
#define IPID_UNRESP 5

static const char *ipid_classes[] = {"none", "incr", "rand", "echo",
				     "const", "unresp"};

#define METHOD_ICMP     0
#define METHOD_TCP      1
#define METHOD_UDP      2
#define METHOD_MAX      2
#define METHOD_NONE     3

#define TEST_PING       0
#define TEST_RADARGUN   1

static void usage(uint32_t opt_mask)
{
  int i;

  fprintf(stderr,
	  "usage:\n"
	  "   sc_radargun [-D]\n"
          "     [-a addrfile] [-o outfile] [-p port] [-U unix]\n"
	  "     [-f fudge] [-O options] [-P pps] [-q attempts]\n"
          "     [-r wait-round] [-R round-count] [-t log]\n"
	  "\n"
	  "   sc_radargun [-d dump] file.warts\n"
	  "\n"
	  "   sc_radargun -?\n"
	  "\n");

  if(opt_mask == 0)
    return;

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "     -?: give an overview of the usage of sc_radargun\n");

  if(opt_mask & OPT_ADDRFILE)
    fprintf(stderr, "     -a: input addressfile\n");

  if(opt_mask & OPT_DUMP)
    {
      fprintf(stderr, "     -d: dump id\n");
      for(i=1; i<dump_funcc; i++)
	fprintf(stderr, "         %d: %s\n", i, dump_funcs[i].descr);
    }

  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D: start as daemon\n");

  if(opt_mask & OPT_FUDGE)
    fprintf(stderr, "     -f: fudge\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "     -o: output warts file\n");

  if(opt_mask & OPT_OPTIONS)
    {
      fprintf(stderr, "     -O: options\n");
      fprintf(stderr, "         nobs: do not consider byteswapped ipids\n");
      fprintf(stderr, "         nobudget: skip budget check\n");
      fprintf(stderr, "         noradargun: skip radargun step\n");
      fprintf(stderr, "         noreserved: skip reserved addresses\n");
      fprintf(stderr, "         rows: input file consists of sets to test\n");
      fprintf(stderr, "         tc: dump transitive closure\n");
    }

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -p: port to find scamper on\n");

  if(opt_mask & OPT_PPS)
    fprintf(stderr, "     -P: pps\n");

  if(opt_mask & OPT_ATTEMPTS)
    fprintf(stderr, "     -q: attempts\n");

  if(opt_mask & OPT_WAITROUND)
    fprintf(stderr, "     -r: time between rounds (seconds)\n");

  if(opt_mask & OPT_ROUNDCOUNT)
    fprintf(stderr, "     -R: round count\n");

  if(opt_mask & OPT_LOGFILE)
    fprintf(stderr, "     -t: log file\n");

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U: unix domain to find scamper on\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  int       ch;
  long      lo;
  char     *opts = "a:d:Df:o:O:p:P:q:r:R:t:U:?";
  char     *opt_port = NULL, *opt_roundcount = NULL, *opt_waitround = NULL;
  char     *opt_logfile = NULL, *opt_attempts = NULL, *opt_pps = NULL;
  char     *opt_fudge = NULL, *opt_dump = NULL;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'a':
	  options |= OPT_ADDRFILE;
	  addrfile = optarg;
	  break;

	case 'd':
	  options |= OPT_DUMP;
	  opt_dump = optarg;
	  break;

	case 'D':
	  options |= OPT_DAEMON;
	  break;

	case 'f':
	  options |= OPT_FUDGE;
	  opt_fudge = optarg;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  outfile_name = optarg;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "nobs") == 0)
	    flags |= FLAG_NOBS;
	  else if(strcasecmp(optarg, "noreserved") == 0)
	    flags |= FLAG_NORESERVED;
	  else if(strcasecmp(optarg, "rows") == 0)
	    flags |= FLAG_ROWS;
	  else if(strcasecmp(optarg, "nobudget") == 0)
	    flags |= FLAG_NOBUDGET;
	  else if(strcasecmp(optarg, "tc") == 0)
	    flags |= FLAG_TC;
	  else
	    {
	      usage(OPT_OPTIONS);
	      return -1;
	    }
	  break;

	case 'p':
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case 'P':
	  options |= OPT_PPS;
	  opt_pps = optarg;
	  break;

	case 'q':
	  options |= OPT_ATTEMPTS;
	  opt_attempts = optarg;
	  break;

	case 'r':
	  options |= OPT_WAITROUND;
	  opt_waitround = optarg;
	  break;

	case 'R':
	  options |= OPT_ROUNDCOUNT;
	  opt_roundcount = optarg;
	  break;

	case 't':
	  options |= OPT_LOGFILE;
	  opt_logfile = optarg;
	  break;

	case 'U':
	  options |= OPT_UNIX;
	  unix_name = optarg;
	  break;

	case '?':
	default:
	  usage(0xffffffff);
	  return -1;
	}
    }

  if(options == 0)
    {
      usage(0);
      return -1;
    }

  if(options & OPT_FUDGE)
    {
      if(string_tolong(opt_fudge, &lo) != 0 || lo < 0 || lo > 10000)
	{
	  usage(OPT_FUDGE);
	  return -1;
	}
      fudge = lo;
    }
  else
    {
      if((options & OPT_DUMP) == 0)
	fudge = 5000;
    }

  if((options & OPT_DUMP) != 0)
    {
      /* no other options permitted when -d is used */
      if((options & ~(OPT_DUMP|OPT_FUDGE)) != 0 || argc - optind != 1)
	{
	  usage(0);
	  return -1;
	}
      if(string_tolong(opt_dump, &lo) != 0 || lo < 1 || lo > dump_funcc)
	{
	  usage(OPT_DUMP);
	  return -1;
	}
      dump_id = lo;
      dump_file = argv[optind];
      return 0;
    }

  if((options & (OPT_ADDRFILE|OPT_OUTFILE)) == 0 ||
     (options & (OPT_PORT|OPT_UNIX)) == 0 ||
     (options & (OPT_PORT|OPT_UNIX)) == (OPT_PORT|OPT_UNIX))
    {
      usage(OPT_ADDRFILE|OPT_OUTFILE|OPT_PORT|OPT_UNIX);
      return -1;
    }

  if(options & OPT_PORT)
    {
      if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
	{
	  usage(OPT_PORT);
	  return -1;
	}
      port = lo;
    }

  if(options & OPT_ATTEMPTS)
    {
      if(string_tolong(opt_attempts, &lo) != 0 || lo < 1 || lo > 10)
	{
	  usage(OPT_ATTEMPTS);
	  return -1;
	}
      attempts = lo;
    }

  if(options & OPT_PPS)
    {
      if(string_tolong(opt_pps, &lo) != 0 || lo < 1 || lo > 1000)
	{
	  usage(OPT_PPS);
	  return -1;
	}
      pps = lo;
    }

  if(options & OPT_ROUNDCOUNT)
    {
      if(string_tolong(opt_roundcount, &lo) != 0 || lo < 5 || lo > 60)
	{
	  usage(OPT_ROUNDCOUNT);
	  return -1;
	}
      round_count = lo;
    }

  if(options & OPT_WAITROUND)
    {
      if(string_tolong(opt_waitround, &lo) != 0 || lo < 1 || lo > 60)
	{
	  usage(OPT_WAITROUND);
	  return -1;
	}
      wait_round = (lo * 1000);
    }

  if(opt_logfile != NULL)
    {
      if((logfile = fopen(opt_logfile, "w")) == NULL)
	{
	  usage(OPT_LOGFILE);
	  fprintf(stderr, "could not open %s\n", opt_logfile);
	  return -1;
	}
    }

  return 0;
}

static int tree_to_dlist(void *ptr, void *entry)
{
  if(dlist_tail_push((dlist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

static int tree_to_slist(void *ptr, void *entry)
{
  if(slist_tail_push((slist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

static void print(char *format, ...)
{
  va_list ap;
  char msg[512];

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  if(msg[510] != '\n')
    {
      msg[506] = ' ';
      msg[507] = msg[508] = msg[509] = '.';
      msg[510] = '\n';
      msg[511] = '\0';
    }

  printf("%ld: %s", (long int)now.tv_sec, msg);

  if(logfile != NULL)
    {
      fprintf(logfile, "%ld: %s", (long int)now.tv_sec, msg);
      fflush(logfile);
    }

  return;
}

static void status(char *format, ...)
{
  va_list ap;
  char pref[32];
  char msg[512];

  snprintf(pref, sizeof(pref), "p %d, w %d, r %d", probing,
	   heap_count(waiting), clist_count(rglist));

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  print("%s : %s\n", pref, msg);
  return;
}

static sc_test_t *sc_test_alloc(int type, void *data)
{
  sc_test_t *test;
  if((test = malloc_zero(sizeof(sc_test_t))) == NULL)
    return NULL;
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

static int sc_waittest(sc_test_t *test)
{
  sc_waittest_t *wt;
  if((wt = malloc_zero(sizeof(sc_waittest_t))) == NULL)
    return -1;
  timeval_add_s(&wt->tv, &now, waittime);
  wt->test = test;
  if(heap_insert(waiting, wt) == NULL)
    return -1;
  return 0;
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
	  print("%s: could not remove %s from tree\n", __func__,
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
      print("%s: could not add %s to tree\n", __func__,
	    scamper_addr_tostr(target->addr, buf, sizeof(buf)));
      return -1;
    }
  return 0;
}

static void sc_ping_free(sc_ping_t *ping)
{
  if(ping == NULL) return;
  if(ping->addr != NULL) scamper_addr_free(ping->addr);
  free(ping);
  return;
}

static int sc_ping_human_cmp(const sc_ping_t *a, const sc_ping_t *b)
{
  return scamper_addr_human_cmp(a->addr, b->addr);
}

static int sc_ping_cmp(const sc_ping_t *a, const sc_ping_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static sc_ping_t *sc_ping_find(scamper_addr_t *addr)
{
  sc_ping_t fm; fm.addr = addr;
  return splaytree_find(pingtree, &fm);
}

static void sc_pingtest_free(sc_pingtest_t *pt)
{
  if(pt == NULL) return;
  if(pt->target != NULL) sc_target_free(pt->target);
  if(pt->test != NULL) sc_test_free(pt->test);
  if(pt->ping != NULL) sc_ping_free(pt->ping);
  free(pt);
  return;
}

static sc_test_t *sc_pingtest_alloc(scamper_addr_t *addr)
{
  sc_pingtest_t *pt = NULL;

  if((pt = malloc_zero(sizeof(sc_pingtest_t))) == NULL ||
     (pt->ping = malloc_zero(sizeof(sc_ping_t))) == NULL ||
     (pt->test = sc_test_alloc(TEST_PING, pt)) == NULL ||
     (pt->target = sc_target_alloc(addr)) == NULL)
    goto err;

  pt->target->test = pt->test;
  pt->ping->addr = scamper_addr_use(addr);

  if(sc_target_add(pt->target) != 0)
    goto err;

  return pt->test;

 err:
  if(pt != NULL) sc_pingtest_free(pt);
  return NULL;
}

static void sc_radargun_free(sc_radargun_t *rg)
{
  if(rg == NULL)
    return;
  if(rg->targets != NULL)
    slist_free_cb(rg->targets, (slist_free_t)sc_target_free);
  if(rg->test != NULL)
    sc_test_free(rg->test);
  if(rg->addrs != NULL)
    dlist_free_cb(rg->addrs, (dlist_free_t)scamper_addr_free);
  free(rg);
  return;
}

static sc_radargun_t *sc_radargun_alloc(void)
{
  sc_radargun_t *rg;

  if((rg = malloc_zero(sizeof(sc_radargun_t))) == NULL ||
     (rg->addrs = dlist_alloc()) == NULL ||
     (rg->test = sc_test_alloc(TEST_RADARGUN, rg)) == NULL ||
     (rg->rglist_cn = clist_head_push(rglist, rg->test)) == NULL)
    goto err;
  return rg;

 err:
  if(rg != NULL) sc_radargun_free(rg);
  return NULL;
}

static const char *method_tostr(uint8_t method)
{
  if(method == METHOD_TCP)
    return "tcp-ack-sport";
  else if(method == METHOD_UDP)
    return "udp-dport";
  else if(method == METHOD_ICMP)
    return "icmp-echo";
  return NULL;
}

static int do_method_ping(sc_test_t *test, char **cmd_out, size_t *len_out)
{
  sc_pingtest_t *pt = test->data;
  size_t off = 0;
  char cmd[256];
  char buf[64];

  string_concat(cmd, sizeof(cmd), &off, "ping -P %s -i %d",
		method_tostr(pt->ping->method), wait_probe / 1000);
  if((wait_probe % 1000) != 0)
    string_concat(cmd, sizeof(cmd), &off, ".%d", wait_probe % 1000);
  string_concat(cmd, sizeof(cmd), &off, " -c %d -o %d %s\n",
		attempts+2, attempts,
		scamper_addr_tostr(pt->ping->addr, buf, sizeof(buf)));

  *len_out = off;
  *cmd_out = strdup(cmd);
  return 0;
}

static int do_method_radargun(sc_test_t *test, char **cmd_out, size_t *len_out)
{
  sc_radargun_t *rg = test->data;
  scamper_addr_t *addr;
  sc_target_t *tg;
  sc_test_t *test2;
  sc_ping_t *ping;
  dlist_node_t *dn, *dn2;
  size_t i, incrc;
  char **defs = NULL, *cmd = NULL;
  char tmp[256], buf[64], header[128];
  size_t len = 0;
  size_t off;
  int rg_waitprobe = 0;

  *cmd_out = NULL;
  *len_out = 0;

  /* to start with, we need to figure out how to probe each address */
  while(rg->addrs_dn != NULL)
    {
      addr = dlist_node_item(rg->addrs_dn);
      rg->addrs_dn = dlist_node_next(rg->addrs_dn);
      if(sc_ping_find(addr) == NULL && sc_target_findaddr(addr) == NULL)
	{
	  if((test2 = sc_pingtest_alloc(addr)) == NULL)
	    {
	      print("%s: could not alloc pingtest for %s\n", __func__,
		    scamper_addr_tostr(addr, buf, sizeof(buf)));
	      goto err;
	    }
	  return do_method_ping(test2, cmd_out, len_out);
	}
    }

  if(rg->rglist_cn != NULL)
    {
      if(rglist_cn == rg->rglist_cn)
	{
	  rglist_cn = clist_node_next(rg->rglist_cn);
	  if(rglist_cn == rg->rglist_cn)
	    rglist_cn = NULL;
	}
      clist_node_pop(rglist, rg->rglist_cn);
      rg->rglist_cn = NULL;
    }

  /* wait for all ping tests to complete */
  dn = dlist_head_node(rg->addrs);
  while(dn != NULL)
    {
      dn2 = dlist_node_next(dn);
      addr = dlist_node_item(dn);
      if((ping = sc_ping_find(addr)) == NULL)
	{
	  if((tg = sc_target_findaddr(addr)) == NULL)
	    {
	      print("%s: could not find pingtest for %s\n", __func__,
		    scamper_addr_tostr(addr, buf, sizeof(buf)));
	      goto err;
	    }
	  sc_target_block(tg, test);
	  return 0;
	}
      else if(ping->method == METHOD_NONE)
	{
	  dlist_node_pop(rg->addrs, dn);
	}
      else if((tg = sc_target_findaddr(addr)) != NULL)
	{
	  sc_target_block(tg, test);
	  return 0;
	}
      dn = dn2;
    }

  /* all ping tests have completed, and we have the all clear to probe */
  if((incrc = dlist_count(rg->addrs)) < 2)
    {
      sc_radargun_free(rg);
      return 0;
    }

  if(round_count == 0)
    round_count = 30;

  if(wait_round == 0)
    {
      if(incrc < 30)
	{
	  wait_round = incrc * 1000;
	  rg_waitprobe = 1000;
	}
      else
	{
	  wait_round = 30000;
	}
    }

  if(rg_waitprobe == 0)
    rg_waitprobe = wait_round / incrc;

  if((flags & FLAG_NOBUDGET) == 0 && (1000 / pps) > rg_waitprobe)
    {
      print("%s: unable to use available probing budget: %d > %d, %d\n",
	    __func__, 1000/pps, rg_waitprobe);
      sc_radargun_free(rg);
      return 0;
    }

  if((defs = malloc_zero(sizeof(char *) * incrc)) == NULL)
    {
      print("%s: could not malloc %d defs\n", __func__, incrc);
      goto err;
    }

  string_concat(header, sizeof(header), &len,
		"dealias -m radargun -O shuffle -q %d -W %d -r %d",
		round_count, rg_waitprobe, wait_round);

  if((rg->targets = slist_alloc()) == NULL)
    {
      print("%s: could not alloc list\n", __func__);
      goto err;
    }

  dlist_qsort(rg->addrs, (dlist_cmp_t)scamper_addr_human_cmp);
  i = 0;
  for(dn=dlist_head_node(rg->addrs); dn != NULL; dn=dlist_node_next(dn))
    {
      addr = dlist_node_item(dn);
      scamper_addr_tostr(addr, buf, sizeof(buf));

      if((tg = sc_target_alloc(addr)) == NULL)
	{
	  print("%s: could not alloc target for %s\n", __func__, buf);
	  goto err;
	}
      tg->test = test;
      if(sc_target_add(tg) != 0 || slist_tail_push(rg->targets, tg) == NULL)
	{
	  print("%s: could not add target for %s\n", __func__, buf);
	  goto err;
	}

      ping = sc_ping_find(addr);
      off = 0;
      string_concat(tmp, sizeof(tmp), &off, " -p '-P %s -i %s'",
		    method_tostr(ping->method),
		    scamper_addr_tostr(addr, buf, sizeof(buf)));
      if((defs[i] = strdup(tmp)) == NULL)
	{
	  print("%s: could not dup str %s\n", __func__);
	  goto err;
	}
      len += off; i++;
    }

  len += 2; /* \n\0 */
  if((cmd = malloc(len)) == NULL)
    {
      print("%s: could not malloc cmd string of %d bytes\n", __func__, len);
      goto err;
    }
  off = 0;
  string_concat(cmd, len, &off, "%s", header);
  for(i=0; i<incrc; i++)
    string_concat(cmd, len, &off, "%s", defs[i]);
  string_concat(cmd, len, &off, "\n");

  for(i=0; i<incrc; i++)
    if(defs[i] != NULL)
      free(defs[i]);
  free(defs);

  assert(off+1 == len);
  *cmd_out = cmd;
  *len_out = off;
  return 0;

 err:
  sc_radargun_free(rg);
  if(defs != NULL)
    {
      for(i=0; i<incrc; i++)
	if(defs[i] != NULL)
	  free(defs[i]);
      free(defs);
    }
  if(cmd != NULL) free(cmd);
  return -1;
}

static int do_method(void)
{
  static int (*const func[])(sc_test_t *, char **, size_t *) = {
    do_method_ping,     /* TEST_PING */
    do_method_radargun, /* TEST_RADARGUN */
  };
  sc_waittest_t *wt;
  sc_test_t *test;
  char *cmd;
  size_t off;

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
      else if(rglist_cn != NULL &&
	      (rglist_cn = clist_node_next(rglist_cn)) != NULL)
	{
	  test = clist_node_item(rglist_cn);
	}
      else
	{
	  return 0;
	}

      /* something went wrong */
      if(func[test->type](test, &cmd, &off) != 0)
	{
	  fprintf(stderr, "something went wrong\n");
	  return -1;
	}

      if(off > 0)
	break;
    }

  /* got a command, send it */
  write_wrap(scamper_fd, cmd, NULL, off);
  probing++;
  more--;

  print("p %d, w %d, r %d : %s", probing, heap_count(waiting),
	clist_count(rglist), cmd);
  free(cmd);

  return 0;
}

static int ping_classify(scamper_ping_t *ping)
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
	 SCAMPER_PING_REPLY_FROM_TARGET(ping, rx))
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
      if(u32 > f)
	nobs++;

      if((flags & FLAG_NOBS) == 0)
	{
	  n0 = byteswap16(n0);
	  n1 = byteswap16(n1);
	  if(n0 < n1)
	    u32 = n1 - n0;
	  else
	    u32 = (n1 + 0x10000) - n0;
	  if(u32 > f)
	    bs++;
	}

      ln0 = ln1;
      ln1 = slist_node_next(ln0);
    }

  if(nobs != 0 && ((flags & FLAG_NOBS) != 0 || bs != 0))
    rc = IPID_RAND;
  else
    rc = IPID_INCR;

 done:
  if(list != NULL) slist_free(list);
  return rc;
}

static int process_ping(scamper_ping_t *ping)
{
  sc_pingtest_t *pt;
  sc_target_t *tg;
  sc_test_t *tt;
  char buf[64];
  int c;

  if((tg = sc_target_findaddr(ping->dst)) == NULL ||
     (c = ping_classify(ping)) < 0)
    goto err;
  scamper_ping_free(ping); ping = NULL;

  tt = tg->test;
  pt = tt->data;

  if(c != IPID_INCR)
    {
      if(pt->ping->method == METHOD_MAX)
	{
	  status("%s not-incr",
		 scamper_addr_tostr(pt->ping->addr, buf, sizeof(buf)));
	  pt->ping->method = METHOD_NONE;
	  goto done;
	}
      pt->ping->method++;
      if(sc_waittest(tg->test) != 0)
	goto err;
      return 0;
    }

  status("%s %s incr",
	 scamper_addr_tostr(pt->ping->addr, buf, sizeof(buf)),
	 method_tostr(pt->ping->method));

 done:
  if(splaytree_insert(pingtree, pt->ping) == NULL)
    goto err;
  pt->ping = NULL;
  sc_pingtest_free(pt);
  return 0;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return -1;
}

static int process_dealias(scamper_dealias_t *dealias)
{
  scamper_dealias_radargun_t *srg = dealias->data;
  sc_radargun_t *rg;
  sc_target_t *tg;

  if((tg = sc_target_findaddr(srg->probedefs[0].dst)) == NULL)
    goto err;
  rg = tg->test->data;
  sc_radargun_free(rg);
  scamper_dealias_free(dealias);
  return 0;

 err:
  scamper_dealias_free(dealias);
  return -1;
}

static int do_decoderead(void)
{
  void     *data;
  uint16_t  type;

  /* try and read a traceroute from the warts decoder */
  if(scamper_file_read(decode_in, ffilter, &type, &data) != 0)
    {
      fprintf(stderr, "do_decoderead: scamper_file_read errno %d\n", errno);
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

  if(type == SCAMPER_FILE_OBJ_PING)
    return process_ping(data);
  else if(type == SCAMPER_FILE_OBJ_DEALIAS)
    return process_dealias(data);

  return -1;
}

/*
 * do_scamperread
 *
 * the fd for the scamper process is marked as readable, so do a read
 * on it.
 */
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
	  else return -1;
	}
    }
  else if(rc == 0)
    {
      close(scamper_fd);
      scamper_fd = -1;
    }
  else if(errno == EINTR || errno == EAGAIN)
    {
      return 0;
    }
  else
    {
      fprintf(stderr, "could not read: errno %d\n", errno);
      return -1;
    }

  /* process whatever is in the readbuf */
  if(readbuf_len == 0)
    {
      goto done;
    }

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
		  fprintf(stderr, "could not uudecode_line\n");
		  goto err;
		}

	      if(uus != 0)
		{
		  write_wrap(decode_out_fd, uu, NULL, uus);
		  write_wrap(outfile_fd, uu, NULL, uus);
		}

	      data_left -= (linelen + 1);
	    }
	  /* if the scamper process is asking for more tasks, give it more */
	  else if(linelen == 4 && strncasecmp(head, "MORE", linelen) == 0)
	    {
	      more++;
	      if(do_method() != 0)
		goto err;
	    }
	  /* new piece of data */
	  else if(linelen > 5 && strncasecmp(head, "DATA ", 5) == 0)
	    {
	      l = strtol(head+5, &ptr, 10);
	      if(*ptr != '\n' || l < 1)
		{
		  head[linelen] = '\0';
		  fprintf(stderr, "could not parse %s\n", head);
		  goto err;
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
	      goto err;
	    }
	  else
	    {
	      head[linelen] = '\0';
	      fprintf(stderr, "unknown response '%s'\n", head);
	      goto err;
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

 done:
  return 0;

 err:
  return -1;
}

/*
 * addrfile_resolve:
 *
 *
 */
static int addrfile_resolve(const char *str, splaytree_t *tree)
{
  scamper_addr_t *addr = NULL;

  if((addr = scamper_addr_resolve(AF_INET, str)) == NULL)
    goto err;

  if((flags & FLAG_NORESERVED) != 0 && scamper_addr_isreserved(addr) != 0)
    {
      scamper_addr_free(addr);
      return 0;
    }

  if(splaytree_find(tree,addr) == NULL)
    {
      if(splaytree_insert(tree,addr) == NULL)
	goto err;
    }
  else
    {
      scamper_addr_free(addr);
    }

  return 0;

 err:
  if(addr != NULL) scamper_addr_free(addr);
  return -1;
}

/*
 * addrfile_line:
 *
 *
 */
static int addrfile_line(char *line, void *param)
{
  splaytree_t *tree = param;
  sc_radargun_t *rg = NULL;
  char *start, *ptr;
  int last = 0;

  if(line[0] == '#' || line[0] == '\0')
    return 0;

  if(flags & FLAG_ROWS)
    {
      start = ptr = line;
      while(last == 0)
	{
	  if(*ptr == '\0' || isspace(*ptr) != 0)
	    {
	      if(*ptr == '\0')
		last = 1;
	      *ptr = '\0';

	      if(addrfile_resolve(start, tree) != 0)
		goto err;

	      if(last == 0)
		{
		  ptr++;
		  while(*ptr != '\0' && isspace(*ptr) != 0)
		    ptr++;
		  if(*ptr == '\0')
		    last = 1;
		  else
		    start = ptr;
		}
	    }
	  else ptr++;
	}

      if((rg = sc_radargun_alloc()) == NULL)
	goto err;
      splaytree_inorder(tree, tree_to_dlist, rg->addrs);
      splaytree_empty(tree, NULL);
      dlist_shuffle(rg->addrs);
      rg->addrs_dn = dlist_head_node(rg->addrs);
    }
  else
    {
      if(addrfile_resolve(line, tree) != 0)
	goto err;
    }
  return 0;

 err:
  return -1;
}

static int do_addrfile(void)
{
  splaytree_t *tree;
  sc_radargun_t *rg;

  if((tree = splaytree_alloc((splaytree_cmp_t)scamper_addr_cmp)) == NULL ||
     file_lines(addrfile, addrfile_line, tree) != 0)
    goto err;

  if((flags & FLAG_ROWS) == 0)
    {
      if((rg = sc_radargun_alloc()) == NULL)
	goto err;
      splaytree_inorder(tree, tree_to_dlist, rg->addrs);
      splaytree_empty(tree, NULL);
      dlist_shuffle(rg->addrs);
      rg->addrs_dn = dlist_head_node(rg->addrs);
    }

  rglist_cn = clist_head_node(rglist);
  splaytree_free(tree, (splaytree_free_t)scamper_addr_free);
  return 0;

 err:
  if(tree != NULL) splaytree_free(tree, (splaytree_free_t)scamper_addr_free);
  return -1;
}

/*
 * do_files
 *
 * open a socketpair that can be used to feed warts data into one end and
 * have the scamper_file routines decode it via the other end.
 *
 * also open a file to send the binary warts data file to.
 */
static int do_files(void)
{
  mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  int flags = O_WRONLY | O_CREAT | O_TRUNC;
  int pair[2];

  if((outfile_fd = open(outfile_name, flags, mode)) == -1)
    return -1;

  /*
   * setup a socketpair that is used to decode warts from a binary input.
   * pair[0] is used to write to the file, while pair[1] is used by
   * the scamper_file_t routines to parse the warts data.
   */
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
    return -1;

  decode_in_fd  = pair[0];
  decode_out_fd = pair[1];
  decode_in = scamper_file_openfd(decode_in_fd, NULL, 'r', "warts");
  if(decode_in == NULL)
    return -1;

  if(fcntl_set(decode_in_fd, O_NONBLOCK) == -1)
    return -1;

  return 0;
}

/*
 * do_scamperconnect
 *
 * allocate socket and connect to scamper process listening on the port
 * specified.
 */
static int do_scamperconnect(void)
{
#ifdef HAVE_SOCKADDR_UN
  struct sockaddr_un sn;
#endif

  struct sockaddr_in sin;
  struct in_addr in;

  if(options & OPT_PORT)
    {
      inet_aton("127.0.0.1", &in);
      sockaddr_compose((struct sockaddr *)&sin, AF_INET, &in, port);
      if((scamper_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
	  fprintf(stderr, "could not allocate new socket\n");
	  return -1;
	}
      if(connect(scamper_fd, (const struct sockaddr *)&sin, sizeof(sin)) != 0)
	{
	  fprintf(stderr, "could not connect to scamper process\n");
	  return -1;
	}
      return 0;
    }
#ifdef HAVE_SOCKADDR_UN
  else if(options & OPT_UNIX)
    {
      if(sockaddr_compose_un((struct sockaddr *)&sn, unix_name) != 0)
	{
	  fprintf(stderr, "could not build sockaddr_un\n");
	  return -1;
	}
      if((scamper_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
	  fprintf(stderr, "could not allocate unix domain socket\n");
	  return -1;
	}
      if(connect(scamper_fd, (const struct sockaddr *)&sn, sizeof(sn)) != 0)
	{
	  fprintf(stderr, "could not connect to scamper process\n");
	  return -1;
	}
      return 0;
    }
#endif

  return -1;
}

static int sc_ipid_tx_cmp(const void *va, const void *vb)
{
  const sc_ipid_t *a = va;
  const sc_ipid_t *b = vb;
  return timeval_cmp(&a->tx, &b->tx);
}

static int inseq(scamper_dealias_radargun_t *rg,
		 sc_ipid_t *pts, int ptc, int limit)
{
  int i;

  for(i=0; i<ptc-1; i++)
    {
      if(pts[i+1].seq > limit)
	break;

      /* adjacent samples are for the same probedef. */
      if(pts[i].def == pts[i+1].def)
	continue;

      /* in sequence */
      if(pts[i].ipid < pts[i+1].ipid)
	continue;

      /* not in sequence, but within a fudge factor and overlapping in time */
      if((fudge == 0 || pts[i].ipid < pts[i+1].ipid + fudge) &&
	 timeval_cmp(&pts[i+1].tx, &pts[i].rx) <= 0)
	continue;

      return 0;
    }

  return 1;
}

static int points_add(scamper_dealias_t *dealias, sc_ipid_t *points,
		      uint32_t *p, scamper_dealias_probedef_t *def)
{
  scamper_dealias_radargun_t *rg = dealias->data;
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply;
  uint32_t k, f=0, i=0;

  for(k=0; k<rg->attempts; k++)
    {
      probe = dealias->probes[(def->id*rg->attempts)+k];
      if(probe->replyc != 1)
	continue;
      reply = probe->replies[0];
      if(SCAMPER_DEALIAS_REPLY_FROM_TARGET(probe, reply) == 0)
	continue;

      points[*p+i].def  = def;
      points[*p+i].seq  = probe->seq;
      points[*p+i].ipid = f + reply->ipid;
      timeval_cpy(&points[*p+i].tx, &probe->tx);
      timeval_cpy(&points[*p+i].rx, &reply->rx);

      if(i > 0 && points[*p+i].ipid < points[*p+i-1].ipid)
	{
	  points[*p+i].ipid += 0x10000;
	  f += 0x10000;
	}

      i++;
    }

  /* need at least 25% of replies to make a reasonable comparison */
  if(i * 4 < rg->attempts)
    return 0;

  *p += i;
  return i;
}

static void initialwrap(sc_ipid_t *pts, int ptc)
{
  scamper_dealias_probedef_t *def;
  int i;

  for(i=0; i<ptc-1; i++)
    if(pts[i].def != pts[i+1].def)
      break;

  if(i == ptc-1 || pts[i].ipid <= pts[i+1].ipid)
    return;

  i++;
  def = pts[i].def;

  while(i < ptc)
    {
      if(pts[i].def == def)
	pts[i].ipid += 0x10000;
      i++;
    }

  return;
}

static int sc_addr2set_cmp(const sc_addr2set_t *a, const sc_addr2set_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static void sc_addr2set_free(sc_addr2set_t *a2s)
{
  if(a2s == NULL)
    return;
  if(a2s->addr != NULL) scamper_addr_free(a2s->addr);
  free(a2s);
  return;
}

static sc_addr2set_t *sc_addr2set_find(splaytree_t *tree, scamper_addr_t *addr)
{
  sc_addr2set_t fm; fm.addr = addr;
  return splaytree_find(tree, &fm);
}

static sc_addr2set_t *sc_addr2set_get(splaytree_t *tree, scamper_addr_t *addr)
{
  sc_addr2set_t *a2s;
  if((a2s = sc_addr2set_find(tree, addr)) != NULL)
    return a2s;
  if((a2s = malloc_zero(sizeof(sc_addr2set_t))) == NULL)
    goto err;
  a2s->addr = scamper_addr_use(addr);
  if(splaytree_insert(tree, a2s) == NULL)
    goto err;
  return a2s;

 err:
  if(a2s != NULL) sc_addr2set_free(a2s);
  return NULL;
}

static void sc_addrset_free(sc_addrset_t *set)
{
  if(set == NULL)
    return;
  if(set->addrs != NULL)
    slist_free_cb(set->addrs, (slist_free_t)sc_addrset_free);
  free(set);
  return;
}

static sc_addrset_t *sc_addrset_alloc(dlist_t *list)
{
  sc_addrset_t *set;
  if((set = malloc_zero(sizeof(sc_addrset_t))) == NULL ||
     (set->addrs = slist_alloc()) == NULL ||
     (set->node = dlist_tail_push(list, set)) == NULL)
    {
      sc_addrset_free(set);
      return NULL;
    }
  return set;
}

static int sc_addrset_cmp(const sc_addrset_t *a, const sc_addrset_t *b)
{
  int ac = slist_count(a->addrs);
  int bc = slist_count(b->addrs);
  sc_addr2set_t *a2s_a = slist_head_item(a->addrs);
  sc_addr2set_t *a2s_b = slist_head_item(b->addrs);
  if(ac > bc) return -1;
  if(ac < bc) return  1;
  return scamper_addr_human_cmp(a2s_a->addr, a2s_b->addr);
}

static int process_dealias_1(scamper_dealias_t *dealias)
{
  scamper_dealias_radargun_t *rg;
  sc_ipid_t *points = NULL;
  splaytree_t *tree = NULL;
  dlist_t *list = NULL;
  dlist_node_t *dn;
  slist_node_t *sn;
  sc_addrset_t *addrset;
  sc_addr2set_t *a2s_a, *a2s_b, *a2s;
  uint32_t i, j, p;
  char a[32], b[32];

  if(!SCAMPER_DEALIAS_METHOD_IS_RADARGUN(dealias))
    return 0;
  rg = dealias->data;

  if((points = malloc(sizeof(sc_ipid_t) * rg->attempts * 2)) == NULL)
    goto err;

  if((flags & FLAG_TC) != 0 &&
     ((list = dlist_alloc()) == NULL ||
      (tree = splaytree_alloc((splaytree_cmp_t)sc_addr2set_cmp)) == NULL))
    goto err;

  scamper_dealias_probes_sort_def(dealias);
  for(i=0; i<rg->probedefc; i++)
    {
      for(j=i+1; j<rg->probedefc; j++)
	{
	  p = 0;
	  if(points_add(dealias, points, &p, &rg->probedefs[i]) == 0)
	    break;
	  if(points_add(dealias, points, &p, &rg->probedefs[j]) == 0)
	    continue;
	  qsort(points, p, sizeof(sc_ipid_t), sc_ipid_tx_cmp);

	  initialwrap(points, p);

	  if(inseq(rg, points, p, rg->attempts) != 0)
	    {
	      if((flags & FLAG_TC) == 0)
		{
		  scamper_addr_tostr(rg->probedefs[i].dst, a, sizeof(a));
		  scamper_addr_tostr(rg->probedefs[j].dst, b, sizeof(b));
		  printf("%s %s\n", a, b);
		}
	      else
		{
		  a2s_a = sc_addr2set_get(tree, rg->probedefs[i].dst);
		  a2s_b = sc_addr2set_get(tree, rg->probedefs[j].dst);
		  if(a2s_a->set == NULL && a2s_b->set == NULL)
		    {
		      if((addrset = sc_addrset_alloc(list)) == NULL)
			goto err;
		      a2s_a->set = addrset;
		      a2s_b->set = addrset;
		      if(slist_tail_push(addrset->addrs, a2s_a) == NULL ||
			 slist_tail_push(addrset->addrs, a2s_b) == NULL)
			goto err;
		    }
		  else if(a2s_a->set == NULL)
		    {
		      a2s_a->set = a2s_b->set;
		      if(slist_tail_push(a2s_b->set->addrs, a2s_a) == NULL)
			goto err;
		    }
		  else if(a2s_b->set == NULL)
		    {
		      a2s_b->set = a2s_a->set;
		      if(slist_tail_push(a2s_a->set->addrs, a2s_b) == NULL)
			goto err;
		    }
		  else if(a2s_a->set != a2s_b->set)
		    {
		      addrset = a2s_b->set;
		      while((a2s = slist_head_pop(addrset->addrs)) != NULL)
			{
			  slist_tail_push(a2s_a->set->addrs, a2s);
			  a2s->set = a2s_a->set;
			}
		      dlist_node_pop(list, addrset->node);
		      sc_addrset_free(addrset);
		    }
		}
	    }
	}
    }

  if(list != NULL)
    {
      for(dn=dlist_head_node(list); dn != NULL; dn = dlist_node_next(dn))
	{
	  addrset = dlist_node_item(dn);
	  slist_qsort(addrset->addrs, (slist_cmp_t)sc_addr2set_cmp);
	}
      dlist_qsort(list, (dlist_cmp_t)sc_addrset_cmp);
      
      while((addrset = dlist_head_pop(list)) != NULL)
	{
	  i = 0;
	  for(sn = slist_head_node(addrset->addrs); sn != NULL;
	      sn = slist_node_next(sn))
	    {
	      a2s = slist_node_item(sn);
	      if(i > 0) printf(" ");
	      printf("%s", scamper_addr_tostr(a2s->addr, a, sizeof(a)));
	      i++;
	    }
	  printf("\n");
	}
      dlist_free_cb(list, (dlist_free_t)sc_addrset_free);
    }

  if(tree != NULL)
    splaytree_free(tree, NULL);
  free(points);

  return 0;

 err:
  if(tree != NULL) splaytree_free(tree, NULL);
  if(list != NULL) dlist_free_cb(list, (dlist_free_t)sc_addrset_free);
  if(points != NULL) free(points);
  return -1;
}

static int init_2(void)
{
  if((pingtree = splaytree_alloc((splaytree_cmp_t)sc_ping_cmp)) == NULL)
    return -1;
  return 0;
}

static int process_ping_2(scamper_ping_t *ping)
{
  sc_ping_t *scp = NULL;
  int class;

  if((scp = sc_ping_find(ping->dst)) == NULL)
    {
      if((scp = malloc_zero(sizeof(sc_ping_t))) == NULL)
	goto err;
      scp->addr = scamper_addr_use(ping->dst);
      scp->class = ping_classify(ping);
      if(splaytree_insert(pingtree, scp) == NULL)
	goto err;
    }
  else
    {
      if((class = ping_classify(ping)) < 0)
	return -1;
      if(class < scp->class)
	scp->class = class;
    }

  return 0;

 err:
  if(scp != NULL) sc_ping_free(scp);
  return -1;
}

static void finish_2(void)
{
  slist_t *list = NULL;
  slist_node_t *sn;
  sc_ping_t *scp;
  char buf[64];

  if((list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(pingtree, (splaytree_inorder_t)tree_to_slist, list);
  slist_qsort(list, (slist_cmp_t)sc_ping_human_cmp);
  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
    {
      scp = slist_node_item(sn);
      printf("%s %s\n", scamper_addr_tostr(scp->addr, buf, sizeof(buf)),
	     ipid_classes[scp->class]);
    }

 done:
  if(list != NULL) slist_free(list);
  return;
}

static int do_dump(void)
{
  scamper_file_t *in = NULL;
  uint16_t type;
  void *data;

  if(dump_id == 1)
    type = SCAMPER_FILE_OBJ_DEALIAS;
  else
    type = SCAMPER_FILE_OBJ_PING;
  if((ffilter = scamper_file_filter_alloc(&type, 1)) == NULL)
    return -1;

  if((in = scamper_file_open(dump_file, 'r', NULL)) == NULL)
    {
      fprintf(stderr, "could not open %s: %s\n", dump_file, strerror(errno));
      return -1;
    }
  if(dump_funcs[dump_id].init != NULL && dump_funcs[dump_id].init() != 0)
    {
      fprintf(stderr,"could not init dump %d: %s\n", dump_id, strerror(errno));
      return -1;
    }

  while(scamper_file_read(in, ffilter, &type, &data) == 0)
    {
      if(data == NULL)
	break;
      if(type == SCAMPER_FILE_OBJ_DEALIAS)
	{
	  if(dump_funcs[dump_id].proc_dealias != NULL)
	    dump_funcs[dump_id].proc_dealias(data);
	  scamper_dealias_free(data);
	}
      else
	{
	  if(dump_funcs[dump_id].proc_ping != NULL)
	    dump_funcs[dump_id].proc_ping(data);
	  scamper_ping_free(data);
	}
    }

  scamper_file_close(in); in = NULL;

  if(dump_funcs[dump_id].finish != NULL)
    dump_funcs[dump_id].finish();

  return 0;
}

static int do_probing(void)
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_PING,
		      SCAMPER_FILE_OBJ_DEALIAS,
  };
  int typec = sizeof(types) / sizeof(uint16_t);
  struct timeval tv, *tv_ptr;
  sc_waittest_t *wait;
  fd_set rfds;
  char cmd[10];
  int nfds;

  /* start a daemon if asked to */
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    return -1;

  gettimeofday_wrap(&now);
  srandom(now.tv_usec);

  if((ffilter = scamper_file_filter_alloc(types, typec)) == NULL ||
     (pingtree = splaytree_alloc((splaytree_cmp_t)sc_ping_cmp)) == NULL ||
     (rglist = clist_alloc()) == NULL ||
     (targets = splaytree_alloc((splaytree_cmp_t)sc_target_cmp)) == NULL ||
     (waiting = heap_alloc(sc_waittest_cmp)) == NULL ||
     do_scamperconnect() != 0)
    return -1;
  if((options & OPT_ADDRFILE) && do_addrfile() != 0)
    return -1;
  if(do_files() != 0)
    return -1;

  snprintf(cmd, sizeof(cmd), "attach\n");
  if(write_wrap(scamper_fd, cmd, NULL, 7) != 0)
    {
      fprintf(stderr, "could not attach to scamper process\n");
      return -1;
    }

  for(;;)
    {
      nfds = 0;
      FD_ZERO(&rfds);

      if(scamper_fd < 0 && decode_in_fd < 0)
	break;

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
	  if(clist_count(rglist) > 0 ||
	     (wait != NULL && timeval_cmp(&wait->tv, &now) <= 0))
	    {
	      if(do_method() != 0)
		return -1;
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

      if(splaytree_count(targets) == 0 && clist_count(rglist) == 0 &&
	 heap_count(waiting) == 0 && probing == 0)
	{
	  print("done\n");
	  break;
	}

      if(select(nfds+1, &rfds, NULL, NULL, tv_ptr) < 0)
	{
	  if(errno == EINTR) continue;
	  fprintf(stderr, "select error\n");
	  break;
	}

      gettimeofday_wrap(&now);

      if(more > 0 && do_method() != 0)
	return -1;

      if(scamper_fd >= 0 && FD_ISSET(scamper_fd, &rfds) &&
	 do_scamperread() != 0)
	return -1;

      if(decode_in_fd >= 0 && FD_ISSET(decode_in_fd, &rfds) &&
	 do_decoderead() != 0)
	return -1;
    }

  return 0;
}

static void cleanup(void)
{
  if(rglist != NULL)
    {
      clist_free(rglist);
      rglist = NULL;
    }

  if(pingtree != NULL)
    {
      splaytree_free(pingtree, (splaytree_free_t)sc_ping_free);
      pingtree = NULL;
    }

  if(waiting != NULL)
    {
      heap_free(waiting, NULL);
      waiting = NULL;
    }

  if(targets != NULL)
    {
      splaytree_free(targets, NULL);
      targets = NULL;
    }

  if(decode_in != NULL)
    {
      scamper_file_close(decode_in);
      decode_in = NULL;
    }

  if(ffilter != NULL)
    {
      scamper_file_filter_free(ffilter);
      ffilter = NULL;
    }

  if(logfile != NULL)
    {
      fclose(logfile);
      logfile = NULL;
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

  if(options & OPT_DUMP)
    return do_dump();

  return do_probing();
}
