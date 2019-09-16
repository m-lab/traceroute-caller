/*
 * sc_prefixscan : scamper driver to collect evidence of pt2pt links
 *                 using the prefixscan method
 *
 * $Id: sc_prefixscan.c,v 1.8 2019/07/12 21:40:13 mjl Exp $
 *
 * Copyright (C) 2011, 2016 The University of Waikato
 * Copyright (C) 2019       Matthew Luckie
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
  "$Id: sc_prefixscan.c,v 1.8 2019/07/12 21:40:13 mjl Exp $";
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
#include "scamper_writebuf.h"
#include "scamper_linepoll.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "mjl_heap.h"
#include "utils.h"

#define TEST_PING     1
#define TEST_SCAN     2

#define IPID_NONE   0
#define IPID_INCR   1
#define IPID_RAND   2
#define IPID_ECHO   3
#define IPID_CONST  4
#define IPID_UNRESP 5

#define OPT_HELP        0x0001
#define OPT_INFILE      0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008
#define OPT_WAIT        0x0010
#define OPT_LOG         0x0020
#define OPT_DAEMON      0x0040
#define OPT_UNIX        0x0080
#define OPT_READ        0x0100
#define OPT_PREFIXLEN   0x0200

static uint32_t               options       = 0;
static int                    scamper_fd    = -1;
static scamper_linepoll_t    *scamper_lp    = NULL;
static scamper_writebuf_t    *scamper_wb    = NULL;
static char                  *infile        = NULL;
static unsigned int           port          = 0;
static char                  *unix_name     = NULL;
static char                  *outfile_name  = NULL;
static char                  *datafile      = NULL;
static FILE                  *text          = NULL;
static splaytree_t           *targets       = NULL;
static splaytree_t           *ipidseqs      = NULL;
static slist_t               *virgin        = NULL;
static heap_t                *waiting       = NULL;
static int                    data_left     = 0;
static int                    error         = 0;
static int                    more          = 0;
static int                    probing       = 0;
static unsigned int           waittime      = 5;
static uint8_t                prefix_len    = 0;
static int                    outfile_fd    = -1;
static scamper_file_filter_t *ffilter       = NULL;
static scamper_file_t        *decode_in     = NULL;
static int                    decode_in_fd  = -1;
static int                    decode_out_fd = -1;
static scamper_writebuf_t    *decode_wb     = NULL;
static struct timeval         now;

/*
 * sc_ipidseq
 *
 * given a particular address, list the methods that allow aliases to be
 * tested by way of IPID.
 */
typedef struct sc_ipidseq
{
  scamper_addr_t   *addr;
  uint8_t           udp;
  uint8_t           tcp;
  uint8_t           icmp;
} sc_ipidseq_t;

typedef struct sc_test
{
  int               type;
  void             *data;
} sc_test_t;

typedef struct sc_waittest
{
  struct timeval    tv;
  sc_test_t        *test;
} sc_waittest_t;

typedef struct sc_target
{
  scamper_addr_t   *addr;
  sc_test_t        *test;
  splaytree_node_t *node;
  slist_t          *blocked;
} sc_target_t;

typedef struct sc_scantest
{
  scamper_addr_t   *a;
  scamper_addr_t   *b;
  int               pfx;
  int               step;
  sc_target_t      *tg;
} sc_scantest_t;

typedef struct sc_pingtest
{
  scamper_addr_t   *addr;
  int               step;
  sc_target_t      *tg;
} sc_pingtest_t;

typedef struct sc_prefixscan
{
  scamper_addr_t *a;
  scamper_addr_t *b;
  scamper_addr_t *ab;
} sc_prefixscan_t;

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
	  "usage: sc_prefixscan [-D] [-i infile] [-o outfile] [-p port]\n"
	  "                     [-l log] [-U unix] [-w wait] [-x prefixlen]\n"
	  "\n"
	  "       sc_prefixscan [-r data-file] [-x prefixlen]\n"
	  "\n");

  if(opt_mask == 0)
    {
      fprintf(stderr, "       sc_prefixscan -?\n\n");
      return;
    }

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "     -? give an overview of the usage of sc_prefixscan\n");

  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D start as daemon\n");

  if(opt_mask & OPT_INFILE)
    fprintf(stderr, "     -i input links file\n");

  if(opt_mask & OPT_LOG)
    fprintf(stderr, "     -l log\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "     -o output warts file\n");

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -p port to find scamper on\n");

  if(opt_mask & OPT_READ)
    fprintf(stderr, "     -r input warts data file\n");

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U unix domain to find scamper on\n");

  if(opt_mask & OPT_WAIT)
    fprintf(stderr, "     -w number of seconds to wait between methods\n");

  if(opt_mask & OPT_PREFIXLEN)
    fprintf(stderr, "     -x maximum size of prefix to consider\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  int       ch;
  long      lo;
  char     *opts = "Di:l:o:p:r:U:w:x:?";
  char     *opt_port = NULL, *opt_wait = NULL, *opt_log = NULL;
  char     *opt_unix = NULL, *opt_prefixlen = NULL;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'D':
	  options |= OPT_DAEMON;
	  break;

	case 'i':
	  options |= OPT_INFILE;
	  infile = optarg;
	  break;

	case 'l':
	  options |= OPT_LOG;
	  opt_log = optarg;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  outfile_name = optarg;
	  break;

	case 'p':
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case 'r':
	  options |= OPT_READ;
	  datafile = optarg;
	  break;

	case 'U':
	  options |= OPT_UNIX;
	  opt_unix = optarg;
	  break;

	case 'w':
	  options |= OPT_WAIT;
	  opt_wait = optarg;
	  break;

	case 'x':
	  options |= OPT_PREFIXLEN;
	  opt_prefixlen = optarg;
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

  /* check if the prefix length was specified on the command line */
  if(options & OPT_PREFIXLEN)
    {
      if(string_tolong(opt_prefixlen, &lo) != 0 || lo < 24 || lo > 31)
	{
	  usage(OPT_PREFIXLEN);
	  return -1;
	}
      prefix_len = lo;
    }

  /* if there were no options specified, then list the most important ones */
  if((options & (OPT_INFILE|OPT_OUTFILE|OPT_PORT|OPT_UNIX|OPT_READ)) == 0)
    {
      usage(OPT_INFILE|OPT_OUTFILE|OPT_PORT|OPT_UNIX|OPT_READ);
      return -1;
    }

  /* if we are reading a previously collected datafile, then we're done */
  if(options & OPT_READ)
    {
      if(options & ~(OPT_READ|OPT_PREFIXLEN))
	{
	  usage(OPT_READ|OPT_PREFIXLEN);
	  return -1;
	}
      return 0;
    }

  if((options & (OPT_INFILE|OPT_OUTFILE)) != (OPT_INFILE|OPT_OUTFILE) ||
     (options & (OPT_PORT|OPT_UNIX)) == 0 ||
     (options & (OPT_PORT|OPT_UNIX)) == (OPT_PORT|OPT_UNIX))
    {
      usage(OPT_INFILE|OPT_OUTFILE|OPT_PORT|OPT_UNIX);
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
  else if(options & OPT_UNIX)
    {
      unix_name = opt_unix;
    }

  /* find out how long to wait in between traceroute methods */
  if(opt_wait != NULL)
    {
      if(string_tolong(opt_wait, &lo) != 0 || lo < 0)
	{
	  usage(OPT_WAIT);
	  return -1;
	}
      waittime = lo;
    }

  if(opt_log != NULL)
    {
      if((text = fopen(opt_log, "w")) == NULL)
	{
	  usage(OPT_LOG);
	  fprintf(stderr, "could not open %s\n", opt_log);
	  return -1;
	}
    }

  if(prefix_len == 0)
    prefix_len = 30;

  return 0;
}

static int tree_to_slist(void *ptr, void *entry)
{
  slist_tail_push((slist_t *)ptr, entry);
  return 0;
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

static void print(char *format, ...)
{
  va_list ap;
  char msg[512];

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  printf("%ld: %s", (long int)now.tv_sec, msg);

  if(text != NULL)
    {
      fprintf(text, "%ld: %s", (long int)now.tv_sec, msg);
      fflush(text);
    }

  return;
}

static void status(char *format, ...)
{
  va_list ap;
  char pref[32];
  char msg[512];

  snprintf(pref, sizeof(pref), "p %d, w %d, v %d",
	   probing, heap_count(waiting), slist_count(virgin));

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  print("%s : %s\n", pref, msg);
  return;
}

static void sc_ipidseq_free(sc_ipidseq_t *seq)
{
  if(seq == NULL)
    return;

  if(seq->addr != NULL)
    scamper_addr_free(seq->addr);
  free(seq);
  return;
}

static int sc_ipidseq_cmp(const void *a, const void *b)
{
  return scamper_addr_cmp(((sc_ipidseq_t *)a)->addr,((sc_ipidseq_t *)b)->addr);
}

static sc_ipidseq_t *sc_ipidseq_alloc(scamper_addr_t *addr)
{
  sc_ipidseq_t *seq;

  if((seq = malloc_zero(sizeof(sc_ipidseq_t))) == NULL)
    return NULL;

  seq->addr = scamper_addr_use(addr);

  if(splaytree_insert(ipidseqs, seq) == NULL)
    {
      scamper_addr_free(seq->addr);
      free(seq);
      return NULL;
    }

  return seq;
}

static sc_ipidseq_t *sc_ipidseq_get(scamper_addr_t *addr)
{
  sc_ipidseq_t findme;
  findme.addr = addr;
  return splaytree_find(ipidseqs, &findme);
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
  if(test == NULL)
    return;
  free(test);
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

static sc_target_t *sc_target_add(scamper_addr_t *addr, sc_test_t *test)
{
  sc_target_t *tg = malloc_zero(sizeof(sc_target_t));
  if(tg == NULL)
    {
      fprintf(stderr, "could not malloc target\n");
      return NULL;
    }
  tg->addr = scamper_addr_use(addr);
  tg->test = test;

  if((tg->node = splaytree_insert(targets, tg)) == NULL)
    {
      fprintf(stderr, "could not add target to tree\n");
      scamper_addr_free(tg->addr);
      free(tg);
      return NULL;
    }

  return tg;
}

static void sc_target_detach(sc_target_t *tg)
{
  sc_test_t *test;

  if(tg == NULL)
    return;

  if(tg->node != NULL)
    {
      splaytree_remove_node(targets, tg->node);
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

static int sc_target_cmp(const void *a, const void *b)
{
  return scamper_addr_cmp(((sc_target_t *)a)->addr, ((sc_target_t *)b)->addr);
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

static void sc_pingtest_free(sc_pingtest_t *pt)
{
  if(pt == NULL)
    return;
  if(pt->addr != NULL)
    scamper_addr_free(pt->addr);
  if(pt->tg != NULL)
    sc_target_free(pt->tg);
  free(pt);
  return;
}

static sc_test_t *sc_pingtest_new(scamper_addr_t *addr)
{
  sc_pingtest_t *pt = NULL;
  sc_test_t *test = NULL;

  assert(addr != NULL);

  if((pt = malloc_zero(sizeof(sc_pingtest_t))) == NULL)
    {
      fprintf(stderr, "could not malloc pingtest\n");
      goto err;
    }
  pt->addr = scamper_addr_use(addr);

  /* create a generic test structure which we put in a list of tests */
  if((test = sc_test_alloc(TEST_PING, pt)) == NULL)
    goto err;

  return test;

 err:
  if(pt != NULL) sc_pingtest_free(pt);
  if(test != NULL) sc_test_free(test);
  return NULL;
}

static void sc_scantest_free(sc_scantest_t *ps)
{
  if(ps == NULL)
    return;
  if(ps->a != NULL) scamper_addr_free(ps->a);
  if(ps->b != NULL) scamper_addr_free(ps->b);
  if(ps->tg != NULL) sc_target_free(ps->tg);
  free(ps);
  return;
}

static int sc_prefixscan_cmp(const sc_prefixscan_t *a, const sc_prefixscan_t *b)
{
  int i;
  if((i = scamper_addr_cmp(a->a, b->a)) != 0) return i;
  if((i = scamper_addr_cmp(a->b, b->b)) != 0) return i;
  return scamper_addr_cmp(a->ab, b->ab);
}

static int sc_prefixscan_human_cmp(const sc_prefixscan_t *a,
				   const sc_prefixscan_t *b)
{
  int i;
  if((i = scamper_addr_human_cmp(a->a, b->a)) != 0) return i;
  if((i = scamper_addr_human_cmp(a->b, b->b)) != 0) return i;
  return scamper_addr_human_cmp(a->ab, b->ab);
}

static void sc_prefixscan_free(sc_prefixscan_t *pfs)
{
  if(pfs == NULL)
    return;
  if(pfs->a != NULL) scamper_addr_free(pfs->a);
  if(pfs->b != NULL) scamper_addr_free(pfs->b);
  if(pfs->ab != NULL) scamper_addr_free(pfs->ab);
  free(pfs);
  return;
}

static int infile_line(char *str, void *param)
{
  static int line = 0;
  sc_scantest_t *ps = NULL;
  sc_test_t *test = NULL;
  char *ptr;

  line++;

  if(str[0] == '#' || str[0] == '\0')
    return 0;
  if((ptr = string_nextword(str)) == NULL || string_nextword(ptr) != NULL)
    {
      fprintf(stderr, "malformed line %d: expected two IP addresses\n", line);
      return -1;
    }

  if((ps = malloc_zero(sizeof(sc_scantest_t))) == NULL ||
     (ps->a = scamper_addr_resolve(AF_UNSPEC, str)) == NULL ||
     (ps->b = scamper_addr_resolve(AF_UNSPEC, ptr)) == NULL ||
     (test = sc_test_alloc(TEST_SCAN, ps)) == NULL ||
     slist_tail_push(virgin, test) == NULL)
    goto err;

  ps->pfx = prefix_len;
  return 0;

 err:
  fprintf(stderr, "malformed line %d: expected two IP addresses\n", line);
  if(ps != NULL) sc_scantest_free(ps);
  if(test != NULL) sc_test_free(test);
  return -1;
}

static int process_ping(sc_test_t *test, scamper_ping_t *ping)
{
  sc_pingtest_t *pt = test->data;
  sc_ipidseq_t *seq;
  scamper_ping_reply_t *r[4], *rx;
  uint32_t u32;
  char addr[64], icmp[10], tcp[10], udp[10];
  int class, i, j, rc;
  int samples[65536];

  assert(ping != NULL);

  if((seq = sc_ipidseq_get(pt->addr)) == NULL &&
     (seq = sc_ipidseq_alloc(pt->addr)) == NULL)
    {
      return -1;
    }

  if(ping->stop_reason == SCAMPER_PING_STOP_NONE ||
     ping->stop_reason == SCAMPER_PING_STOP_ERROR)
    {
      class = IPID_UNRESP;
      goto done;
    }

  rc = 0;
  for(j=0; j<ping->ping_sent && rc < 4; j++)
    {
      if((rx = ping->ping_replies[j]) == NULL)
	continue;
      if(SCAMPER_PING_REPLY_FROM_TARGET(ping, rx))
	r[rc++] = rx;
    }

  if(rc < 4)
    {
      class = IPID_UNRESP;
      goto done;
    }

  /*
   * if at least two of four samples have the same ipid as what was sent,
   * then declare it echos.  this handles the observed case where some
   * responses echo but others increment.
   */
  u32 = 0;
  for(i=0; i<4; i++)
    {
      if(r[i]->probe_ipid == r[i]->reply_ipid)
	u32++;
    }
  if(u32 > 1)
    {
      class = IPID_ECHO;
      goto done;
    }

  u32 = 0;
  memset(samples, 0, sizeof(samples));
  for(i=0; i<4; i++)
    {
      samples[r[i]->reply_ipid]++;
      if(samples[r[i]->reply_ipid] > 1)
	u32++;
    }
  if(u32 > 1)
    {
      class = IPID_CONST;
      goto done;
    }

  for(i=0; i<3; i++)
    {
      if(r[i+0]->reply_ipid < r[i+1]->reply_ipid)
	u32 = r[i+1]->reply_ipid - r[i-0]->reply_ipid;
      else
	u32 = (r[i+1]->reply_ipid + 0x10000) - r[i+0]->reply_ipid;

      if(u32 > 5000)
	break;
    }

  if(i == 3)
    class = IPID_INCR;
  else
    class = IPID_RAND;

 done:
  if(SCAMPER_PING_METHOD_IS_UDP(ping))
    seq->udp = class;
  else if(SCAMPER_PING_METHOD_IS_TCP(ping))
    seq->tcp = class;
  else if(SCAMPER_PING_METHOD_IS_ICMP(ping))
    seq->icmp = class;

  scamper_addr_tostr(pt->addr, addr, sizeof(addr));
  scamper_ping_free(ping); ping = NULL;

  pt->step++;

  if(pt->step < 3)
    {
      if(sc_waittest(test) != 0)
	goto err;

      status("wait ping %s step %d", addr, pt->step);
      return 0;
    }

  status("done ping %s udp %s tcp %s icmp %s", addr,
	 class_tostr(udp, sizeof(udp), seq->udp),
	 class_tostr(tcp, sizeof(tcp), seq->tcp),
	 class_tostr(icmp, sizeof(icmp), seq->icmp));

  sc_pingtest_free(pt);
  sc_test_free(test);

  return 0;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return -1;
}

static int process_scan(sc_test_t *test, scamper_dealias_t *dealias)
{
  sc_scantest_t *ps = test->data;
  scamper_dealias_prefixscan_t *scan = dealias->data;
  char a[64], b[64], ab[64];
  int done = 0;

  scamper_addr_tostr(scan->a, a, sizeof(a));
  scamper_addr_tostr(scan->b, b, sizeof(b));

  if(scan->ab != NULL)
    {
      status("done scan %s %s/%d %s", a, b, ps->pfx,
	     scamper_addr_tostr(scan->ab, ab, sizeof(ab)));
      done = 1;
    }

  scamper_dealias_free(dealias);
  if(done != 0)
    goto done;

  ps->step++;
  if(ps->step < 3)
    {
      if(sc_waittest(test) != 0)
	return -1;

      status("wait scan %s %s/%d step %d", a, b, ps->pfx, ps->step);
      return 0;
    }

 done:
  sc_scantest_free(ps);
  sc_test_free(test);
  return 0;
}

static int sc_test_ping(sc_test_t *test, char *cmd, size_t len)
{
  sc_pingtest_t *pt = test->data;
  scamper_addr_t *dst = pt->addr;
  sc_target_t *tg;
  size_t off = 0;
  char buf[64];

  assert(pt->step >= 0);
  assert(pt->step <= 2);

  /* first, check to see if the test is runnable. if not block */
  if((tg = sc_target_findaddr(dst)) != NULL && tg->test != test)
    {
      if(sc_target_block(tg, test) != 0)
	return -1;
      return 0;
    }
  else if(tg == NULL)
    {
      if((pt->tg = sc_target_add(dst, test)) == NULL)
	return -1;
    }

  string_concat(cmd, len, &off, "ping -P ");

  if(pt->step == 0)
    string_concat(cmd, len, &off, "udp-dport");
  else if(pt->step == 1)
    string_concat(cmd, len, &off, "icmp-echo");
  else if(pt->step == 2)
    string_concat(cmd, len, &off, "tcp-ack-sport");
  else
    return -1;

  string_concat(cmd, len, &off, " -c 6 -o 4 %s\n",
		scamper_addr_tostr(dst, buf, sizeof(buf)));

  return off;
}

static int sc_test_scan(sc_test_t *test, char *cmd, size_t len)
{
  sc_scantest_t *ps = test->data;
  sc_pingtest_t *pt;
  sc_test_t *test2;
  sc_ipidseq_t *seq;
  sc_target_t *tg;
  size_t off = 0;
  uint8_t ipid;
  char a[64], b[64], *meth;

  /* first, check to see if the test is runnable. if not block */
  if((tg = sc_target_findaddr(ps->a)) != NULL && tg->test != test)
    {
      if(sc_target_block(tg, test) != 0)
	return -1;
      return 0;
    }

  /* check if we know the available probe methods for the A address */
  if((seq = sc_ipidseq_get(ps->a)) == NULL)
    {
      if((test2 = sc_pingtest_new(ps->a)) == NULL)
	return -1;
      pt = test2->data;
      if((pt->tg = sc_target_add(ps->a, test2)) == NULL)
	return -1;
      if(sc_target_block(pt->tg, test) != 0)
	return -1;
      return sc_test_ping(test2, cmd, len);
    }

  /* add a pointer to the test in the target tree */
  if(tg == NULL && (ps->tg = sc_target_add(ps->a, test)) == NULL)
    return -1;

  while(ps->step <= 2)
    {
      if(ps->step == 0) ipid = seq->udp;
      else if(ps->step == 1) ipid = seq->tcp;
      else ipid = seq->icmp;

      if(ipid == IPID_INCR)
	break;

      ps->step++;
    }

  if(ps->step > 2)
    {
      sc_scantest_free(ps);
      sc_test_free(test);
      return 0;
    }

  if(ps->step == 0) meth = "udp";
  else if(ps->step == 1) meth = "tcp-ack-sport";
  else meth = "icmp-echo";

  string_concat(cmd, len, &off,
		"dealias -m prefixscan -f 1000 -p '-P %s' %s %s/%d\n",
		meth,
		scamper_addr_tostr(ps->a, a, sizeof(a)),
		scamper_addr_tostr(ps->b, b, sizeof(b)),
		ps->pfx);

  return off;
}

static int do_method(void)
{
  static int (*const func[])(sc_test_t *, char *, size_t) = {
    sc_test_ping, /* TEST_PING */
    sc_test_scan, /* TEST_SCAN */
  };
  sc_waittest_t *wt;
  sc_test_t *test;
  char cmd[512];
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
      else if((test = slist_head_pop(virgin)) == NULL)
	{
	  return 0;
	}

      /* something went wrong */
      if((off = func[test->type-1](test, cmd, sizeof(cmd))) == -1)
	{
	  fprintf(stderr, "something went wrong\n");
	  error = 1;
	  return -1;
	}

      /* got a command, send it */
      if(off != 0)
	{
	  write_wrap(scamper_fd, cmd, NULL, off);
	  probing++;
	  more--;

	  print("p %d, w %d, v %d : %s", probing, heap_count(waiting),
		slist_count(virgin), cmd);

	  break;
	}
    }

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
  struct sockaddr_un sun;
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
  else if(options & OPT_UNIX)
    {
      if(sockaddr_compose_un((struct sockaddr *)&sun, unix_name) != 0)
	{
	  fprintf(stderr, "could not build sockaddr_un\n");
	  return -1;
	}
      if((scamper_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
	  fprintf(stderr, "could not allocate unix domain socket\n");
	  return -1;
	}
      if(connect(scamper_fd, (const struct sockaddr *)&sun, sizeof(sun)) != 0)
	{
	  fprintf(stderr, "could not connect to scamper process\n");
	  return -1;
	}
      return 0;
    }

  return -1;
}

static int do_scamperread_line(void *param, uint8_t *buf, size_t linelen)
{
  char *head = (char *)buf;
  uint8_t uu[64];
  size_t uus;
  long l;

  /* skip empty lines */
  if(head[0] == '\0')
    return 0;

  /* if currently decoding data, then pass it to uudecode */
  if(data_left > 0)
    {
      uus = sizeof(uu);
      if(uudecode_line(head, linelen, uu, &uus) != 0)
	{
	  fprintf(stderr, "could not uudecode_line\n");
	  error = 1;
	  return -1;
	}

      if(uus != 0)
	{
	  scamper_writebuf_send(decode_wb, uu, uus);
	  write_wrap(outfile_fd, uu, NULL, uus);
	}

      data_left -= (linelen + 1);
      return 0;
    }

  /* feedback letting us know that the command was accepted */
  if(linelen >= 2 && strncasecmp(head, "OK", 2) == 0)
    return 0;

  /* if the scamper process is asking for more tasks, give it more */
  if(linelen == 4 && strncasecmp(head, "MORE", linelen) == 0)
    {
      more++;
      if(do_method() != 0)
	return -1;
      return 0;
    }

  /* new piece of data */
  if(linelen > 5 && strncasecmp(head, "DATA ", 5) == 0)
    {
      if(string_isnumber(head+5) == 0 || string_tolong(head+5, &l) != 0)
	{
	  fprintf(stderr, "could not parse %s\n", head);
	  error = 1;
	  return -1;
	}
      data_left = l;
      return 0;
    }

  /* feedback letting us know that the command was not accepted */
  if(linelen >= 3 && strncasecmp(head, "ERR", 3) == 0)
    {
      error = 1;
      return -1;
    }

  fprintf(stderr, "unknown response '%s'\n", head);
  error = 1;
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
  uint8_t buf[512];

  if((rc = read(scamper_fd, buf, sizeof(buf))) > 0)
    {
      scamper_linepoll_handle(scamper_lp, buf, rc);
      return 0;
    }
  else if(rc == 0)
    {
      close(scamper_fd);
      scamper_fd = -1;
      return 0;
    }
  else if(errno == EINTR || errno == EAGAIN)
    {
      return 0;
    }

  fprintf(stderr, "could not read: errno %d\n", errno);
  return -1;
}

static int do_files(void)
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_PING, SCAMPER_FILE_OBJ_DEALIAS};
  mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  int flags = O_WRONLY | O_CREAT | O_TRUNC;
  int pair[2];

  if((ffilter = scamper_file_filter_alloc(types, 2)) == NULL)
    {
      return -1;
    }

  if((outfile_fd = open(outfile_name, flags, mode)) == -1)
    {
      return -1;
    }

  /*
   * setup a socketpair that is used to decode warts from a binary input.
   * pair[0] is used to write to the file, while pair[1] is used by
   * the scamper_file_t routines to parse the warts data.
   */
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
    {
      return -1;
    }

  decode_in_fd  = pair[0];
  decode_out_fd = pair[1];
  if((decode_in = scamper_file_openfd(decode_in_fd,NULL,'r',"warts")) == NULL)
    {
      return -1;
    }

  if(fcntl_set(decode_in_fd, O_NONBLOCK) == -1)
    {
      return -1;
    }

  return 0;
}

static int do_decoderead(void)
{
  sc_target_t                  *target, findme;
  sc_test_t                    *test;
  void                         *data;
  uint16_t                      type;
  char                          buf[64];
  scamper_ping_t               *ping = NULL;
  scamper_dealias_t            *dealias = NULL;
  scamper_dealias_prefixscan_t *ps = NULL;
  int rc;

  /* try and read a traceroute from the warts decoder */
  if(scamper_file_read(decode_in, ffilter, &type, &data) != 0)
    {
      fprintf(stderr, "do_decoderead: scamper_file_read errno %d\n", errno);
      goto err;
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
    {
      ping = (scamper_ping_t *)data;
      findme.addr = ping->dst;
    }
  else if(type == SCAMPER_FILE_OBJ_DEALIAS)
    {
      dealias = (scamper_dealias_t *)data;
      ps = (scamper_dealias_prefixscan_t *)dealias->data;
      findme.addr = ps->a;
    }
  else return -1;

  if((target = splaytree_find(targets, &findme)) == NULL)
    {
      fprintf(stderr, "do_decoderead: could not find dst %s\n",
	      scamper_addr_tostr(findme.addr, buf, sizeof(buf)));
      goto err;
    }
  test = target->test;

  if(test->type == TEST_PING)
    rc = process_ping(test, ping);
  else if(test->type == TEST_SCAN)
    rc = process_scan(test, dealias);
  else
    rc = -1;

  return rc;

 err:
  if(dealias != NULL) scamper_dealias_free(dealias);
  if(ping != NULL) scamper_ping_free(ping);
  return -1;
}

static int pf_data(void)
{
  struct timeval tv, *tv_ptr;
  sc_waittest_t *wait;
  fd_set rfds, wfds, *wfdsp;
  int nfds;

  random_seed();

  /* global data structures used to keep track of the set of traceset */
  if((targets = splaytree_alloc(sc_target_cmp)) == NULL)
    return -1;
  if((ipidseqs = splaytree_alloc(sc_ipidseq_cmp)) == NULL)
    return -1;
  if((virgin = slist_alloc()) == NULL)
    return -1;
  if((waiting = heap_alloc(sc_waittest_cmp)) == NULL)
    return -1;
  if(file_lines(infile, infile_line, NULL) != 0)
    {
      fprintf(stderr, "could not read %s\n", infile);
      return -1;
    }

  /*
   * connect to the scamper process
   */
  if(do_scamperconnect() != 0)
    return -1;

  /*
   * sort out the files that we'll be working with.
   */
  if(do_files() != 0)
    return -1;

  if((scamper_lp = scamper_linepoll_alloc(do_scamperread_line, NULL)) == NULL ||
     (scamper_wb = scamper_writebuf_alloc()) == NULL ||
     (decode_wb = scamper_writebuf_alloc()) == NULL)
    return -1;
  scamper_writebuf_send(scamper_wb, "attach\n", 7);

  while(error == 0)
    {
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

      nfds = 0; FD_ZERO(&rfds); FD_ZERO(&wfds); wfdsp = NULL;
      if(scamper_fd < 0 && decode_in_fd < 0)
	break;

      if(scamper_fd >= 0)
	{
	  FD_SET(scamper_fd, &rfds);
	  if(nfds < scamper_fd) nfds = scamper_fd;
	  if(scamper_writebuf_len(scamper_wb) > 0)
	    {
	      FD_SET(scamper_fd, &wfds);
	      wfdsp = &wfds;
	    }
	}

      if(decode_in_fd >= 0)
	{
	  FD_SET(decode_in_fd, &rfds);
	  if(nfds < decode_in_fd) nfds = decode_in_fd;
	}

      if(decode_out_fd >= 0 && scamper_writebuf_len(decode_wb) > 0)
	{
	  FD_SET(decode_out_fd, &wfds);
	  wfdsp = &wfds;
	  if(nfds < decode_out_fd) nfds = decode_out_fd;
	}

      if(splaytree_count(targets) == 0 && slist_count(virgin) == 0 &&
	 heap_count(waiting) == 0)
	{
	  break;
	}

      if(select(nfds+1, &rfds, wfdsp, NULL, tv_ptr) < 0)
	{
	  if(errno == EINTR) continue;
	  fprintf(stderr, "select error\n");
	  break;
	}

      gettimeofday_wrap(&now);

      if(more > 0)
	{
	  if(do_method() != 0)
	    return -1;
	}

      if(scamper_fd >= 0)
	{
	  if(FD_ISSET(scamper_fd, &rfds) && do_scamperread() != 0)
	    return -1;
	  if(wfdsp != NULL && FD_ISSET(scamper_fd, wfdsp) &&
	     scamper_writebuf_write(scamper_fd, scamper_wb) != 0)
	    return -1;
	}

      if(decode_in_fd >= 0)
	{
	  if(FD_ISSET(decode_in_fd, &rfds) && do_decoderead() != 0)
	    return -1;
	}

      if(decode_out_fd >= 0)
	{
	  if(wfdsp != NULL && FD_ISSET(decode_out_fd, wfdsp) &&
	     scamper_writebuf_write(decode_out_fd, decode_wb) != 0)
	    return -1;

	  if(scamper_fd < 0 && scamper_writebuf_len(decode_wb) == 0)
	    {
	      close(decode_out_fd);
	      decode_out_fd = -1;
	    }
	}
    }

  return 0;
}

static int pf_read(void)
{
  splaytree_t *tree = NULL;
  slist_t *list = NULL;
  scamper_file_t *in = NULL;
  scamper_dealias_t *dealias;
  scamper_dealias_prefixscan_t *ps;
  char a[64], b[64], ab[64];
  sc_prefixscan_t *pfs;
  uint16_t type;
  void *data;

  if(strcmp(datafile, "-") == 0)
    in = scamper_file_openfd(STDIN_FILENO, "-", 'r', "warts");
  else
    in = scamper_file_open(datafile, 'r', NULL);
  if(in == NULL)
    {
      fprintf(stderr, "could not open %s: %s\n", datafile, strerror(errno));
      goto err;
    }

  type = SCAMPER_FILE_OBJ_DEALIAS;
  if((ffilter = scamper_file_filter_alloc(&type, 1)) == NULL)
    goto err;

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_prefixscan_cmp)) == NULL)
    goto err;

  while(scamper_file_read(in, ffilter, &type, &data) == 0)
    {
      if(data == NULL)
	break;

      dealias = data;
      if(SCAMPER_DEALIAS_METHOD_IS_PREFIXSCAN(dealias))
	{
	  ps = dealias->data;
	  if(ps->ab != NULL &&
	     scamper_addr_prefixhosts(ps->b, ps->ab) >=
	     (prefix_len == 0 ? ps->prefix : 30))
	    {
	      if((pfs = malloc_zero(sizeof(sc_prefixscan_t))) == NULL)
		{
		  fprintf(stderr, "could not record scan result\n");
		  goto err;
		}
	      pfs->a = scamper_addr_use(ps->a);
	      pfs->b = scamper_addr_use(ps->b);
	      pfs->ab = scamper_addr_use(ps->ab);
	      if(splaytree_insert(tree, pfs) == NULL)
		{
		  fprintf(stderr, "could not add scan result\n");
		  goto err;
		}
	    }
	}
      scamper_dealias_free(dealias);
    }
  scamper_file_close(in); in = NULL;

  if((list = slist_alloc()) == NULL)
    {
      fprintf(stderr, "could not alloc list: %s\n", strerror(errno));
      goto err;
    }
  splaytree_inorder(tree, tree_to_slist, list);
  splaytree_free(tree, NULL); tree = NULL;
  slist_qsort(list, (slist_cmp_t)sc_prefixscan_human_cmp);
  while((pfs = slist_head_pop(list)) != NULL)
    {
      printf("%s %s %s/%d\n",
	     scamper_addr_tostr(pfs->a, a, sizeof(a)),
	     scamper_addr_tostr(pfs->b, b, sizeof(b)),
	     scamper_addr_tostr(pfs->ab, ab, sizeof(ab)),
	     scamper_addr_prefixhosts(pfs->b, pfs->ab));
      sc_prefixscan_free(pfs);
    }
  slist_free(list);

  return 0;

 err:
  return -1;
}

static void cleanup(void)
{
  if(virgin != NULL)
    {
      slist_free(virgin);
      virgin = NULL;
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

  if(ipidseqs != NULL)
    {
      splaytree_free(ipidseqs, (splaytree_free_t)sc_ipidseq_free);
      ipidseqs = NULL;
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

  if(text != NULL)
    {
      fclose(text);
      text = NULL;
    }

  if(decode_wb != NULL)
    {
      scamper_writebuf_free(decode_wb);
      decode_wb = NULL;
    }

  if(scamper_wb != NULL)
    {
      scamper_writebuf_free(scamper_wb);
      scamper_wb = NULL;
    }

  if(scamper_lp != NULL)
    {
      scamper_linepoll_free(scamper_lp, 0);
      scamper_lp = NULL;
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

  /* start a daemon if asked to */
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    return -1;

  if((options & OPT_READ) != 0)
    return pf_read();

  return pf_data();
}
