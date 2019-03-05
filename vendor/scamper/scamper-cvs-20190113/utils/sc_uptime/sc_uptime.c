/*
 * sc_uptime: system to probe routers to identify reboot events
 *
 * $Id: sc_uptime.c,v 1.67 2018/12/17 04:45:57 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2015 The Regents of the University of California
 * Copyright (C) 2017 Matthew Luckie
 * Copyright (C) 2018 The University of Waikato
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
  "$Id: sc_uptime.c,v 1.67 2018/12/17 04:45:57 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include <sqlite3.h>

#include "scamper_addr.h"
#include "scamper_list.h"
#include "ping/scamper_ping.h"
#include "scamper_file.h"
#include "scamper_writebuf.h"
#include "scamper_linepoll.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "mjl_heap.h"
#include "mjl_prefixtree.h"
#include "utils.h"

#define OPT_HELP        0x0001
#define OPT_DBFILE      0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008
#define OPT_UNIX        0x0010
#define OPT_LOG         0x0020
#define OPT_CREATE      0x0040
#define OPT_ADDRFILE    0x0100
#define OPT_OPTIONS     0x0200
#define OPT_SRCADDR     0x0400
#define OPT_IMPORT      0x0800
#define OPT_REBOOTS     0x1000
#define OPT_INTERVAL    0x2000
#define OPT_EXPIRE      0x4000
#define OPT_DONOTPROBE  0x8000
#define OPT_ALL         0xffff

static splaytree_t           *tree          = NULL;
static heap_t                *heap_p1       = NULL;
static slist_t               *list          = NULL;
static uint32_t               options       = 0;
static unsigned int           port          = 0;
static char                  *unix_name     = NULL;
static scamper_writebuf_t    *scamper_wb    = NULL;
static int                    scamper_fd    = -1;
static scamper_linepoll_t    *scamper_lp    = NULL;
static scamper_writebuf_t    *decode_wb     = NULL;
static scamper_file_t        *decode_in     = NULL;
static int                    decode_in_fd  = -1;
static int                    decode_out_fd = -1;
static char                  *dbfile        = NULL;
static char                  *srcaddr       = NULL;
static scamper_file_t        *outfile       = NULL;
static scamper_file_filter_t *ffilter       = NULL;
static int                    data_left     = 0;
static int                    more          = 0;
static int                    probing       = 0;
static int                    interval      = 0;
static int                    expire        = 0;
static int                    fudge         = 65535;
static int                    init_data     = 0;
static int                    init_state    = 0;
static int                    safe_db       = 0;
static int                    vacuum_db     = 0;
static int                    verbose       = 0;
static struct timeval         now;
static struct timeval         deadline;
static FILE                  *logfile       = NULL;
static sqlite3               *db            = NULL;
static sqlite3_stmt          *st_class      = NULL;
static sqlite3_stmt          *st_addr_i     = NULL;
static sqlite3_stmt          *st_addr_u     = NULL;
static char                 **opt_args      = NULL;
static int                    opt_argc      = 0;
static int                    up_import_stop = 0;

#define CLASS_NONE    0
#define CLASS_UNRESP  1
#define CLASS_RANDOM  2
#define CLASS_INCR    3

#define ST_CLASS_CLASS     1
#define ST_CLASS_NEXT      2
#define ST_CLASS_LAST_IPID 3
#define ST_CLASS_LAST_RX   4
#define ST_CLASS_LOSS      5
#define ST_CLASS_ID        6

#define BLOB_SIZE_MIN 214 /* 10 21 byte records + 4 bytes of length */

typedef struct sc_dst
{
  sqlite3_int64     id;
  scamper_addr_t   *addr;
  sqlite3_int64     samples_rowid; /* zero if no samples */
  int               class;
  uint32_t          last_ipid;
  uint32_t          last_rx;
  uint32_t          next;
  int               loss;
  splaytree_node_t *tree_node;
} sc_dst_t;

typedef struct sc_sample sc_sample_t;
struct sc_sample
{
  uint8_t       type;
  uint32_t      tx_sec;
  uint32_t      tx_usec;
  uint32_t      rx_sec;
  uint32_t      rx_usec;
  uint32_t      ipid;
  sc_sample_t  *next;
};

typedef struct sc_reboot
{
  uint32_t      left;
  uint32_t      right;
} sc_reboot_t;

typedef struct sc_ipidseq sc_ipidseq_t;
struct sc_ipidseq
{
  sc_sample_t **samples;
  int           samplec;
  double        velocity;
  uint8_t       type;     /* 0: incr. 1: random. 2: reseed on PTB */
  sc_ipidseq_t *prev;
  sc_ipidseq_t *next;
};

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
    "usage: sc_uptime [-o] [-d dbfile] [-E expire] [-I interval]\n"
    "                      [-l log] [-o outfile] [-O option] [-p port]\n"
    "                      [-S srcaddr] [-U unix] outfile.warts\n"
    "\n"
    "       sc_update [-a] [-d dbfile] [-E expire] [-O option] addrfile.txt\n"
    "\n"
    "       sc_update [-c] [-d dbfile] [-O option]\n"
    "\n"
    "       sc_uptime [-i] [-d dbfile] [-O option] infile.warts\n"
    "\n"
    "       sc_uptime [-r] [-d dbfile] [-O option] ip1 .. ipN\n"
    "\n"
    "       sc_uptime [-x] [-d dbfile] [-O option] do-not-probe.txt\n"
    "\n");

  if(opt_mask == 0)
    fprintf(stderr, "       sc_uptime -?\n\n");

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "   -? give an overview of the usage of sc_uptime\n");

  if(opt_mask & OPT_ADDRFILE)
    fprintf(stderr, "   -a input address file\n");

  if(opt_mask & OPT_CREATE)
    fprintf(stderr, "   -c create db file\n");

  if(opt_mask & OPT_DBFILE)
    fprintf(stderr, "   -d sqlite db file\n");

  if(opt_mask & OPT_EXPIRE)
    fprintf(stderr, "   -E how long, in days, before expiring probe state\n");

  if(opt_mask & OPT_IMPORT)
    fprintf(stderr, "   -i import samples into database\n");

  if(opt_mask & OPT_INTERVAL)
    fprintf(stderr, "   -I probe interval, in seconds, between %d and %d\n",
	    60, 60 * 60);

  if(opt_mask & OPT_LOG)
    fprintf(stderr, "   -l output logfile\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "   -o output warts file\n");

  if(opt_mask & OPT_OPTIONS)
    {
      fprintf(stderr, "   -O options\n");
      fprintf(stderr, "      init-state: initialise database for probing\n");
      fprintf(stderr, "      init-data: initialise database for analysis\n");
      fprintf(stderr, "      safe-db: use safe sqlite3 operations\n");
      fprintf(stderr, "      vacuum-db: vacuum the database before use\n");
      fprintf(stderr, "      verbose: increase verbosity\n");
    }

  if(opt_mask & OPT_REBOOTS)
    fprintf(stderr, "   -r infer reboots from samples in database\n");

  if(opt_mask & OPT_SRCADDR)
    fprintf(stderr, "   -S IPv6 unicast source address for probes\n");

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "   -p port to find scamper on\n");

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "   -U unix domain to find scamper on\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  scamper_addr_t *sa;
  char *opts = "?acd:E:iI:l:oO:p:rS:U:x";
  char *opt_port = NULL, *opt_unix = NULL, *opt_log = NULL;
  char *opt_srcaddr = NULL, *opt_interval = NULL;
  char *opt_expire = NULL;
  uint32_t u32;
  long lo;
  int ch;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'a':
	  options |= OPT_ADDRFILE;
	  break;

	case 'c':
	  options |= OPT_CREATE;
	  break;

	case 'd':
	  options |= OPT_DBFILE;
	  dbfile = optarg;
	  break;

	case 'E':
	  options |= OPT_EXPIRE;
	  opt_expire = optarg;
	  break;

	case 'i':
	  options |= OPT_IMPORT;
	  break;

	case 'I':
	  options |= OPT_INTERVAL;
	  opt_interval = optarg;
	  break;

	case 'l':
	  options |= OPT_LOG;
	  opt_log = optarg;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "init-data") == 0)
	    init_data = 1;
	  else if(strcasecmp(optarg, "init-state") == 0)
	    init_state = 1;
	  else if(strcasecmp(optarg, "safe-db") == 0)
	    safe_db = 1;
	  else if(strcasecmp(optarg, "vacuum-db") == 0)
	    vacuum_db = 1;
	  else if(strcasecmp(optarg, "verbose") == 0)
	    verbose = 1;
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

	case 'r':
	  options |= OPT_REBOOTS;
	  break;

	case 'U':
	  options |= OPT_UNIX;
	  opt_unix = optarg;
	  break;

	case 'S':
	  options |= OPT_SRCADDR;
	  opt_srcaddr = optarg;
	  break;

	case 'x':
	  options |= OPT_DONOTPROBE;
	  break;

	case '?':
	default:
	  usage(OPT_ALL);
	  return -1;
	}
    }

  if(options == 0)
    {
      usage(0);
      return -1;
    }

  opt_args = argv + optind;
  opt_argc = argc - optind;

  /* the database file has to be specified */
  if((options & OPT_DBFILE) == 0)
    {
      usage(OPT_DBFILE);
      return -1;
    }

  /* at least one of these options must be specified, but only one */
  u32 =
    OPT_ADDRFILE |
    OPT_CREATE |
    OPT_IMPORT |
    OPT_REBOOTS |
    OPT_OUTFILE |
    OPT_DONOTPROBE;
  if(options == 0 || countbits32(options & u32) != 1)
    {
      usage(0);
      return -1;
    }

  if(vacuum_db != 0)
    {
      if((options & (OPT_ADDRFILE|OPT_DONOTPROBE|OPT_IMPORT)) == 0)
	{
	  usage(OPT_OPTIONS|OPT_ADDRFILE|OPT_DONOTPROBE|OPT_IMPORT);
	  return -1;
	}
    }

  if(opt_expire != NULL)
    {
      /* -E is only valid with either -a or -o */
      if((options & (OPT_ADDRFILE|OPT_OUTFILE)) == 0)
	{
	  usage(OPT_INTERVAL);
	  return -1;
	}

      /* expire interval has to be at least 2 days */
      if(string_tolong(opt_expire, &lo) != 0 || lo < 2)
	{
	  usage(OPT_INTERVAL);
	  return -1;
	}
      expire = lo * 24 * 60 * 60;
    }

  /* infer reboots from imported database samples */
  if(options & OPT_REBOOTS)
    {
      return 0;
    }

  /* check if we are creating the database file */
  if(options & OPT_CREATE)
    {
      if(vacuum_db != 0 || (init_data == 0 && init_state == 0))
	{
	  usage(OPT_OPTIONS);
	  return -1;
	}
      return 0;
    }

  /* importing addresses into the state database */
  if(options & OPT_ADDRFILE)
    {
      if(opt_argc != 1)
	{
	  usage(OPT_ADDRFILE);
	  return -1;
	}
      return 0;
    }

  /* making sure the addresses in the state database are ok to probe */
  if(options & OPT_DONOTPROBE)
    {
      if(opt_argc != 1)
	{
	  usage(OPT_DONOTPROBE);
	  return -1;
	}
      return 0;
    }

  /* importing warts files into a database */
  if(options & OPT_IMPORT)
    {
      if(opt_argc < 1)
	{
	  usage(OPT_IMPORT);
	  return -1;
	}
      return 0;
    }

  if((options & OPT_OUTFILE) == 0 ||
     (options & (OPT_PORT|OPT_UNIX)) == 0 ||
     (options & (OPT_PORT|OPT_UNIX)) == (OPT_PORT|OPT_UNIX) ||
     opt_argc != 1)
    {
      usage(OPT_OUTFILE|OPT_PORT|OPT_UNIX);
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

  if(opt_srcaddr != NULL)
    {
      if((sa = scamper_addr_resolve(AF_INET6, opt_srcaddr)) == NULL ||
	 scamper_addr_isunicast(sa) != 1)
	{
	  usage(OPT_SRCADDR);
	  if(sa != NULL) scamper_addr_free(sa);
	  return -1;
	}
      scamper_addr_free(sa);
      srcaddr = opt_srcaddr;
    }

  if(opt_interval != NULL)
    {
      /* interval has to be between 1 minute and 1 hour */
      if(string_tolong(opt_interval, &lo) != 0 || lo < 60 || lo > 60 * 60)
	{
	  usage(OPT_INTERVAL);
	  return -1;
	}
      interval = lo;
    }

  if(opt_log != NULL)
    {
      if((logfile = fopen(opt_log, "w")) == NULL)
	{
	  usage(OPT_LOG);
	  fprintf(stderr, "could not open log %s\n", opt_log);
	  return -1;
	}
    }

  return 0;
}

static void logprint(char *format, ...)
{
  va_list ap;
  char msg[131072];

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  if(logfile != NULL)
    {
      fprintf(logfile, "%ld: %s", (long int)now.tv_sec, msg);
      fflush(logfile);
    }
  else
    {
      fprintf(stdout, "%ld: %s", (long int)now.tv_sec, msg);
    }
  return;
}

static const char *class_tostr(int class)
{
  switch(class)
    {
    case CLASS_NONE: return "none";
    case CLASS_UNRESP: return "unresp";
    case CLASS_RANDOM: return "random";
    case CLASS_INCR: return "incr";
    }
  return "???";
}

static int sc_dst_cmp(sc_dst_t *a, sc_dst_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static sc_dst_t *sc_dst_find(scamper_addr_t *addr)
{
  sc_dst_t fm; fm.addr = addr;
  return (sc_dst_t *)splaytree_find(tree, &fm);
}

static int sc_dst_insert(sc_dst_t *dst)
{
  if((dst->tree_node = splaytree_insert(tree, dst)) == NULL)
    return -1;
  return 0;
}

static void sc_dst_free(sc_dst_t *dst)
{
  if(dst->addr != NULL)
    scamper_addr_free(dst->addr);
  free(dst);
  return;
}

static int sc_dst_next_cmp(const sc_dst_t *a, const sc_dst_t *b)
{
  /* items that are due to be probed soon have a higher priority */
  if(a->next < b->next) return  1;
  if(a->next > b->next) return -1;
  return 0;
}

static sc_dst_t *sc_dst_alloc(uint32_t id, scamper_addr_t *addr)
{
  sc_dst_t *dst;
  if((dst = malloc_zero(sizeof(sc_dst_t))) == NULL)
    return NULL;
  dst->addr = addr;
  dst->id = id;
  return dst;
}

static int do_method(void)
{
  char cmd[256], buf[128];
  size_t off = 0;
  sc_dst_t *dst;

  if(more < 1)
    return 0;

  if((dst = heap_head_item(heap_p1)) != NULL && dst->next <= now.tv_sec)
    heap_remove(heap_p1);
  else if((interval != 0 && timeval_cmp(&now, &deadline) >= 0) ||
	  (dst = slist_head_pop(list)) == NULL)
    return 0;

  scamper_addr_tostr(dst->addr, buf, sizeof(buf));
  if(sc_dst_insert(dst) != 0)
    {
      fprintf(stderr, "%s: could not insert %s into tree\n", __func__, buf);
      return -1;
    }

  /* form the ping command */
  string_concat(cmd, sizeof(cmd), &off, "ping -O dl -s 1300 -M 1280");
  if(srcaddr != NULL)
    string_concat(cmd, sizeof(cmd), &off, " -S %s", srcaddr);
  if(dst->class != CLASS_INCR)
    string_concat(cmd, sizeof(cmd), &off, " -c 6 %s\n", buf);
  else
    string_concat(cmd, sizeof(cmd), &off, " -c 2 -o 1 -O tbt %s\n", buf);

  if(scamper_writebuf_send(scamper_wb, cmd, off) != 0)
    {
      fprintf(stderr, "%s: could not send %s\n", __func__, cmd);
      return -1;
    }

  probing++;
  more--;

  logprint("p %d, p1 %d, l %d : %s", probing, heap_count(heap_p1),
	   slist_count(list), cmd);

  return 0;
}

static int ipid_inseq2(uint64_t a, uint64_t b)
{
  assert(fudge > 0);
  if(a == b)
    return 0;
  if(a > b)
    b += 0x100000000ULL;
  if(b - a > fudge)
    return 0;
  return 1;
}

static int ipid_inseq3(uint64_t a, uint64_t b, uint64_t c)
{
  if(a == b || b == c || a == c)
    return 0;
  if(a > b)
    b += 0x100000000ULL;
  if(a > c)
    c += 0x100000000ULL;

  if(fudge != 0)
    {
      if(b - a > fudge || c - b > fudge)
	return 0;
    }
  else
    {
      if(a > b || b > c)
	return 0;
    }
  return 1;
}

static int ipid_incr(sc_sample_t *ipids, int ipidc)
{
  int i;
  if(ipidc < 3)
    return 0;
  for(i=2; i<ipidc; i++)
    if(ipid_inseq3(ipids[i-2].ipid, ipids[i-1].ipid, ipids[i].ipid) == 0)
      return 0;
  return 1;
}

static int next_random(int *next, int next_min, int next_max)
{
  uint32_t upper = next_max - next_min;
  uint32_t u32, min = -upper % upper;

  for(;;)
    {
      if(random_u32(&u32) != 0)
	return -1;
      if(u32 >= min)
	break;
    }

  *next = next_min + (u32 % upper);
  return 0;
}

static int do_sqlite_vacuum(void)
{
  char *errmsg;
  if(sqlite3_exec(db, "vacuum", NULL, NULL, &errmsg) != SQLITE_OK)
    return -1;
  return 0;
}

/*
 * db_update
 *
 * sql = "update state_dsts set class=?,next=?,last_ipid=?,last_rx=?,loss=? "
 *       "where id=?";
 *
 */
static int db_update(sc_dst_t *dst)
{
  int next;

  sqlite3_reset(st_class);
  sqlite3_clear_bindings(st_class);
  sqlite3_bind_int(st_class, ST_CLASS_CLASS, dst->class);

  if(dst->class != CLASS_INCR)
    {
      /* probe again in 7-14 days time */
      if(next_random(&next, 7 * 24 * 60 * 60, 14 * 24 * 60 * 60) != 0)
	{
	  fprintf(stderr, "%s: could not get next_random\n", __func__);
	  return -1;
	}
      sqlite3_bind_int(st_class, ST_CLASS_NEXT, now.tv_sec + next);
    }
  else
    {
      /*
       * probe approx every hour for 24 hours after losing at least 10
       * over 2 hours
       */
      if(dst->loss > 10 &&
	 now.tv_sec - dst->last_rx > (2 * 60 * 60) &&
	 now.tv_sec - dst->last_rx < (24 * 60 * 60))
	{
	  sqlite3_bind_int(st_class, ST_CLASS_NEXT, now.tv_sec + (60 * 60));
	}
      else
	{
	  if(interval != 0)
	    {
	      /* probe at the next specified time */
	      sqlite3_bind_int(st_class, ST_CLASS_NEXT, now.tv_sec + interval);
	    }
	  else
	    {
	      /* probe at some point in the next run */
	      sqlite3_bind_int(st_class, ST_CLASS_NEXT, 0);
	    }
	}
    }

  sqlite3_bind_int64(st_class, ST_CLASS_LAST_IPID, dst->last_ipid);
  sqlite3_bind_int64(st_class, ST_CLASS_LAST_RX, dst->last_rx);
  sqlite3_bind_int(st_class, ST_CLASS_LOSS, dst->loss);
  sqlite3_bind_int64(st_class, ST_CLASS_ID, dst->id);

  if(sqlite3_step(st_class) != SQLITE_DONE)
    {
      fprintf(stderr, "%s: could not execute st_class %lld:%d\n",
	      __func__, dst->id, dst->class);
      return -1;
    }

  return 0;
}

static int do_decoderead_ping(scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  sc_sample_t ipids[10];
  int i, rc = 0, ipidc = 0, replyc = 0, freedst = 1;
  sc_dst_t *dst;
  char buf[128];

  scamper_addr_tostr(ping->dst, buf, sizeof(buf));

  if((dst = sc_dst_find(ping->dst)) == NULL)
    {
      fprintf(stderr, "%s: could not find dst %s\n", __func__, buf);
      return -1;
    }
  splaytree_remove_node(tree, dst->tree_node);
  dst->tree_node = NULL;

  for(i=0; i<ping->ping_sent; i++)
    {
      if((reply = ping->ping_replies[i]) == NULL)
	continue;
      if(SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply) == 0)
	continue;
      replyc++;
      if(reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID)
	{
	  if(ipidc == 10)
	    break;
	  ipids[ipidc].ipid   = reply->reply_ipid32;
	  ipids[ipidc].tx_sec = reply->tx.tv_sec;
	  ipidc++;
	}
    }
  scamper_ping_free(ping); ping = NULL;

  if(dst->class != CLASS_INCR)
    {
      if(ipidc == 0)
	{
	  dst->class = CLASS_UNRESP;
	}
      else if(ipidc >= 3)
	{
	  if(ipid_incr(ipids, ipidc) != 0)
	    dst->class = CLASS_INCR;
	  else
	    dst->class = CLASS_RANDOM;
	}
      dst->loss = 0;
    }
  else if(ipidc > 0)
    {
      /*
       * if the IPID values are not in sequence, probe again to decide
       * if the router is still assigning values from a counter
       */
      if(ipid_inseq2(dst->last_ipid, ipids[0].ipid) == 0)
	{
	  dst->class = CLASS_NONE;
	  dst->next = now.tv_sec + 2;
	  heap_insert(heap_p1, dst);
	  freedst = 0;
	}
      dst->loss = 0;
    }
  else if(ipidc == 0)
    {
      dst->loss++;
      if(dst->loss > 10 && now.tv_sec - dst->last_rx > (24 * 60 * 60))
	{
	  dst->class = CLASS_UNRESP;
	}
    }

  logprint("%s replyc: %d ipidc: %d class: %s\n",
	   buf, replyc, ipidc, class_tostr(dst->class));

  /*
   * update the last time we received an IPID value if we got one in
   * sequence
   */
  if(ipidc > 0 && dst->class == CLASS_INCR)
    {
      dst->last_ipid = ipids[ipidc-1].ipid;
      dst->last_rx   = ipids[ipidc-1].tx_sec;
    }

  db_update(dst);

  if(freedst != 0) sc_dst_free(dst);
  return rc;
}

static int do_decoderead(void)
{
  void     *data;
  uint16_t  type;

  /* try and read a traceroute from the warts decoder */
  if(scamper_file_read(decode_in, ffilter, &type, &data) != 0)
    {
      fprintf(stderr, "%s: scamper_file_read errno %d\n", __func__, errno);
      return -1;
    }
  if(data == NULL)
    return 0;
  probing--;

  if(scamper_file_write_obj(outfile, type, data) != 0)
    {
      fprintf(stderr, "%s: could not write obj %d\n", __func__, type);
      return -1;
    }

  if(type == SCAMPER_FILE_OBJ_PING)
    return do_decoderead_ping(data);

  return -1;
}

static int do_scamperread_line(void *param, uint8_t *buf, size_t linelen)
{
  char *head = (char *)buf;
  uint8_t uu[64];
  size_t uus;
  long lo;

  /* skip empty lines */
  if(head[0] == '\0')
    return 0;

  /* if currently decoding data, then pass it to uudecode */
  if(data_left > 0)
    {
      uus = sizeof(uu);
      if(uudecode_line(head, linelen, uu, &uus) != 0)
	{
	  fprintf(stderr, "%s: could not uudecode_line\n", __func__);
	  return -1;
	}
      if(uus != 0)
	scamper_writebuf_send(decode_wb, uu, uus);
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
      if(string_isnumber(head+5) == 0 || string_tolong(head+5, &lo) != 0)
	{
	  fprintf(stderr, "%s: could not parse %s\n", __func__, head);
	  return -1;
	}
      data_left = lo;
      return 0;
    }

  /* feedback letting us know that the command was not accepted */
  if(linelen >= 3 && strncasecmp(head, "ERR", 3) == 0)
    {
      more++;
      if(do_method() != 0)
	return -1;
      return 0;
    }

  fprintf(stderr, "%s: unknown response '%s'\n", __func__, head);
  return -1;
}

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

  fprintf(stderr, "%s: could not read: %s\n", __func__, strerror(errno));
  return -1;
}

/*
 * do_scamperconnect
 *
 * allocate socket and connect to scamper process listening on the port
 * specified.
 */
static int do_scamperconnect(void)
{
  struct sockaddr *sa;
  struct sockaddr_un sun;
  struct sockaddr_in sin;
  struct in_addr in;
  socklen_t sl;

  if(options & OPT_PORT)
    {
      inet_aton("127.0.0.1", &in);
      sockaddr_compose((struct sockaddr *)&sin, AF_INET, &in, port);
      sa = (struct sockaddr *)&sin; sl = sizeof(sin);
      if((scamper_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
	  fprintf(stderr, "%s: could not allocate new socket\n", __func__);
	  return -1;
	}
    }
  else if(options & OPT_UNIX)
    {
      if(sockaddr_compose_un((struct sockaddr *)&sun, unix_name) != 0)
	{
	  fprintf(stderr, "%s: could not build sockaddr_un\n", __func__);
	  return -1;
	}
      sa = (struct sockaddr *)&sun; sl = sizeof(sun);
      if((scamper_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
	  fprintf(stderr, "%s: could not allocate unix domain socket\n",
		  __func__);
	  return -1;
	}
    }
  else return -1;

  if(connect(scamper_fd, sa, sl) != 0)
    {
      fprintf(stderr, "%s: could not connect to scamper process\n",
	      __func__);
      return -1;
    }

  if(fcntl_set(scamper_fd, O_NONBLOCK) == -1)
    {
      fprintf(stderr, "%s: could not set nonblock on scamper_fd\n", __func__);
      return -1;
    }

  return 0;
}

static int donotprobe_line(char *line, void *param)
{
  prefixtree_t *tree = param;
  prefix6_t *pf6 = NULL;
  struct in6_addr in6;
  int netlen = 128;
  long lo;
  char *netp = NULL, *lenp = NULL;
  char buf[256];

  if(line[0] == '\0' || line[0] == '#')
    return 0;

  netp = lenp = line;
  while(*lenp != '/' && *lenp != '\0')
    lenp++;
  if(*lenp == '/')
    {
      *lenp = '\0';
      lenp++;
      if(string_tolong(lenp, &lo) != 0 || lo < 1 || lo > 128)
	{
	  fprintf(stderr, "%s: invalid prefix length %s\n", __func__, lenp);
	  return -1;
	}
      netlen = lo;
    }

  if(inet_pton(AF_INET6, netp, &in6) != 1)
    {
      fprintf(stderr, "%s: could not convert %s\n", __func__, netp);
      return -1;
    }

  if(prefixtree_find_exact6(tree, &in6, netlen) != NULL)
    return 0;

  if((pf6 = prefix6_alloc(&in6, netlen, NULL)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc %s/%u\n", __func__,
	      inet_ntop(AF_INET6, &in6, buf, sizeof(buf)), netlen);
      return -1;
    }

  if(prefixtree_insert6(tree, pf6) == NULL)
    {
      fprintf(stderr, "%s: could not insert %s/%u\n", __func__,
	      inet_ntop(AF_INET6, &in6, buf, sizeof(buf)), netlen);
      return -1;
    }

  return 0;
}

static int addrfile_line(char *line, void *param)
{
  scamper_addr_t *sa = NULL;
  sc_dst_t *dst;
  char buf[256];
  int rc = -1;

  if(line[0] == '\0' || line[0] == '#')
    return 0;

  if((sa = scamper_addr_resolve(AF_INET6, line)) == NULL)
    {
      /* for now, don't abort if the input file has a malformed addr */
      fprintf(stderr, "%s: could not resolve %s\n", __func__, line);
      rc = 0;
      goto done;
    }
  if(scamper_addr_isunicast(sa) != 1)
    {
      rc = 0;
      goto done;
    }

  scamper_addr_tostr(sa, buf, sizeof(buf));

  if((dst = sc_dst_find(sa)) == NULL)
    {
      /* insert the address into the database */
      sqlite3_clear_bindings(st_addr_i);
      sqlite3_reset(st_addr_i);
      sqlite3_bind_text(st_addr_i, 1, buf, strlen(buf), SQLITE_TRANSIENT);
      sqlite3_bind_int64(st_addr_i, 2, now.tv_sec);
      if(sqlite3_step(st_addr_i) != SQLITE_DONE)
	goto done;

      /*
       * create a record of the address in the probe list as a fresh
       * to probe address, as well as in the tree to avoid duplicates
       */
      if((dst = sc_dst_alloc(sqlite3_last_insert_rowid(db), sa)) == NULL)
	goto done;
      sa = NULL;
      dst->class = CLASS_NONE;
      if(sc_dst_insert(dst) != 0)
	{
	  fprintf(stderr, "%s: could not insert %s in tree\n", __func__, buf);
	  goto done;
	}
    }
  else
    {
      sqlite3_clear_bindings(st_addr_u);
      sqlite3_reset(st_addr_u);
      sqlite3_bind_int64(st_addr_u, 1, now.tv_sec);
      sqlite3_bind_int64(st_addr_u, 2, dst->id);
      if(sqlite3_step(st_addr_u) != SQLITE_DONE)
	{
	  fprintf(stderr, "%s: could not update %s\n", __func__, buf);
	  goto done;
	}
    }

  rc = 0;

 done:
  if(sa != NULL) scamper_addr_free(sa);
  return rc;
}

/*
 * do_sqlite_state_create
 *
 * the database file is initialised to act as a probing state
 * database.
 */
static int do_sqlite_init_state(void)
{
  static const char *sql =
    "create table \"state_dsts\" ("
    "\"id\" INTEGER PRIMARY KEY, "
    "\"addr\" TEXT NOT NULL, "
    "\"class\" INTEGER NOT NULL, "
    "\"next\" INTEGER NOT NULL, "
    "\"last_tr\" INTEGER NOT NULL, "
    "\"last_ipid\" INTEGER, "
    "\"last_rx\" INTEGER, "
    "\"loss\" INTEGER)";
  char *errmsg;

  if(sqlite3_exec(db, sql, NULL, NULL, &errmsg) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not execute sql: %s\n", __func__, errmsg);
      return -1;
    }

  return 0;
}

static int do_sqlite_init_data(void)
{
  static const char *create_sql[] = {
    /* destination table */
    "create table \"data_dsts\" ("
    "\"id\" INTEGER PRIMARY KEY,"
    "\"addr\" TEXT UNIQUE NOT NULL,"
    "\"data_samples_rowid\" INTEGER NOT NULL)",
    /* file table */
    "create table \"data_files\" ("
    "\"filename\" TEXT UNIQUE NOT NULL)",
    /* sample table */
    "create table \"data_samples\" ("
    "\"id\" INTEGER PRIMARY KEY,"
    "\"dst_id\" INTEGER NOT NULL,"
    "\"data\" BLOB NOT NULL)",
    /* indexes */
    "create index data_samples_dst_id on data_samples(dst_id)",
    "create index data_files_filename on data_files(filename)",
    "create index data_dsts_addr on data_dsts(addr)",
  };
  char *errmsg;
  int i;

  for(i=0; i<sizeof(create_sql) / sizeof(char *); i++)
    {
      if(sqlite3_exec(db, create_sql[i], NULL, NULL, &errmsg) != SQLITE_OK)
	{
	  fprintf(stderr, "%s: could not execute sql: %s\n", __func__, errmsg);
	  return -1;
	}
    }

  return 0;
}

/*
 * do_sqlite_open
 *
 * open the database specified in dbfile.  Ensure the database file
 * exists before opening if OPT_CREATE is not set.
 */
static int do_sqlite_open(void)
{
  struct stat sb;
  int rc;

  /*
   * before opening the database file, check if it exists.
   * if the file does not exist, only create the dbfile if we've been told.
   */
  rc = stat(dbfile, &sb);
  if(options & OPT_CREATE)
    {
      if(rc == 0 || errno != ENOENT)
	{
	  fprintf(stderr, "%s: will not create db called %s without -c\n",
		  __func__, dbfile);
	  return -1;
	}
    }
  else
    {
      if(rc != 0)
	{
	  fprintf(stderr, "%s: db %s does not exist, use -c\n",
		  __func__, dbfile);
	  return -1;
	}
    }

  if((rc = sqlite3_open(dbfile, &db)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not open %s: %s\n",
	      __func__, dbfile, sqlite3_errstr(rc));
      return -1;
    }

  return 0;
}

static int do_sqlite_state_expire(void)
{
  static const char *sql =
    "delete from state_dsts where class != ? and last_tr != 0 and last_tr < ?";
  sqlite3_stmt *stmt = NULL;
  int x, rc = -1;

  if((x = sqlite3_prepare_v2(db,sql,strlen(sql)+1,&stmt,NULL)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n", __func__,
	      sqlite3_errstr(x));
      goto done;
    }
  sqlite3_bind_int(stmt, 1, CLASS_INCR);
  sqlite3_bind_int(stmt, 2, now.tv_sec - expire);
  if(sqlite3_step(stmt) != SQLITE_DONE)
    {
      fprintf(stderr, "%s: could not expire\n", __func__);
      goto done;
    }
  rc = 0;

 done:
  if(stmt != NULL) sqlite3_finalize(stmt);
  return rc;
}

static int do_sqlite_state(void)
{
  sqlite3_stmt *stmt = NULL;
  const unsigned char *addr;
  scamper_addr_t *sa;
  sqlite3_int64 id;
  const char *sql;
  sc_dst_t *dst;
  int next, rc = -1, x, len;

  if(expire != 0 && do_sqlite_state_expire() != 0)
    goto done;

  sql = "select next,id,addr,class,last_ipid,last_rx,loss from state_dsts";
  if((x = sqlite3_prepare_v2(db,sql,strlen(sql)+1,&stmt,NULL)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n", __func__,
	      sqlite3_errstr(x));
      goto done;
    }
  while(sqlite3_step(stmt) == SQLITE_ROW)
    {
      /*
       * if the time to probe next parameter is set, but we haven't
       * reached the timeout yet, and will not reach it during this probe
       * interval, then skip this address.
       *
       * note, this handles the new behavior where we probe addresses
       * scheduled to be probed within this interval, and the old
       * behavior where we probe addresses if they are due to be probed
       * again. i.e. :
       *
       * if((interval != 0 && now.tv_sec + interval < next) ||
       *    (interval == 0 && now.tv_sec < next))
       *
       */
      next = sqlite3_column_int(stmt, 0);
      if(next != 0 && now.tv_sec + interval < next)
	continue;

      id   = sqlite3_column_int64(stmt, 1);
      addr = sqlite3_column_text(stmt, 2);
      if((sa = scamper_addr_resolve(AF_INET6, (const char *)addr)) == NULL)
	{
	  fprintf(stderr, "%s: could not resolve %s\n", __func__, addr);
	  continue;
	}
      if(scamper_addr_isunicast(sa) != 1)
	{
	  scamper_addr_free(sa);
	  continue;
	}

      if((dst = sc_dst_alloc(id, sa)) == NULL)
	{
	  fprintf(stderr, "%s: could not malloc dst\n", __func__);
	  goto done;
	}
      sa = NULL;
      dst->next = next;
      dst->class = sqlite3_column_int(stmt, 3);
      if(dst->class == CLASS_INCR)
	{
	  dst->last_ipid = sqlite3_column_int64(stmt, 4);
	  dst->last_rx = sqlite3_column_int64(stmt, 5);
	  dst->loss = sqlite3_column_int(stmt, 6);
	}

      if(interval != 0 && next != 0)
	{
	  /*
	   * if we are probing with a defined interval, then put the
	   * destination on the heap if we have to probe it at a
	   * particular time
	   */
	  if(heap_insert(heap_p1, dst) == NULL)
	    {
	      fprintf(stderr, "%s: could not put %s on heap: %s\n",
		      __func__, addr, strerror(errno));
	      goto done;
	    }
	}
      else
	{
	  if(slist_tail_push(list, dst) == NULL)
	    {
	      fprintf(stderr, "%s: could not put %s on list: %s\n",
		      __func__, addr, strerror(errno));
	      goto done;
	    }
	}
    }
  sqlite3_finalize(stmt); stmt = NULL;

  slist_shuffle(list);

  sql = "update state_dsts set class=?,next=?,last_ipid=?,last_rx=?,loss=? "
    "where id=?";
  len = strlen(sql);
  if((x = sqlite3_prepare_v2(db, sql, len+1, &st_class, NULL)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare %s: %s\n",
	      __func__, sql, sqlite3_errstr(x));
      goto done;
    }

  rc = 0;

 done:
  if(stmt != NULL) sqlite3_finalize(stmt);
  return rc;
}

static int up_data(void)
{
  struct timeval tv, *tv_ptr, tv_next;
  fd_set rfds, wfds, *wfdsp;
  sc_dst_t *dst;
  int pair[2];
  int nfds;
  int rc = -1;

  random_seed();
  gettimeofday_wrap(&now);
  timeval_add_s(&deadline, &now, interval);

  if((list = slist_alloc()) == NULL ||
     (heap_p1 = heap_alloc((heap_cmp_t)sc_dst_next_cmp)) == NULL ||
     do_sqlite_state() != 0 || do_scamperconnect() != 0 ||
     (outfile = scamper_file_open(opt_args[0], 'w', "warts")) == NULL ||
     (scamper_wb = scamper_writebuf_alloc()) == NULL ||
     (scamper_lp = scamper_linepoll_alloc(do_scamperread_line,NULL)) == NULL ||
     (decode_wb = scamper_writebuf_alloc()) == NULL ||
     (tree = splaytree_alloc((splaytree_cmp_t)sc_dst_cmp)) == NULL ||
     socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0 ||
     (decode_in = scamper_file_openfd(pair[0], NULL, 'r', "warts")) == NULL ||
     fcntl_set(pair[0], O_NONBLOCK) == -1 ||
     fcntl_set(pair[1], O_NONBLOCK) == -1)
    return -1;

  decode_in_fd = pair[0];
  decode_out_fd = pair[1];
  scamper_writebuf_send(scamper_wb, "attach\n", 7);

  for(;;)
    {
      /*
       * need to set a timeout on select if scamper's processing window is
       * not full and there is an interface in a waiting queue.
       */
      tv_ptr = NULL;
      if(more > 0)
	{
	  gettimeofday_wrap(&now);

	  /*
	   * if there is something ready to probe now, then try and
	   * do it.  the logic is as follows:
	   * (1) anything in the p1 heap will get probed,
	   * (2) anything in the list will get probed if the deadline
	   *     has not passed
	   */
	  dst = heap_head_item(heap_p1);
	  if((dst != NULL && dst->next <= now.tv_sec) ||
	     ((interval == 0 || timeval_cmp(&now, &deadline) < 0) &&
	      slist_count(list) > 0))
	    {
	      if(do_method() != 0)
		goto done;
	    }

	  /*
	   * if we could not send a new command just yet, but scamper
	   * wants one (more > 0), then wait for an appropriate length
	   * of time.
	   */
	  dst = heap_head_item(heap_p1);
	  if(more > 0 && dst != NULL)
	    {
	      tv_next.tv_sec = dst->next; tv_next.tv_usec = 0;
	      if(timeval_cmp(&tv_next, &now) > 0)
		timeval_diff_tv(&tv, &now, &tv_next);
	      else
		memset(&tv, 0, sizeof(tv));
	      tv_ptr = &tv;
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

      /*
       * keep probing until we're done.  we're done if all of this is true:
       * (1) there are no outstanding tasks in scamper (the tree is empty)
       * (2) there is nothing in the high priority heap
       * (3) the list of things to probe is empty or the deadline has passed
       */
      if(splaytree_count(tree) == 0 && heap_count(heap_p1) == 0 &&
	 (slist_count(list) == 0 ||
	  (interval != 0 && timeval_cmp(&now, &deadline) >= 0)))
	{
	  logprint("done\n");
	  break;
	}

      if(select(nfds+1, &rfds, wfdsp, NULL, tv_ptr) < 0)
	{
	  if(errno == EINTR) continue;
	  fprintf(stderr, "%s: select error\n", __func__);
	  break;
	}

      gettimeofday_wrap(&now);

      if(more > 0 && do_method() != 0)
	goto done;

      if(scamper_fd >= 0)
	{
	  if(FD_ISSET(scamper_fd, &rfds) && do_scamperread() != 0)
	    goto done;
	  if(wfdsp != NULL && FD_ISSET(scamper_fd, wfdsp) &&
	     scamper_writebuf_write(scamper_fd, scamper_wb) != 0)
	    goto done;
	}

      if(decode_in_fd >= 0)
	{
	  if(FD_ISSET(decode_in_fd, &rfds) && do_decoderead() != 0)
	    goto done;
	}

      if(decode_out_fd >= 0)
	{
	  if(wfdsp != NULL && FD_ISSET(decode_out_fd, wfdsp) &&
	     scamper_writebuf_write(decode_out_fd, decode_wb) != 0)
	    goto done;
	}
    }

  rc = 0;

 done:
  return rc;
}

static int up_create(void)
{
  if(init_state != 0 && do_sqlite_init_state() != 0)
    return -1;
  if(init_data != 0 && do_sqlite_init_data() != 0)
    return -1;
  return 0;
}

/*
 * up_addrfile
 *
 * load the address file into memory and update the last_tr field as
 * appropriate.
 */
static int up_addrfile(void)
{
  scamper_addr_t *sa = NULL;
  sqlite3_stmt *stmt = NULL;
  sqlite3_int64 id;
  sc_dst_t *dst = NULL;
  const unsigned char *addr;
  const char *sql;
  int begun = 0, rc = -1, x;

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_dst_cmp)) == NULL)
    goto done;

  sql = "select id, addr from state_dsts";
  if((x = sqlite3_prepare_v2(db,sql,strlen(sql)+1,&stmt,NULL)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n", __func__,
	      sqlite3_errstr(x));
      goto done;
    }
  while(sqlite3_step(stmt) == SQLITE_ROW)
    {
      id   = sqlite3_column_int64(stmt, 0);
      addr = sqlite3_column_text(stmt, 1);

      /* resolve the address and make sure it is unicast */
      if((sa = scamper_addr_resolve(AF_INET6, (const char *)addr)) == NULL)
	{
	  fprintf(stderr, "%s: could not resolve %s\n", __func__, addr);
	  continue;
	}
      if(scamper_addr_isunicast(sa) != 1)
	{
	  scamper_addr_free(sa);
	  continue;
	}

      /* create state so we can map an addr to an id */
      if((dst = sc_dst_alloc(id, sa)) == NULL)
	goto done;
      sa = NULL;
      if(sc_dst_insert(dst) != 0)
	{
	  fprintf(stderr, "%s: could not insert %s\n", __func__, addr);
	  goto done;
	}
      dst = NULL;
    }
  sqlite3_finalize(stmt); stmt = NULL;

  sqlite3_exec(db, "begin", NULL, NULL, NULL); begun = 1;
  sql = "insert into state_dsts(addr,class,next,last_tr) values(?,0,0,?)";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_addr_i, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare st_addr_i: %s\n", __func__,
	      sqlite3_errstr(x));
      goto done;
    }

  sql = "update state_dsts set last_tr=? where id=?";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_addr_u, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare st_addr_u: %s\n", __func__,
	      sqlite3_errstr(x));
      goto done;
    }

  if(file_lines(opt_args[0], addrfile_line, NULL) != 0)
    goto done;

  if(expire != 0 && do_sqlite_state_expire() != 0)
    goto done;

  if(vacuum_db != 0 && do_sqlite_vacuum() != 0)
    goto done;

  rc = 0;

 done:
  if(tree != NULL)
    {
      splaytree_free(tree, (splaytree_free_t)sc_dst_free);
      tree = NULL;
    }
  if(st_addr_i != NULL) { sqlite3_finalize(st_addr_i); st_addr_i = NULL; }
  if(st_addr_u != NULL) { sqlite3_finalize(st_addr_u); st_addr_u = NULL; }
  if(begun != 0) sqlite3_exec(db, "commit", NULL, NULL, NULL);
  return rc;
}

static int up_donotprobe(void)
{
  sqlite3_stmt *st_s = NULL, *st_d = NULL;
  prefixtree_t *tree = NULL;
  const unsigned char *addr;
  struct in6_addr in6;
  sqlite3_int64 id;
  const char *sql;
  int x, rc = 1, begun = 0;

  if((tree = prefixtree_alloc6()) == NULL)
    {
      fprintf(stderr, "%s: could not alloc tree\n", __func__);
      goto done;
    }
  if(file_lines(opt_args[0], donotprobe_line, tree) != 0)
    goto done;

  sqlite3_exec(db, "begin", NULL, NULL, NULL); begun = 1;

  sql = "select id, addr from state_dsts";
  if((x = sqlite3_prepare_v2(db,sql,strlen(sql)+1,&st_s,NULL)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare select sql: %s\n", __func__,
	      sqlite3_errstr(x));
      goto done;
    }
  sql = "delete from state_dsts where id=?";
  if((x = sqlite3_prepare_v2(db,sql,strlen(sql)+1,&st_d,NULL)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare delete sql: %s\n", __func__,
	      sqlite3_errstr(x));
      goto done;
    }

  while(sqlite3_step(st_s) == SQLITE_ROW)
    {
      id   = sqlite3_column_int64(st_s, 0);
      addr = sqlite3_column_text(st_s, 1);

      if(inet_pton(AF_INET6, (const char *)addr, &in6) != 1)
	{
	  fprintf(stderr, "%s: %s is not a valid address\n", __func__, addr);
	  goto done;
	}

      if(prefixtree_find_ip6(tree, &in6) != NULL)
	{
	  sqlite3_reset(st_d);
	  sqlite3_clear_bindings(st_d);
	  sqlite3_bind_int64(st_d, 1, id);
	  if(sqlite3_step(st_d) != SQLITE_DONE)
	    {
	      fprintf(stderr, "%s: could not delete %s\n", __func__, addr);
	      goto done;
	    }
	}
    }

  if(vacuum_db != 0 && do_sqlite_vacuum() != 0)
    goto done;

  rc = 0;

 done:
  if(st_s != NULL) sqlite3_finalize(st_s);
  if(st_d != NULL) sqlite3_finalize(st_d);
  if(begun != 0) sqlite3_exec(db, "commit", NULL, NULL, NULL);
  if(tree != NULL) prefixtree_free_cb(tree, (prefix_free_t)prefix6_free);
  return rc;
}

/*
 * up_import_sample:
 *
 * blob record format
 *
 *   ipid32 from dst, 21 bytes:
 *     uint8_t  code = 1
 *     uint32_t tx_sec
 *     uint32_t tx_usec
 *     uint32_t rx_sec
 *     uint32_t rx_usec
 *     uint32_t ipid
 *
 *   reply from dst, 17 bytes:
 *     uint8_t  code = 2
 *     uint32_t tx_sec
 *     uint32_t tx_usec
 *     uint32_t rx_sec
 *     uint32_t rx_usec
 *
 *   no reply, 9 bytes:
 *     uint8_t  code = 3
 *     uint32_t tx_sec
 *     uint32_t tx_usec
 */
static int up_import_sample(sqlite3_blob *blob, uint8_t *buf,
			    uint32_t *off, uint32_t len)
{
  int x;

  x = sqlite3_blob_write(blob, buf, len, *off);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not write %d bytes at %d: %s\n",
	      __func__, len, *off, sqlite3_errstr(x));
      return -1;
    }
  *off += len;
  bytes_htonl(buf, *off);
  sqlite3_blob_write(blob, buf, 4, 0);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not update offset: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }

  return 0;
}

static int up_import_blob_new(sc_dst_t *dst, sqlite3_stmt *st_sample_ins,
			      sqlite3_stmt *st_addr_upd)
{
  int x;

  /* insert an empty blob into the database */     
  sqlite3_bind_int64(st_sample_ins, 1, dst->id);
  if((x = sqlite3_step(st_sample_ins)) != SQLITE_DONE)
    {
      fprintf(stderr, "%s: could not insert blob: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }
  dst->samples_rowid = sqlite3_last_insert_rowid(db);
  sqlite3_clear_bindings(st_sample_ins);
  sqlite3_reset(st_sample_ins);

  /* update the dst entry with the sample rowid */
  sqlite3_bind_int64(st_addr_upd, 1, dst->samples_rowid);
  sqlite3_bind_int64(st_addr_upd, 2, dst->id);
  if((x = sqlite3_step(st_addr_upd)) != SQLITE_DONE)
    {
      fprintf(stderr, "%s: could not update address: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }
  sqlite3_clear_bindings(st_addr_upd);
  sqlite3_reset(st_addr_upd);

  return 0;
}

static int up_import_blob_get(sc_dst_t *dst, sqlite3_blob **blob)
{
  int x;

  if(*blob != NULL)
    x = sqlite3_blob_reopen(*blob, dst->samples_rowid);
  else
    x = sqlite3_blob_open(db, "main", "data_samples", "data",
			  dst->samples_rowid, 1, blob);

  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not open blob: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }

  return 0;
}

static void up_import_sigint(int signo)
{
  up_import_stop = 1;
  return;
}

static int up_import(void)
{
  sqlite3_stmt *stmt = NULL;
  sqlite3_stmt *st_filename_sel = NULL;
  sqlite3_stmt *st_filename_ins = NULL;
  sqlite3_stmt *st_addr_ins = NULL;
  sqlite3_stmt *st_addr_upd = NULL;
  sqlite3_stmt *st_sample_ins = NULL;
  sqlite3_blob *blob = NULL;
  sqlite3_int64 id, samples_rowid;
  scamper_file_t *in;
  scamper_ping_t *ping;
  scamper_ping_reply_t *r;
  const unsigned char *addr;
  scamper_addr_t *sa;
  struct timeval tv;
  struct tm *tm;
  time_t t;
  const char *sql, *ptr;
  char buf[128];
  sc_dst_t *dst;
  uint16_t j, type;
  uint32_t blob_off, blob_len;
  int blob_size;
  uint8_t u8[21];
  void *data;
  char *errmsg;
  int i, c, x, rc = -1, rx;

  if(vacuum_db != 0 && do_sqlite_vacuum() != 0)
    goto done;

  if(safe_db == 0)
    {
      sqlite3_exec(db, "PRAGMA synchronous = OFF", NULL, NULL, &errmsg);
      sqlite3_exec(db, "PRAGMA journal_mode = MEMORY", NULL, NULL, &errmsg);
      if(signal(SIGINT, up_import_sigint) == SIG_ERR)
	goto done;
    }

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_dst_cmp)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc tree\n", __func__);
      goto done;
    }

  /* get a copy of all the destinations so far */
  sql = "select id, addr, data_samples_rowid from data_dsts";
  if((x = sqlite3_prepare_v2(db,sql,strlen(sql)+1,&stmt,NULL)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n",
	      __func__, sqlite3_errstr(x));
      goto done;
    }
  while((x = sqlite3_step(stmt)) == SQLITE_ROW)
    {
      id   = sqlite3_column_int64(stmt, 0);
      addr = sqlite3_column_text(stmt, 1);
      samples_rowid = sqlite3_column_int64(stmt, 2);

      if((sa = scamper_addr_resolve(AF_INET6, (const char *)addr)) == NULL)
	{
	  fprintf(stderr, "%s: could not resolve %s\n", __func__, addr);
	  goto done;
	}

      if((dst = sc_dst_alloc(id, sa)) == NULL)
	{
	  fprintf(stderr, "%s: could not malloc dst\n", __func__);
	  goto done;
	}
      dst->samples_rowid = samples_rowid;
      sa = NULL;
      if(sc_dst_insert(dst) != 0)
	{
	  fprintf(stderr, "%s: could not insert %s into tree\n",
		  __func__, addr);
	  goto done;
	}
    }
  sqlite3_finalize(stmt); stmt = NULL;

  /* prepare the sql statements */
  sql = "select filename from data_files where filename=?";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_filename_sel, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n",
	      __func__, sqlite3_errstr(x));
      goto done;
    }
  sql = "insert into data_files(filename) values(?)";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_filename_ins, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n",
	      __func__, sqlite3_errstr(x));
      goto done;
    }
  sql = "insert into data_dsts(addr, data_samples_rowid) values(?, 0)";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_addr_ins, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n",
	      __func__, sqlite3_errstr(x));
      goto done;
    }
  sql = "update data_dsts set data_samples_rowid=? where id=?";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_addr_upd, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n",
	      __func__, sqlite3_errstr(x));
      goto done;
    }

  snprintf(buf, sizeof(buf), "insert into data_samples(dst_id, data)"
	   " values(?, zeroblob(%d))", BLOB_SIZE_MIN);
  x = sqlite3_prepare_v2(db, buf, strlen(buf)+1, &st_sample_ins, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n",
	      __func__, sqlite3_errstr(x));
      goto done;
    }

  /* import all the files */
  for(i=0; i<opt_argc && up_import_stop == 0; i++)
    {
      /* check this file has not already been imported into the database */
      if((ptr = string_lastof_char(opt_args[i], '/')) == NULL)
	ptr = opt_args[i];
      else if(ptr[1] != '\0')
	ptr = ptr+1;
      else
	{
	  fprintf(stderr, "%s: invalid filename %s\n", __func__, opt_args[i]);
	  goto done;
	}

      gettimeofday_wrap(&tv);
      t = tv.tv_sec; tm = localtime(&t);
      fprintf(stderr, "[%02d:%02d:%02d] %s %d of %d\n",
	      tm->tm_hour, tm->tm_min, tm->tm_sec, opt_args[i], i, opt_argc);

      sqlite3_clear_bindings(st_filename_sel);
      sqlite3_reset(st_filename_sel);
      sqlite3_bind_text(st_filename_sel, 1, ptr, strlen(ptr), SQLITE_STATIC);
      if((x = sqlite3_step(st_filename_sel)) != SQLITE_DONE)
	{
	  if(x == SQLITE_ROW)
	    {
	      fprintf(stderr, "%s: %s already inserted\n", __func__, ptr);
	      continue;
	    }
	  fprintf(stderr, "%s: %s bad\n", __func__, ptr);
	  goto done;
	}

      if((in = scamper_file_open(opt_args[i], 'r', NULL)) == NULL)
	{
	  fprintf(stderr, "%s: could not open %s\n", __func__, opt_args[i]);
	  goto done;
	}

      c = 0;
      sqlite3_exec(db, "begin", NULL, NULL, NULL);
      while(scamper_file_read(in, ffilter, &type, &data) == 0)
	{
	  if(data == NULL)
	    break;
	  ping = data;

	  /* get dst record from database */
	  if((dst = sc_dst_find(ping->dst)) == NULL)
	    {
	      if((dst = sc_dst_alloc(0, ping->dst)) == NULL)
		{
		  fprintf(stderr, "%s: could not malloc dst\n", __func__);
		  goto done;
		}
	      scamper_addr_use(ping->dst);
	      if(sc_dst_insert(dst) != 0)
		{
		  fprintf(stderr, "%s: could not insert dst\n", __func__);
		  goto done;
		}

	      /* insert the address into the database */
	      scamper_addr_tostr(ping->dst, buf, sizeof(buf));
	      sqlite3_bind_text(st_addr_ins,1,buf,strlen(buf),SQLITE_STATIC);
	      if((x = sqlite3_step(st_addr_ins)) != SQLITE_DONE)
		{
		  fprintf(stderr, "%s: could not insert address %s: %s\n",
			  __func__, buf, sqlite3_errstr(x));
		  goto done;
		}	      
	      dst->id = sqlite3_last_insert_rowid(db);
	      sqlite3_clear_bindings(st_addr_ins);
	      sqlite3_reset(st_addr_ins);

	      if(up_import_blob_new(dst, st_sample_ins, st_addr_upd) != 0)
		goto done;
	    }

	  if(up_import_blob_get(dst, &blob) != 0)
	    goto done;
	  blob_size = sqlite3_blob_bytes(blob);
	  if((x = sqlite3_blob_read(blob, u8, 4, 0)) != SQLITE_OK)
	    {
	      fprintf(stderr, "%s: could not read 4 bytes at offset 0: %s\n",
		      __func__, sqlite3_errstr(x));
	      goto done;
	    }
	  blob_off = bytes_ntohl(u8);
	  if(blob_off == 0)
	    blob_off = 4;

	  rx = 0;
	  for(j=0; j<ping->ping_sent; j++)
	    {
	      r = ping->ping_replies[j];
	      if(r != NULL && SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(r))
		{
		  rx++;

		  timeval_add_tv3(&tv, &r->tx, &r->rtt);
		  bytes_htonl(u8+1, (uint32_t)r->tx.tv_sec);
		  bytes_htonl(u8+5, (uint32_t)r->tx.tv_usec);
		  bytes_htonl(u8+9, (uint32_t)tv.tv_sec);
		  bytes_htonl(u8+13, (uint32_t)tv.tv_usec);
		  if(r->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID)
		    {
		      u8[0] = 1;
		      bytes_htonl(u8+17, r->reply_ipid32);
		      blob_len = 21;
		    }
		  else
		    {
		      u8[0] = 2;
		      blob_len = 17;
		    }

		  if(blob_size - blob_off < blob_len)
		    {
		      if(up_import_blob_new(dst,st_sample_ins,st_addr_upd) != 0)
			goto done;
		      if(up_import_blob_get(dst, &blob) != 0)
			goto done;
		      blob_off = 4;
		    }

		  c++;
		  if(up_import_sample(blob, u8, &blob_off, blob_len) != 0)
		    goto done;
		}
	    }

	  if(rx == 0)
	    {
	      u8[0] = 3;
	      bytes_htonl(u8+1, (uint32_t)ping->start.tv_sec);
	      bytes_htonl(u8+5, (uint32_t)ping->start.tv_usec);
	      blob_len = 9;

	      if(blob_size - blob_off < blob_len)
		{
		  if(up_import_blob_new(dst,st_sample_ins,st_addr_upd) != 0)
		    goto done;
		  if(up_import_blob_get(dst, &blob) != 0)
		    goto done;
		  blob_off = 4;
		}

	      c++;
	      if(up_import_sample(blob, u8, &blob_off, blob_len) != 0)
		goto done;
	    }

	  scamper_ping_free(ping);
	}
      scamper_file_close(in);

      fprintf(stderr, "%s: %s %d samples\n", __func__, ptr, c);

      sqlite3_clear_bindings(st_filename_ins);
      sqlite3_reset(st_filename_ins);
      sqlite3_bind_text(st_filename_ins, 1, ptr, strlen(ptr), SQLITE_STATIC);
      if((x = sqlite3_step(st_filename_ins)) != SQLITE_DONE)
	{
	  fprintf(stderr, "%s: could not insert filename %s: %s\n",
		  __func__, ptr, sqlite3_errstr(x));
	  goto done;
	}

      sqlite3_blob_close(blob); blob = NULL;
      sqlite3_exec(db, "commit", NULL, NULL, NULL);
    }

  rc = 0;

 done:
  if(stmt != NULL) sqlite3_finalize(stmt);
  if(blob != NULL) sqlite3_blob_close(blob);
  if(st_filename_sel != NULL) sqlite3_finalize(st_filename_sel);
  if(st_filename_ins != NULL) sqlite3_finalize(st_filename_ins);
  if(st_addr_ins != NULL) sqlite3_finalize(st_addr_ins);
  if(st_addr_upd != NULL) sqlite3_finalize(st_addr_upd);
  if(st_sample_ins != NULL) sqlite3_finalize(st_sample_ins);
  if(rc == 0 && up_import_stop == 0)
    sqlite3_exec(db, "PRAGMA optimize", NULL, NULL, &errmsg);

  return rc;
}

static int up_reboots_arerandom(sc_sample_t **samples,int samplec, int l,int r)
{
  uint32_t posdiff_min, u32;
  double sum = 0, mean, abs;
  int posdiffc = 0;
  int i;

  if(l < 0) l = 0;
  if(r > samplec) r = samplec;
  if(r-l < 2)
    return 0;

  i = l;
  for(;;)
    {
      sum += samples[i]->ipid;
      if(i == r-1)
	break;

      if(samples[i+1]->ipid > samples[i]->ipid)
	{
	  u32 = samples[i+1]->ipid - samples[i]->ipid;
	  if(posdiffc == 0 || u32 < posdiff_min)
	    posdiff_min = u32;
	  posdiffc++;
	}
      i++;
    }

  if(posdiffc == 0)
    return 0;
  if(posdiff_min < 1000)
    return 0;
  if(r-l-1 == posdiffc)
    return 0;
  if(((double)(r-l-1)) - posdiffc / 1.0 / posdiffc > 0.5)
    return 1;

  mean = sum / (r-l);
  if(mean < 2147483648)
    abs = 2147483648 - mean;
  else
    abs = mean - 2147483648;
  if(abs < 100000)
    return 1;
  return 0;
}

/*
 * up_reboots_init
 *
 *
 */
static int up_reboots_init(slist_t *list, sc_sample_t ***out, int *outc)
{
  sc_sample_t **samples = NULL, *sample;
  slist_node_t *sn, *s2;
  int i, samplec = 0;

  *out = NULL;
  *outc = 0;
  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
    {
      sample = slist_node_item(sn);
      if((s2 = slist_node_next(sn)) != NULL)
	sample->next = slist_node_item(s2);
      else
	sample->next = NULL;
      if(sample->type == 1)
	samplec++;
    }
  if(samplec < 10)
    return 0;

  if((samples = malloc_zero(sizeof(sc_sample_t *) * (samplec))) == NULL)
    return -1;

  i = 0;
  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
    {
      sample = slist_node_item(sn);
      if(sample->type == 1)
	samples[i++] = sample;
    }

  *out = samples;
  *outc = samplec;
  return 0;  
}

static void sc_ipidseq_free(sc_ipidseq_t *seq)
{
  if(seq->samples != NULL) free(seq->samples);
  free(seq);
  return;
}

static int up_reboots_seqs_make(slist_t *seqs, sc_sample_t **samples,
				int l, int r)
{
  sc_ipidseq_t *seq = NULL;
  double sample_velocity;
  uint32_t ipid, last_ipid, tx, last_tx;
  int i;

  if((seq = malloc_zero(sizeof(sc_ipidseq_t))) == NULL ||
     (seq->samples = malloc(sizeof(sc_sample_t) * (r - l))) == NULL ||
     slist_tail_push(seqs, seq) == NULL)
    goto err;

  for(i=0; i<r-l; i++)
    seq->samples[i] = samples[l+i];
  seq->samplec = r - l;
  seq->velocity = 0;

  if(up_reboots_arerandom(seq->samples, seq->samplec, 0, seq->samplec) == 1)
    {
      seq->type = 1;
      return 0;
    }

  if(seq->samplec < 4)
    {
      seq->type = 3;
      return 0;
    }

  /* compute velocity for the time series */
  seq->type = 0;
  for(i=1; i<seq->samplec; i++)
    {
      tx = seq->samples[i]->tx_sec; ipid = seq->samples[i]->ipid;
      last_tx = seq->samples[i-1]->tx_sec; last_ipid = seq->samples[i-1]->ipid;
      sample_velocity = 0.01;
      if(tx > last_tx && ipid > last_ipid)
	sample_velocity = ((double)(ipid - last_ipid)) / (tx - last_tx);
      seq->velocity = (0.8 * seq->velocity) + (0.2 * sample_velocity);
    }

  return 0;

 err:
  if(seq != NULL) sc_ipidseq_free(seq);
  return -1;      
}

static int up_reboots_seqs_class_reseed(slist_t *seqs)
{
  slist_t *series = NULL;
  sc_ipidseq_t *seq;
  slist_node_t *sn;
  int rc = -1;

  if((series = slist_alloc()) == NULL)
    goto done;

  for(sn=slist_head_node(seqs); sn != NULL; sn=slist_node_next(sn))
    {
      seq = slist_node_item(sn);
      if(seq->type != 0 ||
	 seq->samples[seq->samplec-1]->tx_sec - seq->samples[0]->tx_sec > 60)
	{
	  if(slist_count(series) >= 10)
	    while((seq = slist_head_pop(series)) != NULL)
	      seq->type = 2;
	  slist_empty(series);
	  continue;
	}
      if(seq->type == 0 && slist_tail_push(series, seq) == NULL)
	goto done;
    }

  if(slist_count(series) >= 10)
    while((seq = slist_head_pop(series)) != NULL)
      seq->type = 2;
  rc = 0;

 done:
  if(series != NULL) slist_free(series);
  return rc;
}

static void up_reboots_seqs_merge_wrap32(slist_t *seqs)
{
  uint32_t last_tx, last_ipid, tx, ipid;
  uint64_t max_expected_ipid;
  sc_ipidseq_t *seq, *seq_next;
  slist_node_t *sn, *sn_next;

  /*
   * merge sequences where the IPID value is implemented with a 32 bit
   * counter, and the counter wraps.
   */
  for(sn=slist_head_node(seqs); sn != NULL; sn=slist_node_next(sn))
    {
      seq = slist_node_item(sn);
      if(seq->type != 0)
	continue;
      if((sn_next = slist_node_next(sn)) == NULL)
	break;
      seq_next = slist_node_item(sn_next);

      last_tx = seq->samples[seq->samplec-1]->tx_sec;
      last_ipid = seq->samples[seq->samplec-1]->ipid;
      tx = seq_next->samples[0]->tx_sec;
      ipid = seq_next->samples[0]->ipid;
      max_expected_ipid = last_ipid + ((tx-last_tx) * 10 * seq->velocity);
      if(max_expected_ipid >= 0xFFFFFFFFULL &&
	 (max_expected_ipid & 0xFFFFFFFFULL) > ipid)
	{
	  seq->next = seq_next;
	  seq_next->prev = seq;
	}
    }

  return;
}

/*
 * up_reboots_seqs_merge_wrap16:
 *
 * merge sequences where the IPID value is implemented with a 16 bit
 * counter, the counter wraps, but the counter is slow moving.  we do
 * this by maintaining a window of the most recent three sequences to
 * get some confidence the limit is 65536 (actually a 17 bit value)
 */
static void up_reboots_seqs_merge_wrap16(slist_t *seqs)
{
  uint32_t last_tx, last_ipid, tx, ipid;
  uint64_t max_expected_ipid;
  sc_ipidseq_t *seq, *seq_prev, *seq_next;
  slist_node_t *sn, *sn_prev, *sn_next;

  if((sn_prev = slist_head_node(seqs)) == NULL)
    return;

  sn = slist_node_next(sn_prev);
  while(sn != NULL)
    {
      if((sn_next = slist_node_next(sn)) == NULL)
	break;
      seq_prev = slist_node_item(sn_prev);
      seq      = slist_node_item(sn);
      seq_next = slist_node_item(sn_next);
      sn_prev = sn; sn = sn_next;

      /* the wrap point must be smaller than a 16 bit integer */
      if(seq->type != 0 ||
	 seq_prev->samples[seq_prev->samplec-1]->ipid > 65535 ||
	 seq->samples[seq->samplec-1]->ipid > 65535)
	continue;

      last_ipid = seq_prev->samples[seq_prev->samplec-1]->ipid;
      last_tx = seq_prev->samples[seq_prev->samplec-1]->tx_sec;
      ipid = seq->samples[0]->ipid;
      tx = seq->samples[0]->tx_sec;
      max_expected_ipid = last_ipid + ((tx-last_tx)*2*seq_prev->velocity);
      if(max_expected_ipid < 65535 ||
	 max_expected_ipid - last_ipid > 10000 ||
	 max_expected_ipid < ipid + 0xFFFFUL)
	continue;

      last_ipid = seq->samples[seq->samplec-1]->ipid;
      last_tx = seq->samples[seq->samplec-1]->tx_sec;
      ipid = seq_next->samples[0]->ipid;
      tx = seq_next->samples[0]->tx_sec;
      max_expected_ipid = last_ipid + ((tx-last_tx) * 2 * seq->velocity);
      if(max_expected_ipid < 65535 ||
	 max_expected_ipid - last_ipid > 10000 ||
	 max_expected_ipid < ipid + 0xFFFFUL)
	continue;

      seq_prev->next = seq;
      seq->prev = seq_prev;
      seq->next = seq_next;
      seq_next->prev = seq;
    }

  return;
}

/*
 * up_reboots_seqs_merge_parallel:
 *
 * merge sequences where IPID samples appear to have been derived
 * from multiple counters.
 */
static int up_reboots_seqs_merge_parallel(slist_t *seqs)
{
  uint32_t last_tx, last_ipid, tx, ipid;
  uint64_t max_expected_ipid;
  sc_ipidseq_t *seq, *seq_prev;
  slist_node_t *sn;
  dlist_node_t *dn, *dn_next;
  dlist_t *ctrs = NULL;

  if((ctrs = dlist_alloc()) == NULL)
    return -1;
  for(sn=slist_head_node(seqs); sn != NULL; sn=slist_node_next(sn))
    {
      seq = slist_node_item(sn);
      if(seq->type != 0)
	continue;

      tx = seq->samples[0]->tx_sec;
      ipid = seq->samples[0]->ipid;
      for(dn=dlist_head_node(ctrs); dn != NULL; dn=dlist_node_next(dn))
	{
	  seq_prev = dlist_node_item(dn);
	  last_tx = seq_prev->samples[seq_prev->samplec-1]->tx_sec;
	  last_ipid = seq_prev->samples[seq_prev->samplec-1]->ipid;
	  max_expected_ipid = last_ipid + ((tx-last_tx)*10*seq_prev->velocity);
	  if((last_ipid > ipid && last_ipid - ipid < fudge && ipid > fudge) ||
	     (ipid > last_ipid && ipid < max_expected_ipid + fudge))
	    {
	      seq_prev->next = seq;
	      seq->prev = seq_prev;
	      dlist_node_pop(ctrs, dn);
	      break;
	    }
	}
      dlist_tail_push(ctrs, seq);

      /*
       * eject any sequences where the last IPID value was sampled
       * more than two days ago
       */
      dn = dlist_head_node(ctrs);
      while(dn != NULL)
	{
	  dn_next = dlist_node_next(dn);
	  seq_prev = dlist_node_item(dn);
	  if(seq_prev->samples[seq_prev->samplec-1]->tx_sec + (48*60*60) < tx)
	    dlist_node_pop(ctrs, dn);
	  dn = dn_next;
	}
    }
  dlist_free(ctrs);

  return 0;
}

static slist_t *up_reboots_seqs(sc_sample_t **samples, int samplec)
{
  uint32_t last_tx, last_ipid, tx, ipid;
  double velocity = 0, sample_velocity;
  uint64_t max_expected_ipid;
  slist_t *seqs = NULL;
  int random = 0;
  int l, i;

  /* infer how the router assigns IPID values */
  if(up_reboots_arerandom(samples, samplec, 0, 5) == 1)
    random = 1;

  l = 0;

  if((seqs = slist_alloc()) == NULL)
    goto err;

  last_tx = samples[0]->tx_sec;
  last_ipid = samples[0]->ipid;
  for(i=1; i <= samplec; i++)
    {
      /* include the last sequence of IPID values and then we're done */
      if(i == samplec)
	{
	  if(up_reboots_seqs_make(seqs, samples, l, i) != 0)
	    goto err;
	  break;
	}

      tx = samples[i]->tx_sec;
      ipid = samples[i]->ipid;

      /* check if the random sequence continues */
      if(random == 1)
	{
	  if(up_reboots_arerandom(samples, samplec, i, i+5) == 0)
	    {
	      if(up_reboots_seqs_make(seqs, samples, l, i) != 0)
		goto err;
	      l = i;
	      random = 0;
	      last_tx = tx;
	      last_ipid = ipid;
	    }
	  continue;
	}

      sample_velocity = 0.01;
      if(tx > last_tx && ipid > last_ipid)
	sample_velocity = ((double)(ipid - last_ipid)) / (tx - last_tx);
      max_expected_ipid = last_ipid + ((tx-last_tx) * 10 * velocity);

      if(ipid < last_ipid || ipid > max_expected_ipid + fudge)
	{
	  if(up_reboots_seqs_make(seqs, samples, l, i) != 0)
	    goto err;
	  if(up_reboots_arerandom(samples, samplec, i, i+5) == 1)
	    random = 1;
	  l = i;
	}
      else
	{
	  velocity = (0.8 * velocity) + (0.2 * sample_velocity);
	}

      last_tx = tx;
      last_ipid = ipid;
    }

  if(up_reboots_seqs_class_reseed(seqs) != 0)
    goto err;
  up_reboots_seqs_merge_wrap32(seqs);
  up_reboots_seqs_merge_wrap16(seqs);
  if(up_reboots_seqs_merge_parallel(seqs) != 0)
    goto err;

  return seqs;

 err:
  if(seqs != NULL) slist_free_cb(seqs, (slist_free_t)sc_ipidseq_free);
  return NULL;
}

static int ptrcmp(const void *a, const void *b)
{
  if(a < b) return -1;
  if(a > b) return  1;
  return 0;
}

static int up_reboots_doone(sc_dst_t *dst, slist_t *samplist, slist_t *reboots)
{
  splaytree_t *tree = NULL;
  sc_sample_t **samples = NULL;
  sc_ipidseq_t *seq, *seq_last = NULL;
  slist_node_t *sn;
  sc_reboot_t *reboot;
  int samplec = 0;
  slist_t *seqs = NULL;
  uint32_t tx, last_tx;

  if(up_reboots_init(samplist, &samples, &samplec) != 0)
    goto err;
  if(samples == NULL)
    return 0;
  if((tree = splaytree_alloc(ptrcmp)) == NULL)
    goto err;
  if((seqs = up_reboots_seqs(samples, samplec)) == NULL)
    goto err;

  for(sn=slist_head_node(seqs); sn != NULL; sn=slist_node_next(sn))
    {
      seq = slist_node_item(sn);

      /* if this sequence ends here, remove it */
      if(splaytree_find(tree, seq) != NULL)
	splaytree_remove_item(tree, seq);

      /* if sequence is contained within a continuous sequence, no reboot */
      if(splaytree_count(tree) != 0)
	goto next;

      /* if a sequence ended here, then no reboot */
      if(seq->prev != NULL)
	goto next;
      
      /*
       * both the current and previous sequences must be assigned from
       * a counter to infer a reboot
       */
      if(seq->type != 0 || seq_last == NULL || seq_last->type != 0)
	goto next;

      /*
       * make sure the difference in sample times is enough for a reboot
       * to have occurred, and that the difference in sample times was
       * not absurdedly large.
       */
      last_tx = seq_last->samples[seq_last->samplec-1]->tx_sec;
      tx = seq->samples[0]->tx_sec;
      if(tx - last_tx < 60 || tx - last_tx > (7 * 24 * 60 * 60))
	goto next;

      if((reboot = malloc(sizeof(sc_reboot_t))) == NULL)
	goto err;
      reboot->left = last_tx;
      reboot->right = tx;
      if(slist_tail_push(reboots, reboot) == NULL)
	{
	  free(reboot);
	  goto err;
	}

    next:
      if(seq->next != NULL && splaytree_insert(tree, seq->next) == NULL)
	goto err;
      seq_last = seq;
    }
  return 0;

 err:
  if(seqs != NULL) slist_free_cb(seqs, (slist_free_t)sc_ipidseq_free);
  if(samples != NULL) free(samples);
  return -1;
}

static int sc_sample_cmp(const sc_sample_t *a, const sc_sample_t *b)
{
  if(a->tx_sec < b->tx_sec) return -1;
  if(a->tx_sec > b->tx_sec) return  1;
  if(a->rx_sec < b->rx_sec) return -1;
  if(a->rx_sec > b->rx_sec) return  1;
  if(a->type > b->type) return -1;
  if(a->type < b->type) return  1;
  if(a->ipid < b->ipid) return -1;
  if(a->ipid > b->ipid) return  1;
  return 0;
}

static void up_reboots_samples_dumpone(sc_sample_t *sample)
{
  struct tm *tm;
  uint32_t rtt;
  time_t t;

  t = sample->tx_sec; tm = gmtime(&t);
  printf("%04d%02d%02d %02d:%02d:%02d:%03d",
	 tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	 tm->tm_hour, tm->tm_min, tm->tm_sec, sample->tx_usec / 1000);

  if(sample->type == 1 || sample->type == 2)
    {
      rtt = ((sample->rx_sec - sample->tx_sec) * 1000) +
	(sample->rx_usec / 1000) - (sample->tx_usec / 1000);
      printf(" %u", rtt);
      if(sample->type == 1)
	printf(" %u", sample->ipid);
      else
	printf(" - ");
    }
  else
    {
      printf(" -");
    }
  printf("\n");
  return;
}

static void up_reboots_samples_dump(slist_t *samplist)
{
  sc_sample_t **samples = NULL;
  sc_ipidseq_t *seq;
  slist_t *seqs = NULL;
  slist_node_t *sn;
  sc_sample_t *s, *last_s = NULL;
  int samplec = 0;

  if(up_reboots_init(samplist, &samples, &samplec) != 0)
    return;
  if(samples == NULL)
    return;
  if((seqs = up_reboots_seqs(samples, samplec)) == NULL)
    return;

  /* print any probes sent prior to the first inferred sequence */
  seq = slist_head_item(seqs);
  for(sn=slist_head_node(samplist); sn != NULL; sn=slist_node_next(sn))
    {
      s = slist_node_item(sn);
      if(seq != NULL && s == seq->samples[0])
	break;
      up_reboots_samples_dumpone(s);
      last_s = s;
    }

  for(sn=slist_head_node(seqs); sn != NULL; sn=slist_node_next(sn))
    {
      seq = slist_node_item(sn);
      printf("## %d %d %.3f\n", seq->samplec, seq->type, seq->velocity);
      if(seq->prev != NULL)
	{
	  printf(" prev: ");
	  up_reboots_samples_dumpone(seq->prev->samples[seq->prev->samplec-1]);
	}

      /*
       * print out any samples between the previous sequence ending and
       * this sequence starting
       */
      if(last_s != NULL)
	for(s=last_s->next; s != seq->samples[0]; s=s->next)
	  up_reboots_samples_dumpone(s);

      /* print out all samples in this sequence */
      for(s=seq->samples[0]; s != seq->samples[seq->samplec-1]; s=s->next)
	up_reboots_samples_dumpone(s);
      up_reboots_samples_dumpone(seq->samples[seq->samplec-1]);
      last_s = seq->samples[seq->samplec-1];

      if(seq->next != NULL)
	{
	  printf(" next: ");
	  up_reboots_samples_dumpone(seq->next->samples[0]);
	}
    }

  /* print any probes sent after the last inferred sequence */
  if(seq != NULL)
    {
      for(s=seq->samples[seq->samplec-1]->next; s != NULL; s=s->next)
	up_reboots_samples_dumpone(s);
    }

  slist_free_cb(seqs, (slist_free_t)sc_ipidseq_free);
  return;
}

/*
 * up_reboots
 *
 * test cases:
 * 1. 2001:128c:53f:2::2  (cyclic reboot)
 * 2. large fudge b/c of things like 2a01:3e0:fff0:400::22
 * 3. 2001:1a68:a:3000::136 (fast moving counter)
 * 4. 2001:7f8:1::a500:6730:1 (16bit counter)
 *    2001:3b8:101:20:202:213:193:52 (16bit counter)
 * 5. 2001:49d0:180::6 (multiple counters?)
 *    2001:67c:3fc::7 (multiple counters, small difference)
 * 6. 2001:7f8:1f::4:4134:31:0 (counter wrap)
 * 7. 2001:df0:ce:205::1 (new seed with each new fragment sequence)
      2001:df0:ce:220::1
 */
static int up_reboots(void)
{
  slist_t *addrs = NULL;
  slist_t *samples = NULL;
  slist_t *reboots = NULL;
  sqlite3_stmt *st = NULL;
  sqlite3_blob *blob = NULL;
  sc_sample_t *sample;
  sc_reboot_t *reboot;
  const char *sql, *ptr;
  const unsigned char *addr;
  uint8_t *u8 = NULL;
  int blob_size, blob_bytec = 0;
  char buf[256];
  sc_dst_t *dst;
  scamper_addr_t *sa = NULL;
  uint32_t id;
  uint32_t tx_sec, tx_usec, rx_sec, rx_usec, ipid;
  uint8_t type;
  sqlite3_int64 sample_id;
  uint32_t blob_off, blob_len;
  int i, x, rc = -1;

  if((addrs = slist_alloc()) == NULL)
    goto done;

  if(opt_argc > 0)
    {
      sql = "select id from data_dsts where addr=?";
      x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st, NULL);
      if(x != SQLITE_OK)
	{
	  fprintf(stderr, "%s: could not prepare sql: %s\n",
		  __func__, sqlite3_errstr(x));
	  goto done;
	}
      for(i=0; i<opt_argc; i++)
	{
	  sqlite3_clear_bindings(st);
	  sqlite3_reset(st);
	  ptr = opt_args[i];
	  sqlite3_bind_text(st, 1, ptr, strlen(ptr), SQLITE_STATIC);
	  if((x = sqlite3_step(st)) != SQLITE_ROW)
	    {
	      fprintf(stderr, "%s: %s not in %s\n", __func__, ptr, dbfile);
	      goto done;
	    }
	  if((sa = scamper_addr_resolve(AF_INET6, ptr)) == NULL)
	    {
	      fprintf(stderr, "%s: %s not an ipv6 address\n", __func__, ptr);
	      goto done;
	    }
	  id = sqlite3_column_int64(st, 0);
	  if((dst = sc_dst_alloc(id, sa)) == NULL)
	    {
	      fprintf(stderr, "%s: could not malloc dst %s\n", __func__, ptr);
	      goto done;
	    }
	  sa = NULL;
	  if(slist_tail_push(addrs, dst) == NULL)
	    {
	      fprintf(stderr, "%s: could not push %s to list\n", __func__, ptr);
	      sc_dst_free(dst);
	      goto done;
	    }
	}
    }
  else
    {
      sql = "select id, addr from data_dsts";
      x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st, NULL);
      if(x != SQLITE_OK)
	{
	  fprintf(stderr, "%s: could not prepare sql: %s\n",
		  __func__, sqlite3_errstr(x));
	  goto done;
	}

      while((x = sqlite3_step(st)) == SQLITE_ROW)
	{
	  addr = sqlite3_column_text(st, 1);
	  if((sa = scamper_addr_resolve(AF_INET6, (const char *)addr)) == NULL)
	    {
	      fprintf(stderr, "%s: %s not an ipv6 address\n", __func__, addr);
	      goto done;
	    }
	  id = sqlite3_column_int64(st, 0);
	  if((dst = sc_dst_alloc(id, sa)) == NULL)
	    {
	      fprintf(stderr, "%s: could not malloc dst %s\n", __func__, addr);
	      goto done;
	    }
	  sa = NULL;
	  if(slist_tail_push(addrs, dst) == NULL)
	    {
	      fprintf(stderr, "%s: could not push %s to list\n",
		      __func__, addr);
	      sc_dst_free(dst);
	      goto done;
	    }
	}
    }
  sqlite3_finalize(st); st = NULL;

  if((samples = slist_alloc()) == NULL)
    {
      fprintf(stderr, "%s: could not alloc samples list\n", __func__);
      goto done;
    }
  if((reboots = slist_alloc()) == NULL)
    {
      fprintf(stderr, "%s: could not alloc reboots list\n", __func__);
      goto done;
    }

  sql = "select id from data_samples where dst_id=? order by id";
  if((x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st, NULL)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n",
	      __func__, sqlite3_errstr(x));
      goto done;
    }
  while((dst = slist_head_pop(addrs)) != NULL)
    {
      scamper_addr_tostr(dst->addr, buf, sizeof(buf));
      sqlite3_clear_bindings(st);
      sqlite3_reset(st);
      sqlite3_bind_int(st, 1, dst->id);

      while((x = sqlite3_step(st)) == SQLITE_ROW)
	{
	  sample_id = sqlite3_column_int64(st, 0);

	  if(blob != NULL)
	    x = sqlite3_blob_reopen(blob, sample_id);
	  else
	    x = sqlite3_blob_open(db, "main", "data_samples", "data",
				  sample_id, 0, &blob);
	  if(x != SQLITE_OK)
	    {
	      fprintf(stderr, "%s: could not open blob %lld for %s: %s\n",
		      __func__, sample_id, buf, sqlite3_errstr(x));
	      goto done;
	    }
	  if((blob_size = sqlite3_blob_bytes(blob)) > blob_bytec)
	    {
	      if(realloc_wrap((void **)&u8, blob_size) != 0)
		{
		  fprintf(stderr, "%s: could not realloc %d bytes for %s: %s\n",
			  __func__, blob_size, buf, strerror(errno));
		  goto done;
		}
	      blob_bytec = blob_size;
	    }

	  if((x = sqlite3_blob_read(blob, u8, blob_size, 0)) != SQLITE_OK)
	    {
	      fprintf(stderr, "%s: could not read blob: %s\n",
		      __func__, sqlite3_errstr(x));
	      goto done;
	    }

	  blob_off = 4;
	  blob_len = bytes_ntohl(u8);
	  if(blob_len < blob_off)
	    {
	      fprintf(stderr, "%s: really short blob %u\n", __func__, blob_len);
	      goto done;
	    }

	  for(;;)
	    {
	      if(blob_off == blob_len)
		break;
	      if(blob_len - blob_off < 9)
		{
		  fprintf(stderr, "%s: short blob: %u\n", __func__,
			  blob_len - blob_off);
		  goto done;
		}
	      type = u8[blob_off];
	      tx_sec = bytes_ntohl(u8 + blob_off + 1);
	      tx_usec = bytes_ntohl(u8 + blob_off + 5);
	      rx_sec = rx_usec = ipid = 0;

	      if(type == 1)
		{
		  if(blob_len - blob_off < 21)
		    {
		      fprintf(stderr, "%s: short type %d blob\n",
			      __func__, type);
		      goto done;
		    }
		  rx_sec = bytes_ntohl(u8 + blob_off + 9);
		  rx_usec = bytes_ntohl(u8 + blob_off + 13);
		  ipid = bytes_ntohl(u8 + blob_off + 17);
		  blob_off += 21;
		}
	      else if(type == 2)
		{
		  if(blob_len - blob_off < 17)
		    {
		      fprintf(stderr, "%s: short type %d blob\n",
			      __func__, type);
		      goto done;
		    }
		  rx_sec = bytes_ntohl(u8 + blob_off + 9);
		  rx_usec = bytes_ntohl(u8 + blob_off + 13);
		  blob_off += 17;
		}
	      else if(type == 3)
		{
		  if(blob_len - blob_off < 9)
		    {
		      fprintf(stderr, "%s: short type %d blob\n",
			      __func__, type);
		      goto done;
		    }
		  blob_off += 9;
		}
	      else
		{
		  fprintf(stderr, "%s: unknown blob type %d\n",
			  __func__, type);
		  goto done;
		}

	      if((sample = malloc(sizeof(sc_sample_t))) == NULL)
		{
		  fprintf(stderr, "%s: could not malloc sample\n", __func__);
		  goto done;
		}
	      sample->type = type;
	      sample->tx_sec = tx_sec;
	      sample->tx_usec = tx_usec;
	      sample->rx_sec = rx_sec;
	      sample->rx_usec = rx_usec;
	      sample->ipid = ipid;
	      if(slist_tail_push(samples, sample) == NULL)
		{
		  fprintf(stderr, "%s: could not push sample\n", __func__);
		  goto done;
		}
	    }
	}

      slist_qsort(samples, (slist_cmp_t)sc_sample_cmp);
      if(verbose != 0)
	up_reboots_samples_dump(samples);
      up_reboots_doone(dst, samples, reboots);
      while((sample = slist_head_pop(samples)) != NULL)
	free(sample);
      if(slist_count(reboots) > 0)
	{
	  printf("%s", scamper_addr_tostr(dst->addr, buf, sizeof(buf)));
	  while((reboot = slist_head_pop(reboots)) != NULL)
	    {
	      printf(" %u,%u", reboot->left, reboot->right);
	      free(reboot);
	    }
	  printf("\n");
	  fflush(stdout);
	}

      sc_dst_free(dst);
    }
  rc = 0;

 done:
  if(blob != NULL) sqlite3_blob_close(blob);
  sqlite3_finalize(st);
  if(reboots != NULL) slist_free(reboots);
  if(samples != NULL) slist_free(samples);
  if(addrs != NULL) slist_free(addrs);
  return rc;
}

static int up_init(void)
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_PING};
  int typec = sizeof(types) / sizeof(uint16_t);
  if((ffilter = scamper_file_filter_alloc(types, typec)) == NULL)
    return -1;
  if(do_sqlite_open() != 0)
    return -1;
  return 0;
}

static void cleanup(void)
{
  if(tree != NULL) splaytree_free(tree, (splaytree_free_t)sc_dst_free);
  if(list != NULL) slist_free_cb(list, (slist_free_t)sc_dst_free);
  if(heap_p1 != NULL) heap_free(heap_p1, (heap_free_t)sc_dst_free);
  if(scamper_wb != NULL) scamper_writebuf_free(scamper_wb);
  if(scamper_lp != NULL) scamper_linepoll_free(scamper_lp, 0);
  if(decode_wb != NULL) scamper_writebuf_free(decode_wb);
  if(outfile != NULL) scamper_file_close(outfile);
  if(decode_in != NULL) scamper_file_close(decode_in);
  if(ffilter != NULL) scamper_file_filter_free(ffilter);
  if(logfile != NULL) fclose(logfile);
  if(st_class != NULL) sqlite3_finalize(st_class);
  if(db != NULL) sqlite3_close(db);
  if(decode_in_fd != -1) close(decode_in_fd);
  if(decode_out_fd != -1) close(decode_out_fd);
  if(scamper_fd != -1) close(scamper_fd);
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

  if(up_init() != 0)
    return -1;

  if(options & OPT_CREATE)
    return up_create();

  if(options & OPT_ADDRFILE)
    return up_addrfile();

  if(options & OPT_DONOTPROBE)
    return up_donotprobe();

  if(options & OPT_IMPORT)
    return up_import();

  if(options & OPT_REBOOTS)
    return up_reboots();

  return up_data();
}
