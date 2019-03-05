/*
 * sc_uptime: system to probe routers to identify reboot events
 *
 * $Id: sc_uptime.c,v 1.18 2018/01/26 07:11:48 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2015 The Regents of the University of California
 * Copyright (C) 2017 Matthew Luckie
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
  "$Id: sc_uptime.c,v 1.18 2018/01/26 07:11:48 mjl Exp $";
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
#include "mjl_patricia.h"
#include "mjl_heap.h"
#include "utils.h"

#define OPT_HELP        0x0001
#define OPT_DBFILE      0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008
#define OPT_UNIX        0x0010
#define OPT_LOG         0x0020
#define OPT_ADDRFILE    0x0100
#define OPT_OPTIONS     0x0200
#define OPT_SRCADDR     0x0400
#define OPT_IMPORT      0x0800
#define OPT_REBOOTS     0x1000
#define OPT_ALL         0xffff

static patricia_t            *tree          = NULL;
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
static char                  *addrfile      = NULL;
static char                  *outfile_name  = NULL;
static char                  *srcaddr       = NULL;
static scamper_file_t        *outfile       = NULL;
static scamper_file_filter_t *ffilter       = NULL;
static int                    data_left     = 0;
static int                    more          = 0;
static int                    probing       = 0;
static int                    fudge         = 65535;
static int                    create_db     = 0;
static int                    safe_db       = 0;
static int                    vacuum_db     = 0;
static struct timeval         now;
static FILE                  *logfile       = NULL;
static heap_t                *waiting       = NULL;
static sqlite3               *db            = NULL;
static sqlite3_stmt          *st_class      = NULL;
static char                 **opt_args      = NULL;
static int                    opt_argc      = 0;

#define CLASS_NONE    0
#define CLASS_UNRESP  1
#define CLASS_RANDOM  2
#define CLASS_INCR    3

typedef struct sc_dst
{
  sqlite3_int64     id;
  scamper_addr_t   *addr;
  int               class;
  uint8_t           flags;
  uint32_t          last_ipid;
  uint32_t          last_tx;
  int               loss;
  patricia_node_t  *tree_node;
} sc_dst_t;

typedef struct sc_ipid
{
  uint32_t      tx;
  uint32_t      ipid;
} sc_ipid_t;

typedef struct sc_reboot
{
  uint32_t      left;
  uint32_t      right;
} sc_reboot_t;

typedef struct sc_wait
{
  struct timeval  tv;
  sc_dst_t       *dst;
} sc_wait_t;

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
    "usage: sc_uptime [-a addrfile] [-d dbfile] [-l log] [-o outfile]\n"
    "                 [-O option] [-p port] [-S srcaddr] [-U unix]\n"
    "\n"
    "       sc_uptime [-i] [-d dbfile] [-O option] file.warts\n"
    "\n"
    "       sc_uptime [-r] [-d dbfile] [-O option] [ip1 .. ipN]\n"
    "\n");

  if(opt_mask == 0)
    fprintf(stderr, "       sc_uptime -?\n\n");

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "   -? give an overview of the usage of sc_uptime\n");

  if(opt_mask & OPT_ADDRFILE)
    fprintf(stderr, "   -a input address file\n");

  if(opt_mask & OPT_DBFILE)
    fprintf(stderr, "   -d sqlite db file\n");

  if(opt_mask & OPT_IMPORT)
    fprintf(stderr, "   -i import samples into database\n");
  
  if(opt_mask & OPT_LOG)
    fprintf(stderr, "   -l output logfile\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "   -o output warts file\n");

  if(opt_mask & OPT_OPTIONS)
    {
      fprintf(stderr, "   -O options\n");
      fprintf(stderr, "      create-db: initialise sqlite3 database\n");
      fprintf(stderr, "      safe-db: use safe sqlite3 operations\n");
      fprintf(stderr, "      vacuum-db: vacuum the database before use\n");
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
  char *opts = "?a:d:il:o:O:p:rS:U:";
  char *opt_port = NULL, *opt_unix = NULL, *opt_log = NULL;
  char *opt_srcaddr = NULL, *opt_dbfile = NULL;
  long lo;
  int ch;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'a':
	  options |= OPT_ADDRFILE;
	  addrfile = optarg;
	  break;

	case 'd':
	  options |= OPT_DBFILE;
	  opt_dbfile = optarg;
	  break;

	case 'i':
	  options |= OPT_IMPORT;
	  break;

	case 'l':
	  options |= OPT_LOG;
	  opt_log = optarg;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  outfile_name = optarg;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "create-db") == 0)
	    create_db = 1;
	  else if(strcasecmp(optarg, "safe-db") == 0)
	    safe_db = 1;
	  else if(strcasecmp(optarg, "vacuum-db") == 0)
	    vacuum_db = 1;
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

	case '?':
	default:
	  usage(OPT_ALL);
	  return -1;
	}
    }

  if(options == 0 ||
     countbits32(options & (OPT_IMPORT|OPT_REBOOTS|OPT_OUTFILE)) != 1)
    {
      usage(0);
      return -1;
    }

  if(create_db != 0 && vacuum_db != 0)
    {
      usage(OPT_OPTIONS);
      return -1;
    }

  /* importing warts files into a database */
  if(options & OPT_IMPORT)
    {
      if((options & OPT_DBFILE) == 0)
	{
	  usage(OPT_DBFILE|OPT_IMPORT);
	  return -1;
	}
      dbfile = opt_dbfile;
      if(argc - optind < 1)
	{
	  usage(OPT_IMPORT);
	  return -1;
	}
      opt_args = argv + optind;
      opt_argc = argc - optind;
      return 0;
    }

  /* infer reboots from imported database samples */
  if(options & OPT_REBOOTS)
    {
      if((options & OPT_DBFILE) == 0 || create_db != 0)
	{
	  usage(OPT_DBFILE|OPT_REBOOTS);
	  return -1;
	}
      dbfile = opt_dbfile;
      opt_args = argv + optind;
      opt_argc = argc - optind;
      return 0;
    }

  if((options & OPT_OUTFILE) == 0 || (options & OPT_DBFILE) == 0 ||
     (options & (OPT_PORT|OPT_UNIX)) == 0 ||
     (options & (OPT_PORT|OPT_UNIX)) == (OPT_PORT|OPT_UNIX) ||
     argc - optind > 0)
    {
      usage(OPT_DBFILE|OPT_OUTFILE|OPT_PORT|OPT_UNIX);
      return -1;
    }
  dbfile = opt_dbfile;

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

  if(opt_log != NULL)
    {
      if((logfile = fopen(opt_log, "w")) == NULL)
	{
	  usage(OPT_LOG);
	  fprintf(stderr, "could not open %s\n", opt_log);
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

static int sc_dst_bit(const sc_dst_t *dst, int bit)
{
  return scamper_addr_bit(dst->addr, bit);
}

static int sc_dst_fbd(const sc_dst_t *a, const sc_dst_t *b)
{
  return scamper_addr_fbd(a->addr, b->addr);
}

static int sc_dst_cmp(sc_dst_t *a, sc_dst_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static sc_dst_t *sc_dst_find(scamper_addr_t *addr)
{
  sc_dst_t fm; fm.addr = addr;
  return (sc_dst_t *)patricia_find(tree, &fm);
}

static void sc_dst_free(sc_dst_t *dst)
{
  if(dst->addr != NULL) scamper_addr_free(dst->addr);
  free(dst);
  return;
}

static void sc_wait_free(sc_wait_t *wt)
{
  if(wt->dst != NULL) sc_dst_free(wt->dst);
  free(wt);
  return;
}

static int sc_wait_cmp(const void *a, const void *b)
{
  return timeval_cmp(&((sc_wait_t *)b)->tv, &((sc_wait_t *)a)->tv);
}

static int sc_wait(sc_dst_t *dst)
{
  sc_wait_t *w;
  if((w = malloc_zero(sizeof(sc_wait_t))) == NULL)
    return -1;
  timeval_add_s(&w->tv, &now, 1);
  w->dst = dst;
  if(heap_insert(waiting, w) == NULL)
    return -1;
  return 0;
}

static int do_method(void)
{
  char cmd[256], buf[128];
  size_t off = 0;
  sc_wait_t *w;
  sc_dst_t *dst;
  
  if(more < 1)
    return 0;

  if((w = heap_head_item(waiting)) != NULL && timeval_cmp(&now, &w->tv) >= 0)
    {
      heap_remove(waiting);
      dst = w->dst;
      free(w);
    }
  else if((dst = slist_head_pop(list)) == NULL)
    return 0;

  scamper_addr_tostr(dst->addr, buf, sizeof(buf));
  if((dst->tree_node = patricia_insert(tree, dst)) == NULL)
    {
      fprintf(stderr, "could not insert %s into tree\n", buf);
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
      fprintf(stderr, "could not send %s\n", cmd);
      return -1;
    }

  probing++;
  more--;

  logprint("p %d, w %d, l %d : %s", probing, heap_count(waiting),
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

static int ipid_incr(sc_ipid_t *ipids, int ipidc)
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

/*
 * db_update
 *
 * sql = "update state_dsts set class=?,next=?,last_ipid=?,last_tx=?,loss=? "
 *       "where id=?";
 *
 */
static int db_update(sc_dst_t *dst)
{
  int next;

  sqlite3_reset(st_class);
  sqlite3_clear_bindings(st_class);
  sqlite3_bind_int(st_class, 1, dst->class);

  if(dst->class != CLASS_INCR)
    {
      /* probe again in 7-14 days time */
      if(next_random(&next, 7 * 24 * 60 * 60, 14 * 24 * 60 * 60) != 0)
	{
	  fprintf(stderr, "could not get next_random\n");
	  return -1;
	}
      sqlite3_bind_int(st_class, 2, now.tv_sec + next);
    }
  else
    {
      /*
       * probe approx every hour for 24 hours after losing at least 10
       * over 2 hours
       */
      if(dst->loss > 10 &&
	 now.tv_sec - dst->last_tx > (2 * 60 * 60) &&
	 now.tv_sec - dst->last_tx < (24 * 60 * 60))
	{
	  sqlite3_bind_int(st_class, 2, now.tv_sec + (60 * 60));
	}
      else
	{
	  sqlite3_bind_int(st_class, 2, 0);
	}
    }

  sqlite3_bind_int64(st_class, 3, dst->last_ipid);
  sqlite3_bind_int64(st_class, 4, dst->last_tx);
  sqlite3_bind_int(st_class, 5, dst->loss);
  sqlite3_bind_int64(st_class, 6, dst->id);

  if(sqlite3_step(st_class) != SQLITE_DONE)
    {
      fprintf(stderr, "could not execute st_class %lld:%d\n",
	      dst->id, dst->class);
      return -1;
    }

  return 0;
}

static int do_decoderead_ping(scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  sc_ipid_t ipids[10];
  int i, rc = 0, ipidc = 0, replyc = 0, freedst = 1;
  sc_dst_t *dst;
  char buf[128];

  scamper_addr_tostr(ping->dst, buf, sizeof(buf));
  
  if((dst = sc_dst_find(ping->dst)) == NULL)
    {
      fprintf(stderr, "could not find dst %s\n", buf);
      return -1;
    }
  patricia_remove_node(tree, dst->tree_node);
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
	  ipids[ipidc].ipid = reply->reply_ipid32;
	  ipids[ipidc].tx   = reply->tx.tv_sec;
	  ipidc++;
	}
    }

  logprint("%s %d %d\n", buf, replyc, ipidc);

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
      if(ipid_inseq2(dst->last_ipid, ipids[0].ipid) == 0)
	{
	  dst->class = CLASS_NONE;
	  sc_wait(dst);
	  freedst = 0;
	}
      dst->loss = 0;
    }
  else if(ipidc == 0)
    {
      dst->loss++;
      if(dst->loss > 10 && now.tv_sec - dst->last_tx > (24 * 60 * 60))
	{
	  dst->class = CLASS_UNRESP;
	}
    }

  /*
   * update the last time we received an IPID value if we got one in
   * sequence
   */
  if(ipidc > 0 && dst->class == CLASS_INCR)
    {
      dst->last_ipid = ipids[ipidc-1].ipid;
      dst->last_tx   = ipids[ipidc-1].tx;
    }

  db_update(dst);

  scamper_ping_free(ping);
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
      fprintf(stderr, "do_decoderead: scamper_file_read errno %d\n", errno);
      return -1;
    }
  if(data == NULL)
    return 0;
  probing--;

  if(scamper_file_write_obj(outfile, type, data) != 0)
    {
      fprintf(stderr, "do_decoderead: could not write obj %d\n", type);
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
	  fprintf(stderr, "could not uudecode_line\n");
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
	  fprintf(stderr, "could not parse %s\n", head);
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

  fprintf(stderr, "unknown response '%s'\n", head);
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

  fprintf(stderr, "could not read: errno %d\n", errno);
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
  else return -1;

  if(fcntl_set(scamper_fd, O_NONBLOCK) == -1)
    {
      fprintf(stderr, "could not set nonblock on scamper_fd\n");
      return -1;
    }

  return 0;
}

static int addrfile_line(char *line, void *param)
{
  sqlite3_stmt *stmt = param;
  scamper_addr_t *sa = NULL;
  sc_dst_t *dst;
  char buf[256];

  if(line[0] == '\0' || line[0] == '#')
    return 0;

  if((sa = scamper_addr_resolve(AF_INET6, line)) == NULL)
    {
      fprintf(stderr, "could not resolve %s\n", line);
      return 0;
    }
  if(scamper_addr_isunicast(sa) != 1 || patricia_find(tree, sa) != NULL)
    {
      scamper_addr_free(sa);
      return 0;
    }

  scamper_addr_tostr(sa, buf, sizeof(buf));

  sqlite3_clear_bindings(stmt);
  sqlite3_reset(stmt);
  sqlite3_bind_text(stmt, 1, buf, strlen(buf), SQLITE_TRANSIENT);
  if(sqlite3_step(stmt) != SQLITE_DONE || patricia_insert(tree, sa) == NULL)
    {
      scamper_addr_free(sa);
      return -1;
    }
  scamper_addr_use(sa);

  if((dst = malloc_zero(sizeof(sc_dst_t))) == NULL)
    return -1;
  dst->id = sqlite3_last_insert_rowid(db);
  dst->addr = sa;
  dst->class = CLASS_NONE;
  if(slist_tail_push(list, dst) == NULL)
    {
      fprintf(stderr, "could not put %s on list: %s\n", buf, strerror(errno));
      return -1;
    }
  return 0;
}

static int do_sqlite_open(void)
{
  struct stat sb;
  char *errmsg;
  int rc;

  rc = stat(dbfile, &sb);

  if(options & OPT_REBOOTS)
    {
      if(rc != 0)
	{
	  fprintf(stderr, "db %s does not exist\n", dbfile);
	  return -1;
	}
    }
  else
    {
      if(create_db != 0 && (rc == 0 || errno != ENOENT))
	{
	  fprintf(stderr, "will not create a db called %s\n", dbfile);
	  return -1;
	}
      else if(create_db == 0 && rc != 0)
	{
	  fprintf(stderr, "db %s does not exist, use -O create-db\n", dbfile);
	  return -1;
	}
    }

  if((rc = sqlite3_open(dbfile, &db)) != SQLITE_OK)
    {
      fprintf(stderr, "could not open %s: %s\n", dbfile, sqlite3_errstr(rc));
      return -1;
    }

  if(vacuum_db != 0)
    sqlite3_exec(db, "vacuum", NULL, NULL, &errmsg);

  return 0;
}

static int do_sqlite_state(void)
{
  static const char *create_sql =
    "create table \"state_dsts\" ("
    "\"id\" INTEGER PRIMARY KEY, "
    "\"addr\" TEXT NOT NULL, "
    "\"class\" INTEGER NOT NULL, "
    "\"next\" INTEGER NOT NULL, "
    "\"last_ipid\" INTEGER, "
    "\"last_tx\" INTEGER, "
    "\"loss\" INTEGER)";
  const char *sql;
  const unsigned char *addr;
  sqlite3_stmt *stmt;
  sqlite3_int64 id;
  scamper_addr_t *sa;
  sc_dst_t *dst;
  char *errmsg;
  int next, rc;

  if(do_sqlite_open() != 0)
    return -1;

  if(create_db != 0 &&
     sqlite3_exec(db, create_sql, NULL, NULL, &errmsg) != SQLITE_OK)
    {
      fprintf(stderr, "could not execute create sql: %s\n", errmsg);
      return -1;
    }

  if(addrfile != NULL &&
     (tree = patricia_alloc((patricia_bit_t)scamper_addr_bit,
			    (patricia_cmp_t)scamper_addr_cmp,
			    (patricia_fbd_t)scamper_addr_fbd)) == NULL)
    {
      fprintf(stderr, "could not allocate patricia\n");
      goto err;
    }

  sql = "select id,addr,next,class,last_ipid,last_tx,loss from state_dsts";
  if((rc = sqlite3_prepare_v2(db,sql,strlen(sql)+1,&stmt,NULL)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n", __func__,
	      sqlite3_errstr(rc));
      goto err;
    }
  while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
    {
      id   = sqlite3_column_int64(stmt, 0);
      addr = sqlite3_column_text(stmt, 1);
      next = sqlite3_column_int(stmt, 2);

      if((sa = scamper_addr_resolve(AF_INET6, (const char *)addr)) == NULL)
	{
	  fprintf(stderr, "could not resolve %s\n", addr);
	  continue;
	}
      if(scamper_addr_isunicast(sa) != 1)
	{
	  scamper_addr_free(sa);
	  continue;
	}

      if(tree != NULL && patricia_insert(tree, scamper_addr_use(sa)) == NULL)
	{
	  fprintf(stderr, "could not insert %s\n", addr);
	  scamper_addr_free(sa);
	  goto err;
	}

      /*
       * if the time to probe next parameter is set, but we haven't
       * reached the timeout yet, then skip this address
       */
      if(next != 0 && now.tv_sec < next)
	{
	  scamper_addr_free(sa);
	  continue;
	}

      if((dst = malloc_zero(sizeof(sc_dst_t))) == NULL)
	{
	  fprintf(stderr, "could not malloc dst\n");
	  goto err;
	}
      dst->id = id;
      dst->addr = sa; sa = NULL;
      dst->class = sqlite3_column_int(stmt, 3);
      if(dst->class == CLASS_INCR)
	{
	  dst->last_ipid = sqlite3_column_int64(stmt, 4);
	  dst->last_tx = sqlite3_column_int64(stmt, 5);
	  dst->loss = sqlite3_column_int(stmt, 6);
	}

      if(slist_tail_push(list, dst) == NULL)
	{
	  fprintf(stderr, "could not put %s on list: %s\n",
		  addr, strerror(errno));
	  goto err;
	}
    }
  sqlite3_finalize(stmt);

  if(addrfile != NULL)
    {
      sqlite3_exec(db, "begin", NULL, NULL, NULL);
      sql = "insert into state_dsts(addr,class,next) values(?,0,0)";
      rc = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &stmt, NULL);
      if(rc != SQLITE_OK || file_lines(addrfile, addrfile_line, stmt) != 0)
	{
	  sqlite3_finalize(stmt);
	  sqlite3_exec(db, "commit", NULL, NULL, NULL);
	  goto err;
	}
      sqlite3_exec(db, "commit", NULL, NULL, NULL);
      sqlite3_finalize(stmt);
      patricia_free_cb(tree, (patricia_free_t)scamper_addr_free);
      tree = NULL;
    }

  slist_shuffle(list);

  sql = "update state_dsts set class=?,next=?,last_ipid=?,last_tx=?,loss=? "
    "where id=?";
  rc = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_class, NULL);
  if(rc != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare %s: %s\n",
	      __func__, sql, sqlite3_errstr(rc));
      goto err;
    }

  return 0;

 err:
  if(tree != NULL)
    {
      patricia_free_cb(tree, (patricia_free_t)scamper_addr_free);
      tree = NULL;
    }
  return -1;
}

static int up_data(void)
{
  struct timeval tv, *tv_ptr;
  fd_set rfds, wfds, *wfdsp;
  sc_wait_t *w;
  int pair[2];
  int nfds;

  random_seed();
  gettimeofday_wrap(&now);

  if((list = slist_alloc()) == NULL ||
     do_sqlite_state() != 0 || do_scamperconnect() != 0 ||
     (outfile = scamper_file_open(outfile_name, 'w', "warts")) == NULL ||
     (waiting = heap_alloc(sc_wait_cmp)) == NULL ||
     (scamper_wb = scamper_writebuf_alloc()) == NULL ||
     (scamper_lp = scamper_linepoll_alloc(do_scamperread_line,NULL)) == NULL ||
     (decode_wb = scamper_writebuf_alloc()) == NULL ||
     (tree = patricia_alloc((patricia_bit_t)sc_dst_bit,
			    (patricia_cmp_t)sc_dst_cmp,
			    (patricia_fbd_t)sc_dst_fbd)) == NULL ||
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
	  w = heap_head_item(waiting);
	  if(slist_count(list) > 0 ||
	     (w != NULL && timeval_cmp(&w->tv, &now) <= 0))
	    {
	      if(do_method() != 0)
		return -1;
	    }

	  /*
	   * if we could not send a new command just yet, but scamper
	   * wants one, then wait for an appropriate length of time.
	   */
	  w = heap_head_item(waiting);
	  if(more > 0 && tv_ptr == NULL && w != NULL)
	    {
	      tv_ptr = &tv;
	      if(timeval_cmp(&w->tv, &now) > 0)
		timeval_diff_tv(&tv, &now, &w->tv);
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

      if(patricia_count(tree) == 0 && slist_count(list) == 0 &&
	 heap_count(waiting) == 0)
	{
	  logprint("done\n");
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
	}
    }

  return 0;
}

static int up_import(void)
{
  static const char *create_sql[] = {
    /* destination table */
    "create table \"data_dsts\" ("
    "\"id\" INTEGER PRIMARY KEY,"
    "\"addr\" TEXT NOT NULL)",
    /* file table */
    "create table \"data_files\" ("
    "\"filename\" TEXT UNIQUE NOT NULL)",
    /* sample table */
    "create table \"data_samples\" ("
    "\"dst_id\" INTEGER NOT NULL,"
    "\"ipid\" INTEGER NOT NULL,"
    "\"tx_sec\" INTEGER NOT NULL,"
    "\"tx_usec\" INTEGER NOT NULL,"
    "\"rx_sec\" INTEGER NOT NULL,"
    "\"rx_usec\" INTEGER NOT NULL)",
    /* indexes */
    "create index data_samples_select on data_samples(dst_id,ipid,tx_sec)",
    "create index data_files_filename on data_files(filename)",
    "create index data_dsts_addr on data_dsts(addr)",
  };
  sqlite3_stmt *stmt = NULL;
  sqlite3_stmt *st_filename_sel = NULL;
  sqlite3_stmt *st_filename_ins = NULL;
  sqlite3_stmt *st_addr_ins = NULL;
  sqlite3_stmt *st_sample_ins = NULL;
  sqlite3_int64 id;
  scamper_file_t *in;
  scamper_ping_t *ping;
  scamper_ping_reply_t *r;
  const unsigned char *addr;
  scamper_addr_t *sa;
  struct timeval tv;
  const char *sql, *ptr;
  char buf[128];
  sc_dst_t *dst;
  uint16_t j, type;
  void *data;
  char *errmsg;
  int i, x, rc = -1, rx;

  if(do_sqlite_open() != 0)
    goto done;

  if(create_db != 0)
    {
      for(i=0; i<sizeof(create_sql) / sizeof(char *); i++)
	{
	  if(sqlite3_exec(db, create_sql[i], NULL, NULL, &errmsg) != SQLITE_OK)
	    {
	      fprintf(stderr, "could not execute create sql: %s\n", errmsg);
	      goto done;
	    }
	}
    }

  if(safe_db == 0)
    {
      sqlite3_exec(db, "PRAGMA synchronous = OFF", NULL, NULL, &errmsg);
      sqlite3_exec(db, "PRAGMA journal_mode = MEMORY", NULL, NULL, &errmsg);
    }

  if((tree = patricia_alloc((patricia_bit_t)sc_dst_bit,
			    (patricia_cmp_t)sc_dst_cmp,
			    (patricia_fbd_t)sc_dst_fbd)) == NULL)
    {
      fprintf(stderr, "could not alloc patricia\n");
      goto done;
    }

  /* get a copy of all the destinations so far */
  sql = "select id, addr from data_dsts";
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
      if((sa = scamper_addr_resolve(AF_INET6, (const char *)addr)) == NULL)
	{
	  fprintf(stderr, "could not resolve %s\n", addr);
	  goto done;
	}

      if((dst = malloc_zero(sizeof(sc_dst_t))) == NULL)
	{
	  fprintf(stderr, "could not malloc dst\n");
	  goto done;
	}
      dst->id = id;
      dst->addr = sa; sa = NULL;
      if((dst->tree_node = patricia_insert(tree, dst)) == NULL)
	{
	  fprintf(stderr, "could not insert %s into tree\n", addr);
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
  sql = "insert into data_dsts(addr) values(?)";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_addr_ins, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n",
	      __func__, sqlite3_errstr(x));
      goto done;
    }
  sql =
    "insert into data_samples(dst_id,ipid,tx_sec,tx_usec,rx_sec,rx_usec)"
    " values(?,?,?,?,?,?)";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_sample_ins, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n",
	      __func__, sqlite3_errstr(x));
      goto done;
    }

  /* import all the files */
  for(i=0; i<opt_argc; i++)
    {
      /* check this file has not already been imported into the database */
      if((ptr = string_lastof_char(opt_args[i], '/')) == NULL)
	ptr = opt_args[i];
      else if(ptr[1] != '\0')
	ptr = ptr+1;
      else
	{
	  fprintf(stderr, "invalid filename %s\n", opt_args[i]);
	  goto done;
	}
      printf("%s\n", opt_args[i]);

      sqlite3_clear_bindings(st_filename_sel);
      sqlite3_reset(st_filename_sel);
      sqlite3_bind_text(st_filename_sel, 1, ptr, strlen(ptr), SQLITE_STATIC);
      if((x = sqlite3_step(st_filename_sel)) != SQLITE_DONE)
	{
	  if(x == SQLITE_ROW)
	    {
	      fprintf(stderr, "%s already inserted\n", ptr);
	      continue;
	    }
	  fprintf(stderr, "%s bad\n", ptr);
	  goto done;
	}

      if((in = scamper_file_open(opt_args[i], 'r', NULL)) == NULL)
	{
	  fprintf(stderr, "could not open %s\n", opt_args[i]);
	  goto done;
	}

      sqlite3_exec(db, "begin", NULL, NULL, NULL);
      while(scamper_file_read(in, ffilter, &type, &data) == 0)
	{
	  if(data == NULL)
	    break;
	  ping = data;

	  /* get dst record from database */
	  if((dst = sc_dst_find(ping->dst)) == NULL)
	    {
	      if((dst = malloc_zero(sizeof(sc_dst_t))) == NULL)
		{
		  fprintf(stderr, "could not malloc dst\n");
		  goto done;
		}
	      dst->addr = scamper_addr_use(ping->dst);
	      if((dst->tree_node = patricia_insert(tree, dst)) == NULL)
		{
		  fprintf(stderr, "could not insert dst\n");
		  goto done;
		}

	      scamper_addr_tostr(ping->dst, buf, sizeof(buf));
	      sqlite3_clear_bindings(st_addr_ins);
	      sqlite3_reset(st_addr_ins);
	      sqlite3_bind_text(st_addr_ins,1,buf,strlen(buf),SQLITE_STATIC);
	      sqlite3_step(st_addr_ins);
	      dst->id = sqlite3_last_insert_rowid(db);
	    }

	  rx = 0;
	  for(j=0; j<ping->ping_sent; j++)
	    {
	      r = ping->ping_replies[j];
	      if(r != NULL && SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(r))
		{
		  rx++;
		  sqlite3_clear_bindings(st_sample_ins);
		  sqlite3_reset(st_sample_ins);
		  sqlite3_bind_int(st_sample_ins, 1, dst->id);
		  if(r->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID)
		    sqlite3_bind_int64(st_sample_ins, 2, r->reply_ipid32);
		  else
		    sqlite3_bind_int(st_sample_ins, 2, -1);
		  timeval_add_tv3(&tv, &r->tx, &r->rtt);

		  sqlite3_bind_int(st_sample_ins, 3, r->tx.tv_sec);
		  sqlite3_bind_int(st_sample_ins, 4, r->tx.tv_usec);
		  sqlite3_bind_int(st_sample_ins, 5, tv.tv_sec);
		  sqlite3_bind_int(st_sample_ins, 6, tv.tv_usec);
		  sqlite3_step(st_sample_ins);
		}
	    }

	  if(rx == 0)
	    {
	      sqlite3_clear_bindings(st_sample_ins);
	      sqlite3_reset(st_sample_ins);
	      sqlite3_bind_int(st_sample_ins, 1, dst->id);
	      sqlite3_bind_int(st_sample_ins, 2, -2);
	      sqlite3_bind_int(st_sample_ins, 3, ping->start.tv_sec);
	      sqlite3_bind_int(st_sample_ins, 4, ping->start.tv_usec);
	      sqlite3_bind_int(st_sample_ins, 5, 0);
	      sqlite3_bind_int(st_sample_ins, 6, 0);
	      sqlite3_step(st_sample_ins);
	    }

	  scamper_ping_free(ping);
	}
      scamper_file_close(in);

      sqlite3_clear_bindings(st_filename_ins);
      sqlite3_reset(st_filename_ins);
      sqlite3_bind_text(st_filename_ins, 1, ptr, strlen(ptr), SQLITE_STATIC);
      sqlite3_step(st_filename_ins);
      sqlite3_exec(db, "commit", NULL, NULL, NULL);
    }

  rc = 0;

 done:
  if(stmt != NULL) sqlite3_finalize(stmt);
  if(st_filename_sel != NULL) sqlite3_finalize(st_filename_sel);
  if(st_filename_ins != NULL) sqlite3_finalize(st_filename_ins);
  if(st_addr_ins != NULL) sqlite3_finalize(st_addr_ins);
  if(st_sample_ins != NULL) sqlite3_finalize(st_sample_ins);
  if(rc == 0) sqlite3_exec(db, "PRAGMA optimize", NULL, NULL, &errmsg);

  return rc;
}

static int up_reboots_arerandom(sc_ipid_t **samples, int samplec, int l, int r)
{
  uint32_t posdiff_min, u32;
  double sum = 0, mean, abs;
  int posdiffc = 0;
  int ipidc = 0;
  int i;

  if(l < 0) l = 0;
  if(r > samplec) r = samplec;

  for(i=l; i<r-1; i++)
    {
      if(samples[i+1]->ipid <= samples[i]->ipid)
	{
	  u32 = samples[i+1]->ipid - samples[i]->ipid;
	  if(posdiffc == 0 || u32 < posdiff_min)
	    posdiff_min = u32;
	  posdiffc++;
	}
      else
	{
	  u32 = samples[i]->ipid - samples[i+1]->ipid;
	}
      sum += u32;
      ipidc++;
    }

  if(r-l < 2)
    return 0;
  if(posdiffc == 0)
    return 0;
  if(posdiff_min < 1000)
    return 0;
  if(ipidc == posdiffc)
    return 0;
  if(((double)ipidc) - posdiffc / 1.0 / posdiffc > 0.5)
    return 1;

  mean = sum / ipidc;
  if(mean < 2147483648)
    abs = 2147483648 - mean;
  else
    abs = mean - 2147483648;
  if(abs < 100000)
    return 1;
  return 0;
}

static int up_reboots_inference(sc_ipid_t **samples, int samplec, int i,
				uint32_t min_ipid, uint64_t max_expected_ipid)
{

  uint32_t ipid = samples[i]->ipid;
  uint32_t last_ipid = samples[i-1]->ipid;
  uint32_t tx = samples[i]->tx;
  uint32_t last_tx = samples[i-1]->tx;
  uint32_t fudge = 65536;
  uint32_t diff;

  if(tx - last_tx < 60)
    return 0;
  if(tx - last_tx > (7 * 24 * 60 * 60))
    return 0;
  if(ipid < last_ipid)
    {
      /* counter wrap */
      if(max_expected_ipid >= 0xFFFFFFFFULL &&
	 (max_expected_ipid & 0xFFFFFFFFULL) > ipid)
	return 0;
      if(ipid < min_ipid)
	diff = min_ipid - ipid;
      else
	diff = ipid - min_ipid;
      if(diff < fudge && ipid > fudge)
	return 0;
      if(up_reboots_arerandom(samples, samplec, i, i + 10) == 0 &&
	 up_reboots_arerandom(samples, samplec, i-10, i-1) == 0)
	return 1;
    }
  /* cyclic reboots with a higher IPID than expected, based on velocity */
  else if(ipid > max_expected_ipid + fudge)
    {
      if(up_reboots_arerandom(samples, samplec, i, i+10) == 0)
	return 1;
    }

  return 0;
}

static int up_reboots_doone(sc_dst_t *dst, slist_t *samplist, slist_t *reboots)
{
  double velocity = 0, sample_velocity, coverage, reboots_per_day;
  uint64_t expected_ipid;
  sc_ipid_t **samples = NULL;
  sc_reboot_t *reboot;
  slist_node_t *sn;
  uint32_t last_tx, last_ipid, min_ipid, tx, ipid;
  uint32_t threshold = 0;
  int samplec = slist_count(samplist);
  int i;

  if(samplec < 10)
    return 0;

  if((samples = malloc_zero(sizeof(sc_ipid_t *) * samplec)) == NULL)
    goto err;
  i = 0;
  for(sn=slist_head_node(samplist); sn != NULL; sn=slist_node_next(sn))
    samples[i++] = slist_node_item(sn);

  last_tx = samples[0]->tx;
  last_ipid = samples[0]->ipid;
  min_ipid = samples[0]->ipid;
  for(i=1; i<samplec; i++)
    {
      tx = samples[i]->tx;
      ipid = samples[i]->ipid;
      sample_velocity = 0.01;
      if(tx > last_tx && ipid > last_ipid)
	sample_velocity = ((double)(ipid - last_ipid)) / (tx - last_tx);
      expected_ipid = last_ipid + ((tx-last_tx) * 10 * velocity);
      if(up_reboots_inference(samples, samplec, i, min_ipid, expected_ipid))
	{
	  min_ipid = ipid;
	  velocity = 0;
	  sample_velocity = 0.01;
	  if(tx - last_tx > threshold)
	    {
	      if((reboot = malloc(sizeof(sc_reboot_t))) == NULL)
		goto err;
	      reboot->left = last_tx;
	      reboot->right = tx;
	      if(slist_tail_push(reboots, reboot) == NULL)
		{
		  free(reboot);
		  goto err;
		}
	    }
	}

      last_tx = tx;
      last_ipid = ipid;
      if(ipid < min_ipid)
	min_ipid = ipid;
      velocity = (0.8 * velocity) + (0.2 * sample_velocity);
    }

  coverage = ((double)(samples[samplec-1]->tx-samples[0]->tx)) / (60*60*24);
  reboots_per_day = slist_count(reboots) / coverage;
  if(coverage > 100 && reboots_per_day > 5)
    {
      while((reboot = slist_head_pop(reboots)) != NULL)
	free(reboot);
    }

  free(samples);
  return 0;

 err:
  if(samples != NULL) free(samples);
  return -1;
}

/*
 * up_reboots
 *
 * test cases:
 * 1. 2001:128c:53f:2::2  (cyclic reboot)
 * 2. large fudge b/c of things like 2a01:3e0:fff0:400::22
 * 3. 2001:1a68:a:3000::136 (fast moving counter)
 * 4. 2001:428:c02:10:0:16:0:2 (16bit counter?)
 * 5. 2001:fe0:4775:11f::1 (multiple counters?)
 * 6. 2001:7f8:1f::4:4134:31:0 (counter wrap)
 */
static int up_reboots(void)
{
  slist_t *addrs = NULL;
  slist_t *samples = NULL;
  slist_t *reboots = NULL;
  sqlite3_stmt *st = NULL;
  sc_ipid_t *sample;
  sc_reboot_t *reboot;
  const char *sql, *ptr;
  const unsigned char *addr;
  char buf[256];
  sc_dst_t *dst;
  sqlite3_int64 tx_sec, ipid;
  int i, x, rc = -1;

  if(do_sqlite_open() != 0)
    return -1;

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
	      fprintf(stderr, "%s not in %s\n", ptr, dbfile);
	      goto done;
	    }
	  if((dst = malloc_zero(sizeof(sc_dst_t))) == NULL)
	    {
	      fprintf(stderr, "could not malloc dst %s\n", ptr);
	      goto done;
	    }
	  dst->id = sqlite3_column_int64(st, 0);
	  if((dst->addr = scamper_addr_resolve(AF_INET6, ptr)) == NULL)
	    {
	      fprintf(stderr, "%s not an ipv6 address\n", ptr);
	      sc_dst_free(dst);
	      goto done;
	    }
	  if(slist_tail_push(addrs, dst) == NULL)
	    {
	      fprintf(stderr, "could not push %s to list\n", ptr);
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
	  if((dst = malloc_zero(sizeof(sc_dst_t))) == NULL)
	    {
	      fprintf(stderr, "could not malloc dst %s\n", addr);
	      goto done;
	    }
	  dst->id = sqlite3_column_int64(st, 0);
	  dst->addr = scamper_addr_resolve(AF_INET6, (const char *)addr);
	  if(dst->addr == NULL)
	    {
	      fprintf(stderr, "%s not an ipv6 address\n", addr);
	      sc_dst_free(dst);
	      goto done;
	    }
	  if(slist_tail_push(addrs, dst) == NULL)
	    {
	      fprintf(stderr, "could not push %s to list\n", addr);
	      sc_dst_free(dst);
	      goto done;
	    }
	}
    }
  sqlite3_finalize(st); st = NULL;

  if((samples = slist_alloc()) == NULL)
    {
      fprintf(stderr, "could not alloc samples list\n");
      goto done;
    }
  if((reboots = slist_alloc()) == NULL)
    {
      fprintf(stderr, "could not alloc reboots list\n");
      goto done;
    }

  sql = "select tx_sec, ipid from data_samples where dst_id=?"
    "order by tx_sec, ipid";
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
	  tx_sec = sqlite3_column_int64(st, 0);
	  ipid = sqlite3_column_int64(st, 1);
	  if(ipid < 0)
	    continue;
	  if((sample = malloc(sizeof(sc_ipid_t))) == NULL)
	    {
	      fprintf(stderr, "could not malloc sample\n");
	      goto done;
	    }
	  sample->tx = tx_sec;
	  sample->ipid = ipid;
	  if(slist_tail_push(samples, sample) == NULL)
	    {
	      fprintf(stderr, "could not push sample to list\n");
	      goto done;
	    }
	}

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
	}

      sc_dst_free(dst);
    }
  rc = 0;

 done:
  sqlite3_finalize(st);
  slist_free(reboots);
  slist_free(samples);
  slist_free(addrs);
  return rc;
}

static int up_init(void)
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_PING};
  int typec = sizeof(types) / sizeof(uint16_t);
  if((ffilter = scamper_file_filter_alloc(types, typec)) == NULL)
    return -1;
  return 0;
}

static void cleanup(void)
{
  if(tree != NULL) patricia_free_cb(tree, (patricia_free_t)sc_dst_free);
  if(list != NULL) slist_free_cb(list, (slist_free_t)sc_dst_free);
  if(waiting != NULL) heap_free(waiting, (heap_free_t)sc_wait_free);
  if(scamper_wb != NULL) scamper_writebuf_free(scamper_wb);
  if(scamper_lp != NULL) scamper_linepoll_free(scamper_lp, 0);
  if(decode_wb != NULL) scamper_writebuf_free(decode_wb);
  if(outfile != NULL) scamper_file_close(outfile);
  if(decode_in != NULL) scamper_file_close(decode_in);
  if(ffilter != NULL) scamper_file_filter_free(ffilter);
  if(logfile != NULL) fclose(logfile);
  if(st_class != NULL) sqlite3_finalize(st_class);
  if(db != NULL) sqlite3_close(db);
  if(srcaddr != NULL) free(srcaddr);
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

  if(options & OPT_IMPORT)
    return up_import();

  if(options & OPT_REBOOTS)
    return up_reboots();

  return up_data();
}
