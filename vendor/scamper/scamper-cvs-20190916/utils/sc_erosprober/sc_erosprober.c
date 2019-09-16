/*
 * sc_erosprober : probe a set of addresses in a loop, periodically
 *               : rotating the output file.
 *
 * Authors       : Matthew Luckie
 *
 * Copyright (C) 2018-2019 Matthew Luckie
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
  "$Id: sc_erosprober.c,v 1.9 2019/09/08 00:34:01 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "ping/scamper_ping.h"
#include "trace/scamper_trace.h"
#include "scamper_file.h"
#include "scamper_writebuf.h"
#include "scamper_linepoll.h"
#include "mjl_list.h"
#include "mjl_heap.h"
#include "mjl_patricia.h"
#include "utils.h"

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
static char                  *addrfile_name = NULL;
static char                  *outfile_name  = NULL;
static scamper_file_t        *outfile       = NULL;
static scamper_file_filter_t *decode_filter = NULL;
static FILE                  *logfile       = NULL;
static int                    data_left     = 0;
static int                    more          = 0;
static int                    interval      = 0;
static int                    rotation      = 0;
static int                    shuffle       = 1;
static int                    nooutfile     = 0;
static char                  *command       = NULL;
static heap_t                *waiting       = NULL;
static patricia_t            *probing4      = NULL;
static patricia_t            *probing6      = NULL;
static int                    ep_stop       = 0;
static struct timeval         now;

typedef struct sc_ep
{
  struct timeval  tv;    /* timeval */
  scamper_addr_t *addr;  /* address to probe */
  uint8_t         type;  /* probe or rotate */
} sc_ep_t;

#define EP_TYPE_PROBE  0
#define EP_TYPE_ROTATE 1

#define OPT_ADDRFILE 0x0001
#define OPT_OUTFILE  0x0002
#define OPT_PORT     0x0004
#define OPT_UNIX     0x0008
#define OPT_LOG      0x0010
#define OPT_INTERVAL 0x0020
#define OPT_ROTATION 0x0040
#define OPT_COMMAND  0x0080
#define OPT_OPTION   0x0100
#define OPT_HELP     0x0200
#define OPT_ALL      0xffff

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
  "usage: sc_erosprober [-?] [-a addrfile] [-c cmd] [-o outfile] [-p port]\n"
  "                     [-U unix] [-I interval] [-O option] [-R rotation]\n"
  "                     [-l logfile]\n"
  "\n");

  if(opt_mask == 0)
    {
      fprintf(stderr, "       sc_erosprober -?\n\n");
      return;
    }

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "   -? give an overview of the usage of sc_erosprober\n");

  if(opt_mask & OPT_ADDRFILE)
    fprintf(stderr, "   -a input address file\n");
  if(opt_mask & OPT_COMMAND)
    fprintf(stderr, "   -c scamper command to use\n");
  if(opt_mask & OPT_INTERVAL)
    fprintf(stderr, "   -I probe interval, in seconds\n");
  if(opt_mask & OPT_LOG)
    fprintf(stderr, "   -l output logfile\n");
  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "   -o output warts file prefix\n");
  if(opt_mask & OPT_OPTION)
    {
      fprintf(stderr, "   -O options\n");
      fprintf(stderr, "      noshuffle: do not shuffle address file\n");
      fprintf(stderr, "      nooutfile: do not write an output file\n");
    }
  if(opt_mask & OPT_PORT)
    fprintf(stderr, "   -p port to find scamper on\n");
  if(opt_mask & OPT_ROTATION)
    fprintf(stderr, "   -R rotation interval, in seconds\n");
  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "   -U unix domain to find scamper on\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  char *opts = "?a:c:I:l:o:p:R:U:";
  char *opt_port = NULL, *opt_log = NULL;
  char *opt_interval = NULL, *opt_rotation = NULL;
  long lo;
  int ch;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'a':
	  options |= OPT_ADDRFILE;
	  addrfile_name = optarg;
	  break;

	case 'c':
	  options |= OPT_COMMAND;
	  command = optarg;
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
	  outfile_name = optarg;
	  break;

	case 'O':
	  options |= OPT_OPTION;
	  if(strcasecmp(optarg, "noshuffle") == 0)
	    shuffle = 0;
	  else if(strcasecmp(optarg, "nooutfile") == 0)
	    nooutfile = 1;
	  break;

	case 'p':
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case 'R':
	  options |= OPT_ROTATION;
	  opt_rotation = optarg;
	  break;

	case 'U':
	  options |= OPT_UNIX;
	  unix_name = optarg;
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

  if(addrfile_name == NULL)
    {
      usage(OPT_ADDRFILE);
      return -1;
    }

  if(command == NULL)
    {
      usage(OPT_COMMAND);
      return -1;
    }

  /* XXX: 60 */
  if(opt_interval == NULL || string_tolong(opt_interval, &lo) != 0 || lo < 10)
    {
      usage(OPT_INTERVAL);
      return -1;
    }
  interval = lo;

  if(opt_rotation == NULL || string_tolong(opt_rotation, &lo) != 0 || lo < 10)
    {
      usage(OPT_ROTATION);
      return -1;
    }
  rotation = lo;

  if(outfile_name == NULL && nooutfile == 0)
    {
      usage(OPT_OUTFILE);
      return -1;
    }

  if(opt_port == NULL && unix_name == NULL)
    {
      usage(OPT_PORT | OPT_UNIX);
      return -1;
    }

  if(opt_port != NULL)
    {
      if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
	{
	  usage(OPT_PORT);
	  return -1;
	}
      port = lo;
    }

  if(opt_log != NULL)
    {
      if(strcmp(opt_log, "-") == 0)
	logfile = stdout;
      else if((logfile = fopen(opt_log, "w")) == NULL)
	{
	  usage(OPT_LOG);
	  return -1;
	}
    }

  return 0;
}

static void logprint(char *format, ...)
{
  va_list ap;
  char msg[131072];

  if(logfile == NULL)
    return;

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  if(logfile != NULL)
    {
      fprintf(logfile, "%ld: %s", (long int)now.tv_sec, msg);
      fflush(logfile);
    }

  return;
}

static void sc_ep_free(sc_ep_t *ep)
{
  if(ep->addr != NULL) scamper_addr_free(ep->addr);
  free(ep);
  return;
}

static int sc_ep_tv_cmp(const sc_ep_t *a, const sc_ep_t *b)
{
  return timeval_cmp(&b->tv, &a->tv);
}

static int sc_ep_addr_cmp(const sc_ep_t *a, const sc_ep_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static int sc_ep_addr_fbd(const sc_ep_t *a, const sc_ep_t *b)
{
  return scamper_addr_fbd(a->addr, b->addr);
}

static int sc_ep_addr_bit(const sc_ep_t *ep, int bit)
{
  return scamper_addr_bit(ep->addr, bit);
}

static int ep_tree_to_heap(scamper_addr_t *addr)
{
  patricia_t *pt;
  sc_ep_t fm, *ep;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(addr))
    pt = probing4;
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(addr))
    pt = probing6;
  else
    return -1;

  fm.addr = addr;
  if((ep = patricia_find(pt, &fm)) == NULL)
    return -1;
  patricia_remove_item(pt, ep);
  if(heap_insert(waiting, ep) == NULL)
    return -1;

  return 0;
}

static int addrfile_line(char *line, void *param)
{
  slist_t *list = param;
  scamper_addr_t *sa = NULL;
  int rc = -1;

  if(line[0] == '\0' || line[0] == '#')
    return 0;

  if((sa = scamper_addr_resolve(AF_UNSPEC, line)) == NULL)
    {
      /* for now, don't abort if the input file has a malformed addr */
      fprintf(stderr, "%s: could not resolve %s\n", __func__, line);
      rc = 0;
      goto done;
    }

  if(slist_tail_push(list, sa) == NULL)
    {
      fprintf(stderr, "%s:could not push %s to list\n", __func__, line);
      goto done;
    }
  sa = NULL;
  rc = 0;

 done:
  if(sa != NULL) scamper_addr_free(sa);
  return rc;
}

/*
 * do_addrfile
 *
 * read the input file for all addresses.  then, calculate the time
 * between tasks that approximately balances out probing across the
 * defined interval.
 */
static int do_addrfile(void)
{
  scamper_addr_t *sa = NULL;
  struct timeval next, gap;
  slist_t *list = NULL;
  sc_ep_t *ep = NULL;
  uint64_t gap64;
  int rc = -1;

  if((list = slist_alloc()) == NULL)
    {
      fprintf(stderr, "could not alloc list");
      goto done;
    }
  if(file_lines(addrfile_name, addrfile_line, list) != 0)
    goto done;
  if(shuffle != 0)
    slist_shuffle(list);

  gettimeofday_wrap(&now);
  gap64 = (interval * 1000000) / slist_count(list);
  gap.tv_sec = gap64 / 1000000;
  gap.tv_usec = gap64 % 1000000;
  timeval_cpy(&next, &now);

  while((sa = slist_head_pop(list)) != NULL)
    {
      if((ep = malloc(sizeof(sc_ep_t))) == NULL)
	{
	  fprintf(stderr, "%s: could not alloc ep\n", __func__);
	  goto done;
	}
      ep->type = EP_TYPE_PROBE;
      ep->addr = sa; sa = NULL;
      timeval_add_tv(&next, &gap);
      timeval_cpy(&ep->tv, &next);
      if(heap_insert(waiting, ep) == NULL)
	{
	  fprintf(stderr, "%s: could not add ep to heap\n", __func__);
	  goto done;
	}

      ep = NULL;
    }

  rc = 0;

 done:
  if(ep != NULL) sc_ep_free(ep);
  if(list != NULL) slist_free_cb(list, (slist_free_t)scamper_addr_free);
  return rc;
}

static int do_outfile(void)
{
  sc_ep_t *ep = NULL;
  char buf[256];

  if(outfile != NULL)
    {
      scamper_file_close(outfile);
      outfile = NULL;
    }

  gettimeofday_wrap(&now);
  snprintf(buf, sizeof(buf), "%s.%ld.warts",
	   outfile_name, (long int)now.tv_sec);
  logprint("%s\n", buf);

  if((outfile = scamper_file_open(buf, 'w', "warts")) == NULL)
    {
      fprintf(stderr, "%s: could not open %s\n", __func__, buf);
      return -1;
    }

  if((ep = malloc(sizeof(sc_ep_t))) == NULL)
    {
      fprintf(stderr, "%s: could not alloc ep\n", __func__);
      return -1;
    }
  ep->addr = NULL;
  ep->type = EP_TYPE_ROTATE;
  timeval_add_s(&ep->tv, &now, rotation);
  if(heap_insert(waiting, ep) == NULL)
    {
      fprintf(stderr, "%s: could not insert rotate into heap\n", __func__);
      return -1;
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
  struct sockaddr *sa;
  struct sockaddr_in sin;
  struct sockaddr_un sun;
  struct in_addr in;
  socklen_t sl;

  if(port != 0)
    {
      inet_aton("127.0.0.1", &in);
      sockaddr_compose((struct sockaddr *)&sin, AF_INET, &in, port);
      if((scamper_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
	  fprintf(stderr, "could not allocate new socket: %s\n",
		  strerror(errno));
	  return -1;
	}
      sa = (struct sockaddr *)&sin;
      sl = sizeof(sin);
    }
  else if(unix_name != NULL)
    {
      if(sockaddr_compose_un((struct sockaddr *)&sun, unix_name) != 0)
	{
	  fprintf(stderr, "%s: could not build sockaddr_un: %s\n",
		  __func__, strerror(errno));
	  return -1;
	}
      if((scamper_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
	  fprintf(stderr, "%s: could not allocate unix domain socket: %s\n",
		  __func__, strerror(errno));
	  return -1;
	}
      sa = (struct sockaddr *)&sun;
      sl = sizeof(sun);
    }
  else return -1;

  if(connect(scamper_fd, sa, sl) != 0)
    {
      fprintf(stderr, "%s: could not connect to scamper process: %s\n",
	      __func__, strerror(errno));
      return -1;
    }

  if(fcntl_set(scamper_fd, O_NONBLOCK) == -1)
    {
      fprintf(stderr, "%s: could not set nonblock on scamper_fd: %s\n",
	      __func__, strerror(errno));
      return -1;
    }

  return 0;
}

static int do_method(void)
{
  char cmd[256], buf[128];
  patricia_t *pt;
  sc_ep_t *ep;
  int bc;

  ep = heap_head_item(waiting);
  assert(ep != NULL);
  assert(ep->type == EP_TYPE_PROBE || ep->type == EP_TYPE_ROTATE);

  gettimeofday_wrap(&now);
  if(timeval_cmp(&now, &ep->tv) < 0)
    return 0;

  if(ep->type == EP_TYPE_ROTATE)
    {
      ep = heap_remove(waiting);
      sc_ep_free(ep);
      if(do_outfile() != 0)
	return -1;
      ep = heap_head_item(waiting);
      assert(ep != NULL);
      if(timeval_cmp(&now, &ep->tv) < 0)
	return 0;
    }

  if(ep->type != EP_TYPE_PROBE || more < 1)
    return 0;
  ep = heap_remove(waiting);

  if(SCAMPER_ADDR_TYPE_IS_IPV4(ep->addr))
    pt = probing4;
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(ep->addr))
    pt = probing6;
  else
    return -1;

  scamper_addr_tostr(ep->addr, buf, sizeof(buf));
  if((bc = snprintf(cmd, sizeof(cmd), "%s %s\n", command, buf)) < 0 ||
     bc >= sizeof(cmd))
    {
      fprintf(stderr, "%s: could not form command %s: %s\n", __func__, buf,
	      strerror(errno));
      return -1;
    }

  if(scamper_writebuf_send(scamper_wb, cmd, bc) != 0)
    {
      fprintf(stderr, "%s: could not probe %s: %s\n", __func__, buf,
	      strerror(errno));
      return -1;
    }

  timeval_add_s(&ep->tv, &now, interval);
  if(patricia_insert(pt, ep) == NULL)
    {
      fprintf(stderr, "%s: could not insert %s\n", __func__, buf);
      return -1;
    }

  more--;

  logprint("p %d w %d: %s",
	   patricia_count(probing4) + patricia_count(probing6),
	   heap_count(waiting), cmd);
  return 0;
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
      close(scamper_fd); scamper_fd = -1;
      return 0;
    }
  else if(errno == EINTR || errno == EAGAIN)
    {
      return 0;
    }

  fprintf(stderr, "%s: could not read: %s\n", __func__, strerror(errno));
  return -1;
}

static int do_decoderead(void)
{
  scamper_trace_t *trace = NULL;
  scamper_ping_t *ping = NULL;
  uint16_t type;
  void *data;
  int rc = -1;

  if(scamper_file_read(decode_in, decode_filter, &type, &data) != 0)
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

  if(type == SCAMPER_FILE_OBJ_PING)
    {
      ping = data;
      if(ep_tree_to_heap(ping->dst) != 0)
	goto done;
      if(nooutfile == 0 && scamper_file_write_ping(outfile, ping) != 0)
	goto done;
      rc = 0;
    }
  else if(type == SCAMPER_FILE_OBJ_TRACE)
    {
      trace = data;
      if(ep_tree_to_heap(trace->dst) != 0)
	goto done;
      if(nooutfile == 0 && scamper_file_write_trace(outfile, trace) != 0)
	goto done;
      rc = 0;
    }

 done:
  if(ping != NULL) scamper_ping_free(ping);
  if(trace != NULL) scamper_trace_free(trace);
  return rc;
}

static void cleanup(void)
{
  if(waiting != NULL)
    {
      heap_free(waiting, (heap_free_t)sc_ep_free);
      waiting = NULL;
    }

  if(probing4 != NULL)
    {
      patricia_free_cb(probing4, (patricia_free_t)sc_ep_free);
      probing4 = NULL;
    }

  if(probing6 != NULL)
    {
      patricia_free_cb(probing6, (patricia_free_t)sc_ep_free);
      probing6 = NULL;
    }

  if(decode_in != NULL)
    {
      scamper_file_close(decode_in);
      decode_in = NULL;
    }

  if(decode_filter != NULL)
    {
      scamper_file_filter_free(decode_filter);
      decode_filter = NULL;
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

  if(decode_wb != NULL)
    {
      scamper_writebuf_free(decode_wb);
      decode_wb = NULL;
    }

  if(logfile != NULL)
    {
      fclose(logfile);
      logfile = NULL;
    }

  if(outfile != NULL)
    {
      scamper_file_close(outfile);
      outfile = NULL;
    }

  return;
}

static void ep_sigint(int signo)
{
  ep_stop = 1;
  return;
}

int main(int argc, char *argv[])
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_PING, SCAMPER_FILE_OBJ_TRACE};
  struct timeval tv, *tv_ptr;
  fd_set rfds, wfds, *wfdsp;
  sc_ep_t *ep;
  int pair[2];
  int nfds;

#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

  random_seed();

  if((waiting = heap_alloc((heap_cmp_t)sc_ep_tv_cmp)) == NULL ||
     (probing4 = patricia_alloc((patricia_bit_t)sc_ep_addr_bit,
				(patricia_cmp_t)sc_ep_addr_cmp,
				(patricia_fbd_t)sc_ep_addr_fbd)) == NULL ||
     (probing6 = patricia_alloc((patricia_bit_t)sc_ep_addr_bit,
				(patricia_cmp_t)sc_ep_addr_cmp,
				(patricia_fbd_t)sc_ep_addr_fbd)) == NULL ||
     (scamper_wb = scamper_writebuf_alloc()) == NULL ||
     (scamper_lp = scamper_linepoll_alloc(do_scamperread_line,NULL)) == NULL ||
     (decode_wb = scamper_writebuf_alloc()) == NULL ||
     do_addrfile() != 0 ||
     (nooutfile == 0 && do_outfile() != 0) ||
     do_scamperconnect() != 0 ||
     (decode_filter = scamper_file_filter_alloc(types, 1)) == NULL ||
     socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0 ||
     (decode_in = scamper_file_openfd(pair[0], NULL, 'r', "warts")) == NULL ||
     fcntl_set(pair[0], O_NONBLOCK) == -1 ||
     fcntl_set(pair[1], O_NONBLOCK) == -1 ||
     signal(SIGINT, ep_sigint) == SIG_ERR)
    return -1;

  decode_in_fd  = pair[0];
  decode_out_fd = pair[1];
  scamper_writebuf_send(scamper_wb, "attach\n", 7);

  while(ep_stop == 0)
    {
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

      tv_ptr = NULL;
      if((ep = heap_head_item(waiting)) != NULL)
	{
	  gettimeofday_wrap(&now);
	  if(timeval_cmp(&now, &ep->tv) <= 0)
	    timeval_diff_tv(&tv, &now, &ep->tv);
	  else
	    memset(&tv, 0, sizeof(tv));
	  tv_ptr = &tv;
	}

      if(select(nfds+1, &rfds, wfdsp, NULL, tv_ptr) < 0)
	{
	  if(errno == EINTR) continue;
	  fprintf(stderr, "select error\n");
	  break;
	}

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
	    {
	      fprintf(stderr, "could not write to scamper_fd: %s\n",
		      strerror(errno));
	      return -1;
	    }
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
	    {
	      fprintf(stderr, "could not write to decode_out_fd: %s\n",
		      strerror(errno));
	      return -1;
	    }

	  if(scamper_fd < 0 && scamper_writebuf_len(decode_wb) == 0)
	    {
	      close(decode_out_fd);
	      decode_out_fd = -1;
	    }
	}
    }

  return 0;
}
