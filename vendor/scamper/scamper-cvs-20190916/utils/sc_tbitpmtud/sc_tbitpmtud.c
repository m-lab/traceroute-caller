/*
 * sc_tbitpmtud : scamper driver to collect data on PMTUD failures using the
 *              : tbit approach.
 *
 * Author       : Matthew Luckie.
 *
 * Copyright (C) 2010, 2018 The University of Waikato
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
 * $Id: sc_tbitpmtud.c,v 1.20 2019/07/12 21:40:13 mjl Exp $
 */

#ifndef lint
static const char rcsid[] =
  "$Id: sc_tbitpmtud.c,v 1.20 2019/07/12 21:40:13 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "ping/scamper_ping.h"
#include "tbit/scamper_tbit.h"
#include "scamper_file.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "mjl_heap.h"
#include "mjl_prefixtree.h"
#include "utils.h"

typedef struct sc_dump
{
  char  *descr;
  char  *label;
  int  (*init)(void);
  int  (*proc_tbit)(scamper_tbit_t *tbit);
  int  (*proc_ping)(scamper_ping_t *ping);
  int  (*finish)(void);
} sc_dump_t;

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
  int              af;
  union
  {
    prefix4_t      *v4;
    prefix6_t      *v6;
  } pfx;
  sc_asmap_t       *asmap;
} sc_prefix_t;

static int init_1(void);
static int process_1_tbit(scamper_tbit_t *);
static int finish_1(void);
static int init_2(void);
static int process_2_tbit(scamper_tbit_t *);
static int finish_2(void);

static uint32_t               options       = 0;
static splaytree_t           *tree          = NULL;
static slist_t               *list          = NULL;
static heap_t                *heap          = NULL;
static int                    scamper_fd    = -1;
static char                  *readbuf       = NULL;
static size_t                 readbuf_len   = 0;
static int                    port          = 31337;
static char                  *addressfile   = NULL;
static char                  *outfile_name  = NULL;
static scamper_file_t        *outfile       = NULL;
static int                    outfile_obj   = 0;
static int                    outfile_i     = 0;
static int                    window        = 0;
static int                    limit         = 10000;
static uint16_t               mtu           = 1280;
static scamper_file_filter_t *ffilter       = NULL;
static scamper_file_t        *decode_in     = NULL;
static int                    decode_in_fd  = -1;
static int                    decode_out_fd = -1;
static int                    data_left     = 0;
static char                   command_buf[512];
static int                    more          = 0;
static int                    probing       = 0;
static slist_t               *ip2as_files   = NULL;
static prefixtree_t          *ip2as_pt_4    = NULL;
static prefixtree_t          *ip2as_pt_6    = NULL;
static splaytree_t           *asmaptree     = NULL;
static FILE                  *text          = NULL;
static FILE                  *comp          = NULL;
static struct timeval         now;
static char                 **opt_args      = NULL;
static int                    opt_argc      = 0;
static int                    dump_id       = 0;
static const sc_dump_t        dump_funcs[]  = {
  {NULL, NULL, NULL, NULL, NULL, NULL},
  {"dump results by MSS", "mssresults",
   init_1, process_1_tbit, NULL, finish_1},
  {"dump results by ASN", "asnresults",
   init_2, process_2_tbit, NULL, finish_2},
};
static int dump_funcc = sizeof(dump_funcs) / sizeof(sc_dump_t);

#define MODE_PING 0
#define MODE_TBIT 1

/*
 * the prefix size ranges that are allowed.  in v4, we consider a prefix
 * valid if it is >= 8 && <= 24.  in v6, >= 19 && <= 48.
 */
#define IPV4_PREFIX_MIN 8
#define IPV4_PREFIX_MAX 24
#define IPV6_PREFIX_MIN 19
#define IPV6_PREFIX_MAX 48

typedef struct target_url
{
  char *url;
  int   size;
} target_url_t;

typedef struct target
{
  scamper_addr_t   *addr;
  struct timeval    next;
  uint32_t          pos;
  heap_t           *urls;
  int               mode;
  uint16_t          mtu;
  uint16_t          mss;
  uint16_t          sport;
  heap_node_t      *hn;
  splaytree_node_t *tn;
} target_t;

#define OPT_HELP        0x0001
#define OPT_ADDRESSFILE 0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008
#define OPT_TEXT        0x0010
#define OPT_LIMIT       0x0020
#define OPT_WINDOW      0x0040
#define OPT_COMPLETED   0x0080
#define OPT_RANDOM      0x0100
#define OPT_MTU         0x0200
#define OPT_DUMP        0x0400
#define OPT_IP2AS       0x0800

static void usage(uint32_t opts)
{
  int i;

  fprintf(stderr,
  "usage: sc_tbitpmtud [-r] [-a addressfile] [-o outfile] [-p port]\n"
  "                    [-c completed] [-l limit] [-m mtu] [-t textfile]\n"
  "                    [-w window]\n"
  "\n"
  "       sc_tbitpmtud [-d dumpid] [-A ip2as] [-m mtu] file1 .. fileN\n");

  if(opts == 0)
    {
      fprintf(stderr, "\n       sc_tbitpmtud -?\n");
      return;
    }
  fprintf(stderr, "\n");

  if(opts & OPT_ADDRESSFILE)
    fprintf(stderr, "       -a: file of systems to probe\n");
  if(opts & OPT_IP2AS)
    fprintf(stderr, "       -A: ip2as file\n");
  if(opts & OPT_COMPLETED)
    fprintf(stderr, "       -c: file to place completed IP addresses\n");
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
  if(opts & OPT_LIMIT)
    fprintf(stderr, "       -l: how many tests before rotating output file\n");
  if(opts & OPT_MTU)
    fprintf(stderr, "       -m: pseudo maximum transmission unit\n");
  if(opts & OPT_OUTFILE)
    fprintf(stderr, "       -o: write raw data to specified file\n");
  if(opts & OPT_PORT)
    fprintf(stderr, "       -p: find local scamper process on local port\n");
  if(opts & OPT_LIMIT)
  if(opts & OPT_RANDOM)
    fprintf(stderr, "       -r: probe systems in random order\n");
  if(opts & OPT_TEXT)
    fprintf(stderr, "       -t: output log file\n");
  if(opts & OPT_WINDOW)
    fprintf(stderr, "       -w: number of tasks allowed to be outstanding\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  int x = 0, ch; long lo;
  char *opts = "?A:a:c:d:l:m:o:p:rt:w:";
  char *opt_port = NULL, *opt_text = NULL, *opt_limit = NULL;
  char *opt_window = NULL, *opt_comp = NULL, *opt_mtu = NULL;
  char *opt_dumpid = NULL;
  uint32_t mandatory = OPT_ADDRESSFILE | OPT_OUTFILE | OPT_PORT;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'a':
	  options |= OPT_ADDRESSFILE;
	  addressfile = optarg;
	  break;

	case 'A':
	  options |= OPT_IP2AS;
	  if(ip2as_files == NULL && (ip2as_files = slist_alloc()) == NULL)
	    return -1;
	  if(slist_tail_push(ip2as_files, optarg) == NULL)
	    return -1;
	  break;

	case 'c':
	  options |= OPT_COMPLETED;
	  opt_comp = optarg;
	  break;

	case 'd':
	  options |= OPT_DUMP;
	  opt_dumpid = optarg;
	  break;

	case 'l':
	  options |= OPT_LIMIT;
	  opt_limit = optarg;
	  break;

	case 'm':
	  options |= OPT_MTU;
	  opt_mtu = optarg;
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
	  options |= OPT_RANDOM;
	  break;

	case 't':
	  options |= OPT_TEXT;
	  opt_text = optarg;
	  break;

	case 'w':
	  options |= OPT_WINDOW;
	  opt_window = optarg;
	  break;

	case '?':
	  usage(0xffffffff);
	  return -1;

	default:
	  usage(0);
	  return -1;
	}
    }

  opt_args = argv + optind;
  opt_argc = argc - optind;

  if(options & OPT_DUMP)
    {
      if(string_isnumber(opt_dumpid) != 0)
	{
	  if(string_tolong(opt_dumpid, &lo) != 0 || lo < 1 || lo > dump_funcc)
	    {
	      usage(OPT_DUMP);
	      return -1;
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
	      return -1;
	    }
	  dump_id = x;
	}

      if(opt_argc < 1)
	{
	  usage(0);
	  return -1;
	}

      if(dump_id == 2 && ip2as_files == NULL)
	{
	  usage(OPT_IP2AS);
	  return -1;
	}
      
      return 0;
    }

  /* these options are mandatory */
  if((options & mandatory) != mandatory)
    {
      if(options == 0) usage(0);
      else             usage(mandatory);
      return -1;
    }

  /* find out which port scamper can be found listening on */
  if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
    {
      usage(OPT_PORT);
      return -1;
    }
  port = lo;

  if(opt_limit != NULL)
    {
      if(string_tolong(opt_limit, &lo) != 0 || lo < 1 || lo > 10000)
	{
	  usage(OPT_LIMIT);
	  return -1;
	}
      limit = lo;
    }
  outfile_obj = limit;

  if(opt_window != NULL)
    {
      if(string_tolong(opt_window, &lo) != 0 || lo < 1)
	{
	  usage(OPT_WINDOW);
	  return -1;
	}
      window = lo;
    }

  if(opt_text != NULL)
    {
      if((text = fopen(opt_text, "w")) == NULL)
	{
	  usage(OPT_TEXT);
	  fprintf(stderr, "could not open %s\n", opt_text);
	  return -1;
	}
    }

  if(opt_comp != NULL)
    {
      if((comp = fopen(opt_comp, "a")) == NULL)
	{
	  usage(OPT_COMPLETED);
	  fprintf(stderr, "could not open %s\n", opt_comp);
	  return -1;
	}
    }

  if(opt_mtu != NULL)
    {
      if(string_tolong(opt_mtu, &lo) != 0 ||
	 (lo != 0 && lo != 256 && lo != 576 && lo != 1280 && lo != 1500))
	{
	  usage(OPT_MTU);
	  return -1;
	}
      mtu = (uint16_t)lo;
    }

  return 0;
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
  char time[32], msg[512];
  struct tm *tm;
  time_t t;

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  t = now.tv_sec;
  if((tm = localtime(&t)) != NULL)
    {
      snprintf(time, sizeof(time), "[%02d:%02d:%02d:%03ld]", tm->tm_hour,
	       tm->tm_min, tm->tm_sec, (long int)now.tv_usec / 1000);
    }
  else
    {
      snprintf(time, sizeof(time), "[%12ld]", (long int)now.tv_sec);
    }

  printf("%s %s", time, msg);

  if(text != NULL)
    {
      fprintf(text, "%s %s", time, msg);
      fflush(text);
    }

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

static void target_url_free(target_url_t *url)
{
  if(url == NULL)
    return;

  if(url->url != NULL)
    free(url->url);
  free(url);
  return;
}

static int target_url_size_cmp(const void *va, const void *vb)
{
  const target_url_t *a = va;
  const target_url_t *b = vb;
  if(a->size < b->size) return  1;
  if(a->size > b->size) return -1;
  return 0;
}

static int target_next_cmp(const void *va, const void *vb)
{
  const target_t *a = va;
  const target_t *b = vb;
  return timeval_cmp(&b->next, &a->next);
}

static int target_addr_cmp(const void *va, const void *vb)
{
  const target_t *a = va;
  const target_t *b = vb;
  return scamper_addr_cmp(a->addr, b->addr);
}

static void target_onremove(void *ptr)
{
  target_t *target = ptr;
  target->hn = NULL;
  return;
}

static void target_free(target_t *target)
{
  target_url_t *url;

  if(target == NULL)
    return;

  if(target->urls != NULL)
    {
      while((url = heap_remove(target->urls)) != NULL)
	target_url_free(url);
      heap_free(target->urls, NULL);
    }

  if(target->hn != NULL)
    heap_delete(heap, target->hn);

  if(target->tn != NULL)
    splaytree_remove_node(tree, target->tn);

  if(target->addr != NULL)
    scamper_addr_free(target->addr);

  free(target);
  return;
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

static int do_method(void)
{
  target_t *target;
  target_url_t *url;
  char addr[128];
  size_t off = 0;

  if(more < 1)
    return 0;

  if((target = heap_head_item(heap)) != NULL &&
     timeval_cmp(&target->next, &now) <= 0)
    {
      target = heap_remove(heap);
    }
  else if((target = slist_head_pop(list)) == NULL)
    {
      return 0;
    }

  if(target->tn == NULL && (target->tn=splaytree_insert(tree,target)) == NULL)
    {
      return -1;
    }

  scamper_addr_tostr(target->addr, addr, sizeof(addr));

  if(target->mode == MODE_PING)
    {
      string_concat(command_buf, sizeof(command_buf), &off,
		    "ping -U %d -c 4 -o 1 %s\n", target->pos, addr);
    }
  else if(target->mode == MODE_TBIT)
    {
      if((url = heap_head_item(target->urls)) == NULL)
	{
	  target_free(target);
	  return 0;
	}

      string_concat(command_buf, sizeof(command_buf), &off,
		    "tbit -t pmtud -U %d", target->pos);
      if(string_firstof_char(url->url, '\'') == NULL)
	string_concat(command_buf, sizeof(command_buf), &off, " -u '%s'",
		      url->url);
      else
	string_concat(command_buf, sizeof(command_buf), &off, " -u \"%s\"",
		      url->url);
      string_concat(command_buf, sizeof(command_buf), &off,
		    " -s %d -m %d -M %d %s\n",
		    target->sport, target->mss, target->mtu, addr);

      if(off == sizeof(command_buf))
	{
	  target_free(target);
	  return 0;
	}
    }
  else
    {
      target_free(target);
      return -1;
    }

  write_wrap(scamper_fd, command_buf, NULL, off);
  probing++;
  more--;

  print("p %d/%d, v %d : %s", probing, splaytree_count(tree),
	slist_count(list), command_buf);

  return 0;
}

static int parse_list(char *str, void *param)
{
  char *pos, *size, *ip, *url, *ptr = str;
  target_t *target, tf;
  target_url_t *tu;
  int i;

  if(str[0] == '\0')
    return 0;

  pos = ptr;
  while(*ptr != ',')
    ptr++;
  *ptr = '\0';
  ptr++;

  while(*ptr != ' ')
    ptr++;
  ptr++;

  size = ptr;
  while(*ptr != ' ')
    ptr++;
  *ptr = '\0';
  ptr++;

  ip = ptr;
  while(*ptr != ' ')
    ptr++;
  *ptr = '\0';
  ptr++;

  url = ptr;

  /* skip long URLs that might mean we can't fit an entire command */
  if(strlen(url) > 300)
    return 0;

  if(string_firstof_char(url, '\'') != NULL &&
     string_firstof_char(url, '\"') != NULL)
    return 0;

  i = atoi(pos);

  if((tf.addr = scamper_addr_resolve(AF_UNSPEC, ip)) == NULL)
    return -1;

  if(scamper_addr_isreserved(tf.addr) != 0 ||
     (SCAMPER_ADDR_TYPE_IS_IPV6(tf.addr) &&
      scamper_addr_isunicast(tf.addr) != 1))
    {
      scamper_addr_free(tf.addr);
      return 0;
    }

  if((target = splaytree_find(tree, &tf)) == NULL)
    {
      if((target = malloc_zero(sizeof(target_t))) == NULL)
	return -1;
      if((target->urls = heap_alloc(target_url_size_cmp)) == NULL)
	return -1;

      target->pos   = i;
      target->mtu   = mtu == 0 ? 1480 : mtu;
      target->addr  = scamper_addr_use(tf.addr);
      target->sport = 1024;

      if(target->addr->type == SCAMPER_ADDR_TYPE_IPV4)
	target->mss = 1460;
      else
	target->mss = 1440;

      if(splaytree_insert(tree, target) == NULL)
	return -1;

      if(slist_tail_push(list, target) == NULL)
	return -1;
    }

  scamper_addr_free(tf.addr);

  if(i < target->pos)
    target->pos = i;

  if((tu = malloc_zero(sizeof(target_url_t))) == NULL ||
     (tu->url = strdup(url)) == NULL)
    return -1;
  tu->size = atoi(size);
  if(heap_insert(target->urls, tu) == NULL)
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
  struct sockaddr_in sin;
  struct in_addr in;

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
		write_wrap(decode_out_fd, uu, NULL, uus);

	      data_left -= (linelen + 1);
	    }
	  /* if the scamper process is asking for more tasks, give it more */
	  else if(linelen == 4 && strncasecmp(head, "MORE", linelen) == 0)
	    {
	      if(more != 0)
		{
		  fprintf(stderr, "lost syncrhonisation\n");
		  goto err;
		}
	      more++;
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
	      /* err, nothing to do */
	    }
	  /* feedback letting us know that the command was not accepted */
	  else if(linelen == 3 && strncasecmp(head, "ERR", 3) == 0)
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
 * do_files
 *
 * open a socketpair that can be used to feed warts data into one end and
 * have the scamper_file routines decode it via the other end.
 *
 * also open a file to send the binary warts data file to.
 */
static int do_files(void)
{
  int pair[2];

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

static int process_ping(target_t *target, scamper_ping_t *ping)
{
  assert(target->mode == MODE_PING);
  scamper_ping_free(ping);
  target->mode = MODE_TBIT;

  timeval_add_s(&target->next, &now, 1);

  if((target->hn = heap_insert(heap, target)) == NULL)
    {
      fprintf(stderr, "process_ping: could not insert into heap");
      return -1;
    }

  return 0;
}

static int process_tbit(target_t *target, scamper_tbit_t *tbit)
{
  char buf[128];
  int ipv6 = 0;

  assert(target->mode == MODE_TBIT);

  target->sport++;

  if(target->addr->type == SCAMPER_ADDR_TYPE_IPV6)
    ipv6 = 1;

  /* some conditions mean that we'll stop evaluating pmtud */
  if(mtu != 0 || target->mtu == 256 || (target->mtu == 576 && ipv6))
    {
      if(comp != NULL)
	{
	  fprintf(comp, "%s\n",
		  scamper_addr_tostr(target->addr,buf,sizeof(buf)));
	  fflush(comp);
	}
      target_free(target);
      scamper_tbit_free(tbit);
      return 0;
    }

  if(target->mtu == 1480)
    {
      if(ipv6 == 1 && mtu == 0)
	target->mss = 1380;
      target->mtu = 1280;
    }
  else if(target->mtu == 1280)
    {
      if(ipv6 == 1 && mtu == 0)
	target->mss = 1220;
      target->mtu = 576;
    }
  else if(target->mtu == 576)
    {
      target->mtu = 256;
    }
  else
    {
      target_free(target);
      scamper_tbit_free(tbit);
      return 0;
    }

  /* wait a minute before we try again */
  timeval_add_s(&target->next, &now, 60);
  if((target->hn = heap_insert(heap, target)) == NULL)
    {
      fprintf(stderr, "process_tbit: could not insert into heap");
      return -1;
    }

  scamper_tbit_free(tbit);
  return 0;
}

static int do_decoderead(void)
{
  scamper_ping_t *ping = NULL;
  scamper_tbit_t *tbit = NULL;
  target_t       *target, findme;
  void           *data;
  uint16_t        type;
  char            buf[1024];
  int             rc;

  /* try and read a ping from the warts decoder */
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

  /* rotate the file if necessary */
  if(outfile_obj >= limit)
    {
      if(outfile != NULL)
	{
	  scamper_file_close(outfile);
	  outfile = NULL;
	}
      outfile_obj = 0;
      snprintf(buf, sizeof(buf), "%s_%02d.warts", outfile_name, outfile_i++);
      if((outfile = scamper_file_open(buf, 'w', "warts")) == NULL)
	return -1;
    }

  if(type == SCAMPER_FILE_OBJ_PING)
    {
      ping = (scamper_ping_t *)data;
      findme.addr = ping->dst;
      if(scamper_file_write_ping(outfile, ping) != 0)
	return -1;
      outfile_obj++;
    }
  else if(type == SCAMPER_FILE_OBJ_TBIT)
    {
      tbit = (scamper_tbit_t *)data;
      findme.addr = tbit->dst;
      if(scamper_file_write_tbit(outfile, tbit) != 0)
	return -1;
      outfile_obj++;
    }
  else return -1;

  if((target = splaytree_find(tree, &findme)) == NULL)
    {
      fprintf(stderr, "do_decoderead: could not find dst %s\n",
	      scamper_addr_tostr(findme.addr, buf, sizeof(buf)));
      goto err;
    }

  if(ping != NULL)
    rc = process_ping(target, ping);
  else if(tbit != NULL)
    rc = process_tbit(target, tbit);
  else
    rc = -1;

  return rc;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  if(tbit != NULL) scamper_tbit_free(tbit);
  return -1;
}

static int pmtud_data(void)
{
  struct timeval tv, *tv_ptr;
  target_t *target;
  fd_set rfds;
  int nfds;

  if((tree = splaytree_alloc(target_addr_cmp)) == NULL)
    return -1;
  if((heap = heap_alloc(target_next_cmp)) == NULL)
    return -1;
  heap_onremove(heap, target_onremove);
  if((list = slist_alloc()) == NULL)
    return -1;
  if(file_lines(addressfile, parse_list, NULL) != 0)
    return -1;
  splaytree_empty(tree, NULL);

  if((options & OPT_RANDOM) != 0)
    {
      random_seed();
      slist_shuffle(list);
    }

  if(do_scamperconnect() != 0)
    return -1;
  if(do_files() != 0)
    return -1;

  /* attach */
  snprintf(command_buf, sizeof(command_buf), "attach\n");
  if(write_wrap(scamper_fd, command_buf, NULL, 7) != 0)
    {
      fprintf(stderr, "could not attach to scamper process\n");
      return -1;
    }

  for(;;)
    {
      nfds = 0;
      FD_ZERO(&rfds);

      if(scamper_fd < 0 && decode_in_fd < 0)
	{
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

      if(splaytree_count(tree) == 0 && slist_count(list) == 0)
	break;

      tv_ptr = NULL;
      if(more > 0)
	{
	  if(slist_count(list) > 0 &&
	     (window == 0 || splaytree_count(tree) < window))
	    {
	      memset(&tv, 0, sizeof(tv));
	      tv_ptr = &tv;
	    }
	  else if((target = heap_head_item(heap)) != NULL)
	    {
	      gettimeofday_wrap(&now);
	      if(timeval_cmp(&now, &target->next) <= 0)
		timeval_diff_tv(&tv, &now, &target->next);
	      else
		memset(&tv, 0, sizeof(tv));
	      tv_ptr = &tv;
	    }
	}

      if(select(nfds+1, &rfds, NULL, NULL, tv_ptr) < 0)
	{
	  if(errno == EINTR) continue;
	  break;
	}
      gettimeofday_wrap(&now);

      if(FD_ISSET(decode_in_fd, &rfds))
	{
	  if(do_decoderead() != 0)
	    return -1;
	}

      if(FD_ISSET(scamper_fd, &rfds))
	{
	  if(do_scamperread() != 0)
	    return -1;
	}

      if(more > 0)
	{
	  do_method();
	}
    }

  return 0;
}

static void sc_prefix_free(sc_prefix_t *p)
{
  if(p == NULL)
    return;
  if(p->af == AF_INET)
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

static void prefix4_prefix_free(prefix4_t *p)
{
  sc_prefix_free(p->ptr);
  return;
}

static void prefix6_prefix_free(prefix6_t *p)
{
  sc_prefix_free(p->ptr);
  return;
}

static sc_prefix_t *sc_prefix_alloc(int af, void *net, int len)
{
  sc_prefix_t *p;

  if((p = malloc_zero(sizeof(sc_prefix_t))) == NULL)
    goto err;
  p->af = af;
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

static int ip2as_line(char *line, void *param)
{
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

  if(inet_pton(AF_INET, n, &in) == 1)
    {
      if(lo < IPV4_PREFIX_MIN || lo > IPV4_PREFIX_MAX)
	return 0;
      sa.type = SCAMPER_ADDR_TYPE_IPV4;
      sa.addr = &in;
      if(scamper_addr_isreserved(&sa))
	return 0;
      if((p = sc_prefix_alloc(AF_INET, &in, lo)) == NULL)
	goto err;
    }
  else if(inet_pton(AF_INET6, n, &in6) == 1)
    {
      if(lo < IPV6_PREFIX_MIN || lo > IPV6_PREFIX_MAX)
	return 0;
      sa.type = SCAMPER_ADDR_TYPE_IPV6;
      sa.addr = &in6;
      if(scamper_addr_isreserved(&sa))
	return 0;
      if((p = sc_prefix_alloc(AF_INET6, &in6, lo)) == NULL)
	goto err;
    }
  else goto err;

  for(at = a; last == 0; at++)
    {
      if(*at != '_' && *at != ',' && *at != ' ' && *at != '\0')
	continue;
      if(*at == ' ' || *at == '\0') last = 1;
      *at = '\0';
      u32 = atoi(a);
      /* skip over private / reserved ASNs */
      if(u32 == 0 || u32 == 23456 ||
	 (u32 >= 64512 && u32 <= 65535) || u32 >= 4200000000UL)
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

  if((p->af == AF_INET &&
      prefixtree_insert4(ip2as_pt_4, p->pfx.v4) == NULL) ||
     (p->af == AF_INET6 &&
      prefixtree_insert6(ip2as_pt_6, p->pfx.v6) == NULL))
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

static sc_prefix_t *sc_prefix_find(scamper_addr_t *addr)
{
  prefix4_t *p4;
  prefix6_t *p6;

  if(addr->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      if((p4 = prefixtree_find_ip4(ip2as_pt_4, addr->addr)) == NULL)
        return NULL;
      return p4->ptr;
    }
  else if(addr->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      if((p6 = prefixtree_find_ip6(ip2as_pt_6, addr->addr)) == NULL)
        return NULL;
      return p6->ptr;
    }

  return NULL;
}

static int do_ip2as(void)
{
  char *name;

  if(ip2as_files == NULL)
    return -1;
  if((ip2as_pt_4 = prefixtree_alloc(AF_INET)) == NULL)
    return -1;
  if((ip2as_pt_6 = prefixtree_alloc(AF_INET6)) == NULL)
    return -1;
  if((asmaptree = splaytree_alloc((splaytree_cmp_t)sc_asmap_cmp)) == NULL)
    return -1;

  while((name = slist_head_pop(ip2as_files)) != NULL)
    {
      if(file_lines(name, ip2as_line, NULL) != 0)
	return -1;
    }

  return 0;
}

static char *percentage(char *buf, size_t len, uint32_t a, uint32_t x)
{
  size_t off = 0;
  if(x == 0) string_concat(buf, len, &off, "-");
  else if(a == x) string_concat(buf, len, &off, "100%%");
  else string_concat(buf, len, &off, "%.1f%%", (float)(a * 100) / x);
  return buf;    
}

typedef struct sc_mssresult
{
  uint16_t mss;
  uint32_t count;
  uint32_t results[4]; /* success, fail, toosmall, other */
} sc_mssresult_t;

static sc_mssresult_t **table_1_4 = NULL;
static sc_mssresult_t  *total_1_4 = NULL;
static sc_mssresult_t **table_1_6 = NULL;
static sc_mssresult_t  *total_1_6 = NULL;

static int sc_mssresult_cmp(const sc_mssresult_t *a, const sc_mssresult_t *b)
{
  if(a->count > b->count) return -1;
  if(a->count < b->count) return  1;
  if(a->mss > b->mss) return -1;
  if(a->mss < b->mss) return  1;
  return 0;
}

static int init_1(void)
{
  if((table_1_4 = malloc_zero(sizeof(sc_mssresult_t *) * 65536)) == NULL)
    return -1;
  if((total_1_4 = malloc_zero(sizeof(sc_mssresult_t))) == NULL)
    return -1;
  if((table_1_6 = malloc_zero(sizeof(sc_mssresult_t *) * 65536)) == NULL)
    return -1;
  if((total_1_6 = malloc_zero(sizeof(sc_mssresult_t))) == NULL)
    return -1;
  return 0;
}

static int process_1_tbit(scamper_tbit_t *tbit)
{
  scamper_tbit_pmtud_t *pmtud;
  sc_mssresult_t *mr;
  sc_mssresult_t *tmr;
  int rc = -1;
  int x;

  if(tbit->server_mss == 0 || tbit->type != SCAMPER_TBIT_TYPE_PMTUD)
    {
      rc = 0;
      goto done;
    }

  pmtud = tbit->data;
  if(pmtud->mtu != mtu)
    {
      rc = 0;
      goto done;
    }

  if(SCAMPER_ADDR_TYPE_IS_IPV4(tbit->dst))
    {
      if((mr = table_1_4[tbit->server_mss]) == NULL)
	{
	  if((mr = malloc_zero(sizeof(sc_mssresult_t))) == NULL)
	    goto done;
	  table_1_4[tbit->server_mss] = mr;
	  mr->mss = tbit->server_mss;
	}
      tmr = total_1_4;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(tbit->dst))
    {
      if((mr = table_1_6[tbit->server_mss]) == NULL)
	{
	  if((mr = malloc_zero(sizeof(sc_mssresult_t))) == NULL)
	    goto done;
	  table_1_6[tbit->server_mss] = mr;
	  mr->mss = tbit->server_mss;
	}
      tmr = total_1_6;
    }
  else goto done;

  if(tbit->result == SCAMPER_TBIT_RESULT_PMTUD_SUCCESS)
    x = 0;
  else if(tbit->result == SCAMPER_TBIT_RESULT_PMTUD_FAIL)
    x = 1;
  else if(tbit->result == SCAMPER_TBIT_RESULT_PMTUD_TOOSMALL)
    x = 2;
  else
    x = 3;
  mr->results[x]++;
  tmr->results[x]++;
  mr->count++;
  tmr->count++;

  rc = 0;

 done:
  scamper_tbit_free(tbit);
  return rc;
}

static int finish_1(void)
{
  sc_mssresult_t **table;
  sc_mssresult_t *mr, *tmr;
  slist_t *list = NULL;
  int i, v, rc = -1;
  char buf[8];

  if((list = slist_alloc()) == NULL)
    goto done;

  for(v=0; v<2; v++)
    {
      if(v == 0)
	{
	  table = table_1_4;
	  tmr = total_1_4;
	  printf(" IPv4 |");
	}
      else
	{
	  table = table_1_6;
	  tmr = total_1_6;
	  printf(" IPv6 |");
	}

      for(i=0; i<65536; i++)
	{
	  if(table[i] != NULL && slist_tail_push(list, table[i]) == NULL)
	    goto done;
	}
      slist_qsort(list, (slist_cmp_t)sc_mssresult_cmp);

      printf("    success   |     fail     |   toosmall   |    other    |    total");
      printf("\n");
      printf("total |");
      for(i=0; i<3; i++)
	printf(" %6d %5s |", tmr->results[i],
	       percentage(buf, sizeof(buf), tmr->results[i], tmr->count));
      printf(" %5d %5s | %6d\n", tmr->results[3],
	     percentage(buf, sizeof(buf), tmr->results[3], tmr->count),
	     tmr->count);
      printf("----------------------------------------------------------------------------\n");
      while((mr = slist_head_pop(list)) != NULL)
	{
	  printf("%5d |", mr->mss);
	  for(i=0; i<3; i++)
	    printf(" %6d %5s |", mr->results[i],
		 percentage(buf, sizeof(buf), mr->results[i], mr->count));
	  printf(" %5d %5s |", mr->results[3],
		 percentage(buf, sizeof(buf), mr->results[3], mr->count));
	  printf(" %6d %5s\n", mr->count,
		 percentage(buf, sizeof(buf), mr->count, tmr->count));
	}
      printf("\n");
    }

  rc = 0;

 done:
  for(i=0; i<65536; i++)
    if(table_1_4[i] != NULL)
      free(table_1_4[i]);
  free(table_1_4);
  for(i=0; i<65536; i++)
    if(table_1_6[i] != NULL)
      free(table_1_6[i]);
  free(table_1_6);
  free(total_1_4);
  free(total_1_6);
  if(list != NULL) slist_free(list);
  return rc;
}

typedef struct sc_asnresult
{
  sc_asmap_t *asmap;
  uint32_t count;
  uint32_t results[4]; /* success, fail, toosmall, other */
} sc_asnresult_t;

static int sc_asnresult_as_cmp(const sc_asnresult_t *a,const sc_asnresult_t *b)
{
  return sc_asmap_cmp(a->asmap, b->asmap);
}

static int sc_asnresult_c_cmp(const sc_asnresult_t *a,const sc_asnresult_t *b)
{
  if(a->count > b->count) return -1;
  if(a->count < b->count) return  1;
  return sc_asmap_cmp(a->asmap, b->asmap);
}

static sc_asnresult_t *sc_asnresult_get(splaytree_t *tree, sc_asmap_t *asmap)
{
  sc_asnresult_t fm, *asr;

  fm.asmap = asmap;
  if((asr = splaytree_find(tree, &fm)) != NULL)
    return asr;

  if((asr = malloc_zero(sizeof(sc_asnresult_t))) == NULL)
    return NULL;
  asr->asmap = asmap;
  if(splaytree_insert(tree, asr) == NULL)
    {
      free(asr);
      return NULL;
    }

  return asr;
}

static splaytree_t *tree_2_4 = NULL;
static splaytree_t *tree_2_6 = NULL;
static sc_asnresult_t *total_2_4 = NULL;
static sc_asnresult_t *total_2_6 = NULL;

static int init_2(void)
{
  if(do_ip2as() != 0)
    return -1;

  tree_2_4 = splaytree_alloc((splaytree_cmp_t)sc_asnresult_as_cmp);
  tree_2_6 = splaytree_alloc((splaytree_cmp_t)sc_asnresult_as_cmp);
  if(tree_2_4 == NULL || tree_2_6 == NULL)
    return -1;

  if((total_2_4 = malloc_zero(sizeof(sc_asnresult_t))) == NULL ||
     (total_2_6 = malloc_zero(sizeof(sc_asnresult_t))) == NULL)
    return -1;

  return 0;
}

static int process_2_tbit(scamper_tbit_t *tbit)
{
  scamper_tbit_pmtud_t *pmtud;
  sc_asnresult_t *tasr, *asr;
  splaytree_t *tree;
  sc_prefix_t *pfx;
  int x, rc = -1;

  if(tbit->server_mss == 0 || tbit->type != SCAMPER_TBIT_TYPE_PMTUD)
    {
      rc = 0;
      goto done;
    }

  pmtud = tbit->data;
  if(pmtud->mtu != mtu || (pfx = sc_prefix_find(tbit->dst)) == NULL)
    {
      rc = 0;
      goto done;
    }

  if(SCAMPER_ADDR_TYPE_IS_IPV4(tbit->dst))
    {
      tree = tree_2_4;
      tasr = total_2_4;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(tbit->dst))
    {
      tree = tree_2_6;
      tasr = total_2_6;
    }
  else goto done;

  if((asr = sc_asnresult_get(tree, pfx->asmap)) == NULL)
    goto done;
  
  if(tbit->result == SCAMPER_TBIT_RESULT_PMTUD_SUCCESS)
    x = 0;
  else if(tbit->result == SCAMPER_TBIT_RESULT_PMTUD_FAIL)
    x = 1;
  else if(tbit->result == SCAMPER_TBIT_RESULT_PMTUD_TOOSMALL)
    x = 2;
  else
    x = 3;
  asr->results[x]++;
  asr->count++;
  tasr->results[x]++;
  tasr->count++;
  rc = 0;

 done:
  scamper_tbit_free(tbit);
  return rc;
}

static int finish_2(void)
{
  splaytree_t *tree;
  sc_asnresult_t *tasr, *asr;
  slist_t *list = NULL;
  int i, v, rc = -1;
  char buf[256];

  if((list = slist_alloc()) == NULL)
    goto done;

  for(v=0; v<2; v++)
    {
      if(v == 0)
	{
	  tree = tree_2_4;
	  tasr = total_2_4;
	}
      else
	{
	  tree = tree_2_6;
	  tasr = total_2_6;
	}
      
      splaytree_inorder(tree, tree_to_slist, list);
      if(slist_count(list) == 0)
	continue;
      slist_qsort(list, (slist_cmp_t)sc_asnresult_c_cmp);

      if(v == 0)
	printf("  IPv4 |");
      else
	printf("  IPv6 |");

      printf("    success   |     fail     |   toosmall   |    other    |    total");
      printf("\n");
      printf(" total |");
      for(i=0; i<3; i++)
	printf(" %6d %5s |", tasr->results[i],
	       percentage(buf, sizeof(buf), tasr->results[i], tasr->count));
      printf(" %5d %5s | %6d\n", tasr->results[3],
	     percentage(buf, sizeof(buf), tasr->results[3], tasr->count),
	     tasr->count);
      printf("----------------------------------------------------------------------------\n");
      while((asr = slist_head_pop(list)) != NULL)
	{
	  printf("%6s |", sc_asmap_tostr(asr->asmap, buf, sizeof(buf)));
	  for(i=0; i<3; i++)
	    printf(" %6d %5s |", asr->results[i],
		 percentage(buf, sizeof(buf), asr->results[i], asr->count));
	  printf(" %5d %5s |", asr->results[3],
		 percentage(buf, sizeof(buf), asr->results[3], asr->count));
	  printf(" %6d %5s\n", asr->count,
		 percentage(buf, sizeof(buf), asr->count, tasr->count));
	}
      printf("\n");
    }
  rc = 0;

 done:
  if(list != NULL) slist_free(list);
  if(tree_2_4 != NULL) splaytree_free(tree_2_4, free);
  if(tree_2_6 != NULL) splaytree_free(tree_2_6, free);
  if(total_2_4 != NULL) free(total_2_4);
  if(total_2_6 != NULL) free(total_2_6);
  return rc;
}

static int pmtud_dump(void)
{
  scamper_file_t *in;
  char *filename;
  uint16_t type;
  void *data;
  int rc = -1, i, x, stdin_used=0;

  if(dump_funcs[dump_id].init != NULL && dump_funcs[dump_id].init() != 0)
    return -1;

  for(i=0; i<opt_argc; i++)
    {
      filename = opt_args[i];
      if(strcmp(filename, "-") == 0)
	{
	  if(stdin_used == 1)
	    {
	      fprintf(stderr, "stdin already used\n");
	      goto done;
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
	  goto done;
	}

      while(scamper_file_read(in, ffilter, &type, &data) == 0)
	{
	  /* EOF */
	  if(data == NULL)
	    break;

	  x = 0;
	  if(type == SCAMPER_FILE_OBJ_TBIT)
	    {
	      if(dump_funcs[dump_id].proc_tbit != NULL)
		x = dump_funcs[dump_id].proc_tbit(data);
	      else
		scamper_tbit_free(data);
	    }
	  else if(type == SCAMPER_FILE_OBJ_PING)
	    {
	      if(dump_funcs[dump_id].proc_ping != NULL)
		x = dump_funcs[dump_id].proc_ping(data);
	      else
		scamper_ping_free(data);
	    }
	  else x = -1;

	  if(x != 0)
	    goto done;
	}

      scamper_file_close(in);
    }

  if(dump_funcs[dump_id].finish != NULL)
    rc = dump_funcs[dump_id].finish();

 done:
  return rc;
}

static void cleanup(void)
{
  if(ip2as_pt_4 != NULL)
    {
      prefixtree_free_cb(ip2as_pt_4, (prefix_free_t)prefix4_prefix_free);
      ip2as_pt_4 = NULL;
    }

  if(ip2as_pt_6 != NULL)
    {
      prefixtree_free_cb(ip2as_pt_6, (prefix_free_t)prefix6_prefix_free);
      ip2as_pt_6 = NULL;
    }

  if(asmaptree != NULL)
    {
      splaytree_free(asmaptree, (splaytree_free_t)sc_asmap_free);
      asmaptree = NULL;
    }

  if(ip2as_files != NULL)
    {
      slist_free(ip2as_files);
      ip2as_files = NULL;
    }

  if(tree != NULL)
    {
      splaytree_free(tree, NULL);
      tree = NULL;
    }

  if(list != NULL)
    {
      slist_free(list);
      list = NULL;
    }

  if(heap != NULL)
    {
      heap_free(heap, NULL);
      heap = NULL;
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

  if(outfile != NULL)
    {
      scamper_file_close(outfile);
      outfile = NULL;
    }

  return;
}

int pmtud_init(void)
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_TBIT, SCAMPER_FILE_OBJ_PING};
  if((ffilter = scamper_file_filter_alloc(types, 2)) == NULL)
    return -1;
  return 0;
}

int main(int argc, char *argv[])
{
#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

  if(pmtud_init() != 0)
    return -1;

  if(options & OPT_DUMP)
    return pmtud_dump();

  return pmtud_data();
}
