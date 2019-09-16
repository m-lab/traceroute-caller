/*
 * sc_tbitblind : scamper driver to collect data on receiver response to
 *              : packets that might have been sent by a blind in-window
 *              : attacker.
 *
 * Authors      : Matthew Luckie, Robert Beverly.
 *
 * Copyright (C) 2015 The Regents of the University of California
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
  "$Id: sc_tbitblind.c,v 1.5 2019/07/12 21:40:13 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "tbit/scamper_tbit.h"
#include "scamper_file.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "mjl_heap.h"
#include "utils.h"

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
static int                    ttl           = 0;
static int                    wait_between  = 0;
static int                    limit         = 10000;
static int                    tbit_app      = SCAMPER_TBIT_APP_HTTP;
static int                    noshuffle     = 0;
static scamper_file_filter_t *decode_filter = NULL;
static scamper_file_t        *decode_in     = NULL;
static int                    decode_in_fd  = -1;
static int                    decode_out_fd = -1;
static int                    data_left     = 0;
static char                   cmd[512];
static int                    more          = 0;
static int                    probing       = 0;
static FILE                  *text          = NULL;
static FILE                  *comp          = NULL;
static struct timeval         now;

static char *methods[] = {
  "-t blind-rst",
  "-t blind-rst -o -70000",
  "-t blind-syn",
  "-t blind-syn -o -70000",
  "-t blind-data",
  "-t blind-data -o 70000",
};
static const int methodc = sizeof(methods) / sizeof(char *);

#define MODE_ICW   0
#define MODE_BLIND 1
#define MODE_FP    2
#define MODE_LAST  2

typedef struct target
{
  scamper_addr_t   *addr;
  struct timeval    next;
  int               mode;
  union
  {
    char           *url;
    uint16_t        asn;
  } un;
  slist_t          *methods;
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
#define OPT_COMPLETED   0x0080
#define OPT_RANDOM      0x0100
#define OPT_WAIT        0x0200
#define OPT_OPTIONS     0x0400
#define OPT_APPTYPE     0x0800
#define OPT_TTL         0x1000

/* XXX: need to handle -? */
static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
  "usage: sc_tbitblind [-?r] [-a addressfile] [-o outfile] [-p port]\n"
  "                    [-A app] [-c comp] [-l limit] [-t logfile] [-T ttl]\n"
  "                    [-O options] [-w wait]\n");
  return;
}

static int check_options(int argc, char *argv[])
{
  int ch;
  long lo;
  char *opts = "A:a:c:l:o:O:p:rt:T:w:";
  char *opt_port = NULL, *opt_text = NULL, *opt_limit = NULL;
  char *opt_wait = NULL, *opt_comp = NULL;
  char *opt_apptype = NULL, *opt_ttl = NULL;
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
	  options |= OPT_APPTYPE;
	  opt_apptype = optarg;
	  break;
	  
	case 'c':
	  options |= OPT_COMPLETED;
	  opt_comp = optarg;
	  break;

	case 'l':
	  options |= OPT_LIMIT;
	  opt_limit = optarg;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  outfile_name = optarg;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "noshuffle") == 0)
	    noshuffle = 1;
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
	  options |= OPT_RANDOM;
	  break;

	case 't':
	  options |= OPT_TEXT;
	  opt_text = optarg;
	  break;

	case 'T':
	  options |= OPT_TTL;
	  opt_ttl = optarg;
	  break;

	case 'w':
	  options |= OPT_WAIT;
	  opt_wait = optarg;
	  break;

	case '?':
	default:
	  usage(0xffffffff);
	  return -1;
	}
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

  if(opt_wait != NULL)
    {
      if(string_tolong(opt_wait, &lo) != 0 || lo < 1 || lo > 180)
	{
	  usage(OPT_WAIT);
	  return -1;
	}
      wait_between = lo;
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

  if(opt_apptype != NULL)
    {
      if(strcasecmp(opt_apptype, "http") == 0)
	tbit_app = SCAMPER_TBIT_APP_HTTP;
      else if(strcasecmp(opt_apptype, "bgp") == 0)
	tbit_app = SCAMPER_TBIT_APP_BGP;
      else
	{
	  usage(OPT_APPTYPE);
	  return -1;
	}
    }

  if(wait_between == 0)
    {
      if(tbit_app == SCAMPER_TBIT_APP_HTTP)
	wait_between = 60;
      else if(tbit_app == SCAMPER_TBIT_APP_BGP)
	wait_between = 180;
    }

  if(opt_ttl != NULL)
    {
      if(string_tolong(opt_ttl, &lo) != 0 || lo < 1 || lo > 255)
	{
	  usage(OPT_TTL);
	  return -1;
	}
      ttl = lo;
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

  return 0;
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
  if(target == NULL)
    return;

  if(tbit_app == SCAMPER_TBIT_APP_HTTP && target->un.url != NULL)
    free(target->un.url);

  if(target->hn != NULL)
    heap_delete(heap, target->hn);

  if(target->tn != NULL)
    splaytree_remove_node(tree, target->tn);

  if(target->addr != NULL)
    scamper_addr_free(target->addr);

  if(target->methods != NULL)
    slist_free(target->methods);
  
  free(target);
  return;
}

static int do_method(void)
{
  target_t *target;
  char addr[128];
  size_t off = 0;
  char *m = NULL;
  int i;

  if(more < 1)
    return 0;

  if((target = heap_head_item(heap)) != NULL &&
     timeval_cmp(&target->next, &now) <= 0)
    {
      target = heap_remove(heap);
    }
  else if((target = slist_head_pop(list)) != NULL)
    {
      if((target->methods = slist_alloc()) == NULL)
	return -1;
      for(i=0; i<methodc; i++)
	if(slist_tail_push(target->methods, methods[i]) == NULL)
	  return -1;
      if(noshuffle == 0)
	slist_shuffle(target->methods);
    }
  else
    {
      return 0;
    }

  if(target->tn == NULL && (target->tn=splaytree_insert(tree,target)) == NULL)
    {
      return -1;
    }

  if(target->mode == MODE_ICW)
    m = "-t icw";
  else if(target->mode == MODE_BLIND)
    m = slist_head_pop(target->methods);
  else if(target->mode == MODE_FP)
    m = "-t null -w 2 -O tcpts -O sack";
  if(m == NULL)
    return -1;

  if(tbit_app == SCAMPER_TBIT_APP_HTTP)
    {
      if(string_firstof_char(target->un.url, '\'') == NULL)
	string_concat(cmd,sizeof(cmd),&off, "tbit -u '%s'", target->un.url);
      else
	string_concat(cmd,sizeof(cmd),&off, "tbit -u \"%s\"", target->un.url);
      if(ttl != 0)
	string_concat(cmd,sizeof(cmd),&off, " -T %d", ttl);
    }
  else if(tbit_app == SCAMPER_TBIT_APP_BGP)
    {
      string_concat(cmd, sizeof(cmd), &off, "tbit -p bgp -T %d -b %d",
		    ttl == 0 ? 69 : ttl, target->un.asn);
    }
  else return -1;

  string_concat(cmd, sizeof(cmd), &off, " %s -s %d %s\n", m, target->sport,
		scamper_addr_tostr(target->addr, addr, sizeof(addr)));
  write_wrap(scamper_fd, cmd, NULL, off);
  probing++;
  more--;

  print("p %d/%d, v %d : %s", probing, splaytree_count(tree),
	slist_count(list), cmd);

  return 0;
}

static int parse_list(char *str, void *param)
{
  char *ip, *url, *asn, *ptr = str;
  target_t *target;
  long lo;

  if(str[0] == '#' || str[0] == '\0')
    return 0;

  if(tbit_app == SCAMPER_TBIT_APP_HTTP)
    {
      /* position in the list */
      while(*ptr != ',' && *ptr != '\0')
	ptr++;
      if(*ptr == '\0')
	return -1;
      *ptr = '\0';
      ptr++;

      while(*ptr != ' ' && *ptr != '\0')
	ptr++;
      if(*ptr == '\0')
	return -1;
      ptr++;

      /* size of the object */
      while(*ptr != ' ' && *ptr != '\0')
	ptr++;
      if(*ptr == '\0')
	return -1;
      *ptr = '\0';
      ptr++;

      ip = ptr;
      while(*ptr != ' ' && *ptr != '\0')
	ptr++;
      if(*ptr == '\0')
	return -1;
      *ptr = '\0';
      ptr++;

      url = ptr;

      /* skip over urls with ' in them */
      if(string_firstof_char(url, '\'') != NULL &&
	 string_firstof_char(url, '\"') != NULL)
	return 0;

      if((target = malloc_zero(sizeof(target_t))) == NULL ||
	 (target->un.url = strdup(url)) == NULL)
	return -1;
      target->addr  = scamper_addr_resolve(AF_UNSPEC, ip);
      target->sport = 1050;
    }
  else if(tbit_app == SCAMPER_TBIT_APP_BGP)
    {
      /* ipaddress asn */
      ip = ptr;
      while(*ptr != ' ' && *ptr != '\0')
	ptr++;
      *ptr = '\0';
      ptr++;

      asn = ptr;
      while(*ptr != ' ' && *ptr != '\0')
	ptr++;
      *ptr = '\0';

      if(string_tolong(asn, &lo) != 0 || lo < 1 || lo > 65535)
	return -1;
      if((target = malloc_zero(sizeof(target_t))) == NULL)
	return -1;
      target->addr = scamper_addr_resolve(AF_UNSPEC, ip);
      target->sport = 1050;
      target->un.asn = lo;
      target->mode = MODE_BLIND;
    }
  else return -1;

  if(splaytree_insert(tree, target) == NULL ||
     slist_tail_push(list, target) == NULL)
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
  uint16_t types[] = {SCAMPER_FILE_OBJ_TBIT};
  int  pair[2];

  if((decode_filter = scamper_file_filter_alloc(types, 1)) == NULL)
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

static int process_tbit(target_t *target, scamper_tbit_t *tbit)
{
  char buf[128];
  int rc = -1;

  target->sport++;

  if(target->mode == MODE_BLIND)
    {
      if(slist_count(target->methods) == 0)
	target->mode++;
    }
  else
    {
      target->mode++;
    }
  
  if(target->mode > MODE_LAST)
    goto completed;
  
  /* wait before we try again, by default a minute */
  timeval_add_s(&target->next, &now, wait_between);
  if((target->hn = heap_insert(heap, target)) == NULL)
    {
      fprintf(stderr, "process_tbit: could not insert into heap");
      goto done;
    }
  rc = 0;

 done:
  scamper_tbit_free(tbit);
  return rc;

 completed:
  if(comp != NULL)
    {
      fprintf(comp, "%s\n", scamper_addr_tostr(target->addr,buf,sizeof(buf)));
      fflush(comp);
    }
  target_free(target);
  scamper_tbit_free(tbit);
  return 0;
}

static int do_decoderead(void)
{
  scamper_tbit_t *tbit = NULL;
  target_t       *target, findme;
  void           *data;
  uint16_t        type;
  char            buf[1024];
  int             rc;

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

  if(type == SCAMPER_FILE_OBJ_TBIT)
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

  if(tbit != NULL)
    rc = process_tbit(target, tbit);
  else
    rc = -1;

  return rc;

 err:
  if(tbit != NULL) scamper_tbit_free(tbit);
  return -1;
}

static void cleanup(void)
{
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

  if(decode_filter != NULL)
    {
      scamper_file_filter_free(decode_filter);
      decode_filter = NULL;
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

int main(int argc, char *argv[])
{
  struct timeval tv, *tv_ptr;
  target_t *target;
  fd_set rfds;
  int nfds;

#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

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
      if(noshuffle == 0)
	slist_shuffle(list);
    }

  if(do_scamperconnect() != 0)
    return -1;
  if(do_files() != 0)
    return -1;

  /* attach */
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

      if(splaytree_count(tree) == 0 && slist_count(list) == 0)
	break;

      tv_ptr = NULL;
      gettimeofday_wrap(&tv);
      if(more > 0)
	{
	  if(slist_count(list) > 0)
	    {
	      memset(&tv, 0, sizeof(tv));
	      tv_ptr = &tv;
	    }
	  else if((target = heap_head_item(heap)) != NULL)
	    {
	      if(timeval_cmp(&tv, &target->next) <= 0)
		timeval_diff_tv(&tv, &tv, &target->next);
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
