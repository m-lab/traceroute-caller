/*
 * sc_attach : scamper driver to collect data by connecting to scamper on
 *             a specified port and supplying it with commands.
 *
 * Author    : Matthew Luckie
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012-2015 Regents of the University of California
 * Copyright (C) 2015-2019 Matthew Luckie
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
  "$Id: sc_attach.c,v 1.25 2019/07/12 21:38:23 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_file.h"
#include "scamper_writebuf.h"
#include "scamper_linepoll.h"
#include "mjl_list.h"
#include "utils.h"

#define OPT_HELP        0x0001
#define OPT_INFILE      0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008
#define OPT_STDOUT      0x0010
#define OPT_VERSION     0x0020
#define OPT_DEBUG       0x0040
#define OPT_PRIORITY    0x0080
#define OPT_DAEMON      0x0100
#define OPT_COMMAND     0x0200
#define OPT_REMOTE      0x0400
#define OPT_OPTIONS     0x0800
#define OPT_UNIX        0x1000

#define FLAG_RANDOM     0x0001
#define FLAG_IMPATIENT  0x0002

static uint32_t               options       = 0;
static uint8_t                flags         = 0;
static char                  *infile_name   = NULL;
static char                  *dst_addr      = NULL;
static int                    dst_port      = 0;
static char                  *unix_name     = NULL;
static uint32_t               priority      = 1;
static int                    scamper_fd    = -1;
static scamper_writebuf_t    *scamper_wb    = NULL;
static scamper_linepoll_t    *scamper_lp    = NULL;
static int                    stdin_fd      = -1;
static scamper_linepoll_t    *stdin_lp      = NULL;
static int                    stdout_fd     = -1;
static scamper_writebuf_t    *stdout_wb     = NULL;
static char                  *outfile_name  = NULL;
static int                    outfile_fd    = -1;
static int                    data_left     = 0;
static int                    more          = 0;
static int                    error         = 0;
static slist_t               *commands      = NULL;
static char                  *opt_command   = NULL;
static int                    done          = 0;

static void cleanup(void)
{
  if(dst_addr != NULL)
    {
      free(dst_addr);
      dst_addr = NULL;
    }

  if(commands != NULL)
    {
      slist_free_cb(commands, free);
      commands = NULL;
    }

  if(outfile_fd != -1)
    {
      close(outfile_fd);
      outfile_fd = -1;
    }

  if(scamper_fd != -1)
    {
      close(scamper_fd);
      scamper_fd = -1;
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

  if(stdin_lp != NULL)
    {
      scamper_linepoll_free(stdin_lp, 0);
      stdin_lp = NULL;
    }

  if(stdout_wb != NULL)
    {
      scamper_writebuf_free(stdout_wb);
      stdout_wb = NULL;
    }

  return;
}

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
	  "usage: sc_attach [-?dDv] [-c command] [-i infile] [-o outfile]\n"
	  "                 [-O options] [-p [ip:]port] [-P priority] \n"
	  "                 [-R unix] [-U unix]\n");

  if(opt_mask == 0) return;

  fprintf(stderr, "\n");

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "     -? give an overview of the usage of sc_attach\n");

  if(opt_mask & OPT_DEBUG)
    fprintf(stderr, "     -d output debugging information to stderr\n");

  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D operate as a daemon\n");

  if(opt_mask & OPT_VERSION)
    fprintf(stderr, "     -v give the version string of sc_attach\n");

  if(opt_mask & OPT_COMMAND)
    fprintf(stderr, "     -c command to use with addresses in input file\n");

  if(opt_mask & OPT_INFILE)
    fprintf(stderr, "     -i input file\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "     -o output warts file\n");

  if(opt_mask & OPT_OPTIONS)
    {
      fprintf(stderr, "     -O options\n");
      fprintf(stderr, "        random: send commands in random order\n");
      fprintf(stderr, "        impatient: send commands in bulk\n");
    }

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -p [ip:]port to find scamper on\n");

  if(opt_mask & OPT_PRIORITY)
    fprintf(stderr, "     -P priority\n");

  if(opt_mask & OPT_REMOTE)
    fprintf(stderr, "     -R unix domain socket for remote scamper\n");

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U unix domain socket for local scamper\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  int       ch;
  long      lo;
  char     *opts = "c:dDi:o:O:p:P:R:U:v?";
  char     *opt_port = NULL, *opt_priority = NULL, *opt_unix = NULL;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'c':
	  opt_command = optarg;
	  break;

	case 'd':
	  options |= OPT_DEBUG;
	  break;

	case 'D':
	  options |= OPT_DAEMON;
	  break;

	case 'i':
	  if(strcasecmp(optarg, "-") == 0)
	    stdin_fd = STDIN_FILENO;
	  else if((options & OPT_INFILE) == 0)
	    infile_name = optarg;
	  else
	    return -1;
	  options |= OPT_INFILE;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  if(strcasecmp(optarg, "-") == 0)
	    options |= OPT_STDOUT;
	  else if(outfile_name == NULL)
	    outfile_name = optarg;
	  else
	    return -1;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "random") == 0)
	    flags |= FLAG_RANDOM;
	  else if(strcasecmp(optarg, "impatient") == 0)
	    flags |= FLAG_IMPATIENT;
	  else
	    return -1;
	  break;

	case 'p':
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case 'P':
	  options |= OPT_PRIORITY;
	  opt_priority = optarg;
	  break;

	case 'R':
	  options |= OPT_REMOTE;
	  opt_unix = optarg;
	  break;

	case 'U':
	  options |= OPT_UNIX;
	  opt_unix = optarg;
	  break;

	case 'v':
	  printf("$Id: sc_attach.c,v 1.25 2019/07/12 21:38:23 mjl Exp $\n");
	  return -1;

	case '?':
	default:
	  usage(0xffffffff);
	  return -1;
	}
    }

  /* these options are mandatory */
  if((options & (OPT_INFILE|OPT_OUTFILE)) != (OPT_INFILE|OPT_OUTFILE) ||
     (options & (OPT_PORT|OPT_REMOTE|OPT_UNIX)) == 0 ||
     ((options & (OPT_PORT|OPT_REMOTE|OPT_UNIX)) != OPT_PORT &&
      (options & (OPT_PORT|OPT_REMOTE|OPT_UNIX)) != OPT_REMOTE &&
      (options & (OPT_PORT|OPT_REMOTE|OPT_UNIX)) != OPT_UNIX))
    {
      if(options == 0) usage(0);
      else usage(OPT_INFILE|OPT_OUTFILE|OPT_PORT|OPT_REMOTE|OPT_UNIX);
      return -1;
    }

  if(options & OPT_PORT)
    {
      if(string_addrport(opt_port, &dst_addr, &dst_port) != 0)
	{
	  usage(OPT_PORT);
	  return -1;
	}
    }
  else if(options & (OPT_REMOTE|OPT_UNIX))
    {
      unix_name = opt_unix;
    }

  if((options & OPT_PRIORITY) != 0)
    {
      if(string_tolong(opt_priority, &lo) != 0 || lo < 1)
	{
	  usage(OPT_PRIORITY);
	  return -1;
	}
      priority = lo;
    }

  if((options & OPT_DAEMON) != 0 &&
     ((options & (OPT_STDOUT|OPT_DEBUG)) != 0 || stdin_fd != -1))
    {
      usage(OPT_DAEMON);
      return -1;
    }

  if(options & OPT_STDOUT)
    {
      stdout_fd = STDOUT_FILENO;
      if(fcntl_set(stdout_fd, O_NONBLOCK) == -1)
	return -1;
      if((stdout_wb = scamper_writebuf_alloc()) == NULL)
	return -1;
      scamper_writebuf_usewrite(stdout_wb);
    }

  return 0;
}

static int command_new(char *line, void *param)
{
  char *tmp = NULL, buf[65535];
  size_t off = 0;

  if(line[0] == '#' || line[0] == '\0')
    return 0;

  if(opt_command != NULL)
    string_concat(buf, sizeof(buf), &off, "%s %s\n", opt_command, line);
  else
    string_concat(buf, sizeof(buf), &off, "%s\n", line);

  if((tmp=memdup(buf,off+1)) == NULL || slist_tail_push(commands,tmp) == NULL)
    {
      fprintf(stderr, "could not push command onto list\n");
      if(tmp != NULL) free(tmp);
      return -1;
    }

  return 0;
}

/*
 * do_outfile
 *
 * open a file to send the binary warts data file to.
 */
static int do_outfile(void)
{
  mode_t mode   = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  int    flags  = O_WRONLY | O_CREAT | O_TRUNC;

  if(outfile_name == NULL)
    return 0;

  if((outfile_fd = open(outfile_name, flags, mode)) == -1)
    {
      fprintf(stderr, "%s: could not open %s: %s\n",
	      __func__, outfile_name, strerror(errno));
      return -1;
    }

  return 0;
}

static int do_method(void)
{
  struct timeval tv;
  char *command;

  if(slist_count(commands) == 0)
    {
      if(stdin_fd == -1 && done == 0)
	{
	  scamper_writebuf_send(scamper_wb, "done\n", 5);
	  done = 1;
	  more = 0;
	}
      return 0;
    }

  gettimeofday_wrap(&tv);
  command = slist_head_pop(commands);
  scamper_writebuf_send(scamper_wb, command, strlen(command));
  if((options & OPT_DEBUG) != 0)
    fprintf(stderr, "%ld: %s", (long int)tv.tv_sec, command);
  if((flags & FLAG_IMPATIENT) == 0)
    more = 0;
  free(command);

  return 0;
}

static int do_stdinread_line(void *param, uint8_t *buf, size_t linelen)
{
  return command_new((char *)buf, NULL);
}

/*
 * do_stdinread
 *
 * the fd for stdin is marked as readable, so do a read on it.
 */
static int do_stdinread(void)
{
  ssize_t rc;
  uint8_t buf[4096];

  if((rc = read(stdin_fd, buf, sizeof(buf))) > 0)
    {
      scamper_linepoll_handle(stdin_lp, buf, rc);
      return 0;
    }
  else if(rc == 0)
    {
      scamper_linepoll_flush(stdin_lp);
      stdin_fd = -1;
      return 0;
    }
  else if(errno == EINTR || errno == EAGAIN)
    {
      return 0;
    }

  fprintf(stderr, "%s: could not read: %s\n", __func__, strerror(errno));
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
	  if(outfile_fd != -1)
	    write_wrap(outfile_fd, uu, NULL, uus);
	  if(stdout_fd != -1)
	    scamper_writebuf_send(stdout_wb, uu, uus);
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
      more = 1;
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
      fprintf(stderr, "%s: command not accepted\n", __func__);
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
  uint8_t buf[4096];

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
 * do_scamperwrite
 *
 * the fd for the scamper process is marked as writable, so write to it.
 */
static int do_scamperwrite(void)
{
  if(scamper_writebuf_write(scamper_fd, scamper_wb) != 0)
    {
      fprintf(stderr, "%s: could not write: %s\n", __func__, strerror(errno));
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
  struct sockaddr_un sun;
  struct sockaddr_storage sas;
  struct sockaddr *sa = (struct sockaddr *)&sas;
  struct in_addr in;
  char buf[256];
  size_t off = 0;

  if(options & OPT_PORT)
    {
      if(dst_addr != NULL)
	{
	  if(sockaddr_compose_str(sa, dst_addr, dst_port) != 0)
	    {
	      fprintf(stderr, "%s: could not compose sockaddr from %s:%d\n",
		      __func__, dst_addr, dst_port);
	      return -1;
	    }
	}
      else
	{
	  in.s_addr = htonl(INADDR_LOOPBACK);
	  sockaddr_compose(sa, AF_INET, &in, dst_port);
	}

      if((scamper_fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
	  fprintf(stderr, "%s: could not allocate new socket: %s\n",
		  __func__, strerror(errno));
	  return -1;
	}
      if(connect(scamper_fd, sa, sockaddr_len(sa)) != 0)
	{
	  fprintf(stderr, "%s: could not connect to scamper process: %s\n",
		  __func__, strerror(errno));
	  return -1;
	}
    }
  else
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
      if(connect(scamper_fd, (const struct sockaddr *)&sun, sizeof(sun)) != 0)
	{
	  fprintf(stderr, "%s: could not connect to scamper process: %s\n",
		  __func__, strerror(errno));
	  return -1;
	}
    }

  if(fcntl_set(scamper_fd, O_NONBLOCK) == -1)
    {
      fprintf(stderr, "%s: could not set nonblock: %s\n",
	      __func__, strerror(errno));
      return -1;
    }

  if((scamper_lp = scamper_linepoll_alloc(do_scamperread_line,NULL)) == NULL ||
     (scamper_wb = scamper_writebuf_alloc()) == NULL)
    {
      fprintf(stderr, "%s: could not alloc wb/lp: %s\n",
	      __func__, strerror(errno));
      return -1;
    }

  if(options & (OPT_PORT|OPT_UNIX))
    {
      string_concat(buf, sizeof(buf), &off, "attach");
      if((options & OPT_PRIORITY) != 0)
	string_concat(buf, sizeof(buf), &off, " priority %d", priority);
      string_concat(buf, sizeof(buf), &off, "\n");
      if(scamper_writebuf_send(scamper_wb, buf, off) != 0)
	{
	  fprintf(stderr, "%s: could not attach to scamper process: %s\n",
		  __func__, strerror(errno));
	  return -1;
	}
    }

  return 0;
}

/*
 * do_stdoutwrite
 *
 * the fd for stdout is marked as writable, so write to it.
 */
static int do_stdoutwrite(void)
{
  if(scamper_writebuf_write(stdout_fd, stdout_wb) != 0)
    {
      fprintf(stderr, "%s: could not write to stdout: %s\n",
	      __func__, strerror(errno));
      return -1;
    }
  if(scamper_writebuf_len(stdout_wb) == 0 && scamper_fd == -1)
    stdout_fd = -1;
  return 0;
}

/*
 * do_infile
 *
 * read the contents of the infile in one hit.
 */
static int do_infile(void)
{
  if(infile_name != NULL)
    {
      if(file_lines(infile_name, command_new, NULL) != 0)
	{
	  fprintf(stderr, "%s: could not read input file %s: %s\n",
		  __func__, infile_name, strerror(errno));
	  return -1;
	}
      if((flags & FLAG_RANDOM) && slist_shuffle(commands) != 0)
	{
	  fprintf(stderr, "%s: could not shuffle commands: %s\n",
		  __func__, strerror(errno));
	  return -1;
	}
    }
  else if(stdin_fd != -1)
    {
      if((stdin_lp = scamper_linepoll_alloc(do_stdinread_line, NULL)) == NULL)
	{
	  fprintf(stderr, "%s: could not alloc linepoll: %s\n",
		  __func__, strerror(errno));
	  return -1;
	}
    }
  return 0;
}

int main(int argc, char *argv[])
{
  fd_set rfds, wfds, *rfdsp, *wfdsp;
  int nfds;

#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  random_seed();

  if(check_options(argc, argv) != 0)
    return -1;

#ifdef HAVE_DAEMON
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    return -1;
#endif

  /* connect to the scamper process */
  if(do_scamperconnect() != 0)
    return -1;

  if((commands = slist_alloc()) == NULL)
    {
      fprintf(stderr, "could not alloc commands list\n");
      return -1;
    }

  if(do_infile() != 0)
    return -1;

  if(do_outfile() != 0)
    return -1;

  while(error == 0)
    {
      nfds = 0; FD_ZERO(&rfds); rfdsp = NULL; FD_ZERO(&wfds); wfdsp = NULL;

      if(more != 0)
	do_method();

      /* interactions with the scamper process */
      if(scamper_fd != -1)
	{
	  FD_SET(scamper_fd, &rfds); rfdsp = &rfds;
	  if(nfds < scamper_fd)
	    nfds = scamper_fd;
	  if(scamper_writebuf_len(scamper_wb) > 0)
	    {
	      FD_SET(scamper_fd, &wfds);
	      wfdsp = &wfds;
	    }
	}

      /* might read commands from stdin */
      if(stdin_fd != -1)
	{
	  FD_SET(stdin_fd, &rfds); rfdsp = &rfds;
	  if(nfds < stdin_fd)
	    nfds = stdin_fd;
	}

      /* might send output to stdout */
      if(stdout_fd != -1 && scamper_writebuf_len(stdout_wb) > 0)
	{
	  FD_SET(stdout_fd, &wfds); wfdsp = &wfds;
	  if(nfds < stdout_fd)
	    nfds = stdout_fd;
	}

      if(nfds == 0)
	break;

      if(select(nfds+1, rfdsp, wfdsp, NULL, NULL) < 0)
	{
	  if(errno == EINTR) continue;
	  fprintf(stderr, "%s: could not select: %s\n",
		  __func__, strerror(errno));
	  break;
	}

      if(stdin_fd != -1 && rfdsp != NULL && FD_ISSET(stdin_fd, rfdsp) &&
	 do_stdinread() != 0)
	return -1;

      if(scamper_fd != -1 && rfdsp != NULL && FD_ISSET(scamper_fd, rfdsp) &&
	 do_scamperread() != 0)
	return -1;

      if(scamper_fd != -1 && wfdsp != NULL && FD_ISSET(scamper_fd, wfdsp) &&
	 do_scamperwrite() != 0)
	return -1;

      if(stdout_fd != -1 && wfdsp != NULL && FD_ISSET(stdout_fd, wfdsp) &&
	 do_stdoutwrite() != 0)
	return -1;
    }

  return 0;
}
