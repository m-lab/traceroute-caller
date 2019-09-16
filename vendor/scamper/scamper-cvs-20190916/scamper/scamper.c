/*
 * scamper
 *
 * $Id: scamper.c,v 1.263 2019/01/13 06:58:50 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2014      The Regents of the University of California
 * Copyright (C) 2014-2019 Matthew Luckie
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
  "$Id: scamper.c,v 1.263 2019/01/13 06:58:50 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_debug.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_file.h"
#include "scamper_outfiles.h"
#include "scamper_fds.h"
#include "scamper_task.h"
#include "scamper_sources.h"
#include "scamper_source_cmdline.h"
#include "scamper_source_file.h"
#include "scamper_source_tsps.h"
#include "scamper_queue.h"
#include "scamper_getsrc.h"
#include "scamper_addr2mac.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_udp4.h"
#include "scamper_udp6.h"
#include "scamper_tcp4.h"
#include "scamper_rtsock.h"
#include "scamper_dl.h"
#include "scamper_firewall.h"
#include "scamper_probe.h"
#include "scamper_privsep.h"
#include "scamper_control.h"
#include "scamper_osinfo.h"
#include "trace/scamper_trace_do.h"
#include "ping/scamper_ping_do.h"
#include "tracelb/scamper_tracelb_do.h"
#include "dealias/scamper_dealias_do.h"
#include "sting/scamper_sting_do.h"
#include "neighbourdisc/scamper_neighbourdisc_do.h"
#include "tbit/scamper_tbit_do.h"
#include "sniff/scamper_sniff_do.h"
#include "host/scamper_host_do.h"

#include "utils.h"

#define OPT_PPS             0x00000001 /* p: */
#define OPT_OUTFILE         0x00000002 /* o: */
#define OPT_OPTION          0x00000004 /* O: */
#define OPT_PIDFILE         0x00000010 /* e: */
#define OPT_VERSION         0x00000020 /* v: */
#define OPT_DAEMON          0x00000200 /* D: */
#define OPT_IP              0x00000400 /* i: */
#define OPT_MONITORNAME     0x00002000 /* M: */
#define OPT_COMMAND         0x00004000 /* c: */
#define OPT_HELP            0x00008000 /* ?: */
#define OPT_WINDOW          0x00010000 /* w: */
#define OPT_DEBUGFILE       0x00020000 /* d: */
#define OPT_LISTNAME        0x00040000 /* l: */
#define OPT_LISTID          0x00080000 /* L: */
#define OPT_CYCLEID         0x00100000 /* C: */
#define OPT_FIREWALL        0x00200000 /* F: */
#define OPT_CMDLIST         0x00400000 /* I: */
#define OPT_INFILE          0x00800000 /* f: */
#define OPT_CTRL_INET       0x01000000 /* P: */
#define OPT_CTRL_UNIX       0x02000000 /* U: */
#define OPT_CTRL_REMOTE     0x04000000 /* R: */

#define FLAG_NOINITNDC       0x00000001
#define FLAG_OUTCOPY         0x00000002
#define FLAG_SELECT          0x00000004
#define FLAG_KQUEUE          0x00000008
#define FLAG_PLANETLAB       0x00000010
#define FLAG_EPOLL           0x00000020
#define FLAG_RAWTCP          0x00000040
#define FLAG_DEBUGFILEAPPEND 0x00000080
#define FLAG_TLS             0x00000100
#define FLAG_NOTLS           0x00000200

/*
 * parameters configurable by the command line:
 *
 * options:     bitmask corresponding to command line arguments
 * command:     default command to use with scamper
 * pps:         how many probe packets to send per second
 * window:      maximum number of concurrent tasks to actively probe
 * outfile:     where to send results by default
 * outtype:     format to use when writing results to outfile
 * intype:      format of input file
 * ctrl_inet_addr: address to use for control socket
 * ctrl_inet_port: port to use for control socket
 * ctrl_unix:   file to use for unix domain control
 * ctrl_rem_port: port on remote host to connect to for direction
 * ctrl_rem_name: name or IP address of remote host to connect to
 * monitorname: canonical name of monitor assigned by human
 * listname:    name of list assigned by human
 * listid:      id of list assigned by human
 * cycleid:     id of cycle assigned by human
 * arglist:     whatever is left over after getopt processing
 * arglist_len: number of arguments left over after getopt processing
 * debugfile:   place to write debugging output
 * firewall:    scamper should use the system firewall when needed
 * pidfile:     place to write process id
 */
static uint32_t options    = 0;
static uint32_t flags      = 0;
static char  *command      = NULL;
static int    pps          = SCAMPER_PPS_DEF;
static int    window       = SCAMPER_WINDOW_DEF;
static char  *outfile      = "-";
static char  *outtype      = "text";
static char  *intype       = NULL;
static char  *ctrl_inet_addr = NULL;
static int    ctrl_inet_port = 0;
static char  *ctrl_unix    = NULL;
static int    ctrl_rem_port = 0;
static char  *ctrl_rem_name = NULL;
static char  *monitorname  = NULL;
static char  *listname     = NULL;
static int    listid       = -1;
static int    cycleid      = -1;
static char **arglist      = NULL;
static int    arglist_len  = 0;
static char  *firewall     = NULL;
static char  *pidfile      = NULL;

#ifndef WITHOUT_DEBUGFILE
static char  *debugfile    = NULL;
#endif

/*
 * parameters calculated by scamper at run time:
 *
 * wait_between:   calculated wait between probes to reach pps, in microseconds
 * probe_window:   maximum extension of probing window before truncation
 * exit_when_done: exit scamper when current window of tasks is completed
 */
static int    wait_between   = 1000000 / SCAMPER_PPS_DEF;
static int    probe_window   = 250000;
static int    exit_when_done = 1;

/* central cache of addresses that scamper is dealing with */
scamper_addrcache_t *addrcache = NULL;

/* Source port to use in our probes */
static uint16_t default_sport = 0;

typedef struct scamper_multicall
{
  char         *argv0;
  char         *cmd;
  int         (*validate)(int, char **, int *);
  const char *(*usage)(void);
} scamper_multicall_t;

static void version(void)
{
  fprintf(stderr, "scamper version %s\n", SCAMPER_VERSION);
  return;
}

static void usage_str(char c, const char *str)
{
  fprintf(stderr, "            -%c %s\n", c, str);
  return;
}

static void usage_line(const char *str)
{
  fprintf(stderr, "               %s\n", str);
  return;
}

static void usage(uint32_t opt_mask)
{
  char buf[256];

  fprintf(stderr,
    "usage: scamper [-?Dv] [-c command] [-p pps] [-w window]\n"
    "               [-M monitorname] [-l listname] [-L listid] [-C cycleid]\n"
    "               [-o outfile] [-O options] [-F firewall] [-e pidfile]\n"
#ifndef WITHOUT_DEBUGFILE
    "               [-d debugfile]\n"
#endif
    "               [-i IPs | -I cmds | -f file | -P [ip:]port | -R name:port"
#if defined(AF_UNIX) && !defined(_WIN32)
    " |\n                -U unix]\n");
#else
    "]\n");
#endif

  if(opt_mask == 0) return;

  fprintf(stderr, "\n");

  if((opt_mask & OPT_HELP) != 0)
    usage_str('?', "give an overview of the usage of scamper");

  if((opt_mask & OPT_COMMAND) != 0)
    {
      (void)snprintf(buf, sizeof(buf),
		     "command string (default: %s)", SCAMPER_COMMAND_DEF);
      usage_str('c', buf);
    }

  if((opt_mask & OPT_CYCLEID) != 0)
    usage_str('C', "cycle id");

#ifndef WITHOUT_DEBUGFILE
  if((opt_mask & OPT_DEBUGFILE) != 0)
    usage_str('d', "write debugging information to the specified file");
#endif

#ifdef HAVE_DAEMON
  if((opt_mask & OPT_DAEMON) != 0)
    usage_str('D', "start as a daemon listening for commands on a port");
#endif

  if((opt_mask & OPT_PIDFILE) != 0)
    usage_str('e', "write process ID to specified file");

  if((opt_mask & OPT_INFILE) != 0)
    usage_str('f', "list of files provided on the command line");

  if((opt_mask & OPT_FIREWALL) != 0)
    usage_str('F', "use the system firewall to install rules as necessary");

  if((opt_mask & OPT_IP) != 0)
    usage_str('i', "list of IP addresses provided on the command line");

  if((opt_mask & OPT_CMDLIST) != 0)
    usage_str('I', "list of scamper commands provided on the command line");

  if((opt_mask & OPT_LISTID) != 0)
    usage_str('l', "name to assign to default list");

  if((opt_mask & OPT_LISTNAME) != 0)
    usage_str('L', "list id for default list");

  if((opt_mask & OPT_MONITORNAME) != 0)
    usage_str('M', "specify the canonical name of the monitor");

  if((opt_mask & OPT_OUTFILE) != 0)
    usage_str('o', "specify the file to write output to");

  if((opt_mask & OPT_OPTION) != 0)
    {
      usage_str('O', "specify options to use:");
      usage_line("text: output results in plain text for interactive use");
      usage_line("warts: output results in warts format for science");
      usage_line("tsps: input file for ping -T tsprespec=%s");
      usage_line("cmdfile: input file specifies whole commands");
      usage_line("json: output results in json format, better to use warts");
      usage_line("planetlab: necessary to use safe raw sockets on planetlab");
      usage_line("noinitndc: do not initialise neighbour discovery cache");
      usage_line("outcopy: output copy of all results collected to file");
      usage_line("rawtcp: use raw socket to send IPv4 TCP probes");
#ifdef HAVE_OPENSSL
      usage_line("notls: do not use TLS anywhere in scamper");
      usage_line("tls: require TLS on remote control sockets");
#endif
#ifndef _WIN32
      usage_line("select: use select(2) rather than poll(2)");
#endif
#ifdef HAVE_KQUEUE
      usage_line("kqueue: use kqueue(2) rather than poll(2)");
#endif
#ifdef HAVE_EPOLL
      usage_line("epoll: use epoll(7) rather than poll(2)");
#endif
#ifndef WITHOUT_DEBUGFILE
      usage_line("debugfileappend: append to debugfile, rather than truncate");
#endif
    }

  if((opt_mask & OPT_PPS) != 0)
    {
      snprintf(buf, sizeof(buf),
	       "number of packets per second to send (%d <= pps <= %d)",
	       SCAMPER_PPS_MIN, SCAMPER_PPS_MAX);
      usage_str('p', buf);
    }

  if((opt_mask & OPT_CTRL_INET) != 0)
    usage_str('P', "[ip:]port for control socket, default to loopback");

  if((opt_mask & OPT_CTRL_REMOTE) != 0)
    usage_str('R', "name and port of remote host to receive commands from");

  if((opt_mask & OPT_CTRL_UNIX) != 0)
    usage_str('U', "name of control socket in the file system");

  if((opt_mask & OPT_VERSION) != 0)
    usage_str('v', "output the version of scamper this binary is");

  if((opt_mask & OPT_WINDOW) != 0)
    usage_str('w', "limit the window of actively probing tasks");

  return;
}

static int set_opt(uint32_t opt, char *str, int (*setfunc)(int))
{
  long l = 0;

  if(string_isnumber(str) == 0 || string_tolong(str, &l) == -1)
    {
      usage(opt);
      return -1;
    }

  return setfunc(l);
}

static int multicall_do(const scamper_multicall_t *mc, int argc, char *argv[])
{
  char *str;
  size_t off, len, tmp;
  int i, stop;

  if(argc == 1 || mc->validate(argc, argv, &stop) != 0 || stop == argc)
    {
      if(mc->usage != NULL)
	{
	  printf("usage: scamper-%s <ip list>\n", mc->usage());
	}
      return -1;
    }

  /* assemble the command string */
  len = strlen(mc->cmd) + 1;
  for(i=1; i<stop; i++)
    {
      len += strlen(argv[i]) + 1;
    }
  if((str = malloc_zero(len)) == NULL)
    {
      printerror(__func__, "could not assemble %s command", mc->cmd);
      return -1;
    }
  off = strlen(mc->cmd);
  memcpy(str, mc->cmd, off);
  str[off++] = ' ';
  for(i=1; i<stop; i++)
    {
      tmp = strlen(argv[i]);
      memcpy(str+off, argv[i], tmp);
      off += tmp;
      str[off++] = ' ';
    }
  str[off] = '\0';

  /* set the command */
  scamper_command_set(str);
  free(str);

  options |= OPT_IP;

  arglist     = argv + stop;
  arglist_len = argc - stop;

  return 0;
}

static int cycleid_set(const int cid)
{
  if(cid > 0 && cid <= 0x7fffffff)
    {
      cycleid = cid;
      return 0;
    }
  return -1;
}

static int listid_set(const int lid)
{
  if(lid > 0 && lid <= 0x7fffffff)
    {
      listid = lid;
      return 0;
    }
  return -1;
}

static int ppswindow_set(int p, int w)
{
  if(p == 0 && w == 0)
    return -1;

  if(p != pps)
    {
      if(p != 0 && (p < SCAMPER_PPS_MIN || p > SCAMPER_PPS_MAX))
	return -1;

      /*
       * reset the pps scamper is operating at.  re-calculate the
       * inter-probe delay, and the maximum size of the probe window.
       */
      pps = p;
      if(p != 0)
	wait_between = 1000000 / pps;
      else
	wait_between = 0;
      probe_window = 250000;
      if(wait_between > 250000)
	probe_window += wait_between;
    }

  if(w != window)
    {
      if(w != 0 && (w < SCAMPER_WINDOW_MIN || w > SCAMPER_WINDOW_MAX))
	return -1;
      window = w;
    }

  return 0;
}

static int check_options(int argc, char *argv[])
{
  static const scamper_multicall_t multicall[] = {
    {"scamper-trace",   "trace",
     scamper_do_trace_arg_validate, scamper_do_trace_usage},
    {"scamper-ping",    "ping",
     scamper_do_ping_arg_validate, scamper_do_ping_usage},
    {"scamper-tracelb", "tracelb",
     scamper_do_tracelb_arg_validate, scamper_do_tracelb_usage},
    {"scamper-dealias", "dealias",
     scamper_do_dealias_arg_validate, scamper_do_dealias_usage},
    {"scamper-sting",   "sting",
     scamper_do_sting_arg_validate, scamper_do_sting_usage},
    {"scamper-neighbourdisc", "neighbourdisc",
     scamper_do_neighbourdisc_arg_validate, scamper_do_neighbourdisc_usage},
    {"scamper-tbit", "tbit",
     scamper_do_tbit_arg_validate, scamper_do_tbit_usage},
    {"scamper-sniff", "sniff",
     scamper_do_sniff_arg_validate, scamper_do_sniff_usage},
    {"scamper-host", "host",
     scamper_do_host_arg_validate, scamper_do_host_usage},
  };
  int   i;
  long  lo_w = window, lo_p = pps;
  char  opts[64];
  char *opt_cycleid = NULL, *opt_listid = NULL, *opt_listname = NULL;
  char *opt_ctrl_inet = NULL, *opt_ctrl_unix = NULL, *opt_monitorname = NULL;
  char *opt_pps = NULL, *opt_command = NULL, *opt_window = NULL;
  char *opt_firewall = NULL, *opt_pidfile = NULL, *opt_ctrl_remote = NULL;

#ifndef WITHOUT_DEBUGFILE
  char *opt_debugfile = NULL;
#endif
  
  size_t argv0 = strlen(argv[0]);
  size_t m, len;
  size_t off;
  uint32_t o;

  for(m=0; m<sizeof(multicall)/sizeof(scamper_multicall_t); m++)
    {
      len = strlen(multicall[m].argv0);
      if(argv0 >= len && strcmp(argv[0]+argv0-len, multicall[m].argv0) == 0)
	{
	  return multicall_do(&multicall[m], argc, argv);
	}
    }

  off = 0;
  string_concat(opts, sizeof(opts), &off, "c:C:e:fF:iIl:L:M:o:O:p:P:R:vw:?");
#ifndef WITHOUT_DEBUGFILE
  string_concat(opts, sizeof(opts), &off, "d:");
#endif
#if HAVE_DAEMON
  string_concat(opts, sizeof(opts), &off, "D");
#endif
#if defined(AF_UNIX)
  string_concat(opts, sizeof(opts), &off, "U:");
#endif

  while((i = getopt(argc, argv, opts)) != -1)
    {
      switch(i)
	{
	case 'c':
	  options |= OPT_COMMAND;
	  opt_command = optarg;
	  break;

	case 'C':
	  options |= OPT_CYCLEID;
	  opt_cycleid = optarg;
	  break;

#ifndef WITHOUT_DEBUGFILE
	case 'd':
	  options |= OPT_DEBUGFILE;
	  opt_debugfile = optarg;
	  break;
#endif

#ifdef HAVE_DAEMON
	case 'D':
	  options |= OPT_DAEMON;
	  break;
#endif

	case 'e':
	  options |= OPT_PIDFILE;
	  opt_pidfile = optarg;
	  break;

	case 'f':
	  options |= OPT_INFILE;
	  break;

	case 'F':
	  options |= OPT_FIREWALL;
	  opt_firewall = optarg;
	  break;

	case 'i':
	  options |= OPT_IP;
	  break;

	case 'I':
	  options |= OPT_CMDLIST;
	  break;

	case 'l':
	  options |= OPT_LISTNAME;
	  opt_listname = optarg;
	  break;

	case 'L':
	  options |= OPT_LISTID;
	  opt_listid = optarg;
	  break;

	case 'M':
	  options |= OPT_MONITORNAME;
	  opt_monitorname = optarg;
	  break;

        case 'o':
          options |= OPT_OUTFILE;
          outfile = optarg;
          break;

	case 'O':
	  if(strcasecmp(optarg, "text") == 0)
	    outtype = optarg;
	  else if(strcasecmp(optarg, "warts") == 0)
	    outtype = optarg;
	  else if(strcasecmp(optarg, "json") == 0)
	    outtype = optarg;
	  else if(strcasecmp(optarg, "tsps") == 0)
	    intype = optarg;
	  else if(strcasecmp(optarg, "cmdfile") == 0)
	    intype = optarg;
	  else if(strcasecmp(optarg, "planetlab") == 0)
	    flags |= FLAG_PLANETLAB;
	  else if(strcasecmp(optarg, "noinitndc") == 0)
	    flags |= FLAG_NOINITNDC;
	  else if(strcasecmp(optarg, "outcopy") == 0)
	    flags |= FLAG_OUTCOPY;
	  else if(strcasecmp(optarg, "rawtcp") == 0)
	    flags |= FLAG_RAWTCP;
#ifdef HAVE_OPENSSL
	  else if(strcasecmp(optarg, "tls") == 0)
	    flags |= FLAG_TLS;
	  else if(strcasecmp(optarg, "notls") == 0)
	    flags |= FLAG_NOTLS;
#endif
#ifndef _WIN32
	  else if(strcasecmp(optarg, "select") == 0)
	    flags |= FLAG_SELECT;
#endif
#ifdef HAVE_KQUEUE
	  else if(strcasecmp(optarg, "kqueue") == 0)
	    flags |= FLAG_KQUEUE;
#endif
#ifdef HAVE_EPOLL
	  else if(strcasecmp(optarg, "epoll") == 0)
	    flags |= FLAG_EPOLL;
#endif
#ifndef WITHOUT_DEBUGFILE
	  else if(strcasecmp(optarg, "debugfileappend") == 0)
	    flags |= FLAG_DEBUGFILEAPPEND;
#endif
	  else
	    {
	      usage(OPT_OPTION);
	      return -1;
	    }
	  break;

	case 'p':
	  options |= OPT_PPS;
	  opt_pps = optarg;
	  break;

	case 'P':
	  options |= OPT_CTRL_INET;
	  opt_ctrl_inet = optarg;
	  break;

	case 'R':
	  options |= OPT_CTRL_REMOTE;
	  opt_ctrl_remote = optarg;
	  break;

	case 'U':
	  options |= OPT_CTRL_UNIX;
	  opt_ctrl_unix = optarg;
	  break;

	case 'v':
	  options |= OPT_VERSION;
	  break;

	case 'w':
	  options |= OPT_WINDOW;
	  opt_window = optarg;
	  break;

	case '?':
	  options |= OPT_HELP;
	  usage(0xffffffff);
	  return -1;

	default:
	  printerror(__func__, "could not parse command line options");
	  return -1;
	}
    }

  if(options & OPT_VERSION)
    {
      version();
      return -1;
    }

 
  /*
   * if one of -IPRUi is not provided, pretend that -f was for backward
   * compatibility
   */
  if((options & (OPT_CMDLIST | OPT_CTRL_INET | OPT_CTRL_REMOTE |
		 OPT_CTRL_UNIX | OPT_IP)) == 0)
    {
      options |= OPT_INFILE;
    }

  if(options & (OPT_PPS|OPT_WINDOW))
    {
      if(opt_window != NULL && string_tolong(opt_window, &lo_w) != 0)
	{
	  usage(OPT_WINDOW);
	  return -1;
	}
      if(opt_pps != NULL && string_tolong(opt_pps, &lo_p) != 0)
	{
	  usage(OPT_PPS);
	  return -1;
	}
      if(ppswindow_set(lo_p, lo_w) != 0)
	{
	  usage(OPT_PPS|OPT_WINDOW);
	  return -1;
	}
    }

  if(options & OPT_FIREWALL && (firewall = strdup(opt_firewall)) == NULL)
    {
      printerror(__func__, "could not strdup firewall");
      return -1;
    }

  if(options & OPT_MONITORNAME &&
     (monitorname = strdup(opt_monitorname)) == NULL)
    {
      printerror(__func__, "could not strdup monitorname");
      return -1;
    }

  if(options & OPT_LISTNAME && (listname = strdup(opt_listname)) == NULL)
    {
      printerror(__func__, "could not strdup listname");
      return -1;
    }

  if(options & OPT_LISTID && set_opt(OPT_LISTID, opt_listid, listid_set) != 0)
    {
      usage(OPT_LISTID);
      return -1;
    }

  if(options & OPT_CYCLEID &&
     set_opt(OPT_CYCLEID, opt_cycleid, cycleid_set) != 0)
    {
      usage(OPT_CYCLEID);
      return -1;
    }

#ifndef WITHOUT_DEBUGFILE
  if(options & OPT_DEBUGFILE && (debugfile = strdup(opt_debugfile)) == NULL)
    {
      printerror(__func__, "could not strdup debugfile");
      return -1;
    }
#endif

  if(options & OPT_PIDFILE && (pidfile = strdup(opt_pidfile)) == NULL)
    {
      printerror(__func__, "could not strdup pidfile");
      return -1;
    }

  /* make sure incompatible flags were not specified */
  if((flags & (FLAG_TLS|FLAG_NOTLS)) == (FLAG_TLS|FLAG_NOTLS))
    {
      usage(OPT_OPTION);
      return -1;
    }

  /* these are the left-over arguments */
  arglist     = argv + optind;
  arglist_len = argc - optind;

  /* if one of -PUi is used, then a default command must be set */
  if((options & (OPT_CTRL_INET | OPT_CTRL_UNIX | OPT_IP | OPT_INFILE)) != 0 &&
     scamper_command_set((options & OPT_COMMAND) ?
			 opt_command : SCAMPER_COMMAND_DEF) != 0)
    {
      return -1;
    }

#ifdef HAVE_DAEMON
  if((options & OPT_DAEMON) &&
     (options & (OPT_CTRL_INET|OPT_CTRL_UNIX|OPT_CTRL_REMOTE)) == 0)
    {
      usage(OPT_DAEMON | OPT_CTRL_INET | OPT_CTRL_UNIX | OPT_CTRL_REMOTE);
      return -1;
    }
#endif

  o = options & (OPT_CTRL_INET | OPT_CTRL_UNIX | OPT_CTRL_REMOTE |
		 OPT_IP | OPT_CMDLIST | OPT_INFILE);

  if(options & (OPT_CTRL_INET|OPT_CTRL_REMOTE|OPT_CTRL_UNIX))
    {
      if(options & (OPT_IP | OPT_CMDLIST | OPT_INFILE))
	{
	  usage(o);
	  return -1;
	}

      if(options & OPT_CTRL_INET)
	{
	  /* if listening on control socket there should be no leftover args */
	  if(arglist_len != 0 ||
	     string_addrport(opt_ctrl_inet, &ctrl_inet_addr, &ctrl_inet_port) != 0)
	    {
	      usage(OPT_CTRL_INET);
	      return -1;
	    }
	}
      if(options & OPT_CTRL_REMOTE)
	{
	  /*
	   * if using a remote control socket, there should be no
	   * leftover args
	   */
	  if(arglist_len != 0 ||
	     string_addrport(opt_ctrl_remote, &ctrl_rem_name, &ctrl_rem_port) != 0)
	    {
	      scamper_debug(__func__, "hello %s %d", opt_ctrl_remote, arglist_len);
	      usage(OPT_CTRL_REMOTE);
	      return -1;
	    }
	}
      if(options & OPT_CTRL_UNIX)
	{
	  /* if listening on control socket there should be no leftover args */
	  if(arglist_len != 0)
	    {
	      usage(OPT_CTRL_UNIX);
	      return -1;
	    }
	  ctrl_unix = opt_ctrl_unix;
	}
    }
  else if(options & (OPT_IP | OPT_CMDLIST))
    {
      /* only one of the following should be specified */
      if((options & (OPT_CTRL_INET|OPT_CTRL_REMOTE|OPT_CTRL_UNIX|OPT_INFILE)) ||
	 ((options & OPT_IP) && (options & OPT_CMDLIST)))
	{
	  usage(o);
	  return -1;
	}

      /*
       * if a list of IP addresses or commands is to be supplied, there has to
       * be at least one left over argument.
       */
      if(arglist_len < 1)
	{
	  if(options & OPT_IP)
	    usage(OPT_IP);
	  else if(options & OPT_CMDLIST)
	    usage(OPT_CMDLIST);
	  return -1;
	}
    }
  else
    {
      /*
       * if a listfile is specified, then there may only be one left over
       * argument, which specifies the listfile.
       */
      assert(o == OPT_INFILE);
      if(arglist_len != 1)
	{
	  usage(0);
	  return -1;
	}
    }

  return 0;
}

const char *scamper_command_get(void)
{
  assert(command != NULL);
  return command;
}

int scamper_command_set(const char *command_in)
{
  char *d;

  if(command_in == NULL)
    {
      return -1;
    }

  if((d = strdup(command_in)) == NULL)
    {
      printerror(__func__, "could not strdup command");
      return -1;
    }

  if(command != NULL)
    free(command);

  command = d;
  return 0;
}

void scamper_exitwhendone(int on)
{
  if(on == 1 || on == 0)
    {
      exit_when_done = on;
    }
  return;
}

int scamper_pps_get()
{
  return pps;
}

int scamper_pps_set(const int p)
{
  return ppswindow_set(p, window);
}

int scamper_window_get()
{
  return window;
}

int scamper_window_set(const int w)
{
  return ppswindow_set(pps, w);
}

const char *scamper_monitorname_get()
{
  return monitorname;
}

int scamper_monitorname_set(const char *mn)
{
  char *tmp;

  /*
   * before removing the old monitor name, get a copy of the monitor name
   * since that's what we'll be using to store afterward
   */
  if(mn != NULL)
    {
      if((tmp = strdup(mn)) == NULL)
	{
	  return -1;
	}
    }
  else
    {
      tmp = NULL;
    }

  if(monitorname != NULL)
    {
      free(monitorname);
    }

  monitorname = tmp;
  return 0;
}

int scamper_option_planetlab(void)
{
  if(flags & FLAG_PLANETLAB) return 1;
  return 0;
}

int scamper_option_select(void)
{
  if(flags & FLAG_SELECT) return 1;
  return 0;
}

int scamper_option_kqueue(void)
{
  if(flags & FLAG_KQUEUE) return 1;
  return 0;
}

int scamper_option_epoll(void)
{
  if(flags & FLAG_EPOLL) return 1;
  return 0;
}

int scamper_option_noinitndc(void)
{
  if(flags & FLAG_NOINITNDC) return 1;
  return 0;
}

int scamper_option_rawtcp(void)
{
  if(flags & FLAG_RAWTCP) return 1;
  return 0;
}

int scamper_option_debugfileappend(void)
{
  if(flags & FLAG_DEBUGFILEAPPEND) return 1;
  return 0;
}

int scamper_option_tls(void)
{
  if(flags & FLAG_TLS) return 1;
  return 0;
}

int scamper_option_notls(void)
{
  if(flags & FLAG_NOTLS) return 1;
  return 0;
}

int scamper_option_daemon(void)
{
  if(options & OPT_DAEMON) return 1;
  return 0;
}

static int scamper_pidfile(void)
{
  char buf[32];
  mode_t mode;
  size_t len;
  int fd, flags = O_WRONLY | O_TRUNC | O_CREAT;

#ifndef _WIN32
  pid_t pid = getpid();
  mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
#else
  DWORD pid = GetCurrentProcessId();
  mode = _S_IREAD | _S_IWRITE;
#endif

#if defined(WITHOUT_PRIVSEP)
  fd = open(pidfile, flags, mode);
#else
  fd = scamper_privsep_open_file(pidfile, flags, mode);
#endif

  if(fd == -1)
    {
      printerror(__func__, "could not open %s", pidfile);
      goto err;
    }

  snprintf(buf, sizeof(buf), "%ld\n", (long)pid);
  len = strlen(buf);
  if(write_wrap(fd, buf, NULL, len) != 0)
    {
      printerror(__func__, "could not write pid");
      goto err;
    }
  close(fd);

  return 0;

 err:
  if(fd != -1) close(fd);
  return -1;
}

#ifndef _WIN32
static void scamper_chld(int sig)
{
  int status;

  if(sig != SIGCHLD)
    return;

  for(;;)
    {
      if(waitpid(-1, &status, WNOHANG) == -1)
	{
	  break;
	}
    }

  return;
}
#endif

static void scamper_sport_init(void)
{
#ifndef _WIN32
  pid_t pid = getpid();
#else
  DWORD pid = GetCurrentProcessId();
#endif
  default_sport = (pid & 0x7fff) + 0x8000;
  return;
}

uint16_t scamper_sport_default(void)
{
  return default_sport;
}

/*
 * scamper_timeout
 *
 * figure out how long the timeout on the poll (or equivalent) should be.
 *
 * returns:
 *  zero if there is a timeout value computed
 *  one  if there is no timeout value computed
 *  two  if scamper should exit because it is done.
 */
static int scamper_timeout(struct timeval *timeout, struct timeval *nextprobe,
			   struct timeval *lastprobe)
{
  struct timeval tv;
  int probe = 0;
  
  if(scamper_queue_readycount() > 0 ||
     ((window == 0 || scamper_queue_windowcount() < window) &&
      scamper_sources_isready() != 0))
    {
      /*
       * if there is something ready to be probed right now, then set the
       * timeout to go off when it is time to send the next probe
       */
      timeval_add_us(nextprobe, lastprobe, wait_between);
      probe = 1;
    }
  else if(scamper_queue_count() > 0)
    {
      /*
       * if there isn't anything ready to go right now, but we are
       * waiting on a response from an earlier probe, then set the timer
       * to go off when that probe expires.
       */
      scamper_queue_waittime(nextprobe);
      probe = 1;
    }
  else
    {
      if(exit_when_done != 0 && scamper_sources_isempty() == 1)
	return 2;
    }

  /*
   * if there are no events to consider, then we only need to consider
   * if there are events in the future
   */
  if(scamper_queue_event_waittime(&tv) == 0)
    {
      if(probe == 0)
	return 1;
      timeval_cpy(timeout, nextprobe);
      return 0;
    }

  /*
   * there is an event and (maybe) a probe timeout to consider.
   * figure out which comes first: the event or the probe
   */
  if(probe != 0 && timeval_cmp(nextprobe, &tv) <= 0)
    timeval_cpy(timeout, nextprobe);
  else
    timeval_cpy(timeout, &tv);
  return 0;
}

/*
 * scamper:
 *
 * this bit of code contains most of the logic for driving the parallel
 * measurement processes.
 */
static int scamper(int argc, char *argv[])
{
  struct timeval           tv;
  struct timeval           lastprobe;
  struct timeval           nextprobe;
  struct timeval           timeout, *timeout_ptr;
  const char              *sofname;
  scamper_source_params_t  ssp;
  scamper_source_t        *source = NULL;
  scamper_task_t          *task;
  scamper_outfile_t       *sof, *sof2;
  scamper_file_t          *file;
  int                      rc;

  if(check_options(argc, argv) == -1)
    {
      return -1;
    }

#ifdef HAVE_DAEMON
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    {
      printerror(__func__, "could not daemon");
      return -1;
    }
#endif

  scamper_debug_init();

  /*
   * now that we've forked for privsep and again for daemon, write the
   * pidfile.
   */
  if((options & OPT_PIDFILE) != 0 && scamper_pidfile() != 0)
    return -1;

  if(scamper_osinfo_init() != 0)
    return -1;

  /*
   * this has to be done before priviledge separation, as if scamper is
   * running on a BPF system it has to open a BPF fd to establish
   * version compatibility
   */
  if(scamper_dl_init() == -1)
    {
      return -1;
    }

#ifdef HAVE_OPENSSL
  if((flags & FLAG_NOTLS) == 0)
    SSL_library_init();
#endif

#ifndef WITHOUT_PRIVSEP
  /* revoke the root priviledges we started with */
  if(scamper_privsep_init() == -1)
    {
      return -1;
    }
#endif

  random_seed();

  if(firewall != NULL)
    {
      if(scamper_firewall_init(firewall) != 0)
	return -1;
      free(firewall);
      firewall = NULL;
    }

#ifndef WITHOUT_DEBUGFILE
  /*
   * open the debug file immediately so initialisation debugging information
   * makes it to the file
   */
  if(debugfile != NULL && scamper_debug_open(debugfile) != 0)
    {
      return -1;
    }
#endif

  /* determine a suitable default value for the source port in packets */
  scamper_sport_init();

  /* allocate the cache of addresses for scamper to keep track of */
  if((addrcache = scamper_addrcache_alloc()) == NULL)
    {
      return -1;
    }

  /* init the probing code */
  if(scamper_probe_init() != 0)
    return -1;

  /* initialise the queues that hold the current tasks */
  if(scamper_queue_init() == -1)
    return -1;

  /* setup the file descriptor monitoring code */
  if(scamper_fds_init() == -1)
    {
      return -1;
    }

  if(options & (OPT_CTRL_INET|OPT_CTRL_UNIX|OPT_CTRL_REMOTE))
    {
      if(scamper_control_init() != 0)
	return -1;
      if(options & OPT_CTRL_INET &&
	 scamper_control_add_inet(ctrl_inet_addr, ctrl_inet_port) != 0)
	return -1;
      if(options & OPT_CTRL_UNIX &&
	 scamper_control_add_unix(ctrl_unix) != 0)
	return -1;
      if(options & OPT_CTRL_REMOTE &&
	 scamper_control_add_remote(ctrl_rem_name, ctrl_rem_port) != 0)
	return -1;

      /* wait for more tasks when finished with the active window */
      exit_when_done = 0;
    }

  /* initialise the subsystem responsible for obtaining source addresses */
  if(scamper_getsrc_init() == -1)
    {
      return -1;
    }

  /* initialise the subsystem responsible for recording mac addresses */
  if(scamper_addr2mac_init() == -1)
    {
      return -1;
    }

  if(scamper_rtsock_init() == -1)
    {
      return -1;
    }

  /* initialise the structures necessary to keep track of addresses to probe */
  if(scamper_sources_init() == -1)
    {
      return -1;
    }

  /*
   * initialise the data structures necessary to keep track of the signatures
   * of tasks currently being probed
   */
  if(scamper_task_init() == -1)
    {
      return -1;
    }

  /*
   * initialise the data structures necessary to keep track of output files
   * currently being written to
   */
  if(scamper_outfiles_init(outfile, outtype) == -1)
    {
      return -1;
    }

  /* initialise scamper so it is ready to traceroute and ping */
  if(scamper_do_trace_init() != 0 ||
     scamper_do_ping_init() != 0 ||
     scamper_do_tracelb_init() != 0 ||
     scamper_do_dealias_init() != 0 ||
     scamper_do_sting_init() != 0 ||
     scamper_do_neighbourdisc_init() != 0 ||
     scamper_do_tbit_init() != 0 ||
     scamper_do_sniff_init() != 0 ||
     scamper_do_host_init() != 0)
    {
      return -1;
    }

  /* parameters for the default list */
  memset(&ssp, 0, sizeof(ssp));
  ssp.name     = "default";
  ssp.descr    = "default";
  ssp.priority = 1;
  ssp.sof      = scamper_outfiles_get(NULL);
  if(options & OPT_LISTNAME)
    ssp.name = listname;
  if(options & OPT_LISTID)
    ssp.list_id = listid;
  if(options & OPT_CYCLEID)
    ssp.cycle_id = cycleid;

  /*
   * if we have an address list of some description on the command line,
   * read the addresses now
   */
  if(options & (OPT_IP|OPT_CMDLIST))
    {
      if((source = scamper_source_cmdline_alloc(&ssp, command,
						arglist, arglist_len)) == NULL)
	{
	  return -1;
	}
    }
  else if((options & (OPT_CTRL_INET|OPT_CTRL_UNIX|OPT_CTRL_REMOTE)) == 0)
    {
      if(intype == NULL)
	source = scamper_source_file_alloc(&ssp, arglist[0], command, 1, 0);
      else if(strcasecmp(intype, "tsps") == 0)
	source = scamper_source_tsps_alloc(&ssp, arglist[0]);
      else if(strcasecmp(intype, "cmdfile") == 0)
	source = scamper_source_file_alloc(&ssp, arglist[0], NULL, 1, 0);
      if(source == NULL)
	return -1;
    }

  if(source != NULL)
    {
      scamper_sources_add(source);
      scamper_source_free(source);
    }

  gettimeofday_wrap(&lastprobe);

  for(;;)
    {
      if((rc = scamper_timeout(&timeout, &nextprobe, &lastprobe)) == 0)
	{
	  /*
	   * we've been told to calculate a timeout value.  figure out what
	   * it should be.
	   */
	  gettimeofday_wrap(&tv);
	  if(timeval_cmp(&timeout, &tv) <= 0)
	    memset(&tv, 0, sizeof(tv));
	  else
	    timeval_diff_tv(&tv, &tv, &timeout);
	  timeout_ptr = &tv;
	}
      else if(rc == 1)
	{
	  timeout_ptr = NULL;
	}
      else
	{
	  /* exit when done */
	  break;
	}

      /* listen until it is time to send the next probe */
      if(scamper_fds_poll(timeout_ptr) == -1)
	return -1;

      /* get the current time */
      gettimeofday_wrap(&tv);

      if(scamper_queue_event_proc(&tv) != 0)
	return -1;
      
      /* take any 'done' tasks and output them now */
      while((task = scamper_queue_getdone(&tv)) != NULL)
	{
	  /* write the data out */
	  if((source = scamper_task_getsource(task)) != NULL &&
	     (sofname = scamper_source_getoutfile(source)) != NULL &&
	     (sof = scamper_outfiles_get(sofname)) != NULL)
	    {
	      file = scamper_outfile_getfile(sof);
	      scamper_task_write(task, file);

	      /*
	       * write a copy of the data out if asked to, and it has not
	       * already been written to this output file.
	       */
	      if((flags & FLAG_OUTCOPY) != 0 &&
		 (sof2 = scamper_outfiles_get(NULL)) != NULL && sof != sof2)
		{
		  file = scamper_outfile_getfile(sof2);
		  scamper_task_write(task, file);
		}
	    }

	  /* cleanup the task */
	  scamper_task_free(task);
	}

      /*
       * if there is something waiting to be probed, then find out if it is
       * time to probe yet
       */
      if(scamper_queue_readycount() > 0 || scamper_sources_isready() == 1)
	{
	  /*
	   * check for large differences between the time the last probe
	   * was sent and the current time.  don't allow the difference to
	   * be larger than a particular amount, since that could result in
	   * either a large flutter of probes to be sent, or a large time
	   * before the next probe is sent
	   */
	  if(timeval_inrange_us(&tv, &lastprobe, probe_window) == 0)
	    timeval_sub_us(&lastprobe, &tv, wait_between);

	  /*
	   * when probing at > HZ, scamper might find that select blocks it
	   * from achieving the specified packets per second rate if it sends
	   * one probe per select.  Based on the time spent in the last call
	   * to select, send the necessary number of packets to fill that
	   * window where we sent no packets.
	   */
	  for(;;)
	    {
	      timeval_add_us(&nextprobe, &lastprobe, wait_between);

	      /* if the next probe is not due to be sent, don't send one */
	      if(timeval_cmp(&nextprobe, &tv) > 0)
		break;

	      /*
	       * look for an address that we can send a probe to.  if
	       * scamper doesn't have a task on the probe queue waiting
	       * to be probed, then get a fresh task. if there's absolutely
	       * nothing that scamper can probe, then break.
	       */
	      if((task = scamper_queue_select()) == NULL)
		{
		  /*
		   * if we are already probing to the window limit, don't
		   * add any new tasks
		   */
		  if(window != 0 && scamper_queue_windowcount() >= window)
		    break;

		  /*
		   * if there are no more tasks ready to be added yet, there's
		   * nothing more to be done in the loop
		   */
		  if(scamper_sources_gettask(&task) != 0 || task == NULL)
		    break;
		}

	      scamper_task_probe(task);
	      timeval_cpy(&lastprobe, &nextprobe);
	    }
	}
    }

  return 0;
}

/*
 * cleanup:
 *
 * be nice to the system and clean up all our mallocs
 */
static void cleanup(void)
{
  scamper_firewall_cleanup();
  scamper_getsrc_cleanup();
  scamper_rtsock_cleanup();

  scamper_icmp4_cleanup();
  scamper_icmp6_cleanup();
  scamper_udp4_cleanup();
  scamper_tcp4_cleanup();

  scamper_addr2mac_cleanup();

  scamper_do_trace_cleanup();
  scamper_do_ping_cleanup();
  scamper_do_tracelb_cleanup();
  scamper_do_dealias_cleanup();
  scamper_do_sting_cleanup();
  scamper_do_neighbourdisc_cleanup();
  scamper_do_tbit_cleanup();
  scamper_do_sniff_cleanup();
  scamper_do_host_cleanup();

  scamper_dl_cleanup();

  if(options & (OPT_CTRL_INET|OPT_CTRL_UNIX|OPT_CTRL_REMOTE))
    scamper_control_cleanup();

  scamper_sources_cleanup();
  scamper_outfiles_cleanup();
  scamper_fds_cleanup();

#ifndef WITHOUT_PRIVSEP
  scamper_privsep_cleanup();
#endif

  /* free the address cache, if one was used */
  if(addrcache != NULL)
    {
      scamper_addrcache_free(addrcache);
      addrcache = NULL;
    }

  if(ctrl_inet_addr != NULL)
    {
      free(ctrl_inet_addr);
      ctrl_inet_addr = NULL;
    }

  if(ctrl_rem_name != NULL)
    {
      free(ctrl_rem_name);
      ctrl_rem_name = NULL;
    }

  if(monitorname != NULL)
    {
      free(monitorname);
      monitorname = NULL;
    }

  if(firewall != NULL)
    {
      free(firewall);
      firewall = NULL;
    }

  if(command != NULL)
    {
      free(command);
      command = NULL;
    }
  scamper_queue_cleanup();
  scamper_task_cleanup();
  scamper_probe_cleanup();

#ifndef WITHOUT_DEBUGFILE
  if(options & OPT_DEBUGFILE)
    scamper_debug_close();
#endif

  scamper_osinfo_cleanup();

#ifndef WITHOUT_DEBUGFILE
  if(debugfile != NULL)
    {
      free(debugfile);
      debugfile = NULL;
    }
#endif

  if(pidfile != NULL)
    {
      free(pidfile);
      pidfile = NULL;
    }

  return;
}

int main(int argc, char *argv[])
{
  int i;

#ifndef _WIN32
  struct sigaction si_sa;
#endif

#ifdef _WIN32
  WSADATA wsaData;
#endif

  /*
   * if we are using dmalloc, then we want to get it to register its
   * logdump function to occur after we have used cleanup to free up
   * scamper's core data structures.  this is a dirty hack.
   *
   * if we are running a debug build on freebsd, make poor malloc use more
   * prone to causing scamper to crash.
   */
#if defined(DMALLOC)
  free(malloc(1));
#elif !defined (NDEBUG) && defined(__FreeBSD__) && __FreeBSD_version >= 500014 && __FreeBSD_version < 1000011
  _malloc_options = "AJ";
#endif

#ifdef _WIN32
  WSAStartup(MAKEWORD(2,2), &wsaData);
  timeBeginPeriod(1);
#endif

#ifndef _WIN32
  if(signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
      printerror(__func__, "could not ignore SIGPIPE");
      return -1;
    }

  sigemptyset(&si_sa.sa_mask);
  si_sa.sa_flags   = 0;
  si_sa.sa_handler = scamper_chld;
  if(sigaction(SIGCHLD, &si_sa, 0) == -1)
    {
      printerror(__func__, "could not set sigaction for SIGCHLD");
      return -1;
    }
#endif

  i = scamper(argc, argv);

  cleanup();

#ifdef _WIN32
  timeEndPeriod(1);
  WSACleanup();
#endif

  return i;
}
