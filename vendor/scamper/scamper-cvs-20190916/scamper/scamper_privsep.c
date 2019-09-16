/*
 * scamper_privsep.c: code that does root-required tasks
 *
 * $Id: scamper_privsep.c,v 1.90 2019/05/26 08:37:49 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2013-2014 The Regents of the University of California
 * Copyright (C) 2016      Matthew Luckie
 * Author: Matthew Luckie
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef WITHOUT_PRIVSEP

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_privsep.c,v 1.90 2019/05/26 08:37:49 mjl Exp $";
#endif

#include "internal.h"

#include "scamper_privsep.h"
#include "scamper_debug.h"

#include "scamper_dl.h"
#include "scamper_rtsock.h"
#include "scamper_firewall.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_udp4.h"
#include "scamper_ip4.h"

#include "utils.h"

typedef struct privsep_msg
{
  uint16_t plen;
  uint16_t type;
} privsep_msg_t;

typedef struct privsep_func
{
  int (*dofunc)(uint16_t len, const uint8_t *param);
  int (*txfunc)(int, int, uint8_t);
} privsep_func_t;

static pid_t root_pid  = -1; /* the process id of the root code */
static int   root_fd   = -1; /* the fd the root code send/recv on */
static int   lame_fd   = -1; /* the fd that the lame code uses */
static void *cmsgbuf   = NULL; /* cmsgbuf sized for one fd */

/*
 * the privilege separation code works by allowing the lame process to send
 * request messages to the root process.  these define the messages that
 * the root process understands.
 */
#define SCAMPER_PRIVSEP_EXIT          0x00U
#define SCAMPER_PRIVSEP_OPEN_DATALINK 0x01U
#define SCAMPER_PRIVSEP_OPEN_FILE     0x02U
#define SCAMPER_PRIVSEP_OPEN_RTSOCK   0x03U
#define SCAMPER_PRIVSEP_OPEN_ICMP     0x04U
#define SCAMPER_PRIVSEP_OPEN_SOCK     0x05U
#define SCAMPER_PRIVSEP_OPEN_RAWUDP   0x06U
#define SCAMPER_PRIVSEP_OPEN_UNIX     0x07U
#define SCAMPER_PRIVSEP_OPEN_RAWIP    0x08U
#define SCAMPER_PRIVSEP_UNLINK        0x09U
#define SCAMPER_PRIVSEP_IPFW_INIT     0x0aU
#define SCAMPER_PRIVSEP_IPFW_CLEANUP  0x0bU
#define SCAMPER_PRIVSEP_IPFW_ADD      0x0cU
#define SCAMPER_PRIVSEP_IPFW_DEL      0x0dU
#define SCAMPER_PRIVSEP_PF_INIT       0x0eU
#define SCAMPER_PRIVSEP_PF_CLEANUP    0x0fU
#define SCAMPER_PRIVSEP_PF_ADD        0x10U
#define SCAMPER_PRIVSEP_PF_DEL        0x11U

#define SCAMPER_PRIVSEP_MAXTYPE (SCAMPER_PRIVSEP_PF_DEL)

/*
 * privsep_open_rawsock
 *
 * open a raw icmp socket.  one integer parameter corresponding to the 'type'
 * is supplied in param.
 *
 */
static int privsep_open_icmp(uint16_t plen, const uint8_t *param)
{
  int type;

  if(plen != sizeof(type))
    {
      scamper_debug(__func__, "plen %d != %d", plen, sizeof(type));
      return -1;
    }

  memcpy(&type, param, sizeof(type));

  if(type == AF_INET)
    return scamper_icmp4_open_fd();
  if(type == AF_INET6)
    return scamper_icmp6_open_fd();

  scamper_debug(__func__, "type %d != AF_INET || AF_INET6", type);
  errno = EINVAL;
  return -1;
}

/*
 * privsep_open_rtsock
 *
 * open a routing socket.  there are no parameters permitted to this
 * method call.
 */
static int privsep_open_rtsock(uint16_t plen, const uint8_t *param)
{
  if(plen != 0)
    {
      scamper_debug(__func__, "plen %d != 0", plen, 0);
      errno = EINVAL;
      return -1;
    }

  return scamper_rtsock_open_fd();
}

/*
 * privsep_open_datalink
 *
 * open a BPF or PF_PACKET socket to the datalink.  the param has a single
 * field: the ifindex of the device to monitor.
 */
static int privsep_open_datalink(uint16_t plen, const uint8_t *param)
{
  int ifindex;

  /* the payload should have an integer field - no more, no less. */
  if(plen != sizeof(ifindex))
    {
      scamper_debug(__func__, "plen %d != %d", plen, sizeof(ifindex));
      errno = EINVAL;
      return -1;
    }

  memcpy(&ifindex, param, sizeof(ifindex));

  return scamper_dl_open_fd(ifindex);
}

static int privsep_open_sock(uint16_t plen, const uint8_t *param)
{
  struct sockaddr_in sin4;
  struct sockaddr_in6 sin6;
  int domain, type, protocol, port;
  const size_t size = sizeof(domain) + sizeof(protocol) + sizeof(port);
  size_t off = 0;
  int fd = -1;

  if(plen != size)
    {
      scamper_debug(__func__, "plen %d != %d", plen, size);
      errno = EINVAL;
      goto err;
    }
  off = 0;
  memcpy(&domain,   param+off, sizeof(domain));   off += sizeof(domain);
  memcpy(&protocol, param+off, sizeof(protocol)); off += sizeof(protocol);
  memcpy(&port,     param+off, sizeof(port));     off += sizeof(port);

  if(off != plen)
    goto inval;

  if(port < 1 || port > 65535)
    {
      scamper_debug(__func__, "refusing to bind to port %d", port);
      goto inval;
    }

  if(protocol == IPPROTO_TCP)      type = SOCK_STREAM;
  else if(protocol == IPPROTO_UDP) type = SOCK_DGRAM;
  else
    {
      scamper_debug(__func__, "unhandled IPv4 protocol %d", protocol);
      goto inval;
    }

  if(domain == AF_INET)
    {
      if((fd = socket(AF_INET, type, protocol)) == -1)
	{
	  printerror(__func__, "could not open IPv4 socket");
	  goto err;
	}
      sockaddr_compose((struct sockaddr *)&sin4, AF_INET, NULL, port);
      if(bind(fd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1)
	{
	  printerror(__func__, "could not bind to IPv4 protocol %d port %d",
		     protocol, port);
	  goto err;
	}
    }
  else if(domain == AF_INET6)
    {
      if((fd = socket(AF_INET6, type, protocol)) == -1)
	{
	  printerror(__func__, "could not open IPv6 socket");
	  goto err;
	}
      sockaddr_compose((struct sockaddr *)&sin6, AF_INET6, NULL, port);
      if(bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) == -1)
	{
	  printerror(__func__, "could not bind to IPv6 protocol %d port %d",
		     protocol, port);
	  goto err;
	}
    }
  else return -1;

  return fd;

 inval:
  errno = EINVAL;
 err:
  if(fd != -1) close(fd);
  return -1;
}

static int privsep_open_rawudp(uint16_t plen, const uint8_t *param)
{
  struct in_addr in;

  if(plen != 4)
    {
      scamper_debug(__func__, "plen %d != 4", plen);
      errno = EINVAL;
      return -1;
    }

  memcpy(&in, param+0, sizeof(in));
  return scamper_udp4_openraw_fd(&in);
}

static int privsep_open_rawip(uint16_t plen, const uint8_t *param)
{
  if(plen != 0)
    {
      scamper_debug(__func__, "plen %d != 4", plen);
      errno = EINVAL;
      return -1;
    }
  return scamper_ip4_openraw_fd();
}

static int privsep_ipfw_init(uint16_t plen, const uint8_t *param)
{
#ifdef HAVE_IPFW
  if(plen != 0)
    {
      scamper_debug(__func__, "plen %d != 0", plen);
      errno = EINVAL;
      return -1;
    }
  return scamper_firewall_ipfw_init();
#else
  scamper_debug(__func__, "not on ipfw system");
  errno = EINVAL;
  return -1;
#endif
}

static int privsep_ipfw_cleanup(uint16_t plen, const uint8_t *param)
{
#ifdef HAVE_IPFW
  if(plen != 0)
    {
      scamper_debug(__func__, "plen %d != 0", plen);
      errno = EINVAL;
      return -1;
    }
  scamper_firewall_ipfw_cleanup();
  return 0;
#else
  scamper_debug(__func__, "not on ipfw system");
  errno = EINVAL;
  return -1;
#endif
}

static int privsep_ipfw_add(uint16_t plen, const uint8_t *param)
{
#ifdef HAVE_IPFW
  int n, af, p, sp, dp;
  struct in_addr s4, d4;
  struct in6_addr s6, d6;
  void *s, *d = NULL;
  uint8_t df;
  uint16_t off = 0, al;

  if(plen < 1 + sizeof(int))
    {
      scamper_debug(__func__, "plen %d < %d", plen, 1 + sizeof(int));
      goto inval;
    }

  df = param[0]; off++;
  if(df != 0 && df != 1)
    {
      scamper_debug(__func__, "df %d", df);
      goto inval;
    }

  memcpy(&af, param+off, sizeof(af)); off += sizeof(af);
  if(af == AF_INET)
    {
      s = &s4;
      al = 4;
      if(df == 0)
	{
	  if(plen != 1 + (sizeof(int) * 5) + sizeof(struct in_addr))
	    goto inval;
	}
      else
	{
	  if(plen != 1 + (sizeof(int) * 5) + (sizeof(struct in_addr) * 2))
	    goto inval;
	  d = &d4;
	}
    }
  else if(af == AF_INET6)
    {
      s = &s6;
      al = 16;
      if(df == 0)
	{
	  if(plen != 1 + (sizeof(int) * 5) + sizeof(struct in6_addr))
	    goto inval;
	}
      else
	{
	  if(plen != 1 + (sizeof(int) * 5) + (sizeof(struct in6_addr) * 2))
	    goto inval;
	  d = &d6;
	}
    }
  else goto inval;

  memcpy(&n, param+off, sizeof(n)); off += sizeof(n);
  memcpy(&p, param+off, sizeof(p)); off += sizeof(p);
  memcpy(s, param+off, al); off += al;

  if(df != 0)
    {
      memcpy(d, param+off, al);
      off += al;
    }

  memcpy(&sp, param+off, sizeof(sp)); off += sizeof(sp);
  memcpy(&dp, param+off, sizeof(dp)); off += sizeof(dp);

  if(off != plen)
    goto inval;
  if(sp < 0 || sp > 65535 || dp < 0 || dp > 65535)
    goto inval;
  if(p != IPPROTO_TCP && p != IPPROTO_UDP)
    goto inval;

  return scamper_firewall_ipfw_add(n, af, p, s, d, sp, dp);

 inval:
  errno = EINVAL;
  return -1;
#else
  scamper_debug(__func__, "not on ipfw system");
  errno = EINVAL;
  return -1;
#endif
}

static int privsep_ipfw_del(uint16_t plen, const uint8_t *param)
{
#ifdef HAVE_IPFW
  int n, af;
  uint16_t off = 0;

  if(plen != sizeof(int) * 2)
    {
      scamper_debug(__func__, "plen %d != %d", plen, sizeof(int) * 2);
      goto inval;
    }

  memcpy(&n, param+off, sizeof(n)); off += sizeof(n);
  memcpy(&af, param+off, sizeof(af)); off += sizeof(af);
  if(off != plen)
    goto inval;

  return scamper_firewall_ipfw_del(n, af);

 inval:
  errno = EINVAL;
  return -1;
#else
  scamper_debug(__func__, "not on ipfw system");
  errno = EINVAL;
  return -1;
#endif
}

static int privsep_pf_init(uint16_t plen, const uint8_t *param)
{
#ifdef HAVE_PF
  const char *name = (const char *)param;
  if(plen == 0)
    {
      scamper_debug(__func__, "plen == 0", plen);
      errno = EINVAL;
      return -1;
    }
  if(string_isprint(name, plen) == 0)
    {
      scamper_debug(__func__, "name is not printable");
      errno = EINVAL;
      return -1;
    }
  if(name[plen] != '\0' || strlen(name) + 1 != plen)
    {
      scamper_debug(__func__, "malformed initialisation");
      errno = EINVAL;
      return -1;
    }
  return scamper_firewall_pf_init(name);
#else
  scamper_debug(__func__, "not on pf system");
  errno = EINVAL;
  return -1;
#endif
}

static int privsep_pf_cleanup(uint16_t plen, const uint8_t *param)
{
#ifdef HAVE_PF
  if(plen != 0)
    {
      scamper_debug(__func__, "plen %d != 0", plen);
      errno = EINVAL;
      return -1;
    }
  scamper_firewall_pf_cleanup();
  return 0;
#else
  scamper_debug(__func__, "not on pf system");
  errno = EINVAL;
  return -1;
#endif
}

static int privsep_pf_add(uint16_t plen, const uint8_t *param)
{
#ifdef HAVE_PF
  int n, af, p, sp, dp;
  struct in_addr s4, d4;
  struct in6_addr s6, d6;
  void *s, *d;
  uint16_t off = 0, al;

  if(plen < sizeof(int))
    {
      scamper_debug(__func__, "plen %d < %d", plen, sizeof(int));
      goto inval;
    }

  memcpy(&af, param+off, sizeof(af)); off += sizeof(af);
  if(af == AF_INET)
    {
      if(plen != (sizeof(int) * 5) + (sizeof(struct in_addr) * 2))
	goto inval;
      s = &s4;
      d = &d4;
      al = 4;
    }
  else if(af == AF_INET6)
    {
      if(plen != (sizeof(int) * 5) + (sizeof(struct in6_addr) * 2))
	goto inval;
      s = &s6;
      d = &d6;
      al = 16;
    }
  else goto inval;

  memcpy(&n, param+off, sizeof(n)); off += sizeof(n);
  memcpy(&p, param+off, sizeof(p)); off += sizeof(p);
  memcpy(s, param+off, al); off += al;
  memcpy(d, param+off, al); off += al;
  memcpy(&sp, param+off, sizeof(sp)); off += sizeof(sp);
  memcpy(&dp, param+off, sizeof(dp)); off += sizeof(dp);

  if(off != plen)
    goto inval;
  if(sp < 0 || sp > 65535 || dp < 0 || dp > 65535)
    goto inval;
  if(p != IPPROTO_TCP && p != IPPROTO_UDP)
    goto inval;

  return scamper_firewall_pf_add(n, af, p, s, d, sp, dp);

 inval:
  errno = EINVAL;
  return -1;
#else
  scamper_debug(__func__, "not on pf system");
  errno = EINVAL;
  return -1;
#endif
}

static int privsep_pf_del(uint16_t plen, const uint8_t *param)
{
#ifdef HAVE_PF
  int n;
  if(plen != sizeof(int))
    {
      scamper_debug(__func__, "plen %d != %d", plen, sizeof(int));
      errno = EINVAL;
      return -1;
    }
  memcpy(&n, param, sizeof(n));
  return scamper_firewall_pf_del(n);
#else
  scamper_debug(__func__, "not on pf system");
  errno = EINVAL;
  return -1;
#endif
}

static int privsep_unlink(uint16_t plen, const uint8_t *param)
{
  const char *name = (const char *)param;
  uid_t uid, euid;

  if(plen < 2 || name[plen-1] != '\0')
    return -1;

  uid  = getuid();
  euid = geteuid();
  if(seteuid(uid) != 0)
    return -1;
  unlink(name);
  if(seteuid(euid) != 0)
    exit(-errno);

  return 0;
}

static int privsep_open_unix(uint16_t plen, const uint8_t *param)
{
  const char *name = (const char *)param;
  struct sockaddr_un sn;
  uid_t uid, euid;
  int fd, brc;

  if(plen < 2 || name[plen-1] != '\0')
    return -1;

  if(sockaddr_compose_un((struct sockaddr *)&sn, name) != 0)
    return -1;

  /* set our effective uid to be the user who started scamper */
  uid  = getuid();
  euid = geteuid();
  if(seteuid(uid) != 0)
    return -1;

  /* open the socket, bind it, and make it listen */
  if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) != -1)
    {
      if((brc = bind(fd, (struct sockaddr *)&sn, sizeof(sn))) != 0 ||
	 listen(fd, -1) != 0)
	{
	  close(fd);
	  fd = -1;
	  if(brc == 0)
	    unlink(name);
	}
    }

  if(seteuid(euid) != 0)
    {
      if(fd != -1) close(fd);
      exit(-errno);
    }

  return fd;
}

/*
 * privsep_open_file
 *
 * switch to the user running the process and open the file specified.
 * the param has two fields in it: the mode of open, and the file to open.
 */
static int privsep_open_file(uint16_t plen, const uint8_t *param)
{
  const char *file;
  uid_t       uid, euid;
  int         flags;
  mode_t      mode = 0;
  uint16_t    off;
  int         fd;

  /*
   * if the payload of param is not large enough to hold the flags and a
   * filename, then don't go any further
   */
  if(plen < sizeof(int) + 2)
    return -1;

  memcpy(&flags, param, sizeof(int));
  off = sizeof(int);

  /* if the O_CREAT flag is set, we need to fetch the mode parameter too */
  if(flags & O_CREAT)
    {
      /*
       * the payload length of the parameter must be large enough to hold
       * the flags, mode, and a filename
       */
      if(plen < off + sizeof(mode_t) + 2)
	return -1;

      memcpy(&mode, param+off, sizeof(mode));
      off += sizeof(mode);
    }

  file = (const char *)(param + off);

  /*
   * make sure the length of the file to open checks out.
   * the last byte of the string must be a null character.
   */
  if(file[plen-off-1] != '\0')
    {
      scamper_debug(__func__, "filename not terminated with a null");
      return -1;
    }

  uid  = getuid();
  euid = geteuid();

  /* set our effective uid to be the user who started scamper */
  if(seteuid(uid) == -1)
    {
      return -1;
    }

  if(flags & O_CREAT)
    fd = open(file, flags, mode);
  else
    fd = open(file, flags);

  /*
   * ask for our root permissions back.  if we can't get them back, then
   * this process is crippled and it might as well exit now.
   */
  if(seteuid(euid) == -1)
    {
      if(fd != -1) close(fd);
      exit(-errno);
    }

  return fd;
}

static int privsep_send_rc(int rc, int error, uint8_t msg_type)
{
  uint8_t       buf[sizeof(int) * 2];
  struct msghdr msg;
  struct iovec  vec;

  scamper_debug(__func__, "rc: %d, error: %d, msg_type: 0x%02x",
		rc, error, msg_type);

  memset(&vec, 0, sizeof(vec));
  memset(&msg, 0, sizeof(msg));

  memcpy(buf, &rc, sizeof(int));
  memcpy(buf+sizeof(int), &error, sizeof(int));
  vec.iov_base = (void *)buf;
  vec.iov_len  = sizeof(buf);

  msg.msg_iov    = &vec;
  msg.msg_iovlen = 1;

  if(sendmsg(root_fd, &msg, 0) == -1)
    return -1;

  return 0;

}

/*
 * privsep_send_fd
 *
 * send the fd created using the priviledged code.  if the fd was not
 * successfully created, we send the errno back in the payload of the
 * message.
 */
static int privsep_send_fd(int fd, int error, uint8_t msg_type)
{
  struct msghdr   msg;
  struct iovec    vec;
  struct cmsghdr *cmsg;

  scamper_debug(__func__, "fd: %d error: %d msg_type: 0x%02x",
		fd, error, msg_type);

  memset(&vec, 0, sizeof(vec));
  memset(&msg, 0, sizeof(msg));

  vec.iov_base = (void *)&error;
  vec.iov_len  = sizeof(error);

  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;

  if(fd != -1)
    {
      msg.msg_control = (caddr_t)cmsgbuf;
      msg.msg_controllen = CMSG_SPACE(sizeof(fd));

      cmsg = CMSG_FIRSTHDR(&msg);
      cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      *(int *)CMSG_DATA(cmsg) = fd;
    }

  if(sendmsg(root_fd, &msg, 0) == -1)
    {
      printerror(__func__, "couldnt send fd");
      return -1;
    }

  return 0;
}

static int privsep_recv_fd(void)
{
  struct msghdr   msg;
  struct iovec    vec;
  ssize_t         rc;
  int             fd = -1, error = 0;
  struct cmsghdr *cmsg;

  memset(&vec, 0, sizeof(vec));
  memset(&msg, 0, sizeof(msg));

  vec.iov_base = (char *)&error;
  vec.iov_len  = sizeof(error);

  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;

  msg.msg_control = cmsgbuf;
  msg.msg_controllen = CMSG_SPACE(sizeof(fd));

  if((rc = recvmsg(lame_fd, &msg, 0)) == -1)
    {
      printerror(__func__, "recvmsg failed");
      return -1;
    }
  else if(rc != sizeof(error))
    {
      return -1;
    }

  if(error == 0)
    {
      cmsg = CMSG_FIRSTHDR(&msg);
      if(cmsg != NULL && cmsg->cmsg_type == SCM_RIGHTS)
	{
	  fd = (*(int *)CMSG_DATA(cmsg));
	}
    }
  else
    {
      errno = error;
    }

  return fd;
}

/*
 * privsep_do
 *
 * this is the only piece of code with root priviledges.  we use it to
 * create raw sockets, routing/netlink sockets, BPF/PF_PACKET sockets, and
 * ordinary files that scamper itself cannot do by itself.
 */
static int privsep_do(void)
{
  static const privsep_func_t funcs[] = {
    {NULL, NULL},
    {privsep_open_datalink, privsep_send_fd},
    {privsep_open_file,     privsep_send_fd},
    {privsep_open_rtsock,   privsep_send_fd},
    {privsep_open_icmp,     privsep_send_fd},
    {privsep_open_sock,     privsep_send_fd},
    {privsep_open_rawudp,   privsep_send_fd},
    {privsep_open_unix,     privsep_send_fd},
    {privsep_open_rawip,    privsep_send_fd},
    {privsep_unlink,        privsep_send_rc},
    {privsep_ipfw_init,     privsep_send_rc},
    {privsep_ipfw_cleanup,  privsep_send_rc},
    {privsep_ipfw_add,      privsep_send_rc},
    {privsep_ipfw_del,      privsep_send_rc},
    {privsep_pf_init,       privsep_send_rc},
    {privsep_pf_cleanup,    privsep_send_rc},
    {privsep_pf_add,        privsep_send_rc},
    {privsep_pf_del,        privsep_send_rc},
  };

  privsep_msg_t   msg;
  void           *data = NULL;
  int             ret = 0, error;
  int             fd;

#if defined(HAVE_SETPROCTITLE)
  setproctitle("%s", "[priv]");
#endif

  /* might as well set our copy of the root_pid to something useful */
  root_pid = getpid();

  /*
   * the priviledged process does not need the lame file descriptor for
   * anything, so get rid of it
   */
  close(lame_fd);
  lame_fd = -1;

  for(;;)
    {
      /* read the msg header */
      if((ret = read_wrap(root_fd, (uint8_t *)&msg, NULL, sizeof(msg))) != 0)
	{
	  if(ret == -1)
	    printerror(__func__, "could not read msg hdr");
	  break;
	}

      /* if we've been told to exit, then do so now */
      if(msg.type == SCAMPER_PRIVSEP_EXIT)
	break;

      if(msg.type > SCAMPER_PRIVSEP_MAXTYPE)
	{
	  scamper_debug(__func__, "msg %d > maxtype", msg.type);
	  ret = -EINVAL;
	  break;
	}

      /* if there is more data to read, read it now */
      if(msg.plen != 0)
	{
	  if((data = malloc_zero(msg.plen)) == NULL)
	    {
	      printerror(__func__, "couldnt malloc data");
	      ret = (-errno);
	      break;
	    }

	  if((ret = read_wrap(root_fd, data, NULL, msg.plen)) != 0)
	    {
	      printerror(__func__, "couldnt read data");
	      free(data);
	      break;
	    }
	}
      else data = NULL;

      if((fd = funcs[msg.type].dofunc(msg.plen, data)) == -1)
	error = errno;
      else
	error = 0;

      /* we don't need the data we read anymore */
      if(data != NULL)
	free(data);

      if(funcs[msg.type].txfunc(fd, error, msg.type) != 0)
	break;

      if(funcs[msg.type].txfunc == privsep_send_fd && fd != -1)
	close(fd);
    }

  close(root_fd);
  return ret;
}

/*
 * privsep_lame_send
 *
 * compose and send the messages necessary to communicate with the root
 * process.
 */
static int privsep_lame_send(const uint16_t type, const uint16_t len,
			     const uint8_t *param)
{
  privsep_msg_t msg;

  assert(type != SCAMPER_PRIVSEP_EXIT);
  assert(type <= SCAMPER_PRIVSEP_MAXTYPE);

  /* send the header first */
  msg.type = type;
  msg.plen = len;
  if(write_wrap(lame_fd, &msg, NULL, sizeof(msg)) == -1)
    {
      printerror(__func__, "could not send msg header");
      return -1;
    }

  /* if there is a parameter data to send, send it now */
  if(len != 0 && write_wrap(lame_fd, param, NULL, len) == -1)
    {
      printerror(__func__, "could not send msg param");
      return -1;
    }

  return 0;
}

/*
 * privsep_getfd
 *
 * send a request to the piece of code running as root to do open a file
 * descriptor that requires priviledge to do.  return the file descriptor.
 */
static int privsep_getfd(uint16_t type, uint16_t len, const uint8_t *param)
{
  if(privsep_lame_send(type, len, param) == -1)
    {
      return -1;
    }

  return privsep_recv_fd();
}

static int privsep_dotask(uint16_t type, uint16_t len, const uint8_t *param)
{
  uint8_t buf[sizeof(int)*2];
  int error;
  int rc;

  if(privsep_lame_send(type, len, param) == -1)
    return -1;

  if(read_wrap(lame_fd, buf, NULL, sizeof(buf)) == -1)
    return -1;

  memcpy(&rc, buf, sizeof(rc));
  memcpy(&error, buf+sizeof(int), sizeof(error));

  if(rc != 0)
    errno = error;

  return rc;
}

static int privsep_getfd_1int(const uint16_t type, const int p1)
{
  uint8_t param[sizeof(p1)];
  memcpy(param, &p1, sizeof(p1));
  return privsep_getfd(type, sizeof(param), param);
}

static int privsep_getfd_3int(const uint16_t type,
			      const int p1, const int p2, const int p3)
{
  uint8_t param[sizeof(p1)+sizeof(p2)+sizeof(p3)];
  size_t off = 0;
  memcpy(param+off, &p1, sizeof(p1)); off += sizeof(p1);
  memcpy(param+off, &p2, sizeof(p2)); off += sizeof(p2);
  memcpy(param+off, &p3, sizeof(p3));
  return privsep_getfd(type, sizeof(param), param);
}

int scamper_privsep_open_datalink(const int ifindex)
{
  return privsep_getfd_1int(SCAMPER_PRIVSEP_OPEN_DATALINK, ifindex);
}

int scamper_privsep_open_unix(const char *file)
{
  int len = strlen(file) + 1;
  return privsep_getfd(SCAMPER_PRIVSEP_OPEN_UNIX, len, (const uint8_t *)file);
}

int scamper_privsep_open_file(const char *file,
			      const int flags, const mode_t mode)
{
  uint8_t *param;
  int off, len, fd;

  /*
   * decide how big the message is going to be.  don't pass it if the message
   * length parameter constrains us
   */
  len = sizeof(flags) + strlen(file) + 1;
  if(flags & O_CREAT)
    len += sizeof(mode);

  /*
   * the len is fixed because the length parameter used in the privsep
   * header is a 16-bit unsigned integer.
   */
  if(len > 65535)
    return -1;

  /* allocate the parameter */
  if((param = malloc_zero(len)) == NULL)
    return -1;

  /* copy in the flags parameter, and the mode parameter if necessary */
  memcpy(param, &flags, sizeof(flags)); off = sizeof(flags);
  if(flags & O_CREAT)
    {
      memcpy(param+off, &mode, sizeof(mode));
      off += sizeof(mode);
    }

  /* finally copy in the name of the file to open */
  memcpy(param+off, file, len-off);

  /* get the file descriptor and return it */
  fd = privsep_getfd(SCAMPER_PRIVSEP_OPEN_FILE, len, param);
  free(param);
  return fd;
}

int scamper_privsep_open_rtsock(void)
{
  return privsep_getfd(SCAMPER_PRIVSEP_OPEN_RTSOCK, 0, NULL);
}

int scamper_privsep_open_icmp(const int domain)
{
  return privsep_getfd_1int(SCAMPER_PRIVSEP_OPEN_ICMP, domain);
}

int scamper_privsep_open_tcp(const int domain, const int port)
{
  return privsep_getfd_3int(SCAMPER_PRIVSEP_OPEN_SOCK,domain,IPPROTO_TCP,port);
}

int scamper_privsep_open_udp(const int domain, const int port)
{
  return privsep_getfd_3int(SCAMPER_PRIVSEP_OPEN_SOCK,domain,IPPROTO_UDP,port);
}

int scamper_privsep_open_rawudp(const void *addr)
{
  uint8_t param[4];

  if(addr == NULL)
    memset(param, 0, 4);
  else
    memcpy(param, addr, 4);

  return privsep_getfd(SCAMPER_PRIVSEP_OPEN_RAWUDP, sizeof(param), param);
}

int scamper_privsep_open_rawip(void)
{
  return privsep_getfd(SCAMPER_PRIVSEP_OPEN_RAWIP, 0, NULL);
}

int scamper_privsep_unlink(const char *file)
{
  int len = strlen(file) + 1;
  return privsep_dotask(SCAMPER_PRIVSEP_UNLINK, len, (const uint8_t *)file);
}

int scamper_privsep_ipfw_init(void)
{
  return privsep_dotask(SCAMPER_PRIVSEP_IPFW_INIT, 0, NULL);
}

int scamper_privsep_ipfw_cleanup(void)
{
  return privsep_dotask(SCAMPER_PRIVSEP_IPFW_CLEANUP, 0, NULL);
}

int scamper_privsep_ipfw_add(int n,int af,int p,void *s,void *d,int sp,int dp)
{
  uint8_t param[1 + (sizeof(int) * 5) + (16 * 2)];
  uint16_t len = 0;
  uint16_t al;

  if(d == NULL)
    param[0] = 0;
  else
    param[0] = 1;
  len++;

  if(af == AF_INET)
    al = 4;
  else if(af == AF_INET6)
    al = 16;
  else
    return -1;

  memcpy(param+len, &af, sizeof(af)); len += sizeof(af);
  memcpy(param+len, &n, sizeof(n)); len += sizeof(n);
  memcpy(param+len, &p, sizeof(p)); len += sizeof(p);
  memcpy(param+len, s, al); len += al;
  if(d != NULL)
    {
      memcpy(param+len, d, al);
      len += al;
    }
  memcpy(param+len, &sp, sizeof(sp)); len += sizeof(sp);
  memcpy(param+len, &dp, sizeof(dp)); len += sizeof(dp);

  return privsep_dotask(SCAMPER_PRIVSEP_IPFW_ADD, len, param);
}

int scamper_privsep_ipfw_del(int n, int af)
{
  uint8_t param[(sizeof(int) * 2)];
  uint16_t len = 0;
  memcpy(param+len, &n, sizeof(int)); len += sizeof(n);
  memcpy(param+len, &af, sizeof(int)); len += sizeof(af);
  return privsep_dotask(SCAMPER_PRIVSEP_IPFW_DEL, len, param);
}

int scamper_privsep_pf_init(const char *anchor)
{
  int len = strlen(anchor) + 1;
  return privsep_dotask(SCAMPER_PRIVSEP_PF_INIT, len, (const uint8_t *)anchor);
}

int scamper_privsep_pf_cleanup(void)
{
  return privsep_dotask(SCAMPER_PRIVSEP_PF_CLEANUP, 0, NULL);
}

int scamper_privsep_pf_add(int n,int af,int p,void *s,void *d,int sp,int dp)
{
  uint8_t param[(sizeof(int) * 5) + (16 * 2)];
  uint16_t len = 0;
  uint16_t al;

  if(af == AF_INET)
    al = 4;
  else if(af == AF_INET6)
    al = 16;
  else
    return -1;

  memcpy(param+len, &af, sizeof(af)); len += sizeof(af);
  memcpy(param+len, &n, sizeof(n)); len += sizeof(n);
  memcpy(param+len, &p, sizeof(p)); len += sizeof(p);
  memcpy(param+len, s, al); len += al;
  memcpy(param+len, d, al); len += al;
  memcpy(param+len, &sp, sizeof(sp)); len += sizeof(sp);
  memcpy(param+len, &dp, sizeof(dp)); len += sizeof(dp);

  return privsep_dotask(SCAMPER_PRIVSEP_PF_ADD, len, param);
}

int scamper_privsep_pf_del(int n)
{
  uint8_t param[sizeof(int)];
  memcpy(param, &n, sizeof(int));
  return privsep_dotask(SCAMPER_PRIVSEP_PF_DEL, sizeof(int), param);
}

/*
 * scamper_privsep
 *
 * start a child process that has the root priviledges that scamper starts
 * with.  then, revoke scamper's priviledges to the minimum scamper can
 * obtain
 */
int scamper_privsep_init()
{
  struct addrinfo hints, *res0;
  struct timeval tv;
  struct passwd *pw;
  struct stat sb;
  mode_t mode;
  uid_t  uid;
  gid_t  gid;
  int    sockets[2];
  pid_t  pid;
  int    ret;
  time_t t;

  /* check to see if the PRIVSEP_DIR exists */
  if(stat(PRIVSEP_DIR, &sb) == -1)
    {
      /* if the directory does not exist, try and create it now */
      if(errno == ENOENT)
	{
	  /*
	   * get the uid of the user who will get ownership of the directory.
	   * by default, this will be root.
	   */
	  if((pw = getpwnam(PRIVSEP_DIR_OWNER)) == NULL)
	    {
	      printerror(__func__, "could not getpwnam " PRIVSEP_DIR_OWNER);
	      endpwent();
	      return -1;
	    }
	  uid = pw->pw_uid;
	  endpwent();

	  gid = 0;

	  /* create the directory as 555 : no one can write to it */
	  mode = S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	  if(mkdir(PRIVSEP_DIR, mode) == -1)
	    {
	      printerror(__func__, "could not mkdir " PRIVSEP_DIR);
	      return -1;
	    }

	  /* assign ownership appropriately */
	  if(chown(PRIVSEP_DIR, uid, gid) == -1)
	    {
	      printerror(__func__, "could not chown " PRIVSEP_DIR);
	      rmdir(PRIVSEP_DIR);
	      return -1;
	    }
	}
      else
	{
	  printerror(__func__, "could not stat " PRIVSEP_DIR);
	  return -1;
	}
    }

  /*
   * open up the unix domain sockets that will allow the prober to talk
   * with the priviledged process
   */
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1)
    {
      printerror(__func__, "could not socketpair");
      return -1;
    }

  lame_fd = sockets[0];
  root_fd = sockets[1];

  if((cmsgbuf = malloc_zero(CMSG_SPACE(sizeof(int)))) == NULL)
    {
      printerror(__func__, "could not malloc cmsgbuf");
      return -1;
    }

  if((pid = fork()) == -1)
    {
      printerror(__func__, "could not fork");
      return -1;
    }
  else if(pid == 0) /* child */
    {
      /*
       * this is the process that will do the root tasks.
       * when this function exits, we call exit() on the forked process.
       */
      ret = privsep_do();
      exit(ret);
    }

  /* set our copy of the root_pid to the relevant process id */
  root_pid = pid;

  /*
   * we don't need our copy of the file descriptor passed to the priviledged
   * process any longer
   */
  close(root_fd);
  root_fd = -1;

  /*
   * get the details for the PRIVSEP_USER login, which the rest of scamper
   * will use to get things done
   */
  if((pw = getpwnam(PRIVSEP_USER)) == NULL)
    {
      printerror(__func__, "could not getpwnam " PRIVSEP_USER);
      return -1;
    }
  uid = pw->pw_uid;
  gid = pw->pw_gid;
  memset(pw->pw_passwd, 0, strlen(pw->pw_passwd));
  endpwent();

  /*
   * call localtime now, as then the unpriviledged process will have the
   * local time zone information cached in the process, so localtime will
   * actually mean something
   */
  gettimeofday_wrap(&tv);
  t = tv.tv_sec;
  localtime(&t);

  /*
   * call getaddrinfo now, as then the unpriviledged process will load
   * whatever files it needs to to help resolve IP addresses; the need for
   * this was first noticed in SunOS
   */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_family   = AF_INET;
  getaddrinfo("localhost", NULL, &hints, &res0);
  freeaddrinfo(res0);

  /* change the root directory of the unpriviledged directory */
  if(chroot(PRIVSEP_DIR) == -1)
    {
      printerror(__func__, "could not chroot to " PRIVSEP_DIR);
      return -1;
    }

  /* go into the chroot environment */
  if(chdir("/") == -1)
    {
      printerror(__func__, "could not chdir /");
      return -1;
    }

  /* change the operating group */
  if(setgroups(1, &gid) == -1)
    {
      printerror(__func__, "could not setgroups");
      return -1;
    }
  if(setgid(gid) == -1)
    {
      printerror(__func__, "could not setgid");
      return -1;
    }

  /* change the operating user */
  if(setuid(uid) == -1)
    {
      printerror(__func__, "could not setuid");
      return -1;
    }

  return lame_fd;
}

void scamper_privsep_cleanup()
{
  privsep_msg_t msg;

  if(root_pid != -1)
    {
      msg.plen = 0;
      msg.type = SCAMPER_PRIVSEP_EXIT;

      write_wrap(lame_fd, (uint8_t *)&msg, NULL, sizeof(msg));
      root_pid = -1;
    }

  if(lame_fd != -1)
    {
      close(lame_fd);
      lame_fd = -1;
    }

  if(cmsgbuf != NULL)
    {
      free(cmsgbuf);
      cmsgbuf = NULL;
    }

  return;
}

#endif /* ifndef WITHOUT_PRIVSEP */
