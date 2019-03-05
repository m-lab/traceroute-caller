/*
 * sc_remoted
 *
 * $Id: sc_remoted.c,v 1.50 2016/08/09 07:05:45 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2014-2016 Matthew Luckie
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
 *****************
 *
 * This code defines a protocol that exists between a central server
 * running sc_remoted, and a remote system running scamper.  As the
 * protocol allows multiple local processes to drive a single remote
 * scamper process, the protocol is based around "channels" to
 * separate multiple streams of scamper control connection over a
 * single TCP socket.
 *
 * The protocol is roughly designed as follows:
 *
 * Header:
 * ------
 * uint32_t channel
 * uint16_t msglen
 *
 * The control header is included in every message sent between the
 * scamper instance and the remote controller.
 * The channel number identifies the stream; channel #0 is reserved for
 * control messages.
 * The msglen value defines the size of the message following the header
 *
 * Control Messages:
 * ----------------
 * uint8_t type
 *
 * A control message begins with a mandatory type number.  The following
 * control message types are defined, with arrows defining who may send
 * which message type.
 *
 * 0 - Master      (remoted <- scamper)
 * 1 - New Channel (remoted -> scamper)
 * 2 - Channel FIN (remoted <> scamper)
 *
 * Control Message - Master New:
 * ----------------------------
 *
 * Whenever a scamper instance establishes a TCP connection with a remote
 * controller, it sends a message that identifies itself.  The message
 * is formatted as follows:
 *
 * uint8_t   magic_len
 * uint8_t  *magic
 * uint8_t   monitorname_len
 * char     *monitorname
 *
 * The magic value is generated randomly by the scamper instance when
 * the process starts, and is never modified.  The same magic value is
 * always supplied in a control socket connection and allows the remote
 * controller to identify that the scamper instance supports graceful
 * restart.
 * The monitorname is sent if the remote scamper instance uses the -M
 * option.
 * Both magic_len and monitorname_len include the terminating null byte.
 *
 * Control Message - Master ID:
 * ---------------------------
 *
 * After the "Master New" message has been received by the remote
 * controller, the remote controller sends an ID value to the scamper
 * instance that it can use as a list identifier in warts.  The message
 * is formatted as follows:
 *
 * uint8_t  id_len;
 * char    *id
 *
 * Control Message - New Channel:
 * -----------------------------
 *
 * Whenever a remote controller has a new connection on a unix domain
 * socket, it sends a control message to scamper with a new channel
 * number to use for the connection.  The message is formatted as
 * follows:
 *
 * uint32_t channel
 *
 * Control Message - Client FIN:
 * ----------------------------
 *
 * Whenever a client connection has no more to send, it sends a FIN
 * type.  the FIN message must be sent by both the remote controller
 * and the scamper instance for a channel to be closed.  The message
 * is formatted as follows:
 *
 * uint32_t channel
 *
 */

#ifndef lint
static const char rcsid[] =
  "$Id: sc_remoted.c,v 1.50 2016/08/09 07:05:45 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_linepoll.h"
#include "scamper_writebuf.h"
#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "utils.h"

/*
 * sc_unit
 *
 * this generic structure says what kind of node is pointed to, and is
 * used to help garbage collect with kqueue / epoll.
 */
typedef struct sc_unit
{
  void               *data;
  dlist_t            *list; /* list == gclist if on that list */
  dlist_node_t       *node;
  uint8_t             type;
  uint8_t             gc;
} sc_unit_t;

#define UNIT_TYPE_MASTER  0
#define UNIT_TYPE_CHANNEL 1

/*
 * sc_fd
 *
 * this structure associates a file descriptor with a data pointer, as
 * well as information about what type the fd is and any current
 * state.
 */
typedef struct sc_fd
{
  int                 fd;
  sc_unit_t          *unit;
  uint8_t             type;
  uint8_t             flags;
} sc_fd_t;

#define FD_TYPE_SERVER       0
#define FD_TYPE_MASTER_INET  1
#define FD_TYPE_MASTER_UNIX  2
#define FD_TYPE_CHANNEL_UNIX 3

#define FD_FLAG_READ        1
#define FD_FLAG_WRITE       2

/*
 * sc_master_t
 *
 * this structure holds a mapping between a remote scamper process
 * that is willing to be driven and a local unix domain socket where
 * local processes can connect.  it also includes a list of all
 * clients connected using the socket.
 */
typedef struct sc_master
{
  sc_unit_t          *unit;
  char               *name;
  uint8_t            *magic;
  uint8_t             magic_len;

  sc_fd_t            *unix_fd;
  sc_fd_t             inet_fd;
  scamper_writebuf_t *inet_wb;

#ifdef HAVE_OPENSSL
  int                 inet_mode;
  SSL                *inet_ssl;
  BIO                *inet_rbio;
  BIO                *inet_wbio;
#endif

  struct timeval      tx_ka;
  struct timeval      rx_abort;

  dlist_t            *channels;
  uint32_t            next_channel;
  dlist_node_t       *node;
  uint8_t             buf[65536+6];
  size_t              buf_offset;
} sc_master_t;

/*
 * sc_channel_t
 *
 * this structure holds a mapping between a local process that wants
 * to drive a remote scamper, and a channel corresponding to that
 * instance.
 */
typedef struct sc_channel
{
  uint32_t            id;
  sc_unit_t          *unit;
  sc_fd_t            *unix_fd;
  scamper_linepoll_t *unix_lp;
  scamper_writebuf_t *unix_wb;
  sc_master_t        *master;
  dlist_node_t       *node;
  uint8_t             flags;
} sc_channel_t;

#define OPT_HELP    0x0001
#define OPT_UNIX    0x0002
#define OPT_PORT    0x0004
#define OPT_DAEMON  0x0008
#define OPT_IPV4    0x0010
#define OPT_IPV6    0x0020
#define OPT_OPTION  0x0040
#define OPT_TLSCERT 0x0080
#define OPT_TLSPRIV 0x0100
#define OPT_ALL     0xffff

#define FLAG_SELECT     0x0002
#define FLAG_ALLOW_G    0x0004
#define FLAG_ALLOW_O    0x0008

#define CHANNEL_FLAG_EOF_TX 0x01
#define CHANNEL_FLAG_EOF_RX 0x02

#define CONTROL_MASTER_NEW   0 /* scamper --> remoted */
#define CONTROL_MASTER_ID    1 /* scamper <-- remoted */
#define CONTROL_CHANNEL_NEW  2 /* scamper <-- remoted */
#define CONTROL_CHANNEL_FIN  3 /* scamper <-> remoted */
#define CONTROL_KEEPALIVE    4 /* scamper <-> remoted */

static uint16_t     options        = 0;
static char        *unix_name      = NULL;
static int          port           = 0;
static dlist_t     *mslist         = NULL;
static dlist_t     *gclist         = NULL;
static int          stop           = 0;
static uint16_t     flags          = 0;
static int          serversockets[2];
static struct timeval now;

#if defined(HAVE_EPOLL)
static int          epfd           = -1;
#elif defined(HAVE_KQUEUE)
static int          kqfd           = -1;
#endif

#ifdef HAVE_OPENSSL
static SSL_CTX     *tls_ctx = NULL;
static char        *tls_certfile   = NULL;
static char        *tls_privfile   = NULL;
#define SSL_MODE_ACCEPT      0x00
#define SSL_MODE_ESTABLISHED 0x01
#define SSL_MODE_SHUTDOWN    0x02
#endif

/*
 * sc_unit_gc_t:
 *
 * method to cleanup tasks when its time to garbage collect
 */
typedef void (*sc_unit_gc_t)(void *);
static void sc_channel_free(sc_channel_t *);
static void sc_master_free(sc_master_t *);
static const sc_unit_gc_t unit_gc[] = {
  (sc_unit_gc_t)sc_master_free,      /* UNIT_TYPE_MASTER */
  (sc_unit_gc_t)sc_channel_free,     /* UNIT_TYPE_CHANNEL */
};

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
typedef void (*sc_fd_cb_t)(void *);
static void sc_channel_unix_read(sc_channel_t *);
static void sc_channel_unix_write(sc_channel_t *);
static void sc_master_inet_read(sc_master_t *);
static void sc_master_inet_write(sc_master_t *);
static void sc_master_unix_accept(sc_master_t *);

static const sc_fd_cb_t read_cb[] = {
  NULL,                              /* FD_TYPE_SERVER */
  (sc_fd_cb_t)sc_master_inet_read,   /* FD_TYPE_MASTER_INET */
  (sc_fd_cb_t)sc_master_unix_accept, /* FD_TYPE_MASTER_UNIX */
  (sc_fd_cb_t)sc_channel_unix_read,  /* FD_TYPE_CHANNEL_UNIX */
};
static const sc_fd_cb_t write_cb[] = {
  NULL,                              /* FD_TYPE_SERVER */
  (sc_fd_cb_t)sc_master_inet_write,  /* FD_TYPE_MASTER_INET */
  NULL,                              /* FD_TYPE_MASTER_UNIX */
  (sc_fd_cb_t)sc_channel_unix_write, /* FD_TYPE_CHANNEL_UNIX */
};
#endif

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
	  "usage: sc_remoted [-?46D] [-O option] [-P port] [-U unix]\n"
#ifdef HAVE_OPENSSL
	  "                  [-c certfile] [-p privfile]\n"
#endif
	  );

  if(opt_mask == 0)
    {
      fprintf(stderr, "\n     sc_remoted -?\n\n");
      return;
    }

  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D operate as a daemon\n");

  if(opt_mask & OPT_OPTION)
    {
      fprintf(stderr, "     -O options\n");
      fprintf(stderr, "        allowgroup: allow group access to sockets\n");
      fprintf(stderr, "        allowother: allow other access to sockets\n");
      fprintf(stderr, "        select: use select\n");
    }

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -P port to accept remote scamper connections\n");

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U directory for unix domain sockets\n");

#ifdef HAVE_OPENSSL
  if(opt_mask & OPT_TLSCERT)
    fprintf(stderr, "     -c server certificate in PEM format\n");
  if(opt_mask & OPT_TLSPRIV)
    fprintf(stderr, "     -p private key in PEM format\n");
#endif

  return;
}

static int check_options(int argc, char *argv[])
{
  char *opts = "?46DO:P:c:p:U:", *opt_port = NULL;
  long lo;
  int ch;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case '4':
	  options |= OPT_IPV4;
	  break;

	case '6':
	  options |= OPT_IPV6;
	  break;

	case 'D':
	  options |= OPT_DAEMON;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "select") == 0)
	    flags |= FLAG_SELECT;
	  else if(strcasecmp(optarg, "allowgroup") == 0)
	    flags |= FLAG_ALLOW_G;
	  else if(strcasecmp(optarg, "allowother") == 0)
	    flags |= FLAG_ALLOW_O;
	  else
	    {
	      usage(OPT_ALL);
	      return -1;
	    }
	  break;
	  
	case 'P':
	  opt_port = optarg;
	  break;

#ifdef HAVE_OPENSSL
	case 'c':
	  tls_certfile = optarg;
	  options |= OPT_TLSCERT;
	  break;

	case 'p':
	  tls_privfile = optarg;
	  options |= OPT_TLSPRIV;
	  break;
#endif

	case 'U':
	  unix_name = optarg;
	  break;

	case '?':
	default:
	  usage(OPT_ALL);
	  return -1;
	}
    }

  if((options & (OPT_IPV4|OPT_IPV6)) == 0)
    options |= (OPT_IPV4 | OPT_IPV6);

  if(unix_name == NULL || opt_port == NULL)
    {
      usage(OPT_PORT|OPT_UNIX);
      return -1;
    }

#ifdef HAVE_OPENSSL
  if((options & (OPT_TLSCERT|OPT_TLSPRIV)) != 0 &&
     (options & (OPT_TLSCERT|OPT_TLSPRIV)) != (OPT_TLSCERT|OPT_TLSPRIV))
    {
      usage(OPT_TLSCERT|OPT_TLSPRIV);
      return -1;
    }
#endif
  
  if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
    {
      usage(OPT_PORT);
      return -1;
    }
  port = lo;

  return 0;
}

static void remote_debug(const char *func, const char *format, ...)
{
  char message[512], ts[16];
  struct tm *tm;
  va_list ap;
  time_t t;
  int ms;

  if(options & OPT_DAEMON)
    return;

  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  va_end(ap);

  t = now.tv_sec;
  if((tm = localtime(&t)) == NULL)
    return;
  ms = now.tv_usec / 1000;
  snprintf(ts, sizeof(ts), "[%02d:%02d:%02d:%03d]",
	   tm->tm_hour, tm->tm_min, tm->tm_sec, ms);

  fprintf(stderr, "%s %s: %s\n", ts, func, message);
  fflush(stderr);
  return;
}

static int sc_fd_read_add(sc_fd_t *fd)
{
#if defined(HAVE_EPOLL)
  struct epoll_event ev;
#elif defined(HAVE_KQUEUE)
  struct kevent kev;
#endif

  if((fd->flags & FD_FLAG_READ) != 0)
    return 0;
  fd->flags |= FD_FLAG_READ;
  if((flags & FLAG_SELECT) != 0)
    return 0;

#if defined(HAVE_EPOLL)
  ev.data.ptr = fd;
  if((fd->flags & FD_FLAG_WRITE) == 0)
    {
      ev.events = EPOLLIN;
      if(epoll_ctl(epfd, EPOLL_CTL_ADD, fd->fd, &ev) != 0)
	return -1;
    }
  else
    {
      ev.events = EPOLLIN | EPOLLOUT;
      if(epoll_ctl(epfd, EPOLL_CTL_MOD, fd->fd, &ev) != 0)
	return -1;
    }
#elif defined(HAVE_KQUEUE)
  EV_SET(&kev, fd->fd, EVFILT_READ, EV_ADD, 0, 0, fd);
  if(kevent(kqfd, &kev, 1, NULL, 0, NULL) != 0)
    return -1;
#endif
  return 0;
}

static int sc_fd_read_del(sc_fd_t *fd)
{
#if defined(HAVE_EPOLL)
  struct epoll_event ev;
#elif defined(HAVE_KQUEUE)
  struct kevent kev;
#endif

  if((fd->flags & FD_FLAG_READ) == 0)
    return 0;
  fd->flags &= ~(FD_FLAG_READ);
  if((flags & FLAG_SELECT) != 0)
    return 0;

#if defined(HAVE_EPOLL)
  ev.data.ptr = fd;
  if((fd->flags & FD_FLAG_WRITE) == 0)
    {
      ev.events = 0;
      if(epoll_ctl(epfd, EPOLL_CTL_DEL, fd->fd, &ev) != 0)
	return -1;
    }
  else
    {
      ev.events = EPOLLOUT;
      if(epoll_ctl(epfd, EPOLL_CTL_MOD, fd->fd, &ev) != 0)
	return -1;
    }
#elif defined(HAVE_KQUEUE)
  EV_SET(&kev, fd->fd, EVFILT_READ, EV_DELETE, 0, 0, fd);
  if(kevent(kqfd, &kev, 1, NULL, 0, NULL) != 0)
    return -1;
#endif
  return 0;
}

static int sc_fd_write_add(sc_fd_t *fd)
{
#if defined(HAVE_EPOLL)
  struct epoll_event ev;
#elif defined(HAVE_KQUEUE)
  struct kevent kev;
#endif

  if((fd->flags & FD_FLAG_WRITE) != 0)
    return 0;
  fd->flags |= FD_FLAG_WRITE;
  if((flags & FLAG_SELECT) != 0)
    return 0;

#if defined(HAVE_EPOLL)
  ev.data.ptr = fd;
  if((fd->flags & FD_FLAG_READ) == 0)
    {
      ev.events = EPOLLOUT;
      if(epoll_ctl(epfd, EPOLL_CTL_ADD, fd->fd, &ev) != 0)
	return -1;
    }
  else
    {
      ev.events = EPOLLIN | EPOLLOUT;
      if(epoll_ctl(epfd, EPOLL_CTL_MOD, fd->fd, &ev) != 0)
	return -1;
    }
#elif defined(HAVE_KQUEUE)
  EV_SET(&kev, fd->fd, EVFILT_WRITE, EV_ADD, 0, 0, fd);
  if(kevent(kqfd, &kev, 1, NULL, 0, NULL) != 0)
    return -1;
#endif
  return 0;
}

static int sc_fd_write_del(sc_fd_t *fd)
{
#if defined(HAVE_EPOLL)
  struct epoll_event ev;
#elif defined(HAVE_KQUEUE)
  struct kevent kev;
#endif

  if((fd->flags & FD_FLAG_WRITE) == 0)
    return 0;
  fd->flags &= ~(FD_FLAG_WRITE);
  if((flags & FLAG_SELECT) != 0)
    return 0;

#if defined(HAVE_EPOLL)
  ev.data.ptr = fd;
  if((fd->flags & FD_FLAG_READ) == 0)
    {
      ev.events = 0;
      if(epoll_ctl(epfd, EPOLL_CTL_DEL, fd->fd, &ev) != 0)
	return -1;
    }
  else
    {
      ev.events = EPOLLIN;
      if(epoll_ctl(epfd, EPOLL_CTL_MOD, fd->fd, &ev) != 0)
	return -1;
    }
#elif defined(HAVE_KQUEUE)
  EV_SET(&kev, fd->fd, EVFILT_WRITE, EV_DELETE, 0, 0, fd);
  if(kevent(kqfd, &kev, 1, NULL, 0, NULL) != 0)
    return -1;
#endif
  return 0;
}

#ifdef HAVE_OPENSSL
static int ssl_want_read(sc_master_t *ms)
{
  uint8_t buf[1024];
  int pending, rc, size, off = 0;

  if((pending = BIO_pending(ms->inet_wbio)) < 0)
    return -1;

  while(off < pending)
    {
      if(pending - off > sizeof(buf))
	size = sizeof(buf);
      else
	size = pending - off;

      if((rc = BIO_read(ms->inet_wbio, buf, size)) <= 0)
	{
	  if(BIO_should_retry(ms->inet_wbio) == 0)
	    remote_debug(__func__, "BIO_read should not retry");
	  else
	    remote_debug(__func__, "BIO_read returned %d", rc);
	  return -1;
	}
      off += rc;

      scamper_writebuf_send(ms->inet_wb, buf, rc);
      sc_fd_write_add(&ms->inet_fd);
    }

  return pending;
}
#endif

static void sc_fd_free(sc_fd_t *sfd)
{
  if(sfd == NULL)
    return;
  if(sfd->fd != -1)
    close(sfd->fd);
  free(sfd);
  return;
}

static sc_fd_t *sc_fd_alloc(int fd, uint8_t type, sc_unit_t *unit)
{
  sc_fd_t *sfd;
  if((sfd = malloc_zero(sizeof(sc_fd_t))) == NULL)
    return NULL;
  sfd->fd = fd;
  sfd->type = type;
  sfd->unit = unit;
  return sfd;
}

static void sc_unit_onremove(sc_unit_t *scu)
{
  scu->node = NULL;
  scu->list = NULL;
  return;
}

static void sc_unit_gc(sc_unit_t *scu)
{
  if(scu->gc != 0)
    return;
  scu->gc = 1;
  dlist_node_tail_push(gclist, scu->node);
  scu->list = gclist;
  return;
}

static void sc_unit_free(sc_unit_t *scu)
{
  if(scu == NULL)
    return;
  if(scu->node != NULL)
    dlist_node_pop(scu->list, scu->node);
  free(scu);
  return;
}

static sc_unit_t *sc_unit_alloc(uint8_t type, void *data)
{
  sc_unit_t *scu;
  if((scu = malloc_zero(sizeof(sc_unit_t))) == NULL ||
     (scu->node = dlist_node_alloc(scu)) == NULL)
    {
      if(scu != NULL) sc_unit_free(scu);
      return NULL;
    }
  scu->type = type;
  scu->data = data;
  return scu;
}

static void sc_master_onremove(sc_master_t *ms)
{
  ms->node = NULL;
  return;
}

static sc_channel_t *sc_master_channel_find(sc_master_t *ms, uint32_t id)
{
  dlist_node_t *dn;
  sc_channel_t *cn;
  for(dn=dlist_head_node(ms->channels); dn != NULL; dn=dlist_node_next(dn))
    {
      cn = dlist_node_item(dn);
      if(cn->id == id)
	return cn;
    }
  return NULL;
}

static void sc_master_channels_onremove(sc_channel_t *cn)
{
  cn->node = NULL;
  return;
}

/*
 * sc_master_inet_send
 *
 * transparently handle sending when an SSL socket could be used.
 */
static int sc_master_inet_send(sc_master_t *ms, void *ptr, size_t len)
{
  timeval_add_s(&ms->tx_ka, &now, 30);

#ifdef HAVE_OPENSSL
  if(ms->inet_ssl != NULL)
    {
      SSL_write(ms->inet_ssl, ptr, len);
      if(ssl_want_read(ms) < 0)
	return -1;
      return 0;
    }
#endif

  scamper_writebuf_send(ms->inet_wb, ptr, len);
  sc_fd_write_add(&ms->inet_fd);
  return 0;
}

static void sc_master_inet_write(sc_master_t *ms)
{
  if(scamper_writebuf_write(ms->inet_fd.fd, ms->inet_wb) != 0)
    {
      sc_unit_gc(ms->unit);
      return;
    }

  if(scamper_writebuf_len(ms->inet_wb) == 0 &&
     sc_fd_write_del(&ms->inet_fd) != 0)
    {
      sc_unit_gc(ms->unit);
      return;
    }
  return;
}

static int sc_master_tx_keepalive(sc_master_t *ms)
{
  uint8_t buf[4+2+1];
  bytes_htonl(buf+0, 0);
  bytes_htons(buf+4, 1);
  buf[6] = CONTROL_KEEPALIVE;
  remote_debug(__func__, "%s", ms->name);
  return sc_master_inet_send(ms, buf, sizeof(buf));
}

/*
 * sc_master_control_master
 *
 * a remote scamper connection has said hello.
 * create a unix file descriptor to listen locally for drivers that want to
 * use it.
 *
 */
static int sc_master_control_master(sc_master_t *ms, uint8_t *buf, size_t len)
{
  char sab[128], filename[65535], tmp[512];
  uint8_t resp[4+2+1+1+128];
  struct sockaddr_storage sas;
  struct sockaddr_un sn;
  socklen_t sl;
  uint8_t *magic = NULL;
  char    *monitorname = NULL;
  uint8_t  magic_len = 0, monitorname_len = 0, u8;
  size_t   off = 0;
  mode_t   mode;
  int      fd;

  /*
   * these are set so that we know whether or not to take
   * responsibility for cleaning them up upon a failure condition.
   */
  fd = -1;
  filename[0] = '\0';

  /* ensure that there is a magic value present */
  if(len == 0 || (magic_len = buf[off++]) == 0)
    goto err;
  magic = buf + off;

  /* ensure the magic length value makes sense */
  if(off + magic_len > len)
    goto err;
  off += magic_len;

  /* check if there is a monitorname supplied */
  if(off < len && (monitorname_len = buf[off++]) > 0)
    {
      if(off + monitorname_len > len)
	goto err;
      monitorname = (char *)(buf+off);
      for(u8=0; u8<monitorname_len-1; u8++)
	{
	  if(isalnum(monitorname[u8]) == 0 &&
	     monitorname[u8] != '.' && monitorname[u8] != '-')
	    goto err;
	}
      if(monitorname[monitorname_len-1] != '\0')
	goto err;
      off += monitorname_len;
    }

  sl = sizeof(sas);
  if(getpeername(ms->inet_fd.fd, (struct sockaddr *)&sas, &sl) != 0)
    {
      remote_debug(__func__, "could not getpeername: %s", strerror(errno));
      goto err;
    }

  /* figure out the name for the unix domain socket */
  sockaddr_tostr((struct sockaddr *)&sas, sab, sizeof(sab));
  if(monitorname != NULL)
    {
      off = 0;
      string_concat(tmp, sizeof(tmp), &off, "%s-%s", monitorname, sab);
      ms->name = strdup(tmp);
    }
  else
    {
      ms->name = strdup(sab);
    }
  if(ms->name == NULL)
    {
      remote_debug(__func__, "could not strdup ms->name: %s", strerror(errno));
      goto err;
    }

  if((ms->magic = memdup(magic, magic_len)) == NULL)
    {
      remote_debug(__func__, "could not memdup magic: %s", strerror(errno));
      goto err;
    }
  ms->magic_len = magic_len;

  /* create a unix domain socket for the remote scamper process */
  if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
      remote_debug(__func__, "could not create unix socket: %s",
		   strerror(errno));
      goto err;
    }
  snprintf(filename, sizeof(filename), "%s/%s", unix_name, ms->name);
  if(sockaddr_compose_un((struct sockaddr *)&sn, filename) != 0)
    {
      filename[0] = '\0'; /* could not actually bind so no unlink */
      remote_debug(__func__, "could not compose socket: %s", strerror(errno));
      goto err;
    }
  if(bind(fd, (struct sockaddr *)&sn, sizeof(sn)) != 0)
    {
      filename[0] = '\0'; /* could not actually bind so no unlink */
      remote_debug(__func__, "could not bind unix socket: %s",strerror(errno));
      goto err;
    }

  /* set the requested permissions on the control sockets */
  mode = S_IRWXU;
  if(flags & FLAG_ALLOW_G) mode |= S_IRWXG;
  if(flags & FLAG_ALLOW_O) mode |= S_IRWXO;
  if(chmod(filename, mode) != 0)
    {
      remote_debug(__func__, "could not chmod: %s", strerror(errno));
      goto err;
    }

  if(listen(fd, -1) != 0)
    {
      remote_debug(__func__, "could not listen: %s",strerror(errno));
      goto err;
    }

  /*
   * at this point, allocate the unix_fd structure and take
   * responsibility for the socket and filesystem point
   */
  if((ms->unix_fd = sc_fd_alloc(fd, FD_TYPE_MASTER_UNIX, ms->unit)) == NULL)
    {
      remote_debug(__func__, "could not alloc unix fd: %s", strerror(errno));
      goto err;
    }
  filename[0] = '\0'; fd = -1;

  if(sc_fd_read_add(ms->unix_fd) != 0)
    {
      remote_debug(__func__, "could not monitor unix fd: %s", strerror(errno));
      goto err;
    }

  off = strlen(sab);
  bytes_htonl(resp+0, 0);
  bytes_htons(resp+4, 1 + 1 + off + 1);
  resp[6] = CONTROL_MASTER_ID;
  resp[7] = off + 1;
  memcpy(resp+8, sab, off + 1);
  if(sc_master_inet_send(ms, resp, 4 + 2 + 1 + 1 + off + 1) != 0)
    {
      remote_debug(__func__, "could not write ID: %s\n", strerror(errno));
      goto err;
    }

  return 0;

 err:
  if(fd != -1) close(fd);
  if(filename[0] != '\0') unlink(filename);
  return -1;
}

/*
 * sc_master_control_channel_fin
 *
 *
 */
static int sc_master_control_channel_fin(sc_master_t *ms,
					 uint8_t *buf, size_t len)
{
  sc_channel_t *cn;
  uint32_t id;

  if(len != 4)
    {
      remote_debug(__func__, "malformed channel fin: %u\n",(uint32_t)len);
      return -1;
    }

  id = bytes_ntohl(buf);
  if((cn = sc_master_channel_find(ms, id)) == NULL)
    {
      remote_debug(__func__, "could not find channel %u\n", id);
      return -1;
    }
  cn->flags |= CHANNEL_FLAG_EOF_RX;

  if(cn->unix_wb == NULL || scamper_writebuf_gtzero(cn->unix_wb) == 0)
    sc_unit_gc(cn->unit);
  else
    sc_fd_read_del(cn->unix_fd);

  return 0;
}

static int sc_master_control_keepalive(sc_master_t *ms,uint8_t *buf,size_t len)
{
  if(len != 0)
    {
      remote_debug(__func__, "malformed keepalive: %u", (uint32_t)len);
      return -1;
    }
  remote_debug(__func__, "%s", ms->name);
  return 0;
}

static int sc_master_control(sc_master_t *ms, uint8_t *buf, size_t len)
{
  uint8_t type;

  if(len < 1)
    {
      remote_debug(__func__, "malformed control msg: %u", (uint32_t)len);
      return -1;
    }
  type = buf[0];
  buf++; len--;

  switch(type)
    {
    case CONTROL_MASTER_NEW:
      return sc_master_control_master(ms, buf, len);
    case CONTROL_CHANNEL_FIN:
      return sc_master_control_channel_fin(ms, buf, len);
    case CONTROL_KEEPALIVE:
      return sc_master_control_keepalive(ms, buf, len);
    }

  remote_debug(__func__, "unhandled type %d", type);
  return -1;
}

/*
 * sc_master_inet_read_cb
 *
 * process data from the master inet-facing socket.  the data has been
 * through the SSL decoding routines, if necessary.
 *
 * todo: make this zero copy when the entire message is intact in the buf.
 */
static void sc_master_inet_read_cb(sc_master_t *ms, uint8_t *buf, size_t len)
{
  sc_channel_t *channel;
  uint32_t id;
  uint16_t msglen, x, y;
  size_t off = 0;

  while(off < len)
    {
      /* to start with, ensure that we have a complete header */
      while(ms->buf_offset < 6 && off < len)
	ms->buf[ms->buf_offset++] = buf[off++];
      if(off == len)
	return;

      /* figure out how large the message is supposed to be */
      id = bytes_ntohl(ms->buf);
      msglen = bytes_ntohs(ms->buf+4);

      /* figure out how to build the message */
      x = msglen - (ms->buf_offset - 6);
      y = len - off;

      if(y < x)
	{
	  /* if we cannot complete the message, buffer what we have */
	  memcpy(ms->buf + ms->buf_offset, buf+off, y);
	  ms->buf_offset += y;
	  return;
	}

      /* we now have a complete message */
      memcpy(ms->buf + ms->buf_offset, buf+off, x);
      off += x;

      /* reset the buf_offset for the next message */
      ms->buf_offset = 0;

      /* if the message is a control message */
      if(id == 0)
	{
	  if(sc_master_control(ms, ms->buf + 6, msglen) != 0)
	    goto err;
	  continue;
	}

      if((channel = sc_master_channel_find(ms, id)) == NULL)
	{
	  remote_debug(__func__, "could not find channel %u", id);
	  goto err;
	}

      /* the unix domain socket might have gone away but we need to flush */
      if(channel->unix_wb != NULL)
	{
	  if(scamper_writebuf_send(channel->unix_wb, ms->buf + 6, msglen) != 0)
	    sc_unit_gc(channel->unit);	
	  sc_fd_write_add(channel->unix_fd);
	}
    }

  return;
  
 err:
  sc_unit_gc(ms->unit);
  return;
}

/*
 * sc_master_inet_read
 *
 */
static void sc_master_inet_read(sc_master_t *ms)
{
  ssize_t rrc;
  uint8_t buf[4096];

#ifdef HAVE_OPENSSL
  int rc;
#endif

  if((rrc = read(ms->inet_fd.fd, buf, sizeof(buf))) < 0)
    {
      if(errno == EAGAIN || errno == EINTR)
	return;
      remote_debug(__func__, "read failed: %s", strerror(errno));
      goto err;
    }

  if(rrc == 0)
    {
      remote_debug(__func__, "%s disconnected", ms->name);
      goto err;
    }

  timeval_add_s(&ms->rx_abort, &now, 60);

#ifdef HAVE_OPENSSL
  if(ms->inet_ssl != NULL)
    {
      BIO_write(ms->inet_rbio, buf, rrc);
      if(ms->inet_mode == SSL_MODE_ACCEPT)
	{
	  if((rc = SSL_accept(ms->inet_ssl)) == 0)
	    {
	      remote_debug(__func__, "SSL_accept returned zero: %d",
			   SSL_get_error(ms->inet_ssl, rc));
	      ERR_print_errors_fp(stderr);
	      goto err;
	    }
	  else if(rc == 1)
	    {
	      ms->inet_mode = SSL_MODE_ESTABLISHED;
	      if(ssl_want_read(ms) < 0)
		goto err;
	    }
	  else if(rc < 0)
	    {
	      rc = SSL_get_error(ms->inet_ssl, rc);
	      remote_debug(__func__, "SSL_accept %d", rc);
	      if(rc == SSL_ERROR_WANT_READ)
		{
		  if(ssl_want_read(ms) < 0)
		    goto err;
		}
	      else if(rc != SSL_ERROR_WANT_WRITE)
		{
		  remote_debug(__func__, "mode accept rc %d", rc);
		  goto err;
		}
	    }
	}
      else if(ms->inet_mode == SSL_MODE_ESTABLISHED)
	{
	  while((rc = SSL_read(ms->inet_ssl, buf, sizeof(buf))) > 0)
	    sc_master_inet_read_cb(ms, buf, (size_t)rc);
	  if(rc < 0)
	    {
	      if((rc = SSL_get_error(ms->inet_ssl, rc)) == SSL_ERROR_WANT_READ)
		{
		  if(ssl_want_read(ms) < 0)
		    goto err;
		}
	      else if(rc != SSL_ERROR_WANT_WRITE)
		{
		  remote_debug(__func__, "mode estab rc %d", rc);
		  goto err;
		}
	    }
	}
      return;
    }
#endif

  sc_master_inet_read_cb(ms, buf, (size_t)rrc);
  return;

 err:
  sc_unit_gc(ms->unit);
  return;
}

/*
 * sc_master_unix_accept
 *
 * a local process has connected to the unix domain socket that
 * corresponds to a remote scamper process.  accept the socket and
 * cause the remote scamper process to create a new channel.
 */
static void sc_master_unix_accept(sc_master_t *ms)
{
  struct sockaddr_storage ss;
  socklen_t socklen = sizeof(ss);
  sc_channel_t *cn = NULL;
  uint8_t msg[4+2+1+4];
  int s = -1;

  if((s = accept(ms->unix_fd->fd, (struct sockaddr *)&ss, &socklen)) == -1)
    {
      remote_debug(__func__, "accept failed: %s", strerror(errno));
      goto err;
    }

  if((cn = malloc_zero(sizeof(sc_channel_t))) == NULL)
    goto err;
  cn->id = ms->next_channel++;
  if(ms->next_channel == 0)
    ms->next_channel++;

  /* allocate a unit to describe this structure */
  if((cn->unit = sc_unit_alloc(UNIT_TYPE_CHANNEL, cn)) == NULL)
    {
      remote_debug(__func__, "could not alloc unit: %s", strerror(errno));
      goto err;
    }

  if((cn->unix_fd = sc_fd_alloc(s, FD_TYPE_CHANNEL_UNIX, cn->unit)) == NULL)
    {
      remote_debug(__func__, "could not alloc unix_fd: %s", strerror(errno));
      goto err;
    }
  s = -1;
  sc_fd_read_add(cn->unix_fd);

  if((cn->unix_wb = scamper_writebuf_alloc()) == NULL)
    goto err;
  if((cn->node = dlist_tail_push(ms->channels, cn)) == NULL)
    goto err;
  cn->master = ms;

  bytes_htonl(msg+0, 0);
  bytes_htons(msg+4, 1 + 4);
  msg[6] = CONTROL_CHANNEL_NEW;
  bytes_htonl(msg+7, cn->id);
  if(sc_master_inet_send(ms, msg, 11) != 0)
    {
      goto err;
    }

  return;

 err:
  if(s != -1) close(s);
  if(cn != NULL) sc_channel_free(cn);
  return;
}

/*
 * sc_master_free
 *
 * clean up the sc_master_t.
 */
static void sc_master_free(sc_master_t *ms)
{
  char filename[65535];

  if(ms == NULL)
    return;

  /*
   * if unix_fd is not null, it is our responsibility to both close
   * the fd, and to unlink the socket from the file system
   */
  if(ms->unix_fd != NULL)
    {
      sc_fd_free(ms->unix_fd);
      snprintf(filename, sizeof(filename), "%s/%s", unix_name, ms->name);
      unlink(filename);
    }

  if(ms->channels != NULL)
    dlist_free_cb(ms->channels, (dlist_free_t)sc_channel_free);

  if(ms->unit != NULL) sc_unit_free(ms->unit);

  if(ms->inet_fd.fd != -1) close(ms->inet_fd.fd);
  if(ms->inet_wb != NULL) scamper_writebuf_free(ms->inet_wb);

#ifdef HAVE_OPENSSL
  if(ms->inet_ssl != NULL)
    {
      SSL_free(ms->inet_ssl);
    }
  else
    {
      if(ms->inet_wbio != NULL)
	BIO_free(ms->inet_wbio);
      if(ms->inet_rbio != NULL)
	BIO_free(ms->inet_rbio);
    }
#endif

  if(ms->name != NULL) free(ms->name);
  if(ms->magic != NULL) free(ms->magic);
  if(ms->node != NULL) dlist_node_pop(mslist, ms->node);
  free(ms);
  return;
}

static sc_master_t *sc_master_alloc(int fd)
{
  sc_master_t *ms = NULL;
  
#ifdef HAVE_OPENSSL
  int rc;
#endif

  if((ms = malloc_zero(sizeof(sc_master_t))) == NULL)
    return NULL;
  ms->inet_fd.fd = fd; fd = -1;
  ms->inet_fd.type = FD_TYPE_MASTER_INET;

  if((ms->channels = dlist_alloc()) == NULL)
    {
      remote_debug(__func__, "could not alloc channels: %s", strerror(errno));
      goto err;
    }
  dlist_onremove(ms->channels, (dlist_onremove_t)sc_master_channels_onremove);
  ms->next_channel = 1;

  /* allocate a unit to describe this */
  if((ms->unit = sc_unit_alloc(UNIT_TYPE_MASTER, ms)) == NULL)
    {
      remote_debug(__func__, "could not alloc unit: %s", strerror(errno));
      goto err;
    }
  ms->inet_fd.unit = ms->unit;

  if((ms->inet_wb = scamper_writebuf_alloc()) == NULL)
    {
      remote_debug(__func__, "could not alloc wb: %s", strerror(errno));
      goto err;
    }

#ifdef HAVE_OPENSSL
  if(tls_certfile != NULL)
    {
      if((ms->inet_wbio = BIO_new(BIO_s_mem())) == NULL ||
	 (ms->inet_rbio = BIO_new(BIO_s_mem())) == NULL ||
	 (ms->inet_ssl = SSL_new(tls_ctx)) == NULL)
	{
	  remote_debug(__func__, "could not alloc SSL");
	  goto err;
	}
      SSL_set_bio(ms->inet_ssl, ms->inet_rbio, ms->inet_wbio);
      SSL_set_accept_state(ms->inet_ssl);
      rc = SSL_accept(ms->inet_ssl);
      assert(rc == -1);
      if((rc = SSL_get_error(ms->inet_ssl, rc)) != SSL_ERROR_WANT_READ)
	{
	  remote_debug(__func__, "unexpected %d from SSL_accept", rc);
	  goto err;
	}
      if(ssl_want_read(ms) < 0)
	goto err;
    }
#endif

  return ms;

 err:
  if(ms != NULL) sc_master_free(ms);
  if(fd != -1) close(fd);
  return NULL;
}

/*
 * sc_channel_unix_write
 *
 * we can write to the unix fd without blocking, so do so.
 */
static void sc_channel_unix_write(sc_channel_t *cn)
{
  int gtzero;

  /* if we did a read which returned -1, then the unix_fd will be null */
  if(cn->unix_fd == NULL)
    return;

  if(scamper_writebuf_write(cn->unix_fd->fd, cn->unix_wb) != 0)
    {
      remote_debug(__func__, "write to %s channel %u failed",
		   cn->master->name, cn->id);
      goto err;
    }

  /*
   * if we still have data to write, then wait until we get signal to
   * write again
   */
  if((gtzero = scamper_writebuf_gtzero(cn->unix_wb)) != 0)
    return;

  /* nothing more to write, so remove fd */
  if(sc_fd_write_del(cn->unix_fd) != 0)
    {
      remote_debug(__func__, "could not delete unix write for %s channel %u",
		   cn->master->name, cn->id);
      goto err;
    }

  /* got an EOF, so we're done now */
  if((cn->flags & CHANNEL_FLAG_EOF_RX) != 0)
    {
      remote_debug(__func__, "received EOF for %s channel %u",
		   cn->master->name, cn->id);
      sc_unit_gc(cn->unit);
      return;
    }

  return;

 err:
  /* got an error trying to write, so we're done */
  sc_fd_free(cn->unix_fd); cn->unix_fd = NULL;
  scamper_writebuf_free(cn->unix_wb); cn->unix_wb = NULL;

  /* we've received an EOF, we're done */
  if((cn->flags & CHANNEL_FLAG_EOF_RX) != 0)
    {
      sc_unit_gc(cn->unit);
      return;
    }
  return;
}

/*
 * sc_channel_unix_read
 *
 * a local client process has written to a unix domain socket, which
 * we will process line by line.
 */
static void sc_channel_unix_read(sc_channel_t *cn)
{
  ssize_t rc;
  uint8_t buf[4096];
  uint8_t hdr[4+2];

  if((rc = read(cn->unix_fd->fd, buf, sizeof(buf))) <= 0)
    {
      if(rc == -1 && (errno == EAGAIN || errno == EINTR))
	return;

      /* send an EOF if we haven't tx'd or rx'd an EOF */
      if((cn->flags & (CHANNEL_FLAG_EOF_RX|CHANNEL_FLAG_EOF_TX)) == 0)
	{
	  bytes_htonl(buf+0, 0);
	  bytes_htons(buf+4, 5);
	  buf[6] = CONTROL_CHANNEL_FIN;
	  bytes_htonl(buf+7, cn->id);
	  sc_master_inet_send(cn->master, buf, 11);
	  cn->flags |= CHANNEL_FLAG_EOF_TX;
	}

      /* if we've received an EOF, we're done */
      if((cn->flags & CHANNEL_FLAG_EOF_RX) != 0)
	{
	  sc_unit_gc(cn->unit);
	  return;
	}

      /*
       * if we've received an error, close down the file descriptor
       * and write buf.  we keep the channel around so that when we
       * receive an EOF, we can match it and clean it up.
       */
      if(rc == -1)
	{
	  sc_fd_free(cn->unix_fd); cn->unix_fd = NULL;
	  scamper_writebuf_free(cn->unix_wb); cn->unix_wb = NULL;
	}
      else
	{
	  sc_fd_read_del(cn->unix_fd);
	}
      return;
    }

  bytes_htonl(hdr+0, cn->id);
  bytes_htons(hdr+4, rc);

  sc_master_inet_send(cn->master, hdr, 6);
  sc_master_inet_send(cn->master, buf, rc);

  return;
}

static void sc_channel_free(sc_channel_t *cn)
{
  if(cn == NULL)
    return;
  if(cn->master != NULL && cn->node != NULL)
    dlist_node_pop(cn->master->channels, cn->node);
  if(cn->unix_fd != NULL) sc_fd_free(cn->unix_fd);
  if(cn->unix_lp != NULL) scamper_linepoll_free(cn->unix_lp, 0);
  if(cn->unix_wb != NULL) scamper_writebuf_free(cn->unix_wb);
  if(cn->unit != NULL) sc_unit_free(cn->unit);
  free(cn);
  return;
}

/*
 * serversocket_accept
 *
 * a new connection has arrived.  accept the new connection while we wait
 * to understand the intention behind the socket.
 */
static int serversocket_accept(int ss)
{
  struct sockaddr_storage sas;
  sc_master_t *ms = NULL;
  socklen_t slen;
  int inet_fd = -1;

  slen = sizeof(ss);
  if((inet_fd = accept(ss, (struct sockaddr *)&sas, &slen)) == -1)
    {
      remote_debug(__func__, "could not accept: %s", strerror(errno));
      goto err;
    }
  if(fcntl_set(inet_fd, O_NONBLOCK) == -1)
    {
      remote_debug(__func__, "could not set O_NONBLOCK: %s", strerror(errno));
      goto err;
    }

  ms = sc_master_alloc(inet_fd);
  inet_fd = -1;
  if(ms == NULL)
    goto err;

  if(sc_fd_read_add(&ms->inet_fd) != 0)
    {
      remote_debug(__func__, "could not monitor inet fd: %s", strerror(errno));
      goto err;
    }

  timeval_add_s(&ms->rx_abort, &now, 30);
  timeval_cpy(&ms->tx_ka, &ms->rx_abort);

  if((ms->node = dlist_tail_push(mslist, ms)) == NULL)
    {
      remote_debug(__func__, "could not push to mslist: %s", strerror(errno));
      goto err;
    }

  return 0;

 err:
  if(inet_fd != -1) close(inet_fd);
  if(ms != NULL) sc_master_free(ms);
  return -1;
}

/*
 * serversocket_init
 *
 * create two sockets so that we can use both IPv4 and IPv6 for incoming
 * connections from remote scamper processes.
 */
static int serversocket_init(void)
{
  struct sockaddr_storage sas;
  int i, pf, opt;
  for(i=0; i<2; i++)
    {
      pf = i == 0 ? PF_INET : PF_INET6;
      if((pf == PF_INET  && (options & OPT_IPV4) == 0) ||
	 (pf == PF_INET6 && (options & OPT_IPV6) == 0))
	continue;

      if((serversockets[i] = socket(pf, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
	  remote_debug(__func__, "could not open %s socket: %s",
		       i == 0 ? "ipv4" : "ipv6", strerror(errno));
	  return -1;
	}

      opt = 1;
      if(setsockopt(serversockets[i], SOL_SOCKET, SO_REUSEADDR,
		    (char *)&opt, sizeof(opt)) != 0)
	{
	  remote_debug(__func__, "could not set SO_REUSEADDR on %s socket: %s",
		       i == 0 ? "ipv4" : "ipv6", strerror(errno));
	  return -1;
	}

#ifdef IPV6_V6ONLY
      if(pf == PF_INET6)
	{
	  opt = 1;
	  if(setsockopt(serversockets[i], IPPROTO_IPV6, IPV6_V6ONLY,
			(char *)&opt, sizeof(opt)) != 0)
	    {
	      remote_debug(__func__, "could not set IPV6_V6ONLY: %s",
			   strerror(errno));
	      return -1;
	    }
	}
#endif

      sockaddr_compose((struct sockaddr *)&sas, pf, NULL, port);
      if(bind(serversockets[i], (struct sockaddr *)&sas,
	      sockaddr_len((struct sockaddr *)&sas)) != 0)
	{
	  remote_debug(__func__, "could not bind %s socket to port %d: %s",
		       i == 0 ? "ipv4" : "ipv6", port, strerror(errno));
	  return -1;
	}
      if(listen(serversockets[i], -1) != 0)
	{
	  remote_debug(__func__, "could not listen %s socket: %s",
		       i == 0 ? "ipv4" : "ipv6", strerror(errno));
	  return -1;
	}
    }
  return 0;
}

/*
 * unixdomain_direxists
 *
 * make sure the directory specified actually exists
 */
static int unixdomain_direxists(void)
{
  struct stat sb;
  if(stat(unix_name, &sb) != 0)
    {
      usage(OPT_UNIX);
      remote_debug(__func__,"could not stat %s: %s",unix_name,strerror(errno));
      return -1;
    }
  if((sb.st_mode & S_IFDIR) != 0)
    return 0;
  usage(OPT_UNIX);
  remote_debug(__func__, "%s is not a directory", unix_name);
  return -1;
}

static void cleanup(void)
{
  int i;

  for(i=0; i<2; i++)
    close(serversockets[i]);

  if(mslist != NULL)
    dlist_free_cb(mslist, (dlist_free_t)sc_master_free);

#ifdef HAVE_OPENSSL
  if(tls_ctx != NULL) SSL_CTX_free(tls_ctx);
#endif

  if(gclist != NULL) dlist_free(gclist);

#ifdef HAVE_EPOLL
  if(epfd != -1) close(epfd);
#endif

#ifdef HAVE_KQUEUE
  if(kqfd != -1) close(kqfd);
#endif

  return;
}

static void remoted_sig(int sig)
{
  if(sig == SIGHUP || sig == SIGINT)
    stop = 1;
  return;
}

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
#if defined(HAVE_EPOLL)
static int epoll_loop(void)
#else
static int kqueue_loop(void)
#endif
{
#if defined(HAVE_EPOLL)
  struct epoll_event events[1024];
  int events_c = sizeof(events) / sizeof(struct epoll_event);
  int timeout;
#else
  struct kevent events[1024];
  int events_c = sizeof(events) / sizeof(struct kevent);
  struct timespec ts, *timeout;
#endif
  struct timeval tv, to;
  sc_master_t *ms;
  dlist_node_t *dn;
  sc_fd_t *scfd, scfd_ss[2];
  sc_unit_t *scu;
  int i, rc;

#if defined(HAVE_EPOLL)
  if((epfd = epoll_create(1000)) == -1)
    {
      remote_debug(__func__, "epoll_create failed: %s", strerror(errno));
      return -1;
    }
#else
  if((kqfd = kqueue()) == -1)
    {
      remote_debug(__func__, "kqueue failed: %s", strerror(errno));
      return -1;
    }
#endif

  /* add the server sockets to the poll set */
  memset(&scfd_ss, 0, sizeof(scfd_ss));
  for(i=0; i<2; i++)
    {
      if(serversockets[i] == -1)
	continue;
      scfd_ss[i].type = FD_TYPE_SERVER;
      scfd_ss[i].fd = serversockets[i];
      if(sc_fd_read_add(&scfd_ss[i]) != 0)
	return -1;
    }

  /* main event loop */
  while(stop == 0)
    {
#if defined(HAVE_EPOLL)
      timeout = -1;
#else
      timeout = NULL;
#endif
      rc = 0;
      if((dn = dlist_head_node(mslist)) != NULL)
	{
	  gettimeofday_wrap(&now);

	  /* to start with, handle keepalives */
	  while(dn != NULL)
	    {
	      ms = dlist_node_item(dn);
	      dn = dlist_node_next(dn);

	      /* if the connection has gone silent, abort */
	      if(timeval_cmp(&now, &ms->rx_abort) >= 0)
		{
		  sc_master_free(ms);
		  continue;
		}

	      /*
	       * ensure we send something every 30 seconds.
	       * unix_fd being not null signifies the remote controller
	       * has received an opening "master" frame.
	       */
	      if(ms->unix_fd != NULL && timeval_cmp(&now, &ms->tx_ka) >= 0)
		{
		  timeval_add_s(&ms->tx_ka, &now, 30);
		  if(sc_master_tx_keepalive(ms) != 0)
		    {
		      sc_master_free(ms);
		      continue;
		    }
		}

	      /* now figure out timeout to set */
	      if(timeval_cmp(&ms->rx_abort, &ms->tx_ka) <= 0)
		timeval_diff_tv(&tv, &now, &ms->rx_abort);
	      else
		timeval_diff_tv(&tv, &now, &ms->tx_ka);
	      if(rc == 0)
		{
		  timeval_cpy(&to, &tv);
		  rc++;
		}
	      else
		{
		  if(timeval_cmp(&tv, &to) < 0)
		    timeval_cpy(&to, &tv);
		}
	    }
	}

#if defined(HAVE_EPOLL)
      if(rc != 0)
	{
	  timeout = (to.tv_sec * 1000) + (to.tv_usec / 1000);
	  if(timeout == 0 && to.tv_usec != 0)
	    timeout++;
	}
      if((rc = epoll_wait(epfd, events, events_c, timeout)) == -1)
	{
	  if(errno == EINTR)
	    continue;
	  remote_debug(__func__, "epoll_wait failed: %s", strerror(errno));
	  return -1;
	}
#else
      if(rc != 0)
	{
	  ts.tv_sec = to.tv_sec;
	  ts.tv_nsec = to.tv_usec * 1000;
	  timeout = &ts;
	}
      if((rc = kevent(kqfd, NULL, 0, events, events_c, timeout)) == -1)
	{
	  if(errno == EINTR)
	    continue;
	  remote_debug(__func__, "kqueue_event failed: %s", strerror(errno));
	  return -1;
	}
#endif

      gettimeofday_wrap(&now);

      for(i=0; i<rc; i++)
	{
#if defined(HAVE_EPOLL)
	  scfd = events[i].data.ptr;
#else
	  scfd = events[i].udata;
#endif

	  if((scu = scfd->unit) == NULL)
	    {
	      serversocket_accept(scfd->fd);
	      continue;
	    }

#if defined(HAVE_EPOLL)
	  if(events[i].events & EPOLLIN && scu->gc == 0)
	    read_cb[scfd->type](scu->data);
	  if(events[i].events & EPOLLOUT && scu->gc == 0)
	    write_cb[scfd->type](scu->data);
#else
	  if(scu->gc != 0)
	    continue;
	  if(events[i].filter == EVFILT_READ)
	    read_cb[scfd->type](scu->data);
	  else if(events[i].filter == EVFILT_WRITE)
	    write_cb[scfd->type](scu->data);
#endif
	}

      while((scu = dlist_head_pop(gclist)) != NULL)
	unit_gc[scu->type](scu->data);
    }

  return 0;
}
#endif

static int select_loop(void)
{
  struct timeval tv, to, *timeout;
  fd_set rfds;
  fd_set wfds, *wfdsp;
  int i, count, nfds;
  dlist_node_t *dn, *dn2;
  sc_master_t *ms;
  sc_channel_t *cn;
  sc_unit_t *scu;

  while(stop == 0)
    {
      FD_ZERO(&rfds); FD_ZERO(&wfds);
      wfdsp = NULL; nfds = -1; timeout = NULL;

      for(i=0; i<2; i++)
	{
	  if(serversockets[i] == -1)
	    continue;
	  FD_SET(serversockets[i], &rfds);
	  if(serversockets[i] > nfds)
	    nfds = serversockets[i];
	}

      if((dn = dlist_head_node(mslist)) != NULL)
	{
	  gettimeofday_wrap(&now);

	  /* to start with, handle keepalives */
	  while(dn != NULL)
	    {
	      ms = dlist_node_item(dn);
	      dn = dlist_node_next(dn);

	      /* if the connection has gone silent, abort */
	      if(timeval_cmp(&now, &ms->rx_abort) >= 0)
		{
		  sc_master_free(ms);
		  continue;
		}

	      /*
	       * ensure we send something every 30 seconds
	       * unix_fd being not null signifies the remote controller
	       * has received an opening "master" frame.
	       */
	      if(ms->unix_fd != NULL && timeval_cmp(&now, &ms->tx_ka) >= 0)
		{
		  timeval_add_s(&ms->tx_ka, &now, 30);
		  if(sc_master_tx_keepalive(ms) != 0)
		    {
		      sc_master_free(ms);
		      continue;
		    }
		}

	      /* now figure out timeout to set */
	      if(timeval_cmp(&ms->rx_abort, &ms->tx_ka) <= 0)
		timeval_diff_tv(&tv, &now, &ms->rx_abort);
	      else
		timeval_diff_tv(&tv, &now, &ms->tx_ka);
	      if(timeout == NULL)
		{
		  timeval_cpy(&to, &tv);
		  timeout = &to;
		}
	      else
		{
		  if(timeval_cmp(&tv, &to) < 0)
		    timeval_cpy(&to, &tv);
		}

	      /* put the master inet socket into the select set */
	      FD_SET(ms->inet_fd.fd, &rfds);
	      if(ms->inet_fd.fd > nfds)
		nfds = ms->inet_fd.fd;
	      if(scamper_writebuf_len(ms->inet_wb) > 0)
		{
		  FD_SET(ms->inet_fd.fd, &wfds);
		  wfdsp = &wfds;
		}

	      /* listen on the master unix domain socket for new connections */
	      if(ms->unix_fd != NULL)
		{
		  FD_SET(ms->unix_fd->fd, &rfds);
		  if(ms->unix_fd->fd > nfds) nfds = ms->unix_fd->fd;
		}

	      /* set the unix domain sockets for connected systems */
	      dn2 = dlist_head_node(ms->channels);
	      while(dn2 != NULL)
		{
		  cn = dlist_node_item(dn2);
		  dn2 = dlist_node_next(dn2);
		  if(cn->unix_fd == NULL)
		    continue;
		  if((cn->unix_fd->flags & (FD_FLAG_READ|FD_FLAG_WRITE)) == 0)
		    continue;
		  if(cn->unix_fd->fd > nfds)
		    nfds = cn->unix_fd->fd;
		  if(cn->unix_fd->flags & FD_FLAG_READ)
		    FD_SET(cn->unix_fd->fd, &rfds);
		  if(cn->unix_fd->flags & FD_FLAG_WRITE)
		    {
		      FD_SET(cn->unix_fd->fd, &wfds);
		      wfdsp = &wfds;
		    }
		}
	    }
	}

      if((count = select(nfds+1, &rfds, wfdsp, NULL, timeout)) < 0)
	{
	  if(errno == EINTR)
	    continue;
	  remote_debug(__func__, "select failed: %s", strerror(errno));
	  return -1;
	}

      if(count > 0)
	{
	  for(i=0; i<2; i++)
	    {
	      if(serversockets[i] != -1 &&
		 FD_ISSET(serversockets[i], &rfds) &&
		 serversocket_accept(serversockets[i]) != 0)
		return -1;
	    }

	  for(dn=dlist_head_node(mslist); dn != NULL; dn=dlist_node_next(dn))
	    {
	      ms = dlist_node_item(dn);
	      if(FD_ISSET(ms->inet_fd.fd, &rfds))
		sc_master_inet_read(ms);
	      if(ms->unit->gc == 0 && ms->unix_fd != NULL &&
		 FD_ISSET(ms->unix_fd->fd, &rfds))
		sc_master_unix_accept(ms);
	      if(ms->unit->gc == 0 && wfdsp != NULL &&
		 FD_ISSET(ms->inet_fd.fd, wfdsp))
		sc_master_inet_write(ms);

	      for(dn2 = dlist_head_node(ms->channels);
		  dn2 != NULL && ms->unit->gc == 0;
		  dn2 = dlist_node_next(dn2))
		{
		  cn = dlist_node_item(dn2);
		  if(cn->unix_fd != NULL && FD_ISSET(cn->unix_fd->fd, &rfds))
		    sc_channel_unix_read(cn);
		  if(wfdsp != NULL && cn->unix_fd != NULL &&
		     FD_ISSET(cn->unix_fd->fd, wfdsp))
		    sc_channel_unix_write(cn);
		}
	    }
	}

      while((scu = dlist_head_pop(gclist)) != NULL)
	unit_gc[scu->type](scu->data);
    }

  return 0;
}

int main(int argc, char *argv[])
{
  int i;

#ifndef _WIN32
  struct sigaction si_sa;
#endif

#ifdef DMALLOC
  free(malloc(1));
#endif

  gettimeofday_wrap(&now);

  for(i=0; i<2; i++)
    serversockets[i] = -1;

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

#ifdef HAVE_OPENSSL
  if(tls_certfile != NULL)
    {
      SSL_library_init();
      SSL_load_error_strings();
      if((tls_ctx = SSL_CTX_new(SSLv23_method())) == NULL)
	return -1;
      if(SSL_CTX_use_certificate_chain_file(tls_ctx,tls_certfile)!=1)
	{
	  remote_debug(__func__, "could not SSL_CTX_use_certificate_file");
	  ERR_print_errors_fp(stderr);
	  return -1;
	}
      if(SSL_CTX_use_PrivateKey_file(tls_ctx,tls_privfile,SSL_FILETYPE_PEM)!=1)
	{
	  remote_debug(__func__, "could not SSL_CTX_use_PrivateKey_file");
	  ERR_print_errors_fp(stderr);
	  return -1;
	}
      SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_NONE, NULL);
      SSL_CTX_set_options(tls_ctx,
			  SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
    }
#endif

#ifdef HAVE_DAEMON
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    return -1;
#endif

#ifndef _WIN32
  if(signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
      remote_debug(__func__, "could not ignore SIGPIPE");
      return -1;
    }

  sigemptyset(&si_sa.sa_mask);
  si_sa.sa_flags   = 0;
  si_sa.sa_handler = remoted_sig;
  if(sigaction(SIGHUP, &si_sa, 0) == -1)
    {
      remote_debug(__func__, "could not set sigaction for SIGHUP");
      return -1;
    }
  if(sigaction(SIGINT, &si_sa, 0) == -1)
    {
      remote_debug(__func__, "could not set sigaction for SIGINT");
      return -1;
    }
#endif

  if(unixdomain_direxists() != 0 || serversocket_init() != 0)
    return -1;

  if((mslist = dlist_alloc()) == NULL ||
     (gclist = dlist_alloc()) == NULL)
    return -1;
  dlist_onremove(mslist, (dlist_onremove_t)sc_master_onremove);
  dlist_onremove(gclist, (dlist_onremove_t)sc_unit_onremove);

#if defined(HAVE_EPOLL)
  if((flags & FLAG_SELECT) == 0)
    return epoll_loop();
#elif defined(HAVE_KQUEUE)
  if((flags & FLAG_SELECT) == 0)
    return kqueue_loop();
#endif

  return select_loop();
}
