/*
 * scamper_fds: manage events and file descriptors
 *
 * $Id: scamper_fds.c,v 1.96 2017/12/03 09:38:26 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2014 Matthew Luckie
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2016      Matthew Luckie
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
  "$Id: scamper_fds.c,v 1.96 2017/12/03 09:38:26 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_fds.h"
#include "scamper_debug.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_udp4.h"
#include "scamper_udp6.h"
#include "scamper_tcp4.h"
#include "scamper_tcp6.h"
#include "scamper_ip4.h"
#include "scamper_dl.h"
#ifndef _WIN32
#include "scamper_rtsock.h"
#endif
#include "utils.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"

/*
 * scamper_fd_poll
 *
 * node to hold callback details for the fd.
 */
typedef struct scamper_fd_poll
{
  scamper_fd_t    *fdn;    /* back pointer to the fd struct */
  scamper_fd_cb_t  cb;     /* callback to use when event arises */
  void            *param;  /* user-defined parameter to pass to callback */
  dlist_t         *list;   /* which list the node is in */
  dlist_node_t    *node;   /* node in the poll list */
  uint8_t          flags;  /* flags associated with structure */
} scamper_fd_poll_t;

/*
 * scamper_fd
 *
 * a file descriptor, details of its type and other identifying information,
 * and what to do when read/write events are found.
 */
struct scamper_fd
{
  int               fd;           /* the file descriptor being polled */
  scamper_fd_t     *raw;          /* if udp4, the raw udp socket */
  int               type;         /* the type of the file descriptor */
  int               refcnt;       /* number of references to this structure */
  scamper_fd_poll_t read;         /* if monitored for read events */
  scamper_fd_poll_t write;        /* if monitored for write events */

  splaytree_node_t *fd_tree_node; /* node for this fd in the fd_tree */
  dlist_node_t     *fd_list_node; /* node for this fd in the fd_list */

  struct timeval    tv;           /* when this node should be expired */
  dlist_node_t     *rc0;          /* node in refcnt_0 list */

  union
  {
    struct fd_t_tcp
    {
      void         *addr;
      uint16_t      sport;
    } fd_t_tcp;

    struct fd_t_udp
    {
      void         *addr;
      uint16_t      sport;
    } fd_t_udp;

    struct fd_t_icmp
    {
      void         *addr;
    } fd_t_icmp;

    struct fd_t_dl
    {
      int           ifindex;
      scamper_dl_t *dl;
    } fd_t_dl;

  } fd_t_un;
};

#define SCAMPER_FD_TYPE_PRIVATE  0x00
#define SCAMPER_FD_TYPE_ICMP4    0x01
#define SCAMPER_FD_TYPE_ICMP6    0x02
#define SCAMPER_FD_TYPE_UDP4     0x03
#define SCAMPER_FD_TYPE_UDP4DG   0x04
#define SCAMPER_FD_TYPE_UDP6     0x05
#define SCAMPER_FD_TYPE_TCP4     0x06
#define SCAMPER_FD_TYPE_TCP6     0x07
#define SCAMPER_FD_TYPE_DL       0x08
#define SCAMPER_FD_TYPE_IP4      0x09
#define SCAMPER_FD_TYPE_FILE     0x0a

#ifndef _WIN32
#define SCAMPER_FD_TYPE_RTSOCK   0x0b
#define SCAMPER_FD_TYPE_IFSOCK   0x0c
#endif

#define SCAMPER_FD_TYPE_IS_UDP(fd) (      \
  (fd)->type == SCAMPER_FD_TYPE_UDP4   || \
  (fd)->type == SCAMPER_FD_TYPE_UDP4DG || \
  (fd)->type == SCAMPER_FD_TYPE_UDP6)

#define SCAMPER_FD_TYPE_IS_ICMP(fd) (     \
  (fd)->type == SCAMPER_FD_TYPE_ICMP4 ||  \
  (fd)->type == SCAMPER_FD_TYPE_ICMP6)

#define SCAMPER_FD_TYPE_IS_TCP(fd) (      \
  (fd)->type == SCAMPER_FD_TYPE_TCP4 ||   \
  (fd)->type == SCAMPER_FD_TYPE_TCP6)

#define SCAMPER_FD_TYPE_IS_IPV4(fd) (     \
  (fd)->type == SCAMPER_FD_TYPE_ICMP4  || \
  (fd)->type == SCAMPER_FD_TYPE_UDP4   || \
  (fd)->type == SCAMPER_FD_TYPE_UDP4DG || \
  (fd)->type == SCAMPER_FD_TYPE_TCP4)

#define SCAMPER_FD_TYPE_IS_IPV6(fd) (     \
  (fd)->type == SCAMPER_FD_TYPE_ICMP6 ||  \
  (fd)->type == SCAMPER_FD_TYPE_UDP6  ||  \
  (fd)->type == SCAMPER_FD_TYPE_TCP6)

#define SCAMPER_FD_TYPE_IS_DL(fd) (       \
  (fd)->type == SCAMPER_FD_TYPE_DL)

#define SCAMPER_FD_POLL_FLAG_INACTIVE 0x01 /* the fd should not be polled */

#define fd_tcp_sport  fd_t_un.fd_t_tcp.sport
#define fd_tcp_addr   fd_t_un.fd_t_tcp.addr
#define fd_udp_sport  fd_t_un.fd_t_udp.sport
#define fd_udp_addr   fd_t_un.fd_t_udp.addr
#define fd_icmp_addr  fd_t_un.fd_t_icmp.addr
#define fd_dl_ifindex fd_t_un.fd_t_dl.ifindex
#define fd_dl_dl      fd_t_un.fd_t_dl.dl

static scamper_fd_t **fd_array    = NULL;
static int            fd_array_s  = 0;
static splaytree_t   *fd_tree     = NULL;
static dlist_t       *fd_list     = NULL;
static dlist_t       *read_fds    = NULL;
static dlist_t       *write_fds   = NULL;
static dlist_t       *read_queue  = NULL;
static dlist_t       *write_queue = NULL;
static dlist_t       *refcnt_0    = NULL;
static int          (*pollfunc)(struct timeval *timeout) = NULL;

#ifdef HAVE_SCAMPER_DEBUG

static char *fd_addr_tostr(char *buf, size_t len, int af, void *addr)
{
  char tmp[128];

  if(addr == NULL || addr_tostr(af, addr, tmp, sizeof(tmp)) == NULL)
    return "";

  snprintf(buf, len, " %s", tmp);
  return buf;
}

static char *fd_tostr(scamper_fd_t *fdn)
{
  static char buf[144];
  char addr[128];

  switch(fdn->type)
    {
    case SCAMPER_FD_TYPE_PRIVATE:
      return "private";

    case SCAMPER_FD_TYPE_IP4:
      return "ip4";

    case SCAMPER_FD_TYPE_FILE:
      return "file";

    case SCAMPER_FD_TYPE_ICMP4:
      snprintf(buf, sizeof(buf), "icmp4%s",
	       fd_addr_tostr(addr, sizeof(addr), AF_INET, fdn->fd_icmp_addr));
      return buf;

    case SCAMPER_FD_TYPE_ICMP6:
      snprintf(buf, sizeof(buf), "icmp6%s",
	       fd_addr_tostr(addr, sizeof(addr), AF_INET6, fdn->fd_icmp_addr));
      return buf;

    case SCAMPER_FD_TYPE_UDP4:
      snprintf(buf, sizeof(buf), "udp4%s",
	       fd_addr_tostr(addr, sizeof(addr), AF_INET, fdn->fd_udp_addr));
      return buf;

    case SCAMPER_FD_TYPE_UDP4DG:
      snprintf(buf, sizeof(buf), "udp4dg%s %d",
	       fd_addr_tostr(addr, sizeof(addr), AF_INET, fdn->fd_udp_addr),
	       fdn->fd_udp_sport);
      return buf;

    case SCAMPER_FD_TYPE_UDP6:
      snprintf(buf, sizeof(buf), "udp6%s %d",
	       fd_addr_tostr(addr, sizeof(addr), AF_INET6, fdn->fd_udp_addr),
	       fdn->fd_udp_sport);
      return buf;

    case SCAMPER_FD_TYPE_TCP4:
      snprintf(buf, sizeof(buf), "tcp4%s %d",
	       fd_addr_tostr(addr, sizeof(addr), AF_INET, fdn->fd_tcp_addr),
	       fdn->fd_tcp_sport);
      return buf;

    case SCAMPER_FD_TYPE_TCP6:
      snprintf(buf, sizeof(buf), "tcp6%s %d",
	       fd_addr_tostr(addr, sizeof(addr), AF_INET6, fdn->fd_tcp_addr),
	       fdn->fd_tcp_sport);
      return buf;

    case SCAMPER_FD_TYPE_DL:
      snprintf(buf, sizeof(buf), "dl %d", fdn->fd_dl_ifindex);
      return buf;

#ifdef SCAMPER_FD_TYPE_RTSOCK
    case SCAMPER_FD_TYPE_RTSOCK:
      return "rtsock";
#endif

#ifdef SCAMPER_FD_TYPE_IFSOCK
    case SCAMPER_FD_TYPE_IFSOCK:
      return "ifsock";
#endif
    }

  return "?";
}
#endif

static void fd_close(scamper_fd_t *fdn)
{
  switch(fdn->type)
    {
    case SCAMPER_FD_TYPE_PRIVATE:
    case SCAMPER_FD_TYPE_FILE:
      break;

    case SCAMPER_FD_TYPE_ICMP4:
      scamper_icmp4_close(fdn->fd);
      break;

    case SCAMPER_FD_TYPE_ICMP6:
      scamper_icmp6_close(fdn->fd);
      break;

    case SCAMPER_FD_TYPE_UDP4:
    case SCAMPER_FD_TYPE_UDP4DG:
      scamper_udp4_close(fdn->fd);
      break;

    case SCAMPER_FD_TYPE_UDP6:
      scamper_udp6_close(fdn->fd);
      break;

    case SCAMPER_FD_TYPE_TCP4:
      scamper_tcp4_close(fdn->fd);
      break;

    case SCAMPER_FD_TYPE_TCP6:
      scamper_tcp6_close(fdn->fd);
      break;

    case SCAMPER_FD_TYPE_DL:
      scamper_dl_close(fdn->fd);
      break;

#ifdef SCAMPER_FD_TYPE_RTSOCK
    case SCAMPER_FD_TYPE_RTSOCK:
      scamper_rtsock_close(fdn->fd);
      break;
#endif

#ifdef SCAMPER_FD_TYPE_IFSOCK
    case SCAMPER_FD_TYPE_IFSOCK:
      close(fdn->fd);
      break;
#endif
    }

  return;
}

/*
 * fd_free
 *
 * free up memory allocated to scamper's monitoring of the file descriptor.
 */
static void fd_free(scamper_fd_t *fdn)
{
  scamper_debug(__func__, "fd %d type %s", fdn->fd, fd_tostr(fdn));

  if(fdn->fd >= 0 && fdn->fd < fd_array_s && fd_array != NULL)
    fd_array[fdn->fd] = NULL;

  if(fdn->read.node != NULL)
    dlist_node_pop(fdn->read.list, fdn->read.node);

  if(fdn->write.node != NULL)
    dlist_node_pop(fdn->write.list, fdn->write.node);

  if(fdn->rc0 != NULL)
    dlist_node_pop(refcnt_0, fdn->rc0);

  if(fdn->fd_tree_node != NULL)
    splaytree_remove_node(fd_tree, fdn->fd_tree_node);

  if(fdn->fd_list_node != NULL)
    dlist_node_pop(fd_list, fdn->fd_list_node);

  if(SCAMPER_FD_TYPE_IS_ICMP(fdn))
    {
      if(fdn->fd_icmp_addr != NULL)
	free(fdn->fd_icmp_addr);
    }
  else if(SCAMPER_FD_TYPE_IS_UDP(fdn))
    {
      if(fdn->fd_udp_addr != NULL)
	free(fdn->fd_udp_addr);
    }
  else if(SCAMPER_FD_TYPE_IS_TCP(fdn))
    {
      if(fdn->fd_tcp_addr != NULL)
	free(fdn->fd_tcp_addr);
    }
  else if(SCAMPER_FD_TYPE_IS_DL(fdn))
    {
      if(fdn->fd_dl_dl != NULL)
	scamper_dl_state_free(fdn->fd_dl_dl);
    }

  free(fdn);

  return;
}

/*
 * fd_refcnt_0
 *
 * this function is called whenever a fdn with a refcnt field of zero is
 * found.
 */
static void fd_refcnt_0(scamper_fd_t *fdn)
{
  /*
   * if the fd is in a list that is currently locked, then it can't be
   * removed just yet
   */
  if(dlist_islocked(fd_list) != 0 ||
     (fdn->read.list  != NULL && dlist_islocked(fdn->read.list)  != 0) ||
     (fdn->write.list != NULL && dlist_islocked(fdn->write.list) != 0))
    {
      return;
    }

  /*
   * if this is a private fd and the reference count has reached zero,
   * then the scamper_fd structure can be freed up completely now
   */
  if(fdn->type == SCAMPER_FD_TYPE_PRIVATE ||
     fdn->type == SCAMPER_FD_TYPE_FILE)
    {
      fd_free(fdn);
      return;
    }

  /* if it is not possible to put the node on a list, just free it */
  if((fdn->rc0 = dlist_tail_push(refcnt_0, fdn)) == NULL)
    {
      fd_close(fdn);
      fd_free(fdn);
      return;
    }

  /*
   * set this fd to be closed in ten seconds unless something else comes
   * along and wants to use it.
   */
  gettimeofday_wrap(&fdn->tv);
  fdn->tv.tv_sec += 10;

  return;
}

static int fd_poll_setlist(void *item, void *param)
{
  ((scamper_fd_poll_t *)item)->list = (dlist_t *)param;
  return 0;
}

/*
 * fds_select_assemble
 *
 * given a list of scamper_fd_poll_t structures held in a list, compose an
 * fd_set for them to pass to select.
 */
static int fds_select_assemble(dlist_t *fds, slist_t **file_list,
			       fd_set *fdset, fd_set **fdsp, int *nfds)
{
  scamper_fd_poll_t *fdp;
  dlist_node_t      *node;
  int                count = 0;

  FD_ZERO(fdset);

  node = dlist_head_node(fds);
  while(node != NULL)
    {
      /* file descriptor associated with the node */
      fdp = (scamper_fd_poll_t *)dlist_node_item(node);

      /* get the next node incase this node is subsequently removed */
      node = dlist_node_next(node);

      /* if there is nothing using this fdn any longer, then stop polling it */
      if(fdp->fdn->refcnt == 0 && fdp->fdn->rc0 == NULL)
	{
	  fd_refcnt_0(fdp->fdn);
	  continue;
	}

      /* if the inactive flag is set, then skip over this file descriptor */
      if((fdp->flags & SCAMPER_FD_POLL_FLAG_INACTIVE) != 0)
	{
	  dlist_node_eject(fds, fdp->node);
	  fdp->list = NULL;
	  continue;
	}

      if(fdp->fdn->type == SCAMPER_FD_TYPE_FILE)
	{
	  if((*file_list == NULL && (*file_list = slist_alloc()) == NULL) ||
	     slist_tail_push(*file_list, fdp) == NULL)
	    return -1;
	  continue;
	}

      /* monitor this file descriptor */
      FD_SET(fdp->fdn->fd, fdset);
      count++;

      /* update the maxfd seen if appropriate */
      if(*nfds < fdp->fdn->fd)
	*nfds = fdp->fdn->fd;
    }

  /*
   * if there are no fds in the set to monitor, then return a null pointer
   * to pass to select
   */
  if(count == 0)
    *fdsp = NULL;
  else
    *fdsp = fdset;

  return 0;
}

/*
 * fds_select_check
 *
 * given an fd_set that has been passed to select, as well as a list of
 * fds that are being monitored, figure out which ones have an event and
 * use the callback provided to deal with the event.
 */
static void fds_select_check(fd_set *fdset, dlist_t *fds, int *count)
{
  scamper_fd_poll_t *fdp;
  dlist_node_t *node;

  /* stop now if there is nothing to check */
  if(fdset == NULL || *count == 0)
    {
      return;
    }

  /* nodes in this list should not be removed while this function is called */
  dlist_lock(fds);

  /* loop through */
  node = dlist_head_node(fds);
  while(node != NULL && *count > 0)
    {
      fdp = (scamper_fd_poll_t *)dlist_node_item(node);
      node = dlist_node_next(node);

      if(FD_ISSET(fdp->fdn->fd, fdset))
	{
	  fdp->cb(fdp->fdn->fd, fdp->param);
	  (*count)--;
	}
    }

  /* can modify the list now */
  dlist_unlock(fds);

  return;
}

static void fds_files_check(dlist_t *fds, slist_t *list)
{
  scamper_fd_poll_t *fdp;

  if(list == NULL)
    return;

  dlist_lock(fds);
  while((fdp = slist_head_pop(list)) != NULL)
    fdp->cb(fdp->fdn->fd, fdp->param);
  dlist_unlock(fds);

  return;
}

static int fds_select(struct timeval *timeout)
{
  struct timeval tv;
  fd_set rfds, *rfdsp;
  fd_set wfds, *wfdsp;
  slist_t *rfiles = NULL, *wfiles = NULL;
  int count, nfds = -1;

  /* concat any new fds to monitor now */
  dlist_foreach(read_queue, fd_poll_setlist, read_fds);
  dlist_concat(read_fds, read_queue);
  dlist_foreach(write_queue, fd_poll_setlist, write_fds);
  dlist_concat(write_fds, write_queue);

  /* compose the sets of file descriptors to monitor */
  if(fds_select_assemble(read_fds, &rfiles, &rfds, &rfdsp, &nfds) != 0)
    goto err;
  if(fds_select_assemble(write_fds, &wfiles, &wfds, &wfdsp, &nfds) != 0)
    goto err;

  if(rfiles != NULL || wfiles != NULL)
    {
      tv.tv_sec = 0; tv.tv_usec = 0;
      timeout = &tv;
    }

  /* find out which file descriptors have an event */
#ifdef _WIN32
  if(nfds == -1 && rfiles == NULL && wfiles == NULL)
    {
      if(timeout != NULL && timeout->tv_sec >= 0 && timeout->tv_usec >= 0)
	Sleep((timeout->tv_sec * 1000) + (timeout->tv_usec / 1000));
      count = 0;
    }
  else
#endif
  if((count = select(nfds+1, rfdsp, wfdsp, NULL, timeout)) < 0)
    {
      printerror(__func__, "select failed");
      goto err;
    }

  /* read and write to files outside of select */
  if(rfiles != NULL)
    {
      fds_files_check(read_fds, rfiles);
      slist_free(rfiles); rfiles = NULL;
    }

  if(wfiles != NULL)
    {
      fds_files_check(write_fds, wfiles);
      slist_free(wfiles); wfiles = NULL;
    }

  /* if there are fds to check, then check them */
  if(count > 0)
    {
      fds_select_check(rfdsp, read_fds, &count);
      fds_select_check(wfdsp, write_fds, &count);
    }

  return 0;

 err:
  if(rfiles != NULL) slist_free(rfiles);
  if(wfiles != NULL) slist_free(wfiles);
  return -1;
}

#ifdef HAVE_POLL
static struct pollfd *poll_fds = NULL;
static int poll_fdc = 0;

static void fds_poll_check(short event, int rc, int count)
{
  scamper_fd_t *fd;
  int i;

  for(i=0; i<count; i++)
    {
      /* skip over if we were not interested in this type of event */
      if((poll_fds[i].events & event) == 0)
	continue;

      /* skip over if there is no event of this type */
      if((poll_fds[i].revents & (event|POLLHUP|POLLERR)) == 0)
	continue;

      /*
       * ensure that the fd is still valid as far as scamper's monitoring
       * of it goes.
       */
      if(poll_fds[i].fd >= 0 && poll_fds[i].fd < fd_array_s &&
	 (fd = fd_array[poll_fds[i].fd]) != NULL)
	{
	  if(event == POLLIN)
	    fd->read.cb(fd->fd, fd->read.param);
	  else
	    fd->write.cb(fd->fd, fd->write.param);
	}

      if(--rc == 0)
	break;
    }

  return;
}

static int fds_poll(struct timeval *tv)
{
  scamper_fd_t *fd;
  dlist_node_t *n;
  int timeout;
  int rc, count = 0, in = 0, out = 0;
  size_t size;

  n = dlist_head_node(fd_list);
  while(n != NULL)
    {
      fd = dlist_node_item(n);
      n  = dlist_node_next(n);

      /* if there is nothing using this fdn any longer, then stop polling it */
      if(fd->refcnt == 0 && fd->rc0 == NULL)
	{
	  fd_refcnt_0(fd);
	  continue;
	}

      /* don't poll an inactive fd */
      if((fd->read.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) != 0 &&
	 (fd->write.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) != 0)
	continue;

      if(count + 1 > poll_fdc)
	{
	  size = (count+1) * sizeof(struct pollfd);
	  if(realloc_wrap((void **)&poll_fds, size) != 0)
	    {
	      printerror(__func__, "could not realloc poll_fds");
	      return -1;
	    }
	  poll_fdc = count + 1;
	}

      poll_fds[count].fd = fd->fd;
      poll_fds[count].events = 0;
      poll_fds[count].revents = 0;

      if((fd->read.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) == 0)
	{
	  poll_fds[count].events |= POLLIN;
	  in++;
	}
      if((fd->write.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) == 0)
	{
	  poll_fds[count].events |= POLLOUT;
	  out++;
	}

      count++;
    }

  if(tv != NULL)
    {
      timeout = (tv->tv_sec * 1000) + (tv->tv_usec / 1000);
      if(timeout == 0 && tv->tv_usec != 0)
	timeout++;
    }
  else
    {
      timeout = -1;
    }

  if((rc = poll(poll_fds, count, timeout)) < 0)
    {
      printerror(__func__, "could not poll");
      return -1;
    }

  if(rc > 0)
    {
      if(in != 0)
	fds_poll_check(POLLIN, rc < in ? rc : in, count);
      if(out != 0)
	fds_poll_check(POLLOUT, rc < out ? rc : out, count);
    }

  return 0;
}
#endif

#ifdef HAVE_KQUEUE
static struct kevent *kevlist = NULL;
static int kevlistlen = 0;
static int kq = -1;

static int fds_kqueue_init(void)
{
  if((kq = kqueue()) == -1)
    {
      printerror(__func__, "could not create kqueue");
      return -1;
    }
  scamper_debug(__func__, "fd %d", kq);
  return 0;
}

static void fds_kqueue_set(scamper_fd_t *fd, short filter, u_short flags)
{
  struct kevent kev;
  EV_SET(&kev, fd->fd, filter, flags, 0, 0, fd);
  if(kevent(kq, &kev, 1, NULL, 0, NULL) != 0)
    {
      printerror(__func__, "fd %d %s %s", fd->fd,
		 filter == EVFILT_READ ? "EVFILT_READ" : "EVFILT_WRITE",
		 flags == EV_ADD ? "EV_ADD" : "EV_DELETE");
    }
  return;
}

static int fds_kqueue(struct timeval *tv)
{
  scamper_fd_t *fdp;
  struct timespec ts, *tsp = NULL;
  struct kevent *kev;
  int fd, i, c;

  if((c = dlist_count(read_fds) + dlist_count(write_fds)) >= kevlistlen)
    {
      c += 8;
      if(realloc_wrap((void **)&kevlist, sizeof(struct kevent) * c) != 0)
	{
	  if(kevlistlen == 0)
	    {
	      printerror(__func__, "could not alloc kevlist");
	      return -1;
	    }
	}
      else
	{
	  kevlistlen = c;
	}
    }

  if(tv != NULL)
    {
      ts.tv_sec  = tv->tv_sec;
      ts.tv_nsec = tv->tv_usec * 1000;
      tsp = &ts;
    }

  if((c = kevent(kq, NULL, 0, kevlist, kevlistlen, tsp)) == -1)
    {
      printerror(__func__, "kevent failed");
      return -1;
    }

  for(i=0; i<c; i++)
    {
      kev = &kevlist[i];
      fd = kev->ident;

      if(fd < 0 || fd >= fd_array_s)
	continue;
      if((fdp = fd_array[fd]) == NULL)
	continue;
      if(kev->filter == EVFILT_READ)
	fdp->read.cb(fd, fdp->read.param);
      else if(kev->filter == EVFILT_WRITE)
	fdp->write.cb(fd, fdp->write.param);
    }

  return 0;
}
#endif

#ifdef HAVE_EPOLL
static struct epoll_event *ep_events = NULL;
static int ep_event_c = 0;
static int ep = -1;
static int ep_fdc = 0;

static int fds_epoll_init(void)
{
  if((ep = epoll_create(10)) == -1)
    {
      printerror(__func__, "could not epoll_create");
      return -1;
    }
  scamper_debug(__func__, "fd %d", ep);
  return 0;
}

static void fds_epoll_ctl(scamper_fd_t *fd, uint32_t ev, int op)
{
  struct epoll_event epev;

  if(op == EPOLL_CTL_ADD &&
     ((ev == EPOLLIN &&
       (fd->write.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) == 0) ||
      (ev == EPOLLOUT &&
       (fd->read.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) == 0)))
    {
      op = EPOLL_CTL_MOD;
      ev = EPOLLIN | EPOLLOUT;
    }
  else if(op == EPOLL_CTL_DEL && ev == EPOLLIN &&
	  (fd->write.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) == 0)
    {
      op = EPOLL_CTL_MOD;
      ev = EPOLLOUT;
    }
  else if(op == EPOLL_CTL_DEL && ev == EPOLLOUT &&
	  (fd->read.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) == 0)
    {
      op = EPOLL_CTL_MOD;
      ev = EPOLLIN;
    }

  if(op == EPOLL_CTL_ADD)
    ep_fdc++;
  else if(op == EPOLL_CTL_DEL)
    ep_fdc--;

  epev.data.fd = fd->fd;
  epev.events = ev;

  if(epoll_ctl(ep, op, fd->fd, &epev) != 0)
    printerror(__func__, "fd %d op %d ev %u", fd->fd, op, ev);

  return;
}

static int fds_epoll(struct timeval *tv)
{
  int i, fd, rc, timeout;
  scamper_fd_t *fdp;
  size_t size;

  if(ep_fdc >= ep_event_c)
    {
      rc = ep_fdc + 8;
      size = sizeof(struct epoll_event) * rc;
      if(realloc_wrap((void **)&ep_events, size) != 0)
	{
	  if(ep_event_c == 0)
	    {
	      printerror(__func__, "could not alloc events");
	      return -1;
	    }
	}
      else
	{
	  ep_event_c = rc;
	}
    }

  if(tv != NULL)
    {
      timeout = (tv->tv_sec * 1000) + (tv->tv_usec / 1000);
      if(timeout == 0 && tv->tv_usec != 0)
	timeout++;
    }
  else
    {
      timeout = -1;
    }

  if((rc = epoll_wait(ep, ep_events, ep_event_c, timeout)) == -1)
    {
      printerror(__func__, "could not epoll_wait");
      return -1;
    }

  for(i=0; i<rc; i++)
    {
      fd = ep_events[i].data.fd;
      if(fd < 0 || fd >= fd_array_s)
	continue;

      if(ep_events[i].events & EPOLLIN)
	{
	  if((fdp = fd_array[fd]) == NULL)
	    continue;
	  fdp->read.cb(fd, fdp->read.param);
	}

      if(ep_events[i].events & EPOLLOUT)
	{
	  if((fdp = fd_array[fd]) == NULL)
	    continue;
	  fdp->write.cb(fd, fdp->write.param);
	}
    }

  return 0;
}
#endif

static int fd_addr_cmp(int type, void *a, void *b)
{
  assert(type == SCAMPER_FD_TYPE_TCP4   || type == SCAMPER_FD_TYPE_TCP6 ||
	 type == SCAMPER_FD_TYPE_UDP4   || type == SCAMPER_FD_TYPE_UDP6 ||
	 type == SCAMPER_FD_TYPE_UDP4DG ||
	 type == SCAMPER_FD_TYPE_ICMP4  || type == SCAMPER_FD_TYPE_ICMP6);

  if(a == NULL && b != NULL) return -1;
  if(a != NULL && b == NULL) return  1;
  if(a == NULL && b == NULL) return  0;

  if(type == SCAMPER_FD_TYPE_TCP4   ||
     type == SCAMPER_FD_TYPE_UDP4   ||
     type == SCAMPER_FD_TYPE_UDP4DG ||
     type == SCAMPER_FD_TYPE_ICMP4)
    return addr4_cmp(a, b);
  else
    return addr6_cmp(a, b);
}

/*
 * fd_cmp
 *
 * given two scamper_fd_t structures, determine if their properties are
 * the same.  used to maintain the splaytree of existing file descriptors
 * held by scamper.
 */
static int fd_cmp(const scamper_fd_t *a, const scamper_fd_t *b)
{
  if(a->type < b->type) return -1;
  if(a->type > b->type) return  1;

  switch(a->type)
    {
    case SCAMPER_FD_TYPE_TCP4:
    case SCAMPER_FD_TYPE_TCP6:
      if(a->fd_tcp_sport < b->fd_tcp_sport) return -1;
      if(a->fd_tcp_sport > b->fd_tcp_sport) return  1;
      return fd_addr_cmp(a->type, a->fd_tcp_addr, b->fd_tcp_addr);

    case SCAMPER_FD_TYPE_UDP4:
      return fd_addr_cmp(a->type, a->fd_udp_addr, b->fd_udp_addr);

    case SCAMPER_FD_TYPE_UDP4DG:
    case SCAMPER_FD_TYPE_UDP6:
      if(a->fd_udp_sport < b->fd_udp_sport) return -1;
      if(a->fd_udp_sport > b->fd_udp_sport) return  1;
      return fd_addr_cmp(a->type, a->fd_udp_addr, b->fd_udp_addr);

    case SCAMPER_FD_TYPE_DL:
      if(a->fd_dl_ifindex < b->fd_dl_ifindex) return -1;
      if(a->fd_dl_ifindex > b->fd_dl_ifindex) return  1;
      return 0;

    case SCAMPER_FD_TYPE_ICMP4:
    case SCAMPER_FD_TYPE_ICMP6:
      return fd_addr_cmp(a->type, a->fd_icmp_addr, b->fd_icmp_addr);
    }

  return 0;
}

/*
 * fd_alloc
 *
 * allocate a scamper_fd_t structure and do generic setup tasks.
 */
#ifndef DMALLOC
static scamper_fd_t *fd_alloc(int type, int fd)
#else
#define fd_alloc(type, fd) fd_alloc_dm((type), (fd), __FILE__, __LINE__)
static scamper_fd_t *fd_alloc_dm(int type, int fd, const char *file,
				 const int line)
#endif
{
  scamper_fd_t *fdn = NULL;
  size_t size;
  int i;

#ifndef DMALLOC
  if((fdn = malloc_zero(sizeof(scamper_fd_t))) == NULL)
#else
  if((fdn = malloc_zero_dm(sizeof(scamper_fd_t), file, line)) == NULL)
#endif
    {
      goto err;
    }
  fdn->type   = type;
  fdn->fd     = fd;
  fdn->refcnt = 1;

  /* set up to poll read ability */
  if((fdn->read.node = dlist_node_alloc(&fdn->read)) == NULL)
    {
      goto err;
    }
  fdn->read.fdn   = fdn;
  fdn->read.flags = SCAMPER_FD_POLL_FLAG_INACTIVE;

  /* set up to poll write ability */
  if((fdn->write.node = dlist_node_alloc(&fdn->write)) == NULL)
    {
      goto err;
    }
  fdn->write.fdn   = fdn;
  fdn->write.flags = SCAMPER_FD_POLL_FLAG_INACTIVE;

  /* store the fd in an array indexed by the fd number */
  if(fd+1 > fd_array_s)
    {
      size = sizeof(scamper_fd_t *) * (fd+1);
      if(realloc_wrap((void **)&fd_array, size) != 0)
	goto err;
      for(i=fd_array_s; i<fd+1; i++)
	fd_array[i] = NULL;
      fd_array_s = fd+1;
    }

  /* ensure the same fd is not already registered */
  assert(fd_array[fd] == NULL);
  fd_array[fd] = fdn;

  return fdn;

 err:
  if(fdn != NULL) fd_free(fdn);
  return NULL;
}

/*
 * fd_find
 *
 * search the tree of file descriptors known to scamper for a matching
 * entry.  if one is found, increment its reference count and return it.
 */
static scamper_fd_t *fd_find(scamper_fd_t *findme)
{
  scamper_fd_t *fdn;

  if((fdn = splaytree_find(fd_tree, findme)) != NULL)
    {
      if(fdn->refcnt == 0 && fdn->rc0 != NULL)
	{
	  dlist_node_pop(refcnt_0, fdn->rc0);
	  fdn->rc0 = NULL;
	}

      fdn->refcnt++;
    }

  return fdn;
}

/*
 * fd_null
 *
 * allocate a file descriptor of a specified type.
 */
static scamper_fd_t *fd_null(int type)
{
  scamper_fd_t *fdn = NULL, findme;
  int fd = -1;

  /* first check if a sharable fd exists for this type */
  findme.type = type;
  if((fdn = fd_find(&findme)) != NULL)
    {
      return fdn;
    }

  switch(type)
    {
#if defined(SCAMPER_FD_TYPE_RTSOCK)
    case SCAMPER_FD_TYPE_RTSOCK:
      fd = scamper_rtsock_open();
      break;
#endif

#if defined(SCAMPER_FD_TYPE_IFSOCK)
    case SCAMPER_FD_TYPE_IFSOCK:
      fd = socket(AF_INET, SOCK_DGRAM, 0);
      break;
#endif

    case SCAMPER_FD_TYPE_IP4:
      fd = scamper_ip4_openraw();
      break;
    }

  if(fd == -1 || (fdn = fd_alloc(type, fd)) == NULL ||
     (fdn->fd_tree_node = splaytree_insert(fd_tree, fdn)) == NULL ||
     (fdn->fd_list_node = dlist_tail_push(fd_list, fdn)) == NULL)
    {
      goto err;
    }

  scamper_debug(__func__, "fd %d type %s", fdn->fd, fd_tostr(fdn));
  return fdn;

 err:
  if(fd != -1)
    {
      switch(type)
	{
#if defined(SCAMPER_FD_TYPE_RTSOCK)
	case SCAMPER_FD_TYPE_RTSOCK:
	  scamper_rtsock_close(fd);
	  break;
#endif

#if defined(SCAMPER_FD_TYPE_IFSOCK)
	case SCAMPER_FD_TYPE_IFSOCK:
	  close(fd);
	  break;
#endif

	case SCAMPER_FD_TYPE_IP4:
	  scamper_ip4_close(fd);
	  break;
	}
    }
  if(fdn != NULL) fd_free(fdn);
  return NULL;
}

static scamper_fd_t *fd_icmp(int type, void *addr)
{
  scamper_fd_t *fdn = NULL, findme;
  size_t len = 0;
  int fd = -1;

  findme.type = type;
  findme.fd_icmp_addr = addr;

  if((fdn = fd_find(&findme)) != NULL)
    {
      return fdn;
    }

  if(type == SCAMPER_FD_TYPE_ICMP4)
    {
      fd  = scamper_icmp4_open(addr);
      len = sizeof(struct in_addr);
    }
  else if(type == SCAMPER_FD_TYPE_ICMP6)
    {
      fd  = scamper_icmp6_open(addr);
      len = sizeof(struct in6_addr);
    }

  if(fd == -1 || (fdn = fd_alloc(type, fd)) == NULL ||
     (addr != NULL && (fdn->fd_icmp_addr = memdup(addr, len)) == NULL) ||
     (fdn->fd_tree_node = splaytree_insert(fd_tree, fdn)) == NULL ||
     (fdn->fd_list_node = dlist_tail_push(fd_list, fdn)) == NULL)
    {
      goto err;
    }

  scamper_debug(__func__, "fd %d type %s", fdn->fd, fd_tostr(fdn));
  return fdn;

 err:
  if(fd != -1)
    {
      if(type == SCAMPER_FD_TYPE_ICMP4)
	scamper_icmp4_close(fd);
      else if(type == SCAMPER_FD_TYPE_ICMP6)
	scamper_icmp6_close(fd);
    }
  if(fdn != NULL) fd_free(fdn);
  return NULL;
}

static scamper_fd_t *fd_tcp(int type, void *addr, uint16_t sport)
{
  scamper_fd_t *fdn, findme;
  size_t len = 0;
  int fd = -1;

  assert(type == SCAMPER_FD_TYPE_TCP4 ||
	 type == SCAMPER_FD_TYPE_TCP6);

  findme.type = type;
  findme.fd_tcp_addr = addr;
  findme.fd_tcp_sport = sport;

  if((fdn = fd_find(&findme)) != NULL)
    return fdn;

  if(type == SCAMPER_FD_TYPE_TCP4)
    {
      fd  = scamper_tcp4_open(addr, sport);
      len = sizeof(struct in_addr);
    }
  else if(type == SCAMPER_FD_TYPE_TCP6)
    {
      fd = scamper_tcp6_open(addr, sport);
      len = sizeof(struct in6_addr);
    }

  if(fd == -1 || (fdn = fd_alloc(type, fd)) == NULL ||
     (addr != NULL && (fdn->fd_tcp_addr = memdup(addr, len)) == NULL))
    {
      goto err;
    }
  fdn->fd_tcp_sport = sport;

  if((fdn->fd_tree_node = splaytree_insert(fd_tree, fdn)) == NULL ||
     (fdn->fd_list_node = dlist_tail_push(fd_list, fdn)) == NULL)
    {
      goto err;
    }

  scamper_debug(__func__, "fd %d type %s", fdn->fd, fd_tostr(fdn));
  return fdn;

 err:
  if(fd != -1)
    {
      if(type == SCAMPER_FD_TYPE_TCP4)
	scamper_tcp4_close(fd);
      else if(type == SCAMPER_FD_TYPE_TCP6)
	scamper_tcp6_close(fd);
    }
  if(fdn != NULL) fd_free(fdn);
  return NULL;
}

static scamper_fd_t *fd_udp(int type, void *addr, uint16_t sport)
{
  scamper_fd_t *fdn, findme;
  size_t len = 0;
  int fd = -1;

  findme.type = type;
  findme.fd_udp_addr = addr;
  findme.fd_udp_sport = sport;

  if((fdn = fd_find(&findme)) != NULL)
    return fdn;

  if(type == SCAMPER_FD_TYPE_UDP4)
    {
      fd  = scamper_udp4_openraw(addr);
      len = sizeof(struct in_addr);
    }
  else if(type == SCAMPER_FD_TYPE_UDP6)
    {
      fd  = scamper_udp6_open(addr, sport);
      len = sizeof(struct in6_addr);
    }
  else if(type == SCAMPER_FD_TYPE_UDP4DG)
    {
      fd  = scamper_udp4_opendgram(addr, sport);
      len = sizeof(struct in_addr);
    }

  if(fd == -1 || (fdn = fd_alloc(type, fd)) == NULL ||
     (addr != NULL && (fdn->fd_udp_addr = memdup(addr, len)) == NULL))
    {
      printerror(__func__, "could not open socket");
      goto err;
    }
  fdn->fd_udp_sport = sport;

  if((fdn->fd_tree_node = splaytree_insert(fd_tree, fdn)) == NULL)
    {
      printerror(__func__, "could not add socket to tree");
      goto err;
    }
  if((fdn->fd_list_node = dlist_tail_push(fd_list, fdn)) == NULL)
    {
      printerror(__func__, "could not add socket to list");
      goto err;
    }

  scamper_debug(__func__, "fd %d type %s", fdn->fd, fd_tostr(fdn));
  return fdn;

 err:
  if(fd != -1)
    {
      if(type == SCAMPER_FD_TYPE_UDP4 || type == SCAMPER_FD_TYPE_UDP4DG)
	scamper_udp4_close(fd);
      else if(type == SCAMPER_FD_TYPE_UDP6)
	scamper_udp6_close(fd);
    }
  if(fdn != NULL) fd_free(fdn);
  return NULL;
}

/*
 * scamper_fds_poll
 *
 * the money function: this function polls the file descriptors held by
 * scamper.  for each fd with an event, it calls the callback registered
 * with the fd.
 */
int scamper_fds_poll(struct timeval *timeout)
{
  scamper_fd_t *fdn;
  struct timeval tv;

  /*
   * if there are fds that can be reaped, then do so.
   * if there are fds left over after, use that to guide the select timeout.
   */
  if(dlist_count(refcnt_0) > 0)
    {
      gettimeofday_wrap(&tv);

      while((fdn = (scamper_fd_t *)dlist_head_item(refcnt_0)) != NULL)
	{
	  assert(fdn->refcnt == 0);

	  if(timeval_cmp(&fdn->tv, &tv) > 0)
	    break;

	  fd_close(fdn);
	  fd_free(fdn);
	}

      if(fdn != NULL)
	{
	  timeval_diff_tv(&tv, &tv, &fdn->tv);
	  if(timeout == NULL || timeval_cmp(&tv, timeout) < 0)
	    timeout = &tv;
	}
    }

  return pollfunc(timeout);
}

/*
 * scamper_fd_fd_get
 *
 * return the actual file descriptor associated with the scamper_fd_t
 */
int scamper_fd_fd_get(const scamper_fd_t *fdn)
{
  if(fdn->raw == NULL)
    return fdn->fd;
  return fdn->raw->fd;
}

/*
 * scamper_fd_fd_set
 *
 * set the file descriptor being monitored with the scamper_fd_t
 */
int scamper_fd_fd_set(scamper_fd_t *fdn, int fd)
{
  fdn->fd = fd;
  return 0;
}

/*
 * scamper_fd_read_pause
 *
 * ignore any read events on the fd.
 */
void scamper_fd_read_pause(scamper_fd_t *fdn)
{
#ifdef HAVE_KQUEUE
  if(kq != -1 && (fdn->read.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) == 0)
    fds_kqueue_set(fdn, EVFILT_READ, EV_DELETE);
#endif

#ifdef HAVE_EPOLL
  if(ep != -1 && (fdn->read.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) == 0)
    fds_epoll_ctl(fdn, EPOLLIN, EPOLL_CTL_DEL);
#endif

  fdn->read.flags |= SCAMPER_FD_POLL_FLAG_INACTIVE;
  return;
}

/*
 * scamper_fd_read_unpause
 *
 * monitor read events on the fd.  unset the inactive flag, and push the
 * node back onto the read list
 */
void scamper_fd_read_unpause(scamper_fd_t *fdn)
{
  assert(fdn->read.cb != NULL);

  if((fdn->read.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) != 0)
    {
      fdn->read.flags &= ~(SCAMPER_FD_POLL_FLAG_INACTIVE);

#ifdef HAVE_KQUEUE
      if(kq != -1)
	fds_kqueue_set(fdn, EVFILT_READ, EV_ADD);
#endif

#ifdef HAVE_EPOLL
      if(ep != -1)
	fds_epoll_ctl(fdn, EPOLLIN, EPOLL_CTL_ADD);
#endif

      /*
       * the fd may still be on the read fds list, just with the inactive bit
       * set.  if it isn't, then we have to put it on the queue.
       */
      if(fdn->read.list != read_fds)
	{
	  dlist_node_head_push(read_queue, fdn->read.node);
	  fdn->read.list = read_queue;
	}
    }

  return;
}

/*
 * scamper_fd_write_pause
 *
 * ignore any write events on the fd
 */
void scamper_fd_write_pause(scamper_fd_t *fdn)
{
#ifdef HAVE_KQUEUE
  if(kq != -1 && (fdn->write.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) == 0)
    fds_kqueue_set(fdn, EVFILT_WRITE, EV_DELETE);
#endif

#ifdef HAVE_EPOLL
  if(ep != -1 && (fdn->write.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) == 0)
    fds_epoll_ctl(fdn, EPOLLOUT, EPOLL_CTL_DEL);
#endif

  fdn->write.flags |= SCAMPER_FD_POLL_FLAG_INACTIVE;
  return;
}

/*
 * scamper_fd_write_unpause
 *
 * monitor write events on the fd.  unset the inactive flag, and push the
 * node back onto the write list
 */
void scamper_fd_write_unpause(scamper_fd_t *fdn)
{
  assert(fdn->write.cb != NULL);

  if((fdn->write.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) != 0)
    {
      fdn->write.flags &= ~(SCAMPER_FD_POLL_FLAG_INACTIVE);

#ifdef HAVE_KQUEUE
      if(kq != -1)
	fds_kqueue_set(fdn, EVFILT_WRITE, EV_ADD);
#endif

#ifdef HAVE_EPOLL
      if(ep != -1)
	fds_epoll_ctl(fdn, EPOLLOUT, EPOLL_CTL_ADD);
#endif

      /*
       * the fd may still be on the write fds list, just with the inactive bit
       * set.  if it isn't, then we have to put it on the queue.
       */
      if(fdn->write.list != write_fds)
	{
	  dlist_node_head_push(write_queue, fdn->write.node);
	  fdn->write.list = write_queue;
	}
    }

  return;
}

void scamper_fd_read_set(scamper_fd_t *fdn, scamper_fd_cb_t cb, void *param)
{
  assert(fdn->type == SCAMPER_FD_TYPE_PRIVATE);
  fdn->read.cb = cb;
  fdn->read.param = param;
  return;
}

void scamper_fd_write_set(scamper_fd_t *fdn, scamper_fd_cb_t cb, void *param)
{
  assert(fdn->type == SCAMPER_FD_TYPE_PRIVATE);
  fdn->write.cb = cb;
  fdn->write.param = param;
  return;
}

scamper_fd_t *scamper_fd_icmp4(void *addr)
{
  scamper_fd_t *fdn;

  if((fdn = fd_icmp(SCAMPER_FD_TYPE_ICMP4, addr)) != NULL)
    {
      fdn->read.cb = scamper_icmp4_read_cb;
      scamper_fd_read_unpause(fdn);
    }

  return fdn;
}

scamper_fd_t *scamper_fd_icmp6(void *addr)
{
  scamper_fd_t *fdn;

  if((fdn = fd_icmp(SCAMPER_FD_TYPE_ICMP6, addr)) != NULL)
    {
      fdn->read.cb = scamper_icmp6_read_cb;
      scamper_fd_read_unpause(fdn);
    }

  return fdn;
}

#ifndef _WIN32
scamper_fd_t *scamper_fd_rtsock(void)
{
  scamper_fd_t *fdn;

  if((fdn = fd_null(SCAMPER_FD_TYPE_RTSOCK)) != NULL)
    {
      fdn->read.cb = scamper_rtsock_read_cb;
      scamper_fd_read_unpause(fdn);
    }

  return fdn;
}
#endif

scamper_fd_t *scamper_fd_tcp4(void *addr, uint16_t sport)
{
  return fd_tcp(SCAMPER_FD_TYPE_TCP4, addr, sport);
}

scamper_fd_t *scamper_fd_tcp6(void *addr, uint16_t sport)
{
  return fd_tcp(SCAMPER_FD_TYPE_TCP6, addr, sport);
}

scamper_fd_t *scamper_fd_udp4(void *addr, uint16_t sport)
{
  scamper_fd_t *fd;

  if((fd = fd_udp(SCAMPER_FD_TYPE_UDP4DG, addr, sport)) == NULL)
    return NULL;

  if(fd->raw == NULL)
    {
      if((fd->raw = fd_udp(SCAMPER_FD_TYPE_UDP4, addr, sport)) == NULL)
	{
	  scamper_fd_free(fd);
	  return NULL;
	}
    }
  return fd;
}

scamper_fd_t *scamper_fd_udp6(void *addr, uint16_t sport)
{
  return fd_udp(SCAMPER_FD_TYPE_UDP6, addr, sport);
}

scamper_fd_t *scamper_fd_ip4(void)
{
  return fd_null(SCAMPER_FD_TYPE_IP4);
}

#ifndef _WIN32
scamper_fd_t *scamper_fd_ifsock(void)
{
  return fd_null(SCAMPER_FD_TYPE_IFSOCK);
}
#endif

scamper_fd_t *scamper_fd_dl(int ifindex)
{
  scamper_fd_t *fdn = NULL, findme;
  int fd = -1;

  findme.type = SCAMPER_FD_TYPE_DL;
  findme.fd_dl_ifindex = ifindex;

  if((fdn = fd_find(&findme)) != NULL)
    {
      scamper_fd_read_unpause(fdn);
      return fdn;
    }

  /*
   * open the file descriptor for the ifindex, and then allocate a scamper_fd
   * for the file descriptor
   */
  if((fd  = scamper_dl_open(ifindex)) == -1 ||
     (fdn = fd_alloc(SCAMPER_FD_TYPE_DL, fd)) == NULL)
    {
      goto err;
    }

  /*
   * record the ifindex for the file descriptor, and then allocate the state
   * that is maintained with it
   */
  fdn->fd_dl_ifindex = ifindex;

  /*
   * 1. add the file descriptor to the splay tree
   * 2. allocate state for the datalink file descriptor
   */
  if((fdn->fd_tree_node = splaytree_insert(fd_tree, fdn)) == NULL ||
     (fdn->fd_list_node = dlist_tail_push(fd_list, fdn)) == NULL ||
     (fdn->fd_dl_dl = scamper_dl_state_alloc(fdn)) == NULL)
    {
      goto err;
    }

  /* set the file descriptor up for reading */
  fdn->read.cb     = scamper_dl_read_cb;
  fdn->read.param  = fdn->fd_dl_dl;
  fdn->write.cb    = NULL;
  fdn->write.param = NULL;
  scamper_fd_read_unpause(fdn);

  scamper_debug(__func__, "fd %d type %s", fdn->fd, fd_tostr(fdn));
  return fdn;

 err:
  if(fdn != NULL) free(fdn);
  if(fd != -1) scamper_dl_close(fd);
  return NULL;
}

/*
 * scamper_fd_private
 *
 * allocate a private fd for scamper to manage.  this fd is not shared amongst
 * scamper.
 */
scamper_fd_t *scamper_fd_private(int fd, void *param, scamper_fd_cb_t read_cb,
				 scamper_fd_cb_t write_cb)
{
  scamper_fd_t *fdn = NULL;

  if((fdn = fd_alloc(SCAMPER_FD_TYPE_PRIVATE, fd)) == NULL)
    {
      goto err;
    }

  if((fdn->fd_list_node = dlist_tail_push(fd_list, fdn)) == NULL)
    goto err;

  if(read_cb != NULL)
    {
      scamper_fd_read_set(fdn, read_cb, param);
      scamper_fd_read_unpause(fdn);
    }

  if(write_cb != NULL)
    {
      scamper_fd_write_set(fdn, write_cb, param);
      scamper_fd_write_unpause(fdn);
    }

  return fdn;

 err:
  if(fdn != NULL) fd_free(fdn);
  return NULL;
}

scamper_fd_t *scamper_fd_file(int fd, scamper_fd_cb_t read_cb, void *param)
{
  scamper_fd_t *fdn = NULL;

  if((fdn = fd_alloc(SCAMPER_FD_TYPE_FILE, fd)) == NULL ||
     (fdn->fd_list_node = dlist_tail_push(fd_list, fdn)) == NULL)
    goto err;
  fdn->read.cb = read_cb;
  fdn->read.param = param;
  scamper_fd_read_unpause(fdn);

  return fdn;

 err:
  if(fdn != NULL) fd_free(fdn);
  return NULL;
}

/*
 * scamper_fd_ifindex
 *
 * if the file descriptor is associated with a known ifindex, return details
 * of it.
 */
int scamper_fd_ifindex(const scamper_fd_t *fdn, int *ifindex)
{
  if(fdn->type == SCAMPER_FD_TYPE_DL)
    {
      *ifindex = fdn->fd_dl_ifindex;
      return 0;
    }

  return -1;
}

scamper_dl_t *scamper_fd_dl_get(const scamper_fd_t *fdn)
{
  assert(fdn != NULL);
  assert(fdn->type == SCAMPER_FD_TYPE_DL);
  return fdn->fd_dl_dl;
}

/*
 * scamper_fd_addr
 *
 * if the file descriptor is bound to an address, return details of it.
 * -1 if invalid parameters.  0 if not bound.  1 if bound.
 */
int scamper_fd_addr(const scamper_fd_t *fdn, void *addr, size_t len)
{
  void  *a;
  size_t l;

  switch(fdn->type)
    {
    case SCAMPER_FD_TYPE_UDP4:   a = fdn->fd_udp_addr;  l = 4;  break;
    case SCAMPER_FD_TYPE_UDP4DG: a = fdn->fd_udp_addr;  l = 4;  break;
    case SCAMPER_FD_TYPE_UDP6:   a = fdn->fd_udp_addr;  l = 16; break;
    case SCAMPER_FD_TYPE_TCP4:   a = fdn->fd_tcp_addr;  l = 4;  break;
    case SCAMPER_FD_TYPE_TCP6:   a = fdn->fd_tcp_addr;  l = 16; break;
    case SCAMPER_FD_TYPE_ICMP4:  a = fdn->fd_icmp_addr; l = 4;  break;
    case SCAMPER_FD_TYPE_ICMP6:  a  = fdn->fd_icmp_addr; l = 16; break;
    default: return -1;
    }

  if(len < l)
    return -1;
  if(a == NULL)
    return 0;
  memcpy(addr, a, l);
  return 1;
}

/*
 * scamper_fd_sport
 *
 * if the file descriptor has a known source port, return details of it.
 */
int scamper_fd_sport(const scamper_fd_t *fdn, uint16_t *sport)
{
  if(SCAMPER_FD_TYPE_IS_UDP(fdn))
    {
      *sport = fdn->fd_udp_sport;
      return 0;
    }
  else if(SCAMPER_FD_TYPE_IS_TCP(fdn))
    {
      *sport = fdn->fd_tcp_sport;
      return 0;
    }
  return -1;
}

/*
 * scamper_fd_free
 *
 * this function reduces the reference count for a given file descriptor.
 *
 * if zero is reached, the fd will be dealt with when scamper_fd_poll is next
 * called.  the fd cannot be summarily removed here without the potential
 * to screw up any current call to scamper_fd_poll as that function assumes
 * the list remains intact for the duration of any events found with select.
 *
 */
void scamper_fd_free(scamper_fd_t *fdn)
{
  assert(fdn != NULL);
  assert(fdn->refcnt > 0);

  if(--fdn->refcnt == 0)
    {
      if(fdn->raw != NULL)
	{
	  scamper_fd_free(fdn->raw);
	  fdn->raw = NULL;
	}
      fd_refcnt_0(fdn);
    }

  return;
}

/*
 * alloc_list
 *
 * helper function to allocate a list for scamper_fds_init
 */
static dlist_t *alloc_list(char *name)
{
  dlist_t *list;
  if((list = dlist_alloc()) == NULL)
    printerror(__func__, "alloc %s failed", name);
  return list;
}

/*
 * scamper_fds_init
 *
 * setup the global data structures necessary for scamper to manage a set of
 * file descriptors
 */
int scamper_fds_init()
{
#ifdef HAVE_GETDTABLESIZE
  scamper_debug(__func__, "fd table size: %d", getdtablesize());
#endif

#ifdef HAVE_POLL
  pollfunc = fds_poll;
#endif

#ifdef HAVE_KQUEUE
  if(scamper_option_kqueue())
    {
      pollfunc = fds_kqueue;
      if(fds_kqueue_init() != 0)
	return -1;
    }
#endif

#ifdef HAVE_EPOLL
  if(scamper_option_epoll())
    {
      pollfunc = fds_epoll;
      if(fds_epoll_init() != 0)
	return -1;
    }
#endif

  if(scamper_option_select() || pollfunc == NULL)
    pollfunc = fds_select;

  if((fd_list     = alloc_list("fd_list")) == NULL ||
     (read_fds    = alloc_list("read_fds"))   == NULL ||
     (read_queue  = alloc_list("read_queue"))  == NULL ||
     (write_fds   = alloc_list("write_fds"))  == NULL ||
     (write_queue = alloc_list("write_queue")) == NULL ||
     (refcnt_0    = alloc_list("refcnt_0"))  == NULL)
    {
      return -1;
    }

  if((fd_tree = splaytree_alloc((splaytree_cmp_t)fd_cmp)) == NULL)
    {
      printerror(__func__, "alloc fd tree failed");
      return -1;
    }

  return 0;
}

/*
 * cleanup_list
 *
 * helper function to remove scamper_fd_poll structures from any lists.
 */
static void cleanup_list(dlist_t *list)
{
  scamper_fd_poll_t *poll;

  if(list == NULL) return;

  while((poll = dlist_head_pop(list)) != NULL)
    {
      poll->list = NULL;
      poll->node = NULL;
    }

  dlist_free(list);

  return;
}

/*
 * scamper_fds_cleanup
 *
 * tidy up the state allocated to maintain fd records.
 */
void scamper_fds_cleanup()
{
  scamper_fd_t *fdn;

  /* clean up the lists */
  cleanup_list(read_fds);    read_fds = NULL;
  cleanup_list(write_fds);   write_fds = NULL;
  cleanup_list(read_queue);  read_queue = NULL;
  cleanup_list(write_queue); write_queue = NULL;

  /* reap anything on the reap list */
  if(refcnt_0 != NULL)
    {
      while((fdn = (scamper_fd_t *)dlist_head_item(refcnt_0)) != NULL)
	{
	  fd_close(fdn);
	  fd_free(fdn);
	}
      dlist_free(refcnt_0);
      refcnt_0 = NULL;
    }

  /* clean up the tree */
  if(fd_tree != NULL)
    {
      splaytree_free(fd_tree, NULL);
      fd_tree = NULL;
    }

  /* clean up the list */
  if(fd_list != NULL)
    {
      dlist_free(fd_list);
      fd_list = NULL;
    }

  /* clean up the array */
  if(fd_array != NULL)
    {
      free(fd_array);
      fd_array = NULL;
    }

#ifdef HAVE_POLL
  if(poll_fds != NULL)
    {
      free(poll_fds);
      poll_fds = NULL;
    }
#endif

#ifdef HAVE_KQUEUE
  if(kq != -1)
    {
      close(kq);
      kq = -1;
    }
  if(kevlist != NULL)
    {
      free(kevlist);
      kevlist = NULL;
    }
#endif

#ifdef HAVE_EPOLL
  if(ep != -1)
    {
      close(ep);
      ep = -1;
    }
  if(ep_events != NULL)
    {
      free(ep_events);
      ep_events = NULL;
    }
#endif

  return;
}
