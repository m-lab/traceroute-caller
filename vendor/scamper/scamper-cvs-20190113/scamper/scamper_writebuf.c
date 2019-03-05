/*
 * scamper_writebuf.c: use in combination with select to send without blocking
 *
 * $Id: scamper_writebuf.c,v 1.46 2016/06/27 19:52:53 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
 * Copyright (C) 2014-2016 Matthew Luckie
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

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_writebuf.c,v 1.46 2016/06/27 19:52:53 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_writebuf.h"
#include "mjl_list.h"
#include "utils.h"

static int iov_max = -1;
static size_t pagesize = 8192;

/*
 * scamper_writebuf
 *
 * this is a simple struct to maintain a list of iovec structures that are
 * to be sent when the underlying fd allows.
 *
 */
struct scamper_writebuf
{
  slist_t      *iovs;
  void         *param;
  int           error;
  int           usewrite;
  struct iovec *tail;
};

static struct iovec *iov_alloc(void)
{
  struct iovec *iov;
  if((iov = malloc(sizeof(struct iovec))) == NULL)
    return NULL;
  if((iov->iov_base = malloc(pagesize)) == NULL)
    {
      free(iov);
      return NULL;
    }
  iov->iov_len = 0;
  return iov;
}

static void writebuf_iovfree(scamper_writebuf_t *wb, size_t size)
{
  slist_node_t *node;
  struct iovec *iov;
  uint8_t *bytes;

  while(size > 0)
    {
      node = slist_head_node(wb->iovs);
      iov = slist_node_item(node);

      /* if the whole iovec was used then it can be free'd */
      if(iov->iov_len <= (size_t)size)
	{
	  size -= iov->iov_len;
	  slist_head_pop(wb->iovs);
	  if(iov != wb->tail)
	    {
	      free(iov->iov_base);
	      free(iov);
	    }
	  else
	    {
	      iov->iov_len = 0;
	    }
	  continue;
	}

      /* if this iovec was only partially sent, then shift the vec */
      bytes = (uint8_t *)iov->iov_base;
      memmove(iov->iov_base, bytes + size, iov->iov_len - size);
      iov->iov_len -= size;
      break;
    }

  return;
}

#ifndef _WIN32
static int writebuf_tx(scamper_writebuf_t *wb, int fd)
{
  struct msghdr msg;
  struct iovec *iov;
  slist_node_t *node;
  ssize_t size;
  int i, iovs;

  if((iovs = slist_count(wb->iovs)) <= 0)
    return 0;

  if(wb->usewrite != 0)
    {
      while((iov = slist_head_item(wb->iovs)) != NULL)
	{
	  if((size = write(fd, iov->iov_base, iov->iov_len)) == -1)
	    {
	      if(errno == EAGAIN || errno == EINTR)
		return 0;
	      return -1;
	    }
	  writebuf_iovfree(wb, size);
	}

      return 0;
    }

  if(iovs > iov_max)
    iovs = iov_max;

  /*
   * if there is only one iovec, or we can't allocate an array large enough
   * for the backlog, then just send the first without allocating the
   * array.  otherwise, fill the array with the iovecs to send.
   */
  if(iovs == 1 || (iov = malloc(iovs * sizeof(struct iovec))) == NULL)
    {
      iov = slist_head_item(wb->iovs);
      iovs = 1;
    }
  else
    {
      node = slist_head_node(wb->iovs);
      for(i=0; i<iovs; i++)
	{
	  assert(node != NULL);
	  memcpy(&iov[i], slist_node_item(node), sizeof(struct iovec));
	  node = slist_node_next(node);
	}
    }

  /* fill out the msghdr and set the send buf to be the iovecs */
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = iov;
  msg.msg_iovlen = iovs;
  size = sendmsg(fd, &msg, 0);

  /* if we allocated an array of iovecs, then free it now */
  if(iovs > 1)
    free(iov);

  if(size == -1)
    {
      if(errno == EAGAIN || errno == EINTR)
	return 0;
      return -1;
    }

  /* free up the iovecs that have been sent */
  writebuf_iovfree(wb, size);
  return 0;
}
#endif

#ifdef _WIN32
static int writebuf_tx(scamper_writebuf_t *wb, int fd)
{
  struct iovec *iov;
  int size;

  if(slist_count(wb->iovs) == 0)
    return 0;

  iov = slist_head_item(wb->iovs);
  if((size = send(fd, iov->iov_base, iov->iov_len, 0)) == -1)
    return -1;

  if((size_t)size == iov->iov_len)
    {
      slist_head_pop(wb->iovs);
      if(iov != wb->tail)
	{
	  free(iov->iov_base);
	  free(iov);
	}
      else
	{
	  iov->iov_len = 0;
	}
    }
  else
    {
      iov->iov_len -= size;
      memmove(iov->iov_base, (uint8_t *)iov->iov_base + size, iov->iov_len);
    }

  return 0;
}
#endif

/*
 * scamper_writebuf_write
 *
 * this function is called when the fd is ready to write to.
 */
int scamper_writebuf_write(int fd, scamper_writebuf_t *wb)
{
  if(writebuf_tx(wb, fd) != 0)
    {
      wb->error = errno;
      return -1;
    }
  return 0;
}

/*
 * scamper_writebuf_gtzero
 *
 * if there are iovs to send, then we have more than zero bytes.
 */
int scamper_writebuf_gtzero(const scamper_writebuf_t *wb)
{
  if(slist_count(wb->iovs) > 0)
    return 1;
  return 0;
}

size_t scamper_writebuf_len(const scamper_writebuf_t *wb)
{
  slist_node_t *node = slist_head_node(wb->iovs);
  struct iovec *iov;
  size_t len = 0;

  while(node != NULL)
    {
      iov = slist_node_item(node);
      len += iov->iov_len;
      node = slist_node_next(node);
    }

  return len;
}

size_t scamper_writebuf_len2(const scamper_writebuf_t *wb,char *str,size_t len)
{
  slist_node_t *node;
  struct iovec *iov;
  size_t k = 0, off = 0;
  int c = 0;

  for(node=slist_head_node(wb->iovs); node != NULL; node=slist_node_next(node))
    {
      iov = slist_node_item(node);
      k += iov->iov_len;
      c++;
    }

  string_concat(str, len, &off, "%d,%d%s", k, c, (k != 0) ? ":" : "");
  for(node=slist_head_node(wb->iovs); node != NULL; node=slist_node_next(node))
    {
      iov = slist_node_item(node);
      string_concat(str, len, &off, " %d", iov->iov_len);
    }

  return k;
}

/*
 * scamper_writebuf_send
 *
 * register an iovec to send when it can be sent without blocking the
 * rest of scamper.
 */
int scamper_writebuf_send(scamper_writebuf_t *wb, const void *data, size_t len)
{
  size_t s, x;

  /* make sure there is data to send */
  if(len < 1)
    return 0;

  /*
   * an error occured last time sendmsg(2) was called which makes this
   * writebuf invalid
   */
  if(wb->error != 0)
    return -1;

  while(len > 0)
    {
      /* if the tail iovec is not on the list, put it there now */
      if(wb->tail->iov_len == 0 && slist_tail_push(wb->iovs, wb->tail) == NULL)
	return -1;

      /* figure out how many bytes to copy through to the iovec */
      s = pagesize - wb->tail->iov_len;
      if(len <= s)
	x = len;
      else
	x = s;

      /*
       * copy the bytes in, and create a new iovec if the tail iovec
       * is now full
       */
      memcpy((uint8_t *)wb->tail->iov_base + wb->tail->iov_len, data, x);
      wb->tail->iov_len += x;
      len -= x;
      data += x;
      if(wb->tail->iov_len == pagesize && (wb->tail = iov_alloc()) == NULL)
	return -1;
    }

  return 0;
}

void scamper_writebuf_usewrite(scamper_writebuf_t *wb)
{
  wb->usewrite = 1;
  return;
}

/*
 * scamper_writebuf_free
 *
 */
void scamper_writebuf_free(scamper_writebuf_t *wb)
{
  struct iovec *iov;

  if(wb == NULL)
    return;

  if(wb->iovs != NULL)
    {
      while((iov = slist_head_pop(wb->iovs)) != NULL)
	{
	  if(wb->tail != iov)
	    {
	      free(iov->iov_base);
	      free(iov);
	    }
	}
      slist_free(wb->iovs);
    }

  if(wb->tail != NULL)
    {
      free(wb->tail->iov_base);
      free(wb->tail);
    }

  free(wb);
  return;
}

/*
 * scamper_writebuf_alloc
 *
 */
scamper_writebuf_t *scamper_writebuf_alloc(void)
{
  scamper_writebuf_t *wb = NULL;

  if(iov_max == -1)
    {
#ifdef IOV_MAX
      iov_max = IOV_MAX;
#elif defined(_SC_IOV_MAX)
      iov_max = sysconf(_SC_IOV_MAX);
#else
      iov_max = 1;
#endif

#ifdef HAVE_GETPAGESIZE
      pagesize = getpagesize();
#endif
    }

  if((wb = malloc_zero(sizeof(scamper_writebuf_t))) == NULL ||
     (wb->iovs = slist_alloc()) == NULL ||
     (wb->tail = iov_alloc()) == NULL)
    goto err;
  return wb;

 err:
  scamper_writebuf_free(wb);
  return NULL;
}
