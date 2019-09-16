/*
 * scamper_rtsock.h
 *
 * $Id: scamper_rtsock.h,v 1.18 2012/05/08 17:01:11 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
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

#ifndef __SCAMPER_RTSOCK_H
#define __SCAMPER_RTSOCK_H

int scamper_rtsock_init(void);
void scamper_rtsock_cleanup(void);

int scamper_rtsock_roundup(size_t len);

typedef struct scamper_route scamper_route_t;

#ifdef __SCAMPER_ADDR_H
scamper_route_t *scamper_route_alloc(scamper_addr_t *dst, void *param,
				     void (*cb)(scamper_route_t *rt));
#endif
void scamper_route_free(scamper_route_t *route);

#ifndef _WIN32
int scamper_rtsock_open(void);
int scamper_rtsock_open_fd(void);
void scamper_rtsock_read_cb(const int fd, void *param);
void scamper_rtsock_close(int fd);
#endif

#if defined(_WIN32)
int scamper_rtsock_getroute(scamper_route_t *route);
#elif defined(__SCAMPER_FD_H)
int scamper_rtsock_getroute(scamper_fd_t *fd, scamper_route_t *route);
#endif

#if defined(__SCAMPER_ADDR_H)
struct scamper_route
{
  /*
   * parameters supplied on input:
   *  - destination address to look up,
   *  - function to call back with a result,
   *  - parameter that the caller can set for its own use.
   */
  scamper_addr_t  *dst;
  void           (*cb)(scamper_route_t *rt);
  void            *param;

  /*
   * result of route lookup:
   *  - gateway to use, if any,
   *  - interface to use,
   *  - an error code if the lookup failed.
   */
  scamper_addr_t *gw;
  int             ifindex;
  int             error;

  /* a pointer that is used internally by the routing code */
  void           *internal;
};
#endif

#endif /* SCAMPER_RTSOCK_H */
