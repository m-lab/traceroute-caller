/*
 * scamper_dlhdr.h
 *
 * $Id: scamper_dlhdr.h,v 1.5 2012/04/05 18:00:54 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
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

#ifndef __SCAMPER_DLHDR_H
#define __SCAMPER_DLHDR_H

int scamper_dlhdr_init(void);
void scamper_dlhdr_cleanup(void);

typedef struct scamper_dlhdr scamper_dlhdr_t;

scamper_dlhdr_t *scamper_dlhdr_alloc(void);
void scamper_dlhdr_free(scamper_dlhdr_t *dlhdr);

int scamper_dlhdr_get(scamper_dlhdr_t *dlhdr);

#if defined(__SCAMPER_ADDR_H)
/*
 * scamper_dlhdr
 *
 * this struct holds appropriate layer-2 headers to prepend on a packet
 * to be transmitted with a datalink socket.
 */
struct scamper_dlhdr
{
  /*
   * parameters supplied on input:
   *  - final destination of our packet,
   *  - address of the gateway to use,
   *  - interface index,
   *  - type of interface,
   *  - callback to use when we have a dlhdr result,
   *  - parameter that the caller can set for its own use.
   */
  scamper_addr_t *dst;
  scamper_addr_t *gw;
  int             ifindex;
  int             txtype;
  void          (*cb)(scamper_dlhdr_t *);
  void           *param;

  /*
   * result of dlhdr process:
   *  - if there was no error (zero) or not,
   *  - the header to include, and its length, if any.
   */
  int             error;
  uint8_t        *buf;
  uint16_t        len;

  /* a pointer that is used internally by the dlhdr code */
  void           *internal;
};
#endif

#endif /* __SCAMPER_DLHDR_H */
