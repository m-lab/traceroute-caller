/*
 * scamper_writebuf.h: use in combination with select to send without blocking
 *
 * $Id: scamper_writebuf.h,v 1.16 2016/02/13 16:04:48 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
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

#ifndef __SCAMPER_WRITEBUF_H
#define __SCAMPER_WRITEBUF_H

typedef struct scamper_writebuf scamper_writebuf_t;

scamper_writebuf_t *scamper_writebuf_alloc(void);
void scamper_writebuf_free(scamper_writebuf_t *wb);

/* queue data on the writebuf */
int scamper_writebuf_send(scamper_writebuf_t *wb,const void *data,size_t len);

/* write the data currently buffered to the socket */
int scamper_writebuf_write(int fd, scamper_writebuf_t *wb);

/* return the count of bytes buffered */
size_t scamper_writebuf_len(const scamper_writebuf_t *wb);
size_t scamper_writebuf_len2(const scamper_writebuf_t *, char *, size_t);
int scamper_writebuf_gtzero(const scamper_writebuf_t *wb);

/* tell writebuf to use write() rather than socket send() */
void scamper_writebuf_usewrite(scamper_writebuf_t *wb);

#endif
