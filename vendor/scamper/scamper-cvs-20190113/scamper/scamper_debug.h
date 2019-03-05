/*
 * scamper_debug.h
 *
 * $Id: scamper_debug.h,v 1.19 2017/12/03 09:38:26 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2009 The University of Waikato
 * Copyright (C) 2015,2017 Matthew Luckie
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

#ifndef __SCAMPER_DEBUG_H
#define __SCAMPER_DEBUG_H

void printerror(const char *func, const char *format, ...);
void printerror_gai(const char *func, int ecode, const char *format, ...);
void printerror_msg(const char *func, const char *format, ...);

#ifdef NDEBUG
#define scamper_assert(expr, task) ((void)0)
#else
#define scamper_assert(expr, task) ((expr) ? (void)0 : \
      __scamper_assert(__FILE__,__LINE__,__FUNC__, #expr, task))
void __scamper_assert(const char *file, int line, const char *func,
		      const char *expr, void *task);
#endif

/* only define scamper_debug if scamper is being built in debugging mode */
#if defined(NDEBUG) && defined(WITHOUT_DEBUGFILE)
#define scamper_debug(func, format, ...) ((void)0)
#else
#define HAVE_SCAMPER_DEBUG
void scamper_debug(const char *func, const char *format, ...);
#endif

#ifndef WITHOUT_DEBUGFILE
int scamper_debug_open(const char *debugfile);
void scamper_debug_close(void);
#endif

void scamper_debug_init(void);

#endif /* scamper_debug.h */
