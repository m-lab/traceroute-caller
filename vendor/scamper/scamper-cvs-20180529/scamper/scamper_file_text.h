/*
 * scamper_file_text.h
 *
 * $Id: scamper_file_text.h,v 1.16 2011/09/16 03:15:44 mjl Exp $
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

#ifndef _SCAMPER_FILE_TEXT_H
#define _SCAMPER_FILE_TEXT_H

struct scamper_trace;
int scamper_file_text_write_trace(const scamper_file_t *sf,
				  const struct scamper_trace *trace);

struct scamper_ping;
int scamper_file_text_write_ping(const scamper_file_t *sf,
				 const struct scamper_ping *ping);

struct scamper_tracelb;
int scamper_file_text_write_tracelb(const scamper_file_t *sf,
				    const struct scamper_tracelb *trace);

struct scamper_sting;
int scamper_file_text_write_sting(const scamper_file_t *sf,
				  const struct scamper_sting *sting);

struct scamper_dealias;
int scamper_file_text_write_dealias(const scamper_file_t *sf,
				    const struct scamper_dealias *dealias);

struct scamper_tbit;
int scamper_file_text_write_tbit(const scamper_file_t *sf,
				 const struct scamper_tbit *tbit);

int scamper_file_text_is(const scamper_file_t *sf);

#endif /* _SCAMPER_FILE_TEXT_H */
