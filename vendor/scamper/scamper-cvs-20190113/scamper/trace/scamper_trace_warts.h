/*
 * scamper_trace_warts.h
 *
 * $Id: scamper_trace_warts.h,v 1.3 2011/09/16 03:15:44 mjl Exp $
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

#ifndef __SCAMPER_TRACE_WARTS_H
#define __SCAMPER_TRACE_WARTS_H

int scamper_file_warts_trace_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				  struct scamper_trace **trace_out);

int scamper_file_warts_trace_write(const scamper_file_t *sf,
				   const struct scamper_trace *trace);

#endif
