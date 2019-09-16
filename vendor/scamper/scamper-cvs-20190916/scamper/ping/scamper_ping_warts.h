/*
 * scamper_file_warts_ping.h
 *
 * $Id: scamper_ping_warts.h,v 1.2 2011/09/16 03:15:44 mjl Exp $
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

#ifndef __SCAMPER_FILE_WARTS_PING_H
#define __SCAMPER_FILE_WARTS_PING_H

int scamper_file_warts_ping_write(const scamper_file_t *sf,
				  const scamper_ping_t *ping);
int scamper_file_warts_ping_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_ping_t **ping_out);

#endif
