/*
 * scamper_host_warts.h
 *
 * $Id: scamper_host_warts.h,v 1.1 2019/07/28 09:24:53 mjl Exp $
 *
 * Copyright (C) 2019 Matthew Luckie
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the replye that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef __SCAMPER_HOST_WARTS_H
#define __SCAMPER_HOST_WARTS_H

int scamper_file_warts_host_write(const scamper_file_t *sf,
				  const scamper_host_t *host);

int scamper_file_warts_host_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_host_t **host_out);

#endif
