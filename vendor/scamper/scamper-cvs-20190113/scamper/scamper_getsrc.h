/*
 * scamper_getsrc.h
 *
 * $Id: scamper_getsrc.h,v 1.5 2011/09/16 03:15:44 mjl Exp $
 *
 * Copyright (C) 2005 Matthew Luckie
 * Copyright (C) 2008-2009 University of Waikato
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

#ifndef __SCAMPER_GETSRC_H
#define __SCAMPER_GETSRC_H

scamper_addr_t *scamper_getsrc(const scamper_addr_t *dst, int ifindex);
int scamper_getsrc_init(void);
void scamper_getsrc_cleanup(void);

#endif /* __SCAMPER_GETSRC_H */
