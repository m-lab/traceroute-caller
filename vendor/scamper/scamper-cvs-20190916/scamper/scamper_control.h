/*
 * scamper_control.h
 *
 * $Id: scamper_control.h,v 1.11 2016/07/16 06:01:14 mjl Exp $
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

#ifndef __SCAMPER_CONTROL_H
#define __SCAMPER_CONTROL_H

int scamper_control_add_inet(const char *addr, int port);
int scamper_control_add_unix(const char *name);
int scamper_control_add_remote(const char *name, int port);

int scamper_control_init(void);
void scamper_control_cleanup(void);

#endif
