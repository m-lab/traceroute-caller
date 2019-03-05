/*
 * scamper_privsep.h
 *
 * $Id: scamper_privsep.h,v 1.25 2016/08/07 10:27:56 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2016      Matthew Luckie
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

#ifndef __SCAMPER_PRIVSEP_H
#define __SCAMPER_PRIVSEP_H

#ifndef WITHOUT_PRIVSEP

int scamper_privsep_open_datalink(const int ifindex);

int scamper_privsep_open_file(const char *file,
			      const int flags, const mode_t mode);

int scamper_privsep_open_rtsock(void);

int scamper_privsep_open_icmp(const int domain);
int scamper_privsep_open_udp(const int domain, const int port);
int scamper_privsep_open_tcp(const int domain, const int port);
int scamper_privsep_open_rawudp(const void *addr);
int scamper_privsep_open_rawip(void);
int scamper_privsep_open_unix(const char *file);

int scamper_privsep_ipfw_init(void);
int scamper_privsep_ipfw_cleanup(void);
int scamper_privsep_ipfw_add(int n,int af,int p,void *s,void *d,int sp,int dp);
int scamper_privsep_ipfw_del(int n,int af);

int scamper_privsep_pf_init(const char *anchor);
int scamper_privsep_pf_cleanup(void);
int scamper_privsep_pf_add(int n,int af,int p,void *s,void *d,int sp,int dp);
int scamper_privsep_pf_del(int n);

int scamper_privsep_unlink(const char *file);

int scamper_privsep_init(void);
void scamper_privsep_cleanup(void);

#endif

#endif
