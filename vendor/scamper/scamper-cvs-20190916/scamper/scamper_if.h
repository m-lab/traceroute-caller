/*
 * scamper_if.h
 *
 * $Id: scamper_if.h,v 1.4 2012/04/05 18:00:54 mjl Exp $
 *
 * Copyright (C) 2008-2009 The University of Waikato
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

#ifndef __SCAMPER_IF_H
#define __SCAMPER_IF_H

int scamper_if_getmtu(const int ifindex, uint16_t *ifmtu);
int scamper_if_getmac(const int ifindex, uint8_t *mac);
int scamper_if_getifindex(const char *ifname, int *ifindex);
int scamper_if_getifname(char *str, size_t len, int ifindex);
int scamper_if_getifindex_byaddr(const struct sockaddr *addr, int *ifindex);

#endif
