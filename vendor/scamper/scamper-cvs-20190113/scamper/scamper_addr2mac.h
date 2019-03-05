/*
 * scamper_addr2mac.h: an implementation of two neighbour discovery methods
 *
 * $Id: scamper_addr2mac.h,v 1.8 2011/09/16 03:15:43 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2009 The University of Waikato
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

#ifndef __SCAMPER_ADDR2MAC_H
#define __SCAMPER_ADDR2MAC_H

scamper_addr_t *scamper_addr2mac_whohas(const int ifindex,scamper_addr_t *dst);
int scamper_addr2mac_add(int ifindex, scamper_addr_t *ip, scamper_addr_t *mac);
int scamper_addr2mac_init(void);
void scamper_addr2mac_cleanup(void);

#endif /* __SCAMPER_ADDR2MAC_H */
