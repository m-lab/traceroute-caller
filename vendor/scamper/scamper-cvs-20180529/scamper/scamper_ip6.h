/*
 * scamper_ip6.h
 *
 * $Id: scamper_ip6.h,v 1.7 2011/09/20 06:48:48 mjl Exp $
 *
 * Copyright (C) 2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
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

#ifndef __SCAMPER_IP6_H
#define __SCAMPER_IP6_H

int scamper_ip6_build(scamper_probe_t *probe, uint8_t *buf, size_t *len);
int scamper_ip6_hlen(scamper_probe_t *probe, size_t *ip6hlen);
int scamper_ip6_frag_build(scamper_probe_t *probe, uint8_t *buf, size_t *len);

#endif /* __SCAMPER_IP6_H */
