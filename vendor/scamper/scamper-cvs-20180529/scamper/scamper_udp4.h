/*
 * scamper_udp4.h
 *
 * $Id: scamper_udp4.h,v 1.23 2015/04/23 21:57:49 mjl Exp $
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

#ifndef __SCAMPER_UDP4_H
#define __SCAMPER_UDP4_H

int scamper_udp4_openraw(const void *addr);
int scamper_udp4_openraw_fd(const void *addr);
int scamper_udp4_opendgram(const void *addr, int sport);
void scamper_udp4_close(int fd);

void scamper_udp4_cleanup(void);

#ifdef __SCAMPER_PROBE_H
int scamper_udp4_probe(scamper_probe_t *probe);
int scamper_udp4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len);
uint16_t scamper_udp4_cksum(scamper_probe_t *probe);
#endif

#endif /* __SCAMPER_UDP4_H */
