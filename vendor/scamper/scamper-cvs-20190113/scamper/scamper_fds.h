/*
 * scamper_fds: manage events for file descriptors
 *
 * $Id: scamper_fds.h,v 1.22 2015/01/04 06:20:15 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2014      Matthew Luckie
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

#ifndef __SCAMPER_FD_H
#define __SCAMPER_FD_H

/* data structure type */
typedef struct scamper_fd scamper_fd_t;

/* when an event occurs, this is the format of the callback used */
typedef void (*scamper_fd_cb_t)(const int fd, void *param);

/* these functions allocate reference to a socket shared throughout scamper */
scamper_fd_t *scamper_fd_icmp4(void *addr);
scamper_fd_t *scamper_fd_icmp6(void *addr);
scamper_fd_t *scamper_fd_udp4(void *addr, uint16_t sport);
scamper_fd_t *scamper_fd_udp6(void *addr, uint16_t sport);
scamper_fd_t *scamper_fd_tcp4(void *addr, uint16_t sport);
scamper_fd_t *scamper_fd_tcp6(void *addr, uint16_t sport);
scamper_fd_t *scamper_fd_dl(int ifindex);
scamper_fd_t *scamper_fd_ip4(void);

#ifndef _WIN32
scamper_fd_t *scamper_fd_rtsock(void);
scamper_fd_t *scamper_fd_ifsock(void);
#endif

/* return information on what the socket is bound to */
int scamper_fd_ifindex(const scamper_fd_t *fdn, int *ifindex);
int scamper_fd_sport(const scamper_fd_t *fdn, uint16_t *sport);
int scamper_fd_addr(const scamper_fd_t *fdn, void *addr, size_t len);

/* this function allocates a socket that is exclusively held by the caller */
scamper_fd_t *scamper_fd_private(int fd, void *param, scamper_fd_cb_t read_cb,
				 scamper_fd_cb_t write_cb);

scamper_fd_t *scamper_fd_file(int fd, scamper_fd_cb_t read_cb, void *param);

/*
 * this function reduces the reference count of the fdn, and closes the fd
 * if there are no remaining references
 */
void scamper_fd_free(scamper_fd_t *fdn);

/* get/set the fd associated with the structure */
int scamper_fd_fd_get(const scamper_fd_t *fdn);
int scamper_fd_fd_set(scamper_fd_t *fdn, int fd);

/* functions to temporarily unmonitor a fd, and then have it rejoin */
void scamper_fd_read_pause(scamper_fd_t *fdn);
void scamper_fd_read_unpause(scamper_fd_t *fdn);
void scamper_fd_write_pause(scamper_fd_t *fdn);
void scamper_fd_write_unpause(scamper_fd_t *fdn);

/* functions to set the callbacks used.  only works for private fds */
void scamper_fd_read_set(scamper_fd_t *fdn, scamper_fd_cb_t cb, void *param);
void scamper_fd_write_set(scamper_fd_t *fdn, scamper_fd_cb_t cb, void *param);

#ifdef __SCAMPER_DL_H
scamper_dl_t *scamper_fd_dl_get(const scamper_fd_t *fdn);
#endif

/* function to check the status of all file descriptors managed */
int scamper_fds_poll(struct timeval *timeout);

/* functions used to initialise or cleanup the fd monitoring state */
int scamper_fds_init(void);
void scamper_fds_cleanup(void);

#endif /* __SCAMPER_FD_H */
