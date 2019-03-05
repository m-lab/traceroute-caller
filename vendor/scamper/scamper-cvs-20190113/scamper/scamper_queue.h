/*
 * scamper_queue.h
 *
 * $Id: scamper_queue.h,v 1.16 2016/07/15 09:16:27 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2015-2016 Matthew Luckie
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

#ifndef __SCAMPER_QUEUE_H
#define __SCAMPER_QUEUE_H

typedef struct scamper_queue scamper_queue_t;

typedef int (*scamper_queue_event_cb_t)(void *param);

/*
 * a scamper task can be in one of the following queues at any one time
 *
 * the probe queue is for storing tasks that are ready to be probed now.
 * the wait queue is for storing tasks that have to wait a particular amount
 * of time before timing out and going back into the probe queue.
 * the done queue is for storing tasks that have completed and will not
 * go back into the probe queue.  some tasks may have to spend some amount
 * of time in the done queue before being taken out.
 */
int scamper_queue_probe(scamper_queue_t *queue);
int scamper_queue_probe_head(scamper_queue_t *sq);
int scamper_queue_wait(scamper_queue_t *queue, int msec);
int scamper_queue_done(scamper_queue_t *queue, int msec);
int scamper_queue_wait_tv(scamper_queue_t *queue, const struct timeval *tv);

int scamper_queue_isprobe(scamper_queue_t *queue);
int scamper_queue_iswait(scamper_queue_t *queue);
int scamper_queue_isdone(scamper_queue_t *queue);

scamper_queue_t *scamper_queue_alloc(scamper_task_t *task);
void scamper_queue_free(scamper_queue_t *queue);

/* if a node needs to be removed from a queue, this function will do that */
void scamper_queue_detach(scamper_queue_t *queue);

/* get the next task to do something with */
struct scamper_task *scamper_queue_select(void);

/* get the next task that is completed and ready to be written out */
struct scamper_task *scamper_queue_getdone(const struct timeval *tv);

/* return the time that the first task on the queue will time out */
int scamper_queue_waittime(struct timeval *tv);

/* return the number of tasks in the various queues */
int scamper_queue_count(void);

/* return the number of tasks that are ready to be probed now */
int scamper_queue_readycount(void);

/* return the number of tasks in the probe and wait queues */
int scamper_queue_windowcount(void);

/* flush the queues of all non-completed tasks */
void scamper_queue_empty(void);

/* put things on the event queue, which are not probe related */
int scamper_queue_event_waittime(struct timeval *tv);
int scamper_queue_event_proc(const struct timeval *tv);
scamper_queue_t *scamper_queue_event(const struct timeval *tv,
				     scamper_queue_event_cb_t cb, void *ptr);
int scamper_queue_event_update_time(scamper_queue_t *sq,
				    const struct timeval *tv);
void scamper_queue_event_update_cb(scamper_queue_t *sq,
				   scamper_queue_event_cb_t cb, void *ptr);

int scamper_queue_init(void);
void scamper_queue_cleanup(void);

#endif /* __SCAMPER_QUEUE_H */
