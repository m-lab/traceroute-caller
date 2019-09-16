/*
 * scamper_queue.c
 *
 * $Id: scamper_queue.c,v 1.43 2017/12/03 09:38:27 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
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

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_queue.c,v 1.43 2017/12/03 09:38:27 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_task.h"
#include "scamper_queue.h"
#include "scamper_debug.h"
#include "utils.h"
#include "mjl_list.h"
#include "mjl_heap.h"

struct scamper_queue
{
  /* when the scamper task should timeout from whatever queue it is on */
  struct timeval            timeout;

  /* the current queue (and associated node) the task is in */
  void                     *queue;
  void                     *node;

  union
  {
    struct scamper_task    *task;
    void                   *ptr;
  } un;

  scamper_queue_event_cb_t  cb;
};

static dlist_t *probe_queue = NULL;
static heap_t  *wait_queue = NULL;
static heap_t  *done_queue = NULL;
static heap_t  *event_queue = NULL;
static int      count = 0;

static int queue_cmp(const scamper_queue_t *a, const scamper_queue_t *b)
{
  return timeval_cmp(&b->timeout, &a->timeout);
}

static void queue_onremove(void *item)
{
  scamper_queue_t *sq = item;
  sq->queue = NULL;
  sq->node = NULL;
  return;
}

/*
 * queue_unlink
 *
 * detach a task from whichever queue it is in
 */
static void queue_unlink(scamper_queue_t *sq)
{
  if(sq->queue == NULL)
    return;

  if(sq->queue == probe_queue)
    dlist_node_pop(sq->queue, sq->node);
  else if(sq->queue == wait_queue || sq->queue == done_queue ||
	  sq->queue == event_queue)
    heap_delete(sq->queue, sq->node);

  count--;
  return;
}

/*
 * queue_link
 *
 * given a task and a queue to insert it in, put the task into the queue.
 * to is a timeout value of when the task should be removed from the queue.
 */
static int queue_link(scamper_queue_t *sq, void *queue)
{
  void *node;

  assert(sq->queue == NULL);
  assert(sq->node  == NULL);

  /* now, put it in the correct queue */
  if(queue == probe_queue)
    {
      node = dlist_tail_push(queue, sq);
    }
  else
    {
      assert(queue == wait_queue || queue == done_queue);
      node = heap_insert(queue, sq);
    }

  /* ensure we've got a node */
  if(node != NULL)
    {
      sq->queue = queue;
      sq->node  = node;
      count++;
      return 0;
    }

  return -1;
}

/*
 * scamper_queue_event_waittime
 *
 * report the earliest event time on the event queue.
 */
int scamper_queue_event_waittime(struct timeval *tv)
{
  scamper_queue_t *sq;

  if((sq = (scamper_queue_t *)heap_head_item(event_queue)) != NULL)
    {
      timeval_cpy(tv, &sq->timeout);
      return 1;
    }

  return 0;
}

/*
 * scamper_queue_event_proc
 *
 * process all events on the queue whose time has come.
 */
int scamper_queue_event_proc(const struct timeval *tv)
{
  scamper_queue_t *sq = heap_head_item(event_queue);

  while(sq != NULL && timeval_cmp(tv, &sq->timeout) >= 0)
    {
      heap_remove(event_queue);
      if(sq->cb(sq->un.ptr) != 0)
	return -1;
      sq = heap_head_item(event_queue);
    }

  return 0;
}

/*
 * scamper_queue_event_update
 *
 * update the event time on the queued event
 */
int scamper_queue_event_update_time(scamper_queue_t *sq,
				    const struct timeval *tv)
{
  assert(sq->queue == NULL || sq->queue == event_queue);
  timeval_cpy(&sq->timeout, tv);

  if(sq->queue == NULL)
    {
      if((sq->node = heap_insert(event_queue, sq)) == NULL)
	{
	  printerror(__func__, "could not add to heap");
	  return -1;
	}
      sq->queue = event_queue;
    }
  else
    {
      heap_remake(event_queue);
    }
  return 0;
}

void scamper_queue_event_update_cb(scamper_queue_t *sq,
				   scamper_queue_event_cb_t cb, void *ptr)
{
  sq->cb = cb;
  sq->un.ptr = ptr;
  return;
}

/*
 * scamper_queue_event
 *
 * add an event to the event queue.
 */
scamper_queue_t *scamper_queue_event(const struct timeval *tv,
				     scamper_queue_event_cb_t cb, void *ptr)
{
  scamper_queue_t *sq = NULL;

  if((sq = malloc_zero(sizeof(scamper_queue_t))) == NULL)
    {
      printerror(__func__, "could not alloc sq");
      goto err;
    }
  timeval_cpy(&sq->timeout, tv);
  sq->queue = event_queue;
  sq->un.ptr = ptr;
  sq->cb = cb;
  if((sq->node = heap_insert(event_queue, sq)) == NULL)
    {
      printerror(__func__, "could add to heap");
      goto err;
    }

  return sq;

 err:
  return NULL;
}

/*
 * scamper_queue_probe_head
 *
 * special function to put a particular task at the head of the probe
 * queue for immediate attention.  this function should be used sparingly.
 */
int scamper_queue_probe_head(scamper_queue_t *sq)
{
  dlist_node_t *node;

  queue_unlink(sq);

  if((node = dlist_head_push(probe_queue, sq)) == NULL)
    {
      printerror(__func__, "could not push node");
      return -1;
    }

  sq->queue = probe_queue;
  sq->node  = node;
  count++;
  return 0;
}

int scamper_queue_probe(scamper_queue_t *sq)
{
  queue_unlink(sq);
  return queue_link(sq, probe_queue);
}

int scamper_queue_isprobe(scamper_queue_t *sq)
{
  if(sq->queue == probe_queue)
    return 1;
  return 0;
}

int scamper_queue_wait(scamper_queue_t *sq, int msec)
{
  queue_unlink(sq);
  gettimeofday_wrap(&sq->timeout);
  timeval_add_ms(&sq->timeout, &sq->timeout, msec);
  return queue_link(sq, wait_queue);
}

int scamper_queue_iswait(scamper_queue_t *sq)
{
  if(sq->queue == wait_queue)
    return 1;
  return 0;
}

int scamper_queue_wait_tv(scamper_queue_t *sq, const struct timeval *tv)
{
  queue_unlink(sq);
  timeval_cpy(&sq->timeout, tv);
  return queue_link(sq, wait_queue);
}

int scamper_queue_done(scamper_queue_t *sq, int msec)
{
  queue_unlink(sq);
  gettimeofday_wrap(&sq->timeout);
  timeval_add_ms(&sq->timeout, &sq->timeout, msec);
  return queue_link(sq, done_queue);
}

int scamper_queue_isdone(scamper_queue_t *sq)
{
  if(sq->queue == done_queue)
    return 1;
  return 0;
}

void scamper_queue_detach(scamper_queue_t *sq)
{
  queue_unlink(sq);
  return;
}

/*
 * scamper_queue_select
 *
 * return the next task in the probe queue to deal with
 */
struct scamper_task *scamper_queue_select()
{
  scamper_queue_t *sq;

  if((sq = dlist_head_pop(probe_queue)) != NULL)
    {
      count--;
      return sq->un.task;
    }

  return NULL;
}

/*
 * scamper_queue_getdone
 *
 */
struct scamper_task *scamper_queue_getdone(const struct timeval *tv)
{
  scamper_queue_t *sq;

  if((sq = (scamper_queue_t *)heap_head_item(done_queue)) == NULL)
    return NULL;

  if(timeval_cmp(tv, &sq->timeout) >= 0)
    {
      queue_unlink(sq);
      return sq->un.task;
    }

  return NULL;
}

/*
 * scamper_queue_waittime
 *
 * tell the caller how long it should wait in select before it makes a
 * pass through the queues.  note that this function does not check the
 * probe queue where something is immediately ready to be probed.
 *
 * if there is nothing in any of the queues, we return 0.  otherwise we
 * return the number of active queues and the tv parameter contains the
 * time that the first queue will have something to deal with.
 */
int scamper_queue_waittime(struct timeval *tv)
{
  scamper_queue_t *sq;
  heap_t *queues[2];
  int i, set = 0;

  queues[0] = wait_queue;
  queues[1] = done_queue;

  for(i=(sizeof(queues)/sizeof(heap_t *))-1; i >= 0; i--)
    {
      if((sq = (scamper_queue_t *)heap_head_item(queues[i])) != NULL)
	{
	  if(set == 0 || timeval_cmp(tv, &sq->timeout) > 0)
	    {
	      timeval_cpy(tv, &sq->timeout);
	      set++;
	    }
	}
    }

  return set;
}

/*
 * scamper_queue_readycount
 *
 * this function causes the wait queue to be checked to see if any of the
 * members should be punted onto the probe queue for
 * action.
 *
 * we then return the count of ready tasks, which is the count of items on
 * the probe queue.
 */
int scamper_queue_readycount()
{
  scamper_queue_t *sq;
  struct timeval tv;

  if(heap_count(wait_queue) > 0)
    {
      gettimeofday_wrap(&tv);

      /* timeout any tasks on the wait queue that are due to be probed again */
      while((sq = heap_head_item(wait_queue)) != NULL)
	{
	  if(timeval_cmp(&tv, &sq->timeout) < 0)
	    break;

	  queue_unlink(sq);

	  scamper_task_handletimeout(sq->un.task);

	  if(sq->queue == NULL)
	    queue_link(sq, probe_queue);
	}
    }

  return dlist_count(probe_queue);
}

int scamper_queue_windowcount()
{
  return dlist_count(probe_queue) + heap_count(wait_queue);
}

/*
 * scamper_queue_empty
 *
 * for whatever reason, the queue of 'active' tasks must be flushed.
 * drop all active tasks by removing them from the probe and wait queues.
 */
void scamper_queue_empty()
{
  scamper_queue_t *sq;

  while((sq = (scamper_queue_t *)heap_remove(wait_queue)) != NULL)
    count--;

  while((sq = (scamper_queue_t *)dlist_head_pop(probe_queue)) != NULL)
    count--;

  return;
}

int scamper_queue_count()
{
  return count;
}

scamper_queue_t *scamper_queue_alloc(scamper_task_t *task)
{
  scamper_queue_t *sq;
  if((sq = malloc_zero(sizeof(scamper_queue_t))) != NULL)
    sq->un.task = task;
  return sq;
}

void scamper_queue_free(scamper_queue_t *sq)
{
  if(sq == NULL)
    return;

  queue_unlink(sq);
  free(sq);
  return;
}

int scamper_queue_init()
{
  if((probe_queue = dlist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc probe_queue");
      return -1;
    }
  dlist_onremove(probe_queue, queue_onremove);

  if((wait_queue = heap_alloc((heap_cmp_t)queue_cmp)) == NULL)
    {
      printerror(__func__, "could not alloc wait_queue");
      return -1;
    }
  heap_onremove(wait_queue, queue_onremove);

  if((done_queue = heap_alloc((heap_cmp_t)queue_cmp)) == NULL)
    {
      printerror(__func__, "could not alloc done_queue");
      return -1;
    }
  heap_onremove(done_queue, queue_onremove);

  if((event_queue = heap_alloc((heap_cmp_t)queue_cmp)) == NULL)
    {
      printerror(__func__, "could not alloc event_queue");
      return -1;
    }
  heap_onremove(event_queue, queue_onremove);

  return 0;
}

void scamper_queue_cleanup()
{
  if(event_queue != NULL)
    {
      heap_free(event_queue, NULL);
      event_queue = NULL;
    }

  if(done_queue != NULL)
    {
      heap_free(done_queue, NULL);
      done_queue = NULL;
    }

  if(wait_queue != NULL)
    {
      heap_free(wait_queue, NULL);
      wait_queue = NULL;
    }

  if(probe_queue != NULL)
    {
      dlist_free(probe_queue);
      probe_queue = NULL;
    }

  return;
}
