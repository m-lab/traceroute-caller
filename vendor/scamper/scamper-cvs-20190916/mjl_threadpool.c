/*
 * Thread Pool routines
 *
 * Copyright (C) 2018 Matthew Luckie. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Matthew Luckie ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Matthew Luckie BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: mjl_threadpool.c,v 1.1 2019/09/16 04:09:14 mjl Exp $
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "mjl_threadpool.h"

#ifdef HAVE_PTHREAD
typedef struct threadpool_task threadpool_task_t;
struct threadpool_task
{
  threadpool_func_t  func;
  void              *ptr;
  threadpool_task_t *next;
};
#endif

struct threadpool
{
  long               threadc;
#ifdef HAVE_PTHREAD
  pthread_t         *threads;
  pthread_mutex_t    mutex;
  pthread_cond_t     cond;
  threadpool_task_t *head;
  threadpool_task_t *tail;
  int                stop;
  unsigned int       flags;
#endif
};

#define TP_FLAG_MUTEX 0x01
#define TP_FLAG_COND  0x02

#ifdef HAVE_PTHREAD
static void *threadpool_run(void *ptr)
{
  threadpool_t *tp = (threadpool_t *)ptr;
  threadpool_task_t *task;

  for(;;)
    {
      pthread_mutex_lock(&tp->mutex);

      /* pthread_cond_signal might wake up more than one thread */
      while(tp->head == NULL && tp->stop == 0)
	pthread_cond_wait(&tp->cond, &tp->mutex);

      /* if we've been told to stop, then stop if the task pool is empty */
      if(tp->head == NULL && tp->stop != 0)
	break;

      /* get the task to work on */
      task = tp->head;
      tp->head = tp->head->next;
      if(tp->head == NULL)
	tp->tail = NULL;

      /* release the lock to let another thread get some work */
      pthread_mutex_unlock(&tp->mutex);

      /* do the work */
      task->func(task->ptr);
      free(task);
    }

  /* we've been told to stop, release the mutex */
  pthread_mutex_unlock(&tp->mutex);
  return NULL;
}
#endif

static void threadpool_free(threadpool_t *tp)
{
#ifdef HAVE_PTHREAD
  threadpool_task_t *task;

  while((task = tp->head) != NULL)
    {
      tp->head = task->next;
      free(task);
    }

  if(tp->threads != NULL)
    free(tp->threads);

  if(tp->flags & TP_FLAG_COND)
    pthread_cond_destroy(&tp->cond);

  if(tp->flags & TP_FLAG_MUTEX)
    pthread_mutex_destroy(&tp->mutex);
#endif

  free(tp);
  return;
}

#ifdef HAVE_PTHREAD
#ifndef DMALLOC
static threadpool_task_t *threadpool_task_alloc(threadpool_func_t func,
						void *ptr)
#else
static threadpool_task_t *threadpool_task_alloc_dm(threadpool_func_t func,
						   void *ptr,
						   const char *file,
						   const int line)
#endif
{
  threadpool_task_t *task;
  size_t len = sizeof(threadpool_task_t);

#ifndef DMALLOC
  task = (threadpool_task_t *)malloc(len);
#else
  task = (threadpool_task_t *)dmalloc_malloc(file, line, len,
					     DMALLOC_FUNC_MALLOC, 0, 0);
#endif

  if(task == NULL)
    return NULL;
  task->func = func;
  task->ptr = ptr;
  return task;
}
#endif

#ifndef DMALLOC
int threadpool_tail_push(threadpool_t *tp, threadpool_func_t func, void *ptr)
#else
int threadpool_tail_push_dm(threadpool_t *tp, threadpool_func_t func,
			    void *ptr, const char *file, const int line)
#endif
{
#ifdef HAVE_PTHREAD
  threadpool_task_t *task;

  assert(tp != NULL);

  if(tp->threadc == 0)
    {
      func(ptr);
      return 0;
    }

#ifndef DMALLOC
  task = threadpool_task_alloc(func, ptr);
#else
  task = threadpool_task_alloc_dm(func, ptr, file, line);
#endif

  if(task == NULL)
    return -1;

  /* take the lock and append the task to the list */
  if(pthread_mutex_lock(&tp->mutex) != 0)
    {
      free(task);
      return -1;
    }
  if(tp->tail != NULL)
    tp->tail->next = task;
  else
    tp->tail = tp->head = task;
  task->next = NULL;
  tp->tail = task;
  task = NULL;

  /* signal to the thread pool that there's a task waiting */
  if(pthread_cond_signal(&tp->cond) != 0)
    return -1;

  /* release the mutex to allow a thread to take it up */
  if(pthread_mutex_unlock(&tp->mutex) != 0)
    return -1;
#else
  func(ptr);
#endif

  return 0;
}

/*
 * threadpool_join:
 *
 * signal to the threads that there is nothing left to do, and wait
 * for them to complete work
 */
int threadpool_join(threadpool_t *tp)
{
#ifdef HAVE_PTHREAD
  int i;

  if(tp->threadc > 0)
    {
      assert(tp->threads != NULL);
      assert((tp->flags & TP_FLAG_MUTEX) != 0);
      assert((tp->flags & TP_FLAG_COND) != 0);

      /* take the mutex to set the stop variable */
      if(pthread_mutex_lock(&tp->mutex) != 0)
	return -1;

      /* set the stop flag and wake up all the worker threads */
      assert(tp->stop == 0);
      tp->stop = 1;
      if(pthread_cond_broadcast(&tp->cond) != 0)
	return -1;

      /* release the mutex to allow other threads to proceed */
      if(pthread_mutex_unlock(&tp->mutex) != 0)
	return -1;

      /* wait for all threads to stop */
      for(i=0; i<tp->threadc; i++)
	if(pthread_join(tp->threads[i], NULL) != 0)
	  return -1;
    }
#endif

  threadpool_free(tp);
  return 0;
}

#ifndef DMALLOC
threadpool_t *threadpool_alloc(int threadc)
#else
threadpool_t *threadpool_alloc_dm(int threadc,const char *file,const int line)
#endif
{
  threadpool_t *tp = NULL;
  size_t len;

  if(threadc < 0)
    return NULL;

#ifndef HAVE_PTHREAD
  if(threadc > 0)
    return NULL;
#endif

  len = sizeof(threadpool_t);
#ifndef DMALLOC
  tp = (threadpool_t *)malloc(len);
#else
  tp = (threadpool_t *)dmalloc_malloc(file,line,len,DMALLOC_FUNC_MALLOC,0,0);
#endif
  if(tp == NULL)
    goto err;

  tp->threadc = 0;

#ifdef HAVE_PTHREAD
  tp->threads = NULL;
  tp->head = NULL;
  tp->tail = NULL;
  tp->flags = 0;
  tp->stop = 0;

  if(pthread_mutex_init(&tp->mutex, NULL) != 0)
    goto err;
  tp->flags |= TP_FLAG_MUTEX;

  if(pthread_cond_init(&tp->cond, NULL) != 0)
    goto err;
  tp->flags |= TP_FLAG_COND;

  len = sizeof(pthread_t) * threadc;
#ifndef DMALLOC
  tp->threads = (pthread_t *)malloc(len);
#else
  tp->threads = (pthread_t *)dmalloc_malloc(file, line, len,
					    DMALLOC_FUNC_MALLOC, 0, 0);
#endif
  if(tp->threads == NULL)
    goto err;

  /* create the pool of threads that will get work done */
  while(tp->threadc < threadc)
    {
      if(pthread_create(&tp->threads[tp->threadc],NULL,threadpool_run,tp) != 0)
	goto err;
      tp->threadc++;
    }
#endif

  return tp;

 err:
  if(tp != NULL) threadpool_join(tp);
  return NULL;
}
