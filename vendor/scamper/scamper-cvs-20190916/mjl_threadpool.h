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
 * $Id: mjl_threadpool.h,v 1.1 2019/09/16 04:09:14 mjl Exp $
 *
 */

#ifndef __MJL_THREADPOOL_H
#define __MJL_THREADPOOL_H

typedef struct threadpool threadpool_t;
typedef void (*threadpool_func_t)(void *);

#ifndef DMALLOC
threadpool_t *threadpool_alloc(int threadc);
int threadpool_tail_push(threadpool_t *tp, threadpool_func_t func,void *param);
#else
threadpool_t *threadpool_alloc_dm(int threadc,
				  const char *file, const int line);
int threadpool_tail_push_dm(threadpool_t *tp, threadpool_func_t func,
			    void *param,  const char *file, const int line);

#define threadpool_alloc(threadc) \
  threadpool_alloc_dm((threadc),  __FILE__, __LINE__)
#define threadpool_tail_push(tp, func, param) \
  threadpool_tail_push_dm((tp), (func), (param), __FILE__, __LINE__)
#endif

int threadpool_join(threadpool_t *tp);

#endif /* __MJL_THREADPOOL_H */
