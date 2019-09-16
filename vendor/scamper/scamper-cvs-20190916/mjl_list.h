/*
 * linked list routines
 * by Matthew Luckie
 *
 * Copyright (C) 2004-2019 Matthew Luckie. All rights reserved.
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
 * $Id: mjl_list.h,v 1.41 2019/05/22 06:12:57 mjl Exp $
 *
 */

#ifndef __MJL_LIST_H
#define __MJL_LIST_H

typedef struct slist slist_t;
typedef struct dlist dlist_t;
typedef struct clist clist_t;

typedef struct slist_node slist_node_t;
typedef struct dlist_node dlist_node_t;
typedef struct clist_node clist_node_t;

typedef int (*slist_foreach_t)(void *item, void *param);
typedef int (*dlist_foreach_t)(void *item, void *param);
typedef int (*clist_foreach_t)(void *item, void *param);

typedef void (*slist_onremove_t)(void *item);
typedef void (*dlist_onremove_t)(void *item);
typedef void (*clist_onremove_t)(void *item);

typedef int (*slist_cmp_t)(const void *a, const void *b);
typedef int (*dlist_cmp_t)(const void *a, const void *b);

typedef void (*slist_free_t)(void *item);
typedef void (*dlist_free_t)(void *item);
typedef void (*clist_free_t)(void *item);

#ifndef DMALLOC
slist_t *slist_alloc(void);
slist_t *slist_dup(slist_t *list, const slist_foreach_t func, void *param);
slist_node_t *slist_head_push(slist_t *list, void *item);
slist_node_t *slist_tail_push(slist_t *list, void *item);
#endif

#ifdef DMALLOC
slist_t *slist_alloc_dm(const char *file, const int line);
slist_t *slist_dup_dm(slist_t *oldlist,const slist_foreach_t func,void *param,
		      const char *file, const int line);
slist_node_t *slist_head_push_dm(slist_t *list, void *item,
				 const char *file, const int line);
slist_node_t *slist_tail_push_dm(slist_t *list, void *item,
				 const char *file, const int line);

#define slist_alloc() slist_alloc_dm(__FILE__, __LINE__)
#define slist_dup(old,func,param) slist_dup_dm((old), (func), (param), \
					    __FILE__, __LINE__)
#define slist_head_push(list, item) slist_head_push_dm((list), (item), \
						       __FILE__, __LINE__)
#define slist_tail_push(list, item) slist_tail_push_dm((list), (item), \
						       __FILE__, __LINE__)
#endif

void slist_init(slist_t *list);
void slist_onremove(slist_t *list, slist_onremove_t onremove);
void slist_concat(slist_t *first, slist_t *second);
void *slist_head_pop(slist_t *list);
void *slist_head_item(const slist_t *list);
void *slist_tail_item(const slist_t *list);
void *slist_node_item(const slist_node_t *node);
slist_node_t *slist_head_node(const slist_t *list);
slist_node_t *slist_tail_node(const slist_t *list);
slist_node_t *slist_node_next(const slist_node_t *node);
int slist_foreach(slist_t *list, const slist_foreach_t func, void *param);
int slist_count(const slist_t *list);
int slist_qsort(slist_t *list, slist_cmp_t func);
int slist_shuffle(slist_t *list);
void slist_lock(slist_t *list);
void slist_unlock(slist_t *list);
int slist_islocked(slist_t *list);
void slist_empty(slist_t *list);
void slist_empty_cb(slist_t *list, slist_free_t func);
void slist_free(slist_t *list);
void slist_free_cb(slist_t *list, slist_free_t func);

#ifndef DMALLOC
dlist_t *dlist_alloc(void);
dlist_t *dlist_dup(dlist_t *list, const dlist_foreach_t func, void *param);
dlist_node_t *dlist_node_alloc(void *item);
dlist_node_t *dlist_head_push(dlist_t *list, void *item);
dlist_node_t *dlist_tail_push(dlist_t *list, void *item);
#else
dlist_t *dlist_alloc_dm(const char *file, const int line);
dlist_t *dlist_dup_dm(dlist_t *oldlist,const dlist_foreach_t func,void *param,
		      const char *file, const int line);
dlist_node_t *dlist_node_alloc_dm(void *item,const char *file,const int line);
dlist_node_t *dlist_head_push_dm(dlist_t *list, void *item,
				 const char *file, const int line);
dlist_node_t *dlist_tail_push_dm(dlist_t *list, void *item,
				 const char *file, const int line);
#define dlist_alloc() dlist_alloc_dm(__FILE__, __LINE__)
#define dlist_node_alloc(item) dlist_node_alloc_dm((item), __FILE__, __LINE__)
#define dlist_head_push(list,item) dlist_head_push_dm((list), (item), \
						      __FILE__, __LINE__)
#define dlist_tail_push(list,item) dlist_tail_push_dm((list), (item), \
						      __FILE__, __LINE__)
#endif

void dlist_init(dlist_t *list);
void dlist_onremove(dlist_t *list, dlist_onremove_t onremove);
void dlist_concat(dlist_t *first, dlist_t *second);
void *dlist_head_pop(dlist_t *list);
void *dlist_tail_pop(dlist_t *list);
void *dlist_head_item(const dlist_t *list);
void *dlist_tail_item(const dlist_t *list);
void *dlist_node_pop(dlist_t *list, dlist_node_t *node);
void *dlist_node_item(const dlist_node_t *node);
dlist_node_t *dlist_head_node(const dlist_t *list);
dlist_node_t *dlist_tail_node(const dlist_t *list);
dlist_node_t *dlist_node_next(const dlist_node_t *node);
dlist_node_t *dlist_node_prev(const dlist_node_t *node);
void dlist_node_eject(dlist_t *list, dlist_node_t *node);
void dlist_node_head_push(dlist_t *list, dlist_node_t *node);
void dlist_node_tail_push(dlist_t *list, dlist_node_t *node);
int dlist_foreach(dlist_t *list, const dlist_foreach_t func, void *param);
int dlist_count(const dlist_t *list);
int dlist_qsort(dlist_t *list, dlist_cmp_t func);
int dlist_shuffle(dlist_t *list);
void dlist_lock(dlist_t *list);
void dlist_unlock(dlist_t *list);
int dlist_islocked(dlist_t *list);
void dlist_empty(dlist_t *list);
void dlist_empty_cb(dlist_t *list, dlist_free_t func);
void dlist_free(dlist_t *list);
void dlist_free_cb(dlist_t *list, dlist_free_t func);

#ifndef DMALLOC
clist_t *clist_alloc(void);
clist_node_t *clist_tail_push(clist_t *list, void *item);
#else
clist_t *clist_alloc_dm(const char *file, const int line);
clist_node_t *clist_tail_push_dm(clist_t *list, void *item,
				 const char *file, const int line);
#define clist_alloc() clist_alloc_dm(__FILE__, __LINE__)
#define clist_tail_push(list,item) clist_tail_push_dm((list), (item), \
						      __FILE__, __LINE__)
#endif

void clist_init(clist_t *list);
void clist_onremove(clist_t *list, clist_onremove_t onremove);
clist_node_t *clist_head_node(const clist_t *list);
clist_node_t *clist_head_push(clist_t *list, void *item);
void *clist_head_pop(clist_t *list);
void *clist_tail_pop(clist_t *list);
void *clist_head_item(const clist_t *list);
void *clist_tail_item(const clist_t *list);
void *clist_node_pop(clist_t *list, clist_node_t *node);
void *clist_node_item(const clist_node_t *node);
clist_node_t *clist_node_next(const clist_node_t *node);
clist_node_t *clist_head_left(clist_t *node);
clist_node_t *clist_head_right(clist_t *node);
int clist_foreach(clist_t *list, const clist_foreach_t func, void *param);
int clist_count(const clist_t *list);
void clist_lock(clist_t *list);
void clist_unlock(clist_t *list);
int clist_islocked(clist_t *list);
void clist_free(clist_t *list);
void clist_free_cb(clist_t *list, clist_free_t func);

#endif
