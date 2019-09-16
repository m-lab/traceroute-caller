/*
 * mjl_patricia
 *
 * Copyright (C) 2016,2019 Matthew Luckie. All rights reserved.
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
 * $Id: mjl_patricia.h,v 1.4 2019/05/25 09:16:32 mjl Exp $
 *
 */

#ifndef MJL_PATRICIA_H
#define MJL_PATRICIA_H

typedef struct patricia_node patricia_node_t;
typedef struct patricia patricia_t;

typedef int (*patricia_bit_t)(const void *item, int bit);
typedef int (*patricia_cmp_t)(const void *a, const void *b);
typedef int (*patricia_fbd_t)(const void *a, const void *b);
typedef void (*patricia_free_t)(void *item);

void *patricia_find(const patricia_t *trie, const void *item);
int patricia_remove_node(patricia_t *trie, patricia_node_t *node);
int patricia_remove_item(patricia_t *trie, const void *item);
int patricia_count(const patricia_t *trie);

#ifndef DMALLOC
patricia_node_t *patricia_insert(patricia_t *trie, void *item);
patricia_t *patricia_alloc(patricia_bit_t bit, patricia_cmp_t cmp,
			   patricia_fbd_t fbd);
#else
patricia_t *patricia_alloc_dm(patricia_bit_t bit, patricia_cmp_t cmp,
			      patricia_fbd_t fbd,
			      const char *file, const int line);
patricia_node_t *patricia_insert_dm(patricia_t *trie, void *item,
				    const char *file, const int line);
#define patricia_alloc(bit,cmp,fbd) patricia_alloc_dm((bit),(cmp),(fbd), \
						      __FILE__, __LINE__)
#define patricia_insert(trie,item) patricia_insert_dm((trie), (item), \
						      __FILE__, __LINE__)
#endif

void patricia_free_cb(patricia_t *trie, patricia_free_t free_cb);
void patricia_free(patricia_t *trie);

int patricia_node_bit(const patricia_node_t *node);
void *patricia_node_item(const patricia_node_t *node);
void *patricia_node_left_item(const patricia_node_t *node);
void *patricia_node_right_item(const patricia_node_t *node);
patricia_node_t *patricia_head_node(const patricia_t *trie);
patricia_node_t *patricia_node_left_node(const patricia_node_t *node);
patricia_node_t *patricia_node_right_node(const patricia_node_t *node);

#endif /* MJL_PATRICIA_H */
