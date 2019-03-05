/*
 * mjl_splaytree
 *
 * The (almost) completely reusable splay tree data structure and accompanying
 * algorithms.
 * this code was written for 0657.317 1999 at the University of Waikato
 * by Matthew Luckie
 *
 * Copyright (C) 1999-2018 Matthew Luckie. All rights reserved.
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
 * $Id: mjl_splaytree.h,v 1.16 2018/05/12 21:49:04 mjl Exp $
 *
 */

#ifndef __MJL_SPLAYTREE_H
#define __MJL_SPLAYTREE_H

typedef struct splaytree splaytree_t;
typedef struct splaytree_node splaytree_node_t;

typedef int  (*splaytree_cmp_t)(const void *a, const void *b);
typedef int  (*splaytree_diff_t)(const void *a, const void *b);
typedef void (*splaytree_display_t)(const void *ptr, int pad);
typedef int  (*splaytree_inorder_t)(void *ptr, void *entry);
typedef void (*splaytree_free_t)(void *ptr);
typedef void (*splaytree_onremove_t)(void *ptr);

#ifndef DMALLOC
/*
 * functions for
 * (1) allocating and freeing a splaytree structure
 * (2) inserting a node into the tree
 */
splaytree_t *splaytree_alloc(splaytree_cmp_t cmp);
splaytree_node_t *splaytree_insert(splaytree_t *tree, const void *ptr);
#endif

#ifdef DMALLOC
/* dmalloc-enabled functions that do the same as the functions above */
splaytree_t *splaytree_alloc_dm(splaytree_cmp_t cmp,
				const char *file, const int line);
splaytree_node_t *splaytree_insert_dm(splaytree_t *tree, const void *ptr,
				      const char *file, const int line);
#define splaytree_alloc(cmp) splaytree_alloc_dm((cmp), __FILE__, __LINE__)
#define splaytree_insert(t,p) splaytree_insert_dm((t), (p), __FILE__, __LINE__)
#endif

void splaytree_free(splaytree_t *tree, splaytree_free_t free_ptr);
void splaytree_empty(splaytree_t *tree, splaytree_free_t free_ptr);
void splaytree_onremove(splaytree_t *tree, splaytree_onremove_t onremove);

/* remove a node from the tree */
int splaytree_remove_item(splaytree_t *tree, const void *ptr);
int splaytree_remove_node(splaytree_t *tree, splaytree_node_t *node);

/* find a node in the tree and return it */
void *splaytree_find(splaytree_t *tree, const void *ptr);
void *splaytree_find_ro(const splaytree_t *tree, const void *ptr);

/* find a value in the tree closest to a particular value */
void *splaytree_findclosest(splaytree_t *tree, const void *ptr,
			    splaytree_diff_t diff);

/* return the right most node on the left branch of the tree */
void *splaytree_getrmlb(splaytree_t *tree);

/* return the left most node on the right branch of the tree */
void *splaytree_getlmrb(splaytree_t *tree);

/* return the node at the head of the tree */
void *splaytree_gethead(splaytree_t *tree);

/* pop the node at the head of the tree */
void *splaytree_pophead(splaytree_t *tree);

/* calculate the longest search path of the subtree passed in */
int splaytree_depth(splaytree_t *tree);

void splaytree_display(splaytree_t *tree, splaytree_display_t disp);

int splaytree_count(splaytree_t *tree);

void splaytree_inorder(splaytree_t *tree, splaytree_inorder_t func, void *in);

#endif /* __MJL_SPLAYTREE_H */
