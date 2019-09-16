/*
 * mjl_patricia
 *
 * Adapted from the patricia trie in "Robert Sedgewick's Algorithms in C++"
 * and from the Java implementation by Josh Hentosh and Robert Sedgewick.
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
 * $Id: mjl_patricia.c,v 1.4 2019/05/25 09:16:32 mjl Exp $
 *
 */

#ifndef lint
static const char rcsid[] =
  "$Id: mjl_patricia.c,v 1.4 2019/05/25 09:16:32 mjl Exp $";
#endif

#include <stdlib.h>
#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "mjl_patricia.h"

struct patricia
{
  patricia_node_t *head;
  patricia_bit_t   bit;
  patricia_cmp_t   cmp;
  patricia_fbd_t   fbd;
  int              count;
};

struct patricia_node
{
  void            *item;
  int              bit;
  patricia_node_t *left;
  patricia_node_t *right;
};

int patricia_node_bit(const patricia_node_t *node)
{
  return node->bit;
}

void *patricia_node_item(const patricia_node_t *node)
{
  return node->item;
}

void *patricia_node_left_item(const patricia_node_t *node)
{
  if(node->left == NULL)
    return NULL;
  return node->left->item;
}

patricia_node_t *patricia_node_left_node(const patricia_node_t *node)
{
  return node->left;
}

void *patricia_node_right_item(const patricia_node_t *node)
{
  if(node->right == NULL)
    return NULL;
  return node->right->item;
}

patricia_node_t *patricia_node_right_node(const patricia_node_t *node)
{
  return node->right;
}

patricia_node_t *patricia_head_node(const patricia_t *trie)
{
  return trie->head;
}

void *patricia_find(const patricia_t *trie, const void *item)
{
  patricia_node_t *p, *x = trie->head;

  do
    {
      p = x;
      if(x->bit != 0 && trie->bit(item, x->bit) == 0)
	x = x->left;
      else
	x = x->right;
    }
  while(p->bit < x->bit);

  if(x->item != NULL && trie->cmp(item, x->item) == 0)
    return x->item;
  return NULL;
}

#ifndef DMALLOC
patricia_node_t *patricia_insert(patricia_t *trie, void *item)
#else
patricia_node_t *patricia_insert_dm(patricia_t *trie, void *item,
				    const char *file, const int line)
#endif
{
  patricia_node_t *t, *p, *x = trie->head;
  size_t len;
  int b;

  assert(x != NULL);
  do
    {
      p = x;
      if(x->bit != 0 && trie->bit(item, x->bit) == 0)
	x = x->left;
      else
	x = x->right;
      assert(x != NULL);
    }
  while(p->bit < x->bit);

  b = 0;
  if(x->item != NULL)
    {
      /* cannot insert the item if it is already in the trie */
      if(trie->cmp(item, x->item) == 0)
	return NULL;

      /*
       * find the left most bit position where the two items differ
       *
       * note: trie->fbd should return the same as the following
       * computation.
       *
       * while(trie->bit(x->item, b) == trie->bit(item, b))
       *   b++;
       *
       */
      b = trie->fbd(x->item, item);
    }

  /* travel down the trie to that point */
  x = trie->head;
  do
    {
      p = x; assert(p != NULL);
      if(x->bit != 0 && trie->bit(item, x->bit) == 0)
	x = x->left;
      else
	x = x->right;
      assert(x != NULL);
    }
  while(p->bit < x->bit && x->bit < b);

  /* insert a new node at this point */
  len = sizeof(patricia_node_t);
#ifndef DMALLOC
  t = malloc(len);
#else
  t = dmalloc_malloc(file, line, len, DMALLOC_FUNC_MALLOC, 0, 0);
#endif
  if(t == NULL)
    return NULL;
  t->item = item;
  t->bit = b;
  if(t->bit != 0 && trie->bit(item, t->bit) == 0)
    {
      t->left = t;
      t->right = x;
    }
  else
    {
      t->left = x;
      t->right = t;
    }

  if(p->bit != 0 && trie->bit(item, p->bit) == 0)
    p->left = t;
  else
    p->right = t;

  trie->count++;
  return t;
}

static int patricia_gpx_node(patricia_t *trie, patricia_node_t *node,
			     patricia_node_t **g, patricia_node_t **p,
			     patricia_node_t **x)
{
  *p = trie->head;
  *x = trie->head;

  do
    {
      *g = *p; *p = *x;
      if((*x)->bit != 0 && trie->bit(node->item, (*x)->bit) == 0)
	*x = (*x)->left;
      else
	*x = (*x)->right;
    }
  while((*p)->bit < (*x)->bit);

  if(node != *x)
    return 0;
  return 1;
}

static int patricia_gpx_item(patricia_t *trie, const void *item,
			     patricia_node_t **g, patricia_node_t **p,
			     patricia_node_t **x)
{
  *p = trie->head;
  *x = trie->head;

  do
    {
      *g = *p; *p = *x;
      if((*x)->bit != 0 && trie->bit(item, (*x)->bit) == 0)
	*x = (*x)->left;
      else
	*x = (*x)->right;
    }
  while((*p)->bit < (*x)->bit);

  if((*x)->item == NULL || trie->cmp((*x)->item, item) != 0)
    return 0;
  return 1;
}

static void patricia_gpx_remove(patricia_t *trie,
				patricia_node_t *g, patricia_node_t *p,
				patricia_node_t *x)
{
  patricia_node_t *z, *y, *c;

  y = trie->head;
  do
    {
      assert(y != NULL);
      z = y;
      if(y->bit != 0 && trie->bit(x->item, y->bit) == 0)
	y = y->left;
      else
	y = y->right;
    }
  while(y != x);

  if(x == p)
    {
      if(x->bit != 0 && trie->bit(x->item, x->bit) == 0)
	{
	  assert(x->right != x);
	  c = x->right;
	}
      else
	{
	  assert(x->left != x);
	  c = x->left;
	}
      if(z->bit != 0 && trie->bit(x->item, z->bit) == 0)
	z->left = c;
      else
	z->right = c;
    }
  else
    {
      assert(p != NULL);
      if(p->bit != 0 && trie->bit(x->item, p->bit) == 0)
	c = p->right;
      else
	c = p->left;
      assert(g != NULL);
      if(g->bit != 0 && trie->bit(x->item, g->bit) == 0)
	g->left = c;
      else
	g->right = c;
      assert(z != NULL);
      if(z->bit != 0 && trie->bit(x->item, z->bit) == 0)
	z->left = p;
      else
	z->right = p;

      /*
       * set the trie up for when x is removed.  handle the case when
       * x points to itself
       */
      if(x->left != x)
	p->left = x->left;
      else
	p->left = p;
      if(x->right != x)
	p->right = x->right;
      else
	p->right = p;
      p->bit = x->bit;
    }

  /* when the trie is empty, reset it to how it was at initialisation */
  if(--trie->count == 0)
    {
      trie->head->left = trie->head;
      trie->head->right = trie->head;
      trie->head->bit = 0;
      trie->head->item = NULL;
    }

  assert(x != trie->head);

  /* don't need the node structure anymore, so free it */
  free(x);
  if(trie->head->left == x)
    trie->head->left = trie->head;
  if(trie->head->right == x)
    trie->head->right = trie->head;

  return;
}

int patricia_remove_node(patricia_t *trie, patricia_node_t *node)
{
  patricia_node_t *g, *p, *x;
  if(patricia_gpx_node(trie, node, &g, &p, &x) == 0)
    return -1;
  patricia_gpx_remove(trie, g, p, x);
  return 0;
}

int patricia_remove_item(patricia_t *trie, const void *item)
{
  patricia_node_t *g, *p, *x;
  if(patricia_gpx_item(trie, item, &g, &p, &x) == 0)
    return -1;
  patricia_gpx_remove(trie, g, p, x);
  return 0;
}

int patricia_count(const patricia_t *trie)
{
  if(trie == NULL)
    return -1;
  return trie->count;
}

#ifndef DMALLOC
patricia_t *patricia_alloc(patricia_bit_t bit, patricia_cmp_t cmp,
			   patricia_fbd_t fbd)
#else
patricia_t *patricia_alloc_dm(patricia_bit_t bit, patricia_cmp_t cmp,
			      patricia_fbd_t fbd,
			      const char *file, const int line)
#endif
{
  patricia_t *trie = NULL;
  size_t len;

  /*
   * allocate the patricia trie data structure
   */
  len = sizeof(patricia_t);
#ifndef DMALLOC
  trie = malloc(len);
#else
  trie = dmalloc_malloc(file, line, len, DMALLOC_FUNC_MALLOC, 0, 0);
#endif
  if(trie == NULL)
    goto err;
  trie->bit = bit;
  trie->cmp = cmp;
  trie->fbd = fbd;
  trie->count = 0;

  /*
   * allocate an initial head node for the patricia trie
   */
  len = sizeof(patricia_node_t);
#ifndef DMALLOC
  trie->head = malloc(len);
#else
  trie->head = dmalloc_malloc(file, line, len, DMALLOC_FUNC_MALLOC, 0, 0);
#endif
  if(trie->head == NULL)
    goto err;
  trie->head->left = trie->head;
  trie->head->right = trie->head;
  trie->head->bit = 0;
  trie->head->item = NULL;

  return trie;

 err:
  if(trie != NULL) patricia_free(trie);
  return NULL;
}

/*
 * patricia_free_rec
 *
 * implementation by trial and error
 */
static void patricia_free_rec(patricia_t *trie, patricia_node_t *node,
			      patricia_free_t free_cb)
{
  patricia_node_t *tmp;
  if(node != node->left && node->left != NULL &&
     (node->bit <= node->left->bit || node->left->bit == 0))
    {
      tmp = node->left; node->left = NULL;
      patricia_free_rec(trie, tmp, free_cb);
    }
  if(node != node->right && node->right != NULL &&
     (node->bit <= node->right->bit || node->right->bit == 0))
    {
      tmp = node->right; node->right = NULL;
      patricia_free_rec(trie, tmp, free_cb);
    }
  if(node != trie->head)
    {
      if(free_cb != NULL)
	free_cb(node->item);
      free(node);
    }
  return;
}

void patricia_free_cb(patricia_t *trie, patricia_free_t free_cb)
{
  if(trie == NULL)
    return;
  if(trie->head != NULL)
    {
      patricia_free_rec(trie, trie->head->left, free_cb);
      if(trie->head->right != trie->head->left && trie->head->right != NULL)
	patricia_free_rec(trie, trie->head->right, free_cb);
      free(trie->head);
    }
  free(trie);
  return;
}

void patricia_free(patricia_t *trie)
{
  patricia_free_cb(trie, NULL);
  return;
}
