/*
 * mjl_prefixtree
 *
 * Adapted from Dave Plonka's Net::Patricia, which includes material
 * from MRT.  Some of the variables are named as they are in
 * mjl_patricia for clarity with that code.  The main improvements are
 * in the bit testing, which uses a method shared with bit testing in
 * mjl_patricia.  Note, we cannot use a generic Patricia Trie to do
 * longest matching prefix lookup, hence this tree.
 *
 * Copyright (C) 2016 Matthew Luckie. All rights reserved.
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
 * $Id: mjl_prefixtree.c,v 1.13 2018/09/18 00:25:57 mjl Exp $
 *
 */

#ifndef lint
static const char rcsid[] =
  "$Id: mjl_prefixtree.c,v 1.13 2018/09/18 00:25:57 mjl Exp $";
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(__sun__)
# define s6_addr32 _S6_un._S6_u32
#elif !defined(s6_addr32)
# define s6_addr32 __u6_addr.__u6_addr32
#endif

#include "mjl_prefixtree.h"

struct prefixtree_node
{
  union
  {
    prefix4_t       *v4;
    prefix6_t       *v6;
    void            *raw;
  } pref;

  prefixtree_node_t *parent;
  prefixtree_node_t *left;
  prefixtree_node_t *right;
  int                bit;
};

struct prefixtree
{
  prefixtree_node_t *head;
  int                v;
};

static const uint32_t uint32_netmask[] = {
  0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
  0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
  0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
  0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
  0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
  0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
  0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
  0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff,
};

#ifdef _WIN32
static const uint16_t uint16_mask[] = {
  0x8000, 0xc000, 0xe000, 0xf000,
  0xf800, 0xfc00, 0xfe00, 0xff00,
  0xff80, 0xffc0, 0xffe0, 0xfff0,
  0xfff8, 0xfffc, 0xfffe, 0xffff,
};
#endif

#ifndef DMALLOC
prefix4_t *prefix4_alloc(struct in_addr *net, uint8_t len, void *ptr)
#else
prefix4_t *prefix4_alloc_dm(struct in_addr *net, uint8_t len, void *ptr,
			    const char *file, const int line)
#endif
{
  prefix4_t *p;
#ifndef DMALLOC
  p = malloc(sizeof(prefix4_t));
#else
  p = dmalloc_malloc(file, line, sizeof(prefix4_t), DMALLOC_FUNC_MALLOC, 0, 0);
#endif
  if(p == NULL)
    return NULL;
  p->net.s_addr = net->s_addr;
  p->len = len;
  p->ptr = ptr;
  return p;
}

#ifndef DMALLOC
prefix4_t *prefix4_dup(const prefix4_t *item)
#else
prefix4_t *prefix4_dup_dm(const prefix4_t *item,
			  const char *file, const int line)
#endif
{
  prefix4_t *dup;
#ifndef DMALLOC
  dup = malloc(sizeof(prefix4_t));
#else
  dup = dmalloc_malloc(file,line,sizeof(prefix4_t), DMALLOC_FUNC_MALLOC, 0, 0);
#endif
  if(dup == NULL)
    return NULL;
  memcpy(dup, item, sizeof(prefix4_t));
  dup->ptr = NULL;
  return dup;
}

void prefix4_free(prefix4_t *pref)
{
  free(pref);
  return;
}

int prefix4_cmp(const prefix4_t *a, const prefix4_t *b)
{
  uint32_t ua = ntohl(a->net.s_addr);
  uint32_t ub = ntohl(b->net.s_addr);
  if(ua < ub) return -1;
  if(ua > ub) return  1;
  if(a->len < b->len) return -1;
  if(a->len > b->len) return  1;
  return 0;
}

#ifndef DMALLOC
prefix6_t *prefix6_alloc(struct in6_addr *net, uint8_t len, void *ptr)
#else
prefix6_t *prefix6_alloc_dm(struct in6_addr *net, uint8_t len, void *ptr,
			    const char *file, const int line)
#endif
{
  prefix6_t *p;
#ifndef DMALLOC
  p = malloc(sizeof(prefix6_t));
#else
  p = dmalloc_malloc(file, line, sizeof(prefix6_t), DMALLOC_FUNC_MALLOC, 0, 0);
#endif
  if(p == NULL)
    return NULL;
  memcpy(&p->net, net, sizeof(struct in6_addr));
  p->len = len;
  p->ptr = ptr;
  return p;
}

#ifndef DMALLOC
prefix6_t *prefix6_dup(const prefix6_t *item)
#else
prefix6_t *prefix6_dup_dm(const prefix6_t *item,
			  const char *file, const int line)
#endif
{
  prefix6_t *dup;
#ifndef DMALLOC
  dup = malloc(sizeof(prefix6_t));
#else
  dup = dmalloc_malloc(file,line,sizeof(prefix6_t), DMALLOC_FUNC_MALLOC, 0, 0);
#endif
  if(dup == NULL)
    return NULL;
  memcpy(dup, item, sizeof(prefix6_t));
  dup->ptr = NULL;
  return dup;
}

void prefix6_free(prefix6_t *pref)
{
  free(pref);
  return;
}

int prefix6_cmp(const prefix6_t *a, const prefix6_t *b)
{
  int i;
#ifndef _WIN32
  uint32_t ua, ub;
  for(i=0; i<4; i++)
    {
      ua = ntohl(a->net.s6_addr32[i]);
      ub = ntohl(b->net.s6_addr32[i]);
      if(ua < ub) return -1;
      if(ua > ub) return  1;
    }
#else
  uint16_t ua, ub;
  for(i=0; i<8; i++)
    {
      ua = ntohs(a->net.u.Word[i]);
      ub = ntohs(b->net.u.Word[i]);
      if(ua < ub) return -1;
      if(ua > ub) return  1;
    }
#endif

  if(a->len < b->len) return -1;
  if(a->len > b->len) return  1;
  return 0;
}

#ifndef DMALLOC
static prefixtree_node_t *prefixtree_node_alloc(void *pref, int bit)
#else
static prefixtree_node_t *prefixtree_node_alloc_dm(void *pref, int bit,
						   const char *file,
						   const int line)
#endif
{
  prefixtree_node_t *n;
#ifndef DMALLOC
  n = malloc(sizeof(prefixtree_node_t));
#else
  n = dmalloc_malloc(file,line,sizeof(prefixtree_node_t),
		     DMALLOC_FUNC_MALLOC, 0, 0);
#endif
  if(n == NULL)
    return NULL;
  n->pref.raw = pref;
  n->bit = bit;
  n->parent = n->left = n->right = NULL;
  return n;
}

static int ip4_bit(const struct in_addr *ip, int bit)
{
  assert(bit >= 0); assert(bit < 32);
  return (ntohl(ip->s_addr) >> (31 - bit)) & 1;
}

static int ip6_bit(const struct in6_addr *ip, int bit)
{
  assert(bit >= 0); assert(bit < 128);
#ifndef _WIN32
  return (ntohl(ip->s6_addr32[bit/32]) >> (32 - ((bit+1) % 32))) & 1;
#else
  return (ntohs(ip->u.Word[bit/16]) >> (16 - ((bit+1) % 16))) & 1;
#endif
}

static int prefix4_bit(const prefix4_t *pref, int bit)
{
  assert(bit >= 0); assert(bit < 32);
  return (ntohl(pref->net.s_addr) >> (31 - bit)) & 1;
}

static int prefix6_bit(const prefix6_t *pref, int bit)
{
  assert(bit >= 0); assert(bit < 128);
#ifndef _WIN32
  return (ntohl(pref->net.s6_addr32[bit/32]) >> (32 - ((bit+1) % 32))) & 1;
#else
  return (ntohs(pref->net.u.Word[bit/16]) >> (16 - ((bit+1) % 16))) & 1;
#endif
}

static int prefix4_fbd(const prefix4_t *a, const prefix4_t *b)
{
  uint32_t v;
  int r;

  if((v = ntohl(a->net.s_addr ^ b->net.s_addr)) == 0)
    return 32;

#ifdef HAVE___BUILTIN_CLZ
  r = __builtin_clz(v);
#else
  r = 0;
  if(v & 0xFFFF0000) { v >>= 16; r += 16; }
  if(v & 0xFF00)     { v >>= 8;  r += 8;  }
  if(v & 0xF0)       { v >>= 4;  r += 4;  }
  if(v & 0xC)        { v >>= 2;  r += 2;  }
  if(v & 0x2)        {           r += 1;  }
  r = 31 - r;
#endif

  return r;
}

static int prefix6_fbd(const prefix6_t *a, const prefix6_t *b)
{
  uint32_t v;
  int i, r;

  for(i=0; i<4; i++)
    {
      if((v = ntohl(a->net.s6_addr32[i] ^ b->net.s6_addr32[i])) == 0)
	continue;

#ifdef HAVE___BUILTIN_CLZ
      r = __builtin_clz(v) + (i * 32);
#else
      r = 0;
      if(v & 0xFFFF0000) { v >>= 16; r += 16; }
      if(v & 0xFF00)     { v >>= 8;  r += 8;  }
      if(v & 0xF0)       { v >>= 4;  r += 4;  }
      if(v & 0xC)        { v >>= 2;  r += 2;  }
      if(v & 0x2)        {           r += 1;  }
      r = (31 - r) + (i * 32);
#endif

      return r;
    }

  return 128;
}

static int prefix4_ip_in(const prefix4_t *p4, const struct in_addr *ip4)
{
  assert(p4->len <= 32);
  if(p4->len == 0)
    return 1;
  if(((ip4->s_addr ^ p4->net.s_addr) & htonl(uint32_netmask[p4->len-1])) == 0)
    return 1;
  return 0;
}

static int prefix6_ip_in(const prefix6_t *p6, const struct in6_addr *ip6)
{
  int i, len;

#ifndef _WIN32
  uint32_t mask;
#else
  uint16_t mask;
#endif

  assert(p6->len <= 128);
  if((len = p6->len) == 0)
    return 1;

#ifndef _WIN32
  for(i=0; i<4; i++)
    {
      /*
       * handle the fact that we can only check 32 bits at a time.
       * no need to change byte order as all bytes are the same
       */
      if(len > 32)
	mask = uint32_netmask[31];
      else
	mask = htonl(uint32_netmask[len-1]);

      if(((ip6->s6_addr32[i] ^ p6->net.s6_addr32[i]) & mask) != 0)
	return 0;

      if(len <= 32)
	return 1;

      len -= 32;
    }
#else
  for(i=0; i<8; i++)
    {
      if(len > 16)
	mask = uint16_mask[15];
      else
	mask = htons(uint16_mask[len-1]);

      if(((ip6->u.Word[i] ^ p6->net.u.Word[i]) & mask) != 0)
	return 0;

      if(len <= 16)
	return 1;

      len -= 16;
    }
#endif

  return -1;
}

prefix4_t *prefixtree_find_ip4(const prefixtree_t *tree,
			       const struct in_addr *ip4)
{
  prefixtree_node_t *x = tree->head;
  prefix4_t *stack[33];
  int i = 0;

  assert(tree->v == 4);

  /* go through the tree, assembling possible prefix matches */
  while(x != NULL && x->bit < 32)
    {
      if(x->pref.v4 != NULL)
	stack[i++] = x->pref.v4;
      if(ip4_bit(ip4, x->bit) == 0)
	x = x->left;
      else
	x = x->right;
    }
  if(x != NULL && x->pref.v4 != NULL)
    stack[i++] = x->pref.v4;

  /* go from the top of the stack, looking for the longest prefix match */
  while(--i >= 0)
    if(prefix4_ip_in(stack[i], ip4) != 0)
      return stack[i];

  return NULL;
}

prefix4_t *prefixtree_find_best4(const prefixtree_t *tree,
				 const prefix4_t *item)
{
  prefixtree_node_t *x = tree->head;
  prefix4_t *stack[33];
  int i = 0;

  assert(tree->v == 4);

  /* go through the tree, assembling possible prefix matches */
  while(x != NULL && x->bit < item->len)
    {
      if(x->pref.v4 != NULL && x->pref.v4->len <= item->len)
	stack[i++] = x->pref.v4;
      if(ip4_bit(&item->net, x->bit) == 0)
	x = x->left;
      else
	x = x->right;
    }
  if(x != NULL && x->pref.v4 != NULL && x->pref.v4->len <= item->len)
    stack[i++] = x->pref.v4;

  /*
   * go from the top of the stack, looking for the most specific
   * enclosing prefix
   */
  while(--i >= 0)
    if(prefix4_ip_in(stack[i], &item->net) != 0)
      return stack[i];

  return NULL;
}

prefix4_t *prefixtree_find_exact4(const prefixtree_t *tree,
				  const struct in_addr *net, uint8_t len)
{
  prefix4_t fm, *p;
  fm.net.s_addr = net->s_addr;
  fm.len = len;
  if((p = prefixtree_find_best4(tree, &fm)) != NULL && p->len == len)
    return p;
  return NULL;
}

prefix6_t *prefixtree_find_ip6(const prefixtree_t *tree,
			       const struct in6_addr *ip6)
{
  prefixtree_node_t *x = tree->head;
  prefix6_t *stack[129];
  int i = 0;

  assert(tree->v == 6);

  /* go through the tree, assembling possible prefix matches */
  while(x != NULL && x->bit < 128)
    {
      if(x->pref.v6 != NULL)
	stack[i++] = x->pref.v6;
      if(ip6_bit(ip6, x->bit) == 0)
	x = x->left;
      else
	x = x->right;
    }
  if(x != NULL && x->pref.v6 != NULL)
    stack[i++] = x->pref.v6;

  /* go from the top of the stack, looking for the longest prefix match */
  while(--i >= 0)
    if(prefix6_ip_in(stack[i], ip6) != 0)
      return stack[i];

  return NULL;
}

prefix6_t *prefixtree_find_best6(const prefixtree_t *tree,
				 const prefix6_t *item)
{
  prefixtree_node_t *x = tree->head;
  prefix6_t *stack[129];
  int i = 0;

  assert(tree->v == 6);

  /* go through the tree, assembling possible prefix matches */
  while(x != NULL && x->bit < item->len)
    {
      if(x->pref.v6 != NULL && x->pref.v6->len <= item->len)
	stack[i++] = x->pref.v6;
      if(ip6_bit(&item->net, x->bit) == 0)
	x = x->left;
      else
	x = x->right;
    }
  if(x != NULL && x->pref.v6 != NULL && x->pref.v6->len <= item->len)
    stack[i++] = x->pref.v6;

  /*
   * go from the top of the stack, looking for the most specific
   * enclosing prefix
   */
  while(--i >= 0)
    if(prefix6_ip_in(stack[i], &item->net) != 0)
      return stack[i];

  return NULL;
}

prefix6_t *prefixtree_find_exact6(const prefixtree_t *tree,
				  const struct in6_addr *net, uint8_t len)
{
  prefix6_t fm, *p;
  memcpy(&fm.net, net, sizeof(struct in6_addr));
  fm.len = len;
  if((p = prefixtree_find_best6(tree, &fm)) != NULL && p->len == len)
    return p;
  return NULL;
}

#ifndef DMALLOC
prefixtree_node_t *prefixtree_insert4(prefixtree_t *tree, prefix4_t *pref)
#else
prefixtree_node_t *prefixtree_insert4_dm(prefixtree_t *tree, prefix4_t *pref,
					 const char *file, const int line)
#endif
{
  prefixtree_node_t *t, *g, *p, *x;
  struct in_addr *a;
  int bit, fbd;

  assert(tree->v == 4);

  if((x = tree->head) == NULL)
    {
#ifndef DMALLOC
      t = prefixtree_node_alloc(pref, pref->len);
#else
      t = prefixtree_node_alloc_dm(pref, pref->len, file, line);
#endif
      if(t == NULL)
	return NULL;
      tree->head = t;
      return t;
    }

  /* go through the tree until we get to the appropriate level */
  while(x->bit < pref->len || x->pref.v4 == NULL)
    {
      if(x->bit == 32 || prefix4_bit(pref, x->bit) == 0)
	{
	  if(x->left == NULL)
	    break;
	  x = x->left;
	}
      else
	{
	  if(x->right == NULL)
	    break;
	  x = x->right;
	}
    }

  if(x->bit < pref->len)
    bit = x->bit;
  else
    bit = pref->len;
  
  /* get the first bit different between the two prefixes */
  fbd = prefix4_fbd(x->pref.v4, pref);
  if(fbd > bit)
    fbd = bit;

  /*
   * remember the address that we want to reference when inserting,
   * before we go up the tree
   */
  a = &x->pref.v4->net;
  p = x->parent;
  while(p != NULL && p->bit >= fbd)
    {
      x = p;
      p = x->parent;
    }

  if(fbd == pref->len && x->bit == pref->len)
    {
      /* not going to insert the same prefix twice */
      if(x->pref.v4 != NULL)
	return NULL;
      x->pref.v4 = pref;
      return x;
    }

#ifndef DMALLOC
  t = prefixtree_node_alloc(pref, pref->len);
#else
  t = prefixtree_node_alloc_dm(pref, pref->len, file, line);
#endif
  if(t == NULL)
    return NULL;

  if(x->bit == fbd)
    {
      t->parent = x;
      if(x->bit == 32 || prefix4_bit(pref, x->bit) == 0)
	x->left = t;
      else
	x->right = t;
    }
  else if(pref->len == fbd)
    {
      if(pref->len == 32 || ip4_bit(a, pref->len) == 0)
	t->left = x;
      else
	t->right = x;
      t->parent = x->parent;
      if(x->parent == NULL)
	tree->head = t;
      else if(x->parent->left == x)
	x->parent->left = t;
      else
	x->parent->right = t;
      x->parent = t;
    }
  else
    {
      /* insert a new branch node (with no attached prefix) into the tree */
#ifndef DMALLOC
      g = prefixtree_node_alloc(NULL, fbd);
#else
      g = prefixtree_node_alloc_dm(NULL, fbd, file, line);
#endif
      if(g == NULL)
	{
	  free(t);
	  return NULL;
	}
      g->parent = x->parent;
      if(fbd == 32 || prefix4_bit(pref, fbd) == 0)
	{
	  g->left = t;
	  g->right = x;
	}
      else
	{
	  g->left = x;
	  g->right = t;
	}
      t->parent = g;
      if(x->parent == NULL)
	tree->head = g;
      else if(x->parent->left == x)
	x->parent->left = g;
      else
	x->parent->right = g;
      x->parent = g;
    }

  return t;
}

#ifndef DMALLOC
prefixtree_node_t *prefixtree_insert6(prefixtree_t *tree, prefix6_t *pref)
#else
prefixtree_node_t *prefixtree_insert6_dm(prefixtree_t *tree, prefix6_t *pref,
					 const char *file, const int line)
#endif
{
  prefixtree_node_t *t, *g, *p, *x;
  struct in6_addr *a;
  int bit, fbd;

  assert(tree->v == 6);

  if((x = tree->head) == NULL)
    {
#ifndef DMALLOC
      t = prefixtree_node_alloc(pref, pref->len);
#else
      t = prefixtree_node_alloc_dm(pref, pref->len, file, line);
#endif
      if(t == NULL)
	return NULL;
      tree->head = t;
      return t;
    }

  /* go through the tree until we get to the appropriate level */
  while(x->bit < pref->len || x->pref.v6 == NULL)
    {
      if(x->bit == 128 || prefix6_bit(pref, x->bit) == 0)
	{
	  if(x->left == NULL)
	    break;
	  x = x->left;
	}
      else
	{
	  if(x->right == NULL)
	    break;
	  x = x->right;
	}
    }

  if(x->bit < pref->len)
    bit = x->bit;
  else
    bit = pref->len;
  
  /* get the first bit different between the two prefixes */
  fbd = prefix6_fbd(x->pref.v6, pref);
  if(fbd > bit)
    fbd = bit;

  /*
   * remember the address that we want to reference when inserting,
   * before we go up the tree
   */
  a = &x->pref.v6->net;
  p = x->parent;
  while(p != NULL && p->bit >= fbd)
    {
      x = p;
      p = x->parent;
    }

  if(fbd == pref->len && x->bit == pref->len)
    {
      /* not going to insert the same prefix twice */
      if(x->pref.v6 != NULL)
	return NULL;
      x->pref.v6 = pref;
      return x;
    }

#ifndef DMALLOC
  t = prefixtree_node_alloc(pref, pref->len);
#else
  t = prefixtree_node_alloc_dm(pref, pref->len, file, line);
#endif
  if(t == NULL)
    return NULL;

  if(x->bit == fbd)
    {
      t->parent = x;
      if(x->bit == 128 || prefix6_bit(pref, x->bit) == 0)
	x->left = t;
      else
	x->right = t;
    }
  else if(pref->len == fbd)
    {
      if(pref->len == 128 || ip6_bit(a, pref->len) == 0)
	t->left = x;
      else
	t->right = x;
      t->parent = x->parent;
      if(x->parent == NULL)
	tree->head = t;
      else if(x->parent->left == x)
	x->parent->left = t;
      else
	x->parent->right = t;
      x->parent = t;
    }
  else
    {
      /* insert a new branch node (with no attached prefix) into the tree */
#ifndef DMALLOC
      g = prefixtree_node_alloc(NULL, fbd);
#else
      g = prefixtree_node_alloc_dm(NULL, fbd, file, line);
#endif
      if(g == NULL)
	{
	  free(t);
	  return NULL;
	}
      g->parent = x->parent;
      if(fbd == 128 || prefix6_bit(pref, fbd) == 0)
	{
	  g->left = t;
	  g->right = x;
	}
      else
	{
	  g->left = x;
	  g->right = t;
	}
      t->parent = g;
      if(x->parent == NULL)
	tree->head = g;
      else if(x->parent->left == x)
	x->parent->left = g;
      else
	x->parent->right = g;
      x->parent = g;
    }

  return t;
}

#ifndef DMALLOC
prefixtree_t *prefixtree_alloc4(void)
#else
prefixtree_t *prefixtree_alloc4_dm(const char *file, const int line)
#endif
{
  prefixtree_t *tree;
#ifndef DMALLOC
  tree = malloc(sizeof(prefixtree_t));
#else
  tree = dmalloc_malloc(file, line, sizeof(prefixtree_t),
			DMALLOC_FUNC_MALLOC, 0, 0);
#endif
  if(tree == NULL)
    return NULL;
  tree->v = 4;
  tree->head = NULL;
  return tree;
}

#ifndef DMALLOC
prefixtree_t *prefixtree_alloc6(void)
#else
prefixtree_t *prefixtree_alloc6_dm(const char *file, const int line)
#endif
{
  prefixtree_t *tree;
#ifndef DMALLOC
  tree = malloc(sizeof(prefixtree_t));
#else
  tree = dmalloc_malloc(file, line, sizeof(prefixtree_t),
			DMALLOC_FUNC_MALLOC, 0, 0);
#endif
  if(tree == NULL)
    return NULL;
  tree->v = 6;
  tree->head = NULL;
  return tree;
}

#ifndef DMALLOC
prefixtree_t *prefixtree_alloc(int af)
#else
prefixtree_t *prefixtree_alloc_dm(int af, const char *file, const int line)
#endif
{
#ifndef DMALLOC
  if(af == AF_INET) return prefixtree_alloc4();
  if(af == AF_INET6) return prefixtree_alloc6();
#else
  if(af == AF_INET) return prefixtree_alloc4_dm(file, line);
  if(af == AF_INET6) return prefixtree_alloc6_dm(file, line);
#endif
  return NULL;
}

static void prefixtree_free_cb2(prefixtree_node_t *node, prefix_free_t cb)
{
  if(node->left != NULL)
    prefixtree_free_cb2(node->left, cb);
  if(node->right != NULL)
    prefixtree_free_cb2(node->right, cb);
  if(cb != NULL && node->pref.raw != NULL)
    cb(node->pref.raw);
  free(node);
  return;
}

void prefixtree_free_cb(prefixtree_t *tree, prefix_free_t cb)
{
  if(tree == NULL)
    return;
  if(tree->head != NULL)
    prefixtree_free_cb2(tree->head, cb);
  free(tree);
  return;
}

void prefixtree_free(prefixtree_t *tree)
{
  if(tree == NULL)
    return;
  if(tree->head != NULL)
    prefixtree_free_cb2(tree->head, NULL);
  free(tree);
  return;
}
