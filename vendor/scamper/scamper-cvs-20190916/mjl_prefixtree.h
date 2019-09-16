/*
 * mjl_prefixtree
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
 * $Id: mjl_prefixtree.h,v 1.7 2018/09/18 00:25:57 mjl Exp $
 *
 */

#ifndef MJL_PREFIXTREE_H
#define MJL_PREFIXTREE_H

typedef struct prefix4
{
  struct in_addr net;
  uint8_t        len;
  void          *ptr;
} prefix4_t;

typedef struct prefix6
{
  struct in6_addr net;
  uint8_t         len;
  void           *ptr;
} prefix6_t;

typedef struct prefixtree prefixtree_t;
typedef struct prefixtree_node prefixtree_node_t;
typedef void (*prefix_free_t)(void *item);

#ifndef DMALLOC
prefixtree_t *prefixtree_alloc4(void);
prefixtree_t *prefixtree_alloc6(void);
prefixtree_t *prefixtree_alloc(int);
#else
prefixtree_t *prefixtree_alloc4_dm(const char *file, const int line);
prefixtree_t *prefixtree_alloc6_dm(const char *file, const int line);
prefixtree_t *prefixtree_alloc_dm(int, const char *file, const int line);
#define prefixtree_alloc4() prefixtree_alloc4_dm(__FILE__, __LINE__)
#define prefixtree_alloc6() prefixtree_alloc6_dm(__FILE__, __LINE__)
#define prefixtree_alloc(af) prefixtree_alloc_dm((af), __FILE__, __LINE__)
#endif

void prefixtree_free(prefixtree_t *tree);
void prefixtree_free_cb(prefixtree_t *tree, prefix_free_t cb);

#ifndef DMALLOC
prefixtree_node_t *prefixtree_insert4(prefixtree_t *tree, prefix4_t *item);
prefixtree_node_t *prefixtree_insert6(prefixtree_t *tree, prefix6_t *item);
#else
prefixtree_node_t *prefixtree_insert4_dm(prefixtree_t *tree, prefix4_t *item,
					 const char *file, const int line);
prefixtree_node_t *prefixtree_insert6_dm(prefixtree_t *tree, prefix6_t *item,
					 const char *file, const int line);
#define prefixtree_insert4(tree,item) prefixtree_insert4_dm((tree), (item), \
							    __FILE__, __LINE__)
#define prefixtree_insert6(tree,item) prefixtree_insert6_dm((tree), (item), \
							    __FILE__, __LINE__)
#endif

prefix4_t *prefixtree_find_ip4(const prefixtree_t *tree,
			       const struct in_addr *ip4);
prefix6_t *prefixtree_find_ip6(const prefixtree_t *tree,
			       const struct in6_addr *ip6);

prefix4_t *prefixtree_find_best4(const prefixtree_t *tree,
				 const prefix4_t *item);
prefix6_t *prefixtree_find_best6(const prefixtree_t *tree,
				 const prefix6_t *item);

prefix4_t *prefixtree_find_exact4(const prefixtree_t *tree,
				  const struct in_addr *net, uint8_t len);
prefix6_t *prefixtree_find_exact6(const prefixtree_t *tree,
				  const struct in6_addr *net, uint8_t len);

#ifndef DMALLOC
prefix4_t *prefix4_alloc(struct in_addr *net, uint8_t len, void *ptr);
prefix6_t *prefix6_alloc(struct in6_addr *net, uint8_t len, void *ptr);
#else
prefix4_t *prefix4_alloc_dm(struct in_addr *net, uint8_t len, void *ptr,
			    const char *file, const int line);
prefix6_t *prefix6_alloc_dm(struct in6_addr *net, uint8_t len, void *ptr,
			    const char *file, const int line);
#define prefix4_alloc(net,len,ptr) prefix4_alloc_dm((net),(len),(ptr), \
						    __FILE__, __LINE__)
#define prefix6_alloc(net,len,ptr) prefix6_alloc_dm((net),(len),(ptr), \
						    __FILE__, __LINE__)
#endif

void prefix4_free(prefix4_t *pfx);
void prefix6_free(prefix6_t *pfx);

int prefix4_cmp(const prefix4_t *a, const prefix4_t *b);
int prefix6_cmp(const prefix6_t *a, const prefix6_t *b);

#ifndef DMALLOC
prefix4_t *prefix4_dup(const prefix4_t *item);
prefix6_t *prefix6_dup(const prefix6_t *item);
#else
prefix4_t *prefix4_dup_dm(const prefix4_t *item,
			  const char *file, const int line);
prefix6_t *prefix6_dup_dm(const prefix6_t *item,
			  const char *file, const int line);
#define prefix4_dup(item) prefix4_dup_dm((item), __FILE__, __LINE__)
#define prefix6_dup(item) prefix6_dup_dm((item), __FILE__, __LINE__)
#endif

#endif /* MJL_PREFIXTREE */
