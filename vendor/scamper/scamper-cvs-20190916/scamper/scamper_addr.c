/*
 * scamper_addr.c
 *
 * $Id: scamper_addr.c,v 1.70 2019/05/25 23:34:28 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2013-2014 The Regents of the University of California
 * Copyright (C) 2016      Matthew Luckie
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
  "$Id: scamper_addr.c,v 1.70 2019/05/25 23:34:28 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "mjl_splaytree.h"
#include "scamper_addr.h"
#include "utils.h"

/*
 * convenient table for masking off portions of addresses for checking
 * if an address falls in a prefix
 */
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

static const uint32_t uint32_hostmask[] = {
  0xffffffff, 0x7fffffff, 0x3fffffff, 0x1fffffff,
  0x0fffffff, 0x07ffffff, 0x03ffffff, 0x01ffffff,
  0x00ffffff, 0x007fffff, 0x003fffff, 0x001fffff,
  0x000fffff, 0x0007ffff, 0x0003ffff, 0x0001ffff,
  0x0000ffff, 0x00007fff, 0x00003fff, 0x00001fff,
  0x00000fff, 0x000007ff, 0x000003ff, 0x000001ff,
  0x000000ff, 0x0000007f, 0x0000003f, 0x0000001f,
  0x0000000f, 0x00000007, 0x00000003, 0x00000001,
};

#ifdef _WIN32
static const uint16_t uint16_mask[] = {
  0x8000, 0xc000, 0xe000, 0xf000,
  0xf800, 0xfc00, 0xfe00, 0xff00,
  0xff80, 0xffc0, 0xffe0, 0xfff0,
  0xfff8, 0xfffc, 0xfffe, 0xffff,
};
#endif

static int ipv4_cmp(const scamper_addr_t *, const scamper_addr_t *);
static int ipv4_human_cmp(const scamper_addr_t *, const scamper_addr_t *);
static int ipv6_cmp(const scamper_addr_t *, const scamper_addr_t *);
static int ipv6_human_cmp(const scamper_addr_t *, const scamper_addr_t *);
static int ethernet_cmp(const scamper_addr_t *, const scamper_addr_t *);
static int firewire_cmp(const scamper_addr_t *, const scamper_addr_t *);

static void ipv4_tostr(const scamper_addr_t *, char *, const size_t);
static void ipv6_tostr(const scamper_addr_t *, char *, const size_t);
static void ethernet_tostr(const scamper_addr_t *, char *, const size_t);
static void firewire_tostr(const scamper_addr_t *, char *, const size_t);

static int ipv4_inprefix(const scamper_addr_t *, const void *, int len);
static int ipv6_inprefix(const scamper_addr_t *, const void *, int len);

static int ipv4_prefix(const scamper_addr_t *, const scamper_addr_t *);
static int ipv4_prefixhosts(const scamper_addr_t *, const scamper_addr_t *);
static int ipv6_prefix(const scamper_addr_t *, const scamper_addr_t *);

static int ipv4_bit(const scamper_addr_t *, int bit);
static int ipv6_bit(const scamper_addr_t *, int bit);
static int ethernet_bit(const scamper_addr_t *, int bit);
static int firewire_bit(const scamper_addr_t *, int bit);

static int ipv4_fbd(const scamper_addr_t *, const scamper_addr_t *);
static int ipv6_fbd(const scamper_addr_t *, const scamper_addr_t *);
static int ethernet_fbd(const scamper_addr_t *, const scamper_addr_t *);
static int firewire_fbd(const scamper_addr_t *, const scamper_addr_t *);

static int ipv4_islinklocal(const scamper_addr_t *);
static int ipv6_islinklocal(const scamper_addr_t *);

static int ipv4_netaddr(const scamper_addr_t *, void *, int);
static int ipv6_netaddr(const scamper_addr_t *, void *, int);

static int ipv4_isreserved(const scamper_addr_t *);
static int ipv6_isreserved(const scamper_addr_t *);

static int ipv6_isunicast(const scamper_addr_t *);

struct handler
{
  int     type;
  size_t  size;
  int    (*cmp)(const scamper_addr_t *sa, const scamper_addr_t *sb);
  int    (*human_cmp)(const scamper_addr_t *sa, const scamper_addr_t *sb);
  void   (*tostr)(const scamper_addr_t *addr, char *buf, const size_t len);
  int    (*inprefix)(const scamper_addr_t *addr, const void *prefix, int len);
  int    (*prefix)(const scamper_addr_t *a, const scamper_addr_t *b);
  int    (*prefixhosts)(const scamper_addr_t *a, const scamper_addr_t *b);
  int    (*islinklocal)(const scamper_addr_t *a);
  int    (*netaddr)(const scamper_addr_t *a, void *net, int netlen);
  int    (*isunicast)(const scamper_addr_t *a);
  int    (*isreserved)(const scamper_addr_t *a);
  int    (*bit)(const scamper_addr_t *a, int bit);
  int    (*fbd)(const scamper_addr_t *a, const scamper_addr_t *b);
};

static const struct handler handlers[] = {
  {
    SCAMPER_ADDR_TYPE_IPV4,
    4,
    ipv4_cmp,
    ipv4_human_cmp,
    ipv4_tostr,
    ipv4_inprefix,
    ipv4_prefix,
    ipv4_prefixhosts,
    ipv4_islinklocal,
    ipv4_netaddr,
    NULL,
    ipv4_isreserved,
    ipv4_bit,
    ipv4_fbd,
  },
  {
    SCAMPER_ADDR_TYPE_IPV6,
    16,
    ipv6_cmp,
    ipv6_human_cmp,
    ipv6_tostr,
    ipv6_inprefix,
    ipv6_prefix,
    NULL,
    ipv6_islinklocal,
    ipv6_netaddr,
    ipv6_isunicast,
    ipv6_isreserved,
    ipv6_bit,
    ipv6_fbd,
  },
  {
    SCAMPER_ADDR_TYPE_ETHERNET,
    6,
    ethernet_cmp,
    ethernet_cmp,
    ethernet_tostr,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ethernet_bit,
    ethernet_fbd,
  },
  {
    SCAMPER_ADDR_TYPE_FIREWIRE,
    8,
    firewire_cmp,
    firewire_cmp,
    firewire_tostr,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    firewire_bit,
    firewire_fbd,
  }
};

struct scamper_addrcache
{
  splaytree_t *tree[sizeof(handlers)/sizeof(struct handler)];
};

static int ipv4_cmp(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  struct in_addr *a, *b;

  assert(sa->type == SCAMPER_ADDR_TYPE_IPV4);
  assert(sb->type == SCAMPER_ADDR_TYPE_IPV4);

  a = (struct in_addr *)sa->addr;
  b = (struct in_addr *)sb->addr;

  if(a->s_addr < b->s_addr) return -1;
  if(a->s_addr > b->s_addr) return  1;

  return 0;
}

static int ipv4_human_cmp(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  uint32_t a, b;

  assert(sa->type == SCAMPER_ADDR_TYPE_IPV4);
  assert(sb->type == SCAMPER_ADDR_TYPE_IPV4);

  a = ntohl(((struct in_addr *)sa->addr)->s_addr);
  b = ntohl(((struct in_addr *)sb->addr)->s_addr);

  if(a < b) return -1;
  if(a > b) return  1;

  return 0;
}

static void ipv4_tostr(const scamper_addr_t *addr, char *buf, const size_t len)
{
  addr_tostr(AF_INET, addr->addr, buf, len);
  return;
}

static int ipv4_inprefix(const scamper_addr_t *sa, const void *p, int len)
{
  const struct in_addr *addr = sa->addr;
  const struct in_addr *prefix = p;

  if(len == 0)
    return 1;

  if(len > 32)
    return -1;

  if(((addr->s_addr ^ prefix->s_addr) & htonl(uint32_netmask[len-1])) == 0)
    return 1;

  return 0;
}

static int ipv4_prefix(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  const struct in_addr *a = sa->addr;
  const struct in_addr *b = sb->addr;
  int i;

  for(i=32; i>0; i--)
    {
      if(((a->s_addr ^ b->s_addr) & htonl(uint32_netmask[i-1])) == 0)
	break;
    }

  return i;
}

static int ipv4_prefixhosts(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  const struct in_addr *a = sa->addr;
  const struct in_addr *b = sb->addr;
  struct in_addr c;
  int i;

  for(i=32; i>0; i--)
    {
      if(((a->s_addr ^ b->s_addr) & htonl(uint32_netmask[i-1])) == 0)
	break;
    }
  if(i >= 31)
    return i;

  while(i>0)
    {
      c.s_addr = ntohl(a->s_addr) & uint32_hostmask[i];
      if(c.s_addr == 0 || c.s_addr == uint32_hostmask[i])
	{
	  i--;
	  continue;
	}

      c.s_addr = ntohl(b->s_addr) & uint32_hostmask[i];
      if(c.s_addr == 0 || c.s_addr == uint32_hostmask[i])
	{
	  i--;
	  continue;
	}

      break;
    }

  return i;
}

/*
 * ipv4_islinklocal
 *
 * an IPv4 address is a link local address if it is in 169.254.0.0/16
 */
static int ipv4_islinklocal(const scamper_addr_t *sa)
{
  const struct in_addr *a = sa->addr;
  if((ntohl(a->s_addr) & 0xffff0000) == 0xa9fe0000)
    return 1;
  return 0;
}

static int ipv4_netaddr(const scamper_addr_t *sa, void *net, int netlen)
{
  const struct in_addr *a = sa->addr;
  struct in_addr p;
  if(netlen <= 0 || netlen > 32 || sa == NULL || net == NULL)
    return -1;
  p.s_addr = htonl(ntohl(a->s_addr) & uint32_netmask[netlen-1]);
  memcpy(net, &p, sizeof(p));
  return 0;
}

static int ipv4_isreserved(const scamper_addr_t *a)
{
  static const uint32_t prefs[][2] = {
    {0x00000000, 0xff000000}, /* 0.0.0.0/8 */
    {0x0a000000, 0xff000000}, /* 10.0.0.0/8 */
    {0x64400000, 0xffc00000}, /* 100.64.0.0/10 */
    {0x7f000000, 0xff000000}, /* 127.0.0.0/8 */
    {0xa9fe0000, 0xffff0000}, /* 169.254.0.0/16 */
    {0xac100000, 0xfff00000}, /* 172.16.0.0/12 */
    {0xc0000000, 0xffffff00}, /* 192.0.0.0/24 */
    {0xc0000200, 0xffffff00}, /* 192.0.2.0/24 */
    {0xc0586300, 0xffffff00}, /* 192.88.99.0/24 */
    {0xc0a80000, 0xffff0000}, /* 192.168.0.0/16 */
    {0xc6120000, 0xfffe0000}, /* 198.18.0.0/15 */
    {0xc6336400, 0xffffff00}, /* 198.51.100.0/24 */
    {0xcb007100, 0xffffff00}, /* 203.0.113.0/24 */
    {0xe0000000, 0xf0000000}, /* 224.0.0.0/4 */
    {0xf0000000, 0xf0000000}, /* 240.0.0.0/4 */
  };
  static const int prefc = 15;
  uint32_t addr = ntohl(((const struct in_addr *)a->addr)->s_addr);
  int i;
  for(i=0; i<prefc; i++)
    if((addr & prefs[i][1]) == prefs[i][0])
      return 1;
  return 0;
}

/*
 * ipv4_bit:
 *
 * return a bit from the IPv4 address.  bit 1 is the left most bit,
 * bit 32 is the right most bit.
 */
static int ipv4_bit(const scamper_addr_t *sa, int bit)
{
  struct in_addr *a = (struct in_addr *)sa->addr;
  assert(bit > 0); assert(bit <= 32);
  return (ntohl(a->s_addr) >> (31 - (bit-1))) & 1;
}

/*
 * ipv4_fbd:
 *
 * determine the first bit that is different between two IPv4 addresses.
 * bit 32 is the right most bit
 */
static int ipv4_fbd(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  const struct in_addr *a, *b;
  uint32_t v, r;

  assert(sa->type == SCAMPER_ADDR_TYPE_IPV4);
  assert(sb->type == SCAMPER_ADDR_TYPE_IPV4);
  a = (const struct in_addr *)sa->addr;
  b = (const struct in_addr *)sb->addr;

  v = ntohl(a->s_addr ^ b->s_addr);

#ifdef HAVE___BUILTIN_CLZ
  if(v != 0)
    r = __builtin_clz(v) + 1;
  else
    r = 32;
#else
  r = 0;
  if(v & 0xFFFF0000) { v >>= 16; r += 16; }
  if(v & 0xFF00)     { v >>= 8;  r += 8;  }
  if(v & 0xF0)       { v >>= 4;  r += 4;  }
  if(v & 0xC)        { v >>= 2;  r += 2;  }
  if(v & 0x2)        {           r += 1;  }
  r = 32 - r;
#endif

  return r;
}

static int ipv6_cmp(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  struct in6_addr *a, *b;
  int i;

  assert(sa->type == SCAMPER_ADDR_TYPE_IPV6);
  assert(sb->type == SCAMPER_ADDR_TYPE_IPV6);

  a = (struct in6_addr *)sa->addr;
  b = (struct in6_addr *)sb->addr;

#ifndef _WIN32
  for(i=0; i<4; i++)
    {
      if(a->s6_addr32[i] < b->s6_addr32[i]) return -1;
      if(a->s6_addr32[i] > b->s6_addr32[i]) return  1;
    }
#else
  for(i=0; i<8; i++)
    {
      if(a->u.Word[i] < b->u.Word[i]) return -1;
      if(a->u.Word[i] > b->u.Word[i]) return  1;
    }
#endif

  return 0;
}

static int ipv6_human_cmp(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  struct in6_addr *a, *b;
  int i;

#ifndef _WIN32
  uint32_t as, bs;
#else
  uint16_t as, bs;
#endif

  assert(sa->type == SCAMPER_ADDR_TYPE_IPV6);
  assert(sb->type == SCAMPER_ADDR_TYPE_IPV6);

  a = (struct in6_addr *)sa->addr;
  b = (struct in6_addr *)sb->addr;

#ifndef _WIN32
  for(i=0; i<4; i++)
    {
      as = ntohl(a->s6_addr32[i]);
      bs = ntohl(b->s6_addr32[i]);

      if(as < bs) return -1;
      if(as > bs) return  1;
    }
#else
  for(i=0; i<8; i++)
    {
      as = ntohs(a->u.Word[i]);
      bs = ntohs(b->u.Word[i]);

      if(as < bs) return -1;
      if(as > bs) return  1;
    }
#endif

  return 0;
}

static void ipv6_tostr(const scamper_addr_t *addr, char *buf, const size_t len)
{
  addr_tostr(AF_INET6, addr->addr, buf, len);
  return;
}

static int ipv6_inprefix(const scamper_addr_t *sa, const void *p, int len)
{
  const struct in6_addr *addr = sa->addr;
  const struct in6_addr *prefix = p;
  int i;

#ifndef _WIN32
  uint32_t mask;
#else
  uint16_t mask;
#endif

  if(len == 0)
    return 1;

  if(len > 128)
    return -1;

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

      if(((addr->s6_addr32[i] ^ prefix->s6_addr32[i]) & mask) != 0)
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

      if(((addr->u.Word[i] ^ prefix->u.Word[i]) & mask) != 0)
	return 0;

      if(len <= 16)
	return 1;

      len -= 16;
    }
#endif

  /* we should never get to this return statement */
  return -1;
}

static int ipv6_prefix(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  const struct in6_addr *a = sa->addr;
  const struct in6_addr *b = sb->addr;
  int i, j, x = 0;

#ifndef _WIN32
  uint32_t ua, ub;
#else
  uint16_t ua, ub;
#endif

#ifndef _WIN32
  for(i=0; i<4; i++)
    {
      ua = a->s6_addr32[i];
      ub = b->s6_addr32[i];

      if(ua == ub)
	{
	  x += 32;
	  continue;
	}

      for(j=0; j<32; j++)
	{
	  if(((ua ^ ub) & htonl(uint32_netmask[j])) != 0)
	    return x;
	  x++;
	}
    }
#else
  for(i=0; i<8; i++)
    {
      ua = a->u.Word[i];
      ub = b->u.Word[i];

      if(ua == ub)
	{
	  x += 16;
	  continue;
	}

      for(j=0; j<16; j++)
	{
	  if(((ua ^ ub) & htons(uint16_mask[j])) != 0)
	    return x;
	  x++;
	}
    }
#endif

  return x;
}

/*
 * ipv6_islinklocal
 *
 * an IPv6 address is a link local address if it is in fe80::/10
 */
static int ipv6_islinklocal(const scamper_addr_t *sa)
{
  const struct in6_addr *a = sa->addr;
  if(a->s6_addr[0] == 0xfe && (a->s6_addr[1] & 0xc0) == 0x80)
    return 1;
  return 0;
}

static int ipv6_netaddr(const scamper_addr_t *sa, void *net, int nl)
{
  const struct in6_addr *a = sa->addr;
  struct in6_addr p;
  int i;

  if(nl <= 0 || nl > 128 || sa == NULL || net == NULL)
    return -1;
  memset(&p, 0, sizeof(p));

#ifndef _WIN32
  for(i=0; i<4; i++)
    {
      if(nl >= 32)
	p.s6_addr32[i] = a->s6_addr32[i];
      else
	p.s6_addr32[i] = htonl(ntohl(a->s6_addr32[i]) & uint32_netmask[nl-1]);

      if(nl <= 32)
	break;
      nl -= 32;
    }
#else
  for(i=0; i<8; i++)
    {
      if(nl >= 16)
	p.u.Word[i] = a->u.Word[i];
      else
	p.u.Word[i] = htons(ntohs(a->u.Word[i]) & uint16_mask[nl-1]);
      if(nl <= 16)
	break;
      nl -= 16;
    }
#endif

  memcpy(net, &p, sizeof(p));
  return 0;
}

static int ipv6_isreserved(const scamper_addr_t *sa)
{
  const struct in6_addr *a = sa->addr;

  /* if the address falls outside of 2000::/3, then its reserved */
  if((a->s6_addr[0] & 0xe0) != 0x20)
    return 1;

  /* 2002::/16 (6to4) */
  if(a->s6_addr[1] == 0x02)
    return 1;

  /* 2001::/16 (many) */
  if(a->s6_addr[1] == 0x01)
    {
      if(a->s6_addr[2] == 0)
	{
	  /* 2001::/32 (teredo) */
	  if(a->s6_addr[3] == 0)
	    return 1;

	  /* 2001:2::/48 (benchmarking) */
	  if(a->s6_addr[3] == 0x2 && a->s6_addr[4] == 0 && a->s6_addr[5] == 0)
	    return 1;

	  /* 2001:3::/32 (AMT) */
	  if(a->s6_addr[3] == 0x3)
	    return 1;

	  /* 2001:4:112::/48 (AS112-v6) */
	  if(a->s6_addr[4] == 0x4 && a->s6_addr[5] == 0x1 &&
	     a->s6_addr[6] == 0x12)
	    return 1;

	  /* 2001:10::/28 (ORCHID) and 2001:20::/28 (ORCHIDv2) */
	  if(((a->s6_addr[3] & 0xf0) == 0x10) ||
	     ((a->s6_addr[3] & 0xf0) == 0x20))
	    return 1;
	}

      /* 2001:db8::/32 (documentation */
      if(a->s6_addr[2] == 0x0d && a->s6_addr[3] == 0xb8)
	return 1;
    }

  return 0;
}

static int ipv6_isunicast(const scamper_addr_t *sa)
{
  const struct in6_addr *a = sa->addr;
  if((a->s6_addr[0] & 0xe0) == 0x20)
    return 1;
  return 0;
}

static int ipv6_bit(const scamper_addr_t *sa, int bit)
{
  struct in6_addr *a = (struct in6_addr *)sa->addr;
  assert(bit > 0); assert(bit <= 128);
#ifndef _WIN32
  return (ntohl(a->s6_addr32[(bit-1)/32]) >> (31 - ((bit-1) % 32))) & 1;
#else
  return (ntohs(a->u.Word[(bit-1)/16]) >> (15 - ((bit-1) % 16))) & 1;
#endif
}

static int ipv6_fbd(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  const struct in6_addr *a, *b;
  int i, r;
  uint32_t v;

  assert(sa->type == SCAMPER_ADDR_TYPE_IPV6);
  assert(sb->type == SCAMPER_ADDR_TYPE_IPV6);
  a = (const struct in6_addr *)sa->addr;
  b = (const struct in6_addr *)sb->addr;

  for(i=0; i<4; i++)
    {
      if((v = ntohl(a->s6_addr32[i] ^ b->s6_addr32[i])) == 0)
	continue;

#ifdef HAVE___BUILTIN_CLZ
      r = __builtin_clz(v) + 1 + (i * 32);
#else
      r = 0;
      if(v & 0xFFFF0000) { v >>= 16; r += 16; }
      if(v & 0xFF00)     { v >>= 8;  r += 8;  }
      if(v & 0xF0)       { v >>= 4;  r += 4;  }
      if(v & 0xC)        { v >>= 2;  r += 2;  }
      if(v & 0x2)        {           r += 1;  }
      r = (32 - r) + (i * 32);
#endif

      return r;
    }

  return 128;
}

static int ethernet_cmp(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  assert(sa->type == SCAMPER_ADDR_TYPE_ETHERNET);
  assert(sb->type == SCAMPER_ADDR_TYPE_ETHERNET);
  return memcmp(sa->addr, sb->addr, 6);
}

static void ethernet_tostr(const scamper_addr_t *addr,
			   char *buf, const size_t len)
{
  uint8_t *mac = (uint8_t *)addr->addr;
  snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
	   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return;
}

static int ethernet_bit(const scamper_addr_t *addr, int bit)
{
  static const uint8_t mask[] = {0x01,0x80,0x40,0x20,0x10,0x08,0x04,0x02};
  static const uint8_t shift[] = {0, 7, 6, 5, 4, 3, 2, 1};
  uint8_t *mac = (uint8_t *)addr->addr;
  assert(bit > 0 && bit <= 48);
  return (mac[(bit-1)/8] & mask[bit%8]) >> shift[bit%8];
}

static int ethernet_fbd(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  const uint8_t *a, *b;
  uint8_t v;
  int i, r = 0;

  assert(sa->type == SCAMPER_ADDR_TYPE_ETHERNET);
  assert(sb->type == SCAMPER_ADDR_TYPE_ETHERNET);
  a = (const uint8_t *)sa->addr;
  b = (const uint8_t *)sb->addr;

  for(i=0; i<6; i++)
    {
      if((v = a[i] ^ b[i]) == 0)
	continue;
      if(v & 0xF0) { v >>= 4; r += 4; }
      if(v & 0xC)  { v >>= 2; r += 2; }
      if(v & 0x2)  {          r += 1; }
      r = (8 - r) + (i * 8);
      break;
    }

  return r;
}

static int firewire_cmp(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  assert(sa->type == SCAMPER_ADDR_TYPE_FIREWIRE);
  assert(sb->type == SCAMPER_ADDR_TYPE_FIREWIRE);
  return memcmp(sa->addr, sb->addr, 8);
}

static void firewire_tostr(const scamper_addr_t *addr,
			   char *buf, const size_t len)
{
  uint8_t *lla = (uint8_t *)addr->addr;
  snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
	   lla[0], lla[1], lla[2], lla[3], lla[4], lla[5], lla[6], lla[7]);
  return;
}

static int firewire_bit(const scamper_addr_t *addr, int bit)
{
  static const uint8_t mask[] = {0x01,0x80,0x40,0x20,0x10,0x08,0x04,0x02};
  static const uint8_t shift[] = {0, 7, 6, 5, 4, 3, 2, 1};
  uint8_t *lla = (uint8_t *)addr->addr;
  assert(bit > 0 && bit <= 64);
  return (lla[(bit-1)/8] >> mask[bit%8]) >> shift[bit%8];
}

static int firewire_fbd(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  const uint8_t *a, *b;
  uint8_t v;
  int i, r = 0;

  assert(sa->type == SCAMPER_ADDR_TYPE_FIREWIRE);
  assert(sb->type == SCAMPER_ADDR_TYPE_FIREWIRE);
  a = (const uint8_t *)sa->addr;
  b = (const uint8_t *)sb->addr;

  for(i=0; i<8; i++)
    {
      if((v = a[i] ^ b[i]) == 0)
	continue;
      if(v & 0xF0) { v >>= 4; r += 4; }
      if(v & 0xC)  { v >>= 2; r += 2; }
      if(v & 0x2)  {          r += 1; }
      r = (8 - r) + (i * 8);
      break;
    }

  return r;
}

size_t scamper_addr_size(const scamper_addr_t *sa)
{
  return handlers[sa->type-1].size;
}

const char *scamper_addr_tostr(const scamper_addr_t *sa,
			       char *dst, const size_t size)
{
  handlers[sa->type-1].tostr(sa, dst, size);
  return dst;
}

scamper_addr_t *scamper_addr_alloc(const int type, const void *addr)
{
  scamper_addr_t *sa;

  assert(addr != NULL);
  assert(type-1 >= 0);
  assert((size_t)(type-1) < sizeof(handlers)/sizeof(struct handler));

  if((sa = malloc_zero(sizeof(scamper_addr_t))) != NULL)
    {
      if((sa->addr = memdup(addr, handlers[type-1].size)) == NULL)
	{
	  free(sa);
	  return NULL;
	}

      sa->type = type;
      sa->refcnt = 1;
      sa->internal = NULL;
    }

  return sa;
}

/*
 * scamper_addr_resolve:
 *
 * resolve the address contained in addr to a sockaddr that
 * tells us what family the address belongs to, and has a binary
 * representation of the address
 */
scamper_addr_t *scamper_addr_resolve(const int af, const char *addr)
{
  struct addrinfo hints, *res, *res0;
  scamper_addr_t *sa = NULL;
  void *va;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags    = AI_NUMERICHOST;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_family   = af;

  if(getaddrinfo(addr, NULL, &hints, &res0) != 0 || res0 == NULL)
    {
      return NULL;
    }

  for(res = res0; res != NULL; res = res->ai_next)
    {
      if(res->ai_family == PF_INET)
	{
	  va = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
	  sa = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4, va);
	  break;
	}
      else if(res->ai_family == PF_INET6)
	{
	  va = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
	  sa = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6, va);
	  break;
	}
    }

  freeaddrinfo(res0);
  return sa;
}

int scamper_addr_inprefix(const scamper_addr_t *addr, const void *p, int len)
{
  if(handlers[addr->type-1].inprefix != NULL)
    return handlers[addr->type-1].inprefix(addr, p, len);
  return -1;
}

int scamper_addr_bit(const scamper_addr_t *a, int bit)
{
  return handlers[a->type-1].bit(a, bit);
}

int scamper_addr_fbd(const scamper_addr_t *a, const scamper_addr_t *b)
{
  return handlers[a->type-1].fbd(a, b);
}

int scamper_addr_prefix(const scamper_addr_t *a, const scamper_addr_t *b)
{
  if(a->type != b->type || handlers[a->type-1].prefix == NULL)
    return -1;

  return handlers[a->type-1].prefix(a, b);
}

int scamper_addr_prefixhosts(const scamper_addr_t *a, const scamper_addr_t *b)
{
  if(a->type != b->type || handlers[a->type-1].prefixhosts == NULL)
    return -1;

  return handlers[a->type-1].prefixhosts(a, b);
}

int scamper_addr_af(const scamper_addr_t *sa)
{
  if(sa->type == SCAMPER_ADDR_TYPE_IPV4)
    return AF_INET;
  else if(sa->type == SCAMPER_ADDR_TYPE_IPV6)
    return AF_INET6;
  else
    return -1;
}

int scamper_addr_islinklocal(const scamper_addr_t *a)
{
  if(handlers[a->type-1].islinklocal == NULL)
    return 0;
  return handlers[a->type-1].islinklocal(a);
}

int scamper_addr_netaddr(const scamper_addr_t *a, void *net, int netlen)
{
  if(handlers[a->type-1].netaddr == NULL)
    return -1;
  return handlers[a->type-1].netaddr(a, net, netlen);
}

int scamper_addr_isrfc1918(const scamper_addr_t *sa)
{
  uint32_t x;

  if(sa->type != SCAMPER_ADDR_TYPE_IPV4)
    return 0;

  x = ntohl(((const struct in_addr *)sa->addr)->s_addr);
  if((x & 0xff000000) == 0x0a000000 || /* 10.0.0.0    /8  */
     (x & 0xfff00000) == 0xac100000 || /* 172.16.0.0  /12 */
     (x & 0xffff0000) == 0xc0a80000)   /* 192.168.0.0 /16 */
    {
      return 1;
    }
  return 0;
}

int scamper_addr_is6to4(const scamper_addr_t *sa)
{
  const struct in6_addr *a;

  if(sa->type != SCAMPER_ADDR_TYPE_IPV6)
    return 0;

  a = sa->addr;
#ifndef _WIN32
  if(a->s6_addr[0] == 0x20 && a->s6_addr[1] == 0x02)
    return 1;
#else
  if(a->u.Word[0] == htons(0x2002))
     return 1;
#endif

  return 0;
}

int scamper_addr_isunicast(const scamper_addr_t *sa)
{
  if(handlers[sa->type-1].isunicast == NULL)
    return -1;
  return handlers[sa->type-1].isunicast(sa);
}

int scamper_addr_isreserved(const scamper_addr_t *sa)
{
  if(handlers[sa->type-1].isreserved == NULL)
    return -1;
  return handlers[sa->type-1].isreserved(sa);
}

scamper_addr_t *scamper_addrcache_get(scamper_addrcache_t *ac,
				      const int type, const void *addr)
{
  scamper_addr_t *sa, findme;

  findme.type = type;
  findme.addr = (void *)addr;

  if((sa = splaytree_find(ac->tree[type-1], &findme)) != NULL)
    {
      assert(sa->internal == ac);
      sa->refcnt++;
      return sa;
    }

  if((sa = scamper_addr_alloc(type, addr)) != NULL)
    {
      if(splaytree_insert(ac->tree[type-1], sa) == NULL)
	goto err;
      sa->internal = ac;
    }

  return sa;

 err:
  scamper_addr_free(sa);
  return NULL;
}

/*
 * scamper_addr_resolve:
 *
 * resolve the address contained in addr to a sockaddr that
 * tells us what family the address belongs to, and has a binary
 * representation of the address
 */
scamper_addr_t *scamper_addrcache_resolve(scamper_addrcache_t *addrcache,
					  const int af, const char *addr)
{
  struct addrinfo hints, *res, *res0;
  scamper_addr_t *sa = NULL;
  void *va;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags    = AI_NUMERICHOST;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_family   = af;

  if(getaddrinfo(addr, NULL, &hints, &res0) != 0 || res0 == NULL)
    {
      return NULL;
    }

  for(res = res0; res != NULL; res = res->ai_next)
    {
      if(res->ai_family == PF_INET)
	{
	  va = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
	  sa = scamper_addrcache_get(addrcache, SCAMPER_ADDR_TYPE_IPV4, va);
	  break;
	}
      else if(res->ai_family == PF_INET6)
	{
	  va = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
	  sa = scamper_addrcache_get(addrcache, SCAMPER_ADDR_TYPE_IPV6, va);
	  break;
	}
    }

  freeaddrinfo(res0);
  return sa;
}

scamper_addr_t *scamper_addr_use(scamper_addr_t *sa)
{
  if(sa != NULL)
    sa->refcnt++;
  return sa;
}

void scamper_addr_free(scamper_addr_t *sa)
{
  scamper_addrcache_t *ac;

  if(sa == NULL)
    {
      return;
    }

  assert(sa->refcnt > 0);

  if(--sa->refcnt > 0)
    return;

  if((ac = sa->internal) != NULL)
    splaytree_remove_item(ac->tree[sa->type-1], sa);

  free(sa->addr);
  free(sa);
  return;
}

int scamper_addr_cmp(const scamper_addr_t *a, const scamper_addr_t *b)
{
  assert(a->type > 0 && a->type <= sizeof(handlers)/sizeof(struct handler));
  assert(b->type > 0 && b->type <= sizeof(handlers)/sizeof(struct handler));

  /*
   * if the two address structures point to the same memory, then they are
   * a match
   */
  if(a == b)
    {
      return 0;
    }

  /*
   * if the two address types are the same, then do a comparison on the
   * underlying addresses
   */
  if(a->type == b->type)
    {
      return handlers[a->type-1].cmp(a, b);
    }

  /* otherwise, return a code based on the difference between the types */
  if(a->type < b->type)
    {
      return -1;
    }
  else
    {
      return 1;
    }
}

int scamper_addr_human_cmp(const scamper_addr_t *a, const scamper_addr_t *b)
{
  assert(a->type > 0 && a->type <= sizeof(handlers)/sizeof(struct handler));
  assert(b->type > 0 && b->type <= sizeof(handlers)/sizeof(struct handler));

  /*
   * if the two address structures point to the same memory, then they are
   * a match
   */
  if(a == b)
    {
      return 0;
    }

  /*
   * if the two address types are the same, then do a comparison on the
   * underlying addresses
   */
  if(a->type == b->type)
    {
      return handlers[a->type-1].human_cmp(a, b);
    }

  /* otherwise, return a code based on the difference between the types */
  if(a->type < b->type)
    {
      return -1;
    }
  else
    {
      return 1;
    }
}

int scamper_addr_raw_cmp(const scamper_addr_t *a, const void *raw)
{
  return memcmp(a->addr, raw, handlers[a->type-1].size);
}

static void free_cb(void *node)
{
  ((scamper_addr_t *)node)->internal = NULL;
  return;
}

void scamper_addrcache_free(scamper_addrcache_t *ac)
{
  int i;

  for(i=(sizeof(handlers)/sizeof(struct handler))-1; i>=0; i--)
    if(ac->tree[i] != NULL)
      splaytree_free(ac->tree[i], free_cb);
  free(ac);

  return;
}

scamper_addrcache_t *scamper_addrcache_alloc()
{
  scamper_addrcache_t *ac;
  int i;

  if((ac = malloc_zero(sizeof(scamper_addrcache_t))) == NULL)
    return NULL;

  for(i=(sizeof(handlers)/sizeof(struct handler))-1; i>=0; i--)
    {
      ac->tree[i] = splaytree_alloc((splaytree_cmp_t)handlers[i].cmp);
      if(ac->tree[i] == NULL)
	goto err;
    }

  return ac;

 err:
  scamper_addrcache_free(ac);
  return NULL;
}
