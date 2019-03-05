/*
 * scamper_addr2mac.c: handle a cache of IP to MAC address mappings
 *
 * $Id: scamper_addr2mac.c,v 1.41 2017/12/03 09:38:26 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2014 The Regents of the University of California
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
  "$Id: scamper_addr2mac.c,v 1.41 2017/12/03 09:38:26 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#if defined(__APPLE__)
#define HAVE_BSD_ARPCACHE
#endif

#if defined(__FreeBSD__)
#define HAVE_BSD_ARPCACHE
#endif

#if defined(__NetBSD__)
#define HAVE_BSD_ARPCACHE
#endif

#if defined(__OpenBSD__)
#define HAVE_BSD_ARPCACHE
#endif

#if defined(__DragonFly__)
#define HAVE_BSD_ARPCACHE
#endif

#if defined(__linux__)
struct ndmsg
{
  unsigned char   ndm_family;
  unsigned char   ndm_pad1;
  unsigned short  ndm_pad2;
  int             ndm_ifindex;
  uint16_t        ndm_state;
  uint8_t         ndm_flags;
  uint8_t         ndm_type;
};

struct sockaddr_nl
{
  sa_family_t     nl_family;
  unsigned short  nl_pad;
  uint32_t        nl_pid;
  uint32_t        nl_groups;
};

struct nlmsghdr
{
  uint32_t        nlmsg_len;
  uint16_t        nlmsg_type;
  uint16_t        nlmsg_flags;
  uint32_t        nlmsg_seq;
  uint32_t        nlmsg_pid;
};

struct rtattr
{
  unsigned short  rta_len;
  unsigned short  rta_type;
};

#define NLMSG_ERROR         0x2
#define NLMSG_DONE          0x3
#define NLMSG_ALIGNTO       4
#define NLMSG_ALIGN(len)    (((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1))
#define NLMSG_LENGTH(len)   ((len)+NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_DATA(nlh)     ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
#define NLMSG_NEXT(nlh,len) ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
                             (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh,len)   ((len) > 0 && (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
                             (nlh)->nlmsg_len <= (len))

#define RTA_ALIGNTO           4
#define RTA_ALIGN(len)        (((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1))
#define RTA_LENGTH(len)       (RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_DATA(rta)         ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
#define RTA_OK(rta,len)       ((len) > 0 && (rta)->rta_len >= sizeof(struct rtattr) && \
                               (rta)->rta_len <= (len))
#define RTA_NEXT(rta,attrlen) ((attrlen) -= RTA_ALIGN((rta)->rta_len), \
                               (struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_PAYLOAD(rta)      ((int)((rta)->rta_len) - RTA_LENGTH(0))

#define NDA_DST         1
#define NDA_LLADDR      2
#define NDA_MAX        (NDA_LLADDR+1)
#define NDA_RTA(r)      ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))

#define RTM_BASE        0x10
#define RTM_NEWNEIGH   (RTM_BASE+12)
#define RTM_GETNEIGH   (RTM_BASE+14)
#define NLM_F_REQUEST   1
#define NLM_F_ROOT      0x100
#define NLM_F_MATCH     0x200
#define NETLINK_ROUTE   0
#define NUD_REACHABLE   0x02

#endif /* __linux__ */

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_addr2mac.h"
#include "scamper_rtsock.h"
#include "scamper_debug.h"
#include "utils.h"
#include "mjl_splaytree.h"

typedef struct addr2mac
{
  int             ifindex;
  scamper_addr_t *ip;
  scamper_addr_t *mac;
  time_t          expire;
} addr2mac_t;

static splaytree_t *tree = NULL;
extern scamper_addrcache_t *addrcache;

static int addr2mac_cmp(const addr2mac_t *a, const addr2mac_t *b)
{
  if(a->ifindex < b->ifindex) return -1;
  if(a->ifindex > b->ifindex) return  1;
  return scamper_addr_cmp(a->ip, b->ip);
}

static void addr2mac_free(addr2mac_t *addr2mac)
{
  if(addr2mac->ip != NULL) scamper_addr_free(addr2mac->ip);
  if(addr2mac->mac != NULL) scamper_addr_free(addr2mac->mac);
  free(addr2mac);
  return;
}

static addr2mac_t *addr2mac_alloc(const int ifindex, scamper_addr_t *ip,
				  scamper_addr_t *mac, time_t expire)
{
  addr2mac_t *addr2mac;

  if((addr2mac = malloc_zero(sizeof(addr2mac_t))) == NULL)
    {
      printerror(__func__, "could not malloc addr2mac");
      return NULL;
    }

  addr2mac->ifindex = ifindex;
  addr2mac->ip      = ip  != NULL ? scamper_addr_use(ip)  : NULL;
  addr2mac->mac     = mac != NULL ? scamper_addr_use(mac) : NULL;
  addr2mac->expire  = expire;
  return addr2mac;
}

static int addr2mac_add(const int ifindex, const int type, const void *ipraw,
			const void *macraw, const time_t expire)
{
  const int mt = SCAMPER_ADDR_TYPE_ETHERNET;
  scamper_addr_t *mac = NULL;
  scamper_addr_t *ip  = NULL;
  addr2mac_t *addr2mac = NULL;
  char ipstr[128], macstr[128];

  if((ip = scamper_addrcache_get(addrcache, type, ipraw)) == NULL)
    {
      printerror(__func__, "could not get ip");
      goto err;
    }

  if((mac = scamper_addrcache_get(addrcache, mt, macraw)) == NULL)
    {
      printerror(__func__, "could not get mac");
      goto err;
    }

  if((addr2mac = addr2mac_alloc(ifindex, ip, mac, expire)) == NULL)
    {
      goto err;
    }

  scamper_addr_free(ip);  ip  = NULL;
  scamper_addr_free(mac); mac = NULL;

  if(splaytree_insert(tree, addr2mac) == NULL)
    {
      printerror(__func__, "could not add %s:%s to tree",
		 scamper_addr_tostr(addr2mac->ip, ipstr, sizeof(ipstr)),
		 scamper_addr_tostr(addr2mac->mac, macstr, sizeof(macstr)));
      goto err;
    }

  scamper_debug(__func__, "ifindex %d ip %s mac %s expire %d", ifindex,
		scamper_addr_tostr(addr2mac->ip, ipstr, sizeof(ipstr)),
		scamper_addr_tostr(addr2mac->mac, macstr, sizeof(macstr)),
		expire);
  return 0;

 err:
  if(addr2mac != NULL) addr2mac_free(addr2mac);
  if(mac != NULL) scamper_addr_free(mac);
  if(ip != NULL) scamper_addr_free(ip);
  return -1;
}

int scamper_addr2mac_add(int ifindex, scamper_addr_t *ip, scamper_addr_t *mac)
{
  addr2mac_t *a2m = NULL;
  char ipstr[128], macstr[128];

  if(scamper_addr2mac_whohas(ifindex, ip) != NULL)
    return 0;

  if((a2m = addr2mac_alloc(ifindex, ip, mac, 0)) == NULL)
    return -1;

  if(splaytree_insert(tree, a2m) == NULL)
    {
      printerror(__func__, "could not add %s:%s to tree",
		 scamper_addr_tostr(a2m->ip, ipstr, sizeof(ipstr)),
		 scamper_addr_tostr(a2m->mac, macstr, sizeof(macstr)));
      addr2mac_free(a2m);
      return -1;
    }

  scamper_debug(__func__, "ifindex %d ip %s mac %s", ifindex,
		scamper_addr_tostr(a2m->ip, ipstr, sizeof(ipstr)),
		scamper_addr_tostr(a2m->mac, macstr, sizeof(macstr)));
  return 0;
}

/*
 * scamper_addr2mac_whohas
 *
 * return the MAC address associated with an IP address, if it is cached.
 */
scamper_addr_t *scamper_addr2mac_whohas(const int ifindex, scamper_addr_t *dst)
{
  addr2mac_t findme, *addr2mac;

  findme.ifindex = ifindex;
  findme.ip = dst;

  /* see if this IP address has a record in our tree */
  if((addr2mac = splaytree_find(tree, &findme)) != NULL)
    {
      return addr2mac->mac;
    }

  return NULL;
}

#if defined(__linux__)
static int addr2mac_init_linux()
{
  struct nlmsghdr   *nlmsg;
  struct ndmsg      *ndmsg;
  struct rtattr     *rta, *tb[NDA_MAX];
  struct sockaddr_nl snl;
  struct msghdr      msg;
  struct iovec       iov;
  struct timeval     tv;
  pid_t              pid;
  uint8_t            buf[16384];
  ssize_t            ssize;
  ssize_t            len;
  int                rlen;
  int                fd = -1;
  void              *ip, *mac;
  int                iptype;

  pid = getpid();

  memset(buf, 0, sizeof(buf));
  nlmsg = (struct nlmsghdr *)buf;
  nlmsg->nlmsg_len   = NLMSG_LENGTH(sizeof(struct ndmsg));
  nlmsg->nlmsg_type  = RTM_GETNEIGH;
  nlmsg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH;
  nlmsg->nlmsg_seq   = 0;
  nlmsg->nlmsg_pid   = pid;

  ndmsg = NLMSG_DATA(nlmsg);
  ndmsg->ndm_family = AF_UNSPEC;

  if((fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) == -1)
    {
      printerror(__func__, "could not open netlink");
      goto err;
    }

  len = nlmsg->nlmsg_len;
  if((ssize = send(fd, buf, len, 0)) < len)
    {
      if(ssize == -1)
	{
	  printerror(__func__, "could not send netlink");
	}
      goto err;
    }

  for(;;)
    {
      iov.iov_base = buf;
      iov.iov_len = sizeof(buf);

      msg.msg_name = &snl;
      msg.msg_namelen = sizeof(snl);
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_control = NULL;
      msg.msg_controllen = 0;
      msg.msg_flags = 0;

      if((len = recvmsg(fd, &msg, 0)) == -1)
	{
	  if(errno == EINTR) continue;
	  printerror(__func__, "could not recvmsg");
	  goto err;
	}

      gettimeofday_wrap(&tv);

      nlmsg = (struct nlmsghdr *)buf;
      while(NLMSG_OK(nlmsg, len))
	{
	  if(nlmsg->nlmsg_pid != pid || nlmsg->nlmsg_seq != 0)
	    {
	      goto skip;
	    }

	  if(nlmsg->nlmsg_type == NLMSG_DONE)
	    {
	      goto done;
	    }

	  if(nlmsg->nlmsg_type == NLMSG_ERROR)
	    {
	      scamper_debug(__func__, "nlmsg error");
	      goto err;
	    }

	  /* get current neighbour entries only */
	  if(nlmsg->nlmsg_type != RTM_NEWNEIGH)
	    {
	      goto skip;
	    }

	  /* make sure the address is reachable */
	  ndmsg = NLMSG_DATA(nlmsg);
	  if((ndmsg->ndm_state & NUD_REACHABLE) == 0)
	    {
	      goto skip;
	    }

	  /* make sure we can process this address type */
	  switch(ndmsg->ndm_family)
	    {
	    case AF_INET:
	      iptype = SCAMPER_ADDR_TYPE_IPV4;
	      break;

	    case AF_INET6:
	      iptype = SCAMPER_ADDR_TYPE_IPV6;
	      break;

	    default:
	      goto skip;
	    }

	  /* fill a table with parameters from the payload */
	  memset(tb, 0, sizeof(tb));
	  rlen = nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));
	  for(rta = NDA_RTA(ndmsg); RTA_OK(rta,rlen); rta = RTA_NEXT(rta,rlen))
	    {
	      if(rta->rta_type >= NDA_MAX)
		continue;
	      tb[rta->rta_type] = rta;
	    }

	  /*
	   * skip if we don't have a destination IP address, or if
	   * we don't have an ethernet mac address
	   */
	  if(tb[NDA_DST] == NULL ||
	     tb[NDA_LLADDR] == NULL || RTA_PAYLOAD(tb[NDA_LLADDR]) != 6)
	    {
	      goto skip;
	    }

	  ip = RTA_DATA(tb[NDA_DST]);
	  mac = RTA_DATA(tb[NDA_LLADDR]);

	  addr2mac_add(ndmsg->ndm_ifindex, iptype, ip, mac, tv.tv_sec+600);

	skip:
	  nlmsg = NLMSG_NEXT(nlmsg, len);
	}
    }

 done:
  close(fd);
  return 0;

 err:
  close(fd);
  return -1;
}
#endif

#if defined(HAVE_BSD_ARPCACHE)
static void addr2mac_mib_make(int *mib, int af)
{
  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = af;
  mib[4] = NET_RT_FLAGS;
#if defined(RTF_LLINFO)
  mib[5] = RTF_LLINFO;
#else
  mib[5] = 0;
#endif
  return;
}

static int addr2mac_init_bsd(void)
{
  struct rt_msghdr      *rtm;
  struct sockaddr_inarp *sin;
  struct sockaddr_in6   *sin6;
  struct sockaddr_dl    *sdl;
  int                    iptype;
  void                  *ip, *mac;
  int                    mib[6];
  void                  *vbuf = NULL;
  uint8_t               *buf;
  size_t                 i, j, size;

  /*
   * firstly, get the IPv4 ARP cache and load that.
   * we get it by using the sysctl interface to the cache and parsing each
   * entry
   */
  addr2mac_mib_make(mib, AF_INET);
  if(sysctl_wrap(mib, 6, &vbuf, &size) == -1)
    {
      printerror(__func__, "sysctl arp cache");
      goto err;
    }

  iptype = SCAMPER_ADDR_TYPE_IPV4;
  buf = (uint8_t *)vbuf;
  for(i=0; i<size; i += rtm->rtm_msglen)
    {
      j = i;
      rtm = (struct rt_msghdr *)(buf + j); j += sizeof(struct rt_msghdr);
      sin = (struct sockaddr_inarp *)(buf + j);
      j += scamper_rtsock_roundup(sin->sin_len);
      sdl = (struct sockaddr_dl *)(buf + j);

      /* don't deal with permanent arp entries at this time */
      if(sdl->sdl_type != IFT_ETHER ||
	 sdl->sdl_alen != ETHER_ADDR_LEN)
	{
	  continue;
	}

      ip = &sin->sin_addr;
      mac = sdl->sdl_data + sdl->sdl_nlen;

      addr2mac_add(sdl->sdl_index, iptype, ip, mac,
		   (time_t)rtm->rtm_rmx.rmx_expire);
    }
  if(vbuf != NULL)
    {
      free(vbuf);
      vbuf = NULL;
    }

  /* now it is time to get the IPv6 neighbour discovery cache */
  addr2mac_mib_make(mib, AF_INET6);
  if(sysctl_wrap(mib, 6, &vbuf, &size) == -1)
    {
      /*
       * assume that EINVAL means that IPv6 support is not provided on
       * this system
       */
      if(errno == EINVAL || errno == EAFNOSUPPORT)
	return 0;

      printerror(__func__, "sysctl ndp cache");
      goto err;
    }

  iptype = SCAMPER_ADDR_TYPE_IPV6;
  buf = (uint8_t *)vbuf;
  for(i=0; i<size; i += rtm->rtm_msglen)
    {
      j = i;
      rtm = (struct rt_msghdr *)(buf + j); j += sizeof(struct rt_msghdr);
      sin6 = (struct sockaddr_in6 *)(buf + j);
      j += scamper_rtsock_roundup(sin6->sin6_len);
      sdl = (struct sockaddr_dl *)(buf + j);

      if(sdl->sdl_family != AF_LINK ||
	 sdl->sdl_type != IFT_ETHER ||
	 sdl->sdl_alen != ETHER_ADDR_LEN ||
	 (rtm->rtm_flags & RTF_HOST) == 0)
	{
	  continue;
	}

      /* clear out any embedded ifindex in a linklocal address */
      if(IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
	{
	  sin6->sin6_addr.s6_addr[2] = 0;
	  sin6->sin6_addr.s6_addr[3] = 0;
	}

      ip = &sin6->sin6_addr;
      mac = sdl->sdl_data + sdl->sdl_nlen;

      addr2mac_add(sdl->sdl_index, iptype, ip, mac,
		   (time_t)rtm->rtm_rmx.rmx_expire);
    }
  if(vbuf != NULL)
    {
      free(vbuf);
      vbuf = NULL;
    }

  return 0;

 err:
  if(vbuf != NULL) free(vbuf);
  return -1;
}
#endif

#ifdef _WIN32
static int GetIpNetTable_wrap(MIB_IPNETTABLE **table, ULONG *size)
{
  int rc;

  *table = NULL;
  *size  = 0;

  for(;;)
    {
      if(*size > 0 && (*table = malloc_zero(*size)) == NULL)
	return -1;

      if((rc = GetIpNetTable(*table, size, FALSE)) == NO_ERROR)
	return 0;

      free(*table);
      *table = NULL;

      if(rc != ERROR_INSUFFICIENT_BUFFER)
	break;
    }

  return -1;
}

static int addr2mac_init_win32()
{
  MIB_IPNETTABLE *table;
  ULONG           size;
  DWORD           dw;
  int             iptype;

  iptype = SCAMPER_ADDR_TYPE_IPV4;
  if(GetIpNetTable_wrap(&table, &size) == 0 && table != NULL)
    {
      for(dw=0; dw<table->dwNumEntries; dw++)
	{
	  addr2mac_add(table->table[dw].dwIndex, iptype,
		       &table->table[dw].dwAddr,
		       table->table[dw].bPhysAddr, 0);
	}
      free(table);
    }

  return 0;
}
#endif

int scamper_addr2mac_init()
{
  if((tree = splaytree_alloc((splaytree_cmp_t)addr2mac_cmp)) == NULL)
    {
      printerror(__func__, "could not alloc tree");
      return -1;
    }

  if(scamper_option_noinitndc() != 0)
    return 0;

#ifdef HAVE_BSD_ARPCACHE
  if(addr2mac_init_bsd() != 0)
    {
      return -1;
    }
#endif

#ifdef __linux__
  if(addr2mac_init_linux() != 0)
    {
      return -1;
    }
#endif

#ifdef _WIN32
  if(addr2mac_init_win32() != 0)
    {
      return -1;
    }
#endif

  return 0;
}

void scamper_addr2mac_cleanup()
{
  splaytree_free(tree, (splaytree_free_t)addr2mac_free);
  return;
}
