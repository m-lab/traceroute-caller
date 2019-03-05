/*
 * scamper_rtsock: code to deal with a route socket or equivalent
 *
 * $Id: scamper_rtsock.c,v 1.82 2017/12/03 09:38:27 mjl Exp $
 *
 *          Matthew Luckie
 *
 *          Supported by:
 *           The University of Waikato
 *           NLANR Measurement and Network Analysis
 *           CAIDA
 *           The WIDE Project
 *
 * The purpose of this code is to obtain the outgoing interface's index
 * using whatever mechanisms the operating system supports.  A route
 * socket is created where necessary and is kept open for the lifetime
 * of scamper.
 *
 * scamper_rtsock_getifindex returns the interface index on success.
 * if an error occurs, it returns -1.  as route sockets are unreliable
 * sockets, if we do not get an expected response, we return -2 to
 * indicate to the caller to try again.
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
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
  "$Id: scamper_rtsock.c,v 1.82 2017/12/03 09:38:27 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#if defined(__APPLE__)
static int broken = -1;
#endif

/* include support for the netlink socket in linux */
#if defined(__linux__)

struct nlmsghdr
{
  uint32_t        nlmsg_len;
  uint16_t        nlmsg_type;
  uint16_t        nlmsg_flags;
  uint32_t        nlmsg_seq;
  uint32_t        nlmsg_pid;
};

struct nlmsgerr
{
  int             error;
  struct nlmsghdr msg;
};

struct rtattr
{
  unsigned short  rta_len;
  unsigned short  rta_type;
};

struct rtmsg
{
  unsigned char   rtm_family;
  unsigned char   rtm_dst_len;
  unsigned char   rtm_src_len;
  unsigned char   rtm_tos;
  unsigned char   rtm_table;
  unsigned char   rtm_protocol;
  unsigned char   rtm_scope;
  unsigned char   rtm_type;
  unsigned        rtm_flags;
};

#define NLMSG_ERROR         0x2
#define NLMSG_ALIGNTO       4
#define NLMSG_ALIGN(len)   (((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1))
#define NLMSG_LENGTH(len)  ((len)+NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_DATA(nlh)    ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))

#define RTA_ALIGNTO           4
#define RTA_ALIGN(len)        (((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1))
#define RTA_LENGTH(len)       (RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_DATA(rta)         ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
#define RTA_OK(rta,len)       ((len) > 0 && (rta)->rta_len >= sizeof(struct rtattr) && \
                               (rta)->rta_len <= (len))
#define RTA_NEXT(rta,attrlen) ((attrlen) -= RTA_ALIGN((rta)->rta_len), \
                               (struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_UNSPEC            0
#define RTA_DST               1
#define RTA_SRC               2
#define RTA_IIF               3
#define RTA_OIF               4
#define RTA_GATEWAY           5
#define RTA_PRIORITY          6
#define RTA_PREFSRC           7
#define RTA_METRICS           8
#define RTA_MULTIPATH         9
#define RTA_PROTOINFO         10
#define RTA_FLOW              11
#define RTA_CACHEINFO         12
#define RTA_SESSION           13

#define RTM_RTA(r)         ((struct rtattr*)(((char*)(r)) + \
                            NLMSG_ALIGN(sizeof(struct rtmsg))))
#define RTM_BASE            0x10
#define RTM_NEWROUTE       (RTM_BASE+8)
#define RTM_GETROUTE       (RTM_BASE+10)
#define NLM_F_REQUEST       1
#define NETLINK_ROUTE       0

#endif

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_fds.h"
#include "scamper_rtsock.h"
#include "scamper_privsep.h"
#include "scamper_osinfo.h"
#include "scamper_debug.h"
#include "utils.h"
#include "mjl_list.h"

extern scamper_addrcache_t *addrcache;

#ifndef _WIN32
typedef struct rtsock_pair
{
  scamper_route_t *route; /* query */
  uint16_t         seq;   /* sequence number used */
  dlist_node_t    *node;  /* pointer to node in pair dlist */
} rtsock_pair_t;

static pid_t    pid;          /* [unpriviledged] process id */
static uint16_t seq   = 0;    /* next sequence number to use */
static dlist_t *pairs = NULL; /* list of addresses queried with their seq */

static rtsock_pair_t *rtsock_pair_alloc(scamper_route_t *route, int seq)
{
  rtsock_pair_t *pair;
  if((pair = malloc_zero(sizeof(rtsock_pair_t))) == NULL)
    return NULL;
  pair->route = route;
  pair->seq = seq;
  if((pair->node = dlist_head_push(pairs, pair)) == NULL)
    {
      free(pair);
      return NULL;
    }
  route->internal = pair;
  return pair;
}

static void rtsock_pair_free(rtsock_pair_t *pair)
{
  if(pair == NULL)
    return;
  pair->route->internal = NULL;
  if(pair->node != NULL)
    dlist_node_pop(pairs, pair->node);
  free(pair);
  return;
}

static rtsock_pair_t *rtsock_pair_get(uint16_t seq)
{
  rtsock_pair_t *pair;
  dlist_node_t  *node;

  for(node=dlist_head_node(pairs); node != NULL; node=dlist_node_next(node))
    {
      pair = dlist_node_item(node);
      if(pair->seq != seq)
	continue;
      dlist_node_pop(pairs, node);
      pair->node = NULL;
      return pair;
    }

  return NULL;
}

#if defined(HAVE_BSD_ROUTE_SOCKET)
#if 0
static void rtmsg_dump(const uint8_t *buf, size_t len)
{
  char str[80];
  size_t i, off = 0;
  int k = 0;

  for(i=0; i<len; i++)
    {
      if(k == 20)
	{
	  printerror_msg(__func__, "%s", str);
	  k = 0;
	  off = 0;
	}

      if(k != 0 && (k % 4) == 0)
	string_concat(str, sizeof(str), &off, " ");
      string_concat(str, sizeof(str), &off, "%02x", buf[i]);
      k++;
    }

  if(k != 0)
    printerror_msg(__func__, "%s", str);
  return;
}
#endif

int scamper_rtsock_roundup(size_t len)
{
#ifdef __APPLE__
  const scamper_osinfo_t *osinfo;

  if(broken == -1)
    {
      osinfo = scamper_osinfo_get();
      if(osinfo->os_id == SCAMPER_OSINFO_OS_DARWIN &&
	 osinfo->os_rel_dots > 0 && osinfo->os_rel[0] >= 10)
	broken = 1;
      else
	broken = 0;
    }

  if(broken != 0)
    {
      if(len > 0)
	return (1 + ((len - 1) | (sizeof(uint32_t) - 1)));
      else
	return sizeof(uint32_t);
    }
#endif

  return ((len > 0) ? (1 + ((len - 1) | (sizeof(long) - 1))) : sizeof(long));
}

/*
 * scamper_rtsock_getifindex
 *
 * figure out the outgoing interface id / route using route sockets
 *
 * route(4) gives an overview of the functions called in here
 */
static int scamper_rtsock_getifindex(int fd, scamper_addr_t *dst)
{
  struct sockaddr_storage sas;
  struct sockaddr_dl *sdl;
  struct rt_msghdr *rtm;
  uint8_t buf[1024];
  size_t len;
  ssize_t ss;
  int slen;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(dst))
    sockaddr_compose((struct sockaddr *)&sas, AF_INET, dst->addr, 0);
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(dst))
    sockaddr_compose((struct sockaddr *)&sas, AF_INET6, dst->addr, 0);
  else
    return -1;

  if((slen = sockaddr_len((struct sockaddr *)&sas)) <= 0)
    return -1;

  len = sizeof(struct rt_msghdr) + scamper_rtsock_roundup(slen) +
    scamper_rtsock_roundup(sizeof(struct sockaddr_dl));
  if(len > sizeof(buf))
    return -1;

  memset(buf, 0, len);
  rtm = (struct rt_msghdr *)buf;
  rtm->rtm_msglen  = len;
  rtm->rtm_version = RTM_VERSION;
  rtm->rtm_type    = RTM_GET;
  rtm->rtm_addrs   = RTA_DST | RTA_IFP;
  rtm->rtm_pid     = pid;
  rtm->rtm_seq     = seq;
  memcpy(buf + sizeof(struct rt_msghdr), &sas, (size_t)slen);

  sdl = (struct sockaddr_dl *)(buf + sizeof(struct rt_msghdr) +
			       scamper_rtsock_roundup(slen));
  sdl->sdl_family = AF_LINK;

#if !defined(__sun__)
  sdl->sdl_len    = sizeof(struct sockaddr_dl);
#endif

  if((ss = write(fd, buf, len)) < 0 || (size_t)ss != len)
    {
      printerror(__func__, "could not write routing socket");
      return -1;
    }

  return 0;
}
#endif /* HAVE_BSD_ROUTE_SOCKET */

#if defined(__linux__)
/*
 * scamper_rtsock_getifindex
 *
 * figure out the outgoing interface id / route using linux netlink
 *
 * this works on Linux systems with netlink compiled into the kernel.
 * i think netlink comes compiled into the kernel with most distributions
 * these days.
 *
 * the man pages netlink(3), netlink(7), rtnetlink(3), and rtnetlink(7)
 * give an overview of the functions and structures used in here, but the
 * documentation in those man pages is pretty crap.
 * you'd be better off studying netlink.h and rtnetlink.h
 */
static int scamper_rtsock_getifindex(int fd, scamper_addr_t *dst)
{
  struct nlmsghdr *nlmsg;
  struct rtmsg    *rtmsg;
  struct rtattr   *rta;
  int              error;
  int              dst_len;
  uint8_t          buf[1024];
  int              af;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(dst))
    {
      dst_len  = 4;
      af       = AF_INET;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(dst))
    {
      dst_len  = 16;
      af       = AF_INET6;
    }
  else
    {
      return -1;
    }

  /*
   * fill out a route request.
   * we use the standard netlink header, with a route msg subheader
   * to query for the outgoing interface.
   * the message includes one attribute - the destination address
   * we are querying the route for.
   */
  memset(buf, 0, sizeof(buf));
  nlmsg  = (struct nlmsghdr *)buf;
  nlmsg->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
  nlmsg->nlmsg_type  = RTM_GETROUTE;
  nlmsg->nlmsg_flags = NLM_F_REQUEST;
  nlmsg->nlmsg_seq   = seq;
  nlmsg->nlmsg_pid   = pid;

  /* netlink wants the bit length of each address */
  rtmsg = NLMSG_DATA(nlmsg);
  rtmsg->rtm_family  = af;
  rtmsg->rtm_flags   = 0;
  rtmsg->rtm_dst_len = dst_len * 8;

  rta = (struct rtattr *)(buf + NLMSG_ALIGN(nlmsg->nlmsg_len));
  rta->rta_type = RTA_DST;
  rta->rta_len  = RTA_LENGTH(dst_len);
  nlmsg->nlmsg_len += RTA_LENGTH(dst_len);
  memcpy(RTA_DATA(rta), dst->addr, dst_len);

  /* send the request */
  if((error = send(fd, buf, nlmsg->nlmsg_len, 0)) != nlmsg->nlmsg_len)
    {
      printerror(__func__, "could not send");
      return -1;
    }

  return 0;
}
#endif

int scamper_rtsock_getroute(scamper_fd_t *fdn, scamper_route_t *route)
{
  int fd;

  /* get the route socket fd */
  if((fd = scamper_fd_fd_get(fdn)) == -1)
    return -1;

  /* ask the question */
  if(scamper_rtsock_getifindex(fd, route->dst) != 0)
    return -1;

  /* keep track of the question */
  if(rtsock_pair_alloc(route, seq++) == NULL)
    return -1;
  return 0;
}

#if defined(__linux__)
#if 0
static void rtattr_dump(struct rtattr *rta)
{
  char *rta_type;
  char  rta_data[64];
  int   i;

  switch(rta->rta_type)
    {
    case RTA_UNSPEC:    rta_type = "unspec";    break;
    case RTA_DST:       rta_type = "dst";       break;
    case RTA_SRC:       rta_type = "src";       break;
    case RTA_IIF:       rta_type = "iif";       break;
    case RTA_OIF:       rta_type = "oif";       break;
    case RTA_GATEWAY:   rta_type = "gateway";   break;
    case RTA_PRIORITY:  rta_type = "priority";  break;
    case RTA_PREFSRC:   rta_type = "prefsrc";   break;
    case RTA_METRICS:   rta_type = "metrics";   break;
    case RTA_MULTIPATH: rta_type = "multipath"; break;
    case RTA_PROTOINFO: rta_type = "protoinfo"; break;
    case RTA_FLOW:      rta_type = "flow";      break;
    case RTA_CACHEINFO: rta_type = "cacheinfo"; break;
    case RTA_SESSION:   rta_type = "session";   break;
    default:            rta_type = "<unknown>"; break;
    }

  for(i=0;i<rta->rta_len-sizeof(struct rtattr)&&i<(sizeof(rta_data)/2)-1;i++)
    {
      snprintf(&rta_data[i*2], 3, "%02x",
	       *(uint8_t *)(((char *)rta) + sizeof(struct rtattr) + i));
    }

  if(i != 0)
    {
      scamper_debug(__func__, "type %s len %d data %s",
		    rta_type, rta->rta_len-sizeof(struct rtattr), rta_data);
    }
  else
    {
      scamper_debug(__func__, "type %s\n", rta_type);
    }

  return;
}
#endif

static void rtsock_parsemsg(uint8_t *buf, size_t len)
{
  struct nlmsghdr *nlmsg;
  struct nlmsgerr *nlerr;
  struct rtmsg    *rtmsg;
  struct rtattr   *rta;
  void            *gwa = NULL;
  int              ifindex = -1;
  scamper_addr_t  *gw = NULL;
  rtsock_pair_t   *pair = NULL;
  scamper_route_t *route = NULL;

  if(len < sizeof(struct nlmsghdr))
    {
      scamper_debug(__func__, "len %d != %d", len, sizeof(struct nlmsghdr));
      return;
    }

  nlmsg = (struct nlmsghdr *)buf;

  /* if the message isn't addressed to this pid, drop it */
  if(nlmsg->nlmsg_pid != pid)
    return;

  if((pair = rtsock_pair_get(nlmsg->nlmsg_seq)) == NULL)
    return;
  route = pair->route;
  rtsock_pair_free(pair);

  if(nlmsg->nlmsg_type == RTM_NEWROUTE)
    {
      rtmsg = NLMSG_DATA(nlmsg);

      /* this is the payload length of the response packet */
      len = nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));

      /* hunt through the payload for the RTA_OIF entry */
      rta = RTM_RTA(rtmsg);
      while(RTA_OK(rta, len))
	{
	  switch(rta->rta_type)
	    {
	    case RTA_OIF:
	      ifindex = *(unsigned *)RTA_DATA(rta);
	      break;

	    case RTA_GATEWAY:
	      gwa = RTA_DATA(rta);
	      break;
	    }
	  rta = RTA_NEXT(rta, len);
	}

      if(gwa != NULL)
	{
	  if(rtmsg->rtm_family == AF_INET)
	    gw = scamper_addrcache_get_ipv4(addrcache, gwa);
	  else if(rtmsg->rtm_family == AF_INET6)
	    gw = scamper_addrcache_get_ipv6(addrcache, gwa);
	  else
	    route->error = EINVAL;
	}
    }
  else if(nlmsg->nlmsg_type == NLMSG_ERROR)
    {
      nlerr = NLMSG_DATA(nlmsg);
      route->error = nlerr->error;
    }
  else goto skip;

  route->gw = gw;
  route->ifindex = ifindex;
  route->cb(route);

  return;

 skip:
  if(route != NULL) scamper_route_free(route);
  return;
}
#endif

#if defined(HAVE_BSD_ROUTE_SOCKET)
static void rtsock_parsemsg(uint8_t *buf, size_t len)
{
  struct rt_msghdr   *rtm;
  struct sockaddr    *addrs[RTAX_MAX];
  struct sockaddr_dl *sdl;
  struct sockaddr    *sa;
  struct in6_addr    *ip6;
  size_t              off, tmp, x;
  int                 i, ifindex;
  void               *addr;
  scamper_addr_t     *gw;
  rtsock_pair_t      *pair;
  scamper_route_t    *route;

  x = 0;
  while(x < len)
    {
      if(len - x < sizeof(struct rt_msghdr))
	{
	  scamper_debug(__func__,"len %d != %d",len,sizeof(struct rt_msghdr));
	  return;
	}

      /*
       * check if the message is something we want, and that we have
       * a pair for it
       */
      rtm = (struct rt_msghdr *)(buf + x);
      if(rtm->rtm_pid != pid ||
	 rtm->rtm_msglen > len - x ||
	 rtm->rtm_type != RTM_GET ||
	 (rtm->rtm_flags & RTF_DONE) == 0 ||
	 (pair = rtsock_pair_get(rtm->rtm_seq)) == NULL)
	{
	  x += rtm->rtm_msglen;
	  continue;
	}

      route = pair->route;
      rtsock_pair_free(pair);

      ifindex = -1;
      addr = NULL;
      gw = NULL;

      if(rtm->rtm_errno != 0)
	{
	  route->error = rtm->rtm_errno;
	  goto done;
	}

      off = sizeof(struct rt_msghdr);
      memset(addrs, 0, sizeof(addrs));
      for(i=0; i<RTAX_MAX; i++)
	{
	  if(rtm->rtm_addrs & (1 << i))
	    {
	      addrs[i] = sa = (struct sockaddr *)(buf + x + off);
	      if((tmp = sockaddr_len(sa)) == -1)
		{
		  printerror_msg(__func__, "unhandled af %d", sa->sa_family);
		  route->error = EINVAL;
		  goto done;
		}
	      off += scamper_rtsock_roundup(tmp);
	    }
	}

      if((sdl = (struct sockaddr_dl *)addrs[RTAX_IFP]) != NULL)
	{
	  if(sdl->sdl_family != AF_LINK)
	    {
	      printerror_msg(__func__, "sdl_family %d", sdl->sdl_family);
	      route->error = EINVAL;
	      goto done;
	    }
	  ifindex = sdl->sdl_index;
	}

      if((sa = addrs[RTAX_GATEWAY]) != NULL)
	{
	  if(sa->sa_family == AF_INET)
	    {
	      i = SCAMPER_ADDR_TYPE_IPV4;
	      addr = &((struct sockaddr_in *)sa)->sin_addr;
	    }
	  else if(sa->sa_family == AF_INET6)
	    {
	      /*
	       * check to see if the gw address is a link local address.  if
	       * it is, then drop the embedded index from the gateway address
	       */
	      ip6 = &((struct sockaddr_in6 *)sa)->sin6_addr;
	      if(IN6_IS_ADDR_LINKLOCAL(ip6))
		{
		  ip6->s6_addr[2] = 0;
		  ip6->s6_addr[3] = 0;
		}
	      i = SCAMPER_ADDR_TYPE_IPV6;
	      addr = ip6;
	    }
	  else if(sa->sa_family == AF_LINK)
	    {
	      sdl = (struct sockaddr_dl *)sa;
	      if(sdl->sdl_type == IFT_ETHER && sdl->sdl_alen == ETHER_ADDR_LEN)
		{
		  i = SCAMPER_ADDR_TYPE_ETHERNET;
		  addr = sdl->sdl_data + sdl->sdl_nlen;
		}
	    }

	  /*
	   * if we have got a gateway address that we know what to do with,
	   * then store it here.
	   */
	  if(addr != NULL &&
	     (gw = scamper_addrcache_get(addrcache, i, addr)) == NULL)
	    {
	      scamper_debug(__func__, "could not get rtsmsg->rr.gw");
	      route->error = EINVAL;
	      goto done;
	    }
	}

    done:
      route->gw      = gw;
      route->ifindex = ifindex;
      route->cb(route);
      x += rtm->rtm_msglen;
    }

  return;
}
#endif

/*
 * scamper_rtsock_read_cb
 *
 * this callback handles reading a message from the route socket.
 * we check to see if the message is something that we have sent by parsing
 * the message out.  if we did send the message, then we search for the
 * address-sequence pair, which matches the sequence number with a route
 * lookup.
 * if we get a pair back, then we remove it from the list and look for a
 * trace matching the address.  we then take the result from the route
 * lookup and apply it to the trace.
 */
void scamper_rtsock_read_cb(const int fd, void *param)
{
  uint8_t buf[2048];
  ssize_t len;

  if((len = recv(fd, buf, sizeof(buf), 0)) < 0)
    {
      printerror(__func__, "recv failed");
      return;
    }

  if(len > 0)
    rtsock_parsemsg(buf, len);

  return;
}

void scamper_rtsock_close(int fd)
{
  close(fd);
  return;
}

int scamper_rtsock_open_fd()
{
#if defined(HAVE_BSD_ROUTE_SOCKET)
  return socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
#elif defined(__linux__)
  return socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
#else
#error "route socket support for this system not implemented"
#endif
}

int scamper_rtsock_open()
{
  int fd;

#if defined(WITHOUT_PRIVSEP)
  if((fd = scamper_rtsock_open_fd()) == -1)
#else
  if((fd = scamper_privsep_open_rtsock()) == -1)
#endif
    {
      printerror(__func__, "could not open route socket");
      return -1;
    }

  return fd;
}
#endif

#ifdef _WIN32
static int scamper_rtsock_getroute4(scamper_route_t *route)
{
  struct in_addr *in = route->dst->addr;
  MIB_IPFORWARDROW fw;
  DWORD dw;

  if((dw = GetBestRoute(in->s_addr, 0, &fw)) != NO_ERROR)
    {
      route->error = dw;
      return -1;
    }

  route->ifindex = fw.dwForwardIfIndex;

  /* determine the gateway address to use, if one is specified */
  if((dw = fw.dwForwardNextHop) != 0)
    {
      if((route->gw = scamper_addrcache_get_ipv4(addrcache, &dw)) == NULL)
	{
	  route->error = errno;
	  return -1;
	}
    }

  return 0;
}

int scamper_rtsock_getroute(scamper_route_t *route)
{
  if(SCAMPER_ADDR_TYPE_IS_IPV4(route->dst) &&
     scamper_rtsock_getroute4(route) == 0)
    {
      route->cb(route);
      return 0;
    }

  return -1;
}
#endif

void scamper_route_free(scamper_route_t *route)
{
  if(route == NULL)
    return;
#ifndef _WIN32
  if(route->internal != NULL)
    rtsock_pair_free(route->internal);
#endif
  if(route->dst != NULL)
    scamper_addr_free(route->dst);
  if(route->gw != NULL)
    scamper_addr_free(route->gw);
  free(route);
  return;
}

scamper_route_t *scamper_route_alloc(scamper_addr_t *dst, void *param,
				     void (*cb)(scamper_route_t *rt))
{
  scamper_route_t *route;
  if((route = malloc_zero(sizeof(scamper_route_t))) == NULL)
    return NULL;
  route->dst = scamper_addr_use(dst);
  route->param = param;
  route->cb = cb;
  return route;
}

int scamper_rtsock_init()
{
#ifndef _WIN32
  if((pairs = dlist_alloc()) == NULL)
    {
      printerror(__func__, "could not allocate pair list");
      return -1;
    }
  pid = getpid();
#endif

  return 0;
}

void scamper_rtsock_cleanup()
{
#ifndef _WIN32
  rtsock_pair_t *pair;

  if(pairs != NULL)
    {
      while((pair = dlist_head_pop(pairs)) != NULL)
	{
	  pair->node = NULL;
	  rtsock_pair_free(pair);
	}

      dlist_free(pairs);
      pairs = NULL;
    }
#endif

  return;
}
