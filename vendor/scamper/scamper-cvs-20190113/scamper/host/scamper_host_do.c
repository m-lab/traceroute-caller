/*
 * scamper_do_host
 *
 * $Id: scamper_host_do.c,v 1.21 2019/01/13 07:32:32 mjl Exp $
 *
 * Copyright (C) 2018 Matthew Luckie
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
  "$Id: scamper_host_do.c,v 1.21 2019/01/13 07:32:32 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_host.h"
#include "scamper_task.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_debug.h"
#include "scamper_host_do.h"
#include "scamper_fds.h"
#include "scamper_options.h"
#include "scamper_privsep.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "utils.h"

static scamper_task_funcs_t host_funcs;
static splaytree_t *queries = NULL;
static uint8_t *pktbuf = NULL;
static size_t pktbuf_len = 0;
static scamper_addr_t *default_ns = NULL;
static scamper_fd_t *dns4_fd = NULL;
static scamper_queue_t *dns4_sq = NULL;
static scamper_fd_t *dns6_fd = NULL;
static scamper_queue_t *dns6_sq = NULL;
static uint16_t dns_id = 1;

typedef struct host_id
{
  uint16_t          id;   /* query ID */
  dlist_t          *list; /* list of scamper_task_t */
  splaytree_node_t *node; /* node in queries splaytree */
} host_id_t;

typedef struct host_pid
{
  host_id_t        *hid;
  dlist_node_t     *dn;   /* node in hid->list */
} host_pid_t;

typedef struct host_state
{
  char             *qname;
  dlist_t          *pids; /* pointers to host ids */
  dlist_t          *cbs;  /* if we need to pass result to another task */
} host_state_t;

struct scamper_host_do
{
  scamper_task_t *task;
  void           *param;
  void          (*cb)(void *, const char *name);
  dlist_node_t   *node;
};

#define HOST_OPT_NORECURSE 1
#define HOST_OPT_RETRIES   2
#define HOST_OPT_SERVER    3
#define HOST_OPT_TYPE      4
#define HOST_OPT_USERID    5
#define HOST_OPT_WAIT      6

static const scamper_option_in_t opts[] = {
  {'r', NULL, HOST_OPT_NORECURSE, SCAMPER_OPTION_TYPE_NULL},
  {'R', NULL, HOST_OPT_RETRIES,   SCAMPER_OPTION_TYPE_NUM},
  {'S', NULL, HOST_OPT_SERVER,    SCAMPER_OPTION_TYPE_STR},
  {'t', NULL, HOST_OPT_TYPE,      SCAMPER_OPTION_TYPE_STR},
  {'U', NULL, HOST_OPT_USERID,    SCAMPER_OPTION_TYPE_NUM},
  {'W', NULL, HOST_OPT_WAIT,      SCAMPER_OPTION_TYPE_NUM},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_host_usage(void)
{
  return
    "host [-r] [-R number] [-S server] [-t type] [-U userid] [-W wait] name\n";
}

static int host_fd_close(void *param)
{
  scamper_fd_t *fdp = param;
  int fd = scamper_fd_fd_get(fdp);

  if(fdp == dns4_fd)
    {
      scamper_queue_free(dns4_sq);
      dns4_sq = NULL;
      dns4_fd = NULL;
    }
  else if(fdp == dns6_fd)
    {
      scamper_queue_free(dns6_sq);
      dns6_sq = NULL;
      dns6_fd = NULL;
    }
  else return -1;

  scamper_fd_free(fdp);
  close(fd);
  return 0;
}

static scamper_host_t *host_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static host_state_t *host_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static void host_stop(scamper_task_t *task, uint8_t reason)
{
  scamper_host_t *host = host_getdata(task);
  host->stop = reason;
  scamper_task_queue_done(task, 0);
  return;
}

static void host_id_free(host_id_t *hid)
{
  if(hid == NULL)
    return;
  if(hid->list != NULL)
    dlist_free(hid->list);
  free(hid);
  return;
}

static int host_id_cmp(const host_id_t *a, const host_id_t *b)
{
  if(a->id < b->id) return -1;
  if(a->id > b->id) return  1;
  return 0;
}

static host_id_t *host_id_find(uint16_t id)
{
  host_id_t fm; fm.id = id;
  return splaytree_find(queries, &fm);
}

static int host_query_add(uint16_t id, scamper_task_t *task)
{
  host_state_t *state = host_getstate(task);
  host_pid_t *pid = NULL;
  host_id_t *hid = NULL;

  if((pid = malloc_zero(sizeof(host_pid_t))) == NULL)
    goto err;

  if((hid = host_id_find(id)) == NULL)
    {
      if((hid = malloc_zero(sizeof(host_id_t))) == NULL ||
	 (hid->list = dlist_alloc()) == NULL)
	goto err;
      hid->id = id;
      if((hid->node = splaytree_insert(queries, hid)) == NULL)
	goto err;
    }

  pid->hid = hid;
  if((pid->dn = dlist_tail_push(hid->list, task)) == NULL)
    goto err;

  if(dlist_tail_push(state->pids, pid) == NULL)
    goto err;

  return 0;

 err:
  return -1;
}

static void host_state_free(host_state_t *state)
{
  host_pid_t *pid;

  if(state == NULL)
    return;
  if(state->qname != NULL)
    free(state->qname);
  if(state->cbs != NULL)
    dlist_free(state->cbs);
  if(state->pids != NULL)
    {
      while((pid = dlist_head_pop(state->pids)) != NULL)
	{
	  dlist_node_pop(pid->hid->list, pid->dn);
	  if(dlist_count(pid->hid->list) == 0)
	    {
	      splaytree_remove_node(queries, pid->hid->node);
	      host_id_free(pid->hid);
	    }
	  free(pid);
	}
      dlist_free(state->pids);
    }
  free(state);
  return;
}

static host_state_t *host_state_alloc(scamper_task_t *task)
{
  scamper_host_t *host = host_getdata(task);
  host_state_t *state = NULL;
  scamper_addr_t *sa = NULL;
  struct in_addr *in4;
  struct in6_addr *in6;
  uint32_t u32;
  size_t off;
  char qname[128];
  int i;

#ifdef _WIN32
  uint16_t u16;
#endif

  if((state = malloc_zero(sizeof(host_state_t))) == NULL ||
     (state->pids = dlist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc state");
      goto err;
    }

  if(host->qtype == SCAMPER_HOST_TYPE_PTR)
    {
      if((sa = scamper_addr_resolve(AF_UNSPEC, host->qname)) == NULL)
	{
	  printerror(__func__, "could not resolve %s", host->qname);
	  goto err;
	}
      if(SCAMPER_ADDR_TYPE_IS_IPV4(sa))
	{
	  in4 = sa->addr;
	  u32 = ntohl(in4->s_addr);
	  snprintf(qname, sizeof(qname), "%u.%u.%u.%u.in-addr.arpa",
		   u32 & 0xff, (u32>>8) & 0xff, (u32>>16) & 0xff, (u32>>24));
	}
      else if(SCAMPER_ADDR_TYPE_IS_IPV6(sa))
	{
	  in6 = sa->addr; off = 0;
#ifndef _WIN32
	  for(i=3; i>=0; i--)
	    {
	      u32 = ntohl(in6->s6_addr32[i]);
	      string_concat(qname, sizeof(qname), &off,
			    "%x.%x.%x.%x.%x.%x.%x.%x.", u32 & 0xf,
			    (u32 >>  4) & 0xf, (u32 >>  8) & 0xf,
			    (u32 >> 12) & 0xf, (u32 >> 16) & 0xf,
			    (u32 >> 20) & 0xf, (u32 >> 24) & 0xf,
			    (u32 >> 28) & 0xf);
	    }
#else
  	  for(i=7; i>=0; i--)
	    {
	      u16 = ntohs(in6->u.Word[i]);
	      string_concat(qname, sizeof(qname), &off,
			    "%x.%x.%x.%x.", u16 & 0xf, (u16 >>  4) & 0xf,
			    (u16 >> 8) & 0xf, (u16 >> 12) & 0xf);
	    }
#endif
	  string_concat(qname, sizeof(qname), &off, "ip6.arpa");
	}
      scamper_addr_free(sa);
      if((state->qname = strdup(qname)) == NULL)
	{
	  printerror(__func__, "could not strdup qname");
	  goto err;
	}
    }
  else
    {
      if((state->qname = strdup(host->qname)) == NULL)
	{
	  printerror(__func__, "could not strdup qname");
	  goto err;
	}
    }

  scamper_task_setstate(task, state);
  return state;

 err:
  if(sa != NULL) scamper_addr_free(sa);
  if(state != NULL) host_state_free(state);
  return NULL;
}

static int extract_name(char *name, uint8_t *pktbuf, size_t off)
{
  int ptr_used = 0, i = 0, rc = 0;
  uint16_t u16;
  uint8_t u8;

  for(;;)
    {
      u8 = pktbuf[off];

      if(u8 == 0)
	{
	  if(ptr_used == 0)
	    rc++;
	  break;
	}

      if((u8 & 0xc0) == 0xc0)
	{
	  u16 = bytes_ntohs(pktbuf+off) & 0x3fff;
	  if(u16 >= off)
	    {
	      scamper_debug(__func__, "ptr %u >= %u\n", u16, off);
	      return -1;
	    }
	  off = u16;
	  if(ptr_used == 0)
	    {
	      ptr_used = 1;
	      rc += 2;
	    }
	  continue;
	}

      memcpy(name+i, pktbuf+off+1, u8);
      off += u8 + 1;
      i += u8;
      name[i++] = '.';
      if(ptr_used == 0)
	rc += u8 + 1;
    }

  name[i-1] = '\0';
  return rc;
}

static int extract_soa(scamper_host_rr_t *rr, uint8_t *pktbuf, size_t off)
{
  scamper_host_rr_soa_t *soa = NULL;
  char mname[256], rname[256];
  uint32_t serial, refresh, retry, expire, minimum;
  int i;

  if((i = extract_name(mname, pktbuf, off)) <= 0)
    return -1;
  off += i;
  if((i = extract_name(rname, pktbuf, off)) <= 0)
    return -1;
  off += i;

  serial = bytes_ntohl(pktbuf+off); off += 4;
  refresh = bytes_ntohl(pktbuf+off); off += 4;
  retry = bytes_ntohl(pktbuf+off); off += 4;
  expire = bytes_ntohl(pktbuf+off); off += 4;
  minimum = bytes_ntohl(pktbuf+off); off += 4;

  if((soa = scamper_host_rr_soa_alloc(mname, rname)) == NULL)
    return -1;
  soa->serial = serial;
  soa->refresh = refresh;
  soa->retry = retry;
  soa->expire = expire;
  soa->minimum = minimum;
  rr->un.soa = soa;

  return 0;
}

static int extract_mx(scamper_host_rr_t *rr, uint8_t *pktbuf, size_t off)
{
  scamper_host_rr_mx_t *mx = NULL;
  char exchange[256];
  uint16_t preference;

  preference = bytes_ntohs(pktbuf+off); off += 2;
  if(extract_name(exchange, pktbuf, off) <= 0)
    return -1;
  if((mx = scamper_host_rr_mx_alloc(preference, exchange)) == NULL)
    return -1;
  rr->un.mx = mx;

  return 0;
}

static void do_host_read(const int fd, void *param)
{
  scamper_task_t *task;
  scamper_host_t *host;
  host_state_t *state;
  struct in6_addr in6;
  struct in_addr in4;
  slist_t *rr_list = NULL;
  scamper_host_rr_t **rrs;
  dlist_node_t *dn;
  host_id_t *hid;
  scamper_host_query_t *q = NULL;
  scamper_host_rr_t *rr = NULL;
  uint16_t id, flags, qdcount, ancount, nscount, arcount;
  uint16_t qtype, qclass, rdlength, type, class;
  uint32_t ttl;
  ssize_t off, len;
  char name[256], str[256];
  int i, j, k, x;

  if((len = recv(fd, pktbuf, pktbuf_len, 0)) < 0)
    return;
  if(len < 12)
    return;

  id = bytes_ntohs(pktbuf+0);
  flags = bytes_ntohs(pktbuf+2);
  qdcount = bytes_ntohs(pktbuf+4);

  /* QR bit must be set, as we want a response, and one Q per query */
  if((flags & 0x8000) == 0 || qdcount != 1)
    return;

  ancount = bytes_ntohs(pktbuf+6);
  nscount = bytes_ntohs(pktbuf+8);
  arcount = bytes_ntohs(pktbuf+10);
  off = 12;

  /* get the question out of the packet */
  if((i = extract_name(name, pktbuf, off)) <= 0)
    {
      scamper_debug(__func__, "could not extract qname");
      return;
    }
  off += i;
  qtype = bytes_ntohs(pktbuf+off); off += 2;
  qclass = bytes_ntohs(pktbuf+off); off += 2;

  /* find the relevant query we sent */
  if((hid = host_id_find(id)) == NULL)
    {
      scamper_debug(__func__, "no host id %d", id);
      return;
    }
  for(dn=dlist_head_node(hid->list); dn != NULL; dn=dlist_node_next(dn))
    {
      task = dlist_node_item(dn);
      host = host_getdata(task);
      state = host_getstate(task);
      if(host->qtype == qtype && host->qclass == qclass &&
	 strcasecmp(state->qname, name) == 0)
	break;
    }
  if(dn == NULL)
    {
      scamper_debug(__func__, "no matching query");
      return;
    }
  for(i=0; i<host->qcount; i++)
    if(host->queries[i]->id == id)
      break;
  if(i == host->qcount)
    {
      scamper_debug(__func__, "could not find id in host->queries");
      return;
    }
  q = host->queries[i];
  gettimeofday_wrap(&q->rx);

  if((rr_list = slist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc rr_list");
      return;
    }

  q->ancount = ancount;
  q->nscount = nscount;
  q->arcount = arcount;

  for(i=0; i<3; i++)
    {
      if(i == 0) x = ancount;
      else if(i == 1) x = nscount;
      else if(i == 2) x = arcount;

      for(j=0; j<x; j++)
	{
	  if((k = extract_name(name, pktbuf, off)) <= 0)
	    {
	      scamper_debug(__func__, "could not extract name");
	      return;
	    }
	  off += k;

	  type = bytes_ntohs(pktbuf+off); off += 2;
	  class = bytes_ntohs(pktbuf+off); off += 2;
	  ttl = bytes_ntohl(pktbuf+off); off += 4;
	  rdlength = bytes_ntohs(pktbuf+off); off += 2;
	  if((rr = scamper_host_rr_alloc(name, class, type, ttl)) == NULL)
	    {
	      printerror(__func__, "could not alloc rr");
	      goto err;
	    }

	  if(class == 1 &&
	     (type == SCAMPER_HOST_TYPE_NS ||
	      type == SCAMPER_HOST_TYPE_CNAME ||
	      type == SCAMPER_HOST_TYPE_PTR))
	    {
	      if(extract_name(str, pktbuf, off) <= 0)
		goto err;
	      if((rr->un.str = strdup(str)) == NULL)
		goto err;
	    }
	  else if(class == 1 && type == SCAMPER_HOST_TYPE_A)
	    {
	      if(rdlength != 4)
		goto err;
	      memcpy(&in4, pktbuf+off, rdlength);
	      inet_ntop(AF_INET, &in4, str, sizeof(str));
	      if((rr->un.addr = scamper_addr_alloc_ipv4(&in4)) == NULL)
		goto err;
	    }
	  else if(class == 1 && type == SCAMPER_HOST_TYPE_AAAA)
	    {
	      if(rdlength != 16)
		goto err;
	      memcpy(&in6, pktbuf+off, rdlength);
	      inet_ntop(AF_INET6, &in6, str, sizeof(str));
	      if((rr->un.addr = scamper_addr_alloc_ipv6(&in6)) == NULL)
		goto err;
	    }
	  else if(class == 1 && type == SCAMPER_HOST_TYPE_SOA)
	    {
	      if(extract_soa(rr, pktbuf, off) != 0)
		goto err;
	    }
	  else if(class == 1 && type == SCAMPER_HOST_TYPE_MX)
	    {
	      if(extract_mx(rr, pktbuf, off) != 0)
		goto err;
	    }

	  if(slist_tail_push(rr_list, rr) == NULL)
	    {
	      printerror(__func__, "could not push rr");
	      goto err;
	    }

	  off += rdlength;
	}

      x = slist_count(rr_list);
      if(i == 0)
	{
	  if((q->an = malloc_zero(sizeof(scamper_host_rr_t *) * x)) == NULL)
	    goto err;
	  rrs = q->an;
	}
      else if(i == 1)
	{
	  if((q->ns = malloc_zero(sizeof(scamper_host_rr_t *) * x)) == NULL)
	    goto err;
	  rrs = q->ns;
	}
      else if(i == 2)
	{
	  if((q->ar = malloc_zero(sizeof(scamper_host_rr_t *) * x)) == NULL)
	    goto err;
	  rrs = q->ar;
	}

      x = 0;
      while((rr = slist_head_pop(rr_list)) != NULL)
	rrs[x++] = rr;
    }

  slist_free(rr_list); rr_list = NULL;

  scamper_debug(__func__, "received %d bytes, %u %04x %u %u %u %u", len,
		id, flags, qdcount, ancount, nscount, arcount);

  host_stop(task, SCAMPER_HOST_STOP_DONE);
  return;

 err:
  if(rr_list != NULL) slist_free(rr_list);
  return;
}

static void do_host_probe(scamper_task_t *task)
{
  scamper_host_t *host = host_getdata(task);
  host_state_t *state = host_getstate(task);
  scamper_host_query_t *q = NULL;
  const char *ptr, *dot;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  struct sockaddr *sa;
  struct timeval tv;
  uint16_t id;
  ssize_t ss;
  size_t off, len;
  int fd;

  if(state == NULL && (state = host_state_alloc(task)) == NULL)
    goto err;

  if(host->queries == NULL)
    {
      len = sizeof(scamper_host_query_t *) * (host->retries + 1);
      if((host->queries = malloc_zero(len)) == NULL)
	goto err;
      gettimeofday_wrap(&host->start);
    }

  scamper_debug(__func__, "%s", state->qname);

  /* when to close the DNS fd */
  gettimeofday_wrap(&tv); tv.tv_sec += 10;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(host->server))
    {
      if(dns4_fd == NULL)
	{
	  if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
	    {
	      printerror(__func__, "could not open dns4_fd");
	      goto err;
	    }
	  if((dns4_fd = scamper_fd_private(fd,NULL,do_host_read,NULL)) == NULL)
	    {
	      printerror(__func__, "could not register dns4_fd");
	      goto err;
	    }
	}
      else fd = scamper_fd_fd_get(dns4_fd);

      if(dns4_sq == NULL)
	{
	  if((dns4_sq = scamper_queue_event(&tv,host_fd_close,dns4_fd)) == NULL)
	    {
	      printerror(__func__, "could not register dns4_sq");
	      goto err;
	    }
	}
      else if(scamper_queue_event_update_time(dns4_sq, &tv) != 0)
	{
	  printerror(__func__, "could not updarte dns4_sq");
	  goto err;
	}

      sa = (struct sockaddr *)&sin;
      sockaddr_compose(sa, AF_INET, host->server->addr, 53);
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(host->server))
    {
      if(dns6_fd == NULL)
	{
	  if((fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1)
	    {
	      printerror(__func__, "could not open dns6_fd");
	      return;
	    }
	  if((dns6_fd = scamper_fd_private(fd,NULL,do_host_read,NULL)) == NULL)
	    {
	      printerror(__func__, "could not register dns6_fd");
	      return;
	    }
	}
      else fd = scamper_fd_fd_get(dns6_fd);

      if(dns6_sq == NULL)
	{
	  if((dns6_sq = scamper_queue_event(&tv,host_fd_close,dns6_fd)) == NULL)
	    {
	      printerror(__func__, "could not register dns6_sq");
	      goto err;
	    }
	}
      else if(scamper_queue_event_update_time(dns6_sq, &tv) != 0)
	{
	  printerror(__func__, "could not updarte dns6_sq");
	  goto err;
	}

      sa = (struct sockaddr *)&sin6;
      sockaddr_compose(sa, AF_INET6, host->server->addr, 53);
    }

  if(pktbuf == NULL)
    {
      pktbuf_len = 8192;
      if((pktbuf = malloc(pktbuf_len)) == NULL)
	{
	  printerror(__func__, "could not malloc pktbuf");
	  goto err;
	}
    }

  id = dns_id++;
  if(host_query_add(id, task) != 0)
    goto err;

  /* 12 bytes of DNS header */
  bytes_htons(pktbuf, id);       /* DNS ID, 16 bits */
  bytes_htons(pktbuf+2, 0x0100); /* recursion desired */
  bytes_htons(pktbuf+4, 1);      /* QDCOUNT */
  bytes_htons(pktbuf+6, 0);      /* ANCOUNT */
  bytes_htons(pktbuf+8, 0);      /* NSCOUNT */
  bytes_htons(pktbuf+10, 0);     /* ARCOUNT */
  off = 12;

  if(host->qtype == SCAMPER_HOST_TYPE_A ||
     host->qtype == SCAMPER_HOST_TYPE_AAAA ||
     host->qtype == SCAMPER_HOST_TYPE_PTR)
    {
      ptr = state->qname;
      for(;;)
	{
	  dot = ptr;
	  while(*dot != '.' && *dot != '\0')
	    dot++;
	  pktbuf[off++] = dot - ptr;
	  while(ptr != dot)
	    {
	      pktbuf[off] = *ptr;
	      ptr++; off++;
	    }
	  if(*ptr == '.')
	    ptr++;
	  else
	    break;
	}
      pktbuf[off++] = 0;
      bytes_htons(pktbuf+off, host->qtype); off += 2;
      bytes_htons(pktbuf+off, host->qclass); off += 2;
    }
  else return;

  if((q = malloc_zero(sizeof(scamper_host_query_t))) == NULL)
    {
      printerror(__func__, "could not malloc q");
      goto err;
    }
  gettimeofday_wrap(&q->tx);
  q->id = id;

  if((ss = sendto(fd, pktbuf, off, 0, sa, sockaddr_len(sa))) == -1)
    {
      printerror(__func__, "could not send query");
      goto err;
    }
  host->queries[host->qcount++] = q; q = NULL;
  scamper_task_queue_wait(task, host->wait);

  return;

 err:
  if(q != NULL) free(q);
  host_stop(task, SCAMPER_HOST_STOP_ERROR);
  return;
}

static void do_host_handle_timeout(scamper_task_t *task)
{
  scamper_host_t *host = host_getdata(task);
  if(host->qcount >= host->retries + 1)
    host_stop(task, SCAMPER_HOST_STOP_TIMEOUT);
  return;
}

static int host_arg_param_validate(int optid, char *param, long *out)
{
  scamper_addr_t *addr;
  long tmp = 0;

  switch(optid)
    {
    case HOST_OPT_NORECURSE:
      return 0;

    case HOST_OPT_RETRIES:
      if(string_tolong(param, &tmp) != 0 || tmp < 0 || tmp > 3)
	return -1;
      break;

    case HOST_OPT_SERVER:
      if((addr = scamper_addr_resolve(AF_INET, param)) == NULL)
	return -1;
      scamper_addr_free(addr);
      break;

    case HOST_OPT_TYPE:
      if(strcasecmp(param, "A") == 0)
	tmp = SCAMPER_HOST_TYPE_A;
      else if(strcasecmp(param, "AAAA") == 0)
	tmp = SCAMPER_HOST_TYPE_AAAA;
      else if(strcasecmp(param, "PTR") == 0)
	tmp = SCAMPER_HOST_TYPE_PTR;
      else return -1;
      break;

    case HOST_OPT_WAIT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 5)
	return -1;
      tmp *= 1000;
      break;
    }

  if(out != NULL)
    *out = tmp;

  return 0;
}

int scamper_do_host_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  host_arg_param_validate);
}

scamper_task_t *scamper_do_host_alloctask(void *data, scamper_list_t *list,
					  scamper_cycle_t *cycle)
{
  scamper_host_t *host = (scamper_host_t *)data;
  scamper_task_sig_t *sig = NULL;
  scamper_task_t *task = NULL;

  /* allocate a task structure and store the host query with it */
  if((task = scamper_task_alloc(host, &host_funcs)) == NULL)
    goto err;

  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_HOST)) == NULL)
    goto err;
  sig->sig_host_name = strdup(host->qname);
  if(scamper_task_sig_add(task, sig) != 0)
    goto err;
  sig = NULL;

  host->list = scamper_list_use(list);
  host->cycle = scamper_cycle_use(cycle);

  return task;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  if(task != NULL)
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  return NULL;
}

void *scamper_do_host_alloc(char *str)
{
  scamper_host_t *host = NULL;
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_addr_t *server = NULL;
  scamper_addr_t *name_addr = NULL;
  char *name = NULL;
  uint8_t retries = 0;
  uint32_t userid = 0;
  uint16_t wait = 5000;
  uint16_t flags = 0;
  uint16_t qclass = 1;
  uint16_t qtype = 0;
  long tmp = 0;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &name) != 0)
    {
      scamper_debug(__func__, "could not parse command");
      goto err;
    }

  if(name == NULL)
    goto err;

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 host_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	case HOST_OPT_NORECURSE:
	  flags |= SCAMPER_HOST_FLAG_NORECURSE;
	  break;

	case HOST_OPT_RETRIES:
	  retries = (uint8_t)tmp;
	  break;

	case HOST_OPT_SERVER:
	  if(server != NULL)
	    goto err;
	  if((server = scamper_addr_resolve(AF_INET, opt->str)) == NULL)
	    goto err;
	  break;

	case HOST_OPT_TYPE:
	  qtype = (uint16_t)tmp;
	  break;

	case HOST_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case HOST_OPT_WAIT:
	  wait = (uint16_t)tmp;
	  break;

	default:
	  scamper_debug(__func__, "unhandled option %d", opt->id);
	  goto err;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if(qtype == 0)
    {
      if((name_addr = scamper_addr_resolve(AF_UNSPEC, name)) != NULL)
	qtype = SCAMPER_HOST_TYPE_PTR;
      else
	qtype = SCAMPER_HOST_TYPE_A;
    }
  else if(qtype == SCAMPER_HOST_TYPE_A || qtype == SCAMPER_HOST_TYPE_AAAA)
    {
      if((name_addr = scamper_addr_resolve(AF_UNSPEC, name)) != NULL)
	goto err;
    }
  else if(qtype == SCAMPER_HOST_TYPE_PTR)
    {
      if((name_addr = scamper_addr_resolve(AF_UNSPEC, name)) == NULL)
	goto err;
    }
  else goto err;

  if((host = scamper_host_alloc()) == NULL ||
     (host->qname = strdup(name)) == NULL)
    goto err;

  host->userid  = userid;
  host->flags  |= flags;
  host->wait    = wait;
  host->retries = retries;
  host->qtype   = qtype;
  host->qclass  = qclass;

  if(server == NULL)
    {
      if(default_ns == NULL)
	goto err;
      host->server = scamper_addr_use(default_ns);
    }
  else
    {
      host->server = server;
      server = NULL;
    }

  scamper_debug(__func__, "ok %s", host->qname);
  return host;

 err:
  scamper_debug(__func__, "err");
  if(host != NULL) scamper_host_free(host);
  if(name_addr != NULL) scamper_addr_free(name_addr);
  if(server != NULL) scamper_addr_free(server);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

void scamper_host_do_free(scamper_host_do_t *hostdo)
{
  scamper_task_t *task;
  host_state_t *state;
  
  if(hostdo == NULL)
    return;

  if((task = hostdo->task) != NULL)
    {
      state = host_getstate(task);
      if(state != NULL && hostdo->node != NULL)
	dlist_node_pop(state->cbs, hostdo->node);
    }

  free(hostdo);
  return;
}

/*
 * scamper_host_do_add
 *
 */
static scamper_host_do_t *scamper_host_do_add(
  scamper_task_t *task, void *param, void (*cb)(void *,const char *name))
{
  scamper_host_do_t *hostdo = NULL;
  host_state_t *state = host_getstate(task);

  if(state->cbs == NULL && (state->cbs = dlist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc state->cbs");
      return NULL;
    }
  if((hostdo = malloc_zero(sizeof(scamper_host_do_t))) == NULL)
    {
      printerror(__func__, "could not alloc hostdo");
      return NULL;
    }

  hostdo->task = task;
  hostdo->cb = cb;
  hostdo->param = param;
  if((hostdo->node = dlist_tail_push(state->cbs, hostdo)) == NULL)
    {
      printerror(__func__, "could not add hostdo");
      free(hostdo);
      return NULL;
    }

  return hostdo;
}

/*
 * scamper_do_host_do_ptr
 *
 * do a PTR lookup on the IP address.  the supplied callback will be called
 * when the hostname lookup has completed.
 */
scamper_host_do_t *scamper_do_host_do_ptr(scamper_addr_t *ip, void *param,
					  void (*cb)(void *,const char *name))
{
  scamper_task_t *task = NULL;
  scamper_host_t *host = NULL;
  scamper_task_sig_t sig;
  char qname[128];

  scamper_addr_tostr(ip, qname, sizeof(qname));

  memset(&sig, 0, sizeof(sig));
  sig.sig_type = SCAMPER_TASK_SIG_TYPE_TX_ND;
  sig.sig_host_name = qname;

  /* piggy back on existing host task if there is one */
  if((task = scamper_task_find(&sig)) != NULL)
    return scamper_host_do_add(task, param, cb);

  /* build a new host task */
  if((host = scamper_host_alloc()) == NULL ||
     (host->qname = strdup(qname)) == NULL)
    {
      printerror(__func__, "could not alloc host");
      goto err;
    }
  host->wait = 5000;
  host->retries = 1;
  host->qclass = 1;
  host->qtype = SCAMPER_HOST_TYPE_PTR;
  host->server = scamper_addr_use(default_ns);

  if((task = scamper_do_host_alloctask(host, NULL, NULL)) == NULL)
    {
      printerror(__func__, "could not alloc task");
      goto err;
    }
  host = NULL;
  if(scamper_task_sig_install(task) != 0)
    {
      printerror(__func__, "could not install task");
      goto err;
    }
  if(host_state_alloc(task) == NULL)
    {
      printerror(__func__, "could not alloc state");
      goto err;
    }
  do_host_probe(task);
  if(scamper_task_queue_isdone(task))
    {
      printerror(__func__, "done");
      goto err;
    }
  return scamper_host_do_add(task, param, cb);

 err:
  if(host != NULL) scamper_host_free(host);
  return NULL;
}

void scamper_do_host_free(void *data)
{
  scamper_host_free((scamper_host_t *)data);
  return;
}

void scamper_do_host_cleanup()
{
  int fd;

  if(dns4_fd != NULL)
    {
      fd = scamper_fd_fd_get(dns4_fd);
      scamper_fd_free(dns4_fd);
      dns4_fd = NULL;
      close(fd);
    }
  if(dns4_sq != NULL)
    {
      scamper_queue_free(dns4_sq);
      dns4_sq = NULL;
    }

  if(dns6_fd != NULL)
    {
      fd = scamper_fd_fd_get(dns6_fd);
      scamper_fd_free(dns6_fd);
      dns6_fd = NULL;
      close(fd);
    }
  if(dns6_sq != NULL)
    {
      scamper_queue_free(dns6_sq);
      dns6_sq = NULL;
    }

  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  if(default_ns != NULL)
    {
      scamper_addr_free(default_ns);
      default_ns = NULL;
    }

  if(queries != NULL)
    {
      splaytree_free(queries, NULL);
      queries = NULL;
    }

  return;
}

static void do_host_write(scamper_file_t *sf, scamper_task_t *task)
{
  /* XXX: implement */
  scamper_debug(__func__, "hello");
  return;
}

static void do_host_halt(scamper_task_t *task)
{
  host_stop(task, SCAMPER_HOST_STOP_HALTED);
  return;
}

static void do_host_free(scamper_task_t *task)
{
  scamper_host_do_t *hostdo;
  scamper_host_t *host = host_getdata(task);
  scamper_host_rr_t *rr;
  host_state_t *state = host_getstate(task);
  char *name = NULL;
  int i, j;

  if(state != NULL && state->cbs != NULL && host != NULL)
    {
      for(i=0; i<host->qcount && name == NULL; i++)
	{
	  for(j=0; j<host->queries[i]->ancount; j++)
	    {
	      rr = host->queries[i]->an[j];
	      if(rr->type == SCAMPER_HOST_TYPE_PTR)
		{
		  name = rr->un.str;
		  break;
		}
	    }
	}

      while((hostdo = dlist_head_pop(state->cbs)) != NULL)
	{
	  hostdo->node = NULL;
	  hostdo->cb(hostdo->param, name);
	  free(hostdo);
	}
      dlist_free(state->cbs);
      state->cbs = NULL;
    }

  if(host != NULL)
    scamper_host_free(host);

  if(state != NULL)
    host_state_free(state);

  return;
}

static int etc_resolv_line(char *line, void *param)
{
  scamper_addr_t *sa;
  int x = 0;

  if(line[0] == '\0' || line[0] == '#')
    return 0;

  x = 10;
  if(strncasecmp(line, "nameserver", x) != 0)
    return 0;
  while(isspace(line[x]) != 0)
    x++;
  if(x == 10 || line[x] == '\0')
    return 0;
  if(strcasecmp(line+x, "fe80::1") == 0)
    return 0;

  if((sa = scamper_addr_resolve(AF_UNSPEC, line+x)) == NULL)
    {
      printerror(__func__, "could not resolve %s", line+x);
      return -1;
    }
  if(default_ns == NULL)
    default_ns = sa;
  else
    scamper_addr_free(sa);

  return 0;
}

static int etc_resolv(void)
{
  int fd, flags = O_RDONLY;

#if defined(WITHOUT_PRIVSEP)
  fd = open("/etc/resolv.conf", flags);
#else
  fd = scamper_privsep_open_file("/etc/resolv.conf", flags, 0);
#endif

  if(fd == -1)
    {
      printerror(__func__, "could not open /etc/resolv.conf");
      goto err;
    }

  if(fd_lines(fd, etc_resolv_line, NULL) != 0)
    goto err;
  close(fd); fd = -1;
  if(default_ns == NULL)
    {
      printerror_msg(__func__, "no nameserver in /etc/resolv.conf");
      return -1;
    }

  return 0;

 err:
  if(fd != -1) close(fd);
  return -1;
}

int scamper_do_host_init()
{
  host_funcs.probe          = do_host_probe;
  host_funcs.handle_timeout = do_host_handle_timeout;
  host_funcs.write          = do_host_write;
  host_funcs.task_free      = do_host_free;
  host_funcs.halt           = do_host_halt;

  if(etc_resolv() != 0)
    return -1;

  if((queries = splaytree_alloc((splaytree_cmp_t)host_id_cmp)) == NULL)
    return -1;
  return 0;
}
