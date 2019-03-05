/*
 * scamper_getsrc.c
 *
 * $Id: scamper_getsrc.c,v 1.19 2017/12/03 09:38:26 mjl Exp $
 *
 * Copyright (C) 2005 Matthew Luckie
 * Copyright (C) 2007-2010 The University of Waikato
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
  "$Id: scamper_getsrc.c,v 1.19 2017/12/03 09:38:26 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_debug.h"
#include "scamper_getsrc.h"
#include "utils.h"

static int udp4 = -1;
static int udp6 = -1;

extern scamper_addrcache_t *addrcache;

/*
 * scamper_getsrc
 *
 * given a destination address, determine the src address used in the IP
 * header to transmit probes to it.
 */
scamper_addr_t *scamper_getsrc(const scamper_addr_t *dst, int ifindex)
{
  struct sockaddr_storage sas;
  scamper_addr_t *src;
  socklen_t socklen, sockleno;
  int sock;
  void *addr;
  char buf[64];

  if(dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      if(udp4 == -1 && (udp4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
	{
	  printerror(__func__, "could not open udp4 sock");
	  return NULL;
	}

      sock = udp4;
      addr = &((struct sockaddr_in *)&sas)->sin_addr;
      socklen = sizeof(struct sockaddr_in);

      sockaddr_compose((struct sockaddr *)&sas, AF_INET, dst->addr, 80);
    }
  else if(dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      if(udp6 == -1 && (udp6 = socket(AF_INET6, SOCK_DGRAM,IPPROTO_UDP)) == -1)
	{
	  printerror(__func__, "could not open udp6 sock");
	  return NULL;
	}

      sock = udp6;
      addr = &((struct sockaddr_in6 *)&sas)->sin6_addr;
      socklen = sizeof(struct sockaddr_in6);

      sockaddr_compose((struct sockaddr *)&sas, AF_INET6, dst->addr, 80);

      if(scamper_addr_islinklocal(dst) != 0)
	{
	  ((struct sockaddr_in6 *)&sas)->sin6_scope_id = ifindex;
	}
    }
  else return NULL;

  if(connect(sock, (struct sockaddr *)&sas, socklen) != 0)
    {
      printerror(__func__, "connect to dst failed for %s",
		 scamper_addr_tostr(dst, buf, sizeof(buf)));
      return NULL;
    }

  sockleno = socklen;
  if(getsockname(sock, (struct sockaddr *)&sas, &sockleno) != 0)
    {
      printerror(__func__, "could not getsockname for %s",
		 scamper_addr_tostr(dst, buf, sizeof(buf)));
      return NULL;
    }

  src = scamper_addrcache_get(addrcache, dst->type, addr);

  memset(&sas, 0, sizeof(sas));
  connect(sock, (struct sockaddr *)&sas, socklen);
  return src;
}

int scamper_getsrc_init()
{
  return 0;
}

void scamper_getsrc_cleanup()
{
  if(udp4 != -1)
    {
#ifndef _WIN32
      close(udp4);
#else
      closesocket(udp4);
#endif
      udp4 = -1;
    }

  if(udp6 != -1)
    {
#ifndef _WIN32
      close(udp6);
#else
      closesocket(udp6);
#endif
      udp6 = -1;
    }

  return;
}
