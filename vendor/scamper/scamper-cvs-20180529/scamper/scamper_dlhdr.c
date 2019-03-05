/*
 * scamper_dlhdr.c
 *
 * $Id: scamper_dlhdr.c,v 1.16 2014/06/12 19:59:48 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
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
  "$Id: scamper_dlhdr.c,v 1.16 2014/06/12 19:59:48 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_debug.h"
#include "scamper_fds.h"
#include "scamper_addr.h"
#include "scamper_addr2mac.h"
#include "scamper_task.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_if.h"
#include "scamper_list.h"
#include "neighbourdisc/scamper_neighbourdisc_do.h"
#include "utils.h"

static void dlhdr_ethmake(scamper_dlhdr_t *dlhdr, scamper_addr_t *mac)
{
  if((dlhdr->buf = malloc_zero(14)) == NULL)
    {
      dlhdr->error = errno;
      return;
    }
  dlhdr->len = 14;

  /* copy the destination mac address to use */
  memcpy(dlhdr->buf, mac->addr, 6);

  /* the source mac address to use */
  if(scamper_if_getmac(dlhdr->ifindex, dlhdr->buf+6) != 0)
    {
      dlhdr->error = errno;
      scamper_debug(__func__, "could not get source mac");
      return;
    }

  /* the ethertype */
  if(SCAMPER_ADDR_TYPE_IS_IPV4(dlhdr->dst))
    {
      dlhdr->buf[12] = 0x08;
      dlhdr->buf[13] = 0x00;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(dlhdr->dst))
    {
      dlhdr->buf[12] = 0x86;
      dlhdr->buf[13] = 0xDD;
    }
  else
    {
      dlhdr->error = EINVAL;
      scamper_debug(__func__, "unhandled ip->type %d", dlhdr->dst->type);
    }
  return;
}

/*
 * dlhdr_ethcb
 *
 * this callback is used by the neighbour discovery code.
 */
static void dlhdr_ethcb(void *param, scamper_addr_t *ip, scamper_addr_t *mac)
{
  scamper_dlhdr_t *dlhdr = param;
  dlhdr->internal = NULL;
  if(mac != NULL)
    {
      scamper_addr2mac_add(dlhdr->ifindex, ip, mac);
      dlhdr_ethmake(dlhdr, mac);
    }
  else
    {
      dlhdr->error = ENOENT;
    }
  dlhdr->cb(dlhdr);
  return;
}

/*
 * dlhdr_ethernet
 *
 * form an ethernet header.  as this requires mac addresses, and scamper
 * may not know the mac address of the relevant IP, this function deals with
 * doing a neighbour discovery.
 */
static int dlhdr_ethernet(scamper_dlhdr_t *dlhdr)
{
  scamper_neighbourdisc_do_t *nd = NULL;
  scamper_addr_t *ip = NULL;
  scamper_addr_t *mac = NULL;
  int ifindex = dlhdr->ifindex;

  /* determine what we should be looking up */
  if(dlhdr->gw == NULL)
    ip = dlhdr->dst;
  else if(dlhdr->gw->type == SCAMPER_ADDR_TYPE_ETHERNET)
    mac = dlhdr->gw;
  else
    ip = dlhdr->gw;

  /* if we need to get a mac address, then look it up */
  if(mac == NULL && (mac = scamper_addr2mac_whohas(ifindex, ip)) == NULL)
    {
      nd = scamper_do_neighbourdisc_do(ifindex, ip, dlhdr, dlhdr_ethcb);
      if(nd == NULL)
	{
	  dlhdr->error = errno;
	  goto done;
	}
      dlhdr->internal = nd;
      return 0;
    }

  /* give the user what they asked for */
  dlhdr_ethmake(dlhdr, mac);

 done:
  dlhdr->cb(dlhdr);
  return 0;
}

static int dlhdr_ethloop(scamper_dlhdr_t *dlhdr)
{
  if((dlhdr->buf = malloc_zero(14)) == NULL)
    {
      dlhdr->error = errno;
      goto done;
    }
  dlhdr->len = 14;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(dlhdr->dst))
    {
      dlhdr->buf[12] = 0x08;
      dlhdr->buf[13] = 0x00;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(dlhdr->dst))
    {
      dlhdr->buf[12] = 0x86;
      dlhdr->buf[13] = 0xDD;
    }
  else
    {
      dlhdr->error = EINVAL;
      goto done;
    }

 done:
  dlhdr->cb(dlhdr);
  return 0;
}

static int dlhdr_null(scamper_dlhdr_t *dlhdr)
{
  int af;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(dlhdr->dst))
    af = AF_INET;
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(dlhdr->dst))
    af = AF_INET6;
  else
    {
      dlhdr->error = EINVAL;
      goto done;
    }

  if((dlhdr->buf = memdup(&af, sizeof(af))) == NULL)
    {
      dlhdr->error = errno;
      goto done;
    }
  dlhdr->len = sizeof(af);

 done:
  dlhdr->cb(dlhdr);
  return 0;
}

static int dlhdr_raw(scamper_dlhdr_t *dlhdr)
{
  dlhdr->cb(dlhdr);
  return 0;
}

static int dlhdr_unsupp(scamper_dlhdr_t *dlhdr)
{
  return -1;
}

/*
 * scamper_dlhdr_get
 *
 * determine the datalink header to use when framing a packet.
 */
int scamper_dlhdr_get(scamper_dlhdr_t *dlhdr)
{
  static int (*const func[])(scamper_dlhdr_t *dlhdr) = {
    dlhdr_unsupp,
    dlhdr_ethernet,
    dlhdr_null,
    dlhdr_raw,
    dlhdr_ethloop,
  };

  if(dlhdr->txtype < 0 || dlhdr->txtype > 4)
    {
      dlhdr->error = EINVAL;
      return -1;
    }

  return func[dlhdr->txtype](dlhdr);
}

scamper_dlhdr_t *scamper_dlhdr_alloc(void)
{
  return (scamper_dlhdr_t *)malloc_zero(sizeof(scamper_dlhdr_t));
}

void scamper_dlhdr_free(scamper_dlhdr_t *dlhdr)
{
  if(dlhdr == NULL)
    return;
  if(dlhdr->gw != NULL) scamper_addr_free(dlhdr->gw);
  if(dlhdr->dst != NULL) scamper_addr_free(dlhdr->dst);
  if(dlhdr->buf != NULL) free(dlhdr->buf);
  if(dlhdr->internal != NULL) scamper_neighbourdisc_do_free(dlhdr->internal);
  free(dlhdr);
  return;
}
