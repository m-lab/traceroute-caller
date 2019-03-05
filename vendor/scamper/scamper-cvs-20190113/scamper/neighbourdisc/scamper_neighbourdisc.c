/*
 * scamper_neighbourdisc.c
 *
 * $Id: scamper_neighbourdisc.c,v 1.4 2010/09/11 22:10:42 mjl Exp $
 *
 * Copyright (C) 2009-2010 Matthew Luckie
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
  "$Id: scamper_neighbourdisc.c,v 1.4 2010/09/11 22:10:42 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_neighbourdisc.h"

#include "utils.h"

scamper_addr_t *scamper_neighbourdisc_addr(const void *va)
{
  const scamper_neighbourdisc_t *nd = va;
  return nd->dst_ip;
}

scamper_neighbourdisc_reply_t *scamper_neighbourdisc_reply_alloc(void)
{
  return malloc_zero(sizeof(scamper_neighbourdisc_reply_t));
}

void scamper_neighbourdisc_reply_free(scamper_neighbourdisc_reply_t *reply)
{
  if(reply->mac != NULL) scamper_addr_free(reply->mac);
  free(reply);
  return;
}

int scamper_neighbourdisc_reply_add(scamper_neighbourdisc_probe_t *probe,
				    scamper_neighbourdisc_reply_t *reply)
{
  size_t len = sizeof(scamper_neighbourdisc_reply_t *) * (probe->rxc+1);
  if(realloc_wrap((void **)&probe->rxs, len) != 0)
    return -1;
  probe->rxs[probe->rxc++] = reply;
  return 0;
}

int scamper_neighbourdisc_replies_alloc(scamper_neighbourdisc_probe_t *probe,
					uint16_t c)
{
  size_t len = sizeof(scamper_neighbourdisc_reply_t *) * c;
  if((probe->rxs = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

scamper_neighbourdisc_probe_t *scamper_neighbourdisc_probe_alloc(void)
{
  return malloc_zero(sizeof(scamper_neighbourdisc_probe_t));
}

void scamper_neighbourdisc_probe_free(scamper_neighbourdisc_probe_t *probe)
{
  uint16_t i;

  if(probe == NULL)
    return;

  if(probe->rxs != NULL)
    {
      for(i=0; i<probe->rxc; i++)
	scamper_neighbourdisc_reply_free(probe->rxs[i]);
      free(probe->rxs);
    }
  free(probe);
  return;
}

int scamper_neighbourdisc_probe_add(scamper_neighbourdisc_t *nd,
				    scamper_neighbourdisc_probe_t *probe)
{
  size_t len = sizeof(scamper_neighbourdisc_probe_t *) * (nd->probec+1);
  if(realloc_wrap((void **)&nd->probes, len) != 0)
    return -1;
  nd->probes[nd->probec++] = probe;
  return 0;
}

int scamper_neighbourdisc_probes_alloc(scamper_neighbourdisc_t *nd, uint16_t c)
{
  size_t len = sizeof(scamper_neighbourdisc_probe_t *) * c;
  if((nd->probes = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

scamper_neighbourdisc_t *scamper_neighbourdisc_alloc()
{
  size_t len = sizeof(scamper_neighbourdisc_t);
  return (scamper_neighbourdisc_t *)malloc_zero(len);
}

int scamper_neighbourdisc_ifname_set(scamper_neighbourdisc_t *nd, char *ifname)
{
  if(nd->ifname != NULL)
    free(nd->ifname);

  if((nd->ifname = strdup(ifname)) == NULL)
    return -1;

  return 0;
}

void scamper_neighbourdisc_free(scamper_neighbourdisc_t *nd)
{
  uint16_t i;

  if(nd == NULL)
    return;

  if(nd->probes != NULL)
    {
      for(i=0; i<nd->probec; i++)
	scamper_neighbourdisc_probe_free(nd->probes[i]);
      free(nd->probes);
    }

  if(nd->ifname != NULL) free(nd->ifname);
  if(nd->dst_mac != NULL) scamper_addr_free(nd->dst_mac);
  if(nd->dst_ip != NULL) scamper_addr_free(nd->dst_ip);
  if(nd->src_mac != NULL) scamper_addr_free(nd->src_mac);
  if(nd->src_ip != NULL) scamper_addr_free(nd->src_ip);
  if(nd->cycle != NULL) scamper_cycle_free(nd->cycle);
  if(nd->list != NULL) scamper_list_free(nd->list);

  free(nd);
  return;
}
