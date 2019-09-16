/*
 * scamper_dealias.c
 *
 * $Id: scamper_sting.c,v 1.11 2014/06/12 19:59:48 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
 * Author: Matthew Luckie
 *
 * This file implements algorithms described in the sting-0.7 source code,
 * as well as the paper:
 *
 *  Sting: a TCP-based Network Measurement Tool
 *  by Stefan Savage
 *  1999 USENIX Symposium on Internet Technologies and Systems
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
  "$Id: scamper_sting.c,v 1.11 2014/06/12 19:59:48 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_sting.h"
#include "utils.h"

scamper_sting_pkt_t *scamper_sting_pkt_alloc(uint8_t flags, uint8_t *data,
					     uint16_t len, struct timeval *tv)
{
  scamper_sting_pkt_t *pkt;

  if((pkt = malloc_zero(sizeof(scamper_sting_pkt_t))) == NULL)
    goto err;

  pkt->flags = flags;
  if(len != 0 && data != NULL)
    {
      if((pkt->data = memdup(data, len)) == NULL)
	goto err;
      pkt->len = len;
    }
  if(tv != NULL) timeval_cpy(&pkt->tv, tv);
  return pkt;

 err:
  free(pkt);
  return NULL;
}

void scamper_sting_pkt_free(scamper_sting_pkt_t *pkt)
{
  if(pkt == NULL)
    return;
  if(pkt->data != NULL) free(pkt->data);
  free(pkt);
  return;
}

int scamper_sting_data(scamper_sting_t *sting,const uint8_t *data,uint16_t len)
{
  if(len == 0 || (sting->data = memdup(data, len)) == NULL)
    return -1;
  sting->datalen = len;
  return 0;
}

int scamper_sting_pkt_record(scamper_sting_t *sting, scamper_sting_pkt_t *pkt)
{
  size_t len = (sting->pktc + 1) * sizeof(scamper_sting_pkt_t *);

  /* Add a new element to the pkts array */
  if(realloc_wrap((void**)&sting->pkts, len) != 0)
    return -1;

  sting->pkts[sting->pktc++] = pkt;
  return 0;
}

int scamper_sting_pkts_alloc(scamper_sting_t *sting, uint32_t pktc)
{
  size_t size = pktc * sizeof(scamper_sting_pkt_t *);
  if((sting->pkts = (scamper_sting_pkt_t **)malloc_zero(size)) == NULL)
    return -1;
  return 0;
}

void scamper_sting_free(scamper_sting_t *sting)
{
  if(sting == NULL)
    return;

  if(sting->src != NULL)   scamper_addr_free(sting->src);
  if(sting->dst != NULL)   scamper_addr_free(sting->dst);
  if(sting->list != NULL)  scamper_list_free(sting->list);
  if(sting->cycle != NULL) scamper_cycle_free(sting->cycle);
  if(sting->data != NULL)  free(sting->data);

  free(sting);
  return;
}

scamper_sting_t *scamper_sting_alloc(void)
{
  return (scamper_sting_t *)malloc_zero(sizeof(scamper_sting_t));
}
