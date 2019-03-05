/*
 * scamper_sniff.c
 *
 * $Id: scamper_sniff.c,v 1.2 2016/09/17 05:40:58 mjl Exp $
 *
 * Copyright (C) 2011 The University of Waikato
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
  "$Id: scamper_sniff.c,v 1.2 2016/09/17 05:40:58 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_sniff.h"

#include "utils.h"

scamper_sniff_pkt_t *scamper_sniff_pkt_alloc(uint8_t *data, uint16_t len,
					     struct timeval *tv)
{
  scamper_sniff_pkt_t *pkt;

  if((pkt = malloc_zero(sizeof(scamper_sniff_pkt_t))) == NULL)
    goto err;

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

void scamper_sniff_pkt_free(scamper_sniff_pkt_t *pkt)
{
  if(pkt == NULL)
    return;
  if(pkt->data != NULL)
    free(pkt->data);
  free(pkt);
  return;
}

scamper_sniff_t *scamper_sniff_alloc(void)
{
  return malloc_zero(sizeof(scamper_sniff_t));
}

void scamper_sniff_free(scamper_sniff_t *sniff)
{
  uint32_t i;

  if(sniff == NULL)
    return;

  if(sniff->list != NULL)
    scamper_list_free(sniff->list);
  if(sniff->cycle != NULL)
    scamper_cycle_free(sniff->cycle);
  if(sniff->src != NULL)
    scamper_addr_free(sniff->src);

  if(sniff->pkts != NULL)
    {
      for(i=0; i<sniff->pktc; i++)
	if(sniff->pkts[i] != NULL)
	  scamper_sniff_pkt_free(sniff->pkts[i]);
      free(sniff->pkts);
    }

  free(sniff);

  return;
}

int scamper_sniff_pkts_alloc(scamper_sniff_t *sniff, int pktc)
{
  size_t size = pktc * sizeof(scamper_sniff_pkt_t *);
  if((sniff->pkts = (scamper_sniff_pkt_t **)malloc_zero(size)) == NULL)
    return -1;
  sniff->pktc = pktc;
  return 0;
}
