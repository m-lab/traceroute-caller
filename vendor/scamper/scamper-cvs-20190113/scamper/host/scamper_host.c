/*
 * scamper_host
 *
 * $Id: scamper_host.c,v 1.3 2018/12/12 09:17:35 mjl Exp $
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
  "$Id: scamper_host.c,v 1.3 2018/12/12 09:17:35 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_host.h"

#include "utils.h"

int scamper_host_query_counts(scamper_host_query_t *q,
			      uint16_t an, uint16_t ns, uint16_t ar)
{
  q->ancount = an;
  q->nscount = ns;
  q->arcount = ar;

  if(an > 0 && (q->an = malloc_zero(sizeof(scamper_host_rr_t *) * an)) == NULL)
    return -1;
  if(ns > 0 && (q->ns = malloc_zero(sizeof(scamper_host_rr_t *) * ns)) == NULL)
    return -1;
  if(ar > 0 && (q->ar = malloc_zero(sizeof(scamper_host_rr_t *) * ar)) == NULL)
    return -1;

  return 0;
}

void scamper_host_rr_soa_free(scamper_host_rr_soa_t *soa)
{
  if(soa == NULL)
    return;
  if(soa->mname != NULL) free(soa->mname);
  if(soa->rname != NULL) free(soa->rname);
  free(soa);
  return;
}

scamper_host_rr_soa_t *scamper_host_rr_soa_alloc(const char *mn,const char *rn)
{
  scamper_host_rr_soa_t *soa;
  if((soa = malloc_zero(sizeof(scamper_host_rr_soa_t))) == NULL ||
     (soa->mname = strdup(mn)) == NULL ||
     (soa->rname = strdup(rn)) == NULL)
    {
      scamper_host_rr_soa_free(soa);
      return NULL;
    }
  return soa;
}

void scamper_host_rr_mx_free(scamper_host_rr_mx_t *mx)
{
  if(mx == NULL)
    return;
  if(mx->exchange != NULL) free(mx->exchange);
  free(mx);
  return;
}

scamper_host_rr_mx_t *scamper_host_rr_mx_alloc(uint16_t pref, const char *exch)
{
  scamper_host_rr_mx_t *mx;
  if((mx = malloc_zero(sizeof(scamper_host_rr_mx_t))) == NULL ||
     (mx->exchange = strdup(exch)) == NULL)
    {
      scamper_host_rr_mx_free(mx);
      return NULL;
    }
  mx->preference = pref;
  return mx;
}

void scamper_host_rr_free(scamper_host_rr_t *rr)
{
  if(rr == NULL)
    return;

  if(rr->name != NULL)
    free(rr->name);

  if(rr->un.str != NULL)
    {
      switch(rr->type)
	{
	case SCAMPER_HOST_TYPE_NS:
	case SCAMPER_HOST_TYPE_CNAME:
	case SCAMPER_HOST_TYPE_PTR:
	  free(rr->un.str);
	  break;

	case SCAMPER_HOST_TYPE_A:
	case SCAMPER_HOST_TYPE_AAAA:
	  scamper_addr_free(rr->un.addr);
	  break;

	case SCAMPER_HOST_TYPE_SOA:
	  scamper_host_rr_soa_free(rr->un.soa);
	  break;

	case SCAMPER_HOST_TYPE_MX:
	  scamper_host_rr_mx_free(rr->un.mx);
	  break;
	}
    }

  free(rr);
  return;
}

scamper_host_rr_t *scamper_host_rr_alloc(const char *name, uint16_t class,
					 uint16_t type, uint32_t ttl)
{
  scamper_host_rr_t *rr;

  if((rr = malloc_zero(sizeof(scamper_host_rr_t))) == NULL ||
     (rr->name = strdup(name)) == NULL)
    {
      scamper_host_rr_free(rr);
      return NULL;
    }
  rr->class = class;
  rr->type = type;
  rr->ttl = ttl;
  return rr;
}

void scamper_host_query_free(scamper_host_query_t *query)
{
  int r;

  if(query == NULL)
    return;

  if(query->an != NULL)
    {
      for(r=0; r<query->ancount; r++)
	scamper_host_rr_free(query->an[r]);
      free(query->an);
    }
  if(query->ns != NULL)
    {
      for(r=0; r<query->nscount; r++)
	scamper_host_rr_free(query->ns[r]);
      free(query->ns);
    }
  if(query->ar != NULL)
    {
      for(r=0; r<query->arcount; r++)
	scamper_host_rr_free(query->ar[r]);
      free(query->ar);
    }

  free(query);
  return;
}

void scamper_host_free(scamper_host_t *host)
{
  int q;

  if(host == NULL)
    return;

  if(host->queries != NULL)
    {
      for(q=0; q<host->qcount; q++)
	scamper_host_query_free(host->queries[q]);
      free(host->queries);
    }

  if(host->qname != NULL) free(host->qname);
  if(host->server != NULL) scamper_addr_free(host->server);
  if(host->cycle != NULL) scamper_cycle_free(host->cycle);
  if(host->list != NULL) scamper_list_free(host->list);

  free(host);
  return;  
}

scamper_host_t *scamper_host_alloc(void)
{
  return (scamper_host_t *)malloc_zero(sizeof(scamper_host_t));
}
