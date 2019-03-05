/*
 * scamper_list.c
 *
 * $Id: scamper_list.c,v 1.22 2011/09/16 03:15:44 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
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
  "$Id: scamper_list.c,v 1.22 2011/09/16 03:15:44 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_list.h"
#include "utils.h"

/*
 * scamper_cycle_cmp
 *
 * utility function for comparing two cycles.  note that the stop time
 * parameters are not compared; one cycle with a stop time might be
 * compared with the (same) cycle without a stop time, and be rejected
 * incorrectly.
 */
int scamper_cycle_cmp(scamper_cycle_t *a, scamper_cycle_t *b)
{
  int i;

  if(a == b)
    {
      return 0;
    }

  /* compare lists */
  if((i = scamper_list_cmp(a->list, b->list)) != 0)
    {
      return i;
    }

  /* compare cycle ids */
  if(a->id < b->id) return -1;
  if(a->id > b->id) return 1;

  /* compare start times */
  if(a->start_time < b->start_time) return -1;
  if(a->start_time > b->start_time) return 1;

  /* compare host names */
  if(a->hostname != NULL || b->hostname != NULL)
    {
      if(a->hostname == NULL && b->hostname != NULL) return -1;
      if(a->hostname != NULL && b->hostname == NULL) return 1;
      if((i = strcmp(a->hostname, b->hostname)) != 0) return i;
    }

  /* they're the same, as best we can tell */
  return 0;
}

scamper_cycle_t *scamper_cycle_alloc(scamper_list_t *list)
{
  scamper_cycle_t *cycle;

  if(list == NULL)
    {
      return NULL;
    }

  if((cycle = malloc_zero(sizeof(struct scamper_cycle))) == NULL)
    {
      return NULL;
    }

  cycle->list = scamper_list_use(list);
  cycle->refcnt = 1;

  return cycle;
}

scamper_cycle_t *scamper_cycle_use(scamper_cycle_t *cycle)
{
  if(cycle != NULL) cycle->refcnt++;
  return cycle;
}

void scamper_cycle_free(scamper_cycle_t *cycle)
{
  if(cycle != NULL)
    {
      assert(cycle->refcnt > 0);

      if(--cycle->refcnt > 0)
	{
	  return;
	}

      if(cycle->list != NULL) scamper_list_free(cycle->list);
      if(cycle->hostname != NULL) free(cycle->hostname);
      free(cycle);
    }

  return;
}

int scamper_list_cmp(const scamper_list_t *a, const scamper_list_t *b)
{
  int i;

  /* if the lists are in the same piece of memory, they're identical */
  if(a == b)
    {
      return 0;
    }

  /* compare list ids */
  if(a->id < b->id) return -1;
  if(a->id > b->id) return 1;

  /* compare name strings */
  if(a->name != NULL || b->name != NULL)
    {
      if(a->name == NULL && b->name != NULL) return -1;
      if(a->name != NULL && b->name == NULL) return 1;
      if((i = strcmp(a->name, b->name)) != 0) return i;
    }

  /* compare description strings */
  if(a->descr != NULL || b->descr != NULL)
    {
      if(a->descr == NULL && b->descr != NULL) return -1;
      if(a->descr != NULL && b->descr == NULL) return 1;
      if((i = strcmp(a->descr, b->descr)) != 0) return i;
    }

  /* compare monitor strings */
  if(a->monitor != NULL || b->monitor != NULL)
    {
      if(a->monitor == NULL && b->monitor != NULL) return -1;
      if(a->monitor != NULL && b->monitor == NULL) return 1;
      if((i = strcmp(a->monitor, b->monitor)) != 0) return i;
    }

  /* they're the same, as best we can tell */
  return 0;
}

scamper_list_t *scamper_list_alloc(const uint32_t id, const char *name,
				   const char *descr, const char *monitor)
{
  scamper_list_t *list;

  if((list = malloc_zero(sizeof(struct scamper_list))) == NULL)
    {
      return NULL;
    }

  list->id = id;
  list->refcnt = 1;

  if(name != NULL && (list->name = strdup(name)) == NULL)
    {
      goto err;
    }

  if(descr != NULL && (list->descr = strdup(descr)) == NULL)
    {
      goto err;
    }

  if(monitor != NULL && (list->monitor = strdup(monitor)) == NULL)
    {
      goto err;
    }

  return list;

 err:
  scamper_list_free(list);
  return NULL;
}

scamper_list_t *scamper_list_use(scamper_list_t *list)
{
  if(list != NULL) list->refcnt++;
  return list;
}

void scamper_list_free(scamper_list_t *list)
{
  if(list != NULL)
    {
      assert(list->refcnt > 0);

      if(--list->refcnt > 0)
	{
	  return;
	}

      if(list->name != NULL) free(list->name);
      if(list->descr != NULL) free(list->descr);
      if(list->monitor != NULL) free(list->monitor);
      free(list);
    }

  return;
}
