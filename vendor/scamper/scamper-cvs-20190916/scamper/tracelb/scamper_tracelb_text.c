/*
 * scamper_tracelb_text.c
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
 * Author: Matthew Luckie
 *
 * $Id: scamper_tracelb_text.c,v 1.6 2018/05/23 08:52:39 mjl Exp $
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
  "$Id: scamper_tracelb_text.c,v 1.6 2018/05/23 08:52:39 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tracelb.h"
#include "scamper_file.h"
#include "scamper_tracelb_text.h"
#include "utils.h"

static void probeset_summary_tostr(scamper_tracelb_probeset_summary_t *sum,
				   char *buf, size_t len, size_t *off)
{
  char dst[64];
  int k;

  if(sum->nullc > 0 && sum->addrc == 0)
    {
      string_concat(buf, len, off, "*");
      return;
    }

  scamper_addr_tostr(sum->addrs[0], dst, sizeof(dst));
  string_concat(buf, len, off, "(%s", dst);
  for(k=1; k<sum->addrc; k++)
    {
      scamper_addr_tostr(sum->addrs[k], dst, sizeof(dst));
      string_concat(buf, len, off, ", %s", dst);
    }
  if(sum->nullc > 0)
    string_concat(buf, len, off, ", *)");
  else
    string_concat(buf, len, off, ")");

  return;
}

int scamper_file_text_tracelb_write(const scamper_file_t *sf,
				    const scamper_tracelb_t *trace)
{
  scamper_tracelb_probeset_summary_t *sum = NULL;
  scamper_tracelb_probeset_t *set;
  const scamper_tracelb_node_t *node;
  scamper_tracelb_link_t *link;
  size_t len;
  size_t off;
  char buf[1024], src[64], dst[64];
  int fd = scamper_file_getfd(sf);
  int i, j;

  snprintf(buf, sizeof(buf),
	   "tracelb from %s to %s, %d nodes, %d links, %d probes, %d%%\n",
	   scamper_addr_tostr(trace->src, src, sizeof(src)),
	   scamper_addr_tostr(trace->dst, dst, sizeof(dst)),
	   trace->nodec, trace->linkc, trace->probec, trace->confidence);

  len = strlen(buf);
  write_wrap(fd, buf, NULL, len);

  for(i=0; i<trace->nodec; i++)
    {
      node = trace->nodes[i];

      if(node->addr != NULL)
	scamper_addr_tostr(node->addr, src, sizeof(src));
      else
	snprintf(src, sizeof(src), "*");

      if(node->linkc > 1)
	{
	  for(j=0; j<node->linkc; j++)
	    {
	      scamper_addr_tostr(node->links[j]->to->addr, dst, sizeof(dst));
	      snprintf(buf, sizeof(buf), "%s -> %s\n", src, dst);
	      len = strlen(buf);
	      write_wrap(fd, buf, NULL, len);
	    }
	}
      else if(node->linkc == 1)
	{
	  link = node->links[0];
	  off = 0;

	  string_concat(buf, sizeof(buf), &off, "%s -> ", src);
	  for(j=0; j<link->hopc-1; j++)
	    {
	      set = link->sets[j];
	      if((sum = scamper_tracelb_probeset_summary_alloc(set)) == NULL)
		return -1;
	      probeset_summary_tostr(sum, buf, sizeof(buf), &off);
	      string_concat(buf, sizeof(buf), &off, " -> ");
	      scamper_tracelb_probeset_summary_free(sum); sum = NULL;
	    }

	  if(link->to != NULL)
	    {
	      scamper_addr_tostr(link->to->addr, dst, sizeof(dst));
	      string_concat(buf, sizeof(buf), &off, "%s", dst);
	    }
	  else
	    {
	      set = link->sets[link->hopc-1];
	      if((sum = scamper_tracelb_probeset_summary_alloc(set)) == NULL)
		return -1;
	      probeset_summary_tostr(sum, buf, sizeof(buf), &off);
	      scamper_tracelb_probeset_summary_free(sum); sum = NULL;
	    }

	  string_concat(buf, sizeof(buf), &off, "\n");
	  write_wrap(fd, buf, NULL, off);
	}
    }

  return 0;
}
