/*
 * scamper_sting_text.c
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Author: Matthew Luckie
 *
 * $Id: scamper_sting_text.c,v 1.2 2010/10/18 07:02:57 mjl Exp $
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
  "$Id: scamper_sting_text.c,v 1.2 2010/10/18 07:02:57 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_sting.h"
#include "scamper_file.h"
#include "scamper_sting_text.h"
#include "utils.h"

int scamper_file_text_sting_write(const scamper_file_t *sf,
				  const scamper_sting_t *sting)
{
  int      fd = scamper_file_getfd(sf);
  char     buf[192], src[64], dst[64];
  size_t   len;
  uint32_t i, txc = 0;

  snprintf(buf, sizeof(buf),
	   "sting from %s:%d to %s:%d, %d probes, %dms mean\n"
	   " data-ack count %d, holec %d\n",
	   scamper_addr_tostr(sting->src, src, sizeof(src)), sting->sport,
	   scamper_addr_tostr(sting->dst, dst, sizeof(dst)), sting->dport,
	   sting->count, sting->mean, sting->dataackc, sting->holec);

  len = strlen(buf);
  write_wrap(fd, buf, NULL, len);

  if(sting->holec > 0)
    {
      for(i=0; i<sting->pktc; i++)
	{
	  if((sting->pkts[i]->flags & SCAMPER_STING_PKT_FLAG_DATA) == 0)
	    continue;
	  txc++;

	  if(sting->pkts[i]->flags & SCAMPER_STING_PKT_FLAG_HOLE)
	    {
	      snprintf(buf, sizeof(buf), "  probe %d hole\n", txc);
	      len = strlen(buf);
	      write_wrap(fd, buf, NULL, len);
	    }
	}
    }

  return 0;
}
