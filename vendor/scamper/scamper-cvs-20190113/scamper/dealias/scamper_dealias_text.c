/*
 * scamper_dealias_text.c
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Copyright (C) 2013      Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_dealias_text.c,v 1.3 2013/01/05 22:00:38 mjl Exp $
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
  "$Id: scamper_dealias_text.c,v 1.3 2013/01/05 22:00:38 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_file.h"
#include "scamper_dealias.h"
#include "scamper_dealias_text.h"
#include "utils.h"

int scamper_file_text_dealias_write(const scamper_file_t *sf,
				    const scamper_dealias_t *dealias)
{
  scamper_dealias_ally_t *ally;
  char buf[256], a[64], b[64], c[32];
  int fd = scamper_file_getfd(sf);

  if(SCAMPER_DEALIAS_METHOD_IS_ALLY(dealias))
    {
      ally = dealias->data;
      if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
	snprintf(c, sizeof(c), "aliases");
      else if(dealias->result == SCAMPER_DEALIAS_RESULT_NOTALIASES)
	snprintf(c, sizeof(c), "not aliases");
      else if(dealias->result == SCAMPER_DEALIAS_RESULT_NONE)
	snprintf(c, sizeof(c), "none");
      else
	snprintf(c, sizeof(c), "%d", dealias->result);

      snprintf(buf, sizeof(buf), "%s %s %s\n",
	       scamper_addr_tostr(ally->probedefs[0].dst, a, sizeof(a)),
	       scamper_addr_tostr(ally->probedefs[1].dst, b, sizeof(b)),
	       c);

      write_wrap(fd, buf, NULL, strlen(buf));
    }
  return 0;
}
