/*
 * scamper_file_text.c
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Author: Matthew Luckie
 *
 * $Id: scamper_file_text.c,v 1.87 2011/09/16 03:15:44 mjl Exp $
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
  "$Id: scamper_file_text.c,v 1.87 2011/09/16 03:15:44 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_file.h"
#include "scamper_file_text.h"
#include "utils.h"

int scamper_file_text_is(const scamper_file_t *sf)
{
  char buf[10];
  int fd;

  fd = scamper_file_getfd(sf);

  if(lseek(fd, 0, SEEK_SET) == -1)
    {
      return 0;
    }

  if(read_wrap(fd, buf, NULL, sizeof(buf)) != 0)
    {
      return 0;
    }

  if(strncmp(buf, "traceroute", 10) == 0)
    {
      if(lseek(fd, 0, SEEK_SET) == -1)
	{
	  return 0;
	}
      return 1;
    }

  return 0;
}
