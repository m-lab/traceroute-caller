/*
 * scamper_osinfo.c
 *
 * $Id: scamper_osinfo.c,v 1.5 2017/12/03 09:38:27 mjl Exp $
 *
 * Copyright (C) 2006 Matthew Luckie
 * Copyright (C) 2014 The Regents of the University of California
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
  "$Id: scamper_osinfo.c,v 1.5 2017/12/03 09:38:27 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_debug.h"
#include "scamper_osinfo.h"
#include "mjl_list.h"
#include "utils.h"

static scamper_osinfo_t *osinfo = NULL;

const scamper_osinfo_t *scamper_osinfo_get(void)
{
  return osinfo;
}

/*
 * uname_wrap
 *
 * do some basic parsing on the output from uname
 */
#ifndef _WIN32
int scamper_osinfo_init(void)
{
  struct utsname    utsname;
  int               i;
  char             *str, *ptr;
  slist_t          *nos = NULL;
  size_t            size;

  /* call uname to get the information */
  if(uname(&utsname) < 0)
    {
      printerror(__func__, "could not uname");
      goto err;
    }

  /* allocate our wrapping struct */
  if((osinfo = malloc_zero(sizeof(scamper_osinfo_t))) == NULL)
    {
      printerror(__func__, "could not malloc osinfo");
      goto err;
    }

  /* copy sysname in */
  if((osinfo->os = strdup(utsname.sysname)) == NULL)
    {
      printerror(__func__, "could not strdup sysname");
      goto err;
    }

  /* parse the OS name */
  if(strcasecmp(osinfo->os, "FreeBSD") == 0)
    osinfo->os_id = SCAMPER_OSINFO_OS_FREEBSD;
  else if(strcasecmp(osinfo->os, "OpenBSD") == 0)
    osinfo->os_id = SCAMPER_OSINFO_OS_OPENBSD;
  else if(strcasecmp(osinfo->os, "NetBSD") == 0)
    osinfo->os_id = SCAMPER_OSINFO_OS_NETBSD;
  else if(strcasecmp(osinfo->os, "SunOS") == 0)
    osinfo->os_id = SCAMPER_OSINFO_OS_SUNOS;
  else if(strcasecmp(osinfo->os, "Linux") == 0)
    osinfo->os_id = SCAMPER_OSINFO_OS_LINUX;
  else if(strcasecmp(osinfo->os, "Darwin") == 0)
    osinfo->os_id = SCAMPER_OSINFO_OS_DARWIN;

  /* parse the release integer string */
  if((nos = slist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc nos");
      goto err;
    }

  str = utsname.release;
  for(;;)
    {
      ptr = str;
      while(isdigit((int)*ptr) != 0)
	ptr++;

      if(*ptr == '.')
	{
	  *ptr = '\0';
	  if(slist_tail_push(nos, str) == NULL)
	    {
	      printerror(__func__, "could not push str");
	      goto err;
	    }
	  str = ptr + 1;
	  continue;
	}

      *ptr = '\0';
      if(str != ptr)
	{
	  if(slist_tail_push(nos, str) == NULL)
	    {
	      printerror(__func__, "could not push str");
	      goto err;
	    }
	  break;
	}
    }

  osinfo->os_rel_dots = slist_count(nos);
  if(osinfo->os_rel_dots != 0)
    {
      size = osinfo->os_rel_dots * sizeof(long);
      if((osinfo->os_rel = malloc_zero(size)) == NULL)
	{
	  printerror(__func__, "could not malloc os_rel");
	  goto err;
	}

      i = 0;
      while((str = slist_head_pop(nos)) != NULL)
	{
	  if(string_tolong(str, &osinfo->os_rel[i]) != 0)
	    {
	      printerror(__func__, "could not tolong");
	      goto err;
	    }
	  i++;
	}
    }

  slist_free(nos);
  return 0;

 err:
  if(nos != NULL) slist_free(nos);
  return -1;
}
#endif

#ifdef _WIN32
int scamper_osinfo_init(void)
{
  if((osinfo = malloc_zero(sizeof(scamper_osinfo_t))) == NULL)
    goto err;
  if((osinfo->os = strdup("Windows")) == NULL)
    goto err;
  osinfo->os_id = SCAMPER_OSINFO_OS_WINDOWS;
  return 0;

 err:
  return -1;
}
#endif

void scamper_osinfo_cleanup(void)
{
  if(osinfo == NULL)
    return;
  if(osinfo->os != NULL) free(osinfo->os);
  if(osinfo->os_rel != NULL) free(osinfo->os_rel);
  free(osinfo);
  return;
}
