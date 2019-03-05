/*
 * scamper_file_json.c
 *
 * $Id: scamper_file_json.c,v 1.2 2018/05/08 06:47:19 mjl Exp $
 *
 * Copyright (C) 2017 Matthew Luckie
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
  "$Id: scamper_file_json.c,v 1.2 2018/05/08 06:47:19 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_list.h"
#include "scamper_file.h"
#include "scamper_file_json.h"
#include "utils.h"

int scamper_file_json_cyclestart_write(const scamper_file_t *sf,
				       scamper_cycle_t *c)
{
  char buf[1024];
  size_t off = 0;

  string_concat(buf, sizeof(buf), &off,
		"{\"type\":\"cycle-start\", \"list_name\":\"%s\", \"id\":%u",
		c->list->name, c->id);
  if(c->hostname != NULL)
    string_concat(buf,sizeof(buf),&off, ", \"hostname\":\"%s\"", c->hostname);
  string_concat(buf,sizeof(buf),&off, ", \"start_time\":%u}\n",c->start_time);

  return json_write(sf, buf, off);
}

int scamper_file_json_cyclestop_write(const scamper_file_t *sf,
				      scamper_cycle_t *c)
{
  char buf[1024];
  size_t off = 0;

  string_concat(buf, sizeof(buf), &off,
		"{\"type\":\"cycle-stop\", \"list_name\":\"%s\", \"id\":%u",
		c->list->name, c->id);
  if(c->hostname != NULL)
    string_concat(buf,sizeof(buf),&off, ", \"hostname\":\"%s\"", c->hostname);
  string_concat(buf,sizeof(buf),&off, ", \"stop_time\":%u}\n", c->stop_time);

  return json_write(sf, buf, off);
}

int json_write(const scamper_file_t *sf, const void *buf, size_t len)
{
  scamper_file_writefunc_t wf = scamper_file_getwritefunc(sf);
  json_state_t *state = scamper_file_getstate(sf);
  off_t off = 0;
  void *param;
  int fd;

  if(wf != NULL)
    {
      param = scamper_file_getwriteparam(sf);
      return wf(param, buf, len);
    }

  fd = scamper_file_getfd(sf);
  if(state->isreg && (off = lseek(fd, 0, SEEK_CUR)) == (off_t)-1)
    return -1;

  if(write_wrap(fd, buf, NULL, len) != 0)
    {
      /*
       * if we could not write the buf out, then truncate the file at
       * the hdr we just wrote out above.
       */
      if(state->isreg != 0)
	{
	  if(ftruncate(fd, off) != 0)
	    return -1;
	}

      return -1;
    }

  return 0;
}

int scamper_file_json_init_write(scamper_file_t *sf)
{
  json_state_t *s = NULL;
  struct stat sb;
  int fd;

  if((s = malloc_zero(sizeof(json_state_t))) == NULL)
    goto err;

  if((fd = scamper_file_getfd(sf)) != -1)
    {
      if(fstat(fd, &sb) != 0)
	goto err;
      if(S_ISREG(sb.st_mode))
	s->isreg = 1;
    }

  scamper_file_setstate(sf, s);
  return 0;

 err:
  if(s != NULL) free(s);
  return -1;
}

void scamper_file_json_free_state(scamper_file_t *sf)
{
  json_state_t *state;

  if((state = scamper_file_getstate(sf)) == NULL)
    return;

  free(state);
  return;
}
