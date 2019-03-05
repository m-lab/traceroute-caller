/*
 * sc_warts2json
 *
 * $Id: sc_warts2json.c,v 1.8 2018/05/22 10:08:59 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2013      The Regents of the University of California
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
  "$Id: sc_warts2json.c,v 1.8 2018/05/22 10:08:59 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_file.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "ping/scamper_ping.h"
#include "trace/scamper_trace.h"
#include "tracelb/scamper_tracelb.h"
#include "dealias/scamper_dealias.h"
#include "tbit/scamper_tbit.h"
#include "utils.h"

int main(int argc, char *argv[])
{
  uint16_t types[] = {
    SCAMPER_FILE_OBJ_CYCLE_START,
    SCAMPER_FILE_OBJ_CYCLE_STOP,
    SCAMPER_FILE_OBJ_PING,
    SCAMPER_FILE_OBJ_TRACE,
    SCAMPER_FILE_OBJ_TRACELB,
    SCAMPER_FILE_OBJ_DEALIAS,
    SCAMPER_FILE_OBJ_TBIT,
  };
  scamper_file_t *in, *out;
  scamper_file_filter_t *filter;
  char **files = NULL;
  int filec;
  uint16_t type;
  void *data;
  int i;

  if((out = scamper_file_openfd(STDOUT_FILENO, NULL, 'w', "json")) == NULL)
    {
      fprintf(stderr, "could not associate stdout\n");
      return -1;
    }

  filter = scamper_file_filter_alloc(types, sizeof(types)/sizeof(uint16_t));
  if(filter == NULL)
    {
      fprintf(stderr, "could not allocate filter\n");
      return -1;
    }

  filec = argc - 1;
  if(filec > 0)
    files = argv + 1;

  for(i=0; i<=filec; i++)
    {
      if(filec == 0)
	{
	  if((in = scamper_file_openfd(STDIN_FILENO,"-",'r',"warts")) == NULL)
	    {
	      fprintf(stderr, "could not use stdin\n");
	      return -1;
	    }
	}
      else if(i < filec)
	{
	  if((in = scamper_file_open(files[i], 'r', NULL)) == NULL)
	    {
	      fprintf(stderr, "could not open %s: %s\n",
		      files[i], strerror(errno));
	      return -1;
	    }
	}
      else break;

      while(scamper_file_read(in, filter, &type, (void *)&data) == 0)
	{
	  if(data == NULL)
	    break; /* EOF */

	  if(scamper_file_write_obj(out, type, data) != 0)
	    return -1;

	  if(type == SCAMPER_FILE_OBJ_PING)
	    scamper_ping_free(data);
	  else if(type == SCAMPER_FILE_OBJ_TRACE)
	    scamper_trace_free(data);
	  else if(type == SCAMPER_FILE_OBJ_DEALIAS)
	    scamper_dealias_free(data);
	  else if(type == SCAMPER_FILE_OBJ_TBIT)
	    scamper_tbit_free(data);
	  else if(type == SCAMPER_FILE_OBJ_TRACELB)
	    scamper_tracelb_free(data);
	}

      scamper_file_close(in);
    }

  scamper_file_filter_free(filter);
  scamper_file_close(out);
  return 0;
}
