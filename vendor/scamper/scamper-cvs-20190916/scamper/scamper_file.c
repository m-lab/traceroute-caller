/*
 * scamper_file.c
 *
 * $Id: scamper_file.c,v 1.74 2019/07/28 09:24:53 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
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
  "$Id: scamper_file.c,v 1.74 2019/07/28 09:24:53 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_file_text.h"
#include "scamper_file_arts.h"
#include "scamper_file_json.h"

#include "trace/scamper_trace.h"
#include "trace/scamper_trace_text.h"
#include "trace/scamper_trace_warts.h"
#include "trace/scamper_trace_json.h"
#include "ping/scamper_ping.h"
#include "ping/scamper_ping_text.h"
#include "ping/scamper_ping_warts.h"
#include "ping/scamper_ping_json.h"
#include "sting/scamper_sting.h"
#include "sting/scamper_sting_text.h"
#include "sting/scamper_sting_warts.h"
#include "tracelb/scamper_tracelb.h"
#include "tracelb/scamper_tracelb_text.h"
#include "tracelb/scamper_tracelb_warts.h"
#include "tracelb/scamper_tracelb_json.h"
#include "dealias/scamper_dealias.h"
#include "dealias/scamper_dealias_text.h"
#include "dealias/scamper_dealias_warts.h"
#include "dealias/scamper_dealias_json.h"
#include "neighbourdisc/scamper_neighbourdisc.h"
#include "neighbourdisc/scamper_neighbourdisc_warts.h"
#include "tbit/scamper_tbit.h"
#include "tbit/scamper_tbit_text.h"
#include "tbit/scamper_tbit_warts.h"
#include "tbit/scamper_tbit_json.h"
#include "sniff/scamper_sniff.h"
#include "sniff/scamper_sniff_warts.h"
#include "host/scamper_host.h"
#include "host/scamper_host_warts.h"

#include "utils.h"

#define SCAMPER_FILE_NONE       (-1)
#define SCAMPER_FILE_TEXT        0
#define SCAMPER_FILE_ARTS        1
#define SCAMPER_FILE_WARTS       2
#define SCAMPER_FILE_JSON        3

typedef int (*write_obj_func_t)(scamper_file_t *sf, const void *);

struct scamper_file
{
  char                     *filename;
  int                       fd;
  void                     *state;
  int                       type;
  char                      error_str[256];
  uint32_t                  capability;
  int                       eof;
  scamper_file_writefunc_t  writefunc;
  void                     *writeparam;
  scamper_file_readfunc_t   readfunc;
  void                     *readparam;
};

struct scamper_file_filter
{
  uint32_t *flags;
  uint16_t  max;
};

struct handler
{
  char *type;
  int (*detect)(const scamper_file_t *sf);

  int (*init_read)(scamper_file_t *sf);
  int (*init_write)(scamper_file_t *sf);
  int (*init_append)(scamper_file_t *sf);

  int (*read)(scamper_file_t *sf, scamper_file_filter_t *filter,
	      uint16_t *type, void **data);

  int (*write_trace)(const scamper_file_t *sf,
		     const struct scamper_trace *trace);

  int (*write_cycle_start)(const scamper_file_t *sf,
			   scamper_cycle_t *cycle);

  int (*write_cycle_stop)(const scamper_file_t *sf,
			  scamper_cycle_t *cycle);

  int (*write_ping)(const scamper_file_t *sf,
		    const struct scamper_ping *ping);

  int (*write_tracelb)(const scamper_file_t *sf,
		       const struct scamper_tracelb *trace);

  int (*write_sting)(const scamper_file_t *sf,
		     const struct scamper_sting *sting);

  int (*write_dealias)(const scamper_file_t *sf,
		       const struct scamper_dealias *dealias);

  int (*write_neighbourdisc)(const scamper_file_t *sf,
			     const struct scamper_neighbourdisc *nd);

  int (*write_tbit)(const scamper_file_t *sf,
		    const struct scamper_tbit *tbit);

  int (*write_sniff)(const scamper_file_t *sf,
		     const struct scamper_sniff *sniff);

  int (*write_host)(const scamper_file_t *sf,
		    const struct scamper_host *host);

  void (*free_state)(scamper_file_t *sf);
};

static struct handler handlers[] = {
  {"text",                                 /* type */
   NULL,                                   /* detect */
   NULL,                                   /* init_read */
   NULL,                                   /* init_write */
   NULL,                                   /* init_append */
   NULL,                                   /* read */
   scamper_file_text_trace_write,          /* write_trace */
   NULL,                                   /* write_cycle_start */
   NULL,                                   /* write_cycle_stop */
   scamper_file_text_ping_write,           /* write_ping */
   scamper_file_text_tracelb_write,        /* write_tracelb */
   scamper_file_text_sting_write,          /* write_sting */
   scamper_file_text_dealias_write,        /* write_dealias */
   NULL,                                   /* write_neighbourdisc */
   scamper_file_text_tbit_write,           /* write_tbit */
   NULL,                                   /* write_sniff */
   NULL,                                   /* write_host */
   NULL,                                   /* free_state */
  },
  {"arts",                                 /* type */
   scamper_file_arts_is,                   /* detect */
   scamper_file_arts_init_read,            /* init_read */
   NULL,                                   /* init_write */
   NULL,                                   /* init_append */
   scamper_file_arts_read,                 /* read */
   NULL,                                   /* write_trace */
   NULL,                                   /* write_cycle_start */
   NULL,                                   /* write_cycle_stop */
   NULL,                                   /* write_ping */
   NULL,                                   /* write_tracelb */
   NULL,                                   /* write_sting */
   NULL,                                   /* write_dealias */
   NULL,                                   /* write_neighbourdisc */
   NULL,                                   /* write_tbit */
   NULL,                                   /* write_sniff */
   NULL,                                   /* write_host */
   scamper_file_arts_free_state,           /* free_state */
  },
  {"warts",                                /* type */
   scamper_file_warts_is,                  /* detect */
   scamper_file_warts_init_read,           /* init_read */
   scamper_file_warts_init_write,          /* init_write */
   scamper_file_warts_init_append,         /* init_append */
   scamper_file_warts_read,                /* read */
   scamper_file_warts_trace_write,         /* write_trace */
   scamper_file_warts_cyclestart_write,    /* write_cycle_start */
   scamper_file_warts_cyclestop_write,     /* write_cycle_stop */
   scamper_file_warts_ping_write,          /* write_ping */
   scamper_file_warts_tracelb_write,       /* write_tracelb */
   scamper_file_warts_sting_write,         /* write_sting */
   scamper_file_warts_dealias_write,       /* write_dealias */
   scamper_file_warts_neighbourdisc_write, /* write_neighbourdisc */
   scamper_file_warts_tbit_write,          /* write_tbit */
   scamper_file_warts_sniff_write,         /* write_sniff */
   scamper_file_warts_host_write,          /* write_host */
   scamper_file_warts_free_state,          /* free_state */
  },
  {"json",                                 /* type */
   NULL,                                   /* detect */
   NULL,                                   /* init_read */
   scamper_file_json_init_write,           /* init_write */
   NULL,                                   /* init_append */
   NULL,                                   /* read */
   scamper_file_json_trace_write,          /* write_trace */
   scamper_file_json_cyclestart_write,     /* write_cycle_start */
   scamper_file_json_cyclestop_write,      /* write_cycle_stop */
   scamper_file_json_ping_write,           /* write_ping */
   scamper_file_json_tracelb_write,        /* write_tracelb */
   NULL,                                   /* write_sting */
   scamper_file_json_dealias_write,        /* write_dealias */
   NULL,                                   /* write_neighbourdisc */
   scamper_file_json_tbit_write,           /* write_tbit */
   NULL,                                   /* write_sniff */
   NULL,                                   /* write_host */
   scamper_file_json_free_state,           /* free_state */
  },
};

static int handler_cnt = sizeof(handlers) / sizeof(struct handler);

int scamper_file_getfd(const scamper_file_t *sf)
{
  return sf->fd;
}

void *scamper_file_getstate(const scamper_file_t *sf)
{
  return sf->state;
}

char *scamper_file_getfilename(scamper_file_t *sf)
{
  return sf->filename;
}

void scamper_file_setstate(scamper_file_t *sf, void *state)
{
  sf->state = state;
  return;
}

void scamper_file_setreadfunc(scamper_file_t *sf,
			      void *param, scamper_file_readfunc_t rf)
{
  sf->readfunc  = rf;
  sf->readparam = param;
  return;
}

scamper_file_readfunc_t scamper_file_getreadfunc(const scamper_file_t *sf)
{
  return sf->readfunc;
}

void *scamper_file_getreadparam(const scamper_file_t *sf)
{
  return sf->readparam;
}

void scamper_file_setwritefunc(scamper_file_t *sf,
			       void *param, scamper_file_writefunc_t wf)
{
  sf->writefunc  = wf;
  sf->writeparam = param;
  return;
}

scamper_file_writefunc_t scamper_file_getwritefunc(const scamper_file_t *sf)
{
  return sf->writefunc;
}

void *scamper_file_getwriteparam(const scamper_file_t *sf)
{
  return sf->writeparam;
}

int scamper_file_write_trace(scamper_file_t *sf,
			     const struct scamper_trace *trace)
{
  int rc = -1;

  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_trace != NULL)
    {
      rc = handlers[sf->type].write_trace(sf, trace);
    }

  return rc;
}

int scamper_file_write_ping(scamper_file_t *sf,
			    const struct scamper_ping *ping)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_ping != NULL)
    {
      return handlers[sf->type].write_ping(sf, ping);
    }
  return -1;
}

int scamper_file_write_tracelb(scamper_file_t *sf,
			       const struct scamper_tracelb *trace)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_tracelb != NULL)
    {
      return handlers[sf->type].write_tracelb(sf, trace);
    }
  return -1;
}

int scamper_file_write_sting(scamper_file_t *sf,
			     const struct scamper_sting *sting)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_sting != NULL)
    {
      return handlers[sf->type].write_sting(sf, sting);
    }
  return -1;
}

int scamper_file_write_dealias(scamper_file_t *sf,
			       const struct scamper_dealias *dealias)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_dealias != NULL)
    {
      return handlers[sf->type].write_dealias(sf, dealias);
    }
  return -1;
}

int scamper_file_write_neighbourdisc(scamper_file_t *sf,
				     const struct scamper_neighbourdisc *nd)
{
  if(sf->type != SCAMPER_FILE_NONE &&
     handlers[sf->type].write_neighbourdisc != NULL)
    {
      return handlers[sf->type].write_neighbourdisc(sf, nd);
    }
  return -1;
}

int scamper_file_write_tbit(scamper_file_t *sf,
			    const struct scamper_tbit *tbit)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_tbit != NULL)
    {
      return handlers[sf->type].write_tbit(sf, tbit);
    }
  return -1;
}

int scamper_file_write_sniff(scamper_file_t *sf,
			     const struct scamper_sniff *sniff)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_sniff != NULL)
    {
      return handlers[sf->type].write_sniff(sf, sniff);
    }
  return -1;

}

int scamper_file_write_host(scamper_file_t *sf,
			    const struct scamper_host *host)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_host != NULL)
    {
      return handlers[sf->type].write_host(sf, host);
    }
  return -1;
}

int scamper_file_write_obj(scamper_file_t *sf, uint16_t type, const void *data)
{
  static int (*const func[])(scamper_file_t *sf, const void *) = {
    NULL,
    NULL, /* SCAMPER_FILE_OBJ_LIST */
    (write_obj_func_t)scamper_file_write_cycle_start,
    NULL, /* SCAMPER_FILE_OBJ_CYCLE_DEF */
    (write_obj_func_t)scamper_file_write_cycle_stop,
    NULL, /* SCAMPER_FILE_OBJ_ADDR */
    (write_obj_func_t)scamper_file_write_trace,
    (write_obj_func_t)scamper_file_write_ping,
    (write_obj_func_t)scamper_file_write_tracelb,
    (write_obj_func_t)scamper_file_write_dealias,
    (write_obj_func_t)scamper_file_write_neighbourdisc,
    (write_obj_func_t)scamper_file_write_tbit,
    (write_obj_func_t)scamper_file_write_sting,
    (write_obj_func_t)scamper_file_write_sniff,
    (write_obj_func_t)scamper_file_write_host,
  };
  if(type > 13 || func[type] == NULL)
    return -1;
  return func[type](sf, data);
}

/*
 * scamper_file_read
 *
 *
 */
int scamper_file_read(scamper_file_t *sf, scamper_file_filter_t *filter,
		      uint16_t *type, void **object)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].read != NULL)
    {
      return handlers[sf->type].read(sf, filter, type, object);
    }

  return -1;
}

/*
 * scamper_file_filter_isset
 *
 * check to see if the particular type is set in the filter or not
 */
int scamper_file_filter_isset(scamper_file_filter_t *filter, uint16_t type)
{
  if(filter == NULL || type > filter->max)
    {
      return 0;
    }

  if((filter->flags[type/32] & (0x1 << ((type%32)-1))) == 0)
    {
      return 0;
    }

  return 1;
}

/*
 * scamper_file_filter_alloc
 *
 * allocate a filter for reading data objects from scamper files based on an
 * array of types the caller is interested in.
 */
scamper_file_filter_t *scamper_file_filter_alloc(uint16_t *types, uint16_t num)
{
  scamper_file_filter_t *filter = NULL;
  size_t size;
  int i, j, k;

  /* sanity checks */
  if(types == NULL || num == 0)
    {
      goto err;
    }

  /* allocate filter structure which will be returned to caller */
  if((filter = malloc_zero(sizeof(scamper_file_filter_t))) == NULL)
    {
      goto err;
    }

  /* first, figure out the maximum type value of interest */
  for(i=0; i<num; i++)
    {
      /* sanity check */
      if(types[i] == 0)
	{
	  goto err;
	}
      if(types[i] > filter->max)
	{
	  filter->max = types[i];
	}
    }

  /* sanity check */
  if(filter->max == 0)
    {
      goto err;
    }

  /* allocate the flags array */
  size = sizeof(uint32_t) * filter->max / 32;
  if((filter->max % 32) != 0) size += sizeof(uint32_t);
  if((filter->flags = malloc_zero(size)) == NULL)
    {
      goto err;
    }

  /* go through each type and set the appropriate flag */
  for(i=0; i<num; i++)
    {
      if(types[i] % 32 == 0)
	{
	  j = ((types[i]) / 32) - 1;
	  k = 32;
	}
      else
	{
	  j = types[i] / 32;
	  k = types[i] % 32;
	}

      filter->flags[j] |= (0x1 << (k-1));
    }

  return filter;

 err:
  if(filter != NULL)
    {
      if(filter->flags != NULL) free(filter->flags);
      free(filter);
    }
  return NULL;
}

void scamper_file_filter_free(scamper_file_filter_t *filter)
{
  if(filter != NULL)
    {
      if(filter->flags != NULL) free(filter->flags);
      free(filter);
    }

  return;
}

int scamper_file_write_cycle_start(scamper_file_t *sf, scamper_cycle_t *cycle)
{
  if(sf->type != SCAMPER_FILE_NONE &&
     handlers[sf->type].write_cycle_start != NULL)
    {
      return handlers[sf->type].write_cycle_start(sf, cycle);
    }
  return -1;
}

int scamper_file_write_cycle_stop(scamper_file_t *sf, scamper_cycle_t *cycle)
{
  if(sf->type != SCAMPER_FILE_NONE &&
     handlers[sf->type].write_cycle_stop != NULL)
    {
      return handlers[sf->type].write_cycle_stop(sf, cycle);
    }
  return -1;
}

/*
 * scamper_file_geteof
 *
 */
int scamper_file_geteof(scamper_file_t *sf)
{
  if(sf == NULL || sf->fd == -1) return -1;
  return sf->eof;
}

/*
 * scamper_file_seteof
 *
 */
void scamper_file_seteof(scamper_file_t *sf)
{
  if(sf != NULL && sf->fd != -1)
    sf->eof = 1;
  return;
}

/*
 * scamper_file_free
 *
 */
void scamper_file_free(scamper_file_t *sf)
{
  if(sf != NULL)
    {
      if(sf->filename) free(sf->filename);
      free(sf);
    }
  return;
}

/*
 * scamper_file_close
 *
 */
void scamper_file_close(scamper_file_t *sf)
{
  /* free state associated with the type of scamper_file_t */
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].free_state != NULL)
    {
      handlers[sf->type].free_state(sf);
    }

  /* close the file descriptor */
  if(sf->fd != -1)
    {
      close(sf->fd);
    }

  /* free general state associated */
  scamper_file_free(sf);

  return;
}

char *scamper_file_type_tostr(scamper_file_t *sf, char *buf, size_t len)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].type != NULL)
    {
      strncpy(buf, handlers[sf->type].type, len);
      return buf;
    }

  return NULL;
}

static int file_type_get(char *type)
{
  int i;
  if(type == NULL)
    return SCAMPER_FILE_NONE;
  for(i=0; i<handler_cnt; i++)
    if(strcasecmp(type, handlers[i].type) == 0)
      return i;
  return SCAMPER_FILE_NONE;
}

static int file_type_detect(scamper_file_t *sf)
{
  int i;
  for(i=0; i<handler_cnt; i++)
    if(handlers[i].detect != NULL && handlers[i].detect(sf) == 1)
      return i;
  return SCAMPER_FILE_NONE;
}

static int file_open_read(scamper_file_t *sf)
{
  struct stat sb;

  if(sf->fd != -1)
    {
      if(fstat(sf->fd, &sb) != 0)
	return -1;

      if(sb.st_size != 0 && (sb.st_mode & S_IFIFO) == 0)
	sf->type = file_type_detect(sf);
    }

  if(sf->type == SCAMPER_FILE_NONE)
    return -1;

  if(handlers[sf->type].init_read == NULL)
    return -1;

  return handlers[sf->type].init_read(sf);
}

static int file_open_write(scamper_file_t *sf)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].init_write != NULL)
    return handlers[sf->type].init_write(sf);
  return 0;
}

static int file_open_append(scamper_file_t *sf)
{
  struct stat sb;

  if(fstat(sf->fd, &sb) != 0)
    return -1;

  if(sb.st_size == 0)
    {
      if(sf->type == SCAMPER_FILE_WARTS)
	return handlers[sf->type].init_write(sf);
      else if(sf->type == SCAMPER_FILE_TEXT || sf->type == SCAMPER_FILE_JSON)
	return 0;
      return -1;
    }

  /* can't append to pipes */
  if((sb.st_mode & S_IFIFO) != 0)
    return -1;

  sf->type = file_type_detect(sf);
  if(handlers[sf->type].init_append != NULL)
    return handlers[sf->type].init_append(sf);
  else if(sf->type != SCAMPER_FILE_TEXT && sf->type != SCAMPER_FILE_JSON)
    return -1;

  return 0;
}

static scamper_file_t *file_open(int fd, char *fn, char mode, int type)
{
  scamper_file_t *sf;
  int (*open_func)(scamper_file_t *);

  if(mode == 'r')      open_func = file_open_read;
  else if(mode == 'w') open_func = file_open_write;
  else if(mode == 'a') open_func = file_open_append;
  else return NULL;

  if((sf = (scamper_file_t *)malloc_zero(sizeof(scamper_file_t))) == NULL)
    {
      return NULL;
    }

  if(fn != NULL && (sf->filename = strdup(fn)) == NULL)
    {
      free(sf);
      return NULL;
    }

  sf->type = type;
  sf->fd   = fd;
  if(open_func(sf) == -1)
    {
      scamper_file_close(sf);
      return NULL;
    }

  return sf;
}

scamper_file_t *scamper_file_opennull(char mode, char *format)
{
  uint8_t file_type;

  if(strcasecmp(format, "warts") == 0)
    file_type = SCAMPER_FILE_WARTS;
  else if(strcasecmp(format, "json") == 0)
    file_type = SCAMPER_FILE_JSON;
  else
    return NULL;

  return file_open(-1, NULL, mode, file_type);
}

scamper_file_t *scamper_file_openfd(int fd, char *fn, char mode, char *type)
{
  return file_open(fd, fn, mode, file_type_get(type));
}

/*
 * scamper_file_open
 *
 * open the file specified with the appropriate mode.
 * the modes that we know about are 'r' read-only, 'w' write-only on a
 * brand new file, and 'a' for appending.
 *
 * in 'w' mode [and conditionally for 'a'] an optional parameter may be
 * supplied that says what type of file should be written.
 *  'w' for warts
 *  't' for text
 *  'a' for arts [not implemented]
 *
 * when a file is opened for appending, this second parameter is only
 * used when the file is empty so that writes will be written in the
 * format expected.
 */
scamper_file_t *scamper_file_open(char *filename, char mode, char *type)
{
  scamper_file_t *sf;
  mode_t mo;
  int ft = file_type_get(type);
  int flags = 0;
  int fd = -1;

#ifndef _WIN32
  mo = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
#else
  mo = _S_IREAD | _S_IWRITE;
#endif

  if(mode == 'r')
    {
      if(strcmp(filename, "-") == 0)
	{
	  fd = STDIN_FILENO;
	}
      else
	{
	  flags = O_RDONLY;
	}
    }
  else if(mode == 'w' || mode == 'a')
    {
      /* sanity check the type of file to be written */
      if(ft == SCAMPER_FILE_NONE || ft == SCAMPER_FILE_ARTS)
	{
	  return NULL;
	}

      if(strcmp(filename, "-") == 0)
	{
	  fd = STDIN_FILENO;
	}
      else
	{
	  if(mode == 'w') flags = O_WRONLY | O_TRUNC | O_CREAT;
	  else            flags = O_RDWR | O_APPEND | O_CREAT;
	}
    }
  else
    {
      return NULL;
    }

#ifdef _WIN32
  flags |= O_BINARY;
#endif

  if(fd == -1)
    {
      if(mode == 'r') fd = open(filename, flags);
      else            fd = open(filename, flags, mo);

      if(fd == -1)
	{
	  return NULL;
	}
    }

  sf = file_open(fd, filename, mode, ft);

  return sf;
}
