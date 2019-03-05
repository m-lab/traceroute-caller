/*
 * scamper_source_tsps.c
 *
 * $Id: scamper_source_tsps.c,v 1.10 2017/12/03 09:38:27 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
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
  "$Id: scamper_source_tsps.c,v 1.10 2017/12/03 09:38:27 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_debug.h"
#include "scamper_outfiles.h"
#include "scamper_task.h"
#include "scamper_sources.h"
#include "scamper_linepoll.h"
#include "scamper_fds.h"
#include "scamper_privsep.h"
#include "scamper_source_tsps.h"
#include "utils.h"

typedef struct scamper_source_tsps
{
  scamper_source_t   *source;
  char               *filename;
  scamper_fd_t       *fd;
  scamper_linepoll_t *lp;
  int                 done;
} scamper_source_tsps_t;

static int stdin_used = 0;

/*
 * ssf_free
 *
 * free up all resources related to an address-list-file.
 */
static void ssf_free(scamper_source_tsps_t *ssf)
{
  int fd = -1;

  if(ssf->lp != NULL)
    {
      scamper_linepoll_free(ssf->lp, 0);
      ssf->lp = NULL;
    }

  if(ssf->filename != NULL)
    {
      free(ssf->filename);
      ssf->filename = NULL;
    }

  if(ssf->fd != NULL)
    {
      fd = scamper_fd_fd_get(ssf->fd);
      scamper_fd_free(ssf->fd);
      ssf->fd = NULL;
    }

  if(fd != -1)
    {
      close(fd);
    }

  free(ssf);
  return;
}

static int ssf_open(const char *filename)
{
  int fd = -1;

  /* get a file descriptor to the file */
  if(strcmp(filename, "-") != 0)
    {
#if defined(WITHOUT_PRIVSEP)
      fd = open(filename, O_RDONLY);
#else
      fd = scamper_privsep_open_file(filename, O_RDONLY, 0);
#endif
    }
  else if(stdin_used == 0)
    {
      fd = 1;
      stdin_used = 1;
    }

  if(fd == -1)
    goto err;

#ifdef O_NONBLOCK
  if(fcntl_set(fd, O_NONBLOCK) == -1)
    goto err;
#endif

  return fd;

 err:
  if(fd != -1) close(fd);
  return -1;
}

/*
 * ssf_read_line
 *
 * this callback receives a single line per call, which should contain an
 * address in string form.  it combines that address with the source's
 * default command and then passes the string to source_command for further
 * processing.  the line eventually ends up in the commands queue.
 */
static int ssf_read_line(void *param, uint8_t *buf, size_t len)
{
  scamper_source_tsps_t *ssf = (scamper_source_tsps_t *)param;
  scamper_source_t *source = ssf->source;
  char *str = (char *)buf;
  char *bits[5];
  int   i, bitc = 0;
  char cb[256];
  size_t off = 0;

  /* make sure the string contains only printable characters */
  if(string_isprint(str, len) == 0)
    goto err;

  /* make sure the line isn't blank or a comment line */
  if(str[0] == '\0' || str[0] == '#')
    return 0;

  for(;;)
    {
      if(bitc == 5)
	goto err;

      bits[bitc++] = str;
      while(isdigit((int)*str) != 0 || *str == '.')
	str++;

      if(*str == '\0')
	break;

      if(*str == ' ' || *str == '\t')
	{
	  *str = '\0'; str++;
	  if(*str == '\0')
	    goto err;
	}
      else
	goto err;
    }

  string_concat(cb, sizeof(cb), &off, "ping");
  if(bitc > 1)
    {
      string_concat(cb, sizeof(cb), &off, " -T tsprespec=%s", bits[1]);
      for(i=2; i<bitc; i++)
	string_concat(cb, sizeof(cb), &off, ",%s", bits[i]);
    }
  string_concat(cb, sizeof(cb), &off, " %s", bits[0]);

  if(scamper_source_command(source, cb) != 0)
    goto err;

  return 0;

 err:
  return -1;
}

static void ssf_read(const int fd, void *param)
{
  scamper_source_tsps_t *ssf = (scamper_source_tsps_t *)param;
  scamper_source_t *source = ssf->source;
  uint8_t buf[1024];
  ssize_t rc;

  assert(ssf->done == 0);

  if((rc = read(fd, buf, sizeof(buf))) > 0)
    {
      /* got data to read. parse the buffer for addresses, one per line. */
      scamper_linepoll_handle(ssf->lp, buf, (size_t)rc);

      /*
       * if probe queue for this source is sufficiently large, then
       * don't read any more for the time being
       */
      if(scamper_source_getcommandcount(source) >= scamper_pps_get())
	{
	  scamper_fd_read_pause(ssf->fd);
	}
    }
  else if(rc == 0)
    {
      scamper_linepoll_flush(ssf->lp);
      ssf->done = 1;
      scamper_fd_read_pause(ssf->fd);
    }
  else
    {
      if(errno != EAGAIN && errno != EINTR)
	{
	  printerror(__func__, "read failed");
	  goto err;
	}
    }

  return;

 err:
  /*
   * an error occurred.  the simplest way to cause the source to disappear
   * gracefully is to set the done parameter to one, which will signal
   * to the sources code that there are no more commands to come
   */
  ssf->done = 1;
  return;
}

static int ssf_take(void *data)
{
  scamper_source_tsps_t *ssf = (scamper_source_tsps_t *)data;

  if(scamper_source_getcommandcount(ssf->source) < scamper_pps_get() &&
     ssf->done == 0)
    {
      scamper_fd_read_unpause(ssf->fd);
    }
  return 0;
}

static void ssf_freedata(void *data)
{
  ssf_free((scamper_source_tsps_t *)data);
  return;
}

static int ssf_isfinished(void *data)
{
  scamper_source_tsps_t *ssf = (scamper_source_tsps_t *)data;
  return ssf->done;
}

const char *scamper_source_tsps_getfilename(const scamper_source_t *source)
{
  scamper_source_tsps_t *ssf;
  if((ssf = (scamper_source_tsps_t *)scamper_source_getdata(source)) != NULL)
    return ssf->filename;
  return NULL;
}

scamper_source_t *scamper_source_tsps_alloc(scamper_source_params_t *ssp,
					    const char *filename)
{
  scamper_source_tsps_t *ssf = NULL;
  int fd = -1;

  /* sanity checks */
  if(ssp == NULL || filename == NULL)
    {
      goto err;
    }

  /* allocate the structure for keeping track of the address list file */
  if((ssf = malloc_zero(sizeof(scamper_source_tsps_t))) == NULL ||
     (ssf->filename = strdup(filename)) == NULL)
    {
      goto err;
    }

  if((fd = ssf_open(filename)) == -1)
    {
      goto err;
    }

  /* allocate a scamper_fd_t to monitor when new data is able to be read */
  if((ssf->fd = scamper_fd_file(fd, ssf_read, ssf)) == NULL)
    {
      goto err;
    }
  fd = -1;

  if((ssf->lp = scamper_linepoll_alloc(ssf_read_line, ssf)) == NULL)
    {
      goto err;
    }

  /*
   * data and callback functions that scamper_source_alloc needs to know about
   */
  ssp->data        = ssf;
  ssp->take        = ssf_take;
  ssp->freedata    = ssf_freedata;
  ssp->isfinished  = ssf_isfinished;
  ssp->type        = SCAMPER_SOURCE_TYPE_TSPS;

  /* allocate the parent source structure */
  if((ssf->source = scamper_source_alloc(ssp)) == NULL)
    {
      goto err;
    }

  return ssf->source;

 err:
  if(ssf != NULL)
    {
      assert(ssf->source == NULL);
      ssf_free(ssf);
    }
  if(fd != -1) close(fd);
  return NULL;
}
