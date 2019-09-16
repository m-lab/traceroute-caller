/*
 * warts2traceroute
 *
 * $Id: sc_warts2text.c,v 1.26 2018/01/26 07:11:48 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
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
  "$Id: sc_warts2text.c,v 1.26 2018/01/26 07:11:48 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_file.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "trace/scamper_trace.h"
#include "ping/scamper_ping.h"
#include "tracelb/scamper_tracelb.h"
#include "dealias/scamper_dealias.h"
#include "tbit/scamper_tbit.h"
#include "sting/scamper_sting.h"
#include "mjl_splaytree.h"
#include "utils.h"

static splaytree_t *tree = NULL;
static char       **files = NULL;
static int          filec = 0;

typedef int  (*wf_t)(scamper_file_t *, void *);
typedef void (*ff_t)(void *);
typedef scamper_addr_t *(*df_t)(void *);

typedef struct ip2descr
{
  scamper_addr_t *addr;
  char           *descr;
} ip2descr_t;

typedef struct funcset
{
  wf_t write;
  ff_t datafree;
  df_t dst;
} funcset_t;

static int ip2descr_cmp(const ip2descr_t *a, const ip2descr_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

/*
 * ip2descr_line
 *
 * parse lines that look like the following:
 * 1.2.3.4 "foo"
 * 5.6.7.8 "bar"
 */
static int ip2descr_line(char *line, void *param)
{
  static int line_no = 1;
  scamper_addr_t *addr = NULL;
  ip2descr_t fm, *ip2descr = NULL;
  char *ip = line, *descr = line, *tmp;

  if(line[0] == '\0')
    return 0;

  while(*descr != '\0')
    {
      if(*descr == ' ' || *descr == '\t')
	break;
      descr++;
    }
  if(*descr == '\0')
    {
      fprintf(stderr, "premature end to line %d\n", line_no);
      goto err;
    }
  *descr = '\0';
  descr++;

  while(*descr == ' ' || *descr == '\t')
    descr++;

  if(*descr != '"')
    {
      fprintf(stderr, "expected \" on line %d\n", line_no);
      goto err;
    }
  descr++;

  tmp = descr;
  while(*tmp != '\0')
    {
      if(*tmp == '"')
	break;
      tmp++;
    }
  if(*tmp == '\0')
    {
      fprintf(stderr, "missing closing \" on line %d\n", line_no);
      goto err;
    }
  *tmp = '\0';

  if((addr = scamper_addr_resolve(AF_UNSPEC, ip)) == NULL)
    {
      fprintf(stderr, "invalid address '%s' on line %d\n", ip, line_no);
      goto err;
    }

  fm.addr = addr;
  if(splaytree_find(tree, &fm) != NULL)
    {
      fprintf(stderr, "duplicate definition for %s on line %d\n", ip, line_no);
      goto err;
    }

  if((ip2descr = malloc_zero(sizeof(ip2descr_t))) == NULL)
    {
      fprintf(stderr, "could not malloc ip2descr\n");
      goto err;
    }
  if((ip2descr->descr = strdup(descr)) == NULL)
    {
      fprintf(stderr, "could not dup descr on line %d\n", line_no);
      goto err;
    }
  ip2descr->addr = addr; addr = NULL;

  if(splaytree_insert(tree, ip2descr) == NULL)
    {
      fprintf(stderr, "could not add line %d\n", line_no);
      goto err;
    }

  line_no++;
  return 0;

 err:
  if(ip2descr != NULL)
    {
      if(ip2descr->addr != NULL) scamper_addr_free(ip2descr->addr);
      if(ip2descr->descr != NULL) free(ip2descr->descr);
      free(ip2descr);
    }
  if(addr != NULL) scamper_addr_free(addr);
  return -1;
}

static char *ip2descr_lookup(scamper_addr_t *addr)
{
  ip2descr_t fm, *ip2descr;
  fm.addr = addr;
  if((ip2descr = splaytree_find(tree, &fm)) == NULL)
    return NULL;
  return ip2descr->descr;
}

static scamper_addr_t *trace_dst(void *data)
{
  return ((scamper_trace_t *)data)->dst;
}

static scamper_addr_t *ping_dst(void *data)
{
  return ((scamper_ping_t *)data)->dst;
}

static scamper_addr_t *tracelb_dst(void *data)
{
  return ((scamper_tracelb_t *)data)->dst;
}

static scamper_addr_t *tbit_dst(void *data)
{
  return ((scamper_tbit_t *)data)->dst;
}

static scamper_addr_t *sting_dst(void *data)
{
  return ((scamper_sting_t *)data)->dst;
}

static int check_options(int argc, char *argv[])
{
  char *opt_descr = NULL;
  int i;

  while((i = getopt(argc, argv, "d:")) != -1)
    {
      switch(i)
	{
	case 'd':
	  opt_descr = optarg;
	  break;

	default:
	  return -1;
	}
    }

  if(opt_descr != NULL)
    {
      if((tree = splaytree_alloc((splaytree_cmp_t)ip2descr_cmp)) == NULL)
	return -1;
      if(file_lines(opt_descr, ip2descr_line, NULL) != 0)
	return -1;
    }

  filec = argc - optind;
  if(filec > 0)
    files = argv + optind;

  return 0;
}

int main(int argc, char *argv[])
{
  funcset_t funcs[] = {
    {NULL, NULL, NULL},
    {NULL, NULL, NULL}, /* list */
    {NULL, NULL, NULL}, /* cycle start */
    {NULL, NULL, NULL}, /* cycle def */
    {NULL, NULL, NULL}, /* cycle stop */
    {NULL, NULL, NULL}, /* addr */
    {(wf_t)scamper_file_write_trace,  (ff_t)scamper_trace_free, trace_dst},
    {(wf_t)scamper_file_write_ping,   (ff_t)scamper_ping_free, ping_dst},
    {(wf_t)scamper_file_write_tracelb,(ff_t)scamper_tracelb_free, tracelb_dst},
    {(wf_t)scamper_file_write_dealias,(ff_t)scamper_dealias_free, NULL},
    {NULL, NULL, NULL}, /* neighbour discovery */
    {(wf_t)scamper_file_write_tbit,   (ff_t)scamper_tbit_free, tbit_dst},
    {(wf_t)scamper_file_write_sting,  (ff_t)scamper_sting_free, sting_dst},
    {NULL, NULL, NULL}, /* sniff */
  };
  uint16_t types[] = {
    SCAMPER_FILE_OBJ_TRACE,
    SCAMPER_FILE_OBJ_PING,
    SCAMPER_FILE_OBJ_TRACELB,
    SCAMPER_FILE_OBJ_DEALIAS,
    SCAMPER_FILE_OBJ_TBIT,
    SCAMPER_FILE_OBJ_STING,
  };
  scamper_file_t *in, *out;
  scamper_file_filter_t *filter;
  scamper_addr_t *addr;
  uint16_t type;
  void *data;
  char *descr;
  int i;

  if(check_options(argc, argv) != 0)
    {
      return -1;
    }

  if((out = scamper_file_openfd(STDOUT_FILENO, NULL, 'w', "text")) == NULL)
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
	  if(data == NULL) break; /* EOF */

	  assert(type < sizeof(funcs)/sizeof(funcset_t));
	  assert(funcs[type].write != NULL);

	  if(tree != NULL && funcs[type].dst != NULL &&
	     (addr = funcs[type].dst(data)) != NULL &&
	     (descr = ip2descr_lookup(addr)) != NULL)
	    {
	      printf("%s\n", descr);
	    }

	  funcs[type].write(out, data);
	  funcs[type].datafree(data);
	}

      scamper_file_close(in);
    }

  scamper_file_close(out);
  return 0;
}
