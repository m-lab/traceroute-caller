/*
 * sc_warts2pcap
 *
 * $Id: sc_warts2pcap.c,v 1.3 2015/04/29 04:40:01 mjl Exp $
 *
 * Copyright (C) 2010 Stephen Eichler
 * Copyright (C) 2011 University of Waikato
 * Authors: Stephen Eichler, Matthew Luckie
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
  "$Id";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_file.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "tbit/scamper_tbit.h"
#include "sting/scamper_sting.h"
#include "sniff/scamper_sniff.h"
#include "utils.h"
#include "mjl_list.h"

/*
 * pcap file header
 */
typedef struct phdr {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} phdr_t;

/*
 * pcap record
 */
typedef struct prec {
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
} prec_t;

typedef struct pkt
{
  uint8_t       *data;
  uint16_t       len;
  struct timeval tv;
} pkt_t;

typedef struct sort
{
  int (*init)(void);
  int (*foreach)(uint16_t type, void *data);
  int (*finish)(void);
} sort_t;

static scamper_file_filter_t *filter = NULL;
static char *outfile_name = NULL;
static FILE *outfile_fd = NULL;
static char **files = NULL;
static int filec = 0;
static int sorti = 0;

static int sort_0(uint16_t type, void *data);
static int init_1(void);
static int sort_1(uint16_t type, void *data);
static int finish_1(void);

static const sort_t sort[] = {
  {NULL,   sort_0, NULL},
  {init_1, sort_1, finish_1},
};

static void usage(void)
{
  fprintf(stderr,
	  "usage: sc_warts2pcap [-o outfile] [-s sorting] warts-files\n");
  return;
}

static int check_options(int argc, char *argv[])
{
  int ch;

  while((ch = getopt(argc, argv, "o:s:")) != -1)
    {
      switch(ch)
	{
	case 'o':
	  outfile_name = optarg;
	  break;

	case 's':
	  if(strcasecmp(optarg, "none") == 0)
	    sorti = 0;
	  else if(strcasecmp(optarg, "packet") == 0)
	    sorti = 1;
	  else
	    return -1;
	  break;
	}
    }

  if(outfile_name == NULL)
    {
      outfile_name = "-";
      usage();
      return -1;
    }

  files = argv + optind;
  filec = argc - optind;
  return 0;
}

static int pkt_write(uint8_t *data, uint16_t len, struct timeval *tv, void *p)
{
  prec_t rec;

  memset(&rec, 0, sizeof(rec));
  rec.ts_sec = tv->tv_sec;
  rec.ts_usec = tv->tv_usec;
  rec.incl_len = len;
  rec.orig_len = len;

  if(fwrite(&rec, sizeof(rec), 1, outfile_fd) != 1)
    return -1;
  if(fwrite(data, len, 1, outfile_fd) != 1)
    return -1;
  return 0;
}

static void pkt_free(pkt_t *pkt)
{
  if(pkt == NULL) return;
  if(pkt->data != NULL) free(pkt->data);
  free(pkt);
  return;
}

static int pkt_cmp(const pkt_t *a, const pkt_t *b)
{
  return timeval_cmp(&a->tv, &b->tv);
}

static int pkt_push(uint8_t *data, uint16_t len, struct timeval *tv, void *p)
{
  slist_t *list = p;
  pkt_t *pkt = NULL;

  if((pkt = malloc_zero(sizeof(pkt_t))) == NULL)
    goto err;
  if((pkt->data = memdup(data, len)) == NULL)
    goto err;
  pkt->len = len;
  timeval_cpy(&pkt->tv, tv);

  if(slist_tail_push(list, pkt) == NULL)
    goto err;

  return 0;

 err:
  pkt_free(pkt);
  return -1;
}

static int doit(uint16_t type, void *data,
		int (*func)(uint8_t *, uint16_t, struct timeval *, void *),
		void *param)
{
  scamper_tbit_t *tbit = NULL;
  scamper_tbit_pkt_t *tbit_pkt;
  scamper_sting_t *sting = NULL;
  scamper_sting_pkt_t *sting_pkt;
  scamper_sniff_t *sniff = NULL;
  scamper_sniff_pkt_t *sniff_pkt;
  uint32_t i;

  if(type == SCAMPER_FILE_OBJ_TBIT)
    {
      tbit = data;
      for(i=0; i<tbit->pktc; i++)
	{
	  tbit_pkt = tbit->pkts[i];
	  if(func(tbit_pkt->data, tbit_pkt->len, &tbit_pkt->tv, param) != 0)
	    goto err;
	}
      scamper_tbit_free(tbit);
    }
  else if(type == SCAMPER_FILE_OBJ_STING)
    {
      sting = data;
      for(i=0; i<sting->pktc; i++)
	{
	  sting_pkt = sting->pkts[i];
	  if(func(sting_pkt->data, sting_pkt->len, &sting_pkt->tv, param) != 0)
	    goto err;
	}
      scamper_sting_free(sting);
    }
  else if(type == SCAMPER_FILE_OBJ_SNIFF)
    {
      sniff = data;
      for(i=0; i<sniff->pktc; i++)
	{
	  sniff_pkt = sniff->pkts[i];
	  if(func(sniff_pkt->data, sniff_pkt->len, &sniff_pkt->tv, param) != 0)
	    goto err;
	}
      scamper_sniff_free(sniff);
    }
  else return -1;

  return 0;

 err:
  if(tbit != NULL) scamper_tbit_free(tbit);
  if(sting != NULL) scamper_sting_free(sting);
  if(sniff != NULL) scamper_sniff_free(sniff);
  return -1;
}

static int sort_0(uint16_t type, void *data)
{
  return doit(type, data, pkt_write, NULL);
}

static slist_t *list = NULL;

static int init_1(void)
{
  if((list = slist_alloc()) == NULL)
    return -1;
  return 0;
}

static int sort_1(uint16_t type, void *data)
{
  return doit(type, data, pkt_push, list);
}

static int finish_1(void)
{
  pkt_t *pkt;
  if(slist_qsort(list, (slist_cmp_t)pkt_cmp) != 0)
    return -1;
  while((pkt = slist_head_pop(list)) != NULL)
    {
      if(pkt_write(pkt->data, pkt->len, &pkt->tv, NULL) != 0)
	return -1;
      pkt_free(pkt);
    }
  slist_free(list);
  return 0;
}

static int do_file(scamper_file_t *in)
{
  uint16_t type;
  void *data;
  int rc;

  while((rc = scamper_file_read(in, filter, &type, &data)) == 0)
    {
      if(data == NULL)
	break;
      if(sort[sorti].foreach(type, data) != 0)
	goto err;
    }
  if(rc != 0)
    goto err;

  scamper_file_close(in);
  return 0;

 err:
  return -1;
}

int main(int argc, char *argv[])
{
  uint16_t filter_types[] = {
    SCAMPER_FILE_OBJ_TBIT,
    SCAMPER_FILE_OBJ_STING,
    SCAMPER_FILE_OBJ_SNIFF,
  };
  uint16_t filter_cnt = sizeof(filter_types)/sizeof(uint16_t);
  scamper_file_t *in;
  phdr_t hdr;
  int i;

  if(check_options(argc, argv) != 0)
    goto err;

  if((filter = scamper_file_filter_alloc(filter_types, filter_cnt)) == NULL)
    {
      fprintf(stderr, "could not allocate ffilter\n");
      goto err;
    }

  /* open the output file */
  if(strcasecmp(outfile_name, "-") != 0)
    {
      if((outfile_fd = fopen(outfile_name, "w")) == NULL)
	{
	  fprintf(stderr, "could not open for output: %s\n", outfile_name);
	  goto err;
	}
    }
  else
    {
      /* writing to stdout; don't dump a binary structure to a tty. */
      if(isatty(STDOUT_FILENO) != 0)
	{
	  fprintf(stderr, "not going to dump pcap to a tty, sorry\n");
	  return -1;
	}

      if((outfile_fd = fdopen(STDOUT_FILENO, "w")) == NULL)
	{
	  fprintf(stderr, "could not fdopen stdout\n");
	  goto err;
	}
    }

  /* write the pcap header */
  hdr.magic_number = 0xa1b2c3d4;
  hdr.version_major = 2;
  hdr.version_minor = 4;
  hdr.thiszone = 0;
  hdr.sigfigs = 0;
  hdr.snaplen = 65535;
  hdr.network = 12; /* DLT_RAW */
  if(fwrite(&hdr, sizeof(phdr_t), 1, outfile_fd) != 1)
    goto err;

  if(sort[sorti].init != NULL && sort[sorti].init() != 0)
    goto err;

  if(filec != 0)
    {
      for(i=0; i<filec; i++)
	{
	  if((in = scamper_file_open(files[i], 'r', NULL)) == NULL)
	    {
	      fprintf(stderr, "could not open %s\n", files[i]);
	      goto err;
	    }

	  if(do_file(in) != 0)
	    goto err;
	}
    }
  else
    {
      if((in = scamper_file_openfd(STDIN_FILENO, "-", 'r', "warts")) == NULL)
	{
	  fprintf(stderr, "could not open stdin for reading\n");
	  goto err;
	}

      if(do_file(in) != 0)
	goto err;
    }

  if(sort[sorti].finish != NULL && sort[sorti].finish() != 0)
    goto err;

  fclose(outfile_fd);
  outfile_fd = NULL;

  return 0;

 err:
  return -1;
}
