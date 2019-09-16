/*
 * sc_hoiho: Holistic Orthography of Internet Hostname Observations
 *
 * $Id: sc_hoiho.c,v 1.1 2019/09/16 04:09:14 mjl Exp $
 *
 *         Matthew Luckie
 *         mjl@luckie.org.nz
 *
 * Copyright (C) 2017-2019 The University of Waikato
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#ifdef HAVE_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#else
#include <pcre.h>
#endif

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#include "scamper/scamper_addr.h"
#include "mjl_threadpool.h"
#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "utils.h"

typedef struct sc_router sc_router_t;
typedef struct sc_routerinf sc_routerinf_t;
typedef struct sc_routerdom sc_routerdom_t;
typedef struct sc_regex sc_regex_t;
typedef struct sc_regex_fn sc_regex_fn_t;

typedef struct sc_css
{
  char           *css;     /* common substrings, each null terminated */
  int             cssc;    /* number of common substrings */
  size_t          len;     /* total length of the common substrings */
  int             count;   /* count variable for counting matches */
} sc_css_t;

typedef struct sc_domain
{
  char           *domain;  /* the domain */
  char           *escape;  /* escaped domain suffix */
  size_t          escapel; /* length of escaped suffix */
  slist_t        *routers; /* training routers with an iface in the domain */
  slist_t        *appl;    /* other interfaces we can't train from */
  slist_t        *regexes; /* set of regexes built */
  uint32_t        ifacec;  /* number of training interfaces in the domain */
  uint32_t        tpmlen;  /* how wide the tp_mask variable is */
  uint32_t        rtmlen;  /* how wide a mask for router tags should be */

#ifdef HAVE_PTHREAD
  pthread_mutex_t mutex;   /* lock the domain */
  uint8_t         mutex_o; /* mutex is initialised */
#endif
} sc_domain_t;

typedef struct sc_regexn
{
  /* these parameters are properties of the regex node */
  char           *str;     /* the regex */
  uint32_t        capc;    /* number of capture elements */

  /* these parameters are set during evaluation */
  uint32_t        matchc;  /* how many times this regex matched */
  uint32_t        rt_c;    /* number of routers this regex matched */
} sc_regexn_t;

struct sc_regex
{
  /* these parameters are properties of the regex set */
  sc_regexn_t   **regexes; /* the regexes */
  int             regexc;  /* number of regexes */
  int             score;   /* regex specificity score */
  sc_domain_t    *dom;     /* the domain this regex is for */

  /* these parameters are set during evaluation */
  uint32_t        matchc;  /* number of matches */
  uint32_t        namelen; /* lengths of names */
  uint32_t        tp_c;    /* true positives */
  uint32_t        fp_c;    /* false positives */
  uint32_t        fne_c;   /* false negatives, matched */
  uint32_t        fnu_c;   /* false negatives, not matched */
  uint32_t        ip_c;    /* matches including IP address string */
  uint32_t        sp_c;    /* true positives involving single iface routers */
  uint32_t        sn_c;    /* false negatives involving single iface routers */
  uint32_t        rt_c;    /* router count */
  uint32_t       *tp_mask; /* which interfaces in training set are TPs */
};

typedef struct sc_regex_css
{
  sc_regex_t     *regex;   /* a more specific regex with a literal component */
  sc_css_t       *css;     /* the literal that made it more specific */
  sc_regex_t     *work;    /* current working version */
} sc_regex_css_t;

typedef struct sc_iface
{
  char           *name;    /* hostname */
  size_t          len;     /* length of hostname */
  scamper_addr_t *addr;    /* corresponding IP address */
  sc_router_t    *rtr;     /* backpointer to router */
  int16_t         ip_s;    /* possible start of IP address */
  int16_t         ip_e;    /* possible end of IP address */
  uint8_t         ip_b;    /* which bytes of address are present */
} sc_iface_t;

struct sc_router
{
  sc_iface_t    **ifaces;  /* interfaces inferred to be part of the router */
  int             ifacec;  /* number of interfaces involved */
};

typedef struct sc_ifacedom
{
  char           *label;   /* label excluding domain suffix */
  size_t          len;     /* length of the label */
  sc_iface_t     *iface;   /* pointer to the interface */
  sc_routerdom_t *rd;      /* backpointer to the router */
  uint32_t        id;      /* unique ID for the interface in this domain */
} sc_ifacedom_t;

struct sc_routerdom
{
  sc_ifacedom_t **ifaces;  /* interfaces within domain */
  int             ifacec;  /* number of interfaces within domain */
  sc_router_t    *rtr;     /* complete router */
  sc_css_t       *css;     /* longest common substring within router */
  uint32_t        id;      /* unique ID for the router in this domain */
};

typedef struct sc_routername
{
  sc_routerdom_t *rd;      /* pointer to router */
  sc_css_t       *css;     /* inferred name, if there was one */
  int             matchc;  /* largest frequency */
} sc_routername_t;

typedef struct sc_ifaceinf
{
  sc_ifacedom_t  *ifd;     /* interface from training */
  sc_css_t       *css;     /* inferred name */
  sc_routerinf_t *ri;      /* pointer to inferred router */
  int             rtrc;    /* how many interfaces from training routers */
  int             regex;   /* regex id */
  char            class;   /* classification */
  uint8_t         ipm;     /* do we believe extraction contains IP literal */
} sc_ifaceinf_t;

struct sc_routerinf
{
  sc_ifaceinf_t **ifaces;  /* interfaces inferred to belong to the router */
  int             ifacec;  /* number of inferred interfaces */
  int             maxrtrc; /* max number of interfaces from a training rtr */
  int             ip;      /* name includes IP string */
};

struct sc_regex_fn
{
  sc_regex_t     *re;      /* regex that we might improve on */
  sc_regex_fn_t  *refn;    /* pointer to a related refn */
  sc_regex_t     *base;    /* the original regex */
  int             done;    /* whether or not we're done with this regex */
};

typedef struct sc_domain_fn
{
  slist_t        *work;    /* current working list of regexes */
  slist_t        *base;    /* base list of all regexes in sc_regex_fn_t */
  int             done;    /* whether or not we're done with this domain */
} sc_domain_fn_t;

typedef struct sc_ifdptr
{
  sc_ifacedom_t  *ifd;     /* interface */
  void           *ptr;     /* tag */
} sc_ifdptr_t;

typedef struct sc_ptrc
{
  void           *ptr;
  int             c;
} sc_ptrc_t;

typedef struct sc_charpos
{
  char            c[32];   /* the character for the nibble */
  int             pos[32]; /* the position of the character in the string */
  int             left;    /* the left-most digit in the string */
  int             right;   /* the right-most digit in the string */
  int             digits;  /* the number of digits in the string */
} sc_charpos_t;

typedef struct sc_charposl
{
  int            *pos;
  int             posc;
} sc_charposl_t;

typedef struct sc_rework
{
  int                c;          /* number of regexes in the set */
  int                k;          /* which regex matched */
  int                m;          /* number of elements in ovector */
#ifdef HAVE_PCRE2
  pcre2_code       **pcre;
  pcre2_match_data  *match_data;
  PCRE2_SIZE        *ovector;
#else
  pcre             **pcre;
  pcre_extra       **study;
  int               *ovector;
  int                n;          /* max elements in ovector */
#endif
} sc_rework_t;

typedef struct sc_suffix
{
  struct sc_suffix  *parent;
  char              *label;
  int                end;
  struct sc_suffix **suffixes;
  int                suffixc;
} sc_suffix_t;

/*
 * sc_lcs_pt
 *
 */
typedef struct sc_lcs_pt
{
  int S_start, S_end;
  int T_start, T_end;
} sc_lcs_pt_t;

typedef struct sc_rebuild
{
  char   buf[2048]; /* regex built so far */
  size_t off;       /* length of regex built so far */
  int    score;     /* specificity score so far */
  int    f;         /* which of the builder functions should run next */
  int    x;         /* where in the bits array we are up to */
  int    o;         /* where in the hostname string we are up to */
  int    any;       /* have we used .+ in this regex yet? */
  int    capc;      /* the number of capture elements so far */
} sc_rebuild_t;

/*
 * sc_rebuild_p
 *
 * parameters passed in to sc_regex_build that do not change
 */
typedef struct sc_rebuild_p
{
  sc_domain_t *dom;
  const int   *bits;
  int          bitc;
  char        *buf;
  size_t       len;
} sc_rebuild_p_t;

typedef struct sc_segscore
{
  char *seg;
  int   score;
} sc_segscore_t;

typedef struct sc_dump
{
  char  *descr;
  char  *label;
  int  (*func)(void);
} sc_dump_t;

static int dump_1(void);
static int dump_2(void);
static int dump_3(void);

typedef size_t (*sc_regex_build_t)(const char *,           /* name */
				   const sc_rebuild_p_t *, /* build params */
				   const sc_rebuild_t *,   /* build state */
				   int *,                  /* score */
				   int *);                 /* name offset */

static slist_t         *router_list  = NULL;
static char            *router_file  = NULL;
static char            *suffix_file  = NULL;
static sc_suffix_t     *suffix_root  = NULL;
static splaytree_t     *domain_tree  = NULL;
static slist_t         *domain_list  = NULL;
static char            *domain_eval  = NULL;
static const char      *regex_eval   = NULL;
static int              verbose      = 0;
static int              refine_sets  = 1;
static int              refine_ip    = 1;
static int              refine_fp    = 1;
static int              refine_fne   = 1;
static int              refine_fnu   = 1;
static int              refine_tp    = 1;
static int              refine_class = 1;
static int              thin_same    = 1;
static int              thin_matchc  = 1;
static int              thin_mask    = 1;
static int              do_ri        = 0;
static int              do_appl      = 0;
static int              do_jit       = 1;
static int              do_json      = 0;
static int              ip_v         = 4;
static long             threadc      = -1;
static threadpool_t    *tp           = NULL;
static long             dump_id      = 1;
static const sc_dump_t  dump_funcs[] = {
  {NULL, NULL, NULL},
  {"dump working set of regexes", "working-set", dump_1},
  {"apply best regex to routers", "routers", dump_2},
  {"dump best regex for each domain", "best-regex", dump_3},
};
static int              dump_funcc = sizeof(dump_funcs) / sizeof(sc_dump_t);

#define OPT_THREADC   0x0001
#define OPT_DUMPID    0x0002
#define OPT_DOMAIN    0x0004
#define OPT_REGEX     0x0008
#define OPT_OPTION    0x0010
#define OPT_IPV6      0x0020

static void usage(uint32_t opts)
{
  int i;

  fprintf(stderr,
	  "usage: sc_hoiho [-6] [-d dumpid] [-D domain] [-O options]\n"
	  "                [-r regex] [-t threadc]\n"
	  "                <public-suffix-list> <router-file>\n");

  if(opts == 0)
    {
      fprintf(stderr, "\n       sc_hoiho -?\n\n");
      return;
    }
  fprintf(stderr, "\n");

  if(opts & OPT_IPV6)
    fprintf(stderr, "       -6: input files are IPv6\n");
  if(opts & OPT_DUMPID)
    {
      fprintf(stderr, "       -d: dump id\n");
      for(i=1; i<dump_funcc; i++)
	{
	  fprintf(stderr, "           %d", i);
	  if(dump_funcs[i].label != NULL)
	    fprintf(stderr, " / %s", dump_funcs[i].label);
	  fprintf(stderr, ": %s\n", dump_funcs[i].descr);
	}
    }

  if(opts & OPT_DOMAIN)
    fprintf(stderr, "       -D: the domain suffix to operate on\n");

  if(opts & OPT_OPTION)
    {
      fprintf(stderr, "       -O: options\n");
      fprintf(stderr, "           application: show outcome of regexes\n");
      fprintf(stderr, "           json: output inferences in json format\n");
      fprintf(stderr, "           nojit: do not use PCRE JIT complication\n");
      fprintf(stderr, "           norefine: do not refine regexes\n");
      fprintf(stderr, "           norefine-tp: do not do TP refinement\n");
      fprintf(stderr, "           refine-tp: do TP refinement\n");
      fprintf(stderr, "           norefine-fne: do not do FNE refinement\n");
      fprintf(stderr, "           refine-fne: do FNE refinement\n");
      fprintf(stderr, "           norefine-class: do not do class refinement\n");
      fprintf(stderr, "           refine-class: do class refinement\n");
      fprintf(stderr, "           norefine-fnu: do not do FNU refinement\n");
      fprintf(stderr, "           refine-fnu: do FNU refinement\n");
      fprintf(stderr, "           norefine-sets: do not build sets\n");
      fprintf(stderr, "           refine-sets: build sets\n");
      fprintf(stderr, "           norefine-ip: do not build IP filters\n");
      fprintf(stderr, "           refine-ip: build IP filters\n");
      fprintf(stderr, "           norefine-fp: do not build FP filters\n");
      fprintf(stderr, "           refine-fp: build FP filters\n");
      fprintf(stderr, "           nothin: do not thin redundant regexes\n");
      fprintf(stderr, "           nothin-matchc: do not thin regexes with few matches\n");
      fprintf(stderr, "           thin-matchc: thin regexes with few matches\n");
      fprintf(stderr, "           nothin-same: do not thin equivalent regexes\n");
      fprintf(stderr, "           thin-same: thin equivalent regexes\n");
      fprintf(stderr, "           randindex: compute the Rand Index metric\n");
      fprintf(stderr, "           verbose: output debugging information\n");
    }

  if(opts & OPT_REGEX)
    fprintf(stderr, "       -r: the regex (or file of regexes) to apply\n");
  if(opts & OPT_THREADC)
    fprintf(stderr, "       -t: the number of threads to use\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  char *opts = "6d:D:O:r:t:?";
  char *opt_threadc = NULL, *opt_dumpid = NULL;
  struct stat sb;
  long lo;
  int ch, x;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case '6':
	  ip_v = 6;
	  break;

	case 'd':
	  opt_dumpid = optarg;
	  break;

	case 'D':
	  domain_eval = optarg;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "norefine") == 0)
	    {
	      refine_ip = 0;
	      refine_sets = 0;
	      refine_fp = 0;
	      refine_fne = 0;
	      refine_tp = 0;
	      refine_fnu = 0;
	      refine_class = 0;
	    }
	  else if(strcasecmp(optarg, "norefine-ip") == 0)
	    refine_ip = 0;
	  else if(strcasecmp(optarg, "refine-ip") == 0)
	    refine_ip = 1;
	  else if(strcasecmp(optarg, "norefine-sets") == 0)
	    refine_sets = 0;
	  else if(strcasecmp(optarg, "refine-sets") == 0)
	    refine_sets = 1;
	  else if(strcasecmp(optarg, "norefine-fp") == 0)
	    refine_fp = 0;
	  else if(strcasecmp(optarg, "refine-fp") == 0)
	    refine_fp = 1;
	  else if(strcasecmp(optarg, "norefine-fne") == 0)
	    refine_fne = 0;
	  else if(strcasecmp(optarg, "refine-fne") == 0)
	    refine_fne = 1;
	  else if(strcasecmp(optarg, "norefine-fnu") == 0)
	    refine_fnu = 0;
	  else if(strcasecmp(optarg, "refine-fnu") == 0)
	    refine_fnu = 1;
	  else if(strcasecmp(optarg, "norefine-tp") == 0)
	    refine_tp = 0;
	  else if(strcasecmp(optarg, "refine-tp") == 0)
	    refine_tp = 1;
	  else if(strcasecmp(optarg, "norefine-class") == 0)
	    refine_class = 0;
	  else if(strcasecmp(optarg, "refine-class") == 0)
	    refine_class = 1;
	  else if(strcasecmp(optarg, "nothin") == 0)
	    {
	      thin_matchc = 0;
	      thin_same = 0;
	      thin_mask = 0;
	    }
	  else if(strcasecmp(optarg, "thin-matchc") == 0)
	    thin_matchc = 1;
	  else if(strcasecmp(optarg, "nothin-matchc") == 0)
	    thin_matchc = 0;
	  else if(strcasecmp(optarg, "thin-same") == 0)
	    thin_same = 1;
	  else if(strcasecmp(optarg, "nothin-same") == 0)
	    thin_same = 0;
	  else if(strcasecmp(optarg, "thin-mask") == 0)
	    thin_mask = 1;
	  else if(strcasecmp(optarg, "nothin-mask") == 0)
	    thin_mask = 0;
	  else if(strcasecmp(optarg, "randindex") == 0)
	    do_ri = 1;
	  else if(strcasecmp(optarg, "application") == 0)
	    do_appl = 1;
	  else if(strcasecmp(optarg, "verbose") == 0)
	    verbose = 1;
	  else if(strcasecmp(optarg, "nojit") == 0)
	    do_jit = 0;
	  else if(strcasecmp(optarg, "json") == 0)
	    do_json = 1;
	  else
	    {
	      usage(0);
	      return -1;
	    }
	  break;

	case 'r':
	  regex_eval = optarg;
	  break;

	case 't':
	  opt_threadc = optarg;
	  break;

	case '?':
	  usage(0xffffffff);
	  return -1;

	default:
	  usage(0);
	  return -1;
	}
    }

  if(argc - optind != 2)
    {
      usage(0);
      return -1;
    }

  /*
   * -r can be either a single regex, or a file.  if its a single
   * regex, the domain involved must be specified.
   */
  if(regex_eval != NULL && stat(regex_eval, &sb) != 0 && domain_eval == NULL)
    {
      usage(OPT_REGEX|OPT_DOMAIN);
      return -1;
    }

  if(opt_dumpid != NULL)
    {
      if(string_isnumber(opt_dumpid) != 0)
	{
	  if(string_tolong(opt_dumpid, &lo) != 0 || lo < 1 || lo >= dump_funcc)
	    {
	      usage(OPT_DUMPID);
	      return -1;
	    }
	  dump_id = lo;
	}
      else
	{
	  for(x=1; x<dump_funcc; x++)
	    {
	      if(dump_funcs[x].label == NULL)
		continue;
	      if(strcasecmp(dump_funcs[x].label, opt_dumpid) == 0)
		break;
	    }
	  if(x == dump_funcc)
	    {
	      usage(OPT_DUMPID);
	      return -1;
	    }
	  dump_id = x;
	}
    }

  if(opt_threadc != NULL)
    {
      if(string_tolong(opt_threadc, &lo) != 0 || lo < 0)
	{
	  usage(OPT_THREADC);
	  return -1;
	}
#ifndef HAVE_PTHREAD
      if(lo > 1)
	{
	  usage(OPT_THREADC);
	  return -1;
	}
#endif
      threadc = lo;
    }

  suffix_file = argv[optind + 0];
  router_file = argv[optind + 1];
  return 0;
}

static int string_isdigit(const char *str)
{
  if(*str == '\0')
    return 0;
  while(isdigit(*str) != 0)
    str++;
  if(*str == '\0')
    return 1;
  return 0;
}

static int ptrcmp(const void *a, const void *b)
{
  if(a < b) return -1;
  if(a > b) return  1;
  return 0;
}

static int slist_to_dlist(void *entry, void *ptr)
{
  if(dlist_tail_push((dlist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

static int dlist_to_slist(void *entry, void *ptr)
{
  if(slist_tail_push((slist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

static int tree_to_slist(void *ptr, void *entry)
{
  if(slist_tail_push((slist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

static int tree_to_dlist(void *ptr, void *entry)
{
  if(dlist_tail_push((dlist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

static void json_print(const char *str)
{
  while(*str != '\0')
    {
      if(*str == '\\')
	printf("\\\\");
      else
	printf("%c", *str);
      str++;
    }
  return;
}

static int sc_ptrc_ptr_cmp(const sc_ptrc_t *a, const sc_ptrc_t *b)
{
  if(a->ptr < b->ptr) return -1;
  if(a->ptr > b->ptr) return  1;
  return 0;
}

static sc_ptrc_t *sc_ptrc_find(splaytree_t *tree, void *ptr)
{
  sc_ptrc_t fm; fm.ptr = ptr;
  return splaytree_find(tree, &fm);
}

static void sc_ptrc_free2(sc_ptrc_t *ptrc)
{
  if(ptrc != NULL)
    {
      if(ptrc->ptr != NULL) free(ptrc->ptr);
      free(ptrc);
    }
  return;
}

static void sc_ptrc_free(sc_ptrc_t *ptrc)
{
  free(ptrc);
  return;
}

static sc_ptrc_t *sc_ptrc_get(splaytree_t *tree, void *ptr)
{
  sc_ptrc_t *ptrc;
  if((ptrc = sc_ptrc_find(tree, ptr)) != NULL)
    return ptrc;
  if((ptrc = malloc(sizeof(sc_ptrc_t))) == NULL)
    goto err;
  ptrc->ptr = ptr;
  ptrc->c = 0;
  if(splaytree_insert(tree, ptrc) == NULL)
    goto err;
  return ptrc;

 err:
  if(ptrc != NULL) free(ptrc);
  return NULL;
}

static int char_within(const char *name, int l, int r, char c)
{
  int i;
  for(i=l; i<=r; i++)
    if(name[i] == c)
      return 1;
  return 0;
}

static int dotcount(const char *ptr)
{
  int c = 0;
  while(*ptr != '\0')
    {
      if(*ptr == '.')
	c++;
      ptr++;
    }
  return c;
}

/*
 * re_escape
 *
 * return an escaped character in the buffer.  return zero if there is
 * not enough space, otherwise return the number of characters for the
 * sequence, excluding the null termination.
 */
static size_t re_escape(char *buf, size_t len, char c)
{
  if(c == '.' || c == '{' || c == '}' || c == '(' || c == ')' ||
     c == '^' || c == '$' || c == '|' || c == '?' || c == '*' ||
     c == '+' || c == '[' || c == ']')
    {
      if(len < 3)
	return 0;
      buf[0] = '\\';
      buf[1] = c;
      buf[2] = '\0';
      return 2;
    }
  else if(c == '\\')
    {
      if(len < 3)
	return 0;
      buf[0] = buf[1] = '\\';
      buf[2] = '\0';
      return 2;
    }

  if(len < 2)
    return -1;
  buf[0] = c;
  buf[1] = '\0';
  return 1;
}

static char *re_escape_str(char *buf, size_t len, char *in)
{
  size_t r, off = 0;
  char tmp[4];

  while(*in != '\0')
    {
      if((r = re_escape(tmp, sizeof(tmp), *in)) == 0)
	return NULL;
      /* string_concat(buf, len, &off, "%s", tmp); */
      if(len - off < r + 1)
	return NULL;
      memcpy(buf+off, tmp, r + 1); off += r;
      in++;
    }

  return buf;
}

static int hex_toascii(char *buf, size_t len, const char *str)
{
  size_t off = 0;
  size_t x = 0;
  int c;

  while(str[x] != '\0')
    {
      if(str[x] == '\\' && str[x+1] == 'x')
	{
	  if(str[x+2] >= '0' && str[x+2] <= '9')
	    c = (str[x+2] - '0') * 16;
	  else
	    c = (str[x+2] - 'a' + 10) * 16;
	  if(str[x+3] >= '0' && str[x+3] <= '9')
	    c += (str[x+3] - '0');
	  else
	    c += (str[x+3] - 'a' + 10);
	  if(isprint(c) && c != ' ')
	    {
	      buf[off++] = c;
	      x += 4;
	    }
	  else
	    {
	      buf[0] = '\0';
	      return 0;
	    }
	}
      else buf[off++] = str[x++];
    }

  buf[off] = '\0';
  return 0;
}

static int overlap(int a, int b, int x, int y)
{
  if((a < x && y < b) || (a < x && b > x && b < y) ||
     (x < a && y > a && y < b) || (a >= x && y >= b))
    return 1;
  return 0;
}

static int pt_to_bits_trip(slist_t *list, int m, int x, int y)
{
  int *trip = NULL;

  assert(x <= y);

  if((trip = malloc(sizeof(int) * 3)) == NULL ||
     slist_tail_push(list, trip) == NULL)
    goto err;
  trip[0] = m;
  trip[1] = x;
  trip[2] = y;
  return 0;

 err:
  if(trip != NULL) free(trip);
  return -1;
}

/*
 * pt_to_bits_lit
 *
 * plan out the matches and literals given the input constraints.
 */
static int pt_to_bits_lit(const char *s, int *l, int lc, int **out, int *bitc)
{
  slist_t *list = NULL;
  int *trip, *bits = NULL;
  int i, j, k;
  int rc = -1;

  if((list = slist_alloc()) == NULL)
    goto done;

  /* if the first literal doesn't begin at the start of the string */
  if(l[0] != 0)
    {
      /* calculate boundaries of skip */
      k = l[0]-1;
      while(isalnum(s[k]) == 0 && k > 0)
	k--;
      if(pt_to_bits_trip(list, 0, 0, k) != 0)
	goto done;
    }

  for(i=0; i<lc; i+=2)
    {
      /* literal portion */
      if(pt_to_bits_trip(list, 2, l[i], l[i+1]) != 0)
	goto done;

      /* open the next skip portion */
      j = l[i+1]+1;
      while(s[j] != '\0' && isalnum(s[j]) == 0)
	j++;

      /* skip portion */
      if(s[j] != '\0' && (i+2 == lc || l[i+2] != j))
	{
	  if(i+2 < lc)
	    {
	      if(l[i+1] + 1 == l[i+2])
		goto done;
	      k = l[i+2]-1;
	      while(isalnum(s[k]) == 0 && k > l[i+1])
		k--;
	    }
	  else
	    {
	      k = j;
	      while(s[k+1] != '\0')
		k++;
	    }

	  if(pt_to_bits_trip(list, 0, j, k) != 0)
	    goto done;
	}
    }

  if((bits = malloc(slist_count(list) * sizeof(int) * 3)) == NULL)
    goto done;
  i = 0;
  while((trip = slist_head_pop(list)) != NULL)
    {
      bits[i++] = trip[0];
      bits[i++] = trip[1];
      bits[i++] = trip[2];
      free(trip);
    }

  *out = bits; bits = NULL;
  *bitc = i;
  rc = 0;

 done:
  if(bits != NULL) free(bits);
  if(list != NULL) slist_free_cb(list, free);
  return rc;
}

/*
 * pt_to_bits_ip:
 *
 * plan out the matches and literals given the input constraints.
 */
static int pt_to_bits_ip(const sc_ifacedom_t *ifd, int *l, int lc,
			 int **out, int *bitc)
{
  slist_t *list = NULL;
  int i, j, k, x;
  int ip_s = ifd->iface->ip_s;
  int ip_e = ifd->iface->ip_e;
  int *trip, *bits = NULL;
  int rc = -1;

  if((list = slist_alloc()) == NULL)
    goto done;

  j = 0;

  /* the first match doesn't begin at the start of the string */
  if(ip_s != 0 && lc != 0 && l[0] != 0)
    {
      k = (ip_s < l[0] ? ip_s : l[0]);
      if(pt_to_bits_trip(list, 0, 0, k-1) != 0)
	goto done;
      j = k;
    }

  while(j < ifd->len)
    {
      /* IP match */
      if(j == ip_s)
	{
	  if(pt_to_bits_trip(list, 4, ip_s, ip_e) != 0)
	    goto done;
	  j = ip_e + 1;
	  continue;
	}

      /* is there a literal match starting here? */
      for(i=0; i<lc; i+=2)
	if(j == l[i])
	  break;
      if(i != lc)
	{
	  if(pt_to_bits_trip(list, 2, l[i], l[i+1]) != 0)
	    goto done;
	  j = l[i+1] + 1;
	  continue;
	}

      /* figure out the start of the next literal */
      for(i=0; i<lc; i+=2)
	if(j < l[i])
	  break;
      if(i != lc)
	{
	  if(l[i] < ip_s)
	    k = ip_s - 1;
	  else
	    k = l[i] - 1;
	}
      else if(j < ip_s)
	k = ip_s - 1;
      else
	k = ifd->len - 1;

      /* skip over punctuation */
      while(isalnum(ifd->label[j]) == 0 && j < k)
	j++;
      x = k;
      while(isalnum(ifd->label[x]) == 0 && x >= j)
	x--;
      if(x >= j && pt_to_bits_trip(list, 0, j, x) != 0)
	goto done;
      j = k + 1;
    }

  if((bits = malloc(slist_count(list) * sizeof(int) * 3)) == NULL)
    goto done;
  x = 0;
  while((trip = slist_head_pop(list)) != NULL)
    {
      bits[x++] = trip[0];
      bits[x++] = trip[1];
      bits[x++] = trip[2];
      free(trip);
    }

  if(verbose != 0 && threadc == 1)
    {
      printf("%s %d | %d %d", ifd->label, (int)ifd->len, ip_s, ip_e);
      if(lc > 0)
	{
	  printf(" |");
	  for(i=0; i<lc; i++)
	    printf(" %d", l[i]);
	}
      printf(" |");
      for(i=0; i<x; i++)
	printf(" %d", bits[i]);
      printf("\n");
    }

  *out = bits; bits = NULL;
  *bitc = x;
  rc = 0;

 done:
  if(bits != NULL) free(bits);
  if(list != NULL) slist_free_cb(list, free);
  return rc;
}

static void pt_merge(int *LA, int *L, int Lc, int *LX, int LXc)
{
  int a = 0, l = 0, x = 0;

  while(l < Lc || x < LXc)
    {
      if(l < Lc && x < LXc)
	{
	  if(L[2*l] < LX[2*x])
	    {
	      LA[a++] = L[2*l];
	      LA[a++] = L[(2*l)+1];
	      l++;
	    }
	  else
	    {
	      LA[a++] = LX[2*x];
	      LA[a++] = LX[(2*x)+1];
	      x++;
	    }
	}
      else if(l < Lc)
	{
	  LA[a++] = L[2*l];
	  LA[a++] = L[(2*l)+1];
	  l++;
	}
      else
	{
	  LA[a++] = LX[2*x];
	  LA[a++] = LX[(2*x)+1];
	  x++;
	}
    }

  return;
}

static int pt_overlap(int *X, int Xc, int *L, int Lc)
{
  int x, l;

  for(x=0; x<Xc-1; x++)
    assert(X[x+1] >= X[x]);
  for(l=0; l<Lc-1; l++)
    assert(L[l+1] >= L[l]);

  for(x=0; x<Xc; x+=2)
    {
      for(l=0; l<Lc; l+=2)
	{
	  /* X 13 25, L 25 25: L contained within X */
	  if(X[x] <= L[l] && L[l+1] <= X[x+1])
	    return 1;

	  /* X 13 25, L 12 25: X contained within L */
	  if(X[x] >= L[l] && L[l+1] >= X[x+1])
	    return 1;

	  /*
	   * right of X overlaps with left of L
	   * X 12 13, L 13 14
	   * X 12 14, L 13 15
	   */
	  if(X[x] < L[l] && X[x+1] >= L[l]) /* && X[x+1] <= L[l+1])*/
	    return 1;

	  /*
	   * left of X overlaps with right of L
	   * L 12 13, X 13 14
	   * L 12 14, X 13 15
	   */
	  if(L[l] < X[x] && L[l+1] >= X[x]) /* && L[l+1] <= X[x+1]) */
	    return 1;
	}
    }

  return 0;
}

/*
 * pt_to_bits:
 *
 * plan out the matches, captures, and literals given the input
 * constraints.
 *
 * the approach makes two passes: figuring out where the capture and
 * skip boundaries are in phase 1, and then refining those based on
 * literal match restrictions
 *
 * c:    input capture tuples.  each tuple consists of where the match
 *       begins, and where the match ends.
 *
 * l:    input literal tuples.  each tuple consists of where the literal
 *       begins, and where the literal ends.
 *
 * bits: output triples.  the first value in the triple specifies the mode,
 *       and the next values specify the scope (beginning and end).
 *       mode 0: skip
 *       mode 1: capture.
 *       mode 2: skip, literal.
 *       mode 3: capture, literal.
 *
 */
static int pt_to_bits(const char *s, int *c, int cc, int *l, int lc,
		      int **out, int *bitc)
{
  slist_t *list = NULL, *list2 = NULL;
  int i, j, k, x, *trip, *bits = NULL, rc = -1;

  if((list = slist_alloc()) == NULL || (list2 = slist_alloc()) == NULL)
    goto done;

  /* if the first capture doesn't begin at the start of the string */
  if(c[0] != 0)
    {
      /* calculate boundaries of skip */
      k = c[0]-1;
      while(isalnum(s[k]) == 0 && k > 0)
	k--;
      if(pt_to_bits_trip(list, 0, 0, k) != 0)
	goto done;
    }

  for(i=0; i<cc; i+=2)
    {
      /* capture portion */
      if(pt_to_bits_trip(list, 1, c[i+0], c[i+1]) != 0)
	goto done;

      /* open the next skip portion, skipping over dashes and dots */
      j = c[i+1]+1;
      while(s[j] != '\0' && isalnum(s[j]) == 0)
	j++;

      /* skip portion */
      if(s[j] != '\0' && (i+2==cc || c[i+2] != j))
	{
	  if(i+2<cc)
	    {
	      k = c[i+2]-1;
	      while(isalnum(s[k]) == 0 && k > c[i+1])
		k--;
	    }
	  else
	    {
	      k = c[i+1];
	      while(s[k+1] != '\0')
		k++;
	    }

	  if(pt_to_bits_trip(list, 0, j, k) != 0)
	    goto done;
	}
    }

  /* make the second pass that takes account of literal matches (if any) */
  while((trip = slist_head_pop(list)) != NULL)
    {
      /* find a literal, if one exists, that impacts the matching */
      for(i=0; i<lc; i+=2)
	if(overlap(l[i+0], l[i+1], trip[1], trip[2]) != 0)
	  break;

      /* there is no literal that impacts this match */
      if(i == lc)
	{
	  /* push what we have without modification and move on */
	  if(slist_tail_push(list2, trip) == NULL)
	    goto done;
	  continue;
	}

      /* the literal covers the whole match */
      if(l[i+0] <= trip[1] && l[i+1] >= trip[2])
	{
	  /* turn this into a literal version and move on */
	  trip[0] += 2;
	  if(slist_tail_push(list2, trip) == NULL)
	    goto done;
	  continue;
	}

      /* if this literal begins in the middle of this segment */
      if(l[i+0] > trip[1])
	{
	  k = l[i+0]-1;
	  while(isalnum(s[k]) == 0 && k > trip[1])
	    k--;
	  if(pt_to_bits_trip(list2, trip[0], trip[1], k) != 0)
	    goto done;
	}

      while(i < lc)
	{
	  /* get the right edge of the new literal trip */
	  k = l[i+1] <= trip[2] ? l[i+1] : trip[2];
	  if(pt_to_bits_trip(list2, trip[0]+2, l[i+0], k) != 0)
	    goto done;
	  if(l[i+1] == trip[2])
	    break;

	  /* get the right edge of the next non-literal trip */
	  if(i+2 < lc && overlap(l[i+2], l[i+3], trip[1], trip[2]) != 0)
	    {
	      k = l[i+2]-1;
	      while(isalnum(s[k]) == 0)
		k--;
	    }
	  else k = trip[2];

	  j = l[i+1]+1;
	  while(isalnum(s[j]) == 0 && j < k)
	    j++;

	  /* non-literal trip */
	  if(j <= k && pt_to_bits_trip(list2, trip[0], j, k) != 0)
	    goto done;
	  if(k == trip[2])
	    break;

	  i += 2;
	}

      free(trip);
    }

  if((bits = malloc(slist_count(list2) * sizeof(int) * 3)) == NULL)
    goto done;
  x = 0;
  while((trip = slist_head_pop(list2)) != NULL)
    {
      bits[x++] = trip[0];
      bits[x++] = trip[1];
      bits[x++] = trip[2];
      free(trip);
    }

  if(verbose != 0 && threadc == 1)
    {
      printf("%s |", s);
      for(i=0; i<cc; i++)
	printf(" %d", c[i]);
      if(lc > 0)
	{
	  printf(" |");
	  for(i=0; i<lc; i++)
	    printf(" %d", l[i]);
	}
      printf(" |");
      for(i=0; i<x; i++)
	printf(" %d", bits[i]);
      printf("\n");
    }

  *out = bits; bits = NULL;
  *bitc = x;
  rc = 0;

 done:
  if(list != NULL) slist_free_cb(list, free);
  if(list2 != NULL) slist_free_cb(list2, free);
  if(bits != NULL) free(bits);
  return rc;
}

/*
 * pt_to_bits_noip
 *
 * the capture portion is known to overlap with an IP address literal.
 * adjust the capture so it doesn't.
 */
static int pt_to_bits_noip(const sc_ifacedom_t *ifd,
			   int *c, int cc, int **out, int *bitc)
{
  int ip_s = ifd->iface->ip_s;
  int ip_e = ifd->iface->ip_e;
  int *d = NULL;
  int dc = 0;
  int i, x;

  /*
   * we might need more space in the output incase the ip_s and ip_e
   * fall within a capture portion
   */
  if((d = malloc(sizeof(int) * (cc + 2))) == NULL)
    return -1;

  for(i=0; i<cc; i+=2)
    {
      /*
       * if the capture portion is entirely contained within the
       * apparent IP address literal, then skip it
       */
      if(ip_s <= c[i] && c[i+1] <= ip_e)
	continue;

      /*
       * if there is no overlap at all, then copy the capture portion
       * across
       */
      if(ip_s > c[i+1] || ip_e < c[i])
	{
	  assert(dc < cc + 2);
	  d[dc++] = c[i];
	  d[dc++] = c[i+1];
	  continue;
	}

      if(ip_s > c[i])
	{
	  x = ip_s-1;
	  while(isalpha(ifd->label[x]) == 0 && x > c[i])
	    x--;
	  assert(dc < cc + 2);
	  d[dc++] = c[i];
	  d[dc++] = x;
	}

      if(ip_e < c[i+1])
	{
	  x = ip_e+1;
	  while(isalpha(ifd->label[x]) == 0 && x < c[i+1])
	    x++;
	  assert(dc < cc + 2);
	  d[dc++] = x;
	  d[dc++] = c[i+1];
	}
    }

  if(dc == 0)
    {
      free(d);
      *out = NULL;
      *bitc = 0;
      return 0;
    }

  x = pt_to_bits(ifd->label, d, dc, NULL, 0, out, bitc);
  free(d);
  return x;
}

static sc_lcs_pt_t *sc_lcs_pt_alloc(int S_s, int S_e, int T_s, int T_e)
{
  sc_lcs_pt_t *pt = NULL;
  if((pt = malloc(sizeof(sc_lcs_pt_t))) == NULL)
    goto err;
  pt->S_start = S_s;
  pt->S_end = S_e;
  pt->T_start = T_s;
  pt->T_end = T_e;
  return pt;
 err:
  if(pt != NULL) free(pt);
  return NULL;
}

static void sc_lcs_pt_free(sc_lcs_pt_t *pt)
{
  free(pt);
  return;
}

static int sc_lcs_pt_cmp(const sc_lcs_pt_t *a, const sc_lcs_pt_t *b)
{
  if(a->S_start < b->S_start) return -1;
  if(a->S_start > b->S_start) return  1;
  return 0;
}

static int sc_lcs_pt_push(slist_t *X, int S_s, int S_e, int T_s, int T_e)
{
  sc_lcs_pt_t *pt = NULL;
  if((pt = sc_lcs_pt_alloc(S_s, S_e, T_s, T_e)) == NULL ||
     slist_tail_push(X, pt) == NULL)
    goto err;
  return 0;
 err:
  if(pt != NULL) free(pt);
  return -1;
}

static int lcs_check(slist_t *X)
{
  sc_lcs_pt_t *last = NULL, *pt;
  slist_node_t *sn;

  for(sn=slist_head_node(X); sn != NULL; sn=slist_node_next(sn))
    {
      pt = slist_node_item(sn);
      if(last != NULL && pt->T_start < last->T_start)
	return 0;
      last = pt;
    }

  return 1;
}

#if 0
static void lcs_print(const char *S, const char *T, slist_t *X)
{
  slist_node_t *sn;
  sc_lcs_pt_t *pt;
  char buf[512];
  int x = 0;

  printf("%s %s ", S, T);
  for(sn = slist_head_node(X); sn != NULL; sn = slist_node_next(sn))
    {
      if(x != 0)
	printf("|");
      pt = slist_node_item(sn);
      memcpy(buf, &S[pt->S_start], pt->S_end - pt->S_start + 1);
      buf[pt->S_end - pt->S_start + 1] = '\0';
      printf("%s", buf);
      x++;
    }

  for(sn = slist_head_node(X); sn != NULL; sn = slist_node_next(sn))
    {
      pt = slist_node_item(sn);
      printf(" %d,%d", pt->S_start, pt->S_end);
    }
  printf(" :");
  for(sn = slist_head_node(X); sn != NULL; sn = slist_node_next(sn))
    {
      pt = slist_node_item(sn);
      printf(" %d,%d", pt->T_start, pt->T_end);
    }
  printf("\n");
  return;
}
#endif

static int idx(int S_len, int T_len, int S_i, int T_i)
{
  assert(S_i >= 0); assert(S_i < S_len);
  assert(T_i >= 0); assert(T_i < T_len);
  return ((S_i * T_len) + T_i);
}

static int char_class(char c)
{
  if(isalpha(c))
    return 0;
  else if(isdigit(c))
    return 1;
  return 2;
}

static int lcs_trim_class(slist_t *X, const char *S, const char *T)
{
  slist_t *Y = NULL;
  sc_lcs_pt_t *pt;
  int class;

  if((Y = slist_alloc()) == NULL)
    return -1;
  while((pt = slist_head_pop(X)) != NULL)
    {
      /* shift start offset */
      class = char_class(S[pt->S_start]);
      while(pt->S_start != pt->S_end && pt->T_start != pt->T_end)
	{
	  if((pt->S_start > 0 && char_class(S[pt->S_start-1]) == class) ||
	     (pt->T_start > 0 && char_class(T[pt->T_start-1]) == class))
	    {
	      pt->S_start++;
	      pt->T_start++;
	    }
	  else break;
	}

      /*
       * if the class we ended on is non-alphanum, then continue
       * shifting
       */
      if(isalnum(S[pt->S_start]) == 0)
	{
	  while(pt->S_start != pt->S_end && pt->T_start != pt->T_end)
	    {
	      if(isalnum(S[pt->S_start]) == 0)
		{
		  pt->S_start++;
		  pt->T_start++;
		}
	      else break;
	    }
	}

      /* shift end offset */
      if(S[pt->S_end+1] != '\0' && T[pt->T_end+1] != '\0')
	{
	  class = char_class(S[pt->S_end+1]);
	  while(pt->S_start != pt->S_end && pt->T_start != pt->T_end)
	    {
	      if(char_class(S[pt->S_end]) == class ||
		 char_class(T[pt->T_end]) == class)
		{
		  pt->S_end--;
		  pt->T_end--;
		}
	      else break;
	    }
	}

      /*
       * if the class we ended on is non-alphanum, then continue
       * shifting
       */
      if(isalnum(S[pt->S_end]) == 0)
	{
	  while(pt->S_start != pt->S_end && pt->T_start != pt->T_end)
	    {
	      if(isalnum(S[pt->S_end]) == 0)
		{
		  pt->S_end--;
		  pt->T_end--;
		}
	      else break;
	    }
	}

      if(isalnum(S[pt->S_start]) != 0 &&
	 (pt->S_start == 0 ||
	  char_class(S[pt->S_start-1]) != char_class(S[pt->S_start])) &&
	 (pt->T_start == 0 ||
	  char_class(T[pt->T_start-1]) != char_class(T[pt->T_start])) &&
	 (S[pt->S_end+1] == '\0' ||
	  char_class(S[pt->S_end]) != char_class(S[pt->S_end+1])) &&
	 (T[pt->T_end+1] == '\0' ||
	  char_class(T[pt->T_end]) != char_class(T[pt->T_end+1])))
	{
	  if(slist_tail_push(Y, pt) == NULL)
	    goto err;
	}
      else
	{
	  sc_lcs_pt_free(pt);
	}
    }
  slist_concat(X, Y);
  slist_free(Y);
  return 0;

 err:
  if(Y != NULL) slist_free_cb(Y, (slist_free_t)sc_lcs_pt_free);
  return -1;
}

static int lcs_trim(slist_t *X, const char *S, const char *T)
{
  slist_t *Y = NULL;
  sc_lcs_pt_t *pt;

  if((Y = slist_alloc()) == NULL)
    return -1;
  while((pt = slist_head_pop(X)) != NULL)
    {
      /* shift start offset */
      while(pt->S_start != pt->S_end && pt->T_start != pt->T_end)
	{
	  if((pt->S_start > 0 && isalnum(S[pt->S_start-1]) != 0) ||
	     (pt->T_start > 0 && isalnum(T[pt->T_start-1]) != 0) ||
	     isalnum(S[pt->S_start]) == 0)
	    {
	      pt->S_start++;
	      pt->T_start++;
	    }
	  else break;
	}

      /* shift end offset */
      if(S[pt->S_end+1] != '\0' && T[pt->T_end+1] != '\0')
	{
	  while(pt->S_start != pt->S_end && pt->T_start != pt->T_end)
	    {
	      if(isalnum(S[pt->S_end+1]) != 0 ||
		 isalnum(T[pt->T_end+1]) != 0 ||
		 isalnum(S[pt->S_end]) == 0)
		{
		  pt->S_end--;
		  pt->T_end--;
		}
	      else break;
	    }
	}

      if((pt->S_start == 0 || isalnum(S[pt->S_start-1]) == 0) &&
	 (pt->T_start == 0 || isalnum(T[pt->T_start-1]) == 0) &&
	 isalnum(S[pt->S_end+1]) == 0 &&
	 isalnum(T[pt->T_end+1]) == 0)
	{
	  if(slist_tail_push(Y, pt) == NULL)
	    goto err;
	}
      else
	{
	  sc_lcs_pt_free(pt);
	}
    }
  slist_concat(X, Y);
  slist_free(Y);
  return 0;

 err:
  if(Y != NULL) slist_free_cb(Y, (slist_free_t)sc_lcs_pt_free);
  return -1;
}

/*
 * lcs
 *
 * longest common substring, based off wikipedia's description of the
 * dynamic programming solution.
 */
static slist_t *lcs(const char *S, int r, const char *T, int n, int min_z)
{
  slist_t *bits = NULL;
  slist_t *X = NULL;
  sc_lcs_pt_t *pt;
  int *L = NULL;
  int x, z;
  int i, j, rc = -1;

  assert(min_z > 0);

  if(r == 0) r = strlen(S);
  if(n == 0) n = strlen(T);

  if((X = slist_alloc()) == NULL ||
     (bits = slist_alloc()) == NULL ||
     (L = malloc(sizeof(int) * (r * n))) == NULL)
    goto done;

  x = 0;
  for(i=0; i<r; i++)
    {
      for(j=0; j<n; j++)
	{
	  if(S[i] == '\0' || T[j] == '\0')
	    {
	      L[x] = 0;
	    }
	  else if(S[i] == T[j])
	    {
	      if(i == 0 || j == 0)
		L[x] = 1;
	      else
		L[x] = L[x-n-1] + 1; /* L[x] = L[((i-1) * n) + (j-1)] + 1; */
	    }
	  else
	    {
	      L[x] = 0;
	    }
	  x++; /* x = (i * n) + j; */
	}
    }

#if 0
  for(i=1; i<r; i++)
    for(j=1; j<n; j++)
      if(L[(i * n) + j] != 0 && L[(i * n) + j] - 1 != L[((i-1) * n) + (j-1)])
	printf(" ***");
  printf("\n");
  printf("%s %s\n", S, T);
  printf("  |");
  for(i=0; i<n; i++)
    printf(" %2c", T[i] != '\0' ? T[i] : ' ');
  printf("\n");
  for(i=0; i<r; i++)
    {
      printf("%c |", S[i] != '\0' ? S[i] : ' ');
      for(j=0; j<n; j++)
	{
	  printf(" %2d", L[(i * n) + j]);
	}
      printf("\n");
    }
#endif

  for(;;)
    {
      x = 0; z = 0;
      for(i=0; i<r; i++)
	{
	  for(j=0; j<n; j++)
	    {
	      if(L[x] > z)
		{
		  z = L[x];
		  slist_empty_cb(bits, (slist_free_t)sc_lcs_pt_free);
		  sc_lcs_pt_push(bits, i-L[x]+1, i, j-L[x]+1, j);
		}
	      else if(L[x] == z && z > 0)
		{
		  sc_lcs_pt_push(bits, i-L[x], i, j-L[x], j);
		}
	      x++;
	    }
	}

      if(z < min_z)
	break;

      pt = slist_head_pop(bits);
      slist_empty_cb(bits, (slist_free_t)sc_lcs_pt_free);
      slist_tail_push(X, pt);

      for(i=pt->S_start; i<pt->S_end; i++)
	{
	  for(j=0; j<n; j++)
	    L[(i * n) + j] = 0;
	}
      for(j=0; j<n; j++)
	{
	  if((z = L[idx(r,n,pt->S_end,j)]) == 0)
	    continue;
	  for(i=0;j+i<n&&(pt->S_end+i)<r && L[idx(r,n,pt->S_end+i,j+i)]>0;i++)
	    L[((pt->S_end + i) * n) + (j + i)] -= z;
	}

      for(j=pt->T_start; j<pt->T_end; j++)
	{
	  for(i=0; i<r; i++)
	    L[(i * n) + j] = 0;
	}
      for(i=0; i<r; i++)
	{
	  if((z = L[idx(r,n,i,pt->T_end)]) == 0)
	    continue;
	  for(j=0;pt->T_end+j<n&&(i+j)<r && L[idx(r,n,i+j,pt->T_end+j)]>0;j++)
	    L[((i+j) * n) + (pt->T_end + j)] -= z;
	}
    }

  slist_qsort(X, (slist_cmp_t)sc_lcs_pt_cmp);
  //lcs_print(S, T, X);

  rc = 0;

 done:
  if(rc != 0 && X != NULL)
    {
      slist_free_cb(X, (slist_free_t)sc_lcs_pt_free);
      X = NULL;
    }
  if(bits != NULL) slist_free_cb(bits, (slist_free_t)sc_lcs_pt_free);
  if(L != NULL) free(L);
  return X;
}

static void sc_css_free(sc_css_t *css)
{
  if(css->css != NULL) free(css->css);
  free(css);
  return;
}

static sc_css_t *sc_css_alloc0(void)
{
  sc_css_t *css;
  if((css = malloc(sizeof(sc_css_t))) == NULL)
    return NULL;
  css->css = NULL;
  css->cssc = 0;
  css->len = 0;
  css->count = 0;
  return css;
}

static sc_css_t *sc_css_alloc(size_t len)
{
  sc_css_t *css;
  if((css = malloc(sizeof(sc_css_t))) == NULL ||
     (css->css = malloc(len)) == NULL)
    goto err;
  css->cssc = 0;
  css->len = 0;
  css->count = 0;
  return css;

 err:
  if(css != NULL) sc_css_free(css);
  return NULL;
}

static int sc_css_hasalpha(const sc_css_t *css)
{
  char *ptr = css->css;
  int i;

  for(i=0; i<css->cssc; i++)
    {
      while(*ptr != '\0')
	{
	  if(isalpha(*ptr) != 0)
	    return 1;
	  ptr++;
	}
      ptr++;
    }

  return 0;
}

static char *sc_css_tostr(const sc_css_t *css,char delim,char *out,size_t len)
{
  size_t off = 0;
  char *ptr = css->css;
  int i;

  for(i=0; i<css->cssc; i++)
    {
      if(off + 1 >= len)
	break;
      if(i > 0)
	{
	  out[off++] = delim;
	  ptr++;
	}
      while(*ptr != '\0')
	{
	  if(off + 1 >= len)
	    break;
	  out[off++] = *ptr;
	  ptr++;
	}
    }
  out[off++] = '\0';
  assert(off <= len);

  return out;
}

/*
 * sc_css_morespecific
 *
 * try and determine if the evaluated css contains the string in base, plus
 * a bit extra.
 */
static int sc_css_morespecific(const sc_css_t *base, const sc_css_t *eval)
{
  const char *base_p = base->css, *eval_p = eval->css;
  int base_i = 0, eval_i = 0;

  if(eval->len <= base->len)
    return 0;

  while(eval_i < eval->cssc)
    {
      if(strcmp(base_p, eval_p) == 0)
	{
	  base_i++;
	  if(base_i == base->cssc)
	    return 1;
	  while(*base_p != '\0')
	    base_p++;
	  base_p++;

	  eval_i++;
	  while(*eval_p != '\0')
	    eval_p++;
	  eval_p++;
	}
      else
	{
	  eval_i++;
	  if(eval_i == eval->cssc)
	    break;
	  while(*eval_p != '\0')
	    eval_p++;
	  eval_p++;
	}
    }

  return 0;
}

/*
 * sc_css_morespecific_ex
 *
 * return the "bit extra" in the out css.
 */
static int sc_css_morespecific_ex(const sc_css_t *base, const sc_css_t *eval,
				  sc_css_t **out)
{
  const char *base_p = base->css, *eval_p = eval->css;
  char *tmp_p;
  int base_i = 0, eval_i = 0;
  sc_css_t *tmp = NULL;
  size_t len;

  *out = NULL;

  /* nothing to return if eval is not more specific than base */
  if(sc_css_morespecific(base, eval) == 0)
    return 0;

  /* alloc a css structure to contain the more specific part */
  if((tmp = sc_css_alloc(eval->len + 1)) == NULL)
    return -1;
  tmp_p = tmp->css;

  while(eval_i < eval->cssc)
    {
      if(base_i < base->cssc && strcmp(base_p, eval_p) == 0)
	{
	  base_i++;
	  if(base_i < base->cssc)
	    {
	      while(*base_p != '\0')
		base_p++;
	      base_p++;
	    }
	}
      else
	{
	  len = strlen(eval_p) + 1;
	  memcpy(tmp->css, eval_p, len);
	  tmp->cssc++;
	  tmp->len += len;
	  tmp_p += len;
	}

      eval_i++;
      if(eval_i == eval->cssc)
	break;
      while(*eval_p != '\0')
	eval_p++;
      eval_p++;
    }

  *out = tmp;
  return 0;
}

/*
 * sc_css_morespecific_ov
 *
 * which output vector, if any, contains the "bit extra" specified in the
 * css structure.
 */
static int sc_css_morespecific_ov(sc_rework_t *rew, sc_css_t *ex,
				  const sc_iface_t *iface, int *cap)
{
  int i, m, start, len;

  *cap = 0;

#ifdef HAVE_PCRE2
  m = pcre2_match(rew->pcre[0], (PCRE2_SPTR)iface->name, iface->len, 0, 0,
		  rew->match_data, NULL);
#else
  m = pcre_exec(rew->pcre[0], rew->study[0], iface->name, iface->len, 0, 0,
		rew->ovector, rew->n);
#endif

  assert(m != 0);
  if(m <= 0)
    return -1;

#ifdef HAVE_PCRE2
  rew->ovector = pcre2_get_ovector_pointer(rew->match_data);
#endif

  for(i=1; i<m; i++)
    {
      start = rew->ovector[2*i];
      len = rew->ovector[(2*i)+1] - start;
      if(len != ex->len-1)
	continue;
      if(memcmp(iface->name + start, ex->css, len) == 0)
	{
	  *cap = i;
	  return 1;
	}
    }

  return 0;
}

static uint32_t sc_css_strlen(const sc_css_t *css)
{
  char *ptr = css->css;
  uint32_t len = 0;
  int i;

  for(i=0; i<css->cssc; i++)
    {
      while(*ptr != '\0')
	{
	  ptr++;
	  len++;
	}
      ptr++;
    }

  return len;
}

static int sc_css_css_cmp(const sc_css_t *a, const sc_css_t *b)
{
  int x;
  if((x = memcmp(a->css, b->css, a->len <= b->len ? a->len : b->len)) != 0)
    return x;
  if(a->len < b->len) return -1;
  if(a->len > b->len) return  1;
  return 0;
}

static int sc_css_count_cmp(const sc_css_t *a, const sc_css_t *b)
{
  if(a->count > b->count) return -1;
  if(a->count < b->count) return  1;
  return sc_css_css_cmp(a, b);
}

static int sc_css_count_min_cmp(const sc_css_t *a, const sc_css_t *b)
{
  if(a->count < b->count) return -1;
  if(a->count > b->count) return  1;
  return 0;
}

static sc_css_t *sc_css_alloc_lcs(const slist_t *X, const char *S)
{
  sc_css_t *css = NULL;
  slist_node_t *sn;
  sc_lcs_pt_t *pt;
  size_t off = 0;

  assert(slist_count(X) > 0);

  for(sn=slist_head_node(X); sn != NULL; sn = slist_node_next(sn))
    {
      pt = slist_node_item(sn);
      off += pt->S_end - pt->S_start + 1 + 1;
    }

  if((css = sc_css_alloc(off)) == NULL)
    goto err;
  for(sn=slist_head_node(X); sn != NULL; sn = slist_node_next(sn))
    {
      pt = slist_node_item(sn);
      memcpy(css->css+css->len, &S[pt->S_start], pt->S_end - pt->S_start + 1);
      css->len += pt->S_end - pt->S_start + 1;
      css->css[css->len++] = '\0';
      css->cssc++;
    }

  return css;

 err:
  if(css != NULL) sc_css_free(css);
  return NULL;
}

static sc_css_t *sc_css_dup(const sc_css_t *css)
{
  sc_css_t *x;
  if((x = malloc(sizeof(sc_css_t))) == NULL ||
     (x->css = memdup(css->css, css->len)) == NULL)
    goto err;
  x->len = css->len;
  x->cssc = css->cssc;
  x->count = css->count;
  return x;

 err:
  if(x != NULL) sc_css_free(x);
  return NULL;
}

static sc_css_t *sc_css_find(splaytree_t *tree, const sc_css_t *css)
{
  assert(css->cssc > 0);
  return splaytree_find(tree, css);
}

static int sc_css_insert(splaytree_t *tree, const sc_css_t *css)
{
  assert(css->cssc > 0);
  if(splaytree_insert(tree, css) == NULL)
    return -1;
  return 0;
}

static sc_css_t *sc_css_get(splaytree_t *tree, const sc_css_t *css)
{
  sc_css_t *x;
  assert(css->cssc > 0);
  if((x = sc_css_find(tree, css)) != NULL)
    return x;
  if((x = sc_css_dup(css)) == NULL ||
     splaytree_insert(tree, x) == NULL)
    goto err;
  return x;

 err:
  if(x != NULL) sc_css_free(x);
  return NULL;
}

static sc_css_t *sc_css_get_str(splaytree_t *tree, const char *str)
{
  sc_css_t fm;

  fm.css = (char *)str;
  fm.cssc = 1;
  fm.len = strlen(str) + 1;
  fm.count = 0;

  return sc_css_get(tree, &fm);
}

/*
 * sc_css_match
 *
 * is all of the common substring in the input string?
 */
static int sc_css_match(const sc_css_t *css, const char *S, int *out, int alnum)
{
  int i, c, x, y;

  assert(css->cssc != 0);

  c = 0; x = 0; i = 0;
  while(i < css->cssc)
    {
      /* end of string, no match */
      if(S[x] == '\0')
	return 0;
      if(S[x] != css->css[c])
	{
	  x++;
	  continue;
	}

      /* go through and see if this part matches this substring portion */
      y = 0;
      while(S[x+y] == css->css[c+y] && css->css[c+y] != '\0')
	y++;

      /* this part matched */
      if(css->css[c+y] == '\0' &&
	 (alnum == 0 ||
	  ((x == 0 || isalnum(S[x-1]) == 0) && isalnum(S[x+y]) == 0)))
	{
	  if(out != NULL)
	    {
	      out[(i*2)+0] = x;
	      out[(i*2)+1] = x+y-1;
	    }

	  i++;
	  c = c + y + 1;
	  x = x + y;
	}
      else x++;
    }

  return 1;
}

static sc_css_t *sc_css_matchxor(const sc_css_t *css, const sc_ifacedom_t *ifd)
{
  sc_css_t *out = NULL;
  int Xc, *X_array = NULL;
  int l, r;
  int rc = -1;

  Xc = css->cssc * 2;
  if((out = sc_css_alloc(ifd->len + 1)) == NULL ||
     (X_array = malloc_zero(Xc * sizeof(int))) == NULL ||
     sc_css_match(css, ifd->label, X_array, 1) != 1)
    goto done;

  if(X_array[0] > 0)
    {
      l = 0;
      r = X_array[0] - 1;
      while(isalnum(ifd->label[l]) == 0 && l < r)
	l++;
      while(isalnum(ifd->label[r]) == 0 && r > l)
	r--;

      if(l != r)
	{
	  memcpy(out->css+out->len, ifd->label+l, r - l + 1);
	  out->len += r - l + 1;
	  out->css[out->len++] = '\0';
	  out->cssc++;
	}
    }
  rc = 0;

 done:
  if(rc != 0 && out != NULL)
    {
      sc_css_free(out);
      out = NULL;
    }
  if(X_array != NULL) free(X_array);
  return out;
}

/*
 * sc_regex_caprep
 *
 * substitute the strings from the css into the capture portions of
 * the regex
 */
static char *sc_regex_caprep_css(const char *in, const sc_css_t *css)
{
  const char *ptr = in;
  const char *css_ptr = css->css;
  int css_i = 0;
  char *out = NULL, *dup;
  size_t off = 0, len;

  /* allocate a temporary buffer that should be large enough */
  len = strlen(in) + sc_css_strlen(css) + 1;
  if((out = malloc(len)) == NULL)
    goto err;

  while(*ptr != '\0')
    {
      if(ptr[0] == '\\')
	{
	  if(ptr[1] == '\0')
	    goto err;
	  out[off++] = *ptr; ptr++;
	  out[off++] = *ptr; ptr++;
	}
      else if(ptr[0] == '(' && ptr[1] == '?' && ptr[2] == ':')
	{
	  out[off++] = *ptr;
	  ptr++;
	}
      else if(*ptr == '(')
	{
	  if(css_i == css->cssc)
	    goto err;
	  out[off++] = *ptr; ptr++;
	  while(*css_ptr != '\0')
	    {
	      out[off++] = *css_ptr;
	      css_ptr++;
	    }
	  css_i++;
	  while(*ptr != '\0')
	    {
	      if(*ptr == ')')
		break;
	      else if(ptr[0] == '\\')
		{
		  if(ptr[1] == '\0')
		    goto err;
		  ptr += 2;
		}
	      ptr++;
	    }
	  if(*ptr != ')')
	    goto err;
	  out[off++] = *ptr; ptr++;
	}
      else
	{
	  out[off++] = *ptr;
	  ptr++;
	}
    }

  /* return a string only just large enough */
  out[off++] = '\0';
  if((dup = memdup(out, off)) == NULL)
    return out;
  free(out);
  return dup;

 err:
  if(out != NULL) free(out);
  return NULL;
}

/*
 * sc_regex_caprep
 *
 * replace the specified capture element in the regex with the string
 * in lit.
 */
static char *sc_regex_caprep(const char *in, int rep, int cap, const char *lit)
{
  const char *ptr = in;
  char *out, *dup;
  int element = 0;
  size_t off = 0, len;

  /* allocate a temporary buffer that should be large enough */
  len = strlen(in) + strlen(lit) + 1;
  if((out = malloc(len)) == NULL)
    return NULL;

  while(*ptr != '\0')
    {
      if(ptr[0] == '(' && ptr[1] == '?' && ptr[2] == ':')
	{
	  out[off++] = *ptr;
	  ptr++;
	}
      else if(*ptr == '(' && ++element == rep)
	{
	  if(cap != 0) out[off++] = '(';
	  while(*lit != '\0')
	    {
	      out[off++] = *lit;
	      lit++;
	    }
	  if(cap != 0) out[off++] = ')';
	  while(*ptr != ')')
	    ptr++;
	  ptr++;
	}
      else
	{
	  out[off++] = *ptr;
	  ptr++;
	}
    }

  /* return a string only just large enough */
  out[off++] = '\0';
  if((dup = memdup(out, off)) == NULL)
    return out;
  free(out);
  return dup;
}

/*
 * sc_regex_caprep_list
 *
 * replace the specified capture element in the regex with the elements
 * in the list, using an or statement in the regex syntax, i.e.,
 * (?:foo|bar)
 */
static char *sc_regex_caprep_list(const char *in, int rep, dlist_t *list)
{
  const char *ptr = in;
  const char *litp;
  dlist_node_t *dn;
  sc_css_t *lit;
  char *out, *dup;
  int cap = 0;
  size_t off, len;
  int i = 0;

  /* compute the upper bound on the string size necessary */
  len = 0;
  dlist_qsort(list, (dlist_cmp_t)sc_css_css_cmp);
  for(dn=dlist_head_node(list); dn != NULL; dn=dlist_node_next(dn))
    {
      lit = dlist_node_item(dn);
      len += lit->len + 1;
    }
  len += strlen(in) + 3;
  if((out = malloc(len)) == NULL)
    return NULL;

  off = 0;
  while(*ptr != '\0')
    {
      if(ptr[0] == '(' && ptr[1] == '?' && ptr[2] == ':')
	{
	  out[off++] = *ptr;
	  ptr++;
	}
      else if(*ptr == '(' && ++cap == rep)
	{
	  if(dlist_count(list) > 1)
	    {
	      out[off++] = '('; out[off++] = '?'; out[off++] = ':';
	    }
	  for(dn=dlist_head_node(list); dn != NULL; dn=dlist_node_next(dn))
	    {
	      if(i > 0) out[off++] = '|';
	      lit = dlist_node_item(dn);
	      litp = lit->css;
	      while(*litp != '\0')
		{
		  out[off++] = *litp;
		  litp++;
		}
	      i++;
	    }
	  if(dlist_count(list) > 1)
	    out[off++] = ')';
	  while(*ptr != ')')
	    ptr++;
	  ptr++;
	}
      else
	{
	  out[off++] = *ptr;
	  ptr++;
	}
    }

  out[off++] = '\0';
  if((dup = memdup(out, off)) == NULL)
    return out;
  free(out);
  return dup;
}

static char *sc_regex_caponly(const char *in, int only)
{
  const char *ptr = in;
  char *out = NULL;
  int cap = 0;
  size_t off = 0;
  char ch;

  if((out = malloc(strlen(in) + 1)) == NULL)
    return NULL;

  while(*ptr != '\0')
    {
      ch = *ptr; ptr++;
      if(ch == '(')
	{
	  cap++;
	  if(cap != only)
	    continue;
	}
      else if(ch == ')')
	{
	  if(cap != only)
	    continue;
	}
      out[off++] = ch;
    }

  out[off] = '\0';
  return out;
}

static int sc_regex_capget_css_lit2(char *buf, size_t len, size_t *off_in,
				    const char *start, const char *end)
{
  const char *litend = end;
  const char *ptr = start;
  size_t off = *off_in;

  while(litend >= start && isalnum(*litend) == 0)
    litend--;

  buf[off++] = '(';

  if(litend < start)
    {
      while(ptr <= end)
	{
	  buf[off++] = *ptr;
	  ptr++;
	}
      buf[off++] = ')';
      goto done;
    }

  while(ptr <= litend)
    {
      buf[off++] = *ptr;
      ptr++;
    }
  buf[off++] = ')';
  while(ptr <= end)
    {
      buf[off++] = *ptr;
      ptr++;
    }

 done:
  *off_in = off;
  return 0;
}

static int sc_regex_capget_css(const char *in, sc_css_t **out)
{
  const char *start = NULL, *ptr;
  sc_css_t *css = NULL;
  slist_t *list = NULL;
  size_t len = 0, tmp;
  char *dup = NULL;
  int rc = -1;

  if((list = slist_alloc()) == NULL)
    goto done;

  ptr = in;
  while(*ptr != '\0')
    {
      if(ptr[0] == '(' && ptr[1] != '?')
	{
	  start = ptr + 1;
	}
      else if(ptr[0] == ')' && start != NULL)
	{
	  tmp = ptr - start + 1;
	  if((dup = memdup(start, tmp)) == NULL)
	    goto done;
	  dup[tmp-1] = '\0';
	  if(slist_tail_push(list, dup) == NULL)
	    goto done;
	  dup = NULL;
	  start = NULL;
	  len += tmp;
	}
      ptr++;
    }

  if((css = sc_css_alloc(len)) == NULL)
    goto done;
  while((dup = slist_head_pop(list)) != NULL)
    {
      len = strlen(dup);
      memcpy(css->css + css->len, dup, len);
      css->len += len;
      free(dup); dup = NULL;
      css->cssc++;
      css->css[css->len++] = '\0';
    }
  *out = css; css = NULL;
  slist_free(list); list = NULL;
  rc = 0;

 done:
  if(list != NULL) slist_free_cb(list, (slist_free_t)free);
  if(css != NULL) sc_css_free(css);
  return rc;
}

static int sc_regex_capget(const char *in, int capitem, char *out, size_t len)
{
  const char *ptr = in;
  size_t off = 0;
  int cap = 0;

  while(*ptr != '\0')
    {
      if(ptr[0] == '(' && ptr[1] == '?' && ptr[2] == ':')
	{
	  ptr++;
	}
      else if(ptr[0] == '(' && ++cap == capitem)
	{
	  ptr++;
	  while(*ptr != ')' && *ptr != '\0')
	    {
	      out[off++] = *ptr;
	      ptr++;
	    }
	  if(*ptr != ')')
	    return -1;
	  out[off] = '\0';
	  return 0;
	}
      else
	{
	  ptr++;
	}
    }
  return -1;
}

static int sc_regex_pt_decons2(slist_t *list, int *c, int cc, int co,
			       int *o, int oo, int use)
{
  sc_ptrc_t *ptrc = NULL;

  if(use != 0)
    {
      o[oo++] = c[co];
      o[oo++] = c[co+1];
    }

  co += 2;

  if(co == cc)
    {
      if(oo == 0)
	return 0;
      if((ptrc = malloc_zero(sizeof(sc_ptrc_t))) == NULL ||
	 (ptrc->ptr = memdup(o, sizeof(int) * oo)) == NULL ||
	 slist_tail_push(list, ptrc) == NULL)
	goto err;
      ptrc->c = oo;
      ptrc = NULL;
    }
  else
    {
      if(sc_regex_pt_decons2(list, c, cc, co, o, oo, 0) != 0 ||
	 sc_regex_pt_decons2(list, c, cc, co, o, oo, 1) != 0)
	goto err;
    }

  return 0;

 err:
  if(ptrc != NULL) sc_ptrc_free2(ptrc);
  return -1;
}

static int sc_regex_pt_decons(slist_t *list, int *c, int cc)
{
  int *dup = NULL;
  int rc = -1;

  if(cc < 4)
    return 0;

  if((dup = memdup(c, sizeof(int) * cc)) == NULL ||
     sc_regex_pt_decons2(list, c, cc, 0, dup, 0, 0) != 0 ||
     sc_regex_pt_decons2(list, c, cc, 0, dup, 0, 1) != 0)
    goto done;
  rc = 0;

 done:
  if(dup != NULL) free(dup);
  return rc;
}

/*
 * sc_css_reduce_ls
 *
 * given a set of literal values in the tree, escape them as necessary,
 * and build less-specific versions of digit classes with \d* and \d+.
 * return the literal values in a new list.
 */
static dlist_t *sc_css_reduce_ls(splaytree_t *tree)
{
  dlist_t *out_list = NULL;
  splaytree_t *out = NULL;
  slist_t *list = NULL;
  slist_node_t *sn;
  sc_css_t *css, fm;
  char *ptr;
  char buf[512], tmp[8];
  int al, num, skip;
  size_t r, off;

  if((out = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL ||
     (list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(tree, tree_to_slist, list);

  for(sn = slist_head_node(list); sn != NULL; sn = slist_node_next(sn))
    {
      css = slist_node_item(sn);
      if(css->cssc != 1)
	continue;

      /* make a copy of the literal on the out list, properly escaped */
      if(re_escape_str(buf, sizeof(buf), css->css) == NULL)
	goto done;
      fm.css = buf;
      fm.cssc = 1;
      fm.count = 3;
      fm.len = strlen(buf) + 1;
      if(sc_css_get(out, &fm) == NULL)
	goto done;

      /*
       * check to see if we are going to use \d in the literal.  the
       * rule with this part of the code is that we are only allowed
       * digits after the first occurance of a digit in the string.
       * i.e, we allow ae2.
       *
       * the next block of code handles cases like ae-1-2.
       */
      ptr = css->css;
      al = 0; num = 0; skip = 0;
      for(ptr = css->css; *ptr != '\0' && skip == 0; ptr++)
	{
	  if(isdigit(*ptr) == 0)
	    {
	      if(num != 0)
		skip = 1;
	      else if(al == 0)
		al = 1;
	    }
	  else
	    {
	      if(num == 0)
		num = 1;
	    }
	}

      /* if we are skipping, or there are no digits here, move on */
      if(skip != 0 || num == 0)
	continue;

      /* do proper off / len comparisons to prevent buffer overflow */
      off = 0;
      if(al != 0)
	{
	  for(ptr = css->css; *ptr != '\0'; ptr++)
	    {
	      if(isdigit(*ptr) != 0)
		break;
	      if((r = re_escape(tmp, sizeof(tmp), *ptr)) == 0)
		goto done;
	      if(sizeof(buf) - off < r)
		goto done;
	      /* string_concat(buf, sizeof(buf), &off, tmp); */
	      memcpy(buf+off, tmp, r); off += r;
	    }
	}
      buf[off++] = '\\';
      buf[off++] = 'd';
      buf[off++] = '+';
      buf[off++] = '\0';

      fm.css = buf;
      fm.cssc = 1;
      fm.len = off;
      fm.count = 2;
      if(sc_css_get(out, &fm) == NULL)
	goto done;

      /* don't allow a regex that is just \d* */
      if(off == 4)
	continue;

      /* the last character and the score changes, but nothing else */
      buf[off-2] = '*';
      fm.count = 1;
      if(sc_css_get(out, &fm) == NULL)
	goto done;
    }

  /* this block of code takes ae-1-2 and outputs ae-\d+-\d+ */
  for(sn = slist_head_node(list); sn != NULL; sn = slist_node_next(sn))
    {
      css = slist_node_item(sn);
      if(css->cssc != 1)
	continue;

      off = 0;
      ptr = css->css;
      while(*ptr != '\0')
	{
	  if(isdigit(*ptr) != 0)
	    {
	      buf[off++] = '\\';
	      buf[off++] = 'd';
	      buf[off++] = '+';
	      ptr++;
	      while(isdigit(*ptr) != 0)
		ptr++;
	    }
	  else
	    {
	      if((r = re_escape(tmp, sizeof(tmp), *ptr)) == 0)
		goto done;
	      /* string_concat(buf, sizeof(buf), &off, tmp); */
	      memcpy(buf+off, tmp, r); off += r;
	      ptr++;
	    }
	}
      buf[off++] = '\0';

      fm.css = buf;
      fm.cssc = 1;
      fm.len = off;
      fm.count = 1;
      if(sc_css_get(out, &fm) == NULL)
	goto done;
    }

  if((out_list = dlist_alloc()) == NULL)
    goto done;
  splaytree_inorder(out, tree_to_dlist, out_list);
  splaytree_free(out, NULL); out = NULL;

 done:
  if(out != NULL) splaytree_free(out, (splaytree_free_t)sc_css_free);
  if(list != NULL) slist_free(list);
  return out_list;
}

static int sc_css_reduce_pair(sc_css_t *a, sc_css_t *b, int trim, int min_z,
			      sc_css_t **out)
{
  sc_css_t *css = NULL;
  slist_t *X = NULL;
  int rc = -1;

  *out = NULL;
  if((X = lcs(a->css, a->len, b->css, b->len, min_z)) == NULL)
    goto done;
  if(trim == 1)
    lcs_trim(X, a->css, b->css);
  else if(trim == 2)
    lcs_trim_class(X, a->css, b->css);
  if(slist_count(X) == 0 || lcs_check(X) == 0)
    {
      rc = 0;
      goto done;
    }

  if((css = sc_css_alloc_lcs(X, a->css)) == NULL)
    goto done;
  *out = css;
  rc = 0;

 done:
  if(X != NULL) slist_free_cb(X, (slist_free_t)sc_lcs_pt_free);
  return rc;
}

/*
 * sc_css_reduce
 *
 * trim mode 0: no trim
 * trim mode 1: trim non non-alpha
 * trim mode 2: trim on character class change
 *
 * note: the code uses the count variable to prevent comparison between
 * two css structures that have already been compared.
 */
static int sc_css_reduce(splaytree_t *tree, int trim, int min_z)
{
  sc_css_t *css, *css2, *cssa = NULL;
  slist_node_t *sn;
  slist_t *list = NULL;
  int i, rc = -1;

  if((list = slist_alloc()) == NULL)
    goto done;

  /*
   * work through the longest common substrings until we converge on
   * candidate longest common substrings
   */
  do
    {
      splaytree_inorder(tree, tree_to_slist, list);
      slist_qsort(list, (slist_cmp_t)sc_css_count_min_cmp);
      i = 0;
      while((css = slist_head_pop(list)) != NULL)
	{
	  if(css->count != 0)
	    {
	      slist_empty(list);
	      break;
	    }
	  for(sn = slist_head_node(list); sn != NULL; sn = slist_node_next(sn))
	    {
	      /* determine if there are any common substrings within */
	      css2 = slist_node_item(sn);
	      if(sc_css_reduce_pair(css, css2, trim, min_z, &cssa) != 0)
		goto done;
	      if(cssa == NULL)
		continue;

	      /* if we already have this css in the tree, move on */
	      if(sc_css_find(tree, cssa) != NULL)
		{
		  sc_css_free(cssa); cssa = NULL;
		  continue;
		}

	      /* put the css in the tree */
	      if(sc_css_insert(tree, cssa) != 0)
		goto done;
	      cssa = NULL;
	      i++;
	    }
	  css->count = 1;
	}
    }
  while(i != 0);
  rc = 0;

  /* reset the count variables to zero */
  splaytree_inorder(tree, tree_to_slist, list);
  while((css = slist_head_pop(list)) != NULL)
    css->count = 0;

 done:
  if(cssa != NULL) sc_css_free(cssa);
  if(list != NULL) slist_free(list);
  return rc;
}

/*
 * label_get:
 *
 * return a pointer to the start of a label in a domain name.  x is
 * numbered from zero, starting at the right of the string -- i.e.,
 * the TLD is zero.
 */
static const char *label_get(const char *string, int x)
{
  const char *ptr;
  int off = 0;

  if(string[0] == '\0')
    return NULL;

  ptr = string;
  while(*ptr != '\0')
    ptr++;
  ptr--;

  while(ptr != string)
    {
      if(*ptr == '.')
	{
	  if(off == x)
	    return ptr + 1;
	  off++;
	}
      ptr--;
    }

  if(off == x)
    return string;

  return NULL;
}

static int capcount(const char *str)
{
  int rc = -1;
#ifdef HAVE_PCRE2
  pcre2_code *pcre;
  uint32_t n;
  PCRE2_SIZE erroffset;
  int errnumber;
  if((pcre = pcre2_compile((PCRE2_SPTR)str, PCRE2_ZERO_TERMINATED, 0,
			   &errnumber, &erroffset, NULL)) == NULL ||
     pcre2_pattern_info(pcre, PCRE2_INFO_CAPTURECOUNT, &n) != 0)
    goto done;
  rc = n;
 done:
  if(pcre != NULL) pcre2_code_free(pcre);
#else
  const char *error;
  int erroffset, n;
  pcre *pcre;
  if((pcre = pcre_compile(str, 0, &error, &erroffset, NULL)) == NULL ||
     pcre_fullinfo(pcre, NULL, PCRE_INFO_CAPTURECOUNT, &n) != 0)
    goto done;
  rc = n;
 done:
  if(pcre != NULL) pcre_free(pcre);
#endif
  return rc;
}

static int sc_rework_matchk(sc_rework_t *rew, int k, const char *str)
{
  int rc;

  assert(k < rew->c);

#ifdef HAVE_PCRE2
  rc = pcre2_match(rew->pcre[k], (PCRE2_SPTR)str, strlen(str), 0, 0,
		   rew->match_data, NULL);
  if(rc <= 0)
    {
      if(rc == PCRE2_ERROR_NOMATCH)
	return 0;
      return -1;
    }
  rew->ovector = pcre2_get_ovector_pointer(rew->match_data);
#else
  rc = pcre_exec(rew->pcre[k], rew->study[k], str, strlen(str), 0, 0,
		 rew->ovector, rew->n);
  if(rc <= 0)
    {
      if(rc == PCRE_ERROR_NOMATCH)
	return 0;
      return -1;
    }
#endif

  rew->m = rc;
  rew->k = k;

  return 1;
}

/*
 * sc_rework_match:
 *
 * apply the regex to the string.
 *  returns -1 on error
 *  returns  0 if the regex didn't match
 *  returns  1 if the regex matches, with whatever was captured in the css.
 */
static int sc_rework_match(sc_rework_t *rew, sc_iface_t *iface, sc_css_t **out)
{
  sc_css_t *css = NULL;
  size_t off;
  int i, l, k, rc;

  if(out != NULL)
    *out = NULL;

  assert(rew->c > 0);
  for(k=0; k<rew->c; k++)
    {
#ifdef HAVE_PCRE2
      rc = pcre2_match(rew->pcre[k], (PCRE2_SPTR)iface->name, iface->len,
		       0, 0, rew->match_data, NULL);
#else
      rc = pcre_exec(rew->pcre[k], rew->study[k], iface->name, iface->len,
		     0, 0, rew->ovector, rew->n);
#endif
      assert(rc != 0);
      if(rc <= 0)
	{
#ifdef HAVE_PCRE2
	  if(rc == PCRE2_ERROR_NOMATCH)
	    continue;
#else
	  if(rc == PCRE_ERROR_NOMATCH)
	    continue;
#endif
	  return -1;
	}
      else break;
    }
  if(k == rew->c)
    return 0;

  rew->m = rc;
  rew->k = k;

#ifdef HAVE_PCRE2
  rew->ovector = pcre2_get_ovector_pointer(rew->match_data);
#endif

  if(out == NULL)
    return 1;

  /* calc the size of the matched portion */
  off = 0;
  for(i=1; i<rc; i++)
    {
      off += rew->ovector[(2*i)+1] - rew->ovector[2*i];
      off++;
    }
  if(off == 0)
    return 1;

  /* allocate a css for the matched portion */
  if((css = sc_css_alloc(off)) == NULL)
    goto err;

  /* fill the css */
  off = 0;
  for(i=1; i<rc; i++)
    {
      l = rew->ovector[(2*i)+1] - rew->ovector[2*i];
      memcpy(css->css+off, iface->name + rew->ovector[2*i], l);
      off += l;
      css->css[off++] = '\0';
      css->cssc++;
    }
  css->len = off;
  *out = css;

  return 1;

 err:
  if(css != NULL) sc_css_free(css);
  return -1;
}

static void sc_rework_free(sc_rework_t *rew)
{
  int i;

  if(rew->pcre != NULL)
    {
      for(i=0; i<rew->c; i++)
	if(rew->pcre[i] != NULL)
#ifdef HAVE_PCRE2
	  pcre2_code_free(rew->pcre[i]);
#else
	  pcre_free(rew->pcre[i]);
#endif
      free(rew->pcre);
    }

#ifdef HAVE_PCRE2
  if(rew->match_data != NULL)
    pcre2_match_data_free(rew->match_data);
#else
  if(rew->study != NULL)
    {
      for(i=0; i<rew->c; i++)
	if(rew->study[i] != NULL)
	  pcre_free_study(rew->study[i]);
      free(rew->study);
    }
  if(rew->ovector != NULL)
    free(rew->ovector);
#endif

  free(rew);

  return;
}

static int sc_rework_capcount(const sc_rework_t *rew, int i)
{
  int n;
#ifdef HAVE_PCRE2
  uint32_t x;
  if(pcre2_pattern_info(rew->pcre[i], PCRE2_INFO_CAPTURECOUNT, &x) != 0)
    return -1;
  n = x;
#else
  if(pcre_fullinfo(rew->pcre[i],rew->study[i],PCRE_INFO_CAPTURECOUNT,&n)!=0)
    return -1;
#endif
  return n;
}

static sc_rework_t *sc_rework_alloc(sc_regex_t *re)
{
  sc_rework_t *rew;
  const char *str;
  int i, k, n;

#ifdef HAVE_PCRE2
  PCRE2_SIZE erroffset;
  int errnumber;
#else
  int erroffset, options = 0;
  const char *error;
#endif

  if((rew = malloc_zero(sizeof(sc_rework_t))) == NULL)
    goto err;
  rew->c = re->regexc;

#ifdef HAVE_PCRE2
  if((rew->pcre = malloc_zero(sizeof(pcre2_code *) * rew->c)) == NULL)
    goto err;
#else
  if((rew->pcre = malloc_zero(sizeof(pcre *) * rew->c)) == NULL ||
     (rew->study = malloc_zero(sizeof(struct pcre_extra *) * rew->c)) == NULL)
    goto err;
#endif

  k = 0;
  for(i=0; i<re->regexc; i++)
    {
      str = re->regexes[i]->str;

#ifdef HAVE_PCRE2
      if((rew->pcre[i] = pcre2_compile((PCRE2_SPTR)str, PCRE2_ZERO_TERMINATED,
				       0,&errnumber,&erroffset,NULL)) == NULL)
	goto err;
      if(do_jit != 0)
	pcre2_jit_compile(rew->pcre[i], PCRE2_JIT_COMPLETE);
#else
      if((rew->pcre[i] = pcre_compile(str,0,&error,&erroffset,NULL)) == NULL)
	goto err;
#ifdef PCRE_STUDY_JIT_COMPILE
      if(do_jit != 0)
	options |= PCRE_STUDY_JIT_COMPILE;
#endif
      rew->study[i] = pcre_study(rew->pcre[i], options, &error);
#endif

      /* figure out how large the ovector has to be for this regex */
      if((n = sc_rework_capcount(rew, i)) < 0)
	goto err;
      if(n <= k)
	continue;
      k = n;
    }

#ifdef HAVE_PCRE2
  if((rew->match_data = pcre2_match_data_create(k + 1, NULL)) == NULL)
    goto err;
#else
  n = ((k + 1) * 3);
  if((rew->ovector = malloc_zero(sizeof(int) * n)) == NULL)
    goto err;
  rew->n = n;
#endif

  return rew;

 err:
  if(rew != NULL) sc_rework_free(rew);
  return NULL;
}

static void sc_suffix_free(sc_suffix_t *suffix)
{
  int i;
  if(suffix->label != NULL)
    free(suffix->label);
  if(suffix->suffixes != NULL)
    {
      for(i=0; i<suffix->suffixc; i++)
	sc_suffix_free(suffix->suffixes[i]);
      free(suffix->suffixes);
    }
  free(suffix);
  return;
}

static int sc_suffix_label_cmp(const sc_suffix_t *a, const sc_suffix_t *b)
{
  return strcmp(a->label, b->label);
}

static int suffix_file_line(char *line, void *param)
{
  slist_t *list = param;
  static int end_icann = 0;
  char *ptr;

  if(line[0] == '\0')
    return 0;

  if(end_icann != 0)
    return 0;

  if(line[0] == '/')
    {
      if(strncmp(line, "// ===END", 9) == 0)
	end_icann = 1;
      return 0;
    }
  if(line[0] == '!')
    return 0;

  if(line[0] == '*' && line[1] == '.')
    line = line + 2;

  for(ptr=line; *ptr != '\0'; ptr++)
    {
      if(*ptr == '.' || *ptr == '-' ||
	 (*ptr >= '0' && *ptr <= '9') ||
	 (*ptr >= 'a' && *ptr <= 'z'))
	continue;
      break;
    }
  if(*ptr != '\0')
    {
      // fprintf(stderr, "skipping %s\n", line);
      return 0;
    }

  if((ptr = strdup(line)) == NULL ||
     slist_tail_push(list, ptr) == NULL)
    return -1;

  return 0;
}

static sc_suffix_t *sc_suffix_get(const char *suffix)
{
  const char *ptr, *end = NULL;
  sc_suffix_t *ss = suffix_root;
  sc_suffix_t fm, *s = NULL;
  char buf[256];
  int i, c, dc;

  dc = dotcount(suffix);
  for(i=0; i<=dc; i++)
    {
      ptr = label_get(suffix, i);
      if(end == NULL)
	{
	  snprintf(buf, sizeof(buf), "%s", ptr);
	}
      else
	{
	  c = end - ptr - 1;
	  memcpy(buf, ptr, c);
	  buf[c] = '\0';
	}
      end = ptr;
      fm.label = buf;

      if((s = array_find((void **)ss->suffixes, ss->suffixc, &fm,
			 (array_cmp_t)sc_suffix_label_cmp)) == NULL)
	{
	  if((s = malloc_zero(sizeof(sc_suffix_t))) == NULL ||
	     (s->label = strdup(buf)) == NULL)
	    {
	      if(s != NULL) free(s);
	      return NULL;
	    }
	  s->parent = ss;
	  array_insert((void ***)&ss->suffixes, &ss->suffixc, s,
		       (array_cmp_t)sc_suffix_label_cmp);
	}

      ss = s;
    }

  /* domains can be registered with this suffix */
  if(s != NULL)
    s->end = 1;

  return s;
}

static const char *sc_suffix_find(const char *domain)
{
  const char *ptr, *m = NULL, *end = NULL;
  sc_suffix_t *ss = suffix_root, *s = NULL, fm;
  char buf[256];
  int i, c, dc;

  if(domain == NULL)
    return NULL;

  dc = dotcount(domain);
  for(i=0; i<=dc; i++)
    {
      ptr = label_get(domain, i);
      if(end == NULL)
	{
	  snprintf(buf, sizeof(buf), "%s", ptr);
	}
      else
	{
	  c = end - ptr - 1;
	  memcpy(buf, ptr, c);
	  buf[c] = '\0';
	}
      end = ptr;
      fm.label = buf;

      if((s = array_find((void **)ss->suffixes, ss->suffixc, &fm,
			 (array_cmp_t)sc_suffix_label_cmp)) == NULL)
	break;

      if(s->end == -1)
	return NULL;

      if(s->end == 1)
	m = ptr;

      ss = s;
    }

  if(m == NULL || m-2 <= domain)
    return NULL;
  m = m - 2;
  while(m >= domain)
    {
      if(*m == '.')
	return m + 1;
      m--;
    }

  return NULL;
}

static int sc_iface_suffix_cmp(const sc_iface_t *a, const sc_iface_t *b)
{
  const char *as = sc_suffix_find(a->name);
  const char *bs = sc_suffix_find(b->name);
  int i;

  if(as != NULL || bs != NULL)
    {
      if(as == NULL) return 1;
      if(bs == NULL) return -1;
      if((i = strcmp(as, bs)) != 0)
	return i;
    }
  if((i = strcmp(a->name, b->name)) != 0)
    return i;
  return scamper_addr_human_cmp(a->addr, b->addr);
}

static int sc_segscore_cmp(const sc_segscore_t *a, const sc_segscore_t *b)
{
  return strcmp(a->seg, b->seg);
}

static void sc_segscore_free(sc_segscore_t *ss)
{
  if(ss->seg != NULL) free(ss->seg);
  free(ss);
  return;
}

static sc_segscore_t *sc_segscore_alloc(const char *seg, int score)
{
  sc_segscore_t *ss = NULL;
  if((ss = malloc_zero(sizeof(sc_segscore_t))) == NULL ||
     (ss->seg = strdup(seg)) == NULL)
    {
      if(ss != NULL) sc_segscore_free(ss);
      return NULL;
    }
  ss->score = score;
  return ss;
}

static int sc_segscore_get(splaytree_t *tree, char *seg, int score)
{
  sc_segscore_t fm, *ss;
  fm.seg = seg;
  fm.score = score;
  if(splaytree_find(tree, &fm) != NULL)
    return 0;
  if((ss = sc_segscore_alloc(seg, score)) == NULL ||
     splaytree_insert(tree, ss) == NULL)
    {
      if(ss != NULL) sc_segscore_free(ss);
      return -1;
    }
  return 0;
}

static void sc_regexn_free(sc_regexn_t *ren)
{
  if(ren->str != NULL) free(ren->str);
  free(ren);
  return;
}

static sc_regexn_t *sc_regexn_dup(sc_regexn_t *in)
{
  sc_regexn_t *out = NULL;
  if((out = malloc_zero(sizeof(sc_regexn_t))) == NULL ||
     (out->str = strdup(in->str)) == NULL)
    {
      if(out != NULL) sc_regexn_free(out);
      return NULL;
    }
  out->capc = in->capc;
  return out;
}

static sc_regexn_t *sc_regexn_alloc(char *str)
{
  sc_regexn_t *ren = NULL;
  if((ren = malloc_zero(sizeof(sc_regexn_t))) == NULL ||
     (ren->str = strdup(str)) == NULL)
    {
      if(ren != NULL) sc_regexn_free(ren);
      return NULL;
    }
  return ren;
}

static int sc_regex_findnew(const sc_regex_t *cur, const sc_regex_t *can)
{
  int i;

  assert(cur->regexc < can->regexc);
  assert(cur->regexc + 1 == can->regexc);

  for(i=0; i<cur->regexc; i++)
    if(strcmp(cur->regexes[i]->str, can->regexes[i]->str) != 0)
      return i;

  return can->regexc-1;
}

static int sc_regex_score_tpa(const sc_regex_t *re)
{
  return (int)re->tp_c - (int)(re->fp_c + re->fne_c + re->ip_c);
}

static float sc_regex_score_tpr(const sc_regex_t *re)
{
  return (float)re->tp_c / (re->fp_c + re->fne_c + re->ip_c + 1);
}

static void sc_regex_score_reset(sc_regex_t *re)
{
  int i;
  for(i=0; i<re->regexc; i++)
    {
      re->regexes[i]->matchc = 0;
      re->regexes[i]->capc = 0;
      re->regexes[i]->rt_c = 0;
    }
  if(re->tp_mask != NULL)
    {
      free(re->tp_mask);
      re->tp_mask = NULL;
    }
  re->matchc = 0;
  re->namelen = 0;
  re->tp_c = 0;
  re->fp_c = 0;
  re->fne_c = 0;
  re->fnu_c = 0;
  re->ip_c = 0;
  re->sp_c = 0;
  re->sn_c = 0;
  re->rt_c = 0;
  return;
}

static char *sc_regex_tostr(const sc_regex_t *re, char *buf, size_t len)
{
  size_t off = 0;
  int i;
  string_concat(buf, len, &off, "%s", re->regexes[0]->str);
  for(i=1; i<re->regexc; i++)
    string_concat(buf, len, &off, " %s", re->regexes[i]->str);
  return buf;
}

static char *sc_regex_score_tostr(const sc_regex_t *re, char *buf, size_t len)
{
  uint32_t tp, fp;
  size_t off = 0;

  if(re->matchc == 0)
    {
      string_concat(buf, len, &off, "no matches");
      return buf;
    }

  tp = re->tp_c;
  fp = re->fp_c + re->ip_c;

  string_concat(buf, len, &off,	"ppv %.3f, rt %u tp %u fp %u",
		((float)tp) / (tp+fp), re->rt_c, re->tp_c, re->fp_c);

  if(re->fne_c > 0)
    string_concat(buf, len, &off, " fne %u", re->fne_c);
  if(re->fnu_c > 0)
    string_concat(buf, len, &off, " fnu %u", re->fnu_c);
  if(re->sp_c > 0)
    string_concat(buf, len, &off, " sp %u", re->sp_c);
  if(re->sn_c > 0)
    string_concat(buf, len, &off, " sn %u", re->sn_c);
  if(re->ip_c > 0)
    string_concat(buf, len, &off, " ip %u", re->ip_c);

  string_concat(buf, len, &off, " tpr %.1f tpa %d",
		sc_regex_score_tpr(re), sc_regex_score_tpa(re));

  string_concat(buf, len, &off, ", score %u matches %u", re->score, re->matchc);

  return buf;
}

static char *sc_regex_score_tojson(const sc_regex_t *re, char *buf, size_t len)
{
  size_t off = 0;
  string_concat(buf, len, &off,
		"\"rt\":%d, \"tp\":%d, \"fp\":%d, \"fne\":%d, \"fnu\":%d, "
		"\"sp\":%d, \"sn\":%d, \"ip\":%d",
		re->rt_c, re->tp_c, re->fp_c, re->fne_c, re->fnu_c,
		re->sp_c, re->sn_c, re->ip_c);
  return buf;
}

/*
 * sc_regex_str_cmp
 *
 * provide sorting to check if a regex already exists in the tree
 */
static int sc_regex_str_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  int i, x;
  if(a->regexc < b->regexc) return -1;
  if(a->regexc > b->regexc) return  1;
  for(i=0; i<a->regexc; i++)
    if((x = strcmp(a->regexes[i]->str, b->regexes[i]->str)) != 0)
      return x;
  return 0;
}

static int sc_regex_str_len(const sc_regex_t *re)
{
  size_t len = 0;
  int i;
  for(i=0; i<re->regexc; i++)
    len += strlen(re->regexes[i]->str);
  return len;
}

static int sc_regex_score_tie_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  size_t al, bl;
  int ac, bc, i, x;

  /* pick the regex that gets the same work done with less regexes */
  if(a->regexc < b->regexc) return -1;
  if(a->regexc > b->regexc) return  1;

  /* pick the regex that uses the least capture elements */
  ac = 0;
  for(i=0; i<a->regexc; i++)
    ac += a->regexes[i]->capc;
  bc = 0;
  for(i=0; i<b->regexc; i++)
    bc += b->regexes[i]->capc;
  if(ac < bc) return -1;
  if(ac > bc) return  1;

  /* pick the regex with the highest specificity score */
  if(a->score > b->score) return -1;
  if(a->score < b->score) return  1;

  /*
   * pick longer extraction names
   *
   * this breaks a tie between ([^-]+)\..+\.comcast\.net$ and
   * ([^-]+)\.comcast\.net$
   */
  if(a->namelen > b->namelen) return -1;
  if(a->namelen < b->namelen) return  1;

  /* pick longer regexes */
  al = sc_regex_str_len(a);
  bl = sc_regex_str_len(b);
  if(al > bl) return -1;
  if(al < bl) return  1;

  /* break ties with alphabetical sort */
  for(i=0; i<a->regexc; i++)
    if((x = strcmp(a->regexes[i]->str, b->regexes[i]->str)) != 0)
      return x;

  return 0;
}

/*
 * sc_regex_score_thin_cmp
 *
 * this function is used to cluster regexes that might be equivalent
 */
static int sc_regex_score_thin_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  if(a->tp_c  > b->tp_c)  return -1;
  if(a->tp_c  < b->tp_c)  return  1;
  if(a->fp_c  < b->fp_c)  return -1;
  if(a->fp_c  > b->fp_c)  return  1;
  if(a->ip_c  < b->ip_c)  return -1;
  if(a->ip_c  > b->ip_c)  return  1;
  if(a->fne_c < b->fne_c) return -1;
  if(a->fne_c > b->fne_c) return  1;
  if(a->fnu_c < b->fnu_c) return -1;
  if(a->fnu_c > b->fnu_c) return  1;
  if(a->sp_c  < b->sp_c)  return -1;
  if(a->sp_c  > b->sp_c)  return  1;
  if(a->sn_c  < b->sn_c)  return -1;
  if(a->sn_c  > b->sn_c)  return  1;
  return 0;
}

static int sc_regex_score_thin_sort_cmp(const sc_regex_t *a,const sc_regex_t *b)
{
  int x;
  if((x = sc_regex_score_thin_cmp(a, b)) != 0)
    return x;
  return sc_regex_score_tie_cmp(a, b);
}

static int sc_regex_score_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  if(a->rt_c > b->rt_c) return -1;
  if(a->rt_c < b->rt_c) return  1;
  if(a->fp_c < b->fp_c) return -1;
  if(a->fp_c > b->fp_c) return  1;
  if(a->tp_c > b->tp_c) return -1;
  if(a->tp_c < b->tp_c) return  1;
  return sc_regex_score_tie_cmp(a, b);
}

static int sc_regex_score_rank_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  int a_tpa, b_tpa;

  a_tpa = sc_regex_score_tpa(a);
  b_tpa = sc_regex_score_tpa(b);

  if(a_tpa > b_tpa)
    return -1;
  if(a_tpa < b_tpa)
    return 1;

  if(a->fp_c < b->fp_c) return -1;
  if(a->fp_c > b->fp_c) return  1;
  if(a->tp_c > b->tp_c) return -1;
  if(a->tp_c < b->tp_c) return  1;

  return sc_regex_score_tie_cmp(a, b);
}

/*
 * sc_regex_score_fp_cmp:
 *
 * this score function is used in the false positive refinement step.
 * sort the regexes by max(tp-fp), followed by single interfaces that
 * were matched.
 */
static int sc_regex_score_fp_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  int ac = a->tp_c - a->fp_c;
  int bc = b->tp_c - b->fp_c;
  if(ac > bc) return -1;
  if(ac < bc) return 1;
  if(a->sp_c > b->sp_c) return -1;
  if(a->sp_c < b->sp_c) return  1;
  return sc_regex_score_tie_cmp(a, b);
}

/*
 * sc_reegx_score_ip_cmp:
 *
 * this score function is used to evaluate regexes that filter IP matches.
 * sort the regexes by max(tp-fp)
 */
static int sc_regex_score_ip_cmp(const sc_regex_t *a, const sc_regex_t *b)
{
  int ac = a->tp_c - a->fp_c;
  int bc = b->tp_c - b->fp_c;
  if(a->fp_c < b->fp_c) return -1;
  if(a->fp_c > b->fp_c) return  1;
  if(ac > bc) return -1;
  if(ac < bc) return 1;
  return sc_regex_score_tie_cmp(a, b);
}

static void sc_regex_free(sc_regex_t *re)
{
  int i;
  if(re->regexes != NULL)
    {
      for(i=0; i<re->regexc; i++)
	if(re->regexes[i] != NULL)
	  sc_regexn_free(re->regexes[i]);
      free(re->regexes);
    }
  if(re->tp_mask != NULL) free(re->tp_mask);
  free(re);
  return;
}

static sc_regex_t *sc_regex_plus1(sc_regex_t *re, sc_regexn_t *ren, int i)
{
  sc_regex_t *out = NULL;
  int j, regexc = re->regexc + 1;

  assert(i >= 0);
  assert(i < regexc);

  if((out = malloc_zero(sizeof(sc_regex_t))) == NULL ||
     (out->regexes = malloc_zero(sizeof(sc_regexn_t *) * regexc)) == NULL)
    goto err;
  out->regexc = regexc;
  out->dom = re->dom;

  for(j=0; j<i; j++)
    if((out->regexes[j] = sc_regexn_dup(re->regexes[j])) == NULL)
      goto err;
  if((out->regexes[i] = sc_regexn_dup(ren)) == NULL)
    goto err;
  for(j=i; j<re->regexc; j++)
    if((out->regexes[j+1] = sc_regexn_dup(re->regexes[j])) == NULL)
      goto err;

  return out;

 err:
  if(out != NULL) sc_regex_free(out);
  return NULL;
}

static sc_regex_t *sc_regex_head_push(sc_regex_t *re, sc_regexn_t *ren)
{
  return sc_regex_plus1(re, ren, 0);
}

static sc_regex_t *sc_regex_tail_push(sc_regex_t *re, sc_regexn_t *ren)
{
  return sc_regex_plus1(re, ren, re->regexc);
}

static sc_regex_t *sc_regex_alloc_list(slist_t *list)
{
  sc_regex_t *re = NULL;
  slist_node_t *sn;
  char *ptr;
  int k = 0;

  if((re = malloc_zero(sizeof(sc_regex_t))) == NULL)
    goto err;
  re->regexc = slist_count(list);
  if((re->regexes = malloc_zero(sizeof(sc_regexn_t *) * re->regexc)) == NULL)
    goto err;
  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
    {
      ptr = slist_node_item(sn);
      if((re->regexes[k] = sc_regexn_alloc(ptr)) == NULL)
	goto err;
      if((re->regexes[k]->capc = capcount(ptr)) < 0)
	goto err;
      k++;
    }
  return re;

 err:
  if(re != NULL) sc_regex_free(re);
  return NULL;
}

static sc_regex_t *sc_regex_alloc_str(char *str)
{
  sc_regex_t *re = NULL;
  slist_t *list = NULL;
  char *ptr = str, *next;

  if((list = slist_alloc()) == NULL)
    goto err;

  do
    {
      string_nullterm_char(ptr, ' ', &next);
      if(slist_tail_push(list, ptr) == NULL)
	goto err;
      ptr = next;
    }
  while(ptr != NULL);

  if((re = sc_regex_alloc_list(list)) == NULL)
    goto err;
  slist_free(list); list = NULL;

  return re;

 err:
  if(list != NULL) slist_free(list);
  if(re != NULL) sc_regex_free(re);
  return NULL;
}

static sc_regex_t *sc_regex_alloc_css(const sc_css_t *in)
{
  const char *ptr = in->css;
  const char *start;
  sc_regex_t *re = NULL;
  slist_t *list = NULL;
  int i = 0;
  char buf[256], *dup = NULL;
  size_t off, len = 0;

  if((list = slist_alloc()) == NULL)
    goto err;

  while(i != in->cssc)
    {
      start = NULL;
      off = 0;
      buf[off++] = '^';

      while(*ptr != '\0')
	{
	  if(*ptr == '[')
	    {
	      if(start != NULL)
		{
		  sc_regex_capget_css_lit2(buf,sizeof(buf),&off,start,ptr-1);
		  start = NULL;
		}

	      /* skip over [X]+ */
	      while(*ptr != ']' && *ptr != '\0')
		{
		  buf[off++] = *ptr;
		  ptr++;
		}
	      if(*ptr == '\0')
		goto err;
	      buf[off++] = *ptr; ptr++;
	      buf[off++] = *ptr; ptr++;
	    }
	  else if(ptr[0] == '\\' && ptr[1] == 'd' && ptr[2] == '+')
	    {
	      if(start != NULL)
		{
		  sc_regex_capget_css_lit2(buf,sizeof(buf),&off,start,ptr-1);
		  start = NULL;
		}

	      /* skip over \d+ */
	      buf[off++] = *ptr; ptr++;
	      buf[off++] = *ptr; ptr++;
	      buf[off++] = *ptr; ptr++;
	    }
	  else if(*ptr == '.')
	    {
	      if(start != NULL)
		{
		  sc_regex_capget_css_lit2(buf,sizeof(buf),&off,start,ptr-1);
		  start = NULL;
		}

	      /* skip over .+ */
	      buf[off++] = *ptr; ptr++;
	      buf[off++] = *ptr; ptr++;
	    }
	  else if(*ptr == '\\')
	    {
	      if(start == NULL)
		{
		  buf[off++] = ptr[0];
		  buf[off++] = ptr[1];
		}
	      /* skip over escaped characters */
	      ptr++; ptr++;
	    }
	  else
	    {
	      if(start == NULL)
		start = ptr;
	      ptr++;
	    }
	}

      if(start != NULL)
	sc_regex_capget_css_lit2(buf, sizeof(buf), &off, start, ptr-1);

      buf[off++] = '$';
      buf[off++] = '\0';
      if((dup = memdup(buf,off)) == NULL || slist_tail_push(list,dup) == NULL)
	goto err;
      dup = NULL;

      len += off;
      ptr++;
      i++;
    }

  if((re = sc_regex_alloc_list(list)) == NULL)
    goto err;

  slist_free_cb(list, (slist_free_t)free);
  return re;

 err:
  if(list != NULL) slist_free_cb(list, (slist_free_t)free);
  if(re != NULL) sc_regex_free(re);
  return NULL;
}

/*
 * sc_regex_capseg
 *
 * rewrite the input regex so that any character class segments are
 * captured separately so they can be further analyzed.
 */
static char *sc_regex_capseg(const char *in)
{
  const char *ptr = in;
  char *buf = NULL, *dup = NULL;
  size_t off, len;

  /* allocate a working buffer larger than we could possibly need */
  len = strlen(in) * 3;
  if((buf = malloc(len)) == NULL)
    goto done;

  off = 0;
  while(*ptr != '\0')
    {
      if(ptr[0] == '[' && ptr[1] == '^')
	{
	  buf[off++] = '(';
	  while(*ptr != ']' && *ptr != '\0')
	    {
	      buf[off++] = *ptr;
	      ptr++;
	    }
	  if(*ptr == '\0')
	    goto done;
	  buf[off++] = *ptr; ptr++; /* ] */
	  buf[off++] = *ptr; ptr++; /* + */
	  buf[off++] = ')';
	}
      else if(ptr[0] == '(' && ptr[1] == '?' && ptr[2] == ':')
	{
	  while(*ptr != ')' && *ptr != '\0')
	    {
	      buf[off++] = *ptr;
	      ptr++;
	    }
	  if(*ptr == '\0')
	    goto done;
	  buf[off++] = *ptr; ptr++;
	}
      else if(ptr[0] == '.' && ptr[1] == '+')
	{
	  buf[off++] = '(';
	  buf[off++] = *ptr; ptr++;
	  buf[off++] = *ptr; ptr++;
	  buf[off++] = ')';
	}
      else if(ptr[0] == '\\')
	{
	  buf[off++] = *ptr; ptr++;
	  if(*ptr == '\0')
	    goto done;
	  buf[off++] = *ptr; ptr++;
	}
      else if(ptr[0] == '(' || ptr[0] == ')')
	{
	  ptr++;
	}
      else
	{
	  buf[off++] = *ptr; ptr++;
	}
    }
  buf[off++] = '\0';
  dup = strdup(buf);

 done:
  if(buf != NULL) free(buf);
  return dup;
}

#ifndef DMALLOC
static sc_regex_t *sc_regex_alloc(char *str)
#else
#define sc_regex_alloc(str) sc_regex_alloc_dm((str), __FILE__, __LINE__)
static sc_regex_t *sc_regex_alloc_dm(char *str,const char *file,const int line)
#endif
{
  sc_regex_t *re;

#ifndef DMALLOC
  re = malloc_zero(sizeof(sc_regex_t));
#else
  re = malloc_zero_dm(sizeof(sc_regex_t), file, line);
#endif

  if(re == NULL ||
     (re->regexes = malloc_zero(sizeof(sc_regexn_t *) * 1)) == NULL ||
     (re->regexes[0] = malloc_zero(sizeof(sc_regexn_t))) == NULL ||
     (re->regexes[0]->capc = capcount(str)) < 0)
    goto err;
  re->regexc = 1;
  re->regexes[0]->str = str;
  return re;

 err:
  if(re != NULL) sc_regex_free(re);
  return NULL;
}

static sc_regex_t *sc_regex_dup(sc_regex_t *in)
{
  sc_regex_t *out = NULL;
  size_t len;
  int i;

  if((out = memdup(in, sizeof(sc_regex_t))) == NULL)
    goto err;
  out->regexes = NULL;
  out->tp_mask = NULL;
  len = sizeof(sc_regexn_t *) * in->regexc;
  if((out->regexes = malloc_zero(len)) == NULL)
    goto err;
  if(in->tp_mask != NULL)
    {
      len = sizeof(uint32_t) * in->dom->tpmlen;
      if((out->tp_mask = memdup(in->tp_mask, len)) == NULL)
	goto err;
    }

  for(i=0; i<in->regexc; i++)
    if((out->regexes[i] = sc_regexn_dup(in->regexes[i])) == NULL)
      goto err;

  return out;

 err:
  if(out != NULL) sc_regex_free(out);
  return NULL;
}

static sc_regex_t *sc_regex_find(splaytree_t *tree, char *str)
{
  sc_regex_t fm;
  sc_regexn_t *regexes[1];
  sc_regexn_t ren;

  ren.str = str;
  regexes[0] = &ren;
  fm.regexes = regexes;
  fm.regexc  = 1;

  return splaytree_find(tree, &fm);
}

#ifndef DMALLOC
static sc_regex_t *sc_regex_get(splaytree_t *tree, char *str)
#else
#define sc_regex_get(tree, str) sc_regex_get_dm((tree),(str),__FILE__,__LINE__)
static sc_regex_t *sc_regex_get_dm(splaytree_t *tree, char *str,
				   const char *file, const int line)
#endif
{
  sc_regex_t *re = NULL;
  char *dup = NULL;

  if((re = sc_regex_find(tree, str)) != NULL)
    return re;
  if((dup = strdup(str)) == NULL)
    goto err;
#ifndef DMALLOC
  re = sc_regex_alloc(dup);
#else
  re = sc_regex_alloc_dm(dup, file, line);
#endif
  if(re == NULL)
    goto err;
  dup = NULL;
  if(splaytree_insert(tree, re) == NULL)
    goto err;
  return re;

 err:
  if(dup != NULL) free(dup);
  if(re != NULL) sc_regex_free(re);
  return NULL;
}

static void sc_iface_free(sc_iface_t *iface)
{
  if(iface->addr != NULL)
    scamper_addr_free(iface->addr);
  if(iface->name != NULL)
    free(iface->name);
  free(iface);
  return;
}

static int sc_ifaceinf_css_null(sc_ifaceinf_t *ifi, void *param)
{
  ifi->css = NULL;
  return 0;
}

static void sc_ifaceinf_free(sc_ifaceinf_t *ifi)
{
  if(ifi->css != NULL) sc_css_free(ifi->css);
  free(ifi);
  return;
}

static int sc_ifaceinf_inf_cmp(const sc_ifaceinf_t *a, const sc_ifaceinf_t *b)
{
  if(a->css == NULL && b->css == NULL) return 0;
  if(a->css == NULL) return 1;
  if(b->css == NULL) return -1;
  return sc_css_css_cmp(a->css, b->css);
}

static int sc_ifaceinf_ifd_rd_cmp(const sc_ifaceinf_t *a,
				  const sc_ifaceinf_t *b)
{
  if(a->ifd->rd < b->ifd->rd) return -1;
  if(a->ifd->rd > b->ifd->rd) return  1;
  return 0;
}

static int sc_ifaceinf_rtrc_cmp(const sc_ifaceinf_t *a, const sc_ifaceinf_t *b)
{
  if(a->rtrc > b->rtrc) return -1;
  if(a->rtrc < b->rtrc) return  1;
  return ptrcmp(a->ifd->rd, b->ifd->rd);
}

static sc_ifaceinf_t *sc_ifaceinf_get(slist_t *list, sc_ifacedom_t *ifd,
				      sc_css_t *css, int ip, int regex)
{
  sc_ifaceinf_t *ifi;
  if((ifi = malloc(sizeof(sc_ifaceinf_t))) == NULL)
    goto err;
  ifi->ifd = ifd;
  ifi->css = css;
  ifi->ri = NULL;
  ifi->rtrc = 0;
  ifi->regex = regex;
  ifi->class = '\0';
  ifi->ipm = ip;
  if(slist_tail_push(list, ifi) == NULL)
    goto err;
  return ifi;

 err:
  if(ifi != NULL) sc_ifaceinf_free(ifi);
  return NULL;
}

static void sc_regex_css_free(sc_regex_css_t *recss)
{
  if(recss == NULL)
    return;
  if(recss->work != NULL)
    sc_regex_free(recss->work);
  if(recss->regex != NULL)
    sc_regex_free(recss->regex);
  if(recss->css != NULL)
    sc_css_free(recss->css);
  free(recss);
  return;
}

static int sc_regex_css_score_cmp(const sc_regex_css_t *a,
				  const sc_regex_css_t *b)
{
  return sc_regex_score_cmp(a->regex, b->regex);
}

static int sc_regex_css_work_score_cmp(const sc_regex_css_t *a,
				       const sc_regex_css_t *b)
{
  return sc_regex_score_cmp(a->work, b->work);
}

static sc_iface_t *sc_iface_alloc(char *ip, char *name)
{
  sc_iface_t *iface;
  if((iface = malloc_zero(sizeof(sc_iface_t))) == NULL ||
     (iface->addr = scamper_addr_resolve(AF_UNSPEC, ip)) == NULL ||
     (name[0] != '\0' && (iface->name = strdup(name)) == NULL))
    goto err;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(iface->addr))
    {
      if(ip_v != 4)
	{
	  printf("%s", ip);
	  if(name[0] != '\0')
	    printf(" for %s", name);
	  printf(" is an IPv4 address, but -6 was specified");
	  goto err;
	}
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(iface->addr))
    {
      if(ip_v != 6)
	{
	  printf("%s", ip);
	  if(name[0] != '\0')
	    printf(" for %s", name);
	  printf(" is an IPv6 address, but -6 was not specified");
	  goto err;
	}
    }
  else
    {
      printf("unhandled address type\n");
      goto err;
    }

  iface->len = strlen(name);
  iface->ip_s = -1;
  iface->ip_e = -1;
  return iface;
 err:
  if(iface != NULL) sc_iface_free(iface);
  return NULL;
}

static int sc_iface_ip_find_4(sc_iface_t *iface, const char *suffix)
{
  uint32_t addr = ntohl(((struct in_addr *)iface->addr->addr)->s_addr);
  const char *ptr = iface->name;
  const char *so[200][2]; /* string offsets */
  long sb[200]; /* string address bytes */
  long ab[4]; /* IP address bytes */
  long set[4];
  int c, i, j, k, l, bo = 0, ip_s = -1, ip_e = -1;
  char *ep;
  char buf[128];

  while(bo < sizeof(sb) / sizeof(long))
    {
      while(isdigit(*ptr) == 0 && ptr != suffix)
	ptr++;
      if(ptr >= suffix)
	break;
      sb[bo] = strtol(ptr, &ep, 10);
      so[bo][0] = ptr;
      so[bo][1] = ep;
      bo++;
      ptr = ep;
    }

  if(bo == 0)
    return 0;

  ab[0] = (addr >> 24) & 0xFF;
  ab[1] = (addr >> 16) & 0xFF;
  ab[2] = (addr >> 8) & 0xFF;
  ab[3] = addr & 0xFF;

  /*
   * the approach is as follows: we first try to find examples where
   * all 4 bytes are present.  then, we try to find examples where at
   * least 3 bytes are present.  then two.  we do not try and find
   * examples where only a single byte of the address is present
   */
  for(l=4; l>=2; l--)
    {
      for(i=0; i<bo-l+1; i++)
	{
	  c = 0;
	  for(k=0; k<4; k++)
	    set[k] = 0;
	  ip_s = -1; ip_e = -1;

	  /* j is used to index the sb array, offset by i */
	  for(j=0; j<l; j++)
	    {
	      /*
	       * k is used to index the ab array.  we allow each byte
	       * of the ab array to be used once
	       */
	      for(k=0; k<4; k++)
		{
		  if(sb[i+j] == ab[k] && set[k] == 0)
		    {
		      if(ip_s == -1 || ip_s > so[i+j][0] - iface->name)
			ip_s = so[i+j][0] - iface->name;
		      if(ip_s == -1 || ip_e < so[i+j][1] - iface->name - 1)
			ip_e = so[i+j][1] - iface->name - 1;
		      set[k] = 1;
		      c++;
		      break;
		    }
		}
	    }

	  if(c == l)
	    {
	      iface->ip_s = ip_s;
	      iface->ip_e = ip_e;
	      if(verbose != 0 && threadc == 1)
		{
		  printf("found %s in %s bytes %d - %d\n",
			 scamper_addr_tostr(iface->addr, buf, sizeof(buf)),
			 iface->name, iface->ip_s, iface->ip_e);
		}
	      return 1;
	    }
	}
    }

  return 0;
}

static int pos_diff(int x, int y)
{
  if(x < y)
    return y - x;
  return x - y;
}

#if 0
static int sc_charpos_isvalid(sc_iface_t *iface, sc_charpos_t *cp, int x)
{
  int i;

  for(i=0; i<32; i++)
    {
      if(cp->pos[i] == -1)
	continue;
      if(iface->name[cp->pos[i]] != cp->c[i])
	{
	  printf("%s %d: %c != %c at pos %d\n", iface->name, x,
		 iface->name[cp->pos[i]], cp->c[i], cp->pos[i]);
	}
    }

  return 0;
}
#endif

#if 0
static void sc_charpos_print(const sc_iface_t *iface, sc_charpos_t *cp)
{
  char buf[256];
  int i;

  printf("%s %s %d %d %d\n", iface->name,
	 scamper_addr_tostr(iface->addr, buf, sizeof(buf)),
	 cp->left, cp->right, cp->digits);
  for(i=0; i<32; i++)
    {
      if(cp->pos[i] == -1)
	continue;
      printf("%c %d %d\n", cp->c[i], i, cp->pos[i]);
    }

  return;
}
#endif

#if 0
static void sc_charposl_dump(sc_charposl_t *posl)
{
  static const char c[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			   'a', 'b', 'c', 'd', 'e', 'f'};
  int i, j;

  for(i=0; i<16; i++)
    {
      printf("%c:", posl[i].c);
      for(j=0; j<posl[i].posc; j++)
	printf(" %d", posl[i].pos[j]);
      printf("\n");
    }

  return;
}
#endif

static void sc_charpos_score(sc_charpos_t *cp)
{
  int i;

  cp->left = -1;
  cp->right = -1;
  cp->digits = 0;

  for(i=0; i<32; i++)
    {
      if(cp->pos[i] == -1)
	continue;
      cp->digits++;
      if(cp->pos[i] < cp->left || cp->left == -1)
	cp->left = cp->pos[i];
      if(cp->pos[i] > cp->right || cp->right == -1)
	cp->right = cp->pos[i];
    }

  return;
}

static int sc_charpos_score_cmp(const sc_charpos_t *a, const sc_charpos_t *b)
{
  int ar, br;
  if(a->digits > b->digits) return -1;
  if(a->digits < b->digits) return  1;
  ar = a->right - a->left + 1;
  br = b->right - a->right + 1;
  if(ar < br) return -1;
  if(ar > br) return  1;
  return 0;
}

static int sc_iface_ip_isok(const sc_iface_t *iface, const sc_charpos_t *cp)
{
  int i, j, x, nonzero[8], set[8], left, right;

  /*
   * check each digit is set in each block when any digit in the block
   * is set.
   */
  for(i=0; i<8; i++)
    {
      nonzero[i] = 0;
      set[i] = 0;
      x = i * 4;

      /* check if any character in the block is not zero */
      for(j=0; j<4; j++)
	if(cp->c[x+j] != '0')
	  break;
      if(j != 4)
	nonzero[i] = 1;

      /* check if any character after a set character is unset */
      for(j=0; j<4; j++)
	if(cp->pos[x+j] != -1)
	  break;
      if(j == 4)
	continue;
      set[i] = 1;
      for(j=j+1; j<4; j++)
	if(cp->pos[x+j] == -1)
	  return 0;
    }

  /* determine if there is a gap in block coverage, and reject if there is */
  x = 0; j = 0;
  for(i=0; i<8; i++)
    {
      if(set[i] == 1 && j == 0)
	j = 1;
      else if(j == 1 && set[i] == 0 && nonzero[i] != 0)
	x = 1;
      else if(set[i] == 1 && x == 1)
	return 0;
    }

  /* determine if there is any non-alnum character not covered */
  left = -1; right = -1;
  for(i=0; i<32; i++)
    {
      if(cp->pos[i] == -1)
	continue;
      if(cp->pos[i] < left || left == -1)
	left = cp->pos[i];
      if(cp->pos[i] > right || right == -1)
	right = cp->pos[i];
    }
  for(i=left+1; i<right; i++)
    {
      if(isalnum(iface->name[i]) == 0 || iface->name[i] == '0')
	continue;
      if(ishex(iface->name[i]) == 0)
	return 0;
      for(j=0; j<32; j++)
	if(cp->pos[j] == i)
	  break;
      if(j == 32)
	return 0;
    }

  return 1;
}

static void sc_iface_ip_unfill_zero(sc_charpos_t *cp)
{
  int i;
  for(i=0; i<32; i++)
    if(cp->c[i] == '0')
      cp->pos[i] = -1;
  return;
}

static void sc_iface_ip_fill_zero(sc_iface_t *iface, sc_charpos_t *cp)
{
  int i, j, x, pos, asc = 0, desc = 0;

  for(i=0; i<8; i++)
    {
      pos = -1;
      for(j=0; j<4; j++)
	{
	  if(cp->pos[(i*4)+j] == -1)
	    continue;
	  if(pos != -1)
	    {
	      if(pos < cp->pos[(i*4)+j])
		asc++;
	      else
		desc++;
	    }
	  pos = cp->pos[(i*4)+j];
	}
    }

  for(i=0; i<8; i++)
    {
      /* find the first set character in the block */
      x = i * 4;
      for(j=0; j<4; j++)
	if(cp->pos[x+j] != -1)
	  break;
      if(j == 4)
	continue;
      pos = j;

      if(asc > desc && asc > 0)
	{
	  /*
	   * make sure there are zeros for all unfilled positions to
	   * the right of the first set character in the block
	   */
	  for(j=pos+1; j<4; j++)
	    {
	      if(cp->pos[x+j] == -1 &&
		 iface->name[cp->pos[x+pos] + (j - pos)] != '0')
		break;
	    }
	  if(j != 4)
	    continue;

	  /* fill zeros to the left of the first set character */
	  for(j=pos-1; j>=0; j--)
	    {
	      if(iface->name[cp->pos[x+pos] - (pos - j)] != '0')
		break;
	      cp->pos[x+j] = cp->pos[x+pos] - (pos - j);
	    }

	  /* fill zeros to the right of the first set character */
	  for(j=pos+1; j<4; j++)
	    {
	      if(cp->pos[x+j] != -1)
		continue;
	      if(iface->name[cp->pos[x+pos] + (j - pos)] != '0')
		break;
	      cp->pos[x+j] = cp->pos[x+pos] + (j - pos);
	    }
	}
      else if(desc > asc && desc > 0)
	{
	  /*
	   * make sure there are zeros for all unfilled positions to
	   * the left of the first set character in the block
	   */
	  for(j=pos+1; j<4; j++)
	    {
	      if(cp->pos[x+j] == -1 &&
		 iface->name[cp->pos[x+pos] - (j - pos)] != '0')
		break;
	    }
	  if(j != 4)
	    continue;

	  /* fill zeros to the left of the first set character */
	  for(j=pos-1; j>=0; j--)
	    {
	      if(iface->name[cp->pos[x+pos] + (pos - j)] != '0')
		break;
	      cp->pos[x+j] = cp->pos[x+pos] + (pos - j);
	    }

	  /* fill zeros to the right of the first set character */
	  for(j=pos+1; j<4; j++)
	    {
	      if(cp->pos[x+j] != -1)
		continue;
	      if(iface->name[cp->pos[x+pos] - (j - pos)] != '0')
		break;
	      cp->pos[x+j] = cp->pos[x+pos] - (j - pos);
	    }
	}
    }

  return;
}

static int sc_iface_ip_find_6_rec(sc_iface_t *iface, const char *suffix,
				  sc_charposl_t *posl, sc_charpos_t *cp, int x,
				  sc_charpos_t *best)
{
  int i, j, k, c, v;
  int a[4];

  /* for each 16 bit block, check for some basic properties or early reject */
  if((x % 4) == 0 && x != 0)
    {
      /* start offset */
      i = ((x / 4) - 1) * 4;

      /* ensure positions are sequential */
      c = 0;
      for(j=0; j<4; j++)
	if(cp->pos[i+j] != -1)
	  a[c++] = cp->pos[i+j];
      for(j=2; j<c; j++)
	if((a[j-2] < a[j-1] && a[j-1] > a[j]) ||
	   (a[j-2] > a[j-1] && a[j-1] < a[j]))
	  return 0;

      /* if any bit is set, make sure all non-zero chars are represented */
      if(c > 0 &&
	 ((cp->pos[i+0] == -1 && cp->c[i+0] != '0') ||
	  (cp->pos[i+1] == -1 && cp->c[i+1] != '0') ||
	  (cp->pos[i+2] == -1 && cp->c[i+2] != '0') ||
	  (cp->pos[i+3] == -1 && cp->c[i+3] != '0')))
	return 0;

      /* ensure the positions seem reasonable */
      for(j=0; j<4; j++)
	{
	  if(cp->pos[i+j] == -1)
	    continue;
	  for(k=j+1; k<4; k++)
	    {
	      if(cp->pos[i+k] == -1)
		continue;
	      if(pos_diff(cp->pos[i+j], cp->pos[i+k]) != k - j)
		return 0;
	    }
	}
    }

  if(x == 32)
    {
      sc_iface_ip_fill_zero(iface, cp);
      if(sc_iface_ip_isok(iface, cp) != 0)
	{
	  sc_charpos_score(cp);
	  if(sc_charpos_score_cmp(cp, best) < 0)
	    memcpy(best, cp, sizeof(sc_charpos_t));
	}
      sc_iface_ip_unfill_zero(cp);
      return 0;
    }

  if(isdigit(cp->c[x]))
    c = cp->c[x] - '0';
  else
    c = cp->c[x] - 'a' + 10;

  if(cp->c[x] == '0')
    {
      sc_iface_ip_find_6_rec(iface, suffix, posl, cp, x+1, best);
      return 0;
    }

  for(i=0; i<posl[c].posc; i++)
    {
      if(posl[c].pos[i] != -1)
	{
	  v = posl[c].pos[i]; posl[c].pos[i] = -1;
	  cp->pos[x] = v;
	  sc_iface_ip_find_6_rec(iface, suffix, posl, cp, x+1, best);
	  posl[c].pos[i] = v;
	}
    }

  cp->pos[x] = -1;
  sc_iface_ip_find_6_rec(iface, suffix, posl, cp, x+1, best);

  return 0;
}

/*
 * sc_iface_ip_find_6:
 *
 * infer if a portion of the hostname happens to correspond to an IPv6
 * address literal.
 */
static int sc_iface_ip_find_6(sc_iface_t *iface, const char *suffix)
{
  sc_charposl_t posl[16];
  sc_charpos_t cp, best;
  uint8_t u;
  char c, *ptr, buf[256];
  int i, j, rc = -1;

  memset(&cp, 0, sizeof(cp));
  memset(posl, 0, sizeof(posl));

  for(i=0; i<32; i++)
    {
      u =
	scamper_addr_bit(iface->addr, (i * 4) + 1) << 3 |
	scamper_addr_bit(iface->addr, (i * 4) + 2) << 2 |
	scamper_addr_bit(iface->addr, (i * 4) + 3) << 1 |
	scamper_addr_bit(iface->addr, (i * 4) + 4);
      if(u <= 9)
	cp.c[i] = '0' + u;
      else
	cp.c[i] = 'a' + (u - 10);
      cp.pos[i] = -1;
    }

  for(i=1; i<16; i++)
    {
      if(i < 10) c = '0' + i;
      else       c = 'a' + (i - 10);

      /* count how many instances of the character are in the string */
      j = 0;
      ptr = iface->name;
      while(ptr != suffix)
	{
	  if(*ptr == c)
	    j++;
	  ptr++;
	}

      /* allocate enough instances */
      if((posl[i].pos = malloc(sizeof(int) * j)) == NULL)
	goto done;
      posl[i].posc = j;
      j = 0;
      ptr = iface->name;
      while(ptr != suffix)
	{
	  if(*ptr == c)
	    {
	      posl[i].pos[j] = ptr - iface->name;
	      j++;
	    }
	  ptr++;
	}
    }

  memset(&best, 0, sizeof(best));
  sc_iface_ip_find_6_rec(iface, suffix, posl, &cp, 0, &best);

  /* count how many bits are set.  if less than four, we're done */
  if(best.digits < 4)
    {
      rc = 0;
      goto done;
    }

  iface->ip_s = best.left;
  iface->ip_e = best.right;
  if(verbose != 0 && threadc == 1)
    {
      printf("found %s in %s bytes %d - %d\n",
	     scamper_addr_tostr(iface->addr, buf, sizeof(buf)),
	     iface->name, iface->ip_s, iface->ip_e);
    }
  rc = 1;

 done:
  for(i=0; i<16; i++)
    if(posl[i].pos != NULL)
      free(posl[i].pos);
  return rc;
}

static void sc_iface_ip_find_thread(sc_iface_t *iface)
{
  const char *suffix = sc_suffix_find(iface->name);
  if(SCAMPER_ADDR_TYPE_IS_IPV4(iface->addr))
    sc_iface_ip_find_4(iface, suffix);
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(iface->addr))
    sc_iface_ip_find_6(iface, suffix);
  return;
}

/*
 * sc_iface_ip_matched
 *
 * determine if the regex matched part of a string that appears to have
 * been derived from the corresponding IP address
 */
static int sc_iface_ip_matched(sc_iface_t *iface, sc_rework_t *rew)
{
  int i;

  if(iface->ip_s == -1)
    return 0;

#if 0
  printf("%s %d %d:", iface->name, iface->ip_s, iface->ip_e);
  for(i=1; i<rew->m; i++)
    printf(" %d,%d", rew->ovector[2*i], rew->ovector[(2*i)+1]);
  printf("\n");
#endif

  for(i=1; i<rew->m; i++)
    {
      if(iface->ip_e < rew->ovector[2*i])
	continue;
      if(iface->ip_s > rew->ovector[(2*i)+1])
	continue;
      return 1;
    }

  return 0;
}

static void sc_ifdptr_free(sc_ifdptr_t *ifp)
{
  free(ifp);
  return;
}

static int sc_ifdptr_cmp(const sc_ifdptr_t *a, const sc_ifdptr_t *b)
{
  if(a->ifd < b->ifd) return -1;
  if(a->ifd > b->ifd) return  1;
  return 0;
}

static sc_ifdptr_t *sc_ifdptr_find(splaytree_t *tree, sc_ifacedom_t *ifd)
{
  sc_ifdptr_t fm; fm.ifd = ifd;
  return splaytree_find(tree, &fm);
}

static sc_ifdptr_t *sc_ifdptr_get(splaytree_t *tree, sc_ifacedom_t *ifd)
{
  sc_ifdptr_t *ifp;
  if((ifp = sc_ifdptr_find(tree, ifd)) != NULL)
    return ifp;
  if((ifp = malloc_zero(sizeof(sc_ifdptr_t))) == NULL)
    return NULL;
  ifp->ifd = ifd;
  ifp->ptr = NULL;
  if(splaytree_insert(tree, ifp) == NULL)
    {
      free(ifp);
      return NULL;
    }
  return ifp;
}

/*
 * sc_ifdptr_tree
 *
 * build a tree that can map each interface in a set of routers to
 * some other object.
 */
static splaytree_t *sc_ifdptr_tree(const slist_t *routers)
{
  splaytree_t *ifp_tree = NULL;
  sc_ifdptr_t *ifp;
  slist_node_t *sn;
  sc_routerdom_t *rd;
  int i;

  if((ifp_tree = splaytree_alloc((splaytree_cmp_t)sc_ifdptr_cmp)) == NULL)
    goto err;

  for(sn=slist_head_node(routers); sn != NULL; sn=slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      for(i=0; i<rd->ifacec; i++)
	{
	  if((ifp = sc_ifdptr_get(ifp_tree, rd->ifaces[i])) == NULL)
	    goto err;
	}
    }

  return ifp_tree;

 err:
  if(ifp_tree != NULL) splaytree_free(ifp_tree, (splaytree_free_t)sc_ifdptr_free);
  return NULL;
}

/*
 * sc_ifdptr_tree_ri
 *
 * given a tree filled with ifp constructed from a set of routers, attach
 * the inferred router interfaces to each ifp.
 */
static int sc_ifdptr_tree_ri(splaytree_t *ifp_tree, const slist_t *ri_list)
{
  slist_node_t *sn;
  sc_routerinf_t *ri;
  sc_ifdptr_t *ifp;
  int i;

  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);
      for(i=0; i<ri->ifacec; i++)
	{
	  if((ifp=sc_ifdptr_find(ifp_tree, ri->ifaces[i]->ifd)) == NULL)
	    return -1;
	  ifp->ptr = ri->ifaces[i];
	}
    }

  return 0;
}

static int sc_routername_cmp(const sc_routername_t *a,const sc_routername_t *b)
{
  int rc;

  if(a->css != NULL && b->css != NULL)
    {
      if((rc = sc_css_css_cmp(a->css, b->css)) != 0)
	return rc;
      if(a->css->count > b->css->count) return -1;
      if(a->css->count < b->css->count) return  1;
    }
  else if(a->css != NULL && b->css == NULL)
    return -1;
  else if(a->css == NULL && b->css != NULL)
    return 1;

  if(a->rd->ifacec > b->rd->ifacec) return -1;
  if(a->rd->ifacec < b->rd->ifacec) return  1;
  return scamper_addr_human_cmp(a->rd->ifaces[0]->iface->addr,
				b->rd->ifaces[0]->iface->addr);
}

static void sc_routername_free(sc_routername_t *rn)
{
  if(rn->css != NULL) sc_css_free(rn->css);
  free(rn);
  return;
}

static sc_routername_t *sc_routername_alloc(sc_routerdom_t *rd,sc_rework_t *rew)
{
  sc_css_t *css = NULL, *fm, *css2[2];
  sc_routername_t *rn = NULL;
  splaytree_t *tree = NULL;
  slist_t *list = NULL;
  slist_node_t *sn;
  sc_iface_t *iface;
  int i, x, rc = -1, ip = 0;

  if((rn = malloc_zero(sizeof(sc_routername_t))) == NULL)
    goto done;
  rn->rd = rd;

  /* eval the regex on all interfaces to get name frequency */
  if((tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL)
    goto done;

  for(i=0; i<rd->ifacec; i++)
    {
      iface = rd->ifaces[i]->iface;
      if((x = sc_rework_match(rew, iface, &css)) < 0)
	goto done;
      if(x == 0 || css == NULL)
	continue;
      if(sc_iface_ip_matched(iface, rew) != 0)
	{
	  ip++;
	}
      else
	{
	  if((fm = sc_css_get(tree, css)) == NULL)
	    goto done;
	  fm->count++;
	}
      sc_css_free(css); css = NULL;
    }

  if(splaytree_count(tree) > 0)
    {
      if((list = slist_alloc()) == NULL)
	goto done;
      splaytree_inorder(tree, tree_to_slist, list);
      slist_qsort(list, (slist_cmp_t)sc_css_count_cmp);

      sn = slist_head_node(list);
      for(i=0; i<2; i++)
	{
	  css2[i] = sn != NULL ? slist_node_item(sn) : NULL;
	  sn = sn != NULL ? slist_node_next(sn) : NULL;
	}
      slist_free(list); list = NULL;

      assert(css2[0] != NULL);
      rn->matchc = css2[0]->count;
      if(css2[0] != NULL &&
	 (css2[1] == NULL || css2[0]->count > css2[1]->count) &&
	 (rn->css = sc_css_dup(css2[0])) == NULL)
	goto done;
    }
  else rn->matchc = ip;

  rc = 0;

 done:
  if(tree != NULL) splaytree_free(tree, (splaytree_free_t)sc_css_free);
  if(list != NULL) slist_free(list);
  if(rc != 0)
    {
      if(rn != NULL) sc_routername_free(rn);
      return NULL;
    }
  return rn;
}

static void sc_routernames_free(sc_routername_t **rnames, int rnamec)
{
  int i;
  for(i=0; i<rnamec; i++)
    if(rnames[i] != NULL)
      sc_routername_free(rnames[i]);
  free(rnames);
  return;
}

static sc_routername_t **sc_routernames_alloc(slist_t *rs, sc_rework_t *rew)
{
  sc_routername_t **rnames = NULL, *rn;
  int rnamec = slist_count(rs);
  sc_routerdom_t *rd;
  slist_node_t *sn;
  int i;

  if((rnames = malloc_zero(sizeof(sc_routername_t *) * rnamec)) == NULL)
    goto err;
  i = 0;
  for(sn=slist_head_node(rs); sn != NULL; sn = slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      if((rn = sc_routername_alloc(rd, rew)) == NULL)
	goto err;
      rnames[i++] = rn;
    }
  array_qsort((void **)rnames, rnamec, (array_cmp_t)sc_routername_cmp);
  return rnames;

 err:
  if(rnames != NULL) sc_routernames_free(rnames, rnamec);
  return NULL;
}

static int sc_ifacedom_css(const sc_ifacedom_t *ifd, sc_css_t **out, int trim)
{
  sc_css_t *css = NULL;
  size_t len = strlen(ifd->label);
  size_t off = 0;
  int ip_s, ip_e;

  *out = NULL;

  /* if there is no IP address portion within, then copy whole string in */
  if(ifd->iface->ip_s == -1)
    {
      if((css = sc_css_alloc(len+1)) == NULL)
	goto err;
      memcpy(css->css, ifd->label, len+1);
      css->len = len + 1;
      css->cssc = 1;
      *out = css;
      return 0;
    }

  if((css = sc_css_alloc0()) == NULL)
    goto err;

  /*
   * allocate a common substring structure to store the entire label
   * without the IP address portion
   */
  ip_s = ifd->iface->ip_s;
  ip_e = ifd->iface->ip_e;
  if(trim != 0)
    {
      while(ip_s > 0 && isalnum(ifd->label[ip_s-1]) == 0)
	ip_s--;
      while(ifd->label[ip_e] != '\0' && isalnum(ifd->label[ip_e+1]) == 0)
	ip_e++;
    }
  if(ip_s > 0)
    {
      css->len = ip_s + 1;
      css->cssc++;
    }
  if(ip_e + 1 < len)
    {
      css->len += len - ip_e;
      css->cssc++;
    }

  if(css->cssc == 0)
    {
      sc_css_free(css);
      return 0;
    }
  assert(len > 0);

  if((css->css = malloc(css->len)) == NULL)
    goto err;

  /* copy in the substrings */
  if(ip_s > 0)
    {
      memcpy(css->css+off, ifd->label, ip_s);
      off += ip_s;
      css->css[off++] = '\0';
    }
  if(ip_e + 1 < len)
    {
      memcpy(css->css+off, ifd->label + ip_e + 1, len - ip_e - 1);
      off += len - ip_e - 1;
      css->css[off++] = '\0';
    }

  *out = css;
  return 0;

 err:
  if(css != NULL) sc_css_free(css);
  return -1;
}

static void sc_ifacedom_free(sc_ifacedom_t *ifd)
{
  if(ifd->label != NULL) free(ifd->label);
  free(ifd);
  return;
}

static sc_ifacedom_t *sc_ifacedom_alloc(sc_iface_t *iface, const char *suffix)
{
  sc_ifacedom_t *ifd = NULL;
  size_t len = suffix - iface->name;
  if((ifd = malloc_zero(sizeof(sc_ifacedom_t))) == NULL ||
     (ifd->label = malloc(len)) == NULL)
    goto err;
  memcpy(ifd->label, iface->name, len-1);
  ifd->label[len-1] = '\0';
  ifd->len = len-1;
  ifd->iface = iface;
  return ifd;

 err:
  if(ifd != NULL) sc_ifacedom_free(ifd);
  return NULL;
}

static int sc_routerinf_ifaces_null(sc_routerinf_t *ri, void *param)
{
  if(ri == NULL)
    return 0;
  if(ri->ifaces != NULL)
    free(ri->ifaces);
  ri->ifaces = NULL;
  ri->ifacec = 0;
  return 0;
}

static int sc_routerinf_maxrtrc_cmp(const sc_routerinf_t *a,
				    const sc_routerinf_t *b)
{
  if(a->ip == 0 && b->ip == 1) return -1;
  if(a->ip == 1 && b->ip == 0) return  1;
  if(a->maxrtrc > b->maxrtrc) return -1;
  if(a->maxrtrc < b->maxrtrc) return  1;
  return 0;
}

static void sc_routerinf_free(sc_routerinf_t *ri)
{
  int i;
  if(ri->ifaces != NULL)
    {
      for(i=0; i<ri->ifacec; i++)
	if(ri->ifaces[i] != NULL)
	  sc_ifaceinf_free(ri->ifaces[i]);
      free(ri->ifaces);
    }
  free(ri);
  return;
}

/*
 * sc_routerinf_finish
 *
 * we built an inferred router using extractions from regular
 * expressions.  cluster interfaces from the same training router
 * together, and sort the interfaces in order of the number of
 * interfaces from the same training router.
 */
static int sc_routerinf_finish(sc_routerinf_t *ri)
{
  int x, i, c, ip, no_ip;
  sc_routerdom_t *rd;

  /*
   * count the number of interfaces from the same training routers are
   * represented in the inferred router.  tag each interface on the
   * inferred router with how many interfaces from the same training
   * router are included in the inferred router.
   */
  array_qsort((void **)ri->ifaces, ri->ifacec,
	      (array_cmp_t)sc_ifaceinf_ifd_rd_cmp);
  x = 0; rd = ri->ifaces[x]->ifd->rd;
  for(i=1; i<ri->ifacec; i++)
    {
      if(ri->ifaces[i]->ifd->rd != rd)
	{
	  c = i - x;
	  while(x != i)
	    ri->ifaces[x++]->rtrc = c;
	  x = i; rd = ri->ifaces[x]->ifd->rd;
	}
    }
  c = ri->ifacec - x;
  while(x != ri->ifacec)
    ri->ifaces[x++]->rtrc = c;

  /*
   * sort the interfaces on the inferred router into clusters of
   * interfaces from the same training router, in order by the number
   * of interfaces from the same training router that are present
   */
  array_qsort((void **)ri->ifaces, ri->ifacec,
	      (array_cmp_t)sc_ifaceinf_rtrc_cmp);
  ri->maxrtrc = ri->ifaces[0]->rtrc;

  /*
   * for the interfaces from the first training router that match,
   * determine if all interfaces contain an IP address literal as part
   * of the extraction.  mark the router accordingly.
   */
  no_ip = 0; ip = 0;
  for(i=0; i<ri->ifaces[0]->rtrc; i++)
    {
      if(ri->ifaces[i]->ipm == 0)
	{
	  no_ip++;
	  break;
	}
      else ip++;
    }
  if(ip > 0 && no_ip == 0)
    ri->ip = 1;

  return 0;
}

/*
 * computing the Rand index according to
 *
 * "An Introduction to Information Retrieval"
 *
 * A true positive (TP) decision assigns two similar documents to the
 * same cluster, a true negative (TN) decision assigns two dissimilar
 * documents to different clusters. There are two types of errors we
 * can commit. A false positive (FP) decision assigns two dissimilar
 * documents to the same cluster. A false negative (FN) decision
 * assigns two similar documents to different clusters. The Rand index
 * (RI) measures the percentage of decisions that are correct.
 */
static double randindex(slist_t *ifp_list)
{
  slist_node_t *sn, *sn2;
  sc_ifdptr_t *ifp, *ifp2;
  sc_ifaceinf_t *ifi, *ifi2;
  uint32_t tp = 0, fp = 0, tn = 0, fn = 0;

  for(sn=slist_head_node(ifp_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifp = slist_node_item(sn);
      if(ifp->ptr == NULL)
	continue;
      ifi = ifp->ptr;

      assert(ifi->ri != NULL);
      for(sn2=slist_node_next(sn); sn2 != NULL; sn2=slist_node_next(sn2))
	{
	  ifp2 = slist_node_item(sn2);
	  if(ifp2->ptr == NULL)
	    continue;
	  ifi2 = ifp2->ptr;
	  assert(ifi2->ri != NULL);

	  if(ifp->ifd->iface->rtr == ifp2->ifd->iface->rtr)
	    {
	      if(ifi->ri == ifi2->ri)
		tp++;
	      else
		fn++;
	    }
	  else
	    {
	      if(ifi->ri == ifi2->ri)
		fp++;
	      else
		tn++;
	    }
	}
    }

  return ((double)((tp + tn) * 100)) / (tp + fp + fn + tn);
}

/*
 * sc_regex_eval_ri_build
 *
 * given a set of inferences on router interfaces, build routers
 */
static int sc_regex_eval_ri_build(slist_t *ifi_list_in, slist_t *ri_list_out)
{
  sc_ifaceinf_t *ifi = NULL;
  sc_routerinf_t *ri = NULL;
  slist_t *ifi_list = NULL, *ri_list = NULL;
  slist_node_t *sn;
  int i, rc = -1;

  if((ifi_list = slist_dup(ifi_list_in, NULL, NULL)) == NULL)
    goto done;
  if((ri_list = slist_alloc()) == NULL)
    goto done;

  slist_qsort(ifi_list, (slist_cmp_t)sc_ifaceinf_inf_cmp);
  while((ifi = slist_head_pop(ifi_list)) != NULL)
    {
      i = 1;
      if(ifi->css != NULL)
	{
	  for(sn=slist_head_node(ifi_list); sn != NULL; sn=slist_node_next(sn))
	    {
	      if(sc_ifaceinf_inf_cmp(ifi, slist_node_item(sn)) != 0)
		break;
	      i++;
	    }
	}

      if((ri = malloc(sizeof(sc_routerinf_t))) == NULL ||
	 (ri->ifaces = malloc(sizeof(sc_ifaceinf_t *) * i)) == NULL)
	goto done;
      ri->ifacec = i;
      ri->maxrtrc = 0;
      ri->ip = 0;
      ri->ifaces[0] = ifi; ifi->ri = ri;
      for(i=1; i<ri->ifacec; i++)
	{
	  ri->ifaces[i] = slist_head_pop(ifi_list);
	  ri->ifaces[i]->ri = ri;
	}
      if(sc_routerinf_finish(ri) != 0)
	goto done;

      /* add router to the list of inferred routers */
      if(slist_tail_push(ri_list, ri) == NULL)
	goto done;
      ri = NULL;
    }
  rc = 0;
  slist_concat(ri_list_out, ri_list);

 done:
  if(ri != NULL)
    {
      if(ri->ifaces != NULL) free(ri->ifaces);
      free(ri);
    }
  if(ri_list != NULL)
    {
      while((ri = slist_head_pop(ri_list)) != NULL)
	{
	  free(ri->ifaces);
	  free(ri);
	}
      slist_free(ri_list);
    }
  if(ifi_list != NULL) slist_free(ifi_list);
  return rc;
}

/*
 * sc_regex_eval_ifi_build2
 *
 * given two sets of inferences on router interfaces, build a set of
 * inferences according the priority (p) of inferences in ifi1 and
 * ifi2.
 */
static int sc_regex_eval_ifi_build2(slist_t *ifi1_list, slist_t *ifi2_list,
				    int p, slist_t *ifi_list_out)
{
  slist_t *ifi_list = NULL;
  slist_node_t *sn1, *sn2;
  sc_ifaceinf_t *ifi1, *ifi2;
  int x, rc = -1;

  sn1 = slist_head_node(ifi1_list);
  sn2 = slist_head_node(ifi2_list);
  if((ifi_list = slist_alloc()) == NULL)
    goto done;

  while(sn1 != NULL)
    {
      ifi1 = slist_node_item(sn1); sn1 = slist_node_next(sn1);
      ifi2 = slist_node_item(sn2); sn2 = slist_node_next(sn2);
      assert(ifi1->ifd == ifi2->ifd);

      if(ifi2->regex != -1 && (ifi1->regex >= p || ifi1->regex == -1))
	{
	  /* handle the case where ifi2 supersedes ifi1 */
	  if(sc_ifaceinf_get(ifi_list,ifi2->ifd,ifi2->css,ifi2->ipm,p) == NULL)
	    goto done;
	}
      else if(ifi1->regex != -1)
	{
	  /* adjust the regex id if necessary */
	  x = ifi1->regex >= p ? ifi1->regex + 1 : ifi1->regex;
	  if(sc_ifaceinf_get(ifi_list,ifi1->ifd,ifi1->css,ifi1->ipm,x) == NULL)
	    goto done;
	}
      else
	{
	  if(sc_ifaceinf_get(ifi_list, ifi1->ifd, NULL, 0, -1) == NULL)
	    goto done;
	}
    }
  assert(sn2 == NULL);
  rc = 0;
  slist_concat(ifi_list_out, ifi_list);

 done:
  if(ifi_list != NULL)
    {
      slist_foreach(ifi_list, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
      slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
    }
  return rc;
}

static int sc_regex_eval_ifi_build(sc_regex_t *re, slist_t *ifi_list_out)
{
  sc_routerdom_t *rd;
  slist_node_t *sn;
  int i, x, rc = -1, ip;
  sc_ifacedom_t *ifd;
  sc_css_t *css = NULL;
  slist_t *ifi_list = NULL;
  sc_rework_t *rew = NULL;

  if((ifi_list = slist_alloc()) == NULL ||
     (rew = sc_rework_alloc(re)) == NULL)
    goto done;

  for(i=0; i<re->regexc; i++)
    {
      if((x = sc_rework_capcount(rew, i)) < 0)
	goto done;
      re->regexes[i]->capc = (uint32_t)x;
    }

  /* go through all the interfaces and determine router assignments */
  for(sn=slist_head_node(re->dom->routers); sn != NULL; sn=slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      for(i=0; i<rd->ifacec; i++)
	{
	  ifd = rd->ifaces[i];
	  if((x = sc_rework_match(rew, ifd->iface, &css)) < 0)
	    goto done;

	  ip = 0;
	  if(x == 1)
	    {
	      if(css != NULL)
		ip = sc_iface_ip_matched(ifd->iface, rew);
	      if(sc_ifaceinf_get(ifi_list, ifd, css, ip, rew->k) == NULL)
		goto done;
	      css = NULL;
	    }
	  else
	    {
	      if(sc_ifaceinf_get(ifi_list, ifd, NULL, ip, -1) == NULL)
		goto done;
	    }
	}
    }

  slist_concat(ifi_list_out, ifi_list);
  rc = 0;

 done:
  if(rew != NULL) sc_rework_free(rew);
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  return rc;
}

/*
 * sc_regex_eval_ifi_thin
 *
 * go through candidate interface inferences and remove any that are
 * identical to what the current working regex has.
 *
 * return the count of extractions made by cand_l at the end of the
 * thin process
 */
static int sc_regex_eval_ifi_thin(slist_t *ifi_work_l, slist_t *ifi_cand_l)
{
  slist_node_t *sn_work, *sn_cand;
  sc_ifaceinf_t *ifi_work, *ifi_cand;
  int c = 0;

  sn_cand = slist_head_node(ifi_cand_l);
  sn_work = slist_head_node(ifi_work_l);

  while(sn_cand != NULL)
    {
      ifi_work = slist_node_item(sn_work);
      ifi_cand = slist_node_item(sn_cand);

      assert(ifi_work->ifd == ifi_cand->ifd);

      /*
       * if the css is the same across regexes, clear out the
       * inference from cand_ifi so that it doesn't get counted as a
       * contribution from the candidate regex (the working regex
       * already had it covered)
       */
      if(ifi_cand->css != NULL && ifi_work->css != NULL &&
	 sc_css_css_cmp(ifi_cand->css, ifi_work->css) == 0)
	{
	  sc_css_free(ifi_cand->css); ifi_cand->css = NULL;
	  ifi_cand->ipm = 0;
	  ifi_cand->regex = -1;
	}

      if(ifi_cand->css != NULL)
	c++;

      sn_work = slist_node_next(sn_work);
      sn_cand = slist_node_next(sn_cand);
    }

  return c;
}

/*
 * sc_regex_eval_ri_sp
 *
 * the evaluation put a single interface of a router in its own
 * cluster.  is that a single positive or a false negative?  single
 * positive occurs on a multiple interface training router when other
 * interfaces from that training router are intentionally skipped, or
 * an IP address is matched.
 */
static int sc_regex_eval_ri_sp(sc_ifaceinf_t **ifimap, sc_routerdom_t *rd)
{
  int i, matchc = 0;
  sc_ifaceinf_t *ifi;

  if(rd->ifacec == 1)
    return 1;

  for(i=0; i<rd->ifacec; i++)
    {
      ifi = ifimap[rd->ifaces[i]->id-1];

      /*
       * there was another interface in the suffix on the router that
       * the regex did not match.  in the end, decide to count the
       * matched interface as a single positive.
       * if(ifi->regex == -1)
       *   return 0;
       */

      /*
       * if the interface was deliberately skipped, or we matched an
       * IP literal, then skip over -- do not count as something that
       * we ideally would have matched
       */
      if(ifi->css == NULL)
	continue;
      if(ifi->ipm != 0)
	continue;
      matchc++;
    }

  if(matchc == 1)
    return 1;
  return 0;
}

static void sc_regex_eval_tp_mask(sc_regex_t *re, sc_ifacedom_t *ifd)
{
  uint32_t x, i;

  assert(re->dom != NULL);
  assert(re->tp_mask != NULL);

  x = (ifd->id-1) / 32;
  i = (ifd->id-1) % 32;
  assert(x >= 0); assert(x < re->dom->tpmlen);
  re->tp_mask[x] |= (0x1 << i);

  return;
}

/*
 * sc_regex_eval_ri_score
 *
 * evaluate the infererences against the training data, storing results
 * in the regex scores.
 */
static int sc_regex_eval_ri_score(sc_regex_t *re, slist_t *ri_list)
{
  slist_node_t *sn;
  int tp, i, x, rc = -1, *remap = NULL;
  sc_routerdom_t *rd;
  sc_routerinf_t *ri = NULL;
  sc_ifaceinf_t **ifimap = NULL;
  uint32_t *rdmap = NULL;
  size_t len;

  if((remap = malloc(sizeof(int) * re->regexc)) == NULL ||
     (rdmap = malloc_zero(sizeof(uint32_t) * re->dom->rtmlen)) == NULL ||
     (ifimap = malloc(sizeof(sc_ifaceinf_t *) * re->dom->ifacec)) == NULL)
    goto done;

  /* figure out how many bits might be needed for the true positives mask */
  len = sizeof(uint32_t) * re->dom->tpmlen;
  if(re->tp_mask == NULL && (re->tp_mask = malloc_zero(len)) == NULL)
    goto done;

  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);

      for(i=0; i<ri->ifacec; i++)
	{
	  /* record how many times each regex was used */
	  if(ri->ifaces[i]->regex >= 0)
	    {
	      assert(ri->ifaces[i]->regex < re->regexc);
	      re->matchc++;
	      re->regexes[ri->ifaces[i]->regex]->matchc++;
	    }

	  /* tag each sc_ifacedom_t with an sc_ifaceinf_t */
	  ifimap[ri->ifaces[i]->ifd->id-1] = ri->ifaces[i];
	}
    }

  slist_qsort(ri_list, (slist_cmp_t)sc_routerinf_maxrtrc_cmp);
  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);

      /* no inferred name for the router */
      if(ri->ifaces[0]->css == NULL)
	{
	  assert(ri->ifacec == 1);

	  if(ri->ifaces[0]->regex != -1)
	    {
	      ri->ifaces[0]->class = '*';
	      continue;
	    }

	  /*
	   * if the regex didn't match but there were no aliases in the
	   * training data, don't count it as a false negative, but don't
	   * count it as a true positive either.
	   */
	  if(ri->ifaces[0]->ifd->rd->ifacec > 1)
	    {
	      re->fnu_c++;
	      ri->ifaces[0]->class = '~';
	    }
	  else
	    {
	      re->sn_c++;
	      ri->ifaces[0]->class = 'o';
	    }
	  continue;
	}

      /* count how many training routers are in this inferred router */
      x = 1; rd=ri->ifaces[0]->ifd->rd;
      for(i=1; i<ri->ifacec; i++)
	{
	  if(ri->ifaces[i]->ifd->rd != rd)
	    {
	      rd = ri->ifaces[i]->ifd->rd;
	      x++;
	    }
	}

      /*
       * already counted this router.
       * if the inferred router only has interfaces from that router,
       * these are false negatives.
       * otherwise, count all as false positives.
       */
      rd = ri->ifaces[0]->ifd->rd;
      if((rdmap[(rd->id-1)/32] & (0x1 << ((rd->id-1) % 32))) != 0)
	{
	  for(i=0; i<ri->ifacec; i++)
	    {
	      if(ri->ifaces[i]->ipm != 0)
		{
		  re->ip_c++;
		  ri->ifaces[i]->class = 'x';
		}
	      else if(x == 1)
		{
		  re->fne_c++;
		  ri->ifaces[i]->class = '-';
		}
	      else
		{
		  re->fp_c++;
		  ri->ifaces[i]->class = '!';
		}
	    }
	  continue;
	}

      /* this inferred router is made up a single training router */
      if(x == 1)
	{
	  /* if the inferred router has a single interface */
	  if(ri->ifacec == 1)
	    {
	      /* if the match is on an IP address string */
	      if(ri->ifaces[0]->ipm != 0)
		{
		  re->ip_c++;
		  ri->ifaces[0]->class = 'x';
		}
	      /* if the training router also has a single interface */
	      else if(sc_regex_eval_ri_sp(ifimap,ri->ifaces[0]->ifd->rd)== 1)
		{
		  re->sp_c++;
		  ri->ifaces[0]->class = '+';
		}
	      else
		{
		  re->fne_c++;
		  ri->ifaces[0]->class = '-';
		}
	      continue;
	    }

	  /* mark the router as counted */
	  rd = ri->ifaces[0]->ifd->rd;
	  rdmap[(rd->id-1)/32] |= (0x1 << ((rd->id-1) % 32));

	  /* true positives! */
	  tp = 0;
	  for(i=0; i<re->regexc; i++)
	    remap[i] = 0;
	  for(i=0; i<ri->ifacec; i++)
	    {
	      if(ri->ifaces[i]->ipm != 0 && ri->ip != 0)
		{
		  re->ip_c++;
		  ri->ifaces[i]->class = 'x';
		}
	      else
		{
		  tp++;
		  re->tp_c++;
		  ri->ifaces[i]->class = '+';
		  assert(ri->ifaces[i]->regex < re->regexc);
		  remap[ri->ifaces[i]->regex]++;
		  sc_regex_eval_tp_mask(re, ri->ifaces[i]->ifd);
		}
	    }
	  if(tp >= 2)
	    {
	      re->rt_c++;
	      re->namelen += sc_css_strlen(ri->ifaces[0]->css);
	      for(i=0; i<re->regexc; i++)
		if(remap[i] > 0)
		  re->regexes[i]->rt_c++;
	    }
	  continue;
	}
      assert(ri->maxrtrc < ri->ifacec);

      /*
       * if a majority of interfaces are from a single training router,
       * those are TP and the rest FP.
       */
      x = 1;
      rd = ri->ifaces[ri->maxrtrc]->ifd->rd;
      for(i=ri->maxrtrc+1; i<ri->ifacec; i++)
	{
	  if(ri->ifaces[i]->ifd->rd != rd)
	    break;
	  x++;
	}
      if(ri->maxrtrc > x)
	{
	  /* mark the router as counted */
	  rd = ri->ifaces[0]->ifd->rd;
	  rdmap[(rd->id-1)/32] |= (0x1 << ((rd->id-1) % 32));

	  tp = 0;
	  for(i=0; i<re->regexc; i++)
	    remap[i] = 0;
	  for(i=0; i<ri->maxrtrc; i++)
	    {
	      if(ri->ifaces[i]->ipm != 0 && ri->ip != 0)
		{
		  ri->ifaces[i]->class = 'x';
		  re->ip_c++;
		}
	      else
		{
		  tp++;
		  re->tp_c++;
		  ri->ifaces[i]->class = '+';
		  assert(ri->ifaces[i]->regex < re->regexc);
		  remap[ri->ifaces[i]->regex]++;
		  sc_regex_eval_tp_mask(re, ri->ifaces[i]->ifd);
		}
	    }
	  if(tp >= 2)
	    {
	      re->rt_c++;
	      re->namelen += sc_css_strlen(ri->ifaces[0]->css);
	      for(i=0; i<re->regexc; i++)
		if(remap[i] > 0)
		  re->regexes[i]->rt_c++;
	    }

	  for(i=ri->maxrtrc; i<ri->ifacec; i++)
	    {
	      if(ri->ifaces[i]->ipm != 0)
		{
		  ri->ifaces[i]->class = 'x';
		  re->ip_c++;
		}
	      else
		{
		  ri->ifaces[i]->class = '!';
		  re->fp_c++;
		}
	    }
	}
      else
	{
	  for(i=0; i<ri->ifacec; i++)
	    {
	      if(ri->ifaces[i]->ipm != 0)
		{
		  ri->ifaces[i]->class = 'x';
		  re->ip_c++;
		}
	      else
		{
		  ri->ifaces[i]->class = '!';
		  re->fp_c++;
		}
	    }
	}
    }

  rc = 0;

 done:
  if(rdmap != NULL) free(rdmap);
  if(remap != NULL) free(remap);
  if(ifimap != NULL) free(ifimap);
  return rc;
}

static int sc_regex_thin(sc_regex_t *re)
{
  sc_regexn_t **regexes = NULL;
  int i, j, mc = 0;

  /* nothing to do if every regex matched at least one thing */
  for(i=0; i<re->regexc; i++)
    if(re->regexes[i]->matchc > 0)
      mc++;
  if(mc == 0 || mc == re->regexc)
    return 0;

  if((regexes = malloc_zero(sizeof(sc_regexn_t *) * mc)) == NULL)
    return -1;
  j = 0;
  for(i=0; i<re->regexc; i++)
    {
      if(re->regexes[i]->matchc > 0)
	regexes[j++] = re->regexes[i];
      else
	sc_regexn_free(re->regexes[i]);
    }
  free(re->regexes);
  re->regexes = regexes;
  re->regexc = mc;
  return 0;
}

/*
 * sc_regex_issame
 *
 * determine if two different regexes with the same scores are because
 * the regexes are equivalent in all respects.
 */
static int sc_regex_issame(sc_regex_t *re1,slist_t *ifi1_list, sc_regex_t *re2)
{
  slist_t *ifi2_list = NULL;
  sc_ifaceinf_t *ifi1, *ifi2;
  slist_node_t *sn1, *sn2;
  int i, rc = -1;

  /* the regexes must apply to the same domain */
  assert(re1->dom == re2->dom);

  /* two regexes are the same if their strings are the same */
  if(sc_regex_str_cmp(re1, re2) == 0)
    return 1;

  /* the regexes must at least infer the same set of true positives */
  for(i=0; i<re1->dom->tpmlen; i++)
    if(re1->tp_mask[i] != re2->tp_mask[i])
      return 0;

  /* we use ifi1_list across calls to sc_regex_issame to cache inferences */
  if(slist_count(ifi1_list) == 0 &&
     sc_regex_eval_ifi_build(re1, ifi1_list) != 0)
    goto done;

  if((ifi2_list = slist_alloc()) == NULL ||
     sc_regex_eval_ifi_build(re2, ifi2_list) != 0)
    goto done;

  sn1 = slist_head_node(ifi1_list);
  sn2 = slist_head_node(ifi2_list);
  while(sn1 != NULL && sn2 != NULL)
    {
      ifi1 = slist_node_item(sn1);
      ifi2 = slist_node_item(sn2);
      assert(scamper_addr_cmp(ifi1->ifd->iface->addr,
			      ifi2->ifd->iface->addr) == 0);

      if((ifi1->css != NULL && ifi2->css == NULL) ||
	 (ifi1->css == NULL && ifi2->css != NULL) ||
	 (ifi2->css != NULL && sc_css_css_cmp(ifi1->css, ifi2->css) != 0))
	break;

      sn1 = slist_node_next(sn1);
      sn2 = slist_node_next(sn2);
    }

  if(sn1 == NULL && sn2 == NULL)
    rc = 1;
  else
    rc = 0;

 done:
  if(ifi2_list != NULL) slist_free_cb(ifi2_list,(slist_free_t)sc_ifaceinf_free);
  return rc;
}

static int sc_regex_eval_ifi_score(sc_regex_t *re, slist_t *ifi_list)
{
  slist_t *ri_list = NULL;
  int rc = 0;

  sc_regex_score_reset(re);
  if((ri_list = slist_alloc()) == NULL ||
     sc_regex_eval_ri_build(ifi_list, ri_list) != 0 ||
     sc_regex_eval_ri_score(re, ri_list) != 0)
    rc = -1;

  if(ri_list != NULL)
    {
      slist_foreach(ri_list, (slist_foreach_t)sc_routerinf_ifaces_null, NULL);
      slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
    }

  return rc;
}

static int sc_regex_eval(sc_regex_t *re, slist_t *out)
{
  slist_t *ifi_list = NULL, *ri_list = NULL;
  int rc = -1;

  assert(re->dom != NULL);
  sc_regex_score_reset(re);

  if((ifi_list = slist_alloc()) == NULL ||
     sc_regex_eval_ifi_build(re, ifi_list) != 0)
    goto done;
  if(slist_count(ifi_list) == 0)
    {
      rc = 0;
      goto done;
    }

  /* build router structures using the assignments */
  if((ri_list = slist_alloc()) == NULL)
    goto done;
  if(sc_regex_eval_ri_build(ifi_list, ri_list) != 0)
    goto done;
  slist_free(ifi_list); ifi_list = NULL;

  /* score the router inferences */
  if(sc_regex_eval_ri_score(re, ri_list) != 0)
    goto done;

  if(out != NULL)
    slist_concat(out, ri_list);
  rc = 0;

 done:
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  return rc;
}

/*
 * sc_regex_permute
 *
 * given a base regex (work) and inferences derived from that regex
 * (work_ifi), and a second regex (cand) which we are considering
 * permuting into a regex containing both work and cand, compute the
 * combinations.
 */
static int sc_regex_permute(sc_regex_t *work, slist_t *work_ifi,
			    sc_regex_t *cand, slist_t *set)
{
  slist_t *cand_ifi = NULL, *ifi = NULL, *ri_list = NULL;
  sc_regex_t *re = NULL;
  int i, rc = -1;

  /* don't add this regex if its already in the set */
  for(i=0; i<work->regexc; i++)
    if(strcmp(work->regexes[i]->str, cand->regexes[0]->str) == 0)
      return 0;

  if((ifi = slist_alloc()) == NULL || (ri_list = slist_alloc()) == NULL ||
     (cand_ifi = slist_alloc()) == NULL ||
     sc_regex_eval_ifi_build(cand, cand_ifi) != 0)
    goto done;

  /*
   * remove inferences from the candidate regex that are the same as those
   * made by the working regex so that they do not get counted against the
   * candidate.
   */
  if(sc_regex_eval_ifi_thin(work_ifi, cand_ifi) == 0)
    {
      rc = 0;
      goto done;
    }

  for(i=0; i<=work->regexc; i++)
    {
      if((re = sc_regex_plus1(work, cand->regexes[0], i)) == NULL)
	goto done;
      re->score = work->score + cand->score;

      /* build a new set of inferences */
      if(sc_regex_eval_ifi_build2(work_ifi, cand_ifi, i, ifi) != 0)
	goto done;
      if(sc_regex_eval_ri_build(ifi, ri_list) != 0)
	goto done;
      if(sc_regex_eval_ri_score(re, ri_list) != 0)
	goto done;

      /* keep regex around */
      if(slist_tail_push(set, re) == NULL)
	goto done;
      re = NULL;

      slist_foreach(ifi, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
      slist_empty(ifi);
      slist_empty_cb(ri_list, (slist_free_t)sc_routerinf_free);
    }

  rc = 0;

 done:
  if(ifi != NULL)
    {
      if(ri_list != NULL && slist_count(ri_list) > 0)
	{
	  slist_foreach(ifi, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
	  slist_free(ifi);
	}
      else slist_free_cb(ifi, (slist_free_t)sc_ifaceinf_free);
    }
  if(cand_ifi != NULL)
    slist_free_cb(cand_ifi, (slist_free_t)sc_ifaceinf_free);
  if(ri_list != NULL)
    slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(re != NULL)
    sc_regex_free(re);
  return rc;
}

static void sc_regex_fn_free(sc_regex_fn_t *refn)
{
  free(refn);
  return;
}

static int sc_regex_fn_score_rank_cmp(sc_regex_fn_t *a, sc_regex_fn_t *b)
{
  return sc_regex_score_rank_cmp(a->re, b->re);
}

static int sc_regex_fn_base_rank_cmp(sc_regex_fn_t *a, sc_regex_fn_t *b)
{
  return sc_regex_score_rank_cmp(a->base, b->base);
}

static void sc_domain_fn_free(sc_domain_fn_t *domfn)
{
  if(domfn == NULL)
    return;
  if(domfn->work != NULL)
    slist_free_cb(domfn->work, (slist_free_t)sc_regex_fn_free);
  if(domfn->base != NULL)
    slist_free_cb(domfn->base, (slist_free_t)sc_regex_fn_free);
  free(domfn);
  return;
}

static splaytree_t *sc_routerdom_css_tree(const slist_t *routers)
{
  splaytree_t *rd_css_tree = NULL;
  sc_routerdom_t *rd;
  slist_node_t *sn;
  sc_css_t *css = NULL;

  /* build a tree of all inferred sc_routerdom_t names */
  if((rd_css_tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL)
    goto err;
  for(sn=slist_head_node(routers); sn != NULL; sn=slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      if(rd->css == NULL)
	continue;

      if((css = splaytree_find(rd_css_tree, rd->css)) != NULL)
	{
	  css->count++;
	  css = NULL;
	  continue;
	}

      if((css = sc_css_dup(rd->css)) == NULL)
	goto err;
      css->count = 1;
      if(splaytree_insert(rd_css_tree, css) == NULL)
	goto err;
    }

  return rd_css_tree;

 err:
  if(css != NULL) sc_css_free(css);
  if(rd_css_tree != NULL) splaytree_free(rd_css_tree, (splaytree_free_t)sc_css_free);
  return NULL;
}

static int sc_routerdom_lcs(sc_routerdom_t *rd)
{
  splaytree_t *tree = NULL;
  slist_t *list = NULL;
  slist_node_t *sn;
  sc_ifacedom_t *ifd;
  sc_css_t *css = NULL;
  int i, rc = -1;

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL ||
     (list = slist_alloc()) == NULL)
    goto done;

  /* figure out the candidate longest common substrings */
  for(i=0; i<rd->ifacec; i++)
    {
      ifd = rd->ifaces[i];
      if(ifd->iface->ip_s == 0 && ifd->label[ifd->iface->ip_e+1] == '\0')
	continue;

      if(sc_ifacedom_css(ifd, &css, 1) != 0)
	goto done;
      if(css == NULL)
	continue;
      if(sc_css_get(tree, css) == NULL)
	goto done;
      sc_css_free(css); css = NULL;
    }

  if(sc_css_reduce(tree, 1, 2) != 0) /* trim on non-alnum, min length 2 */
    goto done;

  /* count how many interfaces match */
  splaytree_inorder(tree, tree_to_slist, list);
  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
    {
      css = slist_node_item(sn);
      for(i=0; i<rd->ifacec; i++)
	if(sc_css_match(css, rd->ifaces[i]->label, NULL, 1) == 1)
	  css->count++;
    }

  if(slist_count(list) > 0)
    {
      slist_qsort(list, (slist_cmp_t)sc_css_count_cmp);
      css = slist_head_item(list);
      if(css->count > 1 && (rd->css = sc_css_dup(css)) == NULL)
	goto done;
    }

  rc = 0;

 done:
  if(tree != NULL) splaytree_free(tree, (splaytree_free_t)sc_css_free);
  if(list != NULL) slist_free(list);
  return rc;
}

static void sc_routerdom_lcs_thread(sc_routerdom_t *rd)
{
  sc_routerdom_lcs(rd);
  return;
}

static void sc_routerdom_free(sc_routerdom_t *rd)
{
  int i;
  if(rd->ifaces != NULL)
    {
      for(i=0; i<rd->ifacec; i++)
	if(rd->ifaces[i] != NULL)
	  sc_ifacedom_free(rd->ifaces[i]);
      free(rd->ifaces);
    }
  if(rd->css != NULL) sc_css_free(rd->css);
  free(rd);
  return;
}

static int sc_regex_del_ppv_ok(const sc_regex_t *cur, const sc_regex_t *can)
{
  int cur_ppv, del_ppv, del_tp, del_fp;

  if(cur->tp_c >= can->tp_c && cur->fp_c <= can->fp_c)
    return 0;
  if(cur->tp_c <= can->tp_c && cur->fp_c >= can->fp_c)
    return 1;

  assert(can->tp_c > cur->tp_c);
  assert(can->fp_c > cur->fp_c);
  del_tp = can->tp_c - cur->tp_c;
  del_fp = can->fp_c - cur->fp_c;
  del_ppv = (del_tp * 1000) / (del_tp + del_fp);
  cur_ppv = (cur->tp_c * 1000) / (cur->tp_c + cur->fp_c);
  if(del_ppv < cur_ppv && cur_ppv - del_ppv > 100 && del_fp != 1)
    return 0;

  return 1;
}

static sc_regex_t *sc_domain_bestre(sc_domain_t *dom)
{
  int best_tpa, best_ppv, best_len;
  int re_ppv, re_tpa, re_len;
  int diff_tpa, diff_tpa_r;
  int del_ppv, del_tp, del_fp;
  sc_regex_t *re, *best;
  slist_node_t *sn;

  if(slist_count(dom->regexes) < 1)
    return NULL;

  slist_qsort(dom->regexes, (slist_cmp_t)sc_regex_score_rank_cmp);
  best = slist_head_item(dom->regexes);
  best_tpa = sc_regex_score_tpa(best);
  best_len = sc_regex_str_len(best);

  if(best->tp_c != 0 && best->fp_c != 0)
    best_ppv = (best->tp_c * 1000) / (best->tp_c + best->fp_c);
  else
    best_ppv = 0;

  for(sn=slist_head_node(dom->regexes); sn != NULL; sn=slist_node_next(sn))
    {
      re = slist_node_item(sn);
      if(re == best)
	continue;
      if(re->tp_c == 0 && re->fp_c == 0)
	continue;
      if((re_tpa = sc_regex_score_tpa(re)) < 1)
	break;

      /*
       * this is the same logic we apply in sc_regex_del_ppv_ok
       * XXX: what happens when best has more TPs and more FPs?
       */
      if(re->tp_c > best->tp_c && re->fp_c > best->fp_c)
        {
          del_tp = re->tp_c - best->tp_c;
          del_fp = re->fp_c - best->fp_c;
          del_ppv = (del_tp * 1000) / (del_tp + del_fp);
          if(del_ppv < best_ppv && best_ppv - del_ppv > 100 && del_fp != 1)
            continue;
        }

      re_len = sc_regex_str_len(re);
      diff_tpa = best_tpa - re_tpa;
      diff_tpa_r = (diff_tpa * 1000) / re_tpa;

      /*
       * if the best regex has more TPs and more FPs than a candidate
       * regex down the list, the TPA difference is less than 4%, and
       * the delta ppv from the candidate regex to the current best
       * regex is poor, then replace the current best regex.
       */
      if(best->regexc == re->regexc && diff_tpa_r <= 40 &&
	 best->tp_c > re->tp_c && best->fp_c > re->fp_c)
	{
	  del_tp = best->tp_c - re->tp_c;
	  del_fp = best->fp_c - re->fp_c;
	  del_ppv = (del_tp * 1000) / (del_tp + del_fp);
	  re_ppv = (re->tp_c * 1000) / (re->tp_c + re->fp_c);
	  if(del_ppv < re_ppv && re_ppv - del_ppv > 100 && del_fp != 1)
	    {
	      best = re;
	      best_tpa = sc_regex_score_tpa(best);
	      best_len = sc_regex_str_len(best);
	      best_ppv = (best->tp_c * 1000) / (best->tp_c + best->fp_c);
	      continue;
	    }
	}

      if((best->regexc > re->regexc || best_len > re_len * 4) &&
	 (diff_tpa_r <= 40 ||
	  (diff_tpa == 2 && best->tp_c > re->tp_c && best->tp_c - re->tp_c == 1)))
	{
	  best = re;
	  best_tpa = sc_regex_score_tpa(best);
	  best_len = sc_regex_str_len(best);
	  best_ppv = (best->tp_c * 1000) / (best->tp_c + best->fp_c);
	}
    }

  return best;
}

static int sc_domain_lock(sc_domain_t *dom)
{
#ifdef HAVE_PTHREAD
  if(pthread_mutex_lock(&dom->mutex) != 0)
    return -1;
#endif
  return 0;
}

static void sc_domain_unlock(sc_domain_t *dom)
{
#ifdef HAVE_PTHREAD
  pthread_mutex_unlock(&dom->mutex);
#endif
  return;
}

static int sc_domain_cmp(const sc_domain_t *a, const sc_domain_t *b)
{
  return strcasecmp(a->domain, b->domain);
}

static void sc_domain_free(sc_domain_t *dom)
{
  sc_ifacedom_t *ifd;
  if(dom->domain != NULL)
    free(dom->domain);
  if(dom->escape != NULL)
    free(dom->escape);
  if(dom->routers != NULL)
    slist_free_cb(dom->routers, (slist_free_t)sc_routerdom_free);
  if(dom->regexes != NULL)
    slist_free_cb(dom->regexes, (slist_free_t)sc_regex_free);
  if(dom->appl != NULL)
    {
      while((ifd = slist_head_pop(dom->appl)) != NULL)
	{
	  if(ifd->iface != NULL) sc_iface_free(ifd->iface);
	  sc_ifacedom_free(ifd);
	}
      slist_free(dom->appl);
    }
#ifdef HAVE_PTHREAD
  if(dom->mutex_o != 0)
    pthread_mutex_destroy(&dom->mutex);
#endif
  free(dom);
  return;
}

static sc_domain_t *sc_domain_alloc(const char *domain)
{
  sc_domain_t *dom = NULL;
  size_t x, off;

  if((dom = malloc_zero(sizeof(sc_domain_t))) == NULL ||
     (dom->domain = strdup(domain)) == NULL ||
     (dom->regexes = slist_alloc()) == NULL ||
     (dom->appl = slist_alloc()) == NULL ||
     (dom->routers = slist_alloc()) == NULL)
    goto err;

  /* escape the domain suffix */
  off = 0;
  for(x=0; domain[x] != '\0'; x++)
    {
      if(domain[x] == '.')
	off++;
      off++;
    }
  off++;
  if((dom->escape = malloc(off)) == NULL)
    goto err;
  off = 0;
  for(x=0; domain[x] != '\0'; x++)
    {
      if(domain[x] == '.')
	dom->escape[off++] = '\\';
      dom->escape[off++] = domain[x];
    }
  dom->escape[off] = '\0';
  dom->escapel = off;

#ifdef HAVE_PTHREAD
  if(pthread_mutex_init(&dom->mutex, NULL) != 0)
    goto err;
  dom->mutex_o = 1;
#endif

  return dom;

 err:
  if(dom != NULL) sc_domain_free(dom);
  return NULL;
}

static sc_domain_t *sc_domain_find(const char *domain)
{
  sc_domain_t fm; fm.domain = (char *)domain;
  return splaytree_find(domain_tree, &fm);
}

static sc_domain_t *sc_domain_get(const char *domain)
{
  sc_domain_t *dom;

  if((dom = sc_domain_find(domain)) != NULL)
    return dom;
  if((dom = sc_domain_alloc(domain)) == NULL)
    return NULL;
  if(splaytree_insert(domain_tree, dom) == NULL)
    {
      sc_domain_free(dom);
      return NULL;
    }

  return dom;
}

static int sc_domain_finish(sc_domain_t *dom)
{
  uint32_t rtc = slist_count(dom->routers);
  dom->tpmlen = dom->ifacec / 32 + ((dom->ifacec % 32 == 0) ? 0 : 1);
  dom->rtmlen = rtc / 32 + ((rtc % 32 == 0) ? 0 : 1);
  return 0;
}

static int label_cmp(const char *ap, const char *bp)
{
  int j = 0;
  for(;;)
    {
      if((ap[j] == '.' || ap[j] == '\0') && (bp[j] == '.' || bp[j] == '\0'))
	break;
      if(ap[j] == '.' || ap[j] == '\0')
	return -1;
      if(bp[j] == '.' || bp[j] == '\0')
	return  1;
      if(ap[j] < bp[j])
	return -1;
      if(ap[j] > bp[j])
	return  1;
      j++;
    }
  return 0;
}

static int suffix_file_line_cmp(const char *a, const char *b)
{
  const char *ap, *bp;
  int ac = dotcount(a);
  int bc = dotcount(b);
  int i, rc;

  if(ac < bc) return -1;
  if(ac > bc) return  1;

  if(ac == 0) return strcmp(a, b);

  for(i=0; i<=bc; i++)
    {
      ap = label_get(a, i);
      bp = label_get(b, i);
      if((rc = label_cmp(ap, bp)) != 0)
	return rc;
    }

  assert(strcmp(a, b) == 0);
  return 0;
}

static int process_suffix(slist_t *list)
{
  slist_t *tmp;
  sc_suffix_t *se;
  slist_node_t *sn;
  char *suffix;
  int x;

  /*
   * sort the list from shortest to longest suffix, ordered by domain
   * name from TLD.
   */
  slist_qsort(list, (slist_cmp_t)suffix_file_line_cmp);

  /* to start with, get the root prefixes */
  if((tmp = slist_alloc()) == NULL)
    goto err;
  if((suffix_root = malloc_zero(sizeof(sc_suffix_t))) == NULL)
    goto err;
  for(;;)
    {
      if((sn = slist_head_node(list)) == NULL)
	break;
      suffix = slist_node_item(sn);
      if(dotcount(suffix) != 0)
	break;
      slist_head_pop(list);
      slist_tail_push(tmp, suffix);
    }
  if((x = slist_count(tmp)) > 0)
    {
      if((suffix_root->suffixes=malloc_zero(x*sizeof(sc_suffix_t *))) == NULL)
	goto err;
      x = 0;
      while((suffix = slist_head_pop(tmp)) != NULL)
	{
	  if((se = malloc_zero(sizeof(sc_suffix_t))) == NULL)
	    goto err;

	  se->label = suffix;
	  se->end = 1;

	  suffix_root->suffixes[x++] = se;
	}
      suffix_root->suffixc = x;
    }
  slist_free(tmp);

  /* now work through strings with at least two labels */
  while((suffix = slist_head_pop(list)) != NULL)
    {
      if(sc_suffix_get(suffix) == NULL)
	goto err;
      free(suffix);
    }

  if((se = sc_suffix_get("arpa")) != NULL)
    se->end = -1;

  return 0;

 err:
  return -1;
}

static int isliteral(int x)
{
  assert(x >= 0 && x <= 4);
  if(x == 0 || x == 1 || x == 4)
    return 0;
  return 1;
}

static int iscapture(int x)
{
  assert(x >= 0 && x <= 4);
  if(x == 1 || x == 3)
    return 1;
  return 0;
}

static int isip(int x)
{
  assert(x >= 0 && x <= 4);
  if(x == 4)
    return 1;
  return 0;
}

static int sc_regex_build_skip(const char *name, int j, char *buf, size_t len,
			       size_t *to)
{
  char tmp[8];
  int r;

  while(isalnum(name[j]) == 0 && name[j] != '\0')
    {
      if((r = re_escape(tmp, sizeof(tmp), name[j])) == 0)
	return -1;

      /* string_concat(buf, len, to, "%s", tmp); */
      if(len - *to < r + 1)
	return -1;
      memcpy(buf + *to, tmp, r + 1);
      *to = *to + r;

      j++;
    }
  return j;
}

/*
 * sc_regex_build_0
 *
 * if the end of the unspecified content ends with a non alnum, and this
 * separator is not found within the boundaries, then output a match
 * that is anything without that separator.
 *
 * because this segment of the regex only says that a specific character
 * class is not allowed, the score only increases by 1.
 */
static size_t sc_regex_build_0(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0;
  char tmp[8];
  char sep;
  int j, r, x = rb->x;

  /* does not apply to literals or IP address portions */
  if(isliteral(bits[x]) != 0 || isip(bits[x]) != 0)
    return 0;

  /* does not apply if there is no dot or dash separator at the end */
  sep = name[bits[x+2]+1];
  if(sep == '\0')
    sep = '.';
  if(isalnum(sep) != 0)
    return 0;

  /* skip over any dashes and dots at the start of the string */
  if((j = sc_regex_build_skip(name, rb->o, buf, len, &to)) > bits[x+2])
    return 0;

  /* determine if separator at end of string is within */
  if(char_within(name, j, bits[x+2], sep) != 0)
    return 0;
  if((r = re_escape(tmp, sizeof(tmp), sep)) == 0)
    return 0;

  /* string_concat(buf, len, &to, "[^%s]+", tmp); */
  if(len < 4 + r + 1)
    return 0;
  buf[to++] = '['; buf[to++] = '^';
  memcpy(buf+to, tmp, r); to += r;
  buf[to++] = ']'; buf[to++] = '+';
  buf[to] = '\0';

  *o = bits[x+2] + 1;
  *score += 1;
  return to;
}

/*
 * sc_regex_build_1
 *
 * if the start of the unspecified content starts with a non alnum, and
 * this separator is not found within the boundaries, then output a match
 * that is anything without that separator.
 *
 * because this segment of the regex only says that a specific character
 * class is not allowed, the score only increases by 1 for each character
 * class exclusion
 */
static size_t sc_regex_build_1(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0;
  char tmp[8];
  char sep;
  int x = rb->x, j, r, last_sep = -1;

  /* does not apply to literals or IP address portions */
  if(isliteral(bits[x]) != 0 || isip(bits[x]) != 0)
    return 0;

  /* cannot be working at the very start of the string */
  if(rb->o == 0)
    return 0;

  /* needs to be a separator */
  sep = name[rb->o-1];
  if(isalnum(sep) != 0)
    return 0;

  /*
   * go through segment, emitting character class exclusions each time
   * we come across an instance of the separator
   */
  j = rb->o;
  while(j <= bits[x+2])
    {
      if(name[j] == sep)
	{
	  if((r = re_escape(tmp, sizeof(tmp), sep)) == 0)
	    return 0;

	  /* string_concat(buf, len, &to, "[^%s]+", tmp); */
	  if(len - to < 4 + r + 1)
	    return 0;
	  buf[to++] = '['; buf[to++] = '^';
	  memcpy(buf+to, tmp, r); to += r;
	  buf[to++] = ']'; buf[to++] = '+';

	  *score += 1;
	  while(name[j] == sep && j <= bits[x+2])
	    {
	      if((r = re_escape(tmp, sizeof(tmp), name[j])) == 0)
		return 0;

	      /* string_concat(buf, len, &to, "%s", tmp);*/
	      if(len - to < r + 1)
		return 0;
	      memcpy(buf+to, tmp, r); to += r;

	      j++;
	    }
	  last_sep = j;
	}
      else j++;
    }

  if(last_sep != bits[x+2]+1)
    {
      if((r = re_escape(tmp, sizeof(tmp), sep)) == 0)
	return 0;

      /* string_concat(buf, len, &to, "[^%s]+", tmp); */
      if(len - to < 4 + r + 1)
	return 0;
      buf[to++] = '['; buf[to++] = '^';
      memcpy(buf+to, tmp, r); to += r;
      buf[to++] = ']'; buf[to++] = '+';

      *score += 1;
    }
  *o = bits[x+2] + 1;

  buf[to] = '\0';
  return to;
}

/*
 * sc_regex_build_2
 *
 * use .+ if we haven't already.
 *
 * the score does not increase.
 */
static size_t sc_regex_build_2(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0;
  int x = rb->x;

  /* can only use .+ once */
  if(rb->any != 0)
    return 0;

  /* does not apply at the beginning of a string without an anchor */
  if(rb->off == 0 && p->dom != NULL)
    return 0;

  /* does not apply to literals or IP addresses */
  if(isliteral(bits[x]) != 0 || isip(bits[x]) != 0)
    return 0;

  /* string_concat(buf, len, &to, ".+"); */
  if(len < 3)
    return 0;
  buf[to++] = '.'; buf[to++] = '+';
  buf[to] = '\0';

  *o = bits[x+2] + 1;
  return to;
}

/*
 * sc_regex_build_3
 *
 * build a component that uses separators to specify format of string
 *
 * the score increases by 1 for each character class exclusion embedded.
 */
static size_t sc_regex_build_3(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0;
  char tmp[8];
  char sep;
  int x = rb->x, j, r, last_sep = -1;

  /*
   * RB_FIRST_PUNC_END will build what this routine would have, so no
   * need to duplicate its work here
   */
  if(rb->o != bits[x+1])
    return 0;

  /* does not apply to literals or IP address portions */
  if(isliteral(bits[x]) != 0 || isip(bits[x]) != 0)
    return 0;

  /* skip over any dashes and dots at the start of the string */
  if((j = sc_regex_build_skip(name, bits[x+1], buf, len, &to)) > bits[x+2])
    return 0;

  /* according to arrangement of separators observed */
  while(j <= bits[x+2]+1)
    {
      if(isalnum(name[j]) == 0)
	{
	  if(name[j] == '\0')
	    sep = '.';
	  else
	    sep = name[j];
	  if((r = re_escape(tmp, sizeof(tmp), sep)) == 0)
	    return 0;
	  /* string_concat(buf,len,&to, "[^%s]+", tmp); */
	  if(len - to < 4 + r + 1)
	    return 0;
	  buf[to++] = '['; buf[to++] = '^';
	  memcpy(buf+to, tmp, r); to += r;
	  buf[to++] = ']'; buf[to++] = '+';

	  while(j != bits[x+2]+1 && isalnum(name[j]) == 0)
	    {
	      if((r = re_escape(tmp, sizeof(tmp), name[j])) == 0)
		return 0;

	      /* string_concat(buf, len, &to, "%s", tmp);*/
	      if(len - to < r + 1)
		return 0;
	      memcpy(buf+to, tmp, r); to += r;

	      j++;
	    }

	  /* keep track of where the last [^X]+ was used */
	  last_sep = j;

	  *score += 1;
	}
      j++;
    }

  /* if there is a part of the input string not covered then skip */
  if(last_sep != bits[x+2]+1)
    return 0;

  buf[to] = '\0';
  *o = bits[x+2] + 1;
  return to;
}

/*
 * sc_regex_build_4
 *
 * embed a literal
 *
 * the score increases by 4 for each character
 */
static size_t sc_regex_build_4(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0;
  char tmp[8];
  int x = rb->x, j, r;

  /* do not allow partial starts for now */
  if(rb->o != bits[x+1])
    return 0;

  /* only applies to literals */
  if(isliteral(bits[x]) == 0)
    return 0;

  for(j=bits[x+1]; j <= bits[x+2]; j++)
    {
      if((r = re_escape(tmp, sizeof(tmp), name[j])) == 0)
	return 0;

      /* string_concat(buf, len, &to, "%s", tmp); */
      if(len - to < r + 1)
	return 0;
      memcpy(buf+to, tmp, r); to += r;
      *score += 4;
    }

  buf[to] = '\0';
  *o = bits[x+2] + 1;
  return to;
}

/*
 * sc_regex_build_5_v4
 *
 * embed an IPv4 address literal
 *
 * the score increases by 3 for each portion broken by a non alnum
 */
static size_t sc_regex_build_5_v4(const char *name, const sc_rebuild_p_t *p,
				  const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  const char *ptr;
  char tmp[8];
  size_t to = 0;
  int x = rb->x, r;

  /* do not allow partial starts for now */
  if(rb->o != bits[x+1])
    return 0;

  /* only applies to IP literals */
  if(isip(bits[x]) == 0)
    return 0;

  ptr = name + bits[x+1];
  while(ptr < name + bits[x+2] + 1)
    {
      /* string_concat(buf, len, &to, "\\d+"); */
      if(len - to < 4)
	return 0;
      buf[to++] = '\\'; buf[to++] = 'd'; buf[to++] = '+';

      while(isdigit(*ptr) != 0)
	ptr++;
      while(isdigit(*ptr) == 0 && ptr < name + bits[x+2])
	{
	  if((r = re_escape(tmp, sizeof(tmp), *ptr)) == 0)
	    return 0;

	  /* string_concat(buf, len, &to, "%s", tmp); */
	  if(len - to < r + 1)
	    return 0;
	  memcpy(buf+to, tmp, r); to += r;

	  ptr++;
	}
      *score += 3;
    }

  buf[to] = '\0';
  *o = bits[x+2] + 1;
  return to;
}

/*
 * sc_regex_build_5_v6
 *
 * embed an IPv6 address literal
 *
 * the score increases by 3 for each portion broken by a non alnum
 */
static size_t sc_regex_build_5_v6(const char *name, const sc_rebuild_p_t *p,
				  const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  const char *ptr;
  char tmp[8];
  size_t to = 0;
  int x = rb->x, r;

  /* do not allow partial starts for now */
  if(rb->o != bits[x+1])
    return 0;

  /* only applies to IP literals */
  if(isip(bits[x]) == 0)
    return 0;

  ptr = name + bits[x+1];
  while(ptr < name + bits[x+2] + 1)
    {
      /* string_concat(buf, len, &to, "[a-f\\d]+"); */
      if(len - to < 9)
	return 0;
      buf[to++] = '['; buf[to++] = 'a'; buf[to++] = '-'; buf[to++] = 'f';
      buf[to++] = '\\'; buf[to++] = 'd'; buf[to++] = ']'; buf[to++] = '+';

      while(ishex(*ptr) != 0)
	ptr++;
      while(ishex(*ptr) == 0 && ptr < name + bits[x+2])
	{
	  if((r = re_escape(tmp, sizeof(tmp), *ptr)) == 0)
	    return 0;

	  /* string_concat(buf, len, &to, "%s", tmp); */
	  if(len - to < r + 1)
	    return 0;
	  memcpy(buf+to, tmp, r); to += r;

	  ptr++;
	}
      *score += 3;
    }

  buf[to] = '\0';
  *o = bits[x+2] + 1;
  return to;
}

/*
 * sc_regex_build_5
 *
 * embed an IP address literal
 */
static size_t sc_regex_build_5(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  if(ip_v == 4)
    return sc_regex_build_5_v4(name, p, rb, score, o);
  return sc_regex_build_5_v6(name, p, rb, score, o);
}

/*
 * sc_regex_build_6
 *
 * if the part of the string we are concerned with contains only digits,
 * then output \d+.
 *
 * the score increases by 3 as this is a specific formation.
 */
static size_t sc_regex_build_6(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0;
  int digit = 0, j, r, x = rb->x;
  char tmp[8];

  /* do not allow partial starts for now */
  if(rb->o != bits[x+1])
    return 0;

  /* does not apply to literals or IP address portions */
  if(isliteral(bits[x]) != 0 || isip(bits[x]) != 0)
    return 0;

  /* skip over any dashes and dots at the start of the string */
  if((j = sc_regex_build_skip(name, bits[x+1], buf, len, &to)) > bits[x+2])
    return 0;

  /* does the string begin with a sequence of digits? */
  while(j <= bits[x+2])
    {
      if(isdigit(name[j]) == 0)
	break;
      digit++;
      j++;
    }

  /* if digits, concatenate and score */
  if(digit == 0)
    return 0;

  /* string_concat(buf, len, &to, "\\d+"); */
  *score += 3;
  if(len - to < 4)
    return 0;
  buf[to++] = '\\'; buf[to++] = 'd'; buf[to++] = '+';

  /* end with punctuation */
  while(j <= bits[x+2])
    {
      if(name[j] == '\0')
	break;
      if(isalnum(name[j]) != 0)
	return 0;
      if((r = re_escape(tmp, sizeof(tmp), name[j])) == 0)
	return 0;
      /* string_concat(buf, len, &to, "%s", tmp); */
      if(len - to < r + 1)
	return 0;
      memcpy(buf+to, tmp, r); to += r;

      j++;
    }

  buf[to] = '\0';
  *o = bits[x+2] + 1;
  return to;
}

/*
 * sc_regex_build_7
 *
 * output separator segment but only until the end of the next segment.
 *
 * the score increases by 1 because it embeds a single character class
 * exclusion.
 */
static size_t sc_regex_build_7(const char *name, const sc_rebuild_p_t *p,
			       const sc_rebuild_t *rb, int *score, int *o)
{
  const int *bits = p->bits;
  char *buf = p->buf;
  size_t len = p->len;
  size_t to = 0;
  char tmp[8];
  int j, r, x = rb->x;

  /* does not apply to literals or IP address portions */
  if(isliteral(bits[x]) != 0 || isip(bits[x]) != 0)
    return 0;

  /* skip over any dashes and dots at the start of the string */
  if((j = sc_regex_build_skip(name, rb->o, buf, len, &to)) > bits[x+2])
    return 0;

  /* find the next separator in this portion of the string */
  while(j <= bits[x+2]+1)
    {
      if(isalnum(name[j]) == 0)
	break;
      j++;
    }

  /* if the next separator isn't until after the end of the component, skip */
  if(j > bits[x+2]+1)
    return 0;

  /* embed the regex component */
  if((r = re_escape(tmp, sizeof(tmp), name[j] == '\0' ? '.' :  name[j])) == 0)
    return 0;

  /* string_concat(buf, len, &to, "[^%s]+", tmp); */
  if(len - to < 4 + r + 1)
    return 0;
  buf[to++] = '['; buf[to++] = '^';
  memcpy(buf+to, tmp, r); to += r;
  buf[to++] = ']'; buf[to++] = '+';
  buf[to] = '\0';

  *score += 1;
  *o = j;
  return to;
}

static sc_rebuild_t *sc_rebuild_push(slist_t *list, char *buf, size_t off,
				     int score, int f, int x, int o,
				     int any, int capc)
{
  sc_rebuild_t *rb;

  if((rb = malloc(sizeof(sc_rebuild_t))) == NULL ||
     slist_head_push(list, rb) == NULL)
    {
      if(rb != NULL) free(rb);
      return NULL;
    }
  if(off > 0)
    memcpy(rb->buf, buf, off);
  rb->off = off;
  rb->score = score;
  rb->f = f;
  rb->x = x;
  rb->o = o;
  rb->any = any;
  rb->capc = capc;
  return rb;
}

#define RB_BASE \
  (RB_SEG_PUNC_START | RB_SEG_PUNC_END | RB_SEG_ANY | RB_SEG_PUNC)

#define RB_SEG_PUNC_START 0x0001
#define RB_SEG_PUNC_END   0x0002
#define RB_SEG_ANY        0x0004
#define RB_SEG_PUNC       0x0008
#define RB_SEG_LITERAL    0x0010
#define RB_SEG_LITERAL_IP 0x0020
#define RB_SEG_DIGIT      0x0040
#define RB_FIRST_PUNC_END 0x0080

/*
 * sc_regex_build
 *
 * given a string (in name) and instructions (in bits/bitc) construct
 * regular expressions that meet the instructions.  if a suffix is supplied
 * (in domain) append the suffix to the end of the regex.  place unique
 * regular expressions in the tree.
 */
static int sc_regex_build(splaytree_t *tree, const char *name, sc_domain_t *dom,
			  uint16_t build_mask, const int *bits, int bitc)
{
  static const sc_regex_build_t func[] = {
    sc_regex_build_0, /* 0x0001 : non alnum seperator at end */
    sc_regex_build_1, /* 0x0002 : non alnum separator at start */
    sc_regex_build_2, /* 0x0004 : use .+ */
    sc_regex_build_3, /* 0x0008 : match according to separators */
    sc_regex_build_4, /* 0x0010 : embed literal */
    sc_regex_build_5, /* 0x0020 : embed IP address literal */
    sc_regex_build_6, /* 0x0040 : use \d+ where appropriate */
    sc_regex_build_7, /* 0x0080 : non alnum seperator at first non-alnum */
  };

  sc_rebuild_p_t p;
  sc_rebuild_t *rb = NULL;
  slist_t *stack = NULL;
  int k, r, x, o, any, rc = -1;
  sc_regex_t *re;
  char buf[2048], tmp[2048];
  int score, capc;
  size_t off, to;

  if((stack = slist_alloc()) == NULL)
    goto done;

  /*
   * if we are building regex components that are to be used in a
   * larger regex, do not prepend the anchor.
   */
  if(dom != NULL)
    {
      /* XXX: consider a score of 1 */
      if(sc_rebuild_push(stack, "^", 1, 0, 0, 0, 0, 0, 0) == NULL)
	goto done;
      if(bits[0] == 0)
	{
	  assert(bitc > 3); assert(bits[3] != 0);
	  if(sc_rebuild_push(stack, "", 0, 0, 0, 3, bits[3+1], 0, 0) == NULL)
	    goto done;
	}
    }
  else
    {
      if(sc_rebuild_push(stack, "", 0, 0, 0, 0, 0, 0, 0) == NULL)
	goto done;
    }

  p.bits = bits;
  p.bitc = bitc;
  p.dom = dom;
  p.buf = tmp;
  p.len = sizeof(tmp);

  for(;;)
    {
      rb = slist_head_item(stack);
      while(rb != NULL)
	{
	  if(rb->f < sizeof(func)/sizeof(sc_regex_build_t))
	    break;

	  slist_head_pop(stack);
	  free(rb);
	  rb = slist_head_item(stack);
	}
      if(rb == NULL)
	break;

      /* do we apply this build function? */
      if(((1 << rb->f) & build_mask) == 0 || func[rb->f] == NULL)
	{
	  rb->f++;
	  continue;
	}

      score = rb->score;
      o = rb->o;
      to = func[rb->f](name, &p, rb, &score, &o);
      rb->f++;
      if(to == 0)
	continue;

      memcpy(buf, rb->buf, sizeof(buf));
      off = rb->off;
      x = rb->x;
      capc = rb->capc;
      any = strcmp(tmp, ".+") == 0 ? 1 : rb->any;

      /* if we are at the start of a capture */
      if(rb->o == bits[x+1] &&
	 iscapture(bits[x]) == 1 && (x == 0 || iscapture(bits[x-3]) == 0))
	{
	  /* string_concat(buf, sizeof(buf), &off, "("); */
	  if(sizeof(buf) - off < 1)
	    goto done;
	  buf[off++] = '(';
	}

      /* string_concat(buf, sizeof(buf), &off, "%s", tmp); */
      if(sizeof(buf) - off < to)
	goto done;
      memcpy(buf+off, tmp, to); off += to;

      /* if we are at the end of a capture */
      if(o == bits[x+2]+1 &&
	 iscapture(bits[x]) == 1 && (x+3 == bitc || iscapture(bits[x+3]) == 0))
	{
	  /* string_concat(buf, sizeof(buf), &off, ")"); */
	  if(sizeof(buf) - off < 1)
	    goto done;
	  buf[off++] = ')';
	  capc++;
	}

      while(isalnum(name[o]) == 0 && name[o] != '\0' &&
	    (x+3 == bitc || o < bits[x+3+1]))
	{
	  if((r = re_escape(tmp, sizeof(tmp), name[o])) == 0)
	    goto done;
	  /* string_concat(buf, sizeof(buf), &off, "%s", tmp); */
	  if(sizeof(buf) - off < r)
	    goto done;
	  memcpy(buf+off, tmp, r); off += r;
	  o++;
	}

      if(x + 3 == bitc && name[o] == '\0')
	{
	  if(dom != NULL)
	    {
	      /* string_concat(buf,sizeof(buf),&off, "\\.%s$", dom->escape); */
	      if(sizeof(buf) - off < 4 + dom->escapel)
		goto done;
	      buf[off++] = '\\'; buf[off++] = '.';
	      memcpy(buf+off, dom->escape, dom->escapel); off += dom->escapel;
	      buf[off++] = '$'; buf[off++] = '\0';
	    }
	  else
	    {
	      if(sizeof(buf) - off < 1)
		goto done;
	      buf[off++] = '\0';
	    }

	  if(sc_regex_find(tree, buf) != NULL)
	    continue;
	  if(verbose != 0 && threadc == 1)
	    {
	      printf("%s %s", buf, name);
	      for(k=0; k<bitc; k+=3)
		printf(" %d %d %d", bits[k], bits[k+1], bits[k+2]);
	      printf("\n");
	    }
	  if((re = sc_regex_get(tree, buf)) == NULL)
	    return -1;
	  re->score = score;
	  re->dom = dom;
	  re->regexes[0]->capc = capc;
	  continue;
	}

      if(o > bits[x+2])
	x += 3;
      assert(x < bitc);
      if(sc_rebuild_push(stack, buf, off, score, 0, x, o, any, capc) == NULL)
	goto done;
    }

  rc = 0;
 done:
  if(stack != NULL) slist_free_cb(stack, (slist_free_t)free);
  return rc;
}

static int sc_regex_lcs2(splaytree_t *tree, sc_domain_t *dom,
			 const sc_ifacedom_t *R, int *X_array, int Xc)
{
  static const uint16_t mask = RB_BASE | RB_FIRST_PUNC_END;
  int *bits = NULL, bitc, ip[2], rc = -1;

  if(pt_to_bits(R->label, X_array, Xc, NULL, 0, &bits, &bitc) == 0)
    {
      if(sc_regex_build(tree, R->label, dom, mask, bits, bitc) != 0)
	goto done;
    }
  if(bits != NULL)
    {
      free(bits);
      bits = NULL;
    }

  /* if there is no IP literal, or the literal was not captured */
  if(R->iface->ip_s == -1)
    return 0;
  ip[0] = R->iface->ip_s; ip[1] = R->iface->ip_e;
  if(pt_overlap(X_array, Xc, ip, 2) == 0)
    return 0;

  /* remove the IP literal from the capture */
  if(pt_to_bits_noip(R, X_array, Xc, &bits, &bitc) == 0 && bitc > 0)
    {
      if(sc_regex_build(tree, R->label, dom, mask, bits, bitc) != 0)
	goto done;
    }
  if(bits != NULL)
    {
      free(bits);
      bits = NULL;
    }
  rc = 0;

 done:
  if(bits != NULL) free(bits);
  return rc;
}

static int sc_regex_lcs(splaytree_t *tree, sc_domain_t *dom,
			const sc_ifacedom_t *S, const sc_ifacedom_t *T)
{
  int *X_array = NULL;
  slist_t *X = NULL;
  int i, Xc, rc = -1;
  const sc_ifacedom_t *R;
  sc_css_t *X_css = NULL;
  sc_ptrc_t *ptrc = NULL;
  slist_t *X_list = NULL;

  /* determine the parts of strings in common */
  if((X = lcs(S->label, 0, T->label, 0, 2)) == NULL)
    goto done;

  /* trim substrings so that they start and end on a dot or dash boundary */
  lcs_trim(X, S->label, T->label);

  /* skip this pair of strings if no matches, or matches out of order */
  if(slist_count(X) == 0 || lcs_check(X) == 0)
    {
      rc = 0;
      goto done;
    }

  if((X_css = sc_css_alloc_lcs(X, S->label)) == NULL)
    goto done;
  Xc = X_css->cssc * 2;
  if((X_array = malloc(sizeof(int) * Xc)) == NULL)
    goto done;
  if((X_list = slist_alloc()) == NULL)
    goto done;

  for(i=0; i<2; i++)
    {
      /*
       * two identical loops, which only differ on which of the two
       * interface strings under consideration
       */
      if(i == 0)
	R = S;
      else
	R = T;

      if(sc_css_match(X_css, R->label, X_array, 1) == 0)
	continue;

      if(sc_regex_lcs2(tree, dom, R, X_array, Xc) != 0)
	goto done;

      if(Xc > 2)
	{
	  if(sc_regex_pt_decons(X_list, X_array, Xc) != 0)
	    goto done;
	  while((ptrc = slist_head_pop(X_list)) != NULL)
	    {
	      if(sc_regex_lcs2(tree, dom, R, ptrc->ptr, ptrc->c) != 0)
		goto done;
	      sc_ptrc_free2(ptrc); ptrc = NULL;
	    }
	}
    }
  free(X_array); X_array = NULL;
  sc_css_free(X_css); X_css = NULL;

  rc = 0;

 done:
  if(X_list != NULL) slist_free_cb(X_list, (slist_free_t)sc_ptrc_free2);
  if(X != NULL) slist_free_cb(X, (slist_free_t)sc_lcs_pt_free);
  if(X_css != NULL) sc_css_free(X_css);
  if(X_array != NULL) free(X_array);
  return rc;
}

static void sc_router_free(sc_router_t *rtr)
{
  int i;

  if(rtr->ifaces != NULL)
    {
      for(i=0; i<rtr->ifacec; i++)
	sc_iface_free(rtr->ifaces[i]);
      free(rtr->ifaces);
    }

  free(rtr);
  return;
}

/*
 * sc_router_finish
 *
 * a list of router interfaces has been assembled.  take the list of
 * interfaces and build the router, placing the router onto each
 * applicable domain
 */
static int sc_router_finish(slist_t *list)
{
  splaytree_t *dctree = NULL;
  sc_router_t *rtr = NULL;
  sc_routerdom_t *rd = NULL;
  sc_ifacedom_t *ifd = NULL;
  sc_iface_t *iface;
  sc_css_t *dc;
  sc_domain_t *dom;
  slist_node_t *sn;
  int i, c;
  int namec = 0;
  slist_t *tmp = NULL;
  const char *suffix;

  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
    {
      iface = slist_node_item(sn);
      if(iface->name != NULL)
	namec++;
    }
  if(namec == 0)
    {
      slist_empty_cb(list, (slist_free_t)sc_iface_free);
      return 0;
    }

  /* is this a router we cannot train from? */
  if(slist_count(list) == 1)
    {
      /*
       * use the public suffix list to figure out the domain
       * and skip over domains that we're not interested in
       */
      iface = slist_head_pop(list);
      if((suffix = sc_suffix_find(iface->name)) == NULL ||
	 (domain_eval != NULL && strcmp(domain_eval, suffix) != 0))
	{
	  sc_iface_free(iface);
	  return 0;
	}

      if((ifd = sc_ifacedom_alloc(iface, suffix)) == NULL ||
	 (dom = sc_domain_get(suffix)) == NULL ||
	 slist_tail_push(dom->appl, ifd) == NULL)
	{
	  sc_iface_free(iface);
	  goto err;
	}
      return 0;
    }

  /* to start with, build the router and put it on the global list */
  if((rtr = malloc_zero(sizeof(sc_router_t))) == NULL ||
     (rtr->ifaces = malloc_zero(sizeof(sc_iface_t *) * namec)) == NULL)
    goto err;
  while((iface = slist_head_pop(list)) != NULL)
    {
      if(iface->name == NULL)
	{
	  sc_iface_free(iface);
	  continue;
	}
      rtr->ifaces[rtr->ifacec++] = iface;
      iface->rtr = rtr;
    }
  if(slist_tail_push(router_list, rtr) == NULL)
    goto err;

  array_qsort((void **)rtr->ifaces, rtr->ifacec,
	      (array_cmp_t)sc_iface_suffix_cmp);

  /* figure out all the domains the router can be mapped to */
  if((dctree=splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp))==NULL)
    goto err;

  for(i=0; i<rtr->ifacec; i++)
    {
      /* use the public suffix list to figure out the domain */
      iface = rtr->ifaces[i];
      if((suffix = sc_suffix_find(iface->name)) == NULL)
	continue;

      /* skip over domains that we're not interested in */
      if(domain_eval != NULL && strcmp(domain_eval, suffix) != 0)
	continue;

      /* we only want to add the router once per domain */
      if((dc = sc_css_get_str(dctree, suffix)) == NULL)
	goto err;
      dc->count++;
    }

  /*
   * put the unique domains into a list, and push the router onto the list
   * of routers for the domain
   */
  if((tmp = slist_alloc()) == NULL)
    goto err;
  splaytree_inorder(dctree, tree_to_slist, tmp);
  splaytree_free(dctree, NULL);
  while((dc = slist_head_pop(tmp)) != NULL)
    {
      if((dom = sc_domain_get(dc->css)) == NULL)
	goto err;

      /* figure out how many interfaces within the domain the router has */
      c = 0;
      for(i=0; i<rtr->ifacec; i++)
	{
	  iface = rtr->ifaces[i];
	  if((suffix = sc_suffix_find(iface->name)) == NULL ||
	     strcmp(suffix, dc->css) != 0)
	    continue;
	  c++;
	}

      /*
       * allocate a sc_routerdom_t structure which only has the interfaces
       * relevant to the considered suffix
       */
      if((rd = malloc_zero(sizeof(sc_routerdom_t))) == NULL ||
	 (rd->ifaces = malloc_zero(sizeof(sc_ifacedom_t *) * c)) == NULL)
	goto err;
      rd->ifacec = c;
      rd->rtr = rtr;
      rd->id = slist_count(dom->routers) + 1;
      c = 0;
      for(i=0; i<rtr->ifacec; i++)
	{
	  iface = rtr->ifaces[i];
	  if((suffix = sc_suffix_find(iface->name)) == NULL ||
	     strcmp(suffix, dc->css) != 0)
	    continue;
	  if((rd->ifaces[c] = sc_ifacedom_alloc(iface, suffix)) == NULL)
	    goto err;
	  rd->ifaces[c]->rd = rd;
	  rd->ifaces[c]->id = dom->ifacec + c + 1;
	  c++;
	}

      if(slist_tail_push(dom->routers, rd) == NULL)
	goto err;
      dom->ifacec += rd->ifacec;
      rd = NULL;

      sc_css_free(dc);
    }
  slist_free(tmp);

  return 0;

 err:
  if(rd != NULL) sc_routerdom_free(rd);
  if(ifd != NULL) sc_ifacedom_free(ifd);
  return -1;
}

static int router_file_line(char *line, void *param)
{
  slist_t *list = param;
  sc_iface_t *iface = NULL;
  char *ip, *ptr;
  char name[1024];

  if(line[0] == '#')
    return 0;

  if(line[0] == '\0')
    {
      if(slist_count(list) == 0)
	return 0;
      if(sc_router_finish(list) != 0)
	return -1;
      return 0;
    }

  ip = line;
  ptr = line;
  while(*ptr != '\0' && isspace(*ptr) == 0)
    ptr++;
  if(*ptr != '\0')
    {
      *ptr = '\0'; ptr++;
      while(isspace(*ptr) != 0)
	ptr++;
      hex_toascii(name, sizeof(name), ptr);
    }
  else name[0] = '\0';

  if((iface = sc_iface_alloc(ip, name)) == NULL ||
     slist_tail_push(list, iface) == NULL)
    goto err;

  return 0;

 err:
  return -1;
}

static int dump_1(void)
{
  sc_domain_t *dom;
  sc_regex_t *re;
  slist_node_t *sn, *s2;
  char buf[512];
  int k;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if(slist_count(dom->regexes) < 1)
	continue;
      slist_qsort(dom->regexes, (slist_cmp_t)sc_regex_score_rank_cmp);

      printf("suffix %s\n", dom->domain);
      for(s2=slist_head_node(dom->regexes); s2 != NULL; s2=slist_node_next(s2))
	{
	  re = slist_node_item(s2);
	  for(k=0; k<re->regexc; k++)
	    {
	      if(k > 0) printf(" ");
	      printf("%s", re->regexes[k]->str);
	    }
	  printf(": %s\n", sc_regex_score_tostr(re, buf, sizeof(buf)));
	}
    }

  return 0;
}

static int dump_2_regex(sc_domain_t *dom, sc_regex_t *re)
{
  sc_routername_t **rnames = NULL, *rn;
  int rnamec = 0;
  slist_node_t *sn, *sn2;
  sc_rework_t *rew = NULL;
  sc_routerdom_t *rd;
  sc_iface_t *iface;
  sc_ifdptr_t *ifp;
  sc_ifacedom_t *ifd;
  sc_ifaceinf_t *ifi, *ifi2;
  sc_routerinf_t *ri;
  slist_t *ri_list = NULL;
  slist_t *ifp_list = NULL;
  splaytree_t *ifp_tree = NULL;
  splaytree_t *ri_tree = NULL;
  slist_t *appl_list = NULL;
  int i, r, x, ip;
  sc_css_t *last_css, *css = NULL;
  const char *suffix;
  char code;
  char buf[2048];
  int rc = -1;
  double randi;

  if((rew = sc_rework_alloc(re)) == NULL)
    goto done;

  /* take a pass through all routers, and decide on a name for each */
  rnamec = slist_count(dom->routers);
  if((rnames = sc_routernames_alloc(dom->routers, rew)) == NULL)
    goto done;

  /* take another pass, getting all the interfaces within the suffix */
  if((ifp_tree = sc_ifdptr_tree(dom->routers)) == NULL)
    goto done;

  /* take a pass through the inferred routers, pairing inference with iface */
  if((ri_list = slist_alloc()) == NULL)
    goto done;
  if(sc_regex_eval(re, ri_list) != 0)
    goto done;
  if(sc_ifdptr_tree_ri(ifp_tree, ri_list) != 0)
    goto done;

  if(do_ri != 0)
    {
      /* compute the Rand index if requested */
      if((ifp_list = slist_alloc()) == NULL)
	goto done;
      splaytree_inorder(ifp_tree, tree_to_slist, ifp_list);
      randi = randindex(ifp_list);
      slist_free(ifp_list); ifp_list = NULL;
    }
  else randi = 0;

  if(do_json == 0)
    {
      printf("%s: %d routers:", dom->domain, slist_count(dom->routers));
      for(i=0; i<re->regexc; i++)
	printf(" %s", re->regexes[i]->str);
      printf(" %s", sc_regex_score_tostr(re, buf, sizeof(buf)));
      if(do_ri != 0)
	printf(", ri %.2f", randi);
      printf("\n");
    }
  else
    {
      printf("{\"domain\":\"%s\", \"routerc\":%d",
	     dom->domain, slist_count(dom->routers));
      printf(", \"re\":[");
      for(i=0; i<re->regexc; i++)
	{
	  if(i > 0) printf(", ");
	  printf("\"");
	  json_print(re->regexes[i]->str);
	  printf("\"");
	}
      printf("]");
      printf(", \"score\":{%s}", sc_regex_score_tojson(re, buf, sizeof(buf)));
    }

  if(do_json != 0)
    printf(", \"routers\":[");
  last_css = NULL;
  for(r=0; r<rnamec; r++)
    {
      rn = rnames[r];
      rd = rn->rd;

      if(do_json == 0)
	{
	  if(rn->css != NULL)
	    {
	      printf("%s %d", sc_css_tostr(rn->css, '|', buf, sizeof(buf)),
		     rn->css->count);
	      if(last_css != NULL && sc_css_css_cmp(last_css, rn->css) == 0)
		printf(" ***");
	    }
	  else printf("unnamed %d", rn->matchc);
	  if(rd->css != NULL)
	    printf(" %s %d",
		   sc_css_tostr(rd->css,'|',buf,sizeof(buf)), rd->css->count);
	  printf("\n");
	}
      else
	{
	  if(r > 0) printf(", ");
	  if(rn->css != NULL)
	    printf("{\"name\":\"%s\"",
		   sc_css_tostr(rn->css, '|', buf, sizeof(buf)));
	  else
	    printf("{\"name\":\"\"");
	}

      last_css = rn->css;

      if(do_json != 0)
	printf(", \"ifaces\":[");

      for(i=0; i<rd->ifacec; i++)
	{
	  ifd = rd->ifaces[i]; iface = ifd->iface;
	  ifp = sc_ifdptr_find(ifp_tree, ifd); assert(ifp != NULL);
	  ifi = ifp->ptr; assert(ifi != NULL);
	  code = ifi->class;

	  if(do_json == 0)
	    {
	      if(rd->css != NULL && ifi->css != NULL && code == '-' &&
		 (rn->css == NULL || sc_css_css_cmp(rn->css, ifi->css) != 0) &&
		 sc_css_morespecific(rd->css, ifi->css) != 0)
		code = 'M';
	      else if(rn->css != NULL && (code == '~' || code == '-') &&
		      (ifi->css == NULL ||
		       sc_css_css_cmp(rn->css,ifi->css) != 0) &&
		      sc_css_match(rn->css, ifd->label, NULL, 1) == 1)
		code = 'm';

	      printf("%16s %c %s\n",
		     scamper_addr_tostr(iface->addr, buf, sizeof(buf)),
		     code, iface->name);
	    }
	  else
	    {
	      if(i > 0) printf(", ");
	      printf("{\"addr\":\"%s\", \"code\":\"%c\"",
		     scamper_addr_tostr(iface->addr, buf, sizeof(buf)), code);
	      printf(", \"hostname\":\"");
	      json_print(iface->name);
	      printf("\"");
	      if(ifi->css != NULL)
		{
		  if(sc_rework_match(rew, iface, NULL) < 0)
		    goto done;
		  printf(", \"span\":[");
		  for(x=1; x<rew->m; x++)
		    {
		      if(x > 1) printf(", ");
		      printf("%d, %d", (int)rew->ovector[2*x],
			     (int)rew->ovector[(2*x)+1]);
		    }
		  printf("]");
		}
	      printf("}");
	    }
	}

      for(i=0; i<rd->rtr->ifacec; i++)
	{
	  iface = rd->rtr->ifaces[i];
	  if((suffix = sc_suffix_find(iface->name)) == NULL ||
	     strcmp(suffix, dom->domain) != 0)
	    {
	      if(do_json == 0)
		printf("%16s   %s\n",
		       scamper_addr_tostr(iface->addr, buf, sizeof(buf)),
		       iface->name);
	      else
		{
		  printf(", {\"addr\":\"%s\"",
			 scamper_addr_tostr(iface->addr, buf, sizeof(buf)));
		  printf(", \"hostname\":\"");
		  json_print(iface->name);
		  printf("\"}");
		}
	    }
	}

      if(do_json == 0)
	printf("\n");
      else
	printf("]}");
    }
  if(do_json != 0)
    printf("]");

  if(do_appl != 0 && slist_count(dom->appl) > 0)
    {
      /*
       * put the existing inferences into a tree, as the set in
       * "appl" should not match if the training data is perfect
       */
      if((ri_tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL)
	goto done;
      for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
	{
	  ri = slist_node_item(sn);
	  if(ri->ifaces[0]->css == NULL)
	    continue;
	  if(splaytree_insert(ri_tree, ri->ifaces[0]->css) == NULL)
	    goto done;
	}

      if((appl_list = slist_alloc()) == NULL)
	goto done;

      for(sn=slist_head_node(dom->appl); sn != NULL; sn=slist_node_next(sn))
	{
	  ifd = slist_node_item(sn);
	  iface = ifd->iface;
	  code = ' ';

	  if((x = sc_rework_match(rew, iface, &css)) < 0)
	    goto done;

	  ip = 0;
	  if(x == 1)
	    {
	      if(css == NULL)
		code = '*';
	      else if(sc_iface_ip_matched(iface, rew) != 0)
		{
		  ip = 1;
		  code = 'x';
		}
	      else if(splaytree_find(ri_tree, css) != NULL)
		code = '!';
	      else
		code = '+';
	      ifi = sc_ifaceinf_get(appl_list, ifd, css, ip, rew->k);
	    }
	  else
	    {
	      ifi = sc_ifaceinf_get(appl_list, ifd, NULL, ip, -1);
	    }
	  ifi->class = code;
	  css = NULL;
	}

      if(do_json == 0)
	printf("application:\n\n");
      else
	printf(", \"application\":[");

      r = 0;
      slist_qsort(appl_list, (slist_cmp_t)sc_ifaceinf_inf_cmp);
      sn = slist_head_node(appl_list);
      while(sn != NULL)
	{
	  ifi = slist_node_item(sn);
	  if(ifi->css == NULL)
	    break;

	  x = 1;
	  if((sn2 = slist_node_next(sn)) != NULL)
	    {
	      ifi2 = slist_node_item(sn2);
	      while(ifi2->css != NULL && sc_css_css_cmp(ifi->css,ifi2->css)==0)
		{
		  x++;
		  if((sn2 = slist_node_next(sn2)) == NULL)
		    break;
		  ifi2 = slist_node_item(sn2);
		}
	    }

	  sc_css_tostr(ifi->css, '|', buf, sizeof(buf));
	  if(do_json == 0)
	    printf("%s %d\n", buf, x);
	  else
	    {
	      if(r > 0) printf(", ");
	      printf("{\"name\":\"");
	      json_print(buf);
	      printf("\", \"ifaces\":[");
	    }

	  i = 0;
	  while(sn != sn2)
	    {
	      ifi = slist_node_item(sn); iface = ifi->ifd->iface;
	      scamper_addr_tostr(iface->addr, buf, sizeof(buf));
	      if(do_json == 0)
		printf("%16s %c %s\n", buf, ifi->class, iface->name);
	      else
		{
		  if(i > 0) printf(", ");
		  printf("{\"addr\":\"%s\", \"code\":\"%c\"", buf, ifi->class);
		  printf(", \"hostname\":\"");
		  json_print(iface->name);
		  printf("\"");
		  if(sc_rework_match(rew, iface, NULL) < 0)
		    goto done;
		  printf(", \"span\":[");
		  for(x=1; x<rew->m; x++)
		    {
		      if(x > 1) printf(", ");
		      printf("%d, %d", (int)rew->ovector[2*x],
			     (int)rew->ovector[(2*x)+1]);
		    }
		  printf("]}");
		}
	      sn = slist_node_next(sn);
	      i++;
	    }

	  if(do_json == 0)
	    printf("\n");
	  else
	    printf("]}");
	  r++;
	}

      if(do_json != 0)
	printf("]");

      if(sn != NULL)
	{
	  if(do_json == 0)
	    printf("application-unnamed:\n");
	  else
	    printf(", \"application_unnamed\":[");
	  i = 0;
	  while(sn != NULL)
	    {
	      ifi = slist_node_item(sn); iface = ifi->ifd->iface;
	      scamper_addr_tostr(iface->addr, buf, sizeof(buf));

	      if(do_json == 0)
		printf("%16s %c %s\n", buf, ifi->class, iface->name);
	      else
		{
		  if(i > 0) printf(", ");
		  printf("{\"addr\":\"%s\", \"code\":\"%c\"", buf, ifi->class);
		  printf(", \"hostname\":\"");
		  json_print(iface->name);
		  printf("\"}");
		  i++;
		}
	      sn = slist_node_next(sn);
	    }

	  if(do_json != 0)
	    printf("]");
	}

      if(do_json == 0)
	printf("\n");
    }

  if(do_json != 0)
    printf("}\n");

  rc = 0;

 done:
  if(appl_list != NULL)
    slist_free_cb(appl_list, (slist_free_t)sc_ifaceinf_free);
  if(rew != NULL) sc_rework_free(rew);
  if(rnames != NULL) sc_routernames_free(rnames, rnamec);
  if(css != NULL) sc_css_free(css);
  if(ri_tree != NULL) splaytree_free(ri_tree, NULL);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(ifp_list != NULL) slist_free(ifp_list);
  if(ifp_tree != NULL)
    splaytree_free(ifp_tree, (splaytree_free_t)sc_ifdptr_free);
  return rc;
}

static int dump_2(void)
{
  slist_node_t *sn;
  sc_domain_t *dom;
  sc_regex_t *re;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if((re = sc_domain_bestre(dom)) == NULL)
	continue;
      if(dump_2_regex(dom, re) != 0)
	return -1;
    }

  return 0;
}

static int dump_3(void)
{
  slist_node_t *sn;
  sc_domain_t *dom;
  sc_regex_t *best;
  char buf[512];
  int k;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if((best = sc_domain_bestre(dom)) == NULL)
	continue;

      printf("%s:", dom->domain);
      for(k=0; k<best->regexc; k++)
	printf(" %s", best->regexes[k]->str);
      printf(", score: %s", sc_regex_score_tostr(best, buf, sizeof(buf)));
      printf(", routers: %d\n", slist_count(dom->routers));
    }

  return 0;
}

static int thin_regexes_domain_same_set(dlist_t *set, slist_t *kept,
					slist_t *same)
{
  sc_regex_t *re, *re2;
  dlist_node_t *dn, *dn_this;
  slist_t *ifi_list = NULL;
  int rc = -1;

  if((ifi_list = slist_alloc()) == NULL)
    goto done;

  while((re = dlist_head_pop(set)) != NULL)
    {
      if(slist_tail_push(kept, re) == NULL)
	goto done;

      dn = dlist_head_node(set);
      while(dn != NULL)
	{
	  re2 = dlist_node_item(dn); dn_this = dn;
	  dn = dlist_node_next(dn);
	  if(sc_regex_issame(re, ifi_list, re2) == 1)
	    {
	      dlist_node_pop(set, dn_this);
	      if(slist_tail_push(same, re2) == NULL)
		goto done;
	    }
	}

      slist_empty_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
    }
  rc = 0;

 done:
  if(ifi_list != NULL) slist_free_cb(ifi_list,(slist_free_t)sc_ifaceinf_free);
  return rc;
}

static int thin_regexes_domain_same(slist_t *regexes)
{
  slist_t *kept = NULL, *same = NULL;
  dlist_t *set = NULL;
  sc_regex_t *re = NULL, *re2;
  slist_node_t *sn;
  int rc = -1;

  if((sn = slist_head_node(regexes)) == NULL)
    {
      rc = 0;
      goto done;
    }

  if((kept = slist_alloc()) == NULL ||
     (same = slist_alloc()) == NULL || (set = dlist_alloc()) == NULL)
    goto done;

  for(sn=slist_head_node(regexes); sn != NULL; sn=slist_node_next(sn))
    {
      if(re == NULL)
	{
	  re = slist_node_item(sn);
	  if(dlist_tail_push(set, re) == NULL)
	    goto done;
	  continue;
	}

      re2 = slist_node_item(sn);

      /* when we get to a different regex score, thin the set */
      if(sc_regex_score_thin_cmp(re, re2) != 0)
	{
	  if(thin_regexes_domain_same_set(set, kept, same) != 0)
	    goto done;
	  dlist_empty(set);
	  re = re2;
	}

      if(dlist_tail_push(set, re2) == NULL)
	goto done;
    }

  if(thin_regexes_domain_same_set(set, kept, same) != 0)
    goto done;

  rc = 0;
  slist_empty(regexes);
  slist_concat(regexes, kept);
  slist_empty_cb(same, (slist_free_t)sc_regex_free);

 done:
  if(set != NULL) dlist_free(set);
  if(same != NULL) slist_free(same);
  if(kept != NULL) slist_free(kept);
  return rc;
}

static int thin_regexes_domain_matchc(slist_t *regexes)
{
  slist_t *keep = NULL, *del = NULL, *list;
  slist_node_t *sn;
  sc_regex_t *re;
  int rc = -1;

  if((keep = slist_alloc()) == NULL || (del = slist_alloc()) == NULL)
    goto done;

  for(sn = slist_head_node(regexes); sn != NULL; sn = slist_node_next(sn))
    {
      re = slist_node_item(sn);
      if(re->matchc >= 3 && re->rt_c > 0)
	list = keep;
      else
	list = del;
      if(slist_tail_push(list, re) == NULL)
	goto done;
    }

  rc = 0;
  slist_empty(regexes);
  slist_concat(regexes, keep);
  slist_empty_cb(del, (slist_free_t)sc_regex_free);

 done:
  if(keep != NULL) slist_free(keep);
  if(del != NULL) slist_free(del);
  return rc;
}

static int thin_regexes_domain_mask(slist_t *regexes)
{
  dlist_t *kept = NULL;
  slist_t *cont = NULL, *skept = NULL;
  dlist_node_t *dn1, *dn2, *dn3;
  sc_regex_t *re1, *re2;
  int i, c2, masklen, rc = -1;
  uint32_t u;

  if((kept = dlist_alloc()) == NULL || (cont = slist_alloc()) == NULL)
    goto done;
  slist_qsort(regexes, (slist_cmp_t)sc_regex_score_rank_cmp);
  if(slist_foreach(regexes, slist_to_dlist, kept) != 0)
    goto done;

  for(dn1=dlist_head_node(kept); dn1 != NULL; dn1=dlist_node_next(dn1))
    {
      re1 = dlist_node_item(dn1);
      dn2 = dlist_node_next(dn1);
      masklen = re1->dom->tpmlen;

      while(dn2 != NULL)
	{
	  re2 = dlist_node_item(dn2);
	  dn3 = dlist_node_next(dn2);
	  c2 = -1;
	  if(re1->fp_c <= re2->fp_c && re1->tp_c >= re2->tp_c)
	    {
	      c2 = 0;
	      for(i=0; i<masklen; i++)
		{
		  u = re1->tp_mask[i] & re2->tp_mask[i];
		  if((re2->tp_mask[i] & ~u) != 0)
		    {
		      c2++;
		      break;
		    }
		}
	    }

	  if(c2 == 0)
	    {
	      if(slist_tail_push(cont, re2) == NULL)
		goto done;
	      dlist_node_pop(kept, dn2);
	    }
	  dn2 = dn3;
	}
    }

  if((skept = slist_alloc()) == NULL ||
     dlist_foreach(kept, dlist_to_slist, skept) != 0)
    goto done;
  slist_empty(regexes);
  slist_concat(regexes, skept);
  slist_empty_cb(cont, (slist_free_t)sc_regex_free);
  rc = 0;

 done:
  if(kept != NULL) dlist_free(kept);
  if(cont != NULL) slist_free(cont);
  if(skept != NULL) slist_free(skept);
  return rc;
}

static int thin_regexes_domain(slist_t *regexes, uint8_t mask)
{
  /* make sure the regexes are sorted by score */
  slist_qsort(regexes, (slist_cmp_t)sc_regex_score_thin_sort_cmp);
  if((thin_matchc != 0 && (mask & 0x1) != 0 &&
      thin_regexes_domain_matchc(regexes) != 0) ||
     (thin_same != 0 && (mask & 0x2) != 0 &&
      thin_regexes_domain_same(regexes) != 0) ||
     (thin_mask != 0 && (mask & 0x4) != 0 &&
      thin_regexes_domain_mask(regexes) != 0))
    return -1;
  return 0;
}

/*
 * thin_regexes_thread_0:
 *
 * remove regexes that perform the same as other regexes in the set, and
 * those without sufficient matches.
 */
static void thin_regexes_thread_0(sc_domain_t *dom)
{
  thin_regexes_domain(dom->regexes, 0x3);
  return;
}

/*
 * thin_regexes_thread_1:
 *
 * remove regexes that perform the same as other regexes in the set,
 * those without sufficient matches, and those that are contained in
 * another regex in the set.
 */
static void thin_regexes_thread_1(sc_domain_t *dom)
{
  thin_regexes_domain(dom->regexes, 0x7);
  return;
}

/*
 * thin_regexes_thread_2:
 *
 * only remove regexes that perform identically
 */
static void thin_regexes_thread_2(sc_domain_t *dom)
{
  thin_regexes_domain(dom->regexes, 0x2);
  return;
}

static int thin_regexes(int mode)
{
  struct timeval start, finish, tv;
  slist_node_t *sn;
  sc_domain_t *dom;
  int from = 0, to = 0;

  if(thin_same == 0 && thin_matchc == 0 && thin_mask == 0)
    return 0;

  gettimeofday_wrap(&start);
  tp = threadpool_alloc(threadc);

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      from += slist_count(dom->regexes);
      if(mode == 0)
	threadpool_tail_push(tp,(threadpool_func_t)thin_regexes_thread_0,dom);
      else if(mode == 1)
	threadpool_tail_push(tp,(threadpool_func_t)thin_regexes_thread_1,dom);
      else if(mode == 2)
	threadpool_tail_push(tp,(threadpool_func_t)thin_regexes_thread_2,dom);
    }

  threadpool_join(tp); tp = NULL;
  gettimeofday_wrap(&finish);

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      to += slist_count(dom->regexes);
    }

  timeval_diff_tv(&tv, &start, &finish);
  fprintf(stderr, "thinned from %d to %d regexes in %d.%d seconds\n",
	  from, to, (int)tv.tv_sec, (int)(tv.tv_usec / 100000));

  return 0;
}

static int sc_regex_tp_isbetter(sc_regex_t *re, sc_regex_t *can)
{
  uint32_t re_ppv, can_ppv;

  /*
   * if we have at least three routers, or the same number of routers
   * as in the original regex, and we have at least as many true
   * positives and no more false positives, then the candidate regex
   * is better and we're done.
   */
  if((can->rt_c >= 3 || re->rt_c == can->rt_c) &&
     can->tp_c >= re->tp_c && can->fp_c <= re->fp_c)
    return 1;

  /*
   * the following code handles the case when we get less true
   * positives in the candidate regex.  we therefore need to determine
   * if the PPV of the candidate regex is at least as good as what we
   * started with.
   */
  if(can->rt_c < 3)
    return 0;

  re_ppv = (re->tp_c * 1000) / (re->tp_c + re->fp_c + re->ip_c);
  can_ppv = (can->tp_c * 1000) / (can->tp_c + can->fp_c + can->ip_c);
  if(re_ppv > can_ppv)
    return 0;

  return 1;
}

/*
 * sc_regex_refine_tp
 *
 * given a regex with true positives, infer what the matching
 * components of the regex might have in common.
 */
static int sc_regex_refine_tp(sc_regex_t *re)
{
  static const uint16_t mask = RB_BASE | RB_FIRST_PUNC_END | RB_SEG_LITERAL | RB_SEG_DIGIT;
  slist_t *ri_list = NULL, *css_list = NULL, *re_list = NULL, *re2_list = NULL;
  splaytree_t *re_tree = NULL, **css_trees = NULL;
  sc_regex_t *re_eval = NULL, *re_new = NULL;
  int Lc, bitc, *La = NULL, *bits = NULL;
  sc_rework_t *rew = NULL;
  char *str = NULL, *ptr;
  slist_node_t *sn, *s2;
  int i, x, capc, rc = -1;
  sc_routerinf_t *ri;
  sc_css_t *css, css_fm;
  char buf[256];

  /* figure out how many capture elements there are */
  if((rew = sc_rework_alloc(re)) == NULL)
    goto done;
  if((capc = sc_rework_capcount(rew, 0)) < 0)
    goto done;
  if(capc == 0)
    {
      rc = 0;
      goto done;
    }
  sc_rework_free(rew); rew = NULL;

  /* create trees to put captured elements in */
  if((css_trees = malloc_zero(sizeof(splaytree_t *) * capc)) == NULL)
    goto done;
  for(i=0; i<capc; i++)
    {
      css_trees[i] = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp);
      if(css_trees[i] == NULL)
	goto done;
    }

  /*
   * evaluate the current regex, taking note of each captured element
   * in separate trees
   */
  if((ri_list = slist_alloc()) == NULL ||
     sc_regex_eval(re, ri_list) != 0)
    goto done;
  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);
      if(ri->ifacec == 1 || ri->ip != 0)
	continue;
      css = ri->ifaces[0]->css;
      css_fm.css = css->css;
      css_fm.cssc = 1;

      /* go through each captured element and put in the tree */
      for(i=0; i<capc; i++)
	{
	  css_fm.len = strlen(css_fm.css) + 1;
	  if(sc_css_get(css_trees[i], &css_fm) == NULL)
	    goto done;
	  if(i+1 != capc)
	    {
	      while(css_fm.css[0] != '\0')
		css_fm.css++;
	      css_fm.css++;
	    }
	}
    }

  if((css_list = slist_alloc()) == NULL ||
     (re_tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL ||
     (re_list = slist_alloc()) == NULL ||
     (re2_list = slist_alloc()) == NULL)
    goto done;

  for(i=0; i<capc; i++)
    {
      /* trim on non-alnum, min length 1 */
      if(sc_css_reduce(css_trees[i], 1, 1) != 0)
	goto done;
      /* trim on char class, min length 1 */
      if(sc_css_reduce(css_trees[i], 2, 1) != 0)
	goto done;

      /* get all the substrings out for this capture element */
      splaytree_inorder(css_trees[i], tree_to_slist, css_list);
      splaytree_free(css_trees[i], NULL); css_trees[i] = NULL;

      /* figure out regular expressions that match the given strings */
      for(sn=slist_head_node(css_list); sn != NULL; sn=slist_node_next(sn))
	{
	  css = slist_node_item(sn);
	  Lc = css->cssc * 2;
	  La = malloc(sizeof(int) * Lc);
	  for(s2=slist_head_node(ri_list); s2 != NULL; s2=slist_node_next(s2))
	    {
	      ri = slist_node_item(s2);
	      if(ri->ifacec == 1 || ri->ip != 0)
		continue;

	      ptr = ri->ifaces[0]->css->css;
	      for(x=0; x<i; x++)
		{
		  while(ptr[0] != '\0')
		    ptr++;
		  ptr++;
		}

	      if(sc_css_match(css, ptr, La, 0) == 0)
		continue;
	      /*
	       * don't allow a regex to form where the entire capture
	       * portion is specified with a literal
	       */
	      if(capc == 1 && css->cssc == 1 &&
		 La[0] == 0 && ptr[La[1]+1] == '\0')
		continue;
	      if(threadc == 1 && verbose != 0)
		printf("%s %s\n", ptr, sc_css_tostr(css,'|',buf,sizeof(buf)));
	      if(pt_to_bits_lit(ptr, La, Lc, &bits, &bitc) == 0)
		{
		  if(sc_regex_build(re_tree, ptr, NULL, mask, bits, bitc) != 0)
		    goto done;
		}
	      if(bits != NULL)
		{
		  free(bits);
		  bits = NULL;
		}
	    }
	  free(La); La = NULL;
	}
      slist_empty_cb(css_list, (slist_free_t)sc_css_free);
      splaytree_inorder(re_tree, tree_to_slist, re_list);
      splaytree_empty(re_tree, NULL);

      for(sn=slist_head_node(re_list); sn != NULL; sn=slist_node_next(sn))
	{
	  re_eval = slist_node_item(sn);
	  str = sc_regex_caprep(re->regexes[0]->str, i+1, 1,
				re_eval->regexes[0]->str);
	  if(str == NULL || (re_new = sc_regex_alloc(str)) == NULL)
	    goto done;
	  str = NULL;
	  re_new->dom = re->dom;

	  if(sc_regex_eval(re_new, NULL) != 0)
	    goto done;
	  if(re_new->matchc == 0 && threadc == 1 && verbose != 0)
	    printf("no matches %s\n", re_new->regexes[0]->str);
	  if(sc_regex_tp_isbetter(re, re_new) == 0)
	    {
	      sc_regex_free(re_new); re_new = NULL;
	      continue;
	    }
	  re_new->score = re->score + re_eval->score;
	  if(slist_tail_push(re2_list, re_new) == NULL)
	    goto done;
	  re_new = NULL;
	}
      slist_empty_cb(re_list, (slist_free_t)sc_regex_free);

      if(slist_count(re2_list) > 0)
	{
	  thin_regexes_domain(re2_list, 0x3);
	  if(sc_domain_lock(re->dom) != 0)
	    goto done;
	  slist_concat(re->dom->regexes, re2_list);
	  sc_domain_unlock(re->dom);
	}
    }

  rc = 0;

 done:
  if(str != NULL) free(str);
  if(bits != NULL) free(bits);
  if(La != NULL) free(La);
  if(rew != NULL) sc_rework_free(rew);
  if(re_new != NULL) sc_regex_free(re_new);
  if(re_list != NULL) slist_free_cb(re_list, (slist_free_t)sc_regex_free);
  if(re2_list != NULL) slist_free_cb(re2_list, (slist_free_t)sc_regex_free);
  if(re_tree != NULL) splaytree_free(re_tree, (splaytree_free_t)sc_regex_free);
  if(css_list != NULL) slist_free_cb(css_list, (slist_free_t)sc_css_free);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(css_trees != NULL)
    {
      for(i=0; i<capc; i++)
	if(css_trees[i] != NULL)
	  splaytree_free(css_trees[i], (splaytree_free_t)sc_css_free);
      free(css_trees);
    }
  return rc;
}

/*
 * sc_regex_ip_eval
 *
 * if regex matches an interface we wish to filter, tp++, otherwise fp++
 */
static int sc_regex_ip_eval(slist_t *ri_list, sc_regex_t *re)
{
  splaytree_t *tree = NULL;
  sc_rework_t *rew = NULL;
  int rc = -1, i, x;
  slist_node_t *sn;
  sc_routerinf_t *ri;
  sc_routerdom_t *rd;
  sc_iface_t *iface;

  if((rew = sc_rework_alloc(re)) == NULL)
    goto done;
  if((tree = splaytree_alloc((splaytree_cmp_t)ptrcmp)) == NULL)
    goto done;
  sc_regex_score_reset(re);

  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);
      for(i=0; i<ri->ifacec; i++)
	{
	  iface = ri->ifaces[i]->ifd->iface;
	  if((x = sc_rework_match(rew, iface, NULL)) < 0)
	    goto done;

	  /* matched */
	  if(x == 1)
	    {
	      re->matchc++;
	      rd = ri->ifaces[i]->ifd->rd;
	      if(ri->ifaces[i]->class == 'x')
		{
		  re->tp_c++;
		  if(splaytree_find(tree, rd) == NULL &&
		     splaytree_insert(tree, rd) == NULL)
		    goto done;
		}
	      else if(ri->ifaces[i]->class == '+')
		re->fp_c++;
	      else
		re->fne_c++;
	    }
	  else
	    {
	      if(ri->ifaces[i]->class == 'x')
		re->fnu_c++;
	    }
	}
    }
  re->rt_c = splaytree_count(tree);
  rc = 0;

 done:
  if(rew != NULL) sc_rework_free(rew);
  if(tree != NULL) splaytree_free(tree, NULL);
  return rc;
}

/*
 * sc_regex_fne_isbetter
 *
 * three regexes: the current over-specific regex, a previous candidate
 * regex that might be better, a refined candidate regex that might be
 * better again.  determine if can2 > can1.
 */
static int sc_regex_fne_isbetter(sc_regex_t *cur,
				 sc_regex_t *can1, sc_regex_t *can2)
{
  uint32_t cur_tp, cur_fp, cur_ppv;
  uint32_t can1_tp, can1_fp, can1_ppv;
  uint32_t can2_tp, can2_fp, can2_ppv;
  uint32_t del_tp, del_fp, del_ppv;

  /* if we don't gain any true positives, then no better */
  if(can2->tp_c <= can1->tp_c)
    {
#if 0
      printf("no tp_c %s %u %u\n",
	     can2->regexes[can2->regexc-1]->str, can1->tp_c, can2->tp_c);
#endif
      return 0;
    }

  /* if we don't gain three routers, then no better */
  if(can2->rt_c < can1->rt_c + 3 && can2->regexes[can2->regexc-1]->rt_c < 3)
    {
#if 0
      printf("no gain %s %u %u %u\n", can2->regexes[can2->regexc-1]->str,
	     can1->rt_c, can2->rt_c, can2->regexes[can2->regexc-1]->rt_c);
#endif
      return 0;
    }

  /*
   * if we gain false positives, the fraction of correct assignments
   * made in the delta must be better than the current regex does
   */
  can1_fp = can1->fp_c + can1->ip_c;
  can2_fp = can2->fp_c + can2->ip_c;
  if(can2_fp > can1_fp)
    {
      can1_tp = can1->tp_c;
      can2_tp = can2->tp_c;
      del_tp = can2_tp - can1_tp;
      del_fp = can2_fp - can1_fp;

      /* make sure there are more TP than FP */
      if(del_tp <= del_fp)
	return 0;

      cur_tp = cur->tp_c;
      cur_fp = cur->fp_c + cur->ip_c;
      del_ppv = (del_tp * 1000) / (del_tp + del_fp);
      cur_ppv = (cur_tp * 1000) /  (cur_tp + cur_fp);
      can2_ppv = (can2_tp * 1000) / (can2_tp + can2_fp);
      can1_ppv = (can1_tp * 1000) / (can1_tp + can1_fp);

#if 0
      printf("%s %d %d | %d %d %d %d\n",
	     can2->regexes[can2->regexc-1]->str, del_tp, del_fp,
	     del_ppv, cur_ppv, can1_ppv, can2_ppv);
#endif

      if((del_ppv < cur_ppv && del_ppv < can1_ppv &&
	  can1_ppv - del_ppv > 20 && del_fp > 1) ||
	 (can2_ppv < can1_ppv && can1_ppv - can2_ppv > 20))
	{
#if 0
	  printf("poor ppv %s %u %u %u %u\n",
		 can2->regexes[can2->regexc-1]->str,
		 del_tp, del_tp + del_fp, cur_tp, cur_tp+cur_fp);
#endif
	  return 0;
	}
    }

  return 1;
}

static int sc_regex_fne_isbetter2(sc_regex_t *cur, sc_regex_t *can)
{
  uint32_t cur_tp, cur_fp, can_tp, can_fp, cur_ppv, can_ppv;

  can_tp = can->tp_c; can_fp = can->fp_c + can->ip_c;
  cur_tp = cur->tp_c; cur_fp = cur->fp_c + cur->ip_c;

  if(cur->rt_c > 3 && can->rt_c < 3)
    return 0;

  /*
   * the candidate regex has to at least have a true positive to avoid
   * dividing by zero later.
   */
  if(can_tp == 0)
    return 0;

  /* if we get more TPs and less FPs, then better */
  if(can_tp >= cur_tp && can_fp <= cur_fp)
    return 1;

  /* if we get less TPs and more FPs, then worse */
  if(can_tp < cur_tp && can_fp > cur_fp)
    return 0;

  /* if we get more TPs and one more FP, then tag the regex as better */
  if(can_tp > cur_tp && can_fp == cur_fp + 1)
    return 1;

  /* if the candidate has less FP + FNE than the current, then better */
  if(can->fp_c + can->fne_c < cur->fp_c + cur->fne_c)
    return 1;

  /*
   * if the PPV of the candidate regex is less than the current
   * regex, and worse by more than 0.5%, then it is not better
   */
  cur_ppv = (cur_tp * 1000) / (cur_tp + cur_fp);
  can_ppv = (can_tp * 1000) / (can_tp + can_fp);
  if(cur_ppv > can_ppv && cur_ppv - can_ppv > 5)
    return 0;

  return 1;
}

static int sc_regex_css_thin(const sc_regex_t *re, int cap, dlist_t *css_list)
{
  char *str = NULL, *restr = re->regexes[0]->str;
  dlist_t *out = NULL;
  sc_regex_t *re_work = NULL;
  sc_css_t *css;
  size_t len;

  if(dlist_count(css_list) < 2)
    return 0;

  if((out = dlist_alloc()) == NULL)
    goto err;

  len = sizeof(sc_regexn_t *) * dlist_count(css_list);
  if((re_work = malloc_zero(sizeof(sc_regex_t))) == NULL ||
     (re_work->regexes = malloc_zero(len)) == NULL)
    goto err;
  re_work->dom = re->dom;
  re_work->regexc = 1;

  css = dlist_tail_pop(css_list);
  if(dlist_head_push(out, css) == NULL)
    goto err;
  if((str = sc_regex_caprep(restr, cap, 0, css->css)) == NULL ||
     (re_work->regexes[0] = sc_regexn_alloc(str)) == NULL)
    goto err;
  free(str); str = NULL;

  while((css = dlist_tail_pop(css_list)) != NULL)
    {
      if((str = sc_regex_caprep(restr, cap, 0, css->css)) == NULL ||
	 (re_work->regexes[re_work->regexc++] = sc_regexn_alloc(str)) == NULL)
	goto err;
      free(str); str = NULL;
      if(sc_regex_eval(re_work, NULL) != 0)
	goto err;

      if(re_work->regexes[re_work->regexc-1]->matchc != 0)
	{
	  if(dlist_tail_push(out, css) == NULL)
	    goto err;
	}
      else
	{
	  sc_css_free(css);
	  css = NULL;
	  sc_regexn_free(re_work->regexes[re_work->regexc-1]);
	  re_work->regexc--;
	}
    }

  sc_regex_free(re_work);
  dlist_concat(css_list, out);
  dlist_free(out);

  return 0;

 err:
  if(str != NULL) free(str);
  if(re_work != NULL) sc_regex_free(re_work);
  return -1;
}

/*
 * sc_regex_refine_fne
 *
 * given a regex that appears to split interfaces of a router apart,
 * determine if there are literal components in a match component that
 * we should not extract, but we should match on.
 */
static int sc_regex_refine_fne(sc_regex_t *re)
{
  splaytree_t *rd_ri_tree = NULL, *rd_tree = NULL, *css_tree = NULL;
  splaytree_t *re_tree = NULL;
  slist_t *rd_ri_list = NULL, *ri_list = NULL;
  sc_rework_t *rew = NULL, *rew_eval = NULL;
  sc_css_t *ri_css, *rd_css, *css;
  sc_regex_t *re_eval = NULL, *re_work = NULL;
  sc_regexn_t *ren;
  sc_regex_css_t *recss;
  slist_t *list = NULL, *ifi_list = NULL, *ifi2_list = NULL, *ifi3_list = NULL;
  dlist_t *recss_list = NULL, *css_list = NULL;
  slist_node_t *sn; dlist_node_t *dn, *dn_this;
  sc_routerdom_t *rd;
  sc_routerinf_t *ri;
  sc_ptrc_t *ptrc;
  int i, x, cap, capc, rc = -1;
  int *caps = NULL;
  char *str = NULL;
  char buf[128];

  if((rew = sc_rework_alloc(re)) == NULL ||
     (ri_list = slist_alloc()) == NULL ||
     (rd_tree = splaytree_alloc((splaytree_cmp_t)sc_ptrc_ptr_cmp)) == NULL ||
     (rd_ri_list = slist_alloc()) == NULL ||
     (rd_ri_tree = splaytree_alloc((splaytree_cmp_t)sc_ptrc_ptr_cmp)) == NULL)
    goto done;
  if(sc_regex_eval(re, ri_list) != 0)
    goto done;

  if((css_tree = sc_routerdom_css_tree(re->dom->routers)) == NULL)
    goto done;

  /* array to count which element seems to be too specific */
  if((capc = sc_rework_capcount(rew, 0)) < 0)
    goto done;
  if(capc < 2)
    {
      rc = 0;
      goto done;
    }
  if((caps = malloc_zero(sizeof(int) * (capc + 1))) == NULL)
    goto done;

  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      /* skip over interfaces where the regex did not match */
      ri = slist_node_item(sn);
      ri_css = ri->ifaces[0]->css;
      if(ri->ifacec == 1 && ri_css == NULL)
	continue;

      for(i=0; i<ri->ifacec; i++)
	{
	  /*
	   * skip over interfaces which did not have a more specific
	   * name
	   */
	  if(ri->ifaces[i]->class != '-' ||
	     (rd_css = ri->ifaces[i]->ifd->rd->css) == NULL ||
	     sc_css_morespecific(rd_css, ri_css) == 0)
	    continue;

	  /*
	   * if the less specific name is not unique among routers,
	   * skip
	   */
	  if((css = splaytree_find(css_tree, rd_css)) == NULL)
	    goto done;
	  if(css->count > 1)
	    continue;

	  /* count this router as maybe not matching */
	  if((ptrc = sc_ptrc_get(rd_ri_tree, ri->ifaces[i]->ifd->rd)) == NULL)
	    goto done;
	  ptrc->c++;

	  if(sc_css_morespecific_ex(rd_css, ri_css, &css) != 0 ||
	     css == NULL || css->cssc != 1)
	    {
	      if(css != NULL)
		{
		  sc_css_free(css);
		  css = NULL;
		}
	      continue;
	    }
	  sc_css_morespecific_ov(rew, css, ri->ifaces[i]->ifd->iface, &cap);
	  sc_css_free(css); css = NULL;
	  caps[cap]++;
	}

      splaytree_inorder(rd_ri_tree, tree_to_slist, rd_ri_list);
      while((ptrc = slist_head_pop(rd_ri_list)) != NULL)
	{
	  if((ptrc = sc_ptrc_get(rd_tree, ptrc->ptr)) == NULL)
	    goto done;
	  ptrc->c++;
	}
      splaytree_empty(rd_ri_tree, (splaytree_free_t)sc_ptrc_free);
    }
  sc_rework_free(rew); rew = NULL;

  /*
   * if there are at least four routers that appear to be too specific,
   * then look further.  otherwise move on.
   */
  rc = splaytree_count(rd_tree);
  if(rc < 4)
    {
      rc = 0;
      goto done;
    }

  /* figure out the capture element that is likely the too specific one */
  cap = 0;
  for(i=1; i<=capc; i++)
    if(caps[cap] < caps[i])
      cap = i;
  if(cap == 0)
    goto done;
  free(caps); caps = NULL;

  /* build a regex that only matches this element */
  if((str = sc_regex_caponly(re->regexes[0]->str, cap)) == NULL)
    goto done;
  if((re_eval = sc_regex_alloc(str)) == NULL)
    goto done;
  str = NULL;
  re_eval->dom = re->dom;
  if((rew_eval = sc_rework_alloc(re_eval)) == NULL)
    goto done;

  /* loop through the interfaces, extracting the literals seen */
  splaytree_empty(css_tree, (splaytree_free_t)sc_css_free);
  for(sn=slist_head_node(re->dom->routers); sn != NULL; sn=slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      for(i=0; i<rd->ifacec; i++)
	{
	  if((x = sc_rework_match(rew_eval, rd->ifaces[i]->iface, &css)) < 0)
	    goto done;
	  if(x != 1 || css == NULL)
	    continue;
	  if(sc_css_get(css_tree, css) == NULL)
	    goto done;
	  sc_css_free(css);
	}
    }
  sc_rework_free(rew_eval); rew_eval = NULL;
  sc_regex_free(re_eval); re_eval = NULL;

  if((css_list = sc_css_reduce_ls(css_tree)) == NULL)
    goto done;
  splaytree_free(css_tree, (splaytree_free_t)sc_css_free); css_tree = NULL;

  /*
   * build a set of regexes that substitute a more specific extraction
   * with a supplied literal match
   */
  if((recss_list = dlist_alloc()) == NULL ||
     (re_tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL)
    goto done;
  while((css = dlist_head_pop(css_list)) != NULL)
    {
      if((str = sc_regex_caprep(re->regexes[0]->str,cap,0,css->css)) == NULL)
	goto done;
      if(sc_regex_find(re_tree, str) == NULL)
	{
	  /* create and evaluate a regex that matches with the literal */
	  if((re_eval = sc_regex_get(re_tree, str)) == NULL)
	    goto done;
	  re_eval->score = re->score + css->count;
	  re_eval->dom = re->dom;
	  if(sc_regex_eval(re_eval, NULL) != 0)
	    goto done;

	  /* tag the regex with the css */
	  if((recss = malloc_zero(sizeof(sc_regex_css_t))) == NULL)
	    goto done;
	  recss->regex = re_eval; re_eval = NULL;
	  recss->css = css; css = NULL;
	  if(dlist_tail_push(recss_list, recss) == NULL)
	    {
	      sc_regex_css_free(recss);
	      goto done;
	    }
	  re_eval = NULL;
	}
      if(css != NULL)
	{
	  sc_css_free(css);
	  css = NULL;
	}
      free(str); str = NULL;
    }
  splaytree_free(re_tree, NULL); re_tree = NULL;
  dlist_qsort(recss_list, (dlist_cmp_t)sc_regex_css_score_cmp);

  if(verbose != 0 && threadc == 1)
    {
      for(dn=dlist_head_node(recss_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  recss = dlist_node_item(dn);
	  printf("%s %s\n", recss->regex->regexes[0]->str,
		 sc_regex_score_tostr(recss->regex, buf, sizeof(buf)));
	}
    }

  /* take the top element off the list and assume its a good place to start */
  recss = dlist_head_pop(recss_list);
  if(dlist_tail_push(css_list, recss->css) == NULL)
    goto done;
  recss->css = NULL;
  re_work = recss->regex; recss->regex = NULL;
  sc_regex_css_free(recss); recss = NULL;

  /* build a set of inferences which we re-use */
  if((ifi_list = slist_alloc()) == NULL ||
     (ifi2_list = slist_alloc()) == NULL ||
     (ifi3_list = slist_alloc()) == NULL)
    goto done;

  for(;;)
    {
      slist_empty_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
      if(sc_regex_eval_ifi_build(re_work, ifi_list) != 0)
	goto done;

      /* build a new set of regexes that include the current working regex */
      dn = dlist_head_node(recss_list);
      while(dn != NULL)
	{
	  recss = dlist_node_item(dn); dn_this = dn;
	  dn = dlist_node_next(dn);

	  ren = recss->regex->regexes[0];
	  if((re_eval = sc_regex_tail_push(re_work, ren)) == NULL)
	    goto done;
	  re_eval->score = re_work->score + recss->regex->score;
	  if(recss->work != NULL) sc_regex_free(recss->work);
	  recss->work = re_eval; re_eval = NULL;

	  if(sc_regex_eval_ifi_build(recss->regex, ifi2_list) != 0 ||
	     sc_regex_eval_ifi_build2(ifi_list, ifi2_list,
				      recss->work->regexc-1, ifi3_list) != 0 ||
	     sc_regex_eval_ifi_score(recss->work, ifi3_list) != 0)
	    goto done;

	  slist_empty_cb(ifi2_list, (slist_free_t)sc_ifaceinf_free);
	  slist_foreach(ifi3_list, (slist_foreach_t)sc_ifaceinf_css_null,NULL);
	  slist_empty_cb(ifi3_list, (slist_free_t)sc_ifaceinf_free);

	  /* if the regex is no longer relevant, don't try it again */
	  if(recss->work->regexes[recss->work->regexc-1]->matchc <= 0)
	    {
	      sc_regex_css_free(recss);
	      dlist_node_pop(recss_list, dn_this);
	    }
	}
      dlist_qsort(recss_list, (dlist_cmp_t)sc_regex_css_work_score_cmp);

      if(verbose != 0 && threadc == 1)
	{
	  for(dn=dlist_head_node(recss_list);dn != NULL;dn=dlist_node_next(dn))
	    {
	      recss = dlist_node_item(dn);
	      printf("%s %s\n", recss->regex->regexes[0]->str,
		     sc_regex_score_tostr(recss->regex, buf, sizeof(buf)));
	    }
	}

      /* take the first regex refinement that is better */
      for(dn=dlist_head_node(recss_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  recss = dlist_node_item(dn);
	  if(sc_regex_fne_isbetter(re, re_work, recss->work) > 0)
	    {
#if 0
	      printf("%s\n%s\n",
		     recss->work->regexes[recss->work->regexc-1]->str,
		     sc_regex_score_tostr(recss->work, buf, sizeof(buf)));
#endif
	      dlist_node_pop(recss_list, dn);
	      sc_regex_free(re_work);
	      re_work = recss->work; recss->work = NULL;
	      dlist_tail_push(css_list, recss->css); recss->css = NULL;
	      sc_regex_css_free(recss); recss = NULL;
	      break;
	    }
	}
      if(dn == NULL)
	break;
    }

  /* make sure there is no redundancy in the set of literals */
  if(sc_regex_css_thin(re, cap, css_list) != 0)
    goto done;
  sc_regex_free(re_work); re_work = NULL;
  str = sc_regex_caprep_list(re->regexes[0]->str, cap, css_list);
  if(str == NULL)
    goto done;
  if((re_work = sc_regex_alloc(str)) == NULL)
    goto done;
  str = NULL;
  re_work->dom = re->dom;
  re_work->score = re->score;
  for(dn=dlist_head_node(css_list); dn != NULL; dn=dlist_node_next(dn))
    {
      css = dlist_node_item(dn);
      re_work->score += css->count;
    }
  if(sc_regex_eval(re_work, NULL) != 0)
    goto done;

  if(sc_regex_fne_isbetter2(re, re_work) > 0)
    {
      if(sc_domain_lock(re->dom) != 0)
	goto done;
      if(slist_tail_push(re->dom->regexes, re_work) == NULL)
	goto done;
      sc_domain_unlock(re->dom);
      re_work = NULL;
    }
  else if(verbose != 0 && threadc == 1)
    {
      printf("%s %s\n",
	     re_work->regexes[0]->str,
	     sc_regex_score_tostr(re_work, buf, sizeof(buf)));
      printf("is not better than\n");
      printf("%s %s\n",
	     re->regexes[0]->str, sc_regex_score_tostr(re, buf, sizeof(buf)));
      printf("\n");
    }

  rc = 0;

 done:
  if(ifi3_list != NULL)
    {
      slist_foreach(ifi3_list, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
      slist_free_cb(ifi3_list, (slist_free_t)sc_ifaceinf_free);
    }
  if(ifi2_list != NULL)
    {
      slist_foreach(ifi2_list, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
      slist_free_cb(ifi2_list, (slist_free_t)sc_ifaceinf_free);
    }
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(recss_list != NULL)
    dlist_free_cb(recss_list, (dlist_free_t)sc_regex_css_free);
  if(list != NULL) slist_free(list);
  if(rd_tree != NULL) splaytree_free(rd_tree, (splaytree_free_t)sc_ptrc_free);
  if(re_tree != NULL) splaytree_free(re_tree, NULL);
  if(rd_ri_tree != NULL)
    splaytree_free(rd_ri_tree, (splaytree_free_t)sc_ptrc_free);
  if(rd_ri_list != NULL) slist_free(rd_ri_list);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(css_tree != NULL) splaytree_free(css_tree, (splaytree_free_t)sc_css_free);
  if(css_list != NULL) dlist_free_cb(css_list, (dlist_free_t)sc_css_free);
  if(caps != NULL) free(caps);
  if(str != NULL) free(str);
  if(re_eval != NULL) sc_regex_free(re_eval);
  if(re_work != NULL) sc_regex_free(re_work);
  if(rew_eval != NULL) sc_rework_free(rew_eval);
  if(rew != NULL) sc_rework_free(rew);
  return rc;
}

static int sc_regex_refine_init(const sc_regex_t *re, const sc_rework_t *rew,
				int *Xc, int **Xa, int *LXc, int **LXa,
				sc_css_t **capcss, sc_regex_t **capre,
				sc_rework_t **caprew)
{
  int i, rc = -1;

  *Xa = NULL; *LXa = NULL;
  *capcss = NULL; *capre = NULL; *caprew = NULL;

  *Xc = sc_rework_capcount(rew, 0);
  if((*Xa = malloc(sizeof(int) * *Xc * 2)) == NULL)
    goto done;

  /* extract the capture portion of the regex */
  if(sc_regex_capget_css(re->regexes[0]->str, capcss) != 0)
    goto done;
  if((*capcss)->cssc != *Xc)
    goto done;

  /*
   * build a regex that allows us to pick out the literal components in
   * the extraction component of a regex.  check that there are actually
   * literal components at least somewhere...
   */
  if((*capre = sc_regex_alloc_css(*capcss)) == NULL)
    goto done;
  *LXc = 0;
  for(i=0; i<(*capre)->regexc; i++)
    *LXc += (*capre)->regexes[i]->capc;
  if(*LXc == 0)
    {
      sc_regex_free(*capre);
      *capre = NULL;
    }
  else
    {
      if((*LXa = malloc(sizeof(int) * *LXc * 2)) == NULL ||
	 (*caprew = sc_rework_alloc(*capre)) == NULL)
	goto done;
#if 0
      printf("%s\n", sc_css_tostr(*capcss, '|', buf, sizeof(buf)));
      for(i=0; i<(*capre)->regexc; i++)
	printf(" %s\n", (*capre)->regexes[i]->str);
#endif
    }

  rc = 0;

 done:
  return rc;
}

static int sc_regex_refine_class_seg(slist_t *list, sc_regex_t *re, int ro_in,
				     char *buf, size_t len, size_t off_in,
				     slist_t **segs, int c, int cc, int adj)
{
  sc_segscore_t *ss;
  slist_node_t *sn;
  size_t off = off_in, off_x, segl;
  int ro = ro_in;
  char *dup, *res = re->regexes[0]->str;
  sc_regex_t *re_new;

  if(c == cc)
    {
      while(res[ro] != '\0')
	buf[off++] = res[ro++];
      buf[off++] = '\0';
      if((dup = strdup(buf)) == NULL)
	return -1;
      if((re_new = sc_regex_alloc(dup)) == NULL)
	{
	  free(dup);
	  return -1;
	}
      re_new->dom = re->dom;
      re_new->score = re->score + adj;
      if(slist_tail_push(list, re_new) == NULL)
	{
	  sc_regex_free(re_new);
	  return -1;
	}
      return 0;
    }

  while(res[ro] != '\0')
    {
      if(res[ro] == '[' || (res[ro] == '.' && res[ro+1] == '+'))
	{
	  if(res[ro] == '[')
	    {
	      while(res[ro] != '\0' && res[ro] != ']')
		ro++;
	      if(res[ro] != ']' || res[ro+1] != '+')
		return -1;
	      adj -= 1;
	    }
	  ro += 2;

	  off_x = off;
	  for(sn=slist_head_node(segs[c]); sn != NULL; sn=slist_node_next(sn))
	    {
	      ss = slist_node_item(sn);
	      off = off_x;

	      /* string_concat(buf, len, &off, "%s", ss->seg); */
	      segl = strlen(ss->seg);
	      if(len - off < segl + 1)
		return -1;
	      memcpy(buf+off, ss->seg, segl + 1); off += segl;

	      if(sc_regex_refine_class_seg(list, re, ro, buf, len, off,
					   segs, c+1, cc,
					   adj + ss->score) != 0)
		return -1;
	    }
	  return 0;
	}
      else if(res[ro] == '\\')
	{
	  buf[off++] = res[ro++];
	  buf[off++] = res[ro++];
	}
      else
	{
	  buf[off++] = res[ro++];
	}
    }

  return -1;
}

/*
 * sc_regex_refine_class_do
 *
 *
 */
static int sc_regex_refine_class_do(sc_regex_t *re, slist_t *ifd_list,
				    slist_t *out)
{
  splaytree_t **trees = NULL, *seg_tree = NULL;
  slist_t *list = NULL, *re_list = NULL, **segs = NULL;
  sc_regex_t *capre = NULL;
  sc_rework_t *caprew = NULL;
  sc_ifacedom_t *ifd;
  slist_node_t *sn;
  sc_css_t *css = NULL;
  sc_segscore_t *ss = NULL;
  char *str = NULL, *ptr, *dup, buf[256];
  int switchc, alpha, digit, score;
  int i, j, x, cc = 0, rc = -1;
  size_t off, len;

  if((str = sc_regex_capseg(re->regexes[0]->str)) == NULL)
    goto done;
  if((capre = sc_regex_alloc(str)) == NULL)
    goto done;
  str = NULL;
  if((caprew = sc_rework_alloc(capre)) == NULL)
    goto done;
  if((cc = sc_rework_capcount(caprew, 0)) == 0)
    {
      rc = 0;
      goto done;
    }

  if((trees = malloc_zero(sizeof(splaytree_t *) * cc)) == NULL ||
     (list = slist_alloc()) == NULL)
    goto done;

  for(i=0; i<cc; i++)
    if((trees[i] = splaytree_alloc((splaytree_cmp_t)strcmp)) == NULL)
      goto done;

  for(sn=slist_head_node(ifd_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifd = slist_node_item(sn);
      if((x = sc_rework_match(caprew, ifd->iface, &css)) < 0)
	goto done;
      if(x == 0)
	continue;
      ptr = css->css;
      for(j=0; j<css->cssc; j++)
	{
	  if(splaytree_find(trees[j], ptr) == NULL)
	    {
	      if((dup = strdup(ptr)) == NULL ||
		 splaytree_insert(trees[j], dup) == NULL)
		goto done;
	    }
	  while(*ptr != '\0')
	    ptr++;
	  ptr++;
	}
      sc_css_free(css); css = NULL;
    }

  if((seg_tree = splaytree_alloc((splaytree_cmp_t)sc_segscore_cmp)) == NULL)
    goto done;
  if((segs = malloc_zero(sizeof(slist_t *) * cc)) == NULL)
    goto done;

  for(i=0; i<cc; i++)
    {
      splaytree_inorder(trees[i], tree_to_slist, list);
      assert(slist_count(list) > 0);

      if((segs[i] = slist_alloc()) == NULL)
	goto done;
      if(slist_count(list) == 1 && re->rt_c >= 2)
	{
	  ptr = slist_head_pop(list);
	  if(string_isdigit(ptr) != 0)
	    ss = sc_segscore_alloc("\\d+", 3);
	  else
	    ss = sc_segscore_alloc(ptr, 4);
	  if(ss == NULL || slist_tail_push(segs[i], ss) == NULL)
	    goto done;
	  ss = NULL;
	  continue;
	}

      for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
	{
	  ptr = slist_node_item(sn);
	  off = 0; alpha = 0; digit = 0; switchc = 0; score = 0;

	  while(*ptr != '\0')
	    {
	      if(isdigit(*ptr) != 0)
		{
		  if(digit == 0)
		    {
		      if(digit == 0) switchc++;
		      digit = 1; alpha = 0;
		      /* string_concat(buf, sizeof(buf), &off, "\\d+"); */
		      if(sizeof(buf) - off < 4)
			goto done;
		      buf[off++] = '\\'; buf[off++] = 'd'; buf[off++] = '+';
		      buf[off] = '\0';
		      score += 3;
		    }
		}
	      else if(isalpha(*ptr) != 0)
		{
		  if(alpha == 0)
		    {
		      if(alpha == 0) switchc++;
		      alpha = 1; digit = 0;
		      /* string_concat(buf, sizeof(buf), &off, "[a-z]+"); */
		      if(sizeof(buf) - off < 7)
			goto done;
		      buf[off++] = '['; buf[off++] = 'a'; buf[off++] = '-';
		      buf[off++] = 'z'; buf[off++] = ']'; buf[off++] = '+';
		      buf[off] = '\0';
		      score += 3;
		    }
		}
	      else break;
	      ptr++;
	    }

	  if(*ptr != '\0' || switchc == 0)
	    {
	      if(sc_regex_capget(capre->regexes[0]->str, i+1,
				 buf, sizeof(buf)) != 0)
		goto done;
	      if(strcmp(buf, ".+") == 0)
		score = 0;
	      else
		score = 1;
	      if(sc_segscore_get(seg_tree, buf, score) != 0)
		goto done;
	      continue;
	    }

	  if(switchc <= 2 && sc_segscore_get(seg_tree, buf, score) != 0)
	    goto done;
	  if(switchc > 0 && sc_segscore_get(seg_tree, "[a-z\\d]+", 2) != 0)
	    goto done;
	}

      splaytree_inorder(seg_tree, tree_to_slist, segs[i]);
      splaytree_empty(seg_tree, NULL);
      slist_empty(list);
    }

  if(verbose != 0 && threadc == 1)
    {
      for(i=0; i<cc; i++)
	{
	  for(sn=slist_head_node(segs[i]); sn != NULL; sn=slist_node_next(sn))
	    {
	      ss = slist_node_item(sn);
	      printf("%d %s %d\n", i, ss->seg, ss->score);
	    }
	}
    }

  if((re_list = slist_alloc()) == NULL)
    goto done;
  len = strlen(re->regexes[0]->str) * 3;
  if((str = malloc(len)) == NULL)
    goto done;
  sc_regex_refine_class_seg(re_list, re, 0, str, len, 0, segs, 0, cc, 0);
  free(str); str = NULL;

  slist_concat(out, re_list);
  rc = 0;

 done:
  if(trees != NULL)
    {
      for(i=0; i<cc; i++)
	splaytree_free(trees[i], free);
      free(trees);
    }
  if(seg_tree != NULL)
    splaytree_free(seg_tree, (splaytree_free_t)sc_segscore_free);
  if(segs != NULL)
    {
      for(i=0; i<cc; i++)
	if(segs[i] != NULL)
	  slist_free_cb(segs[i], (slist_free_t)sc_segscore_free);
      free(segs);
    }
  if(list != NULL) slist_free(list);
  if(re_list != NULL) slist_free_cb(re_list, (slist_free_t)sc_regex_free);
  if(capre != NULL) sc_regex_free(capre);
  if(caprew != NULL) sc_rework_free(caprew);
  if(str != NULL) free(str);
  return rc;
}

/*
 * sc_regex_refine_class_tree
 *
 * work through the list of classless regexes, adding additional
 * unique regexes that embed classes
 */
static int sc_regex_refine_class_tree(splaytree_t *re_tree, slist_t *ifd_list)
{
  slist_t *re_tree_list = NULL, *re_list = NULL;
  sc_regex_t *re, *re_new = NULL;
  slist_node_t *sn, *sn_tail;
  int rc = -1;

  if((re_tree_list = slist_alloc()) == NULL ||
     (re_list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(re_tree, tree_to_slist, re_tree_list);
  sn_tail = slist_tail_node(re_tree_list);
  for(sn=slist_head_node(re_tree_list); sn != NULL; sn=slist_node_next(sn))
    {
      re = slist_node_item(sn);
      if(sc_regex_refine_class_do(re, ifd_list, re_list) != 0)
	goto done;
      while((re_new = slist_head_pop(re_list)) != NULL)
	{
	  if(splaytree_find(re_tree, re_new) != NULL)
	    {
	      sc_regex_free(re_new); re_new = NULL;
	      continue;
	    }
	  if(splaytree_insert(re_tree, re_new) == NULL)
	    goto done;
	}
      if(sn == sn_tail)
	break;
    }

  rc = 0;

 done:
  if(re_new != NULL) sc_regex_free(re_new);
  if(re_list != NULL) slist_free_cb(re_list, (slist_free_t)sc_regex_free);
  if(re_tree_list != NULL) slist_free(re_tree_list);
  return rc;
}

/*
 * sc_regex_refine_class
 *
 * given an input regex, add character classes
 */
static int sc_regex_refine_class(sc_regex_t *re)
{
  splaytree_t **trees = NULL, *seg_tree = NULL;
  slist_t *ri_list = NULL, *ifd_list = NULL, *re_list = NULL;
  sc_regex_t *capre = NULL, *re_eval;
  sc_rework_t *caprew = NULL;
  sc_routerinf_t *ri;
  sc_ifaceinf_t *ifi;
  slist_node_t *sn;
  char *str = NULL, buf[256];
  int i, cc = 0, rc = -1;

  if((ifd_list = slist_alloc()) == NULL || (re_list = slist_alloc()) == NULL ||
     (ri_list = slist_alloc()) == NULL || sc_regex_eval(re, ri_list) != 0)
    goto done;

  /* assemble the set of interfaces we want to train with */
  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);
      if(ri->ifacec == 1 || ri->ip != 0)
	continue;
      for(i=0; i<ri->ifacec; i++)
	{
	  ifi = ri->ifaces[i];
	  if(ifi->class != '+')
	    continue;
	  if(slist_tail_push(ifd_list, ifi->ifd) == NULL)
	    goto done;
	}
    }
  slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free); ri_list = NULL;

  /* get the set of regexes and evaluate them */
  if(sc_regex_refine_class_do(re, ifd_list, re_list) != 0)
    goto done;
  slist_free(ifd_list); ifd_list = NULL;
  for(sn=slist_head_node(re_list); sn != NULL; sn=slist_node_next(sn))
    {
      re_eval = slist_node_item(sn);
      sc_regex_eval(re_eval, NULL);
    }
  slist_qsort(re_list, (slist_cmp_t)sc_regex_score_rank_cmp);

  if(verbose != 0 && threadc == 1)
    {
      for(sn=slist_head_node(re_list); sn != NULL; sn=slist_node_next(sn))
	{
	  re_eval = slist_node_item(sn);
	  printf("%s %s\n", re_eval->regexes[0]->str,
		 sc_regex_score_tostr(re_eval, buf, sizeof(buf)));
	}
    }

  thin_regexes_domain(re_list, 0x7);
  if(sc_domain_lock(re->dom) != 0)
    goto done;
  slist_concat(re->dom->regexes, re_list);
  sc_domain_unlock(re->dom);

  rc = 0;

 done:
  if(trees != NULL)
    {
      for(i=0; i<cc; i++)
	splaytree_free(trees[i], free);
      free(trees);
    }
  if(seg_tree != NULL)
    splaytree_free(seg_tree, (splaytree_free_t)sc_segscore_free);
  if(re_list != NULL) slist_free_cb(re_list, (slist_free_t)sc_regex_free);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(ifd_list != NULL) slist_free(ifd_list);
  if(capre != NULL) sc_regex_free(capre);
  if(caprew != NULL) sc_rework_free(caprew);
  if(str != NULL) free(str);
  return rc;
}

static int sc_regex_fnu_isbetter(sc_regex_t *cur, sc_regex_t *can, int i)
{
  uint32_t cur_tp, cur_fp, cur_ppv;
  uint32_t del_tp, del_fp, del_ppv;
  uint32_t can_tp, can_fp;

  /*
   * if the current regex has more true positives than the candidate,
   * then this refinement cannot be better.
   */
  if(cur->tp_c >= can->tp_c)
    return 0;

  /*
   * the candidate refinement must find at least three more routers
   * and affect 4% of routers to be better.
   */
  if(can->regexes[i]->rt_c < 3 ||
     (can->regexes[i]->rt_c * 100) / cur->rt_c < 4)
    return 0;

  /*
   * if there are any new false positives, determine if rate of false
   * positives seems reasonable
   */
  can_fp = can->fp_c + can->ip_c;
  cur_fp = cur->fp_c + cur->ip_c;
  if(can_fp > cur_fp)
    {
      can_tp = can->tp_c;
      cur_tp = cur->tp_c;
      del_tp = can_tp - cur_tp;
      del_fp = can_fp - cur_fp;
      cur_ppv = (cur_tp * 1000) / (can_tp + can_fp);
      del_ppv = (del_tp * 1000) / (del_tp + del_fp);

      /*
       * if the PPV of the candidate regex is less than the current
       * regex, and worse by more than 0.5%, then it is not better
       */
      if(cur_ppv > del_ppv && cur_ppv - del_ppv > 5)
	return 0;
    }

  return 1;
}

/*
 * sc_regex_refine_fnu
 *
 * figure out regexes that should be paired with another candidate regex,
 * where the candidate regex infers a name, but the regex does not match.
 */
static int sc_regex_refine_fnu(sc_regex_t *re)
{
  static const uint16_t mask = RB_BASE | RB_SEG_LITERAL | RB_SEG_DIGIT;
  sc_routername_t **rnames = NULL, *rn;
  sc_regex_t *re_eval = NULL, *re_new = NULL, *re_cur = NULL, *re_fnu = NULL;
  slist_t *ri_list = NULL, *ifp_list = NULL, *css_list = NULL;
  splaytree_t *css_tree = NULL, *ifp_tree = NULL, *re_tree = NULL;
  dlist_t *re_list = NULL; slist_t *re2_list = NULL;
  slist_t *ifi_list = NULL, *ifi2_list = NULL, *ifi3_list = NULL;
  slist_t *fnu_list = NULL, *re_set = NULL;
  int *Xa = NULL, Xc, *La = NULL, Lc, *bits = NULL, bitc;
  int r, i, c, d, rc = -1, rnamec = 0;
  sc_rework_t *rew = NULL;
  sc_routerdom_t *rd;
  sc_ifacedom_t *ifd;
  sc_ifdptr_t *ifp;
  sc_ifaceinf_t *ifi;
  slist_node_t *sn;
  dlist_node_t *dn, *dn_this;
  sc_css_t *css;
  sc_css_t *capcss = NULL;
  sc_regex_t *capre = NULL;
  sc_rework_t *caprew = NULL;
  int *LXa = NULL, LXc, LXi, *LAa = NULL, LAc;
  uint32_t tp, fp;
  char buf[256], rebuf[256], *ptr = NULL;

  tp = re->tp_c;
  fp = re->fp_c + re->ip_c;
  if(tp + fp == 0 || tp * 100 / (tp + fp) < 90)
    return 0;

  rnamec = slist_count(re->dom->routers);
  if((rew = sc_rework_alloc(re)) == NULL ||
     (rnames = sc_routernames_alloc(re->dom->routers, rew)) == NULL ||
     (ifp_tree = sc_ifdptr_tree(re->dom->routers)) == NULL ||
     (css_tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL ||
     (re_tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL ||
     (re_list = dlist_alloc()) == NULL ||
     (re2_list = slist_alloc()) == NULL ||
     (css_list = slist_alloc()) == NULL ||
     (ri_list = slist_alloc()) == NULL ||
     sc_regex_eval(re, ri_list) != 0 ||
     sc_ifdptr_tree_ri(ifp_tree, ri_list) != 0)
    goto done;

  if(sc_regex_refine_init(re, rew, &Xc, &Xa, &LXc, &LXa,
			  &capcss, &capre, &caprew) != 0)
    goto done;

  for(r=0; r<rnamec; r++)
    {
      rn = rnames[r];
      rd = rn->rd;
      if(rn->css == NULL)
	continue;

      for(i=0; i<rd->ifacec; i++)
	{
	  ifd = rd->ifaces[i];
	  ifp = sc_ifdptr_find(ifp_tree, ifd); assert(ifp != NULL);
	  ifi = ifp->ptr; assert(ifi != NULL);

	  /* if regex matched then skip this interface */
	  if(ifi->css != NULL && sc_css_css_cmp(ifi->css, rn->css) == 0)
	    continue;

	  /* get the parts of the hostname that were not extracted */
	  if((css = sc_css_matchxor(rn->css, ifd)) != NULL)
	    {
	      if(css->cssc > 0)
		{
		  if(sc_css_get(css_tree, css) == NULL)
		    goto done;
		}
	      else if(Xc == 1 && splaytree_count(re_tree) == 0)
		{
		  /*
		   * if there was no extraction, infer that the entire
		   * hostname is to be extracted, and build a regex
		   * that uses the same capture component
		   */
		  if(sc_regex_capget(re->regexes[0]->str,1,buf,sizeof(buf))!=0)
		    continue;
		  if(snprintf(rebuf, sizeof(rebuf), "^(%s)\\.%s$",
			      buf, re->dom->escape) >= sizeof(rebuf))
		    goto done;
		  if((re_new = sc_regex_get(re_tree, rebuf)) == NULL)
		    goto done;
		  re_new->dom = re->dom;
		  re_new->score = re->score; /* XXX: increase score? */
		  re_new = NULL;
		}
	      sc_css_free(css);
	    }
	}
    }

  if(sc_css_reduce(css_tree, 1, 1) != 0) /* trim on non-alnum, min length 1 */
    goto done;
  if(sc_css_reduce(css_tree, 2, 1) != 0) /* trim on char class, min length 1 */
    goto done;
  splaytree_inorder(css_tree, tree_to_slist, css_list);
  splaytree_free(css_tree, NULL); css_tree = NULL;

  for(sn=slist_head_node(css_list); sn != NULL; sn=slist_node_next(sn))
    {
      css = slist_node_item(sn);

      /* skip over css where we don't have any alpha characters */
      if(sc_css_hasalpha(css) == 0)
	continue;

      /*
       * allocate an array large enough to store where the literal can
       * be found
       */
      Lc = css->cssc;
      if((La = malloc(sizeof(int) * Lc * 2)) == NULL)
	goto done;
      if((LAa = malloc(sizeof(int) * (Lc+LXc) * 2)) == NULL)
	goto done;
      LAc = Lc + LXc;

      /*
       * go through the routers and build regexes for false negatives
       * that the current regex did not match
       */
      for(r=0; r<rnamec; r++)
	{
	  rn = rnames[r];
	  rd = rn->rd;
	  if(rn->css == NULL)
	    continue;

	  for(i=0; i<rd->ifacec; i++)
	    {
	      ifd = rd->ifaces[i];
	      ifp = sc_ifdptr_find(ifp_tree, ifd); assert(ifp != NULL);
	      ifi = ifp->ptr; assert(ifi != NULL);

	      /* if regex matched then skip this interface */
	      if(ifi->css != NULL && sc_css_css_cmp(ifi->css, rn->css) == 0)
		continue;

	      /* if router name is not found in this interface, skip */
	      if(sc_css_match(rn->css, ifd->label, Xa, 1) != 1)
		continue;

	      /*
	       * if the literal is not found in this interface, skip
	       * XXX: need to xor the name out.
	       */
	      if(sc_css_match(css, ifd->label, La, 0) == 0)
		continue;

	      /*
	       * make sure La and Xa do not overlap, i.e. the literal
	       * is not allowed to be within the extraction
	       */
	      if(threadc == 1 && verbose != 0)
		printf("%s %s\n", ifd->label,
		       sc_css_tostr(css, '|', buf, sizeof(buf)));
	      if(pt_overlap(Xa, Xc * 2, La, Lc * 2) != 0)
		continue;

	      if(capre != NULL)
		{
		  LXi = 0;
		  ptr = rn->css->css;
		  for(c=0; c<capre->regexc; c++)
		    {
		      if(capre->regexes[c]->capc > 0 &&
			 sc_rework_matchk(caprew, c, ptr) == 1)
			{
			  for(d=1; d<caprew->m; d++)
			    {
			      LXa[LXi++] = Xa[2*c]+caprew->ovector[2*d];
			      LXa[LXi++] = Xa[2*c]+caprew->ovector[(2*d)+1]-1;
			    }
			}
		      while(*ptr != '\0')
			ptr++;
		      ptr++;
		    }
		  ptr = NULL;
		  pt_merge(LAa, La, Lc, LXa, LXc);
		}
	      else
		{
		  memcpy(LAa, La, Lc * 2 * sizeof(int));
		}

	      if(pt_to_bits(ifd->label, Xa,Xc*2, LAa,LAc*2, &bits, &bitc) == 0)
		{
		  /* 0xff, no char classes */
		  if(sc_regex_build(re_tree, ifd->label, re->dom, mask,
				    bits, bitc) != 0)
		    goto done;
		}
	      if(bits != NULL)
		{
		  free(bits);
		  bits = NULL;
		}
	    }
	}

      free(LAa); LAa = NULL;
      free(La); La = NULL;
    }

  splaytree_inorder(re_tree, tree_to_dlist, re_list);
  splaytree_empty(re_tree, NULL);

  /*
   * make sure the capture format matches the base regex by
   * substituting in the capture from the base.
   */
  for(dn = dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
    {
      re_eval = dlist_node_item(dn);
      if((ptr = sc_regex_caprep_css(re_eval->regexes[0]->str, capcss)) == NULL)
	continue;
      if((re_new = sc_regex_alloc(ptr)) == NULL)
	goto done;
      ptr = NULL;
      if((re_fnu = splaytree_find(re_tree, re_new)) != NULL)
	{
	  if(re_fnu->score < re_eval->score)
	    re_fnu->score = re_eval->score;
	  re_fnu = NULL;
	  sc_regex_free(re_new); re_new = NULL;
	  continue;
	}
      re_new->dom = re_eval->dom;
      re_new->score = re_eval->score;
      if(splaytree_insert(re_tree, re_new) == NULL)
	goto done;
    }
  dlist_empty_cb(re_list, (dlist_free_t)sc_regex_free);
  splaytree_inorder(re_tree, tree_to_dlist, re_list);
  splaytree_free(re_tree, NULL); re_tree = NULL;

  if(threadc == 1 && verbose != 0)
    {
      for(dn=dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  re_eval = dlist_node_item(dn);
	  printf("%s\n", re_eval->regexes[0]->str);
	  re_eval = NULL;
	}
    }

  /* build a set of inferences which we re-use */
  if((ifi_list = slist_alloc()) == NULL ||
     (ifi2_list = slist_alloc()) == NULL ||
     (ifi3_list = slist_alloc()) == NULL)
    goto done;

  /* put the regexes into a new list to concat at the end */
  if((re_set = slist_alloc()) == NULL ||
     (fnu_list = slist_alloc()) == NULL)
    goto done;

  re_cur = sc_regex_dup(re);
  for(;;)
    {
      /* in this block, if r == 0 then we should not loop around */
      r = 0;

      slist_empty_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
      if(sc_regex_eval_ifi_build(re_cur, ifi_list) != 0)
	goto done;

      /* try every candidate regex paired with the current regex */
      dn = dlist_head_node(re_list);
      while(dn != NULL)
	{
	  re_eval = dlist_node_item(dn); dn_this = dn;
	  dn = dlist_node_next(dn);

	  if(sc_regex_permute(re_cur, ifi_list, re_eval, re_set) != 0)
	    goto done;
	  if(slist_count(re_set) == 0)
	    {
	      if(threadc == 1 && verbose != 0)
		printf("no matches %s\n", re_eval->regexes[0]->str);
	      sc_regex_free(re_eval); re_eval = NULL;
	      dlist_node_pop(re_list, dn_this);
	      continue;
	    }

	  /* select the best permutation */
	  re_new = slist_head_pop(re_set);
	  if(slist_tail_push(re2_list, re_new) == NULL)
	    goto done;
	  re_new = NULL;
	  slist_empty_cb(re_set, (slist_free_t)sc_regex_free);
	}
      slist_qsort(re2_list, (slist_cmp_t)sc_regex_score_rank_cmp);

      /* check if any of the paired regexes are better than the current */
      while((re_new = slist_head_pop(re2_list)) != NULL)
	{
	  i = sc_regex_findnew(re_cur, re_new);

	  /* if this regex is no better, then discard it */
	  if(sc_regex_fnu_isbetter(re_cur, re_new, i) != 1)
	    {
	      sc_regex_free(re_new);
	      re_new = NULL;
	      continue;
	    }

	  /*
	   * if the new regex is better than the current regex, put it
	   * in a list for further processing when we finish
	   */
	  if((ptr = strdup(re_new->regexes[i]->str)) == NULL ||
	     (re_fnu = sc_regex_alloc(ptr)) == NULL)
	    goto done;
	  ptr = NULL;
	  if(slist_tail_push(fnu_list, re_fnu) == NULL)
	    goto done;
	  re_fnu->score = re_new->score - re_cur->score;
	  re_fnu->dom = re->dom;
	  re_fnu = NULL;

	  /*
	   * update the current regex so that we can efficiently find
	   * other productive regexes, and loop again (r = 1)
	   */
	  sc_regex_free(re_cur);
	  re_cur = re_new; re_new = NULL;
	  r = 1;
	  break;
	}
      slist_empty_cb(re2_list, (slist_free_t)sc_regex_free);

      /* do not loop anymore */
      if(r == 0)
	break;
    }

  for(sn=slist_head_node(fnu_list); sn != NULL; sn=slist_node_next(sn))
    {
      re_fnu = slist_node_item(sn);
      sc_regex_eval(re_fnu, NULL);
      re_fnu = NULL;
    }

  if(sc_domain_lock(re->dom) != 0)
    goto done;
  slist_concat(re->dom->regexes, fnu_list);
  sc_domain_unlock(re->dom);

  rc = 0;

 done:
  if(ifi3_list != NULL)
    {
      slist_foreach(ifi3_list, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
      slist_free_cb(ifi3_list, (slist_free_t)sc_ifaceinf_free);
    }
  if(ifi2_list != NULL)
    {
      slist_foreach(ifi2_list, (slist_foreach_t)sc_ifaceinf_css_null, NULL);
      slist_free_cb(ifi2_list, (slist_free_t)sc_ifaceinf_free);
    }
  if(ifi_list != NULL) slist_free_cb(ifi_list, (slist_free_t)sc_ifaceinf_free);
  if(La != NULL) free(La);
  if(LAa != NULL) free(LAa);
  if(LXa != NULL) free(LXa);
  if(Xa != NULL) free(Xa);
  if(ptr != NULL) free(ptr);
  if(capcss != NULL) sc_css_free(capcss);
  if(capre != NULL) sc_regex_free(capre);
  if(caprew != NULL) sc_rework_free(caprew);
  if(rew != NULL) sc_rework_free(rew);
  if(rnames != NULL) sc_routernames_free(rnames, rnamec);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(ifp_list != NULL) slist_free(ifp_list);
  if(ifp_tree != NULL)
    splaytree_free(ifp_tree, (splaytree_free_t)sc_ifdptr_free);
  if(css_tree != NULL) splaytree_free(css_tree, (splaytree_free_t)sc_css_free);
  if(re_tree != NULL) splaytree_free(re_tree, (splaytree_free_t)sc_regex_free);
  if(re_list != NULL) dlist_free_cb(re_list, (dlist_free_t)sc_regex_free);
  if(re2_list != NULL) slist_free_cb(re2_list, (slist_free_t)sc_regex_free);
  if(fnu_list != NULL) slist_free_cb(fnu_list, (slist_free_t)sc_regex_free);
  if(re_set != NULL) slist_free_cb(re_set, (slist_free_t)sc_regex_free);
  if(css_list != NULL) slist_free_cb(css_list, (slist_free_t)sc_css_free);
  if(re_new != NULL) sc_regex_free(re_new);
  if(re_cur != NULL) sc_regex_free(re_cur);
  if(re_fnu != NULL) sc_regex_free(re_fnu);
  return rc;
}

/*
 * sc_regex_refine_ip
 *
 * figure out regexes to filter out extractions that contain at least portion
 * of an IP literal
 */
static int sc_regex_refine_ip(sc_regex_t *re)
{
  static const uint16_t mask =
    RB_BASE | RB_SEG_LITERAL_IP | RB_SEG_DIGIT | RB_SEG_LITERAL;
  static const uint16_t mask_nolit =
    RB_BASE | RB_SEG_LITERAL_IP | RB_SEG_DIGIT;
  slist_t *ifd_list = NULL, *ri_list = NULL, *css_list = NULL;
  dlist_t *re_list = NULL;
  sc_domain_t *dom = re->dom;
  splaytree_t *css_tree = NULL, *re_tree = NULL;
  sc_routerinf_t *ri;
  sc_ifacedom_t *ifd;
  slist_node_t *sn, *sn2;
  dlist_node_t *dn, *dn_this;
  sc_css_t *css;
  sc_regex_t *re_ip = NULL, *re_new = NULL;
  int i, rc = -1, *I_array = NULL;
  int *bits = NULL, bitc;
  char buf[256];

  if((re_tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL)
    goto done;

  if((ifd_list = slist_alloc()) == NULL || (ri_list = slist_alloc()) == NULL ||
     (css_tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL)
    goto done;
  if(sc_regex_eval(re, ri_list) != 0)
    goto done;

  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);
      for(i=0; i<ri->ifacec; i++)
	if(ri->ifaces[i]->class == 'x' &&
	   slist_tail_push(ifd_list, ri->ifaces[i]->ifd) == NULL)
	  goto done;
    }

  for(sn=slist_head_node(ifd_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifd = slist_node_item(sn);

      /* generate a regex covering only the IP address, no literals */
      if(pt_to_bits_ip(ifd, NULL, 0, &bits, &bitc) == 0)
	{
	  if(sc_regex_build(re_tree,ifd->label,dom,mask_nolit,bits,bitc) != 0)
	    goto done;
	}
      if(bits != NULL)
	{
	  free(bits);
	  bits = NULL;
	}

      if(ifd->iface->ip_s == 0 && ifd->label[ifd->iface->ip_e+1] == '\0')
	continue;

      if(sc_ifacedom_css(ifd, &css, 0) != 0)
	goto done;
      if(css == NULL)
	continue;

      /* insert the css if not already present */
      if(sc_css_get(css_tree, css) == NULL)
	goto done;
      sc_css_free(css);
    }
  if(sc_css_reduce(css_tree, 1, 1) != 0) /* trim on non-alnum, min length 1 */
    goto done;
  if(sc_css_reduce(css_tree, 2, 1) != 0) /* trim on char class, min length 1 */
    goto done;

  /* use literals to build regexes */
  if((css_list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(css_tree, tree_to_slist, css_list);

  for(sn=slist_head_node(css_list); sn != NULL; sn=slist_node_next(sn))
    {
      css = slist_node_item(sn);
      I_array = malloc(sizeof(int) * 2 * css->cssc);
      for(sn2=slist_head_node(ifd_list); sn2 != NULL; sn2=slist_node_next(sn2))
	{
	  ifd = slist_node_item(sn2);
	  if(sc_css_match(css, ifd->label, I_array, 0) == 1)
	    {
	      if(pt_to_bits_ip(ifd, I_array, css->cssc * 2, &bits, &bitc) == 0)
		{
		  if(sc_regex_build(re_tree,ifd->label,dom,mask,bits,bitc) != 0)
		    goto done;
		}
	      if(bits != NULL)
		{
		  free(bits);
		  bits = NULL;
		}
	    }
	}
      free(I_array); I_array = NULL;
    }

  /* add classes to the regexes */
  if(sc_regex_refine_class_tree(re_tree, ifd_list) != 0)
    goto done;

  if((re_list = dlist_alloc()) == NULL)
    goto done;
  splaytree_inorder(re_tree, tree_to_dlist, re_list);
  splaytree_free(re_tree, NULL); re_tree = NULL;

  for(;;)
    {
      for(dn=dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  re_ip = dlist_node_item(dn);
	  if(sc_regex_ip_eval(ri_list, re_ip) != 0)
	    goto done;
	}
      dlist_qsort(re_list, (dlist_cmp_t)sc_regex_score_ip_cmp);
      slist_empty_cb(ri_list, (slist_free_t)sc_routerinf_free);

      if(verbose != 0 && threadc == 1)
	{
	  for(dn=dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
	    {
	      re_ip = dlist_node_item(dn);
	      printf("%s %s\n", re_ip->regexes[0]->str,
		     sc_regex_score_tostr(re_ip, buf, sizeof(buf)));
	    }
	}

      /* clean out any regexes that did not match at least three routers */
      dn = dlist_head_node(re_list);
      while(dn != NULL)
	{
	  re_ip = dlist_node_item(dn); dn_this = dn;
	  dn = dlist_node_next(dn);
	  if(re_ip->rt_c < 3)
	    {
	      sc_regex_free(re_ip);
	      dlist_node_pop(re_list, dn_this);
	    }
	}

      re_ip = dlist_head_item(re_list);
      if(re_ip != NULL && re_ip->fp_c == 0 && re_ip->rt_c >= 3)
	{
	  if((re_new = sc_regex_head_push(re, re_ip->regexes[0])) == NULL ||
	     sc_regex_eval(re_new, ri_list) != 0)
	    goto done;
	  re_new->score = re->score + re_ip->score;

	  /* put a copy on the regex list */
	  if(sc_domain_lock(dom) != 0)
	    goto done;
	  sn = slist_head_push(dom->regexes, re_new);
	  sc_domain_unlock(dom);

	  if(sn == NULL)
	    goto done;
	  re = re_new;
	  re_new = NULL;

	  /* if there's no more IP addresses to filter, then we're done */
	  if(re->ip_c == 0)
	    break;
	}
      else break;
    }

  rc = 0;

 done:
  if(re_new != NULL) sc_regex_free(re_new);
  if(bits != NULL) free(bits);
  if(I_array != NULL) free(I_array);
  if(ifd_list != NULL) slist_free(ifd_list);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(re_list != NULL) dlist_free_cb(re_list, (dlist_free_t)sc_regex_free);
  if(re_tree != NULL) splaytree_free(re_tree, (splaytree_free_t)sc_regex_free);
  if(css_tree != NULL) splaytree_free(css_tree, (splaytree_free_t)sc_css_free);
  if(css_list != NULL) slist_free(css_list);
  return rc;
}

/*
 * sc_regex_fp_eval
 *
 * if regex matches an interface we wish to filter, tp++
 * if regex matches an interface counted as a TP, fp++
 * if regex matches a single interface router, sp++
 * if regex does not match but should have, fnu++
 */
static int sc_regex_fp_eval(slist_t *ri_list, sc_regex_t *re)
{
  splaytree_t *tree = NULL;
  sc_rework_t *rew = NULL;
  int rc = -1, i, x;
  slist_node_t *sn;
  sc_routerinf_t *ri;
  sc_routerdom_t *rd;
  sc_iface_t *iface;

  if((rew = sc_rework_alloc(re)) == NULL)
    goto done;
  if((tree = splaytree_alloc((splaytree_cmp_t)ptrcmp)) == NULL)
    goto done;
  sc_regex_score_reset(re);

  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);
      for(i=0; i<ri->ifacec; i++)
	{
	  iface = ri->ifaces[i]->ifd->iface;
	  if((x = sc_rework_match(rew, iface, NULL)) < 0)
	    goto done;

	  /* matched */
	  if(x == 1)
	    {
	      re->matchc++;
	      rd = ri->ifaces[i]->ifd->rd;
	      if(ri->ifaces[i]->class == '!')
		{
		  re->tp_c++;
		  if(splaytree_find(tree, rd) == NULL &&
		     splaytree_insert(tree, rd) == NULL)
		    goto done;
		}
	      else if(ri->ifaces[i]->class == 'x')
		re->ip_c++;
	      else if(ri->ifaces[i]->class == '+' && rd->ifacec > 1)
		re->fp_c++;
	      else if(rd->ifacec == 1)
		re->sp_c++;
	      else /* interfaces tagged '-' */
		re->fne_c++;
	    }
	  else
	    {
	      if(ri->ifaces[i]->class == '!')
		re->fnu_c++;
	    }
	}
    }
  re->rt_c = splaytree_count(tree);
  rc = 0;

 done:
  if(rew != NULL) sc_rework_free(rew);
  if(tree != NULL) splaytree_free(tree, NULL);
  return rc;
}

/*
 * sc_regex_fp_isbetter
 *
 * determine if the candidate false positive filter makes the current
 * best regex materially better
 */
static int sc_regex_fp_isbetter(sc_regex_t *cur, sc_regex_t *can, int x)
{
  sc_regex_t *merged = NULL;
  uint32_t m_fp, c_fp;
  uint32_t cur_ppv, can_ppv;
  int rc = 0;

  /*
   * there must be more true positives (matches correctly removed from
   * a router) than false positives (matches incorrectly removed from
   * a router
   */
  if(can->tp_c <= can->fp_c)
    goto done;

  /*
   * there must be at least three different routers with matches
   * correctly filtered
   */
  if(can->rt_c < 3)
    goto done;

  /*
   * the PPV of the candidate filtering regex must be better than the
   * clustering without it
   */
  cur_ppv = (cur->tp_c * 1000) / (cur->tp_c + cur->fp_c);
  can_ppv = (can->tp_c * 1000) / (can->tp_c + can->fp_c);
  if(cur_ppv >= can_ppv)
    goto done;

  if((merged = sc_regex_plus1(cur, can->regexes[0], x)) == NULL ||
     sc_regex_eval(merged, NULL) != 0)
    {
      rc = -1;
      goto done;
    }

  /* if we're left with fewer than 3 inferred routers */
  if(merged->rt_c < 3)
    goto done;

  c_fp = cur->fp_c + cur->ip_c;
  m_fp = merged->fp_c + merged->ip_c;

  /* sanity check: we must at least reduce the number of FPs */
  if(c_fp <= m_fp)
    goto done;

  /*
   * if the reduction in FPs is not at least 10% of the FPs that we
   * started with, then stop
   */
  if(((c_fp - m_fp) * 100 / c_fp) < 10)
    {
      rc = 0;
      goto done;
    }

  rc = 1;

 done:
  if(merged != NULL) sc_regex_free(merged);
  return rc;
}

static int sc_regex_refine_fp_best(sc_regex_t *re, int x, dlist_t *re_list,
				   slist_t *ifd_list, slist_t *ri_list,
				   sc_regex_t **re_out)
{
  sc_regex_t *re_fp, *re_fp2, *re_tmp = NULL;
  dlist_node_t *dn; slist_node_t *sn;
  slist_t *class_list = NULL;
  int rc = -1, i;

  *re_out = NULL;

  for(dn=dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
    {
      re_fp = dlist_node_item(dn);
      if((i = sc_regex_fp_isbetter(re, re_fp, x)) == -1)
	goto done;
      if(i == 1)
	break;
    }
  if(dn == NULL)
    {
      rc = 0;
      goto done;
    }

  if((class_list = slist_alloc()) == NULL)
    goto done;
  if(sc_regex_refine_class_do(re_fp, ifd_list, class_list) != 0)
    goto done;
  if(slist_count(class_list) > 0)
    {
      for(sn=slist_head_node(class_list); sn != NULL; sn=slist_node_next(sn))
	{
	  re_fp = slist_node_item(sn);
	  if(sc_regex_fp_eval(ri_list, re_fp) != 0)
	    goto done;
	}
      slist_qsort(class_list, (slist_cmp_t)sc_regex_score_fp_cmp);

      re_fp = dlist_node_item(dn);
      re_fp2 = slist_head_item(class_list);
      if(sc_regex_score_fp_cmp(re_fp, re_fp2) > 0)
	re_fp = re_fp2;
    }

  if((re_tmp = sc_regex_plus1(re, re_fp->regexes[0], x)) == NULL)
    goto done;
  re_tmp->score = re->score + re_fp->score;
  *re_out = re_tmp;
  rc = 0;

 done:
  if(class_list != NULL) slist_free_cb(class_list, (slist_free_t)sc_regex_free);
  return rc;
}

/*
 * sc_regex_refine_fp
 *
 * given an input regex with false positives, build regexes that might
 * filter those false positives out.
 */
static int sc_regex_refine_fp(sc_regex_t *re)
{
  static const uint16_t mask = RB_BASE | RB_SEG_LITERAL | RB_SEG_DIGIT;
  slist_t *ifd_list = NULL, *ri_list = NULL, *css_list = NULL;
  dlist_t *re_list = NULL;
  splaytree_t *css_tree = NULL, *re_tree = NULL;
  sc_routerinf_t *ri;
  sc_ifacedom_t *ifd;
  slist_node_t *sn, *sn2;
  dlist_node_t *dn, *dn_this;
  sc_css_t *css = NULL;
  sc_regex_t *re_fp = NULL, *re_tmp = NULL;
  int i, x, rc = -1;
  int *bits = NULL, *La = NULL, bitc;
  char buf[256], *str;

  if((re_tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL)
    goto done;

  if((ifd_list = slist_alloc()) == NULL || (ri_list = slist_alloc()) == NULL ||
     (css_tree = splaytree_alloc((splaytree_cmp_t)sc_css_css_cmp)) == NULL)
    goto done;
  if(sc_regex_eval(re, ri_list) != 0)
    goto done;

  /* figure out the interfaces where the associations are bad */
  for(sn=slist_head_node(ri_list); sn != NULL; sn=slist_node_next(sn))
    {
      ri = slist_node_item(sn);
      for(i=0; i<ri->ifacec; i++)
	if(ri->ifaces[i]->class == '!' &&
	   slist_tail_push(ifd_list, ri->ifaces[i]->ifd) == NULL)
	  goto done;
    }

  for(sn=slist_head_node(ifd_list); sn != NULL; sn=slist_node_next(sn))
    {
      ifd = slist_node_item(sn);
      if(sc_ifacedom_css(ifd, &css, 0) != 0)
	goto done;
      if(css == NULL)
	continue;
      if(sc_css_get(css_tree, css) == NULL)
	goto done;
      sc_css_free(css); css = NULL;
    }
  if(sc_css_reduce(css_tree, 1, 1) != 0) /* trim on non-alnum, min length 1 */
    goto done;
  if(sc_css_reduce(css_tree, 2, 1) != 0) /* trim on char class, min length 1 */
    goto done;

  /* use literals to build regexes */
  if((css_list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(css_tree, tree_to_slist, css_list);
  splaytree_free(css_tree, NULL); css_tree = NULL;

  for(sn=slist_head_node(css_list); sn != NULL; sn=slist_node_next(sn))
    {
      css = slist_node_item(sn);
      if(verbose != 0 && threadc == 1)
	printf("%s\n", sc_css_tostr(css, '|', buf, sizeof(buf)));
      La = malloc(sizeof(int) * 2 * css->cssc);
      for(sn2=slist_head_node(ifd_list); sn2 != NULL; sn2=slist_node_next(sn2))
	{
	  ifd = slist_node_item(sn2);
	  str = ifd->label;
	  if(sc_css_match(css, str, La, 0) == 1)
	    {
	      if(pt_to_bits_lit(str,La,css->cssc * 2, &bits, &bitc) == 0)
		{
		  if(sc_regex_build(re_tree,str,re->dom,mask,bits,bitc) != 0)
		    goto done;
		}
	      if(bits != NULL)
		{
		  free(bits);
		  bits = NULL;
		}
	    }
	}
      free(La); La = NULL;
    }

  if((re_list = dlist_alloc()) == NULL)
    goto done;
  splaytree_inorder(re_tree, tree_to_dlist, re_list);
  splaytree_free(re_tree, NULL); re_tree = NULL;

  x = 0;
  for(;;)
    {
      for(dn=dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  re_fp = dlist_node_item(dn);
	  if(sc_regex_fp_eval(ri_list, re_fp) != 0)
	    goto done;
	}
      dlist_qsort(re_list, (dlist_cmp_t)sc_regex_score_fp_cmp);

      if(verbose != 0 && threadc == 1)
	{
	  printf("fp round %d\n", x);
	  for(dn=dlist_head_node(re_list); dn != NULL; dn=dlist_node_next(dn))
	    {
	      re_fp = dlist_node_item(dn);
	      printf("%s %s\n", re_fp->regexes[0]->str,
		     sc_regex_score_tostr(re_fp, buf, sizeof(buf)));
	    }
	}

      /*
       * clear out any with less then three false positives correctly
       * filtered from different routers, because these cannot meet
       * basic criteria to be considered
       */
      dn = dlist_head_node(re_list);
      while(dn != NULL)
	{
	  re_fp = dlist_node_item(dn); dn_this = dn;
	  dn = dlist_node_next(dn);
	  if(re_fp->rt_c < 3)
	    {
	      sc_regex_free(re_fp);
	      dlist_node_pop(re_list, dn_this);
	    }
	}

      if(sc_regex_refine_fp_best(re,x, re_list, ifd_list,ri_list, &re_tmp) != 0)
	goto done;

      if(re_tmp == NULL)
	break;

      x++;
      if(sc_domain_lock(re->dom) != 0)
	goto done;
      sn = slist_tail_push(re->dom->regexes, re_tmp);
      sc_domain_unlock(re->dom);
      if(sn == NULL)
	goto done;
      re = re_tmp; re_tmp = NULL;

      slist_empty_cb(ri_list, (slist_free_t)sc_routerinf_free);
      if(sc_regex_eval(re, ri_list) != 0 || sc_regex_thin(re) != 0)
	goto done;

      if(re->fp_c < 2)
	break;
    }

  rc = 0;

 done:
  if(re_tmp != NULL) sc_regex_free(re_tmp);
  if(ifd_list != NULL) slist_free(ifd_list);
  if(ri_list != NULL) slist_free_cb(ri_list, (slist_free_t)sc_routerinf_free);
  if(re_list != NULL) dlist_free_cb(re_list, (dlist_free_t)sc_regex_free);
  if(re_tree != NULL) splaytree_free(re_tree, (splaytree_free_t)sc_regex_free);
  if(css_tree != NULL) splaytree_free(css_tree, (splaytree_free_t)sc_css_free);
  if(css_list != NULL) slist_free_cb(css_list, (slist_free_t)sc_css_free);
  return rc;
}

/*
 * sc_regex_f_stop
 *
 * should we stop refining this regex, given the gains made this
 * round?
 */
static int sc_regex_f_stop(sc_regex_t *cur, sc_regex_t *can)
{
  int i;

  /* if the score can't realistically be improved */
  if(can->fne_c + can->fnu_c + can->fp_c < 2)
    return 1;

  /* find the new regex in the candidate */
  i = sc_regex_findnew(cur, can);

  /*
   * if the gain affects less than 4% routers over what we started
   * with, then no better
   */
  if(can->regexes[i]->rt_c * 100 / cur->rt_c < 4)
    return 1;

  return 0;
}

/*
 * sc_regex_f_isbetter
 *
 * is the candidate regex better than the current best?
 */
static int sc_regex_f_isbetter(sc_regex_t *cur, sc_regex_t *can)
{
  int i;

  /* if we don't gain any true positives, then no better */
  if(can->tp_c <= cur->tp_c)
    return 0;

  /* if the tpa score does not increase, then no better */
  if(sc_regex_score_tpa(cur) >= sc_regex_score_tpa(can))
    return 0;

  /*
   * if the regex is not involved in clustering at least three true
   * positives, then no better
   */
  i = sc_regex_findnew(cur, can);
  if(can->regexes[i]->rt_c < 3)
    return 0;

  /* make sure the PPV rate is acceptable, otherwise no better */
  if(sc_regex_del_ppv_ok(cur, can) == 0)
    return 0;

  return 1;
}

/*
 * sc_regex_refine_f_permute
 *
 * given a base regex (work) and inferences derived from that regex
 * (work_ifi), and a second regex (cand) which we are considering
 * permuting into a regex containing both work and cand, determine the
 * best combination of the two regexes and return that.
 */
static int sc_regex_refine_f_permute(sc_regex_t *work, slist_t *work_ifi,
				     sc_regex_t *cand, sc_regex_t **best)
{
  slist_t *set = NULL;
  int rc = -1;
  sc_regex_t *re;

  assert(cand->regexc == 1);

  if((set = slist_alloc()) == NULL)
    goto done;
  if(sc_regex_permute(work, work_ifi, cand, set) != 0)
    goto done;
  if(slist_count(set) == 0)
    {
      rc = 0;
      goto done;
    }

  slist_qsort(set, (slist_cmp_t)sc_regex_score_rank_cmp);
  re = slist_head_item(set);
  if(sc_regex_f_isbetter(work, re) != 1 ||
     (*best != NULL && sc_regex_score_rank_cmp(*best, re) <= 0))
    {
      rc = 0;
      goto done;
    }

  if(*best != NULL) sc_regex_free(*best);
  *best = slist_head_pop(set);
  rc = 0;

 done:
  if(set != NULL)
    slist_free_cb(set, (slist_free_t)sc_regex_free);
  return rc;
}

/*
 * sc_regex_refine_f
 *
 *
 */
static int sc_regex_refine_f(sc_regex_fn_t *work)
{
  sc_regex_fn_t *base = work->refn, *refn;
  sc_domain_t *dom = work->re->dom;
  sc_regex_t *best = NULL;
  slist_node_t *sn;
  slist_t *ifi = NULL;
  int rc = -1;

  if(base->refn == NULL)
    {
      work->done = 1;
      return 0;
    }

  if((ifi = slist_alloc()) == NULL ||
     sc_regex_eval_ifi_build(work->re, ifi) != 0)
    {
      work->done = 1;
      goto done;
    }

  for(refn = base->refn; refn != NULL; refn = refn->refn)
    {
      if(sc_regex_refine_f_permute(work->re, ifi, refn->re, &best) != 0)
	{
	  work->done = 1;
	  goto done;
	}
    }

  if(best == NULL)
    {
      work->done = 1; rc = 0;
      goto done;
    }

  /*
   * make a copy of the current working regex and put it in
   * the set
   */
  if(sc_domain_lock(dom) != 0)
    goto done;
  sn = slist_tail_push(dom->regexes, best);
  sc_domain_unlock(dom);

  if(sn == NULL)
    goto done;
  if(sc_regex_f_stop(work->re, best) != 0)
    work->done = 1;
  work->re = best;
  rc = 0;

 done:
  if(ifi != NULL)
    slist_free_cb(ifi, (slist_free_t)sc_ifaceinf_free);
  return rc;
}

static int generate_regexes_domain(sc_domain_t *dom)
{
  splaytree_t *re_tree = NULL;
  sc_routerdom_t *rd;
  slist_node_t *sn;
  int i, j;

  if((re_tree = splaytree_alloc((splaytree_cmp_t)sc_regex_str_cmp)) == NULL)
    goto err;

  for(sn=slist_head_node(dom->routers); sn != NULL; sn=slist_node_next(sn))
    {
      rd = slist_node_item(sn);
      for(i=0; i<rd->ifacec; i++)
	{
	  for(j=i+1; j<rd->ifacec; j++)
	    {
	      if(sc_regex_lcs(re_tree, dom, rd->ifaces[i], rd->ifaces[j]) != 0)
		goto err;
	    }
	}
    }

  /*
   * take the regex strings out of the tree and put them in a list
   * ready to be evaluated
   */
  splaytree_inorder(re_tree, tree_to_slist, dom->regexes);
  splaytree_free(re_tree, NULL); re_tree = NULL;
  return 0;

 err:
  if(re_tree != NULL) splaytree_free(re_tree, NULL);
  return -1;
}

static void generate_regexes_thread(sc_domain_t *dom)
{
  generate_regexes_domain(dom);
  return;
}

static int regex_file_line(char *line, void *param)
{
  static sc_domain_t *dom = NULL;
  uint32_t score = 0;
  sc_regex_t *re;
  char *score_str;
  char *ptr;
  long lo;

  if(line[0] == '\0' || line[0] == '#')
    return 0;

  /* if a suffix line, get the equivalent domain */
  if(strncmp(line, "suffix ", 7) == 0)
    {
      dom = sc_domain_find(line + 7);
      return 0;
    }

  /* don't care about this domain */
  if(dom == NULL)
    return 0;

  /* truncate the string at the end of the regex */
  ptr = line;
  while(*ptr != '\0')
    {
      if(*ptr == ':' && *(ptr+1) == ' ')
	break;
      ptr++;
    }
  if(*ptr == '\0')
    return -1;
  *ptr = '\0';
  ptr++;

  /* if the regex is tagged with a score, copy it */
  if((ptr = (char *)string_findlc(ptr, "score ")) != NULL)
    {
      ptr += 6; score_str = ptr;
      while(*ptr != '\0' && *ptr != ' ')
	ptr++;
      if(*ptr == ' ')
	*ptr = '\0';
      if(string_isnumber(score_str) != 0 && string_tolong(score_str, &lo) == 0)
	score = (uint32_t)lo;
    }

  /* build the regex and tag the score */
  if((re = sc_regex_alloc_str(line)) != NULL)
    {
      re->score = score;
      re->dom = dom;
      if(slist_tail_push(dom->regexes, re) == NULL)
	sc_regex_free(re);
    }

  return 0;
}

static int generate_regexes(void)
{
  struct timeval start, finish, tv;
  int regexc = 0, rc = -1;
  sc_domain_t *dom;
  slist_node_t *sn;
  struct stat sb;
  sc_regex_t *re = NULL;
  char *dup = NULL;

  if(regex_eval != NULL)
    {
      if(stat(regex_eval, &sb) != 0)
	{
	  if((dom = slist_head_item(domain_list)) == NULL ||
	     (dup = strdup(regex_eval)) == NULL ||
	     (re = sc_regex_alloc_str(dup)) == NULL ||
	     slist_tail_push(dom->regexes, re) == NULL)
	    goto done;
	  re->dom = dom;
	  re = NULL;
	}
      else
	{
	  if(file_lines(regex_eval, regex_file_line, NULL) != 0)
	    {
	      fprintf(stderr, "could not read %s\n", regex_eval);
	      goto done;
	    }
	}
      rc = 0;
      goto done;
    }

  gettimeofday_wrap(&start);
  if((tp = threadpool_alloc(threadc)) == NULL)
    goto done;
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      threadpool_tail_push(tp,(threadpool_func_t)generate_regexes_thread,dom);
    }
  threadpool_join(tp); tp = NULL;
  rc = 0;
  gettimeofday_wrap(&finish);

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      regexc += slist_count(dom->regexes);
    }
  timeval_diff_tv(&tv, &start, &finish);
  fprintf(stderr, "generated %d regexes in %d.%d seconds\n", regexc,
	  (int)tv.tv_sec, (int)(tv.tv_usec / 100000));

 done:
  if(re != NULL) sc_regex_free(re);
  if(dup != NULL) free(dup);
  return rc;
}

static void eval_regexes_thread(sc_regex_t *re)
{
  sc_regex_eval(re, NULL);
  return;
}

static int eval_regexes(void)
{
  struct timeval start, finish, tv;
  slist_node_t *sn, *s2;
  sc_domain_t *dom;
  sc_regex_t *re;
  int regexc = 0;

  gettimeofday_wrap(&start);
  tp = threadpool_alloc(threadc);
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      for(s2=slist_head_node(dom->regexes); s2 != NULL; s2=slist_node_next(s2))
	{
	  re = slist_node_item(s2);
	  threadpool_tail_push(tp, (threadpool_func_t)eval_regexes_thread, re);
	  regexc++;
	}
    }
  threadpool_join(tp); tp = NULL;
  gettimeofday_wrap(&finish);

  timeval_diff_tv(&tv, &start, &finish);
  fprintf(stderr, "evaluated %d regexes in %d.%d seconds\n", regexc,
	  (int)tv.tv_sec, (int)(tv.tv_usec / 100000));

  return 0;
}

static void refine_regexes_ip_thread(sc_regex_t *re)
{
  sc_regex_refine_ip(re);
  return;
}

static void refine_regexes_fp_thread(sc_regex_t *re)
{
  sc_regex_refine_fp(re);
  return;
}

static void refine_regexes_class_thread(sc_regex_t *re)
{
  sc_regex_refine_class(re);
  return;
}

static void refine_regexes_fne_thread(sc_regex_t *re)
{
  sc_regex_refine_fne(re);
  return;
}

static void refine_regexes_fnu_thread(sc_regex_t *re)
{
  sc_regex_refine_fnu(re);
  return;
}

static void refine_regexes_tp_thread(sc_regex_t *re)
{
  sc_regex_refine_tp(re);
  return;
}

static void refine_regexes_sets_work_thread(sc_regex_fn_t *refn)
{
  sc_regex_refine_f(refn);
  return;
}

static void refine_regexes_sets_domain_check(sc_domain_fn_t *domfn)
{
  sc_regex_fn_t *work = NULL, *work2;
  slist_node_t *sn, *s2;
  sc_regex_t *head;
  int all_done = 0, work_tpa, head_tpa;

  /* check if we've inferred a near-perfect regex */
  slist_qsort(domfn->work, (slist_cmp_t)sc_regex_fn_score_rank_cmp);
  work = slist_head_item(domfn->work);  assert(work != NULL);
  head = work->re;
  if(head->fne_c + head->fnu_c + head->fp_c < 2)
    {
      domfn->done = 1;
      return;
    }
  head_tpa = sc_regex_score_tpa(head);

  /* put the list back in to the order it started with */
  slist_qsort(domfn->work, (slist_cmp_t)sc_regex_fn_base_rank_cmp);

  /* check if there are any regexes not marked done */
  all_done = 1;
  for(sn=slist_head_node(domfn->work); sn != NULL; sn=slist_node_next(sn))
    {
      work = slist_node_item(sn);
      if(work->done != 0)
	continue;

      /*
       * do not consider further refinement of a naming convention
       * made up of more regexes but a lower TPA score.
       */
      work_tpa = sc_regex_score_tpa(work->re);
      if(head->regexc < work->re->regexc && head_tpa >= work_tpa)
	{
	  work->done = 2;
	  continue;
	}
      for(s2=slist_head_node(domfn->work); s2 != sn; s2=slist_node_next(s2))
	{
	  work2 = slist_node_item(s2);
	  if(work2->re->regexc < work->re->regexc &&
	     sc_regex_score_tpa(work2->re) >= work_tpa)
	    break;
	}
      if(s2 != sn)
	{
	  work->done = 2;
	  continue;
	}

      all_done = 0;
    }
  if(all_done != 0)
    domfn->done = 1;

  return;
}

static int refine_regexes_sets_domain_init(dlist_t *out, sc_domain_t *dom)
{
  sc_regex_fn_t *base = NULL, *work = NULL, *last = NULL;
  sc_domain_fn_t *domfn = NULL;
  slist_node_t *sn, *s2;
  sc_regex_t *head, *re;
  int rc = -1;

  /*
   * nothing to be done if there aren't at least two regexes that
   * could be merged.
   */
  if(slist_count(dom->regexes) < 2)
    return 0;

  /* sc_regex_fn_base_rank_cmp calls sc_regex_score_rank_cmp */
  slist_qsort(dom->regexes, (slist_cmp_t)sc_regex_score_rank_cmp);
  head = slist_head_item(dom->regexes);

  /*
   * nothing to be done if the number of false inferences is less than
   * two
   */
  if(head->fne_c + head->fnu_c + head->fp_c < 2)
    return 0;

  if((domfn = malloc_zero(sizeof(sc_domain_fn_t))) == NULL ||
     (domfn->work = slist_alloc()) == NULL ||
     (domfn->base = slist_alloc()) == NULL)
    goto done;

  for(sn=slist_head_node(dom->regexes); sn != NULL; sn=slist_node_next(sn))
    {
      re = slist_node_item(sn);

      if((base = malloc_zero(sizeof(sc_regex_fn_t))) == NULL ||
	 slist_tail_push(domfn->base, base) == NULL)
	goto done;
      base->re = re;
      if(last != NULL)
	last->refn = base;
      last = base;

      /*
       * do not consider a regex that is worse than the head regex, or
       * one already in the work set
       */
      if(head != re && re->tp_c <= head->tp_c && re->fp_c >= head->fp_c)
	continue;
      for(s2=slist_head_node(domfn->work); s2 != NULL; s2=slist_node_next(s2))
	{
	  work = slist_node_item(s2);
	  if(re->tp_c <= work->re->tp_c && re->fp_c >= work->re->fp_c)
	    break;
	}
      if(s2 != NULL)
	continue;

      if((work = malloc_zero(sizeof(sc_regex_fn_t))) == NULL ||
	 slist_tail_push(domfn->work, work) == NULL)
	goto done;
      work->refn = base;
      work->base = re;
      work->re = re;
    }

  if(dlist_tail_push(out, domfn) == NULL)
    goto done;
  domfn = NULL;
  rc = 0;

 done:
  if(domfn != NULL) sc_domain_fn_free(domfn);
  return rc;
}

static int refine_regexes_sets(void)
{
  dlist_t *domfn_list = NULL;
  char buf[1024], score[128];
  sc_domain_fn_t *domfn;
  sc_regex_fn_t *work;
  dlist_node_t *dn, *dn_this;
  slist_node_t *sn;
  sc_domain_t *dom;
  int rc = -1;

  /*
   * go through the regexes and figure out if there are missed routers
   * with apparent names that we might be able to match with more work
   */
  fprintf(stderr, "refining regexes: build sets\n");

  /* figure out which domains still have work to be done */
  if((domfn_list = dlist_alloc()) == NULL)
    goto done;
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if(refine_regexes_sets_domain_init(domfn_list, dom) != 0)
	goto done;
    }

  while(dlist_count(domfn_list) > 0)
    {
      if(verbose != 0 && threadc == 1)
	printf("\n###\n");
      if((tp = threadpool_alloc(threadc)) == NULL)
	goto done;
      for(dn=dlist_head_node(domfn_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  domfn = dlist_node_item(dn);
	  if(domfn->done != 0)
	    continue;
	  for(sn=slist_head_node(domfn->work); sn!=NULL; sn=slist_node_next(sn))
	    {
	      work = slist_node_item(sn);
	      if(verbose != 0 && threadc == 1)
		printf("%d %s %s\n", work->done,
		       sc_regex_tostr(work->re, buf, sizeof(buf)),
		       sc_regex_score_tostr(work->re, score, sizeof(score)));
	      if(work->done != 0)
		continue;
	      threadpool_tail_push(tp,
				   (threadpool_func_t)refine_regexes_sets_work_thread,
				   work);
	    }
	}
      threadpool_join(tp); tp = NULL;

      if((tp = threadpool_alloc(threadc)) == NULL)
	goto done;
      for(dn=dlist_head_node(domfn_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  domfn = dlist_node_item(dn);
	  threadpool_tail_push(tp,
			       (threadpool_func_t)refine_regexes_sets_domain_check,
			       domfn);
	}
      threadpool_join(tp); tp = NULL;

      dn=dlist_head_node(domfn_list);
      while(dn != NULL)
	{
	  domfn = dlist_node_item(dn); dn_this=dn;
	  dn = dlist_node_next(dn);
	  if(domfn->done != 0)
	    {
	      sc_domain_fn_free(domfn);
	      dlist_node_pop(domfn_list, dn_this);
	    }
	}
    }

  rc = 0;

 done:
  if(domfn_list != NULL)
    dlist_free_cb(domfn_list, (slist_free_t)sc_domain_fn_free);
  return rc;
}

static int refine_regexes_ip(void)
{
  sc_regex_t   *re;
  slist_node_t *sn, *s2, *sn_tail;
  sc_domain_t  *dom;
  int rc = -1;

  /*
   * go through the regexes and figure out if there are matches including
   * IP address literals
   */
  fprintf(stderr, "refining regexes: ip matches\n");

  if((tp = threadpool_alloc(threadc)) == NULL)
    goto done;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      sn_tail = slist_tail_node(dom->regexes);
      for(s2=slist_head_node(dom->regexes); s2 != NULL; s2=slist_node_next(s2))
	{
	  re = slist_node_item(s2);
	  if(re->ip_c == 0 || re->rt_c == 0 || re->tp_c == 0)
	    continue;
	  threadpool_tail_push(tp,
			       (threadpool_func_t)refine_regexes_ip_thread,
			       re);
	  if(s2 == sn_tail)
	    break;
	}
    }

  threadpool_join(tp); tp = NULL;
  rc = 0;

 done:
  return rc;
}

static int refine_regexes_fp(void)
{
  slist_node_t *sn, *s2;
  sc_regex_t *best, *re;
  sc_domain_t *dom;
  int rc = -1;

  fprintf(stderr, "refining regexes: false positives\n");

  if((tp = threadpool_alloc(threadc)) == NULL)
    goto done;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      if((best = sc_domain_bestre(dom)) == NULL)
	continue;
      for(s2=slist_head_node(dom->regexes); s2 != NULL; s2=slist_node_next(s2))
	{
	  re = slist_node_item(s2);
	  if(re->tp_c < best->tp_c || re->rt_c < 3 || re->fp_c < 2)
	    continue;
	  threadpool_tail_push(tp,
			       (threadpool_func_t)refine_regexes_fp_thread,re);
	}
    }

  threadpool_join(tp); tp = NULL;
  rc = 0;

 done:
  return rc;
}

static int refine_regexes_fnu(void)
{
  sc_regex_t   *re;
  slist_node_t *sn, *s2;
  sc_domain_t  *dom;
  int rc = -1;

  fprintf(stderr, "refining regexes: false negative unmatched\n");

  if((tp = threadpool_alloc(threadc)) == NULL)
    goto done;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      for(s2=slist_head_node(dom->regexes); s2 != NULL; s2=slist_node_next(s2))
	{
	  re = slist_node_item(s2);
	  if(re == NULL || re->fnu_c == 0)
	    continue;

	  threadpool_tail_push(tp,
			       (threadpool_func_t)refine_regexes_fnu_thread,
			       re);
	}
    }

  threadpool_join(tp); tp = NULL;
  thin_regexes(2);
  rc = 0;

 done:
  return rc;
}

static int refine_regexes_class(void)
{
  sc_regex_t   *re;
  slist_node_t *sn, *s2, *sn_tail;
  sc_domain_t  *dom;
  int rc = -1;

  fprintf(stderr, "refining regexes: classes\n");

  if((tp = threadpool_alloc(threadc)) == NULL)
    goto done;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      sn_tail = slist_tail_node(dom->regexes);
      for(s2=slist_head_node(dom->regexes); s2 != NULL; s2=slist_node_next(s2))
	{
	  re = slist_node_item(s2);
	  if(re->regexc > 1)
	    continue;
	  threadpool_tail_push(tp,
			       (threadpool_func_t)refine_regexes_class_thread,
			       re);
	  if(s2 == sn_tail)
	    break;
	}
    }

  threadpool_join(tp); tp = NULL;
  thin_regexes(1);
  rc = 0;

 done:
  return rc;
}

static int refine_regexes_fne(void)
{
  sc_regex_t   *re;
  slist_node_t *sn, *s2, *sn_tail;
  sc_domain_t  *dom;
  int rc = -1;

  fprintf(stderr, "refining regexes: false negative extractions\n");

  if((tp = threadpool_alloc(threadc)) == NULL)
    goto done;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      sn_tail = slist_tail_node(dom->regexes);
      for(s2=slist_head_node(dom->regexes); s2 != NULL; s2=slist_node_next(s2))
	{
	  re = slist_node_item(s2);
	  if(re->fne_c == 0)
	    continue;
	  threadpool_tail_push(tp,
			       (threadpool_func_t)refine_regexes_fne_thread,
			       re);
	  if(s2 == sn_tail)
	    break;
	}
    }

  threadpool_join(tp); tp = NULL;
  thin_regexes(1);
  rc = 0;

 done:
  return rc;
}

static int refine_regexes_tp(void)
{
  sc_regex_t   *re;
  slist_node_t *sn, *s2, *sn_tail;
  sc_domain_t  *dom;
  int rc = -1;

  fprintf(stderr, "refining regexes: true positives\n");

  if((tp = threadpool_alloc(threadc)) == NULL)
    goto done;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      sn_tail = slist_tail_node(dom->regexes);
      for(s2=slist_head_node(dom->regexes); s2 != NULL; s2=slist_node_next(s2))
	{
	  re = slist_node_item(s2);
	  if(re->tp_c == 0)
	    continue;
	  threadpool_tail_push(tp,
			       (threadpool_func_t)refine_regexes_tp_thread,
			       re);
	  if(s2 == sn_tail)
	    break;
	}
    }

  threadpool_join(tp); tp = NULL;
  thin_regexes(0);
  rc = 0;

 done:
  return rc;
}

static int refine_regexes(void)
{
  if(refine_tp != 0 && refine_regexes_tp() != 0)
    return -1;

  if(refine_fne != 0 && refine_regexes_fne() != 0)
    return -1;

  if(refine_class != 0 && refine_regexes_class() != 0)
    return -1;

  if(refine_fnu != 0 && refine_regexes_fnu() != 0)
    return -1;

  if(refine_sets != 0 && refine_regexes_sets() != 0)
    return -1;

  if(refine_ip != 0 && refine_regexes_ip() != 0)
    return -1;

  if(refine_fp != 0 && refine_regexes_fp() != 0)
    return -1;

  return 0;
}

static int assert_domains(void)
{
  slist_node_t *sn, *s2;
  sc_domain_t *dom;
  sc_routerdom_t *rd;
  uint32_t id;
  int i;

  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      id = 0;
      for(s2=slist_head_node(dom->routers); s2 != NULL; s2=slist_node_next(s2))
	{
	  rd = slist_node_item(s2);
	  for(i=0; i<rd->ifacec; i++)
	    {
	      if(id + 1 != rd->ifaces[i]->id)
		return -1;
	      id++;
	    }
	}
      if(id != dom->ifacec)
	return -1;
    }

  return 0;
}

static int load_routers(void)
{
  struct timeval start, finish, tv;
  slist_node_t *sn, *s2;
  sc_routerdom_t *rd;
  sc_domain_t *dom;
  sc_iface_t *iface;
  slist_t *list = NULL;
  int i, rc = -1;

  /* load the routers */
  gettimeofday_wrap(&start);
  if((domain_tree = splaytree_alloc((splaytree_cmp_t)sc_domain_cmp)) == NULL||
     (list = slist_alloc()) == NULL ||
     (router_list = slist_alloc()) == NULL)
    goto done;
  if(file_lines(router_file, router_file_line, list) != 0)
    {
      fprintf(stderr, "could not read %s\n", router_file);
      goto done;
    }
  if(slist_count(list) > 0 && sc_router_finish(list) != 0)
    goto done;
  if((domain_list = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(domain_tree, tree_to_slist, domain_list);

  /* infer if the hostnames contain IP address literals */
  tp = threadpool_alloc(threadc);
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      sc_domain_finish(dom);
      for(s2=slist_head_node(dom->routers); s2 != NULL; s2=slist_node_next(s2))
	{
	  rd = slist_node_item(s2);
	  for(i=0; i<rd->ifacec; i++)
	    {
	      iface = rd->ifaces[i]->iface;
	      threadpool_tail_push(tp,
				   (threadpool_func_t)sc_iface_ip_find_thread,
				   iface);
	    }
	}
      for(s2=slist_head_node(dom->routers); s2 != NULL; s2=slist_node_next(s2))
	{
	  iface = slist_node_item(s2);
	  threadpool_tail_push(tp, (threadpool_func_t)sc_iface_ip_find_thread,
			       iface);
	}
    }
  threadpool_join(tp); tp = NULL;

  /* compute likely names for the routers */
  tp = threadpool_alloc(threadc);
  for(sn=slist_head_node(domain_list); sn != NULL; sn=slist_node_next(sn))
    {
      dom = slist_node_item(sn);
      sc_domain_finish(dom);
      for(s2=slist_head_node(dom->routers); s2 != NULL; s2=slist_node_next(s2))
	{
	  threadpool_tail_push(tp, (threadpool_func_t)sc_routerdom_lcs_thread,
			       slist_node_item(s2));
	}
    }
  threadpool_join(tp); tp = NULL;

  gettimeofday_wrap(&finish);

  timeval_diff_tv(&tv, &start, &finish);
  fprintf(stderr, "loaded %d routers in %d domains in %d.%d seconds\n",
	  slist_count(router_list), slist_count(domain_list),
	  (int)tv.tv_sec, (int)(tv.tv_usec / 100000));

  /* run some assertions on the domains */
  if(assert_domains() != 0)
    {
      fprintf(stderr, "checks failed\n");
      goto done;
    }

  rc = 0;

 done:
  if(list != NULL) slist_free(list);
  return rc;
}

static int load_suffix(void)
{
  slist_t *list = NULL;
  int rc = -1;

  if((list = slist_alloc()) == NULL)
    goto done;
  if(file_lines(suffix_file, suffix_file_line, list) != 0)
    {
      fprintf(stderr, "could not read %s\n", suffix_file);
      goto done;
    }
  fprintf(stderr, "loaded %d suffixes\n", slist_count(list));
  process_suffix(list);
  rc = 0;

 done:
  if(list != NULL) slist_free(list);
  return rc;
}

static void cleanup(void)
{
  if(suffix_root != NULL)
    {
      sc_suffix_free(suffix_root);
      suffix_root = NULL;
    }

  if(domain_tree != NULL)
    {
      splaytree_free(domain_tree, (splaytree_free_t)sc_domain_free);
      domain_tree = NULL;
    }

  if(domain_list != NULL)
    {
      slist_free(domain_list);
      domain_list = NULL;
    }

  if(router_list != NULL)
    {
      slist_free_cb(router_list, (slist_free_t)sc_router_free);
      router_list = NULL;
    }

  return;
}

int main(int argc, char *argv[])
{
  int rc = -1;

#ifdef HAVE_PTHREAD
  long i;
#endif

#ifdef DMALLOC
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    {
      return -1;
    }

#ifdef HAVE_PTHREAD
  if(threadc == -1)
    {
      threadc = 1;
#ifdef _SC_NPROCESSORS_ONLN
      if((i = sysconf(_SC_NPROCESSORS_ONLN)) > 1)
	threadc = i;
#endif
    }
  fprintf(stderr, "using %ld threads\n", threadc);
#else
  threadc = 0;
#endif

  /* load the public suffix list */
  if(load_suffix() != 0)
    return -1;

  /* load the routers */
  if(load_routers() != 0)
    return -1;

  /* generate regular expressions */
  if(generate_regexes() != 0)
    return -1;

  /* evaluate regular expressions */
  if(eval_regexes() != 0)
    return -1;

  if(regex_eval == NULL && thin_regexes(0) != 0)
    return -1;

  /* refine regular expressions */
  if(refine_regexes() != 0)
    return -1;

  rc = dump_funcs[dump_id].func();
  return rc;
}
