/*
 * scamper_options.c: code to handle parsing of options
 *
 * $Id: scamper_options.c,v 1.15 2019/07/12 23:37:57 mjl Exp $
 *
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2014-2015 The Regents of the University of California
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
  "$Id: scamper_options.c,v 1.15 2019/07/12 23:37:57 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_options.h"
#include "utils.h"

/*
 * opt_add
 *
 * routine to place the logic for putting together a list holding parsed
 * options.
 */
static int opt_add(scamper_option_out_t **head, scamper_option_out_t **tail,
		   const scamper_option_in_t *opt, char *str)
{
  assert(head != NULL);
  assert(tail != NULL);

  if(*tail == NULL)
    {
      assert(*head == NULL);
      if((*head = malloc_zero(sizeof(scamper_option_out_t))) == NULL)
	return -1;
      *tail = *head;
    }
  else
    {
      if(((*tail)->next = malloc_zero(sizeof(scamper_option_out_t))) == NULL)
	return -1;
      *tail = (*tail)->next;
    }

  (*tail)->id   = opt->id;
  (*tail)->type = opt->type;
  (*tail)->str  = str;

  return 0;
}

/*
 * opt_parse_param
 *
 * this code is used to parse out the parameter pointed to by str based on
 * the supplied parameter type.  the next word in the string is returned
 * in 'next'
 */
static int opt_parse_param(int type, char **str, char **next)
{
  char *tmp = *str;
  char delim;
  int c;

  if(type == SCAMPER_OPTION_TYPE_NUM)
    {
      if(*tmp == '-')
	tmp++;
      c = 0;
      while(isdigit((int)*tmp) != 0)
	{
	  tmp++;
	  c++;
	}

      /* if there are no digits in this parameter */
      if(c == 0)
	goto err;

      /* if the character we stopped on is not whitespace */
      if(*tmp != '\0' && isspace((int)*tmp) == 0)
	goto err;
    }
  else if(type == SCAMPER_OPTION_TYPE_STR)
    {
      /*
       * if the first character is a quoting character, then the string is
       * terminated by the same quoting character
       */
      if(tmp[0] == '"' || tmp[0] == '\'')
	{
	  /* record the type of quoting character, and then advance past it */
	  delim = tmp[0];
	  tmp++; *str = tmp;

	  /*
	   * read the string until we either get the other quoting character,
	   * or the end of the string.  if we don't get the other quoting
	   * character then we have a problem
	   *
	   * XXX: when we fall out of the top-level if statement, the character
	   * pointed to by tmp will be set to null; this corresponds to the
	   * character used for quoting.
	   */
	  while(tmp[0] != delim && tmp[0] != '\0') tmp++;
	  if(tmp[0] == '\0') goto err;
	}
      else
	{
	  *next = string_nextword(*str);
	  return 0;
	}
    }

  /* if we got to the end of the argument list, then nothing else comes next */
  if(tmp[0] == '\0')
    {
      *next = NULL;
      return 0;
    }

  /* null terminate the option parameter string */
  tmp[0] = '\0'; tmp++;

  /*
   * skip past whitespace and advance to the next string in the option.
   * if there is nothing else, then *next is set to NULL.
   */
  while(isspace((int)*tmp) != 0) tmp++;
  if(tmp[0] != '\0') *next = tmp;
  else *next = NULL;

  return 0;

 err:
  *next = NULL;
  return -1;
}

int scamper_options_c2id(const scamper_option_in_t *opts,const int cnt,char c)
{
  int i;
  for(i=0; i<cnt; i++)
    {
      if(c == opts[i].c)
	return opts[i].id;
    }
  return -1;
}

/*
 * scamper_options_parse
 *
 * given the options string, and a definition of what option strings are valid,
 * parse the options out and return a linked list of the options in opts_out.
 *
 * this code is a horrible mess of goto statements.
 */
int scamper_options_parse(char *str,
			  const scamper_option_in_t *opts, const int cnt,
			  scamper_option_out_t **opts_out, char **stop)
{
  scamper_option_out_t *head = NULL;
  scamper_option_out_t *tail = NULL;
  char *next;
  int i;

  /* to begin with, get to the first non-whitespace character */
  while(*str != '\0' && isspace((int)*str) != 0)
    {
      str++;
    }
  /* if it turns out there are no options, then return now */
  if(*str == '\0')
    {
      goto done;
    }

  /* begin parsing the options */
  do
    {
      /*
       * first, ensure the string begins with a hyphen to denote an option.
       * this is done before calling string_nextword since the non-options
       * part of the string needs to be passed back unmodified (which this
       * will be if the first character is not a hyphen)
       */
      if(str[0] != '-')
	{
	  break;
	}

      /*
       * null terminate the current word, and figure out where the next
       * word begins
       */
      next = string_nextword(str);

      /*
       * the code supports both long and short options, so descriminate
       * appropriately.
       */
      if(str[1] == '-')
	{
	  /* look for an option that matches the string */
	  for(i=0; i<cnt; i++)
	    {
	      if(opts[i].str != NULL && strcmp(&str[2], opts[i].str) == 0)
		{
		  break;
		}
	    }

	  if(i != cnt)
	    {
	      /*
	       * found a match.
	       *
	       * if there is no parameter to this option, it can just be
	       * added to the options list now
	       */
	      if(opts[i].type == SCAMPER_OPTION_TYPE_NULL)
		{
		  if(opt_add(&head, &tail, &opts[i], NULL) == -1)
		    {
		      goto err;
		    }
		}
	      else
		{
		  /*
		   * a parameter is required.  make sure that there is a
		   * next word.
		   */
		  if(next == NULL) goto err;

		  /*
		   * parse the parameter.  if successful, insert it
		   * into the option list.
		   */
		  str = next;
		  if(opt_parse_param(opts[i].type, &str, &next) == -1)
		    {
		      goto err;
		    }
		  if(opt_add(&head, &tail, &opts[i], str) == -1)
		    {
		      goto err;
		    }

		  goto next;
		}
	    }
	  else goto err; /* no match for this long option */
	}
      else
	{
	  /* advance to the first short option */
	  str++;

	  /*
	   * short options with no parameters can be strung together,
	   * i.e. -aeiou;
	   * therefore, need to handle this with short options where we don't
	   * with long options.
	   */
	  while(*str != '\0')
	    {
	      /* try and find a matching short option for this character */
	      for(i=0; i<cnt; i++)
		{
		  if(opts[i].c != '\0' && opts[i].c == *str)
		    {
		      /*
		       * found a match.
		       *
		       * if there is no parameter to this option, it can just
		       * be added to the options list now
		       */
		      if(opts[i].type == SCAMPER_OPTION_TYPE_NULL)
			{
			  if(opt_add(&head, &tail, &opts[i], NULL) == -1)
			    {
			      goto err;
			    }

			  break;
			}

		      /*
		       * if we've got this far, then the option should have a
		       * parameter.
		       * first, make sure it actually does by ensuring the
		       * there are no more short options adjacent (next char
		       * is a null byte) and that there is a next word (next
		       * is not NULL)
		       */
		      if(str[1] != '\0' || next == NULL)
			{
			  goto err;
			}

		      /*
		       * parse the parameter.  if successful, insert it
		       * into the option list.
		       */
		      str = next;
		      if(opt_parse_param(opts[i].type, &str, &next) == -1)
			{
			  goto err;
			}
		      if(opt_add(&head, &tail, &opts[i], str) == -1)
			{
			  goto err;
			}

		      goto next;
		    }
		}

	      /* no option to match this character */
	      if(i == cnt) goto err;

	      /* advance to next short option */
	      str++;
	    }
	}

    next:
      str = next;
    }
  while(next != NULL);

 done:
  *stop = str;
  *opts_out = head;
  return 0;

 err:
  *stop = str;
  *opts_out = head;
  return -1;
}

int scamper_options_validate(const scamper_option_in_t *opts, const int cnt,
			     int argc, char *argv[], int *stop,
			     int validate(int optid, char *param,
					  long long *out))
{
  int i, j, k, needp;
  int optid = -1;

  for(i=1; i<argc; i++)
    {
      if(argv[i][0] != '-')
	{
	  *stop = i;
	  return 0;
	}

      j = 1;
      needp = 0;
      while(argv[i][j] != '\0')
	{
	  for(k=0; k<cnt; k++)
	    {
	      if(opts[k].c == argv[i][j])
		{
		  break;
		}
	    }

	  if(k == cnt)
	    goto err;

	  if(opts[k].type != SCAMPER_OPTION_TYPE_NULL)
	    {
	      if(needp != 0)
		goto err;
	      needp++;
	      optid = opts[k].id;
	    }

	  j++;
	}

      if(needp == 1)
	{
	  if(++i == argc)
	    goto err;

	  if(validate(optid, argv[i], NULL) != 0)
	    goto err;
	}
    }

  *stop = i;
  return 0;

 err:
  return -1;
}

/*
 * scamper_options_count
 *
 * simple function to return how many options were parsed
 */
int scamper_options_count(scamper_option_out_t *opts)
{
  int i = 0;

  while(opts != NULL)
    {
      i++;
      opts = opts->next;
    }

  return i;
}

/*
 * scamper_options_free
 *
 * simple function to free up the option_out linked list passed in, which
 * was allocated by scamper_options_parse.
 */
void scamper_options_free(scamper_option_out_t *opts)
{
  scamper_option_out_t *tmp;

  while(opts != NULL)
    {
      tmp = opts->next;
      free(opts);
      opts = tmp;
    }

  return;
}
