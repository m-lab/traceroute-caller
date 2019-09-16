/*
 * scamper_options.h: code to handle parsing of options
 *
 * $Id: scamper_options.h,v 1.8 2019/07/12 23:37:57 mjl Exp $
 *
 * Copyright (C) 2006-2008 The University of Waikato
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

#ifndef __SCAMPER_OPTIONS_H
#define __SCAMPER_OPTIONS_H

#define SCAMPER_OPTION_TYPE_NULL 0x00 /* no parameter to option */
#define SCAMPER_OPTION_TYPE_STR  0x01 /* string parameter */
#define SCAMPER_OPTION_TYPE_NUM  0x02 /* integer (number) parameter */

/*
 * scamper_option_in
 *
 * define the format of an option.  this structure defines the short and long
 * strings used for the option, the parameter type, and an associated integer
 * id for the type, so that the caller does not have to examine the option
 * string after it has been parsed.
 */
typedef struct scamper_option_in
{
  /*
   * the character (for one-letter options) or the string (for long options)
   * defining the option.  if c is '\0', then the option does not have a short
   * form.  if str is NULL, then the option is
   */
  char c;
  char *str;

  /*
   * an integer mapping for the option.  this integer mapping is used when
   * returning the parsed options to the caller.
   */
  int id;

  /*
   * the type of the paramater for the option, if there is one.  type codes
   * are defined above.
   */
  int type;

} scamper_option_in_t;

#define SCAMPER_OPTION_COUNT(opts) (sizeof(opts)/sizeof(scamper_option_in_t))

/*
 * scamper_option_out
 *
 * a simple struct to associate an option with its supplied value.  the
 * id comes from the scamper_option_in structure.
 *
 * the next parameter is used to assemble a linked list of option structures.
 */
typedef struct scamper_option_out
{
  int                        id;
  int                        type;
  char                      *str;
  struct scamper_option_out *next;
} scamper_option_out_t;

/*
 * scamper_options_parse
 *
 * given an input string, parse the string for options based on the options
 * supplied in the opts_in parameter.
 *
 * the parsed options are put into opts_out.  the caller must use
 * scamper_options_free() on the opts_out parameter when the structure is no
 * longer required.
 *
 * this function will modify the opt_str parameter passed in rather than
 * duplicate portions of the input string.
 */
int scamper_options_parse(char *opt_str,
			  const scamper_option_in_t *opts_in, const int cnt_in,
			  scamper_option_out_t **opts_out, char **stop);

int scamper_options_validate(const scamper_option_in_t *opts, const int cnt,
			     int argc, char *argv[], int *stop,
			     int validate(int optid, char *param,
					  long long *out));

/*
 * scamper_options_count
 *
 * return a count of the number of opt_out structures in the list
 */
int scamper_options_count(scamper_option_out_t *opts);

int scamper_options_c2id(const scamper_option_in_t *opts,const int cnt,char c);

/*
 * scamper_options_free
 *
 * free the list of scamper_option_out structures passed as the only parameter.
 */
void scamper_options_free(scamper_option_out_t *opts);

#endif /* __SCAMPER_OPTIONS_H */
