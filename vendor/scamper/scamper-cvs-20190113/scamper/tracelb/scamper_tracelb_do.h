/*
 * scamper_do_tracelb.h
 *
 * $Id: scamper_tracelb_do.h,v 1.10 2018/05/26 21:00:30 mjl Exp $
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Author: Matthew Luckie
 *
 * Load-balancer traceroute technique authored by
 * Brice Augustin, Timur Friedman, Renata Teixeira; "Measuring Load-balanced
 *  Paths in the Internet", in Proc. Internet Measurement Conference 2007.
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

#ifndef __SCAMPER_DO_TRACELB_H
#define __SCAMPER_DO_TRACELB_H

void *scamper_do_tracelb_alloc(char *str);

scamper_task_t *scamper_do_tracelb_alloctask(void *data,
					     scamper_list_t *list,
					     scamper_cycle_t *cycle);

int scamper_do_tracelb_arg_validate(int argc, char *argv[], int *stop);

void scamper_do_tracelb_free(void *);

const char *scamper_do_tracelb_usage(void);

void scamper_do_tracelb_cleanup(void);
int scamper_do_tracelb_init(void);

#endif /*__SCAMPER_DO_TRACELB_H */
