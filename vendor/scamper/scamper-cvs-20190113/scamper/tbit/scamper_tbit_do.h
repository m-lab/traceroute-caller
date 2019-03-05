/*
 * scamper_do_tbit.h
 *
 * $Id: scamper_tbit_do.h,v 1.2 2010/10/24 03:28:31 mjl Exp $
 *
 * Copyright (C) 2009-2010 Ben Stasiewicz
 *
 * This file implements algorithms described in the tbit-1.0 source code,
 * as well as the papers:
 *
 *  "On Inferring TCP Behaviour"
 *      by Jitendra Padhye and Sally Floyd
 *  "Measuring the Evolution of Transport Protocols in the Internet" by
 *      by Alberto Medina, Mark Allman, and Sally Floyd.
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

#ifndef __SCAMPER_DO_TBIT_H
#define __SCAMPER_DO_TBIT_H

const char *scamper_do_tbit_usage(void);

void *scamper_do_tbit_alloc(char *str);

void scamper_do_tbit_free(void *data);

scamper_task_t *scamper_do_tbit_alloctask(void *data,
					  scamper_list_t *list,
					  scamper_cycle_t *cycle);

int scamper_do_tbit_arg_validate(int argc, char *argv[], int *stop);

void scamper_do_tbit_cleanup(void);
int scamper_do_tbit_init(void);

#endif /*__SCAMPER_DO_TBIT_H */
