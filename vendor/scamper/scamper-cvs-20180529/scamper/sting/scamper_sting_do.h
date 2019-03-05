/*
 * scamper_do_sting.h
 *
 * $Id: scamper_sting_do.h,v 1.4 2012/04/05 18:00:54 mjl Exp $
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Author: Matthew Luckie
 *
 * This file implements algorithms described in the sting-0.7 source code,
 * as well as the paper:
 *
 *  Sting: a TCP-based Network Measurement Tool
 *  by Stefan Savage
 *  1999 USENIX Symposium on Internet Technologies and Systems
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

#ifndef __SCAMPER_DO_STING_H
#define __SCAMPER_DO_STING_H

void *scamper_do_sting_alloc(char *str);

scamper_task_t *scamper_do_sting_alloctask(void *data,
					   scamper_list_t *list,
					   scamper_cycle_t *cycle);

int scamper_do_sting_arg_validate(int argc, char *argv[], int *stop);

void scamper_do_sting_free(void *);

const char *scamper_do_sting_usage(void);

void scamper_do_sting_cleanup(void);
int scamper_do_sting_init(void);

#endif /*__SCAMPER_DO_STING_H */
