/*
 * scamper_do_host.h
 *
 * $Id: scamper_host_do.h,v 1.2 2018/12/13 09:31:29 mjl Exp $
 *
 * Copyright (C) 2018 Matthew Luckie
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

#ifndef __SCAMPER_DO_HOST_H
#define __SCAMPER_DO_HOST_H

typedef struct scamper_host_do scamper_host_do_t;

void *scamper_do_host_alloc(char *str);

scamper_task_t *scamper_do_host_alloctask(void *data,
					  scamper_list_t *list,
					  scamper_cycle_t *cycle);

int scamper_do_host_arg_validate(int argc, char *argv[], int *stop);

void scamper_do_host_free(void *data);

const char *scamper_do_host_usage(void);

/* code to use the host code to do DNS for another scamper task */
scamper_host_do_t *scamper_do_host_do_ptr(
  scamper_addr_t *ip, void *param, void (*cb)(void *, const char *name));
void scamper_host_do_free(scamper_host_do_t *hostdo);

void scamper_do_host_cleanup(void);
int scamper_do_host_init(void);

#endif /* __SCAMPER_DO_HOST_H */
