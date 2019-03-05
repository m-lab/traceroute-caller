/*
 * scamper_file_warts.h
 *
 * $Id: scamper_file_json.h,v 1.1 2017/07/09 09:05:14 mjl Exp $
 *
 * Copyright (C) 2017      Matthew Luckie
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

#ifndef __SCAMPER_FILE_JSON_H
#define __SCAMPER_FILE_JSON_H

typedef struct json_state
{
  int               isreg;
} json_state_t;

int scamper_file_json_cyclestart_write(const scamper_file_t *sf,
				       scamper_cycle_t *c);
int scamper_file_json_cyclestop_write(const scamper_file_t *sf,
				      scamper_cycle_t *c);

int json_write(const scamper_file_t *sf, const void *buf, size_t len);

int scamper_file_json_init_write(scamper_file_t *file);

void scamper_file_json_free_state(scamper_file_t *file);

#endif /* __SCAMPER_FILE_JSON_h */
