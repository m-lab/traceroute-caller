/*
 * scamper_cyclemon: monitor active use of cycle structures so we know when
 *                   to write a cycle-stop record.
 *
 * $Id: scamper_cyclemon.h,v 1.7 2008/05/30 09:45:27 mjl Exp $
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

#ifndef __SCAMPER_CYCLEMON_H
#define __SCAMPER_CYCLEMON_H

struct scamper_source;
struct scamper_outfile;

typedef void (*scamper_cyclemon_finish_t)(scamper_cycle_t *cycle,
					  struct scamper_source *source,
					  struct scamper_outfile *outfile);

/* structure for monitoring the references to a cycle by data producers */
typedef struct scamper_cyclemon scamper_cyclemon_t;

/* allocate a structure to monitor when to write a cycle stop record to file */
scamper_cyclemon_t *scamper_cyclemon_alloc(scamper_cycle_t *cycle,
					   scamper_cyclemon_finish_t finish,
					   struct scamper_source *source,
					   struct scamper_outfile *outfile);

scamper_cycle_t *scamper_cyclemon_cycle(const scamper_cyclemon_t *cyclemon);

void scamper_cyclemon_source_detach(scamper_cyclemon_t *cyclemon);

/* use and unuse the cyclemon structure */
scamper_cyclemon_t *scamper_cyclemon_use(scamper_cyclemon_t *cyclemon);
void scamper_cyclemon_unuse(scamper_cyclemon_t *cyclemon);

int scamper_cyclemon_refcnt(scamper_cyclemon_t *cyclemon);

/* free the cyclemon structure without writing to disk */
void scamper_cyclemon_free(scamper_cyclemon_t *cyclemon);

#endif /* __SCAMPER_CYCLEMON_H */
