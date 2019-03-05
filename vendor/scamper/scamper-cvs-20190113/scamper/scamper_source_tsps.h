/*
 * scamper_source_tsps.h
 *
 * $Id: scamper_source_tsps.h,v 1.1 2010/05/11 02:07:22 mjl Exp $
 *
 * Copyright (C) 2010 The University of Waikato
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

#ifndef __SCAMPER_SOURCE_TSPS_H
#define __SCAMPER_SOURCE_TSPS_H

scamper_source_t *scamper_source_tsps_alloc(scamper_source_params_t *ssp,
					    const char *filename);

const char *scamper_source_tsps_getfilename(const scamper_source_t *source);

#endif /* __SCAMPER_SOURCE_TSPS_H */
