/*
 * scamper_osinfo.h
 *
 * $Id: scamper_osinfo.h,v 1.1 2012/05/08 17:27:22 mjl Exp $
 *
 * Copyright (C) 2006 Matthew Luckie
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

#define SCAMPER_OSINFO_OS_NULL     0
#define SCAMPER_OSINFO_OS_FREEBSD  1
#define SCAMPER_OSINFO_OS_OPENBSD  2
#define SCAMPER_OSINFO_OS_NETBSD   3
#define SCAMPER_OSINFO_OS_SUNOS    4
#define SCAMPER_OSINFO_OS_LINUX    5
#define SCAMPER_OSINFO_OS_DARWIN   6
#define SCAMPER_OSINFO_OS_WINDOWS  7

typedef struct scamper_osinfo
{
  /* name of the OS, and an ID for it */
  char *os;
  int   os_id;

  /* parse the OS version string into integers */
  long *os_rel;
  int   os_rel_dots;

} scamper_osinfo_t;

#define SCAMPER_OSINFO_IS_SUNOS(os) ((os)->os_id == SCAMPER_OSINFO_OS_SUNOS)

int scamper_osinfo_init(void);
void scamper_osinfo_cleanup(void);

const scamper_osinfo_t *scamper_osinfo_get(void);
