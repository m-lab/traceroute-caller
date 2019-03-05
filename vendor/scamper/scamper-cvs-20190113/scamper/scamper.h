/*
 * scamper.h
 *
 * $Id: scamper.h,v 1.59 2017/08/21 22:37:17 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2015      Matthew Luckie
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

#ifndef __SCAMPER_H
#define __SCAMPER_H

#define SCAMPER_PPS_MIN       1
#define SCAMPER_PPS_DEF       20
#define SCAMPER_PPS_MAX       10000
int scamper_pps_get(void);
int scamper_pps_set(const int pps);

#define SCAMPER_WINDOW_MIN    0
#define SCAMPER_WINDOW_DEF    0
#define SCAMPER_WINDOW_MAX    65535
int scamper_window_get(void);
int scamper_window_set(const int window);

#define SCAMPER_COMMAND_DEF   "trace"
const char *scamper_command_get(void);
int scamper_command_set(const char *command);

const char *scamper_monitorname_get(void);
int scamper_monitorname_set(const char *monitorname);

int scamper_option_planetlab(void);
int scamper_option_noinitndc(void);
int scamper_option_notls(void);
int scamper_option_select(void);
int scamper_option_kqueue(void);
int scamper_option_epoll(void);
int scamper_option_rawtcp(void);
int scamper_option_debugfileappend(void);
int scamper_option_tls(void);
int scamper_option_daemon(void);

void scamper_exitwhendone(int on);

uint16_t scamper_sport_default(void);

#define SCAMPER_VERSION "cvs head"

#endif /* __SCAMPER_H */
