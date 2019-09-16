/*
 * scamper_firewall.h
 *
 * $Id: scamper_firewall.h,v 1.5 2016/08/07 10:27:56 mjl Exp $
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Copyright (C) 2016      Matthew Luckie
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

#ifndef __SCAMPER_FIREWALL_H
#define __SCAMPER_FIREWALL_H

#define SCAMPER_FIREWALL_RULE_TYPE_5TUPLE 0x1

/* handle returned when a firewall entry is added to the table */
typedef struct scamper_firewall_entry scamper_firewall_entry_t;

#ifdef __SCAMPER_ADDR_H
typedef struct scamper_firewall_rule
{
  uint16_t type;
  union
  {
    struct fivetuple
    {
      uint8_t         proto;
      scamper_addr_t *src;
      scamper_addr_t *dst;
      uint16_t        sport;
      uint16_t        dport;
    } fivetuple;
  } un;
} scamper_firewall_rule_t;

scamper_firewall_entry_t *scamper_firewall_entry_get(scamper_firewall_rule_t *);
#endif

#define sfw_5tuple_proto un.fivetuple.proto
#define sfw_5tuple_src   un.fivetuple.src
#define sfw_5tuple_dst   un.fivetuple.dst
#define sfw_5tuple_sport un.fivetuple.sport
#define sfw_5tuple_dport un.fivetuple.dport

void scamper_firewall_entry_free(scamper_firewall_entry_t *);

/* routines to handle initialising structures to manage the firewall */
int scamper_firewall_init(const char *opt);
void scamper_firewall_cleanup(void);

#ifdef HAVE_IPFW
int scamper_firewall_ipfw_init(void);
void scamper_firewall_ipfw_cleanup(void);
int scamper_firewall_ipfw_add(int n,int af,int p,void *s,void *d,int sp,int dp);
int scamper_firewall_ipfw_del(int n,int af);
#endif

#ifdef HAVE_PF
int scamper_firewall_pf_init(const char *anchor);
int scamper_firewall_pf_add(int n,int af,int p,void *s,void *d,int sp,int dp);
int scamper_firewall_pf_del(int n);
void scamper_firewall_pf_cleanup(void);
#endif

#endif /* __SCAMPER_FIREWALL_H */
