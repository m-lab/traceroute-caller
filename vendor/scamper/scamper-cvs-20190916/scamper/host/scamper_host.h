/*
 * scamper_host
 *
 * $Id: scamper_host.h,v 1.6 2019/07/28 09:24:53 mjl Exp $
 *
 * Copyright (C) 2018-2019 Matthew Luckie
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

#ifndef __SCAMPER_HOST_H
#define __SCAMPER_HOST_H

#define SCAMPER_HOST_FLAG_NORECURSE 0x0001

#define SCAMPER_HOST_CLASS_IN     1

#define SCAMPER_HOST_TYPE_A       1
#define SCAMPER_HOST_TYPE_NS      2
#define SCAMPER_HOST_TYPE_CNAME   5
#define SCAMPER_HOST_TYPE_SOA     6
#define SCAMPER_HOST_TYPE_PTR    12
#define SCAMPER_HOST_TYPE_MX     15
#define SCAMPER_HOST_TYPE_TXT    16
#define SCAMPER_HOST_TYPE_AAAA   28
#define SCAMPER_HOST_TYPE_DS     43
#define SCAMPER_HOST_TYPE_SSHFP  44
#define SCAMPER_HOST_TYPE_RRSIG  46
#define SCAMPER_HOST_TYPE_NSEC   47
#define SCAMPER_HOST_TYPE_DNSKEY 48

#define SCAMPER_HOST_STOP_NONE    0
#define SCAMPER_HOST_STOP_DONE    1
#define SCAMPER_HOST_STOP_TIMEOUT 2
#define SCAMPER_HOST_STOP_HALTED  3
#define SCAMPER_HOST_STOP_ERROR   4

#define SCAMPER_HOST_RR_DATA_TYPE_ADDR 1
#define SCAMPER_HOST_RR_DATA_TYPE_STR  2
#define SCAMPER_HOST_RR_DATA_TYPE_SOA  3
#define SCAMPER_HOST_RR_DATA_TYPE_MX   4

typedef struct scamper_host_rr_mx
{
  uint16_t                 preference;
  char                    *exchange;
} scamper_host_rr_mx_t;

typedef struct scamper_host_rr_soa
{
  char                    *mname;
  char                    *rname;
  uint32_t                 serial;
  uint32_t                 refresh;
  uint32_t                 retry;
  uint32_t                 expire;
  uint32_t                 minimum;
} scamper_host_rr_soa_t;

typedef struct scamper_host_rr
{
  uint16_t                 class;
  uint16_t                 type;
  char                    *name;
  uint32_t                 ttl;
  union
  {
    void                  *v;
    scamper_addr_t        *addr;
    char                  *str;
    scamper_host_rr_soa_t *soa;
    scamper_host_rr_mx_t  *mx;
  } un;
} scamper_host_rr_t;

typedef struct scamper_host_query
{
  struct timeval           tx;
  struct timeval           rx;
  uint16_t                 id;
  uint16_t                 ancount; /* answer count */
  uint16_t                 nscount; /* authority count */
  uint16_t                 arcount; /* additional count */
  scamper_host_rr_t      **an;
  scamper_host_rr_t      **ns;
  scamper_host_rr_t      **ar;
} scamper_host_query_t;

typedef struct scamper_host
{
  scamper_list_t          *list;     /* list */
  scamper_cycle_t         *cycle;    /* cycle */
  scamper_addr_t          *src;      /* source IP address */
  scamper_addr_t          *dst;      /* DNS server to query */
  uint32_t                 userid;   /* user assigned id */
  struct timeval           start;    /* when started */
  uint16_t                 flags;    /* flags controlling */
  uint16_t                 wait;     /* how long to wait, in ms */
  uint8_t                  stop;     /* reason we stopped */
  uint8_t                  retries;  /* how many retries to make */
  uint16_t                 qtype;    /* query type */
  uint16_t                 qclass;   /* query class */
  char                    *qname;    /* query name */
  scamper_host_query_t   **queries;  /* queries sent */
  uint8_t                  qcount;   /* number of queries sent */
} scamper_host_t;

scamper_host_rr_mx_t *scamper_host_rr_mx_alloc(uint16_t, const char *);
scamper_host_rr_soa_t *scamper_host_rr_soa_alloc(const char *, const char *);

scamper_host_rr_t *scamper_host_rr_alloc(const char *,
					 uint16_t, uint16_t, uint32_t);
void scamper_host_rr_free(scamper_host_rr_t *);

int scamper_host_rr_data_type(const scamper_host_rr_t *rr);

int scamper_host_queries_alloc(scamper_host_t *host, int n);
scamper_host_query_t *scamper_host_query_alloc(void);
int scamper_host_query_rr_alloc(scamper_host_query_t *query);

scamper_host_t *scamper_host_alloc(void);
void scamper_host_free(scamper_host_t *);

#endif /* __SCAMPER_HOST_H */
