/*
 * scamper_neighbourdisc
 *
 * $Id: scamper_neighbourdisc.h,v 1.4 2011/10/20 21:58:33 mjl Exp $
 *
 * Copyright (C) 2009 Matthew Luckie
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

#ifndef __SCAMPER_NEIGHBOURDISC_H
#define __SCAMPER_NEIGHBOURDISC_H

#define SCAMPER_NEIGHBOURDISC_METHOD_ARP     0x01
#define SCAMPER_NEIGHBOURDISC_METHOD_ND_NSOL 0x02

#define SCAMPER_NEIGHBOURDISC_FLAG_ALLATTEMPTS   0x01
#define SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE 0x02

typedef struct scamper_neighbourdisc_reply
{
  struct timeval                  rx;       /* time this reply was received */
  scamper_addr_t                 *mac;      /* MAC address sent */
} scamper_neighbourdisc_reply_t;

typedef struct scamper_neighbourdisc_probe
{
  struct timeval                  tx;       /* time this request was sent */
  scamper_neighbourdisc_reply_t **rxs;      /* replies received */
  uint16_t                        rxc;      /* number of replies received */
} scamper_neighbourdisc_probe_t;

typedef struct scamper_neighbourdisc
{
  scamper_list_t                 *list;     /* list */
  scamper_cycle_t                *cycle;    /* cycle */
  uint32_t                        userid;   /* user assigned id */
  struct timeval                  start;    /* when started */
  char                           *ifname;   /* interface name */
  uint8_t                         method;   /* method of neighbour disc. */
  uint8_t                         flags;    /* misc. flags */
  uint16_t                        wait;     /* how long to wait, in ms */
  uint16_t                        attempts; /* number of attempts to make */
  uint16_t                        replyc;   /* replies requested */
  scamper_addr_t                 *src_ip;   /* source IP address */
  scamper_addr_t                 *src_mac;  /* source MAC address */
  scamper_addr_t                 *dst_ip;   /* target IP address, if any */
  scamper_addr_t                 *dst_mac;  /* target MAC address, if any */
  scamper_neighbourdisc_probe_t **probes;   /* details of probes sent */
  uint16_t                        probec;   /* probe count sent */
} scamper_neighbourdisc_t;

scamper_neighbourdisc_t *scamper_neighbourdisc_alloc(void);
void scamper_neighbourdisc_free(scamper_neighbourdisc_t *);
scamper_addr_t *scamper_neighbourdisc_addr(const void *va);

scamper_neighbourdisc_probe_t *scamper_neighbourdisc_probe_alloc(void);
void scamper_neighbourdisc_probe_free(scamper_neighbourdisc_probe_t *);
int scamper_neighbourdisc_probe_add(scamper_neighbourdisc_t *,
				    scamper_neighbourdisc_probe_t *);
int scamper_neighbourdisc_probes_alloc(scamper_neighbourdisc_t *, uint16_t);

int scamper_neighbourdisc_ifname_set(scamper_neighbourdisc_t *, char *);

scamper_neighbourdisc_reply_t *scamper_neighbourdisc_reply_alloc(void);
void scamper_neighbourdisc_reply_free(scamper_neighbourdisc_reply_t *);
int scamper_neighbourdisc_reply_add(scamper_neighbourdisc_probe_t *,
				    scamper_neighbourdisc_reply_t *);
int scamper_neighbourdisc_replies_alloc(scamper_neighbourdisc_probe_t *,
					uint16_t);

#endif /* __SCAMPER_NEIGHBOURDISC_H */
