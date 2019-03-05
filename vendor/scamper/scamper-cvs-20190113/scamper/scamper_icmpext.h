/*
 * scamper_icmpext.h
 *
 * $Id: scamper_icmpext.h,v 1.2 2012/11/26 20:54:46 mjl Exp $
 *
 * Copyright (C) 2008 The University of Waikato
 * Copyright (C) 2012 Matthew Luckie
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

#ifndef __SCAMPER_ICMPEXT_H
#define __SCAMPER_ICMPEXT_H

/*
 * scamper_icmpext
 *
 * this structure holds an individual icmp extension
 */
typedef struct scamper_icmpext
{
  uint8_t                 ie_cn;   /* class number */
  uint8_t                 ie_ct;   /* class type */
  uint16_t                ie_dl;   /* data length */
  uint8_t                *ie_data; /* data */
  struct scamper_icmpext *ie_next;
} scamper_icmpext_t;

#define SCAMPER_ICMPEXT_IS_MPLS(ie)				\
 ((ie)->ie_cn == 1 && (ie)->ie_ct == 1)

#define SCAMPER_ICMPEXT_IS_UNNUMBERED(ie)			\
 ((ie)->ie_cn == 2)

#define SCAMPER_ICMPEXT_MPLS_COUNT(ie)				\
 ((ie)->ie_dl >> 2)

#define SCAMPER_ICMPEXT_MPLS_LABEL(ie, x)			\
 (( (ie)->ie_data[((x)<<2)+0] << 12) +				\
  ( (ie)->ie_data[((x)<<2)+1] <<  4) +				\
  (((ie)->ie_data[((x)<<2)+2] >>  4) & 0xff))

#define SCAMPER_ICMPEXT_MPLS_EXP(ie, x)				\
 (((ie)->ie_data[((x)<<2)+2] >> 1) & 0x7)

#define SCAMPER_ICMPEXT_MPLS_S(ie, x)				\
 ((ie)->ie_data[((x)<<2)+2] & 0x1)

#define SCAMPER_ICMPEXT_MPLS_TTL(ie, x)				\
 ((ie)->ie_data[((x)<<2)+3])

#define SCAMPER_ICMPEXT_UNNUMBERED_CT_ROLE(ie)			\
 ((ie)->ie_data[0] >> 6)

#define SCAMPER_ICMPEXT_UNNUMBERED_CT_ROLE_ARRIVED_IP		0
#define SCAMPER_ICMPEXT_UNNUMBERED_CT_ROLE_ARRIVED_SUBIP	1
#define SCAMPER_ICMPEXT_UNNUMBERED_CT_ROLE_FORWARD		2
#define SCAMPER_ICMPEXT_UNNUMBERED_CT_ROLE_NEXTHOP		3

#define SCAMPER_ICMPEXT_UNNUMBERED_CT_IFINDEX			4
#define SCAMPER_ICMPEXT_UNNUMBERED_CT_IPADDR			5
#define SCAMPER_ICMPEXT_UNNUMBERED_CT_NAME			6
#define SCAMPER_ICMPEXT_UNNUMBERED_CT_MTU			7

#define SCAMPER_ICMPEXT_UNNUMBERED_CT_IS_IFINDEX(ie)		\
 ((ie)->ie_ct & SCAMPER_ICMPEXT_UNNUMBERED_CT_IFINDEX)

#define SCAMPER_ICMPEXT_UNNUMBERED_CT_IS_IPADDR(ie)		\
 ((ie)->ie_ct & SCAMPER_ICMPEXT_UNNUMBERED_CT_IPADDR)

#define SCAMPER_ICMPEXT_UNNUMBERED_CT_IS_NAME(ie)		\
 ((ie)->ie_ct & SCAMPER_ICMPEXT_UNNUMBERED_CT_NAME)

#define SCAMPER_ICMPEXT_UNNUMBERED_CT_IS_MTU(ie)		\
 ((ie)->ie_ct & SCAMPER_ICMPEXT_UNNUMBERED_CT_MTU)

typedef struct scamper_icmpext_unnumbered
{
  uint8_t  flags;
  uint32_t ifindex;
  int      af;
  union
    {
      struct in_addr v4;
      struct in6_addr v6;
    } un;
  char name[64];
  uint32_t mtu;
} scamper_icmpext_unnumbered_t;

void scamper_icmpext_unnumbered_parse(scamper_icmpext_t *ext,
				      scamper_icmpext_unnumbered_t *unn);

scamper_icmpext_t *scamper_icmpext_alloc(uint8_t cn, uint8_t ct, uint16_t dl,
					 const void *data);
int scamper_icmpext_parse(scamper_icmpext_t **ext, void *data, uint16_t len);
void scamper_icmpext_free(scamper_icmpext_t *exts);

#endif /* __SCAMPER_ICMPEXT_H */
