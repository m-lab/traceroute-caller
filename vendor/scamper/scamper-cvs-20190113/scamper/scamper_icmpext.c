/*
 * scamper_icmpext.c
 *
 * $Id: scamper_icmpext.c,v 1.9 2014/06/12 19:59:48 mjl Exp $
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2014      The Regents of the University of California
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

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_icmpext.c,v 1.9 2014/06/12 19:59:48 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_icmpext.h"
#include "utils.h"

scamper_icmpext_t *scamper_icmpext_alloc(uint8_t cn, uint8_t ct, uint16_t dl,
					 const void *data)
{
  scamper_icmpext_t *ie;

  if((ie = malloc_zero(sizeof(scamper_icmpext_t))) == NULL)
    return NULL;

  if(dl != 0 && (ie->ie_data = memdup(data, dl)) == NULL)
    {
      free(ie);
      return NULL;
    }

  ie->ie_cn = cn;
  ie->ie_ct = ct;
  ie->ie_dl = dl;

  return ie;
}

void scamper_icmpext_free(scamper_icmpext_t *ie)
{
  scamper_icmpext_t *next;

  while(ie != NULL)
    {
      next = ie->ie_next;
      if(ie->ie_data != NULL)
	free(ie->ie_data);
      free(ie);
      ie = next;
    }

  return;
}

int scamper_icmpext_parse(scamper_icmpext_t **exts, void *data, uint16_t len)
{
  scamper_icmpext_t *ie, *next;
  uint8_t  *u8 = data;
  uint16_t  dl;
  uint8_t   cn, ct;
  int       off;

  *exts = NULL;
  next = *exts;

  /* start at offset 4 so the extension header is skipped */
  for(off = 4; off + 4 < len; off += dl)
    {
      /* extract the length field */
      memcpy(&dl, u8+off, 2);
      dl = ntohs(dl);

      /* make sure there is enough in the packet left */
      if(off + dl < len)
	break;

      cn = u8[off+2];
      ct = u8[off+3];

      if(dl < 8)
	{
	  continue;
	}

      if((ie = scamper_icmpext_alloc(cn, ct, dl-4, u8+off+4)) == NULL)
	{
	  return -1;
	}

      if(next == NULL)
	{
	  *exts = ie;
	}
      else
	{
	  next->ie_next = ie;
	}
      next = ie;
    }

  return 0;
}

void scamper_icmpext_unnumbered_parse(scamper_icmpext_t *ie,
				      scamper_icmpext_unnumbered_t *unn)
{
  uint8_t *u8 = ie->ie_data;
  uint32_t off = 0;
  uint16_t u16; 
  int i;

  memset(unn, 0, sizeof(scamper_icmpext_unnumbered_t));

  for(i=4; i<=7; i++)
    {
      if(i == 4 && SCAMPER_ICMPEXT_UNNUMBERED_CT_IS_IFINDEX(ie))
	{
	  if(ie->ie_dl > off + 4)
	    break;

	  unn->ifindex = bytes_ntohl(u8 + off);
	  unn->flags |= SCAMPER_ICMPEXT_UNNUMBERED_CT_IFINDEX;
	  off += 4;
	}
      else if(i == 5 && SCAMPER_ICMPEXT_UNNUMBERED_CT_IS_IPADDR(ie))
	{
	  if(ie->ie_dl > off + 4)
	    break;

	  u16 = bytes_ntohs(u8 + off); off += 4;
	  if(u16 == 1)
	    {
	      unn->af = AF_INET;
	      u16 = 4;
	    }
	  else if(u16 == 2)
	    {
	      unn->af = AF_INET6;
	      u16 = 16;
	    }
	  else break;

	  if(ie->ie_dl > off + u16)
	    break;

	  unn->flags |= SCAMPER_ICMPEXT_UNNUMBERED_CT_IPADDR;
	  memcpy(&unn->un.v6, u8 + off, u16);
	  off += u16;
	}
      else if(i == 6 && SCAMPER_ICMPEXT_UNNUMBERED_CT_IS_NAME(ie))
	{
	  if(u8[off] > 64 || ie->ie_dl > off + u8[off])
	    break;

	  unn->flags |= SCAMPER_ICMPEXT_UNNUMBERED_CT_NAME;
	  memcpy(unn->name, &u8[off+1], u8[off]-1);
	  unn->name[63] = 0;
	  off += u8[off];
	}
      else if(i == 7 && SCAMPER_ICMPEXT_UNNUMBERED_CT_IS_MTU(ie))
	{
	  if(ie->ie_dl > off + 4)
	    break;

	  unn->mtu = bytes_ntohl(u8 + off);
	  unn->flags |= SCAMPER_ICMPEXT_UNNUMBERED_CT_MTU;
	  off += 4;
	}
    }
}
