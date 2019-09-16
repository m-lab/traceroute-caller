/*
 * scamper_icmp_resp.c
 *
 * $Id: scamper_icmp_resp.c,v 1.33 2016/09/17 12:11:20 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2013 The Regents of the University of California
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
  "$Id: scamper_icmp_resp.c,v 1.33 2016/09/17 12:11:20 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "utils.h"
#include "scamper_addr.h"
#include "scamper_task.h"
#include "scamper_icmp_resp.h"
#include "scamper_debug.h"

#if !defined(NDEBUG) || !defined(WITHOUT_DEBUGFILE)
void scamper_icmp_resp_print(const scamper_icmp_resp_t *ir)
{
  char *t = NULL, tbuf[64];
  char *c = NULL, cbuf[64];
  char addr[64];
  char ip[256];
  char icmp[256];
  char inner_ip[256];
  char inner_transport[256];
  char ext[256];
  int  i, j;
  size_t off;

  assert(ir->ir_af == AF_INET || ir->ir_af == AF_INET6);

  if(ir->ir_af == AF_INET)
    {
      addr_tostr(AF_INET, &ir->ir_ip_src.v4, addr, sizeof(addr));

      off = 0;
      string_concat(ip, sizeof(ip), &off,
		    "from %s size %d ttl %d tos 0x%02x ipid 0x%04x",
		    addr, ir->ir_ip_size, ir->ir_ip_ttl, ir->ir_ip_tos,
		    ir->ir_ip_id);

      if(ir->ir_ipopt_rrc > 0)
	string_concat(ip, sizeof(ip), &off, " rr %d", ir->ir_ipopt_rrc);

      switch(ir->ir_icmp_type)
        {
        case ICMP_UNREACH:
          t = "unreach";
          switch(ir->ir_icmp_code)
            {
            case ICMP_UNREACH_NET:           c = "net";           break;
            case ICMP_UNREACH_HOST:          c = "host";          break;
            case ICMP_UNREACH_PROTOCOL:      c = "protocol";      break;
            case ICMP_UNREACH_PORT:          c = "port";          break;
            case ICMP_UNREACH_SRCFAIL:       c = "src-rt failed"; break;
            case ICMP_UNREACH_NET_UNKNOWN:   c = "net unknown";   break;
            case ICMP_UNREACH_HOST_UNKNOWN:  c = "host unknown";  break;
            case ICMP_UNREACH_ISOLATED:      c = "isolated";      break;
            case ICMP_UNREACH_NET_PROHIB:    c = "net prohib";    break;
            case ICMP_UNREACH_HOST_PROHIB:   c = "host prohib";   break;
            case ICMP_UNREACH_TOSNET:        c = "tos net";       break;
            case ICMP_UNREACH_TOSHOST:       c = "tos host";      break;
            case ICMP_UNREACH_FILTER_PROHIB: c = "admin prohib";  break;
            case ICMP_UNREACH_NEEDFRAG:
	      /*
	       * use the type buf to be consistent with the ICMP6
	       * fragmentation required message
	       */
	      snprintf(tbuf, sizeof(tbuf), "need frag %d", ir->ir_icmp_nhmtu);
	      t = tbuf;
	      break;

            default:
	      snprintf(cbuf, sizeof(cbuf), "code %d", ir->ir_icmp_code);
	      c = cbuf;
	      break;
            }
          break;

        case ICMP_TIMXCEED:
          t = "time exceeded";
          switch(ir->ir_icmp_code)
            {
            case ICMP_TIMXCEED_INTRANS: c = "in trans"; break;
            case ICMP_TIMXCEED_REASS:   c = "in reass"; break;
            default:
	      snprintf(cbuf, sizeof(cbuf), "code %d", ir->ir_icmp_code);
	      c = cbuf;
	      break;
            }
          break;

	case ICMP_ECHOREPLY:
	  t = "echo reply";
	  snprintf(cbuf, sizeof(cbuf), "id %d seq %d",
		   ir->ir_icmp_id, ir->ir_icmp_seq);
	  c = cbuf;
	  break;

	case ICMP_TSTAMPREPLY:
	  t = "ts reply";
	  snprintf(cbuf, sizeof(cbuf), "id %d seq %d",
		   ir->ir_icmp_id, ir->ir_icmp_seq);
	  c = cbuf;
	  break;

	case ICMP_PARAMPROB:
	  t = "paramprob";
	  switch(ir->ir_icmp_code)
	    {
	    case ICMP_PARAMPROB_ERRATPTR:
	      snprintf(cbuf, sizeof(cbuf), "erratptr %u", ir->ir_icmp_pptr);
	      c = cbuf;
	      break;
	    case ICMP_PARAMPROB_OPTABSENT: c = "optabsent"; break;
	    case ICMP_PARAMPROB_LENGTH:    c = "length"; break;
	    default:
	      snprintf(cbuf, sizeof(cbuf), "code %d", ir->ir_icmp_code);
	      c = cbuf;
	      break;
	    }
	  break;
        }
    }
  else /* if(ir->ir_af == AF_INET6) */
    {
      addr_tostr(AF_INET6, &ir->ir_ip_src.v6, addr, sizeof(addr));

      snprintf(ip, sizeof(ip), "from %s size %d hlim %d", addr,
	       ir->ir_ip_size, ir->ir_ip_hlim);

      switch(ir->ir_icmp_type)
        {
        case ICMP6_DST_UNREACH:
          t = "unreach";
          switch(ir->ir_icmp_code)
            {
            case ICMP6_DST_UNREACH_NOROUTE:     c = "no route";     break;
            case ICMP6_DST_UNREACH_ADMIN:       c = "admin prohib"; break;
            case ICMP6_DST_UNREACH_BEYONDSCOPE: c = "beyond scope"; break;
            case ICMP6_DST_UNREACH_ADDR:        c = "addr";         break;
            case ICMP6_DST_UNREACH_NOPORT:      c = "port";         break;

            default:
	      snprintf(cbuf, sizeof(cbuf), "code %d", ir->ir_icmp_code);
	      c = cbuf;
	      break;
            }
          break;

        case ICMP6_TIME_EXCEEDED:
          t = "time exceeded";
          switch(ir->ir_icmp_code)
            {
            case ICMP6_TIME_EXCEED_TRANSIT:    c = "in trans"; break;
            case ICMP6_TIME_EXCEED_REASSEMBLY: c = "in reass"; break;

            default:
	      snprintf(cbuf, sizeof(cbuf), "code %d", ir->ir_icmp_code);
	      c = cbuf;
	      break;
            }
          break;

	case ICMP6_PACKET_TOO_BIG:
	  snprintf(tbuf, sizeof(tbuf), "need frag %d", ir->ir_icmp_nhmtu);
	  t = tbuf;
	  break;

	case ICMP6_ECHO_REPLY:
	  t = "echo reply";
	  snprintf(cbuf, sizeof(cbuf), "id %d seq %d",
		   ir->ir_icmp_id, ir->ir_icmp_seq);
	  c = cbuf;
	  break;
        }
    }

  if(t == NULL)
    {
      snprintf(icmp, sizeof(icmp), "icmp %d code %d",
	       ir->ir_icmp_type, ir->ir_icmp_code);
    }
  else if(c == NULL)
    {
      snprintf(icmp, sizeof(icmp), "icmp %s", t);
    }
  else
    {
      snprintf(icmp, sizeof(icmp), "icmp %s %s", t, c);
    }

  if(ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_INNER_IP)
    {
      if(ir->ir_af == AF_INET)
	{
	  addr_tostr(AF_INET, &ir->ir_inner_ip_dst.v4, addr, sizeof(addr));

	  off = 0;
	  string_concat(inner_ip, sizeof(inner_ip), &off,
			" to %s size %d ttl %d tos 0x%02x ipid 0x%04x",
			addr, ir->ir_inner_ip_size, ir->ir_inner_ip_ttl,
			ir->ir_inner_ip_tos, ir->ir_inner_ip_id);
	  if(ir->ir_inner_ipopt_rrc > 0)
	    string_concat(inner_ip, sizeof(inner_ip), &off, " rr %d",
			  ir->ir_inner_ipopt_rrc);
	}
      else /* if(ir->ir_af == AF_INET6) */
	{
	  addr_tostr(AF_INET6, &ir->ir_inner_ip_dst.v6, addr, sizeof(addr));
	  snprintf(inner_ip, sizeof(inner_ip),
		   " to %s size %d hlim %d flow 0x%05x", addr,
		   ir->ir_inner_ip_size, ir->ir_inner_ip_hlim,
		   ir->ir_inner_ip_flow);
	}

      switch(ir->ir_inner_ip_proto)
	{
	case IPPROTO_UDP:
	  snprintf(inner_transport, sizeof(inner_transport),
		   " proto UDP sport %d dport %d sum 0x%04x",
		   ir->ir_inner_udp_sport, ir->ir_inner_udp_dport,
		   ntohs(ir->ir_inner_udp_sum));
	  break;

	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	  snprintf(inner_transport, sizeof(inner_transport),
		   " proto ICMP type %d code %d id %04x seq %d sum %04x",
		   ir->ir_inner_icmp_type, ir->ir_inner_icmp_code,
		   ir->ir_inner_icmp_id, ir->ir_inner_icmp_seq,
		   ntohs(ir->ir_inner_icmp_sum));
	  break;

	case IPPROTO_TCP:
	  snprintf(inner_transport, sizeof(inner_transport),
		   " proto TCP sport %d dport %d seq %08x",
		   ir->ir_inner_tcp_sport, ir->ir_inner_tcp_dport,
		   ir->ir_inner_tcp_seq);
	  break;

	default:
	  inner_transport[0] = '\0';
	  break;
	}
    }
  else
    {
      inner_ip[0] = '\0';
      inner_transport[0] = '\0';
    }

  if(ir->ir_ext != NULL)
    {
      snprintf(ext, sizeof(ext), " icmp-ext");
      j = 9;
      for(i=0; i<ir->ir_extlen; i++)
	{
	  if(i % 4 == 0)
	    {
	      if(sizeof(ext)-j < 4)
		break;
	      ext[j++] = ' ';
	    }
	  else if(sizeof(ext)-j < 3)
	    break;
	  byte2hex(ir->ir_ext[i], ext + j);
	  j += 2;
	}
      ext[j] = '\0';
    }
  else
    {
      ext[0] = '\0';
    }

  scamper_debug(NULL, "%s %s%s%s%s", ip, icmp, inner_ip, inner_transport, ext);
  return;
}
#endif

int scamper_icmp_resp_src(scamper_icmp_resp_t *resp, scamper_addr_t *addr)
{
  if(resp->ir_af == AF_INET)
    {
      addr->type = SCAMPER_ADDR_TYPE_IPV4;
      addr->addr = &resp->ir_ip_src.v4;
      return 0;
    }
  else if(resp->ir_af == AF_INET6)
    {
      addr->type = SCAMPER_ADDR_TYPE_IPV6;
      addr->addr = &resp->ir_ip_src.v6;
      return 0;
    }
  return -1;
}

int scamper_icmp_resp_inner_dst(scamper_icmp_resp_t *resp,scamper_addr_t *addr)
{
  if(resp->ir_af == AF_INET)
    {
      addr->type = SCAMPER_ADDR_TYPE_IPV4;
      addr->addr = &resp->ir_inner_ip_dst.v4;
      return 0;
    }
  else if(resp->ir_af == AF_INET6)
    {
      addr->type = SCAMPER_ADDR_TYPE_IPV6;
      addr->addr = &resp->ir_inner_ip_dst.v6;
      return 0;
    }
  return -1;
}

void scamper_icmp_resp_clean(scamper_icmp_resp_t *ir)
{
  if(ir->ir_ext != NULL)
    free(ir->ir_ext);

  if(ir->ir_ipopt_rrs != NULL)
    free(ir->ir_ipopt_rrs);

  if(ir->ir_ipopt_tsips != NULL)
    free(ir->ir_ipopt_tsips);

  if(ir->ir_ipopt_tstss != NULL)
    free(ir->ir_ipopt_tstss);

  if(ir->ir_inner_ipopt_rrs != NULL)
    free(ir->ir_inner_ipopt_rrs);

  if(ir->ir_inner_ipopt_tsips != NULL)
    free(ir->ir_inner_ipopt_tsips);

  if(ir->ir_inner_ipopt_tstss != NULL)
    free(ir->ir_inner_ipopt_tstss);

  return;
}

void scamper_icmp_resp_handle(scamper_icmp_resp_t *resp)
{
  scamper_task_sig_t sig;
  scamper_task_t *task;
  scamper_addr_t  addr;

  if(SCAMPER_ICMP_RESP_IS_TTL_EXP(resp) ||
     SCAMPER_ICMP_RESP_IS_UNREACH(resp) ||
     SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(resp) ||
     SCAMPER_ICMP_RESP_IS_PARAMPROB(resp))
    {
      /* the probe signature is embedded in the response */
      if(!SCAMPER_ICMP_RESP_INNER_IS_SET(resp))
	return;
      if(scamper_icmp_resp_inner_dst(resp, &addr) != 0)
	return;
    }
  else if(SCAMPER_ICMP_RESP_IS_ECHO_REPLY(resp) ||
	  SCAMPER_ICMP_RESP_IS_TIME_REPLY(resp))
    {
      /* the probe signature is an ICMP echo/ts request */
      if(scamper_icmp_resp_src(resp, &addr) != 0)
	return;
    }
  else
    {
      return;
    }

  memset(&sig, 0, sizeof(sig));
  sig.sig_type = SCAMPER_TASK_SIG_TYPE_TX_IP;
  sig.sig_tx_ip_dst = &addr;
  if((task = scamper_task_find(&sig)) != NULL)
    scamper_task_handleicmp(task, resp);
  return;
}
