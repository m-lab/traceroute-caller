/*
 * scamper_firewall.c
 *
 * $Id: scamper_firewall.c,v 1.53 2017/12/03 09:42:27 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
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

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_firewall.c,v 1.53 2017/12/03 09:42:27 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#ifdef HAVE_NETINET_IP_FW_H
#include <netinet/ip_fw.h>
#ifdef HAVE_NETINET6_IP_FW_H
#include <netinet6/ip6_fw.h>
#endif
#endif

#ifdef HAVE_NET_PFVAR_H
#include <net/pfvar.h>
#endif

#include "scamper_addr.h"
#include "scamper_debug.h"
#include "scamper_firewall.h"
#include "scamper_privsep.h"
#include "scamper_osinfo.h"
#include "mjl_heap.h"
#include "mjl_splaytree.h"
#include "utils.h"

#if defined(HAVE_IPFW) || defined(HAVE_PF)

struct scamper_firewall_entry
{
  int                      slot;
  int                      refcnt;
  splaytree_node_t        *node;
  scamper_firewall_rule_t *rule;
};

static splaytree_t *entries = NULL;
static heap_t *freeslots = NULL;

static int firewall_rule_cmp(const scamper_firewall_rule_t *a,
			     const scamper_firewall_rule_t *b)
{
  int i;

  assert(a->type == SCAMPER_FIREWALL_RULE_TYPE_5TUPLE);
  assert(b->type == SCAMPER_FIREWALL_RULE_TYPE_5TUPLE);

  if(a->type < b->type) return -1;
  if(a->type > b->type) return  1;

  if(a->type == SCAMPER_FIREWALL_RULE_TYPE_5TUPLE)
    {
      if(a->sfw_5tuple_proto < b->sfw_5tuple_proto) return -1;
      if(a->sfw_5tuple_proto > b->sfw_5tuple_proto) return  1;

      if(a->sfw_5tuple_sport < b->sfw_5tuple_sport) return -1;
      if(a->sfw_5tuple_sport > b->sfw_5tuple_sport) return  1;

      if(a->sfw_5tuple_dport < b->sfw_5tuple_dport) return -1;
      if(a->sfw_5tuple_dport > b->sfw_5tuple_dport) return  1;

      if((i = scamper_addr_cmp(a->sfw_5tuple_src, b->sfw_5tuple_src)) != 0)
	return i;

      if(a->sfw_5tuple_dst == NULL && b->sfw_5tuple_dst == NULL)
	return 0;
      if(a->sfw_5tuple_dst != NULL && b->sfw_5tuple_dst == NULL)
	return -1;
      if(a->sfw_5tuple_dst == NULL && b->sfw_5tuple_dst != NULL)
	return 1;

      return scamper_addr_cmp(a->sfw_5tuple_dst, b->sfw_5tuple_dst);
    }

  return 0;
}

static void firewall_rule_free(scamper_firewall_rule_t *sfw)
{
  if(sfw == NULL)
    return;

  if(sfw->sfw_5tuple_src != NULL)
    scamper_addr_free(sfw->sfw_5tuple_src);
  if(sfw->sfw_5tuple_dst != NULL)
    scamper_addr_free(sfw->sfw_5tuple_dst);
  free(sfw);

  return;
}

static scamper_firewall_rule_t *firewall_rule_dup(scamper_firewall_rule_t *sfw)
{
  scamper_firewall_rule_t *dup;

  if((dup = memdup(sfw, sizeof(scamper_firewall_rule_t))) == NULL)
    return NULL;

  scamper_addr_use(dup->sfw_5tuple_src);
  if(dup->sfw_5tuple_dst != NULL)
    scamper_addr_use(dup->sfw_5tuple_dst);

  return dup;
}

static int firewall_entry_cmp(const scamper_firewall_entry_t *a,
			      const scamper_firewall_entry_t *b)
{
  return firewall_rule_cmp(a->rule, b->rule);
}

/*
 * firewall_entry_slot_cmp
 *
 * provide ordering for the freeslots heap by returning the earliest available
 * slot number in a range
 */
static int firewall_entry_slot_cmp(const scamper_firewall_entry_t *a,
				   const scamper_firewall_entry_t *b)
{
  if(a->slot > b->slot) return -1;
  if(a->slot < b->slot) return 1;
  return 0;
}

/*
 * firewall_entry_free
 *
 */
static void firewall_entry_free(scamper_firewall_entry_t *entry)
{
  if(entry->node != NULL)
    splaytree_remove_node(entries, entry->node);
  firewall_rule_free(entry->rule);
  free(entry);
  return;
}

static int firewall_freeslots_alloc(long start, long end)
{
  scamper_firewall_entry_t *entry;
  long i;

  if((freeslots = heap_alloc((heap_cmp_t)firewall_entry_slot_cmp)) == NULL)
    {
      printerror(__func__, "could not create freeslots heap");
      return -1;
    }

  for(i=start; i<=end; i++)
    {
      if((entry = malloc_zero(sizeof(scamper_firewall_entry_t))) == NULL)
	{
	  printerror(__func__, "could not alloc entry %d", i);
	  return -1;
	}
      entry->slot = i;
      if(heap_insert(freeslots, entry) == NULL)
	{
	  printerror(__func__, "could not add entry %d", i);
	  return -1;
	}
    }

  return 0;
}

static int firewall_entries_alloc(void)
{
  if((entries = splaytree_alloc((splaytree_cmp_t)firewall_entry_cmp)) == NULL)
    {
      printerror(__func__, "could not create entries tree");
      return -1;
    }
  return 0;
}
#endif /* HAVE_IPFW || HAVE_PF */

#ifdef HAVE_IPFW
/* variables to keep state with ipfw, which is rule-number based */
static int ipfw_use = 0;
static int ipfw_inited = 0;
static int ipfw_have_ipv6 = 0;
static int ipfw_have_ipv4 = 0;

static int ipfw_sysctl_check(void)
{
  const scamper_osinfo_t *osinfo;
  size_t len;
  char *name;
  int i;

  len = sizeof(i);
  name = "net.inet.ip.fw.enable";
  if(sysctlbyname(name, &i, &len, NULL, 0) != 0)
    {
      printerror(__func__, "could not sysctl %s", name);
      return -1;
    }
  else
    {
      if(i != 0)
	ipfw_have_ipv4 = 1;
      else
	scamper_debug(__func__, "ipfw ipv4 not enabled");
    }

  len = sizeof(i);
  name = "net.inet6.ip6.fw.enable";
  if(sysctlbyname(name, &i, &len, NULL, 0) != 0)
    {
      printerror(__func__, "could not sysctl %s", name);
      if(errno != ENOENT)
	return -1;

      /*
       * check if the system is known to not have a separate sysctl for
       * ipv6 ipfw.
       */
      i = 0;
      osinfo = scamper_osinfo_get();
      if((osinfo->os_id == SCAMPER_OSINFO_OS_FREEBSD &&
	  osinfo->os_rel_dots >= 2 &&
	  osinfo->os_rel[0] == 6 && osinfo->os_rel[1] < 3) ||
	 (osinfo->os_id == SCAMPER_OSINFO_OS_DARWIN &&
	  osinfo->os_rel_dots > 0 && osinfo->os_rel[0] == 8))
	{
	  ipfw_have_ipv6 = ipfw_have_ipv4;
	}
      else i++;

      if(i != 0)
	return -1;
    }
  else
    {
      if(i != 0)
	ipfw_have_ipv6 = 1;
      else
	scamper_debug(__func__, "ipfw ipv6 not enabled");
    }

  return 0;
}

#ifdef _IPFW2_H
static int fws = -1;

int scamper_firewall_ipfw_init(void)
{
  if(fws != -1 || ipfw_sysctl_check() != 0 || ipfw_inited != 0)
    return -1;

  if((fws = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
      printerror(__func__, "could not open socket for ipfw");
      return -1;
    }

  ipfw_inited = 1;
  return 0;
}

void scamper_firewall_ipfw_cleanup(void)
{
  if(fws != -1)
    {
      close(fws);
      fws = -1;
    }
  return;
}

#if __FreeBSD_version >= 600000
static int ipfw_deny_ip6_ext6hdr_frag(int n, void *s, void *d)
{
  struct ip_fw *fw = NULL;
  socklen_t sl;
  uint16_t insnc;
  ipfw_insn_ip6 *insn_ip6;
  ipfw_insn *insn;

  insnc = 1 + 5 + 1 + 1;

  if(d != NULL)
    insnc += 5;
  else
    insnc += 1;

  sl = sizeof(struct ip_fw) + (insnc*4) - 4;

  if((fw = malloc_zero(sl)) == NULL)
    {
      printerror(__func__, "could not malloc ip_fw");
      goto err;
    }

  fw->rulenum = n;
  fw->act_ofs = insnc-1;
  fw->cmd_len = insnc;
  insn = fw->cmd;

  insn->opcode = O_IP6;
  insn->len    = 1;
  insn += insn->len;

  insn_ip6 = (ipfw_insn_ip6 *)insn;
  insn->opcode = O_IP6_SRC;
  insn->len    = 5;
  memcpy(&insn_ip6->addr6, s, 16);
  insn += insn->len;

  if(d != NULL)
    {
      insn_ip6 = (ipfw_insn_ip6 *)insn;
      insn->opcode = O_IP6_DST;
      insn->len    = 5;
      memcpy(&insn_ip6->addr6, d, 16);
    }
  else
    {
      insn->opcode = O_IP6_DST_ME;
      insn->len    = 1;
    }
  insn += insn->len;

  insn->opcode = O_EXT_HDR;
  insn->len    = 1;
  insn->arg1   = EXT_FRAGMENT;
  insn += insn->len;

  insn->opcode = O_DENY;
  insn->len    = 1;

  if(getsockopt(fws, IPPROTO_IP, IP_FW_ADD, fw, &sl) != 0)
    {
      printerror(__func__, "could not add rule");
      goto err;
    }

  free(fw);
  return 0;

 err:
  if(fw != NULL) free(fw);
  return -1;
}
#endif

int scamper_firewall_ipfw_add(int n,int af,int p,void *s,void *d,int sp,int dp)
{
  ipfw_insn_u32 *insn_u32;
  ipfw_insn_u16 *insn_u16;
  struct ip_fw *fw = NULL;
  ipfw_insn *insn;
  socklen_t sl;
  size_t len;

#if __FreeBSD_version >= 600000
  ipfw_insn_ip6 *insn_ip6;
#endif

  /*
   * build ip_fw struct
   *
   * note that the ip_fw struct has one member reserved for
   * the first instruction, so that is not counted here
   */
  len = 2 + 2 + 1; /* O_PROTO + O_IP_SRCPORT + O_IP_DSTPORT + O_DENY */

  if(af == AF_INET)
    len += 2; /* O_IP_SRC */
  else if(af == AF_INET6)
    len += 5; /* O_IP6_SRC */
  else
    goto err;

  if(d == NULL)
    len += 1; /* O_IP_DST_ME -or- O_IP6_DST_ME */
  else if(af == AF_INET)
    len += 2; /* O_IP_DST */
  else if(af == AF_INET6)
    len += 5; /* O_IP6_DST */
  else
    goto err;

  if((fw = malloc_zero(sizeof(struct ip_fw) + (len * 4))) == NULL)
    {
      printerror(__func__, "could not malloc ip_fw");
      goto err;
    }
  sl = sizeof(struct ip_fw) + (len * 4);

#if defined(__APPLE__)
  fw->version = IP_FW_CURRENT_API_VERSION;
#endif

  fw->rulenum = n;
  fw->act_ofs = len;
  fw->cmd_len = len+1;
  insn = fw->cmd;

  /* encode the O_PROTO parameter */
  insn->opcode = O_PROTO;
  insn->len    = 1;
  insn->arg1   = p;
  insn += insn->len;

  /* encode the O_IP_SRC parameter */
  if(af == AF_INET)
    {
      insn_u32 = (ipfw_insn_u32 *)insn;
      memcpy(insn_u32->d, s, 4);
      insn->opcode = O_IP_SRC;
      insn->len    = 2;
    }
#if __FreeBSD_version >= 600000
  else if(af == AF_INET6)
    {
      insn_ip6 = (ipfw_insn_ip6 *)insn;
      memcpy(&insn_ip6->addr6, s, 16);
      insn->opcode = O_IP6_SRC;
      insn->len    = 5;
    }
#endif
  else
    goto err;

  insn += insn->len;

  /* encode the O_IP_SRCPORT parameter */
  insn_u16 = (ipfw_insn_u16 *)insn;
  insn->opcode = O_IP_SRCPORT;
  insn->len    = 2;
  insn_u16->ports[0] = sp;
  insn_u16->ports[1] = sp;
  insn += insn->len;

  /* encode the O_IP_DST parameter */
  if(d == NULL)
    {
      if(af == AF_INET)
	insn->opcode = O_IP_DST_ME;
#if __FreeBSD_version >= 600000
      else if(af == AF_INET6)
	insn->opcode = O_IP6_DST_ME;
#endif
      else
	goto err;
      insn->len = 1;
    }
  else if(af == AF_INET)
    {
      insn_u32 = (ipfw_insn_u32 *)insn;
      memcpy(insn_u32->d, d, 4);
      insn->opcode = O_IP_DST;
      insn->len    = 2;
    }
#if __FreeBSD_version >= 600000
  else if(af == AF_INET6)
    {
      insn_ip6 = (ipfw_insn_ip6 *)insn;
      memcpy(&insn_ip6->addr6, d, 16);
      insn->opcode = O_IP6_DST;
      insn->len    = 5;
    }
#endif
  else
    goto err;
  insn += insn->len;

  /* encode the O_IP_DSTPORT parameter */
  insn_u16 = (ipfw_insn_u16 *)insn;
  insn->opcode = O_IP_DSTPORT;
  insn->len    = 2;
  insn_u16->ports[0] = dp;
  insn_u16->ports[1] = dp;
  insn += insn->len;

  /* encode the O_DENY action */
  insn->opcode = O_DENY;
  insn->len    = 1;

  if(getsockopt(fws, IPPROTO_IP, IP_FW_ADD, fw, &sl) != 0)
    {
      printerror(__func__, "could not add rule");
      goto err;
    }

  free(fw);

#if __FreeBSD_version >= 600000
  if(af == AF_INET6)
    ipfw_deny_ip6_ext6hdr_frag(n, s, d);
#endif

  return 0;

 err:
  if(fw != NULL) free(fw);
  return -1;
}

int scamper_firewall_ipfw_del(int n, int af)
{
  uint32_t rule = n;

  if(setsockopt(fws, IPPROTO_IP, IP_FW_DEL, &rule, sizeof(rule)) != 0)
    {
      printerror(__func__, "could not delete rule %d", n);
      return -1;
    }

  return 0;
}
#endif /* _IPFW2_H */

#if defined(_IP_FW_H) || defined(__APPLE__)
static int fw4s = -1;
static int fw6s = -1;

int scamper_firewall_ipfw_init(void)
{
  if(fw4s != -1 || fw6s != -1 || ipfw_sysctl_check() != 0 || ipfw_inited != 0)
    return -1;

  if(ipfw_have_ipv4 != 0 && (fw4s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
      printerror(__func__, "could not open socket for ipfw");
      return -1;
    }
  if(ipfw_have_ipv6 != 0 && (fw6s = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
      printerror(__func__, "could not open socket for ip6fw");
      return -1;
    }

  ipfw_inited = 1;
  return 0;
}

void scamper_firewall_ipfw_cleanup(void)
{
  if(fw4s != -1)
    {
      close(fw4s);
      fw4s = -1;
    }
  if(fw6s != -1)
    {
      close(fw6s);
      fw6s = -1;
    }
  return;
}

int scamper_firewall_ipfw_add(int n,int af,int p,void *s,void *d,int sp,int dp)
{
  struct ip_fw fw;
  struct ip6_fw fw6;
  int level, optname;
  void *optval;
  socklen_t optlen;
  int i, fd;

  if(af == AF_INET)
    {
      memset(&fw, 0, sizeof(fw));
      fw.fw_number = n;
      fw.fw_flg = IP_FW_F_DENY | IP_FW_F_IN;
      fw.fw_prot = p;
      memcpy(&fw.fw_src, s, 4);
      fw.fw_smsk.s_addr = ~0;
      memcpy(&fw.fw_dst, d, 4);
      fw.fw_dmsk.s_addr = ~0;
      fw.fw_uar.fw_pts[0] = sp;
      IP_FW_SETNSRCP(&fw, 1);
      fw.fw_uar.fw_pts[1] = dp;
      IP_FW_SETNDSTP(&fw, 1);

#ifdef __APPLE__
      fw.version = IP_FW_CURRENT_API_VERSION;
#endif

      level   = IPPROTO_IP;
      optname = IP_FW_ADD;
      optval  = &fw;
      optlen  = sizeof(fw);
      fd      = fw4s;
    }
  else if(af == AF_INET6)
    {
      memset(&fw6, 0, sizeof(fw6));
      fw6.fw_number = n;
      fw6.fw_flg = IPV6_FW_F_DENY | IPV6_FW_F_IN;
      fw6.fw_prot = p;
      memcpy(&fw6.fw_src, s, 16);
      for(i=0; i<4; i++)
	fw6.fw_smsk.s6_addr32[i] = ~0;
      memcpy(&fw6.fw_dst, d, 16);
      for(i=0; i<4; i++)
	fw6.fw_dmsk.s6_addr32[i] = ~0;
      fw6.fw_pts[0] = sp;
      IPV6_FW_SETNSRCP(&fw6, 1);
      fw6.fw_pts[1] = dp;
      IPV6_FW_SETNDSTP(&fw6, 1);

#ifdef __APPLE__
      fw6.version   = IPV6_FW_CURRENT_API_VERSION;
#endif

      level   = IPPROTO_IPV6;
      optname = IPV6_FW_ADD;
      optval  = &fw6;
      optlen  = sizeof(fw6);
      fd      = fw6s;
    }
  else return -1;

  if(setsockopt(fd, level, optname, optval, optlen) != 0)
    {
      printerror(__func__, "could not add fw rule");
      return -1;
    }

  return 0;
}

int scamper_firewall_ipfw_del(int n, int af)
{
  struct ip_fw fw;
  struct ip6_fw fw6;
  int level, optname;
  void *optval;
  socklen_t optlen;
  int fd;

  if(af == AF_INET)
    {
      memset(&fw, 0, sizeof(fw));
      fw.fw_number = n;
#ifdef __APPLE__
      fw.version   = IP_FW_CURRENT_API_VERSION;
#endif

      level   = IPPROTO_IP;
      optname = IP_FW_DEL;
      optval  = &fw;
      optlen  = sizeof(fw);
      fd      = fw4s;
    }
  else if(af == AF_INET6)
    {
      memset(&fw6, 0, sizeof(fw6));
      fw6.fw_number = n;
#ifdef __APPLE__
      fw6.version   = IPV6_FW_CURRENT_API_VERSION;
#endif

      level   = IPPROTO_IPV6;
      optname = IPV6_FW_DEL;
      optval  = &fw6;
      optlen  = sizeof(fw6);
      fd      = fw6s;
    }
  else
    {
      return -1;
    }

  if(setsockopt(fd, level, optname, optval, optlen) != 0)
    {
      printerror(__func__, "could not delete rule %d", n);
      return -1;
    }

  return 0;
}
#endif /* _IPFW_H */

static int ipfw_init(char *opts)
{
  long start, end;
  char *ptr;

  if(opts == NULL)
    {
      scamper_debug(__func__, "no IPFW configuration parameters supplied");
      return -1;
    }

  string_nullterm_char(opts, '-', &ptr);
  if(ptr == NULL || string_isnumber(opts) == 0 || string_isnumber(ptr) == 0)
    {
      scamper_debug(__func__, "invalid IFPW options");
      return -1;
    }
  if(string_tolong(opts, &start) != 0 || start < 1 || start > 65534)
    {
      scamper_debug(__func__, "invalid start rule number for IPFW");
      return -1;
    }
  if(string_tolong(ptr, &end) != 0 || end <= start || end > 65534)
    {
      scamper_debug(__func__, "invalid end rule number for IPFW");
      return -1;
    }

  if(ipfw_sysctl_check() != 0)
    return -1;

  if(firewall_entries_alloc() != 0)
    return -1;

  if(firewall_freeslots_alloc(start, end) != 0)
    return -1;

#ifdef WITHOUT_PRIVSEP
  if(scamper_firewall_ipfw_init() != 0)
    return -1;
#else
  if(scamper_privsep_ipfw_init() != 0)
    return -1;
#endif

  ipfw_use = 1;
  return 0;
}

static int ipfw_add(int ruleno, scamper_firewall_rule_t *sfw)
{
  int af, p, sp, dp;
  void *s, *d;

  assert(ipfw_use != 0);

  if(sfw->sfw_5tuple_src->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      if(ipfw_have_ipv4 == 0)
	{
	  scamper_debug(__func__, "IPv4 rule requested but no IPv4 firewall");
	  return -1;
	}
      af = AF_INET;
    }
  else if(sfw->sfw_5tuple_src->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      if(ipfw_have_ipv6 == 0)
	{
	  scamper_debug(__func__, "IPv6 rule requested but no IPv6 firewall");
	  return -1;
	}
      af = AF_INET6;
    }
  else
    {
      scamper_debug(__func__, "invalid src type");
      return -1;
    }

  p  = sfw->sfw_5tuple_proto;
  dp = sfw->sfw_5tuple_dport;
  sp = sfw->sfw_5tuple_sport;
  s  = sfw->sfw_5tuple_src->addr;
  if(sfw->sfw_5tuple_dst == NULL)
    d = NULL;
  else
    d = sfw->sfw_5tuple_dst->addr;

#ifdef WITHOUT_PRIVSEP
  if(scamper_firewall_ipfw_add(ruleno, af, p, s, d, sp, dp) != 0)
    return -1;
#else
  if(scamper_privsep_ipfw_add(ruleno, af, p, s, d, sp, dp) != 0)
    return -1;
#endif

  return 0;
}

int ipfw_del(const scamper_firewall_entry_t *entry)
{
  int af = scamper_addr_af(entry->rule->sfw_5tuple_src);
#ifdef WITHOUT_PRIVSEP
  return scamper_firewall_ipfw_del(entry->slot, af);
#else
  return scamper_privsep_ipfw_del(entry->slot, af);
#endif
}

#endif /* HAVE_IPFW */

#ifdef HAVE_PF
static int pf_use = 0;
static int pf_inited = 0;
static int pf_fd = -1;
static pid_t pf_pid = 0;
static char *pf_name = NULL;

/*
 * scamper_firewall_pf_init
 *
 * code that can be called both inside scamper_firewall.c and
 * scamper_privsep.c for initalising the PF firewall.
 */
int scamper_firewall_pf_init(const char *name)
{
  struct pf_status status;
  size_t len;

  if(pf_fd != -1 || pf_inited != 0)
    return -1;
  if((len = strlen(name)) == 0 || string_isprint(name, len) == 0)
    return -1;

  if((pf_name = strdup(name)) == NULL)
    {
      printerror(__func__, "could not dup name");
      return -1;
    }

  if((pf_fd = open("/dev/pf", O_RDWR)) == -1)
    {
      printerror(__func__, "could not open socket");
      return -1;
    }

  if(ioctl(pf_fd, DIOCGETSTATUS, &status) == -1)
    {
      printerror(__func__, "could not get status");
      return -1;
    }
  if(status.running == 0)
    {
      scamper_debug(__func__, "pf not running");
      return -1;
    }

  pf_pid = getpid();
  pf_inited = 1;
  return 0;
}

void scamper_firewall_pf_cleanup(void)
{
  if(pf_fd != -1)
    {
      close(pf_fd);
      pf_fd = -1;
    }
  if(pf_name != NULL)
    {
      free(pf_name);
      pf_name = NULL;
    }
  return;
}

int scamper_firewall_pf_add(int n,int af,int p,void *s,void *d,int sp,int dp)
{
  char anchor[PF_ANCHOR_NAME_SIZE];
  struct pfioc_trans_e pfte;
  struct pfioc_trans pft;
  struct pfioc_rule pfr;
  size_t off;

  off = 0;
  string_concat(anchor, sizeof(anchor), &off, "%s/%d.%d", pf_name, pf_pid, n);

  memset(&pft, 0, sizeof(pft));
  pft.size = 1;
  pft.esize = sizeof(pfte);
  pft.array = &pfte;
  memset(&pfte, 0, sizeof(pfte));
  strncpy(pfte.anchor, anchor, sizeof(pfte.anchor)-1);
  pfte.anchor[sizeof(pfte.anchor)-1] = '\0';

#if defined(HAVE_STRUCT_PFIOC_TRANS_E_TYPE)
  pfte.type = PF_TRANS_RULESET;
#endif
#if defined(HAVE_STRUCT_PFIOC_TRANS_E_RS_NUM)
  pfte.rs_num = PF_RULESET_FILTER;
#endif

  if(ioctl(pf_fd, DIOCXBEGIN, &pft) == -1)
    {
      printerror(__func__, "could not begin transaction");
      return -1;
    }

  memset(&pfr, 0, sizeof(pfr));
  strncpy(pfr.anchor, anchor, sizeof(pfr.anchor)-1);
  pfte.anchor[sizeof(pfr.anchor)-1] = '\0';
  pfr.ticket = pfte.ticket;
  pfr.rule.af = af;
  pfr.rule.proto = p;
  pfr.rule.direction = PF_IN;
  pfr.rule.src.addr.type = PF_ADDR_ADDRMASK;
  pfr.rule.dst.addr.type = PF_ADDR_ADDRMASK;
#if defined(HAVE_STRUCT_PF_RULE_NAT)
  pfr.rule.nat.addr.type = PF_ADDR_NONE;
#endif
#if defined(HAVE_STRUCT_PF_RULE_RDR)
  pfr.rule.rdr.addr.type = PF_ADDR_NONE;
#endif

  if(af == AF_INET)
    {
      memcpy(&pfr.rule.src.addr.v.a.addr.v4, s, 4);
      memset(&pfr.rule.src.addr.v.a.mask.v4, 255, 4);
      memcpy(&pfr.rule.dst.addr.v.a.addr.v4, d, 4);
      memset(&pfr.rule.dst.addr.v.a.mask.v4, 255, 4);
    }
  else
    {
      memcpy(&pfr.rule.src.addr.v.a.addr.v6, s, 16);
      memset(&pfr.rule.src.addr.v.a.mask.v6, 255, 16);
      memcpy(&pfr.rule.src.addr.v.a.addr.v6, d, 16);
      memset(&pfr.rule.dst.addr.v.a.mask.v6, 255, 16);
    }

  pfr.rule.src.port_op = PF_OP_EQ;
  pfr.rule.src.port[0] = htons(sp);
  pfr.rule.dst.port_op = PF_OP_EQ;
  pfr.rule.dst.port[0] = htons(dp);
  pfr.rule.action = PF_DROP;
  pfr.rule.quick = 1;

  if(ioctl(pf_fd, DIOCADDRULE, &pfr) == -1)
    {
      printerror(__func__, "could not add rule");
      return -1;
    }

  if(ioctl(pf_fd, DIOCXCOMMIT, &pft) == -1)
    {
      printerror(__func__, "could not commit rule");
      return -1;
    }

  return 0;
}

int scamper_firewall_pf_del(int ruleno)
{
  struct pfioc_trans_e pfte;
  struct pfioc_trans pft;
  size_t off;

  memset(&pft, 0, sizeof(pft));
  pft.size = 1;
  pft.esize = sizeof(pfte);
  pft.array = &pfte;
  memset(&pfte, 0, sizeof(pfte));

  off = 0;
  string_concat(pfte.anchor, sizeof(pfte.anchor), &off,
		"%s/%d.%d", pf_name,pf_pid,ruleno);

#if defined(HAVE_STRUCT_PFIOC_TRANS_E_TYPE)
  pfte.type = PF_TRANS_RULESET;
#endif
#if defined(HAVE_STRUCT_PFIOC_TRANS_E_RS_NUM)
  pfte.rs_num = PF_RULESET_FILTER;
#endif

  if(ioctl(pf_fd, DIOCXBEGIN, &pft) == -1)
    {
      printerror(__func__, "could not begin transaction");
      return -1;
    }

  if(ioctl(pf_fd, DIOCXCOMMIT, &pft) == -1)
    {
      printerror(__func__, "could not commit rule");
      return -1;
    }

  return 0;
}

static int pf_add(int n, scamper_firewall_rule_t *sfw)
{
  int af, p, sp, dp;
  void *s, *d;

  assert(pf_use != 0);

  if(sfw->sfw_5tuple_src->type != SCAMPER_ADDR_TYPE_IPV4 &&
     sfw->sfw_5tuple_src->type != SCAMPER_ADDR_TYPE_IPV6)
    return -1;

  af = scamper_addr_af(sfw->sfw_5tuple_src);
  p  = sfw->sfw_5tuple_proto;
  dp = sfw->sfw_5tuple_dport;
  sp = sfw->sfw_5tuple_sport;
  s  = sfw->sfw_5tuple_src->addr;
  d  = sfw->sfw_5tuple_dst->addr;

#ifdef WITHOUT_PRIVSEP
  if(scamper_firewall_pf_add(n, af, p, s, d, sp, dp) != 0)
    return -1;
#else
  if(scamper_privsep_pf_add(n, af, p, s, d, sp, dp) != 0)
    return -1;
#endif
  return 0;
}

static int pf_del(int n)
{
#ifdef WITHOUT_PRIVSEP
  return scamper_firewall_pf_del(n);
#else
  return scamper_privsep_pf_del(n);
#endif
}

static int pf_init(char *opts)
{
  char *name_str, *num_str;
  long num;

  name_str = opts;
  string_nullterm_char(opts, ':', &num_str);
  if(strlen(name_str) < 1)
    {
      scamper_debug(__func__, "invalid name");
      return -1;
    }
  if(num_str == NULL)
    {
      scamper_debug(__func__, "missing number");
      return -1;
    }

  if(string_isnumber(num_str) == 0 ||
     string_tolong(num_str, &num) != 0 || num < 1 || num > 65535)
    {
      scamper_debug(__func__, "%s is not a valid number", num_str);
      return -1;
    }

  if(firewall_entries_alloc() != 0)
    return -1;

  if(firewall_freeslots_alloc(1, num) != 0)
    return -1;

#ifdef WITHOUT_PRIVSEP
  if(scamper_firewall_pf_init(name_str) != 0)
    return -1;
#else
  if(scamper_privsep_pf_init(name_str) != 0)
    return -1;
#endif

  pf_use = 1;
  return 0;
}
#endif /* HAVE_PF */

scamper_firewall_entry_t *scamper_firewall_entry_get(scamper_firewall_rule_t *sfw)
{
#if defined(HAVE_IPFW) || defined(HAVE_PF)
  scamper_firewall_entry_t findme, *entry = NULL;

  /* sanity check the rule */
  if((sfw->sfw_5tuple_proto != IPPROTO_TCP &&
      sfw->sfw_5tuple_proto != IPPROTO_UDP) ||
      sfw->sfw_5tuple_sport == 0 ||
      sfw->sfw_5tuple_dport == 0 ||
     (sfw->sfw_5tuple_dst == NULL || sfw->sfw_5tuple_src == NULL ||
      sfw->sfw_5tuple_src->type != sfw->sfw_5tuple_dst->type))
    {
      scamper_debug(__func__, "invalid 5tuple rule");
      goto err;
    }

  findme.rule = sfw;
  if((entry = splaytree_find(entries, &findme)) != NULL)
    {
      entry->refcnt++;
      return entry;
    }

  if((entry = heap_remove(freeslots)) == NULL)
    goto err;

  entry->refcnt = 1;
  if((entry->rule = firewall_rule_dup(sfw)) == NULL ||
     (entry->node = splaytree_insert(entries, entry)) == NULL)
    {
      goto err;
    }

#ifdef HAVE_IPFW
  if(ipfw_use != 0)
    {
      if(ipfw_add(entry->slot, sfw) != 0)
	goto err;
      return entry;
    }
#endif

#ifdef HAVE_PF
  if(pf_use != 0)
    {
      if(pf_add(entry->slot, sfw) != 0)
	goto err;
      return entry;
    }
#endif

 err:
  if(entry != NULL)
    {
      if(entry->rule != NULL)
	firewall_rule_free(entry->rule);
      free(entry);
    }

#endif /* HAVE_IPFW || HAVE_PF */

  return NULL;
}

#if defined(HAVE_IPFW) || defined(HAVE_PF)
static int firewall_rule_delete(scamper_firewall_entry_t *entry)
{
#if defined(HAVE_IPFW)
  if(ipfw_use != 0)
    {
      if(ipfw_del(entry) != 0)
	return -1;
      goto done;
    }
#endif

#if defined(HAVE_PF)
  if(pf_use != 0)
    {
      if(pf_del(entry->slot) != 0)
	return -1;
      goto done;
    }
#endif

 done:
  /* put the rule back into the freeslots heap */
  if(heap_insert(freeslots, entry) == NULL)
    {
      printerror(__func__, "could not add entry %d", entry->slot);
      return -1;
    }

  /* free up the firewall rule associated with the entry */
  firewall_rule_free(entry->rule);
  entry->rule = NULL;

  return 0;
}
#endif

void scamper_firewall_entry_free(scamper_firewall_entry_t *entry)
{
#if defined(HAVE_IPFW) || defined(HAVE_PF)
  entry->refcnt--;
  if(entry->refcnt > 0)
    return;

  /* remove the entry from the tree */
  splaytree_remove_node(entries, entry->node);
  entry->node = NULL;

  /*
   * if the entry is still loaded in the firewall, remove it now.
   * note that this code is to handle the case that scamper_firewall_cleanup
   * is called before this function is called.
   */
  if(entry->slot >= 0)
    firewall_rule_delete(entry);
#endif
  return;
}

#if defined(HAVE_IPFW) || defined(HAVE_PF)
static int firewall_entry_cleanup(void *param, scamper_firewall_entry_t *entry)
{
  firewall_rule_delete(entry);
  entry->slot = -1;
  return 0;
}
#endif

void scamper_firewall_cleanup(void)
{
#if defined(HAVE_IPFW) || defined(HAVE_PF)
  scamper_firewall_entry_t *entry;

  if(entries != NULL)
    splaytree_inorder(entries,(splaytree_inorder_t)firewall_entry_cleanup,NULL);

  if(freeslots != NULL)
    {
      while((entry = heap_remove(freeslots)) != NULL)
	firewall_entry_free(entry);
      heap_free(freeslots, NULL);
      freeslots = NULL;
    }

  if(entries != NULL)
    {
      splaytree_free(entries, NULL);
      entries = NULL;
    }
#endif

#ifdef HAVE_IPFW
  if(ipfw_use != 0)
    {
#ifdef WITHOUT_PRIVSEP
      scamper_firewall_ipfw_cleanup();
#else
      if(ipfw_inited != 0)
	scamper_privsep_ipfw_cleanup();
#endif
    }
#endif

#ifdef HAVE_PF
  if(pf_use != 0)
    {
#ifdef WITHOUT_PRIVSEP
      scamper_firewall_pf_cleanup();
#else
      if(pf_inited != 0)
	scamper_privsep_pf_cleanup();
#endif
    }
#endif

  return;
}

int scamper_firewall_init(const char *opt)
{
#if defined(HAVE_IPFW) || defined(HAVE_PF)
  char *dup, *ptr;
  int rc = -1;

  if((dup = strdup(opt)) == NULL)
    {
      printerror(__func__, "could not dup opt");
      return -1;
    }
  string_nullterm_char(dup, ':', &ptr);

#if defined(HAVE_IPFW)
  if(strcasecmp(dup, "ipfw") == 0)
    {
      rc = ipfw_init(ptr);
      goto done;
    }
#endif

#if defined(HAVE_PF)
  if(strcasecmp(dup, "pf") == 0)
    {
      rc = pf_init(ptr);
      goto done;
    }
#endif

 done:
  free(dup);
  return rc;

#endif /* HAVE_IPFW || HAVE_PF */
  return -1;
}
