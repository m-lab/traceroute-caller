/*
 * scamper_task.h
 *
 * $Id: scamper_task.h,v 1.42 2019/01/13 06:58:50 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2013      The Regents of the University of California
 * Copyright (C) 2018      Matthew Luckie
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

#ifndef __SCAMPER_TASK_H
#define __SCAMPER_TASK_H

struct scamper_addr;
struct scamper_queue;
struct scamper_task;
struct scamper_dl_rec;
struct scamper_icmp_resp;
struct scamper_cyclemon;
struct scamper_file;
struct scamper_sourcetask;

#define SCAMPER_TASK_SIG_TYPE_TX_IP 1
#define SCAMPER_TASK_SIG_TYPE_TX_ND 2
#define SCAMPER_TASK_SIG_TYPE_SNIFF 3
#define SCAMPER_TASK_SIG_TYPE_HOST  4

typedef struct scamper_task scamper_task_t;
typedef struct scamper_task_anc scamper_task_anc_t;

typedef struct scamper_task_sig
{
  uint8_t sig_type;
  union
  {
    struct tx_ip
    {
      struct scamper_addr *dst;
      struct scamper_addr *src;
    } ip;
    struct tx_nd
    {
      struct scamper_addr *ip;
    } nd;
    struct sniff
    {
      struct scamper_addr *src;
      uint16_t             icmpid;
    } sniff;
    struct host
    {
      char                *name;
    } host;
  } un;
} scamper_task_sig_t;

#define sig_tx_ip_dst     un.ip.dst
#define sig_tx_ip_src     un.ip.src
#define sig_tx_nd_ip      un.nd.ip
#define sig_sniff_src     un.sniff.src
#define sig_sniff_icmp_id un.sniff.icmpid
#define sig_host_name     un.host.name

typedef struct scamper_task_funcs
{
  /* probe the destination */
  void (*probe)(struct scamper_task *task);

  /* handle some ICMP packet */
  void (*handle_icmp)(struct scamper_task *task,
		      struct scamper_icmp_resp *icmp);

  /* handle some information from the datalink */
  void (*handle_dl)(struct scamper_task *task, struct scamper_dl_rec *dl_rec);

  /* handle the task timing out on the wait queue */
  void (*handle_timeout)(struct scamper_task *task);

  void (*halt)(struct scamper_task *task);

  /* write the task's data object out */
  void (*write)(struct scamper_file *file, struct scamper_task *task);

  /* free the task's data and state */
  void (*task_free)(struct scamper_task *task);

} scamper_task_funcs_t;

scamper_task_t *scamper_task_alloc(void *data, scamper_task_funcs_t *funcs);
void scamper_task_free(scamper_task_t *task);

/* get various items of the task */
void *scamper_task_getdata(const scamper_task_t *task);
void *scamper_task_getstate(const scamper_task_t *task);
struct scamper_source *scamper_task_getsource(scamper_task_t *task);

/* set various items on the task */
void scamper_task_setdatanull(scamper_task_t *task);
void scamper_task_setstate(scamper_task_t *task, void *state);
void scamper_task_setsourcetask(scamper_task_t *task,
				struct scamper_sourcetask *st);
void scamper_task_setcyclemon(scamper_task_t *t, struct scamper_cyclemon *cm);

/* access the various functions registered with the task */
void scamper_task_write(scamper_task_t *task, struct scamper_file *file);
void scamper_task_probe(scamper_task_t *task);
void scamper_task_handleicmp(scamper_task_t *task,struct scamper_icmp_resp *r);
void scamper_task_handletimeout(scamper_task_t *task);
void scamper_task_halt(scamper_task_t *task);

/* pass the datalink record to all appropriate tasks */
void scamper_task_handledl(struct scamper_dl_rec *dl);

/* access the queue structre the task holds */
int scamper_task_queue_probe(scamper_task_t *task);
int scamper_task_queue_probe_head(scamper_task_t *task);
int scamper_task_queue_wait(scamper_task_t *task, int ms);
int scamper_task_queue_wait_tv(scamper_task_t *task, struct timeval *tv);
int scamper_task_queue_done(scamper_task_t *task, int ms);
int scamper_task_queue_isprobe(scamper_task_t *task);
int scamper_task_queue_isdone(scamper_task_t *task);

/* access the file descriptors the task holds */
#ifdef __SCAMPER_FD_H
scamper_fd_t *scamper_task_fd_icmp4(scamper_task_t *task, void *addr);
scamper_fd_t *scamper_task_fd_icmp6(scamper_task_t *task, void *addr);
scamper_fd_t *scamper_task_fd_udp4(scamper_task_t *task, void *a, uint16_t sp);
scamper_fd_t *scamper_task_fd_udp6(scamper_task_t *task, void *a, uint16_t sp);
scamper_fd_t *scamper_task_fd_tcp4(scamper_task_t *task, void *a, uint16_t sp);
scamper_fd_t *scamper_task_fd_tcp6(scamper_task_t *task, void *a, uint16_t sp);
scamper_fd_t *scamper_task_fd_dl(scamper_task_t *task, int ifindex);
scamper_fd_t *scamper_task_fd_ip4(scamper_task_t *task);
#endif

#if defined(__SCAMPER_FD_H) && !defined(_WIN32)
scamper_fd_t *scamper_task_fd_rtsock(scamper_task_t *task);
#endif

/* define and use the task's probe signatures */
scamper_task_sig_t *scamper_task_sig_alloc(uint8_t type);
void scamper_task_sig_free(scamper_task_sig_t *sig);
int scamper_task_sig_add(scamper_task_t *task, scamper_task_sig_t *sig);
scamper_task_t *scamper_task_sig_block(scamper_task_t *task);
int scamper_task_sig_install(scamper_task_t *task);
void scamper_task_sig_deinstall(scamper_task_t *task);
scamper_task_t *scamper_task_find(scamper_task_sig_t *sig);
char *scamper_task_sig_tostr(scamper_task_sig_t *sig, char *buf, size_t len);

/* manage ancillary data attached to the task */
scamper_task_anc_t *scamper_task_anc_add(scamper_task_t *task, void *data,
					 void (*freedata)(void *));
void scamper_task_anc_del(scamper_task_t *task, scamper_task_anc_t *anc);

/*
 * scamper_task_onhold
 *
 * given a task that another is blocked on, register the fact.
 * when the task is free'd, the unhold function will be called.
 *
 * returns a cookie, so the dehold function can cancel the task
 * from  being on hold at a later point.
 */
void *scamper_task_onhold(scamper_task_t *task, void *param,
			  void (*unhold)(void *param));

/*
 * scamper_task_dehold
 *
 * given a task and a cookie returned from putting another task on hold,
 * de-hold the task with this cookie.
 */
int scamper_task_dehold(scamper_task_t *task, void *cookie);

int scamper_task_init(void);
void scamper_task_cleanup(void);

#endif /* __SCAMPER_TASK_H */
