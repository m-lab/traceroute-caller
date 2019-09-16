/*
 * scamper_source
 *
 * $Id: scamper_sources.c,v 1.57 2019/01/13 06:58:50 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2012      The Regents of the University of California
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

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_sources.c,v 1.57 2019/01/13 06:58:50 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_task.h"
#include "scamper_file.h"
#include "scamper_outfiles.h"
#include "scamper_sources.h"
#include "scamper_cyclemon.h"

#include "trace/scamper_trace_do.h"
#include "ping/scamper_ping_do.h"
#include "tracelb/scamper_tracelb_do.h"
#include "dealias/scamper_dealias_do.h"
#include "sting/scamper_sting_do.h"
#include "neighbourdisc/scamper_neighbourdisc_do.h"
#include "tbit/scamper_tbit_do.h"
#include "sniff/scamper_sniff_do.h"
#include "host/scamper_host_do.h"

#include "scamper_debug.h"

#include "utils.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"

/*
 * scamper_source
 *
 * this structure maintains state regarding tasks that come from a particular
 * source.  some of the state is stored in scamper_list_t and scamper_cycle_t
 * structures with the resulting data object.
 *
 */
struct scamper_source
{
  /* basic data collection properties to store with the source */
  scamper_list_t               *list;
  scamper_cycle_t              *cycle;

  /* properties of the source */
  uint32_t                      priority;
  int                           type;
  int                           refcnt;
  scamper_outfile_t            *sof;
  scamper_cyclemon_t           *cyclemon;

  /*
   * commands:     a list of commands for the source that are queued, ready to
   *               be passed out as tasks
   * cycle_points: the number of cycle points in the commands list
   * onhold:       a list of commands that are on hold.
   * tasks:        a list of tasks currently active from the source.
   * id:           the next id number to assign
   * idtree:       a tree of id numbers currently in use
   */
  dlist_t                      *commands;
  int                           cycle_points;
  dlist_t                      *onhold;
  dlist_t                      *tasks;
  uint32_t                      id;
  splaytree_t                  *idtree;

  /*
   * nodes to keep track of whether the source is in the active or blocked
   * lists, and a node to keep track of the source in a splaytree
   */
  void                         *list_;
  void                         *list_node;
  splaytree_node_t             *tree_node;

  /* data and callback functions specific to the type of source this is */
  void                         *data;
  int                         (*take)(void *data);
  void                        (*freedata)(void *data);
  int                         (*isfinished)(void *data);
  char *                      (*tostr)(void *data, char *str, size_t len);
};

struct scamper_sourcetask
{
  scamper_source_t *source;
  scamper_task_t   *task;
  dlist_node_t     *node;
  uint32_t          id;
  splaytree_node_t *idnode;
};

/*
 * scamper_source_observer
 *
 * this structure records details of an observer interested in monitoring
 * source events.
 *
 *  func:  the callback function to use when an event occurs
 *  param: the parameter to pass to the function
 *  node:  the appropriate dlist_node in the observers dlist.
 */
struct scamper_source_observer
{
  scamper_source_eventf_t  func;
  void                    *param;
  dlist_node_t            *node;
};

/*
 * command_funcs
 *
 * a utility struct to save passing loads of functions around individually
 * that are necessary to start a probe command.
 */
typedef struct command_func
{
  char             *command;
  size_t            len;
  void           *(*allocdata)(char *);
  scamper_task_t *(*alloctask)(void *, scamper_list_t *, scamper_cycle_t *);
  void            (*freedata)(void *data);
} command_func_t;

static const command_func_t command_funcs[] = {
  {
    "trace", 5,
    scamper_do_trace_alloc,
    scamper_do_trace_alloctask,
    scamper_do_trace_free,
  },
  {
    "ping", 4,
    scamper_do_ping_alloc,
    scamper_do_ping_alloctask,
    scamper_do_ping_free,
  },
  {
    "tracelb", 7,
    scamper_do_tracelb_alloc,
    scamper_do_tracelb_alloctask,
    scamper_do_tracelb_free,
  },
  {
    "dealias", 7,
    scamper_do_dealias_alloc,
    scamper_do_dealias_alloctask,
    scamper_do_dealias_free,
  },
  {
    "sting", 5,
    scamper_do_sting_alloc,
    scamper_do_sting_alloctask,
    scamper_do_sting_free,
  },
  {
    "neighbourdisc", 13,
    scamper_do_neighbourdisc_alloc,
    scamper_do_neighbourdisc_alloctask,
    scamper_do_neighbourdisc_free,
  },
  {
    "tbit", 4,
    scamper_do_tbit_alloc,
    scamper_do_tbit_alloctask,
    scamper_do_tbit_free,
  },
  {
    "sniff", 5,
    scamper_do_sniff_alloc,
    scamper_do_sniff_alloctask,
    scamper_do_sniff_free,
  },
  {
    "host", 4,
    scamper_do_host_alloc,
    scamper_do_host_alloctask,
    scamper_do_host_free,
  },
};

static size_t command_funcc = sizeof(command_funcs) / sizeof(command_func_t);

/*
 * command
 *
 *  type:  COMMAND_PROBE or COMMAND_CYCLE or COMMAND_TASK
 *  funcs: pointer to appropriate command_func_t
 *  data:  pointer to data allocated for task
 *  param: additional parameters specific to the command's type.
 */
typedef struct command
{
  uint8_t                   type;

  union
  {
    struct command_probe
    {
      const command_func_t *funcs;
      void                 *data;
      scamper_cyclemon_t   *cyclemon;
    } pr;
    scamper_cycle_t        *cycle;
    scamper_sourcetask_t   *sourcetask;
  } un;
} command_t;

#define COMMAND_PROBE      0x00
#define COMMAND_CYCLE      0x01
#define COMMAND_TASK       0x02

#define COMMAND_TYPE_MIN   0x00
#define COMMAND_TYPE_MAX   0x02

/*
 * command_onhold
 *
 * structure to keep details of a command on hold.
 *
 *  st:      the task that is waiting on another task to complete
 *  block:   the task that has blocked this task from executing
 *  source:  pointer to the source that wants to execute the command
 *  node:    pointer to the dlist_node in the source's onhold dlist
 *  cookie:  cookie returned by scamper_task_onhold.
 */
typedef struct command_onhold
{
  scamper_task_t       *block;
  scamper_sourcetask_t *st;
  scamper_source_t     *source;
  dlist_node_t         *node;
  void                 *cookie;
} command_onhold_t;

/*
 * global variables for managing sources:
 *
 * a source is stored in one of two lists depending on its state.  it is
 * either stored in the active list, a round-robin circular list, or in
 * the blocked list.
 *
 * the source, if any, currently being used (that is, has not used up its
 * priority quantum) is pointed to by source_cur.  the number of tasks that
 * have been read from the current source in this rotation is held in
 * source_cnt.
 *
 * the sources are stored in a tree that is searchable by name.
 */
static clist_t          *active      = NULL;
static dlist_t          *blocked     = NULL;
static dlist_t          *finished    = NULL;
static scamper_source_t *source_cur  = NULL;
static uint32_t          source_cnt  = 0;
static splaytree_t      *source_tree = NULL;
static dlist_t          *observers   = NULL;

/* forward declare */
static void source_free(scamper_source_t *source);

#if !defined(NDEBUG) && defined(SOURCES_DEBUG)
static int command_assert(void *item, void *param)
{
  command_t *c = item;
  int *cycles = param;

  assert(c->type <= COMMAND_TYPE_MAX);

  switch(c->type)
    {
    case COMMAND_PROBE:
      assert(c->un.pr.data != NULL);
      assert(c->un.pr.cyclemon != NULL);
      break;

    case COMMAND_TASK:
      assert(c->un.sourcetask != NULL);
      break;

    case COMMAND_CYCLE:
      *cycles = *cycles + 1;
      break;
    }

  return 0;
}

static int source_assert(void *item, void *param)
{
  scamper_source_t *s = item;
  command_onhold_t *c;
  dlist_node_t *dn;
  int cycles;

  /* check the source for valid refcnts */
  assert(s->refcnt > 0);
  if(s->list != NULL)
    assert(s->list->refcnt > 0);
  if(s->cycle != NULL)
    assert(s->cycle->refcnt > 0);
  if(s->sof != NULL)
    assert(scamper_outfile_getrefcnt(s->sof) > 0);

  /* simple checks on parameters in the source struct */
  assert(s->type >= SCAMPER_SOURCE_TYPE_MIN);
  assert(s->type <= SCAMPER_SOURCE_TYPE_MAX);
  assert(s->tasks != NULL);

  /* make sure the list pointer makes sense */
  assert(s->list_ != NULL);
  assert(s->list_ == active || s->list_ == blocked || s->list_ == finished);
  assert(s->list_ == param);

  /* sanity check queued commands */
  assert(s->commands != NULL);
  cycles = 0;
  dlist_foreach(s->commands, command_assert, &cycles);
  /* XXX: should cycles == s->cycle_points? */

  /* make sure the onhold list makes sense */
  assert(s->onhold != NULL);
  for(dn=dlist_head_node(s->onhold); dn != NULL; dn = dlist_node_next(dn))
    {
      c = dlist_node_item(dn);
      assert(c->node == dn);
      assert(c->source == s);
    }

  return 0;
}

static void sources_assert(void)
{
  assert(active != NULL);
  clist_foreach(active, source_assert, active);
  assert(blocked != NULL);
  dlist_foreach(blocked, source_assert, blocked);
  assert(finished != NULL);
  dlist_foreach(finished, source_assert, finished);
  return;
}
#else
#define sources_assert()((void)0)
#endif

static int source_refcnt_dec(scamper_source_t *source)
{
  assert(source->refcnt > 0);
  source->refcnt--;
  return source->refcnt;
}

/*
 * source_event_post_cb
 *
 * callback used by source_event_post to send an event to all the observers
 * in the observers list
 */
static int source_event_post_cb(void *item, void *param)
{
  scamper_source_observer_t *observer = (scamper_source_observer_t *)item;
  scamper_source_event_t *event = (scamper_source_event_t *)param;
  observer->func(event, observer->param);
  return 0;
}

/*
 * scamper_source_event_post
 *
 * send all observers notification that a particular event occured.
 */
void scamper_source_event_post(scamper_source_t *source, int type,
			       scamper_source_event_t *ev)
{
  scamper_source_event_t sse;
  struct timeval tv;

  /* check if there is actually anyone observing */
  if(observers == NULL)
    return;

  /* if null event, then create one from scratch */
  if(ev == NULL)
    {
      memset(&sse, 0, sizeof(sse));
      ev = &sse;
    }

  gettimeofday_wrap(&tv);
  ev->source = source;
  ev->event = type;
  ev->sec = tv.tv_sec;
  dlist_foreach(observers, source_event_post_cb, ev);

  return;
}

static scamper_sourcetask_t *sourcetask_alloc(scamper_source_t *source,
					      scamper_task_t *task)
{
  scamper_sourcetask_t *st = NULL;
  if((st = malloc_zero(sizeof(scamper_sourcetask_t))) == NULL)
    goto err;
  if((st->node = dlist_tail_push(source->tasks, st)) == NULL)
    goto err;
  st->source = scamper_source_use(source);
  st->task = task;
  return st;

 err:
  if(st != NULL) free(st);
  return NULL;
}

static int idtree_cmp(const scamper_sourcetask_t *a,
		      const scamper_sourcetask_t *b)
{
  if(a->id < b->id) return -1;
  if(a->id > b->id) return  1;
  return 0;
}

static command_t *command_alloc(int type)
{
  command_t *cmd;
  if((cmd = malloc_zero(sizeof(command_t))) == NULL)
    {
      printerror(__func__, "could not malloc command");
      return NULL;
    }
  cmd->type = type;
  return cmd;
}

static void command_free(command_t *command)
{
  if(command->type == COMMAND_PROBE)
    {
      if(command->un.pr.funcs->freedata != NULL && command->un.pr.data != NULL)
	command->un.pr.funcs->freedata(command->un.pr.data);
      if(command->un.pr.cyclemon != NULL)
	scamper_cyclemon_unuse(command->un.pr.cyclemon);
    }

  free(command);
  return;
}

/*
 * command_cycle
 *
 * given the commands list, append a cycle command to it.
 */
static int command_cycle(scamper_source_t *source, scamper_cycle_t *cycle)
{
  command_t *command = NULL;

  if((command = command_alloc(COMMAND_CYCLE)) == NULL)
    goto err;
  command->un.cycle = cycle;
  if(dlist_tail_push(source->commands, command) == NULL)
    goto err;
  source->cycle_points++;

  return 0;

 err:
  if(command != NULL) command_free(command);
  return -1;
}

/*
 * source_next
 *
 * advance to the next source to read addresses from, and reset the
 * current count of how many addresses have been returned off the list
 * for this source-cycle
 */
static scamper_source_t *source_next(void)
{
  void *node;

  if((node = clist_node_next(source_cur->list_node)) != source_cur->list_node)
    source_cur = clist_node_item(node);

  source_cnt = 0;

  return source_cur;
}

/*
 * source_active_detach
 *
 * detach the source out of the active list.  move to the next source
 * if it is the current source that is being read from.
 */
static void source_active_detach(scamper_source_t *source)
{
  void *node;

  assert(source->list_ == active);

  source_cur = NULL;
  source_cnt = 0;

  if(source->list_node != NULL)
    {
      if((node = clist_node_next(source->list_node)) != source->list_node)
	source_cur = clist_node_item(node);

      clist_node_pop(active, source->list_node);
    }

  source->list_     = NULL;
  source->list_node = NULL;

  return;
}

/*
 * source_blocked_detach
 *
 * detach the source out of the blocked list.
 */
static void source_blocked_detach(scamper_source_t *source)
{
  assert(source->list_ == blocked);

  dlist_node_pop(blocked, source->list_node);
  source->list_     = NULL;
  source->list_node = NULL;
  return;
}

/*
 * source_finished_detach
 *
 * detach the source out of the finished list.
 */
static void source_finished_detach(scamper_source_t *source)
{
  assert(source->list_ == finished);

  dlist_node_pop(finished, source->list_node);
  source->list_     = NULL;
  source->list_node = NULL;
  return;
}

/*
 * source_active_attach
 *
 * some condition has changed, which may mean the source can go back onto
 * the active list for use by the probing process.
 *
 * a caller MUST NOT assume that the source will necessarily end up on the
 * active list after calling this function.  for example, source_active_attach
 * may be called when new tasks are added to the command list.  however, the
 * source may have a zero priority, which means probing this source is
 * currently paused.
 */
static int source_active_attach(scamper_source_t *source)
{
  if(source->list_ == active)
    return 0;

  if(source->list_ == finished)
    return -1;

  if(source->list_ == blocked)
    {
      /* if the source has a zero priority, it must remain blocked */
      if(source->priority == 0)
	return 0;
      source_blocked_detach(source);
    }

  if((source->list_node = clist_tail_push(active, source)) == NULL)
    return -1;
  source->list_ = active;

  if(source_cur == NULL)
    {
      source_cur = source;
      source_cnt = 0;
    }

  return 0;
}

/*
 * source_blocked_attach
 *
 * put the specified source onto the blocked list.
 */
static int source_blocked_attach(scamper_source_t *source)
{
  if(source->list_ == blocked)
    return 0;

  if(source->list_ == finished)
    return -1;

  if(source->list_node != NULL)
    source_active_detach(source);

  if((source->list_node = dlist_tail_push(blocked, source)) == NULL)
    return -1;
  source->list_ = blocked;

  return 0;
}

/*
 * source_finished_attach
 *
 * put the specified source onto the finished list.
 */
static int source_finished_attach(scamper_source_t *source)
{
  if(source->list_ == finished)
    return 0;

  if(source->list_ == active)
    source_active_detach(source);
  else if(source->list_ == blocked)
    source_blocked_detach(source);

  if((source->list_node = dlist_tail_push(finished, source)) == NULL)
    return -1;

  source->list_ = finished;
  return 0;
}

/*
 * source_command_unhold
 *
 * the task this command was blocked on has now completed, and this callback
 * was used.  put the command at the front of the source's list of things
 * to do.
 */
static void source_command_unhold(void *cookie)
{
  command_onhold_t     *onhold = (command_onhold_t *)cookie;
  scamper_source_t     *source = onhold->source;
  scamper_sourcetask_t *st     = onhold->st;
  command_t            *cmd    = NULL;

  /*
   * 1. disconnect the onhold structure from the source
   * 2. free the onhold structure -- don't need it anymore
   * 3. put the task at the front of the source's command list
   * 4. ensure the source is in active rotation
   */
  dlist_node_pop(source->onhold, onhold->node);
  free(onhold);
  if((cmd = command_alloc(COMMAND_TASK)) == NULL)
    goto err;
  cmd->un.sourcetask = st; st = NULL;
  if(dlist_head_push(source->commands, cmd) == NULL)
    goto err;
  source_active_attach(source);
  return;

 err:
  if(st != NULL) scamper_sourcetask_free(st);
  if(cmd != NULL) free(cmd);
  return;
}

/*
 * source_command_onhold
 *
 *
 */
static int source_command_onhold(scamper_source_t *source,
				 scamper_task_t *block,
				 scamper_sourcetask_t *st)
{
  command_onhold_t *onhold = NULL;

  if((onhold         = malloc_zero(sizeof(command_onhold_t))) == NULL ||
     (onhold->node   = dlist_tail_push(source->onhold, onhold)) == NULL ||
     (onhold->cookie = scamper_task_onhold(block, onhold,
					   source_command_unhold)) == NULL)
    {
      goto err;
    }

  onhold->block  = block;
  onhold->source = source;
  onhold->st     = st;

  return 0;

 err:
  if(onhold != NULL)
    {
      if(onhold->node != NULL) dlist_node_pop(source->onhold, onhold->node);
      free(onhold);
    }
  return -1;
}

/*
 * source_task_install
 *
 * code to install a task if possible and put it onhold if not.
 *
 */
static int source_task_install(scamper_source_t *source,
			       scamper_sourcetask_t *st, scamper_task_t **out)
{
  scamper_task_t *task = st->task;
  scamper_task_t *block;

  if((block = scamper_task_sig_block(task)) == NULL)
    {
      if(scamper_task_sig_install(task) != 0)
	return -1;
      *out = task;
    }
  else
    {
      if(source_command_onhold(source, block, st) != 0)
	return -1;
      *out = NULL;
    }

  return 0;
}

static int command_task_handle(scamper_source_t *source, command_t *command,
			       scamper_task_t **task_out)
{
  scamper_sourcetask_t *st = command->un.sourcetask;
  command_free(command);
  return source_task_install(source, st, task_out);
}

static int command_probe_handle(scamper_source_t *source, command_t *command,
				scamper_task_t **task_out)
{
  const command_func_t *funcs = command->un.pr.funcs;
  scamper_sourcetask_t *st = NULL;
  scamper_cycle_t *cycle;
  scamper_task_t *task = NULL;

  sources_assert();

  /* get a pointer to the cycle for *this* task */
  cycle = scamper_cyclemon_cycle(command->un.pr.cyclemon);

  /* allocate the task structure to keep everything together */
  if((task = funcs->alloctask(command->un.pr.data,source->list,cycle)) == NULL)
    goto err;
  scamper_task_setcyclemon(task, command->un.pr.cyclemon);
  command->un.pr.data = NULL;
  command_free(command);
  command = NULL;

  /*
   * keep a record in the source that this task is now active
   * pass the cyclemon structure to the task
   */
  if((st = sourcetask_alloc(source, task)) == NULL)
    goto err;
  task = NULL;
  scamper_task_setsourcetask(st->task, st);

  if(source_task_install(source, st, task_out) != 0)
    goto err;

  sources_assert();
  return 0;

 err:
  if(st != NULL) scamper_sourcetask_free(st);
  if(task != NULL) scamper_task_free(task);
  if(command != NULL) command_free(command);
  sources_assert();
  return -1;
}

/*
 * command_cycle_handle
 *
 *
 */
static int command_cycle_handle(scamper_source_t *source, command_t *command)
{
  scamper_source_event_t sse;
  scamper_cycle_t *cycle = command->un.cycle;
  scamper_file_t *file;
  struct timeval tv;
  char hostname[MAXHOSTNAMELEN];

  sources_assert();

  /* get the hostname of the system for the cycle point */
  if(gethostname(hostname, sizeof(hostname)) == 0)
    cycle->hostname = strdup(hostname);

  /* get a timestamp for the cycle start point */
  gettimeofday_wrap(&tv);
  cycle->start_time = (uint32_t)tv.tv_sec;

  /* write a cycle start point to disk if there is a file to do so */
  if(source->sof != NULL &&
     (file = scamper_outfile_getfile(source->sof)) != NULL)
    {
      scamper_file_write_cycle_start(file, cycle);
    }

  /* post an event saying the cycle point just rolled around */
  memset(&sse, 0, sizeof(sse));
  sse.sse_cycle_cycle_id = cycle->id;
  scamper_source_event_post(source, SCAMPER_SOURCE_EVENT_CYCLE, &sse);

  command_free(command);
  sources_assert();
  return 0;
}

/*
 * source_cycle_finish
 *
 * when the last cycle is written to disk, we can start on the next cycle.
 */
static void source_cycle_finish(scamper_cycle_t *cycle,
				scamper_source_t *source,
				scamper_outfile_t *outfile)
{
  scamper_file_t *sf;
  struct timeval tv;

  sources_assert();

  /* timestamp when the cycle ends */
  gettimeofday_wrap(&tv);
  cycle->stop_time = (uint32_t)tv.tv_sec;

  /* write the cycle stop record out */
  if(outfile != NULL)
    {
      sf = scamper_outfile_getfile(outfile);
      scamper_file_write_cycle_stop(sf, cycle);
    }

  if(source != NULL)
    source->cycle_points--;

  sources_assert();
  return;
}

/*
 * source_cycle
 *
 * allocate and initialise a cycle start object for the source.
 * write the cycle start to disk.
 */
static int source_cycle(scamper_source_t *source, uint32_t cycle_id)
{
  scamper_cyclemon_t *cyclemon = NULL;
  scamper_cycle_t *cycle = NULL;

  sources_assert();

  /* allocate the new cycle object */
  if((cycle = scamper_cycle_alloc(source->list)) == NULL)
    {
      printerror(__func__, "could not alloc new cycle");
      goto err;
    }

  /* assign the cycle id */
  cycle->id = cycle_id;

  /* allocate structure to monitor references to the new cycle */
  if((cyclemon = scamper_cyclemon_alloc(cycle, source_cycle_finish, source,
					source->sof)) == NULL)
    {
      printerror(__func__, "could not alloc new cyclemon");
      goto err;
    }

  /* append the cycle record to the source's commands list */
  if(command_cycle(source, cycle) != 0)
    {
      printerror(__func__, "could not insert cycle marker");
      goto err;
    }

  /*
   * if there is a previous cycle object associated with the source, then
   * free that.  also free the cyclemon.
   */
  if(source->cycle != NULL)
    scamper_cycle_free(source->cycle);
  if(source->cyclemon != NULL)
    scamper_cyclemon_unuse(source->cyclemon);

  /* store the cycle and we're done */
  source->cycle = cycle;
  source->cyclemon = cyclemon;

  sources_assert();
  return 0;

 err:
  if(cyclemon != NULL) scamper_cyclemon_free(cyclemon);
  if(cycle != NULL) scamper_cycle_free(cycle);
  sources_assert();
  return -1;
}

static int source_cmp(const scamper_source_t *a, const scamper_source_t *b)
{
  return strcasecmp(b->list->name, a->list->name);
}

/*
 * source_flush_commands
 *
 * remove the ability for the source to supply any more commands, and remove
 * any commands it currently has queued.
 */
static void source_flush_commands(scamper_source_t *source)
{
  command_onhold_t *onhold;
  command_t *command;

  sources_assert();

  if(source->data != NULL)
    source->freedata(source->data);

  source->data        = NULL;
  source->take        = NULL;
  source->freedata    = NULL;
  source->isfinished  = NULL;
  source->tostr       = NULL;

  if(source->commands != NULL)
    {
      while((command = dlist_head_pop(source->commands)) != NULL)
	command_free(command);
      dlist_free(source->commands);
      source->commands = NULL;
    }

  if(source->onhold != NULL)
    {
      while((onhold = dlist_head_pop(source->onhold)) != NULL)
	{
	  scamper_task_dehold(onhold->block, onhold->cookie);
	  free(onhold);
	}
      dlist_free(source->onhold);
      source->onhold = NULL;
    }

  sources_assert();
  return;
}

/*
 * source_flush_tasks
 *
 * stop all active tasks that originated from the specified source.
 */
static void source_flush_tasks(scamper_source_t *source)
{
  scamper_sourcetask_t *st;

  sources_assert();

  /* flush all active tasks. XXX: what about completed tasks? */
  if(source->tasks != NULL)
    {
      /* scamper_task_free will free scamper_sourcetask_t */
      while((st = dlist_head_pop(source->tasks)) != NULL)
	{
	  st->node = NULL;
	  scamper_task_free(st->task);
	}
      dlist_free(source->tasks);
      source->tasks = NULL;
    }

  sources_assert();
  return;
}

/*
 * source_detach
 *
 * remove the source from sources management.
 */
static void source_detach(scamper_source_t *source)
{
  /* detach the source from whatever list it is in */
  if(source->list_ == active)
    source_active_detach(source);
  else if(source->list_ == blocked)
    source_blocked_detach(source);
  else if(source->list_ == finished)
    source_finished_detach(source);

  assert(source->list_ == NULL);
  assert(source->list_node == NULL);

  /* remove the source from the tree */
  if(source->tree_node != NULL)
    {
      splaytree_remove_node(source_tree, source->tree_node);
      source->tree_node = NULL;

      /* decrement the reference count held for the source */
      if(source_refcnt_dec(source) == 0)
	source_free(source);
    }

  return;
}

/*
 * scamper_source_isfinished
 *
 * determine if the source has queued all it has to do.
 * note that the tasks list may still have active items currently processing.
 */
int scamper_source_isfinished(scamper_source_t *source)
{
  sources_assert();

  /* if there are commands queued, then the source cannot be finished */
  if(source->commands != NULL && dlist_count(source->commands) > 0)
    return 0;

  /* if there are commands that are on hold, the source cannot be finished */
  if(source->onhold != NULL && dlist_count(source->onhold) > 0)
    return 0;

  /* if there are still tasks underway, the source is not finished */
  if(source->tasks != NULL && dlist_count(source->tasks) > 0)
    return 0;

  /*
   * if the source still has commands to come, then it is not finished.
   * the callback checks with the source-type specific code to see if there
   * are commands to come.
   */
  if(source->isfinished != NULL && source->isfinished(source->data) == 0)
    return 0;

  return 1;
}

/*
 * scamper_source_finished
 *
 * when a source is known to be finished (say a control socket that will no
 * longer be supplying tasks)
 */
void scamper_source_finished(scamper_source_t *source)
{
  sources_assert();
  assert(scamper_source_isfinished(source) != 0);
  if(source->cyclemon != NULL)
    {
      assert(scamper_cyclemon_refcnt(source->cyclemon) == 1);
      scamper_cyclemon_unuse(source->cyclemon);
      source->cyclemon = NULL;
    }
  source_finished_attach(source);
  sources_assert();
  return;
}

/*
 * source_free
 *
 * clean up the source
 */
static void source_free(scamper_source_t *source)
{
  char buf[512];

  assert(source != NULL);
  assert(source->refcnt == 0);

  if(scamper_source_tostr(source, buf, sizeof(buf)) != NULL)
    scamper_debug(__func__, "%s", buf);

  /* the source is now finished.  post a message saying so */
  scamper_source_event_post(source, SCAMPER_SOURCE_EVENT_FINISH, NULL);

  if(source->cyclemon != NULL)
    {
      scamper_cyclemon_source_detach(source->cyclemon);
      scamper_cyclemon_unuse(source->cyclemon);
      source->cyclemon = NULL;
    }

  /* pull the source out of sources management */
  source_detach(source);

  /* empty the source of commands */
  if(source->commands != NULL)
    source_flush_commands(source);

  /* empty the source of tasks */
  if(source->tasks != NULL)
    source_flush_tasks(source);

  /* don't need the idtree any more */
  if(source->idtree != NULL)
    {
      assert(splaytree_count(source->idtree) == 0);
      splaytree_free(source->idtree, NULL);
    }

  /* release this structure's hold on the scamper_outfile */
  if(source->sof != NULL) scamper_outfile_free(source->sof);

  if(source->list != NULL) scamper_list_free(source->list);
  if(source->cycle != NULL) scamper_cycle_free(source->cycle);

  free(source);
  sources_assert();
  return;
}

/*
 * scamper_source_getname
 *
 * return the name of the source
 */
const char *scamper_source_getname(const scamper_source_t *source)
{
  if(source->list == NULL) return NULL;
  return source->list->name;
}

/*
 * scamper_source_getdescr
 *
 * return the description for the source
 */
const char *scamper_source_getdescr(const scamper_source_t *source)
{
  if(source->list == NULL) return NULL;
  return source->list->descr;
}

/*
 * scamper_source_getoutfile
 *
 * return the name of the outfile associated with the source
 */
const char *scamper_source_getoutfile(const scamper_source_t *source)
{
  return scamper_outfile_getname(source->sof);
}

/*
 * scamper_source_getlistid
 *
 * return the list id for the source
 */
uint32_t scamper_source_getlistid(const scamper_source_t *source)
{
  return source->list->id;
}

/*
 * scamper_source_getcycleid
 *
 * return the cycle id for the source
 */
uint32_t scamper_source_getcycleid(const scamper_source_t *source)
{
  return source->cycle->id;
}

/*
 * scamper_source_getpriority
 *
 * return the priority value for the source
 */
uint32_t scamper_source_getpriority(const scamper_source_t *source)
{
  return source->priority;
}

void scamper_source_setpriority(scamper_source_t *source, uint32_t priority)
{
  scamper_source_event_t sse;
  uint32_t old_priority;

  sources_assert();

  old_priority = source->priority;
  source->priority = priority;

  if(priority == 0 && old_priority > 0)
    source_blocked_attach(source);
  else if(priority > 0 && old_priority == 0)
    source_active_attach(source);

  memset(&sse, 0, sizeof(sse));
  sse.sse_update_flags |= 0x04;
  sse.sse_update_priority = priority;
  scamper_source_event_post(source, SCAMPER_SOURCE_EVENT_UPDATE, &sse);

  sources_assert();
  return;
}

const char *scamper_source_type_tostr(const scamper_source_t *source)
{
  switch(source->type)
    {
    case SCAMPER_SOURCE_TYPE_FILE:    return "file";
    case SCAMPER_SOURCE_TYPE_CMDLINE: return "cmdline";
    case SCAMPER_SOURCE_TYPE_CONTROL: return "control";
    case SCAMPER_SOURCE_TYPE_TSPS:    return "tsps";
    }

  return NULL;
}

char *scamper_source_tostr(const scamper_source_t *src, char *buf, size_t len)
{
  char tmp[512];
  size_t off = 0;

  if(src->list == NULL || src->list->name == NULL)
    return NULL;

  string_concat(buf, len, &off, "name %s", src->list->name);
  if(src->tostr != NULL && src->tostr(src->data, tmp, sizeof(tmp)) != NULL)
    string_concat(buf, len, &off, " %s", tmp);

  return buf;
}

/*
 * scamper_source_getcommandcount
 *
 * return the number of commands queued for the source
 */
int scamper_source_getcommandcount(const scamper_source_t *source)
{
  if(source->commands != NULL)
    return dlist_count(source->commands);
  return -1;
}

int scamper_source_getcyclecount(const scamper_source_t *source)
{
  return source->cycle_points;
}

int scamper_source_gettaskcount(const scamper_source_t *source)
{
  if(source->tasks != NULL)
    return dlist_count(source->tasks);
  return -1;
}

int scamper_source_gettype(const scamper_source_t *source)
{
  return source->type;
}

void *scamper_source_getdata(const scamper_source_t *source)
{
  return source->data;
}

static const command_func_t *command_func_get(const char *command)
{
  const command_func_t *func = NULL;
  size_t i;

  for(i=0; i<command_funcc; i++)
    {
      func = &command_funcs[i];
      if(strncasecmp(command, func->command, func->len) == 0 &&
	 isspace((int)command[func->len]) && command[func->len] != '\0')
	{
	  return func;
	}
    }

  return NULL;
}

/*
 * command_func_allocdata:
 *
 * make a copy of the options, since the next function may modify the
 * contents of it
 */
static void *command_func_allocdata(const command_func_t *f, const char *cmd)
{
  char *opts = NULL;
  void *data;
  if((opts = strdup(cmd + f->len)) == NULL)
    {
      printerror(__func__, "could not strdup cmd opts");
      return NULL;
    }
  data = f->allocdata(opts);
  free(opts);
  return data;
}

int scamper_source_halttask(scamper_source_t *source, uint32_t id)
{
  scamper_sourcetask_t *st, fm;
  command_t *cmd;
  dlist_node_t *no;

  sources_assert();

  fm.id = id;
  if(source->idtree == NULL)
    return -1;
  if((st = splaytree_find(source->idtree, &fm)) == NULL)
    return -1;

  scamper_task_halt(st->task);

  for(no=dlist_head_node(source->commands); no != NULL; no=dlist_node_next(no))
    {
      cmd = dlist_node_item(no);
      if(cmd->type == COMMAND_TASK && cmd->un.sourcetask == st)
	{
	  cmd = dlist_node_pop(source->commands, no);
	  command_free(cmd);
	  break;
	}
    }

  sources_assert();
  return 0;
}

/*
 * scamper_source_command2
 *
 * the given command is created as a task immediately and assigned an id
 * which allows the command to be halted.  used by the control socket code.
 */
int scamper_source_command2(scamper_source_t *s, const char *command,
			    uint32_t *id)
{
  const command_func_t *f = NULL;
  scamper_sourcetask_t *st = NULL;
  scamper_task_t *task = NULL;
  command_t *cmd = NULL;
  void *data = NULL;

  sources_assert();

  if(s->idtree == NULL &&
     (s->idtree = splaytree_alloc((splaytree_cmp_t)idtree_cmp)) == NULL)
    {
      printerror(__func__, "could not alloc idtree");
      goto err;
    }

  if((f = command_func_get(command)) == NULL)
    {
      scamper_debug(__func__, "could not determine command type");
      goto err;
    }
  if((data = command_func_allocdata(f, command)) == NULL)
    goto err;
  if((task = f->alloctask(data, s->list, s->cycle)) == NULL)
    goto err;
  data = NULL;

  /*
   * keep a record in the source that this task is now active
   * pass the cyclemon structure to the task
   */
  if((st = sourcetask_alloc(s, task)) == NULL)
    goto err;
  scamper_task_setsourcetask(task, st);
  scamper_task_setcyclemon(task, s->cyclemon);
  task = NULL;

  /* assign an id.  assume for now this will be enough to ensure uniqueness */
  st->id = *id = s->id;
  if(++s->id == 0) s->id = 1;
  if((st->idnode = splaytree_insert(s->idtree, st)) == NULL)
    {
      printerror(__func__, "could not add to idtree");
      goto err;
    }

  if((cmd = command_alloc(COMMAND_TASK)) == NULL)
    goto err;
  cmd->un.sourcetask = st;

  if(dlist_tail_push(s->commands, cmd) == NULL)
    {
      printerror(__func__, "could not add to commands list");
      goto err;
    }

  source_active_attach(s);
  sources_assert();
  return 0;

 err:
  /* XXX free scamper_sourcetask_t ?? */
  if(data != NULL) f->freedata(data);
  if(cmd != NULL) command_free(cmd);
  sources_assert();
  return -1;
}

/*
 * scamper_source_command
 *
 */
int scamper_source_command(scamper_source_t *source, const char *command)
{
  const command_func_t *func = NULL;
  command_t *cmd = NULL;
  char *opts = NULL;
  void *data = NULL;

  sources_assert();

  if((func = command_func_get(command)) == NULL)
    goto err;
  if((data = command_func_allocdata(func, command)) == NULL)
    goto err;

  if((cmd = command_alloc(COMMAND_PROBE)) == NULL)
    goto err;
  cmd->un.pr.funcs    = func;
  cmd->un.pr.data     = data;
  cmd->un.pr.cyclemon = scamper_cyclemon_use(source->cyclemon);

  if(dlist_tail_push(source->commands, cmd) == NULL)
    goto err;

  source_active_attach(source);
  sources_assert();
  return 0;

 err:
  if(opts != NULL) free(opts);
  if(data != NULL) func->freedata(data);
  if(cmd != NULL) free(cmd);
  sources_assert();
  return -1;
}

/*
 * scamper_source_cycle
 *
 * externally visible function to mark a new cycle point; the new cycle
 * id is one greater than the currently active cycle.
 */
int scamper_source_cycle(scamper_source_t *source)
{
  return source_cycle(source, source->cycle->id + 1);
}

scamper_source_t *scamper_sourcetask_getsource(scamper_sourcetask_t *st)
{
  return st->source;
}

/*
 * scamper_sourcetask_free
 *
 * when a task completes, this function is called.  it allows the source
 * to keep track of which tasks came from it.
 */
void scamper_sourcetask_free(scamper_sourcetask_t *st)
{
  scamper_source_t *source = st->source;

  sources_assert();

  if(st->node != NULL)
    dlist_node_pop(source->tasks, st->node);
  if(st->idnode != NULL)
    splaytree_remove_node(source->idtree, st->idnode);
  scamper_source_free(st->source);
  free(st);

  if(scamper_source_isfinished(source) != 0)
    {
      if(source->cyclemon != NULL)
	{
	  assert(scamper_cyclemon_refcnt(source->cyclemon) == 1);
	  scamper_cyclemon_unuse(source->cyclemon);
	  source->cyclemon = NULL;
	}
      source_detach(source);
    }

  sources_assert();
  return;
}

/*
 * scamper_source_use
 *
 */
scamper_source_t *scamper_source_use(scamper_source_t *source)
{
  sources_assert();
  source->refcnt++;
  return source;
}

/*
 * scamper_source_abandon
 *
 */
void scamper_source_abandon(scamper_source_t *source)
{
  sources_assert();
  source_flush_tasks(source);
  source_flush_commands(source);
  source_detach(source);
  sources_assert();
  return;
}

/*
 * scamper_source_free
 *
 * the caller is giving up their reference to the source.  make a note
 * of that.  when the reference count reaches zero and the source is
 * finished, free it.
 */
void scamper_source_free(scamper_source_t *source)
{
  sources_assert();

  /*
   * if there are still references held to the source, or the source is not
   * finished yet, then we don't have to go further.
   */
  if(source_refcnt_dec(source) != 0)
    return;

  source_free(source);
  sources_assert();
  return;
}

/*
 * scamper_source_alloc
 *
 * create a new source based on the parameters supplied.  the source is
 * not put into rotation -- the caller has to call scamper_sources_add
 * for that to occur.
 */
scamper_source_t *scamper_source_alloc(const scamper_source_params_t *ssp)
{
  scamper_source_t *source = NULL;

  /* make sure the caller passes some details of the source to be created */
  if(ssp == NULL || ssp->name == NULL)
    {
      scamper_debug(__func__, "missing necessary parameters");
      goto err;
    }

  if((source = malloc_zero(sizeof(scamper_source_t))) == NULL)
    {
      printerror(__func__, "could not malloc source");
      goto err;
    }
  source->refcnt = 1;

  /* data parameter and associated callbacks */
  source->data        = ssp->data;
  source->take        = ssp->take;
  source->freedata    = ssp->freedata;
  source->isfinished  = ssp->isfinished;
  source->tostr       = ssp->tostr;

  if((source->list = scamper_list_alloc(ssp->list_id, ssp->name, ssp->descr,
					scamper_monitorname_get())) == NULL)
    {
      printerror(__func__, "could not alloc source->list");
      goto err;
    }

  if((source->commands = dlist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc source->commands");
      goto err;
    }

  if((source->onhold = dlist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc source->onhold");
      goto err;
    }

  if((source->tasks = dlist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc source->tasks");
      goto err;
    }

  source->sof = scamper_outfile_use(ssp->sof);
  if(source_cycle(source, ssp->cycle_id) != 0)
    {
      goto err;
    }

  source->type     = ssp->type;
  source->priority = ssp->priority;
  source->id       = 1;

  return source;

 err:
  if(source != NULL)
    {
      if(source->list != NULL) scamper_list_free(source->list);
      if(source->cycle != NULL) scamper_cycle_free(source->cycle);
      if(source->commands != NULL) dlist_free(source->commands);
      if(source->onhold != NULL) dlist_free(source->onhold);
      if(source->tasks != NULL) dlist_free(source->tasks);
      free(source);
    }
  return NULL;
}

/*
 * scamper_sources_observe
 *
 * something wants to monitor the status of the sources managed by scamper.
 * make a note of that.
 */
scamper_source_observer_t *scamper_sources_observe(scamper_source_eventf_t cb,
						   void *param)
{
  scamper_source_observer_t *observer = NULL;

  if((observers == NULL && (observers = dlist_alloc()) == NULL) ||
     (observer = malloc_zero(sizeof(scamper_source_observer_t))) == NULL ||
     (observer->node = dlist_tail_push(observers, observer)) == NULL)
    {
      goto err;
    }

  observer->func  = cb;
  observer->param = param;

  return observer;

 err:
  if(observer != NULL) scamper_sources_unobserve(observer);
  return NULL;
}

/*
 * scamper_sources_unobserve
 *
 */
void scamper_sources_unobserve(scamper_source_observer_t *observer)
{
  dlist_node_pop(observers, observer->node);
  free(observer);

  if(dlist_count(observers) == 0)
    {
      dlist_free(observers);
      observers = NULL;
    }

  return;
}

/*
 * scamper_sources_get
 *
 * given a name, return the matching source -- if one exists.
 */
scamper_source_t *scamper_sources_get(char *name)
{
  scamper_source_t findme;
  scamper_list_t   list;

  list.name   = name;
  findme.list = &list;

  return (scamper_source_t *)splaytree_find(source_tree, &findme);
}

/*
 * scamper_sources_del
 *
 * given a source, remove it entirely.  to do so, existing tasks must be
 * halted, the source must be flushed of on-hold tasks and commands,
 * and it must be removed from the data structures that link the source
 * to the main scamper loop.
 */
int scamper_sources_del(scamper_source_t *source)
{
  sources_assert();

  source_flush_tasks(source);
  source_flush_commands(source);
  source_detach(source);

  /* if there are external references to the source, then don't free it */
  if(source->refcnt > 1)
    {
      return -1;
    }

  scamper_source_event_post(source, SCAMPER_SOURCE_EVENT_DELETE, NULL);
  source_free(source);

  sources_assert();
  return 0;
}

/*
 * scamper_sources_isempty
 *
 * return to the caller if it is likely that the sources have more tasks
 * to return
 */
int scamper_sources_isempty()
{
  sources_assert();

  /*
   * if there are either active or blocked address list sources, the list
   * can't be empty
   */
  if((active   != NULL && clist_count(active)   > 0) ||
     (blocked  != NULL && dlist_count(blocked)  > 0) ||
     (finished != NULL && dlist_count(finished) > 0))
    {
      return 0;
    }

  return 1;
}

/*
 * scamper_sources_isready
 *
 * return to the caller if a source is ready to return a new task.
 */
int scamper_sources_isready(void)
{
  sources_assert();

  if(source_cur != NULL || dlist_count(finished) > 0)
    {
      return 1;
    }

  return 0;
}

/*
 * scamper_sources_empty
 *
 * flush all sources of commands; disconnect all sources.
 */
void scamper_sources_empty()
{
  scamper_source_t *source;

  sources_assert();

  /*
   * for each source, go through and empty the lists, close the files, and
   * leave the list of sources available to read from empty.
   */
  while((source = dlist_tail_item(blocked)) != NULL)
    {
      source_flush_commands(source);
      source_detach(source);
    }

  while((source = clist_tail_item(active)) != NULL)
    {
      source_flush_commands(source);
      source_detach(source);
    }

  while((source = dlist_head_item(finished)) != NULL)
    {
      source_detach(source);
    }

  sources_assert();
  return;
}

/*
 * scamper_sources_foreach
 *
 * externally accessible function for iterating over the collection of sources
 * held by scamper.
 */
void scamper_sources_foreach(void *p, int (*func)(void *, scamper_source_t *))
{
  splaytree_inorder(source_tree, (splaytree_inorder_t)func, p);
  return;
}

/*
 * scamper_sources_gettask
 *
 * pick off the next task ready to be probed.
 */
int scamper_sources_gettask(scamper_task_t **task)
{
  scamper_source_t *source;
  command_t *command;

  sources_assert();

  while((source = dlist_head_item(finished)) != NULL)
    source_detach(source);

  /*
   * if the priority of the source was changed in between calls to this
   * function, then make sure the source's priority hasn't been lowered to
   * below how many tasks it has had allocated in this cycle
   */
  if(source_cur != NULL && source_cnt >= source_cur->priority)
    source_next();

  while((source = source_cur) != NULL)
    {
      assert(source->priority > 0);

      while((command = dlist_head_pop(source->commands)) != NULL)
	{
	  if(source->take != NULL)
	    source->take(source->data);

	  switch(command->type)
	    {
	    case COMMAND_PROBE:
	      if(command_probe_handle(source, command, task) != 0)
		goto err;
	      if(*task == NULL)
		continue;
	      source_cnt++;
	      goto done;

	    case COMMAND_TASK:
	      if(command_task_handle(source, command, task) != 0)
		goto err;
	      if(*task == NULL)
		continue;
	      source_cnt++;
	      goto done;

	    case COMMAND_CYCLE:
	      command_cycle_handle(source, command);
	      break;

	    default:
	      goto err;
	    }
	}

      /* the previous source could not supply a command */
      assert(dlist_count(source->commands) == 0);

      /*
       * if the source is not yet finished, put it on the blocked list;
       * otherwise, the source is detached.
       */
      if(scamper_source_isfinished(source) == 0)
	source_blocked_attach(source);
      else
	source_detach(source);
    }

  *task = NULL;

 done:
  sources_assert();
  return 0;

 err:
  sources_assert();
  return -1;
}

/*
 * scamper_sources_add
 *
 * add a new source into rotation; put it into the active list for now.
 */
int scamper_sources_add(scamper_source_t *source)
{
  char buf[512];

  assert(source != NULL);
  sources_assert();

  if(scamper_source_tostr(source, buf, sizeof(buf)) != NULL)
    scamper_debug(__func__, "%s", buf);

  /* a reference count is used when the source is in the tree */
  if((source->tree_node = splaytree_insert(source_tree, source)) == NULL)
    goto err;
  scamper_source_use(source);

  /* put the source in the active queue */
  if(source_active_attach(source) != 0)
    goto err;

  scamper_source_event_post(source, SCAMPER_SOURCE_EVENT_ADD, NULL);
  sources_assert();
  return 0;

 err:
  sources_assert();
  return -1;
}

/*
 * scamper_sources_init
 *
 *
 */
int scamper_sources_init(void)
{
  if((active = clist_alloc()) == NULL)
    return -1;

  if((blocked = dlist_alloc()) == NULL)
    return -1;

  if((finished = dlist_alloc()) == NULL)
    return -1;

  if((source_tree = splaytree_alloc((splaytree_cmp_t)source_cmp)) == NULL)
    return -1;

  return 0;
}

/*
 * scamper_sources_cleanup
 *
 *
 */
void scamper_sources_cleanup(void)
{
  int f, b, a;

  f = finished != NULL ? dlist_count(finished) : 0;
  b = blocked  != NULL ? dlist_count(blocked)  : 0;
  a = active   != NULL ? clist_count(active)   : 0;

  if(f != 0 || b != 0 || a != 0)
    scamper_debug(__func__, "finished %d, blocked %d, active %d", f, b, a);

  if(source_tree != NULL)
    {
      splaytree_free(source_tree, NULL);
      source_tree = NULL;
    }

  if(blocked != NULL)
    {
      dlist_free(blocked);
      blocked = NULL;
    }

  if(active != NULL)
    {
      clist_free(active);
      active = NULL;
    }

  if(finished != NULL)
    {
      dlist_free(finished);
      finished = NULL;
    }

  return;
}
