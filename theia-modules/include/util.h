#ifndef __UTIL_H__
#define __UTIL_H__

#include <linux/version.h>
#include <linux/delay.h>
#include <linux/net.h>
#include <net/sock.h>

#include <replay_configs.h>
#include <core_pidmap.h>
#include <serialize.h>
#include <theia_core.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0))
#ifdef THEIA_MODIFIED_KERNEL_SOURCES
extern struct socket *sock_from_file(struct file *file, int *err);
#else
typedef struct socket *(*sock_from_file_ptr)(struct file*, int*);
extern sock_from_file_ptr sock_from_file;
#endif
#endif

//the kernel does not export signal_wake_up*()
typedef void (*ptr_signal_wake_up_state)(struct task_struct*, unsigned int);
extern ptr_signal_wake_up_state real_signal_wake_up_state;
static inline void real_signal_wake_up(struct task_struct *t, bool resume)
{
    real_signal_wake_up_state(t, resume ? TASK_WAKEKILL : 0);
}

static inline int test_app_syscall(int number)
{
  struct replay_thread *prt = get_replay_thread();;
  if (prt->app_syscall_addr == 0)
    return 1; // NULL value
  if (prt->app_syscall_addr == 1)
    return 0; // PIN not yet attached
  return (*(int *)(prt->app_syscall_addr) == number);
}

struct record_cache_files* init_record_cache_files(void);
void get_record_cache_files(struct record_cache_files *pfiles);
void put_record_cache_files(struct record_cache_files *pfiles);
int is_record_cache_file_lock(struct record_cache_files *pfiles, int fd);
int is_record_cache_file(struct record_cache_files *pfiles, int fd);
void record_cache_file_unlock(struct record_cache_files *pfiles, int fd);
int set_record_cache_file(struct record_cache_files *pfiles, int fd);
void copy_record_cache_files(struct record_cache_files *pfrom, struct record_cache_files *pto);
void clear_record_cache_file(struct record_cache_files *pfiles, int fd);
void close_record_cache_files(struct record_cache_files *pfiles);
struct replay_cache_files* init_replay_cache_files(void);
void get_replay_cache_files(struct replay_cache_files *pfiles);
void put_replay_cache_files(struct replay_cache_files *pfiles);
int is_replay_cache_file(struct replay_cache_files *pfiles, int fd, int *cache_fd);
int set_replay_cache_file(struct replay_cache_files *pfiles, int fd, int cache_fd);
void copy_replay_cache_files(struct replay_cache_files *pfrom, struct replay_cache_files *pto);
void clear_replay_cache_file(struct replay_cache_files *pfiles, int fd);
void close_replay_cache_files(struct replay_cache_files *pfiles);

#define IS_RECORDED_FILE (1<<3)
#define READ_NEW_CACHE_FILE (1<<4)
long file_cache_check_version(int, struct file*, struct filemap_data*, struct open_retvals*);
long file_cache_update_replay_file(int rc, struct open_retvals *retvals);
/////* I don't think I actually need to do anything with this */
#define file_cache_opened(...)
//long file_cache_opened(struct file *file, int mode);
long file_cache_file_written(struct filemap_data *data, int fd);

#ifdef TRACE_PIPE_READ_WRITE
#define READ_PIPE_WITH_DATA (1<<2)
#define READ_IS_PIPE (1<<1)
#define is_pipe(filp) (S_ISFIFO(file_inode(filp)->i_mode))
extern atomic_t glbl_pipe_id;
extern struct mutex pipe_tree_mutex;
extern struct btree_head64 pipe_tree;
void replay_free_pipe(void *pipe);
struct pipe_track
{
  struct mutex lock;
  int id;
  u64 owner_read_id;
  u64 owner_write_id;

  loff_t owner_read_pos;
  loff_t owner_write_pos;

  int shared;

  struct replayfs_btree128_key key;
};
#endif

//takes struct file*
#define is_socket(filp) (S_ISSOCK(file_inode(filp)->i_mode))
//takes struct socket*
#define is_socket_stateful(s) (s->sk->sk_type == SOCK_STREAM || s->sk->sk_type == SOCK_SEQPACKET)

#ifdef TRACE_SOCKET_READ_WRITE
extern void replay_sock_put(struct sock *sk);
extern int track_usually_pt2pt_read(void *key, int size, struct file *filp);
extern int track_usually_pt2pt_write_begin(void *key, struct file *filp);
extern int track_usually_pt2pt_write(void *key, int size, struct file *filp, int do_shared);
extern void consume_socket_args_read(void *retparams);
extern void consume_socket_args_write(void *retparams);
#else
#define replay_sock_put(...)
#endif

extern unsigned int syslog_recs;

#define rg_lock(prg) mutex_lock(&(prg)->rg_mutex);
#define rg_unlock(prg) mutex_unlock(&(prg)->rg_mutex);

#define KFREE kfree
#define KMALLOC kzalloc
#define VMALLOC vmalloc
#define VFREE vfree
#define argsalloc_size (512 * 1024)
#define ARGSKMALLOC(size, flags...) argsalloc(size)
#define ARGSKFREE(ptr, size...) argsfree(ptr, size)
void *argsalloc(size_t);
void argsfree(const void*, size_t);
void argsfreeall(struct record_thread*);
char *argshead(struct record_thread*);
void argsconsume(struct record_thread*, u_long);
struct argsalloc_node *new_argsalloc_node(void*, size_t);
int add_argsalloc_node(struct record_thread*, void*, size_t);

#define SIGNAL_WHILE_SYSCALL_IGNORED 405
#define REPLAY_STATUS_RUNNING         0 // I am the running thread - should only be one of these per group
#define REPLAY_STATUS_ELIGIBLE        1 // I could run now
#define REPLAY_STATUS_WAIT_CLOCK      2 // Cannot run because waiting for an event
#define REPLAY_STATUS_DONE            3 // Exiting
// how long we wait on the wait_queue before timing out
#define SCHED_TO 1000000
#define REPLAY_PIN_TRAP_STATUS_NONE 0  // Not handling any sort of extra Pin SIGTRIP
#define REPLAY_PIN_TRAP_STATUS_EXIT 1  // I was waiting for a syscall exit, but was interrupted by a Pin SIGTRAP
#define REPLAY_PIN_TRAP_STATUS_ENTER  2  // I was waiting for a syscall enter, but was interrupted by a Pin SIGTRAP

static inline void __syscall_mismatch(struct record_group *precg)
{
  precg->rg_mismatch_flag = 1;
  rg_unlock(precg);
  TPRINT("SYSCALL MISMATCH\n");
#ifdef REPLAY_STATS
  atomic_inc(&rstats.mismatched);
#endif
  real_sys_exit_group(0);
}

static inline long syscall_mismatch(void)
{
  struct record_group *prg = get_replay_thread()->rp_group->rg_rec_group;
  rg_lock(prg);
  __syscall_mismatch(prg);
  BUG();
  return 0; // Should never actually return
}

static inline int is_pin_attached(void)
{
    return get_replay_thread()->app_syscall_addr != 0;
}

static inline void print_replay_threads(void)
{
  struct replay_thread *tmp;
  struct replay_thread *cur_thr = get_replay_thread();
  // See if we can find another eligible thread
  tmp = cur_thr->rp_next_thread;

  MPRINT("Pid %d current thread is %d (recpid %d) status %d clock %ld - clock is %ld\n",
         current->pid, cur_thr->rp_replay_pid, cur_thr->rp_record_thread->rp_record_pid,
         cur_thr->rp_status, cur_thr->rp_wait_clock, *(cur_thr->rp_preplay_clock));
  while (tmp != cur_thr)
  {
    MPRINT("\tthread %d (recpid %d) status %d clock %ld - clock is %ld\n",
            tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status,
            tmp->rp_wait_clock, *(cur_thr->rp_preplay_clock));
    tmp = tmp->rp_next_thread;
  }
}


static inline long new_syscall_enter(long sysnum)
{
  struct syscall_result *psr;
  u_long new_clock, start_clock;
  u_long *p;
  struct record_thread *prt = get_record_thread();

  if (unlikely(prt->rp_in_ptr == syslog_recs))
  {
    /* Filled up log - write it out.  May be better to do this asynchronously */
    // mcc: Are there complications with doing this asynchronously?
    // I can think of a corner case with scheduling this asynchronously,
    // since two asychrnonously scheduled tasks are not guaranteed ordering,
    // we could potentially write out the log in the wrong order.
    // An even worse case of writing out asynchronously is that we only have
    // one syscall_result array in record_thread, so the next system call might
    // overwrite this log before the writout occurs
    write_and_free_kernel_log(prt);
    prt->rp_in_ptr = 0;
  }
  TPRINT("[%s] prt->rp_in_ptr %lu, %p, sysnum %ld\n", __func__,
          prt->rp_in_ptr, &prt->rp_log[prt->rp_in_ptr], sysnum);
  psr = &prt->rp_log[prt->rp_in_ptr];
  psr->sysnum = sysnum;
  new_clock = atomic_add_return(1, prt->rp_precord_clock);
  start_clock = new_clock - prt->rp_expected_clock - 1;
  if (start_clock == 0)
  {
    psr->flags = 0;
  }
  else
  {
    psr->flags = SR_HAS_START_CLOCK_SKIP;
    p = ARGSKMALLOC(sizeof(u_long), GFP_KERNEL);
    if (unlikely(p == NULL)) return -ENOMEM;
    *p = start_clock;
  }
  prt->rp_expected_clock = new_clock;

  return 0;
}

#define new_syscall_done(sysnum, retval) cnew_syscall_done(sysnum, retval, -1, -1)
static inline long cnew_syscall_done(long sysnum, long retval, long prediction, int shift_clock)
{
  struct syscall_result *psr;
  u_long new_clock, stop_clock;
  u_long *ulp;
  long *p;
  struct record_thread *prt = get_record_thread();

  psr = &prt->rp_log[prt->rp_in_ptr];

  if (retval)
  {
    psr->flags |= SR_HAS_NONZERO_RETVAL;
    p = ARGSKMALLOC(sizeof(long), GFP_KERNEL);
    if (unlikely(p == NULL)) return -ENOMEM;
    if (sysnum == 0)
      TPRINT("rec_uuid retval %ld\n", retval);
    *p = retval;
  }

  new_clock = atomic_add_return(1, prt->rp_precord_clock);
  stop_clock = new_clock - prt->rp_expected_clock - 1;
  if (stop_clock)
  {
    psr->flags |= SR_HAS_STOP_CLOCK_SKIP;
    ulp = ARGSKMALLOC(sizeof(u_long), GFP_KERNEL);
    if (unlikely(ulp == NULL)) return -ENOMEM;
    if (sysnum == 0)
      TPRINT("rec_uuid ulp %lu\n", stop_clock);
    *ulp = stop_clock;
  }
  prt->rp_expected_clock = new_clock;

  return 0;
}

#define get_next_syscall_enter(args...) cget_next_syscall_enter(args, 0, NULL)
static inline long cget_next_syscall_enter(struct replay_thread *prt, struct replay_group *prg,
        int syscall, char **ppretparams, struct syscall_result **ppsr, long prediction, u_long *ret_start_clock)
{
  struct syscall_result *psr;
  struct replay_thread *tmp;
  struct record_thread *prect = prt->rp_record_thread;
  u_long start_clock;
  u_long *pclock;
  long retval = 0;
  int ret;
#ifndef USE_SYSNUM
  loff_t peekpos;
  int rc = 0;
  int size = 0;
  loff_t *pos;
#endif

  rg_lock(prg->rg_rec_group);

  if (syscall == TID_WAKE_CALL && prg->rg_rec_group->rg_mismatch_flag)
  {
    // We are just trying to exit after a replay foul-up - just die
    MPRINT("Pid %d We are just trying to exit after a replay foul-up - just die\n", current->pid);
    *ppsr = NULL; // Lets caller know to skip the exit call.
    rg_unlock(prg->rg_rec_group);
    return 0;
  }

  while (prect->rp_in_ptr == prt->rp_out_ptr)
  {
    if (syscall == TID_WAKE_CALL)
    {
      // We did not record an exit so there is no record to consume - just ignore this and let the thread exit
      MPRINT("pid %d recpid %d syscall mismatch during exit is OK - no more syscalls found\n", current->pid, prect->rp_record_pid);
      *ppsr = NULL; // Lets caller know to skip the exit call.
      rg_unlock(prg->rg_rec_group);
      return 0;
    }
    // log overflowed and we need to read in next batch of records
    MPRINT("Pid %d recpid %d syscall %d reached end of in-memory log -- free previous syscall records and rad in new ones\n", current->pid, prect->rp_record_pid, syscall);
    argsfreeall(prect);
    prect->rp_in_ptr = 0;
    read_log_data(prect);
    if (prect->rp_in_ptr == 0)
    {
      // There should be one record there at least
      TPRINT("Pid %d waiting for non-existant syscall record %d - recording not synced yet??? \n", current->pid, syscall);
      __syscall_mismatch(prg->rg_rec_group);
    }
    prt->rp_out_ptr = 0;
  }

  psr = &prect->rp_log[prt->rp_out_ptr];

  start_clock = prt->rp_expected_clock;
  if (psr->flags & SR_HAS_START_CLOCK_SKIP)
  {
    pclock = (u_long *) argshead(prect);
    argsconsume(prect, sizeof(u_long));
    start_clock += *pclock;
    if (start_clock > 100000000) TPRINT("start_clock %ld, pclock %ld, prt->rp_expected_clock %ld\n", start_clock, *pclock, prt->rp_expected_clock);
  }
  prt->rp_expected_clock = start_clock + 1;
  // Pin can interrupt, so we need to save the start clock in case we need to resume
  prt->rp_start_clock_save = start_clock;


  if (unlikely(psr->sysnum != syscall))
  {
    if (psr->sysnum == SIGNAL_WHILE_SYSCALL_IGNORED && prect->rp_in_ptr == prt->rp_out_ptr + 1)
    {
      TPRINT("last record is apparently for a terminal signal - we'll just proceed anyway\n");
    }
    else
    {
      TPRINT("[ERROR]Pid  %d record pid %d expected syscall %d in log, got %d, start clock %ld\n",
             current->pid, prect->rp_record_pid, syscall, psr->sysnum, start_clock);
      dump_stack();
      __syscall_mismatch(prg->rg_rec_group);
    }
  }

  if ((psr->flags & SR_HAS_NONZERO_RETVAL) == 0)
  {
    retval = 0;
  }
  else
  {
    retval = *((long *) argshead(prect));
    TPRINT("argsconsume called at %d, size: %lu\n", __LINE__, sizeof(long));
    argsconsume(prect, sizeof(long));
  }

  // Pin can interrupt, so we need to save the stop clock in case we need to resume
  prt->rp_stop_clock_save = prt->rp_expected_clock;
  if (psr->flags & SR_HAS_STOP_CLOCK_SKIP)   // Nead to read this in exactly this order but use it later
  {
    prt->rp_stop_clock_skip = *((u_long *) argshead(prect));
    MPRINT("Stop clock skip is %lu\n", prt->rp_stop_clock_skip);
    argsconsume(prect, sizeof(u_long));
    prt->rp_stop_clock_save += prt->rp_stop_clock_skip;
  }

  if (ppretparams)
  {
    if (psr->flags & SR_HAS_RETPARAMS)
    {
      *ppretparams = argshead(prect);
    }
    else
    {
      *ppretparams = NULL;
    }
  }
  else if (unlikely((psr->flags & SR_HAS_RETPARAMS) != 0))
  {
    TPRINT("[ERROR]Pid %d record pid %d not expecting return parameters, syscall %d start clock %ld\n",
           current->pid, prect->rp_record_pid, syscall, start_clock);
    __syscall_mismatch(prg->rg_rec_group);
  }

  // Done with syscall record
  prt->rp_out_ptr += 1;

  // Do this twice - once for syscall entry and once for exit
  while (*(prt->rp_preplay_clock) < start_clock)
  {
    MPRINT("Replay pid %d is waiting for clock value %ld on syscall entry but current clock value is %ld\n", current->pid, start_clock, *(prt->rp_preplay_clock));
    prt->rp_status = REPLAY_STATUS_WAIT_CLOCK;
    prt->rp_wait_clock = start_clock;
    tmp = prt->rp_next_thread;
    do
    {
      DPRINT("[syscall enter]Consider thread %d (%d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
      if (tmp->rp_status == REPLAY_STATUS_ELIGIBLE || (tmp->rp_status == REPLAY_STATUS_WAIT_CLOCK && tmp->rp_wait_clock <= *(prt->rp_preplay_clock)))
      {
        tmp->rp_status = REPLAY_STATUS_RUNNING;
        wake_up(&tmp->rp_waitq);
        DPRINT("Wake it up\n");
        break;
      }
      tmp = tmp->rp_next_thread;
      if (tmp == prt)
      {
        TPRINT("Pid %d (recpid %d): Crud! no eligible thread to run on syscall entry\n", current->pid, prect->rp_record_pid);
        TPRINT("current clock value is %ld waiting for %lu\n", *(prt->rp_preplay_clock), start_clock);
        dump_stack(); // how did we get here?
        // cycle around again and print
        tmp = tmp->rp_next_thread;
        while (tmp != current->replay_thrd)
        {
          TPRINT("\t thread %d (recpid %d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
          tmp = tmp->rp_next_thread;
        }
        __syscall_mismatch(prg->rg_rec_group);
      }
    }
    while (tmp != prt);

    while (!(prt->rp_status == REPLAY_STATUS_RUNNING || (prt->rp_replay_exit && prect->rp_in_ptr == prt->rp_out_ptr + 1)))
    {
      MPRINT("Replay pid %d starts to wait for clock value %ld on syscall entry but current clock value is %ld\n", current->pid, start_clock, *(prt->rp_preplay_clock));
      rg_unlock(prg->rg_rec_group);
      ret = wait_event_interruptible_timeout(prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING || prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && prect->rp_in_ptr == prt->rp_out_ptr + 1), SCHED_TO);
      TPRINT("Replay pid %d (%d) woken up from syscall entry, start clock value %ld, current clock %ld\n", current->pid, prt->rp_record_thread->rp_record_pid, start_clock, *(prt->rp_preplay_clock));
      rg_lock(prg->rg_rec_group);
      if (ret == 0) TPRINT("Replay pid %d timed out waiting for clock value %ld on syscall entry but current clock value is %ld\n", current->pid, start_clock, *(prt->rp_preplay_clock));
      if (prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && (prect->rp_in_ptr == prt->rp_out_ptr + 1)))
      {
        MPRINT("Replay pid %d woken up to die on entrance in_ptr %lu out_ptr %lu\n", current->pid, prect->rp_in_ptr, prt->rp_out_ptr);
        rg_unlock(prg->rg_rec_group);
        real_sys_exit(0);
      }
      if (ret == -ERESTARTSYS)
      {
        /*
         * We need to make sure we exit threads in the right order if Pin is attached.
         * If Pin is attached, interupt the system call and return back to Pin.
         * Pin will proceed and handle the SIGTRAP.
         * Pin will then trap back into the kernel, where we then increment the clock
         * and end the syscall.
         *
         * Certain system calls, we need to be more lax with though and
         * simply wait for Pin to finish, such as exec and clone.
         */
        //Yang
        if (is_pin_attached() && (syscall != 59 && syscall != 56))
        {
          MPRINT("Pid %d -- Pin attached -- enterting syscall cannot wait due to signal, would try again but Pin is attaached. exiting with ERESTART\n", current->pid);
          prt->rp_saved_psr = psr;
          prt->rp_pin_restart_syscall = REPLAY_PIN_TRAP_STATUS_ENTER;
          rg_unlock(prg->rg_rec_group);
          return -ERESTART_RESTARTBLOCK;
        }

        TPRINT("Pid %d: entering syscall cannot wait due to signal - try again\n", current->pid);
        rg_unlock(prg->rg_rec_group);
        msleep(1000);
        rg_lock(prg->rg_rec_group);
      }
    }
  }
  (*prt->rp_preplay_clock)++;
  rg_unlock(prg->rg_rec_group);
  MPRINT("[Replay enter]Pid %d (%d) clock on syscall %d gets to %ld\n", current->pid, prt->rp_record_thread->rp_record_pid, psr->sysnum, *(prt->rp_preplay_clock));
  *ppsr = psr;
  return retval;
}

static inline long get_next_syscall_exit(struct replay_thread *prt, struct replay_group *prg, struct syscall_result *psr)
{
  struct record_thread *prect = prt->rp_record_thread;
  struct replay_thread *tmp;
  int ret;
  u_long stop_clock;

  BUG_ON(!psr);

  stop_clock = prt->rp_expected_clock;
  if (psr->flags & SR_HAS_STOP_CLOCK_SKIP) stop_clock += prt->rp_stop_clock_skip;
  prt->rp_expected_clock = stop_clock + 1;

  rg_lock(prg->rg_rec_group);
  while (*(prt->rp_preplay_clock) < stop_clock)
  {
    MPRINT("Replay pid %d is waiting for clock value %ld on syscall exit but current clock value is %ld\n", current->pid, stop_clock, *(prt->rp_preplay_clock));
    prt->rp_status = REPLAY_STATUS_WAIT_CLOCK;
    prt->rp_wait_clock = stop_clock;
    tmp = prt->rp_next_thread;
    do
    {
      DPRINT("[syscall exit]Consider thread %d (%d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
      if (tmp->rp_status == REPLAY_STATUS_ELIGIBLE || (tmp->rp_status == REPLAY_STATUS_WAIT_CLOCK && tmp->rp_wait_clock <= *(prt->rp_preplay_clock)))
      {
        tmp->rp_status = REPLAY_STATUS_RUNNING;
        wake_up(&tmp->rp_waitq);
        DPRINT("Wake it up %d (%d)\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid);
        break;
      }
      tmp = tmp->rp_next_thread;
      if (tmp == prt)
      {
        TPRINT("Pid %d: Crud! no eligible thread to run on syscall exit\n", current->pid);
        TPRINT("replay pid %d waiting for clock value on syscall exit - current clock value is %ld\n", current->pid, *(prt->rp_preplay_clock));
        if (prt->rp_pin_restart_syscall)
        {
          TPRINT("Pid %d: This was a restarted syscall exit, let's sleep and try again\n", current->pid);
          msleep(1000);
          break;
        }
        TPRINT("replay pid %d waiting for clock value %ld on syscall exit - current clock value is %ld\n", current->pid, stop_clock, *(prt->rp_preplay_clock));
        real_sys_exit_group(0);
      }
    }
    while (tmp != prt);

    while (!(prt->rp_status == REPLAY_STATUS_RUNNING || (prt->rp_replay_exit && prect->rp_in_ptr == prt->rp_out_ptr + 1)))
    {
      MPRINT("Replay pid %d starts waiting for clock value %ld on syscall exit but current clock value is %ld\n", current->pid, stop_clock, *(prt->rp_preplay_clock));
      rg_unlock(prg->rg_rec_group);
      ret = wait_event_interruptible_timeout(prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING || prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && prect->rp_in_ptr == prt->rp_out_ptr + 1), SCHED_TO);
			TPRINT("Replay pid %d (%d) woken up from syscall exit, stop clock value %ld, current clock %ld\n", current->pid, prt->rp_record_thread->rp_record_pid, stop_clock, *(prt->rp_preplay_clock));
      rg_lock(prg->rg_rec_group);
      if (ret == 0) TPRINT("Replay pid %d timed out waiting for clock value %ld on syscall exit but current clock value is %ld\n", current->pid, stop_clock, *(prt->rp_preplay_clock));
      if (prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && (prect->rp_in_ptr == prt->rp_out_ptr + 1)))
      {
        rg_unlock(prg->rg_rec_group);
        MPRINT("Replay pid %d woken up to die on exit\n", current->pid);
        real_sys_exit(0);
      }
      if (ret == -ERESTARTSYS)
      {
        /* Pin SIGTRAP interrupted a syscall exit, SIGTRAP is also used by
         *  Pin to reattach after exec, so we need to ignore exec and just wait */
        //Yang
        if (is_pin_attached() && (psr->sysnum != 59 || psr->sysnum != 56))
        {
          MPRINT("Pid %d: exiting syscall cannot wait due to signal - try again, but pin is attached, exiting with ERESTART\n", current->pid);
          prt->rp_saved_psr = psr;
          if (prt->rp_pin_restart_syscall != REPLAY_PIN_TRAP_STATUS_ENTER)
          {
            prt->rp_pin_restart_syscall = REPLAY_PIN_TRAP_STATUS_EXIT;
          }
          rg_unlock(prg->rg_rec_group);
          return -ERESTART_RESTARTBLOCK;
        }

        TPRINT("Pid %d: exiting syscall cannot wait due to signal w/clock %lu - try again\n", current->pid, *(prt->rp_preplay_clock));
        //print_replay_threads();
        rg_unlock(prg->rg_rec_group);
        msleep(1000);
        rg_lock(prg->rg_rec_group);
      }
    }
  }

  if (unlikely((psr->flags & SR_HAS_SIGNAL) != 0))
  {
    MPRINT("Pid %d set deliver signal flag before clock %ld increment\n", current->pid, *(prt->rp_preplay_clock));
    prt->rp_signals = 1;
    real_signal_wake_up(current, 0);
  }

  (*prt->rp_preplay_clock)++;
  MPRINT("[Replay exit] Pid %d (%d) clock on syscall %d gets to %ld\n", current->pid, prt->rp_record_thread->rp_record_pid, psr->sysnum, *(prt->rp_preplay_clock));
  prect->rp_count += 1;

  rg_unlock(prg->rg_rec_group);
  return 0;
}

#define get_next_syscall(args...) cget_next_syscall(args, NULL, 0, NULL)
static inline long cget_next_syscall(int syscall, char **ppretparams, u_char *flag, long prediction, u_long *start_clock)
{
  struct replay_thread *prt = get_replay_thread();
  struct replay_group *prg = prt->rp_group;
  struct syscall_result *psr = NULL;
  long retval;
  long exit_retval;

  retval = cget_next_syscall_enter(prt, prg, syscall, ppretparams, &psr, prediction, start_clock);

  // Needed to exit the threads in the correct order with Pin attached.
  // Essentially, return to Pin after Pin interrupts the syscall with a SIGTRAP.
  // The thread will then begin to exit. recplay_exit_start will exit the threads
  // in the correct order
  if (is_pin_attached() && prt->rp_pin_restart_syscall == REPLAY_PIN_TRAP_STATUS_ENTER)
  {
    prt->rp_saved_rc = retval;
    return retval;
  }

  exit_retval = get_next_syscall_exit(prt, prg, psr);

  // Reset Pin syscall address value to 0 at the end of the system call
  // This is required to differentiate between syscalls when
  // Pin issues the same syscall immediately after the app
  if (is_pin_attached())
  {
    if ((*(int *)(prt->app_syscall_addr)) != 999)
    {
      (*(int *)(prt->app_syscall_addr)) = 997; //Yang: in syscall_64.tbl, 0 is read.. we use 997 instead
      TPRINT("[%s|%d] pid %d, prt->app_syscall_addr is set to 997\n", __func__, __LINE__, current->pid);
    }
  }

  // Need to return restart back to Pin so it knows to continue
  if ((exit_retval == -ERESTART_RESTARTBLOCK) && is_pin_attached())
  {
    prt->rp_saved_rc = retval;
    return exit_retval;
  }
  if (flag) *flag = psr->flags;

  return retval;
}

#define new_syscall_exit(sysnum, retparam) __new_syscall_exit(sysnum, retparam, NULL)
static inline long __new_syscall_exit(long sysnum, void *retparams, void *ahgparams)
{
  struct syscall_result *psr;
  struct record_thread *prt = get_record_thread();

  psr = &prt->rp_log[prt->rp_in_ptr];
  psr->flags = retparams ? (psr->flags | SR_HAS_RETPARAMS) : psr->flags;
  if (unlikely(prt->rp_signals)) real_signal_wake_up(current, 0);  //we want to deliver signals when this syscall exits

  prt->rp_in_ptr += 1;
  prt->rp_count += 1;
  return 0;
}

static inline void change_log_special(void)
{
  struct syscall_result *psr;
  struct record_thread *prt = get_record_thread();
  psr = &prt->rp_log[prt->rp_in_ptr];
  psr->flags |= SR_HAS_SPECIAL_FIRST;
}

//syscall-specific helpers
void theia_read_ahg(unsigned int fd, long rc);

#endif
