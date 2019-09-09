#ifndef __REPLAY_H__
#define __REPLAY_H__

//#define TIME_TRICK
#ifdef TIME_TRICK
#include "det_time.h"
#endif

#define MAX_LOGDIR_STRLEN 256
#define MAX_LIBPATH_STRLEN PAGE_SIZE
#define MAX_WHITELIST_STRLEN 512
#define MAX_DIRENT_STRLEN 256

#include <linux/signal.h>
#include <linux/mm_types.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>

#define REPLAYFS_BASE_PATH "/data"
#define REPLAYFS_LOGDB_SUFFIX "/replay_logdb"
#define REPLAYFS_CACHE_SUFFIX "/replay_cache"
#define REPLAYFS_INDEX_SUFFIX "/ndx"
#define REPLAYFS_FILELIST_SUFFIX "/file_list"

#define REPLAYFS_FILELIST_PATH theia_get_file_list_path()
#define REPLAYFS_LOG_DIR theia_get_replay_logdb_path()
#define LOGDB_DIR theia_get_replay_logdb_path()
#define LOGDB_INDEX theia_get_replay_logdb_ndx_path()
#define REPLAYFS_CACHE_DIR theia_get_replay_cache_path()

// there is no "replayfs". it just refers to "/data/replay_logdb/*", etc.
extern char replayfs_logdb_path[];
extern char replayfs_filelist_path[];
extern char replayfs_cache_path[];
extern char replayfs_index_path[];
static inline const char* theia_get_file_list_path(void) {return replayfs_filelist_path;}
static inline const char* theia_get_replay_logdb_path(void) {return replayfs_logdb_path;}
static inline const char* theia_get_replay_logdb_ndx_path(void) {return replayfs_index_path;}
static inline const char* theia_get_replay_cache_path(void) {return replayfs_cache_path;}

// Macros to swap out the current uid with root for file operations
extern struct path theia_pid1_root;
#define THEIA_DECLARE_CREDS \
  struct path cur_pid_root; /* save root to get around chroot */ \
  const struct cred *uninitialized_var(old_cred);\
  struct cred *cred = NULL

#define THEIA_SWAP_CREDS_TO_ROOT do {\
  /* check if global PID1 root is still not setup */ \
  if (theia_pid1_root.dentry == NULL) {\
    struct task_struct *tsk_pid1 = NULL;\
    tsk_pid1 = pid_task(find_vpid(1), PIDTYPE_PID);\
    if (tsk_pid1) get_fs_root(tsk_pid1->fs, &theia_pid1_root);\
  }\
  /* temporarily swap chroot to real root fs*/ \
  if (theia_pid1_root.dentry != NULL) {\
    get_fs_root(current->fs, &cur_pid_root);\
    set_fs_root(current->fs, &theia_pid1_root);\
  } else {\
    cur_pid_root.dentry = NULL;\
  }\
  /* temporarily swap creds to root uid */ \
  cred = prepare_creds();\
  if (cred) {\
    cred->euid = GLOBAL_ROOT_UID;\
    cred->egid = GLOBAL_ROOT_GID;\
    cred->fsuid = GLOBAL_ROOT_UID;\
    cred->fsgid = GLOBAL_ROOT_GID;\
    old_cred = override_creds(cred);\
  }\
  } while(0)

#define THEIA_RESTORE_CREDS do {\
  /* restore creds */ \
  if (cred) {\
    revert_creds(old_cred);\
    put_cred(cred);\
  }\
  /* restore chroot */ \
  if (cur_pid_root.dentry != NULL) {\
    set_fs_root(current->fs, &cur_pid_root);\
    path_put(&cur_pid_root);\
  }\
  } while(0)

/* Starts replay with a (possibly) multithreaded fork */
int fork_replay (char __user * logdir, const char __user *const __user *args,
		const char __user *const __user *env, char* linker, int save_mmap, int fd,
		int pipe_fd);

/* Restore ckpt from disk - replaces AS of current process (like exec) */
/* Linker may be NULL - otherwise points to special libc linker */
long replay_ckpt_wakeup (int attach_pin, char* logdir, char* linker, int fd, int follow_splits, int save_mmap);

/* Returns linker for exec to use */
char* get_linker (void);

/* These should be used only by a PIN tool */
struct used_address {
    u_long start;
    u_long end;
};

int set_pin_address (u_long pin_address);
long get_log_id (void);
//Yang: for getting inode for pin
int get_inode_for_pin(u_long inode);
unsigned long get_clock_value (void);
long check_clock_before_syscall (int syscall);
long check_clock_after_syscall (int syscall);
long get_used_addresses (struct used_address __user * plist, int listsize);
void print_memory_areas (void);

/* Handles replay-specific work to record a signal */
int get_record_ignore_flag (void);
long check_signal_delivery (int signr, siginfo_t* info, struct k_sigaction* ka, int ignore_flag);
long record_signal_delivery (int signr, siginfo_t* info, struct k_sigaction* ka);
void replay_signal_delivery (int* signr, siginfo_t* info);
int replay_has_pending_signal (void);
int get_record_pending_signal (siginfo_t* info);

/* Called when a record/replay thread exits */
void recplay_exit_start(void);
void recplay_exit_middle(void);
void recplay_exit_finish(void);

/* Called during a vfork */
void record_vfork_handler (struct task_struct* tsk);
void replay_vfork_handler (struct task_struct* tsk);

/* Common helper functions */
struct pt_regs* get_pt_regs(struct task_struct* tsk);
char* get_path_helper (struct vm_area_struct* vma, char* path);
static inline struct record_thread* get_record_thread(void)
{
    return current->record_thrd;
}
static inline struct replay_thread* get_replay_thread(void)
{
    return current->replay_thrd;
}

/* For synchronization points in kernel outside of replay.c */
#define TID_WAKE_CALL 500
struct syscall_result;

long new_syscall_enter_external (long sysnum);
long new_syscall_exit_external (long sysnum, long retval, void* retparams);
long get_next_syscall_enter_external (int syscall, char** ppretparams, struct syscall_result** ppsr);
void get_next_syscall_exit_external (struct syscall_result* psr);

/* For handling randomness within the kernel */
void record_randomness(u_long);
u_long replay_randomness(void);

/* ... and for other exec values */
void record_execval(int uid, int euid, int gid, int egid, int secureexec);
void replay_execval(int* uid, int* euid, int* gid, int* egid, int* secureexec);

/* For replaying exec from a cache file */
const char* replay_get_exec_filename (void);

/* In replay_logdb.c */
__u64 get_replay_id (void);
void get_logdir_for_replay_id (__u64 id, char* buf);
int make_logdir_for_replay_id (__u64 id, char* buf);

/* In replay_ckpt.h */
char* copy_args (const char __user* const __user* args, const char __user* const __user* env, int* buflen, char* libpath, int libpath_len);
#ifdef TIME_TRICK
long replay_checkpoint_to_disk (char* filename, char* execname, char* buf, int buflen, __u64 parent_rg_id, struct timeval* tv, struct timespec* tp);
long replay_resume_from_disk (char* filename, char** execname, char*** argsp, char*** envp, __u64* prg_id, struct timeval* tv, struct timespec* tp);
#else
long replay_checkpoint_to_disk (char* filename, char* execname, char* buf, int buflen, __u64 parent_rg_id);
long replay_resume_from_disk (char* filename, char** execname, char*** argsp, char*** envp, __u64* prg_id);
#endif

/* Optional stats interface */
#define REPLAY_STATS
#ifdef REPLAY_STATS
struct replay_stats {
	atomic_t started;
	atomic_t finished;
	atomic_t mismatched;
};

long get_replay_stats (struct replay_stats __user * ustats);

#endif

/* For tracking where the args are in Pin, only valid on replay */
void save_exec_args(unsigned long argv, int argc, unsigned long envp, int envc);
unsigned long get_replay_args(void);
unsigned long get_env_vars(void);

long get_record_group_id(__u64 __user * prg_id);

/* Calls to read the filemap */
long get_num_filemap_entries(int fd, loff_t offset, int size);
long get_filemap(int fd, loff_t offset, int size, void __user * entries, int num_entries);

long reset_replay_ndx(void);

void write_shr_cache(char *buf, long len);

void remove_process_from_tree(pid_t pid, int sec);

long record_read_test(unsigned int fd, char __user *buf, size_t count);
#endif
