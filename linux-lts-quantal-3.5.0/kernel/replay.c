/* vim: set expandtab tabstop=2 shiftwidth=2 softtabstop=2 : */
/* Kernel sport's for multithreaded replay

   Jason Flinn
   Ed Nightingale */

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/syscalls.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/times.h>
#include <linux/utime.h>
#include <linux/futex.h>
#include <linux/scatterlist.h>
#include <linux/replay.h>
#include <linux/replay_maps.h>
#include <linux/pthread_log.h>
#include <linux/poll.h>
#include <linux/mman.h>
#include <linux/sort.h>
#include <linux/file.h>
#include <linux/tty.h>
#include <linux/fdtable.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/utsname.h>
#include <linux/eventpoll.h>
#include <linux/sysctl.h>
#include <linux/blkdev.h>
#include <linux/audit.h>
#include <linux/security.h>
#include <linux/cgroup.h>
#include <linux/delayacct.h>
#include <linux/mount.h>
#include <linux/limits.h>
#include <linux/utsname.h>
#include <linux/socket.h>
#include <linux/stat.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <asm/atomic.h>
#include <asm/prctl.h>
#include <asm/ldt.h>
#include <asm/syscall.h>
#include <linux/statfs.h>
#include <linux/workqueue.h>
#include <linux/ipc_namespace.h>
#include <linux/delay.h>
#include <linux/prctl.h>
#include <linux/shm.h>
#include <linux/mqueue.h>
#include <linux/keyctl.h>
#include <linux/serial.h>
#include <linux/msg.h>
#include "../ipc/util.h" // For shm utility functions
#include <asm/user_64.h>
#include <linux/slab.h>
#include <net/route.h>
#include <linux/dmi.h>

#include <linux/stacktrace.h>
#include <asm/stacktrace.h>

#include <linux/replay_configs.h>

#include <linux/fs_struct.h>
#include <linux/namei.h>
#include <linux/nmi.h>

//Yang
#include <linux/relay.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/theia_channel.h>
#include <linux/theia_ahglog.h>
#include <linux/theia.h> /* TODO: move stuffs to here */
#include <linux/dirent.h>
#include <linux/netlink.h>
#include <net/theia_cross_track.h>

#include <linux/dcache.h>

//xdou
#include <linux/xcomp.h>
#include <linux/encodebuffer.h>
#include <linux/decodeBuffer.h>
#include <linux/inet.h>
#include <linux/c_cache.h>
#include <linux/clog.h>
#include <linux/c_status.h>
//xdou
/* FIXME: I should move this to include... */
#include "../kernel/replay_graph/replayfs_btree128.h"
#include "../kernel/replay_graph/replayfs_filemap.h"
#include "../kernel/replay_graph/replayfs_syscall_cache.h"
#include "../kernel/replay_graph/replayfs_perftimer.h"

#include <linux/base64.h>

/* max_len should be smaller than or equal to the size of target */
inline void strncpy_safe(char *target, const char *source, size_t max_len)
{
  size_t len = strnlen(source, max_len);
  strncpy(target, source, len);
  target[len] = '\0';
}

//SL
struct timespec ext4_get_crtime(struct inode *inode);
unsigned long get_shm_segsz(int shmid);

void dump_user_stack(void);
void get_user_callstack(char *buffer, size_t bufsize);
char *get_file_fullpath(struct file *opened_file, char *buf, size_t buflen);

bool get_cmdline(struct task_struct *tsk, char *buffer);

void theia_dump_str(char *str, int rc, int sysum);
void theia_dump_auxdata(void);

void theia_setuid_ahg(uid_t uid, int rc);

#define MAX_SOCK_ADDR      128
#define THEIA_INVALID_PORT 0
void get_ip_port_sockaddr(struct sockaddr __user *sockaddr, int addrlen, char *ip, u_long *port, char *sun_path, sa_family_t *sa_family);

void get_ip_port_sockfd(int sockfd, char *ip, u_long *port, char *sun_path, sa_family_t *sa_family, bool is_peer);

inline void get_peer_ip_port_sockfd(int sockfd, char *ip, u_long *port, char *sun_path, sa_family_t *sa_family)
{
  get_ip_port_sockfd(sockfd, ip, port, sun_path, sa_family, true);
}

inline void get_local_ip_port_sockfd(int sockfd, char *ip, u_long *port, char *sun_path, sa_family_t *sa_family)
{
  get_ip_port_sockfd(sockfd, ip, port, sun_path, sa_family, false);
}

/* For debugging failing fs operations */
static int debug_flag = 0;

#define SUBBUF_SIZE 262144
#define N_SUBBUFS 4
bool theia_active_path = 1;
EXPORT_SYMBOL(theia_active_path);
//stored as seconds
unsigned long theia_active_path_timeout = 120;
EXPORT_SYMBOL(theia_active_path_timeout);

//#define APP_DIR   "theia_logs"
struct rchan *theia_chan = NULL;
EXPORT_SYMBOL(theia_chan);
struct dentry *theia_dir = NULL;
//static size_t   subbuf_size = 262144*5;
//static size_t   n_subbufs = 8;
//static size_t   event_n = 20;
//static size_t write_count;
//static int suspended;

#define IDS_LEN 50 // > 8*5 + 7
void get_ids(char *ids);

#define THEIA_UUID_LEN 256
#define THEIA_UUID 1 /* publish inodeinstead of fd? */
// #undef THEIA_UUID

/* inode:[dev:ino], ip:[ip/path:port], pipe:[xxxx], anon_inode:[xxxx] */
bool fd2uuid(int fd, char *uuid_str);
bool addr2uuid(struct socket *sock, struct sockaddr *dest_addr, char *uuid_str);
bool file2uuid(struct file *file, char *uuid_str, int fd);
void path2uuid(const struct path path, char *uuid_str);

#define THEIA_DIRECT_FILE_WRITE 1
#undef THEIA_DIRECT_FILE_WRITE

// used by theia_file_write() to add logs to relayfs ring buffer
static DEFINE_MUTEX(relay_write_lock);

// used as temporary buffer space for sprintf(), d_path(), etc.
static struct kmem_cache *theia_buffers;
#define THEIA_KMEM_SIZE PAGE_SIZE

//if defined, then calls to d_path() will use a stack allocated
//buffer. otherwise, d_path() will use a buffer from kmem_cache
#define DPATH_USE_STACK
#ifdef DPATH_USE_STACK
#define THEIA_DPATH_LEN MAX_LOGDIR_STRLEN+1
#else
#define THEIA_DPATH_LEN PAGE_SIZE
#endif

void theia_file_write(char *buf, size_t size)
{
  unsigned long flags;
  void *reserved = NULL;
  DEFINE_WAIT(wait);
  int __ret = msecs_to_jiffies(theia_active_path_timeout * 1000);
  if (size == 0)
  {
    pr_warn("theia_file_write() called with size 0\n");
    return;
  }
  mutex_lock(&relay_write_lock);
  local_irq_save(flags);
  if (theia_active_path)
  {
    pr_debug_ratelimited("theia_file_write() in active path\n");
    for (;;)
    {
      prepare_to_wait(theia_chan->private_data, &wait, TASK_UNINTERRUPTIBLE);
      reserved = relay_reserve(theia_chan, size);
      if (reserved)
      {
        break;
      }
      else
      {
        pr_warn("deferring relay_write() for pid %d on cpu %d with seq %u\n",
                current->pid, smp_processor_id(), current->no_syscalls);
        local_irq_restore(flags);
        __ret = schedule_timeout(__ret);
        local_irq_save(flags);
        if (!__ret)
        {
          pr_err("theia relay buffer is still unconsumed. disabling active_path.\n");
          theia_active_path = 0;
          break;
        }
        pr_warn("deferred relay_write() is continuing for pid %d on cpu %d with seq %u\n",
                current->pid, smp_processor_id(), current->no_syscalls);
      }
    }
    finish_wait(theia_chan->private_data, &wait);
    //this is relay_write()
    memcpy(reserved, buf, size);
    local_irq_restore(flags);
  }
  else
  {
    local_irq_restore(flags);
    pr_debug_ratelimited("theia_file_write() in original path\n");
    relay_write(theia_chan, buf, size);
  }
  mutex_unlock(&relay_write_lock);
}

bool theia_logging_toggle = 0;
EXPORT_SYMBOL(theia_logging_toggle);
bool theia_recording_toggle = 0;
EXPORT_SYMBOL(theia_recording_toggle);
char theia_linker[MAX_LOGDIR_STRLEN + 1];
EXPORT_SYMBOL(theia_linker);
char theia_libpath[MAX_LIBPATH_STRLEN + 1];
EXPORT_SYMBOL(theia_libpath);
bool theia_ui_toggle = 1;
EXPORT_SYMBOL(theia_ui_toggle);
char theia_proc_whitelist[MAX_WHITELIST_STRLEN + 1];
EXPORT_SYMBOL(theia_proc_whitelist);
size_t theia_proc_whitelist_len;
EXPORT_SYMBOL(theia_proc_whitelist_len);
char theia_dirent_prefix[MAX_DIRENT_STRLEN + 1];
EXPORT_SYMBOL(theia_dirent_prefix);
size_t theia_dirent_prefix_len;
EXPORT_SYMBOL(theia_dirent_prefix_len);

//multi-machine path support for record/replay
char replayfs_logdb_path[PAGE_SIZE];
EXPORT_SYMBOL(replayfs_logdb_path);
char replayfs_filelist_path[PAGE_SIZE];
EXPORT_SYMBOL(replayfs_filelist_path);
char replayfs_cache_path[PAGE_SIZE];
EXPORT_SYMBOL(replayfs_cache_path);
char replayfs_index_path[PAGE_SIZE];
EXPORT_SYMBOL(replayfs_index_path);


//we use pid (and more) to identify the replay process

struct theia_replay_register_data_type
{
  int           pid;
  int           pin;
  char          logdir[MAX_LOGDIR_STRLEN + 1];
  char          *linker;
  int           fd;
  int           follow_splits;
  int           save_mmap;
};
struct theia_replay_register_data_type theia_replay_register_data;
EXPORT_SYMBOL(theia_replay_register_data);

// static unsigned int no_new_proc = 0;

//#define THEIA_TRACK_SHM_OPEN 0
// #define THEIA_TRACK_SHMAT 1

/* dump aux data (callstack, user ids, ...) */
#define THEIA_AUX_DATA 1
//#undef THEIA_AUX_DATA

/*
#define THEIA_USER_RET_ADDR 1
#undef THEIA_USER_RET_ADDR

#define THEIA_USER_IDS 1
#undef THEIA_USER_IDS
*/

//#define REPLAY_PARANOID

// If defined, use file cache for reads of read-only files
#define CACHE_READS

static unsigned int theia_debug = 1;
#define TPRINT if(theia_debug) pr_debug

/* These #defines can be found in replay_config.h */
int verify_debug = 0;
#ifdef VERIFY_COMPRESSED_DATA
#define verify_debugk(...) if (verify_debug) {TPRINT(__VA_ARGS__);}
#else
#define verify_debugk(...)
#endif

#if defined(TRACE_READ_WRITE) && !defined(CACHE_READS)
# error "TRACE_READ_WRITE without CACHE_READS unimplemented!"
#endif

#if defined(TRACE_PIPE_READ_WRITE) && !defined(TRACE_READ_WRITE)
# error "TRACE_PIPE_READ_WRITE without TRACE_READ_WRITE unimplemented!"
#endif

#if defined(TRACE_SOCKET_READ_WRITE) && !defined(TRACE_PIPE_READ_WRITE)
# error "TRACE_SOCKET_READ_WRITE without TRACE_PIPE_READ_WRITE unimplemented!"
#endif

// how long we wait on the wait_queue before timing out
#define SCHED_TO 1000000

// Size of the file cache - default
#define INIT_RECPLAY_CACHE_SIZE 32

#define DPRINT if(replay_debug) pr_debug
//#define DPRINT(x,...)
#define MPRINT if(replay_debug || replay_min_debug) pr_debug
//#define MPRINT(x,...)
//#define MCPRINT

//#define DPRINT(x,...)

//xdou
/*
   * LOG_COMPRESS is the basic compression level, any other compression technique relies on this, i.e. if you want level_1, xproxy or det_time to be on, LOG_COMPRESS should also be on
   * LOG_COMPRESS_1 is not fully tested for firefox, don't turn it on for now; this means level 1 compression
   * X_COMPRESS will enable the application to use the x proxy; after X_COMPRESS is on, the application will talk to x proxy if x_proxy is 1 and will not talk to x proxy if x_proxy is 0
   * x_proxy can be set up in /proc/sys/kernel/x_proxy
   * when x_proxy is equal to 2, the user-level conversion tool should also be used
   * record_x should be set to 1 if you want a copy of all x messages in the replay log; otherwise, only a compressed x message log in the same folder with x proxy is enough for replaying
   *TIME_TRICK is for deterministic time; don't turn it on for now as I'm changing it. TIME_TRICK is defined in replay.h
   */
#define LOG_COMPRESS //log compress level 0
//#define LOG_COMPRESS_1 //log compress level 1
//#define X_COMPRESS  // note: x_compress should be defined at least along with log_compress level 0
#define USE_SYSNUM
//#define REPLAY_PAUSE
#define DET_TIME_DEBUG 0
#define DET_TIME_STAT 0
//#define MULTI_GROUP
#define SYSCALL_CACHE_REC current->record_thrd->rp_clog.syscall_cache
#define SYSCALL_CACHE_REP current->replay_thrd->rp_record_thread->rp_clog.syscall_cache
#define X_STRUCT_REC current->record_thrd->rp_clog.x
#define X_STRUCT_REP current->replay_thrd->rp_record_thread->rp_clog.x
#define x_detail 0
unsigned int x_proxy = 0;
unsigned int record_x = 1;
unsigned int replay_pause_tool = 0;
//xdou

#define ARGSKMALLOC(size, flags) argsalloc(size)
#define ARGSKFREE(ptr, size) argsfree(ptr, size)

#define new_syscall_exit(sysnum, retparam) _new_syscall_exit(sysnum, retparam, NULL)
#define ahg_new_syscall_exit(sysnum, retparam, ahgparam) _new_syscall_exit(sysnum, retparam, ahgparam)

//Yang: inode etc for replay and pin
static char rec_uuid_str[THEIA_UUID_LEN + 1];
static char repl_uuid_str[THEIA_UUID_LEN + 1] = "initial";

//ui globals
static int uiDebug=1;
//int uiLogging=1;
static char * orca_log=NULL;
#define orca_file_name "/tmp/orca.txt"
#define buttonRelease 666
#define buttonPress 667

static long lastPress=0;
static char * danglingX11=NULL;
bool in_nullterm_list(char *target, char *list, size_t list_len);

bool theia_check_channel(void)
{
  char *fpathbuf;
  char *fpath;
  struct mm_struct *mm;
  mm_segment_t old_fs;

  if (theia_logging_toggle == 0)
  {
    return false;
  }

  if (!current->mm) /* kernel thread */
    return false;

  old_fs = get_fs();
  set_fs(KERNEL_DS);

  if (theia_dir == NULL)
  {
    theia_dir = debugfs_create_dir(APP_DIR, NULL);
    if (!theia_dir)
    {
      TPRINT("Couldn't create relay app directory.\n");
      set_fs(old_fs);
      return false;
    }
  }
  if (theia_chan == NULL)
  {
    theia_chan = create_channel(subbuf_size, n_subbufs);
    if (!theia_chan)
    {
      debugfs_remove(theia_dir);
      set_fs(old_fs);
      return false;
    }
  }

  fpath = NULL;
  mm = current->mm;
  fpathbuf = (char *) vmalloc(PATH_MAX);
  if (mm && fpathbuf) {
    down_read(&mm->mmap_sem);
    if (mm->exe_file)
      fpath = get_file_fullpath(mm->exe_file, fpathbuf, PATH_MAX);
    up_read(&mm->mmap_sem);
  }
  if (!IS_ERR_OR_NULL(fpath) && in_nullterm_list(fpathbuf, theia_proc_whitelist, theia_proc_whitelist_len)) {
      vfree(fpathbuf);
      set_fs(old_fs);
      return false;
  }
  if (fpathbuf)
    vfree(fpathbuf);

  set_fs(old_fs);

  return true;
}

bool file2uuid(struct file *file, char *uuid_str, int fd)
{
  struct inode *inode;
  struct socket *sock;
  u_long dev, ino;
  u_long ldev, lino;
  umode_t mode;
  int err;
  char ip[16] = {'\0'};
  int port;
  char local_ip[16] = {'\0'};
  int local_port;
  char sun_path[UNIX_PATH_MAX];
  char local_sun_path[UNIX_PATH_MAX];
  sa_family_t sa_family; /* not used */
  char *sun_path_b64 = NULL;
  char *local_sun_path_b64 = NULL;
  struct stat st;
  mm_segment_t old_fs = get_fs();
  long rc; 

  if (file)
  {
    inode = file->f_dentry->d_inode;
    mode = inode->i_mode;
    dev = inode->i_sb->s_dev;
    ino = inode->i_ino;
    ldev = dev;
    lino = ino;

    //    if (dev == 0x7) { /* socket */
    if (S_ISSOCK(mode))
    {
      if (fd == -1) return false;

      sock = sockfd_lookup(fd, &err);
      if (sock)
      {
        sockfd_put(sock);
        get_peer_ip_port_sockfd(fd, ip, (u_long *)&port, sun_path, &sa_family);
        get_local_ip_port_sockfd(fd, local_ip, (u_long *)&local_port, local_sun_path, &sa_family);
        if (strcmp(ip, "LOCAL") == 0)
        {
          sun_path_b64 = base64_encode(sun_path, strlen(sun_path), NULL);
          if (!sun_path_b64) 
            sun_path_b64 = "";

          if (sun_path[0] == '/') {
            set_fs(KERNEL_DS);
            rc = sys_newstat(sun_path, &st);
            set_fs(old_fs);
            if (rc == 0) {
              dev = st.st_dev;
              ino = st.st_ino;
            }
          }

          if (strcmp(local_ip, "LOCAL") == 0) {
            if (local_sun_path[0] == '/') {
              set_fs(KERNEL_DS);
              rc = sys_newstat(local_sun_path, &st);
              set_fs(old_fs);
              if (rc == 0) {
                ldev = st.st_dev;
                lino = st.st_ino;
              }
            }
            local_sun_path_b64 = base64_encode(local_sun_path, strlen(local_sun_path), NULL);
            if (!local_sun_path_b64) 
              local_sun_path_b64 = "";
            rc = snprintf(uuid_str, THEIA_UUID_LEN, "S|%s|%lx/%lx|%s|%lx/%lx", sun_path_b64, dev, ino, local_sun_path_b64, ldev, lino);
            if (rc < 0) {
              uuid_str[0] = '\0';
              pr_err("file2uuid: uuid_str overflow\n");
            }
            if (local_sun_path_b64[0] != '\0')
              vfree(local_sun_path_b64);
          }
          else {
            rc = snprintf(uuid_str, THEIA_UUID_LEN, "S|%s|%lx/%lx|%s|%d", sun_path_b64, dev, ino, local_ip, local_port);
            if (rc < 0) {
              uuid_str[0] = '\0';
              pr_err("file2uuid: uuid_str overflow\n");
            }
          }

          if (sun_path_b64[0] != '\0')
            vfree(sun_path_b64);
        }
        else {
          if (strcmp(local_ip, "LOCAL") == 0) {
            if (local_sun_path[0] == '/') {
              set_fs(KERNEL_DS);
              rc = sys_newstat(local_sun_path, &st);
              set_fs(old_fs);
              if (rc == 0) {
                ldev = st.st_dev;
                lino = st.st_ino;
              }
            }
            local_sun_path_b64 = base64_encode(local_sun_path, strlen(local_sun_path), NULL);
            if (!local_sun_path_b64) 
              local_sun_path_b64 = "";
            rc = snprintf(uuid_str, THEIA_UUID_LEN, "S|%s|%d|%s|%lx/%lx", ip, port, local_sun_path_b64, ldev, lino);
            if (rc < 0) {
              uuid_str[0] = '\0';
              pr_err("file2uuid: uuid_str overflow\n");
            }
            if (local_sun_path_b64[0] != '\0')
              vfree(local_sun_path_b64);
          }
          else {
            rc = snprintf(uuid_str, THEIA_UUID_LEN, "S|%s|%d|%s|%d", ip, port, local_ip, local_port);
            if (rc < 0) {
              uuid_str[0] = '\0';
              pr_err("file2uuid: uuid_str overflow\n");
            }
          }
        }
      }
      else
      {
        pr_err("sockfd_lookup error: %d\n", err);
        return false;
      }
    }
    //    else if (dev == 0xfd00001 /* in-disk file */ || dev == 0xf /* in-memory file */ || dev == 0x5 /* ptmx */ || dev == 0xb /* pts */ || dev == 0x3 /* procfs */) {
    else if (S_ISBLK(mode) || S_ISCHR(mode) || S_ISDIR(mode) || S_ISREG(mode) || S_ISLNK(mode))
    {
      //Yang: get offset
#ifdef THEIA_PROVIDE_OFFSET
      loff_t offset = vfs_llseek(file, 0, SEEK_CUR);
#endif

      if (dev == 0xfd00001)
      {
        struct timespec ts = ext4_get_crtime(inode);
#ifdef THEIA_PROVIDE_OFFSET
        rc = snprintf(uuid_str, THEIA_UUID_LEN, "I|%lx|%lx|%lx|%llx", dev, ino, ts.tv_sec, offset);
#else
        rc = snprintf(uuid_str, THEIA_UUID_LEN, "I|%lx|%lx|%lx", dev, ino, ts.tv_sec);
#endif
        if (rc < 0) {
          uuid_str[0] = '\0';
          pr_err("file2uuid: uuid_str overflow\n");
        }
      }
      else
      {
#ifdef THEIA_PROVIDE_OFFSET
        rc = snprintf(uuid_str, THEIA_UUID_LEN, "I|%lx|%lx|0|%llx", dev, ino, offset);
#else
        rc = snprintf(uuid_str, THEIA_UUID_LEN, "I|%lx|%lx|0", dev, ino);
#endif
        if (rc < 0) {
          uuid_str[0] = '\0';
          pr_err("file2uuid: uuid_str overflow\n");
        }
      }
    }
    else   /* pipe, anon_inode, or others */
    {
      //Yang: get offset
#ifdef THEIA_PROVIDE_OFFSET
      loff_t offset = vfs_llseek(file, 0, SEEK_CUR);
#endif

#ifdef THEIA_PROVIDE_OFFSET
      rc = snprintf(uuid_str, THEIA_UUID_LEN, "I|%lx|%lx|0|%llx", dev, ino, offset); /* just inode */
#else
      rc = snprintf(uuid_str, THEIA_UUID_LEN, "I|%lx|%lx|0", dev, ino); /* just inode */
#endif
      if (rc < 0) {
        uuid_str[0] = '\0';
        pr_err("file2uuid: uuid_str overflow\n");
      }
    }
    //Yang: we need these later:
    if (uuid_str[0] != '\0')
      strncpy_safe(rec_uuid_str, uuid_str, THEIA_UUID_LEN);
  }
  else
  {
    TPRINT("[file2uuid]: Not a file\n");
    return false;
  }

  if (uuid_str[0] != '\0')
    return true;
  else
    return false;
}

void path2uuid(const struct path path, char *uuid_str)
{
  kuid_t uid;
  kgid_t gid;
  u_long dev, ino;
  struct timespec cr_time;

  cr_time = ext4_get_crtime(path.dentry->d_inode);
  dev = path.dentry->d_inode->i_sb->s_dev;
  ino = path.dentry->d_inode->i_ino;
  uid = path.dentry->d_inode->i_uid;
  gid = path.dentry->d_inode->i_gid;
  snprintf(uuid_str, THEIA_UUID_LEN, "%lx|%lx|%ld|%ld|%u/%u", dev, ino,
          cr_time.tv_sec, cr_time.tv_nsec, uid, gid);
}

bool fd2uuid(int fd, char *uuid_str)
{
  struct file *file;
  int fput_needed;
  int err;
  int ret;
  struct kstat stat;
  char buf[THEIA_UUID_LEN+1];

  file = fget_light(fd, &fput_needed);
  if (file)
  {
    ret = file2uuid(file, uuid_str, fd);
    fput_light(file, fput_needed);
    if (ret == false)
      return false;
  }
  else
  {
    pr_debug("[fd2uuid]: Failed to get file. fd %d\n", fd);
    return false;
  }

  /* owner info */
  err = vfs_fstat(fd, &stat);

  if (!err)
  {
    snprintf(buf, THEIA_UUID_LEN, "|%d/%d", stat.uid, stat.gid);
    strncat(uuid_str, buf, THEIA_UUID_LEN - strnlen(uuid_str, THEIA_UUID_LEN));
  }
  else
    strcat(uuid_str, "|-1/-1");


  return true;
}

#define THEIA_AUX_META_LEN 120
// dump aux data: callstack, ids, ...
void theia_dump_auxdata(void)
{
  char ids[IDS_LEN+1];
  char *callstack;
  char *auxdata;
  int size = 0;

  if (!current->mm)
    return;

  if (theia_logging_toggle)
  {
    get_ids(ids);
    callstack = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    get_user_callstack(callstack, THEIA_KMEM_SIZE-THEIA_AUX_META_LEN);
    auxdata = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    size = snprintf(auxdata, THEIA_KMEM_SIZE-1, "startahg|700|%d|%li|%s%s|%u|endahg\n", 
      current->pid, current->start_time.tv_sec, callstack, ids, current->no_syscalls);
    kmem_cache_free(theia_buffers, callstack);
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(auxdata, size);
    kmem_cache_free(theia_buffers, auxdata);
  }
}

void theia_dump_str(char *str, int rc, int sysnum)
{
    long sec, nsec;
    int size = 0;
    char *buf;
  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  /* packahgv */
  if (theia_logging_toggle)
  {

    get_curr_time(&sec, &nsec);

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    size = snprintf(buf, THEIA_KMEM_SIZE, "startahg|%d|%d|%li|%d|%s|%d|%ld|%ld|%u|endahg\n", \
                   sysnum, current->pid, current->start_time.tv_sec, \
                   rc, str, \
                   current->tgid, sec, nsec, current->no_syscalls++);
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
    kmem_cache_free(theia_buffers, buf);
  }
}

static void theia_dump_ss(const char __user *str1, const char __user *str2, int rc, int sysnum)
{
  char *pcwd = NULL;
  struct path path;
  char *buf;
  int ret = 0;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  if (str1[0] == '/' && str2[0] == '/')
  {
    ret = snprintf(buf, THEIA_KMEM_SIZE, "%s|%s", str1, str2);
  }
  else
  {
    if (current->fs)
    {
      get_fs_pwd(current->fs, &path);
      pcwd = d_path(&path, pbuf, THEIA_DPATH_LEN);
      if (IS_ERR(pcwd))
        pcwd = ".";
    }
    else
    {
      pcwd = ".";
    }

    if (!pcwd)
    {
      ret = snprintf(buf, THEIA_KMEM_SIZE, "%s|%s", str1, str2);
    }
    else if (str1[0] == '/')
    {
      ret = snprintf(buf, THEIA_KMEM_SIZE, "%s|%s/%s", str1, pcwd, str2);
    }
    else if (str2[0] == '/')
    {
      ret = snprintf(buf, THEIA_KMEM_SIZE, "%s/%s|%s", pcwd, str1, str2);
    }
    else
    {
      ret = snprintf(buf, THEIA_KMEM_SIZE, "%s/%s|%s/%s", pcwd, str1, pcwd, str2);
    }
  }

  if (ret < 0) {
    strcpy(buf, "|");
  }

  theia_dump_str(buf, rc, sysnum);
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
}

static void theia_dump_sd(const char __user *str, int val, int rc, int sysnum)
{
  char *pcwd = NULL;
  struct path path;
  char *buf;
  int ret = 0;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  if (str[0] == '/')
  {
    ret = snprintf(buf, THEIA_KMEM_SIZE, "%s|%d", str, val);
  }
  else
  {
    if (current->fs)
    {
      get_fs_pwd(current->fs, &path);
      pcwd = d_path(&path, pbuf, THEIA_DPATH_LEN);
      if (IS_ERR(pcwd))
        pcwd = ".";
    }
    else
    {
      pcwd = ".";
    }

    ret = snprintf(buf, THEIA_KMEM_SIZE, "%s/%s|%d", pcwd, str, val);
  }

  if (ret < 0) {
    strcpy(buf, "|0");
  }

  theia_dump_str(buf, rc, sysnum);
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
}

static void theia_dump_sdd(const char __user *str, int val1, int val2, int rc, int sysnum)
{
  char *pcwd = NULL;
  struct path path;
  char *buf;
  int ret = 0;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  if (str[0] == '/')
  {
    ret = snprintf(buf, THEIA_KMEM_SIZE, "%s|%d|%d", str, val1, val2);
  }
  else
  {
    if (current->fs)
    {
      get_fs_pwd(current->fs, &path);
      pcwd = d_path(&path, pbuf, THEIA_DPATH_LEN);
      if (IS_ERR(pcwd))
        pcwd = ".";
    }
    else
    {
      pcwd = ".";
    }

    ret = snprintf(buf, THEIA_KMEM_SIZE, "%s/%s|%d|%d", pcwd, str, val1, val2);
  }

  if (rc < 0) {
    strcpy(buf, "|0|0");
  }

  theia_dump_str(buf, rc, sysnum);
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
}

static void theia_dump_at_sd(int dfd, const char __user *str, int val, int rc, int sysnum)
{
}

static void theia_dump_dd(long val1, long val2, int rc, int sysnum)
{
  char *buf;
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
  snprintf(buf, THEIA_KMEM_SIZE, "%li|%li", val1, val2);
  theia_dump_str(buf, rc, sysnum);
  kmem_cache_free(theia_buffers, buf);
}

static void theia_dump_ddd(int val1, int val2, int val3, int rc, int sysnum)
{
  char *buf;
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
  snprintf(buf, THEIA_KMEM_SIZE, "%d|%d|%d", val1, val2, val3);
  theia_dump_str(buf, rc, sysnum);
  kmem_cache_free(theia_buffers, buf);
}

struct black_pid
{
  int pid[3];
};

void get_curr_time(long *sec, long *nsec)
{
  struct timespec ts;
  getnstimeofday(&ts);
  *sec = ts.tv_sec;
  *nsec = ts.tv_nsec; //granuality is microsec
  return;
}

/*
 * subbuf_start() relay callback.
 *
 * Defined so that we know when events are dropped due to the buffer-full
 * condition.
 */
static int suspended;
static ulong dropped_count = 0;
static wait_queue_head_t theia_relay_write_q;

static int subbuf_start_handler(struct rchan_buf *buf,
                                void *subbuf,
                                void *prev_subbuf,
                                size_t prev_padding)
{
  if (relay_buf_full(buf))
  {
    if (!suspended)
    {
      suspended = 1;
      TPRINT("cpu %d buffer full, dropped_count: %lu\n", smp_processor_id(), dropped_count);
    }
    dropped_count++;
    return 0;
  }
  else if (suspended)
  {
    suspended = 0;
    TPRINT("cpu %d buffer no longer full.\n", smp_processor_id());
  }
  return 1;
}

/*
 * file_create() callback.  Creates relay file in debugfs.
 */
static struct dentry *create_buf_file_handler(const char *filename,
    struct dentry *parent,
    umode_t mode,
    struct rchan_buf *buf,
    int *is_global)
{
  struct dentry *buf_file;

  buf_file = debugfs_create_file(filename, mode, parent, buf,
                                 &relay_file_operations);

  return buf_file;
}

/*
 * file_remove() default callback.  Removes relay file in debugfs.
 */
static int remove_buf_file_handler(struct dentry *dentry)
{
  debugfs_remove(dentry);

  return 0;
}

/*
 * wake up any tasks that could not relay_write() because the buffer was full
 */
static void after_subbufs_consumed_handler(struct rchan *chan,
    unsigned int cpu,
    size_t subbufs_consumed)
{
  if (theia_active_path)
  {
    if (chan->private_data && waitqueue_active(chan->private_data))
    {
      pr_warn("theia:after_subbufs_consumed() # of bufs consumed = %lu\n", subbufs_consumed);
      wake_up(chan->private_data);
    }
  }
}

/*
 * relay callbacks
 */
static struct rchan_callbacks relay_callbacks =
{
  .subbuf_start = subbuf_start_handler,
  .create_buf_file = create_buf_file_handler,
  .remove_buf_file = remove_buf_file_handler,
  .after_subbufs_consumed = after_subbufs_consumed_handler,
};


/**
 *  create_channel - creates channel /debug/APP_DIR/cpuXXX
 *
 *  Creates channel along with associated produced/consumed control files
 *
 *  Returns channel on success, NULL otherwise
 */
struct rchan *create_channel(size_t size, size_t n)
{
  struct rchan *channel;

  channel = relay_open("cpu", theia_dir, size, n, &relay_callbacks, &theia_relay_write_q);

  if (!channel)
  {
    pr_warn_ratelimited("relay app channel creation failed\n");
    return NULL;
  }

  return channel;
}

DEFINE_MUTEX(theia_process_tree_mutex);
static struct btree_head64 theia_process_tree;
static bool theia_process_tree_init = false;

DEFINE_MUTEX(theia_opened_inode_tree_mutex);
static struct btree_head64 theia_opened_inode_tree;
static bool theia_opened_inode_tree_init = false;

/* Performance evaluation timers... micro monitoring */
//struct perftimer *write_btwn_timer;
static struct perftimer *write_in_timer;
static struct perftimer *write_sys_timer;
static struct perftimer *write_filemap_timer;
static struct perftimer *write_traceread_timer;

//struct perftimer *read_btwn_timer;
static struct perftimer *read_in_timer;
static struct perftimer *read_cache_timer;
static struct perftimer *read_sys_timer;
static struct perftimer *read_traceread_timer;
static struct perftimer *read_filemap_timer;

static struct perftimer *open_timer;
static struct perftimer *open_sys_timer;
static struct perftimer *open_intercept_timer;
static struct perftimer *open_cache_timer;

static struct perftimer *close_timer;
static struct perftimer *close_sys_timer;
static struct perftimer *close_intercept_timer;

/* Keep track of open inodes */

DEFINE_MUTEX(filp_opened_mutex);
static struct btree_head64 inode_tree;

struct inode_data
{
  atomic_t refcnt;
  struct mutex replay_inode_lock;
  int read_opens;
  int write_opens;
  u64 key;
  loff_t version;
};

struct filemap_data
{
#ifdef TRACE_READ_WRITE
  struct replayfs_filemap map;
#endif
  struct inode_data *idata;
  loff_t last_version;
};

static void __inode_data_put(struct inode_data *idata)
{
  mutex_lock(&filp_opened_mutex);
  btree_remove64(&inode_tree, idata->key);
  mutex_unlock(&filp_opened_mutex);
  mutex_destroy(&idata->replay_inode_lock);
  kfree(idata);
}

static inline void inode_data_put(struct inode_data *idata)
{
  if (atomic_dec_and_test(&idata->refcnt))
  {
    __inode_data_put(idata);
  }
}

static struct inode_data *inode_data_create(u64 key)
{
  struct inode_data *ret = kmalloc(sizeof(struct inode_data), GFP_KERNEL);

  BUG_ON(ret == NULL);

  atomic_set(&ret->refcnt, 0);
  ret->read_opens = 0;
  ret->write_opens = 0;
  ret->version = 0;
  ret->key = key;
  mutex_init(&ret->replay_inode_lock);

  btree_insert64(&inode_tree, key, ret, GFP_KERNEL);

  return ret;
}

static struct inode_data *inode_data_get(struct file *filp)
{
  struct inode_data *ret = NULL;

  struct inode *inode = filp->f_dentry->d_inode;

  u64 key;

  key = ((u64)inode->i_sb->s_dev) << 32 | (u64)inode->i_ino;
  /*
  TPRINT("%s %d: dev is %x ino is %lx, key is %llx\n", __func__, __LINE__,
      inode->i_rdev, inode->i_ino, key);
      */

  mutex_lock(&filp_opened_mutex);

  ret = btree_lookup64(&inode_tree, key);
  if (ret == NULL)
  {
    ret = inode_data_create(key);
  }

  mutex_unlock(&filp_opened_mutex);

  atomic_inc(&ret->refcnt);

  return ret;
}

void replay_filp_close(struct file *filp)
{
  if (current->record_thrd != NULL)
  {
    perftimer_start(close_intercept_timer);
    if (filp != NULL)
    {
      if (filp->replayfs_filemap)
      {
        struct filemap_data *data = filp->replayfs_filemap;
#ifdef TRACE_READ_WRITE
        /*
        TPRINT("%s %d: destroying %p\n", __func__, __LINE__,
            filp->replayfs_filemap);
            */
        replayfs_filemap_destroy(&data->map);
#endif

        mutex_lock(&data->idata->replay_inode_lock);
        if ((filp->f_flags & O_ACCMODE) == O_RDONLY)
        {
          data->idata->read_opens--;
        }
        else if ((filp->f_flags & O_ACCMODE) == O_WRONLY)
        {
          data->idata->write_opens--;
        }
        else if ((filp->f_flags & O_ACCMODE) == O_RDWR)
        {
          data->idata->write_opens--;
          data->idata->read_opens--;
        }
        mutex_unlock(&data->idata->replay_inode_lock);

        inode_data_put(data->idata);

        kfree(data);

        filp->replayfs_filemap = NULL;
      }
    }
    perftimer_stop(close_intercept_timer);
  }
}

extern atomic_t open_in_replay;
void replayfs_file_opened(struct file *filp)
{
  /* If we're recording... */
  if (filp != NULL && !IS_ERR(filp))
  {
    if (current->record_thrd != NULL && !atomic_read(&open_in_replay))
    {
      struct inode *inode = filp->f_dentry->d_inode;

      perftimer_start(open_intercept_timer);

      if (inode->i_rdev == 0 && MAJOR(inode->i_sb->s_dev) != 0)
      {
        struct filemap_data *data = kmalloc(sizeof(struct filemap_data),
                                            GFP_KERNEL);

#ifdef TRACE_READ_WRITE
        glbl_diskalloc_init();

        replayfs_filemap_init(&data->map, replayfs_alloc, filp);
#endif
        data->idata = inode_data_get(filp);
        BUG_ON(!data->idata);
        filp->replayfs_filemap = data;
        /*
        TPRINT("%s %d: Allocating %p\n", __func__, __LINE__,
            filp->replayfs_filemap);
            */

        mutex_lock(&data->idata->replay_inode_lock);
        if ((filp->f_flags & O_ACCMODE) == O_RDONLY)
        {
          data->idata->read_opens++;
        }
        else if ((filp->f_flags & O_ACCMODE) == O_WRONLY)
        {
          data->idata->write_opens++;
        }
        else if ((filp->f_flags & O_ACCMODE) == O_RDWR)
        {
          data->idata->write_opens++;
          data->idata->read_opens++;
        }
        mutex_unlock(&data->idata->replay_inode_lock);

      }
      else
      {
        filp->replayfs_filemap = NULL;
      }

      perftimer_stop(open_intercept_timer);
    }
    else
    {
      filp->replayfs_filemap = NULL;
    }
  }
}

#define IS_RECORDED_FILE (1<<3)
#define READ_NEW_CACHE_FILE (1<<4)

#ifdef TRACE_PIPE_READ_WRITE
extern const struct file_operations read_pipefifo_fops;
extern const struct file_operations write_pipefifo_fops;
extern const struct file_operations rdwr_pipefifo_fops;
#define is_pipe(X) ((X)->f_op == &read_pipefifo_fops || (X)->f_op == &write_pipefifo_fops || (X)->f_op == &rdwr_pipefifo_fops)

static atomic_t glbl_pipe_id = {1};

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

#define READ_PIPE_WITH_DATA (1<<2)
#define READ_IS_PIPE (1<<1)

DEFINE_MUTEX(pipe_tree_mutex);
static struct btree_head64 pipe_tree;

void replay_free_pipe(void *pipe)
{
  struct pipe_track *info;

  mutex_lock(&pipe_tree_mutex);
  info = btree_lookup64(&pipe_tree, (u64)pipe);

  if (info != NULL)
  {
    struct replayfs_btree128_key key;
    struct replayfs_filemap map;
    int ret;


    memcpy(&key, &info->key, sizeof(key));

    kfree(info);
    btree_remove64(&pipe_tree, (u64)pipe);
    mutex_unlock(&pipe_tree_mutex);

    /* Get the map that needs to be freed */
    ret = replayfs_filemap_init_key(&map, replayfs_alloc, &key);
    if (!ret)
    {
      /* Free it */
      replayfs_filemap_delete_key(&map, &key);
    }
  }
  else
  {
    mutex_unlock(&pipe_tree_mutex);
  }
}
#else
void replay_free_pipe(void *pipe)
{
}
#endif

#ifdef TRACE_SOCKET_READ_WRITE
extern const struct proto_ops unix_stream_ops;
extern const struct proto_ops unix_dgram_ops;
extern const struct proto_ops unix_seqpacket_ops;

extern struct socket *sock_from_file(struct file *, int *);

void replay_sock_put(struct sock *sk)
{
  struct pipe_track *info;

  mutex_lock(&pipe_tree_mutex);
  info = btree_lookup64(&pipe_tree, (u64)sk);

  if (info != NULL)
  {
    struct replayfs_btree128_key key;
    struct replayfs_filemap map;
    int ret;

    memcpy(&key, &info->key, sizeof(key));

    kfree(info);
    btree_remove64(&pipe_tree, (u64)sk);
    mutex_unlock(&pipe_tree_mutex);

    /* Get the map that needs to be freed */
    ret = replayfs_filemap_init_key(&map, replayfs_alloc, &key);
    if (!ret)
    {
      /* Free it */
      replayfs_filemap_delete_key(&map, &key);
    }
  }
  else
  {
    mutex_unlock(&pipe_tree_mutex);
  }
}
#else
void replay_sock_put(struct sock *sk) {} // Noop
#endif

#define IS_CACHED_MASK 1

// write out the kernel logs asynchronously
//#define WRITE_ASYNC

#ifdef REPLAY_STATS
struct replay_stats rstats;
#endif

#ifdef REPLAY_PARANOID
static int malloc_init = 0;
struct ds_list_t *malloc_hash[1023];
DEFINE_MUTEX(repmalloc_mutex);
// Intended to check for double frees
void *KMALLOC(size_t size, gfp_t flags)
{
  void *ptr;
  int i;

  mutex_lock(&repmalloc_mutex);
  if (!malloc_init)
  {
    malloc_init = 1;
    for (i = 0; i < 1023; i++)
    {
      malloc_hash[i] = ds_list_create(NULL, 0, 0);
    }
  }

  ptr = kmalloc(size, flags);
  if (ptr)
  {
    u_long addr = (u_long) ptr;
    ds_list_insert(malloc_hash[addr % 1023], ptr);
  }
  mutex_unlock(&repmalloc_mutex);
  return ptr;
}

void KFREE(const void *ptr)
{
  int i;

  mutex_lock(&repmalloc_mutex);
  if (!malloc_init)
  {
    malloc_init = 1;
    for (i = 0; i < 1023; i++)
    {
      malloc_hash[i] = ds_list_create(NULL, 0, 0);
    }
  }
  if (ptr)
  {
    u_long addr = (u_long) ptr;
    void *tmp;
    tmp = ds_list_remove(malloc_hash[addr % 1023], (void *) ptr);
    if (tmp == NULL)
    {
      TPRINT("Cannot remove address %p\n", ptr);
      BUG();
    }
  }
  mutex_unlock(&repmalloc_mutex);

  kfree(ptr);
}

atomic_t vmalloc_cnt = ATOMIC_INIT(0);
#define VMALLOC(size) vmalloc(size); atomic_inc(&vmalloc_cnt);
#define VFREE(x) atomic_dec(&vmalloc_cnt); vfree(x);

#else

#define KFREE kfree
#define KMALLOC kmalloc
#define VMALLOC vmalloc
#define VFREE vfree

#endif

//#ifdef REPLAY_PARANOID
//#define REPLAY_LOCK_DEBUG
//#endif

/* Constant defintions */

#define SIGNAL_WHILE_SYSCALL_IGNORED 405

/* Variables configurable via /proc file system */
unsigned int syslog_recs = 2000;
unsigned int replay_debug = 1;
unsigned int replay_min_debug = 1;
unsigned long argsalloc_size = (512 * 1024);
// If the replay clock is greater than this value, MPRINT out the syscalls made by pin
unsigned long pin_debug_clock = LONG_MAX;

/* struct definitions */
struct replay_group;
struct record_group;
struct syscall_result;

/* Data structures */
struct repsignal
{
  int signr;
  siginfo_t info;
  struct k_sigaction ka;
  sigset_t blocked;
  sigset_t real_blocked;
  struct repsignal *next;
};

// This saves record context from when signal was delivered
struct repsignal_context
{
  int                       ignore_flag;
  struct repsignal_context *next;
};

#define SR_HAS_RETPARAMS        0x1
#define SR_HAS_SIGNAL           0x2
#define SR_HAS_START_CLOCK_SKIP 0x4
#define SR_HAS_STOP_CLOCK_SKIP  0x8
#define SR_HAS_NONZERO_RETVAL   0x10
#define SR_HAS_SPECIAL_FIRST  0x20
#define SR_HAS_SPECIAL_SECOND 0x40
//#define SR_HAS_SPECIAL_THIRD  0x80
#define SR_HAS_AHGPARAMS  0x80

// This structure records the result of a system call
struct syscall_result
{
#ifdef USE_HPC
  unsigned long long  hpc_begin;  // Time-stamp counter value when system call started
  unsigned long long  hpc_end;  // Time-stamp counter value when system call finished
#endif
#ifdef USE_SYSNUM
  short     sysnum;   // system call number executed
#endif
  u_char                  flags;          // See defs above
};

#ifdef LOG_COMPRESS
//xdou
struct pipe_fds
{
  int *fds;
  int length;
  int size;
  struct mutex lock;
};
#endif

// This holds a memory range that should be preallocated
struct reserved_mapping
{
  u_long m_begin;
  u_long m_end;
};

#ifdef CACHE_READS
struct record_cache_data
{
  char is_cache_file; // True if this is a cache file descriptor
  struct mutex mutex;  // Only one thread at a time gets to access the descriptor
};

struct record_cache_chunk
{
  int                        count; // Number of files in this chunk
  struct record_cache_data  *data;  // Dynamically allocated array of data
  struct record_cache_chunk *next;  // Next chunk
};

struct record_cache_files
{
  atomic_t                   refcnt; // Refs to this structure
  struct rw_semaphore        sem; // Protects this structure
  int                        count; // Maximum number of files in this struct
  struct record_cache_chunk *list;  // Array of flags per file descriptor
};

struct replay_cache_files
{
  atomic_t refcnt; // Refs to this structure
  int      count; // Maximum number of files in this struct
  int     *data;  // Array of cache fds per file descriptor
};
#else
struct record_cache_files;
struct replay_cache_files;
#endif

struct record_group
{
  __u64 rg_id;                         // Unique identifier for all time for this recording

#ifdef REPLAY_LOCK_DEBUG
  pid_t rg_locker;
  struct semaphore rg_sem;
#else
  struct mutex rg_mutex;      // Protect all structures for group
#endif
  atomic_t rg_refcnt;         // Refs to this structure

  char rg_logdir[MAX_LOGDIR_STRLEN + 1]; // contains the directory to which we will write the log

  struct page *rg_shared_page;          // Used for shared clock below
  atomic_t *rg_pkrecord_clock;          // Where clock is mapped into kernel address space for this record/replay
  char rg_shmpath[MAX_LOGDIR_STRLEN + 1]; // contains the path of the shared-memory file that we will used for user-level mapping of clock

  char rg_linker[MAX_LOGDIR_STRLEN + 1]; // contains the name of a special linker to use - for user level pthread library


#ifdef TIME_TRICK
  struct det_time_struct rg_det_time;
  struct mutex rg_time_mutex;
#endif
  atomic_t rg_record_threads; // Number of active record threads
  int rg_save_mmap_flag;    // If on, records list of mmap regions during record
  ds_list_t *rg_reserved_mem_list; // List of addresses that are mmaped, kept on the fly as they occur
  u_long rg_prev_brk;   // the previous maximum brk, for recording memory maps
  char rg_mismatch_flag;      // Set when an error has occurred and we want to abandon ship
  char *rg_libpath;           // For glibc hack
};

// This structure has task-specific replay data
struct replay_group
{
  struct record_group *rg_rec_group; // Pointer to record group
  ds_list_t *rg_replay_threads; // List of replay threads for this group
  atomic_t rg_refcnt;         // Refs to this structure
  ds_list_t *rg_reserved_mem_list; // List of addresses we should preallocate to keep pin from using them
  u_long rg_max_brk;          // Maximum value of brk address
  ds_list_t *rg_used_address_list; // List of addresses that will be used by the application (and hence, not by pin)
  int rg_follow_splits;       // Ture if we should replay any split-off replay groups
  char cache_dir[CACHE_FILENAME_SIZE];
};


struct argsalloc_node
{
  void            *head;
  void            *pos;
  size_t           size;
  struct list_head list;
};

struct sysv_mapping
{
  int record_id;
  int replay_id;
  struct list_head list;
};

struct sysv_shm
{
  u_long addr;
  u_long len;
  struct list_head list;
};

#define CHECK_K_PTR(x) if ((u_long) (x) < 0xc0000000) { TPRINT ("Bad pointer %p\n", (x)); BUG(); }

#ifdef REPLAY_LOCK_DEBUG
static void rg_lock(struct record_group *prg)
{
#ifdef REPLAY_PARANOID
  if (!write_can_lock(&tasklist_lock))
  {
    MPRINT("replay: pid %d cannot lock tasklist, prg %p, rg_locker %d\n", current->pid, prg, prg->rg_locker);
    write_lock_irq(&tasklist_lock);
    write_unlock_irq(&tasklist_lock);
    MPRINT("tasklist lock succeeded anyway\n");
  }
  while (down_timeout(&(prg)->rg_sem, 125))
  {
    MPRINT("pid %d cannot get replay lock %p - last locker was pid %d\n", current->pid, prg, prg->rg_locker);
  }
  prg->rg_locker = current->pid;
#else
  down(&(prg)->rg_sem);
#endif
}

static void rg_unlock(struct record_group *prg)
{
#ifdef REPLAY_PARANOID
  if (current->pid != prg->rg_locker)
  {
    TPRINT("pid %d locked and pid %d unlocked\n", prg->rg_locker,
           current->pid);
  }
  prg->rg_locker = 0;
#endif
  up(&(prg)->rg_sem);
#ifdef REPLAY_PARANOID
  if (prg->rg_sem.count > 1)
  {
    TPRINT("ERROR: pid %d sees semcount %d\n", current->pid, prg->rg_sem.count);
  }
#endif
}
#else
#define rg_lock(prg) mutex_lock(&(prg)->rg_mutex);
#define rg_unlock(prg) mutex_unlock(&(prg)->rg_mutex);
#endif

static long
rm_cmp(void *rm1, void *rm2)
{
  struct reserved_mapping *prm1 = rm1;
  struct reserved_mapping *prm2 = rm2;
  return prm1->m_begin - prm2->m_begin;
}

// This structure records/replays random values generated by the kernel
// Only used for the execve system call right now - is it needed elsewhere?
// #define REPLAY_MAX_RANDOM_VALUES 10
#define REPLAY_MAX_RANDOM_VALUES 100
struct rvalues
{
  int    cnt;
  u_long val[REPLAY_MAX_RANDOM_VALUES];
};

#ifdef LOG_COMPRESS
/*struct det_time{
  int flag;
};*/
struct clog_struct
{
  //for log compression
  int done;
  int args_size;
  struct syscallCache syscall_cache;

  struct x_struct x;
  long clock_predict;
  struct pipe_fds pfds;

  struct status_info syscall_status;

  //struct det_time time;
};

#endif

// This structure records/replays other values passed to an executable during exec
struct exec_values
{
  int uid;
  int euid;
  int gid;
  int egid;
  int secureexec;
};

//This has record thread specific data
struct record_thread
{
  struct record_group *rp_group; // Points to record group
  struct record_thread *rp_next_thread; // Circular record thread list

  atomic_t rp_refcnt;            // Reference count for this object
  pid_t rp_record_pid;           // Pid of recording task (0 if not set)
  short rp_clone_status;         // Prevent rec task from exiting
  // before rep task is created
  // (0:init,1:cloning,2:completed)
  long rp_sysrc;                 // Return code for replay_prefork

  /* Recording log */
  struct syscall_result *rp_log;  // Logs system calls per thread
  u_long rp_in_ptr;               // Next record to insert
  u64 rp_count;                   // Number of syscalls run by this thread

  loff_t rp_read_log_pos;   // The current position in the log file that is being read
#ifdef LOG_COMPRESS_1
  loff_t rp_read_clog_pos;
#endif
  struct list_head rp_argsalloc_list; // kernel linked list head pointing to linked list of argsalloc_nodes

#ifdef LOG_COMPRESS_1
  struct list_head rp_clog_list;    // the linked list for compressed log, written to another file
#endif

  u_long rp_user_log_addr;        // Where the user log info is stored
#ifdef USE_EXTRA_DEBUG_LOG
  u_long rp_user_extra_log_addr;  // For extra debugging log
  char rp_elog_opened;    // Flag that says whether or not the extra log has been opened
  loff_t rp_read_elog_pos;  // The current position in the extra log file that is being read
#endif
  int __user *rp_ignore_flag_addr;      // Where the ignore flag is stored

  struct rvalues random_values;   // Tracks kernel randomness during syscalls (currently execve only)
  struct exec_values exec_values; // Track other exec-specifc values

  atomic_t *rp_precord_clock;     // Points to the recording clock in use
  u_long  rp_expected_clock;      // Used for delta clock

  char rp_ulog_opened;    // Flag that says whether or not the user log has been opened
  char rp_klog_opened;    // Flag that says whether or not the kernel log has been opened
  char ahg_rp_log_opened;   // Flag that says whether or not the ahg log has been opened
  loff_t rp_read_ulog_pos;  // The current position in the ulog file that is being read
  struct repsignal_context *rp_repsignal_context_stack;  // Saves replay context on signal delivery
  u_long rp_record_hook;          // Used for dumbass linking in glibc
  struct repsignal *rp_signals;   // Stores delayed signals
  struct repsignal *rp_last_signal; // Points to last signal recorded for this process

#define RECORD_FILE_SLOTS 1024
  loff_t prev_file_version[RECORD_FILE_SLOTS];

#ifdef TRACE_READ_WRITE
  struct replayfs_filemap recorded_filemap[RECORD_FILE_SLOTS];
  char recorded_filemap_valid[RECORD_FILE_SLOTS];
#endif

#ifdef CACHE_READS
  struct record_cache_files *rp_cache_files; // Info about open cache files
#endif
#ifdef LOG_COMPRESS
  struct clog_struct rp_clog;   // additional parameters used by compressed log
#endif
};

#define REPLAY_STATUS_RUNNING         0 // I am the running thread - should only be one of these per group
#define REPLAY_STATUS_ELIGIBLE        1 // I could run now
#define REPLAY_STATUS_WAIT_CLOCK      2 // Cannot run because waiting for an event
#define REPLAY_STATUS_DONE            3 // Exiting

#define REPLAY_PIN_TRAP_STATUS_NONE 0  // Not handling any sort of extra Pin SIGTRIP
#define REPLAY_PIN_TRAP_STATUS_EXIT 1  // I was waiting for a syscall exit, but was interrupted by a Pin SIGTRAP
#define REPLAY_PIN_TRAP_STATUS_ENTER  2  // I was waiting for a syscall enter, but was interrupted by a Pin SIGTRAP

// This has replay thread specific data
struct replay_thread
{
  struct replay_group *rp_group; // Points to replay group
  struct replay_thread *rp_next_thread; // Circular replay thread list
  struct record_thread *rp_record_thread; // Points to record thread

  atomic_t rp_refcnt;            // Reference count for this object
  pid_t rp_replay_pid;           // Pid of replaying task (0 if not set)
  u_long rp_out_ptr;             // Next record to read
  short rp_replay_exit;          // Set after a rollback
  u_char rp_signals;             // Set if sig should be delivered
  u_long app_syscall_addr;       // Address in user-land that is set when the syscall should be replayed

  int rp_status;                  // One of the replay statuses above
  u_long rp_wait_clock;           // Valid if waiting for kernel or user-level clock according to rp_status
  u_long rp_stop_clock_skip;      // Temporary storage while processing syscall
  wait_queue_head_t rp_waitq;     // Waiting on this queue if in one of the waiting states

  long rp_saved_rc;               // Stores syscall result when blocking in syscall conflicts with a pin lock
  char *rp_saved_retparams;       // Stores syscall results when blocking in syscall conflicts with a pin lock
  struct syscall_result *rp_saved_psr; // Stores syscall info when blocking in syscall conflicts with a pin lock
  struct rvalues random_values;   // Tracks kernel randomness during syscalls (currently execve only)
  struct exec_values exec_values; // Track other exec-specifc values

  u_long *rp_preplay_clock;       // Points to the replay clock in use
  u_long  rp_expected_clock;      // Used for delta clock
  struct list_head rp_sysv_list;  // List of mappings from replay SYSV IDs to reocrd SYSV IDs
  struct list_head rp_sysv_shms;  // List of SYSV shared memory segments for this process/thread
  u_long rp_replay_hook;          // Used for dumbass linking in glibc

  const char *rp_exec_filename;   // Used during execve to pass same arguments as recording (despite use of cache file)
  int rp_pin_restart_syscall; // Used to see if we should restart a syscall because of Pin
  u_long rp_start_clock_save; // Save the value of the start clock to resume after Pin returns back
  u_long rp_stop_clock_save;  // Save the value of the stop clock to resume after Pin returns back
  u_long argv;      // Save the location of the program args
  int argc;     // Save the number of program args
  u_long envp;      // Save the location of the env. vars
  int envc;     // Save the number of environment vars
  int is_pin_vfork;   // Set 1 when Pin calls clone instead of vfork
#ifdef CACHE_READS
  struct replay_cache_files *rp_cache_files; // Info about open cache files
#endif
};

/* Prototypes */
struct file *init_log_write(struct record_thread *prect, loff_t *ppos, int *pfd);

void term_log_write(struct file *file, int fd);
int read_log_data(struct record_thread *prt);
int read_log_data_internal(struct record_thread *prect, struct syscall_result *psr, int logid, int *syscall_count, loff_t *pos);
static ssize_t write_log_data(struct file *file, loff_t *ppos, struct record_thread *prect, struct syscall_result *psr, int count, bool isAhg);
#ifdef LOG_COMPRESS_1
struct file *init_clog_write(struct record_thread *prect, loff_t *ppos, int *pfd);
void term_clog_write(struct file *file, int fd);
int read_clog_data(struct record_thread *prt);
int read_clog_data_internal(struct record_thread *prect, struct syscall_result *psr, int logid, int *syscall_count, loff_t *pos);
static ssize_t write_clog_data(struct file *file, loff_t *ppos, struct record_thread *prect, struct syscall_result *psr, int count);
#endif
static void destroy_record_group(struct record_group *prg);
static void destroy_replay_group(struct replay_group *prepg);
static void __destroy_replay_thread(struct replay_thread *prp);
static void argsfreeall(struct record_thread *prect);
#ifdef LOG_COMPRESS_1
static void clogfreeall(struct record_thread *prect);
#endif
void write_begin_log(struct file *file, loff_t *ppos, struct record_thread *prect);
static void write_and_free_kernel_log(struct record_thread *prect);
//Yang
//static void ahg_write_and_free_kernel_log(struct record_thread *prect);
void write_mmap_log(struct record_group *prg);
long read_mmap_log(struct record_group *prg);
//static int add_sysv_mapping (struct replay_thread* prt, int record_id, int replay_id);
//static int find_sysv_mapping (struct replay_thread* prt, int record_id);
static void delete_sysv_mappings(struct replay_thread *prt);
#ifdef WRITE_ASYNC
//static void write_and_free_kernel_log_async(struct record_thread *prect);
static void write_and_free_handler(struct work_struct *work);
#endif
static int record_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs);
static int replay_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs);
static asmlinkage long replay_poll(struct pollfd __user *ufds, unsigned int nfds, long timeout_msecs);

/* Return values for complex system calls */
struct gettimeofday_retvals
{
  short           has_tv;
  short           has_tz;
  struct timeval  tv;
  struct timezone tz;
};

struct pselect6_retvals
{
  char            has_inp;
  char            has_outp;
  char            has_exp;
  char            has_tsp;
  fd_set          inp;
  fd_set          outp;
  fd_set          exp;
  struct timespec tsp;
};

struct generic_socket_retvals
{
  int call;
};

// mcc: This should probably be fixed since it allocated an extra 4 bytes
struct accept_retvals
{
  int call;
  int addrlen;
  char addr; // Variable length buffer follows
};

struct socketpair_retvals
{
  int call;
  int sv0;
  int sv1;
};

struct recvfrom_retvals
{
  int call;
  struct sockaddr addr;
  int addrlen;
  char buf;  // Variable length buffer follows
};

struct recvmsg_retvals
{
  int          call;
  int          msg_namelen;
  long         msg_controllen;
  unsigned int msg_flags;
};
// Followed by msg_namelen bytes of msg_name, msg_controllen bytes of msg_control and rc of data

struct getsockopt_retvals
{
  int call;
  int optlen;
  char optval; // Variable length buffer follows
};

// retvals for shmat, since we need to save additional information
struct shmat_retvals
{
  u_long len; // For generic length field
  int    call; // Currently needed for PIN memory allocation - would like to eliminate
  u_long size;
  u_long raddr;
};

// retvals for mmap_pgoff - needed to find cached files for non-COW filesystems
struct mmap_pgoff_retvals
{
  dev_t           dev;
  u_long          ino;
  struct timespec mtime;
};

static inline void
get_replay_group(struct replay_group *prg)
{
  atomic_inc(&prg->rg_refcnt);
}

static inline void
put_replay_group(struct replay_group *prg)
{
  DPRINT("put_replay_group %p refcnt %d\n", prg, atomic_read(&prg->rg_refcnt));
  if (atomic_dec_and_test(&prg->rg_refcnt))
    destroy_replay_group(prg);
}

static inline void
get_record_group(struct record_group *prg)
{
  atomic_inc(&prg->rg_refcnt);
}

static inline void
put_record_group(struct record_group *prg)
{
  if (atomic_dec_and_test(&prg->rg_refcnt)) destroy_record_group(prg);
}

static inline int
test_app_syscall(int number)
{
  struct replay_thread *prt = current->replay_thrd;
  //TPRINT("[%s|%d] pid %d, syscall %d, app_syscall_addr %lx, value %d\n", __func__,__LINE__,current->pid,number,
  // prt->app_syscall_addr,(prt->app_syscall_addr <=1)?-1:*(int*)(prt->app_syscall_addr));
  if (prt->app_syscall_addr == 1) return 0; // PIN not yet attached
  return (prt->app_syscall_addr == 0) || (*(int *)(prt->app_syscall_addr) == number);
}

static inline int
is_pin_attached(void)
{
  TPRINT("[%s|%d] pid %d, app_syscall_addr %lx\n", __func__, __LINE__, current->pid, current->replay_thrd->app_syscall_addr);
  return current->replay_thrd->app_syscall_addr != 0;
}

#ifdef USE_HPC
static inline long long rdtsc(void)
{
  union
  {
    struct
    {
      unsigned int l;  /* least significant word */
      unsigned int h;  /* most significant word */
    } w32;
    unsigned long long w64;
  } v;
  __asm __volatile(".byte 0xf; .byte 0x31     # RDTSC instruction"
                   : "=a"(v.w32.l), "=d"(v.w32.h) :);
  return v.w64;
}
#endif

void print_memory_areas(void)
{
  struct vm_area_struct *existing_mmap;
  if (current->mm)
  {
    existing_mmap = current->mm->mmap;
  }
  else
  {
    existing_mmap = NULL;
  }
  TPRINT("Pid %d let's print out the memory mappings:\n", current->pid);
  while (existing_mmap)
  {
    // vm_area's are a singly-linked list
    TPRINT("  addr: %#lx, len %lu\n", existing_mmap->vm_start, existing_mmap->vm_end - existing_mmap->vm_start);
    existing_mmap = existing_mmap->vm_next;
  }
}

// Cannot unlink shared path page when a replay group is deallocated, so we queue the work up for later
struct replay_paths_to_free
{
  char path[MAX_LOGDIR_STRLEN + 1]; // path to deallocate
  struct replay_paths_to_free *next;
};
static struct replay_paths_to_free *paths_to_free = NULL;
DEFINE_MUTEX(paths_to_free_mutex);

/* Creates a new clock for a record group */
static int
create_shared_clock(struct record_group *prg)
{
  u_long uaddr;
  long fd, rc;
  mm_segment_t old_fs = get_fs();
  struct replay_paths_to_free *ptmp;

  set_fs(KERNEL_DS);
  mutex_lock(&paths_to_free_mutex);
  while (paths_to_free)
  {
    ptmp = paths_to_free;
    paths_to_free = ptmp->next;
    fd = sys_unlink(ptmp->path);
    KFREE(ptmp);
  }
  mutex_unlock(&paths_to_free_mutex);

  snprintf(prg->rg_shmpath, MAX_LOGDIR_STRLEN + 1, "/dev/shm/uclock%d", current->pid);
  fd = sys_open(prg->rg_shmpath, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW, 0644);
  if (fd < 0)
  {
    pr_err("create_shared_clock: pid %d cannot open shared file %s, rc=%ld\n", current->pid, prg->rg_shmpath, fd);
    goto out_oldfs;
  }

  rc = sys_ftruncate(fd, 4096);
  if (rc < 0)
  {
    pr_err("create_shared_clock: pid %d cannot create new shm page, rc=%ld\n", current->pid, rc);
    goto out_close;
  }

  uaddr = sys_mmap_pgoff(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (IS_ERR((void *) uaddr))
  {
    pr_err("create_shared_clock: pid %d cannot map shm page, rc=%ld\n", current->pid, PTR_ERR((void *) uaddr));
    goto out_close;
  }

  rc = get_user_pages(current, current->mm, uaddr, 1, 1, 0, &prg->rg_shared_page, NULL);
  if (rc != 1)
  {
    pr_err("creare_shared_clock: pid %d cannot get shm page, rc=%ld\n", current->pid, rc);
    goto out_unmap;
  }

  prg->rg_pkrecord_clock = (atomic_t *) kmap(prg->rg_shared_page);
  DPRINT("record/replay clock is at %p\n", prg->rg_pkrecord_clock);

  rc = sys_munmap(uaddr, 4096);
  if (rc < 0) pr_err("create_shared_clock: pid %d cannot munmap shared page, rc=%ld\n", current->pid, rc);

  rc = sys_close(fd);
  if (rc < 0) pr_err("create_shared_clock: pid %d cannot close shared file %s, rc=%ld\n", current->pid, prg->rg_shmpath, rc);

  return 0;

out_unmap:
  sys_munmap(uaddr, 4096);
out_close:
  sys_close(fd);
  sys_unlink(prg->rg_shmpath);
out_oldfs:
  set_fs(old_fs);

  return -1;
}

static void
recycle_shared_clock(char *path)
{
  struct replay_paths_to_free *pnew;

  mutex_lock(&paths_to_free_mutex);
  pnew = KMALLOC(sizeof(struct replay_paths_to_free), GFP_KERNEL);
  if (pnew == NULL)
  {
    TPRINT("Cannot alloc memory to queue freed path\n");
  }
  else
  {
    strncpy_safe(pnew->path, path, MAX_LOGDIR_STRLEN);
    pnew->next = paths_to_free;
    paths_to_free = pnew;
  }
  mutex_unlock(&paths_to_free_mutex);
}

#ifdef CACHE_READS
static struct record_cache_files *
init_record_cache_files(void)
{
  struct record_cache_files *pfiles;
  int i;

  pfiles = KMALLOC(sizeof(struct record_cache_files), GFP_KERNEL);
  if (pfiles == NULL)
  {
    TPRINT("init_record_cache_files: cannot allocate struct\n");
    return NULL;
  }

  atomic_set(&pfiles->refcnt, 1);
  init_rwsem(&pfiles->sem);
  pfiles->count = INIT_RECPLAY_CACHE_SIZE;
  pfiles->list = KMALLOC(sizeof(struct record_cache_chunk), GFP_KERNEL);
  if (pfiles->list == NULL)
  {
    TPRINT("init_record_cache_files: cannot allocate list\n");
    KFREE(pfiles);
    return NULL;
  }
  pfiles->list->count = INIT_RECPLAY_CACHE_SIZE;
  pfiles->list->next = NULL;
  pfiles->list->data = KMALLOC(INIT_RECPLAY_CACHE_SIZE * sizeof(struct record_cache_data), GFP_KERNEL);
  if (pfiles->list->data == NULL)
  {
    TPRINT("init_record_cache_files: cannot allocate data\n");
    KFREE(pfiles);
    return NULL;
  }
  for (i = 0; i < INIT_RECPLAY_CACHE_SIZE; i++)
  {
    mutex_init(&pfiles->list->data[i].mutex);
    pfiles->list->data[i].is_cache_file = 0;
  }

  return pfiles;
}

static void
get_record_cache_files(struct record_cache_files *pfiles)
{
  atomic_inc(&pfiles->refcnt);
}

static void
put_record_cache_files(struct record_cache_files *pfiles)
{
  struct record_cache_chunk *pchunk;

  if (atomic_dec_and_test(&pfiles->refcnt))
  {
    pfiles->count = 0;
    while (pfiles->list)
    {
      pchunk = pfiles->list;
      pfiles->list = pchunk->next;
      KFREE(pchunk->data);
      KFREE(pchunk);
    }
    KFREE(pfiles);
  }
}

static int
is_record_cache_file_lock(struct record_cache_files *pfiles, int fd)
{
  struct record_cache_chunk *pchunk;
  int rc = 0;

  down_read(&pfiles->sem);
  if (fd < pfiles->count)
  {
    pchunk = pfiles->list;
    while (fd >= pchunk->count)
    {
      fd -= pchunk->count;
      pchunk = pchunk->next;
    }
    if (pchunk->data[fd].is_cache_file)
    {
      mutex_lock(&pchunk->data[fd].mutex);  /* return locked */
      rc = 1;
    }
  }
  up_read(&pfiles->sem);

  return rc;
}

static int
is_record_cache_file(struct record_cache_files *pfiles, int fd)
{
  struct record_cache_chunk *pchunk;
  int rc = 0;

  down_read(&pfiles->sem);
  if (fd < pfiles->count)
  {
    pchunk = pfiles->list;
    while (fd >= pchunk->count)
    {
      fd -= pchunk->count;
      pchunk = pchunk->next;
    }
    if (pchunk->data[fd].is_cache_file) rc = 1;
  }
  up_read(&pfiles->sem);

  return rc;
}

static void
record_cache_file_unlock(struct record_cache_files *pfiles, int fd)
{
  struct record_cache_chunk *pchunk;

  down_read(&pfiles->sem);
  pchunk = pfiles->list;
  while (fd >= pchunk->count)
  {
    fd -= pchunk->count;
    pchunk = pchunk->next;
  }
  mutex_unlock(&pchunk->data[fd].mutex);
  up_read(&pfiles->sem);
}

static int
set_record_cache_file(struct record_cache_files *pfiles, int fd)
{
  struct record_cache_chunk *tmp, *pchunk;
  int newcount, chunkcount;
  int i;

  down_write(&pfiles->sem);
  if (fd >= pfiles->count)
  {
    newcount = pfiles->count;
    while (fd >= newcount) newcount *= 2;
    chunkcount = newcount - pfiles->count;
    tmp = KMALLOC(sizeof(struct record_cache_chunk), GFP_KERNEL);
    if (tmp == NULL)
    {
      TPRINT("set_record_cache_files: cannot allocate list\n");
      up_write(&pfiles->sem);
      return -ENOMEM;
    }
    tmp->data = KMALLOC(chunkcount * sizeof(struct record_cache_data), GFP_KERNEL);
    if (tmp->data == NULL)
    {
      TPRINT("set_cache_file: cannot allocate new data buffer of size %lu\n", chunkcount * sizeof(struct record_cache_data));
      KFREE(tmp);
      up_write(&pfiles->sem);
      return -ENOMEM;
    }
    for (i = 0; i < chunkcount; i++)
    {
      mutex_init(&tmp->data[i].mutex);
      tmp->data[i].is_cache_file = 0;
    }
    pchunk = pfiles->list;
    while (pchunk->next != NULL) pchunk = pchunk->next;
    pchunk->next = tmp;
    tmp->count = chunkcount;
    tmp->next = NULL;
    pfiles->count = newcount;
  }
  pchunk = pfiles->list;
  while (fd >= pchunk->count)
  {
    fd -= pchunk->count;
    pchunk = pchunk->next;
  }
  pchunk->data[fd].is_cache_file = 1;
  up_write(&pfiles->sem);

  return 0;
}

static void
copy_record_cache_files(struct record_cache_files *pfrom, struct record_cache_files *pto)
{
  struct record_cache_chunk *pchunk;
  int i, fd = 0;

  down_read(&pfrom->sem);
  pchunk = pfrom->list;
  while (pchunk)
  {
    for (i = 0; i < pchunk->count; i++)
    {
      if (pchunk->data[i].is_cache_file)
      {
        set_record_cache_file(pto, fd);
      }
      fd++;
    }
    pchunk = pchunk->next;
  }
  up_read(&pfrom->sem);
}

static void
clear_record_cache_file(struct record_cache_files *pfiles, int fd)
{
  struct record_cache_chunk *pchunk;

  down_read(&pfiles->sem);
  if (fd < pfiles->count)
  {
    pchunk = pfiles->list;
    while (fd >= pchunk->count)
    {
      fd -= pchunk->count;
      pchunk = pchunk->next;
    }
    pchunk->data[fd].is_cache_file = 0;
  }
  up_read(&pfiles->sem);
}

static void
close_record_cache_files(struct record_cache_files *pfiles)
{
  struct record_cache_chunk *pchunk;
  int i;

  down_read(&pfiles->sem);
  pchunk = pfiles->list;
  while (pchunk)
  {
    for (i = 0; i < pchunk->count; i++)
    {
      pchunk->data[i].is_cache_file = 0;
    }
    pchunk = pchunk->next;
  }
  up_read(&pfiles->sem);
}

static struct replay_cache_files *
init_replay_cache_files(void)
{
  struct replay_cache_files *pfiles;
  int i;

  pfiles = KMALLOC(sizeof(struct replay_cache_files), GFP_KERNEL);
  if (pfiles == NULL)
  {
    TPRINT("init_replay_cache_files: cannot allocate struct\n");
    return NULL;
  }
  atomic_set(&pfiles->refcnt, 1);
  pfiles->count = INIT_RECPLAY_CACHE_SIZE;
  pfiles->data = KMALLOC(INIT_RECPLAY_CACHE_SIZE * sizeof(int), GFP_KERNEL);
  if (pfiles->data == NULL)
  {
    TPRINT("init_replay_cache_files: cannot allocate data\n");
    return NULL;
  }
  for (i = 0; i < INIT_RECPLAY_CACHE_SIZE; i++) pfiles->data[i] = -1;

  return pfiles;
}

static void
get_replay_cache_files(struct replay_cache_files *pfiles)
{
  atomic_inc(&pfiles->refcnt);
}

static void
put_replay_cache_files(struct replay_cache_files *pfiles)
{
  if (atomic_dec_and_test(&pfiles->refcnt))
  {
    pfiles->count = 0;
    KFREE(pfiles->data);
  }
}

static int
is_replay_cache_file(struct replay_cache_files *pfiles, int fd, int *cache_fd)
{
  if (fd < 0 || fd >= pfiles->count) return 0;
  *cache_fd = pfiles->data[fd];
  return (pfiles->data[fd] >= 0);
}

static int
set_replay_cache_file(struct replay_cache_files *pfiles, int fd, int cache_fd)
{
  int newcount;
  int *tmp;
  int i;

  if (fd >= pfiles->count)
  {
    newcount = pfiles->count;
    while (fd >= newcount) newcount *= 2;
    tmp = KMALLOC(newcount * sizeof(int), GFP_KERNEL);
    if (tmp == NULL)
    {
      TPRINT("set_cache_file: cannot allocate new data buffer of size %d\n", newcount);
      return -ENOMEM;
    }
    for (i = 0; i < pfiles->count; i++) tmp[i] = pfiles->data[i];
    for (i = pfiles->count; i < newcount; i++) tmp[i] = -1;
    KFREE(pfiles->data);
    pfiles->data = tmp;
    pfiles->count = newcount;
  }
  pfiles->data[fd] = cache_fd;
  return 0;
}

static void
copy_replay_cache_files(struct replay_cache_files *pfrom, struct replay_cache_files *pto)
{
  int i;

  for (i = pfrom->count - 1; i >= 0; i--) // Backward makes allocation in set efficient
  {
    if (pfrom->data[i] != -1)
    {
      set_replay_cache_file(pto, i, pfrom->data[i]);
    }
  }
}

static void
clear_replay_cache_file(struct replay_cache_files *pfiles, int fd)
{
  if (fd < pfiles->count) pfiles->data[fd] = -1;
}

static void
close_replay_cache_files(struct replay_cache_files *pfiles)
{
  int i;

  for (i = 0; i < pfiles->count; i++)
  {
    pfiles->data[i] = -1;
  }
}

#endif


//xdou
#ifdef TIME_TRICK

#define DET_TIME_STRUCT_REC current->record_thrd->rp_group->rg_det_time
#define DET_TIME_STRUCT_REP current->replay_thrd->rp_record_thread->rg_group

inline void add_fake_time(long nsec, struct record_group *prg)
{
  prg->rg_det_time.last_fake_nsec_accum += nsec;
  if (prg->rg_det_time.last_fake_nsec_accum >= 1000000000)
  {
    prg->rg_det_time.last_fake_nsec_accum -= 1000000000;
    ++ prg->rg_det_time.last_fake_sec_accum;
  }
}

inline void add_fake_time_syscall(struct record_group *prg)
{
  // prg->rg_det_time.syscall_count += (atomic_read (prg->rg_pkrecord_clock) - prg->rg_det_time.syscall_count);
  //++ prg->rg_det_time.syscall_count;
}

#endif

//long clock_predict = 0;
static int c_detail = 0;
#define log_compress_debug 0

#ifdef LOG_COMPRESS
inline void pipe_fds_init(struct pipe_fds *fds, int size)
{
  //TPRINT("init pipe fds.\n");
  //fds = kmalloc(sizeof(struct pipe_fds), GFP_KERNEL);
  //if(fds == NULL)
  //  TPRINT("pipe fds init fails.\n");
  if (fds->fds)
    kfree(fds->fds);
  fds->fds = kmalloc(sizeof(int) * size * 2, GFP_KERNEL);
  fds->length = 0;
  fds->size = size;
  mutex_init(&fds->lock);
}



inline struct pipe_fds *pipe_fds_clone(struct pipe_fds *fds)
{
  struct pipe_fds *ret = kmalloc(sizeof(struct pipe_fds), GFP_KERNEL);
  mutex_lock(&fds->lock);
  TPRINT("clone.\n");
  ret->length = fds->length;
  ret->size = fds->size;
  ret->fds = kmalloc(sizeof(int) * fds->size * 2, GFP_KERNEL);
  memcpy(ret->fds, fds->fds, sizeof(int)*fds->size * 2);
  mutex_unlock(&fds->lock);
  return ret;
}

inline void pipe_fds_free(struct pipe_fds *fds)
{
  mutex_lock(&fds->lock);
  if (fds == NULL)
  {
    mutex_unlock(&fds->lock);
    return;
  }
  if (fds->fds == NULL)
  {
    mutex_unlock(&fds->lock);
    return;
  }
  kfree(fds->fds);
  mutex_unlock(&fds->lock);
  //kfree(fds);
}

inline void pipe_fds_insert(struct pipe_fds *fds, int *file)
{
  int *tmp;
  mutex_lock(&fds->lock);
  fds->fds[fds->length * 2] = file[0];
  fds->fds[fds->length * 2 + 1] = file[1];
  ++fds->length;
  if (fds->length == fds->size)
  {
    fds->size *= 2;
    tmp = kmalloc(sizeof(int) * 2 * fds->size, GFP_KERNEL);
    memcpy(tmp, fds->fds, fds->size * sizeof(int));
    kfree(fds->fds);
    fds->fds = tmp;
  }
  mutex_unlock(&fds->lock);
}

inline int pipe_fds_lookup(struct pipe_fds *fds, int fd)
{
  int i = 0;
  for (; i < fds->length * 2; ++i)
  {
    if (fds->fds[i] == fd)
    {
      //TPRINT("Find a pipe fd.\n");
      return 1;
    }
  }
  return 0;
}

inline int pipe_fds_delete(struct pipe_fds *fds, int fd)
{
  int i = 0;
  for (; i < fds->length * 2; ++i)
  {
    //TODO
  }
  return 0;
}

inline void pipe_fds_copy(struct pipe_fds *to, struct pipe_fds *from)
{
  mutex_lock(&from->lock);
  TPRINT("free old pipe_fds.\n");
  pipe_fds_free(to);
  TPRINT("copy pipe_fds_map.\n");
  to->length = from->length;
  to->size = from->size;
  to->fds = kmalloc(sizeof(int) * from->size * 2, GFP_KERNEL);
  memcpy(to->fds, from->fds, sizeof(int)*from->size * 2);
  mutex_unlock(&from->lock);
}

static void inline init_clog_struct(struct clog_struct *clog)
{
  init_x_comp(&clog->x);

  clog->done = 0;
  clog->args_size = 0;
  clog->clock_predict = 0;
  //clog->pfds = NULL;

  clog->pfds.fds = NULL;
  pipe_fds_init(&clog->pfds, 8);
  /*clog->fd_map_table[0] = 0;
  clog->fd_map_table[1] = 1;
  clog->fd_map_table[2] = 2;
  for (i = 3; i < 1024; ++i)
    clog->fd_map_table[i] = -1;
  */
  init_syscall_cache(&clog->syscall_cache);
  status_init(&clog->syscall_status);
  //clog->time.flag = 1;
  //TPRINT ("Pid %d init_clog_struct.\n", current->pid);
}

inline int is_x_socket(unsigned long *a)
{
  //to decide whether the socket is for x server
  struct sockaddr tmp;
  struct sockaddr_in *tmp2;
  int result = 0;

  if (x_detail) 
    TPRINT("Pid %d connect:%s,%lu, %d\n", current->pid, ((char *)(a[1])) + 3, a[2], tmp.sa_family);
  if (strstr(((char *)(a[1])) + 3, "tmp/.X11-unix/X") != NULL)
  {
    TPRINT("Pid %d connect to the x server. socket fd:%lu\n", current->pid, a[0]);
    result = 1;
  }
  else
  {
    tmp2 = (struct sockaddr_in *)(a[1]);
    if (x_detail) 
      TPRINT("connect2: port:%u, addr:%u\n", tmp2->sin_port, tmp2->sin_addr.s_addr);
    if ((tmp2->sin_port == htons(6010)) && tmp2->sin_addr.s_addr == in_aton("127.0.0.1"))
    {
      if (x_detail) TPRINT("connect2 to the x server.\n");
      result = 1;
    }
  }

  return result;
}



inline int is_regular_file(unsigned int fd)
{
  struct files_struct *files = current->files;
  struct file *file;
  /* xdou
   * test if this file is a regular file
   */
  if ((int)fd < 0)
    return 0;
  rcu_read_lock();
  file = fcheck_files(files, fd);
  if (file)
  {
    if (!atomic64_inc_not_zero(&file->f_count))
    {
      rcu_read_unlock();
      return 0;
    }
    if (S_ISREG(file->f_dentry->d_inode->i_mode) || S_ISLNK(file->f_dentry->d_inode->i_mode))
    {
      rcu_read_unlock();
      return 1;
    }
    //if(S_ISFIFO(file->f_dentry->d_inode->i_mode))
    //    TPRINT("Find a FIFO, fd:%d\n", fd);
  }
  else
  {
    TPRINT("error:fd not exist.%u\n", fd);
  }
  rcu_read_unlock();
  /*if(pipe_fds_lookup(&current->replay_thrd->rp_record_thread->pfds, fd) == 1)
  {
    return 1;
  }*/
  return 0;
}

inline void
change_log_special(void)
{
  struct syscall_result *psr;
  struct record_thread *prt = current->record_thrd;
  psr = &prt->rp_log[prt->rp_in_ptr];
  psr->flags |= SR_HAS_SPECIAL_FIRST;
}

inline void
change_log_special_second(void)
{
  struct syscall_result *psr;
  struct record_thread *prt = current->record_thrd;
  psr = &prt->rp_log[prt->rp_in_ptr];
  psr->flags |= SR_HAS_SPECIAL_SECOND;
}

//Yang
/*
inline void
change_log_special_third(void)
{
  struct syscall_result* psr;
  struct record_thread* prt = current->record_thrd;
  psr = &prt->rp_log[prt->rp_in_ptr];
  psr->flags |= SR_HAS_SPECIAL_THIRD;
}
*/
inline void init_evs(void)
{
#ifdef MULTI_GROUP
  struct shmat_rec_merge *tmp_rec = NULL;
  struct shmat_rep_merge *tmp_rep = NULL;
  pid_t *tmp_pid = NULL;
#endif

#ifdef MULTI_GROUP
  if (test_thread_flag(TIF_RECORD))
  {
    if (shmat_rec_list != NULL)
    {
      while ((tmp_rec = ds_list_get_first(shmat_rec_list)) != NULL)
        KFREE(tmp_rec);
      ds_list_destroy(shmat_rec_list);
    }
    shmat_rec_list = ds_list_create(NULL, 0, 1);
  }
  else if (test_thread_flag(TIF_REPLAY))
  {
    if (shmat_rep_list != NULL)
    {
      while ((tmp_rep = ds_list_get_first(shmat_rep_list)) != NULL)
        KFREE(tmp_rep);
      ds_list_destroy(shmat_rep_list);
    }
    shmat_rep_list = ds_list_create(NULL, 0, 1);

  }
  if (forked_process_list != NULL)
  {
    while ((tmp_pid = ds_list_get_first(forked_process_list)) != NULL)
      KFREE(tmp_pid);
    ds_list_destroy(forked_process_list);
  }
  forked_process_list = ds_list_create(NULL, 0, 1);
#endif
  TPRINT("init_evs.\n");
}

inline long get_log_special(void)
{
  struct syscall_result *psr;
  struct record_thread *prt = current->replay_thrd->rp_record_thread;
  psr = &prt->rp_log[current->replay_thrd->rp_out_ptr - 1];
  BUG_ON(current->replay_thrd->rp_out_ptr == 0);
  return psr->flags & SR_HAS_SPECIAL_FIRST;
}

inline long get_log_special_second(void)
{
  struct syscall_result *psr;
  struct record_thread *prt = current->replay_thrd->rp_record_thread;
  psr = &prt->rp_log[current->replay_thrd->rp_out_ptr - 1];
  BUG_ON(current->replay_thrd->rp_out_ptr == 0);
  return psr->flags & SR_HAS_SPECIAL_SECOND;
}
#endif

/* Creates a new replay group for the replaying process info */
static struct replay_group *
new_replay_group(struct record_group *prec_group, int follow_splits, char *cache_dir)
{
  struct replay_group *prg;

  prg = KMALLOC(sizeof(struct replay_group), GFP_KERNEL);
  if (prg == NULL)
  {
    TPRINT("Cannot allocate replay_group\n");
    goto err;
  }
  DPRINT("new_replay_group: %p\n", prg);

  prg->rg_rec_group = prec_group;

  prg->rg_follow_splits = follow_splits;
  prg->rg_replay_threads = ds_list_create(NULL, 0, 1);
  if (prg->rg_replay_threads == NULL)
  {
    TPRINT("Cannot create replay_group rg_replay_threads\n");
    goto err_replaythreads;
  }

  atomic_set(&prg->rg_refcnt, 0);

  prg->rg_reserved_mem_list = ds_list_create(rm_cmp, 0, 1);
  prg->rg_used_address_list = NULL;

  strncpy_safe(prg->cache_dir, cache_dir, CACHE_FILENAME_SIZE);
  printk("prg->cache_dir: (%s)\n", prg->cache_dir);

  // Record group should not be destroyed before replay group
  get_record_group(prec_group);

#ifdef REPLAY_STATS
  atomic_inc(&rstats.started);
#endif

  return prg;

err_replaythreads:
  KFREE(prg);
err:
  return NULL;
}

/* Creates a new record group for the recording process info */
static struct record_group *
new_record_group(char *logdir)
{
  struct record_group *prg;

  MPRINT("Pid %d new_record_group: entered\n", current->pid);

  prg = KMALLOC(sizeof(struct record_group), GFP_KERNEL);
  if (prg == NULL)
  {
    TPRINT("Cannot allocate record_group\n");
    goto err;
  }

  if (logdir == NULL)
  {
    prg->rg_id = get_replay_id();

    if (prg->rg_id == 0)
    {
      TPRINT("Cannot get replay id\n");
      goto err_free;
    }
  }

#ifdef REPLAY_LOCK_DEBUG
  sema_init(&prg->rg_sem, 1);
#else
  mutex_init(&prg->rg_mutex);
#endif
  atomic_set(&prg->rg_refcnt, 0);

#ifdef TIME_TRICK
  mutex_init(&prg->rg_time_mutex);
#endif

  if (create_shared_clock(prg) < 0) goto err_free;

  if (logdir)
  {
    strncpy_safe(prg->rg_logdir, logdir, MAX_LOGDIR_STRLEN);
  }
  else
  {
    make_logdir_for_replay_id(prg->rg_id, prg->rg_logdir);
  }
  memset(prg->rg_linker, 0, MAX_LOGDIR_STRLEN + 1);

  prg->rg_mismatch_flag = 0;
  prg->rg_libpath = NULL;

  atomic_set(&prg->rg_record_threads, 0);
  prg->rg_save_mmap_flag = 0;
  prg->rg_reserved_mem_list = ds_list_create(rm_cmp, 0, 1);
  prg->rg_prev_brk = 0;

  MPRINT("Pid %d new_record_group %lld: exited\n", current->pid, prg->rg_id);
  //Yang: fill rg_id in task, so we can refer to this from signal.c
  current->rg_id = prg->rg_id;

  return prg;

err_free:
  KFREE(prg);
err:
  return NULL;
}

static void
destroy_replay_group(struct replay_group *prepg)
{
  struct replay_thread *prt;
  struct reserved_mapping *pmapping;

  MPRINT("Pid %d destroy replay group %p: enter\n", current->pid, prepg);

  // Destroy replay_threads list
  if (prepg->rg_replay_threads)
  {
    while (ds_list_count(prepg->rg_replay_threads))
    {
      prt = ds_list_first(prepg->rg_replay_threads);
      __destroy_replay_thread(prt);
    }
    ds_list_destroy(prepg->rg_replay_threads);
  }

  // Free all of the mappings
  while ((pmapping = ds_list_get_first(prepg->rg_reserved_mem_list)) != NULL)
  {
    KFREE(pmapping);
  }
  ds_list_destroy(prepg->rg_reserved_mem_list);

  if (is_pin_attached())
  {
    // And the used-address list (if it exists)
    if (prepg->rg_used_address_list)
    {
      while ((pmapping = ds_list_get_first(prepg->rg_used_address_list)) != NULL)
      {
        KFREE(pmapping);
      }
      ds_list_destroy(prepg->rg_used_address_list);
    }
  }

  // Put record group so it can be destroyed
  put_record_group(prepg->rg_rec_group);

  // Free the replay group
  KFREE(prepg);
#ifdef REPLAY_STATS
  atomic_inc(&rstats.finished);
#endif
  TPRINT("Goodbye, cruel lamp!  This replay is over\n");
  MPRINT("Pid %d destroy replay group %p: exit\n", current->pid, prepg);
}

// PARSPEC: eventually: want to make sure that all replay groups are destroyed
static void
destroy_record_group(struct record_group *prg)
{
  struct reserved_mapping *pmapping;

  MPRINT("Pid %d destroying record group %p\n", current->pid, prg);

#ifdef REPLAY_PAUSE
  if (replay_pause_tool)
  {
    atomic_set((prg->rg_pkrecord_clock + 1), 0);
    TPRINT("Pid %d clear up pause clock\n", current->pid);
  }
#endif

  kunmap(prg->rg_shared_page);
  put_page(prg->rg_shared_page);
  if (prg->rg_libpath) KFREE(prg->rg_libpath);

  // Free all of the mappings
  while ((pmapping = ds_list_get_first(prg->rg_reserved_mem_list)) != NULL)
  {
    KFREE(pmapping);
  }
  recycle_shared_clock(prg->rg_shmpath);
  ds_list_destroy(prg->rg_reserved_mem_list);

  KFREE(prg);
#ifdef REPLAY_PARANOID
  TPRINT("vmalloc cnt: %d\n", atomic_read(&vmalloc_cnt));
#endif
}

/* Creates a new record thread */
static struct record_thread *
new_record_thread(struct record_group *prg, u_long recpid, struct record_cache_files *pfiles)
{
  struct record_thread *prp;

  prp = KMALLOC(sizeof(struct record_thread), GFP_KERNEL);
  if (prp == NULL)
  {
    TPRINT("Cannot allocate record_thread\n");
    return NULL;
  }

  prp->rp_group = prg;
  prp->rp_next_thread = prp;

  atomic_set(&prp->rp_refcnt, 1);

  MPRINT("Pid %d creates new record thread: %p, recpid %lu\n", current->pid, prp, recpid);

  prp->rp_record_pid = recpid;
  prp->rp_clone_status = 0;
  prp->rp_sysrc = 0;

  // Recording log inits
  // mcc: current in-memory log segment; the log can be bigger than what we hold in memory,
  // so we just flush it out to disk when this log segment is full and reset the rp_in_ptr
  prp->rp_log = VMALLOC(sizeof(struct syscall_result) * syslog_recs);
  if (prp->rp_log == NULL)
  {
    KFREE(prp);
    return NULL;
  }

  prp->rp_in_ptr = 0;
  prp->rp_count = 0;
  prp->rp_read_log_pos = 0;
#ifdef LOG_COMPRESS_1
  prp->rp_read_clog_pos = 0;
#endif

  INIT_LIST_HEAD(&prp->rp_argsalloc_list);

#ifdef TRACE_READ_WRITE
  memset(prp->recorded_filemap_valid, 0, sizeof(char) * RECORD_FILE_SLOTS);
#endif
#ifdef LOG_COMPRESS_1
  INIT_LIST_HEAD(&prp->rp_clog_list);
#endif

  prp->rp_user_log_addr = 0;
#ifdef USE_EXTRA_DEBUG_LOG
  prp->rp_user_extra_log_addr = 0;
  prp->rp_elog_opened = 0;
  prp->rp_read_elog_pos = 0;
#endif
  prp->rp_ignore_flag_addr = NULL;

  prp->rp_precord_clock = prp->rp_group->rg_pkrecord_clock;
  prp->rp_expected_clock = 0;
  prp->rp_ulog_opened = 0;
  prp->rp_klog_opened = 0;
  prp->ahg_rp_log_opened = 0;
  prp->rp_read_ulog_pos = 0;
  prp->rp_repsignal_context_stack = NULL;
  prp->rp_record_hook = 0;
  prp->rp_signals = NULL;
  prp->rp_last_signal = NULL;

  atomic_inc(&prg->rg_record_threads);
#ifdef CACHE_READS
  if (pfiles)
  {
    prp->rp_cache_files = pfiles;
    get_record_cache_files(pfiles);
  }
  else
  {
    prp->rp_cache_files = init_record_cache_files();
    if (prp->rp_cache_files == NULL)
    {
      KFREE(prp->rp_log);
      KFREE(prp);
      return NULL;
    }
  }

  do
  {
    int i;
    for (i = 0; i < RECORD_FILE_SLOTS; i++)
    {
      prp->prev_file_version[i] = -1;
    }
  }
  while (0);
#endif

#ifdef LOG_COMPRESS
  //xdou
  prp->rp_ignore_flag_addr = NULL;
  init_clog_struct(&prp->rp_clog);
#endif
  get_record_group(prg);
  return prp;
}

/* Creates a new replay thread */
static struct replay_thread *
new_replay_thread(struct replay_group *prg, struct record_thread *prec_thrd, u_long reppid, u_long out_ptr, struct replay_cache_files *pfiles)
{
  struct replay_thread *prp = KMALLOC(sizeof(struct replay_thread), GFP_KERNEL);
  if (prp == NULL)
  {
    TPRINT("Cannot allocate replay_thread\n");
    return NULL;
  }

  MPRINT("New replay thread %p prg %p reppid %ld\n", prp, prg, reppid);

  prp->app_syscall_addr = 0;

  prp->rp_group = prg;
  prp->rp_next_thread = prp;
  prp->rp_record_thread = prec_thrd;

  atomic_set(&prp->rp_refcnt, 1);
  prp->rp_replay_pid = reppid;
  prp->rp_out_ptr = out_ptr;
  prp->rp_replay_exit = 0;
  prp->rp_signals = 0;
  prp->rp_saved_psr = NULL;
  prp->rp_status = REPLAY_STATUS_ELIGIBLE; // We should be able to run immediately
  init_waitqueue_head(&prp->rp_waitq);

  // Increment the refcnt of the record thread so the log isn't
  // deallocated when the record thread's done
  atomic_inc(&prp->rp_record_thread->rp_refcnt);
  MPRINT(" refcnt for record_thread %p pid %d now %d\n",
         prp->rp_record_thread,
         prp->rp_record_thread->rp_record_pid,
         atomic_read(&prp->rp_record_thread->rp_refcnt));

  ds_list_append(prg->rg_replay_threads, prp);

  prp->rp_preplay_clock = (u_long *) prp->rp_group->rg_rec_group->rg_pkrecord_clock;
  prp->rp_expected_clock = 0;
  INIT_LIST_HEAD(&prp->rp_sysv_list);
  INIT_LIST_HEAD(&prp->rp_sysv_shms);

  prp->rp_pin_restart_syscall = 0;
  prp->rp_start_clock_save = 0;
  prp->rp_replay_hook = 0;

  prp->is_pin_vfork = 0;

#ifdef CACHE_READS
  if (pfiles)
  {
    prp->rp_cache_files = pfiles;
    get_replay_cache_files(pfiles);
  }
  else
  {
    prp->rp_cache_files = init_replay_cache_files();
    if (prp->rp_cache_files == NULL)
    {
      KFREE(prp);
      return NULL;
    }
  }
#endif

  get_replay_group(prg);

  return prp;
}

/* Deallocates record per-thread data and per-process data if refcnt = 0 */
static void
__destroy_record_thread(struct record_thread *prp)
{
  struct record_thread *prev;
  struct repsignal *psig;

  DPRINT("      Pid %d __destroy_record_thread: %p\n", current->pid, prp);

  if (!atomic_dec_and_test(&prp->rp_refcnt))
  {
    MPRINT("        pid %d don't destroy record thread! pid = %d, prp = %p, refcnt=%d\n",
           current->pid, prp->rp_record_pid, prp, atomic_read(&prp->rp_refcnt));
    return;
  }

  MPRINT("        pid %d !YES! destroy record thread! pid = %d, prp = %p, refcnt=%d\n",
         current->pid, prp->rp_record_pid, prp, atomic_read(&prp->rp_refcnt));

  DPRINT(" destroy_record_thread freeing log %p: start\n", prp->rp_log);
  argsfreeall(prp);
  VFREE(prp->rp_log);
  DPRINT("       destroy_record_thread freeing log %p: end\n", prp->rp_log);

  while (prp->rp_signals)
  {
    psig = prp->rp_signals;
    prp->rp_signals = psig->next;
    KFREE(psig);
  }

  for (prev = prp; prev->rp_next_thread != prp;
       prev = prev->rp_next_thread);
  prev->rp_next_thread = prp->rp_next_thread;

  put_record_cache_files(prp->rp_cache_files);

  put_record_group(prp->rp_group);

#ifdef LOG_COMPRESS_1
  clogfreeall(prp);
  int bitsin, bitsout;
  TPRINT("Pid %d compresssion summary:\n", current->pid);
  status_summarize(&prp->rp_clog.syscall_status, &bitsin, &bitsout);
  TPRINT("Pid %d compression saves %d bytes.\n", current->pid, (bitsin - bitsout) / 8);
#endif
#ifdef LOG_COMPRESS
  free_syscall_cache(&prp->rp_clog.syscall_cache);
  pipe_fds_free(&prp->rp_clog.pfds);
  free_x_comp(&prp->rp_clog.x);
#endif
  KFREE(prp);
  MPRINT("      Pid %d __destroy_record_thread: exit!\n", current->pid);
}

/* Deallocates replay per-thread data and per-process data iff refcnt
 * is 0.  Call with rg_lock held. */
void
__destroy_replay_thread(struct replay_thread *prp)
{
  struct replay_thread *prev;

  MPRINT("  Pid %d enters destroy_replay_thread: pid %d, prp = %p, refcnt=%d\n",
         current->pid, prp->rp_replay_pid, prp, atomic_read(&prp->rp_refcnt));

  if (!atomic_dec_and_test(&prp->rp_refcnt))
  {
    DPRINT("  -> pid %d don't destroy replay prp = %p, refcnt=%d!!\n",
           current->pid, prp, atomic_read(&prp->rp_refcnt));
    return;
  }

  for (prev = prp; prev->rp_next_thread != prp; prev = prev->rp_next_thread);
  prev->rp_next_thread = prp->rp_next_thread;

  // remove sys mappings
  delete_sysv_mappings(prp);

  BUG_ON(ds_list_remove(prp->rp_group->rg_replay_threads, prp) == NULL);

#ifdef CACHE_READS
  put_replay_cache_files(prp->rp_cache_files);
#endif

  // Decrement the record thread's refcnt and maybe destroy it.
  __destroy_record_thread(prp->rp_record_thread);

  MPRINT("  Pid %d exits destroy_replay_thread: pid %d, prp = %p\n",
         current->pid, prp->rp_replay_pid, prp);

  KFREE(prp);
}

struct task_struct *
copy_process(unsigned long clone_flags, unsigned long stack_start,
             struct pt_regs *regs, unsigned long stack_size,
             int __user *child_tidptr, struct pid *pid); /* In fork.c */

asmlinkage void ret_from_fork_2(void) __asm__("ret_from_fork_2");
void set_tls_desc(struct task_struct *p, int idx, const struct user_desc *info, int n); /* In tls.c */
void fill_user_desc(struct user_desc *info, int idx, const struct desc_struct *desc); /* In tls.c */

struct pt_regs *
get_pt_regs_old(struct task_struct *tsk)
{
  u_long regs;

  if (tsk == NULL)
  {
    regs = (u_long) &tsk;
  }
  else
  {
    regs = (u_long)(tsk->thread.sp);
  }
  regs &= (~(THREAD_SIZE - 1));
  regs += THREAD_SIZE;
  regs -= (8 + sizeof(struct pt_regs));
  return (struct pt_regs *) regs;
}

struct pt_regs *
get_pt_regs(struct task_struct *tsk)
{
  if (tsk == NULL)
  {
    return task_pt_regs(current);
  }
  else
  {
    return task_pt_regs(tsk);
  }
}


#define NO_STACK_ENTRIES 64
// SL: to dump return addresses
void get_user_callstack(char *buffer, size_t bufsize)
{
  struct stack_trace trace;
  unsigned long entries[NO_STACK_ENTRIES];
  int i;
  char uuid_str[THEIA_UUID_LEN + 1];
  struct mm_struct *mm = current->mm;
  struct vm_area_struct *vma;
  struct inode *inode;
  char *ret_str;
  char *ptr;
  char *path = NULL;
  char *path_b64 = NULL;
  char *pbuf;
  int rc;

  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
  ret_str = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  trace.nr_entries  = 0;
  trace.max_entries = NO_STACK_ENTRIES;
  trace.skip        = 0;
  trace.entries     = entries;

  save_stack_trace_user(&trace);

  buffer[0] = '\0';
  for (i = 0; i < trace.nr_entries; ++i)
  {
    vma = find_vma(mm, trace.entries[i]);
    if (!vma)
      continue;

    if (vma->vm_file)
    {
      inode = vma->vm_file->f_dentry->d_inode;
      path = d_path(&(vma->vm_file->f_path), pbuf, THEIA_DPATH_LEN);
      if (IS_ERR(path))
      {
        path = "anon_page";
      }
      file2uuid(vma->vm_file, uuid_str, -1);
      path_b64 = base64_encode(path, strlen(path), NULL);
      if (path_b64) {
        rc = snprintf(ret_str, THEIA_KMEM_SIZE-1, "%s|%s", path_b64, uuid_str);
        vfree(path_b64);
      }
      else {
        strncpy_safe(ret_str, uuid_str, THEIA_UUID_LEN);
      }
      ptr = ret_str;
    }
    else
    {
      strncpy_safe(ret_str, "YW5vbl9wYWdl", THEIA_UUID_LEN); // base64(anon_page)
      ptr = ret_str;
    }

    if (strlen(buffer) + strlen(ptr) > bufsize - 1)
      break;
    strcat(buffer, ptr);
    strcat(buffer, "|");
  }

  kmem_cache_free(theia_buffers, ret_str);
  kmem_cache_free(theia_buffers, pbuf);
}

void
dump_user_stack(void)
{
  u_long __user *p;
  u_long a, v;
  int i = 0;

  struct pt_regs *regs = get_pt_regs(NULL);
  TPRINT("sp is %lx\n", regs->sp);
  p = (u_long __user *) regs->sp;
  do
  {
    get_user(v, p);
    get_user(a, p + 1);
    TPRINT("frame %d (%p) address 0x%08lx\n", i, p, a);
    if (v <= (u_long) p)
    {
      TPRINT("ending stack trace, v=0x%07lx\n", v);
      p = 0;
    }
    else
    {
      p = (u_long __user *) v;
      i++;
    }
  }
  while (p);
  p = (u_long __user *) regs->sp;
  for (i = 0; i < 250; i++)
  {
    get_user(v, p);
    TPRINT("value at address %p is 0x%08lx\n", p, v);
    p++;
  }
}

static void
__syscall_mismatch(struct record_group *precg)
{
  precg->rg_mismatch_flag = 1;
  rg_unlock(precg);
  TPRINT("SYSCALL MISMATCH\n");
#ifdef REPLAY_STATS
  atomic_inc(&rstats.mismatched);
#endif
  sys_exit_group(0);
}

long syscall_mismatch(void)
{
  struct record_group *prg = current->replay_thrd->rp_group->rg_rec_group;
  rg_lock(prg);
  __syscall_mismatch(prg);
  return 0; // Should never actually return
}

void
print_vmas(struct task_struct *tsk)
{
  struct vm_area_struct *mpnt;
  char buf[256];

  TPRINT("vmas for task %d mm %p\n", tsk->pid, tsk->mm);
  down_read(&tsk->mm->mmap_sem);
  for (mpnt = tsk->mm->mmap; mpnt; mpnt = mpnt->vm_next)
  {
    TPRINT("VMA start %lx end %lx", mpnt->vm_start, mpnt->vm_end);
    if (mpnt->vm_file)
    {
      TPRINT(" file %s ", dentry_path(mpnt->vm_file->f_dentry, buf, sizeof(buf)));
      if (mpnt->vm_flags & VM_READ)
      {
        TPRINT("r");
      }
      else
      {
        TPRINT("-");
      }
      if (mpnt->vm_flags & VM_WRITE)
      {
        TPRINT("w");
      }
      else
      {
        TPRINT("-");
      }
      if (mpnt->vm_flags & VM_EXEC)
      {
        TPRINT("x");
      }
      else
      {
        TPRINT("-");
      }
    }
    TPRINT("\n");
  }
  up_read(&tsk->mm->mmap_sem);
}

void
print_replay_threads(void)
{
  struct replay_thread *tmp;
  // See if we can find another eligible thread
  tmp = current->replay_thrd->rp_next_thread;

  MPRINT("Pid %d current thread is %d (recpid %d) status %d clock %ld - clock is %ld\n",
         current->pid, current->replay_thrd->rp_replay_pid, current->replay_thrd->rp_record_thread->rp_record_pid,
         current->replay_thrd->rp_status, current->replay_thrd->rp_wait_clock, *(current->replay_thrd->rp_preplay_clock));
  while (tmp != current->replay_thrd)
  {
    MPRINT("\tthread %d (recpid %d) status %d clock %ld - clock is %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock, *(current->replay_thrd->rp_preplay_clock));
    tmp = tmp->rp_next_thread;
  }
}

static void
create_used_address_list(void)
{
  struct vm_area_struct *mpnt;
  struct reserved_mapping *pmapping;

  current->replay_thrd->rp_group->rg_used_address_list = ds_list_create(NULL, 0, 1);
  down_read(&current->mm->mmap_sem);
  for (mpnt = current->mm->mmap; mpnt; mpnt = mpnt->vm_next)
  {
    pmapping = KMALLOC(sizeof(struct reserved_mapping), GFP_KERNEL);
    if (pmapping == NULL)
    {
      TPRINT("Cannot allocate new reserved mapping\n");
      return;
    }
    pmapping->m_begin = mpnt->vm_start;
    pmapping->m_end = mpnt->vm_end;
    if (mpnt->vm_start <= current->mm->start_brk && mpnt->vm_end >= current->mm->brk)
    {
      DPRINT("Heap runs from %lx to %lx\n", mpnt->vm_start, mpnt->vm_end);
      DPRINT("Expanding end to %lx\n", current->replay_thrd->rp_group->rg_max_brk);
      pmapping->m_end = current->replay_thrd->rp_group->rg_max_brk;
    }
    ds_list_append(current->replay_thrd->rp_group->rg_used_address_list, pmapping);
  }
  up_read(&current->mm->mmap_sem);
}

void ret_from_fork_replay(void)
{
  struct replay_thread *prept = current->replay_thrd;
  int ret;

  /* Nothing to do unless we need to support multiple threads */
  MPRINT("Pid %d ret_from_fork_replay\n", current->pid);
  ret = wait_event_interruptible_timeout(prept->rp_waitq, prept->rp_status == REPLAY_STATUS_RUNNING, SCHED_TO);
  if (ret == 0) TPRINT("Replay pid %d timed out waiting for cloned thread to go\n", current->pid);
  if (ret == -ERESTARTSYS) TPRINT("Pid %d: ret_from_fork_replay cannot wait due to signal - try again\n", current->pid);
  if (prept->rp_status != REPLAY_STATUS_RUNNING)
  {
    MPRINT("Replay pid %d woken up during clone but not running.  We must want it to die\n", current->pid);
    sys_exit(0);
  }
  MPRINT("Pid %d done with ret_from_fork_replay\n", current->pid);
}

void print_userspace_retaddr(void *addr1, void *addr2, void *addr3, void *addr4, void *addr5, void *addr6, void *addr7, void *addr8, void *addr9)
{
  if (current->record_thrd)
  {
    TPRINT("The registers from userspace: 4(esp)-ecx: %lx, 8(esp)-edx: %lx, C(esp)-esi: %lx, 10(esp)-edi: %lx, 14(esp)-ebp: %lx, 18(esp)-eax: %lx, 1C(esp)-ds: %lx, 2C(esp)-orig_eax: %lx, 30(esp)-eip: %lx, pid: %d\n", (u_long)addr1, (u_long)addr2, (u_long)addr3, (u_long)addr4, (u_long)addr5, (u_long)addr6, (u_long)addr7, (u_long)addr8, (u_long)addr9, current->pid);
  }
}

long
get_used_addresses(struct used_address __user *plist, int listsize)
{
  struct reserved_mapping *pmapping;
  ds_list_iter_t *iter;
  long rc = 0;

  if (current->replay_thrd == NULL || current->replay_thrd->rp_group->rg_used_address_list == NULL) return -EINVAL;

  iter = ds_list_iter_create(current->replay_thrd->rp_group->rg_used_address_list);
  while ((pmapping = ds_list_iter_next(iter)) != NULL)
  {
    if (listsize > 0)
    {
      put_user(pmapping->m_begin, &plist->start);
      put_user(pmapping->m_end, &plist->end);
      plist++;
      listsize--;
      rc++;
    }
    else
    {
      TPRINT("get_used_addresses: not enough room to return all mappings\n");
      rc = -EINVAL;
    }
  }
  ds_list_iter_destroy(iter);
  return rc;
}
EXPORT_SYMBOL(get_used_addresses);

void
reserve_memory(u_long addr, u_long len)
{
  struct reserved_mapping *pmapping, *nmapping;
  ds_list_iter_t *iter;
  ds_list_t *reserved_mem_list = NULL;

  if (current->record_thrd)
  {
    reserved_mem_list = current->record_thrd->rp_group->rg_reserved_mem_list;
  }
  else if (current->replay_thrd)
  {
    reserved_mem_list = current->replay_thrd->rp_record_thread->rp_group->rg_reserved_mem_list;
  }
  else
  {
    TPRINT("Pid %d not a record/replay thread, can't reserve memory\n", current->pid);
    return;
  }

  BUG_ON(!reserved_mem_list);

  len = (len % PAGE_SIZE == 0) ? len : len - (len % PAGE_SIZE) + PAGE_SIZE; // pad to nearest page size
  MPRINT("Inserting reserved memory from %lx to %lx\n", addr, addr + len);

  iter = ds_list_iter_create(reserved_mem_list);
  while ((pmapping = ds_list_iter_next(iter)) != NULL)
  {
    MPRINT("Mapping: %08lx-%08lx\n", pmapping->m_begin, pmapping->m_end);
    if (pmapping->m_end >= addr && pmapping->m_begin <= addr + len)
    {
      MPRINT("Overlap - merge the two regions\n");
      if (addr < pmapping->m_begin) pmapping->m_begin = addr;
      if (addr + len > pmapping->m_end) pmapping->m_end = addr + len;
      // Check if subsequent regions need to be merged
      while ((nmapping = ds_list_iter_next(iter)) != NULL)
      {
        MPRINT("Next mapping: %08lx-%08lx\n", nmapping->m_begin, nmapping->m_end);
        if (nmapping->m_begin <= pmapping->m_end &&
            nmapping->m_begin >= pmapping->m_begin)
        {
          MPRINT("Subsumed - join it\n");
          if (nmapping->m_end > pmapping->m_end) pmapping->m_end = nmapping->m_end;
          ds_list_remove(reserved_mem_list, nmapping);
        }
        else
        {
          break;
        }
      }
      ds_list_iter_destroy(iter);
      return;
    }
    else if (pmapping->m_begin > addr + len)
    {
      MPRINT("No need to look further\n");
      break;
    }
  }
  ds_list_iter_destroy(iter);

  // No conflicts - add a new mapping
  pmapping = KMALLOC(sizeof(struct reserved_mapping), GFP_KERNEL);
  if (pmapping == NULL)
  {
    TPRINT("Cannot allocate new reserved mapping\n");
    return;
  }
  pmapping->m_begin = addr;
  pmapping->m_end = addr + len;
  MPRINT("Added mapping %lx-%lx\n", addr, addr + len);
  ds_list_insert(reserved_mem_list, pmapping);
}

// Actually preallocates a region of memory
static long
do_preallocate(u_long start, u_long end)
{
  u_long retval;

  MPRINT("preallocating mmap_pgoff with address %lx and len %lx\n", start, end - start);
  retval = sys_mmap_pgoff(start, end - start, 1, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
  if (start != retval)
  {
    TPRINT("preallocating mmap_pgoff returns different value %lx than %lx\n", retval, start);
    return -1;
  }

  return 0;
}

// Preallocate any reserved regions that do not conflict with the existing mappings
static void
preallocate_memory(struct record_group *prg)
{
  struct vm_area_struct *vma;
  ds_list_iter_t *iter;
  struct reserved_mapping *pmapping;
  u_long begin_at;

  iter = ds_list_iter_create(prg->rg_reserved_mem_list);
  while ((pmapping = ds_list_iter_next(iter)) != NULL)
  {
    MPRINT("Considering pre-allocation from %lx to %lx\n", pmapping->m_begin, pmapping->m_end);

    // Any conflicting VMAs?
    down_read(&current->mm->mmap_sem);
    begin_at = pmapping->m_begin;
    for (vma = current->mm->mmap; vma; vma = vma->vm_next)
    {
      MPRINT("\tConsider vma from %lx to %lx\n", vma->vm_start, vma->vm_end);
      if (vma->vm_start > pmapping->m_end)
      {
        up_read(&current->mm->mmap_sem);
        do_preallocate(begin_at, pmapping->m_end);   // No more mappings that will conflict
        down_read(&current->mm->mmap_sem);
        break;
      }
      if (vma->vm_end > begin_at && vma->vm_start < pmapping->m_end)
      {
        MPRINT("\tConflict\n");
        if (vma->vm_start > begin_at)
        {
          up_read(&current->mm->mmap_sem);
          do_preallocate(begin_at, vma->vm_start);  // Allocate region before VM region
          down_read(&current->mm->mmap_sem);
        }
        if (vma->vm_end < pmapping->m_end)
        {
          begin_at = vma->vm_end; // Consider area after VM region only
          MPRINT("\tConsidering only from %lx now\n", begin_at);
        }
        else
        {
          break;
        }
      }
    }
    up_read(&current->mm->mmap_sem);
  }
  ds_list_iter_destroy(iter);
}

// Need to re-establish preallcoations (if needed) after a deallocation such as a munmap,
// in case that memory area is used again in the future
static void
preallocate_after_munmap(u_long addr, u_long len)
{
  ds_list_iter_t *iter;
  struct reserved_mapping *pmapping;
  u_long begin, end;

  len = (len % PAGE_SIZE == 0) ? len : len - (len % PAGE_SIZE) + PAGE_SIZE; // pad to nearest page size
  MPRINT("Re-allocating reserved memory as needed from %lx to %lx\n", addr, addr + len);

  iter = ds_list_iter_create(current->replay_thrd->rp_record_thread->rp_group->rg_reserved_mem_list);
  while ((pmapping = ds_list_iter_next(iter)) != NULL)
  {
    MPRINT("pre-allocation from %lx to %lx\n", pmapping->m_begin, pmapping->m_end);
    if (pmapping->m_begin > addr + len) break; // No more mappings will matter
    if (pmapping->m_begin <= addr + len && pmapping->m_end >= addr)
    {
      MPRINT("Overlap\n");
      begin = (pmapping->m_begin > addr) ? pmapping->m_begin : addr;
      end = (pmapping->m_end < addr + len) ? pmapping->m_end : addr + len;
      do_preallocate(begin, end);
    }
  }
  ds_list_iter_destroy(iter);
}

static struct argsalloc_node *new_argsalloc_node(void *slab, size_t size)
{
  struct argsalloc_node *new_node;
  new_node = KMALLOC(sizeof(struct argsalloc_node), GFP_KERNEL);
  if (new_node == NULL)
  {
    TPRINT("new_argalloc_node: Cannot allocate struct argsalloc_node\n");
    return NULL;
  }

  new_node->head = slab;
  new_node->pos = slab;
  new_node->size = size;
  //new_node->list should be init'ed in the calling function

  return new_node;
}

#ifdef LOG_COMPRESS_1
static struct clog_node *new_clog_node(void *slab, size_t size)
{
  struct clog_node *new_node;
  new_node = KMALLOC(sizeof(struct clog_node), GFP_KERNEL);
  if (new_node == NULL)
  {
    TPRINT("new_clog_node: Cannot allocate struct clog_node\n");
    return NULL;
  }

  new_node->head = slab;
  new_node->pos = slab;
  new_node->size = size;
  //new_node->list should be init'ed in the calling function

  return new_node;
}
#endif

/*
 * Adds another slab for args/retparams/signals allocation,
 * if no slab exists, then we create one */
static int add_argsalloc_node(struct record_thread *prect, void *slab, size_t size)
{
  struct argsalloc_node *new_node;
  new_node = new_argsalloc_node(slab, size);
  if (new_node == NULL)
  {
    TPRINT("Pid %d add_argsalloc_node: could not create new argsalloc_node\n", prect->rp_record_pid);
    return -1;
  }

  // Add to front of the list
  MPRINT("Pid %d add_argsalloc_node: adding an args slab to record_thread\n", prect->rp_record_pid);
  list_add(&new_node->list, &prect->rp_argsalloc_list);
  return 0;
}

#ifdef LOG_COMPRESS_1
static int add_compress_node(struct record_thread *prect, void *slab, size_t size, struct list_head *rp_list)
{
  struct clog_node *new_node;
  new_node = new_clog_node(slab, size);
  if (new_node == NULL)
  {
    TPRINT("Pid %d add_compress_node: could not create new clog_node\n", prect->rp_record_pid);
    return -1;
  }

  // Add to front of the list
  MPRINT("Pid %d add_compress_node: adding an args slab to record_thread\n", prect->rp_record_pid);
  list_add(&new_node->list, rp_list);
  init_encode_buffer(new_node);  // basically, this function is the same with decodebuffer_init, the only exception is *node->pos = 0;
  return 0;
}
static int inline add_clog_node(struct record_thread *prect, void *slab, size_t size)
{
  MPRINT("Adding node to compress_log buffer.\n");
  return add_compress_node(prect, slab, size, &prect->rp_clog_list);
}
#endif

static void *argsalloc(size_t size)
{
  struct record_thread *prect = current->record_thrd;
  struct argsalloc_node *node;
  size_t asize;
  void *ptr;

  node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);

  //TPRINT("in argsalloc: size %lu\n", size);

  // check to see if we've allocated a slab and if we have enough space left in the slab
  if (unlikely(list_empty(&prect->rp_argsalloc_list) || ((node->head + node->size - node->pos) < size)))
  {
    int rc;
    void *slab;

    MPRINT("Pid %d argsalloc: not enough space left in slab, allocating new slab\n", current->pid);

    asize = (size > argsalloc_size) ? size : argsalloc_size;
    slab = VMALLOC(asize);
    if (slab == NULL)
    {
      TPRINT("Pid %d argsalloc: couldn't alloc slab with size %lu\n", current->pid, asize);
      return NULL;
    }
    rc = add_argsalloc_node(current->record_thrd, slab, asize);
    if (rc)
    {
      TPRINT("Pid %d argalloc: problem adding argsalloc_node\n", current->pid);
      VFREE(slab);
      return NULL;
    }
    // get the new first node of the linked list
    node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);
    ptr = node->pos;
    node->pos += size;
#ifdef LOG_COMPRESS_1
    if (unlikely(list_empty(&prect->rp_clog_list)))
    {
      MPRINT("Pid %d allocate new clog node, clog list is empty\n", current->pid);

      asize = (size > argsalloc_size) ? size : argsalloc_size;
      slab = VMALLOC(asize);
      if (slab == NULL)
      {
        TPRINT("Pid %d argsalloc:(clog) couldn't alloc slab with size %u\n", current->pid, asize);
        return NULL;
      }
      rc = add_clog_node(current->record_thrd, slab, asize);
      if (rc)
      {
        TPRINT("Pid %d argalloc: (clog) problem adding argsalloc_node\n", current->pid);
        VFREE(slab);
        return NULL;
      }
    }
    else
    {
      struct clog_node *cnode = list_first_entry(&prect->rp_clog_list, struct clog_node, list);
      if (cnode->head + cnode->size - cnode->pos < size)
      {
        //copy the last byte to the new cnode
        unsigned char last_byte = *cnode->pos;
        unsigned int free_bits = cnode->freeBitsInDest;
        //after we copy the last byte, the last byte in previous cnode node can be cleared
        cnode->freeBitsInDest = 8;
        TPRINT("Pid %d allocate new clog node, clog run out of space.\n", current->pid);
        asize = (size > argsalloc_size) ? size : argsalloc_size;
        slab = VMALLOC(asize);
        if (slab == NULL)
        {
          TPRINT("Pid %d argsalloc:(clog) couldn't alloc slab with size %u\n", current->pid, asize);
          return NULL;
        }
        rc = add_clog_node(current->record_thrd, slab, asize);
        if (rc)
        {
          TPRINT("Pid %d argalloc: (clog) problem adding argsalloc_node\n", current->pid);
          VFREE(slab);
          return NULL;
        }
        cnode = list_first_entry(&prect->rp_clog_list, struct clog_node, list);
        *cnode->pos = last_byte;
        cnode->freeBitsInDest = free_bits;
      }
    }

#endif
    return ptr;
  }

  // return pointer and then advance
  ptr = node->pos;
  node->pos += size;

  return ptr;
}

#ifdef LOG_COMPRESS_1
static void *compressalloc(size_t size, struct list_head *rp_list)
{
  struct clog_node *node;
  size_t asize;
  void *ptr;

  node = list_first_entry(rp_list, struct clog_node, list);

  // check to see if we've allocated a slab and if we have enough space left in the slab
  if (unlikely(list_empty(rp_list) || ((node->head + node->size - node->pos) < size)))
  {
    int rc;
    void *slab;

    MPRINT("Pid %d compressalloc: not enough space left in slab, allocating new slab\n", current->pid);

    asize = (size > argsalloc_size) ? size : argsalloc_size;
    slab = VMALLOC(asize);
    if (slab == NULL)
    {
      TPRINT("Pid %d compressalloc: couldn't alloc slab with size %u\n", current->pid, asize);
      return NULL;
    }
    rc = add_compress_node(current->record_thrd, slab, asize, rp_list);
    if (rc)
    {
      TPRINT("Pid %d compressalloc: problem adding argsalloc_node\n", current->pid);
      VFREE(slab);
      return NULL;
    }
    // get the new first node of the linked list
    node = list_first_entry(rp_list, struct clog_node, list);
    ptr = node->pos;
    node->pos += size;
    return ptr;
  }

  // return pointer and then advance
  ptr = node->pos;
  node->pos += size;

  return ptr;
}
static inline void *clogalloc(size_t size)
{
  struct record_thread *prect = current->record_thrd;
  return compressalloc(size, &prect->rp_clog_list);
}
#endif

/* Simplified method to return pointer to next data to consume on replay */
static char *
argshead(struct record_thread *prect)
{
  struct argsalloc_node *node;
  node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);
  if (unlikely(list_empty(&prect->rp_argsalloc_list)))
  {
    TPRINT("argshead: pid %d sanity check failed - no anc. data\n", current->pid);
    BUG();
  }
  return node->pos;
}


/* Simplified method to advance pointer on replay */
static void
argsconsume(struct record_thread *prect, u_long size)
{
  struct argsalloc_node *node;
  node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);
  if (unlikely(list_empty(&prect->rp_argsalloc_list)))
  {
    TPRINT("argsconsume: pid %d sanity check failed - no anc. data\n", current->pid);
    BUG();
  }
  if (unlikely(node->head + node->size - node->pos < size))
  {
    TPRINT("argsconsume: pid %d sanity check failed - head %p size %lu pos %p size %lu\n", current->pid, node->head, (u_long) node->size, node->pos, size);
    dump_stack();
    BUG();
  }
  TPRINT("in argsconsume: size %lu\n", size);
  node->pos += size;
}

#ifdef LOG_COMPRESS_1
static inline struct clog_node *clog_alloc(int size)
{
  struct clog_node *cnode = list_first_entry(&current->record_thrd->rp_clog_list, struct clog_node, list);
  return cnode;
}

// IMPORTANT: never use encodeXXX functions directly after ARGSMALLOC if the clog_node structure is defined before ARGSMALLOC
// encodeValue_clog function should never compress more than 256 bytes at one time
inline void encodeValue_clog(unsigned int value, unsigned int numBits, unsigned int blockSize)
{
  struct clog_node *node = clog_alloc(256);
  encodeValue(value, numBits, blockSize, node);
}

static inline struct clog_node *clog_mark_done(void)
{
  current->record_thrd->rp_clog.done = 1;
  return list_first_entry(&current->record_thrd->rp_clog_list, struct clog_node, list);
}

static inline struct clog_node *clog_mark_done_replay(void)
{
  current->replay_thrd->rp_record_thread->rp_clog.done = 1;
  return list_first_entry(&current->replay_thrd->rp_record_thread->rp_clog_list, struct clog_node, list);
}

#endif

/*
 * Adding support for freeing...
 * The only use case for this is in case of an error (like copying from user)
 * and the allocated memory needs to be freed
 */
static void argsfree(const void *ptr, size_t size)
{
  struct record_thread *prect;
  struct argsalloc_node *ra_node;
  prect = current->record_thrd;
  ra_node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);

  if (ptr == NULL)
    return;

  if (ra_node->head == ra_node->pos)
    return;

  // simply rollback allocation (there is the rare case where allocation has
  // created a new slab, but in that case we simply roll back the allocation
  // and keep the slab since calling argsfree itself is rare)
  if ((ra_node->pos - size) >= ra_node->head)
  {
    ra_node->pos -= size;
    return;
  }
  else
  {
    TPRINT("Pid %d argsfree: unhandled case\n", current->pid);
    return;
  }
}

// Free all allocated data values at once
static void argsfreeall(struct record_thread *prect)
{
  struct argsalloc_node *node;
  struct argsalloc_node *next_node;

  list_for_each_entry_safe(node, next_node, &prect->rp_argsalloc_list, list)
  {
    VFREE(node->head);
    list_del(&node->list);
    KFREE(node);
  }
}

#ifdef LOG_COMPRESS_1
static void compressfree(const void *ptr, size_t size, struct list_head *rp_list)
{
  struct record_thread *prect;
  struct clog_node *ra_node;
  prect = current->record_thrd;
  ra_node = list_first_entry(rp_list, struct clog_node, list);

  if (ptr == NULL)
    return;

  if (ra_node->head == ra_node->pos)
    return;

  // simply rollback allocation (there is the rare case where allocation has
  // created a new slab, but in that case we simply roll back the allocation
  // and keep the slab since calling argsfree itself is rare)
  if ((ra_node->pos - size) >= ra_node->head)
  {
    ra_node->pos -= size;
    return;
  }
  else
  {
    TPRINT("Pid %d compressfree: unhandled case\n", current->pid);
    return;
  }
}

// Free all allocated data values at once
static void compressfreeall(struct record_thread *prect, struct list_head *rp_list)
{
  struct clog_node *node;
  struct clog_node *next_node;

  list_for_each_entry_safe(node, next_node, rp_list, list)
  {
    VFREE(node->head);
    list_del(&node->list);
    KFREE(node);
  }
}
static inline void clogfree(const void *ptr, size_t size)
{
  compressfree(ptr, size, &current->record_thrd->rp_clog_list);
}
static inline void clogfreeall(struct record_thread *prect)
{
  TPRINT("clogfreeall\n");
  compressfreeall(prect, &prect->rp_clog_list);
}
#endif

// function to keep track of the sysv identifiers, since we always want to return the record identifier
static int add_sysv_mapping(struct replay_thread *prt, int record_id, int replay_id)
{
  struct sysv_mapping *tmp;
  tmp = KMALLOC(sizeof(struct sysv_mapping), GFP_KERNEL);
  if (tmp == NULL)
  {
    TPRINT("Pid %d (recpid %d) add_sysv_mapping: could not create new sysv_mapping\n", current->pid, prt->rp_record_thread->rp_record_pid);
    return -1;
  }
  tmp->record_id = record_id;
  tmp->replay_id = replay_id;

  // Add to front of the list
  MPRINT("Pid %d (recpid %d) add_sysv_mapping: adding a SYS V ID mapping\n", current->pid, prt->rp_record_thread->rp_record_pid);
  list_add(&tmp->list, &prt->rp_sysv_list);
  return 0;
}

static int find_sysv_mapping(struct replay_thread *prt, int record_id)
{
  struct sysv_mapping *tmp;
  list_for_each_entry(tmp, &prt->rp_sysv_list, list)
  {
    if (tmp->record_id == record_id)
    {
      DPRINT("Pid %d (recpid %d) found sysv replay_id %d for sysv record_id %d\n", current->pid, prt->rp_record_thread->rp_record_pid, tmp->replay_id, record_id);
      return tmp->replay_id;
    }
  }
  return -1;
}

static void delete_sysv_mappings(struct replay_thread *prt)
{
  struct sysv_mapping *tmp;
  struct sysv_mapping *tmp_safe;
  list_for_each_entry_safe(tmp, tmp_safe, &prt->rp_sysv_list, list)
  {
    list_del(&tmp->list);
    KFREE(tmp);
  }
}

/* A pintool uses this for specifying the start of the thread specific data structure.  The function returns the pid on success */
int set_pin_address(u_long pin_address)
{
  if (current->replay_thrd)
  {
    MPRINT("set_pin_address: pin address is %lx\n", pin_address);
    current->replay_thrd->app_syscall_addr = pin_address;
    if (current->replay_thrd->rp_record_thread)
    {
      return current->replay_thrd->rp_record_thread->rp_record_pid;
    }
  }

  TPRINT("set_pin_address called for something that is not a replay process\n");
  return -EINVAL;
}
EXPORT_SYMBOL(set_pin_address);

long get_log_id(void)
{
  if (current->replay_thrd)
  {
    TPRINT("[%s|%d] pid %d, rp_record_pid is %d\n", __func__, __LINE__, current->pid, current->replay_thrd->rp_record_thread->rp_record_pid);
    return current->replay_thrd->rp_record_thread->rp_record_pid;
  }
  else
  {
    TPRINT("get_log_id called by a non-replay process\n");
    return -EINVAL;
  }
}
EXPORT_SYMBOL(get_log_id);


//Yang: get inode,dev,crtime for taint
int get_inode_for_pin(u_long inode)
{
  TPRINT("received get_inode_for_pin request!!!!, inode %lx, repl_uuid_str is %s\n", inode, repl_uuid_str);
  copy_to_user((char *)inode, repl_uuid_str, strlen(repl_uuid_str));
  ((char *)inode)[strlen(repl_uuid_str)] = '\0';
  return 0;
}
EXPORT_SYMBOL(get_inode_for_pin);


unsigned long get_clock_value(void)
{
  if (current->replay_thrd)
  {
    struct replay_thread *prt = current->replay_thrd;
    if (prt->rp_preplay_clock)
    {
      return *(prt->rp_preplay_clock);
    }
    else
    {
      return -EINVAL;
    }
  }
  else if (current->record_thrd)
  {
    struct record_thread *prt = current->record_thrd;
    if (prt->rp_precord_clock)
    {
      return atomic_read(prt->rp_precord_clock);
    }
    else
    {
      return -EINVAL;
    }
  }
  else
  {
    TPRINT("get_clock_value called by a non-replay process\n");
    return -EINVAL;
  }
}
EXPORT_SYMBOL(get_clock_value);

long get_record_group_id(__u64 __user *prg_id)
{
  if (current->record_thrd)
  {
    if (copy_to_user(prg_id, &current->record_thrd->rp_group->rg_id, sizeof(__u64)))
    {
      return -EINVAL;
    }
    return 0;
  }
  else if (current->replay_thrd)
  {
    if (copy_to_user(prg_id, &current->replay_thrd->rp_record_thread->rp_group->rg_id, sizeof(__u64)))
    {
      return -EINVAL;
    }
    return 0;
  }
  TPRINT("get_record_group_id called by a non-replay process\n");
  return -EINVAL;
}
EXPORT_SYMBOL(get_record_group_id);

long get_num_filemap_entries(int fd, loff_t offset, int size)
{
  int num_entries = 0;
  struct file *filp;
  struct replayfs_filemap map;
  //struct replayfs_filemap *map;
  struct replayfs_filemap_entry *entry;

  /* Hacky... but needed... */
  glbl_diskalloc_init();

  filp = fget(fd);
  if (!filp)
  {
    TPRINT("Pid %d got bad filp for fd %d\n", current->pid, fd);
    return -EBADF;
  }
  replayfs_filemap_init(&map, replayfs_alloc, filp);
  /*
  map = filp->replayfs_filemap;
  if (map == NULL) {
    replayfs_file_opened(filp);
    map = filp->replayfs_filemap;
  }
  */

  MPRINT("get filemap entries for fd %d offset %lld, size %d\n", fd, offset, size);
  entry = replayfs_filemap_read(&map, offset, size);
  if (IS_ERR(entry) || entry == NULL)
  {
    TPRINT("get filemap can't find entry %p\n", entry);
    replayfs_filemap_destroy(&map);
    fput(filp);
    if (entry != NULL)
    {
      return PTR_ERR(entry);
    }
    return -ENOMEM;
  }

  replayfs_filemap_destroy(&map);
  fput(filp);

  num_entries = entry->num_elms;
  MPRINT("get_num_filemap_entries is %d\n", num_entries);
  kfree(entry);

  return num_entries;
}
EXPORT_SYMBOL(get_num_filemap_entries);

long get_filemap(int fd, loff_t offset, int size, void __user *entries, int num_entries)
{
  int rc = 0;
  int i = 0;
  struct file *filp;
  struct replayfs_filemap map;
  struct replayfs_filemap_entry *entry;

  /* Hacky... but needed... */
  glbl_diskalloc_init();

  filp = fget(fd);
  if (!filp)
  {
    return -EBADF;
  }
  replayfs_filemap_init(&map, replayfs_alloc, filp);

  entry = replayfs_filemap_read(&map, offset, size);
  if (IS_ERR(entry) || entry == NULL)
  {
    replayfs_filemap_destroy(&map);
    fput(filp);
    if (entry != NULL)
    {
      return PTR_ERR(entry);
    }
    return -ENOMEM;
  }

  replayfs_filemap_destroy(&map);
  fput(filp);

  // okay cool, walk the file map now
  for (i = 0; i < num_entries; i++)
  {
    struct replayfs_filemap_value *value;
    value = (entry->elms) + i;
    if (copy_to_user(entries + (i * sizeof(struct replayfs_filemap_value)), value, sizeof(struct replayfs_filemap_value)))
    {
      rc = -EFAULT;
      break;
    }
  }

  kfree(entry);
  return rc;
}
EXPORT_SYMBOL(get_filemap);

// For glibc hack - allocate and return the LD_LIBRARY_PATH env variable
static char *
get_libpath(const char __user *const __user *env)
{
  const char __user *const __user *up;
  const char __user *pc;
  char tokbuf[16];
  char *retbuf;
  u_long len;

  up = env;
  do
  {
    if (get_user(pc, up))
    {
      TPRINT("copy_args: invalid env value\n");
      return NULL;
    }
    if (pc == 0) break; // No more args
    if (strncpy_from_user(tokbuf, pc, sizeof(tokbuf)) != sizeof(tokbuf))
    {
      up++;
      continue;
    }
    if (memcmp(tokbuf, "LD_LIBRARY_PATH=", sizeof(tokbuf)))
    {
      up++;
      continue;
    }
    len = strnlen_user(pc, 4096);
    if (len > 4096)
    {
      TPRINT("get_libpath: path too long\n");
      return NULL;
    }
    retbuf = KMALLOC(len, GFP_KERNEL);
    if (retbuf == NULL)
    {
      TPRINT("get_libpath cannot allocate buffer\n");
      return NULL;
    }
    if (copy_from_user(retbuf, pc, len))
    {
      TPRINT("get_libpath cannot copy path from user\n");
      return NULL;
    }
    retbuf[len] = '\0';
    return retbuf;
  }
  while (1);

  return NULL;
}

// Checks to see if matching libpath is present in arg/env buffer - returns 0 if true, index if no match, -1 if not present
static int
is_libpath_present(struct record_group *prg, char *p)
{
  int cnt, i, len;

  // Skip args
  cnt = *((int *) p);
  p += sizeof(int);
  for (i = 0; i < cnt; i++)
  {
    len = *((int *) p);
    p += sizeof(int) + len;
  }

  cnt = *((int *) p);
  p += sizeof(int);
  for (i = 0; i < cnt; i++)
  {
    len = *((int *) p);
    if (strncmp(p + sizeof(int), "LD_LIBRARY_PATH=", 16) == 0)
    {
      DPRINT("pid %d: libpath is %s\n", current->pid, (char *)(p + sizeof(int)));
      if (strcmp(p + sizeof(int), prg->rg_libpath) == 0)
      {
        DPRINT("pid %d: libpath matches\n", current->pid);
        return 0; // match found
      }
      DPRINT("pid %d: libpath does not match %lu %d, return %d\n", current->pid, strlen(prg->rg_libpath) + 1, len, i);
      return i; // libarary path there at this index but does not match
    }
    p += sizeof(int) + len;
  }
  DPRINT("pid %d: libpath not found\n", current->pid);
  return -1; // library path not there at all
}

static char **
patch_for_libpath(struct record_group *prg, char *p, int present)
{
  int cnt, env_cnt, i, len;
  char **env;

  // Skip args
  cnt = *((int *) p);
  p += sizeof(int);
  for (i = 0; i < cnt; i++)
  {
    len = *((int *) p);
    p += sizeof(int) + len;
  }

  cnt = *((int *) p);
  p += sizeof(int);
  if (present < 0)
  {
    env_cnt = cnt + 2;
  }
  else
  {
    env_cnt = cnt + 1;
  }
  env = KMALLOC((env_cnt + 1) * sizeof(char *), GFP_KERNEL);
  if (env == NULL)
  {
    TPRINT("patch_for_libpath: unable to allocate env struct\n");
    return NULL;
  }

  for (i = 0; i < cnt; i++)
  {
    len = *((int *) p);
    if (present == i)
    {
      env[i] = KMALLOC(strlen(prg->rg_libpath) + 1, GFP_KERNEL);
      if (env[i] == NULL)
      {
        TPRINT("patch_for_libpath: unable to allocate new env\n");
        return NULL;
      }
      strncpy_safe(env[i], prg->rg_libpath, strlen(prg->rg_libpath));
      DPRINT("pid %d: put libpath at index %d\n", current->pid, i);
    }
    else
    {
      env[i] = KMALLOC(len, GFP_KERNEL);
      if (env[i] == NULL)
      {
        TPRINT("patch_for_libpath: unable to allocate env. %d of length %d\n", i, len);
        return NULL;
      }
      strncpy_safe(env[i], p + sizeof(int), len-1);
    }
    p += sizeof(int) + len;
  }
  if (present < 0)
  {
    DPRINT("pid %d: put libpath at end\n", current->pid);
    env[i] = KMALLOC(strlen(prg->rg_libpath) + 1, GFP_KERNEL);
    if (env[i] == NULL)
    {
      TPRINT("patch_for_libpath: unable to allocate new env\n");
      return NULL;
    }
    strncpy_safe(env[i], prg->rg_libpath, strlen(prg->rg_libpath));
    env[i + 1] = NULL;
  }
  else
  {
    env[i] = NULL;
  }
  return env;
}

static char *
patch_buf_for_libpath(struct record_group *prg, char *buf, int *pbuflen, int present)
{
  int cnt, i, len, env_len = 0, skip_len = 0;
  char *p = buf, *newbuf;
  u_long buflen, newbuflen;

  // Figure out length
  cnt = *((int *) p);
  p += sizeof(int);
  for (i = 0; i < cnt; i++)
  {
    len = *((int *) p);
    p += sizeof(int) + len;
  }
  cnt = *((int *) p);
  if (present < 0) *((int *) p) = cnt + 1; // adding one entry to end
  p += sizeof(int);
  for (i = 0; i < cnt; i++)
  {
    len = *((int *) p);
    if (present == i)
    {
      env_len = len;
      skip_len = (u_long) p - (u_long) buf;
    }
    p += sizeof(int) + len;
  }
  buflen = (u_long) p - (u_long) buf;
  if (present < 0)
  {
    newbuflen = buflen + sizeof(int) + strlen(prg->rg_libpath) + 1;
  }
  else
  {
    newbuflen = buflen + strlen(prg->rg_libpath) + 1 - env_len;
  }
  newbuf = KMALLOC(newbuflen, GFP_KERNEL);
  if (newbuf == NULL)
  {
    TPRINT("patch_buf_for_libpath: cannot allocate buffer of size %lu\n", newbuflen);
    return NULL;
  }
  if (present < 0)
  {
    memcpy(newbuf, buf, buflen);
    p = newbuf + buflen;
    *((int *) p) = strlen(prg->rg_libpath) + 1;
    p += sizeof(int);
    strncpy_safe(p, prg->rg_libpath, strlen(prg->rg_libpath));
  }
  else
  {
    memcpy(newbuf, buf, skip_len);
    p = newbuf + skip_len;
    *((int *) p) = strlen(prg->rg_libpath) + 1;
    p += sizeof(int);
    strncpy_safe(p, prg->rg_libpath, strlen(prg->rg_libpath));
    p += strnlen(prg->rg_libpath, MAX_LIBPATH_STRLEN) + 1;
    memcpy(p, buf + skip_len + sizeof(int) + env_len, buflen - skip_len - sizeof(int) - env_len);
  }

  *pbuflen = newbuflen;
  return newbuf;
}

static void
libpath_env_free(char **env)
{
  int i = 0;

  while (env[i] != NULL)
  {
    KFREE(env[i]);
    i++;
  }
  KFREE(env);
}

/* This function forks off a separate process which replays the foreground task.*/
int fork_replay_theia(char __user *logdir, const char *filename, const char __user *const __user *args,
                      const char __user *const __user *env, char *linker, int save_mmap, int fd,
                      int pipe_fd)
{
  mm_segment_t old_fs;
  struct record_group *prg;
  long retval;
  char ckpt[MAX_LOGDIR_STRLEN + 10];
  char *argbuf;
  int argbuflen;
  void *slab;
  int theia_libpath_len;
#ifdef TIME_TRICK
  struct timeval tv;
  struct timespec tp;
#endif

  MPRINT("[%s|%d] pid %d, fd %d\n", __func__, __LINE__, current->pid, fd);
  if (current->record_thrd || current->replay_thrd)
  {
    TPRINT("fork_replay_theia: pid %d cannot start a new recording while already recording or replaying\n", current->pid);
    return -EINVAL;
  }

  if (atomic_read(&current->mm->mm_users) > 1)
  {
    TPRINT("fork with multiple threads is not currently supported\n");
    return -EINVAL;
  }

  // Create a record_group structure for this task
  prg = new_record_group(NULL);
  if (prg == NULL) return -ENOMEM;

  current->record_thrd = new_record_thread(prg, current->pid, NULL);
  if (current->record_thrd == NULL)
  {
    destroy_record_group(prg);
    return -ENOMEM;
  }
  prg->rg_save_mmap_flag = save_mmap;

  // allocate a slab for retparams
  slab = VMALLOC(argsalloc_size);
  if (slab == NULL) return -ENOMEM;
  if (add_argsalloc_node(current->record_thrd, slab, argsalloc_size))
  {
    VFREE(slab);
    destroy_record_group(prg);
    current->record_thrd = NULL;
    TPRINT("Pid %d fork_replay_theia: error adding argsalloc_node\n", current->pid);
    return -ENOMEM;
  }
  MPRINT("fork_replay_theia added new slab %p to record_thread %p\n", slab, current->record_thrd);
#ifdef LOG_COMPRESS_1
  slab = VMALLOC(argsalloc_size);
  if (slab == NULL) return -ENOMEM;
  if (add_clog_node(current->record_thrd, slab, argsalloc_size))
  {
    VFREE(slab);
    destroy_record_group(prg);
    current->record_thrd = NULL;
    TPRINT("Pid %d fork_replay_theia: error adding clog_node\n", current->pid);
    return -ENOMEM;
  }
  MPRINT("fork_replay_theia added new slab %p to record_thread %p (clog)\n", slab, current->record_thrd);
#endif
#ifdef LOG_COMPRESS
  init_evs();
#endif

  current->replay_thrd = NULL;
  MPRINT("in fork_replay_theia: Record-Pid %d, tsk %p, prp %p\n", current->pid, current, current->record_thrd);

  BUG_ON(IS_ERR_OR_NULL(linker));
  if (linker)
  {
    strncpy_safe(current->record_thrd->rp_group->rg_linker, linker, MAX_LOGDIR_STRLEN);
    MPRINT("Set linker for record process to %s\n", linker);
  }

  if (fd >= 0)
  {
    retval = sys_close(fd);
    if (retval < 0) TPRINT("fork_replay_theia: unable to close fd %d, rc=%ld\n", fd, retval);
  }

  if (pipe_fd >= 0)
  {
    char str[MAX_LOGDIR_STRLEN+1];
    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = snprintf(str, MAX_LOGDIR_STRLEN+1, "%s\n", prg->rg_logdir);
    if (retval < 0) TPRINT("fork_replay_theia: rg_logdir is too long\n");

    sys_write(pipe_fd, str, strlen(str));

    set_fs(old_fs);
  }


  snprintf(ckpt, MAX_LOGDIR_STRLEN+10, "%s/ckpt", prg->rg_logdir);
  BUG_ON(IS_ERR_OR_NULL(theia_libpath));
  //MAX_LIBPAT_STRLEN+1 because theia_libpath should have 1 extra byte for null byte
  theia_libpath_len = strnlen(theia_libpath, MAX_LIBPATH_STRLEN + 1);
  argbuf = copy_args(args, env, &argbuflen, theia_libpath, theia_libpath_len);

  if (argbuf == NULL)
  {
    TPRINT("replay_checkpoint_to_disk: copy_args failed\n");
    return -EFAULT;
  }

#ifdef TIME_TRICK
  retval = replay_checkpoint_to_disk(ckpt, filename, argbuf, argbuflen, 0, &tv, &tp);
  init_det_time(&prg->rg_det_time, &tv, &tp);
#else
  // Save reduced-size checkpoint with info needed for exec
  retval = replay_checkpoint_to_disk(ckpt, (char *)filename, argbuf, argbuflen, 0);
#endif
  DPRINT("replay_checkpoint_to_disk returns %ld\n", retval);
  if (retval)
  {
    TPRINT("replay_checkpoint_to_disk returns %ld\n", retval);
    return retval;
  }

  // Hack to support multiple glibcs - record and LD_LIBRARY_PATH info
  prg->rg_libpath = get_libpath(env);
  if (prg->rg_libpath == NULL)
  {
    TPRINT("fork_replay: libpath not found\n");

    prg->rg_libpath = KMALLOC(theia_libpath_len+1, GFP_KERNEL);
    strncpy_safe(prg->rg_libpath, theia_libpath, theia_libpath_len);
    TPRINT("hardcoded libpath is (%s)", prg->rg_libpath);
    //    return -EINVAL;
  }

  retval = record_execve(filename, args, env, get_pt_regs(NULL));
  if (retval) TPRINT("fork_replay_execve: execve returns %ld\n", retval);
  return retval;
}

void show_kernel_stack(u_long *sp)
{

  unsigned long *irq_stack_end;
  unsigned long *irq_stack;
  unsigned long *stack;
  int cpu;
  int i;

  preempt_disable();
  cpu = smp_processor_id();

  irq_stack_end = (unsigned long *)(per_cpu(irq_stack_ptr, cpu));
  irq_stack = (unsigned long *)(per_cpu(irq_stack_ptr, cpu) - IRQ_STACK_SIZE);

  /*
   * Debugging aid: "show_stack(NULL, NULL);" prints the
   * back trace for this cpu:
   */
  if (sp == NULL)
  {
    if (current)
      sp = (unsigned long *)current->thread.sp;
    else
      sp = (unsigned long *)&sp;
  }

  stack = sp;
  TPRINT("kernel stack: sp: %p\n", (void *)sp);
  for (i = 0; i < kstack_depth_to_print; i++)
  {
    if (stack >= irq_stack && stack <= irq_stack_end)
    {
      if (stack == irq_stack_end)
      {
        stack = (unsigned long *)(irq_stack_end[-1]);
        TPRINT(KERN_CONT " <EOI> ");
      }
    }
    else
    {
      if (((long) stack & (THREAD_SIZE - 1)) == 0)
        break;
    }
    if (i && ((i % STACKSLOTS_PER_LINE) == 0))
      TPRINT(KERN_CONT "\n");
    TPRINT(KERN_CONT " %016lx", *stack++);
    touch_nmi_watchdog();
  }
  preempt_enable();

  TPRINT(KERN_CONT "\n");

}

/* This function forks off a separate process which replays the foreground task.*/
int fork_replay(char __user *logdir, const char __user *const __user *args,
                const char __user *const __user *env, char *linker, int save_mmap, int fd,
                int pipe_fd)
{
  mm_segment_t old_fs;
  long retval;
  char ckpt[MAX_LOGDIR_STRLEN + 10];
  const char __user *pc;
  char *filename;
  char *argbuf;
  int argbuflen;
  void *slab;
#ifdef TIME_TRICK
  struct timeval tv;
  struct timespec tp;
#endif
  struct record_group *prg;
  int theia_libpath_len;

  MPRINT("in fork_replay for pid %d\n", current->pid);

  //show_regs(get_pt_regs(NULL));
  /*
  __asm__ __volatile__ ("mov %%rsp, %0": "=r"(cur_rsp));
  TPRINT("Yang verify: addr cur_rsp: %lx, cur_rsp: %lx\n", &cur_rsp, cur_rsp);
  show_kernel_stack((u_long*)cur_rsp);
  */

  if (current->record_thrd || current->replay_thrd)
  {
    TPRINT("fork_replay: pid %d cannot start a new recording while already recording or replaying\n", current->pid);
    return -EINVAL;
  }

  if (atomic_read(&current->mm->mm_users) > 1)
  {
    TPRINT("fork with multiple threads is not currently supported\n");
    return -EINVAL;
  }

  // Create a record_group structure for this task
  prg = new_record_group(NULL);
  if (prg == NULL) return -ENOMEM;

  current->record_thrd = new_record_thread(prg, current->pid, NULL);
  if (current->record_thrd == NULL)
  {
    destroy_record_group(prg);
    return -ENOMEM;
  }
  prg->rg_save_mmap_flag = save_mmap;

  //show_regs(get_pt_regs(NULL));
  /*
  __asm__ __volatile__ ("mov %%rsp, %0": "=r"(cur_rsp));
  show_kernel_stack((u_long*)cur_rsp);
  */

  // allocate a slab for retparams
  slab = VMALLOC(argsalloc_size);
  if (slab == NULL) return -ENOMEM;
  if (add_argsalloc_node(current->record_thrd, slab, argsalloc_size))
  {
    VFREE(slab);
    destroy_record_group(prg);
    current->record_thrd = NULL;
    TPRINT("Pid %d fork_replay: error adding argsalloc_node\n", current->pid);
    return -ENOMEM;
  }
  MPRINT("fork_replay added new slab %p to record_thread %p\n", slab, current->record_thrd);
#ifdef LOG_COMPRESS_1
  slab = VMALLOC(argsalloc_size);
  if (slab == NULL) return -ENOMEM;
  if (add_clog_node(current->record_thrd, slab, argsalloc_size))
  {
    VFREE(slab);
    destroy_record_group(prg);
    current->record_thrd = NULL;
    TPRINT("Pid %d fork_replay: error adding clog_node\n", current->pid);
    return -ENOMEM;
  }
  MPRINT("fork_replay added new slab %p to record_thread %p (clog)\n", slab, current->record_thrd);
#endif
#ifdef LOG_COMPRESS
  init_evs();
#endif

  current->replay_thrd = NULL;
  MPRINT("Record-Pid %d, tsk %p, prp %p, record_group size %lu, record_thread size %lu\n", current->pid, current, current->record_thrd, sizeof(struct record_group), sizeof(struct record_thread));

  if (linker)
  {
    strncpy_safe(current->record_thrd->rp_group->rg_linker, linker, MAX_LOGDIR_STRLEN);
    MPRINT("Set linker for record process to %s\n", linker);
  }

  if (fd >= 0)
  {
    retval = sys_close(fd);
    if (retval < 0) TPRINT("fork_replay: unable to close fd %d, rc=%ld\n", fd, retval);
  }

  if (pipe_fd >= 0)
  {
    char str[MAX_LOGDIR_STRLEN+1];
    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = snprintf(str, MAX_LOGDIR_STRLEN+1, "%s\n", prg->rg_logdir);
    if (retval < 0) TPRINT("fork_replay: rg_logdir is too long\n");

    sys_write(pipe_fd, str, strlen(str));

    set_fs(old_fs);
  }


  //show_regs(get_pt_regs(NULL));
  /*
  __asm__ __volatile__ ("mov %%rsp, %0": "=r"(cur_rsp));
  show_kernel_stack((u_long*)cur_rsp);
  */

  snprintf(ckpt, MAX_LOGDIR_STRLEN+10, "%s/ckpt", prg->rg_logdir);
  BUG_ON(IS_ERR_OR_NULL(theia_libpath));
  //MAX_LIBPAT_STRLEN+1 because theia_libpath should have 1 extra byte for null byte
  theia_libpath_len = strnlen(theia_libpath, MAX_LIBPATH_STRLEN + 1);
  argbuf = copy_args(args, env, &argbuflen, theia_libpath, theia_libpath_len);

  if (argbuf == NULL)
  {
    TPRINT("replay_checkpoint_to_disk: copy_args failed\n");
    return -EFAULT;
  }

  // Finally do exec from which we should not return
  get_user(pc, args);
  filename = getname(pc);
  TPRINT("fork_replay: filename is %s\n", filename);
  if (IS_ERR(filename))
  {
    TPRINT("fork_replay: unable to copy exec filname\n");
    return -EINVAL;
  }

#ifdef TIME_TRICK
  retval = replay_checkpoint_to_disk(ckpt, filename, argbuf, argbuflen, 0, &tv, &tp);
  init_det_time(&prg->rg_det_time, &tv, &tp);
#else
  // Save reduced-size checkpoint with info needed for exec
  retval = replay_checkpoint_to_disk(ckpt, filename, argbuf, argbuflen, 0);
#endif
  DPRINT("replay_checkpoint_to_disk returns %ld\n", retval);
  if (retval)
  {
    TPRINT("replay_checkpoint_to_disk returns %ld\n", retval);
    return retval;
  }

  // Hack to support multiple glibcs - record and LD_LIBRARY_PATH info
  prg->rg_libpath = get_libpath(env);
  if (prg->rg_libpath == NULL)
  {
    TPRINT("fork_replay: libpath not found\n");

    prg->rg_libpath = KMALLOC(theia_libpath_len+1, GFP_KERNEL);
    strncpy_safe(prg->rg_libpath, theia_libpath, theia_libpath_len);
    TPRINT("hardcoded libpath is (%s)", prg->rg_libpath);
    //    return -EINVAL;
  }
  TPRINT("prg->rg_libpath is (%s)", prg->rg_libpath);

  //show_regs(get_pt_regs(NULL));
  /*
  __asm__ __volatile__ ("mov %%rsp, %0": "=r"(cur_rsp));
  show_kernel_stack((u_long*)cur_rsp);
  */


  TPRINT("Yang before entering record_execve in fork_replay\n");
  retval = record_execve(filename, args, env, get_pt_regs(NULL));

  //show_regs(get_pt_regs(NULL));
  /*
  __asm__ __volatile__ ("mov %%rsp, %0": "=r"(cur_rsp));
  show_kernel_stack((u_long*)cur_rsp);
  */

  if (retval) TPRINT("fork_replay: execve returns %ld\n", retval);
  return retval;
}

EXPORT_SYMBOL(fork_replay);

char *
get_linker(void)
{
  if (current->record_thrd)
  {
    MPRINT("Get linker in record process: %s\n", current->record_thrd->rp_group->rg_linker);
    return current->record_thrd->rp_group->rg_linker;
  }
  else if (current->replay_thrd)
  {
    MPRINT("Get linker from record process: %s\n",
           current->replay_thrd->rp_group->rg_rec_group->rg_linker);
    return current->replay_thrd->rp_group->rg_rec_group->rg_linker;
  }
  else
  {
    TPRINT("Cannot get linker for non record/replay process\n");
    return NULL;
  }
}

long
replay_ckpt_wakeup(int attach_pin, char *logdir, char *linker, int fd, int follow_splits, int save_mmap)
{
  struct record_group *precg;
  struct record_thread *prect;
  struct replay_group *prepg;
  struct replay_thread *prept;
  long record_pid, rc;
  char ckpt[MAX_LOGDIR_STRLEN + 10];
  char **args;
  char **env;
  char *execname;
  __u64 rg_id;
  mm_segment_t old_fs = get_fs();
#ifdef TIME_TRICK
  struct timeval tv;
  struct timespec tp;
#endif
  int copy_len = 0;
  char cache_dir[CACHE_FILENAME_SIZE];

  MPRINT("In replay_ckpt_wakeup\n");
  if (current->record_thrd || current->replay_thrd)
  {
    TPRINT("fork_replay: pid %d cannot start a new replay while already recording or replaying\n", current->pid);
    return -EINVAL;
  }

  // First create a record group and thread for this replay
  precg = new_record_group(logdir);
  if (precg == NULL) return -ENOMEM;
  precg->rg_save_mmap_flag = save_mmap;

  prect = new_record_thread(precg, 0, NULL);
  if (prect == NULL)
  {
    destroy_record_group(precg);
    return -ENOMEM;
  }
  
  copy_len = strstr(logdir, "replay_logdb") - logdir;
  if(!(copy_len > 0 && copy_len < CACHE_FILENAME_SIZE)) {
    destroy_record_group(precg);
    TPRINT("copy_len is not valid %d\n", copy_len);
    return -ENOMEM;
  }
  memcpy(cache_dir, logdir, copy_len); 
  cache_dir[copy_len] = '\0';
  prepg = new_replay_group(precg, follow_splits, cache_dir);
  if (prepg == NULL)
  {
    destroy_record_group(precg);
    return -ENOMEM;
  }

  prept = new_replay_thread(prepg, prect, current->pid, 0, NULL);
  if (prept == NULL)
  {
    destroy_replay_group(prepg);
    destroy_record_group(precg);
    return -ENOMEM;
  }
  prept->rp_status = REPLAY_STATUS_RUNNING;
  // Since there is no recording going on, we need to dec record_thread's refcnt
  atomic_dec(&prect->rp_refcnt);

  // Restore the checkpoint
  strncpy_safe(ckpt, logdir, MAX_LOGDIR_STRLEN);
  strcat(ckpt, "/ckpt");

#ifdef TIME_TRICK
  record_pid = replay_resume_from_disk(ckpt, &execname, &args, &env, &rg_id, &tv, &tp);
  init_det_time(&precg->rg_det_time, &tv, &tp);
#else
  record_pid = replay_resume_from_disk(ckpt, &execname, &args, &env, &rg_id);
#endif
  current->rg_id = rg_id;
  if (record_pid < 0) return record_pid;

  // Read in the log records
  prect->rp_record_pid = record_pid;
  rc = read_log_data(prect);
  if (rc < 0) return rc;
#ifdef LOG_COMPRESS_1
  rc = read_clog_data(prect);
  if (rc < 0) return rc;
#endif

  // Create a replay group and thread for this process
  current->replay_thrd = prept;
  current->record_thrd = NULL;

  MPRINT("Pid %d set_record_group_id to %llu, rp_record_pid %d\n", current->pid, rg_id, prect->rp_record_pid);
  current->replay_thrd->rp_record_thread->rp_group->rg_id = rg_id;
#ifdef LOG_COMPRESS
  init_evs();
#endif

  if (linker)
  {
    strncpy_safe(current->replay_thrd->rp_group->rg_rec_group->rg_linker, linker, MAX_LOGDIR_STRLEN);
    MPRINT("Set linker for replay process to %s\n", linker);
  }

  // If pin, set the process to sleep, so that we can manually attach pin
  // We would then have to wake up the process after pin has been attached.
  if (attach_pin)
  {
    prept->app_syscall_addr = 1;  // Will be set to actual value later
    TPRINT("[%s|%d] pid %d, prt->app_syscall_addr is set to 1\n", __func__, __LINE__, current->pid);

    rc = read_mmap_log(precg);
    if (rc)
    {
      TPRINT("replay_ckpt_wakeup: could not read memory log for Pin support\n");
      return rc;
    }
    preallocate_memory(precg);  // Actually do the prealloaction for this process

    TPRINT("Pid %d sleeping in order to let you attach pin\n", current->pid);
    set_current_state(TASK_INTERRUPTIBLE);
    schedule();
  }

  if (fd >= 0)
  {
    rc = sys_close(fd);
    if (rc < 0) TPRINT("replay_ckpt_wakeup: unable to close fd %d, rc=%ld\n", fd, rc);
  }

  set_fs(KERNEL_DS);
  rc = replay_execve(execname, (const char *const *) args, (const char *const *) env, get_pt_regs(NULL));
  set_fs(old_fs);
  //  if (rc < 0)
  TPRINT("replay_ckpt_wakeup: replay_execve of <%s> returns %ld\n", args[0], rc);
  return rc;
}
EXPORT_SYMBOL(replay_ckpt_wakeup);

static inline long
new_syscall_enter(long sysnum)
{
  struct syscall_result *psr;
  struct record_thread *prt = current->record_thrd;
  u_long new_clock, start_clock;
  u_long *p;

#ifdef MCPRINT
  if (replay_min_debug || replay_debug)
  {
    MPRINT("Pid %d add syscall %ld enter\n", current->pid, sysnum);
  }
#endif

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

  psr = &prt->rp_log[prt->rp_in_ptr];
  psr->sysnum = sysnum;
  new_clock = atomic_add_return(1, prt->rp_precord_clock);
  start_clock = new_clock - prt->rp_expected_clock - 1;
  //TPRINT ("[%s|%d]pid %d incremented precord_clock to %d, expected_clock %d, start_clock %d, on syscall %ld enter\n", __func__,__LINE__,current->pid, atomic_read(prt->rp_precord_clock), prt->rp_expected_clock, start_clock,sysnum);
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
#ifdef LOG_COMPRESS_1
    // compression for start_clock
    encodeValue((unsigned int) start_clock, 32, 4, clog_alloc(4));
    if (c_detail)
      TPRINT("Pid %d encoded 4 bytes.\n", current->pid);
    status_add(&current->record_thrd->rp_clog.syscall_status, 1, sizeof(long) << 3, getCumulativeBitsWritten(list_first_entry(&current->record_thrd->rp_clog_list, struct clog_node, list)));
#endif
  }
  prt->rp_expected_clock = new_clock;
  //  MPRINT ("pid %d incremented clock to %d on syscall %ld enter\n", current->pid, atomic_read(prt->rp_precord_clock), sysnum);

#ifdef USE_HPC
  psr->hpc_begin = rdtsc(); // minus cc_calibration
#endif

#ifdef TIME_TRICK
  return new_clock - 1;
#else
  return 0;
#endif
}

long new_syscall_enter_external(long sysnum)
{
  return new_syscall_enter(sysnum);
}

#if defined(LOG_COMPRESS)
static inline long cnew_syscall_done(long sysnum, long retval, long prediction, int shift_clock)
#else
static inline long
new_syscall_done(long sysnum, long retval)
#endif
{
  struct syscall_result *psr;
  struct record_thread *prt = current->record_thrd;
  u_long new_clock, stop_clock;
  u_long *ulp;
  long *p;

  psr = &prt->rp_log[prt->rp_in_ptr];

#ifdef TIME_TRICK
  if (shift_clock)
    atomic_set(&current->record_thrd->rp_group->rg_det_time.flag, 1);
#endif

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

  //TPRINT ("[%s|%d]pid %d incremented precord_clock to %d, expected_clock %d, start_clock %d, on syscall %ld enter\n", __func__,__LINE__,current->pid, atomic_read(prt->rp_precord_clock), prt->rp_expected_clock, stop_clock,sysnum);
  return 0;
}

#ifdef LOG_COMPRESS
static inline long new_syscall_done(long sysnum, long retval)
{
  return cnew_syscall_done(sysnum, retval, -1, 1);
}
#endif

//Yang
static inline long
_new_syscall_exit(long sysnum, void *retparams, void *ahgparams)
{
  struct syscall_result *psr;
  struct record_thread *prt = current->record_thrd;

  psr = &prt->rp_log[prt->rp_in_ptr];
  psr->flags = retparams ? (psr->flags | SR_HAS_RETPARAMS) : psr->flags;
  //Yang
  psr->flags = ahgparams ? (psr->flags | SR_HAS_AHGPARAMS) : psr->flags;
#ifdef USE_HPC
  psr->hpc_end = rdtsc();
#endif
  if (unlikely(prt->rp_signals)) signal_wake_up(current, 0);  // we want to deliver signals when this syscall exits

#ifdef MCPRINT
  if (replay_min_debug || replay_debug)
  {
    MPRINT("Pid %d add syscall %d exit\n", current->pid, psr->sysnum);
  }
#endif
  prt->rp_in_ptr += 1;
  prt->rp_count += 1;
  return 0;
}

const char *replay_get_exec_filename(void)
{
  MPRINT("Got exec filename: %s\n", current->replay_thrd->rp_exec_filename);
  return current->replay_thrd->rp_exec_filename;
}

long new_syscall_exit_external(long sysnum, long retval, void *retparams)
{
  new_syscall_done(sysnum, retval);
  return new_syscall_exit(sysnum, retparams);
}

int
get_record_pending_signal(siginfo_t *info)
{
  struct record_thread *prt = current->record_thrd;
  struct repsignal *psignal;
  int signr;

  if (!prt->rp_signals)
  {
    TPRINT("get_record_pending_signal: no signal to return\n");
    return 0;
  }
  MPRINT("Delivering deferred signal now at %d\n", atomic_read(prt->rp_precord_clock));
  psignal = prt->rp_signals;
  prt->rp_signals = psignal->next;
  memcpy(info, &psignal->info, sizeof(siginfo_t));
  signr = psignal->signr;
  KFREE(psignal);

  return signr;
}

// Don't use standard debugging by default here because a TPRINT could deadlock kernel
#define SIGPRINT(x,...)
//#define SIGPRINT TPRINT

static int defer_signal(struct record_thread *prt, int signr, siginfo_t *info)
{
  struct repsignal *psignal = KMALLOC(sizeof(struct repsignal), GFP_ATOMIC);
  if (psignal == NULL)
  {
    SIGPRINT("Cannot allocate replay signal\n");
    return 0;  // Replay broken - but might as well let recording proceed
  }
  psignal->signr = signr;
  memcpy(&psignal->info, info, sizeof(siginfo_t));
  psignal->next = prt->rp_signals;
  prt->rp_signals = psignal;
  return -1;
}

int get_record_ignore_flag(void)
{
  struct record_thread *prt = current->record_thrd;
  int ignore_flag = 0;

  if (prt->rp_ignore_flag_addr)
  {
    get_user(ignore_flag, prt->rp_ignore_flag_addr);
  }
  return ignore_flag;
}

// This is called with interrupts disabled so there is little we can do
// If signal is to be deferred, we do that since we can use atomic allocation.
// mcc: Called with current->sighand->siglock held and local interrupts disabled
long
check_signal_delivery(int signr, siginfo_t *info, struct k_sigaction *ka, int ignore_flag)
{
  struct record_thread *prt = current->record_thrd;
  int sysnum = syscall_get_nr(current, get_pt_regs(NULL));
  struct syscall_result *psr;

  if (prt->rp_in_ptr == 0)
  {
    SIGPRINT("Pid %d - no syscall records yet - signal %d\n", current->pid, signr);
    if (sig_fatal(current, signr))
    {
      SIGPRINT("Fatal signal sent w/o recording - replay broken?\n");
      return 0;
    }
    return defer_signal(prt, signr, info);
  }
  psr = &prt->rp_log[(prt->rp_in_ptr - 1)];

  SIGPRINT("Pid %d check signal delivery signr %d fatal %d - clock is currently %d ignore flag %d sysnum %d psr->sysnum %d handler %p\n",
           current->pid, signr, sig_fatal(current, signr), atomic_read(prt->rp_precord_clock), ignore_flag, sysnum, psr->sysnum, ka->sa.sa_handler);

  if (ignore_flag && sysnum >= 0)
  {
    return 0;
  }
  else if (!sig_fatal(current, signr) && sysnum != psr->sysnum && sysnum != 0 /* restarted syscall */)
  {
    // This is an unrecorded system call or a trap.  Since we cannot guarantee that the signal will not delivered
    // at this same place on replay, delay the delivery until we reach such a safe place.  Signals that immediately
    // terminate the program should not be delayed, however.
    SIGPRINT("Pid %d: not a safe place to record a signal - syscall is %d but last recorded syscall is %d ignore flag %d\n", current->pid, sysnum, psr->sysnum, ignore_flag);
    return defer_signal(prt, signr, info);
  }
  return 0; // Will handle this signal later
}

// This is a signal that will actually be handled, we need to record it
long
record_signal_delivery(int signr, siginfo_t *info, struct k_sigaction *ka)
{
  struct record_thread *prt = current->record_thrd;
  struct repsignal *psignal;
  struct syscall_result *psr = &prt->rp_log[(prt->rp_in_ptr - 1)];
  struct repsignal_context *pcontext;
  struct pthread_log_head *phead = (struct pthread_log_head __user *) prt->rp_user_log_addr;
  int ignore_flag, need_fake_calls = 1;
  int sysnum = syscall_get_nr(current, get_pt_regs(NULL));

  if (prt->rp_ignore_flag_addr)
  {
    get_user(ignore_flag, prt->rp_ignore_flag_addr);
  }
  else
  {
    ignore_flag = 0;
  }

  MPRINT("Pid %d recording signal delivery signr %d fatal %d - clock is currently %d ignore flag %d sysnum %d psr->sysnum %d handler %p\n",
         current->pid, signr, sig_fatal(current, signr), atomic_read(prt->rp_precord_clock), ignore_flag, sysnum, psr->sysnum, ka->sa.sa_handler);

  // Note that a negative sysnum means we entered kernel via trap, interrupt, etc.  It is not safe to deliver a signal here, even in the ignore region because
  // We might be in a user-level critical section where we are adding to the log.  Instead, defer and deliver later if possible.
  if (ignore_flag && sysnum >= 0)
  {

    // Signal delivered after an ignored syscall.  We need to add a "fake" syscall for sequencing.
    new_syscall_enter(SIGNAL_WHILE_SYSCALL_IGNORED);
    new_syscall_done(SIGNAL_WHILE_SYSCALL_IGNORED, 0);
    new_syscall_exit(SIGNAL_WHILE_SYSCALL_IGNORED, NULL);
    psr = &prt->rp_log[(prt->rp_in_ptr - 1)];

    // Also, let the user-level know to make syscall on replay by incrementing count in ignore_flag
    get_user(need_fake_calls, &phead->need_fake_calls);
    need_fake_calls++;
    put_user(need_fake_calls, &phead->need_fake_calls);
    MPRINT("Pid %d record_signal inserts fake syscall - ignore_flag now %d, need_fake_calls now %d\n", current->pid, ignore_flag, need_fake_calls);
  }
  else if (!sig_fatal(current, signr) && sysnum != psr->sysnum && sysnum != 0 /* restarted syscall */)
  {
    TPRINT("record_signal_delivery: this should have been handled!!!\n");
    return -1;
  }
  if (sig_fatal(current, signr) && sysnum != psr->sysnum && sysnum != 0 /* restarted syscall */)
  {
    struct pthread_log_head __user *phead = (struct pthread_log_head __user *) prt->rp_user_log_addr;
    // Sweet! There is always guaranteed to be allocated space for a record - also, we do not need to write out a full log since we are always the last record
#ifdef USE_DEBUG_LOG
    struct pthread_log_data __user *pdata;
    MPRINT("Pid %d: after signal, user code will not run again, so the kernel needs to insert a fake call for replay\n", current->pid);
    get_user(pdata, &phead->next);
    if (pdata)
    {
      put_user(need_fake_calls, &pdata->retval);  // Add the record - akin to what pthread_log.c in eglibc does
      put_user(FAKE_SYSCALLS, &pdata->type);
      pdata++;
      put_user(pdata, &phead->next);
      put_user(0, &phead->need_fake_calls);
    }
    else
    {
      TPRINT("record_signal_delivery: pid %d could not get head pointer\n", current->pid);
    }
#else
    char __user *pnext;
    unsigned long entry;

    MPRINT("Pid %d: after signal, user code will not run again, so the kernel needs to insert a fake call for replay\n", current->pid);
    get_user(pnext, &phead->next);
    if (pnext)
    {
      get_user(entry, &phead->num_expected_records);
      entry |= FAKE_CALLS_FLAG;
      put_user(entry, (u_long __user *) pnext);
      pnext += sizeof(u_long);
      put_user(need_fake_calls, (int __user *) pnext);
      pnext += sizeof(int);
      put_user(pnext, &phead->next);
      put_user(0, &phead->num_expected_records);
      put_user(0, &phead->need_fake_calls);
    }
    else
    {
      TPRINT("record_signal_delivery: pid %d could not get head pointer\n", current->pid);
    }
#endif

    if (!ignore_flag)
    {
      // Also need the fake syscall
      new_syscall_enter(SIGNAL_WHILE_SYSCALL_IGNORED);
      new_syscall_done(SIGNAL_WHILE_SYSCALL_IGNORED, 0);
      new_syscall_exit(SIGNAL_WHILE_SYSCALL_IGNORED, NULL);
      psr = &prt->rp_log[(prt->rp_in_ptr - 1)];
    }
  }

  MPRINT("Pid %d: recording and delivering signal\n", current->pid);

  psignal = ARGSKMALLOC(sizeof(struct repsignal), GFP_KERNEL);
  if (psignal == NULL)
  {
    TPRINT("Cannot allocate replay signal\n");
    return 0;  // Replay broken - but might as well let recording proceed
  }
  psignal->signr = signr;
  memcpy(&psignal->info, info, sizeof(siginfo_t));
  memcpy(&psignal->ka, ka, sizeof(struct k_sigaction));
  psignal->blocked = current->blocked;
  psignal->real_blocked = current->real_blocked;
  psignal->next = NULL;

  // Add signal to last record in log - will be delivered after syscall on replay
  if ((psr->flags & SR_HAS_SIGNAL) == 0)
  {
    psr->flags |= SR_HAS_SIGNAL;
  }
  else
  {
    prt->rp_last_signal->next = psignal;
  }
  prt->rp_last_signal = psignal;

  if (ka->sa.sa_handler > SIG_IGN)
  {
    // Also save context from before signal
    pcontext = KMALLOC(sizeof(struct repsignal_context), GFP_ATOMIC);
    pcontext->ignore_flag = ignore_flag;
    pcontext->next = prt->rp_repsignal_context_stack;
    prt->rp_repsignal_context_stack = pcontext;
    // If we were in an ignore region, that is no longer the case
    if (prt->rp_ignore_flag_addr) put_user(0, prt->rp_ignore_flag_addr);
  }

  return 0;
}

void
replay_signal_delivery(int *signr, siginfo_t *info)
{
  struct replay_thread *prt = current->replay_thrd;
  struct repsignal *psignal;

  if (!prt->rp_signals)
  {
    MPRINT("pid %d replay_signal called but no signals, signr is %d\n", current->pid, *signr);
    *signr = 0;
    return;
  }
  psignal = (struct repsignal *) argshead(prt->rp_record_thread);
  argsconsume(prt->rp_record_thread, sizeof(struct repsignal));

  MPRINT("Pid %d replaying signal delivery signo %d, clock %lu\n", current->pid, psignal->signr, *(prt->rp_preplay_clock));
  prt->rp_signals = psignal->next ? 1 : 0;

  *signr = psignal->signr;
  memcpy(info, &psignal->info, sizeof(siginfo_t));

  if (prt->app_syscall_addr == 0)
  {
    MPRINT("Pid %d No Pin attached, so setting blocked signal mask to recorded mask, and copying k_sigaction\n", current->pid);
    memcpy(&current->sighand->action[psignal->signr - 1],
           &psignal->ka, sizeof(struct k_sigaction));
    current->blocked = psignal->blocked;
    current->real_blocked = psignal->real_blocked;
  }
}

int replay_has_pending_signal(void)
{
  if (current->replay_thrd)
  {
    if (current->replay_thrd->rp_signals)
    {
      DPRINT("Pid %d replay_has_pending_signals", current->pid);
      return 1;
    }
  }
  else if (current->record_thrd)     // recording
  {
    struct record_thread *prt = current->record_thrd;
    int sysnum = syscall_get_nr(current, get_pt_regs(NULL));
    if (current->record_thrd->rp_signals && (sysnum == prt->rp_log[(prt->rp_in_ptr - 1)].sysnum))
    {
      DPRINT("safe to return pending signal\n");
      return 1;
    }
  }
  return 0;
}

static void
write_and_free_kernel_log(struct record_thread *prect)
{
  int fd = 0;
  struct syscall_result *write_psr;
  loff_t pos;
  struct file *file = NULL;

  mm_segment_t old_fs = get_fs();
  set_fs(KERNEL_DS);
  file = init_log_write(prect, &pos, &fd);
  if (file)
  {
    write_psr = &prect->rp_log[0];
    write_log_data(file, &pos, prect, write_psr, prect->rp_in_ptr, false);
    term_log_write(file, fd);
  }
  set_fs(old_fs);

  argsfreeall(prect);
}

#ifdef WRITE_ASYNC
// parameters to pass to the work queue thread
struct write_async_params
{
  struct work_struct work;
  struct record_thread *prect;
};


/* Handler that is called when the kernel work queue event thread is run */
static void
write_and_free_handler(struct work_struct *work)
{
  int fd = 0;
  struct syscall_result *write_psr;
  loff_t pos;
  struct file *file = NULL;
  mm_segment_t old_fs;
  struct record_thread *prect;

  struct write_async_params *awp;
  awp = (struct write_async_params *) work;
  prect = awp->prect;
  old_fs = get_fs();

  MPRINT("Pid %d write_and_free_handler called for record pid %d\n", current->pid, prect->rp_record_pid);

  set_fs(KERNEL_DS);
  file = init_log_write(prect, &pos, &fd);
  if (file)
  {
    MPRINT("Writing %lu records for pid %d\n", prect->rp_in_ptr, current->pid);
    write_psr = &prect->rp_log[0];
    write_log_data(file, &pos, prect, write_psr, prect->rp_in_ptr, false);
    term_log_write(file, fd);
  }
#ifdef LOG_COMPRESS_1
  file = init_clog_write(prect, &pos, &fd);
  if (file)
  {
    write_psr = &prect->rp_log[0];
    write_clog_data(file, &pos, prect, write_psr, prect->rp_in_ptr);
    term_clog_write(file, fd);
  }
#endif

  set_fs(old_fs);

  argsfreeall(prect);
#ifdef LOG_COMPRESS_1
  clogfreeall(prect);
#endif
  __destroy_record_thread(prect);
  KFREE(awp);
  return;
}

/* Write and free the kernel log asynchronously by scheduling work on the kernel work queue */
static void
write_and_free_kernel_log_async(struct record_thread *prect)
{
  struct write_async_params *wap;
  wap = KMALLOC(sizeof(struct write_async_params), GFP_KERNEL);
  wap->prect = prect;

  // increment so that we don't destroy record thread until after the handler finishes
  atomic_inc(&prect->rp_refcnt);
  INIT_WORK((struct work_struct *) wap, write_and_free_handler);
  schedule_work((struct work_struct *) wap);
  MPRINT("Pid %d scheduled write_and_free_handler\n", current->pid);
}
#endif

/* Writes out the user log - currently does not handle wraparound - so write in one big chunk */
long
write_user_log(struct record_thread *prect)
{
  struct pthread_log_head __user *phead = (struct pthread_log_head __user *) prect->rp_user_log_addr;
  u_long next;
  char __user *start;
  //struct stat64 st;
  //64port
  struct stat st;
  char filename[MAX_LOGDIR_STRLEN + 20];
  struct file *file;
  int fd;
  mm_segment_t old_fs;
  long to_write, written;
  long rc = 0;

  DPRINT("Pid %d: write_user_log %p\n", current->pid, phead);
  if (phead == 0) return 0; // Nothing to do

  if (copy_from_user(&next, &phead->next, sizeof(u_long)))
  {
    TPRINT("Pid %d: unable to get log head next ptr\n", current->pid);
    return -EINVAL;
  }
  DPRINT("Pid %d: log current address is at %lx\n", current->pid, next);
  start = (char __user *) phead + sizeof(struct pthread_log_head);
  to_write = (char __user *) next - start;
  MPRINT("Pid %d - need to write %ld bytes of user log\n", current->pid, to_write);
  if (to_write == 0)
  {
    MPRINT("Pid %d - no entries to write in ulog\n", current->pid);
    return 0;
  }

  rc = snprintf(filename, MAX_LOGDIR_STRLEN+20, "%s/ulog.id.%d", prect->rp_group->rg_logdir, prect->rp_record_pid);
  if (rc < 0) {
    TPRINT("write_user_log: rg_logdir is too long\n");
    return -EINVAL;
  }

  old_fs = get_fs();
  set_fs(KERNEL_DS);

  // see if we're appending to the user log data before
  if (prect->rp_ulog_opened)
  {
    DPRINT("Pid %d, ulog %s has been opened before, so we'll append\n", current->pid, filename);
    //rc = sys_stat64(filename, &st);
    //64port
    rc = sys_newstat(filename, &st);
    if (rc < 0)
    {
      TPRINT("Pid %d - write_log_data, can't append stat of file %s failed\n", current->pid, filename);
      return -EINVAL;
    }
    fd = sys_open(filename, O_RDWR | O_APPEND | O_LARGEFILE, 0777);
  }
  else
  {
    fd = sys_open(filename, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE, 0777);
    if (fd > 0)
    {
      rc = sys_fchmod(fd, 0777);
      if (rc == -1)
      {
        TPRINT("Pid %d fchmod failed\n", current->pid);
      }
    }
    prect->rp_ulog_opened = 1;
    //rc = sys_stat64(filename, &st);
    //64port
    rc = sys_newstat(filename, &st);
  }

  if (fd < 0)
  {
    TPRINT("Cannot open log file %s, rc =%d\n", filename, fd);
    return -EINVAL;
  }

  file = fget(fd);
  if (file == NULL)
  {
    TPRINT("write_user_log: invalid file\n");
    return -EINVAL;
  }

  // Before each user log segment, we write the number of bytes in the segment
  written = vfs_write(file, (char *) &to_write, sizeof(int), &prect->rp_read_ulog_pos);
  set_fs(old_fs);

  if (written != sizeof(int))
  {
    TPRINT("write_user_log: tried to write %lu, got rc %ld\n", sizeof(int), written);
    rc = -EINVAL;
  }

  written = vfs_write(file, start, to_write, &prect->rp_read_ulog_pos);
  if (written != to_write)
  {
    TPRINT("write_user_log1: tried to write %ld, got rc %ld\n", to_write, written);
    rc = -EINVAL;
  }

  fput(file);
  DPRINT("Pid %d closing %s\n", current->pid, filename);
  sys_close(fd);

  // We reset the next pointer to reflect the records that were written
  // In some circumstances such as failed execs, this will prevent dup. writes
#ifdef USE_DEBUG_LOG
  next = (u_long)((char __user *) phead + sizeof(struct pthread_log_head));
#else
  next = (u_long) phead + sizeof(struct pthread_log_head);
#endif
  if (copy_to_user(&phead->next, &next, sizeof(u_long)))
  {
    TPRINT("Unable to put log head next\n");
    return -EINVAL;
  }

  DPRINT("Pid %d: log current address is at %lx\n", current->pid, next);

  return rc;
}

/* Reads in a user log - currently does not handle wraparound - so read in one big chunk */
long
read_user_log(struct record_thread *prect)
{
  struct pthread_log_head __user *phead = (struct pthread_log_head __user *) prect->rp_user_log_addr;
  char __user *start;
  //struct stat64 st;
  //port
  struct stat st;
  char filename[MAX_LOGDIR_STRLEN + 20];
  struct file *file;
  int fd;
  mm_segment_t old_fs;
  long copyed, rc = 0;

  // the number of entries in this segment
  int num_bytes;

  DPRINT("Pid %d: read_user_log %p\n", current->pid, phead);
  if (phead == 0) return -EINVAL; // Nothing to do

  start = (char __user *) phead + sizeof(struct pthread_log_head);
  DPRINT("Log start is at %p\n", start);

  snprintf(filename, MAX_LOGDIR_STRLEN+20, "%s/ulog.id.%d", prect->rp_group->rg_logdir, prect->rp_record_pid);
  old_fs = get_fs();
  set_fs(KERNEL_DS);
  //rc = sys_stat64(filename, &st);
  //64port
  rc = sys_newstat(filename, &st);
  if (rc < 0)
  {
    TPRINT("Stat of file %s failed\n", filename);
    set_fs(old_fs);
    return rc;
  }
  fd = sys_open(filename, O_RDONLY | O_LARGEFILE, 0644);
  set_fs(old_fs);
  if (fd < 0)
  {
    TPRINT("Cannot open log file %s, rc =%d\n", filename, fd);
    return fd;
  }

  file = fget(fd);
  if (file == NULL)
  {
    TPRINT("read_user_log: invalid file\n");
    return -EINVAL;
  }

  // read how many entries that are in this segment
  set_fs(KERNEL_DS);
  copyed = vfs_read(file, (char *) &num_bytes, sizeof(int), &prect->rp_read_ulog_pos);
  set_fs(old_fs);
  if (copyed != sizeof(int))
  {
    if (copyed) TPRINT("read_user_log: tried to read num entries %lu, got rc %zd\n", sizeof(int), copyed);
    rc = -EINVAL;
    goto close_out;
  }

  // read the entire segment after we've read how many entries are in it
  copyed = vfs_read(file, (char __user *) start, num_bytes, &prect->rp_read_ulog_pos);
  if (copyed != num_bytes)
  {
    TPRINT("read_user_log: tried to read %d, got rc %ld\n", num_bytes, copyed);
    rc = -EINVAL;
  }
  else
  {
    DPRINT("Pid %d read %ld bytes from user log\n", current->pid, copyed);
    put_user(start + copyed, (char **) &phead->end);
  }


close_out:
  fput(file);
  sys_close(fd);

  return rc;
}

#ifdef USE_EXTRA_DEBUG_LOG
/* Writes out the user log - currently does not handle wraparound - so write in one big chunk */
long
write_user_extra_log(struct record_thread *prect)
{
  struct pthread_extra_log_head __user *phead = (struct pthread_extra_log_head __user *) prect->rp_user_extra_log_addr;
  struct pthread_extra_log_head head;
  char __user *start;
  //  struct stat64 st;
  //64port
  struct stat st;
  char filename[MAX_LOGDIR_STRLEN + 20];
  struct file *file;
  int fd;
  mm_segment_t old_fs;
  long to_write, written;
  long rc = 0;

  DPRINT("Pid %d: write_user_extra_log %p\n", current->pid, phead);
  if (phead == 0) return 0; // Nothing to do

  if (copy_from_user(&head, phead, sizeof(struct pthread_extra_log_head)))
  {
    TPRINT("Pid %d: unable to get extra log head\n", current->pid);
    return -EINVAL;
  }
  DPRINT("Pid %d: extra log current address is at %p\n", current->pid, head.next);
  start = (char __user *) phead + sizeof(struct pthread_extra_log_head);
  to_write = (char *) head.next - start;
  MPRINT("Pid %d - need to write %ld bytes of user extra log\n", current->pid, to_write);
  if (to_write == 0)
  {
    MPRINT("Pid %d - no entries to write in extra user log\n", current->pid);
    return 0;
  }

  rc = snprintf(filename, MAX_LOGDIR_STRLEN+20, "%s/elog.id.%d", prect->rp_group->rg_logdir, prect->rp_record_pid);
  if (rc < 0) {
    TPRINT("write_user_extra_log: rg_logdir is too long\n");
    return -EINVAL;
  }

  old_fs = get_fs();
  set_fs(KERNEL_DS);

  // see if we're appending to the user log data before
  if (prect->rp_elog_opened)
  {
    DPRINT("Pid %d, extra log %s has been opened before, so we'll append\n", current->pid, filename);
    //rc = sys_stat64(filename, &st);
    //64port
    rc = sys_newstat(filename, &st);
    if (rc < 0)
    {
      TPRINT("Pid %d - write_extra_log_data, can't append stat of file %s failed\n", current->pid, filename);
      return -EINVAL;
    }
    fd = sys_open(filename, O_RDWR | O_APPEND | O_LARGEFILE, 0777);
  }
  else
  {
    fd = sys_open(filename, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE, 0777);
    if (fd > 0)
    {
      rc = sys_fchmod(fd, 0777);
      if (rc == -1)
      {
        TPRINT("Pid %d fchmod failed\n", current->pid);
      }
    }
    prect->rp_elog_opened = 1;
    //rc = sys_stat64(filename, &st);
    //64port
    rc = sys_newstat(filename, &st);
  }

  if (fd < 0)
  {
    TPRINT("Cannot open exta log file %s, rc =%d\n", filename, fd);
    return -EINVAL;
  }

  file = fget(fd);
  if (file == NULL)
  {
    TPRINT("write_extra_user_log: invalid file\n");
    return -EINVAL;
  }

  // Before each user log segment, we write the number of bytes in the segment
  written = vfs_write(file, (char *) &to_write, sizeof(int), &prect->rp_read_elog_pos);
  set_fs(old_fs);

  if (written != sizeof(int))
  {
    TPRINT("write_user_log: tried to write %d, got rc %ld\n", sizeof(int), written);
    rc = -EINVAL;
  }

  written = vfs_write(file, start, to_write, &prect->rp_read_elog_pos);
  if (written != to_write)
  {
    TPRINT("write_extra_user_log1: tried to write %ld, got rc %ld\n", to_write, written);
    rc = -EINVAL;
  }

  fput(file);
  DPRINT("Pid %d closing %s\n", current->pid, filename);
  sys_close(fd);

  // We reset the next pointer to reflect the records that were written
  // In some circumstances such as failed execs, this will prevent dup. writes
  head.next = (char __user *) phead + sizeof(struct pthread_extra_log_head);

  if (copy_to_user(phead, &head, sizeof(struct pthread_extra_log_head)))
  {
    TPRINT("Unable to put extra log head\n");
    return -EINVAL;
  }

  DPRINT("Pid %d: log extra current address is at %p\n", current->pid, head.next);

  return rc;
}

/* Reads in a user log - currently does not handle wraparound - so read in one big chunk */
long
read_user_extra_log(struct record_thread *prect)
{
  struct pthread_extra_log_head *phead = (struct pthread_extra_log_head __user *) prect->rp_user_extra_log_addr;
  char __user *start;
  //struct stat64 st;
  //64port
  struct stat st;
  char filename[MAX_LOGDIR_STRLEN + 20];
  struct file *file;
  int fd;
  mm_segment_t old_fs;
  long copyed, rc = 0;

  // the number of entries in this segment
  int num_bytes;

  DPRINT("Pid %d: read_user_extra_log %p\n", current->pid, phead);
  if (phead == 0) return -EINVAL; // Nothing to do

  start = (char __user *) phead + sizeof(struct pthread_extra_log_head);
  DPRINT("Extra log start is at %p\n", start);

  rc = snprintf(filename, MAX_LOGDIR_STRLEN+20, "%s/elog.id.%d", prect->rp_group->rg_logdir, prect->rp_record_pid);
  if (rc < 0) {
    TPRINT("read_user_extra_log: rg_logdir is too long\n");
    return -EINVAL;
  }

  old_fs = get_fs();
  set_fs(KERNEL_DS);
  //rc = sys_stat64(filename, &st);
  //64port
  rc = sys_newstat(filename, &st);
  if (rc < 0)
  {
    TPRINT("Stat of file %s failed\n", filename);
    set_fs(old_fs);
    return rc;
  }
  fd = sys_open(filename, O_RDONLY | O_LARGEFILE, 0644);
  set_fs(old_fs);
  if (fd < 0)
  {
    TPRINT("Cannot open extra log file %s, rc =%d\n", filename, fd);
    return fd;
  }

  file = fget(fd);
  if (file == NULL)
  {
    TPRINT("read_user_extra_log: invalid file\n");
    return -EINVAL;
  }

  // read how many entries that are in this segment
  set_fs(KERNEL_DS);
  copyed = vfs_read(file, (char *) &num_bytes, sizeof(int), &prect->rp_read_elog_pos);
  set_fs(old_fs);
  if (copyed != sizeof(int))
  {
    TPRINT("read_extra_user_log: tried to read num entries %d, got rc %ld\n", sizeof(int), copyed);
    rc = -EINVAL;
    goto close_out;
  }

  // read the entire segment after we've read how many entries are in it
  copyed = vfs_read(file, (char __user *) start, num_bytes, &prect->rp_read_elog_pos);
  if (copyed != num_bytes)
  {
    TPRINT("read_user_extra_log: tried to read %d, got rc %ld\n", num_bytes, copyed);
    rc = -EINVAL;
  }
  else
  {
    DPRINT("Pid %d read %ld bytes from extra log\n", current->pid, copyed);
    put_user(start + copyed, &phead->end);
  }

close_out:
  fput(file);
  sys_close(fd);

  return rc;
}
#endif

/* Used for Pin support.
 * We need to consume syscall log entries in a specific order
 * on exit after a SIGTRAP */
static inline long
get_next_clock(struct replay_thread *prt, struct replay_group *prg, long wait_clock_value)
{
  struct replay_thread *tmp;
  long retval = 0;
  int ret;

  while (*(prt->rp_preplay_clock) < wait_clock_value)
  {
    MPRINT("Replay pid %d is waiting for clock value %ld, current clock value is %ld\n", current->pid, wait_clock_value, *(prt->rp_preplay_clock));
    prt->rp_status = REPLAY_STATUS_WAIT_CLOCK;
    prt->rp_wait_clock = wait_clock_value;

    tmp = prt->rp_next_thread;
    do
    {
      MPRINT("Consider thread %d status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_status, tmp->rp_wait_clock);
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
        if (prt->rp_pin_restart_syscall)
        {
          TPRINT("Pid %d: This was a restarted syscall entry, let's sleep and try again\n", current->pid);
          msleep(1000);
          break;
        }
        TPRINT("Pid %d (recpid %d): Crud! no eligible thread to run\n", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid);
        TPRINT("current clock value is %ld waiting for %lu\n", *(prt->rp_preplay_clock), wait_clock_value);
        dump_stack(); // how did we get here?
        // cycle around again and print
        tmp = tmp->rp_next_thread;
        while (tmp != current->replay_thrd)
        {
          TPRINT("\t thread %d (recpid %d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
          tmp = tmp->rp_next_thread;
        }
        sys_exit_group(0);
      }
    }
    while (tmp != prt);

    while (!(prt->rp_status == REPLAY_STATUS_RUNNING || (prt->rp_replay_exit && prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr + 1)))
    {
      MPRINT("Replay pid %d waiting for clock value %ld but current clock value is %ld\n", current->pid, wait_clock_value, *(prt->rp_preplay_clock));
      rg_unlock(prg->rg_rec_group);
      ret = wait_event_interruptible_timeout(prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING || prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr + 1), SCHED_TO);
      rg_lock(prg->rg_rec_group);
      if (ret == 0) TPRINT("Replay pid %d timed out waiting for clock value %ld but current clock value is %ld\n", current->pid, wait_clock_value, *(prt->rp_preplay_clock));
      if (prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && (prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr + 1)))
      {
        MPRINT("Replay pid %d woken up to die on entrance in_ptr %lu out_ptr %lu\n", current->pid, prt->rp_record_thread->rp_in_ptr, prt->rp_out_ptr);
        rg_unlock(prg->rg_rec_group);
        sys_exit(0);
      }
      if (ret == -ERESTARTSYS)
      {
        TPRINT("Pid %d: entering syscall cannot wait due to signal - try again\n", current->pid);
        rg_unlock(prg->rg_rec_group);
        msleep(1000);
        rg_lock(prg->rg_rec_group);
      }
    }
  }
  (*prt->rp_preplay_clock)++;
  rg_unlock(prg->rg_rec_group);
  MPRINT("Pid %d incremented replay clock to %ld\n", current->pid, *(prt->rp_preplay_clock));
  return retval;
}

asmlinkage long
sys_wakeup_paused_process(pid_t pid)
{
  struct task_struct *tsk = NULL;
  struct replay_thread *tmp;
  struct replay_thread *prt;
  tsk = pid_task(find_vpid(pid), PIDTYPE_PID);
  if (tsk && tsk->replay_thrd)
  {
    prt = tsk->replay_thrd;
    tmp = prt;
    do
    {
      TPRINT("Consider thread %d status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_status, tmp->rp_wait_clock);
      if (tmp->rp_status == REPLAY_STATUS_RUNNING && tmp->rp_wait_clock <= *(prt->rp_preplay_clock + 1))
      {
        wake_up(&tmp->rp_waitq);
        DPRINT("Wake it up\n");
        break;
      }
      tmp = tmp->rp_next_thread;
      if (tmp == prt)
      {
        TPRINT("Replay_pause: Pid %d (recpid %d): Crud! no eligible thread to run on syscall entry\n", current->pid, prt->rp_record_thread->rp_record_pid);
        TPRINT("current clock value is %ld looking for %lu\n", *(prt->rp_preplay_clock), *(prt->rp_preplay_clock + 1));
        dump_stack(); // how did we get here?
        // cycle around again and print
        tmp = tmp->rp_next_thread;
        while (tmp != current->replay_thrd)
        {
          TPRINT("\t thread %d (recpid %d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
          tmp = tmp->rp_next_thread;
        }
      }
    }
    while (tmp != prt);
  }
  else
  {
    TPRINT("Pid %d is not a replay thread, please check the paramter.\n", pid);
    return 0;
  }
  return 1;
}

#ifdef LOG_COMPRESS
static inline long cget_next_syscall_enter(struct replay_thread *prt, struct replay_group *prg, int syscall, char **ppretparams, struct syscall_result **ppsr, long prediction, u_long *ret_start_clock)
#else
static inline long
get_next_syscall_enter(struct replay_thread *prt, struct replay_group *prg, int syscall, char **ppretparams, struct syscall_result **ppsr)
#endif
{
  struct syscall_result *psr;
  struct replay_thread *tmp;
  struct record_thread *prect = prt->rp_record_thread;
  u_long start_clock;
  u_long *pclock;
  long retval = 0;
  int ret;
#ifdef LOG_COMPRESS_1
  unsigned int dvalue = 0;
#endif
#ifndef USE_SYSNUM
  loff_t peekpos;
  int rc = 0;
  int size = 0;
  loff_t *pos;
#endif

#ifdef REPLAY_PARANOID
  if (current->replay_thrd == NULL)
  {
    TPRINT("Pid %d replaying but no log\n", current->pid);
    sys_exit(0);
  }
#endif
#ifdef TIME_TRICK
  //add_fake_time(5000, prg->rg_rec_group);
  //add_fake_time_syscall (prg->rg_rec_group);
  //TPRINT("the new fake time.%u, %u\n", fake_tv_sec, fake_tv_usec);
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
#ifdef LOG_COMPRESS_1
    clogfreeall(prect);
    read_clog_data(prt->rp_record_thread);
#endif
    if (prect->rp_in_ptr == 0)
    {
      // There should be one record there at least
      TPRINT("Pid %d waiting for non-existant syscall record %d - recording not synced yet??? \n", current->pid, syscall);
      __syscall_mismatch(prg->rg_rec_group);
    }
    prt->rp_out_ptr = 0;
  }

  psr = &prect->rp_log[prt->rp_out_ptr];

  MPRINT("Replay Pid %d, index %ld sys %d\n", current->pid, prt->rp_out_ptr, psr->sysnum);

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
#ifdef TIME_TRICK
  if (ret_start_clock) *ret_start_clock = start_clock;
#endif

  //Yang: take out the ino, dev, etc
  if (syscall == 0 || syscall == 1 || syscall == 44 ||
      syscall == 45 || syscall == 46 || syscall == 47)
  {
    strncpy_safe(repl_uuid_str, (char *)argshead(prect), THEIA_UUID_LEN);
    TPRINT("syscall %d, repl_uuid is %s, repl_uuid_str len is %lu, retparam len is %lu\n", syscall, repl_uuid_str, strlen(repl_uuid_str), strlen((char *)argshead(prect)));
    argsconsume(prect, strlen(repl_uuid_str) + 1);
  }


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
  MPRINT("Replay Pid %d, index %ld sys %d retval %lx\n", current->pid, prt->rp_out_ptr, psr->sysnum, retval);

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
      DPRINT("Consider thread %d status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_status, tmp->rp_wait_clock);
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
      MPRINT("Replay pid %d waiting for clock value %ld on syscall entry but current clock value is %ld\n", current->pid, start_clock, *(prt->rp_preplay_clock));
      rg_unlock(prg->rg_rec_group);
      ret = wait_event_interruptible_timeout(prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING || prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && prect->rp_in_ptr == prt->rp_out_ptr + 1), SCHED_TO);
      rg_lock(prg->rg_rec_group);
      if (ret == 0) TPRINT("Replay pid %d timed out waiting for clock value %ld on syscall entry but current clock value is %ld\n", current->pid, start_clock, *(prt->rp_preplay_clock));
      if (prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && (prect->rp_in_ptr == prt->rp_out_ptr + 1)))
      {
        MPRINT("Replay pid %d woken up to die on entrance in_ptr %lu out_ptr %lu\n", current->pid, prect->rp_in_ptr, prt->rp_out_ptr);
        rg_unlock(prg->rg_rec_group);
        sys_exit(0);
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
        if (is_pin_attached() && (syscall != 59 || syscall != 56))
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
#ifdef REPLAY_PAUSE
  if (replay_pause_tool && *prt->rp_preplay_clock >= *(prt->rp_preplay_clock + 1))
  {
    TPRINT("Pid %d replay will pause here, clock is %lu now\n", current->pid, *prt->rp_preplay_clock);
    prt->rp_wait_clock = *(prt->rp_preplay_clock + 1);
    rg_unlock(prg->rg_rec_group);
    ret = wait_event_interruptible_timeout(prt->rp_waitq, *prt->rp_preplay_clock < * (prt->rp_preplay_clock + 1), SCHED_TO);
    if (ret == 0) TPRINT("Replay_pause: Replay pid %d timed out waiting for clock value %ld on syscall entry but current clock value is %ld\n", current->pid, start_clock, *(prt->rp_preplay_clock));
    if (ret == -ERESTARTSYS)
    {
      TPRINT("Pid %d: entering syscall cannot wait due to signal for replay_pause\n", current->pid);
    }
    rg_lock(prg->rg_rec_group);
  }
#endif
  (*prt->rp_preplay_clock)++;
  rg_unlock(prg->rg_rec_group);
  MPRINT("Pid %d incremented replay clock on syscall %d entry to %ld\n", current->pid, psr->sysnum, *(prt->rp_preplay_clock));
  *ppsr = psr;
  return retval;
}
#ifdef LOG_COMPRESS
static inline long get_next_syscall_enter(struct replay_thread *prt, struct replay_group *prg, int syscall, char **ppretparams, struct syscall_result **ppsr)
{
  return cget_next_syscall_enter(prt, prg, syscall, ppretparams, ppsr, 0, NULL);
}
#endif

static inline long
get_next_syscall_exit(struct replay_thread *prt, struct replay_group *prg, struct syscall_result *psr)
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
      DPRINT("Consider thread %d status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_status, tmp->rp_wait_clock);
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
        TPRINT("Pid %d: Crud! no eligible thread to run on syscall exit\n", current->pid);
        TPRINT("replay pid %d waiting for clock value on syscall exit - current clock value is %ld\n", current->pid, *(prt->rp_preplay_clock));
        if (prt->rp_pin_restart_syscall)
        {
          TPRINT("Pid %d: This was a restarted syscall exit, let's sleep and try again\n", current->pid);
          msleep(1000);
          break;
        }
        TPRINT("replay pid %d waiting for clock value %ld on syscall exit - current clock value is %ld\n", current->pid, stop_clock, *(prt->rp_preplay_clock));
        sys_exit_group(0);
      }
    }
    while (tmp != prt);

    while (!(prt->rp_status == REPLAY_STATUS_RUNNING || (prt->rp_replay_exit && prect->rp_in_ptr == prt->rp_out_ptr + 1)))
    {
      MPRINT("Replay pid %d waiting for clock value %ld on syscall exit but current clock value is %ld\n", current->pid, stop_clock, *(prt->rp_preplay_clock));
      rg_unlock(prg->rg_rec_group);
      ret = wait_event_interruptible_timeout(prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING || prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && prect->rp_in_ptr == prt->rp_out_ptr + 1), SCHED_TO);
      rg_lock(prg->rg_rec_group);
      if (ret == 0) TPRINT("Replay pid %d timed out waiting for clock value %ld on syscall exit but current clock value is %ld\n", current->pid, stop_clock, *(prt->rp_preplay_clock));
      if (prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && (prect->rp_in_ptr == prt->rp_out_ptr + 1)))
      {
        rg_unlock(prg->rg_rec_group);
        MPRINT("Replay pid %d woken up to die on exit\n", current->pid);
        sys_exit(0);
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
        print_replay_threads();
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
    signal_wake_up(current, 0);
  }

  (*prt->rp_preplay_clock)++;
  MPRINT("Pid %d incremented replay clock on syscall %d exit to %ld\n", current->pid, psr->sysnum, *(prt->rp_preplay_clock));
  prect->rp_count += 1;

  rg_unlock(prg->rg_rec_group);
  return 0;
}

long
get_next_syscall_enter_external(int syscall, char **ppretparams, struct syscall_result **ppsr)
{
  return get_next_syscall_enter(current->replay_thrd, current->replay_thrd->rp_group, syscall, ppretparams, ppsr);
}

void
get_next_syscall_exit_external(struct syscall_result *psr)
{
  get_next_syscall_exit(current->replay_thrd, current->replay_thrd->rp_group, psr);
}

/* This function takes the next syscall of the current task's replay
   log, makes sure the syscall number matches, and returns the
   original return value and any optional data (if ppretparams is set).
   On an error, it calls sys_exit, and so never returns
   */
#ifndef LOG_COMPRESS
static inline long
get_next_syscall(int syscall, char **ppretparams)
{
  struct replay_thread *prt = current->replay_thrd;
  struct replay_group *prg = prt->rp_group;
  struct syscall_result *psr;
  long retval;
  long exit_retval;

  retval = get_next_syscall_enter(prt, prg, syscall, ppretparams, &psr);

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

  return retval;
}
#else
static inline long
cget_next_syscall(int syscall, char **ppretparams, u_char *flag, long prediction, u_long *start_clock)
{
  struct replay_thread *prt = current->replay_thrd;
  struct replay_group *prg = prt->rp_group;
  struct syscall_result *psr;
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
static inline long get_next_syscall(int syscall, char **ppretparams)
{
  return cget_next_syscall(syscall, ppretparams, NULL, 0, NULL);
}
#endif

void consume_remaining_records(void)
{
  struct syscall_result *psr;
  struct replay_thread *prt = current->replay_thrd;
  char *tmp;

  while (prt->rp_record_thread->rp_in_ptr != prt->rp_out_ptr)
  {
    psr = &prt->rp_record_thread->rp_log[prt->rp_out_ptr];
    MPRINT("Pid %d recpid %d consuming unused record: sysnum %d\n", current->pid, prt->rp_record_thread->rp_record_pid, psr->sysnum);
    get_next_syscall(psr->sysnum, &tmp);
  }
  DPRINT("Pid %d recpid %d done consuming unused records clock now %ld\n", current->pid, prt->rp_record_thread->rp_record_pid, *prt->rp_preplay_clock);
}

void record_randomness(u_long value)
{
  if (current->record_thrd->random_values.cnt < REPLAY_MAX_RANDOM_VALUES)
  {
    current->record_thrd->random_values.val[current->record_thrd->random_values.cnt++] = value;
  }
  else
  {
    TPRINT("record_randomness: exceeded maximum number of values\n");
  }
}

u_long replay_randomness(void)
{
  if (current->replay_thrd->random_values.cnt < REPLAY_MAX_RANDOM_VALUES)
  {
    return current->replay_thrd->random_values.val[current->replay_thrd->random_values.cnt++];
  }
  else
  {
    TPRINT("replay_randomness: exceeded maximum number of values\n");
    return -1;
  }
}

// only one for now - likely more though
void record_execval(int uid, int euid, int gid, int egid, int secureexec)
{
  current->record_thrd->exec_values.uid = uid;
  current->record_thrd->exec_values.euid = euid;
  current->record_thrd->exec_values.gid = gid;
  current->record_thrd->exec_values.egid = egid;
  current->record_thrd->exec_values.secureexec = secureexec;
}

void replay_execval(int *uid, int *euid, int *gid, int *egid, int *secureexec)
{
  *uid = current->replay_thrd->exec_values.uid;
  *euid = current->replay_thrd->exec_values.euid;
  *gid = current->replay_thrd->exec_values.gid;
  *egid = current->replay_thrd->exec_values.egid;
  *secureexec = current->replay_thrd->exec_values.secureexec;
  MPRINT("In %s\n", __func__);
}

unsigned long get_replay_args(void)
{
  if (current->replay_thrd)
  {
    return current->replay_thrd->argv;
  }
  else
  {
    TPRINT("Pid %d, no args start on non-replay\n", current->pid);
    return 0;
  }
}
EXPORT_SYMBOL(get_replay_args);

unsigned long get_env_vars(void)
{
  if (current->replay_thrd)
  {
    return current->replay_thrd->envp;
  }
  else
  {
    TPRINT("Pid %d, no env vars on non-replay\n", current->pid);
    return 0;
  }
}
EXPORT_SYMBOL(get_env_vars);

void save_exec_args(unsigned long argv, int argc, unsigned long envp, int envc)
{
  if (current->replay_thrd)
  {
    struct replay_thread *prt = current->replay_thrd;
    prt->argv = argv;
    prt->argc = argc;
    prt->envp = envp;
    prt->envc = envc;
    MPRINT("In %s\n", __func__);
  }
  return;
}

/* These functions check the clock condition before and after a syscall, respectively.  We have to do this for syscalls for which
   Pin holds a lock throughout to avoid a deadlock. */
long check_clock_before_syscall(int syscall)
{
  struct replay_thread *prt = current->replay_thrd;
  int ignore_flag;

  // This should block until it is time to execute the syscall.  We must save the returned values for use in the actual system call
  DPRINT("Pid %d pre-wait for syscall %d\n", current->pid, syscall);

  if (prt->rp_record_thread->rp_ignore_flag_addr)
  {
    get_user(ignore_flag, prt->rp_record_thread->rp_ignore_flag_addr);
  }
  else
  {
    ignore_flag = 0;
  }
  if (!ignore_flag)
  {
    prt->rp_saved_rc = get_next_syscall_enter(prt, prt->rp_group, syscall, &prt->rp_saved_retparams, &prt->rp_saved_psr);
    // Pin calls clone instead of vfork and enforces the vfork semantics at
    // the Pin layer, we need to know this so that we can call replay_clone
    // in place of the vfork
    if (syscall == 58)
    {
      prt->is_pin_vfork = 1;
    }
  }

  return 0;
}
EXPORT_SYMBOL(check_clock_before_syscall);

#ifdef REPLAY_STATS
long
get_replay_stats(struct replay_stats __user *ustats)
{
  if (copy_to_user(ustats, &rstats, sizeof(struct replay_stats)))
  {
    return -EFAULT;
  }
  return 0;
}
EXPORT_SYMBOL(get_replay_stats);
#endif

long check_clock_after_syscall(int syscall)
{
  struct replay_thread *prt = current->replay_thrd;
  int ignore_flag;

  if (prt->rp_record_thread->rp_ignore_flag_addr)
  {
    get_user(ignore_flag, prt->rp_record_thread->rp_ignore_flag_addr);
  }
  else
  {
    ignore_flag = 0;
  }
  if (ignore_flag) return 0;

  // This should block until it is time to execute the syscall.  We must save the returned values for use in the actual system call
  TPRINT("[%s|%d] pid %d, syscall %d, app_syscall_addr %lx, value %d\n", __func__, __LINE__, current->pid, syscall,
         prt->app_syscall_addr, (prt->app_syscall_addr <= 1) ? -1 : * (int *)(prt->app_syscall_addr));
  if (prt->app_syscall_addr <= 1)
  {
    TPRINT("Pid %d calls check_clock_after_syscall, but thread not yet initialized\n", current->pid);
    return -EINVAL;
  }
  if (prt->rp_saved_psr == NULL)
  {
    TPRINT("Pid %d calls check_clock_after_syscall, but psr not saved\n", current->pid);
    return -EINVAL;
  }
  DPRINT("Pid %d post-wait for syscall for syscall %d\n", current->pid, prt->rp_saved_psr->sysnum);
  get_next_syscall_exit(prt, prt->rp_group, prt->rp_saved_psr);
  prt->rp_saved_psr = NULL;
  return 0;
}
EXPORT_SYMBOL(check_clock_after_syscall);

asmlinkage long
sys_pthread_print(const char __user *buf, size_t count)
{
  struct timeval tv;
  long clock;
  int ignore_flag;

  do_gettimeofday(&tv);

  if (current->replay_thrd)
  {
    clock = *(current->replay_thrd->rp_preplay_clock);
    TPRINT("Pid %d recpid %5d PTHREAD:%ld:%ld.%06ld:%s", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid, clock, tv.tv_sec, tv.tv_usec, buf);
  }
  else if (current->record_thrd)
  {
    clock = atomic_read(current->record_thrd->rp_precord_clock);
    if (current->record_thrd->rp_ignore_flag_addr)
    {
      get_user(ignore_flag, current->record_thrd->rp_ignore_flag_addr);
    }
    else
    {
      ignore_flag = 0;
    }
    TPRINT("Pid %d recpid ----- PTHREAD:%ld:%ld.%06ld:%d:%s", current->pid, clock, tv.tv_sec, tv.tv_usec, ignore_flag, buf);
  }
  else
  {
    TPRINT("sys_pthread_print: pid %d is not a record/replay proces: %s\n", current->pid, buf);
    return -EINVAL;
  }

  return 0;
}

asmlinkage long
sys_pthread_init(int __user *status, u_long record_hook, u_long replay_hook)
{
  if (current->record_thrd)
  {
    struct record_thread *prt = current->record_thrd;
    put_user(1, status);
    prt->rp_record_hook = record_hook;
    DPRINT("pid %d sets record hook %lx\n", current->pid, record_hook);
  }
  else if (current->replay_thrd)
  {
    struct replay_thread *prt = current->replay_thrd;
    put_user(2, status);

    prt->rp_replay_hook = replay_hook;
    DPRINT("pid %d sets replay hook %lx\n", current->pid, replay_hook);
  }
  else
  {
    TPRINT("Pid %d calls sys_pthread_init, but not a record/replay process\n", current->pid);
    return -EINVAL;
  }
  return 0;
}

asmlinkage long
sys_pthread_dumbass_link(int __user *status, u_long __user *record_hook, u_long __user *replay_hook)
{
  if (current->record_thrd)
  {
    struct record_thread *prt = current->record_thrd;
    if (prt->rp_record_hook)
    {
      put_user(1, status);
      put_user(prt->rp_record_hook, record_hook);
      DPRINT("pid %d record hook %lx returned\n", current->pid, prt->rp_record_hook);
    }
  }
  else if (current->replay_thrd)
  {
    struct replay_thread *prt = current->replay_thrd;
    if (prt->rp_replay_hook)
    {
      put_user(2, status);
      put_user(prt->rp_replay_hook, replay_hook);
      DPRINT("pid %d replay hook %lx returned\n", current->pid, prt->rp_replay_hook);
    }
  }
  else
  {
    put_user(3, status);
  }
  return 0;
}

asmlinkage long
sys_pthread_log(u_long log_addr, int __user *ignore_addr)
{
  if (current->record_thrd)
  {
    current->record_thrd->rp_user_log_addr = log_addr;
    current->record_thrd->rp_ignore_flag_addr = ignore_addr;
  }
  else if (current->replay_thrd)
  {
    current->replay_thrd->rp_record_thread->rp_user_log_addr = log_addr;
    current->replay_thrd->rp_record_thread->rp_ignore_flag_addr = ignore_addr;
    read_user_log(current->replay_thrd->rp_record_thread);
    MPRINT("Read user log into address %lx for thread %d\n", log_addr, current->pid);
  }
  else
  {
    TPRINT("sys_prthread_log called by pid %d which is neither recording nor replaying\n", current->pid);
    return -EINVAL;
  }
  return 0;
}

asmlinkage long
sys_pthread_elog(int type, u_long addr)
{
#ifdef USE_EXTRA_DEBUG_LOG
  if (type == 0)   // allocate/register log
  {
    if (current->record_thrd)
    {
      current->record_thrd->rp_user_extra_log_addr = addr;
      MPRINT("User extra log info address for thread %d is %lx\n", current->pid, addr);
    }
    else if (current->replay_thrd)
    {
      current->replay_thrd->rp_record_thread->rp_user_extra_log_addr = addr;
      read_user_extra_log(current->replay_thrd->rp_record_thread);
      MPRINT("Read extra user log into address %lx for thread %d\n", addr, current->pid);
    }
    else
    {
      TPRINT("sys_pthread_elog called by pid %d which is neither recording nor replaying\n", current->pid);
      return -EINVAL;
    }
  }
  else     // Log is full
  {
    if (current->record_thrd)
    {
      DPRINT("Pid %d: extra log full\n", current->pid);
      if (write_user_extra_log(current->record_thrd) < 0) TPRINT("Extra debug log write failed\n");
    }
    else if (current->replay_thrd)
    {
      DPRINT("Pid %d: Resetting user log\n", current->pid);
      read_user_extra_log(current->replay_thrd->rp_record_thread);
    }
    else
    {
      TPRINT("sys_pthread_elog called by pid %d which is neither recording nor replaying\n", current->pid);
      return -EINVAL;
    }
  }

  return 0;
#else
  return -EINVAL; // Support not compiled intot this kernel
#endif
}


asmlinkage long
sys_pthread_block(u_long clock)
{
  struct replay_thread *prt, *tmp;
  struct replay_group *prg;
  int ret;

  if (!current->replay_thrd)
  {
    TPRINT("sys_pthread_block called by non-replay process %d\n", current->pid);
    return -EINVAL;
  }
  prt = current->replay_thrd;
  prg = prt->rp_group;

  if (clock == INT_MAX) consume_remaining_records(); // Before we block forever, consume any remaining system call records

  while (*(prt->rp_preplay_clock) < clock)
  {
    MPRINT("Replay pid %d is waiting for user clock value %ld but current clock value is %ld\n", current->pid, clock, *(prt->rp_preplay_clock));
    prt->rp_status = REPLAY_STATUS_WAIT_CLOCK;
    prt->rp_wait_clock = clock;
    tmp = prt->rp_next_thread;
    do
    {
      DPRINT("Consider thread %d status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_status, tmp->rp_wait_clock);
      if (tmp->rp_status == REPLAY_STATUS_ELIGIBLE || (tmp->rp_status == REPLAY_STATUS_WAIT_CLOCK && tmp->rp_wait_clock <= *(prt->rp_preplay_clock)))
      {
        tmp->rp_status = REPLAY_STATUS_RUNNING;
        wake_up(&tmp->rp_waitq);
        break;
      }
      tmp = tmp->rp_next_thread;
      if (tmp == prt)
      {
        TPRINT("Pid %d: Crud! no eligible thread to run on user-level block\n", current->pid);
        TPRINT("Replay pid %d is waiting for user clock value %ld but current clock value is %ld\n", current->pid, clock, *(prt->rp_preplay_clock));
        tmp = prt->rp_next_thread;
        do
        {
          TPRINT("\tthread %d (recpid %d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
          tmp = tmp->rp_next_thread;
        }
        while (tmp != prt);
        syscall_mismatch();
      }
    }
    while (tmp != prt);

    rg_lock(prg->rg_rec_group);
    while (!(prt->rp_status == REPLAY_STATUS_RUNNING || (prt->rp_replay_exit && prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr)))
    {
      MPRINT("Replay pid %d waiting for user clock value %ld\n", current->pid, clock);

      rg_unlock(prg->rg_rec_group);
      ret = wait_event_interruptible_timeout(prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING || prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr), SCHED_TO);
      rg_lock(prg->rg_rec_group);
      if (ret == 0) TPRINT("Replay pid %d timed out waiting for user clock value %ld\n", current->pid, clock);
      if (prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && (prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr))) break; // exit condition below
      if (ret == -ERESTARTSYS)
      {
        TPRINT("Pid %d: blocking syscall cannot wait due to signal - try again (%d)\n", current->pid, prg->rg_rec_group->rg_mismatch_flag);
        rg_unlock(prg->rg_rec_group);
        msleep(1000);
        rg_lock(prg->rg_rec_group);
      }
    }
    if (prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && (prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr)))
    {
      rg_unlock(prg->rg_rec_group);
      MPRINT("Replay pid %d woken up to die on block\n", current->pid);
      sys_exit(0);
    }
    rg_unlock(prg->rg_rec_group);
  }
  MPRINT("Pid %d returning from user-level replay block\n", current->pid);
  return 0;
}

asmlinkage long sys_pthread_full(void)
{
  if (current->record_thrd)
  {
    DPRINT("Pid %d: log full\n", current->pid);
    if (write_user_log(current->record_thrd) < 0) sys_exit_group(0);  // Logging failed
    return 0;
  }
  else if (current->replay_thrd)
  {
    DPRINT("Pid %d: Resetting user log\n", current->pid);
    read_user_log(current->replay_thrd->rp_record_thread);
    return 0;
  }
  else
  {
    TPRINT("Pid %d: pthread_log_full only valid for replay processes\n", current->pid);
    return -EINVAL;
  }
}

asmlinkage long sys_pthread_status(int __user *status)
{
  if (current->record_thrd)
  {
    put_user(1, status);
  }
  else if (current->replay_thrd)
  {
    put_user(2, status);
  }
  else
  {
    put_user(3, status);
  }
  return 0;
}

/* Returns a fd for the shared memory page back to the user */
asmlinkage long sys_pthread_shm_path(void)
{
  int fd;
  mm_segment_t old_fs = get_fs();
  set_fs(KERNEL_DS);

  if (current->record_thrd)
  {
    struct record_group *prg = current->record_thrd->rp_group;
    MPRINT("Pid %d (record) returning existing shmpath %s\n", current->pid, prg->rg_shmpath);
    fd = sys_open(prg->rg_shmpath, O_RDWR | O_NOFOLLOW, 0644);
  }
  else if (current->replay_thrd)
  {
    struct record_group *prg = current->replay_thrd->rp_group->rg_rec_group;
    MPRINT("Pid %d (replay) returning existing shmpath %s\n", current->pid, prg->rg_shmpath);
    fd = sys_open(prg->rg_shmpath, O_RDWR | O_NOFOLLOW, 0644);
  }
  else
  {
    TPRINT("[WARN]Pid %d, neither record/replay is asking for the shm_path???\n", current->pid);
    fd = -EINVAL;
  }

  set_fs(old_fs);

  return fd;
}

asmlinkage long sys_pthread_sysign(void)
{
  // This replays an ignored syscall which delivers a signal
  DPRINT("In sys_pthread_sysign\n");
  return get_next_syscall(SIGNAL_WHILE_SYSCALL_IGNORED, NULL);
}

#define SHIM_CALL_MAIN(number, F_RECORD, F_REPLAY, F_SYS) \
{ \
  int ignore_flag;            \
  if (current->record_thrd) {         \
    if (current->record_thrd->rp_ignore_flag_addr) {  \
      get_user (ignore_flag, current->record_thrd->rp_ignore_flag_addr); \
      if (ignore_flag) return F_SYS;      \
    }             \
    return F_RECORD;          \
  }               \
  if (current->replay_thrd && test_app_syscall(number)) {   \
TPRINT("SHIM_CALL_MAIN: Pid %d, app replay meets syscall %d\n", current->pid, number); \
    if (current->replay_thrd->rp_record_thread->rp_ignore_flag_addr) { \
      get_user (ignore_flag, current->replay_thrd->rp_record_thread->rp_ignore_flag_addr); \
      if (ignore_flag) { \
        TPRINT ("syscall %d ignored\n", number); \
        return F_SYS;       \
      }           \
    }             \
    DPRINT("SHIM_CALL_MAIN: Pid %d, regular replay syscall %d\n", current->pid, number); \
    return F_REPLAY;          \
  }               \
  else if (current->replay_thrd) {        \
TPRINT("SHIM_CALL_MAIN: Pid %d, non replay meets syscall %d\n", current->pid, number); \
    if (*(current->replay_thrd->rp_preplay_clock) > pin_debug_clock) {  \
      DPRINT("Pid %d, pin syscall %d\n", current->pid, number); \
    }             \
  }               \
  return F_SYS;             \
}

#define SHIM_CALL(name, number, args...)          \
{ \
  SHIM_CALL_MAIN(number, record_##name(args), replay_##name(args),  \
           sys_##name(args))    \
}

//special SHIM function for ignored syscalls; currently, only used for futex, gettimeofday and clock_gettime
#define SHIM_CALL_MAIN_IGNORE(number, F_RECORD, F_REPLAY, F_SYS, F_RECORD_IGNORED)  \
{ \
  int ignore_flag;            \
  if (current->record_thrd) {         \
    if (current->record_thrd->rp_ignore_flag_addr) {  \
      get_user (ignore_flag, current->record_thrd->rp_ignore_flag_addr); \
      if (ignore_flag) {          \
        return F_RECORD_IGNORED;    \
      }             \
    }             \
    return F_RECORD;          \
  }               \
  if (current->replay_thrd && test_app_syscall(number)) {   \
    if (current->replay_thrd->rp_record_thread->rp_ignore_flag_addr) { \
      get_user (ignore_flag, current->replay_thrd->rp_record_thread->rp_ignore_flag_addr); \
      if (ignore_flag) { \
        TPRINT ("We should get here, ignored syscall %d\n", number);      \
        return F_SYS;       \
      }           \
    }             \
    DPRINT("Pid %d, regular replay syscall %d\n", current->pid, number); \
    return F_REPLAY;          \
  }               \
  else if (current->replay_thrd) {        \
    if (*(current->replay_thrd->rp_preplay_clock) > pin_debug_clock) {  \
      DPRINT("Pid %d, pin syscall %d\n", current->pid, number); \
    }             \
  }               \
  return F_SYS;             \
}

#define SHIM_CALL_IGNORE(name, number, args...)         \
{ \
  SHIM_CALL_MAIN_IGNORE(number, record_##name(args), replay_##name(args),\
           sys_##name(args), record_##name##_ignored(args))    \
}
//end special SHIM function

#define SIMPLE_RECORD0(name, sysnum)                            \
  static asmlinkage long            \
  record_##name (void)            \
  {               \
    long rc;            \
    new_syscall_enter (sysnum);       \
    rc = sys_##name();          \
    new_syscall_done (sysnum, rc);        \
    new_syscall_exit (sysnum, NULL);      \
    return rc;            \
  }

#define SIMPLE_RECORD1(name, sysnum, arg0type, arg0name)    \
  static asmlinkage long            \
  record_##name (arg0type arg0name)       \
  {               \
    long rc;            \
    new_syscall_enter (sysnum);       \
    rc = sys_##name(arg0name);        \
    new_syscall_done (sysnum, rc);        \
    new_syscall_exit (sysnum, NULL);      \
    return rc;            \
  }

#define SIMPLE_RECORD2(name, sysnum, arg0type, arg0name, arg1type, arg1name)  \
  static asmlinkage long            \
  record_##name (arg0type arg0name, arg1type arg1name)    \
  {               \
    long rc;            \
    new_syscall_enter (sysnum);       \
    rc = sys_##name(arg0name, arg1name);      \
    new_syscall_done (sysnum, rc);        \
    new_syscall_exit (sysnum, NULL);      \
    return rc;            \
  }

#define SIMPLE_RECORD3(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name) \
  static asmlinkage long            \
  record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name) \
  {               \
    long rc;            \
    new_syscall_enter (sysnum);       \
    rc = sys_##name(arg0name, arg1name, arg2name);    \
    new_syscall_done (sysnum, rc);        \
    new_syscall_exit (sysnum, NULL);      \
    return rc;            \
  }

#define SIMPLE_RECORD4(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name) \
  static asmlinkage long            \
  record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name) \
  {               \
    long rc;            \
    new_syscall_enter (sysnum);       \
    rc = sys_##name(arg0name, arg1name, arg2name, arg3name); \
    new_syscall_done (sysnum, rc);        \
    new_syscall_exit (sysnum, NULL);      \
    return rc;            \
  }

#define SIMPLE_RECORD5(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name) \
  static asmlinkage long            \
  record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name) \
  {               \
    long rc;            \
    new_syscall_enter (sysnum);       \
    rc = sys_##name(arg0name, arg1name, arg2name, arg3name, arg4name); \
    new_syscall_done (sysnum, rc);        \
    new_syscall_exit (sysnum, NULL);      \
    return rc;            \
  }

#define SIMPLE_RECORD6(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name, arg5type, arg5name) \
  static asmlinkage long            \
  record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name, arg5type arg5name) \
  {               \
    long rc;            \
    new_syscall_enter (sysnum);       \
    rc = sys_##name(arg0name, arg1name, arg2name, arg3name, arg4name, arg5name); \
    new_syscall_done (sysnum, rc);        \
    new_syscall_exit (sysnum, NULL);      \
    return rc;            \
  }

#define THEIA_SIMPLE_SHIM0(name, sysnum)    \
  static asmlinkage long            \
  theia_sys_##name (void)       \
  {               \
    long rc;            \
    rc = sys_##name();        \
    if (theia_logging_toggle) theia_##name##_ahgx(rc, sysnum);               \
    return rc;            \
  }

#define THEIA_SIMPLE_SHIM1(name, sysnum, arg0type, arg0name)    \
  static asmlinkage long            \
  theia_sys_##name (arg0type arg0name)        \
  {               \
    long rc;            \
    rc = sys_##name(arg0name);        \
    if (theia_logging_toggle) theia_##name##_ahgx(arg0name, rc, sysnum);               \
    return rc;            \
  }

#define THEIA_SIMPLE_SHIM2(name, sysnum, arg0type, arg0name, arg1type, arg1name)  \
  static asmlinkage long            \
  theia_sys_##name (arg0type arg0name, arg1type arg1name)   \
  {               \
    long rc;            \
    rc = sys_##name(arg0name, arg1name);      \
    if (theia_logging_toggle) theia_##name##_ahgx(arg0name, arg1name, rc, sysnum);     \
    return rc;            \
  }

#define THEIA_SIMPLE_SHIM3(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name)  \
  static asmlinkage long            \
  theia_sys_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name)    \
  {               \
    long rc;            \
    rc = sys_##name(arg0name, arg1name, arg2name);      \
    if (theia_logging_toggle) theia_##name##_ahgx(arg0name, arg1name, arg2name, rc, sysnum);   \
    return rc;            \
  }

#define THEIA_SIMPLE_SHIM4(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name)  \
  static asmlinkage long            \
  theia_sys_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name)   \
  {               \
    long rc;            \
    rc = sys_##name(arg0name, arg1name, arg2name, arg3name);      \
    if (theia_logging_toggle) theia_##name##_ahgx(arg0name, arg1name, arg2name, arg3name, rc, sysnum);         \
    return rc;            \
  }

#define THEIA_SIMPLE_SHIM5(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name)  \
  static asmlinkage long            \
  theia_sys_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name)    \
  {               \
    long rc;            \
    rc = sys_##name(arg0name, arg1name, arg2name, arg3name, arg4name);      \
    if (theia_logging_toggle) theia_##name##_ahgx(arg0name, arg1name, arg2name, arg3name, arg4name, rc, sysnum);       \
    return rc;            \
  }

#define THEIA_SIMPLE_SHIM6(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name, arg5type, arg5name)  \
  static asmlinkage long            \
  theia_sys_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name, arg5type arg5name)   \
  {               \
    long rc;            \
    rc = sys_##name(arg0name, arg1name, arg2name, arg3name, arg4name, arg5name);      \
    if (theia_logging_toggle) theia_##name##_ahgx(arg0name, arg1name, arg2name, arg3name, arg4name, arg5name, rc, sysnum);     \
    return rc;            \
  }

#define SIMPLE_REPLAY(name, sysnum, args...)    \
  static asmlinkage long        \
  replay_##name (args)          \
  {             \
    return get_next_syscall (sysnum, NULL); \
  }

#define SIMPLE_SHIM0(name, sysnum)          \
  SIMPLE_RECORD0(name, sysnum);         \
  SIMPLE_REPLAY (name, sysnum, void);       \
  asmlinkage long shim_##name (void) SHIM_CALL(name, sysnum);

#define THEIA_SHIM0(name, sysnum)     \
  SIMPLE_RECORD0(name, sysnum);   \
  SIMPLE_REPLAY (name, sysnum, void);   \
  THEIA_SIMPLE_SHIM0(name, sysnum);   \
  asmlinkage long shim_##name (void)                 \
  SHIM_CALL_MAIN(sysnum, record_##name(), replay_##name(),  \
           theia_sys_##name());

#define SIMPLE_SHIM1(name, sysnum, arg0type, arg0name)      \
  SIMPLE_RECORD1(name, sysnum, arg0type, arg0name);   \
  SIMPLE_REPLAY (name, sysnum, arg0type arg0name);    \
  asmlinkage long shim_##name (arg0type arg0name) SHIM_CALL(name, sysnum, arg0name);

#define THEIA_SHIM1(name, sysnum, arg0type, arg0name)     \
  SIMPLE_RECORD1(name, sysnum, arg0type, arg0name);   \
  SIMPLE_REPLAY (name, sysnum, arg0type arg0name);    \
  THEIA_SIMPLE_SHIM1(name, sysnum, arg0type, arg0name);   \
  asmlinkage long shim_##name (arg0type arg0name)                 \
  SHIM_CALL_MAIN(sysnum, record_##name(arg0name), replay_##name(arg0name),  \
           theia_sys_##name(arg0name));

#define SIMPLE_SHIM2(name, sysnum, arg0type, arg0name, arg1type, arg1name) \
  SIMPLE_RECORD2(name, sysnum, arg0type, arg0name, arg1type, arg1name); \
  SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name) SHIM_CALL(name, sysnum, arg0name, arg1name);

#define THEIA_SHIM2(name, sysnum, arg0type, arg0name, arg1type, arg1name) \
  SIMPLE_RECORD2(name, sysnum, arg0type, arg0name, arg1type, arg1name); \
  SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name); \
  THEIA_SIMPLE_SHIM2(name, sysnum, arg0type, arg0name, arg1type, arg1name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name) \
  SHIM_CALL_MAIN(sysnum, record_##name(arg0name, arg1name), replay_##name(arg0name, arg1name), \
        theia_sys_##name(arg0name, arg1name));

#define SIMPLE_SHIM3(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name) \
  SIMPLE_RECORD3(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name); \
  SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name, arg2type arg2name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name);

#define THEIA_SHIM3(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name) \
  SIMPLE_RECORD3(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name); \
  SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name, arg2type arg2name); \
  THEIA_SIMPLE_SHIM3(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name) \
  SHIM_CALL_MAIN(sysnum, record_##name(arg0name, arg1name, arg2name), replay_##name(arg0name, arg1name, arg2name), \
        theia_sys_##name(arg0name, arg1name, arg2name));

#define SIMPLE_SHIM4(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name) \
  SIMPLE_RECORD4(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name); \
  SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name);

#define THEIA_SHIM4(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name) \
  SIMPLE_RECORD4(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name); \
  SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name); \
  THEIA_SIMPLE_SHIM4(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name) \
  SHIM_CALL_MAIN(sysnum, record_##name(arg0name, arg1name, arg2name, arg3name), replay_##name(arg0name, arg1name, arg2name, arg3name), \
        theia_sys_##name(arg0name, arg1name, arg2name, arg3name));

#define SIMPLE_SHIM5(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name) \
  SIMPLE_RECORD5(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name); \
  SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name, arg4name);

#define THEIA_SHIM5(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name) \
  SIMPLE_RECORD5(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name); \
  SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name); \
  THEIA_SIMPLE_SHIM5(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name) \
  SHIM_CALL_MAIN(sysnum, record_##name(arg0name, arg1name, arg2name, arg3name, arg4name), replay_##name(arg0name, arg1name, arg2name, arg3name, arg4name), \
        theia_sys_##name(arg0name, arg1name, arg2name, arg3name, arg4name));

#define SIMPLE_SHIM6(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name, arg5type, arg5name) \
  SIMPLE_RECORD6(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name, arg5type, arg5name); \
  SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name, arg5type arg5name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name, arg5type arg5name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name, arg4name, arg5name);

#define THEIA_SHIM6(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name, arg5type, arg5name) \
  SIMPLE_RECORD6(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name, arg5type, arg5name); \
  SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name, arg5type arg5name); \
  THEIA_SIMPLE_SHIM6(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type arg3name, arg4type arg4name, arg5type arg5name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name, arg5type arg5name) \
  SHIM_CALL_MAIN(sysnum, record_##name(arg0name, arg1name, arg2name, arg3name, arg4name, arg5name), replay_##name(arg0name, arg1name, arg2name, arg3name, arg4name, arg5name), \
        theia_sys_##name(arg0name, arg1name, arg2name, arg3name, arg4name, arg5name));

#define RET1_RECORD1(name, sysnum, type, dest, arg0type, arg0name)  \
static asmlinkage long record_##name (arg0type arg0name)  \
{                 \
  long rc;              \
  type *pretval = NULL;           \
                  \
  new_syscall_enter (sysnum);         \
  rc = sys_##name (arg0name);         \
  new_syscall_done (sysnum, rc);          \
  if (rc >= 0 && dest) {            \
          pretval = ARGSKMALLOC (sizeof(type), GFP_KERNEL); \
    if (pretval == NULL) {          \
      TPRINT ("record_##name: can't allocate buffer\n"); \
      return -ENOMEM;         \
    }             \
    if (copy_from_user (pretval, dest, sizeof (type))) {  \
      TPRINT ("record_##name: can't copy to buffer\n"); \
      ARGSKFREE(pretval, sizeof(type));   \
      pretval = NULL;         \
      rc = -EFAULT;         \
    }             \
  }               \
                  \
  new_syscall_exit (sysnum, pretval);       \
  return rc;              \
}

#define RET1_RECORD2(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name) \
{                 \
  long rc;              \
  type *pretval = NULL;           \
                  \
  new_syscall_enter (sysnum);         \
  rc = sys_##name (arg0name, arg1name);       \
  new_syscall_done (sysnum, rc);          \
  if (rc >= 0 && dest) {            \
          pretval = ARGSKMALLOC (sizeof(type), GFP_KERNEL); \
    if (pretval == NULL) {          \
      TPRINT ("record_##name: can't allocate buffer\n"); \
      return -ENOMEM;         \
    }             \
    if (copy_from_user (pretval, dest, sizeof (type))) {  \
      TPRINT ("record_##name: can't copy to buffer\n"); \
      ARGSKFREE(pretval, sizeof(type));   \
      pretval = NULL;         \
      rc = -EFAULT;         \
    }             \
  }               \
                  \
  new_syscall_exit (sysnum, pretval);       \
  return rc;              \
}

#define RET1_RECORD3(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name) \
{                 \
  long rc;              \
  type *pretval = NULL;           \
                  \
  new_syscall_enter (sysnum);         \
  rc = sys_##name (arg0name, arg1name, arg2name);     \
  new_syscall_done (sysnum, rc);          \
  if (rc >= 0 && dest) {            \
          pretval = ARGSKMALLOC (sizeof(type), GFP_KERNEL); \
    if (pretval == NULL) {          \
      TPRINT ("record_##name: can't allocate buffer\n"); \
      return -ENOMEM;         \
    }             \
    if (copy_from_user (pretval, dest, sizeof (type))) {  \
      TPRINT ("record_##name: can't copy to buffer\n"); \
      ARGSKFREE(pretval, sizeof(type));   \
      pretval = NULL;         \
      rc = -EFAULT;         \
    }             \
  }               \
                  \
  new_syscall_exit (sysnum, pretval);       \
  return rc;              \
}

#define RET1_RECORD4(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name) \
{                 \
  long rc;              \
  type *pretval = NULL;           \
                  \
  new_syscall_enter (sysnum);         \
  rc = sys_##name (arg0name, arg1name, arg2name, arg3name); \
  new_syscall_done (sysnum, rc);          \
  if (rc >= 0 && dest) {            \
          pretval = ARGSKMALLOC (sizeof(type), GFP_KERNEL); \
    if (pretval == NULL) {          \
      TPRINT ("record_##name: can't allocate buffer\n"); \
      return -ENOMEM;         \
    }             \
    if (copy_from_user (pretval, dest, sizeof (type))) {  \
      TPRINT ("record_##name: can't copy to buffer\n"); \
      ARGSKFREE(pretval, sizeof(type));   \
      pretval = NULL;         \
      rc = -EFAULT;         \
    }             \
  }               \
                  \
  new_syscall_exit (sysnum, pretval);       \
  return rc;              \
}

#define RET1_RECORD5(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name) \
{                 \
  long rc;              \
  type *pretval = NULL;           \
                  \
  new_syscall_enter (sysnum);         \
  rc = sys_##name (arg0name, arg1name, arg2name, arg3name, arg4name); \
  new_syscall_done (sysnum, rc);          \
  if (rc >= 0 && dest) {            \
          pretval = ARGSKMALLOC (sizeof(type), GFP_KERNEL); \
    if (pretval == NULL) {          \
      TPRINT ("record_##name: can't allocate buffer\n"); \
      return -ENOMEM;         \
    }             \
    if (copy_from_user (pretval, dest, sizeof (type))) {  \
      TPRINT ("record_##name: can't copy to buffer\n"); \
      ARGSKFREE(pretval, sizeof(type));   \
      pretval = NULL;         \
      rc = -EFAULT;         \
    }             \
  }               \
                  \
  new_syscall_exit (sysnum, pretval);       \
  return rc;              \
}

#define RET1_REPLAYG(name, sysnum, dest, size, args...)     \
static asmlinkage long replay_##name (args)       \
{                 \
  char *retparams = NULL;           \
  long rc = get_next_syscall (sysnum, (char **) &retparams);  \
                  \
  if (retparams) {            \
    if (copy_to_user (dest, retparams, size)) TPRINT ("replay_##name: pid %d cannot copy to user\n", current->pid); \
TPRINT("argsconsume called at %d, size: %lu\n", __LINE__, size); \
    argsconsume (current->replay_thrd->rp_record_thread, size); \
  }               \
                  \
  return rc;              \
}                 \

#define RET1_REPLAY(name, sysnum, type, dest, args...) RET1_REPLAYG(name, sysnum, dest, sizeof(type), args)

#define RET1_SHIM1(name, sysnum, type, dest, arg0type, arg0name)  \
  RET1_RECORD1(name, sysnum, type, dest, arg0type, arg0name); \
  RET1_REPLAY (name, sysnum, type, dest, arg0type arg0name);  \
  asmlinkage long shim_##name (arg0type arg0name) SHIM_CALL(name, sysnum, arg0name);

#define RET1_SHIM2(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name) \
  RET1_RECORD2(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name); \
  RET1_REPLAY (name, sysnum, type, dest, arg0type arg0name, arg1type arg1name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name) SHIM_CALL(name, sysnum, arg0name, arg1name);

#define RET1_SHIM3(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name) \
  RET1_RECORD3(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name); \
  RET1_REPLAY (name, sysnum, type, dest, arg0type arg0name, arg1type arg1name, arg2type arg2name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name);

#define RET1_SHIM4(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name) \
  RET1_RECORD4(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name); \
  RET1_REPLAY (name, sysnum, type, dest, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name);

#define RET1_SHIM5(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name) \
  RET1_RECORD5(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name); \
  RET1_REPLAY (name, sysnum, type, dest, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name, arg4name);

#define RET1_COUNT_RECORD3(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name) \
{                 \
  long rc;              \
  char *pretval = NULL;           \
                  \
  new_syscall_enter (sysnum);         \
  rc = sys_##name (arg0name, arg1name, arg2name);     \
  new_syscall_done (sysnum, rc);          \
  if (rc >= 0 && dest) {            \
    pretval = ARGSKMALLOC (rc, GFP_KERNEL);     \
    if (pretval == NULL) {          \
      TPRINT ("record_##name: can't allocate buffer\n"); \
      return -ENOMEM;         \
    }             \
    if (copy_from_user (pretval, dest, rc)) {   \
      TPRINT ("record_##name: can't copy to buffer\n"); \
      ARGSKFREE(pretval, rc);       \
      pretval = NULL;         \
      rc = -EFAULT;         \
    }             \
  }               \
                  \
  new_syscall_exit (sysnum, pretval);       \
  return rc;              \
}

#define RET1_COUNT_RECORD4(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name) \
{                 \
  long rc;              \
  char *pretval = NULL;           \
                  \
  new_syscall_enter (sysnum);         \
  rc = sys_##name (arg0name, arg1name, arg2name, arg3name); \
  new_syscall_done (sysnum, rc);          \
  if (rc >= 0 && dest) {            \
    pretval = ARGSKMALLOC (rc, GFP_KERNEL);     \
    if (pretval == NULL) {          \
      TPRINT ("record_##name: can't allocate buffer\n"); \
      return -ENOMEM;         \
    }             \
    if (copy_from_user (pretval, dest, rc)) {   \
      TPRINT ("record_##name: can't copy to buffer\n"); \
      ARGSKFREE(pretval, rc);       \
      pretval = NULL;         \
      rc = -EFAULT;         \
    }             \
  }               \
                  \
  new_syscall_exit (sysnum, pretval);       \
  return rc;              \
}

#define RET1_COUNT_RECORD5(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name) \
{                 \
  long rc;              \
  char *pretval = NULL;           \
                  \
  new_syscall_enter (sysnum);         \
  rc = sys_##name (arg0name, arg1name, arg2name, arg3name, arg4name); \
  new_syscall_done (sysnum, rc);          \
  if (rc >= 0 && dest) {            \
    pretval = ARGSKMALLOC (rc, GFP_KERNEL);     \
    if (pretval == NULL) {          \
      TPRINT ("record_##name: can't allocate buffer\n"); \
      return -ENOMEM;         \
    }             \
    if (copy_from_user (pretval, dest, rc)) {   \
      TPRINT ("record_##name: can't copy to buffer\n"); \
      ARGSKFREE(pretval, rc);       \
      pretval = NULL;         \
      rc = -EFAULT;         \
    }             \
  }               \
                  \
  new_syscall_exit (sysnum, pretval);       \
  return rc;              \
}

#define RET1_COUNT_REPLAY(name, sysnum, dest, args...)      \
static asmlinkage long replay_##name (args)       \
{                 \
  char *retparams = NULL;           \
  long rc = get_next_syscall (sysnum, &retparams);    \
                  \
  if (retparams) {            \
    if (copy_to_user (dest, retparams, rc)) TPRINT ("replay_##name: pid %d cannot copy to user\n", current->pid); \
    argsconsume (current->replay_thrd->rp_record_thread, rc); \
  }               \
                  \
  return rc;              \
}                 \

#define RET1_COUNT_SHIM3(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name) \
  RET1_COUNT_RECORD3(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name); \
  RET1_COUNT_REPLAY (name, sysnum, dest, arg0type arg0name, arg1type arg1name, arg2type arg2name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name);

#define RET1_COUNT_SHIM4(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name) \
  RET1_COUNT_RECORD4(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name); \
  RET1_COUNT_REPLAY (name, sysnum, dest, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name);

#define RET1_COUNT_SHIM5(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name) \
  RET1_COUNT_RECORD5(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name); \
  RET1_COUNT_REPLAY (name, sysnum, dest, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name); \
  asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name, arg4name);

#ifndef USE_DEBUG_LOG
static void
flush_user_log(struct record_thread *prt)
{
  struct pthread_log_head *phead = (struct pthread_log_head __user *) prt->rp_user_log_addr;
  char *pnext;
  u_long entry;
  int fake_calls;

  if (phead == NULL) return;

  get_user(pnext, &phead->next);
  if (pnext)
  {
    get_user(entry, &phead->num_expected_records);
    get_user(fake_calls, &phead->need_fake_calls);
    if (entry == 0 && fake_calls == 0) return;
    if (fake_calls) entry |= FAKE_CALLS_FLAG;
    put_user(entry, (u_long __user *) pnext);
    pnext += sizeof(unsigned long);
    if (fake_calls)
    {
      put_user(fake_calls, (int __user *) pnext);
      pnext += sizeof(int);
    }
    put_user(pnext, &phead->next);
    put_user(0, &phead->need_fake_calls);
    put_user(0, &phead->num_expected_records);
  }
  else
  {
    TPRINT("flush_user_log: next pointer invalid: phead is %p\n", phead);
  }
}
#endif

static void
deallocate_user_log(struct record_thread *prt)
{
  long rc;

  struct pthread_log_head *phead = (struct pthread_log_head __user *) prt->rp_user_log_addr;
  MPRINT("Pid %d -- deallocate user log phead %p\n", current->pid, phead);
  rc = sys_munmap((u_long) phead, PTHREAD_LOG_SIZE + 4096);
  if (rc < 0) TPRINT("pid %d: deallocate_user_log failed, rc=%ld\n", current->pid, rc);
}

/* Called on enter of do_exit() in kernel/exit.c
 *
 * recplay_exit_start is called on enter of do_exit in kernel/exit.c
 * It records the global vector clock value and frees the record log.
 *
 * No locks are held on entry or exit.
 * */
void
recplay_exit_start(void)
{
  struct record_thread *prt = current->record_thrd;

  if (prt)
  {
    MPRINT("Record thread %d starting to exit\n", current->pid);
#ifndef USE_DEBUG_LOG
    flush_user_log(prt);
#endif
    write_user_log(prt);  // Write this out before we destroy the mm
#ifdef USE_EXTRA_DEBUG_LOG
    write_user_extra_log(prt);
#endif
    MPRINT("Pid %d -- Deallocate the user log", current->pid);
    deallocate_user_log(prt);  // For multi-threaded programs, we need to reuse the memory
  }
  else if (current->replay_thrd)
  {
    MPRINT("Replay thread %d starting to exit, recpid %d\n", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid);

    // When exiting threads with Pin attached, we need to make sure we exit the threads
    // in the correct order, while making sure Pin doesn't deadlock
    if (is_pin_attached() && current->replay_thrd->rp_pin_restart_syscall)
    {
      MPRINT("Pid %d, since this was a restart syscall, need to wait for exit, %d\n", current->pid, current->replay_thrd->rp_pin_restart_syscall);
      BUG_ON(!current->replay_thrd->rp_saved_psr);
      if (current->replay_thrd->rp_pin_restart_syscall == REPLAY_PIN_TRAP_STATUS_ENTER)
      {
        u_long wait_clock;
        struct replay_thread *prept = current->replay_thrd;
        BUG_ON(!prept->rp_saved_psr);
        BUG_ON(!prept->rp_start_clock_save);

        MPRINT("Pid %d -- need to consume start clock first", current->pid);

        // since Pin is forcing an exit, we need to consume the last clock value in
        // this thread
        wait_clock = prept->rp_start_clock_save;

        MPRINT("Pid %d, recplay start, wait for clock value %lu from saved syscall entry\n", current->pid, wait_clock);
        get_next_clock(prept, prept->rp_group, wait_clock);
        prept->rp_pin_restart_syscall = REPLAY_PIN_TRAP_STATUS_EXIT;
      }
      MPRINT("Pid %d, recplay start, wait for clock value %lu from saved syscall exit\n", current->pid, current->replay_thrd->rp_stop_clock_save);
      get_next_clock(current->replay_thrd, current->replay_thrd->rp_group, current->replay_thrd->rp_stop_clock_save);
      current->replay_thrd->rp_pin_restart_syscall = REPLAY_PIN_TRAP_STATUS_NONE;
      // So we don't have abnormal termination, since Pin told us to exit
      MPRINT("Pid %d - thread exiting because of Pin\n", current->pid);
      current->replay_thrd->rp_replay_exit = 1;
    }
  }
}

void
recplay_exit_middle(void)
{
  struct replay_thread *tmp;
  u_long clock;
  int num_blocked;

  if (current->record_thrd)
  {
    struct record_thread *prt = current->record_thrd;
    MPRINT("Record thread %d in middle of exit\n", current->pid);

    // Write kernel log after we have updated the tid ptr
#ifdef WRITE_ASYNC
    write_and_free_kernel_log_async(prt);
#else
    write_and_free_kernel_log(prt); // Write out remaining records
#endif
    // write out mmaps if the last record thread to exit the record group
    if (atomic_dec_and_test(&prt->rp_group->rg_record_threads))
    {
      if (prt->rp_group->rg_save_mmap_flag)
      {
        rg_lock(prt->rp_group);
        MPRINT("Pid %d last record thread to exit, write out mmap log\n", current->pid);
        write_mmap_log(prt->rp_group);
        prt->rp_group->rg_save_mmap_flag = 0;
        rg_unlock(prt->rp_group);
      }
    }
  }
  else if (current->replay_thrd)
  {
    if (atomic_dec_and_test(&current->replay_thrd->rp_group->rg_rec_group->rg_record_threads))
    {
      if (current->replay_thrd->rp_group->rg_rec_group->rg_save_mmap_flag)
      {
        rg_lock(current->replay_thrd->rp_group->rg_rec_group);
        MPRINT("Pid %d last record thread to exit, write out mmap log\n", current->pid);
        write_mmap_log(current->replay_thrd->rp_group->rg_rec_group);
        current->replay_thrd->rp_group->rg_rec_group->rg_save_mmap_flag = 0;
        rg_unlock(current->replay_thrd->rp_group->rg_rec_group);
      }
    }
    MPRINT("Replay thread %d recpid %d in middle of exit\n", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid);
    rg_lock(current->replay_thrd->rp_group->rg_rec_group);
    if (current->replay_thrd->rp_status != REPLAY_STATUS_RUNNING || current->replay_thrd->rp_group->rg_rec_group->rg_mismatch_flag)
    {
      if (!current->replay_thrd->rp_replay_exit && !current->replay_thrd->rp_group->rg_rec_group->rg_mismatch_flag)
      {
        // Usually get here by terminating when we see the exit flag and all records have been consumed
        TPRINT("Non-running pid %d is exiting with status %d - abnormal termination?\n", current->pid, current->replay_thrd->rp_status);
        dump_stack();
      }
      current->replay_thrd->rp_status = REPLAY_STATUS_DONE;  // Will run no more
      rg_unlock(current->replay_thrd->rp_group->rg_rec_group);
      return;
    }

    clock = *current->replay_thrd->rp_preplay_clock;
    current->replay_thrd->rp_status = REPLAY_STATUS_DONE;  // Will run no more
    tmp = current->replay_thrd->rp_next_thread;
    num_blocked = 0;
    while (tmp != current->replay_thrd)
    {
      DPRINT("Pid %d considers thread %d (recpid %d) status %d clock %ld - clock is %ld\n", current->pid, tmp->rp_replay_pid, current->replay_thrd->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock, clock);
      if (tmp->rp_status == REPLAY_STATUS_ELIGIBLE || (tmp->rp_status == REPLAY_STATUS_WAIT_CLOCK && tmp->rp_wait_clock <= clock))
      {
        tmp->rp_status = REPLAY_STATUS_RUNNING;
        wake_up(&tmp->rp_waitq);
        break;
      }
      else if (tmp->rp_status != REPLAY_STATUS_DONE)
      {
        num_blocked++;
      }
      tmp = tmp->rp_next_thread;
      if (tmp == current->replay_thrd && num_blocked)
      {
        TPRINT("Pid %d (recpid %d): Crud! no eligible thread to run on exit, clock is %ld\n", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid, clock);
        dump_stack(); // how did we get here?
        // cycle around again and print
        tmp = tmp->rp_next_thread;
        while (tmp != current->replay_thrd)
        {
          TPRINT("\t thread %d (recpid %d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
          tmp = tmp->rp_next_thread;
        }
      }

    }
    rg_unlock(current->replay_thrd->rp_group->rg_rec_group);
  }
}

// PARSPEC: will have replay threads exiting when each epoch is over
void
recplay_exit_finish(void)
{
  if (current->record_thrd)
  {
    struct record_group *prg = current->record_thrd->rp_group;
    MPRINT("Record thread %d has exited\n", current->pid);
    get_record_group(prg);

    rg_lock(prg);
    __destroy_record_thread(current->record_thrd);
    current->record_thrd = NULL;
    MPRINT("Record Pid-%d, tsk %p, exiting!\n", current->pid, current);
    rg_unlock(prg);

    /* Hold a reference to prg through __destroy_record_thread()
     * so it can be unlocked before it is freed. */
    put_record_group(prg);
  }
  else if (current->replay_thrd)
  {
    struct replay_thread *prt = current->replay_thrd;
    struct replay_group *prg = prt->rp_group;
    struct record_group *precg = prg->rg_rec_group;
#ifdef REPLAY_PARANOID
    BUG_ON(!prg);
    BUG_ON(!precg);
#endif
    get_record_group(precg);
    rg_lock(precg);

    MPRINT("Replay Pid %d about to exit\n", current->pid);
    put_replay_group(prg);

    current->replay_thrd = NULL;

    rg_unlock(precg);

    /* Hold a reference to precg so it can be unlocked before it is freed. */
    put_record_group(precg);
  }
}

extern long do_restart_poll(struct restart_block *restart_block); /* In select.c */

static long
record_restart_syscall(struct restart_block *restart)
{
  TPRINT("Pid %d calls record_restart_syscall\n", current->pid);
  if (restart->fn == do_restart_poll)
  {
    long rc;
    char *pretvals = NULL;
    short *p;
    int i;

#ifdef LOG_COMPRESS_1
    struct clog_node *node;
#endif
#ifdef TIME_TRICK
    int shift_clock = 1;
#endif
    new_syscall_enter(219);

    rc = restart->fn(restart);
#ifdef TIME_TRICK
    if (rc <= 0)
      shift_clock = 0;
    cnew_syscall_done(219, rc, -1, shift_clock);
#else
    new_syscall_done(219, rc);
#endif
    if (rc > 0)
    {
      pretvals = ARGSKMALLOC(sizeof(u_long) + restart->poll.nfds * sizeof(short), GFP_KERNEL);
      if (pretvals == NULL)
      {
        TPRINT("restart_record_poll: can't allocate buffer\n");
        return -ENOMEM;
      }
      *((u_long *)pretvals) = restart->poll.nfds * sizeof(short);
      p = (short *)(pretvals + sizeof(u_long));
      for (i = 0; i < restart->poll.nfds; i++)
      {
        if (copy_from_user(p, &restart->poll.ufds[i].revents, sizeof(short)))
        {
          TPRINT("record_poll: can't copy retval %d\n", i);
          ARGSKFREE(pretvals, sizeof(u_long) + restart->poll.nfds * sizeof(short));
          return -EFAULT;
        }
        p++;
      }
#ifdef LOG_COMPRESS_1
      // compress for the retparams of poll
      node = clog_alloc(sizeof(int) + restart->poll.nfds * sizeof(short));
      encodeCachedValue(restart->poll.nfds * sizeof(short), 32, &current->record_thrd->rp_clog.syscall_cache.poll_size, 0, node);
      for (i = 0; i < restart->poll.nfds; ++i)
      {
        encodeCachedValue(restart->poll.ufds[i].revents, 16, &current->record_thrd->rp_clog.syscall_cache.poll_revents, 0, node);
      }
      status_add(&current->record_thrd->rp_clog.syscall_status, 7, (sizeof(int) + restart->poll.nfds * sizeof(short)) << 3, getCumulativeBitsWritten(node));   /* poll */
#endif
    }

    new_syscall_exit(219, pretvals);
#ifdef TIME_TRICK
    if (rc == 0)
    {
      if (restart->poll.has_timeout)
      {
        BUG();
        //add_fake_time(restart->poll.timeout_msecs*1000000, current->record_thrd->rp_group);
        //TPRINT ("semi-det time for poll: timeout %ld ms.\n", timeout_msecs);
      }
    }
#endif

    return rc;
  }
  else
  {
    TPRINT("Record pid %d clock %d unhandled restart function %p do_restart_poll %p\n", current->pid, atomic_read(current->record_thrd->rp_precord_clock), restart->fn, do_restart_poll);
    return restart->fn(restart);
  }
}

static long
replay_restart_syscall(struct restart_block *restart)
{
  TPRINT("Replay pid %d RESTARTING syscall\n", current->pid);
  if (restart->fn == do_restart_poll)
  {
    return replay_poll(restart->poll.ufds, restart->poll.nfds, 0 /* unused */);
  }
  else
  {
    TPRINT("Replay pid %d unhandled restart function\n", current->pid);
    return restart->fn(restart);
  }
}

asmlinkage long
shim_restart_syscall(void)
{
  struct restart_block *restart = &current_thread_info()->restart_block;

  if (current->record_thrd) return record_restart_syscall(restart);
  if (current->replay_thrd) return replay_restart_syscall(restart);
  return restart->fn(restart); // Skip sys_restart_syscall because this is all it does
}

asmlinkage long
shim_exit(int error_code)
{
  if (current->record_thrd) MPRINT("Recording Pid %d naturally exiting\n", current->pid);
  if (current->replay_thrd && test_app_syscall(60)) MPRINT("Replaying Pid %d naturally exiting\n", current->pid);
  return sys_exit(error_code);
}


#ifdef TRACE_SOCKET_READ_WRITE
int track_usually_pt2pt_read(void *key, int size, struct file *filp)
{
  u_int *is_cached;
  u64 rg_id = current->record_thrd->rp_group->rg_id;
  struct pipe_track *info;
  struct replayfs_filemap map;

  is_cached = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);

  *is_cached = READ_IS_PIPE;

  /* We have to lock our pipe tree externally */
  mutex_lock(&pipe_tree_mutex);

  info = btree_lookup64(&pipe_tree, (u64)key);

  /* The pipe is not in the tree, this is its first write (by a recorded process) */
  if (info == NULL)
  {
    /* Create a new pipe_track */
    info = kmalloc(sizeof(struct pipe_track), GFP_KERNEL);
    /* Crap... no memory */
    if (info == NULL)
    {
      /* FIXME: fail cleanly */
      BUG();
    }

    mutex_init(&info->lock);

    /* Now initialize the structure */
    info->owner_read_id = rg_id;
    info->owner_write_id = 0;
    info->id = atomic_inc_return(&glbl_pipe_id);

    info->owner_write_pos = 0;
    info->owner_read_pos = size;

    info->key.id1 = filp->f_dentry->d_inode->i_ino;
    info->key.id2 = filp->f_dentry->d_inode->i_sb->s_dev;

    info->shared = 0;
    if (btree_insert64(&pipe_tree, (u64)key, info, GFP_KERNEL))
    {
      /* FIXME: fail cleanly */
      BUG();
    }

    mutex_unlock(&pipe_tree_mutex);
    /* The pipe is in the tree, update it */
  }
  else
  {
    /* We lock the pipe before we unlock the tree, to ensure that the pipe updates are orded with respect to lookup in the tree */
    mutex_lock(&info->lock);
    mutex_unlock(&pipe_tree_mutex);

    /* If the pipe is exclusive, don't keep any data about it */
    if (info->shared == 0)
    {
      /* It hasn't been read yet */
      if (unlikely(info->owner_read_id == 0))
      {
        info->owner_read_id = rg_id;
        BUG_ON(info->owner_read_pos != 0);
        info->owner_read_pos = size;
        /* If it continues to be exclusive */
      }
      else if (likely(info->owner_read_id == rg_id))
      {
        info->owner_read_pos += size;
        /* This is the un-sharing read */
      }
      else
      {
        info->shared = 1;

        /* Okay, we need to allocate a filemap for this file */
        replayfs_filemap_init(&map, replayfs_alloc, filp);

        /* Write a record of the old data, special case of 0 means held linearly in pipe */
        replayfs_filemap_write(&map, info->owner_write_id, 0, info->id, 0, 0, info->owner_write_pos);

        /* Now append a read record indicating the data we have */
        *is_cached |= READ_PIPE_WITH_DATA;

        info->owner_read_pos += size;
      }
    }
    else
    {
      /* Okay, we need to allocate a filemap for this file */
      replayfs_filemap_init(&map, replayfs_alloc, filp);

      *is_cached |= READ_PIPE_WITH_DATA;

      info->owner_read_pos += size;
    }

    mutex_unlock(&info->lock);
  }

  /* If this is a shared pipe, we will mark multiple writers, and save all the writer data */
  if (*is_cached & READ_PIPE_WITH_DATA)
  {
    struct replayfs_filemap_entry *args;
    struct replayfs_filemap_entry *entry;
    int cpy_size;

    /* Append the data */
    entry = replayfs_filemap_read(&map, info->owner_read_pos - size, size);

    if (IS_ERR(entry) || entry == NULL)
    {
      entry = kmalloc(sizeof(struct replayfs_filemap_entry), GFP_KERNEL);
      entry->num_elms = 0;
    }

    cpy_size = sizeof(struct replayfs_filemap_entry) +
               (entry->num_elms * sizeof(struct replayfs_filemap_value));

    args = ARGSKMALLOC(cpy_size, GFP_KERNEL);

    memcpy(args, entry, cpy_size);

    kfree(entry);

    replayfs_filemap_destroy(&map);

    /* Otherwise, we just need to know the source id of this pipe */
  }
  else
  {
    struct pipe_track *info;
    char *buf = ARGSKMALLOC(sizeof(u64) + sizeof(int), GFP_KERNEL);
    u64 *writer = (void *)buf;
    int *id = (int *)(writer + 1);
    mutex_lock(&pipe_tree_mutex);
    info = btree_lookup64(&pipe_tree, (u64)key);
    BUG_ON(info == NULL);
    mutex_lock(&info->lock);
    mutex_unlock(&pipe_tree_mutex);
    *writer = info->owner_write_id;
    *id = info->id;
    mutex_unlock(&info->lock);
  }

  return 0;
}

int track_usually_pt2pt_write_begin(void *key, struct file *filp)
{
  u64 rg_id = current->record_thrd->rp_group->rg_id;
  struct pipe_track *info;

  /* Wohoo, we have a pipe.  Lets track its writer */

  /* We have to lock our pipe tree externally */
  mutex_lock(&pipe_tree_mutex);

  info = btree_lookup64(&pipe_tree, (u64)key);

  /* The pipe is not in the tree, this is its first write (by a recorded process) */
  if (info == NULL)
  {
    /* Create a new pipe_track */
    info = kmalloc(sizeof(struct pipe_track), GFP_KERNEL);
    /* Crap... */
    if (info == NULL)
    {
      /* FIXME: fail cleanly */
      BUG();
    }

    mutex_init(&info->lock);

    /* Now initialize the structure */
    info->owner_read_id = 0;
    info->owner_write_id = rg_id;
    info->id = atomic_inc_return(&glbl_pipe_id);

    info->owner_write_pos = 0;
    info->owner_read_pos = 0;

    info->key.id1 = filp->f_dentry->d_inode->i_ino;
    info->key.id2 = filp->f_dentry->d_inode->i_sb->s_dev;

    info->shared = 0;
    if (btree_insert64(&pipe_tree, (u64)key, info, GFP_KERNEL))
    {
      /* FIXME: fail cleanly */
      BUG();
    }

    mutex_unlock(&pipe_tree_mutex);
  }
  else
  {
    mutex_unlock(&pipe_tree_mutex);
  }
  return 0;
}

int track_usually_pt2pt_write(void *key, int size, struct file *filp, int do_shared)
{
  u64 rg_id = current->record_thrd->rp_group->rg_id;
  struct pipe_track *info;
  char *pretparams;
  /* Wohoo, we have a pipe.  Lets track its writer */
  u_int *shared;


  if (do_shared)
  {
    shared = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);
    *shared = READ_IS_PIPE;
  }

  /* We have to lock our pipe tree externally */
  mutex_lock(&pipe_tree_mutex);

  info = btree_lookup64(&pipe_tree, (u64)key);

  /* The pipe is not in the tree, this is its first write (by a recorded process) */
  if (info == NULL)
  {
    /* Create a new pipe_track */
    info = kmalloc(sizeof(struct pipe_track), GFP_KERNEL);
    /* Crap... */
    if (info == NULL)
    {
      /* FIXME: fail cleanly */
      BUG();
    }

    mutex_init(&info->lock);

    /* Now initialize the structure */
    info->owner_read_id = 0;
    info->owner_write_id = rg_id;
    info->id = atomic_inc_return(&glbl_pipe_id);

    info->owner_write_pos = size;
    info->owner_read_pos = 0;

    info->key.id1 = filp->f_dentry->d_inode->i_ino;
    info->key.id2 = filp->f_dentry->d_inode->i_sb->s_dev;

    info->shared = 0;
    if (btree_insert64(&pipe_tree, (u64)key, info, GFP_KERNEL))
    {
      /* FIXME: fail cleanly */
      BUG();
    }

    pretparams = ARGSKMALLOC(sizeof(int), GFP_KERNEL);
    BUG_ON(pretparams == NULL);
    *((int *)pretparams) = info->id;

    mutex_unlock(&pipe_tree_mutex);
  }
  else
  {
    mutex_lock(&info->lock);
    mutex_unlock(&pipe_tree_mutex);

    if (info->shared == 0)
    {
      if (unlikely(info->owner_write_id == 0))
      {
        info->owner_write_id = rg_id;
        BUG_ON(info->owner_write_pos != 0);
        info->owner_write_pos = size;
        pretparams = ARGSKMALLOC(sizeof(int), GFP_KERNEL);
        if (pretparams == NULL)
        {
          mutex_unlock(&info->lock);
          return -ENOMEM;
        }
        *((int *)pretparams) = info->id;
      }
      else if (likely(info->owner_write_id == rg_id))
      {
        info->owner_write_pos += size;
        pretparams = ARGSKMALLOC(sizeof(int), GFP_KERNEL);
        if (pretparams == NULL)
        {
          mutex_unlock(&info->lock);
          return -ENOMEM;
        }
        *((int *)pretparams) = info->id;
        /* This is the un-sharing write */
      }
      else
      {
        struct replayfs_filemap map;
        info->shared = 1;
        if (do_shared)
        {
          *shared |= READ_PIPE_WITH_DATA;
        }

        /* Okay, we need to allocate a filemap for this file */
        replayfs_filemap_init(&map, replayfs_alloc, filp);

        /* Write a record of the old data, special case of 0 means held linearly in pipe */
        replayfs_filemap_write(&map, info->owner_write_id, 0, info->id, 0, 0, info->owner_write_pos);

        /* Write a record of our data */
        replayfs_filemap_write(&map, rg_id, current->record_thrd->rp_record_pid, current->record_thrd->rp_count, 0, info->owner_write_pos, size);

        replayfs_filemap_destroy(&map);

        info->owner_write_pos += size;
      }
    }
    else
    {
      struct replayfs_filemap map;
      if (do_shared)
      {
        *shared |= READ_PIPE_WITH_DATA;
      }

      /* Okay, we need to allocate a filemap for this file */
      replayfs_filemap_init(&map, replayfs_alloc, filp);

      /* Write a record of our data */
      replayfs_filemap_write(&map, rg_id, current->record_thrd->rp_record_pid, current->record_thrd->rp_count, 0, info->owner_write_pos, size);

      replayfs_filemap_destroy(&map);

      info->owner_write_pos += size;
    }

    mutex_unlock(&info->lock);
  }
  return 0;
}

void consume_socket_args_read(void *retparams)
{
  int consume_size = 0;
  u_int is_cache_file = *((u_int *)retparams);
  if (is_cache_file & READ_PIPE_WITH_DATA)
  {
    struct replayfs_filemap_entry *entry;

    consume_size = sizeof(u_int);
    entry = (void *)(retparams + consume_size);

    consume_size += sizeof(struct replayfs_filemap_entry) +
                    (entry->num_elms * sizeof(struct replayfs_filemap_value));

    argsconsume(current->replay_thrd->rp_record_thread, consume_size);
  }
  else if (is_cache_file & READ_IS_PIPE)
  {
    consume_size = sizeof(u_int) + sizeof(u64) + sizeof(int);

    argsconsume(current->replay_thrd->rp_record_thread, consume_size);
  }
  else
  {
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_int));
  }
}

void consume_socket_args_write(void *retparams)
{
  u_int shared = *((u_int *)retparams);
  if (shared)
  {
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_int) + sizeof(int));
  }
  else
  {
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_int));
  }
}
#endif


/* fork system call is handled by shim_clone */

#ifdef CACHE_READS

struct open_retvals
{
  dev_t           dev;
  u_long          ino;
  struct timespec mtime;
};

long file_cache_check_version(int fd, struct file *filp,
                              struct filemap_data *data, struct open_retvals *retvals)
{
  long ret = 0;
  /* See if the version within the inode is different than the last one we
   * recorded
   */
  mutex_lock(&data->idata->replay_inode_lock);
  /*
  TPRINT("%s %d: Checking versions, file_version is %lld\n", __func__, __LINE__,
      current->record_thrd->prev_file_version[fd]);
  TPRINT("%s %d: Checking versions, idata is %lld\n", __func__, __LINE__,
      data->idata->version);
      */
  if (current->record_thrd->prev_file_version[fd] == -1)
  {
    current->record_thrd->prev_file_version[fd] = data->idata->version;
  }
  else
  {
    if (current->record_thrd->prev_file_version[fd] < data->idata->version)
    {
      TPRINT("%s %d: !!!!!! Warning - HAVE Out of date file version pid %d fd %d versions %lld %lld !!!!!!!!\n", __func__, __LINE__,
             current->pid, fd, current->record_thrd->prev_file_version[fd], data->idata->version);
#if 0
      ret = READ_NEW_CACHE_FILE;
      /* Stat the file and add it to the cache... */
      add_file_to_cache(filp, &retvals->dev, &retvals->ino, &retvals->mtime);
#endif
    }
    current->record_thrd->prev_file_version[fd] = data->idata->version;
  }
  mutex_unlock(&data->idata->replay_inode_lock);

  return ret;
}

long file_cache_update_replay_file(int rc, struct open_retvals *retvals)
{
  int fd;
  fd = open_cache_file(retvals->dev, retvals->ino, retvals->mtime, O_RDWR, current->replay_thrd->rp_group->cache_dir);

  if (set_replay_cache_file(current->replay_thrd->rp_cache_files, rc, fd) < 0)
  {
    sys_close(fd);
  }

  return 0;
}

/* I don't think I actually need to do anything with this */
long file_cache_opened(struct file *file, int mode)
{
  return 0;
}

long file_cache_file_written(struct filemap_data *data, int fd)
{
  /* increment the version on the file */
  mutex_lock(&data->idata->replay_inode_lock);
  /*
  TPRINT("%s %d: Checking versions, file_version is %lld\n", __func__, __LINE__,
      current->record_thrd->prev_file_version[fd]);
  TPRINT("%s %d: Checking versions, idata is %lld\n", __func__, __LINE__,
      data->idata->version);
      */
  data->idata->version++;
  current->record_thrd->prev_file_version[fd] = data->idata->version;
  mutex_unlock(&data->idata->replay_inode_lock);
  return 0;
}

// return 1 if the current process is associated with an SSH session
static int is_remote(struct task_struct *tsk) {
  return tsk->is_remote;
}
/*
int is_remote(struct task_struct *tsk)
{
  unsigned long env_start;
  unsigned long env_len;
  char *env;
  char *env_mem;
  char *ret;
  int i, skip;
  struct mm_struct *mm = tsk->mm;

  if (!mm)
    return -1;

  env_start = mm->env_start;
  env_len   = mm->env_end - env_start;
  if (!env_start || !env_len)
    return 0;

  env = (char *)vmalloc(env_len);
  env_mem = env;
  copy_from_user((void *)env, (const void __user *)env_start, env_len);

  for (i = 0; i < env_len; i += skip, env += skip)
  {
    ret = strstr(env, "SSH_CONNECTION=");
    if (ret)
    {
      // SL: we can return a remote IP address and port if we want
      vfree(env_mem);
      return 1;
    }
    skip = strlen(env) + 1;
  }

  vfree(env_mem);
  return 0;
}
*/

void get_ids(char *ids)
{
  const struct cred *cred = current_cred();
  snprintf(ids, IDS_LEN, "%d/%d/%d/%d/%d/%d/%d/%d",
          cred->uid, cred->euid, cred->suid, cred->fsuid,
          cred->gid, cred->egid, cred->sgid, cred->fsgid);
}

char *get_file_fullpath(struct file *opened_file, char *buf, size_t buflen)
{
  char *path = NULL;

  if (opened_file)
  {
    path = d_path(&(opened_file->f_path), buf, buflen);
    if (!IS_ERR(path))
    {
      if (path[0] == '\0')
        path = NULL;
    }
    else
      path = NULL;
  }
  else
    path = NULL;

  return path;
}

char *get_task_fullpath(struct task_struct *tsk, char *buf, size_t buflen)
{
  struct mm_struct *mm = get_task_mm(tsk);
  struct file *exe_file;
  char *path = NULL;

  if (!mm)
    return NULL;

  exe_file = get_mm_exe_file(mm);
  if (exe_file)
  {
    path = d_path(&(exe_file->f_path), buf, buflen);
    if (!IS_ERR(path))
    {
      if (path[0] == '\0')
        path = NULL;
    }
    else
      path = NULL;
  }
  else
    path = NULL;

  mmput(mm);
  fput(exe_file);

  return path;
}

// check proc_pid_cmdline() @ fs/proc/base.c
bool get_cmdline(struct task_struct *tsk, char *buffer) {
  struct mm_struct *mm = NULL;
  unsigned long len = 0;
  unsigned long space_cnt = 0;
  int res = 0;
  int i;

  mm = get_task_mm(tsk);
  if (!mm || !mm->arg_end || !buffer) {
    if (mm) mmput(mm);
    return false;
  }

  len = mm->arg_end - mm->arg_start;

  if (len > THEIA_KMEM_SIZE-1)
    len = THEIA_KMEM_SIZE - 1;

  res = access_process_vm(tsk, mm->arg_start, buffer, len, 0);
    
  // setproctitle
  if (res > 0 && buffer[res-1] != '\0' && len < THEIA_KMEM_SIZE-1) {
    len = strnlen(buffer, res);
    if (len < res) {
      res = len;
    }
    else {
      len = mm->env_end - mm->env_start;
      if (len > THEIA_KMEM_SIZE-1 - res)
        len = THEIA_KMEM_SIZE-1 - res;
      res += access_process_vm(tsk, mm->env_start, buffer+res, len, 0);
      len = strnlen(buffer, res);
    }
  }

  for (i = 0; i < len - 1; ++i)
  {
    if (buffer[i] == '\0') {
      buffer[i] = ' ';
      space_cnt++;
    }
  }
  buffer[len] = '\0';

  mmput(mm);

  if (space_cnt > len)
    return false;
  else
    return true;
}

//Yang
struct read_ahgv
{
  int             pid;
  int             fd;
  u_long          bytes;
};


bool is_process_new2(pid_t pid, int sec)
{
  u64 key;
  void *ret;
  key = ((u64)pid) << 32 | (u64)sec;

  if (!theia_process_tree_init)
  {
    btree_init64(&theia_process_tree);
    theia_process_tree_init = true;
  }

  mutex_lock(&theia_process_tree_mutex);
  ret = btree_lookup64(&theia_process_tree, (u64)key);
  if (ret == NULL)
  {
    btree_insert64(&theia_process_tree, (u64)key, (void *)1, GFP_KERNEL);
  }
  mutex_unlock(&theia_process_tree_mutex);

  if (ret == NULL)
    return true;
  else
    return false;
}

void remove_process_from_tree(pid_t pid, int sec)
{
  u64 key;
  void *ret;
  key = ((u64)current->pid) << 32 | (u64)current->start_time.tv_sec;
  mutex_lock(&theia_process_tree_mutex);
  ret = btree_remove64(&theia_process_tree, (u64)key);
  mutex_unlock(&theia_process_tree_mutex);

#define SYS_EXIT 60
  theia_dump_str("exit", 0, SYS_EXIT);
}

bool is_opened_inode(struct inode *inode)
{
  u64 key;
  void *ret;
  key = ((u64)inode->i_sb->s_dev) << 32 | (u64)inode->i_ino;

  if (!theia_opened_inode_tree_init)
  {
    btree_init64(&theia_opened_inode_tree);
    theia_opened_inode_tree_init = true;
  }

  mutex_lock(&theia_opened_inode_tree_mutex);
  ret = btree_lookup64(&theia_opened_inode_tree, (u64)key);
  if (ret == NULL)
  {
    btree_insert64(&theia_opened_inode_tree, (u64)key, (void *)1, GFP_KERNEL);
  }
  mutex_unlock(&theia_opened_inode_tree_mutex);

  if (ret == NULL)
    return false;
  else
    return true;
}

void packahgv_process(struct task_struct *tsk)
{
  int size = 0;
  int is_user_remote;
  struct task_struct *ptsk;
  char *fpathbuf = NULL;
  char *fpath = NULL;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false, args_b64_allocated = false;
  char *args = NULL;
  char *args_b64 = NULL;
  uint32_t buf_size;
  char *buf = NULL;
  bool valid_cmdline = false;  

  if (theia_logging_toggle)
  {
    long sec, nsec;
    char ids[IDS_LEN+1];
    get_ids(ids);
    get_curr_time(&sec, &nsec);
    size = 0;
    is_user_remote = is_remote(tsk);
    rcu_read_lock();
    ptsk = pid_task(find_vpid(tsk->real_parent->pid), PIDTYPE_PID);
    rcu_read_unlock();

    fpathbuf = (char *)vmalloc(PATH_MAX);
    fpath    = get_task_fullpath(tsk, fpathbuf, PATH_MAX);
    if (!fpath)   /* sometimes we can't obtain fullpath */
    {
      fpath = tsk->comm;
    }

    fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
    if (!fpath_b64) 
      fpath_b64 = "";
    else
      fpath_b64_alloced = true;

    args = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    valid_cmdline = get_cmdline(tsk, args);

    if (valid_cmdline) {
      args_b64 = base64_encode(args, strlen(args), NULL);
      args_b64_allocated = true;
    }
    else {
      args_b64 = fpath_b64;
    }

    kmem_cache_free(theia_buffers, args);
    args = NULL;

    //allocate buf
    buf_size = strlen(fpath_b64) + strlen(args_b64) + 256;
    buf = vmalloc(buf_size);

    if (ptsk)
    {
      size = snprintf(buf, buf_size, "startahg|%d|%d|%ld|%s|%d|%ld|%s|%s|%d|%d|%ld|%ld|endahg\n",
                     399/*used for new process*/, tsk->pid, tsk->start_time.tv_sec,
                     ids, tsk->real_parent->pid,
                     ptsk->start_time.tv_sec, fpath_b64, args_b64, is_user_remote, tsk->tgid, sec, nsec);
    }
    else
    {
      size = snprintf(buf, buf_size, "startahg|%d|%d|%ld|%s|%d|%d|%s|%s|%d|%d|%ld|%ld|endahg\n",
                     399/*used for new process*/, tsk->pid, tsk->start_time.tv_sec,
                     ids, tsk->real_parent->pid,
                     -1, fpath_b64, args_b64, is_user_remote, tsk->tgid, sec, nsec);
    }
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
    vfree(fpathbuf);
    if (fpath_b64_alloced)
      vfree(fpath_b64);
    vfree(buf);
    if(args_b64_allocated)
      vfree(args_b64);
  }
}

void packahgv_process_bin(struct task_struct *tsk)
{
  struct task_struct *ptsk;
  struct process_pack_ahg *buf_ahg;
  char *fpathbuf;
  char *fpath;
  int size = 0;
  void *buf;
  void *curr_ptr;

  if (theia_logging_toggle)
  {
    long sec, nsec;
    char ids[IDS_LEN+1];
    get_curr_time(&sec, &nsec);
    rcu_read_lock();
    ptsk = pid_task(find_vpid(tsk->real_parent->pid), PIDTYPE_PID);
    rcu_read_unlock();

    //pack struct
    buf_ahg = vmalloc(sizeof(struct process_pack_ahg));
    buf_ahg->pid = tsk->pid;
    buf_ahg->task_sec = tsk->start_time.tv_sec;
    get_ids(ids);
    buf_ahg->size_ids = strlen(ids);
    TPRINT("ids:(%s),size:%hu\n", ids, buf_ahg->size_ids);
    buf_ahg->p_pid = tsk->real_parent->pid;
    if (ptsk)
      buf_ahg->p_task_sec = ptsk->start_time.tv_sec;
    else
      buf_ahg->p_task_sec = -1;
    fpathbuf = (char *)vmalloc(PATH_MAX);
    fpath = get_task_fullpath(tsk, fpathbuf, PATH_MAX);
    if (!fpath)
    {
      strncpy_safe(fpathbuf, tsk->comm, TASK_COMM_LEN);
    }
    buf_ahg->size_fpathbuf = strlen(fpath);
    TPRINT("fpath:(%s),size:%hu\n", fpathbuf, buf_ahg->size_fpathbuf);
    buf_ahg->is_user_remote = is_remote(tsk);
    buf_ahg->tgid = tsk->tgid;
    buf_ahg->sec = sec;
    buf_ahg->nsec = nsec;

    //pack final buffer
    size = 8/*startahg*/ + 2/*syscall type*/
           + sizeof(struct process_pack_ahg)
           + buf_ahg->size_ids
           + buf_ahg->size_fpathbuf
           + 6/*endahg*/;
    buf = vmalloc(size);
    curr_ptr = buf;
    sprintf((char *)curr_ptr, "startahg");
    curr_ptr += 8;
    *(uint16_t *)(curr_ptr) = 399;
    curr_ptr += 2;
    memcpy(curr_ptr, (void *)buf_ahg, sizeof(struct process_pack_ahg));
    curr_ptr += sizeof(struct process_pack_ahg);
    strncpy_safe((char *)curr_ptr, ids, buf_ahg->size_ids);
    curr_ptr += buf_ahg->size_ids;
    strncpy_safe((char *)curr_ptr, fpath, buf_ahg->size_fpathbuf);
    curr_ptr += buf_ahg->size_fpathbuf;
    sprintf((char *)curr_ptr, "endahg");

    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);

    vfree(buf_ahg);
    vfree(fpathbuf);
    vfree(buf);
  }
}

#define TSK_STACK_SIZE 100
void recursive_packahgv_process(void)
{
  struct task_struct *tsk_stack[TSK_STACK_SIZE];
  int stack_top = 0, i;
  struct task_struct *tsk = current;

  tsk_stack[stack_top++] = tsk;
  rcu_read_lock();
  tsk = tsk->real_parent;
  rcu_read_unlock();

  do
  {
    tsk_stack[stack_top++] = tsk;
    rcu_read_lock();
    tsk = tsk->real_parent;
    rcu_read_unlock();
  }
  while (tsk && stack_top < TSK_STACK_SIZE && is_process_new2(tsk->pid, tsk->start_time.tv_sec));

  for (i = stack_top - 1; i >= 0; --i)
  {
    packahgv_process(tsk_stack[i]);
  }
}

void packahgv_read(struct read_ahgv *sys_args)
{
  char uuid_str[THEIA_UUID_LEN + 1];
  int size = 0;
  char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
  long sec, nsec;

  uint32_t recv_tag = 0;
  struct socket *sock;
  struct sock *sk;
  int err;

  //Yang
  if (theia_logging_toggle)
  {
    get_curr_time(&sec, &nsec);
#ifdef THEIA_UUID
    if (fd2uuid(sys_args->fd, uuid_str) == false)
    {
      TPRINT("fd2uuid returns false, pid %d, fd %d\n", current->pid, sys_args->fd);
      goto err; /* no file, socket, ...? */
    }

#ifdef THEIA_AUX_DATA
    //      too many events are generated and system hangs
    if (strcmp(current->comm, "pthread-lock") == 0)
    {
      theia_dump_auxdata();
    }
#endif

    if(theia_cross_toggle && sys_args->fd >= 0){
      sock = sockfd_lookup(sys_args->fd, &err);
      if(sock) {
        sk = sock->sk;
        if(sk->sk_type == SOCK_DGRAM)
          recv_tag = peek_theia_udp_recv_tag(sk);
        sockfd_put(sock);
      }
    }
    else {
      recv_tag = 0;
    }
    size = snprintf(buf, THEIA_KMEM_SIZE-1, 
        "startahg|%d|%d|%ld|%s|%u|%ld|%d|%ld|%ld|%u|endahg\n", 
        0, sys_args->pid, current->start_time.tv_sec, uuid_str, recv_tag, sys_args->bytes, current->tgid, 
        sec, nsec, current->no_syscalls++);
#else
		int size = snprintf(buf, THEIA_KMEM_SIZE-1, 
        "startahg|%d|%d|%ld|%d|%ld|%d|%ld|%ld|endahg\n", 
				0, sys_args->pid, current->start_time.tv_sec, sys_args->fd, sys_args->bytes, current->tgid, 
				sec, nsec);
#endif
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
err:
    kmem_cache_free(theia_buffers, buf);
  }
}

void theia_read_ahg(unsigned int fd, long rc)
{
  struct read_ahgv *pahgv = NULL;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  //  TPRINT("theia_read_ahg clock", current->record_thrd->rp_precord_clock);
  // Yang: regardless of the return value, passes the failed syscall also
  //  if(rc >= 0)
  {
    pahgv = (struct read_ahgv *)KMALLOC(sizeof(struct read_ahgv), GFP_KERNEL);
    if (pahgv == NULL)
    {
      TPRINT("theia_read_ahg: failed to KMALLOC.\n");
      return;
    }
    pahgv->pid = current->pid;
    pahgv->fd = (int)fd;
    pahgv->bytes = rc;
    packahgv_read(pahgv);
    KFREE(pahgv);
  }

}

static asmlinkage long
record_read(unsigned int fd, char __user *buf, size_t count)
{
  long rc;
  char *pretval = NULL;
  //Yang: for rec_uuid
  char *puuid = NULL;
  struct files_struct *files;
  struct fdtable *fdt;
  struct file *filp;
  int is_cache_file = 0;
  struct open_retvals orets;
#ifdef THEIA_TRACK_SHM_OPEN
  struct vm_area_struct *vma;
  bool shared_none = false;
#endif

#ifdef TRACE_SOCKET_READ_WRITE
  int err;
#endif
#ifdef LOG_COMPRESS
  int shift_clock = 1;
#endif

  //perftimer_tick(read_btwn_timer);
  perftimer_start(read_in_timer);

  filp = fget(fd);
  if (filp != NULL)
  {
    if (filp->replayfs_filemap != NULL)
    {
      is_cache_file = file_cache_check_version(fd, filp, filp->replayfs_filemap,
                      &orets);
    }
    fput(filp);
  }

  new_syscall_enter(0);
  DPRINT("pid %d, record read off of fd %d\n", current->pid, fd);
  //TPRINT("%s %d: In else? of macro?\n", __func__, __LINE__);
  perftimer_start(read_cache_timer);
  is_cache_file |= is_record_cache_file_lock(current->record_thrd->rp_cache_files, fd);

#ifdef THEIA_TRACK_SHM_OPEN
  // TODO: corner case: kernel writes data into shared memory (TA5's test case)
  // what else? recvmsg, ...
  vma = find_vma(current->mm, (unsigned long)buf);
  shared_none = false;
  if (vma->vm_flags & VM_SHARED && !(vma->vm_flags & VM_WRITE))
  {
    err = sys_mprotect((unsigned long)buf, count, PROT_WRITE);
    shared_none = true;
    TPRINT("record_read: a buffer for read() is a shared memory (%p)\n", buf);
  }
#endif

  perftimer_stop(read_cache_timer);
  perftimer_start(read_sys_timer);
  rc = sys_read(fd, buf, count);
  perftimer_stop(read_sys_timer);

#ifdef THEIA_TRACK_SHM_OPEN
  if (shared_none)
    err = sys_mprotect((unsigned long)buf, count, PROT_NONE);
#endif

  //Yang
  if (rc != -EAGAIN) /* ignore some less meaningful errors */
    theia_read_ahg(fd, rc);

  //Yang: we get the inode
  puuid = ARGSKMALLOC(strlen(rec_uuid_str) + 1, GFP_KERNEL);
  if (puuid == NULL)
  {
    TPRINT("record_read: can't allocate pos buffer for rec_uuid_str\n");
    record_cache_file_unlock(current->record_thrd->rp_cache_files, fd);
    return -ENOMEM;
  }
  strncpy_safe((char *)puuid, rec_uuid_str, THEIA_UUID_LEN);
  puuid[THEIA_UUID_LEN] = '\0';
  DPRINT("rec_uuid_str is %s, rc %ld, is_cache %d,clock %d\n", rec_uuid_str, rc, is_cache_file, atomic_read(current->record_thrd->rp_precord_clock));
  DPRINT("copied to pretval is (%s)\n", (char *)puuid);

#ifdef TIME_TRICK
  if (rc <= 0) shift_clock = 0;
#endif

#ifdef LOG_COMPRESS
  if (rc == count && (is_cache_file & 1))
  {
    change_log_special();
    cnew_syscall_done(0, rc, count, shift_clock);
  }
  else
    new_syscall_done(0, rc);
#else
  new_syscall_done(0, rc);
#endif

  //pretval = pretval+strlen(rec_uuid_str)+1;

  if (rc > 0 && buf)
  {
    // For now, include a flag that indicates whether this is a cached read or not - this is only
    // needed for parseklog and so we may take it out later

    files = current->files;
    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);
    if (fd >= fdt->max_fds)
    {
      TPRINT("record_read: invalid fd but read succeeded?\n");
      record_cache_file_unlock(current->record_thrd->rp_cache_files, fd);
      return -EINVAL;
    }

    filp = fdt->fd[fd];
    spin_unlock(&files->file_lock);
    if (is_cache_file & 1)
    {
      int allocsize = sizeof(u_int) + sizeof(loff_t);
      if (is_cache_file & READ_NEW_CACHE_FILE)
      {
        allocsize += sizeof(struct open_retvals);
      }
      // Since not all syscalls handled for cached reads, record the position
      DPRINT("Cached read of fd %u - record by reference\n", fd);
      pretval = ARGSKMALLOC(sizeof(u_int) + sizeof(loff_t), GFP_KERNEL);
      //      pretval = ARGSKMALLOC (strlen(rec_uuid_str)+1+sizeof(u_int) + sizeof(loff_t), GFP_KERNEL);
      if (pretval == NULL)
      {
        TPRINT("record_read: can't allocate pos buffer\n");
        record_cache_file_unlock(current->record_thrd->rp_cache_files, fd);
        return -ENOMEM;
      }

      *((u_int *) pretval) = 1;
      record_cache_file_unlock(current->record_thrd->rp_cache_files, fd);
      *((loff_t *)(pretval + sizeof(u_int))) = filp->f_pos - rc;
      DPRINT("loff_t is (%lld)\n", *((loff_t *)(pretval + sizeof(u_int))));

      if (is_cache_file & READ_NEW_CACHE_FILE)
      {
        void *tmp = ARGSKMALLOC(sizeof(orets), GFP_KERNEL);
        memcpy(tmp, &orets, sizeof(orets));
      }

#ifdef TRACE_READ_WRITE
      do
      {
        struct replayfs_filemap_entry *entry = NULL;
        struct replayfs_filemap *map;
        size_t cpy_size;

        struct replayfs_filemap_entry *args;

        perftimer_start(read_traceread_timer);

        map = filp->replayfs_filemap;
        //replayfs_filemap_init(&map, replayfs_alloc, filp);

        //TPRINT("%s %d - %p: Reading %d\n", __func__, __LINE__, current, fd);
        if (filp->replayfs_filemap)
        {
          perftimer_start(read_filemap_timer);
          entry = replayfs_filemap_read(map, filp->f_pos - rc, rc);
          perftimer_stop(read_filemap_timer);
        }

        if (IS_ERR(entry) || entry == NULL)
        {
          entry = kmalloc(sizeof(struct replayfs_filemap_entry), GFP_KERNEL);
          /* FIXME: Handle this properly */
          BUG_ON(entry == NULL);
          entry->num_elms = 0;
        }

        cpy_size = sizeof(struct replayfs_filemap_entry) +
                   (entry->num_elms * sizeof(struct replayfs_filemap_value));

        args = ARGSKMALLOC(cpy_size, GFP_KERNEL);

        memcpy(args, entry, cpy_size);

        kfree(entry);

        perftimer_stop(read_traceread_timer);

        //replayfs_filemap_destroy(&map);
      }
      while (0);
#endif
#ifdef TRACE_PIPE_READ_WRITE
      /* If this is is a pipe */
    }
    else if (is_pipe(filp))
    {
      struct replayfs_filemap map;
      u_int *is_cached;
      u64 rg_id = current->record_thrd->rp_group->rg_id;
      struct pipe_track *info;
      /* Wohoo, we have a pipe.  Lets track its writer */

      is_cached = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);

      pretval = (char *)is_cached;

      *is_cached = READ_IS_PIPE;

      /* We have to lock our pipe tree externally */
      mutex_lock(&pipe_tree_mutex);

      info = btree_lookup64(&pipe_tree, (u64)filp->f_dentry->d_inode->i_pipe);

      /* The pipe is not in the tree, this is its first write (by a recorded process) */
      if (info == NULL)
      {
        /* Create a new pipe_track */
        info = kmalloc(sizeof(struct pipe_track), GFP_KERNEL);
        /* Crap... no memory */
        if (info == NULL)
        {
          /* FIXME: fail cleanly */
          BUG();
        }

        mutex_init(&info->lock);

        /* Now initialize the structure */
        info->owner_read_id = rg_id;
        info->owner_write_id = 0;
        info->id = atomic_inc_return(&glbl_pipe_id);

        info->owner_write_pos = 0;
        info->owner_read_pos = rc;

        info->key.id1 = filp->f_dentry->d_inode->i_ino;
        info->key.id2 = filp->f_dentry->d_inode->i_sb->s_dev;

        info->shared = 0;
        if (btree_insert64(&pipe_tree, (u64)filp->f_dentry->d_inode->i_pipe, info, GFP_KERNEL))
        {
          /* FIXME: fail cleanly */
          BUG();
        }

        mutex_unlock(&pipe_tree_mutex);
        /* The pipe is in the tree, update it */
      }
      else
      {
        /* We lock the pipe before we unlock the tree, to ensure that the pipe updates are orded with respect to lookup in the tree */
        mutex_lock(&info->lock);
        mutex_unlock(&pipe_tree_mutex);

        /* If the pipe is exclusive, don't keep any data about it */
        if (info->shared == 0)
        {
          /* It hasn't been read yet */
          if (unlikely(info->owner_read_id == 0))
          {
            info->owner_read_id = rg_id;
            BUG_ON(info->owner_read_pos != 0);
            info->owner_read_pos = rc;
            /* If it continues to be exclusive */
          }
          else if (likely(info->owner_read_id == rg_id))
          {
            info->owner_read_pos += rc;
            /* This is the un-sharing read */
          }
          else
          {
            info->shared = 1;

            /* Okay, we need to allocate a filemap for this file */
            replayfs_filemap_init(&map, replayfs_alloc, filp);

            /* Write a record of the old data, special case of 0 means held linearly in pipe */
            replayfs_filemap_write(&map, info->owner_write_id, 0, info->id, 0, 0, info->owner_write_pos);

            /* Now append a read record indicating the data we have */
            *is_cached |= READ_PIPE_WITH_DATA;

            info->owner_read_pos += rc;
          }
        }
        else
        {

          /* Okay, we need to allocate a filemap for this file */
          replayfs_filemap_init(&map, replayfs_alloc, filp);

          *is_cached |= READ_PIPE_WITH_DATA;

          info->owner_read_pos += rc;
        }

        mutex_unlock(&info->lock);
      }

      /* If this is a shared pipe, we will mark multiple writers, and save all the writer data */
      if (*is_cached & READ_PIPE_WITH_DATA)
      {
        struct replayfs_filemap_entry *args;
        struct replayfs_filemap_entry *entry;
        int cpy_size;

        /* Append the data */
        entry = replayfs_filemap_read(&map, info->owner_read_pos - rc, rc);

        if (IS_ERR(entry) || entry == NULL)
        {
          entry = kmalloc(sizeof(struct replayfs_filemap_entry), GFP_KERNEL);
          entry->num_elms = 0;
        }

        cpy_size = sizeof(struct replayfs_filemap_entry) +
                   (entry->num_elms * sizeof(struct replayfs_filemap_value));

        args = ARGSKMALLOC(cpy_size + rc, GFP_KERNEL);

        memcpy(args, entry, cpy_size);

        kfree(entry);

        replayfs_filemap_destroy(&map);

        memcpy(((char *)args) + cpy_size, buf, rc);
        /* Otherwise, we just need to know the source id of this pipe */
      }
      else
      {
        struct pipe_track *info;
        char *buff = ARGSKMALLOC(sizeof(u64) + sizeof(int) + rc, GFP_KERNEL);
        u64 *writer = (void *)buff;
        int *id = (int *)(writer + 1);
        mutex_lock(&pipe_tree_mutex);
        info = btree_lookup64(&pipe_tree, (u64)filp->f_dentry->d_inode->i_pipe);
        mutex_lock(&info->lock);
        mutex_unlock(&pipe_tree_mutex);
        BUG_ON(info == NULL);
        *writer = info->owner_write_id;
        *id = info->id;
        mutex_unlock(&info->lock);

        memcpy(buff + sizeof(u64) + sizeof(int), buf, rc);
      }
#endif
#ifdef TRACE_SOCKET_READ_WRITE
    }
    else if (sock_from_file(filp, &err))
    {
      struct socket *socket = sock_from_file(filp, &err);

      if (socket->ops == &unix_stream_ops || socket->ops == &unix_seqpacket_ops)
      {
        int ret;
        ret = track_usually_pt2pt_read(socket->sk, rc, filp);
        if (ret)
        {
          return ret;
        }
      }
      else
      {
        u_int *is_cached = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);
        if (is_cached == NULL)
        {
          return -ENOMEM;
        }
        *is_cached = 0;
      }

      /* FIXME: This is... hacky */
      pretval = ARGSKMALLOC(rc, GFP_KERNEL);
      if (copy_from_user(pretval, buf, rc))
      {
        TPRINT("record_read: can't copy to buffer\n");
        ARGSKFREE(pretval, rc);
        return -EFAULT;
      }
#endif
    }
    else
    {
      pretval = ARGSKMALLOC(rc + sizeof(u_int), GFP_KERNEL);
      if (pretval == NULL)
      {
        TPRINT("record_read: can't allocate buffer\n");
        return -ENOMEM;
      }
      *((u_int *) pretval) = 0;
      TPRINT("[LINE %d]rec_uuid  set 0, \n", __LINE__);
      if (copy_from_user(pretval + sizeof(u_int), buf, rc))
      {
        TPRINT("record_read: can't copy to buffer\n");
        ARGSKFREE(pretval, rc + sizeof(u_int));
        return -EFAULT;
      }
      TPRINT("[LINE %d]rec_uuid  set buf len: %ld, \n", __LINE__, rc);
#ifdef X_COMPRESS
      if (is_x_fd(&current->record_thrd->rp_clog.x, fd))
      {
        change_log_special_second();
      }
#endif

    }
  }
  else if (is_cache_file)
  {
    record_cache_file_unlock(current->record_thrd->rp_cache_files, fd);
  }

  new_syscall_exit(0, pretval);

  perftimer_stop(read_in_timer);
  return rc;
}

void print_mem(void *addr, int length);
static asmlinkage long
replay_read(unsigned int fd, char __user *buf, size_t count)
{
  char *retparams = NULL;
#ifndef LOG_COMPRESS
  long retval, rc = get_next_syscall(0, &retparams);
#else
  long retval, rc = cget_next_syscall(0, &retparams, NULL, (long)count, NULL);
#endif
  int cache_fd;
  int consume_size = 0;

  DPRINT("[READ] Pid %d replays read returning %ld, fd %u, clock %ld, log_clock %ld\n", current->pid, rc, fd, *(current->replay_thrd->rp_preplay_clock), current->replay_thrd->rp_expected_clock);
  TPRINT("base addr: %p\n", retparams);
  //print_mem(retparams-30, 128);
  if (retparams)
  {

    u_int is_cache_file = *((u_int *)retparams);
    TPRINT("is_cache_file is %u\n", is_cache_file);
    consume_size = 0;

    if (is_cache_file & READ_NEW_CACHE_FILE)
    {
      /* FIXME: Do proper cast */
      file_cache_update_replay_file(fd, (struct open_retvals *)(retparams + sizeof(u_int) +
                                    sizeof(loff_t)));
      consume_size += sizeof(struct open_retvals);
    }

    if (is_replay_cache_file(current->replay_thrd->rp_cache_files, fd, &cache_fd))
    {
      // read from the open cache file
      loff_t off = *((loff_t *)(retparams + sizeof(u_int)));
      DPRINT("read from cache file %d files %p bytes %ld off %ld\n", cache_fd, current->replay_thrd->rp_cache_files, rc, (u_long) off);
      retval = sys_pread64(cache_fd, buf, rc, off);
      if (retval != rc)
      {
        TPRINT("pid %d read from cache file %d files %p orig fd %u off %ld returns %ld not expected %ld\n", current->pid, cache_fd, current->replay_thrd->rp_cache_files, fd, (long) off, retval, rc);
        return syscall_mismatch();
      }
      consume_size += sizeof(u_int) + sizeof(loff_t);
      argsconsume(current->replay_thrd->rp_record_thread, consume_size);

#ifdef TRACE_READ_WRITE
      do
      {
        struct replayfs_filemap_entry *entry = (void *)(retparams + consume_size);

        consume_size = sizeof(struct replayfs_filemap_entry) +
                       (entry->num_elms * sizeof(struct replayfs_filemap_value));

        argsconsume(current->replay_thrd->rp_record_thread, consume_size);
      }
      while (0);
#endif
#ifdef TRACE_PIPE_READ_WRITE
    }
    else if (is_cache_file & READ_PIPE_WITH_DATA)
    {
      struct replayfs_filemap_entry *entry;

      consume_size = sizeof(u_int);
      entry = (void *)(retparams + consume_size);

      consume_size += sizeof(struct replayfs_filemap_entry) +
                      (entry->num_elms * sizeof(struct replayfs_filemap_value));

      if (copy_to_user(buf, retparams + consume_size, rc)) TPRINT("replay_read: pid %d cannot copy to user\n", current->pid);
      TPRINT("READ_PIPE_WITH_DATA consumes %lu\n", consume_size + rc);
      argsconsume(current->replay_thrd->rp_record_thread, consume_size + rc);
    }
    else if (is_cache_file & READ_IS_PIPE)
    {
      consume_size = sizeof(u_int) + sizeof(u64) + sizeof(int);

      if (copy_to_user(buf, retparams + consume_size, rc)) TPRINT("replay_read: pid %d cannot copy to user\n", current->pid);

      argsconsume(current->replay_thrd->rp_record_thread, consume_size + rc);
#endif
    }
    else
    {
#ifdef X_COMPRESS
      if (rc > 0)
      {
        int actual_fd = is_x_fd_replay(&current->replay_thrd->rp_record_thread->rp_clog.x, fd);
        if (actual_fd > 0)
        {
          if (x_detail) TPRINT("Pid %d read for x, fd:%d, buf:%p, count:%d, rc:%ld\n", current->pid, fd, buf, count, rc);
          if (x_proxy)
          {
            retval = sys_read(actual_fd, buf, count);
            if (rc != retval)
              TPRINT("pid %d read from x socket fails, expected:%ld, actual:%ld\n", current->pid, rc, retval);
          }
          if (record_x)
          {
            if (copy_to_user(buf, retparams + sizeof(u_int), rc)) TPRINT("replay_read: pid %d cannot copy to user\n", current->pid);
            consume_size = sizeof(u_int) + rc;
            argsconsume(current->replay_thrd->rp_record_thread, consume_size);
          }
          else
          {
            argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_int));
          }
          //x_decompress_reply (rc, &X_STRUCT_REP, node); // this function should only computes the sequence number
          //validate_decode_buffer (retparams+sizeof(u_int), rc, &X_STRUCT_REP);
          //consume_decode_buffer (rc, &X_STRUCT_REP);
          return rc;
        }
      }
#endif
      // uncached read
      DPRINT("uncached read of fd %u\n", fd);
      if (copy_to_user(buf, retparams + sizeof(u_int), rc)) TPRINT("replay_read: pid %d cannot copy %ld bytes to user\n", current->pid, rc);
      consume_size = sizeof(u_int) + rc;
      argsconsume(current->replay_thrd->rp_record_thread, consume_size);
    }
  }


  return rc;
}

int theia_sys_read(unsigned int fd, char __user *buf, size_t count)
{
  long rc;

#ifdef THEIA_TRACK_SHM_OPEN
  int err;

  // TODO: corner case: kernel writes data into shared memory (TA5's test case)
  // what else? recvmsg, ...
  struct vm_area_struct *vma = find_vma(current->mm, buf);
  bool shared_none = false;
  if (vma->vm_flags & VM_SHARED && !(vma->vm_flags & VM_WRITE))
  {
    err = sys_mprotect(buf, count, PROT_WRITE);
    shared_none = true;
    TPRINT("theia_sys_read: a buffer for read() is a shared memory (%p)\n", buf);
  }
#endif

  rc = sys_read(fd, buf, count);

#ifdef THEIA_TRACK_SHM_OPEN
  if (shared_none)
  {
    err = sys_mprotect(buf, count, PROT_NONE);
    if (err)
    {
      TPRINT("theia_sys_read: mprotect none returned an error\n");
    }
  }
#endif

  // Yang: regardless of the return value, passes the failed syscall also
  if (rc != -EAGAIN)
  {
    theia_read_ahg(fd, rc);
  }
  return rc;
}

asmlinkage ssize_t shim_read(unsigned int fd, char __user *buf, size_t count)
SHIM_CALL_MAIN(0, record_read(fd, buf, count), replay_read(fd, buf, count), theia_sys_read(fd, buf, count))
#else
RET1_COUNT_SHIM3(read, 0, buf, unsigned int, fd, char __user *, buf, size_t, count);
#endif

//Yang
struct write_ahgv
{
  int             pid;
  int             fd;
  u_long          bytes;
  const char*     buf;
  size_t          count;
};

void packahgv_write(struct write_ahgv *sys_args)
{
  char uuid_str[THEIA_UUID_LEN + 1];
  int size = 0;
  char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
  long sec, nsec;

  uint32_t send_tag = 0;
  struct socket *sock;
  struct sock *sk;
  int err;

  //ui data
  struct file* file=NULL;
  int fput_needed=0;
  char *temp;
  char *fpath;
  char *temp2;
  long eventTime;
  char *timeInd;
  char ugly[20];
  char *tempPtr;
  bool needStitch=false;

  //Yang
  if (theia_logging_toggle)
  {
    get_curr_time(&sec, &nsec);
#ifdef THEIA_UUID
    if (fd2uuid(sys_args->fd, uuid_str) == false)
      goto err; /* no file, socket, ...? */

#ifdef THEIA_AUX_DATA
    //      too many events are generated and system hangs
    if (strcmp(current->comm, "pthread-lock") == 0)
    {
      theia_dump_auxdata();
    }
#endif

    if(theia_ui_toggle)
      file=fget_light(sys_args->fd, &fput_needed);

    //ui stuffs
    if(file && theia_ui_toggle)
    {
      temp=kmem_cache_alloc(theia_buffers, PATH_MAX);
      
      fpath=get_file_fullpath(file, temp, PATH_MAX);
      fput_light(file, fput_needed);
      if(strcmp(fpath, orca_file_name)==0 && sys_args->count<4096)
      {
        if(!orca_log)
        {  
          orca_log=vmalloc(4096);
          danglingX11=vmalloc(1024);
          danglingX11[0]='\0';
        }
        temp2=kmem_cache_alloc(theia_buffers, GFP_KERNEL);
        copy_from_user(temp2, sys_args->buf, sys_args->count);
        temp2[sys_args->count]=0;
        if(strstr(temp2, "app.name"))
        {
          strncpy_safe(orca_log, temp2, 4095);
          timeInd=strstr(orca_log, "time=");
          if(timeInd)
          {
            int i=0;
            tempPtr=timeInd+6;
            for(i=0; i<20; i++)
            {
              if(tempPtr[i]!='\'')
                ugly[i]=tempPtr[i];
              else
              {
                ugly[i]='\0';
              }
            }
            if(uiDebug)
              TPRINT("timeInd? %s\n", ugly);
            kstrtol(ugly, 10, &eventTime);
          }
          else
            eventTime=0;
          if(uiDebug)
          {
            TPRINT("orca_log %s %ld\n", orca_log, eventTime);
          }
          if(danglingX11[0] && eventTime>=lastPress)
          {
            //danglingX11[0]='\0';
            if(uiDebug)
              TPRINT("need stitch?\n");
            needStitch=true;
          }
        }
        kmem_cache_free(theia_buffers, temp2);
      }
      kmem_cache_free(theia_buffers, temp);
    }

    if(theia_cross_toggle && sys_args->fd >= 0){
      sock = sockfd_lookup(sys_args->fd, &err);
      if(sock) {
        sk = sock->sk;
        if(sk->sk_type == SOCK_DGRAM)
          send_tag = peek_theia_udp_send_tag(sk);
        sockfd_put(sock);
      }
    }
    else {
      send_tag = 0;
    }
    if(needStitch && orca_log && theia_ui_toggle)
    {
      size = snprintf(buf, THEIA_KMEM_SIZE-1, 
             "%s%u|%s|endahg\n", danglingX11, current->no_syscalls++, orca_log);
      if (size > 0)
        theia_file_write(buf, size);

      danglingX11[0]='\0';
      if(uiDebug)
        TPRINT("x11:LateRelease %s\n", orca_log);
    }
    size = snprintf(buf, THEIA_KMEM_SIZE-1, 
        "startahg|%d|%d|%ld|%s|%u|%ld|%d|%ld|%ld|%u|endahg\n", 
        1, sys_args->pid, current->start_time.tv_sec, uuid_str, send_tag, sys_args->bytes, current->tgid, sec, nsec, current->no_syscalls++);
#else
    int size = snprintf(buf, THEIA_KMEM_SIZE-1, 
        "startahg|%d|%d|%ld|%d|%ld|%d|%ld|%ld|endahg\n", 
				1, sys_args->pid, current->start_time.tv_sec, sys_args->fd, sys_args->bytes, current->tgid, sec, nsec);
#endif
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
err:
    kmem_cache_free(theia_buffers, buf);
  }
}

void theia_write_ahg(unsigned int fd, long rc, const char* buf, size_t count)
{
  struct write_ahgv *pahgv = NULL;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv = (struct write_ahgv *)KMALLOC(sizeof(struct write_ahgv), GFP_KERNEL);
  if (pahgv == NULL)
  {
    TPRINT("theia_write_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv->pid = current->pid;
  pahgv->fd = (int)fd;
  pahgv->bytes = (u_long)rc;
  pahgv->buf=buf;
  pahgv->count=count;
  packahgv_write(pahgv);
  KFREE(pahgv);

}

static asmlinkage ssize_t
record_write(unsigned int fd, const char __user *buf, size_t count)
{
  char *pretparams = NULL;
  //Yang: for embedding uuid
  char *puuid = NULL;
  ssize_t size;
  char kbuf[180];
  struct file *filp;

  //perftimer_tick(write_btwn_timer);
  //  perftimer_start(write_in_timer);

  if (fd == 99999)    // Hack that assists in debugging user-level code
  {
    new_syscall_enter(1);
    new_syscall_done(1, count);
    memset(kbuf, 0, sizeof(kbuf));
    if (copy_from_user(kbuf, buf, count < 179 ? count : 180)) 
      TPRINT("record_write: cannot copy kstring\n");
    //    TPRINT ("Pid %d clock %d logged clock %ld records: %s", current->pid, atomic_read(current->record_thrd->rp_precord_clock)-1, current->record_thrd->rp_expected_clock-1, kbuf);
    new_syscall_exit(1, NULL);
    return count;
  }

  //Yang
  TPRINT("[%s|%d] fd %u, count %lu\n", __func__, __LINE__, fd, count);
  if (fd != 0)
  {
    filp = fget(fd);
    if (filp)
    {
      if (filp->replayfs_filemap)
      {
        file_cache_file_written(filp->replayfs_filemap, fd);
      }

#ifdef TRACE_PIPE_READ_WRITE
      if (is_pipe(filp))
      {
        track_usually_pt2pt_write_begin(filp->f_dentry->d_inode, filp);
      }
#endif
      //Yang
      fput(filp);
    }
  }
  new_syscall_enter(1);
  size = sys_write(fd, buf, count);

  //Yang
  if (size != -EAGAIN)
    theia_write_ahg(fd, size, buf, count);

  //Yang: we get the inode
  puuid = ARGSKMALLOC(strlen(rec_uuid_str) + 1, GFP_KERNEL);
  if (puuid == NULL)
  {
    TPRINT("record_write: can't allocate pos buffer for rec_uuid_str\n");
    return -ENOMEM;
  }
  strncpy_safe((char *)puuid, rec_uuid_str, THEIA_UUID_LEN);
  puuid[THEIA_UUID_LEN] = '\0';
  TPRINT("write: rec_uuid_str is %s,clock %d\n", rec_uuid_str, atomic_read(current->record_thrd->rp_precord_clock));
  TPRINT("write: copied to pretval is (%s)\n", (char *)puuid);

  DPRINT("Pid %d records write returning %zd\n", current->pid, size);
#ifdef X_COMPRESS
  if (is_x_fd(&current->record_thrd->rp_clog.x, fd) && size > 0)
  {
    if (x_detail) TPRINT("Pid %d write for x\n", current->pid);
    BUG_ON(size != count);
    //x_compress_req (buf, size, &X_STRUCT_REC);
  }
#endif
#ifdef LOG_COMPRESS
  cnew_syscall_done(1, size, count, 1);
#else
  new_syscall_done(1, size);
#endif
  //  perftimer_stop(write_sys_timer);

  //#ifdef TRACE_READ_WRITE
  new_syscall_exit(1, pretparams);

  //  perftimer_stop(write_in_timer);

  return size;
}

static asmlinkage ssize_t
replay_write(unsigned int fd, const char __user *buf, size_t count)
{
  ssize_t rc;
  char *pretparams = NULL;
  char kbuf[80];
#ifdef X_COMPRESS
  int actual_fd;
#endif

#ifndef LOG_COMPRESS
  rc = get_next_syscall(1, &pretparams);
#else
  rc = cget_next_syscall(1, &pretparams, NULL, (long)count, NULL);
#endif
  if (fd == 99999)   // Hack that assists in debugging user-level code
  {
    memset(kbuf, 0, sizeof(kbuf));
    if (copy_from_user(kbuf, buf, count < 80 ? count : 79)) TPRINT("replay_write: cannot copy kstring\n");
    TPRINT("Pid %d (recpid %d) clock %ld log_clock %ld replays: %s", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid, *(current->replay_thrd->rp_preplay_clock), current->replay_thrd->rp_expected_clock - 1, kbuf);
  }
  DPRINT("[WRITE] Pid %d replays write returning %zd, fd %u, clock %ld, log_clock %ld\n", current->pid, rc, fd, *(current->replay_thrd->rp_preplay_clock), current->replay_thrd->rp_expected_clock);
#ifdef REPLAY_COMPRESS_READS
  if (pretparams != NULL)
  {
    struct replayfs_syscache_id id;
    id.sysnum = current->replay_thrd->rp_out_ptr - 1;
    id.unique_id = current->replay_thrd->rp_record_thread->rp_group->rg_id;
    id.pid = current->replay_thrd->rp_record_thread->rp_record_pid;

    TPRINT("%s %d: Adding syscache with id {%lld, %lld, %lld}\n", __func__,
           __LINE__, (loff_t)id.sysnum, (loff_t)id.unique_id, (loff_t)id.pid);
    replayfs_syscache_add(&syscache, &id, rc, buf);

    /* We don't actually allocate any space! <insert evil laugh here> */
    //argsconsume (current->replay_thrd->rp_record_thread, sizeof(int));
  }
#elif defined(TRACE_PIPE_READ_WRITE)
  if (pretparams != NULL)
  {
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(int));
  }
#endif

#ifdef X_COMPRESS
  if ((actual_fd = is_x_fd_replay(&current->replay_thrd->rp_record_thread->rp_clog.x, fd)) > 0 && rc > 0)
  {
    if (x_detail) TPRINT("Pid %d write for x\n", current->pid);
    if (x_proxy)
    {
      long retval;
      retval = sys_write(actual_fd, buf, count);
      if (rc != retval)
        TPRINT("pid %d write to x socket fails, expected:%d, actual:%ld\n", current->pid, rc, retval);
    }
    //x_compress_req (buf, rc, &X_STRUCT_REP);
  }
#endif

  return rc;
}

int theia_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
  long rc;
  rc = sys_write(fd, buf, count);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  if (rc != -EAGAIN)
  {
    theia_write_ahg(fd, rc, buf, count);
  }
  return rc;
}

asmlinkage ssize_t shim_write(unsigned int fd, const char __user *buf, size_t count)
//SHIM_CALL (write, 4, fd, buf, count);
SHIM_CALL_MAIN(1, record_write(fd, buf, count), replay_write(fd, buf, count), theia_sys_write(fd, buf, count))

#ifdef CACHE_READS

//Yang
struct open_ahgv
{
  int             pid;
  int             fd;
  char            filename[PATH_MAX+1];
  int             flags;
  int             mode;
  u_long          dev;
  u_long          ino;
  bool            is_new;
};

void packahgv_open(struct open_ahgv *sys_args)
{
  char uuid_str[THEIA_UUID_LEN + 1];
  char *filename_b64 = NULL;
  bool filename_b64_alloced = false;
  uint32_t buf_size;

  if (theia_logging_toggle)
  {
    char *buf = NULL;
#ifndef THEIA_UUID
#ifdef DPATH_USE_STACK
    char pbuf[THEIA_DPATH_LEN];
#else
    char *pbuf = NULL;
#endif
#endif
    long sec, nsec;
    int size = 0;
    get_curr_time(&sec, &nsec);

#ifdef THEIA_UUID
    if (fd2uuid(sys_args->fd, uuid_str) == false)
      return;

    filename_b64 = base64_encode(sys_args->filename, strlen(sys_args->filename), NULL);
    if (!filename_b64) 
      filename_b64 = "";
    else
      filename_b64_alloced = true;

    buf_size = strlen(filename_b64) + 256;
    buf = vmalloc(buf_size);

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, buf_size-1, "startahg|%d|%d|%ld|%s|%s|%d|%d|%d|%d|%ld|%ld|%u|endahg\n",
                   2, sys_args->pid, current->start_time.tv_sec, uuid_str, filename_b64, sys_args->flags, sys_args->mode,
                   sys_args->is_new, current->tgid, sec, nsec, current->no_syscalls++);

    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
    if (filename_b64_alloced)
      vfree(filename_b64);
    vfree(buf);
#else
    buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#ifndef DPATH_USE_STACK
    pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
    if (sys_args->filename[0] == '/')
    {
      size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%d|%s|%d|%d|%lx|%lx|%d|%d|%ld|%ld|endahg\n",
                     2, sys_args->pid, current->start_time.tv_sec, sys_args->fd, sys_args->filename, sys_args->flags, sys_args->mode,
                     sys_args->dev, sys_args->ino, sys_args->is_new, current->tgid, sec, nsec);
    }
    else
    {
      if (current->fs)
      {
        get_fs_pwd(current->fs, &path);
        pcwd = d_path(&path, pbuf, THEIA_DPATH_LEN);
        if (IS_ERR(pcwd))
          pcwd = ".";
      }
      else
      {
        pcwd = ".";
      }

      size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%d|%s/%s|%d|%d|%lx|%lx|%d|%d|%ld|%ld|endahg\n",
                     2, sys_args->pid, current->start_time.tv_sec, sys_args->fd, pcwd, sys_args->filename, sys_args->flags, sys_args->mode,
                     sys_args->dev, sys_args->ino, sys_args->is_new, current->tgid, sec, nsec);
    }
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
    kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
    kmem_cache_free(theia_buffers, pbuf);
#endif
#endif
  }
}

void theia_open_ahg(const char __user *filename, int flags, int mode, long rc, bool is_new)
{
  struct file *file;
  struct inode *inode;
  struct open_ahgv *pahgv = NULL;
  int copied_length = 0;
  int fput_needed = 0;
  char *fpathbuf;
  char *fpath;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv = (struct open_ahgv *)KMALLOC(sizeof(struct open_ahgv), GFP_KERNEL);
  if (pahgv == NULL)
  {
    TPRINT("theia_open_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv->pid = current->pid;
  pahgv->fd = (int)rc;
  pahgv->flags = flags;
  pahgv->mode = mode;
  //  pahgv->is_new = is_new; /* ignore arg */
  pahgv->is_new = true;

  file = NULL;
  if (rc >= 0)
  {
    file = fget_light((unsigned int)rc, &fput_needed);
  }

  if (!file)
  {
    pahgv->dev = 0;
    pahgv->ino = 0;
    if ((copied_length = strncpy_from_user(pahgv->filename, filename, sizeof(pahgv->filename))) != strlen(filename))
    {
      TPRINT("theia_open_ahg: can't copy filename to ahgv, filename length %lu, copied %d, filename:%s\n", strlen(filename), copied_length, filename);
      KFREE(pahgv);
      return;
    }
  }
  else
  {
    inode = file->f_dentry->d_inode;
    //  TPRINT("!!!!!!inode is %p, i_sb: %p,s_dev: %lu, i_ino %lu\n", inode, inode->i_sb, inode->i_sb->s_dev, inode->i_ino);
    pahgv->dev = inode->i_sb->s_dev;
    pahgv->ino = inode->i_ino;

    fpathbuf = (char *)vmalloc(PATH_MAX);
    fpath    = get_file_fullpath(file, fpathbuf, PATH_MAX);
    fput_light(file, fput_needed);
    if (!IS_ERR(fpath))   /* sometimes we can't obtain fullpath */
    {
      strncpy_safe(pahgv->filename, fpath, PATH_MAX);
      vfree(fpathbuf);
    }
    else
    {
      vfree(fpathbuf);
      if ((copied_length = strncpy_from_user(pahgv->filename, filename, sizeof(pahgv->filename))) != strlen(filename))
      {
        TPRINT("theia_open_ahg: can't copy filename to ahgv, filename length %lu, copied %d, filename:%s\n", strlen(filename), copied_length, filename);
        KFREE(pahgv);
        return;
      }
    }
  }

  //Yang: temp avoiding the "Text file busy" for spec cpu2006
  //  sprintf(pahgv->filename, "hellojacket");

  //Reuse dmesg channel
  packahgv_open(pahgv);
  KFREE(pahgv);
}

static asmlinkage long
record_open(const char __user *filename, int flags, int mode)
{
  long rc;
  struct file *file;
  struct inode *inode;
  struct open_retvals *recbuf = NULL;
  mm_segment_t old_fs;
  int ret_access;

  perftimer_start(open_timer);

  new_syscall_enter(2);
  perftimer_start(open_sys_timer);

  //Yang: check whether the file is new
  old_fs = get_fs();
  set_fs(KERNEL_DS);
  ret_access = sys_access(filename, 0/*F_OK*/);
  set_fs(old_fs);

  rc = sys_open(filename, flags, mode);
  perftimer_stop(open_sys_timer);
  new_syscall_done(2, rc);

  // If opened read-only and a regular file, then use replay cache
  MPRINT("record_open of name %s with flags %x returns fd %ld\n", filename, flags, rc);
  if (rc >= 0)
  {
    /*
    do {
      file = fget(rc);
      inode = file->f_dentry->d_inode;
      TPRINT("%s %d: Opened %s to fd %ld with ino %08lX\n", __func__, __LINE__,
          filename, rc, inode->i_ino);
      fput(file);
    } while (0);
    */
    MPRINT("record_open of name %s with flags %x returns fd %ld, sizeof open_ahgv %lu\n", filename, flags, rc, sizeof(struct open_ahgv));

    //Yang
    if (ret_access != 0) //the file is new
      theia_open_ahg(filename, flags, mode, rc, true);
    else
      theia_open_ahg(filename, flags, mode, rc, false);



    if ((flags & O_ACCMODE) == O_RDONLY && !(flags & (O_CREAT | O_DIRECTORY)))
    {
      file = fget(rc);
      inode = file->f_dentry->d_inode;
      DPRINT("i_rdev is %x\n", inode->i_rdev);
      DPRINT("i_sb->s_dev is %x\n", inode->i_sb->s_dev);
      DPRINT("writecount is %d\n", atomic_read(&inode->i_writecount));
      if (inode->i_rdev == 0 && MAJOR(inode->i_sb->s_dev) != 0 && atomic_read(&inode->i_writecount) == 0)
      {
        perftimer_start(open_cache_timer);
        MPRINT("This is an open that we can cache\n");
        recbuf = ARGSKMALLOC(sizeof(struct open_retvals), GFP_KERNEL);
        rg_lock(current->record_thrd->rp_group);
        /* Add entry to filemap cache */
        file_cache_opened(file, mode);
        add_file_to_cache(file, &recbuf->dev, &recbuf->ino, &recbuf->mtime);
        set_record_cache_file(current->record_thrd->rp_cache_files, rc);
        rg_unlock(current->record_thrd->rp_group);
        perftimer_stop(open_cache_timer);
      }
      fput(file);
    }
  }

  //Yang
  new_syscall_exit(2, recbuf);

  perftimer_stop(open_timer);

  return rc;
}

static asmlinkage long
replay_open(const char __user *filename, int flags, int mode)
{
  struct open_retvals *pretvals;
  long rc, fd;

  rc = get_next_syscall(2, (char **) &pretvals);
  DPRINT("replay_open: trying to open %s, rc %ld\n", filename, rc);
  if (pretvals)
  {
    fd = open_cache_file(pretvals->dev, pretvals->ino, pretvals->mtime, flags, current->replay_thrd->rp_group->cache_dir);
    DPRINT("replay_open: opened cache file %s flags %x fd is %ld rc is %ld\n", filename, flags, fd, rc);
    if (set_replay_cache_file(current->replay_thrd->rp_cache_files, rc, fd) < 0) sys_close(fd);
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct open_retvals));
  }

  return rc;
}

int theia_sys_open(const char __user *filename, int flags, int mode)
{
  long rc;
  int ret_access;
  //Yang: check whether the file is new
  mm_segment_t old_fs = get_fs();
  set_fs(KERNEL_DS);
  ret_access = sys_access(filename, 0/*F_OK*/);
  set_fs(old_fs);

  rc = sys_open(filename, flags, mode);

  if (ret_access != 0) //it's a new file
    theia_open_ahg(filename, flags, mode, rc, true);
  else
    theia_open_ahg(filename, flags, mode, rc, false);

  return rc;
}

asmlinkage long shim_open(const char __user *filename, int flags, int mode)
SHIM_CALL_MAIN(2, record_open(filename, flags, mode), replay_open(filename, flags, mode), theia_sys_open(filename, flags, mode))
#else
SIMPLE_SHIM3(open, 2, const char __user *, filename, int, flags, int, mode);
#endif

//Yang
struct close_ahgv
{
  int             pid;
  int             fd;
};

void packahgv_close(struct close_ahgv *sys_args)
{
  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    int size = 0;
    get_curr_time(&sec, &nsec);
    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%d|%d|%ld|%ld|endahg\n", 3,
                   sys_args->pid, current->start_time.tv_sec, 
                   sys_args->fd, current->tgid, sec, nsec);
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
    kmem_cache_free(theia_buffers, buf);
  }
}

void theia_close_ahg(int fd)
{
  struct close_ahgv *pahgv = NULL;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv = (struct close_ahgv *)KMALLOC(sizeof(struct close_ahgv), GFP_KERNEL);
  if (pahgv == NULL)
  {
    TPRINT("theia_close_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv->pid = current->pid;
  pahgv->fd = fd;
  packahgv_close(pahgv);
  KFREE(pahgv);

}


#ifdef CACHE_READS
static asmlinkage long
record_close(int fd)
{
  //Yang
  long rc;

  perftimer_start(close_timer);

#ifdef TRACE_READ_WRITE
  do
  {
    struct file *filp = fget(fd);
    if (filp != NULL)
    {
      replay_filp_close(filp);
      fput(filp);
    }
  }
  while (0);
#endif
  new_syscall_enter(3);
  perftimer_start(close_sys_timer);
  rc = sys_close(fd);
  TPRINT("[%s|%d] fd %d, rc %ld\n", __func__, __LINE__, fd, rc);
  perftimer_stop(close_sys_timer);
  new_syscall_done(3, rc);
  if (rc >= 0) clear_record_cache_file(current->record_thrd->rp_cache_files, fd);
#ifdef X_COMPRESS
  if (is_x_fd(&current->record_thrd->rp_clog.x, fd))
  {
    // don't set it to be -1 after closed
    // -1 is for initial state, -2 is for closed state; the socket to x server may be re-established again
    TPRINT("Pid %d close x server socket %d.\n", current->pid, fd);
    remove_x_fd(&X_STRUCT_REC, fd);
  }
#endif
  new_syscall_exit(3, NULL);

  //Yang
  //  theia_close_ahg(fd);

  perftimer_stop(close_timer);
  return rc;
}

static asmlinkage long
replay_close(int fd)
{
  long rc;
  int cache_fd;
#ifdef X_COMPRESS
  int actual_fd;
#endif

  rc = get_next_syscall(3, NULL);
  if (rc >= 0 && is_replay_cache_file(current->replay_thrd->rp_cache_files, fd, &cache_fd))
  {
    clear_replay_cache_file(current->replay_thrd->rp_cache_files, fd);
    DPRINT("pid %d about to close cache fd %d fd %d\n", current->pid, cache_fd, fd);
    sys_close(cache_fd);
  }
#ifdef X_COMPRESS
  if ((actual_fd = is_x_fd_replay(&current->replay_thrd->rp_record_thread->rp_clog.x, fd)) > 0)
  {
    sys_close(actual_fd);
    remove_x_fd_replay(&current->replay_thrd->rp_record_thread->rp_clog.x, fd);
  }
#endif


  return rc;
}

int theia_sys_close(int fd)
{
  long rc;
  rc = sys_close(fd);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  //    theia_close_ahg(fd);
  return rc;
}



asmlinkage long shim_close(int fd)
SHIM_CALL_MAIN(3, record_close(fd), replay_close(fd), theia_sys_close(fd))
#else
SIMPLE_SHIM1(close, 3, int, fd);
#endif

RET1_SHIM3(waitpid, 7, int, stat_addr, pid_t, pid, int __user *, stat_addr, int, options);

inline void theia_creat_ahgx(const char __user *pathname, int mode, long fd, int sysnum)
{
  //  theia_dump_sd(pathname, mode, rc, sysnum);
  if (fd < 0) return; /* TODO */
  theia_open_ahg(pathname, 0, mode, fd, true);
}

inline void theia_link_ahgx(const char __user *oldname, const char __user *newname, long rc, int sysnum)
{
  theia_dump_ss(oldname, newname, rc, sysnum);
}

void theia_fullpath_ahgx(char __user *pathname, long rc, int sysnum)
{
  char *pcwd = NULL;
  struct path path;
  char *buf;
  int ret;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  if (pathname[0] == '/')
  {
    theia_dump_str(pathname, rc, sysnum);
  }
  else
  {
    if (current->fs)
    {
      get_fs_pwd(current->fs, &path);
      pcwd = d_path(&path, pbuf, THEIA_DPATH_LEN);
      if (IS_ERR(pcwd))
        pcwd = ".";
    }
    else
    {
      pcwd = ".";
    }

    ret = snprintf(buf, THEIA_KMEM_SIZE-1, "%s/%s", pcwd, pathname);
    if (ret > 0)
      theia_dump_str(buf, rc, sysnum);
  }
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
}

inline void theia_symlink_ahgx(const char __user *oldname, const char __user *newname, long rc, int sysnum)
{
  theia_dump_ss(oldname, newname, rc, sysnum);
}

// SIMPLE_SHIM2(creat, 85, const char __user *, pathname, int, mode);
THEIA_SHIM2(creat, 85, const char __user *, pathname, int, mode);
SIMPLE_SHIM2(link, 86, const char __user *, oldname, const char __user *, newname);
// THEIA_SHIM2(link, 86, const char __user *, oldname, const char __user *, newname);

/* unlink/unlinkat begin */
#define SYS_UNLINK    87
void theia_unlink_ahgx(const char *kfilename)
{
  char uuid_str[THEIA_UUID_LEN + 1];
  struct file *file;
  int fd, fput_needed;
  char *fpath = NULL;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false;
  char *buf;
  int rc = 0;
  mm_segment_t old_fs;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  old_fs = get_fs();
  set_fs(KERNEL_DS);
  fd = sys_open(kfilename, O_RDWR, 0);
  set_fs(old_fs);
  if (fd >= 0)
  {
    if (fd2uuid(fd, uuid_str) == false)
    {
      sys_close(fd);
      goto err;
    }

    file = fget_light(fd, &fput_needed);
    if (file)
    {
      fpath = get_file_fullpath(file, pbuf, THEIA_DPATH_LEN);
      if (IS_ERR_OR_NULL(fpath))
      {
        strncpy_safe(pbuf, kfilename, THEIA_DPATH_LEN-1);
        fpath = pbuf;
      }

      fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
      if (!fpath_b64) 
        fpath_b64 = "";
      else
        fpath_b64_alloced = true;

      rc = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%s", uuid_str, fpath_b64);
      if (rc > 0)
        theia_dump_str(buf, 0, SYS_UNLINK);
      fput_light(file, fput_needed);
      if (fpath_b64_alloced)
        vfree(fpath_b64);
    }

    sys_close(fd);
  }
err:
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
}

static asmlinkage long
record_unlink(const char __user *filename)
{
  long rc;
  mm_segment_t old_fs;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif

  strncpy_from_user(pbuf, filename, THEIA_DPATH_LEN);

  /* we should call theia_unlink_ahgx before sys_unlink */
  if (theia_logging_toggle)
    theia_unlink_ahgx(pbuf);

  new_syscall_enter(SYS_UNLINK);
  old_fs = get_fs();
  set_fs(KERNEL_DS);
  rc = sys_unlink(pbuf);
  set_fs(old_fs);
  new_syscall_done(SYS_UNLINK, rc);
  new_syscall_exit(SYS_UNLINK, NULL);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
  return rc;
}

static asmlinkage long
replay_unlink(const char __user *filename)
{
  return get_next_syscall(SYS_UNLINK, NULL);
}

static asmlinkage long
theia_sys_unlink(const char __user *filename)
{
  long rc;
  mm_segment_t old_fs;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif

  strncpy_from_user(pbuf, filename, THEIA_DPATH_LEN);

  /* we should call theia_unlink_ahgx before sys_unlink */
  if (theia_logging_toggle)
    theia_unlink_ahgx(pbuf);

  old_fs = get_fs();
  set_fs(KERNEL_DS);
  rc = sys_unlink(pbuf);
  set_fs(old_fs);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
  return rc;
}

asmlinkage long shim_unlink(const char __user *filename)
SHIM_CALL_MAIN(SYS_UNLINK, record_unlink(filename), replay_unlink(filename), theia_sys_unlink(filename));

#define SYS_UNLINKAT 263
void theia_unlinkat_ahgx(int dfd, const char *kfilename, int flag)
{
  char uuid_str[THEIA_UUID_LEN + 1];
  struct file *file;
  int fd, fput_needed;
  char *fpath = NULL;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false;
  char *buf;
  int rc = 0;
  mm_segment_t old_fs;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  old_fs = get_fs();
  set_fs(KERNEL_DS);
  fd = sys_openat(dfd, kfilename, O_RDWR, 0);
  set_fs(old_fs);
  if (fd >= 0)
  {
    if (fd2uuid(fd, uuid_str) == false)
    {
      sys_close(fd);
      goto err;
    }

    file = fget_light(fd, &fput_needed);
    if (file)
    {
      fpath = get_file_fullpath(file, pbuf, THEIA_DPATH_LEN);
      if (IS_ERR_OR_NULL(fpath))
      {
        strncpy_safe(pbuf, kfilename, THEIA_DPATH_LEN-1);
        fpath = pbuf;
      }

      fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
      if (!fpath_b64) 
        fpath_b64 = "";
      else
        fpath_b64_alloced = true;

      rc = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%s|%d", uuid_str, fpath_b64, flag);
      if (rc > 0)
        theia_dump_str(buf, 0, SYS_UNLINKAT);
      fput_light(file, fput_needed);
      if (fpath_b64_alloced)
        vfree(fpath_b64);
    }

    sys_close(fd);
  }
err:
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
}

static asmlinkage long
record_unlinkat(int dfd, const char __user *filename, int flag)
{
  long rc;
  mm_segment_t old_fs;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  
  strncpy_from_user(pbuf, filename, THEIA_DPATH_LEN);

  /* we should call theia_unlink_ahgx before sys_unlink */
  if (theia_logging_toggle)
    theia_unlinkat_ahgx(dfd, pbuf, flag);

  new_syscall_enter(SYS_UNLINKAT);
  old_fs = get_fs();
  set_fs(KERNEL_DS);
  rc = sys_unlinkat(dfd, pbuf, flag);
  set_fs(old_fs);
  new_syscall_done(SYS_UNLINKAT, rc);
  new_syscall_exit(SYS_UNLINKAT, NULL);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
  return rc;
}

static asmlinkage long
replay_unlinkat(int dfd, const char __user *filename, int flag)
{
  return get_next_syscall(SYS_UNLINKAT, NULL);
}

static asmlinkage long
theia_sys_unlinkat(int dfd, const char __user *filename, int flag)
{
  long rc;
  mm_segment_t old_fs;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif

  strncpy_from_user(pbuf, filename, THEIA_DPATH_LEN);

  /* we should call theia_unlink_ahgx before sys_unlink */
  if (theia_logging_toggle)
    theia_unlinkat_ahgx(dfd, pbuf, flag);

  old_fs = get_fs();
  set_fs(KERNEL_DS);
  rc = sys_unlinkat(dfd, pbuf, flag);
  set_fs(old_fs);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
  return rc;
}

asmlinkage long shim_unlinkat(int dfd, const char __user *filename, int flag)
SHIM_CALL_MAIN(SYS_UNLINKAT, record_unlinkat(dfd, filename, flag), replay_unlinkat(dfd, filename, flag), theia_sys_unlinkat(dfd, filename, flag));
/* unlink/unlinkat end */

/* openat begin */
#define SYS_OPENAT 257
void theia_openat_ahgx(int fd, const char __user *filename, int flag, int mode)
{
  char uuid_str[THEIA_UUID_LEN + 1];
  struct file *file = NULL;
  int fput_needed;
  char *fpath = NULL;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false;
  char *buf = NULL;
  int rc = 0;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf = NULL;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  if (fd < 0) return; /* TODO */

  if (fd2uuid(fd, uuid_str) == false)
    goto err; /* TODO: report openat errors? */

  file = fget_light(fd, &fput_needed);
  if (file)
  {
    fpath = get_file_fullpath(file, pbuf, THEIA_DPATH_LEN);
    if (IS_ERR_OR_NULL(fpath))
    {
      strncpy_safe(pbuf, filename, THEIA_DPATH_LEN-1);
      fpath = pbuf;
    }

    fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
    if (!fpath_b64) 
      fpath_b64 = "";
    else
      fpath_b64_alloced = true;

    rc = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%s|%d|%d", uuid_str, fpath_b64, flag, mode);
    if (rc > 0)
      theia_dump_str(buf, fd, SYS_OPENAT);
    fput_light(file, fput_needed);
    if (fpath_b64_alloced)
      vfree(fpath_b64);
  }
err:
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
}

static asmlinkage long
record_openat(int dfd, const char __user *filename, int flag, int mode)
{
  long rc;

  new_syscall_enter(SYS_OPENAT);
  rc = sys_openat(dfd, filename, flag, mode);
  new_syscall_done(SYS_OPENAT, rc);
  new_syscall_exit(SYS_OPENAT, NULL);

  if (theia_logging_toggle)
    theia_openat_ahgx(rc, filename, flag, mode);

  return rc;
}

static asmlinkage long
replay_openat(int dfd, const char __user *filename, int flag, int mode)
{
  return get_next_syscall(SYS_OPENAT, NULL);
}

static asmlinkage long
theia_sys_openat(int dfd, const char __user *filename, int flag, int mode)
{
  long rc;
  rc = sys_openat(dfd, filename, flag, mode);
  if (theia_logging_toggle)
    theia_openat_ahgx(rc, filename, flag, mode); /* use created fd */
  return rc;
}

asmlinkage long shim_openat(int dfd, const char __user *filename, int flag, int mode)
SHIM_CALL_MAIN(SYS_OPENAT, record_openat(dfd, filename, flag, mode), replay_openat(dfd, filename, flag, mode), theia_sys_openat(dfd, filename, flag, mode));
/* openat end */

// This should be called with the record group lock
static int
add_file_to_cache_by_name(const char __user *filename, dev_t *pdev, u_long *pino, struct timespec *pmtime)
{
  mm_segment_t old_fs;
  struct file *file;
  int fd;

  old_fs = get_fs();
  set_fs(KERNEL_DS);
  fd = sys_open(filename, O_RDONLY, 0);  // note that there is a race here if library is changed after syscall
  if (fd < 0)
  {
    //    TPRINT ("add_file_to_cache_by_name: pid %d cannot open file %s\n", current->pid, filename);
    set_fs(old_fs);
    return -EINVAL;
  }
  file = fget(fd);
  if (file == NULL)
  {
    TPRINT("add_file_to_cache_by_name: pid %d cannot get file\n", current->pid);
    set_fs(old_fs);
    return -EINVAL;
  }
  add_file_to_cache(file, pdev, pino, pmtime);
  fput(file);
  sys_close(fd);
  set_fs(old_fs);

  return 0;
}

struct execve_retvals
{
  u_char is_new_group;
  union
  {
    struct
    {
      struct rvalues     rvalues;
      struct exec_values evalues;
      dev_t              dev;
      u_long             ino;
      struct timespec    mtime;
    } same_group;
    struct
    {
      __u64           log_id;
    } new_group;
  } data;
};

//Yang
struct execve_ahgv
{
  int  pid;
  char filename[PATH_MAX+1];
  int  is_user_remote;
  int  rc;
  char *args;
};

void packahgv_execve(struct execve_ahgv *sys_args)
{
  char ids[IDS_LEN+1];
  int is_user_remote;
  char *fpath = NULL;
  int size = 0;
  char uuid_str[THEIA_UUID_LEN + 1];
  struct file *file;
  int fd, fput_needed;
  mm_segment_t old_fs;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false;
  char *args_b64 = NULL;
  bool args_b64_alloced = false;
  uint32_t buf_size;
  char *buf;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf;
#endif
  //Yang
  if (theia_logging_toggle)
  {
    long sec, nsec;
#ifndef DPATH_USE_STACK
    pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
    get_curr_time(&sec, &nsec);
    get_ids(ids);
    is_user_remote = is_remote(current);
    old_fs = get_fs();

    set_fs(KERNEL_DS);
    fd = sys_open(sys_args->filename, O_RDONLY, 0);
    if (fd >= 0)
    {
      if (fd2uuid(fd, uuid_str) == false)
      {
        sys_close(fd);
        set_fs(old_fs);
        goto err;
      }

      file = fget_light(fd, &fput_needed);
      if (file)
      {
        fpath = get_file_fullpath(file, pbuf, THEIA_DPATH_LEN);
        if (IS_ERR_OR_NULL(fpath))
        {
          strncpy_safe(pbuf, sys_args->filename, THEIA_DPATH_LEN-1);
          fpath = pbuf;
        }
        fput_light(file, fput_needed);
      }
      sys_close(fd);
    }
    else
    {
      TPRINT("XXX: %s %d\n", sys_args->filename, fd);
      set_fs(old_fs);
      goto err; /* TODO: error handling */
    }
    set_fs(old_fs);

    fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
    if (!fpath_b64) 
      fpath_b64 = "";
    else
      fpath_b64_alloced = true;

    args_b64 = base64_encode(sys_args->args, strlen(sys_args->args), NULL);
    if (!args_b64) 
      args_b64 = "";
    else
      args_b64_alloced = true;

    buf_size = strlen(args_b64) + strlen(fpath_b64) + 256;
    buf = vmalloc(buf_size);

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    /* TODO: publish args as well sys_args->args. problem? args can contain | do BASE64 encoding? */
    size = snprintf(buf, buf_size, "startahg|%d|%d|%ld|%d|%s|%s|%s|%s|%d|%d|%ld|%ld|%u|endahg\n",
                   59, sys_args->pid, current->start_time.tv_sec, sys_args->rc,
                   uuid_str, fpath_b64, args_b64, ids, is_user_remote, current->tgid, sec, nsec, current->no_syscalls++);
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);

    vfree(buf);
    if (args_b64_alloced)
      vfree(args_b64);
    if (fpath_b64_alloced)
      vfree(fpath_b64);
err: ;
#ifndef DPATH_USE_STACK
    kmem_cache_free(theia_buffers, pbuf);
#endif
  }
}

// void theia_execve_ahg(const char *filename, const char __user *const __user *envp) {
void theia_execve_ahg(const char *filename, int rc)
{
  struct execve_ahgv *pahgv = NULL;
  char *args = NULL;
  bool valid_cmdline = false;  

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  args = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
  valid_cmdline = get_cmdline(current, args);

  if (!valid_cmdline)
    args[0] = '\0';

  pahgv = (struct execve_ahgv *)KMALLOC(sizeof(struct execve_ahgv), GFP_KERNEL);
  if (pahgv == NULL)
  {
    TPRINT("theia_execve_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv->pid = current->pid;
  strncpy_safe(pahgv->filename, filename, PATH_MAX);
  pahgv->rc = rc;
  pahgv->args = args;
  packahgv_execve(pahgv);
  KFREE(pahgv);
  kmem_cache_free(theia_buffers, args);
}

void print_value(u_long address, int num_of_bytes)
{
  int n = num_of_bytes, i = 0;
  unsigned char *byte_array = (unsigned char *)address;

  while (i < n)
  {
    TPRINT("%02X", (unsigned)byte_array[i]);
    i++;
  }
  TPRINT("\n");
  return;
}

// Simply recording the fact that an execve takes place, we won't replay it
static int
record_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs)
{
  struct execve_retvals *pretval = NULL;
  struct record_thread *prt = current->record_thrd;
  struct record_group *precg;
  struct record_thread *prect;
  void *slab;
#ifdef LOG_COMPRESS_1
  void *clog_slab;
#endif
  char ckpt[MAX_LOGDIR_STRLEN + 10];
  long rc = 0, retval;
  char *argbuf, *newbuf;
  int argbuflen, present;
  char **env;
  mm_segment_t old_fs;
#ifdef TIME_TRICK
  struct timeval tv;
  struct timespec tp;
#endif
  __u64 parent_rg_id;

  pr_debug("Yang just start record_execve\n");
  //show_regs(get_pt_regs(NULL));
  /*
     __asm__ __volatile__ ("mov %%rsp, %0": "=r"(cur_rsp));
     show_kernel_stack((u_long*)cur_rsp);
     */
  /*
     const char *whitelist1;
     whitelist1 = "/usr/lib/firefox/firefox";

     if(strcmp(filename, whitelist1) == 0) {
     TPRINT("theia_start_execve, ignore %s\n", filename);
     rc = do_execve(filename, __argv, __envp, regs);
     theia_execve_ahg(filename);
     return rc;
     }
     */

  MPRINT("Record pid %d performing execve of %s\n", current->pid, filename);
  new_syscall_enter(59);

  current->record_thrd->random_values.cnt = 0;

  // (flush) and write out the user log before exec-ing (otherwise it disappears)
#ifndef USE_DEBUG_LOG
  flush_user_log(prt);
#endif
  write_user_log(prt);
#ifdef USE_EXTRA_DEBUG_LOG
  write_user_extra_log(prt);
#endif
  // Have to copy arguments out before address space goes away - we will likely need them later
  argbuf = copy_args(__argv, __envp, &argbuflen, NULL, 0);

  // Hack to support multiple glibcs - make sure that LD_LIBRARY_PATH is in there
  present = is_libpath_present(current->record_thrd->rp_group, argbuf);
  if (present)
  {
    // Need to copy environments to kernel and modify
    env = patch_for_libpath(current->record_thrd->rp_group, argbuf, present);
    newbuf = patch_buf_for_libpath(current->record_thrd->rp_group, argbuf, &argbuflen, present);
    if (env == NULL || newbuf == NULL)
    {
      TPRINT("libpath patch failed\n");
      return -ENOMEM;
    }
    KFREE(argbuf);
    argbuf = newbuf;
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    rc = do_execve(filename, __argv, (const char __user * const __user *) env, regs);
    set_fs(old_fs);
    libpath_env_free(env);
  }
  else
  {
    /*
       TPRINT("Yang before do_execve\n");
       __asm__ __volatile__ ("mov %%rsp, %0": "=r"(cur_rsp));
       show_kernel_stack((u_long*)cur_rsp);
       */
    rc = do_execve(filename, __argv, __envp, regs);
    /*
       TPRINT("Yang after do_execve\n");
       __asm__ __volatile__ ("mov %%rsp, %0": "=r"(cur_rsp));
       show_kernel_stack((u_long*)cur_rsp);
       */
  }

  //Yang
  theia_execve_ahg(filename, rc);

  new_syscall_done(59, rc);
  TPRINT("Yang record_execve after new_syscall_done, ip: %lx, sp: %lx, r11: %lx, rc %ld\n", regs->ip, regs->sp, regs->r11, rc);
  print_value(regs->sp, 128);
  print_value(regs->sp + 128, 16);
  if (rc >= 0)
  {
    prt->rp_user_log_addr = 0; // User log address no longer valid since new address space entirely
#ifdef USE_EXTRA_DEBUG_LOG
    prt->rp_user_extra_log_addr = 0;
#endif
    // Our rule is that we record a split if there is an exec with more than one thread in the group.   Not sure this is best
    // but I don't know what is better
    if (prt->rp_next_thread != prt)
    {
      TPRINT("Yang prt->rp_next_thread != prt, rc %ld\n", rc);
      parent_rg_id = prt->rp_group->rg_id;
      DPRINT("New record group\n");

      // First setup new record group
      precg = new_record_group(NULL);
      if (precg == NULL)
      {
        current->record_thrd = NULL;
        return -ENOMEM;
      }
      strncpy_safe(precg->rg_linker, prt->rp_group->rg_linker, MAX_LOGDIR_STRLEN);
      precg->rg_save_mmap_flag = prt->rp_group->rg_save_mmap_flag;

      MPRINT("Pid %d - splits a new record group with logdir %s, save_mmap_flag %d\n", current->pid, precg->rg_logdir, precg->rg_save_mmap_flag);

      if (prt->rp_group->rg_libpath)
      {
        precg->rg_libpath = KMALLOC(strlen(prt->rp_group->rg_libpath) + 1, GFP_KERNEL);
        if (precg->rg_libpath == NULL)
        {
          TPRINT("Unable to allocate libpath on execve\n");
          current->record_thrd = NULL;
          return -ENOMEM;
        }
        strncpy_safe(precg->rg_libpath, prt->rp_group->rg_libpath, MAX_LIBPATH_STRLEN);
      }

      prect = new_record_thread(precg, current->pid, NULL);
      if (prect == NULL)
      {
        destroy_record_group(precg);
        current->record_thrd = NULL;
        return -ENOMEM;
      }
      memcpy(&prect->random_values, &prt->random_values, sizeof(prt->random_values));
      memcpy(&prect->exec_values, &prt->exec_values, sizeof(prt->exec_values));

      slab = VMALLOC(argsalloc_size);
      if (slab == NULL)
      {
        destroy_record_group(precg);
        current->record_thrd = NULL;
        return -ENOMEM;
      }

      if (add_argsalloc_node(current->record_thrd, slab, argsalloc_size))
      {
        VFREE(slab);
        destroy_record_group(precg);
        current->record_thrd = NULL;
        return -ENOMEM;
      }
#ifdef LOG_COMPRESS_1
      clog_slab = VMALLOC(argsalloc_size);
      if (clog_slab == NULL)
      {
        destroy_record_group(precg);
        current->record_thrd = NULL;
        return -ENOMEM;
      }

      if (add_clog_node(current->record_thrd, clog_slab, argsalloc_size))
      {
        VFREE(clog_slab);
        destroy_record_group(precg);
        current->record_thrd = NULL;
        return -ENOMEM;
      }
#endif
      // Now write last record to log and flush it to disk
      pretval = ARGSKMALLOC(sizeof(struct execve_retvals), GFP_KERNEL);
      if (pretval == NULL)
      {
        TPRINT("Unable to allocate space for execve retvals\n");
        return -ENOMEM;
      }
      pretval->is_new_group = 1;
      pretval->data.new_group.log_id = precg->rg_id;
      TPRINT("Yang record_execve before new_syscall_exit, rc %ld\n", rc);
      new_syscall_exit(59, pretval);
      write_and_free_kernel_log(prt);

      if (atomic_dec_and_test(&prt->rp_group->rg_record_threads))
      {
        rg_lock(prt->rp_group);
        MPRINT("Pid %d last record thread to exit, write out mmap log\n", current->pid);
        write_mmap_log(prt->rp_group);
        prt->rp_group->rg_save_mmap_flag = 0;
        rg_unlock(prt->rp_group);
      }

      __destroy_record_thread(prt);   // The old group may no longer be valid after this

      // Switch thread to new record group
      current->record_thrd = prt = prect;

      // Write out checkpoint for the new group
      snprintf(ckpt, MAX_LOGDIR_STRLEN+10, "%s/ckpt", precg->rg_logdir);
#ifdef TIME_TRICK
      retval = replay_checkpoint_to_disk(ckpt, (char *) filename, argbuf, argbuflen, parent_rg_id, &tv, &tp);
      init_det_time(&precg->rg_det_time, &tv, &tp);
#else
      retval = replay_checkpoint_to_disk(ckpt, (char *) filename, argbuf, argbuflen, parent_rg_id);
#endif
      if (retval)
      {
        TPRINT("record_execve: replay_checkpoint_to_disk returns %ld\n", retval);
        if (slab) VFREE(slab);
#ifdef LOG_COMPRESS_1
        VFREE(clog_slab);
#endif
        destroy_record_group(precg);
        current->record_thrd = NULL;
        return retval;
      }
      argbuf = NULL;

      // Write out first log record (exec) for the new group - the code below will finish the job
      new_syscall_enter(59);
      new_syscall_done(59, 0);
    }
    else
    {
#ifdef CACHE_READS
      close_record_cache_files(prt->rp_cache_files); // This is conservative - some files may not have been closed on exec - but it is correct
#endif
      prt->rp_ignore_flag_addr = NULL; // No longer valid since address space destroyed
    }

    pretval = ARGSKMALLOC(sizeof(struct execve_retvals), GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("Unable to allocate space for execve retvals\n");
      return -ENOMEM;
    }

    pretval->is_new_group = 0;
    memcpy(&pretval->data.same_group.rvalues, &prt->random_values, sizeof(struct rvalues));
    memcpy(&pretval->data.same_group.evalues, &prt->exec_values, sizeof(struct exec_values));
    rg_lock(prt->rp_group);
    add_file_to_cache_by_name(filename, &pretval->data.same_group.dev, &pretval->data.same_group.ino, &pretval->data.same_group.mtime);
    rg_unlock(prt->rp_group);
  }
  if (argbuf) KFREE(argbuf);
  new_syscall_exit(59, pretval);
  //show_regs(get_pt_regs(NULL));
  /*
     __asm__ __volatile__ ("mov %%rsp, %0": "=r"(cur_rsp));
     show_kernel_stack((u_long*)cur_rsp);
     TPRINT("Yang record_execve after new_syscall_exit, rc %d\n", rc);
     */
  return rc;
}

void complete_vfork_done(struct task_struct *tsk); // In fork.c

// need to advance the record log past the execve, but we don't replay it
// We need to record that an exec happened in the log for knowing when to clear
// preallocated memory in a forked process
static int
replay_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs)
{
  struct replay_thread *prt = current->replay_thrd;
  struct replay_thread *tmp;
  struct replay_group *prg = prt->rp_group;
  struct syscall_result *psr;
  struct execve_retvals *retparams = NULL;
  mm_segment_t old_fs;
  long rc, retval;
  char name[CACHE_FILENAME_SIZE], logdir[MAX_LOGDIR_STRLEN + 1], linker[MAX_LOGDIR_STRLEN + 1];
  int num_blocked, follow_splits;
  u_long clock, app_syscall_addr;
  __u64 logid;

  retval = get_next_syscall_enter(prt, prg, 59, (char **) &retparams, &psr);   // Need to split enter/exit because of vfork/exec wait
  if (retval >= 0)
  {

#ifdef CACHE_READS
    close_replay_cache_files(prt->rp_cache_files);  // Simpler to just close whether group survives or not
#endif
    if (retparams->is_new_group)
    {
      if (current->vfork_done) complete_vfork_done(current);

      get_next_syscall_exit(prt, prg, psr);

      if (prg->rg_follow_splits)
      {

        DPRINT("Following split\n");
        // Let some other thread in this group run because we are done
        get_record_group(prg->rg_rec_group);
        rg_lock(prg->rg_rec_group);
        clock = *prt->rp_preplay_clock;
        prt->rp_status = REPLAY_STATUS_DONE;
        tmp = prt->rp_next_thread;
        num_blocked = 0;
        while (tmp != prt)
        {
          DPRINT("Pid %d considers thread %d status %d clock %ld - clock is %ld\n", current->pid, tmp->rp_replay_pid, tmp->rp_status, tmp->rp_wait_clock, clock);
          if (tmp->rp_status == REPLAY_STATUS_ELIGIBLE || (tmp->rp_status == REPLAY_STATUS_WAIT_CLOCK && tmp->rp_wait_clock <= clock))
          {
            tmp->rp_status = REPLAY_STATUS_RUNNING;
            wake_up(&tmp->rp_waitq);
            break;
          }
          else if (tmp->rp_status != REPLAY_STATUS_DONE)
          {
            num_blocked++;
          }
          tmp = tmp->rp_next_thread;
          if (tmp == prt && num_blocked)
          {
            TPRINT("Pid %d (recpid %d): Crud! no eligible thread to run on exit, clock is %ld\n", current->pid, prt->rp_record_thread->rp_record_pid, clock);
            dump_stack(); // how did we get here?
            // cycle around again and print
            tmp = tmp->rp_next_thread;
            while (tmp != current->replay_thrd)
            {
              TPRINT("\t thread %d (recpid %d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
              tmp = tmp->rp_next_thread;
            }
          }
        }

        // Save id because group may be deleted
        logid = retparams->data.new_group.log_id;
        app_syscall_addr = prt->app_syscall_addr;
        strncpy_safe(linker, prg->rg_rec_group->rg_linker, MAX_LOGDIR_STRLEN);
        follow_splits = prg->rg_follow_splits;

        // Now remove reference to the replay group
        put_replay_group(prg);
        current->replay_thrd = NULL;
        rg_unlock(prg->rg_rec_group);
        put_record_group(prg->rg_rec_group);

        // Now start a new group if needed
        get_logdir_for_replay_id(logid, logdir);
        TPRINT("[%s|%d] pid %d, app_syscall_addr %lx, value %d\n", __func__, __LINE__, current->pid,
               app_syscall_addr, (app_syscall_addr <= 1) ? -1 : * (int *)(app_syscall_addr));
        return replay_ckpt_wakeup(app_syscall_addr, logdir, linker, -1, follow_splits, prg->rg_rec_group->rg_save_mmap_flag);
      }
      else
      {
        DPRINT("Don't follow splits - so just exit\n");
        sys_exit_group(0);
      }
    }
    else
    {
      MPRINT("Replay pid %d performing execve of %s\n", current->pid, filename);
      memcpy(&current->replay_thrd->random_values, &retparams->data.same_group.rvalues, sizeof(struct rvalues));
      memcpy(&current->replay_thrd->exec_values, &retparams->data.same_group.evalues, sizeof(struct exec_values));
      argsconsume(prt->rp_record_thread, sizeof(struct execve_retvals));
      current->replay_thrd->random_values.cnt = 0;

      rg_lock(prt->rp_record_thread->rp_group);
      get_cache_file_name(name, retparams->data.same_group.dev, retparams->data.same_group.ino, retparams->data.same_group.mtime, prt->rp_group->cache_dir);
      rg_unlock(prt->rp_record_thread->rp_group);

      old_fs = get_fs();
      set_fs(KERNEL_DS);
      prt->rp_exec_filename = filename;
      MPRINT("%s %d: do_execve(%s, %p, %p, %p)\n", __func__, __LINE__, name, __argv, __envp, regs);
      rc = do_execve(name, __argv, __envp, regs);
      set_fs(old_fs);

      prt->rp_record_thread->rp_ignore_flag_addr = NULL;

      if (rc != retval)
      {
        TPRINT("[ERROR] Replay pid %d sees execve return %ld, recorded rc was %ld\n", current->pid, rc, retval);
        syscall_mismatch();
      }
    }

    /* Irregardless of splitting, if pin is attached we'll try to attach */
    if (is_pin_attached())
    {
      prt->app_syscall_addr = 1; /* We need to reattach the pin tool after exec */
      TPRINT("[%s|%d] pid %d, prt->app_syscall_addr is set to 1\n", __func__, __LINE__, current->pid);
      preallocate_memory(prt->rp_record_thread->rp_group);  /* And preallocate memory again - our previous preallocs were just destroyed */
      create_used_address_list();
    }
  }
  get_next_syscall_exit(prt, prg, psr);

  MPRINT("replay_execve: sp is %lx, ip is %lx\n", regs->sp, regs->ip);

  return retval;
}

int theia_sys_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs)
{
  long rc;

  rc = do_execve(filename, __argv, __envp, regs);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  {
    theia_execve_ahg(filename, rc);
  }
  return rc;
}

int theia_start_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs)
{
  // white list according to the filename
  int ret;
  int fd;
  long rc = 0;
  const char *devfile = "/dev/spec0";
  struct path linker_path;
  int save_mmap = 1;

  // TPRINT("in theia_start_execve: filename %s\n", filename);

  mm_segment_t old_fs = get_fs();

  set_fs(KERNEL_DS);

  if (theia_recording_toggle == 0
      && theia_replay_register_data.pid == 0)
  {
    goto out_norm;
  }

  ret = sys_access(devfile, 0/*F_OK*/);
  if (ret < 0)  //for ensure the inert_spec.sh is done before record starts.
  {
    TPRINT("%s not accessible yet. ret %d\n", devfile, ret);
    theia_recording_toggle = 0;
    goto out_norm;
  }
  fd = sys_open(devfile, O_RDWR, 0777 /*mode should be ignored anyway*/);
  if (fd < 0)
  {
    TPRINT("%s not open yet. fd %d\n", devfile, fd);
    theia_recording_toggle = 0;
    goto out_norm;
  }

/*white-list of recording*/
  if( (strstr(current->comm, "deja-dup") != NULL) ||
      (strstr(current->comm, "git") != NULL) || 
      (strstr(current->comm, "apt") != NULL) || 
      (strstr(current->comm, "stat") != NULL) || 
      (strstr(current->comm, "dkpg") != NULL) || 
      (strstr(current->comm, "firefox") != NULL) || 
      (strstr(current->comm, "soffice") != NULL) || 
      (strstr(current->comm, "xfce4") != NULL) || 
      (strstr(current->comm, "gnome") != NULL) ) {
    TPRINT("[Record-blacklist] %s is skipped.\n", current->comm);
    goto out_norm;
  }

  if (theia_recording_toggle == 1 && __envp)
  {
    TPRINT("/dev/spec0 ready ! filename: %s\n", filename);
    //should be ready to add the process to record_group
    ret = sys_access(theia_linker, 0/*F_OK*/);
    if (ret < 0)  //if linker is not there, bail out
    {
      pr_warn_ratelimited("theia linker \"%s\" not found\n", theia_linker);
      theia_recording_toggle = 0;
      goto out_norm;
    }
    //check for linker path being a symlink
    ret = kern_path(theia_linker, LOOKUP_FOLLOW, &linker_path);
    if (!ret)
    {
      char followed_buf[MAX_LOGDIR_STRLEN + 1];
      char *followed_path;
      followed_path = d_path(&linker_path, followed_buf, MAX_LOGDIR_STRLEN);
      if (!IS_ERR(followed_path))
      {
        ret = sys_access(followed_path, 0/*F_OK*/);
        if (ret < 0)  //if linker is not there, bail out
        {
          pr_warn_ratelimited("theia linker \"%s\", from symlink \"%s\", not found\n",
                              followed_path, theia_linker);
          theia_recording_toggle = 0;
          goto out_norm;
        }
        strncpy_safe(theia_linker, followed_path, MAX_LOGDIR_STRLEN);
      }
    }

    BUG_ON(IS_ERR_OR_NULL(theia_linker));
    set_fs(old_fs);
    rc = fork_replay_theia(NULL /*logdir*/, filename, __argv, __envp, theia_linker, save_mmap, fd, -1 /*pipe_fd*/);

    TPRINT("fork_replay_theia returns. %s, comm(%s)\n", filename, current->comm);
    goto out;
  }

  // a process is registered to be replayed, we call replay_ckpt_wakeup_theia().
  if (theia_replay_register_data.pid == current->pid)
  {
    set_fs(old_fs);
    TPRINT("Received theia_replay_register_data: \n pid %d, pin %d, logdir %s, linker %s, fd %d, follow_splits %d, save_mmap %d\n",
           theia_replay_register_data.pid,
           theia_replay_register_data.pin,
           theia_replay_register_data.logdir,
           theia_replay_register_data.linker,
           theia_replay_register_data.fd,
           theia_replay_register_data.follow_splits,
           theia_replay_register_data.save_mmap);

    theia_replay_register_data.pid = 0; // we clear this process in case it has more execve;
    //attach_pin should come along with setting theia_replay_toggle
    replay_ckpt_wakeup(theia_replay_register_data.pin,
                       theia_replay_register_data.logdir,
                       theia_replay_register_data.linker,
                       theia_replay_register_data.fd,
                       theia_replay_register_data.follow_splits,
                       theia_replay_register_data.save_mmap);

    TPRINT("replay_ckpt_wakeup returns. %s\n", filename);
    goto out;
    //    goto out_norm;
  }

  goto out_norm;

out:
  return rc;

out_norm:
  set_fs(old_fs);
  rc = do_execve(filename, __argv, __envp, regs);
  theia_execve_ahg(filename, rc);
  return rc;

}

int shim_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs)
SHIM_CALL_MAIN(59, record_execve(filename, __argv, __envp, regs), replay_execve(filename, __argv, __envp, regs), theia_start_execve(filename, __argv, __envp, regs))

inline void theia_chdir_ahgx(char __user *filename, long rc, int sysnum)
{
  theia_fullpath_ahgx(filename, rc, sysnum);
}

SIMPLE_SHIM1(chdir, 80, const char __user *, filename);
// THEIA_SHIM1(chdir, 80, const char __user *, filename);

static asmlinkage long
record_time(time_t __user *tloc)
{
  long rc;
  time_t *pretval = NULL;

  new_syscall_enter(201);
  rc = sys_time(tloc);
  new_syscall_done(201, rc);
  DPRINT("Pid %d records time returning %ld\n", current->pid, rc);
  if (tloc)
  {
    pretval = ARGSKMALLOC(sizeof(time_t), GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_time: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(pretval, tloc, sizeof(time_t)))
    {
      TPRINT("record_time: can't copy from user\n");
      ARGSKFREE(pretval, sizeof(time_t));
      return -EFAULT;
    }
  }
  new_syscall_exit(201, pretval);

  return rc;
}

RET1_REPLAY(time, 201, time_t, tloc, time_t __user *tloc);

asmlinkage long shim_time(time_t __user *tloc) SHIM_CALL(time, 201, tloc);

inline void theia_mknod_ahgx(const char __user *filename, int mode, unsigned dev, long rc, int sysnum)
{
  theia_dump_sdd(filename, mode, dev, rc, sysnum);
}

inline void theia_chmod_ahgx(char __user *filename, mode_t mode, long rc, int sysnum)
{
  struct path path;
  char *fpath = NULL;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false;
  char uuid_str[THEIA_UUID_LEN + 1];
  int error;
  int ret = 0;
  char *buf;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  error = user_path(filename, &path);
  if (error)
    goto err;

  fpath = d_path(&path, pbuf, THEIA_DPATH_LEN);
  if (IS_ERR(fpath) && access_ok(VERIFY_READ, filename, 256))
    fpath = filename;

  fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
  if (!fpath_b64) 
    fpath_b64 = "";
  else
    fpath_b64_alloced = true;

  path2uuid(path, uuid_str);
  ret = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%s|%d", uuid_str, fpath_b64, mode);
  if (ret > 0)
    theia_dump_str(buf, rc, sysnum);
err:
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
  if (fpath_b64_alloced)
    vfree(fpath_b64);
}

inline void theia_fchmod_ahgx(unsigned int fd, mode_t mode, long rc, int sysnum)
{
  struct file *file = NULL;
  char uuid_str[THEIA_UUID_LEN + 1];
  char *fpath = NULL;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false;
  int fput_needed;
  char *buf = NULL;
  int ret = 0;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf = NULL;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  file = fget_light(fd, &fput_needed);
  if (!file)
    goto err;

  fpath = get_file_fullpath(file, pbuf, THEIA_DPATH_LEN);
  if (IS_ERR(fpath))
    goto err;

  if (file2uuid(file, uuid_str, fd) == false)
    goto err;

  fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
  if (!fpath_b64) 
    fpath_b64 = "";
  else
    fpath_b64_alloced = true;

  ret = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%s|%d", uuid_str, fpath_b64, mode);
  if (ret > 0)
    theia_dump_str(buf, rc, sysnum);
err:
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
  if (file)
    fput_light(file, fput_needed);
  if (fpath_b64_alloced)
    vfree(fpath_b64);
}

inline void theia_fchmodat_ahgx(int dfd, char __user *filename, int mode,
                                long rc, int sysnum)
{
  struct path path;
  char *fpath = NULL;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false;
  int error;
  char uuid_str[THEIA_UUID_LEN + 1];
  unsigned int lookup_flags = LOOKUP_FOLLOW;
  char *buf = NULL;
  int ret = 0;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf = NULL;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  error = user_path_at(dfd, filename, lookup_flags, &path);
  if (!error)
  {
    fpath = d_path(&path, pbuf, THEIA_DPATH_LEN);
    if (IS_ERR(fpath) && access_ok(VERIFY_READ, filename, 256))
      fpath = filename;
    else
    {
      fpath = NULL;
    }
  }
  else
  {
    error = user_path(filename, &path);
    if (error)
      goto err;

    fpath = d_path(&path, pbuf, THEIA_DPATH_LEN);
    if (IS_ERR(fpath) && access_ok(VERIFY_READ, filename, 256))
      fpath = filename;
    else
    {
      fpath = NULL;
    }
  }

  if (fpath == NULL)
    goto err;

  fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
  if (!fpath_b64) 
    fpath_b64 = "";
  else
    fpath_b64_alloced = true;

  path2uuid(path, uuid_str);
  ret = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%s|%d", uuid_str, fpath_b64, mode);
  if (ret > 0)
  theia_dump_str(buf, rc, sysnum);
err:
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
  if (fpath_b64_alloced)
    vfree(fpath_b64);
}

inline void theia_fchown_ahgx(unsigned int fd, uid_t user, gid_t group, long rc, int sysnum)
{
  struct file *file = NULL;
  char uuid_str[THEIA_UUID_LEN + 1];
  char *fpath = NULL;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false;
  int fput_needed;
  umode_t mode;
  char *buf = NULL;
  int ret = 0;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf = NULL;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  file = fget_light(fd, &fput_needed);
  if (!file)
    goto err;

  fpath = get_file_fullpath(file, pbuf, THEIA_DPATH_LEN);
  if (IS_ERR(fpath))
    goto err;

  if (file2uuid(file, uuid_str, fd) == false)
    goto err;

  fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
  if (!fpath_b64) 
    fpath_b64 = "";
  else
    fpath_b64_alloced = true;

  mode = file->f_path.dentry->d_inode->i_mode;
  fput_light(file, fput_needed);

  ret = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%s|%u|%d/%d", uuid_str, fpath_b64, mode, user, group);
  if (ret > 0)
    theia_dump_str(buf, rc, sysnum);
err:
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
  if (file)
    fput_light(file, fput_needed);
  if (fpath_b64_alloced)
    vfree(fpath_b64);
}

inline void theia_lchown_ahgx(char __user *filename, uid_t user, gid_t group,
                              long rc, int sysnum)
{
  struct path path;
  umode_t mode;
  char *fpath = NULL;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false;
  char uuid_str[THEIA_UUID_LEN + 1];
  int error;
  char *buf = NULL;
  int ret = 0;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf = NULL;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  error = user_lpath(filename, &path);
  if (error)
    goto err;

  mode = path.dentry->d_inode->i_mode;
  fpath = d_path(&path, pbuf, THEIA_DPATH_LEN);
  if (IS_ERR(fpath) && access_ok(VERIFY_READ, filename, 256))
    fpath = filename;

  fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
  if (!fpath_b64) 
    fpath_b64 = "";
  else
    fpath_b64_alloced = true;

  path2uuid(path, uuid_str);
  ret = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%s|%u|%d/%d", uuid_str, fpath_b64, mode, user, group);
  if (ret > 0)
    theia_dump_str(buf, rc, sysnum);
err:
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
  if (fpath_b64_alloced)
    vfree(fpath_b64);
}

inline void theia_chown_ahgx(char __user *filename, uid_t user,
                             gid_t group, long rc, int sysnum)
{
  struct path path;
  umode_t mode;
  char *fpath = NULL;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false;
  char uuid_str[THEIA_UUID_LEN + 1];
  int error;
  char *buf = NULL;
  int ret = 0;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf = NULL;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  error = user_path(filename, &path);
  if (error)
    goto err;

  fpath = d_path(&path, pbuf, THEIA_DPATH_LEN);
  if (IS_ERR(fpath) && access_ok(VERIFY_READ, filename, 256))
    fpath = filename;

  fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
  if (!fpath_b64) 
    fpath_b64 = "";
  else
    fpath_b64_alloced = true;

  mode = path.dentry->d_inode->i_mode;
  path2uuid(path, uuid_str);
  ret = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%s|%u|%d/%d", uuid_str, fpath_b64, mode, user, group);
  if (ret > 0)
    theia_dump_str(buf, rc, sysnum);
err:
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
  if (fpath_b64_alloced)
    vfree(fpath_b64);
}



inline void theia_fchownat_ahgx(int dfd, char __user *filename, uid_t user,
                                gid_t group, int flag, long rc, int sysnum)
{
  int res;
  char *fpath = NULL;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false;
  umode_t mode;
  struct path path;
  char uuid_str[THEIA_UUID_LEN + 1];
  char *buf = NULL;
  int ret = 0;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf = NULL;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  res = user_path_at(dfd, filename, LOOKUP_FOLLOW, &path);
  if (res == 0)
  {
    fpath = d_path(&path, pbuf, THEIA_DPATH_LEN);
    if (IS_ERR(fpath) && access_ok(VERIFY_READ, filename, 256))
      fpath = filename;

    fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
    if (!fpath_b64) 
      fpath_b64 = "";
    else
      fpath_b64_alloced = true;

    path2uuid(path, uuid_str);
    mode = path.dentry->d_inode->i_mode;
    ret = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%s|%u|%d/%d", uuid_str, fpath_b64, mode, user, group);
    if (ret > 0)
      theia_dump_str(buf, rc, sysnum);
  }
  else
  {
    if (current->fs)
    {
      get_fs_pwd(current->fs, &path);
      fpath = d_path(&path, pbuf, THEIA_DPATH_LEN);
      if (IS_ERR(fpath) && access_ok(VERIFY_READ, filename, 256))
        fpath = filename;

      fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
      if (!fpath_b64) 
        fpath_b64 = "";
      else
        fpath_b64_alloced = true;

      path2uuid(path, uuid_str);
      mode = path.dentry->d_inode->i_mode;
      ret = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%s||%u|%d/%d", uuid_str, fpath_b64, mode, user, group);
      if (ret > 0)
        theia_dump_str(buf, rc, sysnum);
    }
    else
    {
      TPRINT("[fchownat]: dfd & current->fs invalid.\n");
    }
  }
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
  if (fpath_b64_alloced)
    vfree(fpath_b64);
}

inline void theia_lseek_ahgx(unsigned int fd, off_t offset, unsigned int origin, long rc, int sysnum)
{
  theia_dump_ddd(fd, offset, origin, rc, sysnum);
}

//64port
SIMPLE_SHIM3(mknod, 133, const char __user *, filename, int, mode, unsigned, dev);
SIMPLE_SHIM3(lseek, 8, unsigned int, fd, off_t, offset, unsigned int, origin);

THEIA_SHIM2(chmod, 90, char __user *, filename, mode_t,  mode);
THEIA_SHIM2(fchmod, 91, unsigned int, fd, mode_t, mode);

THEIA_SHIM3(chown, 92, char __user *, filename, uid_t, user, gid_t, group);
THEIA_SHIM3(lchown, 94, char __user *, filename, uid_t, user, gid_t, group);
THEIA_SHIM3(fchown, 93, unsigned int, fd, uid_t, user, gid_t, group);

SIMPLE_SHIM0(getpid, 39);

//Yang
struct mount_ahgv
{
  int             pid;
  char            devname[50];
  char            dirname[50];
  char            type[30];
  unsigned long   flags;
  int             rc;
};


void packahgv_mount(struct mount_ahgv *sys_args)
{
  char uuid_str[THEIA_UUID_LEN + 1];
  struct file *file = NULL;
  int fd, fput_needed;
  char *fpath = NULL;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false;
  mm_segment_t old_fs;
  uint32_t buf_size;
  char *buf = NULL;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf = NULL;
#endif
  //Yang
  if (theia_logging_toggle)
  {
    long sec, nsec;
    int size = 0;
#ifndef DPATH_USE_STACK
    pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    fd = sys_open(sys_args->devname, O_RDONLY, 0);
    if (fd >= 0)
    {
      if (fd2uuid(fd, uuid_str) == false)
      {
        sys_close(fd);
        set_fs(old_fs);
        goto err;
      }

      if (uuid_str[0] == '\0')
        strcpy(uuid_str, "I|0|0|0|0|-1/-1");

      file = fget_light(fd, &fput_needed);
      if (file)
      {
        fpath = get_file_fullpath(file, pbuf, THEIA_DPATH_LEN);
        if (IS_ERR_OR_NULL(fpath))
        {
          strncpy_safe(pbuf, sys_args->devname, THEIA_DPATH_LEN-1);
          fpath = pbuf;
        }
        fput_light(file, fput_needed);
      }
      sys_close(fd);
    }
    else
    {
      strcpy(uuid_str, "I|0|0|0|0|-1/-1"); /* imaginary file, e.g., debugfs */
      strncpy_safe(pbuf, sys_args->devname, THEIA_DPATH_LEN-1);
      fpath = pbuf;
    }
    set_fs(old_fs);

    get_curr_time(&sec, &nsec);

    fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
    if (!fpath_b64) 
      fpath_b64 = "";
    else
      fpath_b64_alloced = true;

    buf_size = strlen(fpath_b64) + 256;
    buf = vmalloc(buf_size);

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, buf_size, "startahg|%d|%d|%ld|%s|%s|%s|%s|%lu|%d|%d|%ld|%ld|%u|endahg\n",
                   165, sys_args->pid, current->start_time.tv_sec, uuid_str, fpath_b64, sys_args->dirname, sys_args->type,
                   sys_args->flags, sys_args->rc, current->tgid, sec, nsec, current->no_syscalls++);

    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);

    vfree(buf);
    if (fpath_b64_alloced)
      vfree(fpath_b64);
err: ;
#ifndef DPATH_USE_STACK
    kmem_cache_free(theia_buffers, pbuf);
#endif
  }
}

void theia_mount_ahg(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, int rc)
{
  struct mount_ahgv *pahgv = NULL;
  int copied_length = 0;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  //  TPRINT("theia_read_ahg clock", current->record_thrd->rp_precord_clock);
  // Yang: regardless of the return value, passes the failed syscall also
  //  if(rc >= 0)
  {
    pahgv = (struct mount_ahgv *)KMALLOC(sizeof(struct mount_ahgv), GFP_KERNEL);
    if (pahgv == NULL)
    {
      TPRINT("theia_mount_ahg: failed to KMALLOC.\n");
      return;
    }

    pahgv->pid = current->pid;

    if ((copied_length = strncpy_from_user(pahgv->devname, dev_name, sizeof(pahgv->devname))) != strlen(dev_name))
    {
      TPRINT("theia_mount_ahg: can't copy devname to ahgv, devname length %lu, copied %d, devname:%s\n", strlen(dev_name), copied_length, dev_name);
      KFREE(pahgv);
    }

    if ((copied_length = strncpy_from_user(pahgv->dirname, dir_name, sizeof(pahgv->dirname))) != strlen(dir_name))
    {
      TPRINT("theia_mount_ahg: can't copy dir_name to ahgv, dir_name length %lu, copied %d, dir_name:%s\n", strlen(dir_name), copied_length, dir_name);
      KFREE(pahgv);
    }

    if ((copied_length = strncpy_from_user(pahgv->type, type, sizeof(pahgv->type))) != strlen(type))
    {
      TPRINT("theia_mount_ahg: can't copy type to ahgv, type length %lu, copied %d, type:%s\n", strlen(type), copied_length, type);
      KFREE(pahgv);
    }

    pahgv->flags = flags;
    pahgv->rc = rc;
    packahgv_mount(pahgv);
    KFREE(pahgv);
  }

}

int theia_sys_mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data)
{
  int rc;
  rc = sys_mount(dev_name, dir_name, type, flags, data);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  {
    theia_mount_ahg(dev_name, dir_name, type, flags, rc);
  }
  return rc;
}

static asmlinkage long
record_mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data)
{
  long rc;
  new_syscall_enter(165);
  rc = sys_mount(dev_name, dir_name, type, flags, data);
  theia_mount_ahg(dev_name, dir_name, type, flags, (int)rc);
  new_syscall_done(165, rc);
  new_syscall_exit(165, NULL);
  return rc;

}

SIMPLE_REPLAY(mount, 165, char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data);

asmlinkage long shim_mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data)
SHIM_CALL_MAIN(165, record_mount(dev_name, dir_name, type, flags, data), replay_mount(dev_name, dir_name, type, flags, data), theia_sys_mount(dev_name, dir_name, type, flags, data))

static asmlinkage long
record_ptrace(long request, long pid, long addr, long data)
{
  struct task_struct *tsk = pid_task(find_vpid(pid), PIDTYPE_PID);
  long rc;

  if (tsk)   // Invalid pid should fail, so replay is easy
  {
    if (!tsk->record_thrd)
    {
      TPRINT("[ERROR] pid %d records ptrace of non-recordig pid %ld\n", current->pid, pid);
      return sys_ptrace(request, pid, addr, data);
    }
    else if (tsk->record_thrd->rp_group != current->record_thrd->rp_group)
    {
      TPRINT("[ERROR] pid %d records ptrace of pid %ld in different record group - must merge\n", current->pid, pid);
      return sys_ptrace(request, pid, addr, data);
    } // Now we know two tasks are in same record group, so memory ops should be deterministic (unless they incorrectly involve replay-specific structures) */
  }

  new_syscall_enter(101);
  rc = sys_ptrace(request, pid, addr, data);
  new_syscall_done(101, rc);
  new_syscall_exit(101, NULL);
  return rc;
}

static asmlinkage long
replay_ptrace(long request, long pid, long addr, long data)
{
  struct replay_thread *tmp;
  long rc, retval;

  rc = get_next_syscall(101, NULL);

  // Need to adjust pid to reflect the replay process, not the record process
  tmp = current->replay_thrd->rp_next_thread;
  while (tmp != current->replay_thrd)
  {
    if (tmp->rp_record_thread->rp_record_pid == pid)
    {
      retval = sys_ptrace(request, tmp->rp_record_thread->rp_record_pid, addr, data);
      if (rc != retval)
      {
        TPRINT("ptrace returns %ld on replay but returned %ld on record\n", retval, rc);
        syscall_mismatch();
      }
      return rc;
    }
  }
  TPRINT("ptrace: pid %d cannot find record pid %ld in replay group\n", current->pid, pid);
  return syscall_mismatch();
}

asmlinkage long shim_ptrace(long request, long pid, long addr, long data)
{
  // Paranoid check
  if (!(current->record_thrd  || current->replay_thrd))
  {
    struct task_struct *tsk = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (tsk && tsk->record_thrd)
    {
      TPRINT("[ERROR]: non-recorded process %d ptracing the address space of recorded thread %ld\n", current->pid, pid);
    }
  }
  SHIM_CALL(ptrace, 101, request, pid, addr, data)
}

//64port
SIMPLE_SHIM2(access, 21, const char __user *, filename, int, mode);
SIMPLE_SHIM1(dup, 32, unsigned int, fildes);
SIMPLE_SHIM2(dup2, 33, unsigned int, oldfd, unsigned int, newfd);
SIMPLE_SHIM0(pause, 34);
SIMPLE_SHIM1(alarm, 37, unsigned int, seconds);
SIMPLE_SHIM2(utime, 132, char __user *, filename, struct utimbuf __user *, times);
SIMPLE_SHIM0(sync, 162);

inline void theia_kill_ahgx(int pid, int sig, long rc, int sysnum)
{
  theia_dump_dd(pid, sig, rc, sysnum);
}

inline void theia_rename_ahgx(const char __user *oldname, char __user *newname, long rc, int sysnum)
{
  theia_dump_ss(oldname, newname, rc, sysnum);
}

inline void theia_mkdir_ahgx(char __user *pathname, int mode, long rc, int sysnum)
{
  theia_dump_sd(pathname, mode, rc, sysnum);
}

inline void theia_mkdirat_ahgx(int dfd, char __user *pathname, int mode, long rc, int sysnum)
{
  theia_dump_at_sd(dfd, pathname, mode, rc, sysnum);
}

inline void theia_rmdir_ahgx(char __user *pathname, long rc, int sysnum)
{
  theia_fullpath_ahgx(pathname, rc, sysnum);
}

/*
THEIA_SHIM2(kill, 62, int, pid, int, sig);
THEIA_SHIM2(rename, 82, const char __user *, oldname, const char __user *, newname);
THEIA_SHIM2(mkdir, 83, const char __user *, pathname, int, mode);
THEIA_SHIM1(rmdir, 84, const char __user *, pathname);
*/
SIMPLE_SHIM2(kill, 62, int, pid, int, sig);
SIMPLE_SHIM2(rename, 82, const char __user *, oldname, const char __user *, newname);
SIMPLE_SHIM2(mkdir, 83, const char __user *, pathname, int, mode);
SIMPLE_SHIM1(rmdir, 84, const char __user *, pathname);

//Yang
struct pipe_ahgv
{
  int    pid;
  u_long retval;
  int    pfd1;
  int    pfd2;
  u_long dev1;
  u_long dev2;
  u_long ino1;
  u_long ino2;
};

void packahgv_pipe(struct pipe_ahgv *sys_args)
{
  char uuid_str[THEIA_UUID_LEN + 1];
  int size = 0;
  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    get_curr_time(&sec, &nsec);
    /* TODO: publish both ends' data: dev1, dev2, ino1, ino2 */
#ifdef THEIA_UUID
    if (fd2uuid(sys_args->pfd1, uuid_str) == false)
      goto err; /* no pipe? */

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%ld|%s|%d|%ld|%ld|%u|endahg\n",
                   22, sys_args->pid, current->start_time.tv_sec, sys_args->retval,
                   uuid_str, current->tgid, sec, nsec, current->no_syscalls++);
#else
    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%ld|%d|%d|%lx|%lx|%d|%ld|%ld|endahg\n",
                   22, sys_args->pid, current->start_time.tv_sec, sys_args->retval, sys_args->pfd1, sys_args->pfd2,
                   sys_args->dev1, sys_args->ino1, current->tgid, sec, nsec); // let's focus on pipe inode (dev,ino) itself
#endif
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
err:
    kmem_cache_free(theia_buffers, buf);
  }
}

void theia_pipe_ahg(u_long retval, int pfd1, int pfd2)
{
  struct pipe_ahgv *pahgv = NULL;
  struct file *file = NULL;
  struct inode *inode;
  int fput_needed;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv = (struct pipe_ahgv *)KMALLOC(sizeof(struct pipe_ahgv), GFP_KERNEL);
  if (pahgv == NULL)
  {
    TPRINT("theia_pipe_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv->pid = current->pid;
  pahgv->retval = retval;
  pahgv->pfd1 = pfd1;
  pahgv->pfd2 = pfd2;

  if (pfd1 >= 0)
    file = fget_light(pfd1, &fput_needed);

  if (!file)
  {
    pahgv->dev1 = 0;
    pahgv->ino1 = 0;
  }
  else
  {
    inode = file->f_dentry->d_inode;
    pahgv->dev1 = inode->i_sb->s_dev;
    pahgv->ino1 = inode->i_ino;
    fput_light(file, fput_needed);
  }

  /* seems that file obj for pfd2 is not ready at this point */
  //  pahgv->dev2 = 0; pahgv->ino2 = 0;
  /*
    file = NULL;
    if (pfd2 >= 0)
      file = fget(pfd2);

    if (!file) {
      pahgv->dev2 = 0;
      pahgv->ino2 = 0;
    }
    else {
      inode = file->f_dentry->d_inode;
      pahgv->dev2 = inode->i_sb->s_dev;
      pahgv->ino2 = inode->i_ino;
      fput(file);
    }
  */

  packahgv_pipe(pahgv);
  KFREE(pahgv);
}

asmlinkage long
record_pipe(int __user *fildes)
{
  long rc;
  int *pretval = NULL;

  new_syscall_enter(22);
  rc = sys_pipe(fildes);
  new_syscall_done(22, rc);
  if (rc == 0)
  {
#ifdef LOG_COMPRESS_1
    pipe_fds_insert(&current->record_thrd->rp_clog.pfds, fildes);
#endif
    pretval = ARGSKMALLOC(2 * sizeof(int), GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_pipe: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(pretval, fildes, 2 * sizeof(int)))
    {
      ARGSKFREE(pretval, 2 * sizeof(int));
      return -EFAULT;
    }
    //Yang
    if (rc >= 0)
    {
      theia_pipe_ahg((u_long)rc, *pretval, *(pretval + sizeof(int)));
    }

  }
  new_syscall_exit(22, pretval);

  return rc;
}

#ifndef LOG_COMPRESS_1
RET1_REPLAYG(pipe, 22, fildes, 2 * sizeof(int), int __user *fildes);
#else
static asmlinkage long replay_pipe(int __user *fildes)
{
  char *retparams = NULL;
  long rc = get_next_syscall(22, (char **) &retparams);
  int ret;
  int ret_fildes[2];
  ret = sys_pipe(fildes);
  if (copy_from_user(ret_fildes, fildes, 2 * sizeof(int)))
  {
    TPRINT("Pid %d cannot copy from user. \n", current->pid);
    return syscall_mismatch();
  }

  if (retparams)
  {
    if (copy_to_user(fildes, retparams, 2 * sizeof(int))) TPRINT("replay_pipe: pid %d cannot copy to user\n", current->pid);
    argsconsume(current->replay_thrd->rp_record_thread, 2 * sizeof(int));
  }
  DPRINT("replay_pipe, return:%d(actual:%d), %d(actual:%d)\n", fildes[0], ret_fildes[0], fildes[1], ret_fildes[1]);
  //current->replay_thrd->rp_record_thread->fd_map_table[fildes[0]] = ret_fildes[0];
  //current->replay_thrd->rp_record_thread->fd_map_table[fildes[1]] = ret_fildes[1];
  pipe_fds_insert(&current->replay_thrd->rp_record_thread->rp_clog.pfds, ret_fildes);

  return rc;
}
#endif

int theia_sys_pipe(int __user *fildes)
{
  long rc;

  rc = sys_pipe(fildes);

  if (rc == 0)
  {
    theia_pipe_ahg((u_long)rc, fildes[0], fildes[1]);
  }

  return rc;
}

asmlinkage long shim_pipe(int __user *fildes)
SHIM_CALL_MAIN(22, record_pipe(fildes), replay_pipe(fildes), theia_sys_pipe(fildes))

RET1_SHIM1(times, 100, struct tms, tbuf, struct tms __user *, tbuf);

static asmlinkage unsigned long
record_brk(unsigned long brk)
{
  unsigned long rc;

  rg_lock(current->record_thrd->rp_group);
  new_syscall_enter(12);
  rc = sys_brk(brk);
  new_syscall_done(12, rc);
  new_syscall_exit(12, NULL);

  if (current->record_thrd->rp_group->rg_save_mmap_flag)
  {
    struct record_thread *prt;
    prt = current->record_thrd;

    MPRINT("Pid %d prev_brk %lx brk to %lx\n", current->pid, prt->rp_group->rg_prev_brk, rc);
    if (!prt->rp_group->rg_prev_brk)
    {
      prt->rp_group->rg_prev_brk = rc;
    }
    else
    {
      if (rc > prt->rp_group->rg_prev_brk)
      {
        u_long size;
        size = rc - prt->rp_group->rg_prev_brk;
        if (size)
        {
          MPRINT("Pid %d brk increased size by %lu, reserve %lx to %lx\n", 
            current->pid, size, prt->rp_group->rg_prev_brk, rc);
          reserve_memory(prt->rp_group->rg_prev_brk, size);
          prt->rp_group->rg_prev_brk = rc;
        }
      }
      else
      {
        // else it was a deallocation do nothing
      }
    }
  }

  rg_unlock(current->record_thrd->rp_group);

  return rc;
}

static asmlinkage unsigned long
replay_brk(unsigned long brk)
{
  struct replay_thread *prt;
  u_long old_brk;
  u_long retval;
  u_long rc;

  prt = current->replay_thrd;
  if (is_pin_attached())
  {
    rc = prt->rp_saved_rc;
    (*(int *)(prt->app_syscall_addr)) = 999;
    TPRINT("[%s|%d] pid %d, prt->app_syscall_addr is set to 999\n", 
      __func__, __LINE__, current->pid);
  }
  else
  {
    rc = get_next_syscall(12, NULL);
  }

  if (is_pin_attached())
  {
    struct mm_struct *mm = current->mm;
    down_write(&mm->mmap_sem);
    // since we actually do the brk we can just grab the old one
    old_brk = PAGE_ALIGN(mm->brk);
    up_write(&mm->mmap_sem);
    MPRINT("Pid %d, old brk is %lx, will return brk %lx\n", current->pid, old_brk, rc);
    if (rc > old_brk)
    {
      MPRINT("unmap old preallocation %lx, len %lx\n", old_brk, rc - old_brk);
      MPRINT("  let do_brk do the munmap for us\n");
      // We need to unmap preallocations
      if (do_munmap(mm, old_brk, (rc - old_brk) + 4096))
      {
        TPRINT("Pid %d -- problem deallocating preallocation %lx-%lx before brk\n", current->pid, old_brk, rc);
        return syscall_mismatch();
      }
    }
    else if (rc < old_brk)
    {
      MPRINT("brk shrinks, map back preallocation at %lx, len %lx\n", rc, old_brk - rc);
      // we need to map back preallocations
      preallocate_after_munmap(rc, old_brk - rc);
    }
  }

  retval = sys_brk(brk);
  if (rc != retval)
  {
    TPRINT("Replay brk returns different value %lx than %lx\n", retval, rc);
    syscall_mismatch();
  }
  // Save the regions for preallocation for replay+pin
  if (prt->rp_record_thread->rp_group->rg_save_mmap_flag)
  {
    if (!prt->rp_record_thread->rp_group->rg_prev_brk)
    {
      prt->rp_record_thread->rp_group->rg_prev_brk = retval;
    }
    else
    {
      if (retval > prt->rp_record_thread->rp_group->rg_prev_brk)
      {
        u_long size;
        size = retval - prt->rp_record_thread->rp_group->rg_prev_brk;
        if (size)
        {
          MPRINT("Pid %d brk increased size by %lx, reserve %lx to %lx\n", 
      current->pid, size, prt->rp_record_thread->rp_group->rg_prev_brk, retval);
          reserve_memory(prt->rp_record_thread->rp_group->rg_prev_brk, size);
          prt->rp_record_thread->rp_group->rg_prev_brk = retval;
        }
        else
        {
          // else it was a deallocation, do nothing
        }
      }
    }
  }
  return rc;
}

asmlinkage unsigned long shim_brk(unsigned long abrk) SHIM_CALL(brk, 12, abrk);

inline void theia_signal_ahgx(int sig, __sighandler_t handler, long rc, int sysnum)
{
  theia_dump_dd(sig, (long)handler, rc, sysnum);
}

SIMPLE_SHIM1(acct, 163, char __user *, name)

inline void theia_umount_ahgx(const char __user *name, int flags, long rc, int sysnum)
{
  theia_dump_sd(name, flags, rc, sysnum);
}


SIMPLE_SHIM2(umount, 166, char __user *, name, int, flags);
// THEIA_SHIM2(umount, 166, char __user *, name, int, flags);

struct ioctl_ahgv
{
  int             pid;
  int             fd;
  unsigned int    cmd;
  unsigned long   arg;
  long            rc;
};

void packahgv_ioctl(struct ioctl_ahgv *sys_args)
{
  char uuid_str[THEIA_UUID_LEN + 1];
  int size = 0;
  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    get_curr_time(&sec, &nsec);
#ifdef THEIA_UUID
    if (fd2uuid(sys_args->fd, uuid_str) == false)
      goto err;

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, THEIA_KMEM_SIZE-1, 
                  "startahg|%d|%d|%ld|%s|%d|%ld|%ld|%d|%ld|%ld|%u|endahg\n",
                   16, sys_args->pid, current->start_time.tv_sec,
                   uuid_str, sys_args->cmd, sys_args->arg, sys_args->rc, current->tgid,
                   sec, nsec, current->no_syscalls++);
#else
    size = snprintf(buf, THEIA_KMEM_SIZE-1, 
                   "startahg|%d|%d|%ld|%d|%d|%ld|%ld|%d|%ld|%ld|endahg\n",
                   16, sys_args->pid, current->start_time.tv_sec,
                   sys_args->fd, sys_args->cmd, sys_args->arg, sys_args->rc, current->tgid,
                   sec, nsec);
#endif
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
err:
    kmem_cache_free(theia_buffers, buf);
  }
}

void theia_ioctl_ahg(unsigned int fd, unsigned int cmd, unsigned long arg, long rc)
{
  struct ioctl_ahgv *pahgv = NULL;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  //  TPRINT("theia_read_ahg clock", current->record_thrd->rp_precord_clock);
  // Yang: regardless of the return value, passes the failed syscall also
  //  if(rc >= 0)
  {
    pahgv = (struct ioctl_ahgv *)KMALLOC(sizeof(struct ioctl_ahgv), GFP_KERNEL);
    if (pahgv == NULL)
    {
      TPRINT("theia_ioctl_ahg: failed to KMALLOC.\n");
      return;
    }
    pahgv->pid = current->pid;
    pahgv->fd = (int)fd;
    pahgv->cmd = cmd;
    pahgv->arg = arg;
    pahgv->rc = rc;
    packahgv_ioctl(pahgv);
    KFREE(pahgv);
  }

}


static asmlinkage long
record_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
  char *recbuf = NULL;
  long rc = 0;
  int dir;
  int size;

  switch (cmd)
  {
    case TCSBRK:
    case TCSBRKP:
    case TIOCSBRK:
    case TIOCCBRK:
    case TCFLSH:
    case TIOCEXCL:
    case TIOCNXCL:
    case TIOCSCTTY:
    case FIOCLEX:
    case FIONCLEX:
    case TIOCCONS:
    case TIOCNOTTY:
    case TIOCVHANGUP:
    case TIOCSERCONFIG:
    case TIOCSERGWILD:
    case TIOCSERSWILD:
    case TIOCMIWAIT:
      dir = _IOC_NONE;
      size = 0;
      break;
    case TIOCSTI:
      dir = _IOC_READ;
      size = sizeof(char);
      break;
    case TIOCLINUX:
      dir = _IOC_READ | _IOC_WRITE;
      size = sizeof(char);
      break;
    case FIONBIO:
    case FIOASYNC:
    case FIBMAP:
    case TCXONC:
    case TIOCMBIS:
    case TIOCMBIC:
    case TIOCMSET:
    case TIOCSSOFTCAR:
    case TIOCPKT:
    case TIOCSETD:
      dir = _IOC_READ;
      size = sizeof(int);
      break;
    case TIOCOUTQ:
    case FIGETBSZ:
    case FIONREAD:
    case TIOCMGET:
    case TIOCGSOFTCAR:
    case TIOCGETD:
    case TIOCSERGETLSR:
      dir = _IOC_WRITE;
      size = sizeof(int);
      break;
    case FIOQSIZE:
      dir = _IOC_WRITE;
      size = sizeof(loff_t);
      break;
    case TCGETA:
    case TCGETS:
      dir = _IOC_WRITE;
      size = sizeof(struct termios);
      break;
    case TCSETA:
    case TCSETS:
    case TCSETAW:
    case TCSETAF:
    case TCSETSW:
    case TCSETSF:
      dir = _IOC_READ;
      size = sizeof(struct termios);
      break;
    case TIOCGSID:
      dir = _IOC_WRITE;
      size = sizeof(pid_t);
      break;
    case TIOCGPGRP:
      dir = _IOC_WRITE;
      size = sizeof(struct pid);
      break;
    case TIOCSPGRP:
      dir = _IOC_READ;
      size = sizeof(struct pid);
      break;
    case TIOCGWINSZ:
      dir = _IOC_WRITE;
      size = sizeof(struct winsize);
      break;
    case TIOCSWINSZ:
      dir = _IOC_READ;
      size = sizeof(struct winsize);
      break;
    case TIOCGSERIAL:
      dir = _IOC_WRITE;
      size = sizeof(struct serial_struct);
      break;
    case TIOCSSERIAL:
      dir = _IOC_READ;
      size = sizeof(struct serial_struct);
      break;
    case TIOCGRS485:
      dir = _IOC_WRITE;
      size = sizeof(struct serial_rs485);
      break;
    case TIOCSRS485:
      dir = _IOC_READ;
      size = sizeof(struct serial_rs485);
      break;
    case TCGETX:
      dir = _IOC_WRITE;
      size = sizeof(struct termiox);
      break;
    case TCSETX:
    case TCSETXW:
    case TCSETXF:
      dir = _IOC_READ;
      size = sizeof(struct termiox);
      break;
    case TIOCGLCKTRMIOS:
      dir = _IOC_WRITE;
      size = sizeof(struct termios);
      break;
    case TIOCSLCKTRMIOS:
      dir = _IOC_READ;
      size = sizeof(struct termios);
      break;
    case TIOCGICOUNT:
      dir = _IOC_WRITE;
      size = sizeof(struct serial_icounter_struct);
      break;
    default:
      /* Generic */
      MPRINT("Pid %d recording generic ioctl fd %d cmd %x arg %lx\n", current->pid, fd, cmd, arg);
      dir  = _IOC_DIR(cmd);
      size = _IOC_SIZE(cmd);
      if (dir == _IOC_NONE || size == 0)
      {
        TPRINT("*** Generic IOCTL cmd %x arg %lx has no data! This probably needs special handling!\n", cmd, arg);
        dir = _IOC_NONE;
        size = 0;
      }
      break;
  }

  new_syscall_enter(16);
  if (rc == 0) rc = sys_ioctl(fd, cmd, arg);
  theia_ioctl_ahg(fd, cmd, arg, rc);
  new_syscall_done(16, rc);

  DPRINT("Pid %d records ioctl fd %d cmd 0x%x arg 0x%lx returning %ld\n", current->pid, fd, cmd, arg, rc);

  if (rc >= 0 && (dir & _IOC_WRITE))
  {
    recbuf = ARGSKMALLOC(sizeof(u_long) + size, GFP_KERNEL);
    if (!recbuf)
    {
      TPRINT("record_ioctl: can't allocate return\n");
      rc = -ENOMEM;
    }
    else
    {
      if (copy_from_user(recbuf + sizeof(u_long), (void __user *)arg, size))
      {
        TPRINT("record_ioctl: faulted on readback\n");
        ARGSKFREE(recbuf, sizeof(u_long) + size);
        recbuf = NULL;
        rc = -EFAULT;
      }
      *((u_long *)recbuf) = size;
    }
  }

  new_syscall_exit(16, recbuf);

  return rc;
}

static asmlinkage long
replay_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
  char *retparams = NULL;
  u_long my_size;
  long rc = get_next_syscall(16, &retparams);
  if (retparams)
  {
    my_size = *((u_long *)retparams);
    if (copy_to_user((void __user *)arg, retparams + sizeof(u_long), my_size))
    {
      TPRINT("replay_ioctl: pid %d faulted\n", current->pid);
      return -EFAULT;
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + my_size);
  }
  return rc;
}

int theia_sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
  long rc;
  rc = sys_ioctl(fd, cmd, arg);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  {
    theia_ioctl_ahg(fd, cmd, arg, rc);
  }
  return rc;
}

asmlinkage long shim_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
SHIM_CALL_MAIN(16, record_ioctl(fd, cmd, arg), replay_ioctl(fd, cmd, arg), theia_sys_ioctl(fd, cmd, arg));

void theia_fcntl_ahg(unsigned int fd, unsigned int cmd, unsigned long arg, long rc)
{
  int size = 0;
  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  /* packahgv */
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    get_curr_time(&sec, &nsec);
    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%d|%d|%lu|%d|%ld|%ld|%u|endahg\n",
                   72, current->pid, current->start_time.tv_sec, fd, cmd, arg, current->tgid, sec, nsec, current->no_syscalls++);
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
    kmem_cache_free(theia_buffers, buf);
  }
}

static asmlinkage long
record_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
  char *recbuf = NULL;
  long rc;

  new_syscall_enter(72);
  rc = sys_fcntl(fd, cmd, arg);
  theia_fcntl_ahg(fd, cmd, arg, rc);
  new_syscall_done(72, rc);
  if (rc >= 0)
  {
    if (cmd == F_GETLK)
    {
      recbuf = ARGSKMALLOC(sizeof(u_long) + sizeof(struct flock), GFP_KERNEL);
      if (!recbuf)
      {
        TPRINT("record_fcntl: can't allocate return buffer\n");
        return -ENOMEM;
      }
      *(u_long *) recbuf = sizeof(struct flock);
      if (copy_from_user(recbuf + sizeof(u_long), (struct flock __user *)arg, sizeof(struct flock)))
      {
        TPRINT("record_fcntl: faulted on readback\n");
        KFREE(recbuf);
        return -EFAULT;
      }
    }
    else if (cmd == F_GETOWN_EX)
    {
      recbuf = ARGSKMALLOC(sizeof(u_long) + sizeof(struct f_owner_ex), GFP_KERNEL);
      if (!recbuf)
      {
        TPRINT("record_fcntl: can't allocate return buffer\n");
        return -ENOMEM;
      }
      *(u_long *) recbuf = sizeof(struct f_owner_ex);
      if (copy_from_user(recbuf + sizeof(u_long), (struct f_owner_ex __user *)arg, sizeof(struct f_owner_ex)))
      {
        TPRINT("record_fcntl: faulted on readback\n");
        KFREE(recbuf);
        return -EFAULT;
      }
    }
  }
  new_syscall_exit(72, recbuf);

  return rc;
}

static asmlinkage long
replay_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
  char *retparams = NULL;
  long rc = get_next_syscall(72, &retparams);
  if (retparams)
  {
    u_long bytes = *((u_long *) retparams);
    if (copy_to_user((void __user *)arg, retparams + sizeof(u_long), bytes)) return syscall_mismatch();
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + bytes);
  }
  return rc;
}

int theia_sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
  int rc;
  rc = sys_fcntl(fd, cmd, arg);

  theia_fcntl_ahg(fd, cmd, arg, rc);

  return rc;
}

asmlinkage long shim_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg)
SHIM_CALL_MAIN(72, record_fcntl(fd, cmd, arg), replay_fcntl(fd, cmd, arg), theia_sys_fcntl(fd, cmd, arg))

SIMPLE_SHIM1(umask, 95, int, mask);

inline void theia_chroot_ahgx(char __user *filename, long rc, int sysnum)
{
  theia_fullpath_ahgx(filename, rc, sysnum);
}

// THEIA_SHIM1(chroot, 161, const char __user *, filename);
SIMPLE_SHIM1(chroot, 161, const char __user *, filename);

RET1_SHIM2(ustat, 136, struct ustat, ubuf, unsigned, dev, struct ustat __user *, ubuf);

//asmlinkage int sys_sigaction(int sig, const struct old_sigaction __user *act, struct old_sigaction __user *oact); /* No prototype for sys_sigaction */
//64port
asmlinkage int sys_sigaction(int sig, const struct sigaction __user *act, struct sigaction __user *oact); /* No prototype for sys_sigaction */

//RET1_RECORD3(sigaction, 67, struct old_sigaction, oact, int, sig, const struct old_sigaction __user *, act, struct old_sigaction __user *, oact);
//64port
//RET1_RECORD3(sigaction, 67, struct sigaction, oact, int, sig, const struct sigaction __user *, act, struct sigaction __user *, oact);

//static asmlinkage long replay_sigaction (int sig, const struct old_sigaction __user *act, struct old_sigaction __user *oact)
//64port
//static asmlinkage long replay_sigaction (int sig, const struct sigaction __user *act, struct sigaction __user *oact)
//{
//  char *retparams = NULL;
//  long rc;
//
//  if (current->replay_thrd->app_syscall_addr) {
//    return sys_sigaction (sig, act, oact); // do actual syscall when PIN is attached
//  }
//
//  rc = get_next_syscall (67, (char **) &retparams);
//  if (retparams) {
//    //if (copy_to_user (oact, retparams, sizeof(struct old_sigaction))) TPRINT ("replay_sigaction: pid %d cannot copy to user\n", current->pid);
//    //argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct old_sigaction));
////64port
//    if (copy_to_user (oact, retparams, sizeof(struct sigaction))) TPRINT ("replay_sigaction: pid %d cannot copy to user\n", current->pid);
//    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct sigaction));
//  }
//  return rc;
//}

//asmlinkage int shim_sigaction (int sig, const struct old_sigaction __user *act, struct old_sigaction __user *oact) SHIM_CALL(sigaction, 67, sig, act, oact);
//64port
//asmlinkage int shim_sigaction (int sig, const struct sigaction __user *act, struct sigaction __user *oact) SHIM_CALL(sigaction, 67, sig, act, oact);

SIMPLE_SHIM0(sgetmask, 68);
SIMPLE_SHIM1(ssetmask, 69, int, newmask);
asmlinkage int sys_sigsuspend(int history0, int history1, old_sigset_t mask); /* No prototype for sys_sigsuspend */
RET1_SHIM1(sigpending, 73, old_sigset_t, set, old_sigset_t __user *, set);
SIMPLE_SHIM2(sethostname, 170, char __user *, name, int, len);
SIMPLE_RECORD2(setrlimit, 160, unsigned int, resource, struct rlimit __user *, rlim);

static asmlinkage long
replay_setrlimit(unsigned int resource, struct rlimit __user *rlim)
{
  long rc;
  long rc_orig = get_next_syscall(160, NULL);
  rc = sys_setrlimit(resource, rlim);
  if (rc != rc_orig) TPRINT("setrlim changed its return in replay\n");
  return rc_orig;
}

asmlinkage long shim_setrlimit(unsigned int resource, struct rlimit __user *rlim) SHIM_CALL(setrlimit, 160, resource, rlim);

RET1_SHIM2(old_getrlimit, 76, struct rlimit, rlim, unsigned int, resource, struct rlimit __user *, rlim);
RET1_SHIM2(getrusage, 98, struct rusage, ru, int, who, struct rusage __user *, ru);

static asmlinkage long
record_gettimeofday(struct timeval __user *tv, struct timezone __user *tz)
{
  long rc;
  struct gettimeofday_retvals *pretvals = NULL;
#ifdef LOG_COMPRESS_1
  struct clog_node *node;
  int diff;
#endif
#ifdef TIME_TRICK
  struct record_group *prg = current->record_thrd->rp_group;
  int fake_time = 0;
  long long time_diff;
  int is_shift = 0;
  long current_clock = new_syscall_enter(96);
#else
  new_syscall_enter(96);
#endif
  rc = sys_gettimeofday(tv, tz);
  //note: now we need to put TIME_TRICK here as we update the flag in new_syscall_done
  // note: this could be buggy, fix it later; about the retval of gettimeofday
#ifdef TIME_TRICK
  if (!tv) BUG();
  if (DET_TIME_DEBUG) TPRINT("Pid %d gettimeofday actual time %lu, %lu\n", current->pid, tv->tv_sec, tv->tv_usec);
  mutex_lock(&prg->rg_time_mutex);
  //get the clock count since last update
  if (atomic_read(&prg->rg_det_time.flag))
  {
    //return the actual time here
    update_fake_accum_gettimeofday(&prg->rg_det_time, tv, current_clock);
  }
  else
  {
    time_diff = get_diff_gettimeofday(&prg->rg_det_time, tv, current_clock);
    if ((is_shift = is_shift_time(&prg->rg_det_time, time_diff, current_clock)))
    {
      change_log_special_second();
      update_step_time(time_diff, &prg->rg_det_time, current_clock);
      update_fake_accum_gettimeofday(&prg->rg_det_time, tv, current_clock);
    }
    else
    {
      calc_det_gettimeofday(&prg->rg_det_time, tv, current_clock);
      if (DET_TIME_DEBUG) TPRINT("Pid %d gettimeofday returns det time\n", current->pid);
      fake_time = 1;
    }
  }
  if (DET_TIME_DEBUG) TPRINT("Pid %d gettimeofday finally returns %lu, %lu\n", current->pid, tv->tv_sec, tv->tv_usec);
  atomic_set(&prg->rg_det_time.flag, 0);  //all time queries don't need to update the det time
  cnew_syscall_done(96, rc, -1, 0);
  mutex_unlock(&prg->rg_time_mutex);
#else
  new_syscall_done(96, rc);
#endif

  if (rc == 0)
  {
#ifdef TIME_TRICK
    if (fake_time)
    {
      change_log_special();
      fake_time = 0;
    }
    else
    {
#endif
      pretvals = ARGSKMALLOC(sizeof(struct gettimeofday_retvals), GFP_KERNEL);
      if (pretvals == NULL)
      {
        TPRINT("record_gettimeofday: can't allocate buffer\n");
        return -ENOMEM;
      }
#ifdef LOG_COMPRESS_1
      node = clog_alloc(sizeof(struct gettimeofday_retvals));
#endif
      if (tv)
      {
        pretvals->has_tv = 1;
        if (copy_from_user(&pretvals->tv, tv, sizeof(struct timeval)))
        {
          TPRINT("Pid %d cannot copy tv from user\n", current->pid);
          ARGSKFREE(pretvals, sizeof(struct gettimeofday_retvals));
          return -EFAULT;
        }
#ifdef LOG_COMPRESS_1
        encodeValue(1, 1, 0, node);
        diff = pretvals->tv.tv_sec - SYSCALL_CACHE_REC.tv_sec;
        if (diff == 0)
        {
          encodeValue(0, 1, 0, node);
        }
        else
        {
          encodeValue(1, 1, 0, node);
          SYSCALL_CACHE_REC.tv_sec = pretvals->tv.tv_sec;
          encodeValue(diff, 32, 4, node);
        }
        diff = pretvals->tv.tv_usec - SYSCALL_CACHE_REC.tv_usec;
        SYSCALL_CACHE_REC.tv_usec = pretvals->tv.tv_usec;
        encodeValue(diff, 32, 10, node);
#endif
      }
      else
      {
        pretvals->has_tv = 0;
#ifdef LOG_COMPRESS_1
        encodeValue(0, 1, 0, node);
#endif
      }
      if (tz)
      {
        pretvals->has_tz = 1;
        if (copy_from_user(&pretvals->tz, tz, sizeof(struct timezone)))
        {
          TPRINT("Pid %d cannot copy tz from user\n", current->pid);
          ARGSKFREE(pretvals, sizeof(struct gettimeofday_retvals));
          return -EFAULT;
        }
#ifdef LOG_COMPRESS_1
        encodeValue(1, 1, 0, node);
        diff = pretvals->tz.tz_minuteswest - SYSCALL_CACHE_REC.tz_minuteswest;
        SYSCALL_CACHE_REC.tz_minuteswest = pretvals->tz.tz_minuteswest;
        encodeValue(diff, 32, 9, node);
        diff = pretvals->tz.tz_dsttime - SYSCALL_CACHE_REC.tz_dsttime;
        SYSCALL_CACHE_REC.tz_dsttime = pretvals->tz.tz_dsttime;
        encodeValue(diff, 32, 9, node);

#endif
      }
      else
      {
        pretvals->has_tz = 0;
#ifdef LOG_COMPRESS_1
        encodeValue(0, 1, 0, node);
#endif
      }
#ifdef LOG_COMPRESS_1
      status_add(&current->record_thrd->rp_clog.syscall_status, 78, sizeof(struct gettimeofday_retvals) << 3, getCumulativeBitsWritten(node));
#endif

#ifdef TIME_TRICK
    }
#endif


  }

  new_syscall_exit(96, pretvals);

  return rc;
}

static asmlinkage long
replay_gettimeofday(struct timeval __user *tv, struct timezone __user *tz)
{
  struct gettimeofday_retvals *retparams = NULL;
#ifdef TIME_TRICK
  int fake_time = 0;
  int is_shift = 0;
  u_long start_clock;
  long long time_diff;
  struct record_group *prg = current->replay_thrd->rp_group->rg_rec_group;
  u_char syscall_flag = 0;
  long rc = cget_next_syscall(96, (char **) &retparams, &syscall_flag, 0, &start_clock);
#else
  long rc = get_next_syscall(96, (char **) &retparams);
#endif

#ifdef LOG_COMPRESS_1
  struct clog_node *node;
  int diff;
  int value;
  struct gettimeofday_retvals c_retparams;
#endif

  DPRINT("Pid %d replays gettimeofday(tv=%p,tz=%p) returning %ld\n", current->pid, tv, tz, rc);
#ifdef TIME_TRICK
  if (syscall_flag & SR_HAS_SPECIAL_FIRST) fake_time = 1;
  if (syscall_flag & SR_HAS_SPECIAL_SECOND) is_shift = 1;
#endif
  if (retparams)
  {
    if (retparams->has_tv && tv)
    {
      if (copy_to_user(tv, &retparams->tv, sizeof(struct timeval)))
      {
        TPRINT("Pid %d cannot copy tv to user\n", current->pid);
        return syscall_mismatch();
      }
    }
    if (retparams->has_tz && tz)
    {
      if (copy_to_user(tz, &retparams->tz, sizeof(struct timezone)))
      {
        TPRINT("Pid %d cannot copy tz to user\n", current->pid);
        return syscall_mismatch();
      }
    }
#ifdef LOG_COMPRESS_1
    node = clog_mark_done_replay();
    decodeValue(&value, 1, 0, 0, node);
    if (tv && value)
    {
      decodeValue(&value, 1, 0, 0, node);
      if (value)
      {
        decodeValue(&diff, 32, 4, 0, node);
        c_retparams.tv.tv_sec = diff + SYSCALL_CACHE_REP.tv_sec;
        //put_user
        if (log_compress_debug) BUG_ON(retparams->tv.tv_sec != c_retparams.tv.tv_sec);
        SYSCALL_CACHE_REP.tv_sec = c_retparams.tv.tv_sec;
      }
      else
      {
        //put_user
        c_retparams.tv.tv_sec = SYSCALL_CACHE_REP.tv_sec;
        if (log_compress_debug) BUG_ON(retparams->tv.tv_sec != c_retparams.tv.tv_sec);
      }
      decodeValue(&diff, 32, 10, 0, node);
      //put_user
      c_retparams.tv.tv_usec = diff + SYSCALL_CACHE_REP.tv_usec;
      if (log_compress_debug) BUG_ON(retparams->tv.tv_usec != c_retparams.tv.tv_usec);
      SYSCALL_CACHE_REP.tv_usec = c_retparams.tv.tv_usec;
      if (copy_to_user(tv, &c_retparams.tv, sizeof(struct timeval)))
      {
        TPRINT("Pid %d cannot copy tv to user\n", current->pid);
        return syscall_mismatch();
      }
    }
    decodeValue(&value, 1, 0, 0, node);
    if (tz && value)
    {
      decodeValue(&diff, 32, 9, 0, node);
      //put_user
      c_retparams.tz.tz_minuteswest = diff + SYSCALL_CACHE_REP.tz_minuteswest;
      if (log_compress_debug) BUG_ON(retparams->tz.tz_minuteswest != c_retparams.tz.tz_minuteswest);
      SYSCALL_CACHE_REP.tz_minuteswest = c_retparams.tz.tz_minuteswest;
      decodeValue(&diff, 32, 9, 0, node);
      c_retparams.tz.tz_dsttime = diff + SYSCALL_CACHE_REP.tz_dsttime;
      //put_user
      if (log_compress_debug) BUG_ON(retparams->tz.tz_dsttime != c_retparams.tz.tz_dsttime);
      SYSCALL_CACHE_REP.tz_dsttime = c_retparams.tz.tz_dsttime;
      if (copy_to_user(tz, &c_retparams.tz, sizeof(struct timezone)))
      {
        TPRINT("Pid %d cannot copy tz to user\n", current->pid);
        return syscall_mismatch();
      }
    }

#endif
#ifdef TIME_TRICK
    if (DET_TIME_DEBUG) TPRINT("gettimeofday returns actual time. actual :%ld,%ld\n", tv->tv_sec, tv->tv_usec);
    if (is_shift)
    {
      time_diff = get_diff_gettimeofday(&prg->rg_det_time, &retparams->tv, start_clock);
      update_step_time(time_diff, &prg->rg_det_time, start_clock);
    }
    update_fake_accum_gettimeofday(&prg->rg_det_time, &retparams->tv, start_clock);
#endif
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct gettimeofday_retvals));
  }
#ifdef TIME_TRICK
  else
  {
    //return det_time
    calc_det_gettimeofday(&prg->rg_det_time, tv, start_clock);
    if (DET_TIME_DEBUG) TPRINT("gettimeofday returns deterministic time\n");
  }
  if (DET_TIME_DEBUG) TPRINT("Pid %d gettimeofday finally returns %lu, %lu\n", current->pid, tv->tv_sec, tv->tv_usec);
#endif
  return rc;
}

#ifdef TIME_TRICK
static asmlinkage long record_gettimeofday_ignored(struct timeval __user *tv, struct timezone __user *tz)
{
  long rc;
  rc = sys_gettimeofday(tv, tz);
  BUG(); //fix if needed
  return rc;
}

asmlinkage long shim_gettimeofday(struct timeval __user *tv, struct timezone __user *tz) SHIM_CALL_IGNORE(gettimeofday, 96, tv, tz);
#else
asmlinkage long shim_gettimeofday(struct timeval __user *tv, struct timezone __user *tz) SHIM_CALL(gettimeofday, 96, tv, tz);
#endif

SIMPLE_SHIM2(settimeofday, 164, struct timeval __user *, tv, struct timezone __user *, tz);

// THEIA_SHIM2(symlink, 88, const char __user *, oldname, const char __user *, newname);
SIMPLE_SHIM2(symlink, 88, const char __user *, oldname, const char __user *, newname);

//64port
RET1_COUNT_SHIM3(readlink, 89, buf, const char __user *, path, char __user *, buf, int, bufsiz);

static asmlinkage long
record_uselib(const char __user *library)
{
  long rc;
  struct mmap_pgoff_retvals *recbuf = NULL; // Shouldn't be called - new code uses mmap

  rg_lock(current->record_thrd->rp_group);
  new_syscall_enter(134);
  rc = sys_uselib(library);
  new_syscall_done(134, rc);
  if (rc == 0)
  {
    recbuf = ARGSKMALLOC(sizeof(struct mmap_pgoff_retvals), GFP_KERNEL);
    if (recbuf == NULL)
    {
      TPRINT("record_uselib: pid %d cannot allocate return buffer\n", current->pid);
      return -EINVAL;
    }
    if (add_file_to_cache_by_name(library, &recbuf->dev, &recbuf->ino, &recbuf->mtime) < 0) return -EINVAL;
  }
  new_syscall_exit(134, recbuf);
  rg_unlock(current->record_thrd->rp_group);

  return rc;
}

static asmlinkage long
replay_uselib(const char __user *library)
{
  u_long retval, rc;
  struct mmap_pgoff_retvals *recbuf = NULL;
  struct replay_thread *prt = current->replay_thrd;
  mm_segment_t old_fs;
  char name[CACHE_FILENAME_SIZE];

  rc = get_next_syscall(134, (char **) &recbuf);

  if (recbuf)
  {
    rg_lock(prt->rp_record_thread->rp_group);
    get_cache_file_name(name, recbuf->dev, recbuf->ino, recbuf->mtime, prt->rp_group->cache_dir);
    rg_unlock(prt->rp_record_thread->rp_group);
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    retval = sys_uselib(name);
    set_fs(old_fs);
    if (rc != retval)
    {
      TPRINT("Replay mmap_pgoff returns different value %lx than %lx\n", retval, rc);
      syscall_mismatch();
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct mmap_pgoff_retvals));
  }
  return rc;
}

asmlinkage long shim_uselib(const char __user *library) SHIM_CALL(uselib, 134, library);

SIMPLE_SHIM2(swapon, 167, const char __user *, specialfile, int, swap_flags);
SIMPLE_SHIM4(reboot, 169, int, magic1, int, magic2, unsigned int, cmd, void __user *, arg);

struct old_linux_dirent   // From readdir.c - define this for completeness but system call should never be called
{
  unsigned long d_ino;
  unsigned long d_offset;
  unsigned short  d_namlen;
  char    d_name[1];
};

RET1_SHIM3(old_readdir, 89, struct old_linux_dirent, dirent, unsigned int, fd, struct old_linux_dirent __user *, dirent, unsigned int, count)


struct munmap_ahgv
{
  int             pid;
  u_long          addr;
  size_t          len;
  long            rc;
};

void packahgv_munmap(struct munmap_ahgv *sys_args)
{
  int size = 0;

  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    get_curr_time(&sec, &nsec);

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, THEIA_KMEM_SIZE-1, 
                   "startahg|%d|%d|%ld|%ld|%lx|%ld|%d|%ld|%ld|%u|endahg\n",
                   11, sys_args->pid, current->start_time.tv_sec, sys_args->rc,
                   sys_args->addr, sys_args->len, current->tgid, sec, nsec, current->no_syscalls++);
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
    kmem_cache_free(theia_buffers, buf);
  }
}

void theia_munmap_ahg(unsigned long addr, size_t len, long rc)
{
  struct munmap_ahgv *pahgv = NULL;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv = (struct munmap_ahgv *)KMALLOC(sizeof(struct munmap_ahgv), GFP_KERNEL);
  if (pahgv == NULL)
  {
    TPRINT("theia_munmap_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv->pid = current->pid;
  pahgv->addr = addr;
  pahgv->len = len;
  pahgv->rc = rc;
  packahgv_munmap(pahgv);
  KFREE(pahgv);
}

// old_mmap is a shim that calls sys_mmap_pgoff - we handle record/replay there instead
static asmlinkage long
record_munmap(unsigned long addr, size_t len)
{
  long rc;

  rg_lock(current->record_thrd->rp_group);
  new_syscall_enter(11);
  rc = sys_munmap(addr, len);
  theia_munmap_ahg(addr, len, rc);
  new_syscall_done(11, rc);
  new_syscall_exit(11, NULL);
  DPRINT("Pid %d records munmap of addr %lx returning %ld\n", current->pid, addr, rc);
  rg_unlock(current->record_thrd->rp_group);

  return rc;
}

static asmlinkage long
replay_munmap(unsigned long addr, size_t len)
{
  u_long retval, rc;

  if (is_pin_attached())
  {
    rc = current->replay_thrd->rp_saved_rc;
    (*(int *)(current->replay_thrd->app_syscall_addr)) = 999;
    TPRINT("[%s|%d] pid %d, prt->app_syscall_addr is set to 999\n", __func__, __LINE__, current->pid);
  }
  else
  {
    rc = get_next_syscall(11, NULL);
  }

  retval = sys_munmap(addr, len);
  DPRINT("Pid %d replays munmap of addr %lx len %lu returning %ld\n", current->pid, addr, len, retval);
  if (rc != retval)
  {
    TPRINT("Replay munmap returns different value %lu than %lu\n", retval, rc);
    return syscall_mismatch();
  }
  if (retval == 0 && is_pin_attached()) preallocate_after_munmap(addr, len);

  return rc;
}

int theia_sys_munmap(unsigned long addr, size_t len)
{
  long rc;
  rc = sys_munmap(addr, len);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  {
    theia_munmap_ahg(addr, len, rc);
  }
  return rc;
}

asmlinkage long shim_munmap(unsigned long addr, size_t len)
//SHIM_CALL(munmap, 91, addr, len);
SHIM_CALL_MAIN(11, record_munmap(addr, len), replay_munmap(addr, len), theia_sys_munmap(addr, len))

inline void theia_truncate_ahgx(const char __user *path, unsigned long length, long rc, int sysnum)
{
  theia_dump_sd(path, length, rc, sysnum);
}

inline void theia_ftruncate_ahgx(unsigned int fd, unsigned long length, long rc, int sysnum)
{
  theia_dump_dd(fd, length, rc, sysnum);
}

/*
THEIA_SHIM2(truncate, 76, const char __user *, path, unsigned long, length);
THEIA_SHIM2(ftruncate, 77, unsigned int, fd, unsigned long, length);
*/
SIMPLE_SHIM2(truncate, 76, const char __user *, path, unsigned long, length);
SIMPLE_SHIM2(ftruncate, 77, unsigned int, fd, unsigned long, length);

RET1_SHIM2(statfs, 137, struct statfs, buf, const char __user *, path, struct statfs __user *, buf);
RET1_SHIM2(fstatfs, 138, struct statfs, buf, unsigned int, fd, struct statfs __user *, buf)
SIMPLE_SHIM2(getpriority, 140, int, which, int, who);
SIMPLE_SHIM3(setpriority, 141, int, which, int, who, int, niceval);
/* iopl 172 */
SIMPLE_SHIM3(ioperm, 173, unsigned long, from, unsigned long, num, int, turn_on);
/* create_module 174 */

/* Copied from net/socket.c */
/* Argument list sizes for sys_socketcall */
#define AL(x) ((x) * sizeof(unsigned long))
static const unsigned char nargs[21] =
{
  AL(0), AL(3), AL(3), AL(3), AL(2), AL(3),
  AL(3), AL(3), AL(4), AL(4), AL(4), AL(6),
  AL(6), AL(2), AL(5), AL(5), AL(3), AL(3),
  AL(4), AL(5), AL(4)
};

#undef AL

static char *
copy_iovec_to_args(long size, const struct iovec __user *vec, unsigned long vlen)
{
  char *recbuf = NULL, *copyp;
  struct iovec *kvec;
  long rem_size, to_copy;
  int i;

  if (size > 0)
  {
    recbuf = ARGSKMALLOC(size, GFP_KERNEL);
    if (recbuf == NULL)
    {
      TPRINT("Unable to allocate readv buffer\n");
      return NULL;
    }

    kvec = KMALLOC(vlen * sizeof(struct iovec), GFP_KERNEL);
    if (kvec == NULL)
    {
      TPRINT("Pid %d copy_iovec_to_args allocation of vector failed\n", current->pid);
      KFREE(kvec);
      ARGSKFREE(recbuf, size);
      return NULL;
    }

    if (copy_from_user(kvec, vec, vlen * sizeof(struct iovec)))
    {
      TPRINT("Pid %d copy_iovec_to_args copy_from_user of vector failed\n", current->pid);
      KFREE(kvec);
      ARGSKFREE(recbuf, size);
      return NULL;
    }
    rem_size = size;
    copyp = recbuf;
    for (i = 0; i < vlen; i++)
    {
      to_copy = kvec[i].iov_len;
      if (rem_size < to_copy) to_copy = rem_size;

      if (copy_from_user(copyp, kvec[i].iov_base, to_copy))
      {
        TPRINT("Pid %d copy_iovec_to_args copy_from_user of data failed\n", current->pid);
        KFREE(kvec);
        ARGSKFREE(recbuf, size);
        return NULL;
      }
      copyp += to_copy;
      rem_size -= to_copy;
      if (rem_size == 0) break;
    }
    KFREE(kvec);
  }

  return recbuf;
}

static long
log_mmsghdr(struct mmsghdr __user *msg, long rc, long *plogsize)
{
  long len, i;
  struct mmsghdr *phdr;
  char *pdata;

  plogsize = ARGSKMALLOC(sizeof(u_long), GFP_KERNEL);
  len = sizeof(u_long);
  if (plogsize == NULL)
  {
    TPRINT("record_recvmmsg: can't allocate msg size\n");
    return -ENOMEM;
  }
  for (i = 0; i < rc; i++)
  {
    phdr = ARGSKMALLOC(sizeof(struct mmsghdr), GFP_KERNEL);
    if (phdr == NULL)
    {
      TPRINT("record_recvmmsg: can't allocate msg hdr %ld\n", i);
      ARGSKFREE(plogsize, len);
      return -ENOMEM;
    }
    len += sizeof(struct mmsghdr);
    if (copy_from_user(phdr, msg + i, sizeof(struct mmsghdr)))
    {
      TPRINT("record_recvmmsg: can't allocate msg header %ld\n", i);
      ARGSKFREE(plogsize, len);
      return -EFAULT;
    }

    if (phdr->msg_hdr.msg_namelen)
    {
      pdata = ARGSKMALLOC(phdr->msg_hdr.msg_namelen, GFP_KERNEL);
      if (pdata == NULL)
      {
        TPRINT("record_recvmmsg: can't allocate msg name %ld\n", i);
        ARGSKFREE(plogsize, len);
        return -ENOMEM;
      }
      len += phdr->msg_hdr.msg_namelen;
      if (copy_from_user(pdata, phdr->msg_hdr.msg_name, phdr->msg_hdr.msg_namelen))
      {
        TPRINT("record_recvmmsg: can't copy msg_name %ld of size %d\n", i, phdr->msg_hdr.msg_namelen);
        ARGSKFREE(plogsize, len);
        return -EFAULT;
      }
    }
    if (phdr->msg_hdr.msg_controllen)
    {
      pdata = ARGSKMALLOC(phdr->msg_hdr.msg_controllen, GFP_KERNEL);
      if (pdata == NULL)
      {
        TPRINT("record_recvmmsg: can't allocate msg control %ld\n", i);
        ARGSKFREE(plogsize, len);
        return -ENOMEM;
      }
      len += phdr->msg_hdr.msg_controllen;
      if (copy_from_user(pdata, phdr->msg_hdr.msg_control, phdr->msg_hdr.msg_controllen))
      {
        TPRINT("record_recvmmsg: can't copy msg_control %ld of size %ld\n", i, phdr->msg_hdr.msg_controllen);
        ARGSKFREE(plogsize, len);
        return -EFAULT;
      }
    }
    if (copy_iovec_to_args(phdr->msg_len, phdr->msg_hdr.msg_iov, phdr->msg_hdr.msg_iovlen) == NULL)
    {
      TPRINT("record_recvmmsg: can't allocate or copy msg data %ld\n", i);
      ARGSKFREE(plogsize, len);
      return -ENOMEM;
    }
    len += phdr->msg_len;
  }
  *plogsize = len;
  return 0;
}

static int
copy_args_to_iovec(char *retparams, long size, const struct iovec __user *vec, unsigned long vlen)
{
  char *copyp;
  struct iovec *kvec;
  long rem_size, to_copy;
  int i;

  kvec = KMALLOC(vlen * sizeof(struct iovec), GFP_KERNEL);
  if (kvec == NULL)
  {
    TPRINT("Pid %d replay_readv allocation of vector failed\n", current->pid);
    return -ENOMEM;
  }

  if (copy_from_user(kvec, vec, vlen * sizeof(struct iovec)))
  {
    TPRINT("Pid %d replay_readv copy_from_user of vector failed\n", current->pid);
    KFREE(kvec);
    return -EFAULT;
  }
  rem_size = size;
  copyp = retparams;
  for (i = 0; i < vlen; i++)
  {
    to_copy = kvec[i].iov_len;
    if (rem_size < to_copy) to_copy = rem_size;

    if (copy_to_user(kvec[i].iov_base, copyp, to_copy))
    {
      TPRINT("Pid %d replay_readv copy_to_user of data failed\n", current->pid);
      KFREE(kvec);
      return -EFAULT;
    }
    copyp += to_copy;
    rem_size -= to_copy;
    if (rem_size == 0) break;
  }
  KFREE(kvec);
  return 0;
}

static asmlinkage long
extract_mmsghdr(char *retparams, struct mmsghdr __user *msg, long rc)
{
  struct mmsghdr *phdr;
  long retval, i;
  struct iovec __user *iovec;
  unsigned long iovlen;

  argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + * ((u_long *) retparams));
  retparams += sizeof(u_long);
  for (i = 0; i < rc; i++)
  {
    phdr = (struct mmsghdr *) retparams;
    retparams += sizeof(struct mmsghdr);
    put_user(phdr->msg_len, &msg[i].msg_len);
    put_user(phdr->msg_hdr.msg_controllen, &msg[i].msg_hdr.msg_controllen);  // This is a in-out parameter
    put_user(phdr->msg_hdr.msg_flags, &msg[i].msg_hdr.msg_flags);            // Out parameter

    if (phdr->msg_hdr.msg_namelen)
    {
      if (copy_to_user(&msg[i].msg_hdr.msg_name, retparams, phdr->msg_hdr.msg_namelen))
      {
        TPRINT("extract_mmsghdr: pid %d cannot copy msg_name to user\n", current->pid);
        syscall_mismatch();
      }
      retparams += phdr->msg_hdr.msg_namelen;
    }

    if (phdr->msg_hdr.msg_controllen)
    {
      if (copy_to_user(&msg[i].msg_hdr.msg_control, retparams, phdr->msg_hdr.msg_controllen))
      {
        TPRINT("extract_mmsghdr: pid %d cannot copy msg_control to user\n", current->pid);
        syscall_mismatch();
      }
      retparams += phdr->msg_hdr.msg_controllen;
    }
    get_user(iovec, &msg[i].msg_hdr.msg_iov);
    get_user(iovlen, &msg[i].msg_hdr.msg_iovlen);
    retval = copy_args_to_iovec(retparams, phdr->msg_len, iovec, iovlen);
    if (retval < 0) return retval;
    retparams += retval;
  }
  return 0;
}

void print_mem(void *addr, int length)
{
  unsigned char *cc = (unsigned char *)addr;
  int i;
  for (i = 0; i < length; i++)
  {
    TPRINT("%02x(%d),", cc[i], i);
  }
}

void get_ip_port_sockaddr(struct sockaddr __user *sockaddr, int addrlen, char *ip, u_long *port, char *sun_path, sa_family_t *sa_family)
{
  char address[MAX_SOCK_ADDR];
  struct sockaddr *basic_sockaddr;
  struct sockaddr_in *in_sockaddr;
  unsigned char *cc;
  struct sockaddr_un *un_sockaddr;
  struct sockaddr_nl *nl_sockaddr;

  if (copy_from_user(address, sockaddr, addrlen))
  {
    TPRINT("get_ip_port_sockaddr[%d]: fails to copy sockaddr from userspace\n", __LINE__);
    // TODO: what should we do?
    *port = THEIA_INVALID_PORT;
    strcpy(ip, "NA");
    strcpy(sun_path, "NA");
    return;
  }
  basic_sockaddr = (struct sockaddr *)address;

  *sa_family = basic_sockaddr->sa_family;

  switch (*sa_family)
  {
    case AF_INET:
    case AF_UNSPEC: ; /* likely */
      in_sockaddr = (struct sockaddr_in *)basic_sockaddr;

      *port = in_sockaddr->sin_port;
      cc = (unsigned char *)in_sockaddr;
      snprintf(ip, 15, "%u.%u.%u.%u", cc[4], cc[5], cc[6], cc[7]);

      //    TPRINT("get_ip_port_sockaddr: ip is %s, port: %lu\n", ip, *port);
      break;
    case AF_LOCAL: ;// AF_UNIX
      un_sockaddr = (struct sockaddr_un *)basic_sockaddr;

      *port = THEIA_INVALID_PORT;
      strcpy(ip, "LOCAL");
      if (un_sockaddr->sun_path[0] != '\0') {
        strncpy_safe(sun_path, un_sockaddr->sun_path, UNIX_PATH_MAX-1);
      }
      else { /* an abstract socket address */
        if (addrlen-sizeof(sa_family_t) > 0) {
          sun_path[0] = '@';
          strncpy(sun_path+1, un_sockaddr->sun_path + 1, addrlen-sizeof(sa_family_t));
          sun_path[addrlen-sizeof(sa_family_t)] = '\0';
        }
//        if (addrlen != sizeof(sa_family_t))
//            sun_path[addrlen-sizeof(sa_family_t)] = '\0';
      }
      if (strlen(sun_path) == 0) {
        pr_err("sun_path error: length is zero\n");
        return;
      }
      break;
    case AF_NETLINK: ;
      nl_sockaddr = (struct sockaddr_nl *)basic_sockaddr;

      *port = nl_sockaddr->nl_pid;
      /* Port ID: 0 if dst is kernel or pid of the process owning dst socket */
      strcpy(ip, "NETLINK");
      strcpy(sun_path, "NETLINK");
      break;
    case AF_INET6: /* TODO */
    default:
      TPRINT("get_ip_port_sockaddr: sa_family problem %d\n", basic_sockaddr->sa_family);
      *port = THEIA_INVALID_PORT;
      strcpy(ip, "NA");
      strcpy(sun_path, "NA");
  }
}

void get_ip_port_sockfd(int sockfd, char *ip, u_long *port, char *sun_path, sa_family_t *sa_family, bool is_peer)
{
  char address[MAX_SOCK_ADDR];
  struct sockaddr *sockaddr;
  int len = 0;
  int err = 1;
  unsigned char *cc;
  struct sockaddr_in *in_sockaddr;
  struct sockaddr_un *un_sockaddr;
  struct sockaddr_nl *nl_sockaddr;
  struct socket *sock = sockfd_lookup(sockfd, &err);

  if (sock != NULL)
  {
    if (is_peer)
      err = sock->ops->getname(sock, (struct sockaddr *)address, &len, 1);
    else
      err = sock->ops->getname(sock, (struct sockaddr *)address, &len, 0);
    sockfd_put(sock);
  }
  else {
    pr_err("sockfd_lookup error: %d\n", err);
  }

  *port = THEIA_INVALID_PORT;
  if(is_peer == false) {//local ip
    strcpy(ip, "127.0.0.1");
    strcpy(sun_path, "127.0.0.1");
  }
  else {
    strcpy(ip, "NA");
    strcpy(sun_path, "NA");
  }

  if (err && err != -ENOTCONN)
  {
    pr_debug("getname error: err %d, sock is null? %d\n", err, sock == NULL);
    return;
  }

  sockaddr = (struct sockaddr *)address;

  if (IS_ERR_OR_NULL(sockaddr))
  {
    pr_err("get_ip_port_sockfd: sockaddr is NULL\n");
    return;
  }
  else
  {
    *sa_family = sockaddr->sa_family;
  }

  switch (*sa_family)
  {
    case AF_INET:
    case AF_UNSPEC: ; /* likely */
      in_sockaddr = (struct sockaddr_in *)sockaddr;

      *port = ntohs(in_sockaddr->sin_port);
      cc = (unsigned char *)in_sockaddr;
      snprintf(ip, 15, "%u.%u.%u.%u", cc[4], cc[5], cc[6], cc[7]);

      //    TPRINT("get_ip_port_sockfd: ip is %s, port: %lu\n", ip, *port);
      break;
    case AF_LOCAL: ;// AF_UNIX
      un_sockaddr = (struct sockaddr_un *)sockaddr;

      *port = THEIA_INVALID_PORT;
      strcpy(ip, "LOCAL");
      if (un_sockaddr->sun_path[0] != '\0') {
        strncpy_safe(sun_path, un_sockaddr->sun_path, UNIX_PATH_MAX-1);
      }
      else { /* an abstract socket address */
        if (!len) {
          pr_debug("getname error: len = %i\n", len);
          return;
        }
        if (len-sizeof(sa_family_t) > 0) {
          sun_path[0] = '@';
          strncpy(sun_path+1, un_sockaddr->sun_path + 1, len-sizeof(sa_family_t));
          sun_path[len-sizeof(sa_family_t)] = '\0';
        }
      }
      if (strlen(sun_path) == 0) {
        pr_err("sun_path error: length is zero\n");
        return;
      }
      break;
    case AF_NETLINK: ;
      nl_sockaddr = (struct sockaddr_nl *)sockaddr;

      *port = nl_sockaddr->nl_pid;
      /* Port ID: 0 if dst is kernel or pid of the process owning dst socket */
      strcpy(ip, "NETLINK");
      strcpy(sun_path, "NETLINK");
      break;
    case AF_INET6: /* TODO */
      break;
    default:
      pr_debug("get_ip_port_sockfd: sa_family problem %d\n", sockaddr->sa_family);
      *port = THEIA_INVALID_PORT;
      break;
  }
}

//Yang
struct connect_ahgv
{
  int             pid;
  int             sock_fd;
  char            ip[16];
  u_long          port;
  long              rc;
  sa_family_t     sa_family;
  char            sun_path[UNIX_PATH_MAX];
};

void packahgv_connect(struct connect_ahgv *sys_args)
{
  int size = 0;
  char uuid_str[THEIA_UUID_LEN + 1];

  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    buf[0] = 0x0;
    get_curr_time(&sec, &nsec);
#ifdef THEIA_UUID
    if (fd2uuid(sys_args->sock_fd, uuid_str) == false)
      goto err; /* no file, socket, ...? */
    uuid_str[THEIA_UUID_LEN] = '\0';

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%s|%ld|%d|%ld|%ld|%u|endahg\n",
                    42, sys_args->pid, current->start_time.tv_sec,
                    uuid_str, sys_args->rc, current->tgid, sec, nsec, current->no_syscalls++);
#else
    if (sys_args->sa_family == AF_LOCAL)
    {
      size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%ld|%d|%s|%lu|%d|%ld|%ld|endahg\n",
                      42, sys_args->pid, current->start_time.tv_sec,
                      sys_args->rc, sys_args->sock_fd, sys_args->sun_path, sys_args->port, current->tgid, sec, nsec);
    }
    else
    {
      size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%d|%d|%s|%lu|%d|%ld|%ld|endahg\n",
                      42, sys_args->pid, current->start_time.tv_sec,
                      sys_args->rc, sys_args->sock_fd, sys_args->ip, sys_args->port, current->tgid, sec, nsec);
    }
    //    TPRINT("[socketcall connect]: %s", buf);
#endif
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
err:
    kmem_cache_free(theia_buffers, buf);
  }
}

struct accept_ahgv
{
  int             pid;
  int             sock_fd;
  char            ip[16];
  u_long          port;
  long             rc;
  sa_family_t     sa_family;
  char            sun_path[UNIX_PATH_MAX];
};

void packahgv_accept(struct accept_ahgv *sys_args)
{
  int size = 0;
  char uuid_str[THEIA_UUID_LEN + 1];
  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    get_curr_time(&sec, &nsec);
#ifdef THEIA_UUID
//    if (fd2uuid(sys_args->sock_fd, uuid_str) == false)
//      goto err; /* no file, socket, ...? */

    if (sys_args->sa_family == AF_LOCAL)
      snprintf(uuid_str, THEIA_UUID_LEN, "S|NA|%lu|LOCAL|0", sys_args->port);
    else
      snprintf(uuid_str, THEIA_UUID_LEN, "S|%s|%lu|NA|0", sys_args->ip, sys_args->port);

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%s|%ld|%d|%ld|%ld|%u|endahg\n",
                   43, sys_args->pid, current->start_time.tv_sec,
                   uuid_str, sys_args->rc, current->tgid, sec, nsec, current->no_syscalls++);
#else
    char ip[50] = "";
    if (strlen(sys_args->ip) == 0)
      strcpy(ip, "NA");
    else
      strncpy_safe(ip, sys_args->ip, 49);
    if (sys_args->sa_family == AF_LOCAL)
    {
      size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%ld|%d|L%s|%lu|%d|%ld|%ld|endahg\n",
                     43, sys_args->pid, current->start_time.tv_sec,
                     sys_args->rc, sys_args->sock_fd, sys_args->sun_path, sys_args->port, current->tgid, sec, nsec);
    }
    else
    {
      size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%ld|%d|R%s|%lu|%d|%ld|%ld|endahg\n",
                     43, sys_args->pid, current->start_time.tv_sec,
                     sys_args->rc, sys_args->sock_fd, ip, sys_args->port, current->tgid, sec, nsec);
    }
#endif
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
/* err: */
    kmem_cache_free(theia_buffers, buf);
  }
}

bool addr2uuid(struct socket *sock, struct sockaddr *dest_addr, char *uuid_str) {
  struct sockaddr_in* in_sockaddr;
  unsigned char* cc;
  u_long port, local_port;
	char ip[16] = {'\0'};
	char local_ip[16] = {'\0'};
  
  in_sockaddr = (struct sockaddr_in*)dest_addr;
  port = ntohs(in_sockaddr->sin_port);
  cc = (unsigned char *)in_sockaddr;
  snprintf(ip, 16, "%u.%u.%u.%u", cc[4],cc[5],cc[6],cc[7]);

//get src addr
  if(sock!=NULL) {
  //  sk_buff * skb = sock->sk->sk_send_head;
  //  struct flowi4 fl4 = {
  //    .flowi4_oif = 0,
  //    .flowi4_tos = 0,
  //    .daddr = daddr->sin_addr.s_addr,
  //    .saddr = 0,
  //  };
  //  rt = ip_route_output_key(&init_net, &fl4);
  //  __be32 s_addr = rt->rt_src;
  //  str = inet_ntop4((u_char*)s_addr, tmp4, IN4_STR_LEN);
  }
  else {
    local_port = 0;
    strcpy(local_ip, "127.0.0.1");
  }

//  snprintf(uuid_str, THEIA_UUID_LEN, "S|%s|%lu|%s|%lu", ip, port, local_ip, local_port);
  snprintf(uuid_str, THEIA_UUID_LEN, "S|%s|%lu|%s|%lu|-1/-1", ip, port, local_ip, local_port);
  
  return true;

}

struct sendto_ahgv
{
  int             pid;
  int             sock_fd;
  struct sockaddr dest_addr;
  long            rc;
  sa_family_t     sa_family;
  char            sun_path[UNIX_PATH_MAX];
  theia_udp_tag   send_tag;
};

void packahgv_sendto(struct sendto_ahgv *sys_args)
{
  int size = 0;
  char uuid_str[THEIA_UUID_LEN + 1];

  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    get_curr_time(&sec, &nsec);
#ifdef THEIA_UUID
    if (sys_args->sock_fd != -1) {
      if (fd2uuid(sys_args->sock_fd, uuid_str) == false)
        goto err; 
    }
    else {
      if (addr2uuid(NULL, &sys_args->dest_addr, uuid_str) == false)
        goto err;
    }

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%s|%u|%ld|%d|%ld|%ld|%u|endahg\n",
        44, sys_args->pid, current->start_time.tv_sec, 
        uuid_str, sys_args->send_tag, sys_args->rc, current->tgid, sec, nsec, current->no_syscalls++);
#else
    if (sys_args->sa_family == AF_LOCAL)
    {
      if (strcmp(sys_args->sun_path, "LOCAL") == 0)
        goto err;
      size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%d|%ld|%s|%lu|%d|%ld|%ld|endahg\n",
                     44, sys_args->pid, current->start_time.tv_sec,
                     sys_args->sock_fd, sys_args->rc, sys_args->sun_path,
                     sys_args->port, current->tgid, sec, nsec);
    }
    else
    {
      if (strcmp(sys_args->ip, "LOCAL") == 0 || strcmp(sys_args->ip, "NA") == 0)
        goto err;
      size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%d|%ld|%s|%lu|%d|%ld|%ld|endahg\n",
                     44, sys_args->pid, current->start_time.tv_sec,
                     sys_args->sock_fd, sys_args->rc, sys_args->ip,
                     sys_args->port, current->tgid, sec, nsec);

    }
#endif
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
err:
    kmem_cache_free(theia_buffers, buf);
  }
}

struct recvfrom_ahgv
{
  int             pid;
  int             sock_fd;
  struct sockaddr src_addr;
  long            rc;
  sa_family_t     sa_family;
  char            sun_path[UNIX_PATH_MAX];
  theia_udp_tag   recv_tag;
  char *          ubuf;
};

void packahgv_recvfrom(struct recvfrom_ahgv *sys_args)
{
  int size = 0;
  char uuid_str[THEIA_UUID_LEN + 1];

  //ui stuffs
  char *msg;
  int len=200;
  int temp;
  int type=0;

  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    get_curr_time(&sec, &nsec);
#ifdef THEIA_UUID
    if (sys_args->sock_fd != -1) {
      if (fd2uuid(sys_args->sock_fd, uuid_str) == false)
        goto err; 
    }
    else {
      if (addr2uuid(NULL, &sys_args->src_addr, uuid_str) == false)
        goto err;
    }

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    //if(strncmp(uuid_str, "S|/tmp/.X11-unix/",15)==0)
    if(sys_args->rc > 0 && strncmp(uuid_str, "S|QC90bXAvLlgxMS11bml4", 22)==0 && theia_ui_toggle)
    {
      //if(uiDebug==1)
        //TPRINT("x11:found\n");
      msg=kmem_cache_alloc(theia_buffers, GFP_KERNEL);
      if(sys_args->rc<200)  //arbitrarily chosen max len we need
        len=sys_args->rc;
      else
        len=200;
      if(!copy_from_user(msg, sys_args->ubuf, len))
      {
        temp=msg[0]&0xff;
        if(temp==5 || (temp==35 && len>8 && (msg[8]&0xff)==5))
        { 
          //button release
          type=buttonRelease;
          if(uiDebug==1)
            TPRINT("x11:buttonRelease\n");
        }  
        if(temp==4 || (temp==35 && len>8 && (msg[8]&0xff)==4))
        {
          //button press
          type=buttonPress;
          lastPress=sec;
          if(uiDebug==1)
            TPRINT("x11:buttonPress %ld\n", sec); 
          if(orca_log)
            strcpy(orca_log, "no info");
        }
      }
      
      kmem_cache_free(theia_buffers, msg);

    }

    if(type==buttonRelease && orca_log && theia_ui_toggle)
    {
      if(uiDebug==1 && strncmp(orca_log, "no info", 7)!=0)
        TPRINT("x11:printing release %s\n", orca_log);
      if(strncmp(orca_log, "no info", 7)!=0)
      {
        danglingX11[0]='\0';
        size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%s|%ld|%d|%ld|%ld|%u|%s|endahg\n",
                   buttonRelease, sys_args->pid, current->start_time.tv_sec,
                   uuid_str, sys_args->rc, current->tgid, sec, nsec, current->no_syscalls++, orca_log);
      }
      else
      {
        size = snprintf(danglingX11, 1024, "startahg|%d|%d|%ld|%s|%ld|%d|%ld|%ld|",
                   buttonRelease, sys_args->pid, current->start_time.tv_sec,
                   uuid_str, sys_args->rc, current->tgid, sec, nsec);
        goto err;
      }
    }
    else
    {
      size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%s|%u|%ld|%d|%ld|%ld|%u|endahg\n",
        45, sys_args->pid, current->start_time.tv_sec, 
        uuid_str, sys_args->recv_tag, sys_args->rc, current->tgid, sec, nsec, current->no_syscalls++);
    }
#else
    if (sys_args->sa_family == AF_LOCAL)
    {
      if (strcmp(sys_args->sun_path, "LOCAL") == 0)
        goto err;
      size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%d|%ld|%s|%lu|%d|%ld|%ld|endahg\n",
                     45, sys_args->pid, current->start_time.tv_sec,
                     sys_args->sock_fd, sys_args->rc, sys_args->sun_path,
                     sys_args->port, current->tgid, sec, nsec);
    }
    else
    {
      if (strcmp(sys_args->ip, "LOCAL") == 0 || strcmp(sys_args->ip, "NA") == 0)
        goto err;
      size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%d|%ld|%s|%lu|%d|%ld|%ld|endahg\n",
                     45, sys_args->pid, current->start_time.tv_sec,
                     sys_args->sock_fd, sys_args->rc, sys_args->ip,
                     sys_args->port, current->tgid, sec, nsec);
    }
#endif
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
err:
    kmem_cache_free(theia_buffers, buf);
  }
}

struct sendmsg_ahgv
{
  int         pid;
  int         sock_fd;
  struct sockaddr dest_addr;
  long        rc;
  sa_family_t sa_family;
  char        sun_path[UNIX_PATH_MAX];
  theia_udp_tag send_tag;
};

void packahgv_sendmsg(struct sendmsg_ahgv *sys_args)
{
  int size = 0;
  char uuid_str[THEIA_UUID_LEN + 1];

  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    get_curr_time(&sec, &nsec);
#ifdef THEIA_UUID
    if (sys_args->sock_fd != -1) {
      if (fd2uuid(sys_args->sock_fd, uuid_str) == false)
        goto err; 
    }
    else {
      if (addr2uuid(NULL, &sys_args->dest_addr, uuid_str) == false)
        goto err;
    }
#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%s|%u|%ld|%d|%ld|%ld|%u|endahg\n", 
        46, sys_args->pid, current->start_time.tv_sec, 
        uuid_str, sys_args->send_tag, sys_args->rc, current->tgid, sec, nsec, current->no_syscalls++);
#else
    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%d|%ld|%d|%ld|%ld|endahg\n",
                   46, sys_args->pid, current->start_time.tv_sec,
                   sys_args->sock_fd, sys_args->rc, current->tgid,
                   sec, nsec);
#endif
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
err:
    kmem_cache_free(theia_buffers, buf);
  }
}

struct recvmsg_ahgv
{
  int         pid;
  int         sock_fd;
  struct sockaddr src_addr;
  long        rc;
  sa_family_t sa_family;
  char        sun_path[UNIX_PATH_MAX];
  theia_udp_tag recv_tag;
};

void packahgv_recvmsg(struct recvmsg_ahgv *sys_args)
{
  int size = 0;
  char uuid_str[THEIA_UUID_LEN + 1];

  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    get_curr_time(&sec, &nsec);
#ifdef THEIA_UUID
    if (sys_args->sock_fd != -1) {
      if (fd2uuid(sys_args->sock_fd, uuid_str) == false)
        goto err; 
    }
    else {
      if (addr2uuid(NULL, &sys_args->src_addr, uuid_str) == false)
        goto err;
    }

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%s|%u|%ld|%d|%ld|%ld|%u|endahg\n",
        47, sys_args->pid, current->start_time.tv_sec, 
        uuid_str, sys_args->recv_tag, sys_args->rc, current->tgid, sec, nsec, current->no_syscalls++);
#else
    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%d|%ld|%d|%ld|%ld|endahg\n",
                   47, sys_args->pid, current->start_time.tv_sec,
                   sys_args->sock_fd, sys_args->rc, current->tgid,
                   sec, nsec);
#endif
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
err:
    kmem_cache_free(theia_buffers, buf);
  }
}

/*
 * helper functions inet_ntop4() and inet_ntop6() convert ipv4 and ipv6 addresses
 * into presentation (human readable) strings.
 *
 * original source is from:
 *  eglibc-2.15/resolv/inet_ntop.c
 *
 * they are used by packahgv_echo4() and packahgv_echo6() to log ping replies
 * which are handled by the kernel, not user syscalls.
 *
 * see:
 *  net/ipv4/icmp.c:icmp_echo()
 *  net/ipv6/icmp.c:icmpv6_echo_reply()
 *
 */

/* const char *
 * inet_ntop4(src, dst, size)
 *  format an IPv4 address
 * return:
 *  `dst' (as a const)
 * notes:
 *  (1) uses no statics
 *  (2) takes a u_char* not an in_addr as input
 * author:
 *  Paul Vixie, 1996.
 */
static const char* inet_ntop4(const u_char *src, char *dst, size_t size)
{
  static const char fmt[] = "%u.%u.%u.%u";
  char tmp[sizeof("255.255.255.255")];
  int ret;
  ret = snprintf(tmp, size, fmt, src[0], src[1], src[2], src[3]);
  if (ret < 0)
    return NULL;
  return strcpy(dst, tmp);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *  convert IPv6 binary address into presentation (printable) format
 * author:
 *  Paul Vixie, 1996.
 */
static const char* inet_ntop6(const u_char *src, char *dst, size_t size)
{
#define NS_IN6ADDRSZ sizeof(struct in6_addr)
#define NS_INT16SZ sizeof(__be16)

  /*
   * Note that int32_t and int16_t need only be "at least" large enough
   * to contain a value of the specified size.  On some systems, like
   * Crays, there is no such thing as an integer variable with 16 bits.
   * Keep this in mind if you think this function should have been coded
   * to use pointer overlays.  All the world's not a VAX.
   */
#define size_ipv6_tplt 46
  char tmp[size_ipv6_tplt], *tp;
  struct { int base, len; } best, cur;
  u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
  int i;

  /*
   * Preprocess:
   *  Copy the input (bytewise) array into a wordwise array.
   *  Find the longest run of 0x00's in src[] for :: shorthanding.
   */
  memset(words, '\0', sizeof words);
  for (i = 0; i < NS_IN6ADDRSZ; i += 2)
    words[i / 2] = (src[i] << 8) | src[i + 1];
  best.base = -1;
  cur.base = -1;
  best.len = 0;
  cur.len = 0;
  for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
    if (words[i] == 0) {
      if (cur.base == -1)
        cur.base = i, cur.len = 1;
      else
        cur.len++;
    } else {
      if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len)
          best = cur;
        cur.base = -1;
      }
    }
  }
  if (cur.base != -1) {
    if (best.base == -1 || cur.len > best.len)
      best = cur;
  }
  if (best.base != -1 && best.len < 2)
    best.base = -1;

  /*
   * Format the result.
   */
  tp = tmp;
  for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
    /* Are we inside the best run of 0x00's? */
    if (best.base != -1 && i >= best.base &&
        i < (best.base + best.len)) {
      if (i == best.base)
        *tp++ = ':';
      continue;
    }
    /* Are we following an initial run of 0x00s or any real hex? */
    if (i != 0)
      *tp++ = ':';
    /* Is this address an encapsulated IPv4? */
    if (i == 6 && best.base == 0 &&
        (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
      if (!inet_ntop4(src+12, tp, size_ipv6_tplt - (tp - tmp)))
        return (NULL);
      tp += strlen(tp);
      break;
    }
    tp += snprintf(tp, size_ipv6_tplt-1, "%x", words[i]);
  }
  /* Was it a trailing run of 0x00's? */
  if (best.base != -1 && (best.base + best.len) ==
      (NS_IN6ADDRSZ / NS_INT16SZ))
    *tp++ = ':';
  *tp++ = '\0';

  /*
   * Check for overflow, copy, and we're done.
   */
  if ((size_t)(tp - tmp) > size) {
    return (NULL);
  }
  return strcpy(dst, tmp);
}

void packahgv_echo(const char* ping_str) {
  char ahg_fmt[] = "startahg|47|0|%s|%ld|%ld|%ld|endahg\n";
  int size = 0;
  struct timespec tp;
  struct timespec ts;
  __kernel_long_t uptime;
  // called from interrupt context. GFP_ATOMIC must be used.
  char *buf = kmem_cache_alloc(theia_buffers, GFP_ATOMIC);

  getnstimeofday(&ts);
  ktime_get_ts(&tp);
  monotonic_to_bootbased(&tp);
  uptime = tp.tv_sec + (tp.tv_nsec ? 1 : 0);

  size = snprintf(buf, THEIA_KMEM_SIZE-1, ahg_fmt, ping_str, uptime, ts.tv_sec, ts.tv_nsec);
  if (size > 0) {
    buf[size] = 0x0;
    if(theia_chan)
      // called from interrupt context. theia_file_write() cannot be used.
      relay_write(theia_chan, buf, size);
  }
  kmem_cache_free(theia_buffers, buf);
}

/*
 * packahgv_echo4() is used to log ping replies
 * which are handled by the kernel, not user syscalls.
 *
 * see:
 *  net/ipv4/icmp.c:icmp_echo()
 *
 * NOTE: this is called from interrupt context!!
 *
 */
void packahgv_echo4(const struct sk_buff *skb) {
#define IN4_STR_LEN sizeof("255.255.255.255")
#define PING4_STR_LEN (sizeof("P4|255.255.255.255|255.255.255.255")+1)
  const char *src_str;
  char stmp[IN4_STR_LEN+1];
  const char *dst_str;
  char dtmp[IN4_STR_LEN+1];
  __be32 saddr;
  __be32 daddr;
  char ping4_str[PING4_STR_LEN];
  int size = 0;
  struct rtable *rt;

  rt = skb_rtable(skb);
  saddr = rt->rt_spec_dst;
  src_str = inet_ntop4((u_char*)&saddr, stmp, IN4_STR_LEN);
  daddr = ip_hdr(skb)->saddr;
  dst_str = inet_ntop4((u_char*)&daddr, dtmp, IN4_STR_LEN);

  if (src_str && dst_str) {
    size = snprintf(ping4_str, PING4_STR_LEN, "P4|%s|%s", src_str, dst_str);
  }
  if (size > 0) {
    packahgv_echo(ping4_str);
  }
}
EXPORT_SYMBOL(packahgv_echo4);

/*
 * packahgv_echo6() is used to log ping replies
 * which are handled by the kernel, not user syscalls.
 *
 * see:
 *  net/ipv6/icmp.c:icmpv6_echo_reply()
 *
 * NOTE: this is called from interrupt context!!
 *
 */
void packahgv_echo6(const struct sk_buff *skb) {
  struct in6_addr saddr;
  struct in6_addr daddr;
#define IN6_STR "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"
#define IN6_STR_LEN sizeof(IN6_STR)
  const char *src_str;
  char stmp[IN6_STR_LEN+1];
  const char *dst_str;
  char dtmp[IN6_STR_LEN+1];
#define PING6_STR_LEN (sizeof("P6|" IN6_STR "|" IN6_STR)+1)
  char ping6_str[PING6_STR_LEN];
  int size = 0;

  saddr = ipv6_hdr(skb)->daddr;
  src_str = inet_ntop6((u_char*)&saddr, stmp, IN6_STR_LEN);
  daddr = ipv6_hdr(skb)->saddr;
  dst_str = inet_ntop6((u_char*)&daddr, dtmp, IN6_STR_LEN);

  if (src_str && dst_str) 
    size = snprintf(ping6_str, PING6_STR_LEN, "P6|%s|%s", src_str, dst_str);
  if (size > 0)
    packahgv_echo(ping6_str);
}
EXPORT_SYMBOL(packahgv_echo6);

void theia_connect_ahg(long rc, int fd, struct sockaddr __user *uservaddr, int addrlen)
{
  struct connect_ahgv *pahgv_connect = NULL;
  struct socket *sock;
  int err;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv_connect = (struct connect_ahgv *)KMALLOC(sizeof(struct connect_ahgv), GFP_KERNEL);
  if (pahgv_connect == NULL)
  {
    TPRINT("theia_connect_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv_connect->pid = current->pid;
  pahgv_connect->rc = rc;
  pahgv_connect->sock_fd = fd;

  sock = sockfd_lookup(fd, &err);
  if (sock) {
    sockfd_put(sock);
    get_peer_ip_port_sockfd(fd, pahgv_connect->ip, &(pahgv_connect->port), pahgv_connect->sun_path, &(pahgv_connect->sa_family));
  }
  else {
    pr_err("sockfd_lookup error: %d\n", err);
    pahgv_connect->sock_fd = -1;
    get_ip_port_sockaddr(uservaddr, addrlen, pahgv_connect->ip, &(pahgv_connect->port), pahgv_connect->sun_path, &(pahgv_connect->sa_family));
  }

  packahgv_connect(pahgv_connect);
  KFREE(pahgv_connect);

  return;
}

void theia_accept_ahg(long rc, int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen)
{
  struct accept_ahgv *pahgv_accept = NULL;
  struct socket *sock;
  int err;

  if (upeer_sockaddr == NULL || upeer_addrlen == NULL)
    return;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv_accept = (struct accept_ahgv *)KMALLOC(sizeof(struct accept_ahgv), GFP_KERNEL);
  if (pahgv_accept == NULL)
  {
    TPRINT("theia_accept_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv_accept->pid = current->pid;
  pahgv_accept->rc = rc;
  pahgv_accept->sock_fd = fd;

  sock = sockfd_lookup(fd, &err);
  if (sock) {
    sockfd_put(sock);
    get_peer_ip_port_sockfd(fd, pahgv_accept->ip, &(pahgv_accept->port), pahgv_accept->sun_path, &(pahgv_accept->sa_family));
  }
  else {
    pr_err("sockfd_lookup error: %d\n", err);
    get_ip_port_sockaddr(upeer_sockaddr, *upeer_addrlen, pahgv_accept->ip, &(pahgv_accept->port), pahgv_accept->sun_path, &(pahgv_accept->sa_family));
  }

  packahgv_accept(pahgv_accept);
  KFREE(pahgv_accept);

  return;
}

void theia_sendto_ahg(long rc, int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user *addr, int addr_len)
{
  struct sendto_ahgv *pahgv_sendto = NULL;
  struct socket *sock = NULL;
  int err;
  struct sock *sk;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv_sendto = (struct sendto_ahgv *)KMALLOC(sizeof(struct sendto_ahgv), GFP_KERNEL);
  if (pahgv_sendto == NULL)
  {
    TPRINT("theia_sendto_ahg: failed to KMALLOC.\n");
    goto out;
  }
  pahgv_sendto->pid = current->pid;
  pahgv_sendto->sock_fd = fd;
  pahgv_sendto->rc = rc;

  if(theia_cross_toggle && fd >= 0){
    sock = sockfd_lookup(fd, &err);
    if(sock) {
      sk = sock->sk;
      if(sk->sk_type == SOCK_DGRAM)
        pahgv_sendto->send_tag = peek_theia_udp_send_tag(sk);
      sockfd_put(sock);
    }
  }
  else
    pahgv_sendto->send_tag = 0;

  sock = sockfd_lookup(fd, &err);
  if (sock && (sock->type == SOCK_STREAM || sock->type == SOCK_SEQPACKET)) {
    /* use socket fd */
  }
  else {
    if (addr != NULL && addr_len > 0) {
      pahgv_sendto->sock_fd = -1; /* ignore socket (no connection) */
      if (copy_from_user((char*)&pahgv_sendto->dest_addr, (char*)addr, sizeof(struct sockaddr))) {
        TPRINT ("theia_sendto_ahg: failed to copy dest_addr %p\n", addr);
        goto out;
      }
    }
    else {
      if (sock == NULL)
        goto out;
      /* else: use socket fd */
    }
  }

  packahgv_sendto(pahgv_sendto);

out:
  if (sock)
    sockfd_put(sock);
  KFREE(pahgv_sendto);
  return;
}

void theia_recvfrom_ahg(long rc, int fd, void __user *ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len)
{
  struct recvfrom_ahgv *pahgv_recvfrom = NULL;
  struct socket *sock = NULL;
  int err;
  struct sock *sk ;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv_recvfrom = (struct recvfrom_ahgv *)KMALLOC(sizeof(struct recvfrom_ahgv), GFP_KERNEL);
  if (pahgv_recvfrom == NULL)
  {
    TPRINT("theia_recvfrom_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv_recvfrom->pid = current->pid;
  pahgv_recvfrom->sock_fd = fd;
  pahgv_recvfrom->rc = rc;
  pahgv_recvfrom->ubuf=(char *)ubuf;

  if(theia_cross_toggle && fd >= 0){
    sock = sockfd_lookup(fd, &err);
    if(sock) {
      sk = sock->sk;
      if(sk->sk_type == SOCK_DGRAM)
        pahgv_recvfrom->recv_tag = peek_theia_udp_recv_tag(sk);
      sockfd_put(sock);
    }
  }
  else
    pahgv_recvfrom->recv_tag = 0;

  sock = sockfd_lookup(fd, &err);
  if (sock && (sock->type == SOCK_STREAM || sock->type == SOCK_SEQPACKET)) {
    /* use socket fd */
  }
  else {
    if (addr != NULL && addr_len != NULL) {
      pahgv_recvfrom->sock_fd = -1; /* ignore socket (no connection) */
      if (copy_from_user((char*)&pahgv_recvfrom->src_addr, (char*)addr, sizeof(struct sockaddr))) {
        TPRINT ("theia_recvfrom_ahg: failed to copy src_addr %p\n", addr);
        goto out;
      }
    }
    else {
      if (sock == NULL)
        goto out;
      /* else: use socket fd */
    }
  }

  packahgv_recvfrom(pahgv_recvfrom);

out:
  if (sock)
    sockfd_put(sock);
  KFREE(pahgv_recvfrom);
  return;
}

void theia_sendmsg_ahg(long rc, int fd, struct msghdr __user *msg, unsigned int flags)
{
  struct sendmsg_ahgv *pahgv_sendmsg = NULL;
  struct msghdr kmsg;
  struct sockaddr __user *addr;
  int addr_len;
  struct socket *sock = NULL;
  struct sock *sk;
  int err;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv_sendmsg = (struct sendmsg_ahgv *)KMALLOC(sizeof(struct sendmsg_ahgv), GFP_KERNEL);
  if (pahgv_sendmsg == NULL)
  {
    TPRINT("theia_sendmsg_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv_sendmsg->pid = current->pid;
  pahgv_sendmsg->sock_fd = fd;
  pahgv_sendmsg->rc = rc;

  if(theia_cross_toggle && fd >= 0){
    sock = sockfd_lookup(fd, &err);
    if(sock) {
      sk = sock->sk;
      if(sk->sk_type == SOCK_DGRAM)
        pahgv_sendmsg->send_tag = peek_theia_udp_send_tag(sk);
      sockfd_put(sock);
    }
  }
  else {
    pahgv_sendmsg->send_tag = 0;
  }

  sock = sockfd_lookup(fd, &err);
  if (sock && (sock->type == SOCK_STREAM || sock->type == SOCK_SEQPACKET)) {
    /* use socket fd */
  }
  else {
    if (msg != NULL && !copy_from_user(&kmsg, msg, sizeof(struct msghdr)) && kmsg.msg_name != NULL) {
      addr = (struct sockaddr __user *)kmsg.msg_name;
      addr_len = kmsg.msg_namelen;
      pahgv_sendmsg->sock_fd = -1; /* ignore socket (no connection) */
      if (copy_from_user((char*)&pahgv_sendmsg->dest_addr, (char*)addr, addr_len)) {
        TPRINT ("theia_sendto_ahg: failed to copy dest_addr %p\n", addr);
        goto out;
      }
    }
    else {
      if (sock == NULL)
        goto out;
      /* else: use socket fd */
    }
  }

  packahgv_sendmsg(pahgv_sendmsg);

out:
  if (sock)
    sockfd_put(sock);
  KFREE(pahgv_sendmsg);
  return;
}

void theia_recvmsg_ahg(long rc, int fd, struct msghdr __user *msg, unsigned int flags)
{
  struct recvmsg_ahgv *pahgv_recvmsg = NULL;
  struct msghdr kmsg;
  struct sockaddr __user *addr;
  int addr_len;
  struct socket *sock = NULL;
  struct sock *sk;
  int err;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv_recvmsg = (struct recvmsg_ahgv *)KMALLOC(sizeof(struct recvmsg_ahgv), GFP_KERNEL);
  if (pahgv_recvmsg == NULL)
  {
    TPRINT("theia_recvmsg_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv_recvmsg->pid = current->pid;
  pahgv_recvmsg->sock_fd = fd;
  pahgv_recvmsg->rc = rc;

  if(theia_cross_toggle && fd >= 0){
    sock = sockfd_lookup(fd, &err);
    if(sock) {
      sk = sock->sk;
      if(sk->sk_type == SOCK_DGRAM)
        pahgv_recvmsg->recv_tag = peek_theia_udp_recv_tag(sk);
      sockfd_put(sock);
    }
  }
  else
    pahgv_recvmsg->recv_tag = 0;

  sock = sockfd_lookup(fd, &err);
  if (sock && (sock->type == SOCK_STREAM || sock->type == SOCK_SEQPACKET)) {
    /* use socket fd */
  }
  else {
    if (msg != NULL && !copy_from_user(&kmsg, msg, sizeof(struct msghdr)) && kmsg.msg_name != NULL) {
      addr = (struct sockaddr __user *)kmsg.msg_name;
      addr_len = kmsg.msg_namelen;
      pahgv_recvmsg->sock_fd = -1; /* ignore socket (no connection) */
      if (copy_from_user((char*)&pahgv_recvmsg->src_addr, (char*)addr, addr_len)) {
        TPRINT ("theia_sendto_ahg: failed to copy dest_addr %p\n", addr);
        goto out;
      }
    }
    else {
      if (sock == NULL)
        goto out;
      /* else: use socket fd */
    }
  }

  packahgv_recvmsg(pahgv_recvmsg);

out:
  if (sock)
    sockfd_put(sock);
  KFREE(pahgv_recvmsg);
  return;
}

long theia_sys_socket(int family, int type, int protocol)
{
  long rc;
  rc = sys_socket(family, type, protocol);

  return rc;
}

long theia_sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
  long rc;
  rc = sys_connect(fd, uservaddr, addrlen);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  if (rc != -EAGAIN)
  {
    theia_connect_ahg(rc, fd, uservaddr, addrlen);
  }
  return rc;
}

long theia_sys_accept(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen)
{
  long rc;
  rc = sys_accept4(fd, upeer_sockaddr, upeer_addrlen, 0);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  if (rc != -EAGAIN)
  {
    theia_accept_ahg(rc, fd, upeer_sockaddr, upeer_addrlen);
  }
  return rc;
}

long theia_sys_accept4(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags)
{
  long rc;
  rc = sys_accept4(fd, upeer_sockaddr, upeer_addrlen, flags);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  if (rc != -EAGAIN)
  {
    //we reuse accept interface
    theia_accept_ahg(rc, fd, upeer_sockaddr, upeer_addrlen);
  }
  return rc;
}

long theia_sys_sendto(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user *addr, int addr_len)
{
  long rc;

  rc = sys_sendto(fd, buff, len, flags, addr, addr_len);
  //TPRINT("sendto is called!, pid %d, ret %ld\n", current->pid,rc);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  if (rc != -EAGAIN)
  {
    theia_sendto_ahg(rc, fd, buff, len, flags, addr, addr_len);
  }
  return rc;
}

long theia_sys_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len)
{
  long rc;
  rc = sys_recvfrom(fd, ubuf, size, flags, addr, addr_len);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  if (rc != -EAGAIN)
  {
    theia_recvfrom_ahg(rc, fd, ubuf, size, flags, addr, addr_len);
  }
  return rc;
}

long theia_sys_sendmsg(int fd, struct msghdr __user *msg, unsigned int flags)
{
  long rc;
  rc = sys_sendmsg(fd, msg, flags);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  if (rc != -EAGAIN)
  {
    theia_sendmsg_ahg(rc, fd, msg, flags);
  }
  return rc;
}

long theia_sys_recvmsg(int fd, struct msghdr __user *msg, unsigned int flags)
{
  long rc;
  rc = sys_recvmsg(fd, msg, flags);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  if (rc != -EAGAIN)
  {
    theia_recvmsg_ahg(rc, fd, msg, flags);
  }
  return rc;
}

long theia_sys_shutdown(int fd, int how)
{
  long rc;
  rc = sys_shutdown(fd, how);

  return rc;
}

long theia_sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
  long rc;
  rc = sys_bind(fd, umyaddr, addrlen);

  return rc;
}

long theia_sys_listen(int fd, int backlog)
{
  long rc;
  rc = sys_listen(fd, backlog);

  return rc;
}

long theia_sys_getsockname(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
  long rc;
  rc = sys_getsockname(fd, usockaddr, usockaddr_len);

  return rc;
}

long theia_sys_getpeername(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
  long rc;
  rc = sys_getpeername(fd, usockaddr, usockaddr_len);

  return rc;
}

void theia_socketpair_ahgx(int family, int type, int protocol, int __user *usockvec)
{
  char *buf = NULL;
  struct file *file = NULL;
  int fput_needed;
  struct inode *inode;
  u_long dev, ino;

  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  file = fget_light(usockvec[0], &fput_needed);
  if (!file)
    goto err; 

  inode = file->f_dentry->d_inode;
  dev = inode->i_sb->s_dev;
  ino = inode->i_ino;

#ifdef THEIA_AUX_DATA
  theia_dump_auxdata();
#endif

  snprintf(buf, THEIA_KMEM_SIZE-1, "%lx|%lx", dev, ino);
  theia_dump_str(buf, 0, 53);

err:
  kmem_cache_free(theia_buffers, buf);
  if (file)
    fput_light(file, fput_needed);
}

long theia_sys_socketpair(int family, int type, int protocol, int __user *usockvec)
{
  long rc;
  rc = sys_socketpair(family, type, protocol, usockvec);

  theia_socketpair_ahgx(family, type, protocol, usockvec);

  return rc;
}

long theia_sys_setsockopt(int fd, int level, int optname, char __user *optval, int optlen)
{
  long rc;
  rc = sys_setsockopt(fd, level, optname, optval, optlen);

  return rc;
}

long theia_sys_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen)
{
  long rc;
  rc = sys_getsockopt(fd, level, optname, optval, optlen);

  return rc;
}

static asmlinkage long
record_socket(int family, int type, int protocol)
{
  long rc = 0;
  struct generic_socket_retvals *pretvals = NULL;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(41);

  rc = sys_socket(family, type, protocol);

  new_syscall_done(41, rc);

  DPRINT("Pid %d records socket  returning %ld\n", current->pid, rc);

  pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
  if (pretvals == NULL)
  {
    TPRINT("record_socketcall(socket): can't allocate buffer\n");
    return -ENOMEM;
  }
  pretvals->call = SYS_SOCKET;
  new_syscall_exit(41, pretvals);
  return rc;
}

static asmlinkage long
record_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
  long rc = 0;
  struct generic_socket_retvals *pretvals = NULL;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(42);

  rc = sys_connect(fd, uservaddr, addrlen);

  // Yang also needed at recording
  if (rc != -EAGAIN) /* ignore some less meaningful errors */
    theia_connect_ahg(rc, fd, uservaddr, addrlen);

  new_syscall_done(42, rc);

  pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
  if (pretvals == NULL)
  {
    TPRINT("record_socketcall(socket): can't allocate buffer\n");
    return -ENOMEM;
  }
  pretvals->call = SYS_CONNECT;
  new_syscall_exit(42, pretvals);
  return rc;
}

static asmlinkage long
record_accept(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen)
{
  long rc = 0;
  struct accept_retvals *pretvals = NULL;
  long addrlen;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(43);

  rc = sys_accept(fd, upeer_sockaddr, upeer_addrlen);

  // Yang also needed at recording
  if (rc != -EAGAIN) /* ignore some less meaningful errors */
    theia_accept_ahg(rc, fd, upeer_sockaddr, upeer_addrlen);

  new_syscall_done(43, rc);

  DPRINT("Pid %d record_accept\n", current->pid);
  if (rc >= 0)
  {
    if (upeer_sockaddr)
    {
      addrlen = *((int *) upeer_addrlen);
    }
    else
    {
      addrlen = 0;
    }
    pretvals = ARGSKMALLOC(sizeof(struct accept_retvals) + addrlen, GFP_KERNEL);
    if (pretvals == NULL)
    {
      TPRINT("record_socketcall(accept): can't allocate buffer\n");
      return -ENOMEM;
    }
    pretvals->addrlen = addrlen;
    if (addrlen)
    {
      if (copy_from_user(&pretvals->addr, (char *) upeer_sockaddr, addrlen))
      {
        TPRINT("record_socketcall(accept): can't copy addr\n");
        ARGSKFREE(pretvals, sizeof(struct accept_retvals) + addrlen);
        return -EFAULT;
      }
    }
    pretvals->call = SYS_ACCEPT;
  }
  new_syscall_exit(43, pretvals);
  return rc;
}

static asmlinkage long
record_accept4(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags)
{
  long rc = 0;
  struct accept_retvals *pretvals = NULL;
  long addrlen;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(288);

  rc = sys_accept4(fd, upeer_sockaddr, upeer_addrlen, flags);

  // Yang also needed at recording
  if (rc != -EAGAIN) /* ignore some less meaningful errors */
    //we reuse the accept ahg format
    theia_accept_ahg(rc, fd, upeer_sockaddr, upeer_addrlen);

  new_syscall_done(288, rc);

  DPRINT("Pid %d record_accept\n", current->pid);
  if (rc >= 0)
  {
    if (upeer_sockaddr)
    {
      addrlen = *((int *) upeer_addrlen);
    }
    else
    {
      addrlen = 0;
    }
    pretvals = ARGSKMALLOC(sizeof(struct accept_retvals) + addrlen, GFP_KERNEL);
    if (pretvals == NULL)
    {
      TPRINT("record_socketcall(accept): can't allocate buffer\n");
      return -ENOMEM;
    }
    pretvals->addrlen = addrlen;
    if (addrlen)
    {
      if (copy_from_user(&pretvals->addr, (char *) upeer_sockaddr, addrlen))
      {
        TPRINT("record_socketcall(accept): can't copy addr\n");
        ARGSKFREE(pretvals, sizeof(struct accept_retvals) + addrlen);
        return -EFAULT;
      }
    }
    pretvals->call = SYS_ACCEPT;
  }
  new_syscall_exit(288, pretvals);
  return rc;
}

static asmlinkage long
record_sendto(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user *addr, int addr_len)
{
  long rc = 0;
  int err = 0;
  struct socket *sock;
  char *puuid;
  struct generic_socket_retvals *pretvals = NULL;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(44);

#ifdef TRACE_SOCKET_READ_WRITE
  sock = sockfd_lookup(fd, &err);

  if (sock != NULL && (sock->ops == &unix_stream_ops || sock->ops == &unix_seqpacket_ops))
  {
    int ret;
    struct sock *peer;
    struct sock *sk = sock->sk;
    peer = unix_peer_get(sk);
    if (peer) {
      ret = track_usually_pt2pt_write_begin(peer, sock->file);
      sock_put(peer);
    }
  }
#endif

  rc = sys_sendto(fd, buff, len, flags, addr, addr_len);

  // Yang also needed at recording
  if (rc != -EAGAIN) /* ignore some less meaningful errors */
    theia_sendto_ahg(rc, fd, buff, len, flags, addr, addr_len);

  //Yang: we get the inode
  puuid = ARGSKMALLOC(strlen(rec_uuid_str) + 1, GFP_KERNEL);
  if (puuid == NULL)
  {
    TPRINT("record_sendto: can't allocate pos buffer for rec_uuid_str\n");
    return -ENOMEM;
  }
  strncpy_safe((char *)puuid, rec_uuid_str, THEIA_UUID_LEN);
  pr_debug("sendto: rec_uuid_str is %s,clock %d\n", rec_uuid_str, atomic_read(current->record_thrd->rp_precord_clock));
  pr_debug("sendto: copied to pretval is (%s)\n", (char *)puuid);

  new_syscall_done(44, rc);

  DPRINT("Pid %d records sendto returning %ld\n", current->pid, rc);

#ifdef TRACE_SOCKET_READ_WRITE
  pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
  if (pretvals == NULL)
  {
    TPRINT("record_socketcall(socket): can't allocate buffer\n");
    return -ENOMEM;
  }
  pretvals->call = SYS_SENDTO;

  /* Need to track write info for send and sendto */
  if (rc >= 0)
  {
    struct file *filp = fget(fd);
    struct socket *sock = NULL;

    if (filp) 
      sock = filp->private_data;

    if (sock && (sock->ops == &unix_stream_ops || sock->ops == &unix_seqpacket_ops))
    {
      int ret = 0;
      struct sock *peer;
      struct sock *sk = sock->sk;
      peer = unix_peer_get(sk);
      if (peer)
      {
        ret = track_usually_pt2pt_write(peer, rc, filp, 1);
        sock_put(peer);
      }
      if (ret)
      {
        ARGSKFREE(pretvals, sizeof(struct generic_socket_retvals));
        fput(filp); 
        return ret;
      }
    }
    else
    {
      int *is_cached = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);
      if (is_cached == NULL)
      {
        return -ENOMEM;
      }
      *is_cached = 0;
    }

    if(filp)
      fput(filp);
  }

  new_syscall_exit(44, pretvals);
  return rc;
#else
  struct generic_socket_retvals *pretvals = NULL;
  pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
  if (pretvals == NULL)
  {
    TPRINT("record_socketcall(socket): can't allocate buffer\n");
    return -ENOMEM;
  }
  pretvals->call = SYS_SENDTO;
  new_syscall_exit(44, pretvals);
  return rc;
#endif
}

static asmlinkage long
record_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len)
{
  long rc = 0;
  char *puuid;
  struct recvfrom_retvals *pretvals = NULL;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(45);

  rc = sys_recvfrom(fd, ubuf, size, flags, addr, addr_len);

  // Yang also needed at recording
  if (rc != -EAGAIN) /* ignore some less meaningful errors */
    theia_recvfrom_ahg(rc, fd, ubuf, size, flags, addr, addr_len);

  //Yang: we get the inode
  puuid = ARGSKMALLOC(strlen(rec_uuid_str) + 1, GFP_KERNEL);
  if (puuid == NULL)
  {
    TPRINT("record_recvfrom: can't allocate pos buffer for rec_uuid_str\n");
    return -ENOMEM;
  }
  strncpy_safe((char *)puuid, rec_uuid_str, THEIA_UUID_LEN);
  pr_debug("recvfrom: rec_uuid_str is %s, clock %d\n", rec_uuid_str, atomic_read(current->record_thrd->rp_precord_clock));
  pr_debug("recvfrom: copied to pretval is (%s)\n", (char *)puuid);

  new_syscall_done(45, rc);

  DPRINT("Pid %d records recvfrom returning %ld\n", current->pid, rc);

  if (rc >= 0)
  {
    pretvals = ARGSKMALLOC(sizeof(struct recvfrom_retvals) + rc - 1, GFP_KERNEL);
    if (pretvals == NULL)
    {
      TPRINT("record_socketcall(recvfrom): can't allocate buffer\n");
      return -ENOMEM;
    }

    if (copy_from_user(&pretvals->buf, (char *) ubuf, rc))
    {
      TPRINT("record_socketcall(recvfrom): can't copy data buffer of size %ld\n", rc);
      ARGSKFREE(pretvals, sizeof(struct recvfrom_retvals) + rc - 1);
      return -EFAULT;
    }
    if (addr)
    {
      pretvals->addrlen = *((int *)addr_len);
      if (pretvals->addrlen > sizeof(struct sockaddr))
      {
        TPRINT("record_socketcall(recvfrom): addr length %d too big\n", pretvals->addrlen);
        ARGSKFREE(pretvals, sizeof(struct recvfrom_retvals) + rc - 1);
        return -EFAULT;
      }
      if (copy_from_user(&pretvals->addr, (char *) addr, pretvals->addrlen))
      {
        TPRINT("record_socketcall(recvfrom): can't copy addr\n");
        ARGSKFREE(pretvals, sizeof(struct recvfrom_retvals) + rc - 1);
        return -EFAULT;
      }
    }
    pretvals->call = SYS_RECVFROM;

#ifdef TRACE_SOCKET_READ_WRITE
    do /* magic */
    {
      struct file *filp = fget(fd);
      struct socket *socket = NULL;

      if (filp)
        socket = filp->private_data;

      if (socket && (socket->ops == &unix_stream_ops || socket->ops == &unix_seqpacket_ops))
      {
        int ret;
        ret = track_usually_pt2pt_read(socket->sk, rc, filp);
        if (ret)
        {
          ARGSKFREE(pretvals, sizeof(struct recvfrom_retvals) + rc - 1);
          fput(filp);
          return ret;
        }
      }
      else
      {
        u_int *is_cached = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);
        if (is_cached == NULL)
        {
          return -ENOMEM;
        }
        *is_cached = 0;
      }

      if(filp)
        fput(filp);
    }
    while (0);
#endif
  }

  new_syscall_exit(45, pretvals);
  return rc;
}

static asmlinkage long
record_sendmsg(int fd, struct msghdr __user *msg, unsigned int flags)
{
  long rc = 0;
  char *puuid;
  struct generic_socket_retvals *pretvals = NULL;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(46);

  rc = sys_sendmsg(fd, msg, flags);

  // Yang also needed at recording
  if (rc != -EAGAIN) /* ignore some less meaningful errors */
    theia_sendmsg_ahg(rc, fd, msg, flags);

  //Yang: we get the inode
  puuid = ARGSKMALLOC(strlen(rec_uuid_str) + 1, GFP_KERNEL);
  if (puuid == NULL)
  {
    TPRINT("record_sendmsg: can't allocate pos buffer for rec_uuid_str\n");
    return -ENOMEM;
  }
  strncpy_safe((char *)puuid, rec_uuid_str, THEIA_UUID_LEN);
  pr_debug("sendmsg: rec_uuid_str is %s, clock %d\n", rec_uuid_str, atomic_read(current->record_thrd->rp_precord_clock));
  pr_debug("sendmsg: copied to pretval is (%s)\n", (char *)puuid);

  new_syscall_done(46, rc);

  DPRINT("Pid %d records sendmsg returning %ld\n", current->pid, rc);

  pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
  if (pretvals == NULL)
  {
    TPRINT("record_socketcall(socket): can't allocate buffer\n");
    return -ENOMEM;
  }
  pretvals->call = SYS_SENDMSG;
  new_syscall_exit(46, pretvals);
  return rc;
}

static asmlinkage long
record_recvmsg(int fd, struct msghdr __user *msg, unsigned int flags)
{
  long rc = 0;
  char *puuid;
  struct recvmsg_retvals *pretvals = NULL;
  struct msghdr __user *pmsghdr;
  char *pdata;
  long iovlen, rem_size, to_copy, i;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(47);

  rc = sys_recvmsg(fd, msg, flags);
  TPRINT("[%s|%d] pid %d, fd %d, rc %ld\n", __func__, __LINE__, current->pid, fd, rc);

  // Yang also needed at recording
  if (rc != -EAGAIN) /* ignore some less meaningful errors */
    theia_recvmsg_ahg(rc, fd, msg, flags);

  //Yang: we get the inode
  puuid = ARGSKMALLOC(strlen(rec_uuid_str) + 1, GFP_KERNEL);
  if (puuid == NULL)
  {
    TPRINT("record_recvmsg: can't allocate pos buffer for rec_uuid_str\n");
    return -ENOMEM;
  }
  strncpy_safe((char *)puuid, rec_uuid_str, THEIA_UUID_LEN);
  pr_debug("recvmsg: rec_uuid_str is %s, clock %d\n", rec_uuid_str, atomic_read(current->record_thrd->rp_precord_clock));
  pr_debug("recvmsg: copied to pretval is (%s)\n", (char *)puuid);

#ifdef TIME_TRICK
  shift_clock = 0;
  cnew_syscall_done(47, rc, -1, shift_clock);
#else
  new_syscall_done(47, rc);
#endif

  DPRINT("Pid %d records recvmsg returning %ld\n", current->pid, rc);

  pmsghdr = (struct msghdr __user *) msg;

  if (rc >= 0)
  {

    DPRINT("record_recvmsg: namelen: %d, controllen %ld iov_len %lu rc %ld\n", pmsghdr->msg_namelen, (long) pmsghdr->msg_controllen, pmsghdr->msg_iovlen, rc);

    pretvals = ARGSKMALLOC(sizeof(struct recvmsg_retvals) + pmsghdr->msg_namelen + pmsghdr->msg_controllen + rc, GFP_KERNEL);
    if (pretvals == NULL)
    {
      TPRINT("record_socketcall(recvmsg): can't allocate buffer\n");
      return -ENOMEM;
    }
    pretvals->call = SYS_RECVMSG;
    get_user(pretvals->msg_namelen, &pmsghdr->msg_namelen);
    get_user(pretvals->msg_controllen, &pmsghdr->msg_controllen);
    get_user(pretvals->msg_flags, &pmsghdr->msg_flags);

    pdata = ((char *) pretvals) + sizeof(struct recvmsg_retvals);

    if (pretvals->msg_namelen)
    {
      if (copy_from_user(pdata, pmsghdr->msg_name, pretvals->msg_namelen))
      {
        TPRINT("record_socketcall(recvmsg): can't copy msg_name of size %d\n", pretvals->msg_namelen);
        ARGSKFREE(pretvals, sizeof(struct recvmsg_retvals) + pmsghdr->msg_namelen + pmsghdr->msg_controllen + rc);
        return -EFAULT;
      }
      pdata += pmsghdr->msg_namelen;
    }
    if (pmsghdr->msg_controllen)
    {
      if (copy_from_user(pdata, pmsghdr->msg_control, pretvals->msg_controllen))
      {
        TPRINT("record_socketcall(recvmsg): can't copy msg_control of size %ld\n", pretvals->msg_controllen);
        ARGSKFREE(pretvals, sizeof(struct recvmsg_retvals) + pmsghdr->msg_namelen + pmsghdr->msg_controllen + rc);
        return -EFAULT;
      }
      pdata += pmsghdr->msg_controllen;
    }

    get_user(iovlen, &pmsghdr->msg_iovlen);
    rem_size = rc;
    for (i = 0; i < iovlen; i++)
    {
      get_user(to_copy, &pmsghdr->msg_iov[i].iov_len);
      if (rem_size < to_copy) to_copy = rem_size;

      if (copy_from_user(pdata, pmsghdr->msg_iov[i].iov_base, to_copy))
      {
        TPRINT("Pid %d record_readv copy_from_user of data failed\n", current->pid);
        ARGSKFREE(pretvals, sizeof(struct recvmsg_retvals) + pmsghdr->msg_namelen + pmsghdr->msg_controllen + rc);
        return -EFAULT;
      }
      pdata += to_copy;
      rem_size -= to_copy;
      if (rem_size == 0) break;
    }
    //      if (rem_size != 0) TPRINT ("record_socketcall(recvmsg): %ld bytes of data remain???\n", rem_size);
#ifdef X_COMPRESS
    if (is_x_fd(&X_STRUCT_REC, fd))
    {
      if (x_detail) TPRINT("Pid %d recvmsg: fd:%ld, size:%ld\n", current->pid,  fd, rc);
      change_log_special_second();
    }
#endif
  }

  new_syscall_exit(47, pretvals);
  return rc;
}

static asmlinkage long
record_shutdown(int fd, int how)
{
  long rc = 0;
  struct generic_socket_retvals *pretvals = NULL;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(48);

  rc = sys_shutdown(fd, how);

  new_syscall_done(48, rc);

  DPRINT("Pid %d records bind returning %ld\n", current->pid, rc);

  pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
  if (pretvals == NULL)
  {
    TPRINT("record_socketcall(socket): can't allocate buffer\n");
    return -ENOMEM;
  }
  pretvals->call = SYS_SHUTDOWN;
  new_syscall_exit(48, pretvals);
  return rc;
}

static asmlinkage long
record_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
  long rc = 0;
  struct generic_socket_retvals *pretvals = NULL;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(49);

  rc = sys_bind(fd, umyaddr, addrlen);

  new_syscall_done(49, rc);

  DPRINT("Pid %d records bind returning %ld\n", current->pid, rc);

  pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
  if (pretvals == NULL)
  {
    TPRINT("record_socketcall(socket): can't allocate buffer\n");
    return -ENOMEM;
  }
  pretvals->call = SYS_BIND;
  new_syscall_exit(49, pretvals);
  return rc;
}

static asmlinkage long
record_listen(int fd, int backlog)
{
  long rc = 0;
  struct generic_socket_retvals *pretvals = NULL;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(50);

  rc = sys_listen(fd, backlog);

  new_syscall_done(50, rc);

  DPRINT("Pid %d records listen returning %ld\n", current->pid, rc);

  pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
  if (pretvals == NULL)
  {
    TPRINT("record_socketcall(socket): can't allocate buffer\n");
    return -ENOMEM;
  }
  pretvals->call = SYS_LISTEN;
  new_syscall_exit(50, pretvals);
  return rc;
}

static asmlinkage long
record_getsockname(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
  long rc = 0;
  struct accept_retvals *pretvals = NULL;
  long addrlen;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(51);

  rc = sys_getsockname(fd, usockaddr, usockaddr_len);

  new_syscall_done(51, rc);

  DPRINT("Pid %d records getsockname returning %ld\n", current->pid, rc);

  DPRINT("Pid %d record_getsockname\n", current->pid);
  if (rc >= 0)
  {
    if (usockaddr)
    {
      addrlen = *((int *) usockaddr_len);
    }
    else
    {
      addrlen = 0;
    }
    pretvals = ARGSKMALLOC(sizeof(struct accept_retvals) + addrlen, GFP_KERNEL);
    if (pretvals == NULL)
    {
      TPRINT("record_socketcall(accept): can't allocate buffer\n");
      return -ENOMEM;
    }
    pretvals->addrlen = addrlen;
    if (addrlen)
    {
      if (copy_from_user(&pretvals->addr, (char *) usockaddr, addrlen))
      {
        TPRINT("record_socketcall(accept): can't copy addr\n");
        ARGSKFREE(pretvals, sizeof(struct accept_retvals) + addrlen);
        return -EFAULT;
      }
    }
    pretvals->call = SYS_GETSOCKNAME;
  }
  new_syscall_exit(51, pretvals);
  return rc;
}

static asmlinkage long
record_getpeername(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
  long rc = 0;
  struct accept_retvals *pretvals = NULL;
  long addrlen;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(52);

  rc = sys_getpeername(fd, usockaddr, usockaddr_len);

  new_syscall_done(52, rc);

  DPRINT("Pid %d records getpeername returning %ld\n", current->pid, rc);

  DPRINT("Pid %d record_getsockname\n", current->pid);
  if (rc >= 0)
  {
    if (usockaddr)
    {
      addrlen = *((int *) usockaddr_len);
    }
    else
    {
      addrlen = 0;
    }
    pretvals = ARGSKMALLOC(sizeof(struct accept_retvals) + addrlen, GFP_KERNEL);
    if (pretvals == NULL)
    {
      TPRINT("record_socketcall(accept): can't allocate buffer\n");
      return -ENOMEM;
    }
    pretvals->addrlen = addrlen;
    if (addrlen)
    {
      if (copy_from_user(&pretvals->addr, (char *) usockaddr, addrlen))
      {
        TPRINT("record_socketcall(accept): can't copy addr\n");
        ARGSKFREE(pretvals, sizeof(struct accept_retvals) + addrlen);
        return -EFAULT;
      }
    }
    pretvals->call = SYS_GETPEERNAME;
  }
  new_syscall_exit(52, pretvals);
  return rc;
}

static asmlinkage long
record_socketpair(int family, int type, int protocol, int __user *usockvec)
{
  long rc = 0;
  struct socketpair_retvals *pretvals = NULL;
  int *sv;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(53);

  rc = sys_socketpair(family, type, protocol, usockvec);
  theia_socketpair_ahgx(family, type, protocol, usockvec);

  new_syscall_done(53, rc);

  DPRINT("Pid %d records socketpair returning %ld\n", current->pid, rc);

  if (rc >= 0)
  {
    sv = (int *) usockvec;
    pretvals = ARGSKMALLOC(sizeof(struct socketpair_retvals), GFP_KERNEL);
    if (pretvals == NULL)
    {
      TPRINT("record_socketcall(socketpair): can't allocate buffer\n");
      return -ENOMEM;
    }
    pretvals->call = SYS_SOCKETPAIR;
    pretvals->sv0 = *(sv);
    pretvals->sv1 = *(sv + 1);
    DPRINT("pid %d records socketpair retuning %ld, sockets %d and %d\n", current->pid, rc, pretvals->sv0, pretvals->sv1);
  }
  new_syscall_exit(53, pretvals);
  return rc;
}

static asmlinkage long
record_setsockopt(int fd, int level, int optname, char __user *optval, int optlen)
{
  long rc = 0;
  struct generic_socket_retvals *pretvals = NULL;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(54);

  rc = sys_setsockopt(fd, level, optname, optval, optlen);

  new_syscall_done(54, rc);

  DPRINT("Pid %d records setsockopt returning %ld\n", current->pid, rc);

  pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
  if (pretvals == NULL)
  {
    TPRINT("record_socketcall(socket): can't allocate buffer\n");
    return -ENOMEM;
  }
  pretvals->call = SYS_SETSOCKOPT;
  new_syscall_exit(54, pretvals);
  return rc;
}

static asmlinkage long
record_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen)
{
  long rc = 0;
  struct generic_socket_retvals *pretvals = NULL;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(55);

  rc = sys_getsockopt(fd, level, optname, optval, optlen);

  new_syscall_done(55, rc);

  DPRINT("Pid %d records getsockopt returning %ld\n", current->pid, rc);

  pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
  if (pretvals == NULL)
  {
    TPRINT("record_socketcall(socket): can't allocate buffer\n");
    return -ENOMEM;
  }
  pretvals->call = SYS_GETSOCKOPT;
  new_syscall_exit(55, pretvals);
  return rc;
}


static asmlinkage long
replay_socket(int family, int type, int protocol)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_socket\n", current->pid);

  rc = get_next_syscall(41, &retparams);

  DPRINT("Pid %d, replay_socket, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

#ifndef LOG_COMPRESS
  if (retparams) argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct generic_socket_retvals));
  return rc;
#else
  if (x_proxy)
  {
    long retval = sys_socket(family, type, protocol);
    if (retval <= 0)
      pr_debug("Pid %d create socket fails, expected:%ld, actual:%ld\n", current->pid, rc, retval);
    else
    {
      if (x_detail) pr_debug("Pid %d create socket, recorded fd is %ld, actual fd is %ld\n", current->pid, rc, retval);
      X_STRUCT_REP.last_fd = retval;
    }
  }
  if (retparams) argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct generic_socket_retvals));
  return rc;
#endif
  return syscall_mismatch();
}

static asmlinkage long
replay_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_connect\n", current->pid);

  rc = get_next_syscall(42, &retparams);

  DPRINT("Pid %d, replay_connect, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams) argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct generic_socket_retvals));
  return rc;
}

static asmlinkage long
replay_accept(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_accept\n", current->pid);

  rc = get_next_syscall(43, &retparams);

  DPRINT("Pid %d, replay_accept, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams)
  {
    struct accept_retvals *retvals = (struct accept_retvals *) retparams;
    if (upeer_sockaddr)
    {
      *((int *) upeer_addrlen) = retvals->addrlen;
      if (copy_to_user((char *) upeer_sockaddr, &retvals->addr, retvals->addrlen))
      {
        TPRINT("Pid %d replay_socketcall_accept cannot copy to user\n", current->pid);
      }
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct accept_retvals) + retvals->addrlen);
  }
  return rc;
}

static asmlinkage long
replay_accept4(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_accept4\n", current->pid);

  rc = get_next_syscall(288, &retparams);

  DPRINT("Pid %d, replay_accept4, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams)
  {
    struct accept_retvals *retvals = (struct accept_retvals *) retparams;
    if (upeer_sockaddr)
    {
      *((int *) upeer_addrlen) = retvals->addrlen;
      if (copy_to_user((char *) upeer_sockaddr, &retvals->addr, retvals->addrlen))
      {
        TPRINT("Pid %d replay_socketcall_accept cannot copy to user\n", current->pid);
      }
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct accept_retvals) + retvals->addrlen);
  }
  return rc;
}

static asmlinkage long
replay_sendto(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user *addr, int addr_len)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_sendto\n", current->pid);

  rc = get_next_syscall(44, &retparams);

  DPRINT("Pid %d, replay_sendto, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

#ifdef TRACE_SOCKET_READ_WRITE
  if (retparams)
  {
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct generic_socket_retvals));
    retparams += sizeof(struct generic_socket_retvals);
    if (rc >= 0)
    {
      /* We need to allocate something on write regardless, then use it to determine how much to free... ugh */
      consume_socket_args_write(retparams);
    }
  }
#else
  if (retparams) argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct generic_socket_retvals));
#endif
  return rc;
}

static asmlinkage long
replay_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_recvfrom\n", current->pid);

  rc = get_next_syscall(45, &retparams);

  DPRINT("Pid %d, replay_recvfrom, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams)
  {
    struct recvfrom_retvals *retvals = (struct recvfrom_retvals *) retparams;
    if (copy_to_user((char *) ubuf, &retvals->buf, rc))
    {
      TPRINT("Pid %d replay_recvfrom cannot copy to user\n", current->pid);
    }
    if (addr)
    {
      *((int *) addr_len) = retvals->addrlen;
      if (copy_to_user((char *) addr, &retvals->addr, retvals->addrlen))
      {
        TPRINT("Pid %d cannot copy sockaddr from to user\n", current->pid);
      }

    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct recvfrom_retvals) + rc - 1);
#ifdef TRACE_SOCKET_READ_WRITE
    consume_socket_args_read(retparams + sizeof(struct recvfrom_retvals) + rc - 1);
#endif
  }
  return rc;
}

static asmlinkage long
replay_sendmsg(int fd, struct msghdr __user *msg, unsigned int flags)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_sendmsg\n", current->pid);

  rc = get_next_syscall(46, &retparams);

  DPRINT("Pid %d, replay_sendmsg, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams) argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct generic_socket_retvals));
  return rc;
}

static asmlinkage long
replay_recvmsg(int fd, struct msghdr __user *msg, unsigned int flags)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_recvmsg, fd %d, flags %u, msg %p\n", current->pid, fd, flags, msg);

  rc = get_next_syscall(47, &retparams);

  DPRINT("Pid %d, replay_recvmsg, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams)
  {
    struct recvmsg_retvals *retvals = (struct recvmsg_retvals *) retparams;
    char *pdata = ((char *) retvals) + sizeof(struct recvmsg_retvals);
    //      struct msghdr *msg = (struct msghdr __user *) msg;
    long rem_size, to_copy, i, iovlen;

    pr_debug("[%s|%d] replay_recvmsg, msg %p\n", __func__, __LINE__, msg);
    put_user(retvals->msg_controllen, &msg->msg_controllen);  // This is an in-out parameter
    pr_debug("[%s|%d] replay_recvmsg, retvals msg_controllen size %lu, msg->msg_controllen size %lu, retvals msg_flags size %lu, msg->msg_flags size %lu, retvals->msg_flags %u, msg_flags ptr %p\n", __func__, __LINE__, sizeof(retvals->msg_controllen), sizeof(&msg->msg_controllen), sizeof(retvals->msg_flags), sizeof(msg->msg_flags), retvals->msg_flags, &(msg->msg_flags));
    put_user(retvals->msg_flags, &(msg->msg_flags));            // Out parameter
    TPRINT("[%s|%d] replay_recvmsg, msg_namelen %d, msg->msg_namelen %d\n", __func__, __LINE__, retvals->msg_namelen, msg->msg_namelen);

    if (retvals->msg_namelen)
    {
      long crc = copy_to_user((char *) msg->msg_name, pdata, retvals->msg_namelen);
      if (crc)
      {
        TPRINT("Pid %d cannot copy msg_namelen %p to user %p len %d, rc=%ld\n",
               current->pid, msg->msg_name, pdata, retvals->msg_namelen, crc);
        syscall_mismatch();
      }
      pdata += retvals->msg_namelen;
    }
    TPRINT("[%s|%d] replay_recvmsg\n", __func__, __LINE__);

    if (retvals->msg_controllen)
    {
      long crc = copy_to_user((char *) msg->msg_control, pdata, retvals->msg_controllen);
      if (crc)
      {
        TPRINT("Pid %d cannot copy msg_control %p to user %p len %ld, rc=%ld\n",
               current->pid, msg->msg_control, pdata, retvals->msg_controllen, crc);
        syscall_mismatch();
      }
      pdata += retvals->msg_controllen;
    }
    TPRINT("[%s|%d] replay_recvmsg\n", __func__, __LINE__);

    get_user(iovlen, &msg->msg_iovlen);
    rem_size = rc;
    for (i = 0; i < iovlen; i++)
    {
      get_user(to_copy, &msg->msg_iov[i].iov_len);
      if (rem_size < to_copy) to_copy = rem_size;

      if (copy_to_user(msg->msg_iov[i].iov_base, pdata, to_copy))
      {
        TPRINT("Pid %d replay_readv copy_to_user of data failed\n", current->pid);
        syscall_mismatch();
      }
      pdata += to_copy;
      rem_size -= to_copy;
      if (rem_size == 0) break;
    }

    TPRINT("[%s|%d] replay_recvmsg\n", __func__, __LINE__);
    if (rem_size != 0)
    {
      TPRINT("replay_socketcall(recvmsg): %ld bytes remaining\n", rem_size);
      syscall_mismatch();
    }
#ifdef X_COMPRESS
    if (is_x_fd(&X_STRUCT_REP, fd))
    {
      if (x_detail) TPRINT("Pid %d recvmsg for x\n", current->pid);
      //x_decompress_reply (iovlen, &X_STRUCT_REP, xnode);
      //validate_decode_buffer (((char*) retvals) + sizeof (struct recvmsg_retvals) + retvals->msg_namelen + retvals->msg_controllen, iovlen, &X_STRUCT_REP);
      //consume_decode_buffer (iovlen, &X_STRUCT_REP);
      if (x_proxy)
      {
        long retval = sys_recvmsg(fd, msg, flags);
        // it should be the same with RECV; fix if needed
        BUG();
        if (retval != rc)
          TPRINT("Pid %d recvmsg from x fails, expected:%ld, actual:%ld\n", current->pid, rc, retval);
      }

    }
#endif
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct recvmsg_retvals) + retvals->msg_namelen + retvals->msg_controllen + rc);
  }
  return rc;
}

static asmlinkage long
replay_shutdown(int fd, int how)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_bind\n", current->pid);

  rc = get_next_syscall(48, &retparams);

  DPRINT("Pid %d, replay_shutdown, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams) argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct generic_socket_retvals));
  return rc;
}

static asmlinkage long
replay_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_bind\n", current->pid);

  rc = get_next_syscall(49, &retparams);

  DPRINT("Pid %d, replay_bind, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams) argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct generic_socket_retvals));
  return rc;
}

static asmlinkage long
replay_listen(int fd, int backlog)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_listen\n", current->pid);

  rc = get_next_syscall(50, &retparams);

  DPRINT("Pid %d, replay_listen, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams) argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct generic_socket_retvals));
  return rc;
}

static asmlinkage long
replay_getsockname(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_getsockname\n", current->pid);

  rc = get_next_syscall(51, &retparams);

  DPRINT("Pid %d, replay_getsockname, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams)
  {
    struct accept_retvals *retvals = (struct accept_retvals *) retparams;
    *((int *) usockaddr_len) = retvals->addrlen;
    if (copy_to_user((char *) usockaddr, &retvals->addr, retvals->addrlen))
    {
      TPRINT("Pid %d replay_socketcall_getpeername cannot copy to user\n", current->pid);
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct accept_retvals) + retvals->addrlen);
  }
  return rc;
}

static asmlinkage long
replay_getpeername(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_getpeername\n", current->pid);

  rc = get_next_syscall(52, &retparams);

  DPRINT("Pid %d, replay_getpeername, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams)
  {
    struct accept_retvals *retvals = (struct accept_retvals *) retparams;
    *((int *) usockaddr_len) = retvals->addrlen;
    if (copy_to_user((char *) usockaddr, &retvals->addr, retvals->addrlen))
    {
      TPRINT("Pid %d replay_socketcall_getpeername cannot copy to user\n", current->pid);
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct accept_retvals) + retvals->addrlen);
  }
  return rc;
}

static asmlinkage long
replay_socketpair(int family, int type, int protocol, int __user *usockvec)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_socketpair\n", current->pid);

  rc = get_next_syscall(53, &retparams);

  DPRINT("Pid %d, replay_socketpair, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams)
  {
    int *sv;
    struct socketpair_retvals *retvals = (struct socketpair_retvals *) retparams;

    sv = (int *) KMALLOC(2 * sizeof(int), GFP_KERNEL);
    *sv = retvals->sv0;
    *(sv + 1) = retvals->sv1;

    if (copy_to_user((int *) usockvec, sv, 2 * sizeof(int)))
    {
      TPRINT("Pid %d replay_socketcall_socketpair cannot copy to user\n", current->pid);
    }

    KFREE(sv);
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct socketpair_retvals));
  }
  return rc;
}

static asmlinkage long
replay_setsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_setsockopt\n", current->pid);

  rc = get_next_syscall(54, &retparams);

  DPRINT("Pid %d, replay_setsockopt, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams) argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct generic_socket_retvals));
  return rc;
}

static asmlinkage long
replay_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen)
{
  char *retparams = NULL;
  long rc;

  DPRINT("Pid %d in replay_getsockopt\n", current->pid);

  rc = get_next_syscall(55, &retparams);

  DPRINT("Pid %d, replay_getsockopt, rc is %ld, retparams is %p\n", current->pid, rc, retparams);

  if (retparams)
  {
    struct getsockopt_retvals *retvals = (struct getsockopt_retvals *) retparams;

    if (copy_to_user((char *) optval, &retvals->optval, retvals->optlen))
    {
      TPRINT("Pid %d cannot copy optval to user\n", current->pid);
    }

    if (copy_to_user((char *) optlen, &retvals->optlen, sizeof(int)))
    {
      TPRINT("Pid %d cannot copy optlen to user\n", current->pid);
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct getsockopt_retvals) + retvals->optlen);
  }
  return rc;
}

asmlinkage long shim_socket(int family, int type, int protocol)
SHIM_CALL_MAIN(41, record_socket(family, type, protocol), replay_socket(family, type, protocol), theia_sys_socket(family, type, protocol))

asmlinkage long shim_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
SHIM_CALL_MAIN(42, record_connect(fd, uservaddr, addrlen), replay_connect(fd, uservaddr, addrlen), theia_sys_connect(fd, uservaddr, addrlen))

asmlinkage long shim_accept(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen)
SHIM_CALL_MAIN(43, record_accept(fd, upeer_sockaddr, upeer_addrlen), replay_accept(fd, upeer_sockaddr, upeer_addrlen), theia_sys_accept(fd, upeer_sockaddr, upeer_addrlen))

asmlinkage long shim_sendto(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user *addr, int addr_len)
SHIM_CALL_MAIN(44, record_sendto(fd, buff, len, flags, addr, addr_len), replay_sendto(fd, buff, len, flags, addr, addr_len), theia_sys_sendto(fd, buff, len, flags, addr, addr_len))

asmlinkage long shim_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len)
SHIM_CALL_MAIN(45, record_recvfrom(fd, ubuf, size, flags, addr, addr_len), replay_recvfrom(fd, ubuf, size, flags, addr, addr_len), theia_sys_recvfrom(fd, ubuf, size, flags, addr, addr_len))

asmlinkage long shim_sendmsg(int fd, struct msghdr __user *msg, unsigned int flags)
SHIM_CALL_MAIN(46, record_sendmsg(fd, msg, flags), replay_sendmsg(fd, msg, flags), theia_sys_sendmsg(fd, msg, flags))

asmlinkage long shim_recvmsg(int fd, struct msghdr __user *msg, unsigned int flags)
SHIM_CALL_MAIN(47, record_recvmsg(fd, msg, flags), replay_recvmsg(fd, msg, flags), theia_sys_recvmsg(fd, msg, flags))

asmlinkage long shim_shutdown(int fd, int how)
SHIM_CALL_MAIN(48, record_shutdown(fd, how), replay_shutdown(fd, how), theia_sys_shutdown(fd, how))

asmlinkage long shim_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
SHIM_CALL_MAIN(49, record_bind(fd, umyaddr, addrlen), replay_bind(fd, umyaddr, addrlen), theia_sys_bind(fd, umyaddr, addrlen))

asmlinkage long shim_listen(int fd, int backlog)
SHIM_CALL_MAIN(50, record_listen(fd, backlog), replay_listen(fd, backlog), theia_sys_listen(fd, backlog))

asmlinkage long shim_getsockname(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
SHIM_CALL_MAIN(51, record_getsockname(fd, usockaddr, usockaddr_len), replay_getsockname(fd, usockaddr, usockaddr_len), theia_sys_getsockname(fd, usockaddr, usockaddr_len))

asmlinkage long shim_getpeername(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
SHIM_CALL_MAIN(52, record_getpeername(fd, usockaddr, usockaddr_len), replay_getpeername(fd, usockaddr, usockaddr_len), theia_sys_getpeername(fd, usockaddr, usockaddr_len))

asmlinkage long shim_socketpair(int family, int type, int protocol, int __user *usockvec)
SHIM_CALL_MAIN(53, record_socketpair(family, type, protocol, usockvec), replay_socketpair(family, type, protocol, usockvec), theia_sys_socketpair(family, type, protocol, usockvec))

asmlinkage long shim_setsockopt(int fd, int level, int optname, char __user *optval, int optlen)
SHIM_CALL_MAIN(54, record_setsockopt(fd, level, optname, optval, optlen), replay_setsockopt(fd, level, optname, optval, &optlen), theia_sys_setsockopt(fd, level, optname, optval, optlen))

asmlinkage long shim_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen)
SHIM_CALL_MAIN(55, record_getsockopt(fd, level, optname, optval, optlen), replay_getsockopt(fd, level, optname, optval, optlen), theia_sys_getsockopt(fd, level, optname, optval, optlen))

asmlinkage long shim_accept4(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags)
SHIM_CALL_MAIN(288, record_accept4(fd, upeer_sockaddr, upeer_addrlen, flags), replay_accept4(fd, upeer_sockaddr, upeer_addrlen, flags), theia_sys_accept4(fd, upeer_sockaddr, upeer_addrlen, flags))


static asmlinkage long
record_syslog(int type, char __user *buf, int len)
{
  char *recbuf = NULL;
  long rc;

  new_syscall_enter(103);
  rc = sys_syslog(type, buf, len);
  new_syscall_done(103, rc);
  if (rc > 0 && (type >= 2 && type <= 4))
  {
    recbuf = ARGSKMALLOC(rc, GFP_KERNEL);
    if (recbuf == NULL)
    {
      TPRINT("record_syslog: can't allocate return buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(recbuf, buf, rc))
    {
      TPRINT("record_syslog: faulted on readback\n");
      ARGSKFREE(recbuf, rc);
      return -EFAULT;
    }
  }
  new_syscall_exit(103, recbuf);

  return rc;
}

RET1_COUNT_REPLAY(syslog, 103, buf, int type, char __user *buf, int len);

asmlinkage long shim_syslog(int type, char __user *buf, int len) SHIM_CALL(syslog, 103, type, buf, len);

RET1_SHIM3(setitimer, 38, struct itimerval, ovalue, int, which, struct itimerval __user *, value, struct itimerval __user *, ovalue);
RET1_SHIM2(getitimer, 36, struct itimerval, value, int, which, struct itimerval __user *, value);
RET1_SHIM1(uname, 63, struct old_utsname, name, struct old_utsname __user *, name);
// I believe ptregs_iopl is deterministic, so don't intercept it
SIMPLE_SHIM0(vhangup, 153);
// I believe vm86old is deterministic, so don't intercept it

/* modify_ldt 154 */

struct wait4_retvals
{
  int           stat_addr;
  struct rusage ru;
};

static asmlinkage long
record_wait4(pid_t upid, int __user *stat_addr, int options, struct rusage __user *ru)
{
  long rc;
  struct wait4_retvals *retvals = NULL;

  new_syscall_enter(61);
  rc = sys_wait4(upid, stat_addr, options, ru);
  new_syscall_done(61, rc);
  if (rc >= 0)
  {
    retvals = ARGSKMALLOC(sizeof(struct wait4_retvals), GFP_KERNEL);
    if (retvals == NULL)
    {
      TPRINT("record_wait4: can't allocate buffer\n");
      return -ENOMEM;
    }

    if (stat_addr)
    {
      if (copy_from_user(&retvals->stat_addr, stat_addr, sizeof(int)))
      {
        TPRINT("record_wait4: unable to copy status from user\n");
        ARGSKFREE(retvals, sizeof(struct wait4_retvals));
        return -EFAULT;
      }
    }
    if (ru)
    {
      if (copy_from_user(&retvals->ru, ru, sizeof(struct rusage)))
      {
        TPRINT("record_wait4: unable to copy rusage from user\n");
        ARGSKFREE(retvals, sizeof(struct wait4_retvals));
        return -EFAULT;
      }
    }
  }
  new_syscall_exit(61, retvals);

  return rc;
}

static asmlinkage long
replay_wait4(pid_t upid, int __user *stat_addr, int options, struct rusage __user *ru)
{
  struct wait4_retvals *pretvals;
  long rc = get_next_syscall(61, (char **) &pretvals);
  if (pretvals)
  {
    if (stat_addr)
    {
      if (copy_to_user(stat_addr, &pretvals->stat_addr, sizeof(int)))
      {
        TPRINT("Pid %d replay_wait4 cannot copy status to user\n", current->pid);
        return syscall_mismatch();
      }
    }
    if (ru)
    {
      if (copy_to_user(ru, &pretvals->ru, sizeof(struct rusage)))
      {
        TPRINT("Pid %d replay_wait4 cannot copy status to user\n", current->pid);
        return syscall_mismatch();
      }
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct wait4_retvals));
  }
  return rc;
}

asmlinkage long shim_wait4(pid_t upid, int __user *stat_addr, int options, struct rusage __user *ru) SHIM_CALL(wait4, 61, upid, stat_addr, options, ru);

SIMPLE_SHIM1(swapoff, 168, const char __user *, specialfile);
RET1_SHIM1(sysinfo, 99, struct sysinfo, info, struct sysinfo __user *, info);

struct shmget_ahgv
{
  int pid;
  long  rc;
  int key;
  u_long  size;
  int shmflg;
};

void packahgv_shmget(struct shmget_ahgv *sys_args)
{
  int size = 0;

  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    get_curr_time(&sec, &nsec);

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif
    size = snprintf(buf, THEIA_KMEM_SIZE-1, 
              "startahg|%d|%d|%d|%ld|%ld|%d|%lu|%d|%d|%ld|%ld|%u|endahg\n",
                   29, SHMGET, sys_args->pid, current->start_time.tv_sec,
                   sys_args->rc, sys_args->key, sys_args->size, sys_args->shmflg,
                   current->tgid, sec, nsec, current->no_syscalls++);
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
    kmem_cache_free(theia_buffers, buf);
  }
}

void theia_shmget_ahg(long rc, key_t key, size_t size, int flag)
{
  struct shmget_ahgv *pahgv_shmget = NULL;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv_shmget = (struct shmget_ahgv *)KMALLOC(sizeof(struct shmget_ahgv), GFP_KERNEL);
  if (pahgv_shmget == NULL)
  {
    TPRINT("theia_shmget_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv_shmget->pid = current->pid;
  pahgv_shmget->rc = rc;
  pahgv_shmget->key = key;
  pahgv_shmget->size = size;
  pahgv_shmget->shmflg = flag;
  packahgv_shmget(pahgv_shmget);
  KFREE(pahgv_shmget);
}

int theia_sys_shmget(key_t key, size_t size, int flag)
{
  long rc;

  rc = sys_shmget(key, size, flag);

  theia_shmget_ahg(rc, key, size, flag);

  return rc;
}

static asmlinkage long
record_shmget(key_t key, size_t size, int flag)
{
  char *pretval = NULL;
  long rc;

  new_syscall_enter(29);
  rc = sys_shmget(key, size, flag);

  theia_shmget_ahg(rc, key, size, flag);

  new_syscall_done(29, rc);

  new_syscall_exit(29, pretval);
  return rc;
}

static asmlinkage long
replay_shmget(key_t key, size_t size, int flag)
{
  char *retparams;
  long retval;
  long rc = get_next_syscall(29, (char **) &retparams);

  retval = sys_shmget(key, size, flag);
  if ((rc < 0 && retval >= 0) || (rc >= 0 && retval < 0))
  {
    TPRINT("Pid %d replay_ipc SHMGET, on record we got %ld, but replay we got %ld\n", current->pid, rc, retval);
    return syscall_mismatch();
  }

  // put a mapping from the re-run replay identifier (pseudo), to the record one
  if (add_sysv_mapping(current->replay_thrd, rc, retval))
  {
    TPRINT("Pid %d replay_ipc SHMGET, could not add replay identifier mapping, replay: %ld, record %ld\n", current->pid, retval, rc);
    return syscall_mismatch();
  }

  return rc;
}

asmlinkage long shim_shmget(key_t key, size_t size, int flag)
SHIM_CALL_MAIN(29, record_shmget(key, size, flag),
               replay_shmget(key, size, flag),
               theia_sys_shmget(key, size, flag))

struct shmat_ahgv
{
  int   pid;
  long    rc;
  int   shmid;
  void __user *shmaddr;
  int     shmflg;
  u_long    raddr;
  struct file *file;
};

void packahgv_shmat(struct shmat_ahgv *sys_args)
{
  int size = 0;
  char uuid_str[THEIA_UUID_LEN + 1];

  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    unsigned long shm_segsz = 0;
    get_curr_time(&sec, &nsec);

    shm_segsz = get_shm_segsz(sys_args->shmid);

#ifdef THEIA_UUID
    if (file2uuid(sys_args->file, uuid_str, -1) == false)
      goto err; /* no file, socket, ...? */

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%d|%ld|%s|%lx|%d|%lu|%d|%lx|%lx|%d|%ld|%ld|%u|endahg\n",
                   30, SHMAT, sys_args->pid, current->start_time.tv_sec, uuid_str,
                   sys_args->rc, sys_args->shmid, (unsigned long)sys_args->shmaddr, sys_args->shmflg,
                   shm_segsz, sys_args->raddr, current->tgid, sec, nsec, current->no_syscalls++);
#else
    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%d|%ld|%lx|%d|%lu|%d|%lx|%lx|%d|%ld|%ld|%u|endahg\n",
                   30, SHMAT, sys_args->pid, current->start_time.tv_sec,
                   sys_args->rc, sys_args->shmid, sys_args->shmaddr, sys_args->shmflg,
                   shm_segsz, sys_args->raddr, current->tgid, sec, nsec, current->no_syscalls++);
#endif
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
err:
    kmem_cache_free(theia_buffers, buf);
  }
}

void theia_shmat_ahg(long rc, int shmid, char __user *shmaddr, int shmflg, struct file *file)
{
  unsigned long raddr;
  struct shmat_ahgv *pahgv_shmat = NULL;

  get_user(raddr, (unsigned long __user *) rc);

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();


  pahgv_shmat = (struct shmat_ahgv *)KMALLOC(sizeof(struct shmat_ahgv), GFP_KERNEL);
  if (pahgv_shmat == NULL)
  {
    TPRINT("theia_shmat_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv_shmat->pid = current->pid;
  pahgv_shmat->rc = rc;
  pahgv_shmat->raddr = raddr;
  pahgv_shmat->shmid = shmid;
  pahgv_shmat->shmaddr = shmaddr;
  pahgv_shmat->shmflg = shmflg;
  pahgv_shmat->file = file;
  packahgv_shmat(pahgv_shmat);
  KFREE(pahgv_shmat);
}

long theia_sys_shmat(int shmid, char __user *shmaddr, int shmflg)
{
  long rc;
  unsigned long raddr;
  struct shmid_kernel *shp;
  u_long size;
  struct ipc_namespace *ns;
  struct kern_ipc_perm *ipcp;

  rc = sys_shmat(shmid, shmaddr, shmflg);
  ns = current->nsproxy->ipc_ns;

  get_user(raddr, (unsigned long __user *) rc);


  if (theia_logging_toggle == 0)
    return rc;

  ipcp = ipc_lock(&ns->ids[IPC_SHM_IDS], shmid);
  if (IS_ERR(ipcp))
  {
    TPRINT("theia_sys_shmat: cannot lock ipc for shmat\n");
    return -EINVAL;
  }
  shp = container_of(ipcp, struct shmid_kernel, shm_perm);
  size = shp->shm_segsz;
  ipc_unlock(&shp->shm_perm);

  theia_shmat_ahg(rc, shmid, shmaddr, shmflg, shp->shm_file);

#ifdef THEIA_TRACK_SHMAT
  int ret = 0;
  ret = sys_mprotect(raddr, size, PROT_NONE);
  int __user *address = NULL;
  int np = size / 0x1000;
  if (size % 0x1000) ++np;
  if (!ret)
  {
    int i;
    for (i = 0; i < np; ++i)
    {
      address = (int __user *)(raddr + i * 0x1000);
      *address = *address;
    }

    ret = sys_mprotect(rc, size, PROT_NONE);
    //    TPRINT("protection of a shared page will be changed, ret %d, %d\n", ret, np);
  }
#endif
  return rc;
}

static asmlinkage long
record_shmat(int shmid, char __user *shmaddr, int shmflg)
{
  char *pretval = NULL;
  long rc;
  unsigned long raddr;
  struct shmid_kernel *shp;
  struct ipc_namespace *ns;
  struct kern_ipc_perm *ipcp;

  new_syscall_enter(30);
  rc = sys_shmat(shmid, shmaddr, shmflg);

  get_user(raddr, (unsigned long __user *) rc);
  ns = current->nsproxy->ipc_ns;
  get_user(raddr, (unsigned long __user *) rc);


  if (theia_logging_toggle == 0)
    return rc;

  ipcp = ipc_lock(&ns->ids[IPC_SHM_IDS], shmid);
  if (IS_ERR(ipcp))
  {
    TPRINT("theia_sys_shmat: cannot lock ipc for shmat\n");
    return -EINVAL;
  }
  shp = container_of(ipcp, struct shmid_kernel, shm_perm);
  ipc_unlock(&shp->shm_perm);

  theia_shmat_ahg(rc, shmid, shmaddr, shmflg, shp->shm_file);

  new_syscall_done(30, rc);

  if (rc >= 0)
  {
    struct shmat_retvals *patretval;
    struct shmid_kernel *shp;
    u_long size;
    struct ipc_namespace *ns = current->nsproxy->ipc_ns;
    struct kern_ipc_perm *ipcp;

    // Need to get size in case we need to attach PIN on replay
    ipcp = ipc_lock(&ns->ids[IPC_SHM_IDS], shmid);
    if (IS_ERR(ipcp))
    {
      TPRINT("record_shmat: cannot lock ipc for shmat\n");
      return -EINVAL;
    }
    shp = container_of(ipcp, struct shmid_kernel, shm_perm);
    size = shp->shm_segsz;
    ipc_unlock(&shp->shm_perm);

    pretval = ARGSKMALLOC(sizeof(struct shmat_retvals), GFP_KERNEL);
    patretval = (struct shmat_retvals *) pretval;
    if (patretval == NULL)
    {
      TPRINT("record_shmat(shmat) can't allocate buffer\n");
      return -ENOMEM;
    }
    patretval->len = sizeof(struct shmat_retvals) - sizeof(u_long);
    patretval->call = SHMAT;
    patretval->size = size;
    patretval->raddr = raddr;

#ifdef THEIA_TRACK_SHMAT
    int ret = 0;
    ret = sys_mprotect(raddr, size, PROT_NONE);
    int __user *address = NULL;
    int np = size / 0x1000;
    if (size % 0x1000) ++np;
    if (!ret)
    {
      int i;
      for (i = 0; i < np; ++i)
      {
        address = (int __user *)(raddr + i * 0x1000);
        *address = *address;
      }

      ret = sys_mprotect(rc, size, PROT_NONE);
      //      TPRINT("protection of a shared page will be changed, ret %d, %d\n", ret, np);
    }
#endif

    if (current->record_thrd->rp_group->rg_save_mmap_flag)
    {
      MPRINT("Pid %d, shmat reserve memory %lx len %lx\n",
             current->pid,
             patretval->raddr, patretval->size);
      reserve_memory(patretval->raddr, patretval->size);
    }
  }

  new_syscall_exit(30, pretval);
  return rc;
}

static asmlinkage long
replay_shmat(int shmid, char __user *shmaddr, int shmflg)
{
  char *retparams;
  long retval;
  long rc = get_next_syscall(30, (char **) &retparams);
  int repid;

  if (rc > 0)
  {
    struct shmat_retvals *atretparams = (struct shmat_retvals *) retparams;

    if (current->replay_thrd->rp_record_thread->rp_group->rg_save_mmap_flag)
    {
      MPRINT("Pid %d, replay shmat reserve memory %lx len %lx\n",
             current->pid,
             atretparams->raddr, atretparams->size);
      reserve_memory(atretparams->raddr, atretparams->size);
    }

    // do_shmat checks to see if there are any existing mmaps in the region to be shmat'ed. So we'll have to munmap our preallocations for this region
    // before proceding.
    if (is_pin_attached())
    {
      struct sysv_shm *tmp;
      tmp = KMALLOC(sizeof(struct sysv_shm), GFP_KERNEL);
      if (tmp == NULL)
      {
        TPRINT("Pid %d: could not alllocate for sysv_shm\n", current->pid);
        return -ENOMEM;
      }
      tmp->addr = atretparams->raddr;
      tmp->len = atretparams->size;
      list_add(&tmp->list, &current->replay_thrd->rp_sysv_shms);

      MPRINT("  Pin is attached to pid %d - munmap preallocation before shmat at addr %lx size %lu\n", current->pid, atretparams->raddr, atretparams->size);
      retval = sys_munmap(atretparams->raddr, atretparams->size);
      if (retval) TPRINT("[WARN]Pid %d shmat failed to munmap the preallocation at addr %lx size %lu\n", current->pid, rc, atretparams->size);
    }

    // redo the mapping with at the same address returned during recording
    repid = find_sysv_mapping(current->replay_thrd, shmid);
    retval = sys_shmat(shmid, shmaddr, shmflg);
    if (retval != rc)
    {
      TPRINT("replay_ipc(shmat) returns different value %ld than %ld\n", retval, rc);
      return syscall_mismatch();
    }
    if (retval > 0)
    {
      u_long raddr;
      get_user(raddr, (unsigned long __user *) retval);
      TPRINT("Pid %d replays SHMAT success address %lx\n", current->pid, raddr);
      if (raddr != atretparams->raddr)
      {
        TPRINT("replay_ipc(shmat) returns different address %lx than %lx\n", raddr, atretparams->raddr);
      }
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct shmat_retvals));
  }
  return rc;
}

asmlinkage long shim_shmat(int shmid, char __user *shmaddr, int shmflg)
SHIM_CALL_MAIN(30, record_shmat(shmid, shmaddr, shmflg),
               replay_shmat(shmid, shmaddr, shmflg),
               theia_sys_shmat(shmid, shmaddr, shmflg))

static asmlinkage long
record_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
  char *pretval = NULL;
  u_long len = 0;
  long rc;

  new_syscall_enter(31);
  rc = sys_shmctl(shmid, cmd, buf);

  new_syscall_done(31, rc);

  if (rc >= 0)
  {
    (void)ipc_parse_version(&cmd);
    switch (cmd)
    {
      case IPC_STAT:
      case SHM_STAT:
        len = sizeof(struct shmid_ds);
        break;
      case IPC_INFO:
      case SHM_INFO:
        len = sizeof(struct shminfo);
        break;
    }
    if (len > 0)
    {
      pretval = ARGSKMALLOC(sizeof(u_long) + sizeof(int) + len, GFP_KERNEL);
      if (pretval == NULL)
      {
        TPRINT("record_shmctl: can't allocate return value\n");
        return -ENOMEM;
      }
      *((u_long *) pretval) = sizeof(int) + len;
      *((int *) pretval + sizeof(u_long)) = SHMCTL;
      if (copy_from_user(pretval + sizeof(u_long) + sizeof(int), buf, len))
      {
        TPRINT("record_shmctl: can't copy data from user\n");
        ARGSKFREE(pretval, sizeof(u_long) + sizeof(int) + len);
        return -EFAULT;
      }
    }
  }

  new_syscall_exit(31, pretval);
  return rc;
}

static asmlinkage long
replay_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
  char *retparams;
  long rc = get_next_syscall(31, (char **) &retparams);
  int repid;

  (void)ipc_parse_version(&cmd);
  switch (cmd)
  {
    case IPC_STAT:
    case IPC_INFO:
    case SHM_STAT:
    case SHM_INFO:
      if (retparams && buf)
      {
        u_long len = *((u_long *) retparams);
        if (copy_to_user(buf, retparams + sizeof(u_long) + sizeof(int), len - sizeof(int)))
        {
          TPRINT("replay_ipc (call %d): pid %d cannot copy to user\n", SHMCTL, current->pid);
          return syscall_mismatch();
        }
        argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
      }
      break;
    case IPC_RMID:
      repid = find_sysv_mapping(current->replay_thrd, shmid);
      return sys_shmctl(repid, cmd, buf);
  }

  return rc;
}

asmlinkage long shim_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
SHIM_CALL_MAIN(31, record_shmctl(shmid, cmd, buf),
               replay_shmctl(shmid, cmd, buf),
               sys_shmctl(shmid, cmd, buf))

SIMPLE_SHIM3(semget, 64, key_t, key, int, nsems, int, semflg);
SIMPLE_SHIM3(semop, 65, int, semid, struct sembuf __user *, sops, unsigned, nsops);

static asmlinkage long
record_semctl(int semid, int semnum, int cmd, union semun arg)
{
  mm_segment_t old_fs;
  char *pretval = NULL;
  u_long len = 0;
  long rc;

  new_syscall_enter(66);
  rc = sys_semctl(semid, semnum, cmd, arg);

  new_syscall_done(66, rc);
  if (rc >= 0)
  {
    switch (cmd)
    {
      case IPC_STAT:
      case MSG_STAT:
        len = sizeof(struct semid_ds);
        break;
      case IPC_INFO:
      case MSG_INFO:
        len = sizeof(struct seminfo);
        break;
      case GETALL:
      {
        union semun fourth;
        struct semid_ds info;
        fourth.buf = &info;
        old_fs = get_fs();
        set_fs(KERNEL_DS);
        sys_semctl(semid, semnum, IPC_STAT, fourth);
        set_fs(old_fs);
        len = info.sem_nsems * sizeof(u_short);
        break;
      }
    }
    if (len > 0)
    {
      pretval = ARGSKMALLOC(sizeof(u_long) + sizeof(int) + len, GFP_KERNEL);
      if (pretval == NULL)
      {
        TPRINT("record_ipc (semctl): can't allocate return value\n");
        return -ENOMEM;
      }
      *((u_long *) pretval) = sizeof(int) + len;
      *((int *) pretval + sizeof(u_long)) = SEMCTL;
      if (copy_from_user(pretval + sizeof(u_long) + sizeof(int), arg.buf, len))
      {
        ARGSKFREE(pretval, sizeof(u_long) + sizeof(int) + len);
        return -EFAULT;
      }
    }
  }
  new_syscall_exit(66, pretval);
  return rc;
}

static asmlinkage long
replay_semctl(int semid, int semnum, int cmd, union semun arg)
{
  char *retparams;
  long rc = get_next_syscall(66, (char **) &retparams);

  if (retparams && arg.buf)
  {
    u_long len = *((u_long *) retparams);
    if (copy_to_user(arg.buf, retparams + sizeof(u_long) + sizeof(int), len - sizeof(int)))
    {
      TPRINT("replay_ipc (call %d): pid %d cannot copy to user\n", SEMCTL, current->pid);
      return syscall_mismatch();
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
  }
  return rc;
}

asmlinkage long shim_semctl(int semid, int semnum, int cmd, union semun arg)
SHIM_CALL_MAIN(66, record_semctl(semid, semnum, cmd, arg),
               replay_semctl(semid, semnum, cmd, arg),
               sys_semctl(semid, semnum, cmd, arg))

SIMPLE_SHIM4(semtimedop, 220, int, semid, struct sembuf __user *, sops, unsigned, nsops, const struct timespec __user *, timeout);

static asmlinkage long
record_shmdt(char __user *shmaddr)
{
  long rc;

  new_syscall_enter(67);
  rc = sys_shmdt(shmaddr);
  new_syscall_done(67, rc);

  return rc;
}

static asmlinkage long
replay_shmdt(char __user *shmaddr)
{
  char *retparams;
  long retval;
  long rc = get_next_syscall(67, (char **) &retparams);

  retval = sys_shmdt(shmaddr);
  if (retval != rc)
  {
    TPRINT("replay_ipc(shmdt) returns different value %ld than %ld\n", retval, rc);
    return syscall_mismatch();
  }
  /*
   * For Pin support, we need to preallocate this again if this memory area that was just munmap'ed
   */
  if (!retval && is_pin_attached())
  {
    u_long size = 0;
    struct sysv_shm *tmp;
    struct sysv_shm *tmp_safe;
    list_for_each_entry_safe(tmp, tmp_safe, &current->replay_thrd->rp_sysv_shms, list)
    {
      if (tmp->addr == (u_long)shmaddr)
      {
        size = tmp->len;
        list_del(&tmp->list);
        KFREE(tmp);
      }
    }
    if (size == 0)
    {
      MPRINT("Pid %d replay shmdt: could not find shm %lx ???\n", current->pid, (u_long) shmaddr);
      syscall_mismatch();
    }

    MPRINT("Pid %d Remove shm at addr %lx, len %lx\n", current->pid, (u_long) shmaddr, size);
    preallocate_after_munmap((u_long) shmaddr, size);
  }

  return rc;
}

asmlinkage long shim_shmdt(char __user *shmaddr)
SHIM_CALL_MAIN(67, record_shmdt(shmaddr),
               replay_shmdt(shmaddr),
               sys_shmdt(shmaddr))

SIMPLE_SHIM2(msgget, 68, key_t, key, int, msgflg);
SIMPLE_SHIM4(msgsnd, 69, int, msqid, struct msgbuf __user *, msgp, size_t, msgsz, int, msgflg);

static asmlinkage long
record_msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg)
{
  char *pretval = NULL;
  long rc;

  new_syscall_enter(70);
  rc = sys_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg);
  new_syscall_done(70, rc);

  if (rc >= 0)
  {
    pretval = ARGSKMALLOC(sizeof(u_long) + sizeof(long) + rc, GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_ipc (msgrcv): can't allocate return value\n");
      return -ENOMEM;
    }
    *((u_long *) pretval) = sizeof(int) + sizeof(long) + rc;
    *((int *) pretval + sizeof(u_long)) = MSGRCV;
    if (copy_from_user(pretval + sizeof(u_long) + sizeof(int), msgp, sizeof(long) + rc))
    {
      ARGSKFREE(pretval, sizeof(u_long) + sizeof(int) + sizeof(long) + rc);
      return -EFAULT;
    }
  }
  new_syscall_exit(70, pretval);
  return rc;
}

static asmlinkage long
replay_msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg)
{
  char *retparams;
  long rc = get_next_syscall(70, (char **) &retparams);

  if (retparams && msgp)
  {
    u_long len = *((u_long *) retparams);
    if (copy_to_user(msgp, retparams + sizeof(u_long) + sizeof(int), len - sizeof(int)))
    {
      TPRINT("replay_ipc (call %d): pid %d cannot copy to user\n", MSGRCV, current->pid);
      return syscall_mismatch();
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
  }
  return rc;
}

asmlinkage long shim_msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg)
SHIM_CALL_MAIN(70, record_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg),
               replay_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg),
               sys_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg))

static asmlinkage long
record_msgctl(int msqid, int cmd, struct msqid_ds __user *buf)
{
  char *pretval = NULL;
  u_long len = 0;
  long rc;

  new_syscall_enter(71);
  rc = sys_msgctl(msqid, cmd, buf);

  new_syscall_done(71, rc);
  if (rc >= 0)
  {
    switch (cmd)
    {
      case IPC_STAT:
      case MSG_STAT:
        len = sizeof(struct msqid64_ds);
        break;
      case IPC_INFO:
      case MSG_INFO:
        len = sizeof(struct msginfo);
        break;

    }
    if (len > 0)
    {
      pretval = ARGSKMALLOC(sizeof(u_long) + sizeof(int) + len, GFP_KERNEL);
      if (pretval == NULL)
      {
        TPRINT("record_ipc (msgctl): can't allocate return value\n");
        return -ENOMEM;
      }
      *((u_long *) pretval) = sizeof(int) + len;
      *((int *) pretval + sizeof(u_long)) = MSGCTL;
      if (copy_from_user(pretval + sizeof(u_long) + sizeof(int), buf, len))
      {
        ARGSKFREE(pretval, sizeof(u_long) + sizeof(int) + len);
        return -EFAULT;
      }
    }
  }
  new_syscall_exit(71, pretval);
  return rc;
}

static asmlinkage long
replay_msgctl(int msqid, int cmd, struct msqid_ds __user *buf)
{
  char *retparams;
  long rc = get_next_syscall(71, (char **) &retparams);

  if (retparams && buf)
  {
    u_long len = *((u_long *) retparams);
    if (copy_to_user(buf, retparams + sizeof(u_long) + sizeof(int), len - sizeof(int)))
    {
      TPRINT("replay_ipc (call %d): pid %d cannot copy to user\n", MSGCTL, current->pid);
      return syscall_mismatch();
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
  }
  return rc;
}

asmlinkage long shim_msgctl(int msqid, int cmd, struct msqid_ds __user *buf)
SHIM_CALL_MAIN(71, record_msgctl(msqid, cmd, buf),
               replay_msgctl(msqid, cmd, buf),
               sys_msgctl(msqid, cmd, buf))

//Yang: for now, we only handle shmget, shmat
void theia_ipc_ahg(long rc, uint call, int first, u_long second,
                   u_long third, void __user *ptr, long fifth)
{

  struct shmget_ahgv *pahgv_shmget = NULL;
  struct shmat_ahgv *pahgv_shmat = NULL;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  // Yang: regardless of the return value, passes the failed syscall also
  switch (call)
  {
    case SHMGET:
      pahgv_shmget = (struct shmget_ahgv *)KMALLOC(sizeof(struct shmget_ahgv), GFP_KERNEL);
      if (pahgv_shmget == NULL)
      {
        TPRINT("theia_shmget_ahg: failed to KMALLOC.\n");
        return;
      }
      pahgv_shmget->pid = current->pid;
      pahgv_shmget->rc = rc;
      pahgv_shmget->key = first;
      pahgv_shmget->size = second;
      pahgv_shmget->shmflg = third;
      packahgv_shmget(pahgv_shmget);
      KFREE(pahgv_shmget);
      break;
    case SHMAT:
      pahgv_shmat = (struct shmat_ahgv *)KMALLOC(sizeof(struct shmat_ahgv), GFP_KERNEL);
      if (pahgv_shmat == NULL)
      {
        TPRINT("theia_shmat_ahg: failed to KMALLOC.\n");
        return;
      }
      pahgv_shmat->pid = current->pid;
      pahgv_shmat->rc = rc;
      pahgv_shmat->raddr = third;
      pahgv_shmat->shmid = first;
      pahgv_shmat->shmaddr = ptr;
      pahgv_shmat->shmflg = second;
      packahgv_shmat(pahgv_shmat);
      KFREE(pahgv_shmat);
      break;
    default:
      break;
  }
}



SIMPLE_SHIM1(fsync, 74, unsigned int, fd);

//64port
//unsigned long dummy_sigreturn(struct pt_regs *regs); /* In arch/x86/kernel/signal.c */
long dummy_rt_sigreturn(struct pt_regs *regs); /* In arch/x86/kernel/signal.c */

long shim_sigreturn(struct pt_regs *regs)
{
  if (current->record_thrd)
  {
    struct repsignal_context *pcontext = current->record_thrd->rp_repsignal_context_stack;
    if (pcontext)
    {
      if (current->record_thrd->rp_ignore_flag_addr) put_user(pcontext->ignore_flag, current->record_thrd->rp_ignore_flag_addr);
      current->record_thrd->rp_repsignal_context_stack = pcontext->next;
      KFREE(pcontext);
    }
    else
    {
      TPRINT("Pid %d does sigreturn but no context???\n", current->pid);
    }
  }

  //return dummy_sigreturn(regs);
  //64port
  return dummy_rt_sigreturn(regs);
}

static long
record_clone(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
  struct pthread_log_head __user *phead = NULL;
#ifdef USE_DEBUG_LOG
  struct pthread_log_data __user *start, *old_start = NULL;
#else
  char __user *start, *old_start = NULL;
  u_long old_expected_clock, old_num_expected_records;
#endif
#ifdef USE_EXTRA_DEBUG_LOG
  struct pthread_extra_log_head __user *pehead = NULL;
  char __user *estart, *old_estart = NULL;
#endif
  struct record_group *prg;
  struct task_struct *tsk;
  long rc;
  void *slab;

  prg = current->record_thrd->rp_group;

  new_syscall_enter(56);

  if (!(clone_flags & CLONE_VM))
  {
    /* The intent here is to change the next pointer for the child - the easiest way to do this is to change
       the parent, fork, and then revert the parent */
    phead = (struct pthread_log_head __user *) current->record_thrd->rp_user_log_addr;
#ifdef USE_DEBUG_LOG
    start = (struct pthread_log_data __user *)((char __user *) phead + sizeof(struct pthread_log_head));
#else
    start = (char __user *) phead + sizeof(struct pthread_log_head);
#endif
    get_user(old_start, &phead->next);
    put_user(start, &phead->next);
#ifdef USE_EXTRA_DEBUG_LOG
    pehead = (struct pthread_extra_log_head __user *) current->record_thrd->rp_user_extra_log_addr;
    estart = (char __user *) pehead + sizeof(struct pthread_extra_log_head);
    get_user(old_estart, &pehead->next);
    put_user(estart, &pehead->next);
#endif

#ifndef USE_DEBUG_LOG
    get_user(old_expected_clock, &phead->expected_clock);
    put_user(0, &phead->expected_clock);
    get_user(old_num_expected_records, &phead->num_expected_records);
    put_user(0, &phead->num_expected_records);
#endif
  }

  rc = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
  MPRINT("Pid %d records clone with flags %lx fork %d returning %ld\n", current->pid, clone_flags, (clone_flags & CLONE_VM) ? 0 : 1, rc);

  rg_lock(prg);
  new_syscall_done(56, rc);
  new_syscall_exit(56, NULL);

  if (rc > 0)
  {
    // Create a record thread struct for the child
    tsk = pid_task(find_vpid(rc), PIDTYPE_PID);
    if (tsk == NULL)
    {
      TPRINT("record_clone: cannot find child\n");
      rg_unlock(prg);
      return -ECHILD;
    }

#ifdef CACHE_READS
    if (clone_flags & CLONE_FILES)
    {
      // file descriptor table is shared so share handles to clone files
      tsk->record_thrd = new_record_thread(prg, tsk->pid, current->record_thrd->rp_cache_files);
    }
    else
    {
#endif
      tsk->record_thrd = new_record_thread(prg, tsk->pid, NULL);
#ifdef CACHE_READS
      copy_record_cache_files(current->record_thrd->rp_cache_files, tsk->record_thrd->rp_cache_files);
    }
#endif
    if (tsk->record_thrd == NULL)
    {
      rg_unlock(prg);
      return -ENOMEM;
    }
    tsk->replay_thrd = NULL;

    tsk->record_thrd->rp_next_thread = current->record_thrd->rp_next_thread;
    current->record_thrd->rp_next_thread = tsk->record_thrd;

    if (!(clone_flags & CLONE_VM))
    {
      tsk->record_thrd->rp_user_log_addr = current->record_thrd->rp_user_log_addr;
      tsk->record_thrd->rp_ignore_flag_addr = current->record_thrd->rp_ignore_flag_addr;
      put_user(old_start, &phead->next);
#ifdef USE_EXTRA_DEBUG_LOG
      tsk->record_thrd->rp_user_extra_log_addr = current->record_thrd->rp_user_extra_log_addr;
      put_user(old_estart, &pehead->next);
#endif
#ifndef USE_DEBUG_LOG
      put_user(old_expected_clock, &phead->expected_clock);
      put_user(old_num_expected_records, &phead->num_expected_records);
#endif
    }

    // allocate a slab for retparams
    slab = VMALLOC(argsalloc_size);
    if (slab == NULL) return -ENOMEM;
    if (add_argsalloc_node(tsk->record_thrd, slab, argsalloc_size))
    {
      VFREE(slab);
      TPRINT("Pid %d fork_replay: error adding argsalloc_node\n", current->pid);
      return -ENOMEM;
    }
#ifdef LOG_COMPRESS_1
    // xdou: inherit the parent's fd table and pipe table
    pipe_fds_copy(&tsk->record_thrd->rp_clog.pfds, &current->record_thrd->rp_clog.pfds);
    slab = VMALLOC(argsalloc_size);
    if (slab == NULL) return -ENOMEM;
    if (add_clog_node(tsk->record_thrd, slab, argsalloc_size))
    {
      VFREE(slab);
      TPRINT("Pid %d fork_replay: error adding clog_node\n", current->pid);
      return -ENOMEM;
    }
#endif

    MPRINT("Pid %d records clone returning Record Pid-%d, tsk %p, prp %p\n", current->pid, tsk->pid, tsk, tsk->record_thrd);

    // Now wake up the thread
    wake_up_new_task(tsk);
  }
  rg_unlock(prg);

  return rc;
}

static long
replay_clone(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
  struct task_struct *tsk = NULL;
  struct replay_group *prg;
  struct replay_thread *prept;
  long rc;
  pid_t pid;
  ds_list_iter_t *iter;
  struct record_thread *prt;
  struct syscall_result *psr;

  prg = current->replay_thrd->rp_group;

  MPRINT("Pid %d replay_clone with flags %lx\n", current->pid, clone_flags);
  if (is_pin_attached())
  {
    rc = current->replay_thrd->rp_saved_rc;
    (*(int *)(current->replay_thrd->app_syscall_addr)) = 999;
    TPRINT("[%s|%d] pid %d, prt->app_syscall_addr is set to 999\n", __func__, __LINE__, current->pid);
  }
  else
  {
    rc = get_next_syscall_enter(current->replay_thrd, prg, 56, NULL, &psr);
  }

  if (rc > 0)
  {
    // We need to keep track of whether or not a signal was attached
    // to this system call; sys_clone will clear the flag
    // so we need to be able to set it again at the end of the syscall
    int rp_sigpending = test_thread_flag(TIF_SIGPENDING);

    // We also need to create a clone here
    pid = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
    MPRINT("Pid %d in replay clone spawns child %d\n", current->pid, pid);
    if (pid < 0)
    {
      TPRINT("[DIFF]replay_clone: second clone failed, rc=%d\n", pid);
      return syscall_mismatch();
    }
    tsk = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!tsk)
    {
      TPRINT("[DIFF]replay_clone: cannot find replaying Pid %d\n", pid);
      return -EINVAL;
    }

    // Attach the replay thread struct to the child
    rg_lock(prg->rg_rec_group);

    /* Find the corresponding record thread based on pid.
     * We used to find the last prt with replay_pid == 0,
     * but it fails if child thread spawns another child thread.
     * We should not assume that there is only one thread that
     * spawns other threads.
    */
    for (prt = current->replay_thrd->rp_record_thread->rp_next_thread;
         prt != current->replay_thrd->rp_record_thread; prt = prt->rp_next_thread)
    {
      if (prt->rp_record_pid == rc)
      {
        DPRINT("Pid %d find replay_thrd %p (rec_pid=%d,rep_pid=%d)\n", current->pid, prt, prt->rp_record_pid, pid);
        break;
      }
    }


    // if Pin is attached the record_thread could already exist (via preallocate_mem) so we need to check
    // to see if it exists first before creating
    if (prt == NULL || prt->rp_record_pid != rc)
    {
      /* For replays resumed form disk checkpoint, there will be no record thread.  We should create it here. */
      prt = new_record_thread(prg->rg_rec_group, rc, NULL);
      // Since there is no recording going on, we need to dec record_thread's refcnt
      atomic_dec(&prt->rp_refcnt);
      DPRINT("Created new record thread %p\n", prt);
    }

    /* Ensure that no replay thread in this replay group points to this record thread */
    iter = ds_list_iter_create(prg->rg_replay_threads);
    while ((prept = ds_list_iter_next(iter)) != NULL)
    {
      if (prept->rp_record_thread == prt)
      {
        TPRINT("[DIFF]replay_clone: record thread already cloned?\n");
        ds_list_iter_destroy(iter);
        rg_unlock(prg->rg_rec_group);
        return syscall_mismatch();
      }
    }
    ds_list_iter_destroy(iter);

    /* Update our replay_thrd with this information */
    tsk->record_thrd = NULL;
    DPRINT("Cloning new replay thread\n");
#ifdef CACHE_READS
    if (clone_flags & CLONE_FILES)
    {
      // file descriptor table is shared so share handles to clone files
      tsk->replay_thrd = new_replay_thread(prg, prt, pid, 0, current->replay_thrd->rp_cache_files);
    }
    else
    {
#endif
      tsk->replay_thrd = new_replay_thread(prg, prt, pid, 0, NULL);
#ifdef CACHE_READS
      copy_replay_cache_files(current->replay_thrd->rp_cache_files, tsk->replay_thrd->rp_cache_files);
    }
#endif
    BUG_ON(!tsk->replay_thrd);

    // inherit the parent's app_syscall_addr
    tsk->replay_thrd->app_syscall_addr = current->replay_thrd->app_syscall_addr;

    MPRINT("Pid %d, tsk->pid %d refcnt for replay thread %p now %d\n", current->pid, tsk->pid, tsk->replay_thrd,
           atomic_read(&tsk->replay_thrd->rp_refcnt));
    MPRINT("Pid %d, tsk->pid %d refcnt for record thread pid %d now %d\n", current->pid, tsk->pid, prt->rp_record_pid,
           atomic_read(&prt->rp_refcnt));


    // Fix up the circular thread list
    tsk->replay_thrd->rp_next_thread = current->replay_thrd->rp_next_thread;
    current->replay_thrd->rp_next_thread = tsk->replay_thrd;

    // Fix up parent_tidptr to match recorded pid
    if (clone_flags & CLONE_PARENT_SETTID)
    {
      int nr = rc;
      put_user(nr, parent_tidptr);
    }

    if (!(clone_flags & CLONE_VM))
    {
      DPRINT("This is a fork-style clone - reset the user log appropriately\n");
      tsk->replay_thrd->rp_record_thread->rp_user_log_addr = current->replay_thrd->rp_record_thread->rp_user_log_addr;
#ifdef USE_EXTRA_DEBUG_LOG
      tsk->replay_thrd->rp_record_thread->rp_user_extra_log_addr = current->replay_thrd->rp_record_thread->rp_user_extra_log_addr;
#endif
      tsk->replay_thrd->rp_record_thread->rp_ignore_flag_addr = current->replay_thrd->rp_record_thread->rp_ignore_flag_addr;
    }

    // read the rest of the log
    read_log_data(tsk->replay_thrd->rp_record_thread);
#ifdef LOG_COMPRESS_1
    // xdou: inherit the parent's fd table and pipe table
    // this could be wrong if we have several replay_group ?
    pipe_fds_copy(&tsk->replay_thrd->rp_record_thread->rp_clog.pfds, &current->replay_thrd->rp_record_thread->rp_clog.pfds);
    read_clog_data(tsk->replay_thrd->rp_record_thread);
#endif

    prept = current->replay_thrd;
    tsk->replay_thrd->rp_status = REPLAY_STATUS_ELIGIBLE; // This lets the parent run first - will this make Pin happy?
    //    tsk->thread.ip = (u_long) ret_from_fork_2;
    //KSTK_EIP(tsk) = (u_long) ret_from_fork_2;
    set_tsk_thread_flag(tsk, TIF_FORK_2);

    rg_unlock(prg->rg_rec_group);

    // Now wake up the new thread and wait
    wake_up_new_task(tsk);

    // see above
    if (rp_sigpending)
    {
      DPRINT("Pid %d sig was pending in clone!\n", current->pid);
      signal_wake_up(current, 0);
    }
  }

  if (current->replay_thrd->app_syscall_addr == 0)
  {
    get_next_syscall_exit(current->replay_thrd, prg, psr);
  }

  if (rc > 0 && (clone_flags & CLONE_VM) && is_pin_attached())
  {
    MPRINT("Return real child pid %d to Pin instead of recorded child pid %ld\n", tsk->pid, rc);
    return tsk->pid;
  }

  return rc;
}

struct clone_ahgv
{
  int             pid;
  int             new_pid;
};

void packahgv_clone(struct clone_ahgv *sys_args)
{
  struct task_struct *tsk;
  int size = 0;
  int is_child_remote = 0;

  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    char ids[IDS_LEN+1];
    get_ids(ids);
    get_curr_time(&sec, &nsec);
    tsk = pid_task(find_vpid(sys_args->new_pid), PIDTYPE_PID);

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    if (tsk)
    {
      is_child_remote = is_remote(tsk);
      size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%s|%d|%li|%d|%d|%ld|%ld|%u|endahg\n",
                     56, sys_args->pid, current->start_time.tv_sec, ids, sys_args->new_pid,
                     tsk->start_time.tv_sec, is_child_remote, current->tgid, sec, nsec, current->no_syscalls++);
    }
    else
    {
      size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%s|%d|%ld|%d|%d|%ld|%ld|%u|endahg\n",
                     56, sys_args->pid, current->start_time.tv_sec, ids, sys_args->new_pid,
                     (long) - 1, -1, current->tgid, sec, nsec, current->no_syscalls++);
    }
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
    kmem_cache_free(theia_buffers, buf);
  }
}

void theia_clone_ahg(long new_pid)
{
  struct clone_ahgv *pahgv = NULL;
  struct task_struct *new_tsk;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  rcu_read_lock();
  new_tsk = find_task_by_vpid(new_pid);
  rcu_read_unlock();
  if (new_tsk)
  {
    if (is_process_new2(new_tsk->pid, new_tsk->start_time.tv_sec))
      packahgv_process(new_tsk);
  }

  if (new_pid >= 0)
  {
    pahgv = (struct clone_ahgv *)KMALLOC(sizeof(struct clone_ahgv), GFP_KERNEL);
    if (pahgv == NULL)
    {
      TPRINT("theia_clone_ahg: failed to KMALLOC.\n");
      return;
    }
    pahgv->pid = current->pid;
    pahgv->new_pid = (int)new_pid;
    packahgv_clone(pahgv);
    KFREE(pahgv);
  }
}

int theia_sys_clone(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
  long rc;
  char *fpathbuf = NULL;
  char *fpath = NULL;
  struct task_struct *child;

  rc = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  {
    theia_clone_ahg(rc); //now we only need the new pid
  }

  /* parent */
  if (rc > 0) {
    if (current->is_remote == 0) {
      fpathbuf = (char *)vmalloc(PATH_MAX);
      fpath    = get_task_fullpath(current, fpathbuf, PATH_MAX);

      if (strcmp(fpath, "/usr/sbin/sshd") == 0)
        current->is_remote = 1;

      vfree(fpathbuf);
    }

    if (current->is_remote) {
      rcu_read_lock();
      child = pid_task(find_vpid(rc), PIDTYPE_PID);
      rcu_read_unlock();
      if (child)
        child->is_remote = 1;
    }
  }

  return rc;
}

long
shim_clone(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
  struct task_struct *tsk;
  int child_pid;

  if (current->record_thrd) return record_clone(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
  if (current->replay_thrd)
  {
    if (test_app_syscall(56)) return replay_clone(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
    // Pin calls clone instead of vfork and enforces the vfork semantics at the Pin layer.
    // Allow Pin to do so, by calling replay_clone
    if (is_pin_attached() && current->replay_thrd->is_pin_vfork)
    {
      int child_pid;
      child_pid = replay_clone(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
      current->replay_thrd->is_pin_vfork = 0;
      return child_pid;
    }
    // This is a Pin fork
    child_pid = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
    tsk = pid_task(find_vpid(child_pid), PIDTYPE_PID);
    if (!tsk)
    {
      TPRINT("[DIFF]shim_clone: cannot find replaying Pid %d\n", child_pid);
      return -EINVAL;
    }
    tsk->replay_thrd = NULL;
    // Special case for Pin: Pin threads run along side the application's, but without the
    // replay flag set. Becuase of this, we need to wake up the thread after sys_clone.
    // See copy_process in kernel/fork.c
    wake_up_new_task(tsk);
    MPRINT("Pid %d - Pin fork child %d\n", current->pid, child_pid);
    return child_pid;
  }
  //  return do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
  return theia_sys_clone(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
}

SIMPLE_SHIM2(setdomainname, 171, char __user *, name, int, len);
/* modify_ldt appears to only affect the process and is deterministic, so do not record/replay */
RET1_SHIM1(adjtimex, 159, struct timex, txc_p, struct timex __user *, txc_p);



//Yang
struct mprotect_ahgv
{
  int             pid;
  u_long          retval;
  u_long          address;
  u_long          length;
  uint16_t        protection;
};

void packahgv_mprotect(struct mprotect_ahgv *sys_args)
{
  int size = 0;

  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;

    get_curr_time(&sec, &nsec);

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, THEIA_KMEM_SIZE-1, 
            "startahg|%d|%d|%ld|%lx|%lx|%lx|%d|%d|%ld|%ld|%u|endahg\n",
                   10, sys_args->pid, current->start_time.tv_sec,
                   sys_args->retval, sys_args->address, sys_args->length,
                   sys_args->protection, current->tgid, sec, nsec, current->no_syscalls++);
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
    kmem_cache_free(theia_buffers, buf);
  }
}

void theia_mprotect_ahg(u_long address, u_long len, uint16_t prot, long rc)
{
  struct mprotect_ahgv *pahgv = NULL;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv = (struct mprotect_ahgv *)KMALLOC(sizeof(struct mprotect_ahgv), GFP_KERNEL);
  if (pahgv == NULL)
  {
    TPRINT("theia_mprotect_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv->pid = current->pid;
  pahgv->retval = (u_long)rc;
  pahgv->address = address;
  pahgv->length = len;
  pahgv->protection = prot;
  packahgv_mprotect(pahgv);
  KFREE(pahgv);
}

static asmlinkage long
record_mprotect(unsigned long start, size_t len, unsigned long prot)
{
  long rc;

  rg_lock(current->record_thrd->rp_group);
  new_syscall_enter(10);
  rc = sys_mprotect(start, len, prot);
  //Yang
  if (rc >= 0)
  {
    theia_mprotect_ahg(start, (u_long)len, (uint16_t)prot, rc);
  }

  new_syscall_done(10, rc);
  DPRINT("Pid %d records mprotect %lx for %lx-%lx returning %ld\n", current->pid, prot, start, start + len, rc);
  new_syscall_exit(10, NULL);
  rg_unlock(current->record_thrd->rp_group);

  return rc;
}

static asmlinkage long
replay_mprotect(unsigned long start, size_t len, unsigned long prot)
{
  u_long retval, rc;

  if (is_pin_attached())
  {
    rc = current->replay_thrd->rp_saved_rc;
    (*(int *)(current->replay_thrd->app_syscall_addr)) = 999;
    TPRINT("[%s|%d] pid %d, prt->app_syscall_addr is set to 999\n", __func__, __LINE__, current->pid);
  }
  else
  {
    rc = get_next_syscall(10, NULL);
  }

  retval = sys_mprotect(start, len, prot);
  DPRINT("Pid %d replays mprotect %lx for %lx-%lx returning %ld\n", current->pid, prot, start, start + len, retval);

  if (rc != retval)
  {
    TPRINT("Replay: mprotect returns diff. value %lu than %lu\n", retval, rc);
    return syscall_mismatch();
  }
  return rc;
}

int theia_sys_mprotect(unsigned long start, size_t len, unsigned long prot)
{
  long rc;
  rc = sys_mprotect(start, len, prot);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  {
    theia_mprotect_ahg(start, (u_long)len, (uint16_t)prot, rc);
  }
  return rc;
}

asmlinkage long shim_mprotect(unsigned long start, size_t len, unsigned long prot)
//SHIM_CALL(mprotect, 125, start, len, prot);
SHIM_CALL_MAIN(10, record_mprotect(start, len, prot), replay_mprotect(start, len, prot), theia_sys_mprotect(start, len, prot))

RET1_SHIM3(sigprocmask, 126, old_sigset_t, oset, int, how, old_sigset_t __user *, set, old_sigset_t __user *, oset);

inline void theia_init_module_ahgx(void __user *umod, unsigned long len, const char __user *uargs, long rc, int sysnum)
{
  /* let's ignore uargs for now */
  theia_dump_dd((long)umod, len, rc, sysnum);
}

inline void theia_delete_module_ahgx(const char __user *name_user, unsigned int flags, long rc, int sysnum)
{
  theia_dump_sd(name_user, flags, rc, sysnum);
}


// THEIA_SHIM3(init_module, 175, void __user *, umod, unsigned long,  len, const char __user *, uargs);
// THEIA_SHIM2(delete_module, 176, const char __user *, name_user, unsigned int, flags);
SIMPLE_SHIM3(init_module, 175, void __user *, umod, unsigned long,  len, const char __user *, uargs);
SIMPLE_SHIM2(delete_module, 176, const char __user *, name_user, unsigned int, flags);

/* get_kernel_syms 177 */
/* query_module 178 */

asmlinkage long
record_quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr)
{
  char *pretval = NULL;
  u_int cmds = cmd >> SUBCMDSHIFT;
  long rc;
  u_long len = 0;

  new_syscall_enter(179);
  rc = sys_quotactl(cmd, special, id, addr);
  new_syscall_done(179, rc);
  if (rc >= 0)
  {

    switch (cmds)
    {
      case Q_GETQUOTA:
        len = sizeof(struct if_dqblk);
        break;
      case Q_GETINFO:
        len = sizeof(struct if_dqinfo);
        break;
      case Q_GETFMT:
        len = sizeof(__u32);
        break;
      case Q_XGETQUOTA:
        len = sizeof(struct fs_disk_quota);
        break;
      case Q_XGETQSTAT:
        len = sizeof(struct fs_quota_stat);
        break;
    }
    if (len > 0)
    {
      pretval = ARGSKMALLOC(sizeof(u_long) + len, GFP_KERNEL);
      if (pretval == NULL)
      {
        TPRINT("record_quotactl: can't allocate return value\n");
        return -ENOMEM;
      }
      *((u_long *) pretval) = len;
      if (copy_from_user(pretval + sizeof(u_long), addr, len))
      {
        ARGSKFREE(pretval, sizeof(u_long) + len);
        return -EFAULT;
      }
    }
  }
  new_syscall_exit(179, pretval);
  return rc;
}

asmlinkage long
replay_quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr)
{
  char *retparams = NULL;
  u_long len;
  long rc;

  rc = get_next_syscall(179, &retparams);
  if (retparams && addr)
  {
    len = *((u_long *) retparams);
    if (copy_to_user(addr, retparams + sizeof(u_long), len))
    {
      TPRINT("replay_quotactl: pid %d cannot copy to user\n", current->pid);
      return syscall_mismatch();
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
  }
  return rc;
}

asmlinkage long shim_quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr) SHIM_CALL(quotactl, 179, cmd, special, id, addr);

/* nfsservctl 180 */
/* getpmsg 181 */
/* putpmsg 182 */
/* afs_syscall 183 */
/* tuxcall 184 */
/* security 185 */

SIMPLE_SHIM1(getpgid, 121, pid_t, pid);
SIMPLE_SHIM1(fchdir, 81, unsigned int, fd);

//obsolete: 32bit abi
static asmlinkage long
record_bdflush(int func, long data)
{
  long rc;
  long *pretval = NULL;

  new_syscall_enter(134);
  rc = sys_bdflush(func, data);
  new_syscall_done(134, rc);
  if (rc >= 0 && func > 2 && func % 2 == 0)
  {
    pretval = ARGSKMALLOC(sizeof(long), GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_bdflush: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(pretval, (long __user *) data, sizeof(long)))
    {
      TPRINT("record_bdflush: can't copy to buffer\n");
      ARGSKFREE(pretval, sizeof(long));
      pretval = NULL;
      rc = -EFAULT;
    }
  }

  new_syscall_exit(134, pretval);
  return rc;
}

static asmlinkage long replay_bdflush(int func, long data)
{
  char *retparams = NULL;
  long rc = get_next_syscall(134, &retparams);
  if (retparams)
  {
    if (copy_to_user((long __user *) data, retparams, sizeof(long))) TPRINT("replay_bdflush: pid %d cannot copy to user\n", current->pid);
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(long));
  }

  return rc;
}

asmlinkage long shim_bdflush(int func, long data) SHIM_CALL(bdflush, 134, func, data);

static asmlinkage long
record_sysfs(int option, unsigned long arg1, unsigned long arg2)
{
  long rc, len;
  char *pretval = NULL;

  new_syscall_enter(139);
  rc = sys_sysfs(option, arg1, arg2);
  new_syscall_done(139, rc);
  if (rc >= 0 && option == 2)
  {
    len = strlen_user((char __user *) arg2) + 1;
    if (len <= 0)
    {
      TPRINT("record_sysfs: pid %d unable to determine buffer length\n", current->pid);
      return -EINVAL;
    }
    pretval = ARGSKMALLOC(len + sizeof(long), GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_sysfs: can't allocate buffer\n");
      return -ENOMEM;
    }
    *((u_long *) pretval) = len;
    if (copy_from_user(pretval + sizeof(u_long), (long __user *) arg2, len))
    {
      TPRINT("record_sysfs: can't copy to buffer\n");
      ARGSKFREE(pretval, len);
      return -EFAULT;
    }
  }

  new_syscall_exit(139, pretval);
  return rc;
}

static asmlinkage long
replay_sysfs(int option, unsigned long arg1, unsigned long arg2)
{
  char *retparams = NULL;
  long rc = get_next_syscall(139, &retparams);
  if (retparams)
  {
    u_long len = *((u_long *) retparams);
    if (copy_to_user((char __user *) arg2, retparams + sizeof(u_long), len)) TPRINT("replay_sysfs: pid %d cannot copy to user\n", current->pid);
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
  }

  return rc;
}

asmlinkage long shim_sysfs(int option, unsigned long arg1, unsigned long arg2) SHIM_CALL(sysfs, 139, option, arg1, arg2);

SIMPLE_SHIM1(personality, 135, u_long, parm);
RET1_SHIM5(llseek, 140, loff_t, result, unsigned int, fd, unsigned long, offset_high, unsigned long, offset_low, loff_t __user *, result, unsigned int, origin);
//RET1_COUNT_SHIM3(getdents, 78, dirent, unsigned int, fd, struct linux_dirent __user *, dirent, unsigned int, count);

struct linux_dirent
{
  unsigned long d_ino;
  unsigned long d_off;
  unsigned short  d_reclen;
  char    d_name[1];
};

inline bool in_nullterm_list(char *target, char *list, size_t list_len)
{
  int end_pos = 0;
  int start_pos = 0;
  char c;
  char *buf;
  size_t buf_len = 0;

  while (end_pos < list_len)
  {
    c = list[end_pos];
    if (!c)
    {
      buf = list + start_pos;
      buf_len = end_pos - start_pos;
      if (memcmp(target, buf, buf_len) == 0)
      {
        return true;
      }
      end_pos++;
      start_pos = end_pos;
    }
    end_pos++;
  }
  return false;
}

long theia_hide_dirent(unsigned int fd, struct linux_dirent __user *dirent, long orig_ret)
{
  long ret =  orig_ret;
  int err;
  unsigned long off = 0;
  struct linux_dirent *dir, *kdirent, *prev = NULL;

  struct file *file = NULL;
  int fput_needed = 0;
  char *dpathbuf;
  char *dirpath;
  size_t dirpath_offset = 0;
  char *fullpath = NULL;

  //white list for our own applications
  if (in_nullterm_list(current->comm, theia_proc_whitelist, theia_proc_whitelist_len))
    return orig_ret;
  if (ret <= 0)
    return ret;

  kdirent = kzalloc(ret, GFP_KERNEL);
  if (kdirent == NULL)
    return ret;

  err = copy_from_user(kdirent, dirent, ret);
  if (err)
    goto out;

  //convert dir fd to dir path, then store in front of fullpath
  if (fd >= 0)
    file = fget_light(fd, &fput_needed);
  if (file)
  {
    dpathbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    dirpath = get_file_fullpath(file, dpathbuf, PATH_MAX);
    fput_light(file, fput_needed);
    if (!IS_ERR(dirpath))
    {
      fullpath = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
      dirpath_offset = strlen(dirpath);
      strncpy(fullpath, dirpath, dirpath_offset);
      fullpath[dirpath_offset] = '/';
      dirpath_offset++;
    }
    kmem_cache_free(theia_buffers, dpathbuf);
  }

  while (fullpath && off < ret)
  {
    dir = (void *)kdirent + off;
    strncpy_safe(fullpath + dirpath_offset, dir->d_name, THEIA_KMEM_SIZE-1);
    if (in_nullterm_list(fullpath, theia_dirent_prefix, theia_dirent_prefix_len))
    {
      pr_debug("dropping dirent: dir->d_name: %s, fullpath: %s\n", dir->d_name, fullpath);
      if (dir == kdirent)
      {
        ret -= dir->d_reclen;
        memmove(dir, (void *)dir + dir->d_reclen, ret);
        continue;
      }
      prev->d_reclen += dir->d_reclen;
    }
    else
      prev = dir;
    off += dir->d_reclen;
  }
  err = copy_to_user(dirent, kdirent, ret);
  if (err)
    goto out;
out:
  if (fullpath)
    kmem_cache_free(theia_buffers, fullpath);
  kfree(kdirent);
  return ret;
}

static asmlinkage long
theia_sys_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
{
  long rc, new_rc;
  rc = sys_getdents(fd, dirent, count);
  new_rc = theia_hide_dirent(fd, dirent, rc);
  return new_rc;
}

static asmlinkage long record_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
{
  long rc, new_rc;
  char *pretval = NULL;

  new_syscall_enter(78);
  rc = sys_getdents(fd, dirent, count);
  new_rc = theia_hide_dirent(fd, dirent, rc);
  new_syscall_done(78, new_rc);
  if (new_rc >= 0 && dirent)
  {
    pretval = ARGSKMALLOC(new_rc, GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_getdents: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(pretval, dirent, new_rc))
    {
      TPRINT("record_getdents: can't copy to buffer\n");
      ARGSKFREE(pretval, new_rc);
      pretval = NULL;
      new_rc = -EFAULT;
    }
  }

  new_syscall_exit(78, pretval);
  return new_rc;
}

static asmlinkage long replay_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
{
  char *retparams = NULL;
  long rc = get_next_syscall(78, &retparams);

  if (retparams)
  {
    if (copy_to_user(dirent, retparams, rc)) TPRINT("replay_getdents: pid %d cannot copy to user\n", current->pid);
    argsconsume(current->replay_thrd->rp_record_thread, rc);
  }

  return rc;
}

asmlinkage ssize_t shim_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
SHIM_CALL_MAIN(78, record_getdents(fd, dirent, count), replay_getdents(fd, dirent, count), theia_sys_getdents(fd, dirent, count))


static asmlinkage long
record_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp)
{
  long rc;
  char *pretvals, *p;
  u_long sets = 0, size;

  new_syscall_enter(23);
  rc = sys_select(n, inp, outp, exp, tvp);
  new_syscall_done(23, rc);

  /* Record user's memory regardless of return value in order to capture partial output. */
  if (inp) sets++;
  if (outp) sets++;
  if (exp) sets++;
  size = FDS_BYTES(n) * sets;
  if (tvp) size += sizeof(struct timeval);

  pretvals = ARGSKMALLOC(sizeof(u_long) + size, GFP_KERNEL);
  if (pretvals == NULL)
  {
    TPRINT("record_select: can't allocate buffer\n");
    return -ENOMEM;
  }
  *((u_long *) pretvals) = size; // Needed for parseklog currently
  p = pretvals + sizeof(u_long);
  if (inp)
  {
    if (copy_from_user(p, inp, FDS_BYTES(n)))
    {
      TPRINT("record_select: copy of inp failed\n");
      ARGSKFREE(pretvals, sizeof(u_long) + size);
      return -EFAULT;
    }
    p += FDS_BYTES(n);
  }
  if (outp)
  {
    if (copy_from_user(p, outp, FDS_BYTES(n)))
    {
      TPRINT("record_select: copy of outp failed\n");
      ARGSKFREE(pretvals, sizeof(u_long) + size);
      return -EFAULT;
    }
    p += FDS_BYTES(n);
  }
  if (exp)
  {
    if (copy_from_user(p, exp, FDS_BYTES(n)))
    {
      TPRINT("record_select: copy of exp failed\n");
      ARGSKFREE(pretvals, sizeof(u_long) + size);
      return -EFAULT;
    }
    p += FDS_BYTES(n);
  }
  if (tvp)
  {
    if (copy_from_user(p, tvp, sizeof(struct timeval)))
    {
      TPRINT("record_select: copy of exp failed\n");
      ARGSKFREE(pretvals, sizeof(u_long) + size);
      return -EFAULT;
    }
  }

#ifdef TIME_TRICK
  if (rc == 0 && tvp)
  {
    atomic_set(&current->record_thrd->rp_group->rg_det_time.flag, 1);
    TPRINT("Pid %d select timeout after %lu, %lu\n", current->pid, tvp->tv_sec, tvp->tv_usec);
  }
#endif

  new_syscall_exit(23, pretvals);
  return rc;
}

asmlinkage long
replay_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp)
{
  char *retparams;
  u_long size;
  long rc = get_next_syscall(23, (char **) &retparams);

  size = *((u_long *) retparams);
  retparams += sizeof(u_long);
  if (inp)
  {
    if (copy_to_user(inp, retparams, FDS_BYTES(n)))
    {
      TPRINT("Pid %d cannot copy inp to user\n", current->pid);
      syscall_mismatch();
    }
    retparams += FDS_BYTES(n);
  }
  if (outp)
  {
    if (copy_to_user(outp, retparams, FDS_BYTES(n)))
    {
      TPRINT("Pid %d cannot copy outp to user\n", current->pid);
      syscall_mismatch();
    }
    retparams += FDS_BYTES(n);
  }
  if (exp)
  {
    if (copy_to_user(exp, retparams, FDS_BYTES(n)))
    {
      TPRINT("Pid %d cannot copy exp to user\n", current->pid);
      syscall_mismatch();
    }
    retparams += FDS_BYTES(n);
  }
  if (tvp)
  {
    if (copy_to_user(tvp, retparams, sizeof(struct timeval)))
    {
      TPRINT("Pid %d cannot copy tvp to user\n", current->pid);
      syscall_mismatch();
    }
  }
  argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + size);

  return rc;
}

asmlinkage long shim_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp) SHIM_CALL(select, 23, n, inp, outp, exp, tvp);

SIMPLE_SHIM2(flock, 73, unsigned int, fd, unsigned int, cmd);
SIMPLE_SHIM3(msync, 26, unsigned long, start, size_t, len, int, flags);

#define SYS_READV 19
void theia_readv_ahgx(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, long rc, int sysnum)
{
  char uuid_str[THEIA_UUID_LEN + 1];

  if (fd < 0) return; /* TODO */

  if (fd2uuid(fd, uuid_str) == false)
    return; /* TODO: report openat errors? */

  /* TODO: parse iovec */
  theia_dump_str(uuid_str, rc, sysnum);
}

static asmlinkage long
record_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
  long size;
#ifdef TIME_TRICK
  int shift_clock = 1;
#endif

  new_syscall_enter(19);
  size = sys_readv(fd, vec, vlen);
  if (theia_logging_toggle)
    theia_readv_ahgx(fd, vec, vlen, size, SYS_READV);

#ifdef TIME_TRICK
  if (size <= 0)
  {
    shift_clock = 0;
  }
  cnew_syscall_done(19, size, -1, shift_clock);
#else
  new_syscall_done(19, size);
#endif
#ifdef X_COMPRESS
  if (is_x_fd(&current->record_thrd->rp_clog.x, fd) && size > 0)
  {
    change_log_special_second();
    if (x_detail) TPRINT("Pid %d readv for x\n", current->pid);
    //x_compress_reply (argshead(current->record_thrd) - size, size, &X_STRUCT_REC, node);
  }
#endif

  new_syscall_exit(19, copy_iovec_to_args(size, vec, vlen));
  return size;
}

static asmlinkage long
replay_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
  char *retparams;
  long retval, rc;

  rc = get_next_syscall(19, &retparams);
  if (retparams)
  {
    retval = copy_args_to_iovec(retparams, rc, vec, vlen);
    if (retval < 0) return retval;
#ifdef X_COMPRESS
    BUG_ON(retval != rc);
    if (is_x_fd(&current->replay_thrd->rp_record_thread->rp_clog.x, fd))
    {
      BUG();
      //clog_mark_done_replay();
      if (x_detail) TPRINT("Pid %d readv for x\n", current->pid);
      //x_decompress_reply (retval, &X_STRUCT_REP, node);
      //validate_decode_buffer (argshead(current->replay_thrd->rp_record_thread), retval, &X_STRUCT_REP);
      //consume_decode_buffer (retval, &X_STRUCT_REP);
      if (x_proxy)
      {
        long retval = sys_readv(fd, vec, vlen);
        // it should be the same with RECV, fix if needed;
        if (retval != rc)
          TPRINT("Pid %d readv from x fails, expected:%ld, actual:%ld\n", current->pid, rc, retval);
      }

    }
#endif
    argsconsume(current->replay_thrd->rp_record_thread, rc);
  }

  return rc;
}

static asmlinkage long
theia_sys_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
  long rc;
  rc = sys_readv(fd, vec, vlen);
  if (theia_logging_toggle)
    theia_readv_ahgx(fd, vec, vlen, rc, SYS_READV);
  return rc;
}

asmlinkage long shim_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
// SHIM_CALL(readv, 19, fd, vec, vlen);
SHIM_CALL_MAIN(19, record_readv(fd, vec, vlen), replay_readv(fd, vec, vlen), theia_sys_readv(fd, vec, vlen))

#ifdef X_COMPRESS
static asmlinkage long
record_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
  long rc;
  //int i = 0;

  new_syscall_enter(20);
  /*
  if (x_detail) {
    for (i = 0; i < vlen; ++i) {
      if (x_detail) {
        int j = 0;
        for (; j < vec[i].iov_len; ++j)
          TPRINT ("%u, ", (unsigned int) *((unsigned char*)(vec[i].iov_base) + j));
        TPRINT ("\n");
      }
    }
  }
  */
  rc = sys_writev(fd, vec, vlen);

  if (rc > 0 && is_x_fd(&current->record_thrd->rp_clog.x, fd))
  {
    if (x_detail) TPRINT("Pid %d writev syscall for x proto:%ld, vlen:%lu\n", current->pid, rc, vlen);
    change_log_special_second();

  }
  new_syscall_done(20, rc);
  new_syscall_exit(20, NULL);
  return rc;
}

static asmlinkage long
replay_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
  long size = get_next_syscall(20, NULL);
  int i = 0;
  int count = 0;
  int actual_fd;

  if (size > 0 && (actual_fd = is_x_fd_replay(&X_STRUCT_REP, fd)) > 0)
  {
    if (x_detail) TPRINT("Pid %d writev syscall for x proto:%ld, vlen:%lu\n", current->pid, size, vlen);
    for (i = 0; i < vlen && count < size; ++i)
    {
      if (vec[i].iov_len > 0)
      {
        if (count + vec[i].iov_len > size)
        {
          //x_compress_req ((char*) vec[i].iov_base, size - count, &X_STRUCT_REP);
        }
        else
        {
          //x_compress_req ((char*)(vec[i].iov_base),vec[i].iov_len, &X_STRUCT_REP);
        }
        count += vec[i].iov_len;
      }
    }
    if (x_proxy)
    {
      long retval;
      int bytes_count = 0;
      for (i = 0; i < vlen; ++i)
        if (vec[i].iov_len > 0)
          bytes_count += vec[i].iov_len;
      if (bytes_count > size)
      {
        int sum = 0;
        struct iovec *kvec = KMALLOC(sizeof(struct iovec) * vlen, GFP_KERNEL);
        mm_segment_t old_fs = get_fs();
        if (copy_from_user(kvec, vec, sizeof(struct iovec) * vlen))
        {
          TPRINT("Pid %d writev (modifying) for x cannot copy from user.\n", current->pid);
          return -EFAULT;
        }

        if (x_detail) TPRINT("Pid %d writev for x, to_write is %d bytes.\n", current->pid, bytes_count);
        for (i = 0; i < vlen; ++i)
        {
          if (kvec[i].iov_len <= 0)
            continue;
          if (sum == size)
          {
            kvec[i].iov_len = 0;
            continue;
          }
          if (sum < size)
            sum += kvec[i].iov_len;
          if (sum > size)
          {
            kvec[i].iov_len -= (sum - size);
            sum = size;
          }
        }
        set_fs(KERNEL_DS);
        retval = sys_writev(actual_fd, kvec, vlen);
        set_fs(old_fs);

      }
      else
        retval = sys_writev(actual_fd, vec, vlen);
      if (retval != size)
      {
        TPRINT("Pid %d writev from x fails, expected:%ld, actual:%ld\n", current->pid, size, retval);
        BUG();
      }
    }

  }
  return size;
}

#define SYS_WRITEV 20
void theia_writev_ahgx(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, long rc, int sysnum)
{
  char uuid_str[THEIA_UUID_LEN + 1];

  if (fd < 0) return; /* TODO */

  if (fd2uuid(fd, uuid_str) == false)
    return; /* TODO: report openat errors? */

  /* TODO: parse iovec */
  theia_dump_str(uuid_str, rc, sysnum);
}

static asmlinkage long
theia_sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
  long rc;
  rc = sys_writev(fd, vec, vlen);
  //TPRINT("theia_sys_writev: pid %d, fd %lu, rc %ld\n", current->pid, fd, rc)
  if (theia_logging_toggle)
    theia_writev_ahgx(fd, vec, vlen, rc, SYS_WRITEV);
  return rc;
}

asmlinkage long shim_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
// SHIM_CALL(writev, 20, fd, vec, vlen);
SHIM_CALL_MAIN(20, record_writev(fd, vec, vlen), replay_writev(fd, vec, vlen), theia_sys_writev(fd, vec, vlen))
#else
#define SYS_WRITEV 20
void theia_writev_ahgx(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, long rc, int sysnum)
{
  char uuid_str[THEIA_UUID_LEN + 1];

  if (fd < 0) return; /* TODO */

  if (fd2uuid(fd, uuid_str) == false)
    return; /* TODO: report openat errors? */

  /* TODO: parse iovec */
  theia_dump_str(uuid_str, rc, sysnum);
}

static asmlinkage long
theia_sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
  long rc;
  rc = sys_writev(fd, vec, vlen);
  //TPRINT("theia_sys_writev: pid %d, fd %lu, rc %ld\n", current->pid, fd, rc);
  if (theia_logging_toggle)
    theia_writev_ahgx(fd, vec, vlen, rc, SYS_WRITEV);
  return rc;
}

static asmlinkage long
record_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
  long rc;
  new_syscall_enter(20);
  rc = sys_writev(fd, vec, vlen);
  if (theia_logging_toggle)
    theia_writev_ahgx(fd, vec, vlen, rc, SYS_WRITEV);
  new_syscall_done(20, rc);
  new_syscall_exit(20, NULL);
  return rc;
}

SIMPLE_REPLAY(writev, 20, unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
asmlinkage long shim_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
// SHIM_CALL(writev, 20, fd, vec, vlen);
SHIM_CALL_MAIN(20, record_writev(fd, vec, vlen), replay_writev(fd, vec, vlen), theia_sys_writev(fd, vec, vlen))
//SIMPLE_SHIM3(writev, 20, unsigned long, fd, const struct iovec __user *, vec, unsigned long, vlen);
#endif
SIMPLE_SHIM1(getsid, 124, pid_t, pid);
SIMPLE_SHIM1(fdatasync, 75, int, fd);

static asmlinkage long
record_sysctl(struct __sysctl_args __user *args)
{
  long rc;
  char *pretval = NULL;
  struct __sysctl_args kargs;
  size_t oldlen = 0;

  new_syscall_enter(156);
  rc = sys_sysctl(args);
  new_syscall_done(156, rc);
  if (rc >= 0)
  {
    if (copy_from_user(&kargs, args, sizeof(struct __sysctl_args)))
    {
      TPRINT("record_sysctl: pid %d cannot copy args struct from user\n", current->pid);
      return -EFAULT;
    }
    if (kargs.oldval && kargs.oldlenp)
    {
      if (copy_from_user(&oldlen, &kargs.oldlenp, sizeof(size_t)))
      {
        TPRINT("record_sysctl: pid %d cannot copy size from user\n", current->pid);
        return -EFAULT;
      }
      pretval = ARGSKMALLOC(sizeof(oldlen), GFP_KERNEL);
      if (pretval == NULL)
      {
        TPRINT("record_sysctl: pid %d can't allocate buffer of size %ld\n", current->pid, (long) oldlen);
        return -ENOMEM;
      }
      *((u_long *) pretval) = oldlen;
      if (copy_from_user(pretval + sizeof(u_long), kargs.oldval, oldlen))
      {
        TPRINT("record_sysctl: pid %d cannot copy buffer from user\n", current->pid);
        ARGSKFREE(pretval, oldlen);
        return -EFAULT;
      }
    }
  }
  new_syscall_exit(156, pretval);
  return rc;
}

static asmlinkage long
replay_sysctl(struct __sysctl_args __user *args)
{
  char *retparams = NULL;
  struct __sysctl_args kargs;
  u_long oldlen;

  long rc = get_next_syscall(156, &retparams);
  if (retparams)
  {
    if (copy_from_user(&kargs, args, sizeof(struct __sysctl_args)))
    {
      TPRINT("replay_sysctl: pid %d cannot copy args struct from user\n", current->pid);
      return syscall_mismatch();
    }
    oldlen = *((u_long *) retparams);
    if (copy_to_user(kargs.oldval, retparams + sizeof(u_long), oldlen)) TPRINT("replay_sysctl: pid %d cannot copy to user\n", current->pid);
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + oldlen);
  }

  return rc;
}

asmlinkage long shim_sysctl(struct __sysctl_args __user *args) SHIM_CALL(sysctl, 156, args);

SIMPLE_SHIM2(mlock, 149, unsigned long, start, size_t, len);
SIMPLE_SHIM2(munlock, 150, unsigned long, start, size_t, len);
SIMPLE_SHIM1(mlockall, 151, int, flags);
SIMPLE_SHIM0(munlockall, 152);
SIMPLE_SHIM2(sched_setparam, 142, pid_t, pid, struct sched_param __user *, param);
RET1_SHIM2(sched_getparam, 143, struct sched_param, param, pid_t, pid, struct sched_param __user *, param);
SIMPLE_SHIM3(sched_setscheduler, 144, pid_t, pid, int, policy, struct sched_param __user *, param);
SIMPLE_SHIM1(sched_getscheduler, 145, pid_t, pid);

SIMPLE_RECORD0(sched_yield, 24);
SIMPLE_REPLAY(sched_yield, 24, void);
asmlinkage long shim_sched_yield(void)
{
  struct replay_thread *tmp;
  int ret;

  if (current->replay_thrd && !test_app_syscall(24))
  {
    MPRINT("Pid %d: pin appears to be calling sched yield\n", current->pid);

    // See if we can find another eligible thread
    tmp = current->replay_thrd->rp_next_thread;

    while (tmp != current->replay_thrd)
    {
      MPRINT("Pid %d considers thread %d (recpid %d) status %d clock %ld - clock is %ld\n", current->pid, tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock, *(current->replay_thrd->rp_preplay_clock));
      if (tmp->rp_status == REPLAY_STATUS_ELIGIBLE || (tmp->rp_status == REPLAY_STATUS_WAIT_CLOCK && tmp->rp_wait_clock <= *(current->replay_thrd->rp_preplay_clock)))
      {
        DPRINT("Letting thread %d run - this may be non-deterministic\n", tmp->rp_replay_pid);
        current->replay_thrd->rp_status = REPLAY_STATUS_ELIGIBLE;
        tmp->rp_status = REPLAY_STATUS_RUNNING;
        wake_up(&tmp->rp_waitq);
        ret = wait_event_interruptible_timeout(current->replay_thrd->rp_waitq, current->replay_thrd->rp_status == REPLAY_STATUS_RUNNING || current->replay_thrd->rp_group->rg_rec_group->rg_mismatch_flag, SCHED_TO);
        if (ret == 0) TPRINT("Replay pid %d timed out waiting after yield\n", current->pid);
        if (ret == -ERESTARTSYS)
        {
          TPRINT("Pid %d: cannot wait due to yield - try again\n", current->pid);
          if (test_thread_flag(TIF_SIGPENDING))
          {
            // this is really dumb
            while (current->replay_thrd->rp_status != REPLAY_STATUS_RUNNING)
            {
              TPRINT("Pid %d: cannot wait due to pending signal(s) - try again\n", current->pid);
              msleep(1000);
            }
          }
        }
        if (current->replay_thrd->rp_status != REPLAY_STATUS_RUNNING)
        {
          TPRINT("Replay pid %d woken up but not running.  We must want it to die\n", current->pid);
          do
          {
            TPRINT("\tthread %d (recpid %d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
            tmp = tmp->rp_next_thread;
          }
          while (tmp != current->replay_thrd);
          sys_exit(0);
        }
        DPRINT("Pid %d running after yield\n", current->pid);
        return 0;
      }
      tmp = tmp->rp_next_thread;
      if (tmp == current->replay_thrd)
      {
        TPRINT("Pid %d: Crud! no eligible thread to run on sched_yield\n", current->pid);
        TPRINT("This is probably really bad...sleeping\n");
        msleep(1000);
      }
    }
  }
  SHIM_CALL(sched_yield, 24);
}

SIMPLE_SHIM1(sched_get_priority_max, 146, int, policy);
SIMPLE_SHIM1(sched_get_priority_min, 147, int, policy);
RET1_SHIM2(sched_rr_get_interval, 148, struct timespec, interval, pid_t, pid, struct timespec __user *, interval);
#ifdef TIME_TRICK
static asmlinkage long
record_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp)
{
  long rc;
  struct timespec *pretval = NULL;

  new_syscall_enter(35);
  rc = sys_nanosleep(rqtp, rmtp);
  new_syscall_done(35, rc);
  if (rc == -1 && rmtp)
  {
    pretval = ARGSKMALLOC(sizeof(struct timespec), GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_nanosleep: can't alloc buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(pretval, rmtp, sizeof(struct timespec)))
    {
      TPRINT("record_nanosleep: can't copy to buffer\n");
      ARGSKFREE(pretval, sizeof(struct timespec));
      pretval = NULL;
      rc = -EFAULT;
    }
  }
  TPRINT("Pid %d nanosleep \n", current->pid);
  if (rc == 0)
  {
    TPRINT("Pid %d nanosleep for %lu, %lu\n", current->pid, rqtp->tv_sec, rqtp->tv_nsec);
    atomic_set(&current->record_thrd->rp_group->rg_det_time.flag, 1);
  }
  new_syscall_exit(35, pretval);
  return rc;
}

RET1_REPLAY(nanosleep, 35, struct timespec, rmtp, struct timespec __user *rqtp, struct timespec __user *rmtp);

asmlinkage long shim_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp) SHIM_CALL(nanosleep, 35, rqtp, rmtp);
#else
RET1_SHIM2(nanosleep, 35, struct timespec, rmtp, struct timespec __user *, rqtp, struct timespec __user *, rmtp);
#endif

#define SYS_MREMAP 25
void theia_mremap_ahgx(unsigned long old_addr, unsigned long old_len, unsigned long new_addr, unsigned long new_len)
{
  char *buf;
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  snprintf(buf, THEIA_KMEM_SIZE-1, "%lx|%lx|%lx|%lx", old_addr, old_len, new_addr, new_len);
  theia_dump_str(buf, 0, SYS_MREMAP); // ignore retval (=new_addr)

  kmem_cache_free(theia_buffers, buf);  
}

static asmlinkage unsigned long
record_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)
{
  unsigned long rc;

  rg_lock(current->record_thrd->rp_group);
  new_syscall_enter(25);
  rc = sys_mremap(addr, old_len, new_len, flags, new_addr);
  theia_mremap_ahgx(addr, old_len, rc, new_len);
  new_syscall_done(25, rc);
  new_syscall_exit(25, NULL);

  /* Save the regions to pre-allocate later for replay,
   * Needed for Pin support
   */
  if (current->record_thrd->rp_group->rg_save_mmap_flag)
  {
    if (rc != -1)
    {
      if (new_len > old_len)
      {
        MPRINT("Pid %d record_mremap, growing the mapping, reserve memory addr %lx len %lx\n", current->pid, rc, new_len);
        reserve_memory(rc, new_len);
      }
      else if (old_len < new_len)
      {
        if (rc != addr)
        {
          MPRINT("Pid %d record_mremap, shrinking the mapping, moving it to addr %lx len %lx\n", current->pid, rc, new_len);
          reserve_memory(rc, new_len);
        }
      }
      // Don't need to do anything if we shrink the mapping in-place,
      // since we'll allocate this anyways (from the original mmap)
    }
  }

  rg_unlock(current->record_thrd->rp_group);

  return rc;
}

static asmlinkage unsigned long
replay_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)
{
  u_long retval, rc = get_next_syscall(25, NULL);
#ifdef LOG_COMPRESS
  // xdou: this is for the correctness, not for compression
  if (rc == addr)
    retval = sys_mremap(addr, old_len, new_len, flags, new_addr);
  else
    retval = sys_mremap(addr, old_len, new_len, flags | MREMAP_FIXED | MREMAP_MAYMOVE, rc);
#else
  retval = sys_mremap(addr, old_len, new_len, flags, new_addr);
#endif
  DPRINT("Pid %d replays mremap with address %lx returning %lx\n", current->pid, addr, retval);

  if (rc != retval)
  {
    TPRINT("Replay mremap returns different value %lu than %lu\n", retval, rc);
    return syscall_mismatch();
  }

  // Save the regions for preallocation for replay+pin
  if (current->replay_thrd->rp_record_thread->rp_group->rg_save_mmap_flag)
  {
    if (rc != ((u_long) - 1))
    {
      if (new_len > old_len)
      {
        MPRINT("Pid %d replay_mremap, growing the mapping, reserve memory addr %lx len %lx\n", current->pid, rc, new_len);
        reserve_memory(rc, new_len);
      }
      else if (old_len < new_len)
      {
        if (rc != addr)
        {
          MPRINT("Pid %d replay_mremap, shrinking the mapping, moving it to addr %lx len %lx\n", current->pid, rc, new_len);
          reserve_memory(rc, new_len);
        }
        // Don't need to do anything if we shrink the mapping in-place,
        // since we'll allocate this anyways (from the original mmap)
      }
    }
  }

  // If we've moved the mmap or shrunk it, we have to preallocate that mmaping again
  if (is_pin_attached() && rc != ((u_long) - 1))
  {
    // move and no overlap between mappings
    if (!(rc >= addr && rc < addr + old_len))
    {
      preallocate_after_munmap(addr, old_len);
    }
    // shrink from the back of the mapping
    else if (addr == rc && old_len > new_len)
    {
      preallocate_after_munmap(rc + new_len, (old_len - new_len));
    }
    // shrink from beginning of mapping
    else if ((rc + new_len >= addr + old_len) && (rc > addr))
    {
      preallocate_after_munmap(addr, (rc - addr));
    }
    // else, we didn't shrink or move it. Do nothing.
  }

  return rc;
}

unsigned long
theia_sys_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)
{
  unsigned long rc;
  rc = sys_mremap(addr, old_len, new_len, flags, new_addr);

  if (rc != -1) {
//    TPRINT("mremap: (0x%lx, %lu) -> (0x%lx, %lu)\n", addr, old_len, rc, new_len);
    theia_mremap_ahgx(addr, old_len, rc, new_len);
  }

  return rc;
}

asmlinkage unsigned long shim_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr) 
// SHIM_CALL(mremap, 25, addr, old_len, new_len, flags, new_addr);
SHIM_CALL_MAIN(25, record_mremap(addr, old_len, new_len, flags, new_addr), replay_mremap(addr, old_len, new_len, flags, new_addr), theia_sys_mremap(addr, old_len, new_len, flags, new_addr));

static asmlinkage long
record_poll(struct pollfd __user *ufds, unsigned int nfds, long timeout_msecs)
{
  long rc;
  char *pretvals = NULL;
  short *p;
  int i;
#ifdef LOG_COMPRESS_1
  struct clog_node *node;
#endif
#ifdef TIME_TRICK
  int shift_clock = 1;
  struct record_group *prg = current->record_thrd->rp_group;
#endif
  new_syscall_enter(7);

  rc = sys_poll(ufds, nfds, timeout_msecs);
#ifdef TIME_TRICK
  if (rc <= 0) shift_clock = 0;
  cnew_syscall_done(7, rc, -1, shift_clock);
#else
  new_syscall_done(7, rc);
#endif
  if (rc > 0)
  {
    pretvals = ARGSKMALLOC(sizeof(u_long) + nfds * sizeof(short), GFP_KERNEL);
    if (pretvals == NULL)
    {
      TPRINT("record_poll: can't allocate buffer\n");
      return -ENOMEM;
    }
    *((u_long *)pretvals) = nfds * sizeof(short);
    if (c_detail) TPRINT("Pid %d nfds %u\n", current->pid, nfds);
    p = (short *)(pretvals + sizeof(u_long));
    for (i = 0; i < nfds; i++)
    {
      if (copy_from_user(p, &ufds[i].revents, sizeof(short)))
      {
        TPRINT("record_poll: can't copy retval %d\n", i);
        ARGSKFREE(pretvals, sizeof(u_long) + nfds * sizeof(short));
        return -EFAULT;
      }
      p++;
    }
#ifdef LOG_COMPRESS_1
    // compress for the retparams of poll
    node = clog_alloc(sizeof(int) + nfds * sizeof(short));
    encodeCachedValue(nfds * sizeof(short), 32, &current->record_thrd->rp_clog.syscall_cache.poll_size, 0, node);
    for (i = 0; i < nfds; ++i)
    {
      encodeCachedValue(ufds[i].revents, 16, &current->record_thrd->rp_clog.syscall_cache.poll_revents, 0, node);
    }
    status_add(&current->record_thrd->rp_clog.syscall_status, 7, (sizeof(int) + nfds * sizeof(short)) << 3, getCumulativeBitsWritten(node));
#endif
  }
  new_syscall_exit(7, pretvals);

#ifdef TIME_TRICK
  if (rc == 0 && timeout_msecs > 0)
  {
    atomic_set(&prg->rg_det_time.flag, 1);
    TPRINT("Pid %d poll timeout %ld ms.\n", current->pid, timeout_msecs);
  }
#endif
  return rc;
}

static asmlinkage long
replay_poll(struct pollfd __user *ufds, unsigned int nfds, long timeout_msecs)
{
  char *retparams = NULL;
  long rc;
  int i;
  short *p;
#ifdef LOG_COMPRESS_1
  unsigned int tmp;
  struct clog_node *node;
#endif

  rc = get_next_syscall(7, (char **) &retparams);
  if (rc == -ERESTART_RESTARTBLOCK)   // Save info for restart of syscall
  {
    struct restart_block *restart_block;

    TPRINT("pid %d restarting poll system call\n", current->pid);
    restart_block = &current_thread_info()->restart_block;
    restart_block->fn = do_restart_poll;
    restart_block->poll.ufds = ufds;
    restart_block->poll.nfds = nfds;
    set_thread_flag(TIF_SIGPENDING); // Apparently necessary to actually restart
  }
  if (retparams)
  {
    p = (short *)(retparams + sizeof(u_long));
    for (i = 0; i < nfds; i++)
    {
      if (copy_to_user(&ufds[i].revents, p, sizeof(short)))
      {
        TPRINT("Pid %d cannot copy revent %d to user\n", current->pid, i);
        syscall_mismatch();
      }
      p++;
    }
#ifdef LOG_COMPRESS_1
    node = clog_mark_done_replay();
    decodeCachedValue(&tmp, 32, &current->replay_thrd->rp_record_thread->rp_clog.syscall_cache.poll_size, 0, 0, node);
    if (c_detail)
      TPRINT("record nfds*2:%u, actual: nfds %u\n", tmp, nfds);
    if (log_compress_debug) BUG_ON(tmp  != nfds * sizeof(short));
    p = (short *)(retparams + sizeof(u_long));
    for (i = 0; i < nfds; ++i)
    {
      decodeCachedValue(&tmp, 16, &current->replay_thrd->rp_record_thread->rp_clog.syscall_cache.poll_revents, 0, 0, node);
      BUG_ON((short)tmp != *p);
      if (copy_to_user(&ufds[i].revents, &tmp, sizeof(short)))
      {
        TPRINT("Pid %d cannot copy revent %d to user\n", current->pid, i);
        syscall_mismatch();
      }
      p++;
    }
#endif
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + * ((u_long *) retparams));
  }
  else
  {
    for (i = 0; i < nfds; i++)
    {
      put_user((short) 0, &ufds[i].revents);
    }
  }

  return rc;
}

asmlinkage long shim_poll(struct pollfd __user *ufds, unsigned int nfds, long timeout_msecs) SHIM_CALL(poll, 7, ufds, nfds, timeout_msecs);

asmlinkage long
record_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
  char *pretval = NULL;
  u_long len = 0;
  long rc;

  new_syscall_enter(157);
  rc = sys_prctl(option, arg2, arg3, arg4, arg5);
  new_syscall_done(157, rc);
  if (rc >= 0)
  {
    switch (option)
    {
      case PR_GET_CHILD_SUBREAPER:
      case PR_GET_PDEATHSIG:
      case PR_GET_TSC:
      case PR_GET_UNALIGN:
        len = sizeof(int);
        break;
      case PR_GET_NAME:
        len = 16; /* per man page */
        break;
      case PR_GET_TID_ADDRESS:
        len = sizeof(int *);
        break;
    }
    if (len > 0)
    {
      pretval = ARGSKMALLOC(sizeof(u_long) + len, GFP_KERNEL);
      if (pretval == NULL)
      {
        TPRINT("record_quotactl: can't allocate return value\n");
        return -ENOMEM;
      }
      *((u_long *) pretval) = len;
      if (copy_from_user(pretval + sizeof(u_long), (char __user *) arg2, len))
      {
        ARGSKFREE(pretval, sizeof(u_long) + len);
        return -EFAULT;
      }
    }
  }
  new_syscall_exit(157, NULL);

  return rc;
}

asmlinkage long
replay_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
  char *retparams = NULL;
  long retval;
  long rc = get_next_syscall(157, &retparams);

  DPRINT("Pid %d calls replay_prctl with option %d\n", current->pid, option);
  if (option == PR_SET_NAME || option == PR_SET_MM)   // Do this also during recording
  {
    retval = sys_prctl(option, arg2, arg3, arg4, arg5);
    if (retval != rc)
    {
      TPRINT("pid %d mismatch: prctl option %d returns %ld on replay and %ld during recording\n", current->pid, option, retval, rc);
      return syscall_mismatch();
    }
  }
  if (retparams && arg2)
  {
    u_long len = *((u_long *) retparams);
    if (copy_to_user((char __user *) arg2, retparams + sizeof(u_long), len))
    {
      TPRINT("replay_quotactl: pid %d cannot copy to user\n", current->pid);
      return syscall_mismatch();
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
  }
  return rc;
}

asmlinkage long shim_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) SHIM_CALL(prctl, 157, option, arg2, arg3, arg4, arg5);

asmlinkage long
record_arch_prctl(int code, unsigned long addr)
{
  char *pretval = NULL;
  long rc;

  new_syscall_enter(158);
  rc = sys_arch_prctl(code, addr);
  new_syscall_done(158, rc);
  if (rc == 0)
  {
    pretval = ARGSKMALLOC(sizeof(int) + sizeof(u_long), GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_arch_prctl: can't allocate return value\n");
      return -ENOMEM;
    }
    *((int *) pretval) = code;
    if (code == ARCH_SET_FS || code == ARCH_SET_GS)
    {
      *((unsigned long *)(pretval + sizeof(int))) = addr;
    }
    else
    {
      if (copy_from_user(pretval + sizeof(int), (char __user *) addr, sizeof(unsigned long)))
      {
        ARGSKFREE(pretval, sizeof(u_long) + sizeof(int));
        return -EFAULT;
      }
    }
  }
  new_syscall_exit(158, pretval);

  return rc;
}

asmlinkage long
replay_arch_prctl(int code, unsigned long addr)
{
  char *retparams = NULL;
  long retval;
  long rc = get_next_syscall(158, &retparams);

  DPRINT("Pid %d calls replay_arch_prctl with code %d\n", current->pid, code);
  if (code == ARCH_SET_FS || code == ARCH_SET_GS)   // Do this also during recording
  {
    retval = sys_arch_prctl(code, addr);
    if (retval != rc)
    {
      TPRINT("pid %d mismatch: arch_prctl code %d returns %ld on replay and %ld during recording\n", current->pid, code, retval, rc);
      return syscall_mismatch();
    }
  }
  if (retparams)
  {
    if (copy_to_user((unsigned long __user *) addr, retparams + sizeof(int), sizeof(unsigned long)))
    {
      TPRINT("replay_arch_prctl: pid %d cannot copy to user\n", current->pid);
      return syscall_mismatch();
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + sizeof(int));
  }
  return rc;
}

long theia_sys_arch_prctl(int code, unsigned long addr)
{
  long rc;
  rc = sys_arch_prctl(code, addr);

  return rc;
}

//Yang: when attached with pin, arch_prctl becomes invisible to the shim (blocked?)
//for now, we remove it from being recorded or replayed.
asmlinkage long shim_arch_prctl(int code, unsigned long addr)
{
  return sys_arch_prctl(code, addr);
}
//SHIM_CALL_MAIN(158, record_arch_prctl(code, addr), replay_arch_prctl(code, addr), theia_sys_arch_prctl(code, addr))

long shim_rt_sigreturn(struct pt_regs *regs)
{
  if (current->record_thrd)
  {
    struct repsignal_context *pcontext = current->record_thrd->rp_repsignal_context_stack;
    if (pcontext)
    {
      if (current->record_thrd->rp_ignore_flag_addr) put_user(pcontext->ignore_flag, current->record_thrd->rp_ignore_flag_addr);
      current->record_thrd->rp_repsignal_context_stack = pcontext->next;
      KFREE(pcontext);
    }
    else
    {
      TPRINT("Pid %d does rt_sigreturn but no context???\n", current->pid);
    }
  }

  return dummy_rt_sigreturn(regs);
}

/* Can't find a definition of this in header files */
asmlinkage long sys_rt_sigaction(int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize);

static asmlinkage long
record_rt_sigaction(int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize)
{
  long rc;
  struct sigaction *pretval = NULL;

  new_syscall_enter(13);
  rc = sys_rt_sigaction(sig, act, oact, sigsetsize);
  new_syscall_done(13, rc);

  if (rc == 0 && oact)
  {
    pretval = ARGSKMALLOC(sizeof(struct sigaction), GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_rt_sigaction: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(pretval, oact, sizeof(struct sigaction)))
    {
      ARGSKFREE(pretval, sizeof(struct sigaction));
      pretval = NULL;
      rc = -EFAULT;
    }
  }
  new_syscall_exit(13, pretval);

  return rc;
}

static asmlinkage long
replay_rt_sigaction(int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize)
{
  long rc, retval;
  char *retparams = NULL;
  struct replay_thread *prt = current->replay_thrd;

  if (is_pin_attached())
  {
    rc = prt->rp_saved_rc;
    retparams = prt->rp_saved_retparams;
    // this is an application syscall (with Pin)
    (*(int *)(prt->app_syscall_addr)) = 999;
    TPRINT("[%s|%d] pid %d, prt->app_syscall_addr is set to 999\n", __func__, __LINE__, current->pid);
    // actually perform rt_sigaction
    retval = sys_rt_sigaction(sig, act, oact, sigsetsize);
    if (rc != retval)
    {
      TPRINT("ERROR: sigaction mismatch, got %ld, expected %ld", retval, rc);
      syscall_mismatch();
    }
  }
  else
  {
    rc = get_next_syscall(13, &retparams);
  }

  if (retparams)
  {
    if (oact)
    {
      if (copy_to_user(oact, retparams, sizeof(struct sigaction)))
      {
        TPRINT("Pid %d replay_rt_sigaction cannot copy oact %p to user\n", current->pid, oact);
      }
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct sigaction));
  }

  return rc;
}

asmlinkage long
shim_rt_sigaction(int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize)
SHIM_CALL(rt_sigaction, 13, sig, act, oact, sigsetsize);

static asmlinkage long
record_rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
{
  long rc;
  char *buf = NULL;

  new_syscall_enter(14);
  rc = sys_rt_sigprocmask(how, set, oset, sigsetsize);
  new_syscall_done(14, rc);
  DPRINT("Pid %d records rt_sigprocmask returning %ld\n", current->pid, rc);

  if (rc == 0 && oset)
  {
    /* Buffer describes its own size */
    buf = ARGSKMALLOC(sizeof(u_long) + sigsetsize, GFP_KERNEL);
    if (buf == NULL)
    {
      TPRINT("record_rt_sigprocmask: can't alloc buffer\n");
      return -ENOMEM;
    }
    *((u_long *) buf) = sigsetsize;
    if (copy_from_user(buf + sizeof(u_long), oset, sigsetsize))
    {
      ARGSKFREE(buf, sizeof(u_long) + sigsetsize);
      buf = NULL;
      rc = -EFAULT;
    }
  }
  new_syscall_exit(14, buf);

  return rc;

}

static asmlinkage long
replay_rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
{
  char *retparams = NULL;
  size_t size;
  struct replay_thread *prt = current->replay_thrd;
  long rc, retval;

  if (is_pin_attached())
  {
    retval = sys_rt_sigprocmask(how, set, oset, sigsetsize);
    rc = prt->rp_saved_rc;
    retparams = prt->rp_saved_retparams;

    if (rc != retval)
    {
      TPRINT("ERROR: sigprocmask expected %ld, got %ld\n", rc, retval);
      syscall_mismatch();
    }

    if (prt->rp_saved_psr)
    {
      if (prt->rp_saved_psr->sysnum == 14)
      {
        (*(int *)(prt->app_syscall_addr)) = 999;
        TPRINT("[%s|%d] pid %d, prt->app_syscall_addr is set to 999\n", __func__, __LINE__, current->pid);
      }
    }
  }
  else
  {
    rc = get_next_syscall(14, &retparams);
  }

  if (retparams)
  {
    size = *((size_t *) retparams);
    if (size != sigsetsize)
      TPRINT("Pid %d has diff sigsetsize %lu than %lu\n", current->pid, sigsetsize, size);
    if (copy_to_user(oset, retparams + sizeof(size_t), size)) TPRINT("Pid %d cannot copy to user\n", current->pid);
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + size);
  }
  return rc;
}

asmlinkage long
shim_rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize) SHIM_CALL(rt_sigprocmask, 14, how, set, oset, sigsetsize);

static asmlinkage long
record_rt_sigpending(sigset_t __user *set, size_t sigsetsize)
{
  long rc;
  char *pretval = NULL;

  new_syscall_enter(127);
  rc = sys_rt_sigpending(set, sigsetsize);
  new_syscall_done(127, rc);
  if (rc >= 0 && set)
  {
    pretval = ARGSKMALLOC(sizeof(long) + sigsetsize, GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_rt_sigpending: can't allocate buffer\n");
      return -ENOMEM;
    }
    *((u_long *) pretval) = sigsetsize;
    if (copy_from_user(pretval + sizeof(u_long), set, sigsetsize))
    {
      TPRINT("record_rt_sigpending: can't copy to buffer\n");
      ARGSKFREE(pretval, sizeof(u_long) + sigsetsize);
      rc = -EFAULT;
    }
  }
  new_syscall_exit(127, pretval);

  return rc;
}

static asmlinkage long
replay_rt_sigpending(sigset_t __user *set, size_t sigsetsize)
{
  u_long len;
  char *retparams = NULL;
  long rc = get_next_syscall(127, &retparams);

  if (retparams)
  {
    len = *((u_long *) retparams);
    if (copy_to_user(set, retparams + sizeof(u_long), len)) TPRINT("replay_rt_sigpending: pid %d cannot copy to user\n", current->pid);
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
  }

  return rc;
}

asmlinkage long shim_rt_sigpending(sigset_t __user *set, size_t sigsetsize) SHIM_CALL(rt_sigpending, 127, set, sigsetsize);

/* Note that sigsetsize must by a constant size in the kernel code or rt_sigtimedwait will fail, so special handling not needed */
RET1_SHIM4(rt_sigtimedwait, 128, siginfo_t, uinfo, const sigset_t __user *, uthese, siginfo_t __user *, uinfo, const struct timespec __user *, uts, size_t, sigsetsize);
SIMPLE_SHIM3(rt_sigqueueinfo, 129, int, pid, int, sig, siginfo_t __user *, uinfo);
SIMPLE_SHIM2(rt_sigsuspend, 130, sigset_t __user *, unewset, size_t, sigsetsize);

/* sigaltstack 131 */

#define SYS_PREAD64 17
void theia_pread64_ahgx(unsigned int fd, const char __user *ubuf, size_t count, loff_t pos, long rc, int sysnum)
{
  char uuid_str[THEIA_UUID_LEN + 1];
  char *buf;
  int ret = 0;

  if (fd < 0) return; /* TODO */

  if (fd2uuid(fd, uuid_str) == false)
    return; /* TODO: report openat errors? */

  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
  ret = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%lu|%lli", uuid_str, count, pos);
  if (ret > 0)
    theia_dump_str(buf, rc, sysnum);
  kmem_cache_free(theia_buffers, buf);
}

static asmlinkage long
record_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos)
{
  long rc;
  char *pretval = NULL;
  struct files_struct *files;
  struct fdtable *fdt;
  struct file *filp;
  int is_cache_file;
#ifdef LOG_COMPRESS
  int shift_clock = 1;
#endif

  new_syscall_enter(17);
  DPRINT("pid %d, record read off of fd %d\n", current->pid, fd);
  //TPRINT("%s %d: In else? of macro?\n", __func__, __LINE__);
  is_cache_file = is_record_cache_file_lock(current->record_thrd->rp_cache_files, fd);

  rc = sys_pread64(fd, buf, count, pos);
  if (theia_logging_toggle)
    theia_pread64_ahgx(fd, buf, count, pos, rc, SYS_PREAD64);

#ifdef TIME_TRICK
  if (rc <= 0) shift_clock = 0;
#endif

#ifdef LOG_COMPRESS
  if (rc == count && is_cache_file)
    cnew_syscall_done(17, rc, count, shift_clock);
  else
    new_syscall_done(17, rc);
#else
  new_syscall_done(17, rc);
#endif
  if (rc > 0 && buf)
  {
    // For now, include a flag that indicates whether this is a cached read or not - this is only
    // needed for parseklog and so we may take it out later

    files = current->files;
    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);
    if (fd >= fdt->max_fds)
    {
      TPRINT("record_read: invalid fd but read succeeded?\n");
      record_cache_file_unlock(current->record_thrd->rp_cache_files, fd);
      return -EINVAL;
    }

    filp = fdt->fd[fd];
    spin_unlock(&files->file_lock);
    if (is_cache_file)
    {
      // Since not all syscalls handled for cached reads, record the position
      DPRINT("Cached read of fd %u - record by reference\n", fd);
      pretval = ARGSKMALLOC(sizeof(u_int) + sizeof(loff_t), GFP_KERNEL);
      if (pretval == NULL)
      {
        TPRINT("record_read: can't allocate pos buffer\n");
        record_cache_file_unlock(current->record_thrd->rp_cache_files, fd);
        return -ENOMEM;
      }
      *((u_int *) pretval) = 1;
      record_cache_file_unlock(current->record_thrd->rp_cache_files, fd);
      *((loff_t *)(pretval + sizeof(u_int))) = pos;

#ifdef TRACE_READ_WRITE
      do
      {
        struct replayfs_filemap_entry *entry = NULL;
        struct replayfs_filemap *map;
        size_t cpy_size;

        struct replayfs_filemap_entry *args;

        map = filp->replayfs_filemap;
        //replayfs_filemap_init(&map, replayfs_alloc, filp);

        //TPRINT("%s %d - %p: Reading %d\n", __func__, __LINE__, current, fd);
        if (filp->replayfs_filemap)
        {
          entry = replayfs_filemap_read(map, pos, rc);
        }

        if (IS_ERR(entry) || entry == NULL)
        {
          entry = kmalloc(sizeof(struct replayfs_filemap_entry), GFP_KERNEL);
          /* FIXME: Handle this properly */
          BUG_ON(entry == NULL);
          entry->num_elms = 0;
        }

        cpy_size = sizeof(struct replayfs_filemap_entry) +
                   (entry->num_elms * sizeof(struct replayfs_filemap_value));

        args = ARGSKMALLOC(cpy_size, GFP_KERNEL);

        memcpy(args, entry, cpy_size);

        kfree(entry);

        //replayfs_filemap_destroy(&map);
      }
      while (0);
#endif
    }
    else
    {
      pretval = ARGSKMALLOC(rc + sizeof(u_int), GFP_KERNEL);
      if (pretval == NULL)
      {
        TPRINT("record_read: can't allocate buffer\n");
        return -ENOMEM;
      }
      *((u_int *) pretval) = 0;
      if (copy_from_user(pretval + sizeof(u_int), buf, rc))
      {
        TPRINT("record_read: can't copy to buffer\n");
        ARGSKFREE(pretval, rc + sizeof(u_int));
        return -EFAULT;
      }

    }
  }
  else if (is_cache_file)
  {
    record_cache_file_unlock(current->record_thrd->rp_cache_files, fd);
  }

  new_syscall_exit(17, pretval);

  perftimer_stop(read_in_timer);
  return rc;
}

static asmlinkage long
replay_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos)
{
  char *retparams = NULL;
  long retval, rc = get_next_syscall(17, &retparams);
  int cache_fd;

  if (retparams)
  {
    int consume_size;

    if (is_replay_cache_file(current->replay_thrd->rp_cache_files, fd, &cache_fd))
    {
      // read from the open cache file
      loff_t off = *((loff_t *)(retparams + sizeof(u_int)));
      DPRINT("read from cache file %d files %p bytes %ld off %ld\n", cache_fd, current->replay_thrd->rp_cache_files, rc, (u_long) off);
      retval = sys_pread64(cache_fd, buf, rc, off);
      if (retval != rc)
      {
        TPRINT("pid %d read from cache file %d files %p orig fd %u off %ld returns %ld not expected %ld\n", current->pid, cache_fd, current->replay_thrd->rp_cache_files, fd, (long) off, retval, rc);
        return syscall_mismatch();
      }
      consume_size = sizeof(u_int) + sizeof(loff_t);
      argsconsume(current->replay_thrd->rp_record_thread, consume_size);

#ifdef TRACE_READ_WRITE
      do
      {
        struct replayfs_filemap_entry *entry = (void *)(retparams + consume_size);

        consume_size = sizeof(struct replayfs_filemap_entry) +
                       (entry->num_elms * sizeof(struct replayfs_filemap_value));

        argsconsume(current->replay_thrd->rp_record_thread, consume_size);
      }
      while (0);
#endif
    }
    else
    {
      // uncached read
      DPRINT("uncached read of fd %u\n", fd);
      if (copy_to_user(buf, retparams + sizeof(u_int), rc)) TPRINT("replay_read: pid %d cannot copy %ld bytes to user\n", current->pid, rc);
      consume_size = sizeof(u_int) + rc;
      argsconsume(current->replay_thrd->rp_record_thread, consume_size);
    }
  }

  return rc;
}

#define SYS_PWRITE64 18
void theia_pwrite64_ahgx(unsigned int fd, const char __user *ubuf, size_t count, loff_t pos, long rc, int sysnum)
{
  char uuid_str[THEIA_UUID_LEN + 1];
  char *buf;
  int ret = 0;

  if (fd < 0) return; /* TODO */

  if (fd2uuid(fd, uuid_str) == false)
    return; /* TODO: report openat errors? */

  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
  ret = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%lu|%lli", uuid_str, count, pos);
  if (ret > 0)
    theia_dump_str(buf, rc, sysnum);
  kmem_cache_free(theia_buffers, buf);
}

static asmlinkage long
record_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos)
{
  char *pretparams = NULL;
  ssize_t size;

  new_syscall_enter(18);
  size = sys_pwrite64(fd, buf, count, pos);
  if (theia_logging_toggle)
    theia_pwrite64_ahgx(fd, buf, count, pos, size, SYS_PWRITE64);

  DPRINT("Pid %d records write returning %zd\n", current->pid, size);
#ifdef LOG_COMPRESS
  cnew_syscall_done(18, size, count, 1);
#else
  new_syscall_done(18, size);
#endif

#ifdef TRACE_READ_WRITE
  if (size > 0)
  {
    struct file *filp;
    struct inode *inode;

    filp = fget(fd);
    if(filp) {
      inode = filp->f_dentry->d_inode;

      /*if (inode->i_rdev == 0 && MAJOR(inode->i_sb->s_dev) != 0 && filp->)*/
      if (filp->replayfs_filemap)
      {
        loff_t fpos;
        struct replayfs_filemap *map;
        map = filp->replayfs_filemap;
        if (map == NULL)
        {
          replayfs_file_opened(filp);
          map = filp->replayfs_filemap;
        }

        BUG_ON(map == NULL);
        //replayfs_filemap_init(&map, replayfs_alloc, filp);

        fpos = pos;
        if (fpos >= 0)
        {
          replayfs_filemap_write(map, current->record_thrd->rp_group->rg_id, current->record_thrd->rp_record_pid,
              current->record_thrd->rp_count, 0, fpos, size);
        }

        replayfs_diskalloc_sync(map->entries.allocator);

        //replayfs_filemap_destroy(&map);
      }
      fput(filp);
    }
  }
#endif
  new_syscall_exit(18, pretparams);

  return size;
}

static asmlinkage long
replay_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos)
{
  ssize_t rc;
  char *pretparams = NULL;

  rc = get_next_syscall(18, &pretparams);
  DPRINT("Pid %d replays write returning %zd\n", current->pid, rc);

  return rc;
}

static asmlinkage long
theia_sys_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos)
{
  long rc;
  rc = sys_pread64(fd, buf, count, pos);
  if (theia_logging_toggle)
    theia_pread64_ahgx(fd, buf, count, pos, rc, SYS_PREAD64);
  return rc;
}

static asmlinkage long
theia_sys_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos)
{
  long rc;
  rc = sys_pwrite64(fd, buf, count, pos);
  if (theia_logging_toggle)
    theia_pwrite64_ahgx(fd, buf, count, pos, rc, SYS_PWRITE64);
  return rc;
}

asmlinkage long shim_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos)
//SHIM_CALL(pread64, 17, fd, buf, count, pos);
SHIM_CALL_MAIN(17, record_pread64(fd, buf, count, pos), replay_pread64(fd, buf, count, pos), theia_sys_pread64(fd, buf, count, pos))

asmlinkage long shim_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos)
// SHIM_CALL(pwrite64, 18, fd, buf, count, pos);
SHIM_CALL_MAIN(18, record_pwrite64(fd, buf, count, pos), replay_pwrite64(fd, buf, count, pos), theia_sys_pwrite64(fd, buf, count, pos))

static asmlinkage long
record_getcwd(char __user *buf, unsigned long size)
{
  long rc;
  char *recbuf = NULL;

  new_syscall_enter(79);
  rc = sys_getcwd(buf, size);
  new_syscall_done(79, rc);
  if (rc >= 0)
  {
    recbuf = ARGSKMALLOC(rc, GFP_KERNEL);
    if (recbuf == NULL)
    {
      TPRINT("record_getcwd: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(recbuf, buf, rc))
    {
      ARGSKFREE(recbuf, rc);
      recbuf = NULL;
      rc = -EFAULT;
    }
  }
  new_syscall_exit(79, recbuf);

  return rc;
}

RET1_COUNT_REPLAY(getcwd, 79, buf, char __user *buf, unsigned long size);

asmlinkage long shim_getcwd(char __user *buf, unsigned long size) SHIM_CALL(getcwd, 79, buf, size);

extern int cap_validate_magic(cap_user_header_t header, unsigned *tocopy); // In kernel/capability.h

static asmlinkage long
record_capget(cap_user_header_t header, cap_user_data_t dataptr)
{
  long rc;
  char *retvals = NULL;
  unsigned tocopy;
  u_long size;

  new_syscall_enter(125);
  cap_validate_magic(header, &tocopy);
  rc = sys_capget(header, dataptr);
  new_syscall_done(125, rc);
  if (rc >= 0)
  {
    size = sizeof(struct __user_cap_header_struct);
    if (dataptr) size += tocopy * sizeof(struct __user_cap_data_struct);

    retvals = ARGSKMALLOC(sizeof(u_long) + size, GFP_KERNEL);
    if (retvals == NULL)
    {
      TPRINT("record_capget: can't allocate buffer\n");
      return -ENOMEM;
    }
    *((u_long *) retvals) = size;

    if (copy_from_user(retvals + sizeof(u_long), header, sizeof(struct __user_cap_header_struct)))
    {
      TPRINT("record_capget: unable to copy header from user\n");
      ARGSKFREE(retvals, sizeof(u_long) + size);
      return -EFAULT;
    }
    if (dataptr)
    {
      if (copy_from_user(retvals + sizeof(u_long) + sizeof(struct __user_cap_header_struct), dataptr, tocopy * sizeof(struct __user_cap_data_struct)))
      {
        TPRINT("record_capget: pid %d unable to copy dataptr from user address %p\n", current->pid, dataptr);
        ARGSKFREE(retvals, sizeof(u_long) + size);
        return -EFAULT;
      }
    }
  }
  new_syscall_exit(125, retvals);

  return rc;
}

static asmlinkage long
replay_capget(cap_user_header_t header, cap_user_data_t dataptr)
{
  char *pretvals = NULL;
  unsigned tocopy;
  u_long size;
  long rc;

  cap_validate_magic(header, &tocopy);
  rc = get_next_syscall(125, &pretvals);
  if (pretvals)
  {
    size = *((u_long *) pretvals);
    if (copy_to_user(header, pretvals + sizeof(u_long), sizeof(struct __user_cap_header_struct)))
    {
      TPRINT("Pid %d replay_capget cannot copy header to user\n", current->pid);
      return syscall_mismatch();
    }
    if (dataptr)
    {
      if (copy_to_user(dataptr, pretvals + sizeof(u_long) + sizeof(struct __user_cap_header_struct), tocopy * sizeof(struct __user_cap_data_struct)))
      {
        TPRINT("Pid %d replay_capget cannot copy dataptr to user\n", current->pid);
        return syscall_mismatch();
      }
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + size);
  }
  return rc;
}

asmlinkage long shim_capget(cap_user_header_t header, cap_user_data_t dataptr) SHIM_CALL(capget, 125, header, dataptr)
RET1_SHIM2(capset, 126, struct __user_cap_header_struct, header, cap_user_header_t, header, const cap_user_data_t, data);

void theia_sendfile64_ahgx(int out_fd, int in_fd, loff_t __user *offset, size_t count, long rc)
{
  char socket_uuid_str[THEIA_UUID_LEN + 1];
  char file_uuid_str[THEIA_UUID_LEN + 1];
  loff_t location;
  struct file *file = NULL;
  int fput_needed;
  char *fpath = NULL;
  char *fpath_b64 = NULL;
  bool fpath_b64_alloced = false;
  char *buf = NULL;
  int ret = 0;
#ifdef DPATH_USE_STACK
  char pbuf[THEIA_DPATH_LEN];
#else
  char *pbuf = NULL;
  pbuf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
#endif
  buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);

  if (out_fd >= 0 && in_fd >= 0)
  {
    if (!fd2uuid(out_fd, socket_uuid_str)) goto err;
    if (!fd2uuid(in_fd, file_uuid_str)) goto err;

    get_user(location, offset);

    file = fget_light(in_fd, &fput_needed);
    if (file)
    {
      fpath = get_file_fullpath(file, pbuf, THEIA_DPATH_LEN);
      if (IS_ERR_OR_NULL(fpath))
      {
        pbuf[0] = 0x0;
        fpath = pbuf;
      }
      fput_light(file, fput_needed);
    }
    else
    {
      pbuf[0] = 0x0;
      fpath = pbuf;
    }

    fpath_b64 = base64_encode(fpath, strlen(fpath), NULL);
    if (!fpath_b64) 
      fpath_b64 = "";
    else
      fpath_b64_alloced = true;

    ret = snprintf(buf, THEIA_KMEM_SIZE-1, "%s|%s|%s|%lli|%lu", file_uuid_str, fpath_b64, socket_uuid_str, location, count);
    if (ret > 0)
      theia_dump_str(buf, rc, 40);
  }
err:
  kmem_cache_free(theia_buffers, buf);
#ifndef DPATH_USE_STACK
  kmem_cache_free(theia_buffers, pbuf);
#endif
  if (fpath_b64_alloced)
    vfree(fpath_b64);
}

static asmlinkage long
theia_sys_sendfile64(int out_fd, int in_fd, loff_t __user *offset, size_t count)
{
  long rc;

  rc = sys_sendfile64(out_fd, in_fd, offset, count);

  if (theia_logging_toggle)
    theia_sendfile64_ahgx(out_fd, in_fd, offset, count, rc);

  return rc;
}

static asmlinkage long
record_sendfile64(int out_fd, int in_fd, loff_t __user *offset, size_t count)
{
  long rc;

  new_syscall_enter(40);

  rc = sys_sendfile64(out_fd, in_fd, offset, count);

  if (theia_logging_toggle)
    theia_sendfile64_ahgx(out_fd, in_fd, offset, count, rc);

  MPRINT("Pid %d records sendfile64 returning %ld\n", current->pid, rc);
  new_syscall_done(40, rc);
  new_syscall_exit(40, NULL);

  return rc;
}


//RET1_SHIM4(sendfile64, 40, off_t, offset, int, out_fd, int, in_fd, off_t __user *, offset, size_t, count);
// RET1_RECORD4(sendfile64, 40, loff_t, offset, int, out_fd, int, in_fd, loff_t __user *, offset, size_t, count);
RET1_REPLAY(sendfile64, 40, loff_t, offset, int  out_fd, int  in_fd, loff_t __user   *offset, size_t  count);
asmlinkage long shim_sendfile64(int out_fd, int in_fd, loff_t __user *offset, size_t count)
SHIM_CALL_MAIN(40, record_sendfile64(out_fd, in_fd, offset, count), replay_sendfile64(out_fd, in_fd, offset, count), theia_sys_sendfile64(out_fd, in_fd, offset, count));

void
record_vfork_handler(struct task_struct *tsk)
{
  struct record_group *prg = current->record_thrd->rp_group;
  void *slab;

  DPRINT("In record_vfork_handler\n");
  rg_lock(prg);
  tsk->record_thrd = new_record_thread(prg, tsk->pid, NULL);
  if (tsk->record_thrd == NULL)
  {
    TPRINT("record_vfork_handler: cannot allocate record thread\n");
    rg_unlock(prg);
    return;
  }
  tsk->replay_thrd = NULL;

#ifdef CACHE_READS
  copy_record_cache_files(current->record_thrd->rp_cache_files, tsk->record_thrd->rp_cache_files);
#endif

  tsk->record_thrd->rp_next_thread = current->record_thrd->rp_next_thread;
  current->record_thrd->rp_next_thread = tsk->record_thrd;

  tsk->record_thrd->rp_user_log_addr = 0; // Should not write to user log before exec - otherwise violates vfork principles
#ifdef USE_EXTRA_DEBUG_LOG
  tsk->record_thrd->rp_user_extra_log_addr = 0;
#endif
  tsk->record_thrd->rp_ignore_flag_addr = current->record_thrd->rp_ignore_flag_addr;

  // allocate a slab for retparams
  slab = VMALLOC(argsalloc_size);
  if (slab == NULL)
  {
    rg_unlock(prg);
    TPRINT("record_vfork_handler: no memory for slab\n");
    return;
  }
  if (add_argsalloc_node(tsk->record_thrd, slab, argsalloc_size))
  {
    rg_unlock(prg);
    VFREE(slab);
    TPRINT("Pid %d record_vfork: error adding argsalloc_node\n", current->pid);
    return;
  }
#ifdef LOG_COMPRESS_1
  slab = VMALLOC(argsalloc_size);
  if (slab == NULL)
  {
    rg_unlock(prg);
    TPRINT("record_vfork_handler: no memory for slab (clog)\n");
    return;
  }
  if (add_clog_node(tsk->record_thrd, slab, argsalloc_size))
  {
    rg_unlock(prg);
    VFREE(slab);
    TPRINT("Pid %d record_vfork: error adding clog_node\n", current->pid);
    return;
  }
#endif

  rg_unlock(prg);
  DPRINT("Done with record_vfork_handler\n");
}

static long
record_vfork(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
  long rc;

  new_syscall_enter(58);

  /* On clone, we reset the user log.  On, vfork we do not do this because the parent and child share one
           address space.  This sharing will get fixed on exec. */

  rc = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
  MPRINT("Pid %d records vfork returning %ld\n", current->pid, rc);
  new_syscall_done(58, rc);
  new_syscall_exit(58, NULL);

  return rc;
}

void
replay_vfork_handler(struct task_struct *tsk)
{
  struct replay_group *prg = current->replay_thrd->rp_group;
  struct record_thread *prt;
  struct replay_thread *prept;
  ds_list_iter_t *iter;
  long rc = current->replay_thrd->rp_saved_rc;

  // Attach the replay thread struct to the child
  rg_lock(prg->rg_rec_group);

  /* Find the corresponding record thread based on pid.
   * We used to find the last prt with replay_pid == 0,
   * but it fails if child thread spawns another child thread.
   * We should not assume that there is only one thread that
   * spawns other threads.
   */
  for (prt = current->replay_thrd->rp_record_thread->rp_next_thread;
       prt != current->replay_thrd->rp_record_thread; prt = prt->rp_next_thread)
  {
    if (prt->rp_record_pid == rc)
    {
      DPRINT("Pid %d find replay_thrd %p (rec_pid=%d,rep_pid=%d)\n", current->pid, prt, prt->rp_record_pid, tsk->pid);
      break;
    }
  }

  // if Pin is attached the record_thread could already exist (via preallocate_mem) so we need to check
  // to see if it exists first before creating
  if (prt == NULL || prt->rp_record_pid != rc)
  {
    /* For replays resumed form disk checkpoint, there will be no record thread.  We should create it here. */
    prt = new_record_thread(prg->rg_rec_group, rc, NULL);
    // Since there is no recording going on, we need to dec record_thread's refcnt
    atomic_dec(&prt->rp_refcnt);
    DPRINT("Created new record thread %p\n", prt);
  }

  /* Ensure that no replay thread in this replay group points to this record thread */
  iter = ds_list_iter_create(prg->rg_replay_threads);
  while ((prept = ds_list_iter_next(iter)) != NULL)
  {
    if (prept->rp_record_thread == prt)
    {
      TPRINT("[DIFF]replay_vfork_handler: record thread already cloned?\n");
      ds_list_iter_destroy(iter);
      rg_unlock(prg->rg_rec_group);
      return;
    }
  }
  ds_list_iter_destroy(iter);

  /* Update our replay_thrd with this information */
  tsk->record_thrd = NULL;
  DPRINT("Cloning new replay thread\n");
  tsk->replay_thrd = new_replay_thread(prg, prt, tsk->pid, 0, NULL);
  BUG_ON(!tsk->replay_thrd);

#ifdef CACHE_READS
  copy_replay_cache_files(current->replay_thrd->rp_cache_files, tsk->replay_thrd->rp_cache_files);
#endif

  // inherit the parent's app_syscall_addr
  tsk->replay_thrd->app_syscall_addr = current->replay_thrd->app_syscall_addr;

  MPRINT("Pid %d, tsk->pid %d refcnt for replay thread %p now %d\n", current->pid, tsk->pid, tsk->replay_thrd,
         atomic_read(&tsk->replay_thrd->rp_refcnt));
  MPRINT("Pid %d, tsk->pid %d refcnt for record thread pid %d now %d\n", current->pid, tsk->pid, prt->rp_record_pid,
         atomic_read(&prt->rp_refcnt));

  // Fix up the circular thread list
  tsk->replay_thrd->rp_next_thread = current->replay_thrd->rp_next_thread;
  current->replay_thrd->rp_next_thread = tsk->replay_thrd;

  // read the rest of the log
  read_log_data(tsk->replay_thrd->rp_record_thread);
#ifdef LOG_COMPRESS_1
  read_clog_data(tsk->replay_thrd->rp_record_thread);
#endif

  prept = current->replay_thrd;
  tsk->replay_thrd->rp_status = REPLAY_STATUS_RUNNING; // Child needs to run first to complete vfork
  //  tsk->thread.ip = (u_long) ret_from_fork_2;
  //KSTK_EIP(tsk) = (u_long) ret_from_fork_2;
  set_tsk_thread_flag(tsk, TIF_FORK_2);

  current->replay_thrd->rp_status = REPLAY_STATUS_ELIGIBLE; // So we need to wait
  rg_unlock(prg->rg_rec_group);
}

static long
replay_vfork(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
  struct task_struct *tsk = NULL;
  struct replay_thread *prt = current->replay_thrd;
  struct replay_group *prg = prt->rp_group;
  struct syscall_result *psr = NULL;
  pid_t pid;
  long ret, rc;

  // See above comment about user log

  // This is presumably necessary for PIN handling
  MPRINT("Pid %d replay_vfork syscall enter\n", current->pid);
  if (is_pin_attached())
  {
    rc = prt->rp_saved_rc;
    (*(int *)(prt->app_syscall_addr)) = 999;
    TPRINT("[%s|%d] pid %d, prt->app_syscall_addr is set to 999\n", __func__, __LINE__, current->pid);
  }
  else
  {
    rc = get_next_syscall_enter(prt, prg, 58, NULL, &psr);
    prt->rp_saved_rc = rc;
  }

  DPRINT("Pid %d replay_vfork syscall exit:rc=%ld\n", current->pid, rc);
  if (rc > 0)
  {
    // We need to keep track of whether or not a signal was attached
    // to this system call; sys_clone_internal will clear the flag
    // so we need to be able to set it again at the end of the syscall
    int rp_sigpending = test_thread_flag(TIF_SIGPENDING);

    // We also need to create a child here
    pid = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
    MPRINT("Pid %d in replay_vfork spawns child %d\n", current->pid, pid);
    if (pid < 0)
    {
      TPRINT("[DIFF]replay_vfork: second vfork failed, rc=%d\n", pid);
      return syscall_mismatch();
    }

    // see above
    if (rp_sigpending)
    {
      DPRINT("Pid %d sig was pending in clone!\n", current->pid);
      signal_wake_up(current, 0);
    }

    // Next, we have to wait while child runs
    DPRINT("replay_vfork: pid %d going to sleep\n", current->pid);
    ret = wait_event_interruptible_timeout(prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING, SCHED_TO);

    rg_lock(prg->rg_rec_group);
    if (ret == 0) TPRINT("Replay pid %d timed out waiting for vfork to complete\n", current->pid);
    if (prt->rp_status != REPLAY_STATUS_RUNNING)
    {
      MPRINT("Replay pid %d woken up during vfork but not running.  We must want it to die\n", current->pid);
      rg_unlock(prg->rg_rec_group);
      sys_exit(0);
    }
    rg_unlock(prg->rg_rec_group);
  }

  if (prt->app_syscall_addr == 0)
  {
    get_next_syscall_exit(prt, prg, psr);
  }
  if (rc > 0 && prt->app_syscall_addr)
  {
    MPRINT("Return real child pid %d to Pin instead of recorded child pid %ld\n", tsk->pid, rc);
    return tsk->pid;
  }

  return rc;
}

long
shim_vfork(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
  long rc;
  if (current->record_thrd) return record_vfork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
  if (current->replay_thrd)
  {
    int child_pid;
    struct task_struct *tsk;
    if (test_app_syscall(58))
    {
      return replay_vfork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
    }
    // This is Pin
    // mcc: I'm not sure what it means for Pin to vfork,
    // but this seems to be the right thing to do:
    // actually execute the vfork, remove the replay_thrd, and let it run.
    TPRINT("Pid %d - WARN - Pin is actually running a vfork! -- is this bad?\n", current->pid);
    child_pid = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
    tsk = pid_task(find_vpid(child_pid), PIDTYPE_PID);
    tsk->replay_thrd = NULL;
    wake_up_new_task(tsk);
    MPRINT("Pid %d - Pin vforks a child %d\n", current->pid, child_pid);
    return child_pid;
  }

  rc = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
  theia_clone_ahg(rc); // TODO?: define vfork_ahg?
  return rc;
}

RET1_SHIM2(getrlimit, 97, struct rlimit, rlim, unsigned int, resource, struct rlimit __user *, rlim);

//Yang
struct mmap_ahgv
{
  int             pid;
  int             fd;
  u_long          address;
  u_long          length;
  uint16_t        prot_type;
  u_long          flag;
  u_long          offset;
  //  u_long          clock;
};

void packahgv_mmap(struct mmap_ahgv *sys_args)
{
  char uuid_str[THEIA_UUID_LEN + 1];
  int size = 0;
  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    get_curr_time(&sec, &nsec);
#ifdef THEIA_UUID
    if (sys_args->fd != -1)
    {
      if (fd2uuid(sys_args->fd, uuid_str) == false)
        strcpy(uuid_str, "anon_page");
    }
    else
    {
      strcpy(uuid_str, "anon_page");
    }

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%s|%lx|%lu|%d|%lx|%lx|%d|%ld|%ld|%u|endahg\n",
                   9, sys_args->pid, current->start_time.tv_sec,
                   uuid_str, sys_args->address, sys_args->length, sys_args->prot_type,
                   sys_args->flag, sys_args->offset, current->tgid, sec, nsec, current->no_syscalls++);
#else
    int size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%d|%lx|%lu|%d|%lx|%lx|%d|%ld|%ld|%u|endahg\n",
                       9, sys_args->pid, current->start_time.tv_sec,
                       sys_args->fd, sys_args->address, sys_args->length, sys_args->prot_type,
                       sys_args->flag, sys_args->offset, current->tgid, sec, nsec, current->no_syscalls++);
#endif
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
    kmem_cache_free(theia_buffers, buf);
  }
}

void theia_mmap_ahg(int fd, u_long address, u_long len, uint16_t prot,
                    u_long flags, u_long pgoff, long rc)
{
  struct mmap_ahgv *pahgv = NULL;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  pahgv = (struct mmap_ahgv *)KMALLOC(sizeof(struct mmap_ahgv), GFP_KERNEL);
  if (pahgv == NULL)
  {
    TPRINT("theia_mmap_ahg: failed to KMALLOC.\n");
    return;
  }
  pahgv->pid = current->pid;
  pahgv->fd = fd;
  pahgv->address = (u_long)rc;
  pahgv->length = len;
  pahgv->prot_type = prot;
  pahgv->flag = flags;
  pahgv->offset = pgoff;
  packahgv_mmap(pahgv);
  KFREE(pahgv);

}

static asmlinkage long
record_mmap_pgoff(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
  long rc;
  struct mmap_pgoff_retvals *recbuf = NULL;

#ifdef THEIA_TRACK_SHM_OPEN
  char *vm_file_path = NULL;
  char *path = NULL;
  bool is_shmem = false;
  vm_file_path = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
  memset(vm_file_path, '\0', PATH_MAX);
#endif

  rg_lock(current->record_thrd->rp_group);
  new_syscall_enter(9);

#ifdef THEIA_TRACK_SHM_OPEN
  if (flags & MAP_SHARED)
  {
    flags = flags | MAP_POPULATE;
  }
#endif

  rc = sys_mmap_pgoff(addr, len, prot, flags, fd, pgoff);
  //  TPRINT("mmap record is done. rc:%lx\n", rc);
  //Yang
  theia_mmap_ahg((int)fd, addr, len, (uint16_t)prot, flags, pgoff, rc);

  new_syscall_done(9, rc);

  /* Good thing we have the extra synchronization and rg_lock
   * held, since we need to store some return values of mmap
   * with the argument list: the mapped file, and the memory
   * region allocated (different from that requested).
   */
  if ((rc > 0 || rc < -1024) && ((long) fd) >= 0 && !is_record_cache_file(current->record_thrd->rp_cache_files, fd))
  {
    struct vm_area_struct *vma;
    struct mm_struct *mm = current->mm;
    down_read(&mm->mmap_sem);
    vma = find_vma(mm, rc);
    if (vma && rc >= vma->vm_start && vma->vm_file)
    {
      recbuf = ARGSKMALLOC(sizeof(struct mmap_pgoff_retvals), GFP_KERNEL);
      add_file_to_cache(vma->vm_file, &recbuf->dev, &recbuf->ino, &recbuf->mtime);
      //      TPRINT("record_mmap_pgoff: rc: %lx, vm_file->fdentry->d_iname: %s, prot: %lu.\n", rc, vma->vm_file->f_dentry->d_iname, prot);
      //      sprintf(vm_file_path, "%s", vma->vm_file->f_dentry->d_iname);

#ifdef THEIA_TRACK_SHM_OPEN
      path = d_path(&(vma->vm_file->f_path), vm_file_path, PATH_MAX);
      if (IS_ERR(path))
      {
        pr_err("record_mmap_pgoff() d_path returned an error\n");
        path = current->comm;
      }

      if (!strncmp(path, "/run/shm/", 9) &&
          strncmp(path, "/run/shm/pulse-shm-", 19) &&
          strncmp(path, "/run/shm/uclock", 15))
      {
        // shared memory under /dev/shm
        is_shmem = true;
      }
      if (vm_file_path)
        kmem_cache_free(theia_buffers, vm_file_path);
#endif
    }
    up_read(&mm->mmap_sem);
  }

#ifdef THEIA_TRACK_SHM_OPEN
  if (flags & MAP_SHARED && is_shmem)
  {
    // enforce page allocation
    int __user *address = NULL;

    // TODO: bookeeping vma and prot (read only, read and write, exec)

    int np = len / 0x1000;
    if (len % 0x1000)
      ++np;

    ret = sys_mprotect(rc, len, PROT_WRITE);
    if (!ret)
    {
      int i;
      for (i = 0; i < np; ++i)
      {
        address = (int __user *)(rc + i * 0x1000);
        *address = *address;
      }

      ret = sys_mprotect(rc, len, PROT_NONE);
      //      TPRINT("protection of a shared page will be changed, ret %d\n", ret);
    }
  }
#endif

  DPRINT("Pid %d records mmap_pgoff with addr %lx len %lx prot %lx flags %lx fd %ld ret %lx\n", current->pid, addr, len, prot, flags, fd, rc);

  /* Save the regions to pre-allocate later for replay,
   * Needed for Pin support
   */
  if (current->record_thrd->rp_group->rg_save_mmap_flag)
  {
    if (rc != -1)
    {
      MPRINT("Pid %d record mmap_pgoff reserve memory addr %lx len %lx\n", current->pid, addr, len);
      reserve_memory(rc, len);
    }
  }

  new_syscall_exit(9, recbuf);
  rg_unlock(current->record_thrd->rp_group);

  return rc;
}

static asmlinkage long
replay_mmap_pgoff(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
  u_long retval, rc, is_cache_file;
  int given_fd = fd;
  struct mmap_pgoff_retvals *recbuf = NULL;
  struct replay_thread *prt = current->replay_thrd;
  struct syscall_result *psr;
  struct argsalloc_node *node;
  char vm_file_path[DNAME_INLINE_LEN+1];
  struct vm_area_struct *vma;
  struct mm_struct *mm;

  if (is_pin_attached())
  {
    rc = prt->rp_saved_rc;
    recbuf = (struct mmap_pgoff_retvals *) prt->rp_saved_retparams;
    psr = prt->rp_saved_psr;
    (*(int *)(prt->app_syscall_addr)) = 999;
    TPRINT("[%s|%d] pid %d, prt->app_syscall_addr is set to 999\n", __func__, __LINE__, current->pid);
  }
  else
  {
    rc = get_next_syscall(9, (char **) &recbuf);
  }

  if (recbuf)
  {
    rg_lock(prt->rp_record_thread->rp_group);
    given_fd = open_mmap_cache_file(recbuf->dev, recbuf->ino, recbuf->mtime, (prot & PROT_WRITE) && (flags & MAP_SHARED), prt->rp_group->cache_dir);
    rg_unlock(prt->rp_record_thread->rp_group);
    DPRINT("replay_mmap_pgoff opens cache file %x %lx %lx.%lx, fd = %d\n", recbuf->dev, recbuf->ino, recbuf->mtime.tv_sec, recbuf->mtime.tv_nsec, given_fd);
    if (given_fd < 0)
    {
      TPRINT("replay_mmap_pgoff: can't open cache file, rc=%d\n", given_fd);
      syscall_mismatch();
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct mmap_pgoff_retvals));
  }
  else if (is_replay_cache_file(prt->rp_cache_files, fd, &given_fd))
  {
    DPRINT("replay_mmap_pgoff uses open cache file %d for %lu\n", given_fd, fd);
    is_cache_file = 1;
  }
  else if (given_fd >= 0)
  {
    TPRINT("replay_mmap_pgoff: fd is %d but there are no return values recorded\n", given_fd);
  }

  retval = sys_mmap_pgoff(rc, len, prot, (flags | MAP_FIXED), given_fd, pgoff);
  node = list_first_entry(&(current->replay_thrd->rp_record_thread)->rp_argsalloc_list, struct argsalloc_node, list);
  TPRINT("base addr: %p\n", node->pos);
  //print_mem(node->pos, 1024);
  DPRINT("Pid %d replays mmap_pgoff with address %lx len %lx input address %lx fd %d flags %lx prot %lx pgoff %lx returning %lx, flags & MAP_FIXED %lu\n", current->pid, addr, len, rc, given_fd, flags, prot, pgoff, retval, flags & MAP_FIXED);

  if (rc != retval)
  {
    TPRINT("Replay mmap_pgoff returns different value %lx than %lx\n", retval, rc);
    syscall_mismatch();
  }

  if (recbuf && given_fd > 0 && !is_cache_file) sys_close(given_fd);

  //Yang
  mm = current->mm;
  down_read(&mm->mmap_sem);
  vma = find_vma(mm, rc);
  //  if (vma && rc >= vma->vm_start && vma->vm_file) {
  if (vma)
  {
    TPRINT("vma ok\n");
    if (vma->vm_file)
    {
      TPRINT("vm_file ok\n");
      if (rc >= vma->vm_start)
      {
        TPRINT("rc>=vm_start ok\n");
        TPRINT("replay_mmap_pgoff: rc: %lx, vm_file->fdentry->d_iname: %s, prot: %lu.\n", rc, vma->vm_file->f_dentry->d_iname, prot);
        strncpy_safe(vm_file_path, vma->vm_file->f_dentry->d_iname, DNAME_INLINE_LEN);
      }
      else
        TPRINT("vm_start: %lx\n", vma->vm_start);
    }
  }
  else
    TPRINT("vma is %p\n", vma);
  up_read(&mm->mmap_sem);

  TPRINT("base addr1: %p\n", node->pos);
  //print_mem(node->pos, 1024);
  /*
    if(given_fd == 5) { // only for this test
      TPRINT("replay: protection about myregion1 will be changed\n");
      sys_mprotect(rc, len, PROT_NONE);
    }
  */

  // Save the regions for preallocation for replay+pin
  if (prt->rp_record_thread->rp_group->rg_save_mmap_flag)
  {
    if (rc != -1)
    {
      MPRINT("Pid %d replay mmap_pgoff reserve memory addr %lx len %lx\n", current->pid, rc, len);
      reserve_memory(rc, len);
    }
  }
  TPRINT("base addr2: %p\n", node->pos);
  //print_mem(node->pos, 1024);

  return rc;
}

static asmlinkage long
theia_sys_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
  long rc;

  rc = sys_mmap_pgoff(addr, len, prot, flags, fd, pgoff);

  if (theia_logging_toggle == 0)
    return rc;

  theia_mmap_ahg((int)fd, addr, len, (uint16_t)prot, flags, pgoff, rc);

  if ((flags & MAP_SHARED) == 0)
    return rc;

#ifdef THEIA_TRACK_SHM_OPEN
  char *vm_file_path = NULL;
  vm_file_path = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
  memset(vm_file_path, '\0', PATH_MAX);
  if ((rc > 0 || rc < -1024) && ((long) fd) >= 0)
  {
    struct vm_area_struct *vma;
    struct mm_struct *mm = current->mm;
    down_read(&mm->mmap_sem);
    vma = find_vma(mm, rc);
    if (vma && rc >= vma->vm_start && vma->vm_file)
    {
      TPRINT("theia_sys_mmap: rc: %lx prot: %lu.\n", rc, prot);

      path = d_path(&(vma->vm_file->f_path), vm_file_path, PATH_MAX);
      if (!IS_ERR(path))
      {
        TPRINT("d_path: %s\n", path);
      }
      else
      {
        TPRINT("d_path returned an error!\n");
      }

      if (!strncmp(path, "/run/shm/", 9) &&
          strncmp(path, "/run/shm/pulse-shm-", 19) &&
          strncmp(path, "/run/shm/uclock", 15))
      {
        is_shmem = true;
      }
    }
    up_read(&mm->mmap_sem);
    if (vm_file_path)
      kmem_cache_free(theia_buffers, vm_file_path);
  }

  if (flags & MAP_SHARED && is_shmem)
  {
    // enforce page allocation
    int __user *address = NULL;

    // TODO: bookeeping vma and prot (read only, read and write, exec)

    int np = len / 0x1000;
    if (len % 0x1000)
      ++np;

    ret = sys_mprotect(rc, len, PROT_WRITE);
    if (!ret)
    {
      int i;
      for (i = 0; i < np; ++i)
      {
        address = (int __user *)(rc + i * 0x1000);
        *address = *address;
      }

      ret = sys_mprotect(rc, len, PROT_NONE);
      //      TPRINT("[logging]protection of a shared page will be changed, ret %d, %s\n", ret, path);
    }
  }
#endif

  return rc;
}

asmlinkage long shim_mmap_pgoff(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
SHIM_CALL_MAIN(9, record_mmap_pgoff(addr, len, prot, flags, fd, pgoff), replay_mmap_pgoff(addr, len, prot, flags, fd, pgoff), theia_sys_mmap(addr, len, prot, flags, fd, pgoff))

static asmlinkage long
record_newstat(char __user *filename, struct stat __user *statbuf)
{
  long rc;
  struct stat *pretval = NULL;

  new_syscall_enter(4);
  rc = sys_newstat(filename, statbuf);
  new_syscall_done(4, rc);
  if (rc >= 0 && statbuf)
  {

    pretval = ARGSKMALLOC(sizeof(struct stat), GFP_KERNEL);

    if (pretval == NULL)
    {
      TPRINT("record_stat: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(pretval, statbuf, sizeof(struct stat)))
    {
      TPRINT("record_stat: can't copy to buffer\n");
      ARGSKFREE(pretval, sizeof(struct stat));
      pretval = NULL;
      rc = -EFAULT;
    }
  }

  new_syscall_exit(4, pretval);
  return rc;
}

//64port
RET1_REPLAY(newstat, 4, struct stat, statbuf, char __user *filename, struct stat __user *statbuf);
asmlinkage long shim_newstat(char __user *filename, struct stat __user *statbuf) SHIM_CALL(newstat, 4, filename, statbuf);

static asmlinkage long
record_newlstat(char __user *filename, struct stat __user *statbuf)
{
  long rc;
  struct stat *pretval = NULL;

  new_syscall_enter(6);
  rc = sys_newlstat(filename, statbuf);
  new_syscall_done(6, rc);
  if (rc >= 0 && statbuf)
  {

    pretval = ARGSKMALLOC(sizeof(struct stat), GFP_KERNEL);

    if (pretval == NULL)
    {
      TPRINT("record_stat64: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(pretval, statbuf, sizeof(struct stat)))
    {
      TPRINT("record_stat64: can't copy to buffer\n");
      ARGSKFREE(pretval, sizeof(struct stat));
      pretval = NULL;
      rc = -EFAULT;
    }
  }

  new_syscall_exit(6, pretval);
  return rc;
}

//64port
RET1_REPLAY(newlstat, 6, struct stat, statbuf, char __user *filename, struct stat __user *statbuf);
asmlinkage long shim_newlstat(char __user *filename, struct stat __user *statbuf) SHIM_CALL(newlstat, 6, filename, statbuf);


//64port
static asmlinkage long
record_newfstat(int fd, struct stat __user *statbuf)
{
  long rc;
  struct stat *pretval = NULL;

  new_syscall_enter(5);
  rc = sys_newfstat(fd, statbuf);
  new_syscall_done(5, rc);
  if (rc >= 0 && statbuf)
  {

    pretval = ARGSKMALLOC(sizeof(struct stat), GFP_KERNEL);
    TPRINT("[%s|%d] in record_newfstat: sizeof stat: %lu\n", __func__, __LINE__, sizeof(struct stat));

    if (pretval == NULL)
    {
      TPRINT("record_fstat: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(pretval, statbuf, sizeof(struct stat)))
    {
      TPRINT("record_fstat: can't copy to buffer\n");
      ARGSKFREE(pretval, sizeof(struct stat));
      pretval = NULL;
      rc = -EFAULT;
    }
  }

  new_syscall_exit(5, pretval);
  return rc;
}

//64port
RET1_REPLAY(newfstat, 5, struct stat, statbuf, int fd, struct stat __user *statbuf);

//64port
asmlinkage long shim_newfstat(int fd, struct stat __user *statbuf) SHIM_CALL(newfstat, 5, fd, statbuf);

//64port
SIMPLE_SHIM0(getuid, 102);
SIMPLE_SHIM0(getgid, 104);
SIMPLE_SHIM0(geteuid, 107);
SIMPLE_SHIM0(getegid, 108);
SIMPLE_SHIM2(setpgid, 109, pid_t, pid, pid_t, pgid);
SIMPLE_SHIM0(getppid, 110);
SIMPLE_SHIM0(getpgrp, 111);
SIMPLE_SHIM0(setsid, 112);
// SIMPLE_SHIM2(setreuid, 113, uid_t, ruid, uid_t, euid);

inline void theia_setreuid_ahgx(uid_t ruid, uid_t euid, long rc, int sysnum)
{
  theia_setuid_ahg(euid, rc); // setreuid -> setuid
}

THEIA_SHIM2(setreuid, 113, uid_t, ruid, uid_t, euid);
SIMPLE_SHIM2(setregid, 114, gid_t, rgid, gid_t, egid);

static asmlinkage long
record_getgroups(int gidsetsize, gid_t __user *grouplist)
{
  long rc;
  gid_t *pretval = NULL;

  new_syscall_enter(115);
  rc = sys_getgroups(gidsetsize, grouplist);
  new_syscall_done(115, rc);
  if (gidsetsize > 0 && rc > 0)
  {
    pretval = ARGSKMALLOC(sizeof(gid_t) * rc, GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_getgroups: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(pretval, grouplist, sizeof(gid_t)*rc))
    {
      TPRINT("record_getgroups: can't copy from user %p into %p\n", grouplist, pretval);
      ARGSKFREE(pretval, sizeof(gid_t)*rc);
      return -EFAULT;
    }
  }
  new_syscall_exit(115, pretval);

  return rc;
}

static asmlinkage long
replay_getgroups(int gidsetsize, gid_t __user *grouplist)
{
  gid_t *retparams = NULL;
  long rc = get_next_syscall(115, (char **) &retparams);
  if (retparams)
  {
    if (copy_to_user(grouplist, retparams, sizeof(gid_t)*rc)) TPRINT("Pid %d cannot copy groups to user\n", current->pid);
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(gid_t)*rc);
  }
  return rc;
}

asmlinkage long shim_getgroups(int gidsetsize, gid_t __user *grouplist) SHIM_CALL(getgroups, 115, gidsetsize, grouplist);

SIMPLE_SHIM2(setgroups, 116, int, gidsetsize, gid_t __user *, grouplist);


inline void theia_setresuid_ahgx(uid_t ruid, uid_t euid, uid_t suid, long rc, int sysnum)
{
  theia_setuid_ahg(euid, rc); // setresuid -> setuid
}

THEIA_SHIM3(setresuid, 117, uid_t, ruid, uid_t, euid, uid_t, suid);

static asmlinkage long
record_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid)
{
  long rc;
  uid_t *pretval = NULL;

  new_syscall_enter(118);
  rc = sys_getresuid(ruid, euid, suid);
  new_syscall_done(118, rc);
  if (rc >= 0)
  {
    pretval = ARGSKMALLOC(sizeof(uid_t) * 3, GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_getresuid: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(pretval, ruid, sizeof(uid_t)) ||
        copy_from_user(pretval + 1, euid, sizeof(uid_t)) ||
        copy_from_user(pretval + 2, suid, sizeof(uid_t)))
    {
      ARGSKFREE(pretval, sizeof(uid_t) * 3);
      return -EFAULT;
    }
  }
  new_syscall_exit(118, pretval);

  return rc;
}

static asmlinkage long
replay_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid)
{
  uid_t *retparams = NULL;
  long rc = get_next_syscall(118, (char **) &retparams);
  if (rc >= 0)
  {
    if (retparams)
    {
      if (copy_to_user(ruid, retparams, sizeof(uid_t)) ||
          copy_to_user(euid, retparams + 1, sizeof(uid_t)) ||
          copy_to_user(suid, retparams + 2, sizeof(uid_t)))
      {
        TPRINT("replay_getresuid: pid %d cannot copy uids to user\n", current->pid);
      }
      argsconsume(current->replay_thrd->rp_record_thread, 3 * sizeof(uid_t));
    }
    else
    {
      TPRINT("getresuid has return values but non-negative rc?\n");
    }
  }
  return rc;
}

asmlinkage long shim_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid) SHIM_CALL(getresuid, 118, ruid, euid, suid);

SIMPLE_SHIM3(setresgid, 119, gid_t, rgid, gid_t, egid, gid_t, sgid);

static asmlinkage long
record_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid)
{
  long rc;
  gid_t *pretval = NULL;

  new_syscall_enter(120);
  rc = sys_getresgid(rgid, egid, sgid);
  new_syscall_done(120, rc);
  if (rc >= 0)
  {
    pretval = ARGSKMALLOC(sizeof(gid_t) * 3, GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_getresgid: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(pretval, rgid, sizeof(gid_t)) ||
        copy_from_user(pretval + 1, egid, sizeof(gid_t)) ||
        copy_from_user(pretval + 2, sgid, sizeof(gid_t)))
    {
      ARGSKFREE(pretval, sizeof(gid_t) * 3);
      return -EFAULT;
    }
  }
  new_syscall_exit(120, pretval);

  return rc;
}

static asmlinkage long
replay_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid)
{
  gid_t *retparams = NULL;
  long rc = get_next_syscall(120, (char **) &retparams);
  if (rc >= 0)
  {
    if (retparams)
    {
      if (copy_to_user(rgid, retparams, sizeof(gid_t)) ||
          copy_to_user(egid, retparams + 1, sizeof(gid_t)) ||
          copy_to_user(sgid, retparams + 2, sizeof(gid_t)))
      {
        TPRINT("replay_getresgid: pid %d cannot copy gids to user\n", current->pid);
      }
      argsconsume(current->replay_thrd->rp_record_thread, 3 * sizeof(gid_t));
    }
    else
    {
      TPRINT("getresgid has return values but non-negative rc?\n");
    }
  }
  return rc;
}

asmlinkage long shim_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid) SHIM_CALL(getresgid, 120, rgid, egid, sgid);

//Yang
struct setuid_ahgv
{
  int             pid;
  int             newuid;
  int             rc;
};


void packahgv_setuid(struct setuid_ahgv *sys_args)
{
  char ids[IDS_LEN+1];
  int size = 0;
  int is_newuser_remote;

  //Yang
  if (theia_logging_toggle)
  {
    char *buf = kmem_cache_alloc(theia_buffers, GFP_KERNEL);
    long sec, nsec;
    get_curr_time(&sec, &nsec);
    get_ids(ids);
    is_newuser_remote = is_remote(current);

#ifdef THEIA_AUX_DATA
    theia_dump_auxdata();
#endif

    size = snprintf(buf, THEIA_KMEM_SIZE-1, "startahg|%d|%d|%ld|%d|%s|%d|%d|%d|%ld|%ld|%u|endahg\n",
                   105, sys_args->pid, current->start_time.tv_sec,
                   sys_args->newuid, ids, sys_args->rc, is_newuser_remote, current->tgid,
                   sec, nsec, current->no_syscalls++);
    if (size < 0)
    {
      pr_warn("%s() size = %i\n", __FUNCTION__, size);
    }
    else
      theia_file_write(buf, size);
    kmem_cache_free(theia_buffers, buf);
  }
}

void theia_setuid_ahg(uid_t uid, int rc)
{
  struct setuid_ahgv *pahgv = NULL;

  if (theia_check_channel() == false)
    return;

  if (is_process_new2(current->pid, current->start_time.tv_sec))
    recursive_packahgv_process();

  //  TPRINT("theia_read_ahg clock", current->record_thrd->rp_precord_clock);
  // Yang: regardless of the return value, passes the failed syscall also
  //  if(rc >= 0)
  {
    pahgv = (struct setuid_ahgv *)KMALLOC(sizeof(struct setuid_ahgv), GFP_KERNEL);
    if (pahgv == NULL)
    {
      TPRINT("theia_setuid_ahg: failed to KMALLOC.\n");
      return;
    }
    pahgv->pid = current->pid;
    pahgv->newuid = (int)uid;
    pahgv->rc = rc;
    packahgv_setuid(pahgv);
    KFREE(pahgv);
  }

}

int theia_sys_setuid(uid_t uid)
{
  int rc;
  rc = sys_setuid(uid);

  // Yang: regardless of the return value, passes the failed syscall also
  //  if (rc >= 0)
  {
    theia_setuid_ahg(uid, rc);
  }
  return rc;
}

//SIMPLE_SHIM1(setuid, 105, uid_t, uid);
//SIMPLE_RECORD1(setuid, 105, uid_t, uid);

static asmlinkage long
record_setuid(uid_t uid)
{
  long rc;
  new_syscall_enter(105);
  rc = sys_setuid(uid);
  theia_setuid_ahg(uid, (int)rc);
  new_syscall_done(105, rc);
  new_syscall_exit(105, NULL);
  return rc;

}

SIMPLE_REPLAY(setuid, 105, uid_t uid);

asmlinkage long shim_setuid(uid_t uid)
SHIM_CALL_MAIN(105, record_setuid(uid), replay_setuid(uid), theia_sys_setuid(uid))

SIMPLE_SHIM1(setgid, 106, gid_t, gid);
SIMPLE_SHIM1(setfsuid, 122, uid_t, uid);
SIMPLE_SHIM1(setfsgid, 123, gid_t, gid);
SIMPLE_SHIM2(pivot_root, 155, const char __user *, new_root, const char __user *, put_old);

static asmlinkage long
record_mincore(unsigned long start, size_t len, unsigned char __user *vec)
{
  char *pretvals = NULL;
  unsigned long pages;
  long rc;

  new_syscall_enter(27);
  rc = sys_mincore(start, len, vec);
  new_syscall_done(27, rc);
  if (rc >= 0)
  {
    pages = len >> PAGE_SHIFT;
    pages += (len & ~PAGE_MASK) != 0;

    pretvals = ARGSKMALLOC(sizeof(u_long) + pages, GFP_KERNEL);
    if (!pretvals)
    {
      TPRINT("record_mincore: can't allocate return buffer\n");
      return -ENOMEM;
    }
    *((u_long *) pretvals) = pages;
    if (copy_from_user(pretvals + sizeof(u_long), vec, pages))
    {
      TPRINT("record_mincore: faulted on readback\n");
      ARGSKFREE(pretvals, sizeof(u_long) + pages);
      return -EFAULT;
    }
  }
  new_syscall_exit(27, pretvals);

  return rc;
}

static asmlinkage long
replay_mincore(unsigned long start, size_t len, unsigned char __user *vec)
{
  char *retparams = NULL;
  long rc = get_next_syscall(27, &retparams);
  if (retparams)
  {
    u_long pages = *((u_long *) retparams);
    if (copy_to_user(vec, retparams + sizeof(u_long), pages)) return syscall_mismatch();
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + pages);
  }
  return rc;
}

asmlinkage long shim_mincore(unsigned long start, size_t len, unsigned char __user *vec) SHIM_CALL(mincore, 27, start, len, vec);

static asmlinkage long
record_madvise(unsigned long start, size_t len_in, int behavior)
{
  long rc;

  rg_lock(current->record_thrd->rp_group);
  new_syscall_enter(28);
  rc = sys_madvise(start, len_in, behavior);
  new_syscall_done(28, rc);
  new_syscall_exit(28, NULL);
  rg_unlock(current->record_thrd->rp_group);

  return rc;
}

static asmlinkage long
replay_madvise(unsigned long start, size_t len_in, int behavior)
{
  long retval, rc = get_next_syscall(28, NULL);
  retval = sys_madvise(start, len_in, behavior);

  if (rc != retval)
  {
    TPRINT("Replay madvise returns different val %lu than %lu\n", retval, rc);
    syscall_mismatch();
  }

  return rc;
}

asmlinkage long shim_madvise(unsigned long start, size_t len_in, int behavior) SHIM_CALL(madvise, 28, start, len_in, behavior);

RET1_COUNT_SHIM3(getdents64, 217, dirent, unsigned int, fd, struct linux_dirent64 __user *, dirent, unsigned int, count);

SIMPLE_SHIM0(gettid, 186);
SIMPLE_SHIM3(readahead, 187, int, fd, loff_t, offset, size_t, count);
SIMPLE_SHIM5(setxattr, 188, const char __user *, path, const char __user *, name, const void __user *, value, size_t, size, int, flags);
SIMPLE_SHIM5(lsetxattr, 189, const char __user *, path, const char __user *, name, const void __user *, value, size_t, size, int, flags);
SIMPLE_SHIM5(fsetxattr, 190, int, fd, const char __user *, name, const void __user *, value, size_t, size, int, flags);
RET1_COUNT_SHIM4(getxattr, 191, value, const char __user *, path, const char __user *, name, void __user *, value, size_t, size);
RET1_COUNT_SHIM4(lgetxattr, 192, value, const char __user *, path, const char __user *, name, void __user *, value, size_t, size);
RET1_COUNT_SHIM4(fgetxattr, 193, value, int, fd, const char __user *, name, void __user *, value, size_t, size);
RET1_COUNT_SHIM3(listxattr, 194, list, const char __user *, path, char __user *, list, size_t, size);
RET1_COUNT_SHIM3(llistxattr, 195, list, const char __user *, path, char __user *, list, size_t, size);
RET1_COUNT_SHIM3(flistxattr, 196, list, int, fd, char __user *, list, size_t, size);
SIMPLE_SHIM2(removexattr, 197, const char __user *, path, const char __user *, name);
SIMPLE_SHIM2(lremovexattr, 198, const char __user *, path, const char __user *, name);
SIMPLE_SHIM2(fremovexattr, 199, int, fd, const char __user *, name);
SIMPLE_SHIM2(tkill, 200, int, pid, int, sig);

#ifdef TIME_TRICK
static inline long
record_futex_ignored(u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)
{
  long rc;
  rc = sys_futex(uaddr, op, val, utime, uaddr2, val3);
  if ((op & 1) == FUTEX_WAIT && utime)
  {
    if (rc == -ETIMEDOUT)
    {
      //add a fake syscall here
      /*
      int need_fake_calls = 1;
      new_syscall_enter (SIGNAL_WHILE_SYSCALL_IGNORED);
      new_syscall_done (SIGNAL_WHILE_SYSCALL_IGNORED, 0);
      new_syscall_exit (SIGNAL_WHILE_SYSCALL_IGNORED, NULL);

      get_user (need_fake_calls, &phead->need_fake_calls);
      need_fake_calls ++;
      put_user (need_fake_calls, &phead->need_fake_calls);
      change_log_special ();*/

      atomic_set(&current->record_thrd->rp_group->rg_det_time.flag, 1);
      //TPRINT ("Pid %d futex_wait timeout after waiting for %lu nsec, rc = %ld\n", current->pid, utime->tv_nsec, rc);
    }
  }
  return rc;
}
#endif

static asmlinkage long
record_futex(u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)
{
  struct pt_regs *pregs;
  long rc;

  new_syscall_enter(202);
  rc = sys_futex(uaddr, op, val, utime, uaddr2, val3);
  new_syscall_done(202, rc);
  pregs = get_pt_regs(NULL);
  // Really should not get here because it means we are missing synchronizations at user level
  TPRINT("Pid %d in replay futex uaddr=%p, op=%d, val=%d, ip=%lx, sp=%lx, bp=%lx\n", current->pid, uaddr, op, val, pregs->ip, pregs->sp, pregs->bp);
  new_syscall_exit(202, NULL);

  return rc;
}

static asmlinkage long
replay_futex(u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)
{
  struct pt_regs *pregs;
  long rc = get_next_syscall(202, NULL);
  pregs = get_pt_regs(NULL);
  // Really should not get here because it means we are missing synchronizations at user level
  TPRINT("Pid %d in replay futex uaddr=%p, op=%d, val=%d, ip=%lx, sp=%lx, bp=%lx\n", current->pid, uaddr, op, val, pregs->ip, pregs->sp, pregs->bp);
  return rc;
}

#ifdef TIME_TRICK
asmlinkage long shim_futex(u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3) SHIM_CALL_IGNORE(futex, 202, uaddr, op, val, utime, uaddr2, val3);
#else
asmlinkage long shim_futex(u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3) SHIM_CALL(futex, 202, uaddr, op, val, utime, uaddr2, val3);
#endif

SIMPLE_SHIM3(sched_setaffinity, 203, pid_t, pid, unsigned int, len, unsigned long __user *, user_mask_ptr);

static asmlinkage long
record_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
  long rc;
  char *pretval = NULL;

  new_syscall_enter(204);
  rc = sys_sched_getaffinity(pid, len, user_mask_ptr);
  new_syscall_done(204, rc);
  if (rc >= 0)
  {
    pretval = ARGSKMALLOC(sizeof(u_long) + len, GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_sched_getaffinity: can't allocate buffer\n");
      return -ENOMEM;
    }
    *((u_long *) pretval) = len;
    if (copy_from_user(pretval + sizeof(u_long), user_mask_ptr, len))
    {
      ARGSKFREE(pretval, sizeof(u_long) + len);
      rc = -EFAULT;
    }
  }
  new_syscall_exit(204, pretval);

  return rc;
}

static asmlinkage long
replay_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
  char *retparams = NULL;
  long rc = get_next_syscall(204, &retparams);
  if (retparams)
  {
    u_long bytes = *((u_long *) retparams);
    if (copy_to_user(user_mask_ptr, retparams + sizeof(u_long), bytes)) return syscall_mismatch();
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + bytes);
  }
  return rc;
}

asmlinkage long shim_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr) SHIM_CALL(sched_getaffinity, 204, pid, len, user_mask_ptr)

// Pin virtualizes this system call but we need to replay the prior behavior.  So, we bypass Pin by using a different syscall number
asmlinkage long sys_fake_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
  return replay_sched_getaffinity(pid, len, user_mask_ptr);
}
/* set_thread_area appears to be thread-specific and deterministic, so do not record/replay (205)  */
/* get_thread_area appears to be thread-specific and deterministic, so do not record/replay (211)  */
RET1_SHIM2(io_setup, 206, aio_context_t, ctxp, unsigned, nr_events, aio_context_t __user *, ctxp);
SIMPLE_SHIM1(io_destroy, 207, aio_context_t, ctx);

static asmlinkage long
record_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout)
{
  long rc;
  char *pretvals = NULL;

  new_syscall_enter(208);
  rc = sys_io_getevents(ctx_id, min_nr, nr, events, timeout);
  new_syscall_done(208, rc);
  if (rc > 0)
  {
    pretvals = ARGSKMALLOC(rc * sizeof(struct io_event), GFP_KERNEL);
    if (pretvals == NULL)
    {
      TPRINT("record_io_getevents: can't allocate buffer with %ld record\n", rc);
      return -ENOMEM;
    }
    if (copy_from_user(pretvals, events, rc * sizeof(struct io_event)))
    {
      TPRINT("record_io_getevents: can't copy buffer with %ld record\n", rc);
      ARGSKFREE(pretvals, rc * sizeof(struct io_event));
      return -EFAULT;
    }
  }
  new_syscall_exit(208, pretvals);

  return rc;
}

static asmlinkage long
replay_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout)
{
  long rc;
  char *retparams = NULL;
  rc = get_next_syscall(208, &retparams);
  if (rc > 0)
  {
    if (copy_to_user(events, retparams, rc * sizeof(struct io_event)))
    {
      TPRINT("Pid %d cannot copy io_getevents retvals to user\n", current->pid);
    }
    argsconsume(current->replay_thrd->rp_record_thread, rc * sizeof(struct io_event));
  }

  return rc;
}

asmlinkage long shim_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout) SHIM_CALL(io_getevents, 208, ctx_id, min_nr, nr, events, timeout);

SIMPLE_SHIM3(io_submit, 209, aio_context_t, ctx_id, long, nr, struct iocb __user *__user *, iocbpp);
RET1_SHIM3(io_cancel, 210, struct io_event, result, aio_context_t, ctx_id, struct iocb __user *, iocb, struct io_event __user *, result);
SIMPLE_SHIM4(fadvise64, 221, int, fd, loff_t, offset, size_t, len, int, advice);

static asmlinkage void
record_exit_group(int error_code)
{
  new_syscall_enter(231);
  new_syscall_done(231, 0);
  new_syscall_exit(231, NULL);
  MPRINT("Pid %d recording exit group with code %d\n", current->pid, error_code);
  sys_exit_group(error_code);
}

static asmlinkage void
replay_exit_group(int error_code)
{
  struct replay_group *prg;
  struct task_struct *t;

  get_next_syscall(231, NULL);
  MPRINT("Pid %d replaying exit group with code %d\n", current->pid, error_code);

  /* We need to force any other replay threads that are running and part of this process to exit */
  prg = current->replay_thrd->rp_group;
  rg_lock(prg->rg_rec_group);
  for (t = next_thread(current); t != current; t = next_thread(t))
  {
    MPRINT("exit_group considering thread %d\n", t->pid);
    if (t->replay_thrd)
    {
      t->replay_thrd->rp_replay_exit = 1;
      MPRINT("told it to exit\n");
    }
    else
    {
      TPRINT("cannot tell thread %d to exit because it is not a replay thread???\n", t->pid);
    }
  }
  rg_unlock(prg->rg_rec_group);
  printk("replay_exit_group set all threads to exit\n");
  sys_exit_group(error_code);  /* Signals should wake up any wakers */
}

asmlinkage void
shim_exit_group(int error_code)
{
  if (current->record_thrd) record_exit_group(error_code);
  if (current->replay_thrd && test_app_syscall(231)) replay_exit_group(error_code);
  sys_exit_group(error_code);
}

RET1_COUNT_SHIM3(lookup_dcookie, 212, buf, u64, cookie64, char __user *, buf, size_t, len);
SIMPLE_SHIM1(epoll_create, 213, int, size);
/* epoll_ctl_old 214 */
/* epoll_wait_old 215 */

SIMPLE_SHIM4(epoll_ctl, 233, int, epfd, int, op, int, fd, struct epoll_event __user *, event);

static asmlinkage long
record_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout)
{
  long rc;
  char *pretvals = NULL;

  new_syscall_enter(232);
  rc = sys_epoll_wait(epfd, events, maxevents, timeout);
  new_syscall_done(232, rc);
  if (rc > 0)
  {
    pretvals = ARGSKMALLOC(rc * sizeof(struct epoll_event), GFP_KERNEL);
    if (pretvals == NULL)
    {
      TPRINT("record_epoll_wait: can't allocate buffer with %ld record\n", rc);
      return -ENOMEM;
    }
    if (copy_from_user(pretvals, events, rc * sizeof(struct epoll_event)))
    {
      TPRINT("record_epoll_wait: can't copy buffer with %ld record\n", rc);
      ARGSKFREE(pretvals, rc * sizeof(struct epoll_event));
      return -EFAULT;
    }
  }
  new_syscall_exit(232, pretvals);

  return rc;
}

static asmlinkage long
replay_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout)
{
  long rc;
  char *retparams = NULL;
  rc = get_next_syscall(232, &retparams);
  if (rc > 0)
  {
    if (copy_to_user(events, retparams, rc * sizeof(struct epoll_event)))
    {
      TPRINT("Pid %d cannot copy epoll_wait retvals to user\n", current->pid);
    }
    argsconsume(current->replay_thrd->rp_record_thread, rc * sizeof(struct epoll_event));
  }

  return rc;
}

asmlinkage long shim_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout) SHIM_CALL(epoll_wait, 232, epfd, events, maxevents, timeout);

static asmlinkage unsigned long
record_remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags)
{
  unsigned long rc;

  rg_lock(current->record_thrd->rp_group);
  new_syscall_enter(216);
  rc = sys_remap_file_pages(start, size, prot, pgoff, flags);
  new_syscall_done(216, rc);
  new_syscall_exit(216, NULL);
  rg_unlock(current->record_thrd->rp_group);

  return rc;
}

static asmlinkage unsigned long
replay_remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags)
{
  u_long retval, rc = get_next_syscall(216, NULL);
  retval = sys_remap_file_pages(start, size, prot, pgoff, flags);
  if (rc != retval)
  {
    TPRINT("replay_remap_file_pages for pid %d returns different value %lu than %lu\n", current->pid, retval, rc);
    return syscall_mismatch();
  }
  return rc;
}

asmlinkage long shim_remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags) SHIM_CALL(remap_file_pages, 216, start, size, prot, pgoff, flags);

SIMPLE_RECORD1(set_tid_address, 218, int __user *, tidptr);

static asmlinkage long
replay_set_tid_address(int __user *tidptr)
{
  sys_set_tid_address(tidptr);
  return get_next_syscall(218, NULL);
}

asmlinkage long shim_set_tid_address(int __user *tidptr) SHIM_CALL(set_tid_address, 218, tidptr);

RET1_SHIM3(timer_create, 222, timer_t, created_timer_id, const clockid_t, which_clock, struct sigevent __user *, timer_event_spec, timer_t __user *, created_timer_id);
RET1_SHIM4(timer_settime, 223, struct itimerspec, old_setting, timer_t, timer_id, int, flags, const struct itimerspec __user *, new_setting, struct itimerspec __user *, old_setting);
RET1_SHIM2(timer_gettime, 224, struct itimerspec, setting, timer_t, timer_id, struct itimerspec __user *, setting);
SIMPLE_SHIM1(timer_getoverrun, 225, timer_t, timer_id);
SIMPLE_SHIM1(timer_delete, 226, timer_t, timer_id);
SIMPLE_SHIM2(clock_settime, 227, const clockid_t, which_clock, const struct timespec __user *, tp);
#ifndef LOG_COMPRESS
RET1_SHIM2(clock_gettime, 228, struct timespec, tp, const clockid_t, which_clock, struct timespec __user *, tp);
#else

#ifdef TIME_TRICK
static asmlinkage long record_clock_gettime_ignored(const clockid_t which_clock, struct timespec __user *tp)
{
  long rc;
  struct record_group *prg = current->record_thrd->rp_group;
  long long time_diff;
  int is_shift = 0;
  unsigned long current_clock = atomic_read(prg->rg_pkrecord_clock);

  rc = sys_clock_gettime(which_clock, tp);

  if (!tp) BUG(); /// fix if needed
  if (DET_TIME_DEBUG) TPRINT("Pid %d clock_(ignored)_gettime_enter %lu, %lu\n", current->pid, tp->tv_sec, tp->tv_nsec);
  if (which_clock != CLOCK_MONOTONIC && which_clock != CLOCK_REALTIME)
  {
    TPRINT("Other clock_gettime? which_clock:%d\n", which_clock);
    atomic_set(&prg->rg_det_time.flag, 1);
    BUG();
  }
  mutex_lock(&prg->rg_time_mutex);
  if (which_clock == CLOCK_REALTIME)
  {
    struct timeval tv;
    tv.tv_sec = tp->tv_sec;
    tv.tv_usec = (tp->tv_nsec + 999) / 1000; //round up as time shouldn't go back
    if (DET_TIME_DEBUG) TPRINT("Pid %d CLOCK_REALTIME converted to %lu, %lu\n", current->pid, tv.tv_sec, tv.tv_usec);
    if (!atomic_read(&prg->rg_det_time.flag))
    {
      time_diff = get_diff_gettimeofday(&prg->rg_det_time, &tv, current_clock);
      if (!(is_shift = is_shift_time(&prg->rg_det_time, time_diff, current_clock)))
      {
        calc_det_gettimeofday(&prg->rg_det_time, &tv, current_clock);
        tp->tv_sec = tv.tv_sec;
        tp->tv_nsec = tv.tv_usec * 1000;
      }
    }
  }
  else
  {
    if (!atomic_read(&prg->rg_det_time.flag))
    {
      time_diff = get_diff_clock_gettime(&prg->rg_det_time, tp, current_clock);
      if (!(is_shift = is_shift_time(&prg->rg_det_time, time_diff, current_clock)))
      {
        calc_det_clock_gettime(&prg->rg_det_time, tp, current_clock);
      }
    }
  }
  if (DET_TIME_DEBUG) TPRINT("Pid %d clock_(ignored)_gettime_exit %lu, %lu\n", current->pid, tp->tv_sec, tp->tv_nsec);
  atomic_set(&prg->rg_det_time.flag, 0);
  mutex_unlock(&prg->rg_time_mutex);
  return rc;
}
#endif

static asmlinkage long record_clock_gettime(const clockid_t which_clock, struct timespec __user *tp)
{
  long rc;
  struct timespec *pretval = NULL;
#ifdef LOG_COMPRESS_1
  struct clog_node *node;
  unsigned int diff;
#endif
#ifdef TIME_TRICK
  int fake_time = 0;
  struct record_group *prg = current->record_thrd->rp_group;
  long long time_diff;
  int is_shift = 0;
  unsigned long current_clock = new_syscall_enter(228);
#else
  new_syscall_enter(228);
#endif

  rc = sys_clock_gettime(which_clock, tp);

#ifdef TIME_TRICK
  if (!tp) BUG(); /// fix if needed
  if (DET_TIME_DEBUG) TPRINT("Pid %d clock_gettime actual time %lu, %lu\n", current->pid, tp->tv_sec, tp->tv_nsec);
  if (which_clock != CLOCK_MONOTONIC && which_clock != CLOCK_REALTIME)
  {
    TPRINT("Other clock_gettime? which_clock:%d\n", which_clock);
    atomic_set(&prg->rg_det_time.flag, 1);
  }
  mutex_lock(&prg->rg_time_mutex);
  if (which_clock == CLOCK_REALTIME)
  {
    struct timeval tv;
    tv.tv_sec = tp->tv_sec;
    tv.tv_usec = (tp->tv_nsec + 999) / 1000; //round up as time shouldn't go back
    TPRINT("Pid %d CLOCK_REALTIME converted to %lu, %lu\n", current->pid, tv.tv_sec, tv.tv_usec);
    if (!atomic_read(&prg->rg_det_time.flag))
    {
      time_diff = get_diff_gettimeofday(&prg->rg_det_time, &tv, current_clock);
      if ((is_shift = is_shift_time(&prg->rg_det_time, time_diff, current_clock)))
      {
        change_log_special_second();
        update_step_time(time_diff, &prg->rg_det_time, current_clock);
        update_fake_accum_gettimeofday(&prg->rg_det_time, &tv, current_clock);
      }
      else
      {
        calc_det_gettimeofday(&prg->rg_det_time, &tv, current_clock);
        tp->tv_sec = tv.tv_sec;
        tp->tv_nsec = tv.tv_usec * 1000;
        if (DET_TIME_DEBUG) TPRINT("Pid %d clock_gettime returns det time\n", current->pid);
        fake_time = 1;
      }
    }
  }
  else
  {
    if (atomic_read(&prg->rg_det_time.flag))
    {
      //return the actual time here
      update_fake_accum_clock_gettime(&prg->rg_det_time, tp, current_clock);
    }
    else
    {
      time_diff = get_diff_clock_gettime(&prg->rg_det_time, tp, current_clock);
      if ((is_shift = is_shift_time(&prg->rg_det_time, time_diff, current_clock)))
      {
        change_log_special_second();
        update_step_time(time_diff, &prg->rg_det_time, current_clock);
        update_fake_accum_clock_gettime(&prg->rg_det_time, tp, current_clock);
      }
      else
      {
        calc_det_clock_gettime(&prg->rg_det_time, tp, current_clock);
        if (DET_TIME_DEBUG) TPRINT("Pid %d clock_gettime returns det time\n", current->pid);
        fake_time = 1;
      }
    }
  }
  if (DET_TIME_DEBUG) TPRINT("Pid %d clock_gettime finally returns %lu, %lu\n", current->pid, tp->tv_sec, tp->tv_nsec);
  atomic_set(&prg->rg_det_time.flag, 0);
  cnew_syscall_done(228, rc, -1, 0);
  mutex_unlock(&prg->rg_time_mutex);
#else
  new_syscall_done(228, rc);
#endif
  if (rc >= 0 && tp)
  {
#ifdef TIME_TRICK
    if (fake_time)
    {
      change_log_special();
      fake_time = 0;
    }
    else
    {
#endif
      pretval = ARGSKMALLOC(sizeof(struct timespec), GFP_KERNEL);
      if (pretval == NULL)
      {
        TPRINT("record_clock_gettime: can't allocate buffer\n");
        return -ENOMEM;
      }
      if (copy_from_user(pretval, tp, sizeof(struct timespec)))
      {
        TPRINT("record_clock_gettime: can't copy to buffer\n");
        ARGSKFREE(pretval, sizeof(struct timespec));
        pretval = NULL;
        rc = -EFAULT;
      }
#ifdef LOG_COMPRESS_1
      node = clog_alloc(sizeof(struct timespec));
      diff = pretval->tv_sec - SYSCALL_CACHE_REC.tp.tv_sec;
      if (diff == 0)
      {
        encodeValue(0, 1, 0, node);
      }
      else
      {
        encodeValue(1, 1, 0, node);
        SYSCALL_CACHE_REC.tp.tv_sec = pretval->tv_sec;
        encodeValue(diff, 32, 4, node);
      }
      diff = pretval->tv_nsec - SYSCALL_CACHE_REC.tp.tv_nsec;
      SYSCALL_CACHE_REC.tp.tv_nsec = pretval->tv_nsec;
      encodeValue(diff, 32, 20, node);
      status_add(&current->record_thrd->rp_clog.syscall_status, 265, sizeof(struct timespec) << 3, getCumulativeBitsWritten(node));
#endif
#ifdef TIME_TRICK
    }
#endif
  }

  new_syscall_exit(228, pretval);
  return rc;
}

static asmlinkage long replay_clock_gettime(const clockid_t which_clock, struct timespec __user *tp)
{
  struct timespec *retparams = NULL;
#ifdef TIME_TRICK
  int fake_time = 0;
  int is_shift = 0;
  long long time_diff;
  u_long start_clock;
  u_char syscall_flag = 0;
  struct record_group *prg = current->replay_thrd->rp_group->rg_rec_group;
  long rc = cget_next_syscall(228, (char **) &retparams, &syscall_flag, 0, &start_clock);
#else
  long rc = get_next_syscall(228, (char **) &retparams);
#endif

#ifdef LOG_COMPRESS_1
  struct clog_node *node;
  struct timespec c_retparams;
  unsigned int value;
#endif

#ifdef TIME_TRICK
  if (syscall_flag & SR_HAS_SPECIAL_FIRST) fake_time = 1;
  if (syscall_flag & SR_HAS_SPECIAL_SECOND) is_shift = 1;
#endif

  if (retparams)
  {
    if (copy_to_user(tp, retparams, sizeof(struct timespec)))
      TPRINT("replay_clock_gettime: pid %d cannot copy to user\n", current->pid);
#ifdef LOG_COMPRESS_1
    node = clog_mark_done_replay();
    decodeValue(&value, 1, 0, 0, node);
    if (value == 0)
    {
      //put_user
      c_retparams.tv_sec = SYSCALL_CACHE_REP.tp.tv_sec;
      if (log_compress_debug) BUG_ON(retparams->tv_sec != c_retparams.tv_sec);
    }
    else
    {
      decodeValue(&value, 32, 4, 0, node);
      c_retparams.tv_sec = SYSCALL_CACHE_REP.tp.tv_sec + value;
      //putuser
      if (log_compress_debug) BUG_ON(retparams->tv_sec != c_retparams.tv_sec);
      SYSCALL_CACHE_REP.tp.tv_sec += value;
    }
    decodeValue(&value, 32, 20, 0, node);
    c_retparams.tv_nsec = SYSCALL_CACHE_REP.tp.tv_nsec + value;
    //putuser
    if (log_compress_debug) BUG_ON(retparams->tv_nsec != c_retparams.tv_nsec);
    SYSCALL_CACHE_REP.tp.tv_nsec += value;
    if (copy_to_user(tp, &c_retparams, sizeof(struct timespec)))
      TPRINT("replay_clock_gettime: pid %d cannot copy to user\n", current->pid);
#endif
#ifdef TIME_TRICK
    if (DET_TIME_DEBUG) TPRINT("clock_gettime returns actual time. actual %ld, %ld\n", tp->tv_sec, tp->tv_nsec);
    if (which_clock == CLOCK_MONOTONIC)
    {
      if (is_shift)
      {
        time_diff = get_diff_clock_gettime(&prg->rg_det_time, tp, start_clock);
        update_step_time(time_diff, &prg->rg_det_time, start_clock);
      }
      update_fake_accum_clock_gettime(&prg->rg_det_time, tp, start_clock);
    }
    else if (which_clock == CLOCK_REALTIME)
    {
      struct timeval tv;
      tv.tv_sec = tp->tv_sec;
      tv.tv_usec = (tp->tv_nsec + 999) / 1000;

      if (is_shift)
      {
        time_diff = get_diff_gettimeofday(&prg->rg_det_time, &tv, start_clock);
        update_step_time(time_diff, &prg->rg_det_time, start_clock);
      }
      update_fake_accum_gettimeofday(&prg->rg_det_time, &tv, start_clock);
    }
#endif
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct timespec));
  }
#ifdef TIME_TRICK
  else
  {
    if (which_clock == CLOCK_MONOTONIC)
      calc_det_clock_gettime(&prg->rg_det_time, tp, start_clock);
    else if (which_clock == CLOCK_REALTIME)
    {
      struct timeval tv;
      tv.tv_sec = tp->tv_sec;
      tv.tv_usec = (tp->tv_nsec + 999) / 1000;
      calc_det_gettimeofday(&prg->rg_det_time, &tv, start_clock);
      tp->tv_sec = tv.tv_sec;
      tp->tv_nsec = tv.tv_usec * 1000;

    }
    if (DET_TIME_DEBUG) TPRINT("clock_gettime returns deterministic time.\n");
  }
  if (DET_TIME_DEBUG) TPRINT("Pid %d clock_gettime finally returns %lu, %lu\n", current->pid, tp->tv_sec, tp->tv_nsec);
#endif

  return rc;
}

#ifdef TIME_TRICK
asmlinkage long shim_clock_gettime(const clockid_t which_clock, struct timespec __user *tp) SHIM_CALL_IGNORE(clock_gettime, 265, which_clock, tp);
#else
asmlinkage long shim_clock_gettime(const clockid_t which_clock, struct timespec __user *tp) SHIM_CALL(clock_gettime, 265, which_clock, tp);
#endif

#endif
RET1_SHIM2(clock_getres, 229, struct timespec, tp, const clockid_t, which_clock, struct timespec __user *, tp);
RET1_SHIM4(clock_nanosleep, 230, struct timespec, rmtp, const clockid_t, which_clock, int, flags, const struct timespec __user *, rqtp, struct timespec __user *, rmtp);
SIMPLE_SHIM3(tgkill, 234, int, tgid, int, pid, int, sig);
SIMPLE_SHIM2(utimes, 235, char __user *, filename, struct timeval __user *, utimes);
/* vserver 236 */
SIMPLE_SHIM6(mbind, 237, unsigned long, start, unsigned long, len, unsigned long, mode, unsigned long __user *, nmask, unsigned long, maxnode, unsigned, flags);

static asmlinkage long
record_get_mempolicy(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags)
{
  char *pretvals = NULL;
  long rc;

  new_syscall_enter(239);
  rc = sys_get_mempolicy(policy, nmask, maxnode, addr, flags);
  new_syscall_done(239, rc);
  if (rc >= 0)
  {
    unsigned long copy = ALIGN(maxnode - 1, 64) / 8;
    pretvals = ARGSKMALLOC(sizeof(u_long) + sizeof(int) + copy, GFP_KERNEL);
    if (!pretvals)
    {
      TPRINT("record_get_mempolicy: can't allocate return buffer\n");
      return -ENOMEM;
    }
    *((u_long *) pretvals) = sizeof(int) + copy;
    if (policy)
    {
      int kpolicy;
      if (get_user(kpolicy, policy) == 0) *((int *)(pretvals + sizeof(u_long))) = kpolicy;
    }
    if (copy_from_user(pretvals + sizeof(u_long) + sizeof(int), nmask, copy))
    {
      TPRINT("record_get_mempolicy: faulted on readback\n");
      ARGSKFREE(pretvals, sizeof(u_long) + sizeof(int) + copy);
      return -EFAULT;
    }
  }
  new_syscall_exit(239, pretvals);

  return rc;
}

static asmlinkage long
replay_get_mempolicy(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags)
{
  char *retparams = NULL;
  long rc = get_next_syscall(239, &retparams);
  if (retparams)
  {
    u_long bytes = *((u_long *) retparams);
    if (policy) put_user(*((int *)(retparams + sizeof(u_long))), policy);
    if (copy_to_user(nmask, retparams + sizeof(u_long) + sizeof(int), bytes - sizeof(int))) return syscall_mismatch();
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + bytes);
  }
  return rc;
}

asmlinkage long shim_get_mempolicy(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags) SHIM_CALL(get_mempolicy, 239, policy, nmask, maxnode, addr, flags);

SIMPLE_SHIM3(set_mempolicy, 238, int, mode, unsigned long __user *, nmask, unsigned long, maxnode);
SIMPLE_SHIM4(mq_open, 240, const char __user *, u_name, int, oflag, mode_t, mode, struct mq_attr __user *, u_attr);
SIMPLE_SHIM1(mq_unlink, 241, const char __user *, u_name);
SIMPLE_SHIM5(mq_timedsend, 242, mqd_t, mqdes, const char __user *, u_msg_ptr, size_t, msg_len, unsigned int, msg_prio, const struct timespec __user *, u_abs_timeout);
RET1_COUNT_SHIM5(mq_timedreceive, 243, u_msg_ptr, mqd_t, mqdes, char __user *, u_msg_ptr, size_t, msg_len, unsigned int __user *, u_msg_prio, const struct timespec __user *, u_abs_timeout);
SIMPLE_SHIM2(mq_notify, 244, mqd_t, mqdes, const struct sigevent __user *, u_notification);
RET1_SHIM3(mq_getsetattr, 245, struct mq_attr, u_omqstat, mqd_t, mqdes, const struct mq_attr __user *, u_mqstat, struct mq_attr __user *, u_omqstat);
SIMPLE_SHIM4(kexec_load, 246, unsigned long, entry, unsigned long, nr_segments, struct kexec_segment __user *, segments, unsigned long, flags);

struct waitid_retvals
{
  struct siginfo info;
  struct rusage  ru;
};

static asmlinkage long
record_waitid(int which, pid_t upid, struct siginfo __user *infop, int options, struct rusage __user *ru)
{
  long rc;
  struct waitid_retvals *retvals = NULL;

  new_syscall_enter(247);
  rc = sys_waitid(which, upid, infop, options, ru);
  new_syscall_done(247, rc);
  if (rc >= 0)
  {
    retvals = ARGSKMALLOC(sizeof(struct waitid_retvals), GFP_KERNEL);
    if (retvals == NULL)
    {
      TPRINT("record_waitid: can't allocate buffer\n");
      return -ENOMEM;
    }

    if (infop)
    {
      if (copy_from_user(&retvals->info, infop, sizeof(struct siginfo)))
      {
        TPRINT("record_waitid: unable to copy siginfo from user\n");
        ARGSKFREE(retvals, sizeof(struct waitid_retvals));
        return -EFAULT;
      }
    }
    if (ru)
    {
      if (copy_from_user(&retvals->ru, ru, sizeof(struct rusage)))
      {
        TPRINT("record_waitid: unable to copy rusage from user\n");
        ARGSKFREE(retvals, sizeof(struct waitid_retvals));
        return -EFAULT;
      }
    }
  }
  new_syscall_exit(247, retvals);

  return rc;
}

static asmlinkage long
replay_waitid(int which, pid_t upid, struct siginfo __user *infop, int options, struct rusage __user *ru)
{
  struct waitid_retvals *pretvals;
  long rc = get_next_syscall(247, (char **) &pretvals);
  if (rc >= 0)
  {
    if (infop)
    {
      if (copy_to_user(infop, &pretvals->info, sizeof(struct siginfo)))
      {
        TPRINT("Pid %d replay_waitid cannot copy status to user\n", current->pid);
        return syscall_mismatch();
      }
    }
    if (ru)
    {
      if (copy_to_user(ru, &pretvals->ru, sizeof(struct rusage)))
      {
        TPRINT("Pid %d replay_waitid cannot copy status to user\n", current->pid);
        return syscall_mismatch();
      }
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct waitid_retvals));
  }
  return rc;
}

asmlinkage long shim_waitid(int which, pid_t upid, struct siginfo __user *infop, int options, struct rusage __user *ru) SHIM_CALL(waitid, 247, which, upid, infop, options, ru);

SIMPLE_SHIM5(add_key, 248, const char __user *, _type, const char __user *, _description, const void __user *, _payload, size_t, plen, key_serial_t, ringid);
SIMPLE_SHIM4(request_key, 249, const char __user *, _type, const char __user *, _description, const char __user *, _callout_info, key_serial_t, destringid);

static asmlinkage long
record_keyctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
  char *recbuf = NULL;
  long rc;

  new_syscall_enter(250);
  rc = sys_keyctl(option, arg2, arg3, arg4, arg5);
  new_syscall_done(250, rc);
  if (rc >= 0)
  {
    if (option == KEYCTL_DESCRIBE || option == KEYCTL_READ || option == KEYCTL_GET_SECURITY)
    {
      recbuf = ARGSKMALLOC(arg4 + sizeof(u_long), GFP_KERNEL);
      if (!recbuf)
      {
        TPRINT("record_keyctl: can't allocate return buffer\n");
        return -ENOMEM;
      }
      *(u_long *) recbuf = arg4;
      if (copy_from_user(recbuf + sizeof(u_long), (char __user *) arg3, arg4))
      {
        TPRINT("record_keyctl: faulted on readback\n");
        return -EFAULT;
      }
    }
  }
  new_syscall_exit(250, recbuf);

  return rc;
}

static asmlinkage long
replay_keyctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
  char *retparams = NULL;
  long rc = get_next_syscall(250, &retparams);
  if (retparams)
  {
    u_long bytes = *((u_long *) retparams);
    if (copy_to_user((char __user *)arg3, retparams + sizeof(u_long), bytes)) return syscall_mismatch();
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + bytes);
  }
  return rc;
}

asmlinkage long shim_keyctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) SHIM_CALL(keyctl, 250, option, arg2, arg3, arg4, arg5);

SIMPLE_SHIM3(ioprio_set, 251, int, which, int, who, int, ioprio);
SIMPLE_SHIM2(ioprio_get, 252, int, which, int, who);
SIMPLE_SHIM0(inotify_init, 253);
SIMPLE_SHIM3(inotify_add_watch, 254, int, fd, const char __user *, path, u32, mask);
SIMPLE_SHIM2(inotify_rm_watch, 255, int, fd, u32, wd);
SIMPLE_SHIM4(migrate_pages, 256, pid_t, pid, unsigned long, maxnode, const unsigned long __user *, old_nodes, const unsigned long __user *, new_nodes);
// SIMPLE_SHIM4(openat, 257, int, dfd, const char __user *, filename, int, flags, int, mode);

SIMPLE_SHIM3(mkdirat, 258, int, dfd, const char __user *, pathname, int, mode);
// THEIA_SHIM3(mkdirat, 258, int, dfd, const char __user *, pathname, int, mode);

SIMPLE_SHIM4(mknodat, 259, int, dfd, const char __user *, filename, int, mode, unsigned, dev);
// THEIA_SHIM4(mknodat, 259, int, dfd, const char __user *, filename, int, mode, unsigned, dev);
//SIMPLE_SHIM5(fchownat, 260, int, dfd, const char __user *, filename, uid_t, user, gid_t, group, int, flag);
THEIA_SHIM5(fchownat, 260, int, dfd, char __user *, filename, uid_t, user, gid_t, group, int, flag);

SIMPLE_SHIM3(futimesat, 261, int, dfd, char __user *, filename, struct timeval __user *, utimes);
//64port
RET1_SHIM4(newfstatat, 262, struct stat, statbuf, int, dfd, char __user *, filename, struct stat __user *, statbuf, int, flag);

// SIMPLE_SHIM3(unlinkat, 263, int, dfd, const char __user *, pathname, int, flag);

SIMPLE_SHIM4(renameat, 264, int, olddfd, const char __user *, oldname, int, newdfd, const char __user *, newname);
// THEIA_SHIM4(renameat, 264, int, olddfd, const char __user *, oldname, int, newdfd, const char __user *, newname);
SIMPLE_SHIM5(linkat, 265, int, olddfd, const char __user *, oldname, int, newdfd, const char __user *, newname, int, flags);
// THEIA_SHIM5(linkat, 265, int, olddfd, const char __user *, oldname, int, newdfd, const char __user *, newname, int, flags);
SIMPLE_SHIM3(symlinkat, 266, const char __user *, oldname, int, newdfd, const char __user *, newname);
// THEIA_SHIM3(symlinkat, 266, const char __user *, oldname, int, newdfd, const char __user *, newname);

RET1_COUNT_SHIM4(readlinkat, 267, buf, int, dfd, const char __user *, path, char __user *, buf, int, bufsiz)

//SIMPLE_SHIM3(fchmodat, 268, int, dfd, const char __user *, filename, mode_t, mode);
THEIA_SHIM3(fchmodat, 268, int, dfd, char __user *, filename, mode_t, mode);
SIMPLE_SHIM3(faccessat, 269, int, dfd, const char __user *, filename, int, mode);
// THEIA_SHIM3(faccessat, 269, int, dfd, const char __user *, filename, int, mode);



static asmlinkage long
record_pselect6(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timespec __user *tsp, void __user *sig)
{
  long rc;
  struct pselect6_retvals *pretvals;

  new_syscall_enter(270);
  rc = sys_pselect6(n, inp, outp, exp, tsp, sig);
  new_syscall_done(270, rc);

  /* Record user's memory regardless of return value in order to capture partial output. */
  pretvals = ARGSKMALLOC(sizeof(struct pselect6_retvals), GFP_KERNEL);
  if (pretvals == NULL)
  {
    TPRINT("record_pselect6: can't allocate buffer\n");
    return -ENOMEM;
  }
  memset(pretvals, 0, sizeof(struct pselect6_retvals));
  if (inp && copy_from_user(&pretvals->inp, inp, sizeof(fd_set)) == 0)
    pretvals->has_inp = 1;
  if (outp && copy_from_user(&pretvals->outp, outp, sizeof(fd_set)) == 0)
    pretvals->has_outp = 1;
  if (exp && copy_from_user(&pretvals->exp, exp, sizeof(fd_set)) == 0)
    pretvals->has_exp = 1;
  if (tsp && copy_from_user(&pretvals->tsp, tsp, sizeof(struct timespec)) == 0)
    pretvals->has_tsp = 1;

  new_syscall_exit(270, pretvals);

  return rc;
}

asmlinkage long
replay_pselect6(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timespec __user *tsp, void __user *sig)
{
  struct pselect6_retvals *retparams = NULL;
  long rc = get_next_syscall(270, (char **) &retparams);
  if (retparams->has_inp && copy_to_user(inp, &retparams->inp, sizeof(fd_set)))
  {
    TPRINT("Pid %d cannot copy inp to user\n", current->pid);
  }
  if (retparams->has_outp && copy_to_user(outp, &retparams->outp, sizeof(fd_set)))
  {
    TPRINT("Pid %d cannot copy outp to user\n", current->pid);
  }
  if (retparams->has_exp && copy_to_user(exp, &retparams->exp, sizeof(fd_set)))
  {
    TPRINT("Pid %d cannot copy exp to user\n", current->pid);
  }
  if (retparams->has_tsp && copy_to_user(tsp, &retparams->tsp, sizeof(struct timespec)))
  {
    TPRINT("Pid %d cannot copy tvp to user\n", current->pid);
  }
  argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct pselect6_retvals));

  return rc;
}

asmlinkage long shim_pselect6(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timespec __user *tsp, void __user *sig) SHIM_CALL(pselect6, 270, n, inp, outp, exp, tsp, sig);

static asmlinkage long
record_ppoll(struct pollfd __user *ufds, unsigned int nfds, struct timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize)
{
  long rc;
  char *pretvals;

  new_syscall_enter(271);
  rc = sys_ppoll(ufds, nfds, tsp, sigmask, sigsetsize);
  new_syscall_done(271, rc);

  /* Record user's memory regardless of return value in order to capture partial output. */
  pretvals = ARGSKMALLOC(sizeof(u_long) + nfds * sizeof(struct pollfd), GFP_KERNEL);
  if (pretvals == NULL)
  {
    TPRINT("record_ppoll: can't allocate buffer\n");
    return -ENOMEM;
  }
  *((u_long *)pretvals) = nfds * sizeof(struct pollfd);
  if (copy_from_user(pretvals + sizeof(u_long), ufds, nfds * sizeof(struct pollfd)))
  {
    TPRINT("record_ppoll: can't copy retvals\n");
    ARGSKFREE(pretvals, sizeof(u_long) + nfds * sizeof(struct pollfd));
    return -EFAULT;
  }

  new_syscall_exit(271, pretvals);

  return rc;
}

static asmlinkage long
replay_ppoll(struct pollfd __user *ufds, unsigned int nfds, struct timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize)
{
  char *retparams = NULL;
  long rc;

  rc = get_next_syscall(271, (char **) &retparams);
  if (copy_to_user(ufds, retparams + sizeof(u_long), nfds * sizeof(struct pollfd)))
  {
    TPRINT("Pid %d cannot copy inp to user\n", current->pid);
  }
  argsconsume(current->replay_thrd->rp_record_thread, nfds * sizeof(struct pollfd));

  return rc;
}

asmlinkage long shim_ppoll(struct pollfd __user *ufds, unsigned int nfds, struct timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize) SHIM_CALL(ppoll, 271, ufds, nfds, tsp, sigmask, sigsetsize);

SIMPLE_SHIM1(unshare, 272, unsigned long, unshare_flags);
SIMPLE_SHIM2(set_robust_list, 273, struct robust_list_head __user *, head, size_t, len);

struct get_robust_list_retvals
{
  struct robust_list_head __user *head_ptr;
  size_t                           len;
};

static asmlinkage long
record_get_robust_list(int pid, struct robust_list_head __user *__user *head_ptr, size_t __user *len_ptr)
{
  long rc;
  struct get_robust_list_retvals *retvals = NULL;

  new_syscall_enter(274);
  rc = sys_get_robust_list(pid, head_ptr, len_ptr);
  new_syscall_done(274, rc);
  if (rc >= 0)
  {
    retvals = ARGSKMALLOC(sizeof(struct get_robust_list_retvals), GFP_KERNEL);
    if (retvals == NULL)
    {
      TPRINT("record_get_robust_list: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(&retvals->head_ptr, head_ptr, sizeof(struct robust_list_head __user *)))
    {
      TPRINT("record_get_robust_list: unable to copy head_ptr from user\n");
      ARGSKFREE(retvals, sizeof(struct get_robust_list_retvals));
      return -EFAULT;
    }
    if (copy_from_user(&retvals->len, len_ptr, sizeof(size_t)))
    {
      TPRINT("record_get_robust_list: unable to copy len from user\n");
      ARGSKFREE(retvals, sizeof(struct get_robust_list_retvals));
      return -EFAULT;
    }
  }
  new_syscall_exit(274, retvals);

  return rc;
}

static asmlinkage long
replay_get_robust_list(int pid, struct robust_list_head __user *__user *head_ptr, size_t __user *len_ptr)
{
  struct get_robust_list_retvals *pretvals;
  long rc = get_next_syscall(274, (char **) &pretvals);
  if (rc >= 0)
  {
    if (copy_to_user(head_ptr, &pretvals->head_ptr, sizeof(struct robust_list_head __user *)))
    {
      TPRINT("Pid %d replay_get_robust_list cannot copy head_ptr to user\n", current->pid);
      return syscall_mismatch();
    }
    if (copy_to_user(len_ptr, &pretvals->len, sizeof(size_t)))
    {
      TPRINT("Pid %d replay_get_robust_list cannot copy len to user\n", current->pid);
      return syscall_mismatch();
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct get_robust_list_retvals));
  }
  return rc;
}

asmlinkage long shim_get_robust_list(int pid, struct robust_list_head __user *__user *head_ptr, size_t __user *len_ptr) SHIM_CALL(get_robust_list, 274, pid, head_ptr, len_ptr);

struct splice_retvals
{
  loff_t off_in;
  loff_t off_out;
};

static asmlinkage long
record_splice(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags)
{
  long rc;
  struct splice_retvals *pretvals = NULL;

  new_syscall_enter(275);
  rc = sys_splice(fd_in, off_in, fd_out, off_out, len, flags);
  new_syscall_done(275, rc);
  if (rc == 0)
  {
    pretvals = ARGSKMALLOC(sizeof(struct splice_retvals), GFP_KERNEL);
    if (pretvals == NULL)
    {
      TPRINT("record_splice: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (off_in)
    {
      if (copy_from_user(&pretvals->off_in, off_in, sizeof(loff_t)))
      {
        TPRINT("record_splic: pid %d cannot copy off_in from user\n", current->pid);
        ARGSKFREE(pretvals, sizeof(struct splice_retvals));
        return -EFAULT;
      }
    }
    if (off_out)
    {
      if (copy_from_user(&pretvals->off_out, off_out, sizeof(loff_t)))
      {
        TPRINT("record_splice: pid %d cannot copy off_out from user\n", current->pid);
        ARGSKFREE(pretvals, sizeof(struct splice_retvals));
        return -EFAULT;
      }
    }

  }
  new_syscall_exit(275, pretvals);

  return rc;
}

static asmlinkage long
replay_splice(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags)
{
  struct splice_retvals *retparams = NULL;
  long rc = get_next_syscall(275, (char **) &retparams);

  if (retparams)
  {
    if (off_in)
    {
      if (copy_to_user(off_in, &retparams->off_in, sizeof(loff_t)))
      {
        TPRINT("replay_splice: pid %d cannot copy off_in to user\n", current->pid);
        return syscall_mismatch();
      }
    }
    if (off_out)
    {
      if (copy_to_user(off_out, &retparams->off_out, sizeof(loff_t)))
      {
        TPRINT("replay_splice: pid %d cannot copy tz to user\n", current->pid);
        return syscall_mismatch();
      }
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct splice_retvals));
  }
  return rc;
}

asmlinkage long shim_splice(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags) SHIM_CALL(splice, 275, fd_in, off_in, fd_out, off_out, len, flags);

SIMPLE_SHIM4(tee, 276, int, fdin, int, fdout, size_t, len, unsigned int, flags);
SIMPLE_SHIM4(sync_file_range, 277, int, fd, loff_t, offset, loff_t, nbytes, unsigned int, flags);
SIMPLE_SHIM4(vmsplice, 278, int, fd, const struct iovec __user *, iov, unsigned long, nr_segs, unsigned int, flags);

static asmlinkage long
record_move_pages(pid_t pid, unsigned long nr_pages, const void __user *__user *pages, const int __user *nodes, int __user *status, int flags)
{
  char *pretvals = NULL;
  long rc;

  new_syscall_enter(279);
  rc = sys_move_pages(pid, nr_pages, pages, nodes, status, flags);
  new_syscall_done(279, rc);
  if (rc >= 0)
  {
    pretvals = ARGSKMALLOC(sizeof(u_long) + nr_pages * sizeof(int), GFP_KERNEL);
    if (!pretvals)
    {
      TPRINT("record_move_pages: can't allocate return buffer\n");
      return -ENOMEM;
    }
    *((u_long *) pretvals) = nr_pages;
    if (copy_from_user(pretvals + sizeof(u_long), status, nr_pages * sizeof(int)))
    {
      TPRINT("record_move_pages: faulted on readback\n");
      ARGSKFREE(pretvals, sizeof(u_long) + nr_pages * sizeof(int));
      return -EFAULT;
    }
  }
  new_syscall_exit(279, pretvals);

  return rc;
}

static asmlinkage long
replay_move_pages(pid_t pid, unsigned long nr_pages, const void __user *__user *pages, const int __user *nodes, int __user *status, int flags)
{
  char *retparams = NULL;
  long rc = get_next_syscall(279, &retparams);
  if (retparams)
  {
    u_long bytes = *((u_long *) retparams);
    if (copy_to_user(status, retparams + sizeof(u_long), bytes)) return syscall_mismatch();
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + bytes);
  }
  return rc;
}

asmlinkage long shim_move_pages(pid_t pid, unsigned long nr_pages, const void __user *__user *pages, const int __user *nodes, int __user *status, int flags) SHIM_CALL(move_pages, 279, pid, nr_pages, pages, nodes, status, flags);

static asmlinkage long
record_getcpu(unsigned __user *cpup, unsigned __user *nodep, struct getcpu_cache __user *unused)
{
  long rc;
  //old_uid_t* pretval = NULL;
  //64port
  uid_t *pretval = NULL;

  new_syscall_enter(309);
  rc = sys_getcpu(cpup, nodep, unused);
  new_syscall_done(309, rc);
  if (rc >= 0)
  {
    pretval = ARGSKMALLOC(sizeof(unsigned) * 2, GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_getcpu: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (cpup)
    {
      if (copy_from_user(pretval, cpup, sizeof(unsigned)))
      {
        TPRINT("record_getcpu: can't copy cpup\n");
        ARGSKFREE(pretval, sizeof(unsigned) * 2);
        return -EFAULT;
      }
    }
    if (nodep)
    {
      if (copy_from_user(pretval + 1, nodep, sizeof(unsigned)))
      {
        TPRINT("record_getcpu: can't copy cpup\n");
        ARGSKFREE(pretval, sizeof(unsigned) * 2);
        return -EFAULT;
      }
    }
  }
  new_syscall_exit(309, pretval);

  return rc;
}

static asmlinkage long
replay_getcpu(unsigned __user *cpup, unsigned __user *nodep, struct getcpu_cache __user *unused)
{
  unsigned *retparams = NULL;
  long rc = get_next_syscall(309, (char **) &retparams);
  if (rc >= 0)
  {
    if (retparams)
    {
      if (cpup)
      {
        if (copy_to_user(cpup, retparams, sizeof(unsigned)))
        {
          TPRINT("replay_getcpu: pid %d cannot copy cpup to user\n", current->pid);
        }
      }
      if (nodep)
      {
        if (copy_to_user(nodep, retparams + 1, sizeof(unsigned)))
        {
          TPRINT("replay_getcpu: pid %d cannot copy nodep to user\n", current->pid);
        }
      }
      argsconsume(current->replay_thrd->rp_record_thread, 2 * sizeof(unsigned));
    }
  }
  return rc;
}

asmlinkage long shim_getcpu(unsigned __user *cpup, unsigned __user *nodep, struct getcpu_cache __user *unused) SHIM_CALL(getcpu, 309, cpup, nodep, unused);

static asmlinkage long
record_epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize)
{
  long rc;
  char *pretvals = NULL;

  new_syscall_enter(281);
  rc = sys_epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize);
  new_syscall_done(281, rc);
  if (rc > 0)
  {
    pretvals = ARGSKMALLOC(rc * sizeof(struct epoll_event), GFP_KERNEL);
    if (pretvals == NULL)
    {
      TPRINT("record_epoll_pwait: can't allocate buffer with %ld record\n", rc);
      return -ENOMEM;
    }
    if (copy_from_user(pretvals, events, rc * sizeof(struct epoll_event)))
    {
      TPRINT("record_epoll_pwait: can't copy buffer with %ld record\n", rc);
      ARGSKFREE(pretvals, rc * sizeof(struct epoll_event));
      return -EFAULT;
    }
  }
  new_syscall_exit(281, pretvals);

  return rc;
}

static asmlinkage long
replay_epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize)
{
  long rc;
  char *retparams = NULL;
  rc = get_next_syscall(281, &retparams);
  if (rc > 0)
  {
    if (copy_to_user(events, retparams, rc * sizeof(struct epoll_event)))
    {
      TPRINT("Pid %d cannot copy epoll_pwait retvals to user\n", current->pid);
    }
    argsconsume(current->replay_thrd->rp_record_thread, rc * sizeof(struct epoll_event));
  }

  return rc;
}

asmlinkage long shim_epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize) SHIM_CALL(epoll_pwait, 281, epfd, events, maxevents, timeout, sigmask, sigsetsize);

SIMPLE_SHIM4(utimensat, 280, int, dfd, char __user *, filename, struct timespec __user *, utimes, int, flags);
SIMPLE_SHIM3(signalfd, 282, int, ufd, sigset_t __user *, user_mask, size_t, sizemask);
SIMPLE_SHIM2(timerfd_create, 283, int, clockid, int, flags);
SIMPLE_SHIM1(eventfd, 284, unsigned int, count);
SIMPLE_SHIM4(fallocate, 285, int, fd, int, mode, loff_t, offset, loff_t, len);
RET1_SHIM4(timerfd_settime, 286, struct itimerspec, otmr, int, ufd, int, flags, const struct itimerspec __user *, utmr, struct itimerspec __user *, otmr);
RET1_SHIM2(timerfd_gettime, 287, struct itimerspec, otmr, int, ufd, struct itimerspec __user *, otmr);
SIMPLE_SHIM4(signalfd4, 289, int, ufd, sigset_t __user *, user_mask, size_t, sizemask, int, flags);
SIMPLE_SHIM2(eventfd2, 290, unsigned int, count, int, flags);
SIMPLE_SHIM1(epoll_create1, 291, int, flags);
SIMPLE_SHIM3(dup3, 292, unsigned int, oldfd, unsigned int, newfd, int, flags);

asmlinkage long
record_pipe2(int __user *fildes, int flags)
{
  long rc;
  int *pretval = NULL;

  new_syscall_enter(293);
  rc = sys_pipe2(fildes, flags);
  new_syscall_done(293, rc);
  if (rc == 0)
  {
    pretval = ARGSKMALLOC(2 * sizeof(int), GFP_KERNEL);
    if (pretval == NULL)
    {
      TPRINT("record_pipe2: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (copy_from_user(pretval, fildes, 2 * sizeof(int)))
    {
      ARGSKFREE(pretval, 2 * sizeof(int));
      return -EFAULT;
    }
  }
  new_syscall_exit(293, pretval);

  return rc;
}

RET1_REPLAYG(pipe2, 293, fildes, 2 * sizeof(int), int __user *fildes, int flags);

asmlinkage long shim_pipe2(int __user *fildes, int flags) SHIM_CALL(pipe2, 293, fildes, flags);

SIMPLE_SHIM1(inotify_init1, 294, int, flags);

#define SYS_PREADV 295
void theia_preadv_ahgx(unsigned long fd, const struct iovec __user *vec,  unsigned long vlen, unsigned long pos_l, unsigned long pos_h, long rc, int sysnum)
{
  char uuid_str[THEIA_UUID_LEN + 1];

  if (fd < 0) return; /* TODO */

  if (fd2uuid(fd, uuid_str) == false)
    return; /* TODO: report openat errors? */

  /* TODO: parse iovec */
  theia_dump_str(uuid_str, rc, sysnum);
}

/* TODO: seems that we need to do something more like record_pread */
static asmlinkage long
record_preadv(unsigned long fd, const struct iovec __user *vec,  unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
  long size;

  new_syscall_enter(295);
  size = sys_preadv(fd, vec, vlen, pos_l, pos_h);
  if (theia_logging_toggle)
    theia_preadv_ahgx(fd, vec, vlen, pos_l, pos_h, size, SYS_PREADV);
  new_syscall_done(295, size);
  new_syscall_exit(295, copy_iovec_to_args(size, vec, vlen));
  return size;
}

static asmlinkage long
replay_preadv(unsigned long fd, const struct iovec __user *vec,  unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
  char *retparams;
  long retval, rc;

  rc = get_next_syscall(295, &retparams);
  if (retparams)
  {
    retval = copy_args_to_iovec(retparams, rc, vec, vlen);
    if (retval < 0) return retval;
    argsconsume(current->replay_thrd->rp_record_thread, rc);
  }

  return rc;
}

static asmlinkage long
theia_sys_preadv(unsigned long fd, const struct iovec __user *vec,  unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
  long rc;
  rc = sys_preadv(fd, vec, vlen, pos_l, pos_h);
  if (theia_logging_toggle)
    theia_preadv_ahgx(fd, vec, vlen, pos_l, pos_h, rc, SYS_PREADV);
  return rc;
}

asmlinkage long shim_preadv(unsigned long fd, const struct iovec __user *vec,  unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
//SHIM_CALL(preadv, 295, fd, vec, vlen, pos_l, pos_h);
SHIM_CALL_MAIN(295, record_preadv(fd, vec, vlen, pos_l, pos_h), replay_preadv(fd, vec, vlen, pos_l, pos_h), theia_sys_preadv(fd, vec, vlen, pos_l, pos_h))

#define SYS_PWRITEV 296
void theia_pwritev_ahgx(unsigned long fd, const struct iovec __user *vec,  unsigned long vlen, unsigned long pos_l, unsigned long pos_h, long rc, int sysnum)
{
  char uuid_str[THEIA_UUID_LEN + 1];

  if (fd < 0) return; /* TODO */

  if (fd2uuid(fd, uuid_str) == false)
    return; /* TODO: report openat errors? */

  /* TODO: parse iovec */
  theia_dump_str(uuid_str, rc, sysnum);
}

static asmlinkage long
record_pwritev(unsigned long fd, const struct iovec __user *vec,  unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
  long size;

  new_syscall_enter(SYS_PWRITEV);
  size = sys_pwritev(fd, vec, vlen, pos_l, pos_h);
  if (theia_logging_toggle)
    theia_pwritev_ahgx(fd, vec, vlen, pos_l, pos_h, size, SYS_PWRITEV);
  new_syscall_done(SYS_PWRITEV, size);
  new_syscall_exit(SYS_PWRITEV, copy_iovec_to_args(size, vec, vlen));
  return size;
}

static asmlinkage long
replay_pwritev(unsigned long fd, const struct iovec __user *vec,  unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
  char *retparams;
  long retval, rc;

  rc = get_next_syscall(SYS_PWRITEV, &retparams);
  if (retparams)
  {
    retval = copy_args_to_iovec(retparams, rc, vec, vlen);
    if (retval < 0) return retval;
    argsconsume(current->replay_thrd->rp_record_thread, rc);
  }

  return rc;
}

static asmlinkage long
theia_sys_pwritev(unsigned long fd, const struct iovec __user *vec,  unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
  long rc;
  rc = sys_pwritev(fd, vec, vlen, pos_l, pos_h);
  if (theia_logging_toggle)
    theia_pwritev_ahgx(fd, vec, vlen, pos_l, pos_h, rc, SYS_PWRITEV);
  return rc;
}

// SIMPLE_SHIM5(pwritev, 296, unsigned long, fd, const struct iovec __user *, vec, unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h);
asmlinkage long shim_pwritev(unsigned long fd, const struct iovec __user *vec,  unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
SHIM_CALL_MAIN(SYS_PWRITEV, record_pwritev(fd, vec, vlen, pos_l, pos_h), replay_pwritev(fd, vec, vlen, pos_l, pos_h), theia_sys_pwritev(fd, vec, vlen, pos_l, pos_h))

SIMPLE_SHIM4(rt_tgsigqueueinfo, 297, pid_t, tgid, pid_t, pid, int, sig, siginfo_t __user *, uinfo);
SIMPLE_SHIM5(perf_event_open, 298, struct perf_event_attr __user *, attr_uptr, pid_t, pid, int, cpu, int, group_fd, unsigned long, flags);

static asmlinkage long
record_recvmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout)
{
  long rc, retval;
  long *plogsize = NULL;
  int i;

  new_syscall_enter(299);
  rc = sys_recvmmsg(fd, msg, vlen, flags, timeout);
  for (i = 0; i < vlen; ++i) {
    theia_recvmsg_ahg(msg[i].msg_len, fd, &(msg[i].msg_hdr), flags);
  }

#ifdef X_COPMRESS
  BUG_ON(is_x_fd(&current->record_thrd->rp_clog.x, fd));
#endif
  new_syscall_done(299, rc);
  if (rc > 0)
  {
    retval = log_mmsghdr(msg, rc, plogsize);
    if (retval < 0) return retval;
  }
  new_syscall_exit(299, plogsize);

  return rc;
}

static asmlinkage long
replay_recvmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout)
{
  char *retparams;
  long rc, retval;

  rc = get_next_syscall(299, &retparams);
  if (retparams)
  {
    retval = extract_mmsghdr(retparams, msg, rc);
    if (retval < 0) syscall_mismatch();
  }

  return rc;
}

static asmlinkage long
theia_sys_recvmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout)
{
  long rc;
  int i;

  rc = sys_recvmmsg(fd, msg, vlen, flags, timeout);

  for (i = 0; i < vlen; ++i) {
    theia_recvmsg_ahg(msg[i].msg_len, fd, &(msg[i].msg_hdr), flags);
  }
  return rc;
}

asmlinkage long shim_recvmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout)
SHIM_CALL_MAIN(299, record_recvmmsg(fd, msg, vlen, flags, timeout), replay_recvmmsg(fd, msg, vlen, flags, timeout), theia_sys_recvmmsg(fd, msg, vlen, flags, timeout))

SIMPLE_SHIM2(fanotify_init, 300, unsigned int, flags, unsigned int, event_f_flags);
SIMPLE_SHIM5(fanotify_mark, 301, int, fanotify_fd, unsigned int, flags, u64, mask, int, fd, const char  __user *, pathname);

RET1_RECORD4(prlimit64, 302, struct rlimit64, old_rlim, pid_t, pid, unsigned int, resource, const struct rlimit64 __user *, new_rlim, struct rlimit64 __user *, old_rlim);

static asmlinkage long
replay_prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim)
{
  struct rlimit64 *retparams = NULL;
  long rc_orig, rc;

  rc_orig = get_next_syscall(302, (char **) &retparams);
  if (new_rlim)
  {
    rc = sys_prlimit64(pid, resource, new_rlim, old_rlim);
    if (rc != rc_orig) TPRINT("Pid %d: prlimit64 pid %d resource %u changed its return in replay, rec %ld rep %ld\n", current->pid, pid, resource, rc_orig, rc);
  }
  if (retparams)
  {
    if (copy_to_user(old_rlim, retparams, sizeof(struct rlimit64))) TPRINT("Pid %d replay_prlimit cannot copy to user\n", current->pid);
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct rlimit64));
  }
  DPRINT("replay_prlimit64 pid %d resource %u returns %ld\n", pid, resource, rc_orig);

  return rc_orig;
}

asmlinkage long shim_prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim) SHIM_CALL(prlimit64, 302, pid, resource, new_rlim, old_rlim);

struct name_to_handle_at_retvals
{
  struct file_handle handle;
  int                mnt_id;
};

static asmlinkage long
record_name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag)
{
  long rc;
  struct name_to_handle_at_retvals *pretvals = NULL;

  new_syscall_enter(303);
  rc = sys_name_to_handle_at(dfd, name, handle, mnt_id, flag);
  new_syscall_done(303, rc);
  if (rc == 0)
  {
    pretvals = ARGSKMALLOC(sizeof(struct name_to_handle_at_retvals), GFP_KERNEL);
    if (pretvals == NULL)
    {
      TPRINT("record_name_to_handle_at: can't allocate buffer\n");
      return -ENOMEM;
    }
    if (handle)
    {
      if (copy_from_user(&pretvals->handle, handle, sizeof(struct file_handle)))
      {
        TPRINT("record_name_to_handle_at: pid %d cannot copy handle from user\n", current->pid);
        ARGSKFREE(pretvals, sizeof(struct name_to_handle_at_retvals));
        return -EFAULT;
      }
    }
    if (mnt_id)
    {
      if (copy_from_user(&pretvals->mnt_id, mnt_id, sizeof(int)))
      {
        TPRINT("record_name_to_handle_at: pid %d cannot copy mnt_id from user\n", current->pid);
        ARGSKFREE(pretvals, sizeof(struct name_to_handle_at_retvals));
        return -EFAULT;
      }
    }
  }
  new_syscall_exit(303, pretvals);

  return rc;
}

static asmlinkage long
replay_name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag)
{
  struct name_to_handle_at_retvals *retparams = NULL;
  long rc = get_next_syscall(303, (char **) &retparams);

  if (retparams)
  {
    if (handle)
    {
      if (copy_to_user(handle, &retparams->handle, sizeof(struct file_handle)))
      {
        TPRINT("replay_name_to_handle_at: pid %d cannot copy handle to user\n", current->pid);
        return syscall_mismatch();
      }
    }
    if (mnt_id)
    {
      if (copy_to_user(mnt_id, &retparams->mnt_id, sizeof(int)))
      {
        TPRINT("replay_name_to_handle_at: pid %d cannot copy tz to user\n", current->pid);
        return syscall_mismatch();
      }
    }
    argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct name_to_handle_at_retvals));
  }
  return rc;
}

asmlinkage long shim_name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag) SHIM_CALL(name_to_handle_at, 303, dfd, name, handle, mnt_id, flag);

SIMPLE_SHIM3(open_by_handle_at, 304, int, mountdirfd, struct file_handle __user *, handle, int, flags);
RET1_SHIM2(clock_adjtime, 305, struct timex, tx, clockid_t, which_clock, struct timex __user *, tx);
SIMPLE_SHIM1(syncfs, 306, int, fd);

static asmlinkage long
theia_sys_sendmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags)
{
  long rc;
  int i;

  rc = sys_sendmmsg(fd, msg, vlen, flags);
  for (i = 0; i < vlen; ++i) {
    theia_sendmsg_ahg(msg[i].msg_len, fd, &(msg[i].msg_hdr), flags);
  }
  return rc;
}

/*
   SIMPLE_SHIM4(sendmmsg, 307, int, fd, struct mmsghdr __user *, msg, unsigned int, vlen, unsigned, flags);
 */
asmlinkage long record_sendmmsg(int fd, struct mmsghdr __user * msg, unsigned int vlen, unsigned flags) {
  long rc;
  int i;

  new_syscall_enter (307);
  rc = sys_sendmmsg(fd, msg, vlen, flags);
  for (i = 0; i < vlen; ++i) {
    theia_sendmsg_ahg(msg[i].msg_len, fd, &(msg[i].msg_hdr), flags);
  }
  new_syscall_done (307, rc);
  new_syscall_exit (307, NULL);
  return rc;
}

SIMPLE_REPLAY(sendmmsg, 307, int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags);
asmlinkage long shim_sendmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags)
SHIM_CALL_MAIN(307, record_sendmmsg(fd, msg, vlen, flags), replay_sendmmsg(fd, msg, vlen, flags), theia_sys_sendmmsg(fd, msg, vlen, flags))

SIMPLE_SHIM2(setns, 308, int, fd, int, nstype);

static asmlinkage long
record_process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)
{
  struct task_struct *tsk = pid_task(find_vpid(pid), PIDTYPE_PID);
  long rc;

  if (tsk)   // Invalid pid should fail, so replay is easy
  {
    if (!tsk->record_thrd)
    {
      TPRINT("[ERROR] pid %d records process_vm_read of non-recordig pid %d\n", current->pid, pid);
      return sys_process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags);
    }
    else if (tsk->record_thrd->rp_group != current->record_thrd->rp_group)
    {
      TPRINT("[ERROR] pid %d records process_vm_read of pid %d in different record group - must merge\n", current->pid, pid);
      return sys_process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags);
    } // Now we know two tasks are in same record group, so memory ops should be deterministic (unless they incorrectly involve replay-specific structures) */
  }

  new_syscall_enter(310);
  rc =  sys_process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags);
  new_syscall_done(310, rc);
  new_syscall_exit(310, NULL);
  return rc;
}

static asmlinkage long
replay_process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)
{
  struct replay_thread *tmp;
  long rc, retval;

  rc = get_next_syscall(310, NULL);

  // Need to adjust pid to reflect the replay process, not the record process
  tmp = current->replay_thrd->rp_next_thread;
  while (tmp != current->replay_thrd)
  {
    if (tmp->rp_record_thread->rp_record_pid == pid)
    {
      retval = sys_process_vm_readv(tmp->rp_record_thread->rp_record_pid, lvec, liovcnt, rvec, riovcnt, flags);
      if (rc != retval)
      {
        TPRINT("process_vm_readv returns %ld on replay but returned %ld on record\n", retval, rc);
        syscall_mismatch();
      }
      return rc;
    }
  }
  TPRINT("process_vm_readv: pid %d cannot find record pid %d in replay group\n", current->pid, pid);
  return syscall_mismatch();
}

asmlinkage long shim_process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags) SHIM_CALL(process_vm_readv, 310, pid, lvec, liovcnt, rvec, riovcnt, flags);

static asmlinkage long
record_process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)
{
  struct task_struct *tsk = pid_task(find_vpid(pid), PIDTYPE_PID);
  long rc;

  if (tsk)   // Invalid pid should fail, so replay is easy
  {
    if (!tsk->record_thrd)
    {
      TPRINT("[ERROR] pid %d records process_vm_writev of non-recordig pid %d\n", current->pid, pid);
      return sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags);
    }
    else if (tsk->record_thrd->rp_group != current->record_thrd->rp_group)
    {
      TPRINT("[ERROR] pid %d records process_vm_writev of pid %d in different record group - must merge\n", current->pid, pid);
      return sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags);
    } // Now we know two tasks are in same record group, so memory ops should be deterministic (unless they incorrectly involve replay-specific structures) */
  }

  new_syscall_enter(311);
  rc =  sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags);
  new_syscall_done(311, rc);
  new_syscall_exit(311, NULL);
  return rc;
}

static asmlinkage long
replay_process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)
{
  struct replay_thread *tmp;
  long rc, retval;

  rc = get_next_syscall(311, NULL);

  // Need to adjust pid to reflect the replay process, not the record process
  tmp = current->replay_thrd->rp_next_thread;
  while (tmp != current->replay_thrd)
  {
    if (tmp->rp_record_thread->rp_record_pid == pid)
    {
      retval = sys_process_vm_writev(tmp->rp_record_thread->rp_record_pid, lvec, liovcnt, rvec, riovcnt, flags);
      if (rc != retval)
      {
        TPRINT("process_vm_writev returns %ld on replay but returned %ld on record\n", retval, rc);
        syscall_mismatch();
      }
      return rc;
    }
  }
  TPRINT("process_vm_writev: pid %d cannot find record pid %d in replay group\n", current->pid, pid);
  return syscall_mismatch();
}

static asmlinkage long
theia_sys_process_vm_writev(pid_t pid, const struct iovec __user *lvec,
                            unsigned long liovcnt, const struct iovec __user *rvec,
                            unsigned long riovcnt, unsigned long flags)
{
  long rc;
  rc = sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags);
  return rc;

}


asmlinkage long shim_process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)
{
  // Paranoid check
  if (!(current->record_thrd  || current->replay_thrd))
  {
    struct task_struct *tsk = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (tsk && tsk->record_thrd)
    {
      TPRINT("[ERROR]: non-recorded process %d modifying the address space of recorded thread %d\n", current->pid, pid);
    }
  }
  //SHIM_CALL(process_vm_writev, 311, pid, lvec, liovcnt, rvec, riovcnt, flags);
  SHIM_CALL_MAIN(311, record_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags),
                 replay_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags),
                 theia_sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags));
}

SIMPLE_SHIM5(kcmp, 312, pid_t, pid1, pid_t, pid2, int, type, unsigned long, idx1, unsigned long, idx2);

struct file *init_log_write(struct record_thread *prect, loff_t *ppos, int *pfd)
{
  char filename[MAX_LOGDIR_STRLEN + 20];
  //struct stat64 st;
  //64port
  struct stat st;
  mm_segment_t old_fs;
  int rc;
  struct file *ret = NULL;
  int flags;

  debug_flag = 0;

  rc = snprintf(filename, MAX_LOGDIR_STRLEN+20, "%s/klog.id.%d", prect->rp_group->rg_logdir, prect->rp_record_pid);
  if (rc < 0)
  {
    TPRINT("init_log_write: rg_logdir is too long\n");
    ret = NULL;
    goto out;
  }

  old_fs = get_fs();
  set_fs(KERNEL_DS);
  if (prect->rp_klog_opened)
  {
    //rc = sys_stat64(filename, &st);
    //64port
    rc = sys_newstat(filename, &st);
    if (rc < 0)
    {
      TPRINT("Stat of file %s failed\n", filename);
      ret = NULL;
      goto out;
    }
    *ppos = st.st_size;
    /*
    TPRINT("%s %d: Attempting to re-open log %s\n", __func__, __LINE__,
        filename);
        */
    flags = O_WRONLY | O_APPEND | O_LARGEFILE;
    *pfd = sys_open(filename, flags, 0777);
    MPRINT("Reopened log file %s, pos = %ld\n", filename, (long) *ppos);
  }
  else
  {
#ifdef LOG_COMPRESS_1
    sprintf(filename, "%s/klog.id.%d.clog", prect->rp_group->rg_logdir, prect->rp_record_pid);
    *pfd = sys_open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
    if (*pfd > 0)
    {
      rc = sys_fchmod(*pfd, 0777);
      if (rc == -1)
      {
        TPRINT("Pid %d fchmod of klog %s failed\n", current->pid, filename);
      }
    }
    MPRINT("Opened log file %s\n", filename);
    if (*pfd < 0)
    {
      TPRINT("%s %d: Cannot open log file %s", __func__, __LINE__, filename);
      ret = NULL;
      goto out;
    }
    sprintf(filename, "%s/klog.id.%d", prect->rp_group->rg_logdir, prect->rp_record_pid);
#endif
    flags = O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE;
    *pfd = sys_open(filename, flags, 0777);
    //TPRINT("%s %d: Creating log %s\n", __func__, __LINE__, filename);
    if (*pfd > 0)
    {
      rc = sys_fchmod(*pfd, 0777);
      if (rc == -1)
      {
        TPRINT("Pid %d fchmod of klog %s failed\n", current->pid, filename);
      }
    }
    MPRINT("Opened log file %s\n", filename);
    *ppos = 0;
    prect->rp_klog_opened = 1;
  }
  set_fs(old_fs);
  if (*pfd < 0)
  {
    /*
    dump_stack();
    TPRINT ("%s %d: Cannot open log file %s, rc = %d flags = %d\n", __func__,
        __LINE__, filename, *pfd, flags);
        */
    ret = NULL;
    goto out;
  }

  ret = fget(*pfd);

out:
  debug_flag = 0;

  return ret;
}

void term_log_write(struct file *file, int fd)
{
  int rc;

  fput(file);

  rc = sys_close(fd);
  if (rc < 0) TPRINT("term_log_write: file close failed with rc %d\n", rc);
}

void write_begin_log(struct file *file, loff_t *ppos, struct record_thread *prect)
{
  int copyed;
  unsigned long long hpc1 = 0;
  unsigned long long hpc2 = 0;
  struct timeval tv1;
  struct timeval tv2;

#ifdef USE_HPC
  hpc1 = rdtsc();
  do_gettimeofday(&tv1);
  hpc2 = rdtsc();
  do_gettimeofday(&tv2);
#endif

  copyed = vfs_write(file, (char *) &hpc1, sizeof(unsigned long long), ppos);
  if (copyed != sizeof(unsigned long long))
  {
    TPRINT("[WARN] Pid %d write_hpc_calibration, expected to write %lu got %d (1)\n",
           current->pid, sizeof(unsigned long long), copyed);
  }

  copyed = vfs_write(file, (char *) &tv1, sizeof(struct timeval), ppos);
  if (copyed != sizeof(struct timeval))
  {
    TPRINT("[WARN] Pid %d write_hpc_calibration, expected to write %lu got %d (2)\n",
           current->pid, sizeof(struct timeval), copyed);
  }

  copyed = vfs_write(file, (char *) &hpc2, sizeof(unsigned long long), ppos);
  if (copyed != sizeof(unsigned long long))
  {
    TPRINT("[WARN] Pid %d write_hpc_calibration, expected to write %lu got %d (3)\n",
           current->pid, sizeof(unsigned long long), copyed);
  }

  copyed = vfs_write(file, (char *) &tv2, sizeof(struct timeval), ppos);
  if (copyed != sizeof(struct timeval))
  {
    TPRINT("[WARN] Pid %d write_hpc_calibration, expected to write %lu got %d (4)\n",
           current->pid, sizeof(struct timeval), copyed);
  }
}

static ssize_t write_log_data(struct file *file, loff_t *ppos, struct record_thread *prect, struct syscall_result *psr, int count, bool isAhg)
{
  struct argsalloc_node *node;
  ssize_t copyed = 0;
  struct iovec *pvec; // Concurrent writes need their own vector
  int kcnt = 0;
  u_long data_len;
#ifdef USE_HPC
  unsigned long long hpc1;
  unsigned long long hpc2;
  struct timeval tv1;
  struct timeval tv2;
#endif

  if (count <= 0) return 0;

  MPRINT("Pid %d, start write log data\n", current->pid);

  pvec = KMALLOC(sizeof(struct iovec) * UIO_MAXIOV, GFP_KERNEL);
  if (pvec == NULL)
  {
    TPRINT("Cannot allocate iovec for write_log_data\n");
    return 0;
  }

#ifdef USE_HPC
  hpc1 = rdtsc();
  do_gettimeofday(&tv1);
  msleep(1);
  hpc2 = rdtsc();
  do_gettimeofday(&tv2);

  copyed = vfs_write(file, (char *) &hpc1, sizeof(unsigned long long), ppos);
  if (copyed != sizeof(unsigned long long))
  {
    TPRINT("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (1)\n", current->pid, sizeof(unsigned long long), copyed);
  }

  copyed = vfs_write(file, (char *) &tv1, sizeof(struct timeval), ppos);
  if (copyed != sizeof(struct timeval))
  {
    TPRINT("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (2)\n", current->pid, sizeof(struct timeval), copyed);
  }

  copyed = vfs_write(file, (char *) &hpc2, sizeof(unsigned long long), ppos);
  if (copyed != sizeof(unsigned long long))
  {
    TPRINT("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (3)\n", current->pid, sizeof(unsigned long long), copyed);
  }

  copyed = vfs_write(file, (char *) &tv2, sizeof(struct timeval), ppos);
  if (copyed != sizeof(struct timeval))
  {
    TPRINT("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (4)\n", current->pid, sizeof(struct timeval), copyed);
  }
#endif

  /* First write out syscall records in a bunch */
  copyed = vfs_write(file, (char *) &count, sizeof(count), ppos);
  if (copyed != sizeof(count))
  {
    TPRINT("write_log_data: tried to write record count, got rc %zd\n", copyed);
    KFREE(pvec);
    return -EINVAL;
  }

  MPRINT("Pid %d write_log_data count %d, size %lu\n", current->pid, count, sizeof(struct syscall_result)*count);

  copyed = vfs_write(file, (char *) psr, sizeof(struct syscall_result) * count, ppos);
  if (copyed != sizeof(struct syscall_result)*count)
  {
    TPRINT("write_log_data: tried to write %lu, got rc %zd\n", sizeof(struct syscall_result)*count, copyed);
    KFREE(pvec);
    return -EINVAL;
  }

  /* Now write ancillary data - count of bytes goes first */
  data_len = 0;
  list_for_each_entry_reverse(node, &prect->rp_argsalloc_list, list)
  {
    data_len += node->pos - node->head;
  }
  MPRINT("Ancillary data written is %lu\n", data_len);
  copyed = vfs_write(file, (char *) &data_len, sizeof(data_len), ppos);
  if (copyed != sizeof(data_len))
  {
    TPRINT("write_log_data: tried to write ancillary data length, got rc %zd, sizeof(count): %lu, sizeof(data_len): %lu\n", copyed, sizeof(count), sizeof(data_len));
    KFREE(pvec);
    return -EINVAL;
  }
  list_for_each_entry_reverse(node, &prect->rp_argsalloc_list, list)
  {
    MPRINT("Pid %d argssize write buffer slab size %li\n", current->pid, node->pos - node->head);
    pvec[kcnt].iov_base = node->head;
    pvec[kcnt].iov_len = node->pos - node->head;
    if (++kcnt == UIO_MAXIOV)
    {
      copyed = vfs_writev(file, pvec, kcnt, ppos);
      kcnt = 0;
    }
  }
  vfs_writev(file, pvec, kcnt, ppos);  // Write any remaining data before exit

  DPRINT("Wrote %zd bytes to the file for sysnum %d\n", copyed, psr->sysnum);
  KFREE(pvec);

  return copyed;
}

int read_log_data(struct record_thread *prect)
{
  int rc;
  int count = 0; // num syscalls returned by read
  rc = read_log_data_internal(prect, prect->rp_log, prect->rp_record_pid, &count, &prect->rp_read_log_pos);
  MPRINT("Pid %d read_log_data_internal returned %d syscalls, rc %d\n", current->pid, count, rc);
  prect->rp_in_ptr = count;
  return rc;
}

int read_log_data_internal(struct record_thread *prect, struct syscall_result *psr, int logid, int *syscall_count, loff_t *pos)
{
  char filename[MAX_LOGDIR_STRLEN + 20];
  struct file *file;
  int fd, rc, count;
  mm_segment_t old_fs;
  u_long data_len;
  struct argsalloc_node *node;
  char *slab;

#ifdef USE_HPC
  // for those calibration constants
  char dummy_buffer[2 * sizeof(unsigned long long) + 2 * sizeof(struct timeval)];
#endif
  old_fs = get_fs();
  set_fs(KERNEL_DS);

  MPRINT("Reading logid %d starting at pos %lld\n", logid, (long long) *pos);
  rc = snprintf(filename, MAX_LOGDIR_STRLEN+20, "%s/klog.id.%d", prect->rp_group->rg_logdir, logid);
  if (rc < 0)
  {
    TPRINT("read_log_data: rg_logdir is too long\n");
    return -EINVAL;
  }
  MPRINT("Opening %s\n", filename);
  fd = sys_open(filename, O_RDONLY | O_LARGEFILE, 0644);
  MPRINT("Open returns %d\n", fd);
  if (fd < 0)
  {
    TPRINT("read_log_data: cannot open log file %s\n", filename);
    return -EINVAL;
  }

  file = fget(fd);

#ifdef USE_HPC
  rc = vfs_read(file, (char *) dummy_buffer, 2 * sizeof(unsigned long long) + 2 * sizeof(struct timeval), pos);
  if (rc == 0)
  {
    MPRINT("no more records in the log\n");
    *syscall_count = 0;
    goto error;
  }
  if (rc != 2 * sizeof(unsigned long long) + 2 * sizeof(struct timeval))
  {
    TPRINT("vfs_read returns %d, sizeof calibration constants %d\n", rc, 2 * sizeof(unsigned long long) + 2 * sizeof(struct timeval));
    BUG();
    goto error;
  }
#endif

  // read one section of the log (array of syscall results and then the args/retvals/signals)
  rc = vfs_read(file, (char *) &count, sizeof(count), pos);
  if (rc != sizeof(count))
  {
    MPRINT("vfs_read returns %d, sizeof(count) %lu\n", rc, sizeof(count));
    *syscall_count = 0;
    goto error;
  }

  MPRINT("read_log_data syscall count is %d\n", count);

  rc = vfs_read(file, (char *) &psr[0], sizeof(struct syscall_result) * count, pos);
  if (rc != sizeof(struct syscall_result)*count)
  {
    TPRINT("vfs_read returns %d when %lu of records expected\n", rc, sizeof(struct syscall_result)*count);
    goto error;
  }

  rc = vfs_read(file, (char *) &data_len, sizeof(data_len), pos);
  if (rc != sizeof(data_len))
  {
    TPRINT("vfs_read returns %d, sizeof(data_len) %lu\n", rc, sizeof(data_len));
    *syscall_count = 0;
    goto error;
  }

  /* Read in length of ancillary data, and add it to the argsalloc list */
  MPRINT("read_log_data data length is %lu\n", data_len);
  if (data_len > 0)
  {
    slab = VMALLOC(data_len);
    rc = add_argsalloc_node(prect, slab, data_len);
    if (rc)
    {
      TPRINT("read_log_data_internal: pid %d argalloc: problem adding argsalloc_node\n", current->pid);
      VFREE(slab);
      *syscall_count = 0;
      goto error;
    }

    node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);
    rc = vfs_read(file, node->pos, data_len, pos);
    if (rc != data_len)
    {
      TPRINT("read_log_data_internal: vfs_read of ancillary data returns %d, epected %lu\n", rc, data_len);
      *syscall_count = 0;
      goto error;
    }
    TPRINT("read in klog: len %lu\n", data_len);
    print_mem(node->pos, data_len);
  }

  *syscall_count = count;
  fput(file);

  rc = sys_close(fd);
  if (rc < 0) TPRINT("read_log_data: file close failed with rc %d\n", rc);
  set_fs(old_fs);

  return 0;

error:
  fput(file);
  rc = sys_close(fd);
  if (rc < 0) TPRINT("read_log_data: file close failed with rc %d\n", rc);
  set_fs(old_fs);
  return rc;
}

/* Write out the list of memory regions used in this record group */
void write_mmap_log(struct record_group *prg)
{
  char filename[MAX_LOGDIR_STRLEN + 20];
  int fd = 0;
  loff_t pos = 0;
  struct file *file = NULL;
  mm_segment_t old_fs;

  int copyed;
  ds_list_t *memory_list;
  ds_list_iter_t *iter;
  struct reserved_mapping *pmapping;

  int rc = 0;

  MPRINT("Pid %d write_mmap_log start\n", current->pid);

  if (!prg->rg_save_mmap_flag) return;

  // one mlog per record group
  rc = snprintf(filename, MAX_LOGDIR_STRLEN+20, "%s/mlog", prg->rg_logdir);
  if (rc < 0)
  {
    TPRINT("write_mmap_log: rg_logdir is too long\n");
    return;
  }
  
  old_fs = get_fs();
  set_fs(KERNEL_DS);
  fd = sys_open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
  {
    TPRINT("Pid %d write_mmap_log: could not open file %s, %d\n", current->pid, filename, fd);
    return;
  }
  file = fget(fd);

  if (!file)
  {
    TPRINT("Pid %d write_mmap_log, could not open file %s\n", current->pid, filename);
    return;
  }

  memory_list = prg->rg_reserved_mem_list;

  iter = ds_list_iter_create(memory_list);
  while ((pmapping = ds_list_iter_next(iter)) != NULL)
  {
    DPRINT("Pid %d writing allocation [%lx, %lx)\n",
           current->pid, pmapping->m_begin, pmapping->m_end);
    copyed = vfs_write(file, (char *) pmapping, sizeof(struct reserved_mapping), &pos);
    if (copyed != sizeof(struct reserved_mapping))
    {
      TPRINT("[WARN] Pid %d write reserved_mapping, expected to write %lu got %d\n", current->pid, sizeof(struct reserved_mapping), copyed);
    }
  }
  ds_list_iter_destroy(iter);

  term_log_write(file, fd);
  set_fs(old_fs);

  MPRINT("Pid %d write mmap log done\n", current->pid);
}

/* Reads in a list of memory regions that will be used in a replay */
long read_mmap_log(struct record_group *precg)
{
  int fd;
  long rc = 0;
  char filename[MAX_LOGDIR_STRLEN + 20];
  struct file *file;
  mm_segment_t old_fs;
  loff_t pos = 0;

  //struct stat64 st;
  //64port
  struct stat st;
  int num_entries = 0;
  int i = 0;
  struct reserved_mapping *pmapping;

  old_fs = get_fs();
  set_fs(KERNEL_DS);

  rc = snprintf(filename, MAX_LOGDIR_STRLEN+20, "%s/mlog", precg->rg_logdir);
  if (rc < 0) {
    TPRINT("read_mmap_log: rg_logdir is too long\n");
    return -EINVAL;
  }
 
  MPRINT("Pid %d Opening mlog %s\n", current->pid, filename);
  fd = sys_open(filename, O_RDONLY, 0644);
  if (fd < 0)
  {
    TPRINT("read_mmap_log: cannot open log file %s\n", filename);
    return -EINVAL;
  }
  file = fget(fd);

  // stat the file, see how many pmaps we expect
  //rc = sys_stat64(filename, &st);
  //64port
  rc = sys_newstat(filename, &st);
  if (rc < 0)
  {
    TPRINT("read_mmap_log: cannot stat file %s, %ld\n", filename, rc);
    return -EINVAL;
  }
  num_entries = st.st_size / (sizeof(struct reserved_mapping));

  // Read the mappings from file and put them in the record thread structure
  for (i = 0; i < num_entries; i++)
  {
    pmapping = KMALLOC(sizeof(struct reserved_mapping), GFP_KERNEL);
    if (pmapping == NULL)
    {
      TPRINT("read_mmap_log: Cannot allocate new reserve mapping\n");
      return -ENOMEM;
    }
    rc = vfs_read(file, (char *) pmapping, sizeof(struct reserved_mapping), &pos);
    if (rc < 0)
    {
      TPRINT("Pid %d problem reading in a reserved mapping, rc %ld\n", current->pid, rc);
      KFREE(pmapping);
      return rc;
    }
    if (rc != sizeof(struct reserved_mapping))
    {
      pr_debug("Pid %d read reserved_mapping expected %lu, got %lu\n", current->pid, sizeof(struct reserved_mapping), rc);
      KFREE(pmapping);
      return rc;
    }

    ds_list_insert(precg->rg_reserved_mem_list, pmapping);
  }

  fput(file);
  rc = sys_close((unsigned int)fd);
  if (rc < 0) TPRINT("read_log_data: file close failed with rc %ld\n", rc);
  set_fs(old_fs);
  return rc;
}

#ifdef LOG_COMPRESS_1
// only can be called after init_log_write
struct file *init_clog_write(struct record_thread *prect, loff_t *ppos, int *pfd)
{
  char filename[MAX_LOGDIR_STRLEN + 20];
  //  struct stat64 st;
  //64port
  struct stat st;
  mm_segment_t old_fs;
  int rc;

  rc = snprintf(filename, MAX_LOGDIR_STRLEN+20, "%s/klog.id.%d.clog", prect->rp_group->rg_logdir, prect->rp_record_pid);
  if (rc < 0)
  {
    TPRINT("init_clog_write: rg_logdir is too long\n");
    return NULL;
  }

  old_fs = get_fs();
  set_fs(KERNEL_DS);
  if (prect->rp_klog_opened)
  {
    //rc = sys_stat64(filename, &st);
    //64port
    rc = sys_newstat(filename, &st);
    if (rc < 0)
    {
      TPRINT("Stat of file %s failed\n", filename);
      return NULL;
    }
    *ppos = st.st_size;
    *pfd = sys_open(filename, O_WRONLY | O_APPEND, 0644);
    MPRINT("Reopened log file %s, pos = %ld\n", filename, (long) *ppos);
  }
  else
  {
    TPRINT("Pid %d open clog file %s, the uncompressed log is not opened yet.\n", prect->rp_record_pid, filename);
  }
  set_fs(old_fs);
  if (*pfd < 0)
  {
    TPRINT("Cannot open clog file %s, rc = %d\n", filename, *pfd);
    return NULL;
  }

  return (fget(*pfd));
}

void term_clog_write(struct file *file, int fd)
{
  int rc;

  fput(file);

  rc = sys_close(fd);
  if (rc < 0) TPRINT("term_clog_write: file close failed with rc %d\n", rc);
}

static ssize_t write_clog_data(struct file *file, loff_t *ppos, struct record_thread *prect, struct syscall_result *psr, int count)
{
  struct clog_node *node;
  ssize_t copyed = 0;
  struct iovec *pvec; // Concurrent writes need their own vector
  int kcnt = 0;
  u_long data_len;
#ifdef USE_HPC
  unsigned long long hpc1;
  unsigned long long hpc2;
  struct timeval tv1;
  struct timeval tv2;
#endif

  if (count <= 0) return 0;

  MPRINT("Pid %d, start write log data\n", current->pid);

  pvec = KMALLOC(sizeof(struct iovec) * UIO_MAXIOV, GFP_KERNEL);
  if (pvec == NULL)
  {
    TPRINT("Cannot allocate iovec for write_clog_data\n");
    return 0;
  }

#ifdef USE_HPC
  hpc1 = rdtsc();
  do_gettimeofday(&tv1);
  msleep(1);
  hpc2 = rdtsc();
  do_gettimeofday(&tv2);

  copyed = vfs_write(file, (char *) &hpc1, sizeof(unsigned long long), ppos);
  if (copyed != sizeof(unsigned long long))
  {
    TPRINT("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (1)\n", current->pid, sizeof(unsigned long long), copyed);
  }

  copyed = vfs_write(file, (char *) &tv1, sizeof(struct timeval), ppos);
  if (copyed != sizeof(struct timeval))
  {
    TPRINT("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (2)\n", current->pid, sizeof(struct timeval), copyed);
  }

  copyed = vfs_write(file, (char *) &hpc2, sizeof(unsigned long long), ppos);
  if (copyed != sizeof(unsigned long long))
  {
    TPRINT("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (3)\n", current->pid, sizeof(unsigned long long), copyed);
  }

  copyed = vfs_write(file, (char *) &tv2, sizeof(struct timeval), ppos);
  if (copyed != sizeof(struct timeval))
  {
    TPRINT("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (4)\n", current->pid, sizeof(struct timeval), copyed);
  }
#endif

  /* First write out syscall records in a bunch */
  /*copyed = vfs_write(file, (char *) &count, sizeof(count), ppos);
  if (copyed != sizeof(count)) {
    TPRINT ("write_clog_data: tried to write record count, got rc %d\n", copyed);
    KFREE (pvec);
    return -EINVAL;
  }

  MPRINT ("Pid %d write_clog_data count %d, size %d\n", current->pid, count, sizeof(struct syscall_result)*count);

  copyed = vfs_write(file, (char *) psr, sizeof(struct syscall_result)*count, ppos);
  if (copyed != sizeof(struct syscall_result)*count) {
    TPRINT ("write_clog_data: tried to write %d, got rc %d\n", sizeof(struct syscall_result)*count, copyed);
    KFREE (pvec);
    return -EINVAL;
  }*/

  /* Now write ancillary data - count of bytes goes first */
  data_len = 0;
  list_for_each_entry_reverse(node, &prect->rp_clog_list, list)
  {
    data_len += getDataLength(node);
  }
  MPRINT("Ancillary data written is %lu\n", data_len);
  copyed = vfs_write(file, (char *) &data_len, sizeof(data_len), ppos);
  if (copyed != sizeof(count))
  {
    TPRINT("write_clog_data: tried to write ancillary data length, got rc %d\n", copyed);
    KFREE(pvec);
    return -EINVAL;
  }

  list_for_each_entry_reverse(node, &prect->rp_clog_list, list)
  {
    MPRINT("Pid %d argssize write buffer slab size %d\n", current->pid, node->pos - node->head);
    pvec[kcnt].iov_base = node->head;
    pvec[kcnt].iov_len = getDataLength(node);
    if (++kcnt == UIO_MAXIOV)
    {
      copyed = vfs_writev(file, pvec, kcnt, ppos);
      kcnt = 0;
    }
  }

  vfs_writev(file, pvec, kcnt, ppos);  // Write any remaining data before exit

  DPRINT("Wrote %d bytes to the file for sysnum %d\n", copyed, psr->sysnum);
  KFREE(pvec);

  return copyed;

}

int read_clog_data(struct record_thread *prect)
{
  int rc;
  int count = 0; // num syscalls returned by read
  rc = read_clog_data_internal(prect, prect->rp_log, prect->rp_record_pid, &count, &prect->rp_read_clog_pos);
  MPRINT("Pid %d read_clog_data_internal returned %d syscalls\n", current->pid, count);
  //note this is only for the debug purpose
  // as the rp_in_ptr should be setup by read_log_data
  //BUG_ON (prect->rp_in_ptr != count);
  //prect->rp_in_ptr = count;
  return rc;
}

int read_clog_data_internal(struct record_thread *prect, struct syscall_result *psr, int logid, int *syscall_count, loff_t *pos)
{
  char filename[MAX_LOGDIR_STRLEN + 20];
  struct file *file;
  int fd, rc, count;
  mm_segment_t old_fs;
  u_long data_len;
  struct clog_node *node;
  char *slab;

#ifdef USE_HPC
  // for those calibration constants
  char dummy_buffer[2 * sizeof(unsigned long long) + 2 * sizeof(struct timeval)];
#endif
  old_fs = get_fs();
  set_fs(KERNEL_DS);

  MPRINT("Reading logid %d starting at pos %lld\n", logid, (long long) *pos);
  rc = snprintf(filename, MAX_LOGDIR_STRLEN+20, "%s/klog.id.%d.clog", prect->rp_group->rg_logdir, logid);
  if (rc < 0)
  {
    TPRINT("read_clog_data: rg_logdir is too long\n");
    return -EINVAL;
  }
  MPRINT("Opening %s\n", filename);
  fd = sys_open(filename, O_RDONLY, 0644);
  MPRINT("Open returns %d\n", fd);
  if (fd < 0)
  {
    TPRINT("read_clog_data: cannot open log file %s\n", filename);
    return -EINVAL;
  }

  file = fget(fd);

#ifdef USE_HPC
  rc = vfs_read(file, (char *) dummy_buffer, 2 * sizeof(unsigned long long) + 2 * sizeof(struct timeval), pos);
  if (rc == 0)
  {
    MPRINT("no more records in the log\n");
    *syscall_count = 0;
    goto error;
  }
  if (rc != 2 * sizeof(unsigned long long) + 2 * sizeof(struct timeval))
  {
    TPRINT("vfs_read returns %d, sizeof calibration constants %d\n", rc, 2 * sizeof(unsigned long long) + 2 * sizeof(struct timeval));
    BUG();
    goto error;
  }
#endif

  // read one section of the log (array of syscall results and then the args/retvals/signals)
  /*rc = vfs_read (file, (char *) &count, sizeof(count), pos);
  if (rc != sizeof(count)) {
    MPRINT ("vfs_read returns %d, sizeof(count) %d\n", rc, sizeof(count));
    *syscall_count = 0;
    goto error;
  }

  MPRINT ("read_clog_data syscall count is %d\n", count);

  rc = vfs_read (file, (char *) &psr[0], sizeof(struct syscall_result)*count, pos);
  if (rc != sizeof(struct syscall_result)*count) {
    TPRINT ("vfs_read returns %d when %d of records expected\n", rc, sizeof(struct syscall_result)*count);
    goto error;
  }*/

  rc = vfs_read(file, (char *) &data_len, sizeof(data_len), pos);
  if (rc != sizeof(data_len))
  {
    TPRINT("vfs_read returns %d, sizeof(data_len) %d\n", rc, sizeof(data_len));
    //*syscall_count = 0;
    goto error;
  }

  /* Read in length of ancillary data, and add it to the clog list */
  MPRINT("read_clog_data data length is %lu\n", data_len);
  if (data_len > 0)
  {
    slab = VMALLOC(data_len);
    rc = add_clog_node(prect, slab, data_len);
    if (rc)
    {
      TPRINT("read_clog_data_internal: pid %d argalloc: problem adding clog_node\n", current->pid);
      VFREE(slab);
      //*syscall_count = 0;
      goto error;
    }

    node = list_first_entry(&prect->rp_clog_list, struct clog_node, list);
    rc = vfs_read(file, node->pos, data_len, pos);
    if (rc != data_len)
    {
      TPRINT("read_clog_data_internal: vfs_read of ancillary data returns %d, epected %lu\n", rc, data_len);
      //*syscall_count = 0;
      goto error;
    }
  }

  //*syscall_count = count;
  fput(file);

  rc = sys_close(fd);
  if (rc < 0) TPRINT("read_clog_data: file close failed with rc %d\n", rc);
  set_fs(old_fs);

  return 0;

error:
  fput(file);
  rc = sys_close(fd);
  if (rc < 0) TPRINT("read_clog_data: file close failed with rc %d\n", rc);
  set_fs(old_fs);
  return rc;

}

#endif

int do_is_record(struct ctl_table *table, int write, void __user *buffer,
                 size_t *lenp, loff_t *ppos)
{
  char __user *cbuf = buffer;

  if (!table->maxlen || !*lenp || (*ppos && !write) || (*ppos > 2))
  {
    *lenp = 0;
    return 0;
  }

  if (write)
  {
    return -EINVAL;
  }

  if (*lenp > 0 && *ppos == 0)
  {
    if (current->record_thrd == NULL)
    {
      if (copy_to_user(cbuf, "0", 1))
      {
        return -EFAULT;
      }
    }
    else
    {
      if (copy_to_user(cbuf, "1", 1))
      {
        return -EFAULT;
      }
    }
    *ppos += 1;
    *lenp -= 1;
  }

  if (*ppos == 1 && *lenp > 0)
  {
    if (copy_to_user(cbuf + 1, "\n", 1))
    {
      return -EFAULT;
    }
    *ppos += 1;
    *lenp -= 1;
  }

  /*
  if (*ppos==2 && *lenp > 0) {
    if (copy_to_user(cbuf+2, "\0", 1)) {
      return -EFAULT;
    }
    *ppos += 1;
    *lenp -= 1;
  }
  */

  /*
  TPRINT("%s %d: Returning proc entry with lenp %u, ppos %lld\n", __func__,
      __LINE__, *lenp, *ppos);
      */
  return 0;
}

int btree_print = 0;
int btree_print_init = 0;
int replayfs_btree128_do_verify = 0;
int replayfs_btree128_debug = 0;
int replayfs_btree128_debug_verbose = 0;
int replayfs_filemap_debug = 0;
int replayfs_diskalloc_debug = 0;
int replayfs_diskalloc_debug_full = 0;
int replayfs_diskalloc_debug_cache = 0;
int replayfs_diskalloc_debug_allocref = 0;
int replayfs_diskalloc_debug_lock = 0;
int replayfs_diskalloc_debug_alloc = 0;
int replayfs_diskalloc_debug_alloc_min = 0;

int replayfs_debug_allocnum = -1;
int replayfs_debug_page = -1;

int replayfs_print_leaks = 0;

unsigned long replayfs_debug_page_index = 0xFFFFFFFF;

#ifdef CONFIG_SYSCTL
extern atomic_t diskalloc_num_blocks;
static struct ctl_table print_ctl[] =
{
  {
    .procname = "replayfs_btree_print",
    .data   = &btree_print,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_btree_print_init",
    .data   = &btree_print_init,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_print_leaks",
    .data   = &replayfs_print_leaks,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_debug_btree_page",
    .data   = &replayfs_debug_page,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_debug_btree_allocnum",
    .data   = &replayfs_debug_allocnum,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_btree128_verify",
    .data   = &replayfs_btree128_do_verify,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_btree128_print",
    .data   = &replayfs_btree128_debug,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_btree128_print_verbose",
    .data   = &replayfs_btree128_debug_verbose,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_filemap_print",
    .data   = &replayfs_filemap_debug,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_diskalloc_print_lock",
    .data   = &replayfs_diskalloc_debug_lock,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_diskalloc_print",
    .data   = &replayfs_diskalloc_debug,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_diskalloc_print_cache",
    .data   = &replayfs_diskalloc_debug_cache,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_debug_page_index",
    .data   = &replayfs_debug_page_index,
    .maxlen   = sizeof(unsigned long),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_diskalloc_print_allocref",
    .data   = &replayfs_diskalloc_debug_allocref,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_diskalloc_print_alloc_min",
    .data   = &replayfs_diskalloc_debug_alloc_min,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_diskalloc_print_alloc",
    .data   = &replayfs_diskalloc_debug_alloc,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_diskalloc_print_full",
    .data   = &replayfs_diskalloc_debug_full,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "data_verify_print",
    .data   = &verify_debug,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0666,
    .proc_handler = &proc_dointvec,
  },
  {0, },
};
static struct ctl_table replay_ctl[] =
{
  {
    .procname = "syslog_recs",
    .data   = &syslog_recs,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0644,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replay_debug",
    .data   = &replay_debug,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0644,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replay_min_debug",
    .data   = &replay_min_debug,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0644,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "argsalloc_size",
    .data   = &argsalloc_size,
    .maxlen   = sizeof(unsigned long),
    .mode   = 0644,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "pin_debug_clock",
    .data   = &pin_debug_clock,
    .maxlen   = sizeof(unsigned long),
    .mode   = 0644,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "proc_is_record",
    .data   = NULL,
    .maxlen   = sizeof(unsigned long),
    .mode   = 0644,
    .proc_handler = &do_is_record,
  },
  {
    .procname = "diskalloc_num_blocks",
    .data   = &diskalloc_num_blocks.counter,
    .maxlen   = sizeof(unsigned long),
    .mode   = 0644,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "replayfs_prints",
    .mode   = 0555,
    .child    = print_ctl,
  },
  {
    .procname = "x_proxy",
    .data   = &x_proxy,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0644,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "record_x",
    .data   = &record_x,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0644,
    .proc_handler = &proc_dointvec,
  },
  {
    .procname = "pause_tool",
    .data   = &replay_pause_tool,
    .maxlen   = sizeof(unsigned int),
    .mode   = 0644,
    .proc_handler = &proc_dointvec,
  },
  {0, },
};

static struct ctl_table replay_ctl_root[] =
{
  {
    .procname = "kernel",
    .mode   = 0555,
    .child    = replay_ctl,
  },
  {0, },
};
#endif

//call in replay_init()
//there is no "replayfs". it just refers to "/data/replay_logdb/*", etc.
static void theia_init_replayfs_paths(void) {
  char* dmi_product_uuid = NULL;
  char* theia_machine_id = NULL;
  char* prefix = NULL;
  size_t safe_len = PAGE_SIZE - 1;
  int res = 0;
  memset(replayfs_logdb_path, 0, PAGE_SIZE);
  memset(replayfs_filelist_path, 0, PAGE_SIZE);
  memset(replayfs_cache_path, 0, PAGE_SIZE);
  memset(replayfs_index_path, 0, PAGE_SIZE);
  prefix = kmalloc(PAGE_SIZE, GFP_ATOMIC);
  if (prefix == NULL)
    goto failed;

  dmi_product_uuid = (char*)dmi_get_system_info(DMI_PRODUCT_UUID);
  if (dmi_product_uuid)
    theia_machine_id = strrchr(dmi_product_uuid, '-') + 1;

  memset(prefix, 0, PAGE_SIZE);
  if (!dmi_product_uuid || !theia_machine_id) {
    strncpy_safe(prefix, REPLAYFS_BASE_PATH, safe_len);
  }
  else {
    res = snprintf(prefix, safe_len, "%s/%s", REPLAYFS_BASE_PATH, theia_machine_id);
    if (res < 0) goto failed;
  }

  res = snprintf(replayfs_logdb_path, safe_len, "%s%s/", prefix, REPLAYFS_LOGDB_SUFFIX);
  if (res < 0) goto failed;
  pr_info("replayfs_logdb_path = %s\n", replayfs_logdb_path);

  res = snprintf(replayfs_filelist_path, safe_len, "%s%s%s", prefix, REPLAYFS_LOGDB_SUFFIX, REPLAYFS_FILELIST_SUFFIX);
  if (res < 0) goto failed;
  pr_info("replayfs_filelist_path = %s\n", replayfs_filelist_path);

  res = snprintf(replayfs_index_path, safe_len, "%s%s%s", prefix, REPLAYFS_LOGDB_SUFFIX, REPLAYFS_INDEX_SUFFIX);
  if (res < 0) goto failed;
  pr_info("replayfs_index_path = %s\n", replayfs_index_path);

  res = snprintf(replayfs_cache_path, safe_len, "%s%s/", prefix, REPLAYFS_CACHE_SUFFIX);
  if (res < 0) goto failed;
  pr_info("replayfs_cache_path = %s\n", replayfs_cache_path);

  goto done;

failed:
  strncpy_safe(replayfs_logdb_path, REPLAYFS_BASE_PATH REPLAYFS_LOGDB_SUFFIX "/", safe_len);
  strncpy_safe(replayfs_filelist_path, REPLAYFS_BASE_PATH \
      REPLAYFS_LOGDB_SUFFIX \
      REPLAYFS_FILELIST_SUFFIX \
      "/", safe_len);
  strncpy_safe(replayfs_cache_path, REPLAYFS_BASE_PATH REPLAYFS_CACHE_SUFFIX "/", safe_len);
  strncpy_safe(replayfs_index_path, REPLAYFS_BASE_PATH \
      REPLAYFS_LOGDB_SUFFIX \
      REPLAYFS_INDEX_SUFFIX \
      "/", safe_len);
done:
  if (prefix) kfree(prefix);
}

//this can only be called from user context
static inline void ensure_path(const char* func, char* name, const char* path) {
  int ret = -1;
  char* copy = NULL;
  char* ptr = NULL;
  mm_segment_t old_fs;
  mode_t old_mask;

  old_fs = get_fs();
  set_fs(KERNEL_DS);
  old_mask = sys_umask(0);

  copy = vmalloc(PAGE_SIZE);
  if (!copy) goto failed;

  strncpy_safe(copy, path, PAGE_SIZE);

  for (ptr = copy+1; *ptr; ++ptr) {
    if (*ptr == '/') {
      *ptr = '\0';
      pr_info("ensure_path: trying to create '%s'\n", copy);
      ret = sys_mkdir(copy, 0777);
      if (ret != 0 && ret != -EEXIST) {
        goto failed;
      }
      *ptr = '/';
    }
  }
  pr_info("ensure_path: trying to create '%s'\n", copy);
  ret = sys_mkdir(copy, 0777);
  if (ret != 0 && ret != -EEXIST) {
    goto failed;
  }
  goto done;

failed:
  pr_err("theia:%s: cannot create %s path '%s', rc=%d\n", func, name, path, ret);
done:
  if (copy) vfree(copy);
  sys_umask(old_mask);
  set_fs(old_fs);
}

//this can only be called from user context
//call this right before recording is turned on
void ensure_replayfs_paths(void) {
  struct cred *cred = NULL;
  const struct cred *old_cred;

  cred = prepare_creds();
  if (cred) {
    cred->fsuid = GLOBAL_ROOT_UID;
    cred->fsgid = GLOBAL_ROOT_GID;
    old_cred = override_creds(cred);
  }

  ensure_path(__FUNCTION__, "logdb", LOGDB_DIR);
  ensure_path(__FUNCTION__, "cache", REPLAYFS_CACHE_DIR);

  if (cred) {
    revert_creds(old_cred);
    put_cred(cred);
  }
}
EXPORT_SYMBOL(ensure_replayfs_paths);

static int __init replay_init(void)
{
  mm_segment_t old_fs;
  size_t len;
  char proc_whitelist[] = \
                         "/usr/local/bin/relay-read-file\0"
                         "/usr/local/bin/theia_toggle\0"
                         "/usr/sbin/rsyslogd\0"
                         "/usr/share/logstash/bin/logstash\0"
                         "/usr/sbin/syslog-ng\0"
                         "/usr/lib/gvfs/gvfsd-trash\0"
                         "/usr/lib/deja-dup/deja-dup/deja-dup-monitor\0"
                         "/usr/lib/libvte-2.90-9/gnome-pty-helper\0"
                         ;
  size_t proc_whitelist_len = sizeof(proc_whitelist);
  char hide_list[] = \
                    "/data/handler.log\0"
                    ;
  size_t hide_len = sizeof(hide_list);

  // setup default for theia_linker
  //const char* theia_linker_default = "/home/theia/theia-es/eglibc-2.15/prefix/lib/ld-linux-x86-64.so.2";
  //const char* theia_linker_default = "/usr/local/eglibc/lib/ld-linux-x86-64.so.2";
  const char *theia_linker_default = "/usr/local/eglibc/lib/ld-2.15.so";
  // setup default for theia_libpath
  //const char* theia_libpath_default = "LD_LIBRARY_PATH=/home/theia/theia-es/eglibc-2.15/prefix/lib:/lib/theia_libs:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/usr/local/lib:/usr/lib:/lib";
  const char *theia_libpath_default = "LD_LIBRARY_PATH=/usr/local/eglibc/lib:/usr/local/lib:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/usr/lib:/lib";

  //setup paths for record/replay
  theia_init_replayfs_paths();

  strncpy_safe(theia_linker, theia_linker_default, MAX_LOGDIR_STRLEN);
  theia_linker[MAX_LOGDIR_STRLEN] = 0x0;
  strncpy_safe(theia_libpath, theia_libpath_default, MAX_LIBPATH_STRLEN);
  theia_libpath[MAX_LIBPATH_STRLEN] = 0x0;
#ifdef CONFIG_SYSCTL
  register_sysctl_table(replay_ctl_root);
#endif

  // setup defaults for proc and dirent hiding
  len = proc_whitelist_len;
  BUG_ON(len > MAX_WHITELIST_STRLEN);
  memcpy(theia_proc_whitelist, proc_whitelist, len);
  theia_proc_whitelist_len = len;
  len = hide_len;
  BUG_ON(len > MAX_DIRENT_STRLEN);
  memcpy(theia_dirent_prefix, hide_list, len);
  theia_dirent_prefix_len = len;

  /* Performance monitoring */
  perftimer_init();

  //theia_replay_register init
  theia_replay_register_data.pid = 0;

  //init the wait queue before trying to use it
  init_waitqueue_head(&theia_relay_write_q);

  // init temp buffers
  theia_buffers = kmem_cache_create("theia_buffers", THEIA_KMEM_SIZE, 0, 0, NULL);

  old_fs = get_fs();
  set_fs(KERNEL_DS);

  //theia create relay cpu
  if (theia_dir == NULL)
  {
    pr_info("init: creating relay app dir\n");
    theia_dir = debugfs_create_dir(APP_DIR, NULL);
    if (!theia_dir)
    {
      pr_err("init: failed to create relay app directory.\n");
    }
    else
    {
      pr_info("init: created relay app dir\n");
      if (theia_chan == NULL)
      {
        pr_info("init: creating relay app channel\n");
        theia_chan = create_channel(subbuf_size, n_subbufs);
        if (!theia_chan)
        {
          pr_err("init: failed to create relay app channel.\n");
          debugfs_remove(theia_dir);
        }
        else
        {
          pr_info("init: created relay app channel\n");
        }
      }
    }
  }
  set_fs(old_fs);

  /* Read monitors */
  //read_btwn_timer = perftimer_create("Between Reads", "Read");
  read_in_timer = perftimer_create("Read Total", "Read");
  read_cache_timer = perftimer_create("File Cache", "Read");
  read_sys_timer = perftimer_create("sys_read", "Read");
  read_traceread_timer = perftimer_create("Graph Read", "Read");
  read_filemap_timer = perftimer_create("filemap_read", "Read");

  /* Write monitors */
  //write_btwn_timer = perftimer_create("Between Writes", "Write");
  write_in_timer = perftimer_create("Write Total", "Write");
  write_sys_timer = perftimer_create("sys_write", "Write");
  write_traceread_timer = perftimer_create("Graph Write", "Write");
  write_filemap_timer = perftimer_create("filemap_write", "Write");

  /* Open/close monitors */
  open_timer = perftimer_create("Open Total", "Open");
  open_sys_timer = perftimer_create("sys_open", "Open");
  open_intercept_timer = perftimer_create("Open Intercept", "Open");
  open_cache_timer = perftimer_create("Open Syscache", "Open");

  close_timer = perftimer_create("Close Total", "Close");
  close_sys_timer = perftimer_create("sys_close", "Close");
  close_intercept_timer = perftimer_create("Close Intercept", "Close");

#ifdef TRACE_PIPE_READ_WRITE
  btree_init64(&pipe_tree);
#endif
  btree_init64(&inode_tree);


  return 0;
}

static int theia_secure_flag = 0;
EXPORT_SYMBOL(theia_secure_flag);

static int __init setup_theia_secure(char *str)
{
  theia_secure_flag = 0;
  //from lib/cmdline.c
  get_option(&str, &theia_secure_flag);
  if (theia_secure_flag < 0) theia_secure_flag = 0;
  if (theia_secure_flag > 1) theia_secure_flag = 1;
  if (theia_secure_flag)
    pr_debug("theia secure mode activated");
  else
    pr_debug("theia_secure set but ignored");
  return 1;
}
__setup("theia_secure=", setup_theia_secure);
//https://www.tldp.org/LDP/lki/lki-1.html Section 1.9

module_init(replay_init)
