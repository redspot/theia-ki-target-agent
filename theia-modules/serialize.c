#include <linux/version.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/fs_struct.h>

#include <replay_configs.h>
#include <replay.h>
#include <serialize.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)) && !defined(THEIA_MODIFIED_KERNEL_SOURCES)
struct path theia_pid1_root;
EXPORT_SYMBOL(theia_pid1_root);
#endif

ptr_set_fs_root real_set_fs_root;

void __init serialize_init(void)
{
  // init our PID1 (struct path) root.dentry to NULL so that we know its not setup yet
  theia_pid1_root.dentry = NULL;

  real_set_fs_root = (ptr_set_fs_root)kallsyms_lookup_name("set_fs_root");
}

static int read_log_data_internal(struct record_thread *prect, struct syscall_result *psr, int logid, int *syscall_count, loff_t *pos)
{
  char filename[MAX_LOGDIR_STRLEN + 20];
  struct file *file = NULL;
  int fd = -1, rc, count, ret;
  mm_segment_t old_fs;
  u_long data_len;
  struct argsalloc_node *node;
  char *slab;

#ifdef USE_HPC
  // for those calibration constants
  char dummy_buffer[2 * sizeof(unsigned long long) + 2 * sizeof(struct timeval)];
#endif
  THEIA_DECLARE_CREDS;
  // swap creds to root for vfs operations
  THEIA_SWAP_CREDS_TO_ROOT;

  old_fs = get_fs();
  set_fs(KERNEL_DS);

  MPRINT("Reading logid %d starting at pos %lld\n", logid, (long long) *pos);
  rc = snprintf(filename, MAX_LOGDIR_STRLEN+20, "%s/klog.id.%d", prect->rp_group->rg_logdir, logid);
  if (rc < 0)
  {
    TPRINT("read_log_data: rg_logdir is too long\n");
    goto error;
  }
  MPRINT("Opening %s\n", filename);
  fd = real_sys_open(filename, O_RDONLY | O_LARGEFILE, 0644);
  MPRINT("Open returns %d\n", fd);
  if (fd < 0)
  {
    TPRINT("read_log_data: cannot open log file %s\n", filename);
    goto error;
  }

  file = fget(fd);

  if(!file)
  {
    TPRINT("read_log_data: cannot fget file %s\n", filename);
    goto error;
  }

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
    rc = __add_argsalloc_node(prect, slab, data_len);
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
    //print_mem(node->pos, data_len);
  }

  *syscall_count = count;

  ret = 0;
  goto out;
error:
  ret = -EINVAL;
out:
  if (file) fput(file);
  if (fd > 0) {
    rc = sys_close(fd);
    if (rc < 0) TPRINT("read_log_data: file close failed with rc %d\n", rc);
  }
  set_fs(old_fs);
  THEIA_RESTORE_CREDS;
  return ret;
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

void write_and_free_kernel_log(struct record_thread *prect)
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

  __argsfreeall(prect);
}

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
  THEIA_DECLARE_CREDS;

  //swap creds to root for vfs operations
  THEIA_SWAP_CREDS_TO_ROOT;
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
    rc = real_sys_newstat(filename, &st);
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
    *pfd = real_sys_open(filename, flags, 0777);
    MPRINT("Reopened log file %s, pos = %ld\n", filename, (long) *ppos);
  }
  else
  {
    flags = O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE;
    *pfd = real_sys_open(filename, flags, 0777);
    //TPRINT("%s %d: Creating log %s\n", __func__, __LINE__, filename);
    if (*pfd > 0)
    {
      rc = real_sys_fchmod(*pfd, 0777);
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
  THEIA_RESTORE_CREDS;
  return ret;
}

void term_log_write(struct file *file, int fd)
{
  int rc;
  if (file) fput(file);
  rc = real_sys_close(fd);
  if (rc < 0) TPRINT("term_log_write: file close failed with rc %d\n", rc);
}

ssize_t write_log_data(struct file *file, loff_t *ppos, struct record_thread *prect, 
    struct syscall_result *psr, int count, bool isAhg)
{
  struct argsalloc_node *node;
  ssize_t copyed = 0;
  struct iovec *pvec; // Concurrent writes need their own vector
  int kcnt = 0;
  u_long data_len;
  THEIA_DECLARE_CREDS;

  if (count <= 0) return 0;
  MPRINT("Pid %d, start write log data\n", current->pid);
  pvec = KMALLOC(sizeof(struct iovec) * UIO_MAXIOV, GFP_KERNEL);
  if (pvec == NULL)
  {
    TPRINT("Cannot allocate iovec for write_log_data\n");
    return 0;
  }

  // swap creds to root for vfs operations
  THEIA_SWAP_CREDS_TO_ROOT;

  /* First write out syscall records in a bunch */
  copyed = vfs_write(file, (char *) &count, sizeof(count), ppos);
  if (copyed != sizeof(count))
  {
    TPRINT("write_log_data: tried to write record count, got rc %zd\n", copyed);
    KFREE(pvec);
    goto error;
  }

  MPRINT("Pid %d write_log_data count %d, size %lu\n", current->pid, count, sizeof(struct syscall_result)*count);

  copyed = vfs_write(file, (char *) psr, sizeof(struct syscall_result) * count, ppos);
  if (copyed != sizeof(struct syscall_result)*count)
  {
    TPRINT("write_log_data: tried to write %lu, got rc %zd\n", sizeof(struct syscall_result)*count, copyed);
    KFREE(pvec);
    goto error;
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
    goto error;
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

  THEIA_RESTORE_CREDS;
  return copyed;
error:
  THEIA_RESTORE_CREDS;
  return -EINVAL;
}
