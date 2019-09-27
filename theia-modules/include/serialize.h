#ifndef __SERIALIZE_H__
#define __SERIALIZE_H__

typedef void (*ptr_set_fs_root)(struct fs_struct *fs, struct path *path);
extern ptr_set_fs_root real_set_fs_root;

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
    real_set_fs_root(current->fs, &theia_pid1_root);\
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
    real_set_fs_root(current->fs, &cur_pid_root);\
    path_put(&cur_pid_root);\
  }\
  } while(0)

void serialize_init(void);
void write_and_free_kernel_log(struct record_thread*);
int read_log_data(struct record_thread*);

#endif
