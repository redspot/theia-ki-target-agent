#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/linkage.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>

#define __THEIA_SYSCALLS_C__
#include <replay.h>
#include <theia_hook.h>
#include <theia_syscalls.h>
#include <core_pidmap.h>
#include <shim.h>

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

/*
 * syscall hooks start here
 */

asmlinkage long (*real_sys_read)(SC_PROTO_read);
asmlinkage long theia_hook_read(SC_PROTO_read)
{
  long ret;
  try_module_get(THIS_MODULE);
  pr_debug_ratelimited("%s: called by pid %d\n", __func__, current->pid);
  ret = real_sys_read(SC_ARGS_read);
  pr_debug_ratelimited("%s: ret=%li for pid %d\n", __func__, ret, current->pid);
  module_put(THIS_MODULE);
  return ret;
}
//long __record_read(SC_PROTO_read);
//long replay_read(SC_PROTO_read);
//long theia_sys_read(SC_PROTO_read);
//noinline asmlinkage long theia_hook_read(SC_PROTO_read)
//SHIM_CALL_MAIN(0, __record_read(SC_ARGS_read), replay_read(SC_ARGS_read), real_sys_read(SC_ARGS_read))

asmlinkage long (*real_sys_write)(SC_PROTO_write);
asmlinkage long theia_hook_write(SC_PROTO_write)
{
	long ret;
  try_module_get(THIS_MODULE);
  pr_debug_ratelimited("%s: called by pid %d\n", __func__, current->pid);
  ret = real_sys_write(SC_ARGS_write);
  pr_debug_ratelimited("%s: ret=%li for pid %d\n", __func__, ret, current->pid);
  module_put(THIS_MODULE);
  return ret;
}

asmlinkage long (*real_sys_clone)(SC_PROTO_clone);
asmlinkage long theia_hook_clone(SC_PROTO_clone)
{
	long ret;
  pr_debug_ratelimited("%s: called by pid %d\n", __func__, current->pid);
  ret = real_sys_clone(SC_ARGS_clone);
  pr_debug_ratelimited("%s: ret=%li for pid %d\n", __func__, ret, current->pid);
  return ret;
}

asmlinkage long (*real_sys_execve)(SC_PROTO_execve);
asmlinkage long theia_hook_execve(SC_PROTO_execve)
{
	long ret;
  pr_debug_ratelimited("%s: called by pid %d\n", __func__, current->pid);
  ret = real_sys_execve(SC_ARGS_execve);
  pr_debug_ratelimited("%s: ret=%li for pid %d\n", __func__, ret, current->pid);
  return ret;
}

asmlinkage long (*real_sys_exit)(SC_PROTO_exit);
asmlinkage long theia_hook_exit(SC_PROTO_exit)
{
  pr_debug_ratelimited("%s: called by pid %d\n", __func__, current->pid);
  return real_sys_exit(SC_ARGS_exit);
}

asmlinkage long (*real_sys_exit_group)(SC_PROTO_exit_group);
asmlinkage long theia_hook_exit_group(SC_PROTO_exit_group)
{
  pr_debug_ratelimited("%s: called by pid %d\n", __func__, current->pid);
  return real_sys_exit_group(SC_ARGS_exit_group);
}

SIMPLE_SHIM(link, 86);
SIMPLE_SHIM(sync, 162);
SIMPLE_SHIM(chdir, 80);
SIMPLE_SHIM(pause, 34)
SIMPLE_SHIM(vhangup, 153)
SIMPLE_SHIM(munlockall, 152)
SIMPLE_SHIM(getuid, 102)
SIMPLE_SHIM(getgid, 104)
SIMPLE_SHIM(geteuid, 107)
SIMPLE_SHIM(getegid, 108)
SIMPLE_SHIM(getppid, 110)
SIMPLE_SHIM(getpgrp, 111)
SIMPLE_SHIM(setsid, 112)
SIMPLE_SHIM(gettid, 186)
SIMPLE_SHIM(inotify_init, 253)
SIMPLE_SHIM(mknod, 133)
SIMPLE_SHIM(lseek, 8)
SIMPLE_SHIM(access, 21)
SIMPLE_SHIM(dup, 32)
SIMPLE_SHIM(dup2, 33)
SIMPLE_SHIM(alarm, 37)
SIMPLE_SHIM(utime, 132)
SIMPLE_SHIM(kill, 62)
SIMPLE_SHIM(rename, 82)
SIMPLE_SHIM(mkdir, 83)
SIMPLE_SHIM(rmdir, 84)
SIMPLE_SHIM(acct, 163)
SIMPLE_SHIM(umount, 166)
SIMPLE_SHIM(umask, 95)
SIMPLE_SHIM(chroot, 161)
SIMPLE_SHIM(sethostname, 170)
SIMPLE_SHIM(settimeofday, 164)
SIMPLE_SHIM(symlink, 88)
SIMPLE_SHIM(swapon, 167)
SIMPLE_SHIM(reboot, 169)
SIMPLE_SHIM(truncate, 76)
SIMPLE_SHIM(ftruncate, 77)
SIMPLE_SHIM(getpriority, 140)
SIMPLE_SHIM(setpriority, 141)
SIMPLE_SHIM(swapoff, 168)
SIMPLE_SHIM(semget, 64)
SIMPLE_SHIM(semop, 65)
SIMPLE_SHIM(semtimedop, 220)
SIMPLE_SHIM(msgget, 68)
SIMPLE_SHIM(msgsnd, 69)
SIMPLE_SHIM(fsync, 74)
SIMPLE_SHIM(setdomainname, 171)
SIMPLE_SHIM(init_module, 175)
SIMPLE_SHIM(delete_module, 176)
SIMPLE_SHIM(getpgid, 121)
SIMPLE_SHIM(fchdir, 81)
SIMPLE_SHIM(personality, 135)
SIMPLE_SHIM(flock, 73)
SIMPLE_SHIM(msync, 26)
SIMPLE_SHIM(getsid, 124)
SIMPLE_SHIM(fdatasync, 75)
SIMPLE_SHIM(mlock, 149)
SIMPLE_SHIM(munlock, 150)
SIMPLE_SHIM(mlockall, 151)
SIMPLE_SHIM(sched_setparam, 142)
SIMPLE_SHIM(sched_setscheduler, 144)
SIMPLE_SHIM(sched_getscheduler, 145)
SIMPLE_SHIM(sched_get_priority_max, 146)
SIMPLE_SHIM(sched_get_priority_min, 147)
SIMPLE_SHIM(rt_sigqueueinfo, 129)
SIMPLE_SHIM(rt_sigsuspend, 130)
SIMPLE_SHIM(setpgid, 109)
SIMPLE_SHIM(setregid, 114)
SIMPLE_SHIM(setgroups, 116)
SIMPLE_SHIM(setresgid, 119)
SIMPLE_SHIM(setgid, 106)
SIMPLE_SHIM(setfsuid, 122)
SIMPLE_SHIM(setfsgid, 123)
SIMPLE_SHIM(pivot_root, 155)
SIMPLE_SHIM(readahead, 187)
SIMPLE_SHIM(setxattr, 188)
SIMPLE_SHIM(lsetxattr, 189)
SIMPLE_SHIM(fsetxattr, 190)
SIMPLE_SHIM(removexattr, 197)
SIMPLE_SHIM(lremovexattr, 198)
SIMPLE_SHIM(fremovexattr, 199)
SIMPLE_SHIM(tkill, 200)
SIMPLE_SHIM(sched_setaffinity, 203)
SIMPLE_SHIM(io_destroy, 207)
SIMPLE_SHIM(io_submit, 209)
SIMPLE_SHIM(fadvise64, 221)
SIMPLE_SHIM(epoll_create, 213)
SIMPLE_SHIM(epoll_ctl, 233)
SIMPLE_SHIM(timer_getoverrun, 225)
SIMPLE_SHIM(timer_delete, 226)
SIMPLE_SHIM(clock_settime, 227)
SIMPLE_SHIM(tgkill, 234)
SIMPLE_SHIM(utimes, 235)
SIMPLE_SHIM(mbind, 237)
SIMPLE_SHIM(set_mempolicy, 238)
SIMPLE_SHIM(mq_open, 240)
SIMPLE_SHIM(mq_unlink, 241)
SIMPLE_SHIM(mq_timedsend, 242)
SIMPLE_SHIM(mq_notify, 244)
SIMPLE_SHIM(kexec_load, 246)
SIMPLE_SHIM(add_key, 248)
SIMPLE_SHIM(request_key, 249)
SIMPLE_SHIM(ioprio_set, 251)
SIMPLE_SHIM(ioprio_get, 252)
SIMPLE_SHIM(inotify_add_watch, 254)
SIMPLE_SHIM(inotify_rm_watch, 255)
SIMPLE_SHIM(migrate_pages, 256)
SIMPLE_SHIM(mkdirat, 258)
SIMPLE_SHIM(mknodat, 259)
SIMPLE_SHIM(futimesat, 261)
SIMPLE_SHIM(renameat, 264)
SIMPLE_SHIM(linkat, 265)
SIMPLE_SHIM(symlinkat, 266)
SIMPLE_SHIM(faccessat, 269)
SIMPLE_SHIM(unshare, 272)
SIMPLE_SHIM(set_robust_list, 273)
SIMPLE_SHIM(tee, 276)
SIMPLE_SHIM(sync_file_range, 277)
SIMPLE_SHIM(vmsplice, 278)
SIMPLE_SHIM(utimensat, 280)
SIMPLE_SHIM(signalfd, 282)
SIMPLE_SHIM(timerfd_create, 283)
SIMPLE_SHIM(eventfd, 284)
SIMPLE_SHIM(fallocate, 285)
SIMPLE_SHIM(signalfd4, 289)
SIMPLE_SHIM(eventfd2, 290)
SIMPLE_SHIM(epoll_create1, 291)
SIMPLE_SHIM(dup3, 292)
SIMPLE_SHIM(inotify_init1, 294)
SIMPLE_SHIM(rt_tgsigqueueinfo, 297)
SIMPLE_SHIM(perf_event_open, 298)
SIMPLE_SHIM(fanotify_init, 300)
SIMPLE_SHIM(fanotify_mark, 301)
SIMPLE_SHIM(open_by_handle_at, 304)
SIMPLE_SHIM(syncfs, 306)
SIMPLE_SHIM(setns, 308)

/*
 * syscall hooks end here
 */

/*
 * syscalls that we call but don't hook start here
 */

ptr_sys_pread64 real_sys_pread64;
ptr_sys_close real_sys_close;
ptr_sys_open real_sys_open;
ptr_sys_newstat real_sys_newstat;
ptr_sys_fchmod real_sys_fchmod;

//the kernel does not export signal_wake_up*()
ptr_signal_wake_up_state real_signal_wake_up_state;

void init_extra_syscalls(void)
{
  GET_REAL_SYSCALL(pread64);
  GET_REAL_SYSCALL(close);
  GET_REAL_SYSCALL(open);
  GET_REAL_SYSCALL(newstat);
  GET_REAL_SYSCALL(fchmod);
  real_signal_wake_up_state = (ptr_signal_wake_up_state)kallsyms_lookup_name("signal_wake_up_state");
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)) && !defined(THEIA_MODIFIED_KERNEL_SOURCES)
  sock_from_file = (sock_from_file_ptr)kallsyms_lookup_name("sock_from_file");
#endif
}

/*
 * syscalls that we call but don't hook end here
 */

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

struct ftrace_hook theia_hooks[] = {
  HOOK("sys_read", theia_hook_read, &real_sys_read),
  HOOK("sys_write", theia_hook_write, &real_sys_write),
  HOOK("sys_clone", theia_hook_clone, &real_sys_clone),
  HOOK("sys_execve", theia_hook_execve, &real_sys_execve),
  HOOK("sys_exit", theia_hook_exit, &real_sys_exit),
  HOOK("sys_exit_group", theia_hook_exit_group, &real_sys_exit_group),
  HOOK("sys_link", theia_hook_link, &real_sys_link),
  HOOK("sys_sync", theia_hook_sync, &real_sys_sync),
  HOOK("sys_chdir", theia_hook_chdir, &real_sys_chdir),
  HOOK("sys_pause", theia_hook_pause, &real_sys_pause),
  HOOK("sys_vhangup", theia_hook_vhangup, &real_sys_vhangup),
  HOOK("sys_munlockall", theia_hook_munlockall, &real_sys_munlockall),
  HOOK("sys_getuid", theia_hook_getuid, &real_sys_getuid),
  HOOK("sys_getgid", theia_hook_getgid, &real_sys_getgid),
  HOOK("sys_geteuid", theia_hook_geteuid, &real_sys_geteuid),
  HOOK("sys_getegid", theia_hook_getegid, &real_sys_getegid),
  HOOK("sys_getppid", theia_hook_getppid, &real_sys_getppid),
  HOOK("sys_getpgrp", theia_hook_getpgrp, &real_sys_getpgrp),
  HOOK("sys_setsid", theia_hook_setsid, &real_sys_setsid),
  HOOK("sys_gettid", theia_hook_gettid, &real_sys_gettid),
  HOOK("sys_inotify_init", theia_hook_inotify_init, &real_sys_inotify_init),
  HOOK("sys_mknod", theia_hook_mknod, &real_sys_mknod),
  HOOK("sys_lseek", theia_hook_lseek, &real_sys_lseek),
  HOOK("sys_access", theia_hook_access, &real_sys_access),
  HOOK("sys_dup", theia_hook_dup, &real_sys_dup),
  HOOK("sys_dup2", theia_hook_dup2, &real_sys_dup2),
  HOOK("sys_alarm", theia_hook_alarm, &real_sys_alarm),
  HOOK("sys_utime", theia_hook_utime, &real_sys_utime),
  HOOK("sys_kill", theia_hook_kill, &real_sys_kill),
  HOOK("sys_rename", theia_hook_rename, &real_sys_rename),
  HOOK("sys_mkdir", theia_hook_mkdir, &real_sys_mkdir),
  HOOK("sys_rmdir", theia_hook_rmdir, &real_sys_rmdir),
  HOOK("sys_acct", theia_hook_acct, &real_sys_acct),
  HOOK("sys_umount", theia_hook_umount, &real_sys_umount),
  HOOK("sys_umask", theia_hook_umask, &real_sys_umask),
  HOOK("sys_chroot", theia_hook_chroot, &real_sys_chroot),
  HOOK("sys_sethostname", theia_hook_sethostname, &real_sys_sethostname),
  HOOK("sys_settimeofday", theia_hook_settimeofday, &real_sys_settimeofday),
  HOOK("sys_symlink", theia_hook_symlink, &real_sys_symlink),
  HOOK("sys_swapon", theia_hook_swapon, &real_sys_swapon),
  HOOK("sys_reboot", theia_hook_reboot, &real_sys_reboot),
  HOOK("sys_truncate", theia_hook_truncate, &real_sys_truncate),
  HOOK("sys_ftruncate", theia_hook_ftruncate, &real_sys_ftruncate),
  HOOK("sys_getpriority", theia_hook_getpriority, &real_sys_getpriority),
  HOOK("sys_setpriority", theia_hook_setpriority, &real_sys_setpriority),
  HOOK("sys_swapoff", theia_hook_swapoff, &real_sys_swapoff),
  HOOK("sys_semget", theia_hook_semget, &real_sys_semget),
  HOOK("sys_semop", theia_hook_semop, &real_sys_semop),
  HOOK("sys_semtimedop", theia_hook_semtimedop, &real_sys_semtimedop),
  HOOK("sys_msgget", theia_hook_msgget, &real_sys_msgget),
  HOOK("sys_msgsnd", theia_hook_msgsnd, &real_sys_msgsnd),
  HOOK("sys_fsync", theia_hook_fsync, &real_sys_fsync),
  HOOK("sys_setdomainname", theia_hook_setdomainname, &real_sys_setdomainname),
  HOOK("sys_init_module", theia_hook_init_module, &real_sys_init_module),
  HOOK("sys_delete_module", theia_hook_delete_module, &real_sys_delete_module),
  HOOK("sys_getpgid", theia_hook_getpgid, &real_sys_getpgid),
  HOOK("sys_fchdir", theia_hook_fchdir, &real_sys_fchdir),
  HOOK("sys_personality", theia_hook_personality, &real_sys_personality),
  HOOK("sys_flock", theia_hook_flock, &real_sys_flock),
  HOOK("sys_msync", theia_hook_msync, &real_sys_msync),
  HOOK("sys_getsid", theia_hook_getsid, &real_sys_getsid),
  HOOK("sys_fdatasync", theia_hook_fdatasync, &real_sys_fdatasync),
  HOOK("sys_mlock", theia_hook_mlock, &real_sys_mlock),
  HOOK("sys_munlock", theia_hook_munlock, &real_sys_munlock),
  HOOK("sys_mlockall", theia_hook_mlockall, &real_sys_mlockall),
  HOOK("sys_sched_setparam", theia_hook_sched_setparam, &real_sys_sched_setparam),
  HOOK("sys_sched_setscheduler", theia_hook_sched_setscheduler, &real_sys_sched_setscheduler),
  HOOK("sys_sched_getscheduler", theia_hook_sched_getscheduler, &real_sys_sched_getscheduler),
  HOOK("sys_sched_get_priority_max", theia_hook_sched_get_priority_max, &real_sys_sched_get_priority_max),
  HOOK("sys_sched_get_priority_min", theia_hook_sched_get_priority_min, &real_sys_sched_get_priority_min),
  HOOK("sys_rt_sigqueueinfo", theia_hook_rt_sigqueueinfo, &real_sys_rt_sigqueueinfo),
  HOOK("sys_rt_sigsuspend", theia_hook_rt_sigsuspend, &real_sys_rt_sigsuspend),
  HOOK("sys_setpgid", theia_hook_setpgid, &real_sys_setpgid),
  HOOK("sys_setregid", theia_hook_setregid, &real_sys_setregid),
  HOOK("sys_setgroups", theia_hook_setgroups, &real_sys_setgroups),
  HOOK("sys_setresgid", theia_hook_setresgid, &real_sys_setresgid),
  HOOK("sys_setgid", theia_hook_setgid, &real_sys_setgid),
  HOOK("sys_setfsuid", theia_hook_setfsuid, &real_sys_setfsuid),
  HOOK("sys_setfsgid", theia_hook_setfsgid, &real_sys_setfsgid),
  HOOK("sys_pivot_root", theia_hook_pivot_root, &real_sys_pivot_root),
  HOOK("sys_readahead", theia_hook_readahead, &real_sys_readahead),
  HOOK("sys_setxattr", theia_hook_setxattr, &real_sys_setxattr),
  HOOK("sys_lsetxattr", theia_hook_lsetxattr, &real_sys_lsetxattr),
  HOOK("sys_fsetxattr", theia_hook_fsetxattr, &real_sys_fsetxattr),
  HOOK("sys_removexattr", theia_hook_removexattr, &real_sys_removexattr),
  HOOK("sys_lremovexattr", theia_hook_lremovexattr, &real_sys_lremovexattr),
  HOOK("sys_fremovexattr", theia_hook_fremovexattr, &real_sys_fremovexattr),
  HOOK("sys_tkill", theia_hook_tkill, &real_sys_tkill),
  HOOK("sys_sched_setaffinity", theia_hook_sched_setaffinity, &real_sys_sched_setaffinity),
  HOOK("sys_io_destroy", theia_hook_io_destroy, &real_sys_io_destroy),
  HOOK("sys_io_submit", theia_hook_io_submit, &real_sys_io_submit),
  HOOK("sys_fadvise64", theia_hook_fadvise64, &real_sys_fadvise64),
  HOOK("sys_epoll_create", theia_hook_epoll_create, &real_sys_epoll_create),
  HOOK("sys_epoll_ctl", theia_hook_epoll_ctl, &real_sys_epoll_ctl),
  HOOK("sys_timer_getoverrun", theia_hook_timer_getoverrun, &real_sys_timer_getoverrun),
  HOOK("sys_timer_delete", theia_hook_timer_delete, &real_sys_timer_delete),
  HOOK("sys_clock_settime", theia_hook_clock_settime, &real_sys_clock_settime),
  HOOK("sys_tgkill", theia_hook_tgkill, &real_sys_tgkill),
  HOOK("sys_utimes", theia_hook_utimes, &real_sys_utimes),
  HOOK("sys_mbind", theia_hook_mbind, &real_sys_mbind),
  HOOK("sys_set_mempolicy", theia_hook_set_mempolicy, &real_sys_set_mempolicy),
  HOOK("sys_mq_open", theia_hook_mq_open, &real_sys_mq_open),
  HOOK("sys_mq_unlink", theia_hook_mq_unlink, &real_sys_mq_unlink),
  HOOK("sys_mq_timedsend", theia_hook_mq_timedsend, &real_sys_mq_timedsend),
  HOOK("sys_mq_notify", theia_hook_mq_notify, &real_sys_mq_notify),
  HOOK("sys_kexec_load", theia_hook_kexec_load, &real_sys_kexec_load),
  HOOK("sys_add_key", theia_hook_add_key, &real_sys_add_key),
  HOOK("sys_request_key", theia_hook_request_key, &real_sys_request_key),
  HOOK("sys_ioprio_set", theia_hook_ioprio_set, &real_sys_ioprio_set),
  HOOK("sys_ioprio_get", theia_hook_ioprio_get, &real_sys_ioprio_get),
  HOOK("sys_inotify_add_watch", theia_hook_inotify_add_watch, &real_sys_inotify_add_watch),
  HOOK("sys_inotify_rm_watch", theia_hook_inotify_rm_watch, &real_sys_inotify_rm_watch),
  HOOK("sys_migrate_pages", theia_hook_migrate_pages, &real_sys_migrate_pages),
  HOOK("sys_mkdirat", theia_hook_mkdirat, &real_sys_mkdirat),
  HOOK("sys_mknodat", theia_hook_mknodat, &real_sys_mknodat),
  HOOK("sys_futimesat", theia_hook_futimesat, &real_sys_futimesat),
  HOOK("sys_renameat", theia_hook_renameat, &real_sys_renameat),
  HOOK("sys_linkat", theia_hook_linkat, &real_sys_linkat),
  HOOK("sys_symlinkat", theia_hook_symlinkat, &real_sys_symlinkat),
  HOOK("sys_faccessat", theia_hook_faccessat, &real_sys_faccessat),
  HOOK("sys_unshare", theia_hook_unshare, &real_sys_unshare),
  HOOK("sys_set_robust_list", theia_hook_set_robust_list, &real_sys_set_robust_list),
  HOOK("sys_tee", theia_hook_tee, &real_sys_tee),
  HOOK("sys_sync_file_range", theia_hook_sync_file_range, &real_sys_sync_file_range),
  HOOK("sys_vmsplice", theia_hook_vmsplice, &real_sys_vmsplice),
  HOOK("sys_utimensat", theia_hook_utimensat, &real_sys_utimensat),
  HOOK("sys_signalfd", theia_hook_signalfd, &real_sys_signalfd),
  HOOK("sys_timerfd_create", theia_hook_timerfd_create, &real_sys_timerfd_create),
  HOOK("sys_eventfd", theia_hook_eventfd, &real_sys_eventfd),
  HOOK("sys_fallocate", theia_hook_fallocate, &real_sys_fallocate),
  HOOK("sys_signalfd4", theia_hook_signalfd4, &real_sys_signalfd4),
  HOOK("sys_eventfd2", theia_hook_eventfd2, &real_sys_eventfd2),
  HOOK("sys_epoll_create1", theia_hook_epoll_create1, &real_sys_epoll_create1),
  HOOK("sys_dup3", theia_hook_dup3, &real_sys_dup3),
  HOOK("sys_inotify_init1", theia_hook_inotify_init1, &real_sys_inotify_init1),
  HOOK("sys_rt_tgsigqueueinfo", theia_hook_rt_tgsigqueueinfo, &real_sys_rt_tgsigqueueinfo),
  HOOK("sys_perf_event_open", theia_hook_perf_event_open, &real_sys_perf_event_open),
  HOOK("sys_fanotify_init", theia_hook_fanotify_init, &real_sys_fanotify_init),
  HOOK("sys_fanotify_mark", theia_hook_fanotify_mark, &real_sys_fanotify_mark),
  HOOK("sys_open_by_handle_at", theia_hook_open_by_handle_at, &real_sys_open_by_handle_at),
  HOOK("sys_syncfs", theia_hook_syncfs, &real_sys_syncfs),
  HOOK("sys_setns", theia_hook_setns, &real_sys_setns),
};

const size_t nr_theia_hooks = ARRAY_SIZE(theia_hooks);
