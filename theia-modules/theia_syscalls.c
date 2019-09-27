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
};

const size_t nr_theia_hooks = ARRAY_SIZE(theia_hooks);
