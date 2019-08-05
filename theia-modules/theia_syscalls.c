#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/linkage.h>

#include "theia_syscalls.h"
#include "theia_hook.h"

struct module* get_theia_syscalls_module(void)
{
  return THIS_MODULE;
}
EXPORT_SYMBOL(get_theia_syscalls_module);

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

// this is currently not used
static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename;

	kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (!kernel_filename)
		return NULL;

	if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}

/*
 * syscall hooks start here
 */

static asmlinkage long theia_hook_read(SC_PROTO_read)
{
	long ret;
  pr_info("%s: called by pid %d\n", __func__, current->pid);
  ret = real_sys_read(SC_ARGS_read);
  return ret;
}

static asmlinkage long theia_hook_write(SC_PROTO_write)
{
	long ret;
  pr_info("%s: called by pid %d\n", __func__, current->pid);
  ret = real_sys_write(SC_ARGS_write);
  return ret;
}

static asmlinkage long theia_hook_clone(SC_PROTO_clone)
{
	long ret;
  pr_info("%s: called by pid %d\n", __func__, current->pid);
  ret = real_sys_clone(SC_ARGS_clone);
  return ret;
}

static asmlinkage long theia_hook_execve(SC_PROTO_execve)
{
	long ret;
  pr_info("%s: called by pid %d\n", __func__, current->pid);
  ret = real_sys_execve(SC_ARGS_execve);
  return ret;
}

/*
 * syscall hooks end here
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
};
EXPORT_SYMBOL(theia_hooks);

