/*
 * Hooking kernel functions using ftrace framework
 *
 * Copyright (c) 2018 ilammy
 * Modified by:
 *  wilson.martin@gtri.gatech.edu
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/ratelimit.h>
#include <linux/types.h>

#include <theia_hook.h>
#include <theia_syscalls.h>
#include <replay.h>
#include <serialize.h>

/*
 * Import Theia symbols
 */
#include <theia_core.h>

MODULE_DESCRIPTION("Theia function hooks via ftrace");
MODULE_AUTHOR("ilammy <a.lozovsky@gmail.com>, "
    "wilson.martin@gtri.gatech.edu");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1-THEIA-0000");

#define IS_NULL_OR_LT_PAGE(ptr) (!ptr || (unsigned long)ptr < PAGE_SIZE)

/*
 * local state data
 */
static struct module *theia_core_module = NULL;


static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = kallsyms_lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs)
{
  int within_self = 0;
  int within_core = 0;
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

  if (!atomic_read(&all_hooks_enabled)) return;
  if (IS_NULL_OR_LT_PAGE(regs))
  {
    pr_err_ratelimited("%s: regs is null. perhaps FTRACE_OPS_FL_SAVE_REGS flag was not set.\n", __func__);
    pr_err_ratelimited("%s: all_hooks_enabled = 0\n", __func__);
    atomic_set(&all_hooks_enabled, 0);
    return;
  }
  /* check for regs nullptr before checking regs->ip */
  BUG_ON(IS_NULL_OR_LT_PAGE(regs->ip));
  pr_debug_ratelimited("%s: ip=%p parent_ip=%p\n", __func__, (void*)ip, (void*)parent_ip);
  pr_debug_ratelimited("%s: hook->address=%p name=%s hook->function=%p\n",
      __func__, (void*)hook->address, hook->name, hook->function);
  BUG_ON(IS_NULL_OR_LT_PAGE(hook->function));

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->function;
#else
  within_self = within_module_core(parent_ip, THIS_MODULE);
  if (likely(theia_core_module))
    within_core = within_module_core(parent_ip, theia_core_module);
  if (!within_self && !within_core)
		regs->ip = (unsigned long) hook->function;
#endif
  pr_debug_ratelimited("%s: USE_FENTRY_OFFSET=%d: regs=%p regs->ip=%p\n", __func__, USE_FENTRY_OFFSET, regs, (void*)regs->ip);
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;
  pr_debug("%s: new hook: address=%p name=%s\n", __func__, (void*)hook->address, hook->name);

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION_SAFE.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = 0;
/*
 * FTRACE_OPS_FL_SAVE_REGS and FTRACE_OPS_FL_RECURSION_SAFE first appeared
 * in kernel 3.7.0, however, we have backported the needed ftrace features
 * to kernel 3.5.7.13-ddevec-replay that theia uses.
 */
#if defined(THEIA_MODIFIED_KERNEL_SOURCES) || (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0))
	hook->ops.flags |= FTRACE_OPS_FL_SAVE_REGS;
#endif
#if defined(THEIA_MODIFIED_KERNEL_SOURCES) || (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0))
	hook->ops.flags |= FTRACE_OPS_FL_RECURSION_SAFE;
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0))
	hook->ops.flags |= FTRACE_OPS_FL_IPMODIFY;
#endif

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

static int __init fh_init(void)
{
	int err;

  init_extra_syscalls();
  serialize_init();

  atomic_set(&all_hooks_enabled, 0);
	pr_info("module calling fh_install_hooks()\n");
	err = fh_install_hooks(theia_hooks, nr_theia_hooks);
	if (err)
		return err;

  /* lock our dependent modules into the kernel */
  theia_core_module = get_theia_core_module();
  if (theia_core_module)
    __module_get(theia_core_module);

	pr_info("theia_hook: module loaded\n");
  atomic_set(&all_hooks_enabled, 1);

	return 0;
}
module_init(fh_init);

static void  __exit fh_exit(void)
{
  atomic_set(&all_hooks_enabled, 0);
	fh_remove_hooks(theia_hooks, nr_theia_hooks);

  /* unlock our dependent modules */
  if (theia_core_module)
    module_put(theia_core_module);

	pr_info("theia_hook: module unloaded\n");
}
module_exit(fh_exit);
