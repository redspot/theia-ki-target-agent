#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xb128b138, "module_layout" },
	{ 0x2a9c9077, "get_filemap" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0xca43aea5, "get_used_addresses" },
	{ 0xd6cf74b8, "replay_ckpt_wakeup" },
	{ 0x1571c46d, "__register_chrdev" },
	{ 0xd1213b65, "check_clock_after_syscall" },
	{ 0x6d815394, "get_clock_value" },
	{ 0x5387725, "get_log_id" },
	{ 0x24428be5, "strncpy_from_user" },
	{ 0xcad50acd, "get_num_filemap_entries" },
	{ 0x7c60d66e, "getname" },
	{ 0x50eedeb8, "printk" },
	{ 0x42806fb0, "get_env_vars" },
	{ 0x4fca46bf, "reset_replay_ndx" },
	{ 0x22eaa105, "check_clock_before_syscall" },
	{ 0xb4390f9a, "mcount" },
	{ 0x437b93f9, "get_record_group_id" },
	{ 0x118f01ea, "putname" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x7487e42b, "get_replay_stats" },
	{ 0x8715150e, "get_replay_args" },
	{ 0x67bfbc5c, "fork_replay" },
	{ 0x9969ad71, "set_pin_address" },
	{ 0x362ef408, "_copy_from_user" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "E2D86C84EA0AB792813E4EE");
