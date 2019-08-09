#include <linux/module.h>
#include <linux/init.h>

MODULE_DESCRIPTION("Theia core code and symbols");
MODULE_AUTHOR("wilson.martin@gtri.gatech.edu");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1-THEIA-0000");

struct module* get_theia_core_module(void)
{
  return THIS_MODULE;
}
EXPORT_SYMBOL(get_theia_core_module);

static int __init core_init(void)
{
  pr_info("theia_core loaded\n");
  return 0;
}
module_init(core_init);

static void __exit core_exit(void)
{
  pr_info("theia_core unloaded\n");
}
module_exit(core_exit);
