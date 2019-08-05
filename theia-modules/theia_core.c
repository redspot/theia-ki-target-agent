#include <linux/module.h>

MODULE_DESCRIPTION("Theia core code and symbols");
MODULE_AUTHOR("wilson.martin@gtri.gatech.edu");
MODULE_LICENSE("MIT");
MODULE_VERSION("0.1-THEIA-0000");

struct module* get_theia_core_module(void)
{
  return THIS_MODULE;
}
EXPORT_SYMBOL(get_theia_core_module);
