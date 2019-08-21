#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

MODULE_DESCRIPTION("Theia core code and symbols");
MODULE_AUTHOR("wilson.martin@gtri.gatech.edu");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1-THEIA-0000");

/*
 * Global state for Theia subsystems
 */
static atomic_t all_hooks_enabled = ATOMIC_INIT(0);
EXPORT_SYMBOL(all_hooks_enabled);
/* end of global state */

#define __ENTRY(_name, _mode, _show, _store) \
  static struct kv_entry _name##_kv = { \
  .v = &_name, \
  .ka = __ATTR(_name, _mode, _show, _store), \
}
struct kv_entry {
    void *v;
    struct kobj_attribute ka;
};

static struct attribute **theia_attrs_ptr __read_mostly;

//only use atomic_show with values that are of atomic_t type
static ssize_t atomic_show(struct kobject *kobj, struct kobj_attribute *attr,
    char *buf)
{
  bool flag;
  struct kobj_attribute *ka;
  struct kv_entry *e;
  int i;
  struct attribute *a = NULL;

  i = 0;
  do {
    a = theia_attrs_ptr[i];
    if (!a) break;
    if (strcmp(attr->attr.name, a->name) == 0) {
      ka = container_of(a, struct kobj_attribute, attr);
      e = container_of(ka, struct kv_entry, ka);
      break;
    }
    i++;
  } while (a != NULL);
  if (!a) return -EINVAL;
  flag = atomic_read(e->v);
  return sprintf(buf, "%d\n", flag);
}

static inline int turning_on(long have, long want) { return (have == 0 && want == 1); }
static inline int turning_off(long have, long want) { return (have == 1 && want == 0); }
#define cpu_check(mesg) \
  do { \
    if (num_online_cpus() > 1) { \
      pr_err("error: cannot enable %s if num_online_cpus() > 1\n", mesg); \
      return -EINVAL; \
    } \
  } while (0)

//only use atomic_store with values that are of atomic_t type
static ssize_t atomic_store(struct kobject *kobj, struct kobj_attribute *attr,
    const char *buf, size_t count)
{
  unsigned int flag;
  int error;
  struct kobj_attribute *ka;
  struct kv_entry *e;
  int i;
  struct attribute *a = NULL;

  //10 means base 10 number
  error = kstrtouint(buf, 10, &flag);
  if (error < 0) return error;

  i = 0;
  do {
    a = theia_attrs_ptr[i];
    if (!a) break;
    if (strcmp(attr->attr.name, a->name) == 0) {
      ka = container_of(a, struct kobj_attribute, attr);
      e = container_of(ka, struct kv_entry, ka);
      break;
    }
    i++;
  } while (a != NULL);
  if (!a) return -EINVAL;

  /* special case handlers for certain attributes */
  //if (strcmp(attr->attr.name, "theia_logging_toggle") == 0) {
  //  cpu_check("logging");
  //  if (turning_on(theia_logging_toggle, flag)) {
  //    packahgv_reboot();
  //    if (theia_track_getpid) theia_getpid_counter = 0;
  //  }
  //  if (turning_off(theia_logging_toggle, flag)) {
  //    if (theia_secure_flag) return -EINVAL;
  //    if (theia_track_getpid)
  //      pr_info("theia_getpid_counter = %u\n", theia_getpid_counter);
  //  }
  //}
  //else if (strcmp(attr->attr.name, "theia_recording_toggle") == 0) {
  //  cpu_check("recording");
  //  if (turning_on(theia_recording_toggle, flag))
  //    ensure_replayfs_paths();
  //  if (turning_off(theia_recording_toggle, flag)) {
  //    if (theia_secure_flag) return -EINVAL;
  //  }
  //}
  //else if (strcmp(attr->attr.name, "theia_ui_toggle")==0) {
  //  if (turning_off(theia_ui_toggle, flag)) {
  //    if (theia_secure_flag) return -EINVAL;
  //  }
  //}

  atomic_set(e->v, flag);
  pr_info("%s: %s set to %d\n", __func__, attr->attr.name, flag);
  return count;
}

/* define kobject entries here */
__ENTRY(all_hooks_enabled, 0600, atomic_show, atomic_store);

static struct attribute *theia_attrs[] __read_mostly = {
  &all_hooks_enabled_kv.ka.attr,
  NULL, /* need to NULL terminate the list of attributes */
};
static struct attribute_group theia_attr_group = {
  .attrs = theia_attrs,
};
static struct kobject *theia_kobj;

struct module* get_theia_core_module(void)
{
  return THIS_MODULE;
}
EXPORT_SYMBOL(get_theia_core_module);

static int __init core_init(void)
{
  int retval;
  theia_attrs_ptr = theia_attrs;
  theia_kobj = kobject_create_and_add("theia", kernel_kobj);
  if (!theia_kobj)
    return -ENOMEM;
  retval = sysfs_create_group(theia_kobj, &theia_attr_group);
  if (retval)
    kobject_put(theia_kobj);  // decrement the ref count

  pr_info("theia_core loaded\n");
  return 0;
}
module_init(core_init);

static void __exit core_exit(void)
{
  kobject_put(theia_kobj);
  pr_info("theia_core unloaded\n");
}
module_exit(core_exit);
