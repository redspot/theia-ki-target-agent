/* vim: set expandtab tabstop=2 shiftwidth=2 softtabstop=2 : */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/timer.h>
#include <linux/ioctl.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include <linux/replay.h>

#include <linux/ds_list.h>
#include "devspec.h"

MODULE_AUTHOR("Jason Flinn");
MODULE_LICENSE("GPL");

extern bool theia_logging_toggle;
extern bool theia_recording_toggle;
extern bool theia_cross_toggle;
extern struct theia_replay_register_data_type theia_replay_register_data;
extern char theia_linker[];
extern char theia_libpath[];

static int majorNumber;
static struct class*  charClass  = NULL;
static struct device* charDevice = NULL;

/* Debugging stuff */
//#define DPRINT printk
#define DPRINT(x,...)

static ssize_t str_show(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf)
{
  char* str_attr;

  if (strcmp(attr->attr.name, "theia_linker") == 0)
    str_attr = theia_linker;
  else if (strcmp(attr->attr.name, "theia_libpath") == 0)
    str_attr = theia_libpath;
  else
    return -EINVAL;
  return sprintf(buf, "%s\n", str_attr);
}
static ssize_t str_store(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count)
{
  /* MAX_LOGDIR_STRLEN is in include/linux/replay.h
   * and gets used as a generic buffer size in replay.c
   */
  if (count > MAX_LOGDIR_STRLEN)
    return -ENOENT;
  char* str_attr;

  if (strcmp(attr->attr.name, "theia_linker") == 0)
    str_attr = theia_linker;
  else if (strcmp(attr->attr.name, "theia_libpath") == 0)
    str_attr = theia_libpath;
  else
    return -EINVAL;

  memcpy(str_attr, buf, count);
  str_attr[count] = '\0';
  if (count && str_attr[count-1] == '\n')
    str_attr[count-1] = '\0';
  pr_info("%s set to %s\n", attr->attr.name, str_attr);
  return count;
}
static struct kobj_attribute linker_attribute =
__ATTR(theia_linker, 0600, str_show, str_store);
static struct kobj_attribute libpath_attribute =
__ATTR(theia_libpath, 0600, str_show, str_store);

static ssize_t flag_show(struct kobject *kobj, struct kobj_attribute *attr,
    char *buf)
{
  bool flag;

  if (strcmp(attr->attr.name, "theia_logging_toggle") == 0)
    flag = theia_logging_toggle;
  else if (strcmp(attr->attr.name, "theia_recording_toggle") == 0)
    flag = theia_recording_toggle;
  else
    return -EINVAL;
  return sprintf(buf, "%d\n", flag);
}
static ssize_t flag_store(struct kobject *kobj, struct kobj_attribute *attr,
    const char *buf, size_t count)
{
  unsigned int flag;
  int error;

  error = kstrtouint(buf, 10, &flag);
  if (error || flag > 1) return -EINVAL;

  if (strcmp(attr->attr.name, "theia_logging_toggle") == 0) {
    theia_logging_toggle = flag;
  } else if (strcmp(attr->attr.name, "theia_recording_toggle") == 0) {
    theia_recording_toggle = flag;
  } else
    return -EINVAL;
  pr_info("%s set to %d\n", attr->attr.name, flag);
  return count;
}

static struct kobj_attribute logging_toggle_attribute =
__ATTR(theia_logging_toggle, 0600, flag_show, flag_store);
static struct kobj_attribute recording_toggle_attribute =
__ATTR(theia_recording_toggle, 0600, flag_show, flag_store);

static struct attribute *theia_attrs[] = {
  &linker_attribute.attr,
  &libpath_attribute.attr,
  &logging_toggle_attribute.attr,
  &recording_toggle_attribute.attr,
  NULL,	/* need to NULL terminate the list of attributes */
};
static struct attribute_group theia_attr_group = {
  .attrs = theia_attrs,
};

static struct kobject *theia_kobj;

/* Called by apps to open the device. */ 
static int spec_psdev_open(struct inode* inode, struct file* filp)
{
  DPRINT ("process %d has opened device\n", current->pid);
  return 0;
}

/* Called by apps to release the device */
static int spec_psdev_release(struct inode * inode, struct file * file)
{
  DPRINT ("process %d has closed device\n", current->pid);
  return 0;
}

static long spec_psdev_ioctl (struct file* file, u_int cmd, u_long data)
{
  int len = _IOC_SIZE(cmd), retval;
  struct ckpt_proc *pckpt_proc, *new_ckpt_proc;
  struct record_data rdata;
  struct wakeup_data wdata;
  struct replay_register_user_data replay_data;
  struct get_used_addr_data udata;
  struct filemap_num_data fndata;
  struct filemap_entry_data fedata;
  int syscall;
  u_long app_syscall_addr;
  char logdir[MAX_LOGDIR_STRLEN+1];
  char* tmp = NULL;
  long rc;
  u_long inode;

  pckpt_proc = new_ckpt_proc = NULL;
  DPRINT ("pid %d cmd number 0x%08x\n", current->pid, cmd);

  switch (cmd) {
    case THEIA_LOGGING_ON:
      theia_logging_toggle = 1;
      printk(KERN_INFO "Theia logging on\n");
      return 0;
    case THEIA_LOGGING_OFF:
      theia_logging_toggle = 0;
      printk(KERN_INFO "Theia logging off\n");
      return 0;
    case THEIA_RECORDING_ON:
      theia_recording_toggle = 1;
      printk(KERN_INFO "Theia recording on\n");
      return 0;
    case THEIA_RECORDING_OFF:
      theia_recording_toggle = 0;
      printk(KERN_INFO "Theia recording off\n");
      return 0;
    case THEIA_CROSS_ON:
      theia_cross_toggle = 1;
      return 0;
    case THEIA_CROSS_OFF:
      theia_cross_toggle = 0;
      return 0;

    case THEIA_REPLAY_REGISTER:
      {
        if (len != sizeof(replay_data)) {
          printk ("ioctl THEIA_REPLAY_REGISTER fails, len %d\n", len);
          return -EINVAL;
        }
        if (copy_from_user (&replay_data, (void *) data, sizeof(replay_data)))
          return -EFAULT;
        retval = strncpy_from_user(theia_replay_register_data.logdir, replay_data.logdir, MAX_LOGDIR_STRLEN);
        if (retval < 0 || retval >= MAX_LOGDIR_STRLEN) {
          printk ("ioctl THEIA_REPLAY_REGISTER fails, strcpy returns %d\n", retval);
          return -EINVAL;
        }
        if (replay_data.linker) {
          tmp = getname(replay_data.linker);
          if (tmp == NULL) {
            printk ("THEIA_REPLAY_REGISTER: cannot get linker name\n");
            return -EFAULT;
          } 
        } else {
          tmp = NULL;
        }
        theia_replay_register_data.linker = tmp;
        theia_replay_register_data.pid = replay_data.pid;
        theia_replay_register_data.pin = replay_data.pin;
        theia_replay_register_data.fd = replay_data.fd;
        theia_replay_register_data.follow_splits = replay_data.follow_splits;
        theia_replay_register_data.save_mmap = replay_data.save_mmap;

        printk("THEIA_REPLAY_REGISTER is sent in. %d, logdir %s,linker %s\n", theia_replay_register_data.pid, theia_replay_register_data.logdir, theia_replay_register_data.linker);
        //FIXME:Yang: Do we have a leakage here? Need to find a garbage collection location after replay is done.
        //		if (tmp) putname (tmp);
        return 0;
      }

    case SPECI_REPLAY_FORK:
      if (len != sizeof(rdata)) {
        printk ("ioctl SPECI_FORK_REPLAY fails, len %d\n", len);
        return -EINVAL;
      }
      if (copy_from_user (&rdata, (void *) data, sizeof(rdata))) {
        printk ("ioctl SPECI_FORK_REPLAY fails, inavlid data\n");
        return -EFAULT;
      }
      if (rdata.linkpath) {
        tmp = getname(rdata.linkpath);
        if (tmp == NULL) {
          printk ("SPECI_REPLAY_FORK: cannot get linker name\n");
          return -EFAULT;
        } 
      } else {
        tmp = NULL;
      }
      if (rdata.logdir) {
        retval = strncpy_from_user(logdir, rdata.logdir, MAX_LOGDIR_STRLEN);
        if (retval < 0 || retval >= MAX_LOGDIR_STRLEN) {
          printk ("ioctl SPECI_FOR_REPLAY fails, strcpy returns %d\n", retval);
          return -EINVAL;
        }
        return fork_replay (logdir, rdata.args, rdata.env, tmp, rdata.save_mmap,
            rdata.fd, rdata.pipe_fd);
      } else {
        return fork_replay (NULL, rdata.args, rdata.env, tmp, rdata.save_mmap,
            rdata.fd, rdata.pipe_fd);
      }
    case SPECI_RESUME:
      if (len != sizeof(wdata)) {
        printk ("ioctl SPECI_RESUME fails, len %d\n", len);
        return -EINVAL;
      }
      if (copy_from_user (&wdata, (void *) data, sizeof(wdata)))
        return -EFAULT;
      retval = strncpy_from_user(logdir, wdata.logdir, MAX_LOGDIR_STRLEN);
      if (retval < 0 || retval >= MAX_LOGDIR_STRLEN) {
        printk ("ioctl SPECI_FOR_REPLAY fails, strcpy returns %d\n", retval);
        return -EINVAL;
      }
      if (wdata.linker) {
        tmp = getname(wdata.linker);
        if (tmp == NULL) {
          printk ("SPECI_RESUME: cannot get linker name\n");
          return -EFAULT;
        } 
      } else {
        tmp = NULL;
      }
      rc = replay_ckpt_wakeup (wdata.pin, logdir, tmp, wdata.fd, wdata.follow_splits, wdata.save_mmap);
      if (tmp) putname (tmp);
      return rc;

    case SPECI_SET_PIN_ADDR:
      if (len != sizeof(u_long)) {
        printk ("ioctl SPECI_SET_PIN_ADDR fails, len %d\n", len);
        return -EINVAL;
      }
      if (copy_from_user (&app_syscall_addr, (void *) data, sizeof(app_syscall_addr)))
        return -EFAULT;
      return set_pin_address (app_syscall_addr);
    case SPECI_CHECK_BEFORE:
      if (len != sizeof(int)) {
        printk ("ioctl SPECI_CHECK_BEFORE fails, len %d\n", len);
        return -EINVAL;
      }
      if (copy_from_user (&syscall, (void *) data, sizeof(syscall)))
        return -EFAULT;
      return check_clock_before_syscall (syscall);
    case SPECI_CHECK_AFTER:
      return check_clock_after_syscall (0);
    case SPECI_GET_LOG_ID:
      return get_log_id ();
      //Yang: get inode for pin
    case THEIA_GET_INODE_FORPIN:
      if (len != sizeof(u_long)) {
        printk ("ioctl SPECI_GET_INODE_FORPIN fails, len %d\n", len);
        return -EINVAL;
      }
      if (copy_from_user (&inode, (void *) data, sizeof(u_long)))
        return -EFAULT;
      printk("inode received: %lx\n",inode);
      return get_inode_for_pin(inode);

    case SPECI_GET_CLOCK_VALUE:
      return get_clock_value ();
    case SPECI_GET_USED_ADDR:
      if (len != sizeof(udata)) {
        printk ("ioctl SPECI_GET_USED_ADDR fails, len %d\n", len);
        return -EINVAL;
      }
      if (copy_from_user (&udata, (void *) data, sizeof(udata)))
        return -EFAULT;

      return get_used_addresses (udata.plist, udata.nlist);
    case SPECI_GET_REPLAY_STATS:
      return get_replay_stats ((struct replay_stats *) data);
    case SPECI_GET_REPLAY_ARGS:
      return get_replay_args();
    case SPECI_GET_ENV_VARS:
      return get_env_vars();
    case SPECI_GET_RECORD_GROUP_ID:
      return get_record_group_id((__u64 *) data);
    case SPECI_GET_NUM_FILEMAP_ENTRIES:
      if (len != sizeof(fndata)) {
        printk ("ioctl SPECI_GET_NUM_FILEMAP_ENTRIES fails, len %d\n", len);
        return -EINVAL;
      }
      if (copy_from_user (&fndata, (void *) data, sizeof(fndata))) {
        return -EFAULT;
      }
      return get_num_filemap_entries(fndata.fd, fndata.offset, fndata.size);
    case SPECI_GET_FILEMAP:
      if (len != sizeof(fedata)) {
        printk ("ioctl SPECI_GET_FILEMAP fails, len %d\n", len);
        return -EINVAL;
      }
      if (copy_from_user (&fedata, (void *) data, sizeof(fedata))) {
        return -EFAULT;
      }
      return get_filemap(fedata.fd, fedata.offset, fedata.size, fedata.entries, fedata.num_entries);
    case SPECI_RESET_REPLAY_NDX:
      return reset_replay_ndx();
    default:
      return -EINVAL;
  }
}


static struct file_operations spec_psdev_fops = {
  owner:		THIS_MODULE,
  unlocked_ioctl:	spec_psdev_ioctl,
  open:		spec_psdev_open,
  release:	spec_psdev_release,
};



#ifdef MODULE

int init_module(void)
{
  //allocate dynamic major number
  majorNumber = register_chrdev(0, DEVICE_NAME, &spec_psdev_fops);
  if(majorNumber<0) {
    printk(KERN_ERR DEVICE_NAME": unable to get major dynamically\n");
    return majorNumber;
  }
  //register device class
  charClass = class_create(THIS_MODULE, CLASS_NAME);
  if (IS_ERR(charClass)) {
    unregister_chrdev(majorNumber, DEVICE_NAME);
    printk(KERN_ALERT DEVICE_NAME": Failed to register device class\n");
    return PTR_ERR(charClass);
  }
  //register the device driver
  charDevice = device_create(charClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
  if (IS_ERR(charDevice)) {
    class_destroy(charClass);
    unregister_chrdev(majorNumber, DEVICE_NAME);
    printk(KERN_ALERT DEVICE_NAME": Failed to create the device\n");
    return PTR_ERR(charDevice);
  }

  /*
   * Create a simple kobject with the name of "theia",
   * located under /sys/kernel/
   *
   * As this is a simple directory, no uevent will be sent to
   * userspace.  That is why this function should not be used for
   * any type of dynamic kobjects, where the name and number are
   * not known ahead of time.
   */
  theia_kobj = kobject_create_and_add("theia", kernel_kobj);
  if (!theia_kobj)
    return -ENOMEM;

  /* Create the files associated with this kobject */
  int retval = sysfs_create_group(theia_kobj, &theia_attr_group);
  if (retval)
    kobject_put(theia_kobj);  // decrement the ref count

  printk(KERN_INFO "User-level speculation module version 1.0, major=%d\n", majorNumber);
  return 0;
}

void cleanup_module(void)
{
  printk (KERN_INFO DEVICE_NAME": destroying device and class.\n");
  device_destroy(charClass, MKDEV(majorNumber, 0));
  class_unregister(charClass);
  class_destroy(charClass);
  unregister_chrdev(majorNumber, DEVICE_NAME);
  kobject_put(theia_kobj);  // decrement the ref count
  printk (KERN_INFO "User-Level speculation module 1.0 exiting.\n");
}

#endif
