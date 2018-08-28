/*
 *  Patchguard - Automated restoration of SSDT Hook and Inline Hook
 *  Copyright (C) 2013 by Aaron Lewis <the.warl0ck.1989@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/user.h>
#include <linux/security.h>
#include <linux/unistd.h>
#include <linux/notifier.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <asm/unistd.h>
#include <linux/relay.h>

// TODO: dirty hack on Arch, WTF?
#ifndef NR_syscalls
#define NR_syscalls 274
#endif

static unsigned long *sys_call_table;
static struct timer_list patchguard_timer;
extern struct rchan *theia_chan;
extern int theia_secure_flag;
static struct kmem_cache *buffers;
static int is_module_locked = 0;

// TODO: incoroprate disas engine
#define OPCODE_MAX_BYTES 10
#define PATCHGUARD_CHK_INTERVAL 3000

#define WPOFF do { write_cr0(read_cr0() & (~0x10000)); } while (0);
#define WPON  do { write_cr0(read_cr0() | 0x10000);    } while (0);

#define SYS_CLOSE \
  ({ \
   unsigned int *p = (unsigned int*)__builtin_alloca(12); \
   p[0] = 0x5f737973; \
   p[1] = 0x736f6c63; \
   p[2] = 0x00000065; \
   (char *)p; \
   })

struct ksym {
  char *name;
  unsigned long addr;
};

int find_ksym(void *data, const char *name, struct module *module, unsigned long address) {
  struct ksym *ksym = (struct ksym *)data;
  char *target = ksym->name;

  if (strncmp(target, name, KSYM_NAME_LEN) == 0) {
    ksym->addr = address;
    return 1;
  }

  return 0;
}

unsigned long get_symbol(char *name) {
  unsigned long symbol = 0;
  struct ksym ksym;

  ksym.name = name;
  ksym.addr = 0;
  kallsyms_on_each_symbol(&find_ksym, &ksym);
  symbol = ksym.addr;

  return symbol;
}

void *memmem(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size) {
  char *p;

  for(p = (char *)haystack; p <= ((char *)haystack - needle_size + haystack_size); p++) {
    if(memcmp(p, needle, needle_size) == 0) return (void *)p;
  }
  return NULL;
}

// TODO: check sum support
struct _kern_opcode
{
  unsigned long addr;
  unsigned char bytes[OPCODE_MAX_BYTES];
} kern_opcode [NR_syscalls];


#ifndef CONFIG_64BIT
static unsigned long *get_syscalls_table(void)
{
  unsigned long *start;

  for (start = (unsigned long *)0xc0000000; start < (unsigned long *)0xffffffff; start++)
    if (start[__NR_close] == (unsigned long)sys_close) {
      return start;
    }
  return NULL;
}
#else
//static unsigned long *get_syscalls_table(void)
//{
//    unsigned long *start;
//
//    for (start = (unsigned long *)0xffffffff810001c8; 
//            start < (unsigned long *)0xffffffff81ab41a2; 
//            start++)
//        if (start[__NR_close] == (unsigned long)sys_close) {
//            return start;
//        }
//    return NULL;
//}
static unsigned long *get_syscalls_table(void)
{
  unsigned long sct_off = 0;
  unsigned char code[512];
  char **p;

  rdmsrl(MSR_LSTAR, sct_off);
  memcpy(code, (void *)sct_off, sizeof(code));

  p = (char **)memmem(code, sizeof(code), "\xff\x14\xc5", 3);

  if(p) {
    unsigned long *table = *(unsigned long **)((char *)p + 3);
    table = (unsigned long *)(((unsigned long)table & 0xffffffff) | 0xffffffff00000000);
    return table;
  }
  return NULL;
}
static unsigned long *backup_get_syscalls_table(void)
{
  unsigned long *syscall_table;
  unsigned long _sys_close;
  unsigned long int i;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
  _sys_close = get_symbol(SYS_CLOSE);
#endif

  for (i = PAGE_OFFSET; i < ULONG_MAX; i += sizeof(void *)) {
    syscall_table = (unsigned long *)i;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    if (syscall_table[__NR_close] == (unsigned long)_sys_close)
#else 
      if (syscall_table[__NR_close] == (unsigned long)sys_close)
#endif
        return syscall_table;
  }
  return NULL;
}
#endif

void packahgv_patchguard(char* mesg) {
  struct timespec tp;
  __kernel_long_t uptime;
  struct timespec ts;
  int size = 0;
  char *buf = kmem_cache_alloc(buffers, GFP_ATOMIC);
  getnstimeofday(&ts);

  ktime_get_ts(&tp);
  monotonic_to_bootbased(&tp);
  uptime = tp.tv_sec + (tp.tv_nsec ? 1 : 0);

  size = sprintf(buf, "startahg|%d|%ld|%ld|%ld|%s|endahg\n",
      602/*used for patchguard*/, uptime, ts.tv_sec, ts.tv_nsec, mesg);
  if (size > 0) {
    mesg[size] = 0x0;
    pr_debug("Patchguard::packahgv buf={%s}\n", buf);
    if(theia_chan)
      relay_write(theia_chan, buf, size);
  }
  kmem_cache_free(buffers, buf);
}

static void check_hook(unsigned long data)
{
  int i, j;
  unsigned char *p;
  char* mesg;
  char* call_name;
  int len;
  char* ssdt_mesg = "SSDT_Hook|%d|%p|%s";
  char* inline_mesg = "Inline_Hook|%d|%p|%s";

  //lock/unlock this module from being unloaded
  if (!is_module_locked)
    if (theia_secure_flag) {
      try_module_get(THIS_MODULE);
      is_module_locked = 1;
    }
  //currently, we never unlock once locked
  //else
  //  if (!theia_secure_flag) {
  //    module_put(THIS_MODULE);
  //    is_module_locked = 0;
  //  }

  // TODO: sys_call_table array base address verification
  for (i = 0; i < NR_syscalls; ++i)
  {
    p = (unsigned char*) sys_call_table[i];

    // Verify sys_call_table
    if (sys_call_table[i] != kern_opcode[i].addr)
    {
      call_name = kmem_cache_alloc(buffers, GFP_ATOMIC);
      memset(call_name, 0x0, 128);
      mesg = kmem_cache_alloc(buffers, GFP_ATOMIC);
      memset(mesg, 0x0, 256);
      len = sprint_symbol_no_offset(call_name, (unsigned long)kern_opcode[i].addr);
      call_name[len] = 0x0;
      pr_info("Security Alert - restored SSDT Hook of (%d)%s at %p\n", i, call_name, p);
      len = sprintf(mesg, ssdt_mesg, i, p, call_name);
      if (len > 0) {
        mesg[len] = 0x0;
        pr_debug("Patchguard::check_hook mesg={%s}\n", mesg);
        packahgv_patchguard(mesg);
      }
      kmem_cache_free(buffers, call_name);
      kmem_cache_free(buffers, mesg);

      WPOFF;
      sys_call_table[i] = kern_opcode[i].addr;
      WPON;

      // Update pointer address
      p = (unsigned char*) sys_call_table[i];
    }

    // Inline hook detection
    for (j = 0; j < OPCODE_MAX_BYTES; ++j, ++p)
    {
      if (kern_opcode[i].bytes[j] != *p)
      {
        call_name = kmem_cache_alloc(buffers, GFP_ATOMIC);
        memset(call_name, 0x0, 128);
        mesg = kmem_cache_alloc(buffers, GFP_ATOMIC);
        memset(mesg, 0x0, 256);
        len = sprint_symbol_no_offset(call_name, (unsigned long)kern_opcode[i].addr);
        call_name[len] = 0x0;
        pr_info("Security Alert - restored Inline Hook of (%d)%s at %p\n", i, call_name, p);
        len = sprintf(mesg, inline_mesg, i, p, call_name);
        if (len > 0) {
          mesg[len] = 0x0;
          pr_debug("Patchguard::check_hook mesg={%s}\n", mesg);
          packahgv_patchguard(mesg);
        }
        kmem_cache_free(buffers, call_name);
        kmem_cache_free(buffers, mesg);

        p = (unsigned char*) sys_call_table[i];
        WPOFF;
        for (j = 0; j < OPCODE_MAX_BYTES; ++j)
        {
          *p = kern_opcode[i].bytes[j]; ++p;
        }
        WPON;

        continue;
      }
    }
  }

  if (mod_timer (&patchguard_timer, jiffies + msecs_to_jiffies(PATCHGUARD_CHK_INTERVAL)))
  {
    pr_err("Error - can't set timer!\n");
  }
}

static int __init startup(void)
{
  unsigned char *p;
  int i = 0, j = 0;
  //start unlocked. then, check_hook() will lock/unlock
  is_module_locked = 0;

  sys_call_table = get_syscalls_table();
  if (! sys_call_table)
    sys_call_table = backup_get_syscalls_table();
  if (! sys_call_table)
  {
    pr_info("Error - Unable to acquire sys_call_table!\n");
    return -ECANCELED;
  }

  pr_debug("Patchguard - found sys_call_table = %p\n", (void*)sys_call_table);
  for (i = 0; i < NR_syscalls; ++i)
  {
    kern_opcode[i].addr = sys_call_table[i];
    p = (unsigned char*)sys_call_table[i];

    for (j = 0; j < OPCODE_MAX_BYTES; ++j)
    {
      kern_opcode[i].bytes[j] = *p ++;
    }
  }

  buffers = kmem_cache_create("pguard_buffers", PAGE_SIZE, 0, 0, NULL);

  // TODO: sysctl support
  // Setup timer
  setup_timer(&patchguard_timer, check_hook, 0);
  if (mod_timer (&patchguard_timer, jiffies + msecs_to_jiffies(PATCHGUARD_CHK_INTERVAL)))
  {
    pr_info("Error - can't set timer!\n");
    return -ECANCELED;
  }

  pr_debug("Patchguard Initialized.\n");
  return 0;
}

static void __exit cleanup(void)
{
  del_timer(&patchguard_timer);
  if (buffers)
    kmem_cache_destroy(buffers);
  pr_info("Patchguard removed.\n");
}

module_init(startup);
module_exit(cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aaron Lewis, Wilson Martin");
MODULE_DESCRIPTION("Patchguard Implementation (Linux)");
MODULE_VERSION("1.1-0000");
