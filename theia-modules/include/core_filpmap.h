#ifndef __CORE_FILPMAP_H__
#define __CORE_FILPMAP_H__

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/types.h>

typedef struct {
       u64 key; /* the task that these data refer to */
       struct hlist_node next; /* next entry in the hashmap */
       /* our data goes below here */
       void *data; //to be filled in later by a struct replayfs_filemap
} theia_filpmap_entry;

#undef HASHMAP_BITS
#undef HASHMAP_NAME_PREFIX
#undef HASHMAP_VALUE_TYPE
#undef HASHMAP_ALLOCATOR_FLAGS

/*
 *               12 bits = 4096 entries
 *               theia-vm4, idle, had ~1800 open files
 *               online examples suggest 5-8k
 */
#define HASHMAP_BITS 12
#define HASHMAP_NAME_PREFIX theia_filpmap
#define HASHMAP_VALUE_TYPE theia_filpmap_entry
#define HASHMAP_ALLOCATOR_FLAGS GFP_KERNEL
#include "hashmap/hashmap_type.h"

static inline u64 __filp_key(struct file *filp) {
    u64 key;
    struct inode *inode = filp->f_dentry->d_inode;
    key = ((u64)inode->i_sb->s_dev) << 32 | (u64)inode->i_ino;
    return key;
}

#endif
