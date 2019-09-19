#include "theia_core.h"
#include <linux/slab.h>
#include <linux/fs.h>

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
#define HASHMAP_NAME_PREFIX filpmap
#define HASHMAP_VALUE_TYPE struct theia_filp_map
#define HASHMAP_ALLOCATOR_FLAGS GFP_KERNEL
#include "hashmap/hashmap_type.h"

static inline u64 __filp_key(struct file *filp) {
    u64 key;
    struct inode *inode = filp->f_dentry->d_inode;
    key = ((u64)inode->i_sb->s_dev) << 32 | (u64)inode->i_ino;
    return key;
}
