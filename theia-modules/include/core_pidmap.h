#include "theia_core.h"
#include <linux/slab.h>

#undef HASHMAP_BITS
#undef HASHMAP_NAME_PREFIX
#undef HASHMAP_VALUE_TYPE
#undef HASHMAP_ALLOCATOR_FLAGS

//            8 bits, 256 buckets. vm4 @ idle has ~128 PIDs

#define HASHMAP_BITS 8
#define HASHMAP_NAME_PREFIX pidmap
#define HASHMAP_VALUE_TYPE struct theia_task
#define HASHMAP_ALLOCATOR_FLAGS GFP_KERNEL
#include "hashmap/hashmap_type.h"
