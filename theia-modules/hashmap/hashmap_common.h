#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/version.h>

//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0))
//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0))
//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0))

// v3.7 added hashtable.h
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0))
#include <linux/hashtable.h>
#else
#include "backport/hashtable.h"
#endif

#if !defined(DEFINE_READ_MOSTLY_HASHTABLE) && (LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0))
#define DEFINE_READ_MOSTLY_HASHTABLE(name, bits)                \
    struct hlist_head name[1 << (bits)] __read_mostly =         \
            { [0 ... ((1 << (bits)) - 1)] = HLIST_HEAD_INIT }
#endif


/*
 *      defines needs
 *          HASHMAP_BITS
 *          HASHMAP_NAME_PREFIX
 *          HASHMAP_VALUE_TYPE
 *          HASHMAP_ALLOCATOR_FLAGS
 *
 *      HASHMAP_VALUE_TYPE must be a struct with two required members:
 *          u64 key
 *          struct hlist_node next
 */
#ifndef HASHMAP_BITS
#error HASHMAP_BITS must be defined in order to include hashmap_common.h
#endif
#ifndef HASHMAP_NAME_PREFIX
#error HASHMAP_NAME_PREFIX must be defined in order to include hashmap_common.h
#endif
#ifndef HASHMAP_VALUE_TYPE
#error HASHMAP_VALUE_TYPE must be defined in order to include hashmap_common.h
#endif
#ifndef HASHMAP_ALLOCATOR_FLAGS
#error HASHMAP_ALLOCATOR_FLAGS must be defined in order to include hashmap_common.h
#endif

#undef _MAP_NAME
#undef _POOL_NAME
#undef _LOCK_NAME
#undef _FN
#undef HASHMAP
#undef POOL
#undef LOCK

#undef MAP_INIT
#undef MAP_DESTROY
#undef MAP_GET
#undef MAP_ADD
#undef MAP_DEL

#ifndef _CONCAT
#define _CONCAT(pre, suf) pre ## suf
#endif
#ifndef _PRE_SCORE
#define _PRE_SCORE(suf) _ ## suf
#endif
//hack for function-like macro expansion
//https://gcc.gnu.org/onlinedocs/cpp/Argument-Prescan.html
#ifndef _FORCE_PRESCAN_CONCAT
#define _FORCE_PRESCAN_CONCAT(pre, suf) _CONCAT(pre, suf)
#endif

#define _MAP_NAME() _FORCE_PRESCAN_CONCAT(HASHMAP_NAME_PREFIX, _hashmap)
#define _POOL_NAME() _FORCE_PRESCAN_CONCAT(HASHMAP_NAME_PREFIX, _mempool)
#define _LOCK_NAME() _FORCE_PRESCAN_CONCAT(HASHMAP_NAME_PREFIX, _lock)
#define _FN(suffix) _FORCE_PRESCAN_CONCAT(HASHMAP_NAME_PREFIX, _PRE_SCORE(suffix))
#define HASHMAP _MAP_NAME()
#define POOL _POOL_NAME()
#define LOCK _LOCK_NAME()

#define MAP_INIT int _FN(init)(void)
#define MAP_DESTROY void _FN(destroy)(void)
#define MAP_GET HASHMAP_VALUE_TYPE* _FN(get)(u64 key)
#define MAP_ADD int _FN(add)(u64 key, HASHMAP_VALUE_TYPE **entry)
#define MAP_DEL int _FN(del)(u64 key)
