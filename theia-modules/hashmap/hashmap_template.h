#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/version.h>

//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0))
//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0))
//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0))

// v3.7 added hashtable.h
#include <linux/hashtable.h>
//#include "hashtable.h"

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

#undef _BUNDLE_NAME
#undef _BUNDLE_TYPE
#undef _MAP_NAME
#undef _POOL_NAME
#undef _LOCK_NAME
#undef _FN
#undef HASHMAP
#undef POOL
#undef LOCK

#define _BUNDLE_NAME HASHMAP_NAME_PREFIX ## _hashmap_bundle
#define _BUNDLE_TYPE struct _BUNDLE_NAME
#define _MAP_NAME HASHMAP_NAME_PREFIX ## _hashmap
#define _POOL_NAME HASHMAP_NAME_PREFIX ## _mempool
#define _LOCK_NAME HASHMAP_NAME_PREFIX ## _lock
#define _FN(suffix) HASHMAP_NAME_PREFIX ## _ ## suffix
#define HASHMAP _BUNDLE_NAME._MAP_NAME
#define POOL _BUNDLE_NAME._POOL_NAME
#define LOCK _BUNDLE_NAME._LOCK_NAME

static _BUNDLE_TYPE {
    // v4.5 added DEFINE_READ_MOSTLY_HASHTABLE
    DEFINE_READ_MOSTLY_HASHTABLE(_MAP_NAME, HASHMAP_BITS);
    //DEFINE_HASHTABLE(_MAP_NAME, HASHMAP_BITS);
    struct kmem_cache * _POOL_NAME;
    DEFINE_MUTEX(_LOCK_NAME);
};

static int _FN(init)()
{
    POOL = kmem_cache_create(__stringify(HASHMAP_NAME_PREFIX),
            sizeof(HASHMAP_VALUE_TYPE), 0, 0, NULL);
    if (!POOL)
        return -1;
    return 0;
}

static void _FN(destroy)()
{
    kmem_cache_destroy(POOL);
}

// v3.9 removed the extra node field from hlist iterators
static HASHMAP_VALUE_TYPE* _FN(get)(u64 key)
{
    HASHMAP_VALUE_TYPE *entry = NULL;
    //struct hlist_node *node;

    rcu_read_lock();
    //hash_for_each_possible_rcu(HASHMAP, entry, node, next, key) {
    hash_for_each_possible_rcu(HASHMAP, entry, next, key) {
        if (entry->key == key) {
            rcu_read_unlock();
            return entry;
        }
    }
    rcu_read_unlock();

    return NULL;
}

int _FN(add)(u64 key, HASHMAP_VALUE_TYPE **entry)
{
    HASHMAP_VALUE_TYPE *new = NULL;

    new = _FN(get)(key);
    /* Return if entry already exists */
    if (new)
        return 1;

    new = kmem_cache_alloc(POOL, HASHMAP_ALLOCATOR_FLAGS);
    if (!new)
        return -ENOMEM;
    new->key = key;
    *entry = new;
    mutex_lock(&LOCK);
    hash_add_rcu(HASHMAP, &new->next, key);
    mutex_unlock(&LOCK);
    return 0;
}

int _FN(del)(u64 key)
{
    HASHMAP_VALUE_TYPE *entry = NULL;

    entry = _FN(get)(key);
    /* Return if entry does not exists */
    if (!entry)
        return 1;
    mutex_lock(&LOCK);
    hash_del_rcu(&entry->next);
    mutex_unlock(&LOCK);
    synchronize_rcu();
    kmem_cache_free(entry);
    return 0;
}
