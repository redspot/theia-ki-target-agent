#include "hashmap_common.h"

// v4.5 added DEFINE_READ_MOSTLY_HASHTABLE
static DEFINE_READ_MOSTLY_HASHTABLE(HASHMAP, HASHMAP_BITS);
static struct kmem_cache * POOL;
static DEFINE_MUTEX(LOCK);

MAP_INIT
{
    POOL = kmem_cache_create(__stringify(HASHMAP_NAME_PREFIX),
            sizeof(HASHMAP_VALUE_TYPE), 0, 0, NULL);
    if (!POOL)
        return -1;
    return 0;
}

MAP_DESTROY
{
    kmem_cache_destroy(POOL);
}

//WM define hashmap get
MAP_GET
{
    HASHMAP_VALUE_TYPE *entry = NULL;
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0))
    struct hlist_node *node;
#endif

    rcu_read_lock();
// v3.9 removed the extra node field from hlist iterators
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0))
    hash_for_each_possible_rcu(HASHMAP, entry, next, key) {
#else
    hash_for_each_possible_rcu(HASHMAP, entry, node, next, key) {
#endif
        if (entry->key == key) {
            rcu_read_unlock();
            return entry;
        }
    }
    rcu_read_unlock();

    return NULL;
}

MAP_ADD
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

MAP_DEL
{
    HASHMAP_VALUE_TYPE *entry = NULL;

    entry = _FN(get)(key);
    /* Return if entry does not exist */
    if (!entry)
        return 1;
    mutex_lock(&LOCK);
    hash_del_rcu(&entry->next);
    mutex_unlock(&LOCK);
    synchronize_rcu();
    kmem_cache_free(POOL, entry);
    return 0;
}
