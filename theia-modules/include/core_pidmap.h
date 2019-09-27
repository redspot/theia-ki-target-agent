#ifndef __CORE_PIDMAP_H__
#define __CORE_PIDMAP_H__

#include <linux/slab.h>
#include <linux/sched.h>

/*
 * These entries are taken from the modifications that omniplay/THEIA
 * originally did to the task_struct.
 *
 * The key entry is just a copy of the actual key that will be used in
 * the theia_tasks_hashmap.
 *
 * next is just part of how linux hashtables work.
 */
typedef struct {
       u64 key; /* the task that these data refer to */
       struct hlist_node next; /* next entry in the hashmap */
       /* our data goes below here */
       struct replay_thread*        replay_thrd; /* REPLAY */
       struct record_thread*        record_thrd; /* REPLAY */
       __u64 rg_shm_count; /* count shared vma reads */
       __u64 rg_id;
       __u32 no_syscalls; /* THEIA. I think we don't need u64 */
       __u32 is_remote; /* THEIA. I think we don't need u64 */
} theia_task;

#undef HASHMAP_BITS
#undef HASHMAP_NAME_PREFIX
#undef HASHMAP_VALUE_TYPE
#undef HASHMAP_ALLOCATOR_FLAGS

//            8 bits, 256 buckets. vm4 @ idle has ~128 PIDs

#define HASHMAP_BITS 8
#define HASHMAP_NAME_PREFIX theia_pidmap
#define HASHMAP_VALUE_TYPE theia_task
#define HASHMAP_ALLOCATOR_FLAGS GFP_KERNEL
#include <hashmap/hashmap_type.h>

//theia_task map helpers
static inline theia_task* get_theia_task(struct task_struct *task)
{
    return theia_pidmap_get((u64)task);
}
static inline theia_task* get_current_theia_task(void)
{
    return get_theia_task(current);
}
static inline struct record_thread* get_record_thread(void)
{
    //theia_task *data = get_current_theia_task();
    //if (data) return data->record_thrd;
    return current->record_thrd;
}
static inline struct replay_thread* get_replay_thread(void)
{
    //theia_task *data = get_current_theia_task();
    //if (data) return data->replay_thrd;
    return current->replay_thrd;
}

#endif
