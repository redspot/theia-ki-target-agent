#ifndef __THEIA_CORE_H__
#define __THEIA_CORE_H__

/*
 * These entries are taken from the modifications that omniplay/THEIA
 * originally did to the task_struct.
 *
 * The key entry is just a copy of the actual key that will be used in
 * the theia_tasks_hashmap.
 *
 * next is just part of how linux hashtables work.
 */
struct theia_task {
       u64 key; /* the task that these data refer to */
       struct hlist_node next; /* next entry in the hashmap */
       /* our data goes below here */
       struct replay_thread*        replay_thrd; /* REPLAY */
       struct record_thread*        record_thrd; /* REPLAY */
       __u64 rg_shm_count; /* count shared vma reads */
       __u64 rg_id;
       __u32 no_syscalls; /* THEIA. I think we don't need u64 */
       __u32 is_remote; /* THEIA. I think we don't need u64 */
};

struct theia_filp_map {
       u64 key; /* the task that these data refer to */
       struct hlist_node next; /* next entry in the hashmap */
       /* our data goes below here */
       void *data; //to be filled in later by a struct replayfs_filemap
};
#endif
