#include <replay.h>
#include <util.h>

/* Simplified method to return pointer to next data to consume on replay */
char *__argshead(struct record_thread *prect)
{
  struct argsalloc_node *node;
  node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);
  if (unlikely(list_empty(&prect->rp_argsalloc_list)))
  {
    TPRINT("argshead: pid %d sanity check failed - no anc. data\n", current->pid);
    BUG();
  }
  return node->pos;
}

/* Simplified method to advance pointer on replay */
void __argsconsume(struct record_thread *prect, u_long size)
{
  struct argsalloc_node *node;
  node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);
  if (unlikely(list_empty(&prect->rp_argsalloc_list)))
  {
    TPRINT("argsconsume: pid %d sanity check failed - no anc. data\n", current->pid);
    BUG();
  }
  if (unlikely(node->head + node->size - node->pos < size))
  {
    TPRINT("argsconsume: pid %d sanity check failed - head %p size %lu pos %p size %lu\n", current->pid, node->head, (u_long) node->size, node->pos, size);
    dump_stack();
    BUG();
  }
  TPRINT("in argsconsume: size %lu\n", size);
  node->pos += size;
}

/*
 * Adding support for freeing...
 * The only use case for this is in case of an error (like copying from user)
 * and the allocated memory needs to be freed
 */
void __argsfree(const void *ptr, size_t size)
{
  struct record_thread *prect;
  struct argsalloc_node *ra_node;
  prect = get_record_thread();
  ra_node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);

  if (ptr == NULL)
    return;

  if (ra_node->head == ra_node->pos)
    return;

  // simply rollback allocation (there is the rare case where allocation has
  // created a new slab, but in that case we simply roll back the allocation
  // and keep the slab since calling argsfree itself is rare)
  if ((ra_node->pos - size) >= ra_node->head)
  {
    ra_node->pos -= size;
    return;
  }
  else
  {
    TPRINT("Pid %d argsfree: unhandled case\n", current->pid);
    return;
  }
}

// Free all allocated data values at once
void __argsfreeall(struct record_thread *prect)
{
  struct argsalloc_node *node;
  struct argsalloc_node *next_node;

  list_for_each_entry_safe(node, next_node, &prect->rp_argsalloc_list, list)
  {
    VFREE(node->head);
    list_del(&node->list);
    KFREE(node);
  }
}

struct argsalloc_node *__new_argsalloc_node(void *slab, size_t size)
{
  struct argsalloc_node *new_node;
  new_node = KMALLOC(sizeof(struct argsalloc_node), GFP_KERNEL);
  if (new_node == NULL)
  {
    TPRINT("new_argalloc_node: Cannot allocate struct argsalloc_node\n");
    return NULL;
  }

  new_node->head = slab;
  new_node->pos = slab;
  new_node->size = size;
  //new_node->list should be init'ed in the calling function

  return new_node;
}

/*
 * Adds another slab for args/retparams/signals allocation,
 * if no slab exists, then we create one */
int __add_argsalloc_node(struct record_thread *prect, void *slab, size_t size)
{
  struct argsalloc_node *new_node;
  new_node = __new_argsalloc_node(slab, size);
  if (new_node == NULL)
  {
    TPRINT("Pid %d add_argsalloc_node: could not create new argsalloc_node\n", prect->rp_record_pid);
    return -1;
  }

  // Add to front of the list
  MPRINT("Pid %d add_argsalloc_node: adding an args slab to record_thread\n", prect->rp_record_pid);
  list_add(&new_node->list, &prect->rp_argsalloc_list);
  return 0;
}

void *__argsalloc(size_t size)
{
  struct record_thread *prect = get_record_thread();
  struct argsalloc_node *node;
  size_t asize;
  void *ptr;

  node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);

  // check to see if we've allocated a slab and if we have enough space left in the slab
  if (unlikely(list_empty(&prect->rp_argsalloc_list) || ((node->head + node->size - node->pos) < size)))
  {
    int rc;
    void *slab;

    MPRINT("Pid %d argsalloc: not enough space left in slab, allocating new slab\n", current->pid);

    asize = (size > argsalloc_size) ? size : argsalloc_size;
    slab = VMALLOC(asize);
    if (slab == NULL)
    {
      TPRINT("Pid %d argsalloc: couldn't alloc slab with size %lu\n", current->pid, asize);
      return NULL;
    }
    rc = __add_argsalloc_node(prect, slab, asize);
    if (rc)
    {
      TPRINT("Pid %d argalloc: problem adding argsalloc_node\n", current->pid);
      VFREE(slab);
      return NULL;
    }
    // get the new first node of the linked list
    node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);
    ptr = node->pos;
    node->pos += size;
    return ptr;
  }

  // return pointer and then advance
  ptr = node->pos;
  node->pos += size;

  return ptr;
}

int is_replay_cache_file(struct replay_cache_files *pfiles, int fd, int *cache_fd)
{
  if (fd < 0 || fd >= pfiles->count) return 0;
  *cache_fd = pfiles->data[fd];
  return (pfiles->data[fd] >= 0);
}

int is_record_cache_file_lock(struct record_cache_files *pfiles, int fd)
{
  struct record_cache_chunk *pchunk;
  int rc = 0;

  down_read(&pfiles->sem);
  if (fd < pfiles->count)
  {
    pchunk = pfiles->list;
    while (fd >= pchunk->count)
    {
      fd -= pchunk->count;
      pchunk = pchunk->next;
    }
    if (pchunk->data[fd].is_cache_file)
    {
      mutex_lock(&pchunk->data[fd].mutex);  /* return locked */
      rc = 1;
    }
  }
  up_read(&pfiles->sem);

  return rc;
}

void record_cache_file_unlock(struct record_cache_files *pfiles, int fd)
{
  struct record_cache_chunk *pchunk;

  down_read(&pfiles->sem);
  pchunk = pfiles->list;
  while (fd >= pchunk->count)
  {
    fd -= pchunk->count;
    pchunk = pchunk->next;
  }
  mutex_unlock(&pchunk->data[fd].mutex);
  up_read(&pfiles->sem);
}

/* See if the version within the inode is different than the last one we
 * recorded
 */
long file_cache_check_version(int fd, struct file *filp,
    struct filemap_data *data, struct open_retvals *retvals)
{
  long ret = 0;
  struct record_thread *rec_th = get_record_thread();
  mutex_lock(&data->idata->replay_inode_lock);
  if (rec_th->prev_file_version[fd] == -1)
  {
    rec_th->prev_file_version[fd] = data->idata->version;
  }
  else
  {
    if (rec_th->prev_file_version[fd] < data->idata->version)
    {
      pr_err("%s %d: !!!! Warning - HAVE Out of date file version pid %d fd %d versions %lld %lld !!!!\n",
          __func__, __LINE__, current->pid, fd, rec_th->prev_file_version[fd], data->idata->version);
    }
    rec_th->prev_file_version[fd] = data->idata->version;
  }
  mutex_unlock(&data->idata->replay_inode_lock);
  return ret;
}

long file_cache_update_replay_file(int rc, struct open_retvals *retvals)
{
  int fd;
  struct replay_thread *rep_th = get_replay_thread();
  fd = open_cache_file(retvals->dev, retvals->ino, retvals->mtime, O_RDWR, rep_th->rp_group->cache_dir);

  if (set_replay_cache_file(rep_th->rp_cache_files, rc, fd) < 0)
  {
    real_sys_close(fd);
  }
  return 0;
}

int set_replay_cache_file(struct replay_cache_files *pfiles, int fd, int cache_fd)
{
  int newcount;
  int *tmp;
  int i;

  if (fd >= pfiles->count)
  {
    newcount = pfiles->count;
    while (fd >= newcount) newcount *= 2;
    tmp = KMALLOC(newcount * sizeof(int), GFP_KERNEL);
    if (tmp == NULL)
    {
      TPRINT("set_cache_file: cannot allocate new data buffer of size %d\n", newcount);
      return -ENOMEM;
    }
    for (i = 0; i < pfiles->count; i++) tmp[i] = pfiles->data[i];
    for (i = pfiles->count; i < newcount; i++) tmp[i] = -1;
    KFREE(pfiles->data);
    pfiles->data = tmp;
    pfiles->count = newcount;
  }
  pfiles->data[fd] = cache_fd;
  return 0;
}

int track_usually_pt2pt_read(void *key, int size, struct file *filp)
{
  u_int *is_cached;
  u64 rg_id;
  struct pipe_track *info;
  struct replayfs_filemap map;
  struct record_thread *rec_th = get_record_thread();
  rg_id = rec_th->rp_group->rg_id;

  is_cached = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);
  BUG_ON(is_cached == NULL);
  *is_cached = READ_IS_PIPE;

  /* We have to lock our pipe tree externally */
  mutex_lock(&pipe_tree_mutex);
  info = btree_lookup64(&pipe_tree, (u64)key);
  /* The pipe is not in the tree, this is its first write (by a recorded process) */
  if (info == NULL)
  {
    /* Create a new pipe_track */
    info = kmalloc(sizeof(struct pipe_track), GFP_KERNEL);
    /* Crap... no memory */
    if (info == NULL)
    {
      /* FIXME: fail cleanly */
      BUG();
    }
    /* Now initialize the structure */
    mutex_init(&info->lock);
    info->owner_read_id = rg_id;
    info->owner_write_id = 0;
    info->id = atomic_inc_return(&glbl_pipe_id);
    info->owner_write_pos = 0;
    info->owner_read_pos = size;
    info->key.id1 = file_inode(filp)->i_ino;
    info->key.id2 = file_inode(filp)->i_sb->s_dev;
    info->shared = 0;

    if (btree_insert64(&pipe_tree, (u64)key, info, GFP_KERNEL))
    {
      /* FIXME: fail cleanly */
      BUG();
    }
    mutex_unlock(&pipe_tree_mutex);
    /* The pipe is in the tree, update it */
  }
  else
  {
    /*
     * We lock the pipe before we unlock the tree to ensure that the pipe updates
     * are orded with respect to lookup in the tree
     */
    mutex_lock(&info->lock);
    mutex_unlock(&pipe_tree_mutex);
    /* If the pipe is exclusive, don't keep any data about it */
    if (info->shared == 0)
    {
      /* It hasn't been read yet */
      if (unlikely(info->owner_read_id == 0))
      {
        info->owner_read_id = rg_id;
        BUG_ON(info->owner_read_pos != 0);
        info->owner_read_pos = size;
        /* If it continues to be exclusive */
      }
      else if (likely(info->owner_read_id == rg_id))
      {
        info->owner_read_pos += size;
        /* This is the un-sharing read */
      }
      else
      {
        info->shared = 1;
        /* Okay, we need to allocate a filemap for this file */
        replayfs_filemap_init(&map, replayfs_alloc, filp);
        /* Write a record of the old data, special case of 0 means held linearly in pipe */
        replayfs_filemap_write(&map, info->owner_write_id, 0, info->id, 0, 0, info->owner_write_pos);
        /* Now append a read record indicating the data we have */
        *is_cached |= READ_PIPE_WITH_DATA;
        info->owner_read_pos += size;
      }
    }
    else
    {
      /* Okay, we need to allocate a filemap for this file */
      replayfs_filemap_init(&map, replayfs_alloc, filp);
      *is_cached |= READ_PIPE_WITH_DATA;
      info->owner_read_pos += size;
    }
    mutex_unlock(&info->lock);
  }
  /* If this is a shared pipe, we will mark multiple writers, and save all the writer data */
  if (*is_cached & READ_PIPE_WITH_DATA)
  {
    struct replayfs_filemap_entry *args;
    struct replayfs_filemap_entry *entry;
    int cpy_size;
    /* Append the data */
    entry = replayfs_filemap_read(&map, info->owner_read_pos - size, size);
    if (IS_ERR(entry) || entry == NULL)
    {
      entry = kmalloc(sizeof(struct replayfs_filemap_entry), GFP_KERNEL);
      entry->num_elms = 0;
    }
    cpy_size = sizeof(struct replayfs_filemap_entry) +
      (entry->num_elms * sizeof(struct replayfs_filemap_value));
    args = ARGSKMALLOC(cpy_size, GFP_KERNEL);
    BUG_ON(args == NULL);
    memcpy(args, entry, cpy_size);
    kfree(entry);
    replayfs_filemap_destroy(&map);
    /* Otherwise, we just need to know the source id of this pipe */
  }
  else
  {
    struct pipe_track *info;
    char *buf = ARGSKMALLOC(sizeof(u64) + sizeof(int), GFP_KERNEL);
    u64 *writer = (void *)buf;
    int *id = (int *)(writer + 1);
    mutex_lock(&pipe_tree_mutex);
    info = btree_lookup64(&pipe_tree, (u64)key);
    BUG_ON(info == NULL);
    mutex_lock(&info->lock);
    mutex_unlock(&pipe_tree_mutex);
    *writer = info->owner_write_id;
    *id = info->id;
    mutex_unlock(&info->lock);
  }
  return 0;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)) && !defined(THEIA_MODIFIED_KERNEL_SOURCES)
sock_from_file_ptr sock_from_file = NULL;
EXPORT_SYMBOL(sock_from_file);
#endif
