// replay_logdb.c: manages the organization of replay logs on disk
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/syscalls.h>
#include <linux/replay.h>
#include <asm/uaccess.h>

#define LOGID_INCREMENT 4096

// Global variables
DEFINE_MUTEX(replay_id_mutex);
__u64 last_logid = 0;
__u64 max_logid = 0;

#define RID_LOCK mutex_lock(&replay_id_mutex); 
#define RID_UNLOCK mutex_unlock(&replay_id_mutex);

long reset_replay_ndx (void)
{
	last_logid = 0;
	max_logid = 0;
	return 0;
}
EXPORT_SYMBOL(reset_replay_ndx);

// Returns the next logid - may need to get a range allocated first
__u64 
get_replay_id (void)
{
	mm_segment_t old_fs = get_fs();
	__u64 ret_id;
	int fd = -1, rc;
  THEIA_DECLARE_CREDS;

	RID_LOCK;
	set_fs(KERNEL_DS);
  //swap credentials to root for vfs operations
  THEIA_SWAP_CREDS_TO_ROOT;

	if (max_logid <= last_logid) {

		// First, get maximum log id that was saved persitently to disk
		fd = sys_open (LOGDB_INDEX, O_RDWR, 0);
		if (fd >= 0) {
			rc = sys_read (fd, (char *) &max_logid, sizeof(max_logid));
			if (rc != sizeof(max_logid)) {
				pr_err("get_replay_id: cannot get max allocated id, rc=%d\n", rc);
        ret_id = 0;
        goto out;
			}
			last_logid = max_logid;

			rc = sys_lseek (fd, 0, SEEK_SET);
			if (rc < 0) {
				pr_err("get_replay_id: cannot seek back to beginning of file, rc=%d\n", rc);
        ret_id = 0;
        goto out;
			}
				
		} else if (fd == -ENOENT) {
			fd = sys_open (LOGDB_INDEX, O_RDWR | O_CREAT | O_EXCL, 0666);
			if (fd <= 0) {
				pr_err("get_replay_id: cannot create new index file, rc=%d\n", fd);
        ret_id = 0;
        goto out;
			}
		} else {
			pr_err("get_replay_id: cannot open %s,rc=%d\n", LOGDB_INDEX, fd);
      ret_id = 0;
      goto out;
		}

		// Need to allocate some more ids
		max_logid += LOGID_INCREMENT;

		rc = sys_write (fd, (char *) &max_logid, sizeof(max_logid));
		if (rc != sizeof(max_logid)) {
			pr_err("get_replay_id: cannot write max allocated id, rc=%d\n", rc);
      ret_id = 0;
      goto out;
		}
		if (sys_fsync (fd) < 0) pr_err("get_replay_id: cannot sync index file\n");
    sys_close(fd);
    fd = -1;
	}

	ret_id = ++last_logid;

	if (ret_id >= max_logid) {
		fd = sys_open (LOGDB_INDEX, O_RDWR, 0);

		// Need to allocate some more ids
		max_logid += LOGID_INCREMENT;

		rc = sys_write (fd, (char *) &max_logid, sizeof(max_logid));
		if (rc != sizeof(max_logid)) {
			pr_err("get_replay_id: cannot write max allocated id, rc=%d\n", rc);
      ret_id = 0;
      goto out;
		}
		if (sys_fsync (fd) < 0) pr_err("get_replay_id: cannot sync index file\n");
	}

out:
  sys_close(fd);
  THEIA_RESTORE_CREDS;
	set_fs(old_fs);
	RID_UNLOCK;

	return ret_id;
}

void
get_logdir_for_replay_id (__u64 id, char* buf)
{
	sprintf (buf, "%srec_%lld", LOGDB_DIR, id);
}

int
make_logdir_for_replay_id (__u64 id, char* buf)
{
	mm_segment_t old_fs = get_fs();
	int rc;
	int fd;
  THEIA_DECLARE_CREDS;

	if (id == 0) return -1;
	set_fs(KERNEL_DS);

  //swap credentials to root for vfs operations
  THEIA_SWAP_CREDS_TO_ROOT;

	get_logdir_for_replay_id (id, buf);
	rc = sys_mkdir (buf, 0777);
  if (rc == -EEXIST) {
    pr_debug("make_logdir_for_replay_id: directory %s already exists\n", buf);
    goto out;
  }
	if (rc < 0) {
		pr_warn("make_logdir_for_replay_id: cannot create directory %s, rc=%d\n", buf, rc);
		goto out;
	}
	fd = sys_open(buf, O_DIRECTORY, 0777);
	if (rc < 0) {
		pr_warn( "make_logdir_for_replay_id: cannot open directory %s, rc=%d\n", buf, rc);
		goto out;
	}
	rc = sys_fchmod(fd, 0777);
	if (rc < 0) {
		pr_warn("make_logdir_for_replay_id: cannot fchmod directory %s, rc=%d\n", buf, rc);
		goto out;
	}
	rc = sys_close(fd);
	if (rc < 0) {
		pr_warn("make_logdir_for_replay_id: cannot close directory %s, rc=%d\n", buf, rc);
		goto out;
	}

out:
  THEIA_RESTORE_CREDS;
	set_fs(old_fs);
	return rc;
}

