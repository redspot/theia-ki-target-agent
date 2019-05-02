#include "parseklib.h"

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <sys/timex.h>
#include <sys/quota.h>
#define __USE_LARGEFILE64
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ustat.h>
#include <time.h>
#include <mqueue.h>

#include <linux/net.h>
#include <linux/utsname.h>
#include <linux/ipc.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/statfs.h>
#include <linux/capability.h>
#include <asm/ldt.h>
#define __USE_LARGEFILE64
#include <fcntl.h>
#include <sys/resource.h>

#include <assert.h>

#define REPLAY_MAX_THREADS 16
#define USE_ARGSALLOC
#define USE_DISK_CKPT

#define DEBUG_PRINT

#ifdef DEBUG_PRINT
#define debugf(...) printf(__VA_ARGS__)
#else
#define debugf(...)
#endif



static __attribute__((const)) char *syscall_name(int nr);
static void default_printfcn(FILE *out, struct klog_result *res) {
	char idx[10];
	char spacing[10];
	int len;
	int i;

	//sprintf(idx, "%lld", res->index);
	sprintf(idx, "%ld", res->index);
	len = strlen(idx);
	for (i = 0; i < 5-len; i++) {
		spacing[i] = ' ';
	}
	spacing[i] = '\0';

	fprintf(out, "%s:%ssyscall %-12s (%3d) flags %2x retval %11ld (%08lx) begin %lu end %lu\n",
			idx, spacing,
			syscall_name(res->psr.sysnum), res->psr.sysnum, res->psr.flags, res->retval, res->retval,
			res->start_clock, res->stop_clock);

	/*
	if (res->retparams_size > 0) {
		fprintf(out, "         %d bytes of return parameters included\n", res->retparams_size);
	}
	*/
}

static void default_signal_printfcn(FILE *out, struct klog_result *res) {
	struct repsignal *sig;
	sig = &res->signal->sig;

	while (sig) {
		fprintf(out, "         !!-- Has signal %d --!!\n", *(int*)sig);
		sig = sig->next;
	}
}

static void free_active_psrs(struct klogfile *log) {
	int i;
	for (i = 0; i < log->active_num_psrs; i++) {
		struct klog_result *apsr = &log->active_psrs[i];
		struct klog_signal *sig = apsr->signal;
		if (apsr->retparams) {
			free(apsr->retparams);
		}

		while (sig) {
			struct klog_signal *n;
			n = sig->next;
			free(sig);
			sig = n;
		}
	}
	free(log->active_psrs);
	log->active_psrs = NULL;
}

static u_long getretparamsize(struct klogfile *log,
		struct klog_result *res) {
	u_long ret = 0;
	struct syscall_result *psr = &res->psr;

	if (res->psr.flags & SR_HAS_RETPARAMS) {
		assert(log->parse_rules[psr->sysnum]);
		if (log->parse_rules[psr->sysnum]->get_retparamsize) {
			ret = log->parse_rules[psr->sysnum]->get_retparamsize(log, res);
		} else {
			ret = log->parse_rules[psr->sysnum]->retparamsize;
		}
		assert(ret >= 0);
	}

	return ret;
}

static int read_psr_chunk(struct klogfile *log) {
	int ret = -1;
	int count;
	u_long data_size;
	int i;
	long rc, bytes_read;
	struct syscall_result *psrs;

	/* Read header */
	/* Start with HPC stuff.... if anyone ever uses that ever again */
#ifdef USE_HPC
	rc = read (log->fd, &hpc1, sizeof(unsigned long long));
	if (rc == 0) { // should have reached the end of the log(s) here
		break;
	}
	rc = read (log->fd, &log->tv1, sizeof(struct timeval));
	rc = read (log->fd, &log->hpc2, sizeof(unsigned long long));
	rc = read (log->fd, &log->tv2, sizeof(struct timeval));
	double usecs1 = (double)tv1.tv_sec * 1000000 + (double)tv1.tv_usec;
	double usecs2 = (double)tv2.tv_sec * 1000000 + (double)tv2.tv_usec;
	/*
	printf ("%Lu ticks = %f usecs\n", hpc1, usecs1);
	printf ("%Lu ticks = %f usecs\n", hpc2, usecs2);
	*/
#endif

	debugf("Reading count\n");
	/* Now get how many records there are here */
	rc = read(log->fd, &count, sizeof(count));
  fprintf(stderr, "the count is %d\n", count); 
#if 0
  fprintf(stderr, "uchar size %lu\n", sizeof(u_char)); 
  fprintf(stderr, "rvalues size %lu\n", sizeof(struct rvalues)); 
  fprintf(stderr, "exec_values size %lu\n", sizeof(struct exec_values)); 
  fprintf(stderr, "timespec size %lu\n", sizeof(struct timespec)); 
  fprintf(stderr, "execve_retvals size %lu\n", sizeof(struct execve_retvals)); 
  fprintf(stderr, "ulong size %lu, int size %lu\n", sizeof(u_long), sizeof(int)); 
  fprintf(stderr, "open_retvals size %lu\n", sizeof(struct open_retvals)); 
  fprintf(stderr, "gettimeofday_retvals size %lu\n", sizeof(struct gettimeofday_retvals)); 
  fprintf(stderr, "pselect6_retvals size %lu\n", sizeof(struct pselect6_retvals)); 
  fprintf(stderr, "generic_socket_retvals size %lu\n", sizeof(struct generic_socket_retvals)); 
  fprintf(stderr, "accept_retvals size %lu\n", sizeof(struct accept_retvals)); 
  fprintf(stderr, "exec_values size %lu\n", sizeof(struct exec_values)); 
  fprintf(stderr, "exec_values size %lu\n", sizeof(struct exec_values)); 
  fprintf(stderr, "socketpair_retvals size %lu\n", sizeof(struct socketpair_retvals)); 
  fprintf(stderr, "recvfrom_retvals size %lu\n", sizeof(struct recvfrom_retvals)); 
  fprintf(stderr, "getxattr_retvals size %lu\n", sizeof(struct getxattr_retvals)); 
  fprintf(stderr, "sendfile64_retvals size %lu\n", sizeof(struct sendfile64_retvals)); 
  fprintf(stderr, "recvmsg_retvals size %lu\n", sizeof(struct recvmsg_retvals)); 
  fprintf(stderr, "getsockopt_retvals size %lu\n", sizeof(struct getsockopt_retvals)); 
  fprintf(stderr, "ipc_retvals size %lu\n", sizeof(struct ipc_retvals)); 
  fprintf(stderr, "sem_retvals size %lu\n", sizeof(struct sem_retvals)); 
  fprintf(stderr, "shmat_retvals size %lu\n", sizeof(struct shmat_retvals)); 
  fprintf(stderr, "mmap_pgoff_retvals size %lu\n", sizeof(struct mmap_pgoff_retvals)); 
  fprintf(stderr, "replayfs_filemap_entry size %lu\n", sizeof(struct replayfs_filemap_entry)); 
  fprintf(stderr, "replayfs_filemap_value size %lu\n", sizeof(struct replayfs_filemap_value)); 
  fprintf(stderr, "struct sigaction size %lu\n", sizeof(struct sigaction)); 
#endif


	if (rc == 0) { // should have reached the end of the log(s) here
		/* We're at the end, return success, we just didn't read anything */
		return 0;
	}

	if (rc != sizeof(count)) {
		//fprintf(stderr, "read returns %ld, expected %d, errno = %d\n", rc, sizeof(count), errno);
		fprintf(stderr, "read returns %ld, expected %lu, errno = %d\n", rc, sizeof(count), errno);
		goto out;
	}

	/* Read the records... eventually */
	psrs = calloc(count, sizeof(struct syscall_result));
	if (!psrs) {
		fprintf(stderr, "Cound not calloc %lu bytes\n", sizeof(struct syscall_result)*count);
		goto out;
	}

	if (log->active_psrs) {
		free_active_psrs(log);
	}

	log->active_psrs = calloc(count, sizeof(struct klog_result));
	if (!log->active_psrs) {
		fprintf(stderr, "Could not calloc %lu bytes\n", sizeof(struct klog_result) * count);
		goto out_free;
	}

	rc = read(log->fd, psrs, sizeof(struct syscall_result) * count);
	if (rc != sizeof(struct syscall_result) * count) {
		fprintf(stderr, "Could not read psrs from log\n");
		goto out_free;
	}

	rc = read(log->fd, &data_size, sizeof(data_size));
  fprintf(stderr, "data_size is %lu\n", data_size);
	if (rc != sizeof(data_size)) {
		fprintf(stderr, "Could not read data_size from log\n");
		goto out_free;
	}

	debugf("Read %d active psrs\n", count);

	for (i = 0; i < count; i++) {

		printf("Copying: sysnum %3d flags %x\n",
				psrs[i].sysnum, psrs[i].flags);

		memcpy(&log->active_psrs[i].psr, &psrs[i], sizeof(struct syscall_result));
	}

	log->active_start_idx += log->active_num_psrs;
	log->active_num_psrs = count;

	/* Now handle each psr */
	for (i = 0; i < count; i++) {
		struct klog_result *apsr = &log->active_psrs[i];
		apsr->retparams = NULL;
	}

	for (i = 0; i < count; i++) {
		struct klog_result *apsr = &log->active_psrs[i];
		apsr->log = log;
		apsr->index = log->active_start_idx + i;

		if (log->printfcns[apsr->psr.sysnum]) {
			apsr->printfcn = log->printfcns[apsr->psr.sysnum];
		} else {
			apsr->printfcn = log->default_printfcn;
		}

		debugf("Parsing psr %d (sys %s,%d) with flags 0x%x\n", i, syscall_name(apsr->psr.sysnum), apsr->psr.sysnum, apsr->psr.flags);

		apsr->start_clock = log->expected_clock;
		if ((apsr->psr.flags & SR_HAS_START_CLOCK_SKIP) != 0) {
			u_long clock;
			rc = read (log->fd, &clock, sizeof(u_long));
			debugf("	Reading startclock skip,%lx, %lx\n",clock,lseek(log->fd, 0, SEEK_CUR));
			if (rc != sizeof(u_long)) {
				fprintf(stderr, "cannot read start clock value\n");
				return rc;
			}

			apsr->start_clock += clock;
		}
		log->expected_clock = apsr->start_clock + 1;

		if((apsr->psr.flags & SR_HAS_RECORD_UUID) != 0) {
			char rec_uuid[THEIA_UUID_LEN+1];
			int cnt = 0;
			char one_char;
			while(cnt < THEIA_UUID_LEN+1) {
				rc = read(log->fd, &one_char, 1);
				rec_uuid[cnt] = one_char;
				if(one_char == '\0')
					break;
				cnt++;
			}
			debugf("	Reading RECORD_UUID %s, lseek pos: %lx\n", rec_uuid, lseek(log->fd, 0, SEEK_CUR));
		}


		if ((apsr->psr.flags & SR_HAS_NONZERO_RETVAL) == 0) {
			apsr->retval = 0;
		} else {
			rc = read(log->fd, &apsr->retval, sizeof(long));
			debugf("	Reading retval,%lx,%lx\n",apsr->retval,lseek(log->fd, 0, SEEK_CUR));
			if (rc != sizeof(long)) {
				fprintf(stderr, "cannot read return value\n");
				return -1;
			}
		}

		apsr->stop_clock = log->expected_clock;
		if ((apsr->psr.flags & SR_HAS_STOP_CLOCK_SKIP) != 0) {
			u_long clock;
			rc = read (log->fd, &clock, sizeof(u_long));
			debugf("	Reading stopclock skip,%lx,%lx\n",clock,lseek(log->fd, 0, SEEK_CUR));
			if (rc != sizeof(u_long)) {
				fprintf(stderr, "cannot read start clock value\n");
				return rc;
			}

			apsr->stop_clock += clock;
		}
		log->expected_clock = apsr->stop_clock + 1;

		debugf("	start_clock %lu stop_clock %lu\n", apsr->start_clock, apsr->stop_clock);

		apsr->retparams_size = getretparamsize(log, apsr);
		assert(apsr->retparams_size >= 0);
		debugf("	Got retparams_size %d\n", apsr->retparams_size);
		if (apsr->retparams_size > 0) {
			long rc;
			apsr->retparams = calloc(1,apsr->retparams_size);
			/* FIXME: should fail nicely... */
			assert(apsr->retparams);

			rc = lseek(log->fd, 0, SEEK_CUR);
			debugf("	Reading retparams (%d) from %lx\n", apsr->retparams_size, rc);
			bytes_read = 0;
			do {
				rc = read(log->fd, apsr->retparams+bytes_read, apsr->retparams_size-bytes_read);
				if (rc != apsr->retparams_size) {
					fprintf(stderr, "could not read apsr->retparams (rc=%ld, size=%d)!\n", rc, apsr->retparams_size);
					if (rc <= 0) {
						apsr->retparams_size = 0;
						klog_print(stderr, apsr);
						
						free_active_psrs(log);
						goto out_free;
					}
				}
				bytes_read += rc;
			} while (bytes_read != apsr->retparams_size);
		}

		if (apsr->psr.flags & SR_HAS_SIGNAL) {
			struct klog_signal *n;
			do {
				n = apsr->signal;
				apsr->signal = calloc(1, sizeof(struct klog_signal));
				memset(apsr->signal, 0x0, sizeof(struct klog_signal));
				/* FIXME: exit cleanly */
				assert(apsr->signal);

				if (n == NULL) {
					apsr->signal->sig.next = NULL;
				} else {
					apsr->signal->sig.next = &n->sig;
				}
				apsr->signal->next = n;

				debugf("	Reading signal\n");
				rc = read(log->fd, &apsr->signal->raw, 192);
				if (rc != 192) {
					fprintf (stderr, "read of signal returns %ld, errno = %d\n", rc, errno);
					goto out_free;
				}
				apsr->signal->sig.signr = *(int *)apsr->signal->raw;
			} while (*(char **)(apsr->signal->raw+184));
		} else {
			apsr->signal = NULL;
		}
	}

	ret = 0;

out_free:
	free(psrs);

out:
	return ret;
}

static void add_default_parse_rule_exceptions(struct klogfile *log);
struct klogfile *parseklog_open(const char *filename) {
	struct klogfile *ret = NULL;

	ret = calloc(1, sizeof(*ret));
	if (ret == NULL) {
		goto out;
	}

	/* Set up the parse rules */
	memset(ret->parse_rules, 0, sizeof(ret->parse_rules));

	add_default_parse_rule_exceptions(ret);

	/* Set up the print functions */
	memset(ret->printfcns, 0, sizeof(ret->printfcns));
	ret->default_printfcn = default_printfcn;
	ret->signal_print = default_signal_printfcn;

	/* Open the file and initialize the fd */
	ret->fd = open(filename, O_RDONLY);
	if (ret->fd < 0) {
		perror("open: ");
		goto out_free;
	}

	ret->active_psrs = NULL;

	ret->active_start_idx = 0;
	ret->active_num_psrs = 0;

	ret->num_psrs = 0;
	ret->cur_idx = 0;

	ret->expected_clock = 0;

out:
	return ret;

out_free:
	free(ret);
	ret = NULL;
	goto out;
}


void parseklog_close(struct klogfile *log) {
	close(log->fd);
	free(log);
}

struct klog_result *parseklog_get_next_psr(struct klogfile *log) {
	struct klog_result *ret = NULL;
	loff_t prev_idx;

	prev_idx = log->active_start_idx;

	if (log->cur_idx == log->active_num_psrs) {
		debugf("Reading psr chunk\n");
		if (read_psr_chunk(log)) {
			fprintf(stderr, "Error populating psrs, aborting\n");
			return NULL;
		}
		if (prev_idx != log->active_start_idx) {
			log->cur_idx = 0;
		}
	}

	if (log->cur_idx != log->active_num_psrs) {
		ret = &log->active_psrs[log->cur_idx];
		log->cur_idx++;
	}

	return ret;
}

struct klog_result *parseklog_get_psr(struct klogfile *log, loff_t idx) {
	assert(0 && "Unimplemented");
	return NULL;
}

int parseklog_read_next_chunk(struct klogfile *log) {
	return read_psr_chunk(log);
}

int parseklog_cur_chunk_size(struct klogfile *log) {
	return log->active_num_psrs;
}

int parseklog_do_write_chunk(int count, struct klog_result *psrs, int destfd) {
	int i;
	int rc;
	u_long data_size;
	/* Write the count */
	rc = write(destfd, &count, sizeof(int));
	if (rc != sizeof(int)) {
		fprintf(stderr, "Couldn't record count\n");
		return -1;
	}

	data_size = 0;
	/* Write the psrs */
	/* Calculate the data size... */
	for (i = 0; i < count; i++) {
		struct syscall_result *apsr = &psrs[i].psr;
		rc = write(destfd, apsr, sizeof(struct syscall_result));
		if (rc != sizeof(struct syscall_result)) {
			fprintf(stderr, "Couldn't syscall_result\n");
			return -1;
		}

		if (apsr->flags & SR_HAS_START_CLOCK_SKIP) {
			data_size += sizeof(u_long);
		}
		if (apsr->flags & SR_HAS_NONZERO_RETVAL) {
			data_size += sizeof(long);
		}
		if (apsr->flags & SR_HAS_STOP_CLOCK_SKIP) {
			data_size += sizeof(u_long);
		}
		if (apsr->flags & SR_HAS_SIGNAL) {
			struct klog_signal *n = psrs[i].signal;
			do {
				data_size += 192;
			} while (n->next);
		}

		data_size += psrs[i].retparams_size;
	}

	rc = write(destfd, &data_size, sizeof(data_size));
	if (rc != sizeof(data_size)) {
		fprintf(stderr, "Couldn't record data_size\n");
		return -1;
	}

	/* For each psr */
	for (i = 0; i < count; i++) {
		u_long prev_start_clock;
		u_long prev_stop_clock;
		struct syscall_result *apsr = &psrs[i].psr;
		struct klog_result *res = &psrs[i];

		/* If (has clock) write clock */
		if (apsr->flags & SR_HAS_START_CLOCK_SKIP) {
			/* The 2 is magic... */
			u_long record_clock = res->start_clock-prev_start_clock-2;
			rc = write(destfd, &record_clock, sizeof(u_long));
			if (rc != sizeof(u_long)) {
				fprintf(stderr, "Couldn't record start_clock\n");
				return -1;
			}
		}
		/* If (has retval) write retval */
		if (apsr->flags & SR_HAS_NONZERO_RETVAL) {
			rc = write(destfd, &res->retval, sizeof(long));
			if (rc != sizeof(long)) {
				fprintf(stderr, "Couldn't record retval\n");
				return -1;
			}
		}
		if (apsr->flags & SR_HAS_STOP_CLOCK_SKIP) {
			/* The 2 is magic... */
			u_long record_clock = res->stop_clock-prev_stop_clock-2;
			rc = write(destfd, &record_clock, sizeof(u_long));
			if (rc != sizeof(u_long)) {
				fprintf(stderr, "Couldn't record start_clock\n");
				return -1;
			}
		}
		/* If (has retparams) write retparams */
		if (res->retparams_size) {
			rc = write(destfd, res->retparams, res->retparams_size);
			if (rc != res->retparams_size) {
				fprintf(stderr, "Couldn't record retparams_size\n");
				return -1;
			}
		}

		if (apsr->flags & SR_HAS_SIGNAL) {
			struct klog_signal *n = res->signal;
			do {
				write(destfd, n->raw, 192);
			if (rc != sizeof(long)) {
				fprintf(stderr, "Couldn't record raw signal\n");
				return -1;
			}
			} while (n->next);
		}

		prev_stop_clock = res->stop_clock;
		prev_start_clock = res->start_clock;
	}

	return 0;
}

int parseklog_write_chunk(struct klogfile *log, int destfd) {
	long rc;

	/* Write the header */
#ifdef USE_HPC
	rc = write(destfd, &log->hpc1, sizeof(unsigned long long));
	if (rc != sizeof(unsigned long long)) {
		fprintf(stderr, "Couldn't record hpc1\n");
		return -1;
	}
	rc = write(destfd, &log->tv1, sizeof(struct timeval));
	if (rc != sizeof(struct timeval)) {
		fprintf(stderr, "Couldn't record tv1\n");
		return -1;
	}
	rc = write(destfd, &log->hpc2, sizeof(unsigned long long));
	if (rc != sizeof(unsigned long long)) {
		fprintf(stderr, "Couldn't record hpc2\n");
		return -1;
	}
	rc = write(destfd, &log->tv2, sizeof(struct timeval));
	if (rc != sizeof(struct timeval)) {
		fprintf(stderr, "Couldn't record tv2\n");
		return -1;
	}
#endif

	rc = parseklog_do_write_chunk(log->active_num_psrs, log->active_psrs, destfd);

	return rc;
}

void parseklog_set_signalprint(struct klogfile *log,
		void (*printfcn)(FILE *, struct klog_result *)) {
	log->signal_print = printfcn;
}

void parseklog_set_default_printfcn(struct klogfile *log,
		void (*printfcn)(FILE *, struct klog_result *)) {
	log->default_printfcn = printfcn;
}

void parseklog_set_printfcn(struct klogfile *log,
		void (*printfcn)(FILE *, struct klog_result *), int sysnum) {
	log->printfcns[sysnum] = printfcn;
}

int klog_print(FILE *out, struct klog_result *result) {
	result->printfcn(out, result);
	if (result->signal && result->log->signal_print) {
		result->log->signal_print(out, result);
	}
	return 0;
}

static u_long varsize(struct klogfile *klog, struct klog_result *res) {
	u_long val;
	long orig_pos;

	orig_pos = lseek(klog->fd, 0, SEEK_CUR);

	if (read (klog->fd, &val, sizeof(u_long)) != sizeof(u_long)) {
		fprintf (stderr, "cannot read variable length field\n");
		return -1;
	}
	debugf("\t4 bytes of variable length field header included\n");
	/*
	if (stats) {
		bytes[psr->sysnum] += sizeof(u_long);
	}
	*/
	debugf("\t%lu variable bytes\n", val);
	lseek(klog->fd, orig_pos, SEEK_SET);
	return val + sizeof(u_long);
}

static u_long getretparams_retval(struct klogfile *klog,
		struct klog_result *res) {
	return res->retval;
}

/* Exceptions */
/*{{{*/
static u_long getretparams_read(struct klogfile *log,
		struct klog_result *res) {
	long rc;
	u_long size = 0;
	int extra_bytes = 0;
	long return_pos;
	u_int is_cache_read;

	return_pos = lseek(log->fd, 0, SEEK_CUR);

	rc = read(log->fd, &is_cache_read, sizeof(u_int));
	if (rc != sizeof(u_int)) {
		fprintf (stderr, "cannot read is_cache value\n");
		return -1;
	}
	size += sizeof(u_int);

	debugf("\tis_cache_file: %d\n", is_cache_read);
	if (is_cache_read & CACHE_MASK) {
		size += sizeof(loff_t);

#ifdef TRACE_READ_WRITE
		do {
			off_t orig_pos;
			struct replayfs_filemap_entry entry;
			loff_t bleh;

			orig_pos = lseek(log->fd, 0, SEEK_CUR);
			rc = read(log->fd, &bleh, sizeof(loff_t));
			rc = read(log->fd, &entry, sizeof(struct replayfs_filemap_entry));
			lseek(log->fd, orig_pos, SEEK_SET);

//fprintf(stderr, "111111\n");
			if (rc != sizeof(struct replayfs_filemap_entry)) {
				fprintf(stderr, "cannot read entry\n");
				return -1;
			}

			extra_bytes += sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
			size += sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
		} while (0);
#endif
#ifdef TRACE_PIPE_READ_WRITE
	} else if (is_cache_read & IS_PIPE) {
		if (is_cache_read & IS_PIPE_WITH_DATA) {
			off_t orig_pos;
			struct replayfs_filemap_entry entry;

fprintf(stderr, "111112\n");
			orig_pos = lseek(log->fd, 0, SEEK_CUR);
			rc = read(log->fd, &entry, sizeof(struct replayfs_filemap_entry));
			lseek(log->fd, orig_pos, SEEK_SET);

			if (rc != sizeof(struct replayfs_filemap_entry)) {
				fprintf(stderr, "cannot read entry\n");
				return -1;
			}

			size += sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
		} else {
			size += sizeof(uint64_t) + sizeof(int);
		}

		size += res->retval;
#endif
	} else {
		size += res->retval; 
	}

	lseek(log->fd, return_pos, SEEK_SET);

	return size;
}

static u_long getretparams_write(struct klogfile *klog,
		struct klog_result *res) {
#ifdef TRACE_PIPE_READ_WRITE
	return 4;
#else
	return 0;
#endif
}

static u_long getretparams_getgroups(struct klogfile *klog,
		struct klog_result *res) {
	return sizeof(uint32_t) * res->retval;
}

#if 0
static u_long getretparams_getgroups32(struct klogfile *klog,
		struct klog_result *res) {
	return sizeof(gid_t) * res->retval;
}
#endif

static u_long getretparams_io_getevents(struct klogfile *klog,
		struct klog_result *res) {
	return res->retval * 32;
}

static u_long getretparams_epoll_wait(struct klogfile *klog,
		struct klog_result *res) {
	return res->retval * sizeof(struct epoll_event);
}

static u_long getretparams_socketcall(struct klogfile *log,
		struct klog_result *res) {
	int call;
	long rc;
	u_long size = 0;
	long return_pos;

	
	return_pos = lseek(log->fd, 0, SEEK_CUR);

	rc = read(log->fd, &call, sizeof(int));
	if (rc != sizeof(int)) {
		fprintf(stderr, "cannot read call value\n");
		return -1;
	}
	size += sizeof(int);

	debugf("\tsocketcall %d\n", call);

	// socketcall retvals specific
	switch (call) {
#ifdef TRACE_SOCKET_READ_WRITE
		case SYS_SEND:
		case SYS_SENDTO:
			{
				if (res->retval >= 0) {
					u_int shared;

					shared = 0;
					rc = read(log->fd, &shared, sizeof(u_int));
					if (rc != sizeof(shared)) {
						fprintf(stderr, "%d: read %ld\n", __LINE__, rc);
						return -1;
					}
					size += sizeof(u_int);

					debugf("\tRead shared variable of %d\n", shared);

					if (shared & IS_PIPE_WITH_DATA) {
					} else if (shared & IS_PIPE) {
						int pipe_id;

						rc = read(log->fd, &pipe_id, sizeof(int));
						if (rc != sizeof(int)) {
							fprintf(stderr, "%d: read: %ld\n", __LINE__, rc);
							return -1;
						}
						size += sizeof(int);

						/*
						if (!pipe_write_only) {
							printf("\tWrite is part of pipe: %d\n", pipe_id);
						} else {
							always_print("%d, %ld, %lu, %d\n", pipe_id, retval,
									start_clock, ndx);
						}
						*/
					}
				}
				break;
			}
#endif
		case SYS_ACCEPT: 
		case SYS_GETSOCKNAME:
		case SYS_GETPEERNAME: {
			struct accept_retvals avr;
			rc = read(log->fd, ((char *) &avr) + sizeof(int), 
					 sizeof(struct accept_retvals) - sizeof(int));
			if (rc != sizeof(struct accept_retvals) - sizeof(int)) {
				fprintf(stderr, "cannot read accept value\n");
				return -1;
			}
			size += sizeof(struct accept_retvals) - sizeof(int);

			size += avr.addrlen; 
			break;
		}

		case SYS_RECV:
			size += sizeof(struct recvfrom_retvals) - sizeof(int) + res->retval;
#ifdef TRACE_SOCKET_READ_WRITE
			if (res->retval >= 0) {
				u_int is_cached;
				off_t orig_pos;
				orig_pos = lseek(log->fd, 0, SEEK_CUR);
				rc = lseek(log->fd,
						sizeof(struct recvfrom_retvals) - sizeof(int) + res->retval, SEEK_CUR);
				if (rc == (off_t)-1) {
					fprintf(stderr, "%d: lseek: %ld\n", __LINE__, rc);
					return -1;
				}
				rc = read(log->fd, &is_cached, sizeof(u_int));
				if (rc != sizeof(is_cached)) {
					fprintf(stderr, "%d: Couldn't read is_cached\n", __LINE__);
					return -1;
				}

				debugf("\tSocket is_cached is %d\n", is_cached);

				if (is_cached & IS_PIPE_WITH_DATA) {
					off_t orig_pos2;
					int entry_size;
					struct replayfs_filemap_entry entry;
					struct replayfs_filemap_entry *real_entry;

					orig_pos2 = lseek(log->fd, 0, SEEK_CUR);
					rc = read(log->fd, &entry, sizeof(struct replayfs_filemap_entry));

					if (rc != sizeof(struct replayfs_filemap_entry)) {
						fprintf(stderr, "cannot read entry\n");
						return -1;
					}
					lseek(log->fd, orig_pos2, SEEK_SET);

					entry_size = sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
					size += entry_size;
					real_entry = calloc(1, entry_size);
					if (real_entry == NULL) {
						fprintf(stderr, "Cannot alloc real_entry\n");
						return -1;
					}

					rc = read(log->fd, real_entry, entry_size);
				} else if (is_cached & IS_PIPE) {
					/* Just a simple one-to-one data entry */
					uint64_t writer;
					int pipe_id;
					rc = read(log->fd, &writer, sizeof(uint64_t));
					if (rc != sizeof(writer)) {
						fprintf(stderr, "%d: read: %ld\n", __LINE__, rc);
						return -1;
					}
					rc = read(log->fd, &pipe_id, sizeof(int));
					if (rc != sizeof(pipe_id)) {
						fprintf(stderr, "%d: read: %ld\n", __LINE__, rc);
						return -1;
					}

					size += sizeof(is_cached) + sizeof(writer) + sizeof(pipe_id);
				} else {
					size += sizeof(is_cached);
				}

				lseek(log->fd, orig_pos, SEEK_SET);
			}
#endif
			break;

		case SYS_RECVFROM:
			size += sizeof(struct recvfrom_retvals) - sizeof(int) + res->retval-1; 
#ifdef TRACE_SOCKET_READ_WRITE
			if (res->retval >= 0) {
				u_int is_cached;
				off_t orig_pos;
				orig_pos = lseek(log->fd, 0, SEEK_CUR);
				rc = lseek(log->fd,
						sizeof(struct recvfrom_retvals)-sizeof(int)+res->retval-1, SEEK_CUR);
				if (rc == (off_t)-1) {
					fprintf(stderr, "%d: lseek: %ld\n", __LINE__, rc);
					return -1;
				}
				rc = read(log->fd, &is_cached, sizeof(u_int));
				if (rc != sizeof(is_cached)) {
					fprintf(stderr, "%d: Couldn't read is_cached\n", __LINE__);
					return -1;
				}

				debugf("\tSocket is_cached is %d\n", is_cached);

				if (is_cached & IS_PIPE_WITH_DATA) {
					off_t orig_pos2;
					int entry_size;
					struct replayfs_filemap_entry entry;
					struct replayfs_filemap_entry *real_entry;

					orig_pos2 = lseek(log->fd, 0, SEEK_CUR);
					rc = read(log->fd, &entry, sizeof(struct replayfs_filemap_entry));

					if (rc != sizeof(struct replayfs_filemap_entry)) {
						fprintf(stderr, "cannot read entry\n");
						return -1;
					}
					lseek(log->fd, orig_pos2, SEEK_SET);

					entry_size = sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
					size += entry_size;
					real_entry = calloc(1,entry_size);
					if (real_entry == NULL) {
						fprintf(stderr, "Cannot alloc real_entry\n");
						return -1;
					}

					rc = read(log->fd, real_entry, entry_size);
				} else if (is_cached & IS_PIPE) {
					/* Just a simple one-to-one data entry */
					uint64_t writer;
					int pipe_id;
					rc = read(log->fd, &writer, sizeof(uint64_t));
					if (rc != sizeof(writer)) {
						fprintf(stderr, "%d: read: %ld\n", __LINE__, rc);
						return -1;
					}
					rc = read(log->fd, &pipe_id, sizeof(int));
					if (rc != sizeof(pipe_id)) {
						fprintf(stderr, "%d: read: %ld\n", __LINE__, rc);
						return -1;
					}

					size += sizeof(is_cached) + sizeof(writer) + sizeof(pipe_id);
				} else {
					size += sizeof(is_cached);
				}

				lseek(log->fd, orig_pos, SEEK_SET);
			}
#endif
			break;

		case SYS_RECVMSG: {
			struct recvmsg_retvals msg;
			rc = read(log->fd, ((char *)&msg) + sizeof(int), sizeof(struct recvmsg_retvals) - sizeof(int));
			if (rc != sizeof(struct recvmsg_retvals) - sizeof(int)) {
				fprintf(stderr, "cannot read recvfrom values\n");
				return -1;
			}
			size += sizeof(struct recvmsg_retvals) - sizeof(int);
			debugf("\trecvmsg: msgnamelen %d msg_controllen %ld msg_flags %x\n", msg.msg_namelen, msg.msg_controllen, msg.msg_flags);
			/*
			if (stats) {
				bytes[psr.sysnum] += sizeof(struct recvfrom_retvals) - sizeof(int);
			}
			*/
			size += msg.msg_namelen + msg.msg_controllen + res->retval; 
			break;
		}

		case SYS_RECVMMSG: {
			if (res->retval > 0) {
				long len;
				rc = read(log->fd, ((char *)&len), sizeof(long));
				if (rc != sizeof(long)) {
					fprintf(stderr, "cannot read recvmmsg value\n");
					return -1;
				}
				size += sizeof(long);
				size += len;
			} else {
				size += 0;
			}
			break;
		}

		case SYS_SOCKETPAIR:
			size += sizeof(struct socketpair_retvals) - sizeof(int);
			break;
		case SYS_GETSOCKOPT: {
			struct getsockopt_retvals sor;
			rc = read (log->fd, ((char *) &sor) + sizeof(int),
					sizeof(struct getsockopt_retvals) - sizeof(int));
			if (rc != sizeof(struct getsockopt_retvals)-sizeof(int)) {
				fprintf(stderr, "cannot read getsockopt value\n");
				return -1;
			}
			size += sizeof(struct getsockopt_retvals) - sizeof(int);
			/*
			if (stats) {
				bytes[psr.sysnum] += sizeof(struct getsockopt_retvals) - sizeof(int);
			}
			*/

			size += sor.optlen;
			break;
		}
		default:
			size += 0; 
	}

	lseek(log->fd, return_pos, SEEK_SET);

	return size;
}

static u_long getretparams_pread64 (struct klogfile *log, struct klog_result *res) 
{
	long rc;
	u_long size = 0;
	int extra_bytes = 0;
	long return_pos;
	u_int is_cache_read;

	return_pos = lseek(log->fd, 0, SEEK_CUR);

	rc = read(log->fd, &is_cache_read, sizeof(u_int));
	if (rc != sizeof(u_int)) {
		fprintf (stderr, "cannot read is_cache value\n");
		return -1;
	}
	size += sizeof(u_int);

	debugf("\tis_cache_file: %d\n", is_cache_read);
	if (is_cache_read & CACHE_MASK) {
		size += sizeof(loff_t);

#ifdef TRACE_READ_WRITE
		do {
			off_t orig_pos;
			struct replayfs_filemap_entry entry;
			loff_t bleh;

			orig_pos = lseek(log->fd, 0, SEEK_CUR);
			rc = read(log->fd, &bleh, sizeof(loff_t));
			rc = read(log->fd, &entry, sizeof(struct replayfs_filemap_entry));
			lseek(log->fd, orig_pos, SEEK_SET);

			if (rc != sizeof(struct replayfs_filemap_entry)) {
				fprintf(stderr, "cannot read entry\n");
				return -1;
			}

			extra_bytes += sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
			size += sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
		} while (0);
#endif
	} else {
		size += res->retval; 
	}

	lseek(log->fd, return_pos, SEEK_SET);

	return size;
}


/*}}}*/

/* Rules for klog parsing */
/*{{{*/
#define _DEFRULE(sysnr, default, fcn) \
	static struct parse_rules exception_##sysnr = { \
		.get_retparamsize = (fcn), \
		.retparamsize = (default) \
	}

#define DEFRULE(sysnr, size) _DEFRULE(sysnr, size, NULL)
#define DEFRULE_FCN(sysnr, fcn) _DEFRULE(sysnr, 0, fcn)

#define ADDRULE(sysnr, log) log->parse_rules[sysnr]=&exception_##sysnr
DEFRULE_FCN(0, getretparams_read); //read
DEFRULE_FCN(1, getretparams_write);//write
DEFRULE(2, sizeof(struct open_retvals));//open
DEFRULE(529, sizeof(int));//waitpid
//DEFRULE(59, sizeof(struct execve_retvals));//execve
DEFRULE(59, 864);//execve
DEFRULE(201, sizeof(time_t));//time
//DEFRULE(18, sizeof(struct __old_kernel_stat));//oldstat
//DEFRULE(28, sizeof(struct __old_kernel_stat));//oldfstat
DEFRULE(22, 2*sizeof(int));//pipe
DEFRULE(100, sizeof(struct tms));//times
DEFRULE_FCN(16, varsize);//ioctl
DEFRULE_FCN(72, varsize);//fcntl
//DEFRULE(59, sizeof(struct oldold_utsname));//oldoldunmae
DEFRULE(136, sizeof(struct sigaction));//ustat
//DEFRULE(13, sizeof(struct sigaction));//sigaction
//DEFRULE(127, sizeof(sigset_t));//sigpending
DEFRULE(97, sizeof(struct rlimit));//getrlimit
DEFRULE(98, sizeof(struct rusage));//getrusage
DEFRULE(96, sizeof(struct gettimeofday_retvals));//gettimeofday
DEFRULE_FCN(115, getretparams_getgroups);//getgroups
//DEFRULE(84, sizeof(struct __old_kernel_stat));//oldlstat
DEFRULE_FCN(89, getretparams_retval);//readlink
DEFRULE(134, sizeof(struct mmap_pgoff_retvals));//uselib
//DEFRULE(89, 266); /* sizeof old_linux_dirent??? */ //readdir
DEFRULE(137, sizeof(struct statfs));//statfs
DEFRULE(138, sizeof(struct statfs));//fstatfs
//DEFRULE_FCN(102, getretparams_socketcall);//socketcall
DEFRULE_FCN(41, getretparams_socketcall);//socket
DEFRULE_FCN(42, getretparams_socketcall);//connect
DEFRULE_FCN(43, getretparams_socketcall);//accept
DEFRULE_FCN(44, getretparams_socketcall);//sendto
DEFRULE_FCN(45, getretparams_socketcall);//recvfrom
DEFRULE_FCN(46, getretparams_socketcall);//sendmsg
DEFRULE_FCN(47, getretparams_socketcall);//recvmsg
DEFRULE_FCN(49, getretparams_socketcall);//bind
DEFRULE_FCN(51, getretparams_socketcall);//getsockname
DEFRULE_FCN(52, getretparams_socketcall);//getpeername
DEFRULE_FCN(53, getretparams_socketcall);//socketpair
DEFRULE_FCN(54, getretparams_socketcall);//setsockopt
DEFRULE_FCN(55, getretparams_socketcall);//getsockopt

DEFRULE_FCN(103, getretparams_retval);//syslog
DEFRULE(38, sizeof(struct itimerval));//setitimer
DEFRULE(36, sizeof(struct itimerval));//getitimer
DEFRULE(4, sizeof(struct stat));//stat
DEFRULE(6, sizeof(struct stat));//lstat
DEFRULE(5, sizeof(struct stat));//fstat
//DEFRULE(109, sizeof(struct old_utsname));//olduname
DEFRULE(61, sizeof(struct wait4_retvals));//wait4
DEFRULE(99, sizeof(struct sysinfo));//sysinfo
//DEFRULE_FCN(117, varsize);//ipc
DEFRULE(63, sizeof(struct old_utsname));//uname
DEFRULE(159, sizeof(struct timex));//adjtimex
//DEFRULE(14, sizeof(unsigned long)); // old_sigset_t - def in asm/signal.h but cannot include //sigprocmask
DEFRULE_FCN(179, varsize);//quotactl
//DEFRULE(134, sizeof(long));//bdflush
DEFRULE_FCN(139, varsize);//sysfs
//DEFRULE(140, sizeof(loff_t));//_llseek
DEFRULE_FCN(78, getretparams_retval);//getdents
DEFRULE_FCN(23, varsize);//select
DEFRULE_FCN(19, getretparams_retval);//readv
DEFRULE_FCN(156, varsize);//_sysctl
DEFRULE(143, sizeof(struct sched_param));//sched_getparam
DEFRULE(148, sizeof(struct timespec));//sched_rr_get_interval
DEFRULE(35, sizeof(struct timespec));//nanosleep
DEFRULE(118, sizeof(uint32_t)*3);//getresuid
DEFRULE_FCN(7, varsize);//poll
DEFRULE(120, sizeof(uint32_t)*3);//getresgid
DEFRULE_FCN(157, varsize);//prctl
DEFRULE(13, 32); /* sizeof(struct sigaction)*///rt_sigaction

DEFRULE_FCN(14, varsize);//rt_sigprocmask
DEFRULE_FCN(127, varsize);//rt_sigpending
DEFRULE(128, sizeof(siginfo_t));//rt_sigtimedwait
DEFRULE_FCN(17, getretparams_pread64);//pread64
DEFRULE_FCN(79, getretparams_retval);//getcwd
DEFRULE_FCN(125, varsize);//capget
DEFRULE(126, sizeof(struct __user_cap_header_struct));//capset
DEFRULE(40, sizeof(off_t));//sendfile
//DEFRULE(191, sizeof(struct rlimit));//ugetrlimit
DEFRULE(9, sizeof(struct mmap_pgoff_retvals));//mmap
//DEFRULE(195, sizeof(struct stat64));//stat64
//DEFRULE(196, sizeof(struct stat64));//lstat64
//DEFRULE(197, sizeof(struct stat64));//fstat64
//DEFRULE_FCN(205, getretparams_getgroups32);//getgroups32
//DEFRULE(209, sizeof(uid_t)*3);//getresuid32
//DEFRULE(211, sizeof(gid_t)*3);//getresgid32
DEFRULE_FCN(27, varsize);//mincore
DEFRULE_FCN(217, getretparams_retval);//getdents64
//DEFRULE_FCN(221, varsize);//fcntl64
DEFRULE_FCN(191, getretparams_retval);//getxattr
DEFRULE_FCN(192, getretparams_retval);//lgetxattr
DEFRULE_FCN(193, getretparams_retval);//fgetxattr
DEFRULE_FCN(194, getretparams_retval);//listxattr
DEFRULE_FCN(195, getretparams_retval);//llistxattr
DEFRULE_FCN(196, getretparams_retval);//flistxattr
//DEFRULE(239, sizeof(struct sendfile64_retvals));//sendfile64
DEFRULE_FCN(204, varsize);//sched_getaffinity
DEFRULE(206, sizeof(u_long));//io_setup
DEFRULE_FCN(208, getretparams_io_getevents);//io_getevents
DEFRULE(210, 32);/* struct ioevent *///io_cancel
DEFRULE_FCN(212, getretparams_retval);//lookup_dcookie
DEFRULE_FCN(232, getretparams_epoll_wait);//epoll_wait
DEFRULE(222, sizeof(timer_t));//timer_create
DEFRULE(223, sizeof(struct itimerspec));//timer_settime
DEFRULE(224, sizeof(struct itimerspec));//timer_gettime
DEFRULE(228, sizeof(struct timespec));//clock_gettime
DEFRULE(229, sizeof(struct timespec));//clock_getres
DEFRULE(230, sizeof(struct timespec));//clock_nanosleep
DEFRULE(268, 84); /* statfs 64 *///statfs64
DEFRULE(269, 84); /* statfs 64 *///fstatfs64
DEFRULE_FCN(239, varsize);//get_mempolicy
DEFRULE_FCN(243, getretparams_retval);//mq_timedreceive
DEFRULE(245, sizeof(struct mq_attr));//mq_getsetattr
DEFRULE(247, sizeof(struct waitid_retvals));//waitid
DEFRULE_FCN(250, varsize);//keyctl
DEFRULE(262, sizeof(struct stat));//fstatat64
DEFRULE_FCN(267, getretparams_retval);//readlinkat
DEFRULE(270, sizeof(struct pselect6_retvals));//pselect6
DEFRULE_FCN(271, varsize);//ppoll
DEFRULE(274, sizeof(struct get_robust_list_retvals));//get_robust_list
DEFRULE(275, sizeof(struct splice_retvals));//splice
DEFRULE_FCN(279, varsize);//move_pages
DEFRULE(309, sizeof(unsigned)*2);//getcpu
DEFRULE_FCN(281, getretparams_epoll_wait);//epoll_pwait
DEFRULE(286, sizeof(struct itimerspec));//timerfd_settime
DEFRULE(287, sizeof(struct itimerspec));//timerfd_gettime
DEFRULE(293, 2*sizeof(int));//pipe2
DEFRULE_FCN(295, getretparams_retval);//preadv
DEFRULE_FCN(299, varsize);//recvmmsg
DEFRULE(302, sizeof(struct rlimit64));//prlimit64
DEFRULE(303, sizeof(struct name_to_handle_at_retvals));//name_to_handle_at
DEFRULE(305, sizeof(struct timex));//clock_adjtime
/*}}}*/

/* Adding rules to the excepiton list */
/*{{{*/
static void add_default_parse_rule_exceptions(struct klogfile *log) {

	ADDRULE(0,  log); 
	ADDRULE(1,  log); 
	ADDRULE(2,  log); 
	ADDRULE(529,log); 
	ADDRULE(59, log);
	ADDRULE(201,log); 
	ADDRULE(22, log);
	ADDRULE(23, log);
	ADDRULE(100,log); 
	ADDRULE(16, log);
	ADDRULE(72, log);
	ADDRULE(136,log); 
	ADDRULE(97, log);
	ADDRULE(98, log);
	ADDRULE(96, log);
	ADDRULE(115,log); 
	ADDRULE(89, log);
	ADDRULE(134,log); 
	ADDRULE(137,log); 
	ADDRULE(138,log); 
	ADDRULE(103,log); 
	ADDRULE(38, log);
	ADDRULE(36, log);
	ADDRULE(4,  log);
	ADDRULE(6,  log);
	ADDRULE(5,  log);
	ADDRULE(61, log);
	ADDRULE(99, log);
	ADDRULE(63, log);
	ADDRULE(159,log);
	ADDRULE(14, log);
	ADDRULE(179,log); 
	ADDRULE(139,log); 
	ADDRULE(78, log);
	ADDRULE(19, log);
	ADDRULE(156, log); 
	ADDRULE(143, log); 
	ADDRULE(148, log); 
	ADDRULE(35,  log);
	ADDRULE(118, log); 
	ADDRULE(7,  log);
	ADDRULE(120, log); 
	ADDRULE(157, log); 
	ADDRULE(13,  log);
	ADDRULE(14,  log);
	ADDRULE(127, log);
	ADDRULE(128, log);
	ADDRULE(17,  log);
	ADDRULE(79,  log);
	ADDRULE(125, log);
	ADDRULE(126, log);
	ADDRULE(40,  log);
	ADDRULE(9,   log);
	ADDRULE(27,  log);
	ADDRULE(217, log);
	ADDRULE(191, log);
	ADDRULE(192, log);
	ADDRULE(193, log);
	ADDRULE(194, log);
	ADDRULE(195, log);
	ADDRULE(196, log);
	ADDRULE(204, log);
	ADDRULE(206, log);
	ADDRULE(208, log);
	ADDRULE(210, log);
	ADDRULE(212, log);
	ADDRULE(232, log);
	ADDRULE(222, log);
	ADDRULE(223, log);
	ADDRULE(224, log);
	ADDRULE(228, log);
	ADDRULE(229, log);
	ADDRULE(230, log);
	ADDRULE(268, log);
	ADDRULE(269, log);
	ADDRULE(239, log);
	ADDRULE(243, log);
	ADDRULE(245, log);
	ADDRULE(247, log);
	ADDRULE(250, log);
	ADDRULE(262, log);
	ADDRULE(267, log);
	ADDRULE(270, log);
	ADDRULE(271, log);
	ADDRULE(274, log);
	ADDRULE(275, log);
	ADDRULE(279, log);
	ADDRULE(309, log);
	ADDRULE(281, log);
	ADDRULE(286, log);
	ADDRULE(287, log);
	ADDRULE(293, log);
	ADDRULE(295, log);
	ADDRULE(299, log);
	ADDRULE(302, log);
	ADDRULE(303, log);
	ADDRULE(305, log);

	ADDRULE(41, log); 
	ADDRULE(42, log); 
	ADDRULE(43, log); 
	ADDRULE(44, log); 
	ADDRULE(45, log); 
	ADDRULE(46, log); 
	ADDRULE(47, log); 
	ADDRULE(49, log); 
	ADDRULE(51, log); 
	ADDRULE(52, log); 
	ADDRULE(53, log); 
	ADDRULE(54, log); 
	ADDRULE(55, log); 
}
/*}}}*/

/* Parsing syscall number to syscall name */
/*{{{*/
static __attribute__((const)) char *syscall_name(int nr) {
	char *ret;


	switch(nr) {
		case 0: ret = "read"; break;
		case 1: ret = "write"; break;
		case 2: ret = "open"; break;
		case 3: ret = "close"; break;
		case 4: ret = "stat"; break;
		case 5: ret = "fstat"; break;
		case 6: ret = "lstat"; break;
		case 7: ret = "poll"; break;
		case 8: ret = "lseek"; break;
		case 9: ret = "mmap"; break;
		case 10: ret = "mprotect"; break;
		case 11: ret = "munmap"; break;
		case 12: ret = "brk"; break;
		case 13: ret = "rt_sigaction"; break;
		case 14: ret = "rt_sigprocmask"; break;
		case 15: ret = "rt_sigreturn"; break;
		case 16: ret = "ioctl"; break;
		case 17: ret = "pread64"; break;
		case 18: ret = "pwrite64"; break;
		case 19: ret = "readv"; break;
		case 20: ret = "writev"; break;
		case 21: ret = "access"; break;
		case 22: ret = "pipe"; break;
		case 23: ret = "select"; break;
		case 24: ret = "sched_yield"; break;
		case 25: ret = "mremap"; break;
		case 26: ret = "msync"; break;
		case 27: ret = "mincore"; break;
		case 28: ret = "madvise"; break;
		case 29: ret = "shmget"; break;
		case 30: ret = "shmat"; break;
		case 31: ret = "shmctl"; break;
		case 32: ret = "dup"; break;
		case 33: ret = "dup2"; break;
		case 34: ret = "pause"; break;
		case 35: ret = "nanosleep"; break;
		case 36: ret = "getitimer"; break;
		case 37: ret = "alarm"; break;
		case 38: ret = "setitimer"; break;
		case 39: ret = "getpid"; break;
		case 40: ret = "sendfile"; break;
		case 41: ret = "socket"; break;
		case 42: ret = "connect"; break;
		case 43: ret = "accept"; break;
		case 44: ret = "sendto"; break;
		case 45: ret = "recvfrom"; break;
		case 46: ret = "sendmsg"; break;
		case 47: ret = "recvmsg"; break;
		case 48: ret = "shutdown"; break;
		case 49: ret = "bind"; break;
		case 50: ret = "listen"; break;
		case 51: ret = "getsockname"; break;
		case 52: ret = "getpeername"; break;
		case 53: ret = "socketpair"; break;
		case 54: ret = "setsockopt"; break;
		case 55: ret = "getsockopt"; break;
		case 56: ret = "clone"; break;
		case 57: ret = "fork"; break;
		case 58: ret = "vfork"; break;
		case 59: ret = "execve"; break;
		case 60: ret = "exit"; break;
		case 61: ret = "wait4"; break;
		case 62: ret = "kill"; break;
		case 63: ret = "uname"; break;
		case 64: ret = "semget"; break;
		case 65: ret = "semop"; break;
		case 66: ret = "semctl"; break;
		case 67: ret = "shmdt"; break;
		case 68: ret = "msgget"; break;
		case 69: ret = "msgsnd"; break;
		case 70: ret = "msgrcv"; break;
		case 71: ret = "msgctl"; break;
		case 72: ret = "fcntl"; break;
		case 73: ret = "flock"; break;
		case 74: ret = "fsync"; break;
		case 75: ret = "fdatasync"; break;
		case 76: ret = "truncate"; break;
		case 77: ret = "ftruncate"; break;
		case 78: ret = "getdents"; break;
		case 79: ret = "getcwd"; break;
		case 80: ret = "chdir"; break;
		case 81: ret = "fchdir"; break;
		case 82: ret = "rename"; break;
		case 83: ret = "mkdir"; break;
		case 84: ret = "rmdir"; break;
		case 85: ret = "creat"; break;
		case 86: ret = "link"; break;
		case 87: ret = "unlink"; break;
		case 88: ret = "symlink"; break;
		case 89: ret = "readlink"; break;
		case 90: ret = "chmod"; break;
		case 91: ret = "fchmod"; break;
		case 92: ret = "chown"; break;
		case 93: ret = "fchown"; break;
		case 94: ret = "lchown"; break;
		case 95: ret = "umask"; break;
		case 96: ret = "gettimeofday"; break;
		case 97: ret = "getrlimit"; break;
		case 98: ret = "getrusage"; break;
		case 99: ret = "sysinfo"; break;
		case 100: ret = "times"; break;
		case 101: ret = "ptrace"; break;
		case 102: ret = "getuid"; break;
		case 103: ret = "syslog"; break;
		case 104: ret = "getgid"; break;
		case 105: ret = "setuid"; break;
		case 106: ret = "setgid"; break;
		case 107: ret = "geteuid"; break;
		case 108: ret = "getegid"; break;
		case 109: ret = "setpgid"; break;
		case 110: ret = "getppid"; break;
		case 111: ret = "getpgrp"; break;
		case 112: ret = "setsid"; break;
		case 113: ret = "setreuid"; break;
		case 114: ret = "setregid"; break;
		case 115: ret = "getgroups"; break;
		case 116: ret = "setgroups"; break;
		case 117: ret = "setresuid"; break;
		case 118: ret = "getresuid"; break;
		case 119: ret = "setresgid"; break;
		case 120: ret = "getresgid"; break;
		case 121: ret = "getpgid"; break;
		case 122: ret = "setfsuid"; break;
		case 123: ret = "setfsgid"; break;
		case 124: ret = "getsid"; break;
		case 125: ret = "capget"; break;
		case 126: ret = "capset"; break;
		case 127: ret = "rt_sigpending"; break;
		case 128: ret = "rt_sigtimedwait"; break;
		case 129: ret = "rt_sigqueueinfo"; break;
		case 130: ret = "rt_sigsuspend"; break;
		case 131: ret = "sigaltstack"; break;
		case 132: ret = "utime"; break;
		case 133: ret = "mknod"; break;
		case 134: ret = "uselib"; break;
		case 135: ret = "personality"; break;
		case 136: ret = "ustat"; break;
		case 137: ret = "statfs"; break;
		case 138: ret = "fstatfs"; break;
		case 139: ret = "sysfs"; break;
		case 140: ret = "getpriority"; break;
		case 141: ret = "setpriority"; break;
		case 142: ret = "sched_setparam"; break;
		case 143: ret = "sched_getparam"; break;
		case 144: ret = "sched_setscheduler"; break;
		case 145: ret = "sched_getscheduler"; break;
		case 146: ret = "sched_get_priority_max"; break;
		case 147: ret = "sched_get_priority_min"; break;
		case 148: ret = "sched_rr_get_interval"; break;
		case 149: ret = "mlock"; break;
		case 150: ret = "munlock"; break;
		case 151: ret = "mlockall"; break;
		case 152: ret = "munlockall"; break;
		case 153: ret = "vhangup"; break;
		case 154: ret = "modify_ldt"; break;
		case 155: ret = "pivot_root"; break;
		case 156: ret = "_sysctl"; break;
		case 157: ret = "prctl"; break;
		case 158: ret = "arch_prctl"; break;
		case 159: ret = "adjtimex"; break;
		case 160: ret = "setrlimit"; break;
		case 161: ret = "chroot"; break;
		case 162: ret = "sync"; break;
		case 163: ret = "acct"; break;
		case 164: ret = "settimeofday"; break;
		case 165: ret = "mount"; break;
		case 166: ret = "umount2"; break;
		case 167: ret = "swapon"; break;
		case 168: ret = "swapoff"; break;
		case 169: ret = "reboot"; break;
		case 170: ret = "sethostname"; break;
		case 171: ret = "setdomainname"; break;
		case 172: ret = "iopl"; break;
		case 173: ret = "ioperm"; break;
		case 174: ret = "create_module"; break;
		case 175: ret = "init_module"; break;
		case 176: ret = "delete_module"; break;
		case 177: ret = "get_kernel_syms"; break;
		case 178: ret = "query_module"; break;
		case 179: ret = "quotactl"; break;
		case 180: ret = "nfsservctl"; break;
		case 181: ret = "getpmsg"; break;
		case 182: ret = "putpmsg"; break;
		case 183: ret = "afs_syscall"; break;
		case 184: ret = "tuxcall"; break;
		case 185: ret = "security"; break;
		case 186: ret = "gettid"; break;
		case 187: ret = "readahead"; break;
		case 188: ret = "setxattr"; break;
		case 189: ret = "lsetxattr"; break;
		case 190: ret = "fsetxattr"; break;
		case 191: ret = "getxattr"; break;
		case 192: ret = "lgetxattr"; break;
		case 193: ret = "fgetxattr"; break;
		case 194: ret = "listxattr"; break;
		case 195: ret = "llistxattr"; break;
		case 196: ret = "flistxattr"; break;
		case 197: ret = "removexattr"; break;
		case 198: ret = "lremovexattr"; break;
		case 199: ret = "fremovexattr"; break;
		case 200: ret = "tkill"; break;
		case 201: ret = "time"; break;
		case 202: ret = "futex"; break;
		case 203: ret = "sched_setaffinity"; break;
		case 204: ret = "sched_getaffinity"; break;
		case 205: ret = "set_thread_area"; break;
		case 206: ret = "io_setup"; break;
		case 207: ret = "io_destroy"; break;
		case 208: ret = "io_getevents"; break;
		case 209: ret = "io_submit"; break;
		case 210: ret = "io_cancel"; break;
		case 211: ret = "get_thread_area"; break;
		case 212: ret = "lookup_dcookie"; break;
		case 213: ret = "epoll_create"; break;
		case 214: ret = "epoll_ctl_old"; break;
		case 215: ret = "epoll_wait_old"; break;
		case 216: ret = "remap_file_pages"; break;
		case 217: ret = "getdents64"; break;
		case 218: ret = "set_tid_address"; break;
		case 219: ret = "restart_syscall"; break;
		case 220: ret = "semtimedop"; break;
		case 221: ret = "fadvise64"; break;
		case 222: ret = "timer_create"; break;
		case 223: ret = "timer_settime"; break;
		case 224: ret = "timer_gettime"; break;
		case 225: ret = "timer_getoverrun"; break;
		case 226: ret = "timer_delete"; break;
		case 227: ret = "clock_settime"; break;
		case 228: ret = "clock_gettime"; break;
		case 229: ret = "clock_getres"; break;
		case 230: ret = "clock_nanosleep"; break;
		case 231: ret = "exit_group"; break;
		case 232: ret = "epoll_wait"; break;
		case 233: ret = "epoll_ctl"; break;
		case 234: ret = "tgkill"; break;
		case 235: ret = "utimes"; break;
		case 236: ret = "vserver"; break;
		case 237: ret = "mbind"; break;
		case 238: ret = "set_mempolicy"; break;
		case 239: ret = "get_mempolicy"; break;
		case 240: ret = "mq_open"; break;
		case 241: ret = "mq_unlink"; break;
		case 242: ret = "mq_timedsend"; break;
		case 243: ret = "mq_timedreceive"; break;
		case 244: ret = "mq_notify"; break;
		case 245: ret = "mq_getsetattr"; break;
		case 246: ret = "kexec_load"; break;
		case 247: ret = "waitid"; break;
		case 248: ret = "add_key"; break;
		case 249: ret = "request_key"; break;
		case 250: ret = "keyctl"; break;
		case 251: ret = "ioprio_set"; break;
		case 252: ret = "ioprio_get"; break;
		case 253: ret = "inotify_init"; break;
		case 254: ret = "inotify_add_watch"; break;
		case 255: ret = "inotify_rm_watch"; break;
		case 256: ret = "migrate_pages"; break;
		case 257: ret = "openat"; break;
		case 258: ret = "mkdirat"; break;
		case 259: ret = "mknodat"; break;
		case 260: ret = "fchownat"; break;
		case 261: ret = "futimesat"; break;
		case 262: ret = "newfstatat"; break;
		case 263: ret = "unlinkat"; break;
		case 264: ret = "renameat"; break;
		case 265: ret = "linkat"; break;
		case 266: ret = "symlinkat"; break;
		case 267: ret = "readlinkat"; break;
		case 268: ret = "fchmodat"; break;
		case 269: ret = "faccessat"; break;
		case 270: ret = "pselect6"; break;
		case 271: ret = "ppoll"; break;
		case 272: ret = "unshare"; break;
		case 273: ret = "set_robust_list"; break;
		case 274: ret = "get_robust_list"; break;
		case 275: ret = "splice"; break;
		case 276: ret = "tee"; break;
		case 277: ret = "sync_file_range"; break;
		case 278: ret = "vmsplice"; break;
		case 279: ret = "move_pages"; break;
		case 280: ret = "utimensat"; break;
		case 281: ret = "epoll_pwait"; break;
		case 282: ret = "signalfd"; break;
		case 283: ret = "timerfd_create"; break;
		case 284: ret = "eventfd"; break;
		case 285: ret = "fallocate"; break;
		case 286: ret = "timerfd_settime"; break;
		case 287: ret = "timerfd_gettime"; break;
		case 288: ret = "accept4"; break;
		case 289: ret = "signalfd4"; break;
		case 290: ret = "eventfd2"; break;
		case 291: ret = "epoll_create1"; break;
		case 292: ret = "dup3"; break;
		case 293: ret = "pipe2"; break;
		case 294: ret = "inotify_init1"; break;
		case 295: ret = "preadv"; break;
		case 296: ret = "pwritev"; break;
		case 297: ret = "rt_tgsigqueueinfo"; break;
		case 298: ret = "perf_event_open"; break;
		case 299: ret = "recvmmsg"; break;
		case 300: ret = "fanotify_init"; break;
		case 301: ret = "fanotify_mark"; break;
		case 302: ret = "prlimit64"; break;
		case 303: ret = "name_to_handle_at"; break;
		case 304: ret = "open_by_handle_at"; break;
		case 305: ret = "clock_adjtime"; break;
		case 306: ret = "syncfs"; break;
		case 307: ret = "sendmmsg"; break;
		case 308: ret = "setns"; break;
		case 309: ret = "getcpu"; break;
		case 310: ret = "process_vm_readv"; break;
		case 311: ret = "process_vm_writev"; break;
		case 312: ret = "kcmp"; break;
		default: ret = "unknown";
	}

	return ret;
}
/*}}}*/
