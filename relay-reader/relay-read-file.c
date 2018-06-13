/*
 * read - user program used to test read(2)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2005 - Tom Zanussi (zanussi@us.ibm.com), IBM Corp
 *
 * Usage:
 *
 * mount -t debugfs debugfs /debug
 * insmod read-mod.ko
 * ./read
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <linux/unistd.h>
#include <linux/kernel.h>

// I have no idea why string.h doesnt have this
void *memrchr(const void *s, int c, size_t n);

/* name of directory containing relay files */
char *app_dirname = "/debug/theia_logs";
/* base name of per-cpu relay files (e.g. /debug/cpu0, cpu1, ...) */
char *percpu_basename = "cpu";
/* base name of per-cpu output files (e.g. ./cpu0, cpu1, ...) */
char *percpu_out_basename = "cpu";
// toggle file
//char* togglefile = "/home/yang/theia-on.conf";
char* control_file = "/tmp/theia-control.conf";

// EOF tag.
char* eof_tag = "startahg|end_of_file|endahg\n";

// server ip address
//const char* hostname = "172.16.63.140";
//const char* hostname = "143.215.130.137";
char hostname[20];
//const char* hostname = "ta1-theia-ki-replay-a.tc.bbn.com";
// server port number
int portno = 10000; 

/* maximum number of CPUs we can handle - change if more */
#define NR_CPUS 256
static size_t READ_BUF_LEN = 256 * 1024;
static size_t ROTATE_SIZE = (1*1024*1024*1024);

/* internal variables */
static unsigned int ncpus;

/* per-cpu internal variables */
static int relay_file[NR_CPUS];
static int out_file[NR_CPUS];
static pthread_t reader[NR_CPUS];

static int open_app_files(void);
static void close_app_files(void);
static int kill_percpu_threads(int n);
static int create_percpu_threads(void);
ssize_t chk_write(int fd, const void *buf, size_t count);

int main(int argc, char **argv)
{
	int signal;
	sigset_t signals;

	sigemptyset(&signals);
	sigaddset(&signals, SIGINT);
	sigaddset(&signals, SIGTERM);
#if defined(SIGQUIT)
	sigaddset(&signals, SIGQUIT);
#endif
	pthread_sigmask(SIG_BLOCK, &signals, NULL);

	ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	pid_t pid = getpgrp();
	printf("relay-read-file starting: pid=%d\n", pid);

	if (open_app_files())
		return -1;

	if (create_percpu_threads()) {
		close_app_files();
		return -1;
	}

	while (sigwait(&signals, &signal) == 0) {
    printf("relay-read-file exiting\n");
    kill_percpu_threads(ncpus);
    close_app_files();
  }
  return 0;
}

size_t get_fd_size(int fd) {
  struct stat st;
  if(fstat(fd, &st) != 0) {
    return 0;
  }
  return st.st_size;   
}

inline ssize_t chk_write(int fd, const void *buf, size_t count) {
  int n = write(fd, buf, count);
  if (n < 0) {
    perror("ERROR writing to file");
    exit(1);
  }
  return n;
}

/**
 *	reader_thread - per-cpu channel buffer reader
 */
static void *reader_thread(void *data)
{
	int hostfd = -1;
  char filename[50];
  int dump_ctr = 1;
	char buf[READ_BUF_LEN + 1];
  char* newline;
	int rc, cpu = (int)(long)data;
	struct pollfd pollfd;
  size_t fsize, slen;

  printf("reader thread starting for cpu %i\n", cpu);

	// use a file
  sprintf(filename, "/data/ahg.dump.%d", dump_ctr);
	hostfd = open(filename, O_RDWR|O_CREAT, 0777);

	do {
		pollfd.fd = relay_file[cpu];
		pollfd.events = POLLIN;
		rc = poll(&pollfd, 1, 1);
		if (rc < 0) {
			if (errno != EINTR) {
				printf("poll error: %s\n",strerror(errno));
				exit(1);
			}
			printf("poll warning: %s\n",strerror(errno));
		}
		rc = read(relay_file[cpu], buf, READ_BUF_LEN);
		if (!rc)
			continue;
		if (rc < 0) {
			if (errno == EAGAIN)
				continue;
			perror("read");
			break;
		}

    //printf("rc = %d\n", rc);

    fsize = get_fd_size(hostfd);
    if (fsize + rc < ROTATE_SIZE) {
      // normal write
      chk_write(hostfd, buf, rc);
    } else {
      // split write on last newline
      // then write first half
      // then close, open next file
      // then write second half
      newline = memrchr(buf, '\n', rc);
      slen = (newline - buf) + 1;
      chk_write(hostfd, buf, slen);
      chk_write(hostfd, eof_tag, strlen(eof_tag));
      close(hostfd);
      dump_ctr ++;
      sprintf(filename, "/data/ahg.dump.%d", dump_ctr);
      hostfd = open(filename, O_RDWR|O_CREAT, 0777);
      chk_write(hostfd, newline + 1, rc - slen);
    }
	} while (1);
  printf("reader thread exiting for cpu %i\n", cpu);
  pthread_exit(NULL);
  return NULL;
}

/**
 *      create_percpu_threads - create per-cpu threads
 */
static int create_percpu_threads(void)
{
	int i;

	for (i = 0; i < ncpus; i++) {
		/* create a thread for each per-cpu buffer */
		if (pthread_create(&reader[i], NULL, reader_thread, (void *)(long)i) < 0) {
			printf("Couldn't create thread\n");
			return -1;
		}
	}

	return 0;
}

/**
 *      kill_percpu_threads - kill per-cpu threads 0->n-1
 *      @n: number of threads to kill
 *
 *      Returns number of threads killed.
 */
static int kill_percpu_threads(int n)
{
	int i, killed = 0, err;

	for (i = 0; i < n; i++) {
		if ((err = pthread_cancel(reader[i])) == 0)
			killed++;
		else
			fprintf(stderr, "WARNING: couldn't kill per-cpu thread %d, err = %d\n", i, err);
	}

	if (killed != n)
		fprintf(stderr, "WARNING: couldn't kill all per-cpu threads:  %d killed, %d total\n", killed, n+1);

	return killed;
}

/**
 *	close_cpu_files - close and munmap buffer and open output file for cpu
 */
static void close_cpu_files(int cpu)
{
	close(relay_file[cpu]);
	close(out_file[cpu]);
}

static void close_app_files(void)
{
	int i;

	for (i = 0; i < ncpus; i++)
		close_cpu_files(i);
}

/**
 *	open_files - open and mmap buffer and open output file
 */
static int open_cpu_files(int cpu, const char *dirname, const char *basename,
		const char *out_basename)
{
	char tmp[4096];

	sprintf(tmp, "%s/%s%d", dirname, basename, cpu);
	relay_file[cpu] = open(tmp, O_RDONLY | O_NONBLOCK);
	if (relay_file[cpu] < 0) {
		printf("Couldn't open relay file %s: errcode = %s\n",
				tmp, strerror(errno));
		return -1;
	}

	sprintf(tmp, "%s%d", out_basename, cpu);
	if((out_file[cpu] = open(tmp, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR |
					S_IWUSR | S_IRGRP | S_IROTH)) < 0) {
		printf("Couldn't open output file %s: errcode = %s\n",
				tmp, strerror(errno));
		return -1;
	}

	return 0;
}

static int open_app_files(void)
{
	int i;

	for (i = 0; i < ncpus; i++) {
		if (open_cpu_files(i, app_dirname, percpu_basename,
					percpu_out_basename) < 0)
			return -1;
	}

	return 0;
}


