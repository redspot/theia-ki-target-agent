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
#include <limits.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#ifndef __GNUC__
  #error gcc compiler required
#endif
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8)
  #define atomic_inc(val) __atomic_fetch_add(&val, 1, __ATOMIC_SEQ_CST)
  #define atomic_dec(val) __atomic_fetch_sub(&val, 1, __ATOMIC_SEQ_CST)
#else
  #define atomic_inc(val) __sync_fetch_and_add(&val, 1)
  #define atomic_dec(val) __sync_fetch_and_sub(&val, 1)
#endif

// I have no idea why string.h doesnt have this
void *memrchr(const void *s, int c, size_t n);

/* name of directory containing relay files */
char *app_dirname = "/debug/theia_logs";
/* base name of per-cpu relay files (e.g. /debug/cpu0, cpu1, ...) */
char *percpu_basename = "cpu";
// dump directory
const char dump_prefix[] = "/data";
const char dump_file_template[] = "/ahg.dump.%u.%d";
pthread_mutex_t output_fd_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t output_fd_cond = PTHREAD_COND_INITIALIZER;

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
#define NR_CPUS 1
static size_t READ_BUF_LEN = 256 * 1024;
static size_t ROTATE_SIZE = LONG_MAX;

/* internal variables */
static unsigned int ncpus;
static volatile int stop_threads = 0;
static volatile int reopen_dump = 0;
//the third argument to poll() is the timeout in milliseconds
//poll() will return early if there is IO to perform
#define RELAYFS_TIMEOUT 1000
uint8_t dump_id;

/* per-cpu internal variables */
static int relay_file[NR_CPUS];
static pthread_t reader[NR_CPUS];
// how many children are running
static volatile unsigned int running_children = 0;

static int open_app_files(void);
static void close_app_files(void);
static int kill_percpu_threads(int n);
static int create_percpu_threads(void);
ssize_t chk_write(int fd, const void *buf, size_t count);

int open_dump(unsigned int counter) {
  size_t len = 0;
  int fd = -1;
  char *dump_fn = malloc(PATH_MAX);
  if (!dump_fn) return -1;
  sprintf(dump_fn, "%s", dump_prefix);
  len = strlen(dump_fn);
  sprintf(dump_fn + len, dump_file_template, dump_id, counter);
	fd = open(dump_fn, O_RDWR|O_CREAT|O_APPEND, 0644);
  free(dump_fn);
  return fd;
}

void close_dump(int fd) {
  close(fd);
}

uint8_t get_ip_last_seg(char *full_ip) {
  const int magic_limit = 3;
  int cnt = 0;
  char* partial_ip;
  const char *dot = ".";
  partial_ip = full_ip;

  for(cnt=0;cnt<magic_limit;cnt++) {
    char* index = NULL;
    if((index = strstr(partial_ip, dot))!=NULL)
      partial_ip = index+1;
  }
  return atoi(partial_ip);
}

uint8_t get_last_ip_seg()
{
  int fd;
  struct ifreq ifr;
  char *last_seg;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  /* I want to get an IPv4 IP address */
  ifr.ifr_addr.sa_family = AF_INET;

  /* I want IP address attached to "eth0" */
  strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);

  ioctl(fd, SIOCGIFADDR, &ifr);

  close(fd);

  /* display result */
  printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

  last_seg = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);   

  return get_ip_last_seg(last_seg);
}

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
  // USR1 causes relay-reader to close/open the output dump file
	sigaddset(&signals, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &signals, NULL);

	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpus > NR_CPUS)
		ncpus = NR_CPUS;

	pid_t pid = getpgrp();
	printf("relay-read-file starting: pid=%d\n", pid);

  dump_id = get_last_ip_seg();
	if (open_app_files())
		return -1;

	if (create_percpu_threads()) {
		close_app_files();
		return -1;
	}

  const struct timespec child_wait = {
    .tv_sec = 5,
    .tv_nsec = 0};
  while (1) {
    // check every child_wait to see if all the children
    // have exited early
    signal = sigtimedwait(&signals, NULL, &child_wait);
    if (signal < 0) { // timeout or other signal
      if (running_children < 1) break;
      continue;
    }
    if (signal != SIGUSR1) break;
    // signal threads to close/open output file
    pthread_mutex_lock(&output_fd_mtx);
    reopen_dump = ncpus;
    while (reopen_dump > 0)
      pthread_cond_wait(&output_fd_cond, &output_fd_mtx);
    pthread_mutex_unlock(&output_fd_mtx);
  } // after this, we cleanup and exit
  stop_threads = 1;
  printf("relay-read-file cancelling children\n");
  kill_percpu_threads(ncpus);
  printf("relay-read-file child threads are dead\n");
  close_app_files();
  printf("relay-read-file exiting\n");
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

// this will get called if the thread calls pthread_exit()
// or if the thread is cancelled.
// pthread_cleanup_push(cleanup_child, NULL);
static void cleanup_child(void *arg)
{
  atomic_dec(running_children);
}

/**
 *	reader_thread - per-cpu channel buffer reader
 */
static void *reader_thread(void *data)
{
	int hostfd = -1;
  unsigned int dump_cnt = 1;
	char buf[READ_BUF_LEN + 1];
  char* newline;
	int rc, cpu = (int)(long)data;
	struct pollfd pollfd;
  size_t fsize, slen;

  atomic_inc(running_children);
  pthread_cleanup_push(cleanup_child, NULL);
  printf("reader thread starting for cpu %i\n", cpu);

	// use a file
	hostfd = open_dump(dump_cnt);

  pollfd.fd = relay_file[cpu];
  pollfd.events = POLLIN;
	do {
    //the third argument to poll() is the timeout in milliseconds
    //poll() will return early if there is IO to perform
		rc = poll(&pollfd, 1, RELAYFS_TIMEOUT);
		if (stop_threads)
			break;
    if (reopen_dump > 0) {
      pthread_mutex_lock(&output_fd_mtx);
      close_dump(hostfd);
      hostfd = open_dump(dump_cnt);
      reopen_dump--;
      pthread_cond_signal(&output_fd_cond);
      pthread_mutex_unlock(&output_fd_mtx);
    }
		if (rc < 0) {
			if (errno != EINTR) {
				printf("poll error: %s\n",strerror(errno));
        break;
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
      close_dump(hostfd);
      dump_cnt ++;
      hostfd = open_dump(dump_cnt);
      chk_write(hostfd, newline + 1, rc - slen);
    }
	} while (1);
  printf("reader thread exiting for cpu %i\n", cpu);
  pthread_exit(NULL);  // calls cleanup_child()
  pthread_cleanup_pop(NULL);  //needed to match pthread_cleanup_push()
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
		pthread_join(reader[i], NULL);
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
static int open_cpu_files(int cpu, const char *dirname, const char *basename)
{
	char tmp[4096];

	sprintf(tmp, "%s/%s%d", dirname, basename, cpu);
	relay_file[cpu] = open(tmp, O_RDONLY | O_NONBLOCK);
	if (relay_file[cpu] < 0) {
		printf("Couldn't open relay file %s: errcode = %s\n",
				tmp, strerror(errno));
		return -1;
	}

	return 0;
}

static int open_app_files(void)
{
	int i;

	for (i = 0; i < ncpus; i++) {
		if (open_cpu_files(i, app_dirname, percpu_basename) < 0)
			return -1;
	}

	return 0;
}


