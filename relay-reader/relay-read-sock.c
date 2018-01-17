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
#include <pthread.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <linux/unistd.h>
#include <linux/kernel.h>


/* name of directory containing relay files */
char *app_dirname = "/debug/theia_logs";
/* base name of per-cpu relay files (e.g. /debug/cpu0, cpu1, ...) */
char *percpu_basename = "cpu";
/* base name of per-cpu output files (e.g. ./cpu0, cpu1, ...) */
char *percpu_out_basename = "cpu";
// toggle file
//char* togglefile = "/home/yang/theia-on.conf";
char* control_file = "/tmp/theia-control.conf";

// server ip address
//const char* hostname = "172.16.63.140";
//const char* hostname = "143.215.130.137";
char hostname[20];
//const char* hostname = "ta1-theia-ki-replay-a.tc.bbn.com";
// server port number
int portno = 10000; 

/* maximum number of CPUs we can handle - change if more */
#define NR_CPUS 256

/* internal variables */
static unsigned int ncpus;

static unsigned prev_seq = -1;

/* per-cpu internal variables */
static int relay_file[NR_CPUS];
static int out_file[NR_CPUS];
static pthread_t reader[NR_CPUS];
static pthread_t rsync_reader;

static size_t control_read(const char *dirname,
		const char *filename);
static void control_write(const char *dirname,
		const char *filename,
		size_t val);
static int open_app_files(void);
static void close_app_files(void);
static int summarize(void);
static int kill_percpu_threads(int n);
static int create_percpu_threads(void);

int main(int argc, char **argv)
{
	strcpy(hostname, argv[1]);
	
	int signal;
	sigset_t signals;

	sigemptyset(&signals);
	sigaddset(&signals, SIGINT);
	sigaddset(&signals, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &signals, NULL);

	ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	pid_t pid = getpgrp();
	printf("pgrp in main: %d\n", pid);

	if (open_app_files())
		return -1;

	if (create_percpu_threads()) {
		close_app_files();
		return -1;
	}

	sigemptyset(&signals);
	sigaddset(&signals, SIGINT);
	sigaddset(&signals, SIGTERM);

	while (sigwait(&signals, &signal) == 0) {
		switch(signal) {
			case SIGINT:
			case SIGTERM:
				kill_percpu_threads(ncpus);
				close_app_files();
				exit(0);
		}
	}
}


static void *rsync_thread(void) {
	int status_logdb, status_cache;

	pid_t pid = getpgrp();
	printf("pgrp in rsync_thread: %d\n", pid);
	printf("pid in rsync_thread: %d\n", getpid());

	do {
//Yang: add /etc/passwd to the rsync targets
//		status_logdb = system("rsync -a /replay_logdb theia1@theia1.gtisc.gatech.edu:/data/replay_logdb/");
//		status_cache = system("rsync -a /replay_cache theia1@theia1.gtisc.gatech.edu:/data/replay_cache/");
//		if (status_logdb == 0 || status_cache == 0) {
//			printf("Failed to run rsync, status_logdb: %d, status_cache: %d\n", 
//				status_logdb, status_cache);
//	//		exit(1);
//		}
		sleep(20);
	} while (1);

//	pclose(fp);
}

void get_curr_time(long *sec, long *nsec) {
	struct timeval curr_time;
	gettimeofday(&curr_time, NULL);
	*sec = curr_time.tv_sec;
	*nsec = curr_time.tv_usec; //granuality is microsec
	return;
}


void packahgv_reboot(char* buf) {
	struct sysinfo s_info;
	int error = sysinfo(&s_info);
	if(error != 0) {
		printf("sysinfo fails for reaching uptime %d\n", error);
	}

	long sec, nsec;
	get_curr_time(&sec, &nsec);
	int size = 0;
	size = sprintf(buf, "startahg|%d|%ld|%ld|%ld|endahg\n", 
			601/*used for reboot*/, s_info.uptime, sec, nsec);
}

/**
 *	reader_thread - per-cpu channel buffer reader
 */
static void *reader_thread(void *data)
{
	int sockfd, n = 0; 
  struct sockaddr_in serv_addr;
  struct hostent *server;
	FILE *fp;
	char output[10];
	pid_t rsyslogd_pid;

	/*get the pid of rsyslogd*/
	fp = popen("pgrep -f rsyslogd", "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
		exit(1);
	}
	/* Read the output a line at a time - output it. */
	while (fgets(output, sizeof(output)-1, fp) != NULL) {
		rsyslogd_pid = atoi(output);	
		break;
	}
	/* close */
	pclose(fp);


	pid_t pid = getpgrp();
	printf("pgrp in reader_thread: %d\n", pid);
	int ret = remove(control_file);
	if(ret < 0) {
		printf("control file delete fails. first time?\n");
	}
	int fd = open(control_file, O_RDWR|O_CREAT, 0666);
	if(fd < 0) {
		printf("control_file open fails %d\n",fd);
	}
	else {
		lseek(fd, 0, SEEK_SET);
		write(fd, (char*)&pid, sizeof(pid_t));
		write(fd, (char*)&rsyslogd_pid, sizeof(pid_t));
		close(fd);
	}

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("ERROR opening socket");
    exit(1);
  }

  server = gethostbyname(hostname);

  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
  serv_addr.sin_port = htons(portno);

  /* Now connect to the server */
  if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
      size_t buf_size = 100;
      char err_buf[buf_size];
      snprintf(err_buf, buf_size, "ERROR connecting to port %i:", portno);
      perror(err_buf);
      exit(1);
  }

	char buf[4096 + 1];
	int rc, cpu = (int)data;
	unsigned seq;
	struct pollfd pollfd;

	char reboot_buf[512];
	packahgv_reboot(reboot_buf);

	n = write(sockfd, reboot_buf, strlen(reboot_buf));
	if (n < 0) {
		perror("ERROR writing to socket");
		exit(1);
	}

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
		rc = read(relay_file[cpu], buf, 4096);
		if (!rc)
			continue;
		if (rc < 0) {
			if (errno == EAGAIN)
				continue;
			perror("read");
			break;
		}
#if 0
		printf("read %08u bytes from cpu %d\n", rc, cpu);
#endif

//		printf("rc is %d\n", rc);
	//	if (write(out_file[cpu], buf, rc) < 0) {
	//		printf("Couldn't write to output file for cpu %d, exiting: errcode = %d: %s\n", cpu, errno, strerror(errno));
	//		exit(1);
	//	}
		

		//Theia: we send the traces off the host
		n = write(sockfd, buf, rc);
		if (n < 0) {
			perror("ERROR writing to socket");
			exit(1);
		}

		sleep(1);
		
	} while (1);
}

/**
 *      create_percpu_threads - create per-cpu threads
 */
static int create_percpu_threads(void)
{
	int i;

	for (i = 0; i < ncpus; i++) {
		/* create a thread for each per-cpu buffer */
		if (pthread_create(&reader[i], NULL, reader_thread,
					(void *)i) < 0) {
			printf("Couldn't create thread\n");
			return -1;
		}
	}

/*
	if (pthread_create(&rsync_reader, NULL, rsync_thread,
			(void *)0) < 0) {
		printf("Couldn't create rsync thread\n");
		return -1;
	}
*/

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

	if ((err = pthread_cancel(rsync_reader)) == 0)
		killed++;
	else
		fprintf(stderr, "WARNING: couldn't kill rsync thread, err = %d\n", err);

	if (killed != n + 1)
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


