// A simple program to launch a recorded execution
#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "util.h"
#include <sys/wait.h>
#include <sys/types.h>
#include <stdbool.h>
#include <paths.h>

extern char** environ;

void format ()
{
	fprintf (stderr, "format: launcher [--logdir logdir] [--pthread libdir] [-o |--outfile stdoutput_redirect] [-m] program [args]\n");
	exit(EXIT_FAILURE);
}

static void
scripts_argv (const char *file, char *const argv[], int argc, char **new_argv)
{
  /* Construct an argument list for the shell.  */
  new_argv[0] = (char *) _PATH_BSHELL;
  new_argv[1] = (char *) file;
  while (argc > 1)
    {
      new_argv[argc] = argv[argc - 1];
      --argc;
    }
}

static inline char *strchrnul(const char *s, int c)
{
	while (*s && *s != c)
		s++;
	return (char *)s;
}

int main (int argc, char* argv[])
{
	pid_t pid;
	int fd, rc, i;
	int link_debug = 0; // flag if we should debug linking
	char* libdir = NULL;
	char* logdir = NULL;
	int base;
	char ldpath[4096];
	char* linkpath = NULL;
	int save_mmap = 0;
	char *outfile = NULL;
	char logarr[0x100];
	char *logarr_ptr;
	FILE *infofile;

	int pipe_fds[2];

	struct option long_options[] = {
		{"logdir", required_argument, 0, 0},
		{"pthread", required_argument, 0, 0},
		{"outfile", required_argument, 0, 0},
		{0, 0, 0, 0}
	};

	printf("hello\n");

	/*
	for (i = 0; i < argc; i++) {
		printf("Got input arg of %s\n", argv[i]);
	}
	*/

	while (1) {
		char opt;
		int option_index = 0;

		setenv("POSIXLY_CORRECT", "1", 1);
		opt = getopt_long(argc, argv, "mho:", long_options, &option_index);
		unsetenv("POSIXLY_CORRECT");
		//printf("getopt_long returns %c (%d)\n", opt, opt);

		if (opt == -1) {
			break;
		}

		switch(opt) {
			case 0:
				switch(option_index) {
					case 0:
						//printf("logdir is %s\n", optarg);
						logdir = optarg;
						assert(optarg != NULL);
						break;
					case 1:
						//printf("pthread libdir is %s\n", optarg);
						libdir = optarg;
						break;
					case 2:
						outfile = optarg;
						break;
					default:
						fprintf(stderr, "Unrecognized option\n");
						format();
				}
				break;
			case 'm':
				//printf("save_mmap is on");
				save_mmap = 1;
				break;
			case 'o':
				outfile = optarg;
				break;
			case 'h':
				format();
				break;
			default:
				fprintf(stderr, "Unrecognized option\n");
				format();
				break;
		}
	}
	base = optind;

	/* David D. Replaced with proper getopts */
	/*
	for (base = 1; base < argc; base++) {
		if (argc > base+1 && !strncmp(argv[base], "--pthread", 8)) {
			libdir = argv[base+1];
			base++;
		} else if (argc > base+1 && !strncmp(argv[base], "--logdir", 8)) {
			logdir = argv[base+1];
			base++;
		} else if (!strncmp(argv[base], "--link-debug", 8)) {
			link_debug = 1;
		} else if (!strncmp(argv[base], "-m", 2)) {
			save_mmap = 1;
		} else {
			break; // unrecognized arg - should be logdir
		}
	}
	*/


	if (argc-base < 1) {
		fprintf(stderr, "Program name not specified");
		format();
	}

	/*
	for (i = base; i < argc; i++) {
		printf("Got non-opt arg: %s\n", argv[i]);
	}
	*/

	fd = open ("/dev/spec0", O_RDWR);
	if (fd < 0) {
		perror("open /dev/spec0");
		exit(EXIT_FAILURE);
	}

	if (libdir) { 
		strcpy (ldpath, libdir);
		for (i = 0; i < strlen(ldpath); i++) {
			if (ldpath[i] == ':') {
				ldpath[i] = '\0';
				break;
			}
		}
		strcat(ldpath, "/");
		strcat(ldpath, "ld-linux.so.2");
		argv[base-1] = ldpath;
		linkpath = ldpath;

		setenv("LD_LIBRARY_PATH", libdir, 1);
	}
	if (link_debug) setenv("LD_DEBUG", "libs", 1);

	rc = pipe(pipe_fds);
	if (rc) {
		perror("pipe");
		exit(EXIT_FAILURE);
	}
	rc = fcntl(pipe_fds[0], F_SETFL, FD_CLOEXEC);
	if (rc) {
		perror("fcntl pipe_fds[0]");
		exit(EXIT_FAILURE);
	}

	rc = fcntl(pipe_fds[1], F_SETFL, FD_CLOEXEC);
	if (rc) {
		perror("fcntl pipe_fds[1]");
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid == -1) {
		perror("fork");
		exit(EXIT_FAILURE);
	}

	//printf("linkpath: %s, ldpath: %s\n", linkpath, ldpath);
	if (pid == 0) {
		close(pipe_fds[0]);

		if (strchr (argv[base], '/') != NULL)
		{
			/* Don't search when it contains a slash.  */
			rc = replay_fork(fd, (const char**) &argv[base], (const char **) environ,
					linkpath, logdir, save_mmap, pipe_fds[1]);
		}
		else
		{
			size_t pathlen;
			size_t alloclen = 0;
			char *path = getenv ("PATH");
			if (path == NULL)
			{
				pathlen = confstr (_CS_PATH, (char *) NULL, 0);
				alloclen = pathlen + 1;
			}
			else
				pathlen = strlen (path);

			size_t len = strlen (argv[base]) + 1;
			alloclen += pathlen + len + 1;

			char *name;
			char *path_malloc = NULL;
			{
				path_malloc = name = malloc (alloclen);
				if (name == NULL)
					return -1;
			}

			if (path == NULL)
			{
				/* There is no `PATH' in the environment.
					 The default search path is the current directory
					 followed by the path `confstr' returns for `_CS_PATH'.  */
				path = name + pathlen + len + 1;
				path[0] = ':';
				(void) confstr (_CS_PATH, path + 1, pathlen);
			}

			/* Copy the file name at the top.  */
			name = (char *) memcpy (name + pathlen + 1, argv[base], len);
			/* And add the slash.  */
			*--name = '/';

			char **script_argv = NULL;
			void *script_argv_malloc = NULL;
			bool got_eacces = false;
			char *p = path;
			do
			{
				char *startp;

				path = p;
				p = strchrnul (path, ':');

				if (p == path)
					/* Two adjacent colons, or a colon at the beginning or the end
						 of `PATH' means to search the current directory.  */
					startp = name + 1;
				else
					startp = (char *) memcpy (name - (p - path), path, p - path);


				/* Count the arguments.  */
				int argc = 0;
				while (argv[base+argc++])
					;
				printf("argc is %d\n",argc);
				size_t arglen = (argc + 1) * sizeof (char *);
				script_argv = script_argv_malloc = malloc (arglen);
				if (script_argv == NULL)
				{
					/* A possible EACCES error is not as important as
						 the ENOMEM.  */
					got_eacces = false;
					break;
				}
				scripts_argv (startp, &argv[base], argc, script_argv);

				//				printf("script_argv[0]: %s, script_argv[1]: %s, script_argv[2]: %s\n", script_argv[0], script_argv[1], script_argv[2]);

				int access_rslt = access(script_argv[1], F_OK);
				if(access_rslt == 0) {
					printf("%s is taken\n", script_argv[1]);
					rc = replay_fork(fd, (const char**) &script_argv[1], (const char **) environ,
							linkpath, logdir, save_mmap, pipe_fds[1]);
				}

			}
			while (*p++ != '\0');
		}
		fprintf(stderr, "replay_fork failed, rc = %d\n", rc);
		exit(EXIT_FAILURE);
	}
	close(pipe_fds[1]);

	if (outfile) {
		infofile = fopen(outfile, "w");
		if (infofile == NULL) {
			perror("fopen");
			exit(EXIT_FAILURE);
		}
	} else {
		infofile = stdout;
	}

	fprintf(infofile, "Record log saved to: ");
	logarr_ptr = logarr;
	while (read(pipe_fds[0], logarr_ptr++, 1) > 0);
	close(pipe_fds[0]);
	*logarr_ptr = '\0';
	fprintf(infofile, "%s", logarr);

	if (outfile) {
		fclose(infofile);
	}

	wait(NULL);

	// replay_fork should never return if it succeeds
	return EXIT_SUCCESS;

}

