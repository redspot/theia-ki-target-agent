// theia: toggle the logging and recording of target host
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include <stdio.h>
#include <fcntl.h>

#include <assert.h>

#include <sys/types.h>

int main (int argc, char* argv[]) {
	
	int fd;
	fd = open ("/dev/spec0", O_RDWR);
	if (fd < 0) {
		perror("open /dev/spec0");
		exit(EXIT_FAILURE);
	}

  if(strcmp(argv[1], "logging") == 0) {
		if(strcmp(argv[2], "on") == 0) {
			theia_logging_on(fd);
			printf("Theia logging is on\n");
		}
		else if(strcmp(argv[2], "off") == 0){
			theia_logging_off(fd);
			execl("/bin/rm", "/bin/rm", "/tmp/theia-control.conf", (char*) NULL);
			printf("Theia logging is off\n");
		}
		else {
			printf("Error logging toggle\n");
			return -1;
		}
	}
	else if(strcmp(argv[1], "recording") == 0) {
		if(strcmp(argv[2], "on") == 0) {
			theia_recording_on(fd);
			printf("Theia recording is on\n");
		}
		else if(strcmp(argv[2], "off") == 0){
			theia_recording_off(fd);
			printf("Theia recording is off\n");
		}
		else {
			printf("Error recording toggle\n");
			return -1;
		}
	}
	else {
			printf("Error input\n");
			return -1;
	}

	return 0;

}
