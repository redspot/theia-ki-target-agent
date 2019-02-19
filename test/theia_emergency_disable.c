#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void check_fd(FILE* fd, const char* path)
{
  if (fd == NULL)
  {
    fprintf(stderr, "cannot open '%s' for writing: %s\n", path, strerror(errno));
    exit(1);
  }
}

void toggle_flag(const char* path, int f)
{
  FILE* fd;
  fd = fopen(path, "w");
  check_fd(fd, path);
  fprintf(fd,"%d",f);
  fclose(fd);
}

int main()
{
  const char* logging_path = "/sys/kernel/theia/theia_logging_toggle";
  const char* recording_path = "/sys/kernel/theia/theia_recording_toggle";
  toggle_flag(logging_path, 0);
  toggle_flag(recording_path, 0);

  return 0;
}
