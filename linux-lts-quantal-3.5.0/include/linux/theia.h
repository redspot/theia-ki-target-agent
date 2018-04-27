#ifndef __THEIA_H__
#define __THEIA_H__

void theia_file_write(char *buf, size_t size);
bool is_process_new2(pid_t pid, int nsec);
void recursive_packahgv_process(void);
bool check_and_update_controlfile(void);
void get_curr_time(long *sec, long *nsec);

#endif
