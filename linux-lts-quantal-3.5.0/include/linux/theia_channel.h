#ifndef __THEIA_CHANNEL_H__
#define __THEIA_CHANNEL_H__

#include <linux/ds_list.h> 

//Yang
//const char* togglefile = "/home/yang/theia-on.conf";
//const char* control_file = "/home/yang/theia-control.conf";

#define APP_DIR		"theia_logs"
//static struct rchan	*theia_chan = NULL;
//static struct dentry	*theia_dir = NULL;
static size_t		subbuf_size = 262144*16;
static size_t		n_subbufs = 16;
static size_t		event_n = 20;
static size_t write_count;
static int suspended;

struct rchan *create_channel(unsigned size, unsigned n);

static void destroy_channel(void);

bool is_process_new2(pid_t pid, int nsec);

void recursive_packahgv_process();

bool check_and_update_controlfile();

void get_curr_time(long *sec, long *nsec);

//ds_list_t* glb_process_list = NULL;



#endif
