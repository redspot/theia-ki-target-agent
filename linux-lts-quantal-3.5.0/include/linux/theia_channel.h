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

struct rchan* create_channel(size_t size, size_t n);

//ds_list_t* glb_process_list = NULL;



#endif
