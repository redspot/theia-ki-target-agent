#ifndef __AHG_LOG_H__
#define __AHG_LOG_H__

#include <linux/limits.h>

struct process_pack_ahg {
	int32_t 		pid;
	int32_t 		task_sec;
	uint16_t		size_ids;
	int32_t 		p_pid;
	int32_t 		p_task_sec;
	uint16_t		size_fpathbuf;
	uint8_t			is_user_remote;
	int32_t			tgid;
	int32_t			sec;
	int32_t			nsec;
};
// We decode strings after the struct according to the sizes in struct
//	char 				ids[?];
//	char 				fpathbuf[?];


#endif
