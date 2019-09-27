#ifndef __REPLAY_CONFIG_H
#define __REPLAY_CONFIG_H

#include <linux/version.h>
#include <linux/thread_info.h>

/*
 * Define this to let the rest of the module code know that it's being built
 * against theia source, version 3.5.7.13-ddevec-replay, and not the stock
 * v3.5
 */
#if (LINUX_VERSION_CODE == KERNEL_VERSION(3,5,7)) && defined(TIF_FORK_2)
#define THEIA_MODIFIED_KERNEL_SOURCES
#endif

/*
 * Enables read compression, sourcing reads of a file from another uncompressed file.
 * This will have potential data size and performance implications on both recorded/replayed files
 * AND non-record/replay reads from files whose creations were recorded.
 *
 * It may (however) drastically reduce the size of recorded reads by recording the origin of data, instead of its contents.
 *
 * This automatically disables TRACE_*
 */
//#define REPLAY_COMPRESS_READS

/* 
 * Double checks to make sure the data that comes out of a REPLAY_COMPRESS_READS
 * file is the expected data...
 */
//#define VERIFY_COMPRESSED_DATA

/* 
 * Enables replay-graph tracking for file, pipe, and socket IO respectively.
 */
#define TRACE_READ_WRITE
#define TRACE_PIPE_READ_WRITE
#define TRACE_SOCKET_READ_WRITE

// If defined, use file cache for reads of read-only files
#define CACHE_READS

//xdou
/*
 * LOG_COMPRESS is the basic compression level, any other compression technique relies on this,
 * i.e. if you want level_1, xproxy or det_time to be on, LOG_COMPRESS should also be on
 * LOG_COMPRESS_1 is not fully tested for firefox, don't turn it on for now; this means level 1 compression
 * X_COMPRESS will enable the application to use the x proxy; after X_COMPRESS is on,
 * the application will talk to x proxy if x_proxy is 1 and will not talk to x proxy if x_proxy is 0
 * x_proxy can be set up in /proc/sys/kernel/x_proxy
 * when x_proxy is equal to 2, the user-level conversion tool should also be used
 * record_x should be set to 1 if you want a copy of all x messages in the replay log
 * otherwise, only a compressed x message log in the same folder with x proxy is enough for replaying
 * TIME_TRICK is for deterministic time; don't turn it on for now as I'm changing it.
 */
#define LOG_COMPRESS //log compress level 0
//#define LOG_COMPRESS_1 //log compress level 1
//#define X_COMPRESS  // note: x_compress should be defined at least along with log_compress level 0

#define USE_SYSNUM
//#define REPLAY_STATS

#endif
