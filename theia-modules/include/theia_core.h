#ifndef __THEIA_CORE_H__
#define __THEIA_CORE_H__

#include <core_pidmap.h>
#include <core_filpmap.h>

//EXPORTs
extern atomic_t all_hooks_enabled;
extern atomic_t all_traces_enabled;
extern struct module* get_theia_core_module(void);

#endif
