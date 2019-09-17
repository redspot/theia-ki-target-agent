#include <linux/module.h>

#include "core_pidmap.h"
#include "hashmap/hashmap_implementation.h"

EXPORT_SYMBOL(pidmap_get);
EXPORT_SYMBOL(pidmap_add);
EXPORT_SYMBOL(pidmap_del);

#include "core_filpmap.h"
#include "hashmap/hashmap_implementation.h"

EXPORT_SYMBOL(filpmap_get);
EXPORT_SYMBOL(filpmap_add);
EXPORT_SYMBOL(filpmap_del);
