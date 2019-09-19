#include <linux/module.h>

#include <core_pidmap.h>
#include <hashmap/hashmap_implementation.h>

EXPORT_SYMBOL(theia_pidmap_get);
EXPORT_SYMBOL(theia_pidmap_add);
EXPORT_SYMBOL(theia_pidmap_del);

#include <core_filpmap.h>
#include <hashmap/hashmap_implementation.h>

EXPORT_SYMBOL(theia_filpmap_get);
EXPORT_SYMBOL(theia_filpmap_add);
EXPORT_SYMBOL(theia_filpmap_del);
