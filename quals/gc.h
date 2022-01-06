#ifndef _GC_H_
#define _GC_H_

#include "list.h"
#include <stdint.h>

typedef struct GC {
    uint32_t delcnt;
    int (*gc_list_add)(GC*, list_head*);
    list_head next_g;
} GC;

#endif