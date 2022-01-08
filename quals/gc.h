#ifndef _GC_H_
#define _GC_H_

#include "list.h"
#include <stdint.h>
#inclide <stdlib.h>

typedef struct _GC {
    uint32_t delcnt;
    int (*gc_list_add)(struct _GC*, list_head*);
    list_head next_g;
} GC;

GC *new_gc()
{
    GC *gc = (GC *) malloc(sizeof(GC));
    gc->delcnt = 0;
    gc->gc_list_add = NULL;
    gc->next_g.next = NULL;
    return gc;
}

#endif