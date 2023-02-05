#include "gc.h"
#include <stdlib.h>

GC *new_gc()
{
    GC *gc = (GC *) malloc(sizeof(GC));
    gc->delcnt = 0;
    gc->gc_list_add = NULL;
    gc->next_g.next = NULL;
    return gc;
}