#ifndef _LIST_H_
#define _LIST_H_

#include <stdio.h>

#define offsetof(type, member) ((size_t) &((type*)0)->member)
#define container_of(ptr, type, member) ({                    \
        const typeof(((type *)0)->member) *__mptr = (ptr);   \
        (type *)((char *)__mptr - offsetof(type, member)); })

typedef struct list_head {
    struct list_head *next;
} list_head;

static inline void list_add(list_head *hd, list_head *node)
{
    node->next = hd->next;
    hd->next = node;
}

static inline void list_delete(list_head *hd, list_head *node)
{
    while (hd->next && hd->next != node)
        hd = hd->next;
    hd->next = node->next;
}

#endif