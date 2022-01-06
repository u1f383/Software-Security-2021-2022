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

void list_add(list_head *hd, list_head *node)
{
    if (hd->next)
        node->next = hd->next;
    hd->next = node;
}

void list_delete(list_head *hd, list_head *node)
{
    list_head **indirect = &hd;
    while (*indirect != node)
        indirect = &(*indirect)->next;
    *indirect = node->next;
}

#endif