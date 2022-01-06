#ifndef _USER_H_
#define _USER_H_

#include "list.h"
#include <stdint.h>

static int8_t mu_cnt = 0;

typedef struct _MyUser
{
    int8_t uid;

    char *username;

    list_head next;
} MyUser;

MyUser *__new_ms();

static inline int mu_is_deleted(MyUser *mu)
{
    return mu->uid == -1;
}

#endif