#ifndef _USER_H_
#define _USER_H_

#include <stdint.h>
#define DIR_MAX_DEEP 8

struct _MyUser;
typedef struct _MyUser MyUser;

static int8_t mu_cnt = 0;

#include "fs.h"
struct _MyUser
{
    int8_t uid;
    uint8_t dir_deep;
    char *username;
    MyFile *dir_stack[8];
    MyFile *curr_dir;
    MyFile *softlink;
    MyFile *hardlink;
};

MyUser *__new_mu(const char *username, MyFile *rootfs_mf);
MyUser *new_mu(const char *username, MyFile *rootfs_mf);

static inline int mu_is_deleted(MyUser *mu)
{
    return mu->uid == -1;
}

#endif