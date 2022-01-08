#ifndef _USER_H_
#define _USER_H_

#include "fs.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define DIR_MAX_DEEP 8

static int8_t mu_cnt = 0;

typedef struct _MyUser
{
    int8_t uid;
    uint8_t dir_deep;
    char *username;
    MyFile *dir_stack[8];
    MyFile *curr_dir;
    MyFile *softlink;
    MyFile *hardlink;
} MyUser;

MyUser *__new_mu(const char *username);
MyUser *new_mu(const char *username);

static inline int mu_is_deleted(MyUser *mu)
{
    return mu->uid == -1;
}

MyUser *__new_mu(const char *username)
{
    MyUser *mu = (MyUser *) malloc(sizeof(MyUser));
    mu->uid = mu_cnt++;
    mu->dir_deep = 1;
    mu->username = strdup(username);
    mu->curr_dir = _new_dir(mu->uid, "");
    mu->hardlink = NULL;
    mu->softlink = NULL;
    for (int i = 0; i < DIR_MAX_DEEP; i++)
        mu->dir_stack[i] = NULL;
    return mu;
}

MyUser *new_mu(const char *username)
{
    return __new_mu(username);
}

#endif