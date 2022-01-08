#include "user.h"
#include "fs.h"
#include <stdlib.h>
#include <string.h>

MyUser *__new_mu(const char *username, MyFile *rootfs_mf)
{
    MyUser *mu = (MyUser *) malloc(sizeof(MyUser));
    mu->uid = mu_cnt++;
    mu->dir_deep = 1;
    mu->username = strdup(username);
    mu->curr_dir = rootfs_mf;
    mu->hardlink = NULL;
    mu->softlink = NULL;
    mu->dir_stack[0] = rootfs_mf;
    for (int i = 1; i < DIR_MAX_DEEP; i++)
        mu->dir_stack[i] = NULL;
    return mu;
}

MyUser *new_mu(const char *username, MyFile *rootfs_mf)
{
    return __new_mu(username, rootfs_mf);
}