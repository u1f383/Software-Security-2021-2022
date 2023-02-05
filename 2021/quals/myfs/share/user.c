#include "user.h"
#include "fs.h"
#include <stdlib.h>
#include <string.h>

const uint32_t mu_max_user_cnt = 0x100;
static MyUser *user_list[0x100];

MyUser *__new_mu(const char *username, const char *password, MyFile *rootfs_mf)
{
    if (mu_cnt == mu_max_user_cnt)
        return NULL;

    if (strlen(username) >= MU_MAX_UNAME_LEN)
        return NULL;

    if (_get_mu_by_uname(username) != NULL)
        return NULL;

    MyUser *mu = (MyUser *) malloc(sizeof(MyUser));
    mu->uid = mu_cnt++;
    mu->dir_deep = 1;
    mu->username = strdup(username);
    mu->password = strdup(password);
    mu->curr_dir = rootfs_mf;
    mu->hardlink = NULL;
    mu->softlink = NULL;
    mu->dir_stack[0] = rootfs_mf;
    for (int i = 1; i < MU_DIR_MAX_DEEP; i++)
        mu->dir_stack[i] = NULL;
    user_list[mu_cnt - 1] = mu;
    return mu;
}

MyUser *new_mu(const char *username, const char *password, MyFile *rootfs_mf)
{
    return __new_mu(username, password, rootfs_mf);
}

int delete_mu(const char *username, const char *password, MyUser *curr_mu)
{
    MyUser *mu = _get_mu_by_uname(username);

    if (mu == NULL)
        return -1;

    if (curr_mu == mu)
        return -1;

    if (mu_is_deleted(mu))
        return -1;
    
    if (strcmp(password, mu->password))
        return -1;

    mu->password = NULL;
    return 0;
}

const char *get_uname_by_uid(uint8_t uid)
{
    if (uid >= mu_cnt)
        return NULL;
    
    return user_list[uid]->username;
}

MyUser *login_mu(const char *username, const char *password)
{
    for (int i = 0; i < mu_cnt; i++)
        if (!mu_is_deleted(user_list[i]) &&
            !strcmp(username, user_list[i]->username) &&
            !strcmp(password, user_list[i]->password))
            return user_list[i];
    return NULL;
}

MyUser *_get_mu_by_uname(const char *username)
{
    for (int i = 0; i < mu_cnt; i++)
        if (!strcmp(username, user_list[i]->username))
            return user_list[i];
    return NULL;
}