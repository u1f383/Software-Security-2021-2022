#ifndef _USER_H_
#define _USER_H_

#include <stdint.h>
#define MU_DIR_MAX_DEEP 8
#define MU_MAX_USER_NUM 0x100
#define MU_MAX_UNAME_LEN 0x20

struct _MyUser;
typedef struct _MyUser MyUser;

static uint8_t mu_cnt = 0;

#include "fs.h"
struct _MyUser
{
    uint8_t uid;
    uint8_t dir_deep;
    char *username;
    char *password;
    MyFile *dir_stack[8];
    MyFile *curr_dir;
    MyFile *softlink;
    MyFile *hardlink;
};

static inline int mu_is_deleted(MyUser *mu)
{
    return mu->password == NULL;
}

const char *get_uname_by_uid(uint8_t uid);
MyUser *_get_mu_by_uname(const char *username);

/**
 * new_mu(): create an new user
 * > useradd <username> <password>
 */
MyUser *new_mu(const char *username, const char *password, MyFile *rootfs_mf);
MyUser *__new_mu(const char *username, const char *password, MyFile *rootfs_mf);

/**
 * login_mu(): login
 * > login <username> <password>
 */
MyUser *login_mu(const char *username, const char *password);

/**
 * delete_mu(): delete
 * > userdel <username> <password>
 */
int delete_mu(const char *username, const char *password, MyUser *curr_mu);


#endif