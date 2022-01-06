#include "user.h"
#include <stdlib.h>
#include <string.h>

MyUser *__new_ms(char *username)
{
    MyUser *mu = (MyUser *) malloc(sizeof(MyUser));
    mu->uid = mu_cnt++;
    mu->username = strdup(username);
    return mu;
}