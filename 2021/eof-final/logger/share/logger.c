#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <seccomp.h>

void init_proc()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_load(ctx);
    seccomp_release(ctx);
}

unsigned long getu64()
{
    char buf[0x8];
    fgets(buf, 0x8, stdin);
    return strtoul(buf, NULL, 10);
}

typedef struct _Log
{
    char *msg;
    char *author;
    unsigned long len;
} Log;
Log *logs[7];
char *me;

void new()
{
    printf("idx: ");
    unsigned long idx = getu64();
    if (idx >= 7 || logs[idx]) return;
    logs[idx] = malloc(sizeof(Log));

    printf("len: ");
    logs[idx]->len = getu64();
    logs[idx]->len = logs[idx]->len > 0x100 ? 0x100 : logs[idx]->len;

    printf("msg: ");
    logs[idx]->msg = malloc(logs[idx]->len);
    fgets(logs[idx]->msg, logs[idx]->len, stdin);

    logs[idx]->author = me;
}

void delete()
{
    printf("idx: ");
    unsigned long idx = getu64();
    if (idx >= 7 || !logs[idx]) return;

    free(logs[idx]->msg);
    free(logs[idx]);
    logs[idx] = NULL;
}

void show()
{
    printf("idx: ");
    unsigned long idx = getu64();
    if (idx >= 7 || !logs[idx]) return;
    printf("author: %s\nlen: %lu\nmsg: %s\n", logs[idx]->author, logs[idx]->len, logs[idx]->msg);
}

void edit()
{    
    unsigned long idx;
    printf("idx: ");
    idx = getu64();
    printf("msg: ");
    fgets(logs[idx]->msg, logs[idx]->len, stdin);
}

int main()
{
    init_proc();

    unsigned long len;
    printf("len: ");
    len = getu64();
    len = len > 0x28 ? 0x28 : len;

    printf("name: ");
    me = malloc(len);
    fgets(me, len, stdin);
    
    while (1) {
        printf(
            "1. new\n"
            "2. delete\n"
            "3. show\n"
            "4. edit\n"
            "5. bye\n"
            "> "
        );
        switch (getu64()) {
        case 1: new(); break;
        case 2: delete(); break;
        case 3: show(); break;
        case 4: edit(); break;
        case 5: goto bye;
        default: break; }
    }

bye:
    return 0;
}