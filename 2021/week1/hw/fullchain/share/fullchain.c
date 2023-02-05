#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <seccomp.h>

char global[0x10];

void setup_seccomp()
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_load(ctx);
    seccomp_release(ctx);
    char dummy[0x1000] = {0};
}

void myset(char *addr)
{
    int c;
    size_t len;

    printf("data > ");
    scanf("%d", &c);
    printf("length > ");
    scanf("%lu", &len);

    if (len > 0x10) {
        puts("Too more");
        return;
    }
    memset(addr, c, len);
}

void myread(char *addr)
{
    scanf("%24s", addr);
}

void mywrite(char *addr)
{
    printf(addr);
}

void chal()
{
    char local[0x10] = {0};
    char *ptr = NULL;
    int cnt = 3;

    while (cnt--)
    {
        printf("global or local > ");
        scanf("%10s", local);

        if (!strncmp("local", local, 5))
            ptr = local;
        else if (!strncmp("global", local, 6))
            ptr = global;
        else
            exit(1);

        printf("set, read or write > ");
        scanf("%10s", local);

        if (!strncmp("set", local, 3))
            myset(ptr);
        else if (!strncmp("read", local, 4))
            myread(ptr);
        else if (!strncmp("write", local, 5))
            mywrite(ptr);
        else
            exit(1);
    }
    puts("Bye ~");
    exit(1);
}

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setup_seccomp();
    char buf[0x10];
    memset(buf, 0, 0x1000);
    chal();
}