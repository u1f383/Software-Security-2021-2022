#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <seccomp.h>

char global[0x20];

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
}

void myread(char *addr)
{
    size_t len;

    printf("length > ");
    scanf("%lu", &len);
    if (len > 0x60) {
        puts("Too much");
        return;
    }
    read(0, addr, len);
}

void mywrite(char *addr)
{
    printf(addr); // fmt
}

void chal()
{
    char local[0x20] = {0}; // overflow
    char *ptr = NULL;
    int cnt = 3;

    while (cnt--)
    {
        printf("global or local > ");
        scanf("%16s", local);

        if (!strncmp("local", local, 5))
            ptr = local;
        else if (!strncmp("global", local, 6))
            ptr = global;
        else
            exit(1);

        printf("set, read or write > ");
        scanf("%16s", local);

        if (!strncmp("set", local, 3))
            puts("not implement !");
        else if (!strncmp("read", local, 4))
            myread(ptr);
        else if (!strncmp("write", local, 5))
            mywrite(ptr);
        else
            exit(1);
    }
    puts("Bye ~");
}

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setup_seccomp();
    puts("[*] Flag is in the /home/fullchain-nerf/flag");
    chal();
}