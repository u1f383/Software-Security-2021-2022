#include <stdio.h>
#include <unistd.h>
#include <seccomp.h>

char fn[0x20];
char ROP[0x100];

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_load(ctx);
    seccomp_release(ctx);

    printf("Give me filename: ");
    read(0, fn, 0x20);

    printf("Give me ROP: ");
    read(0, ROP, 0x100);

    char overflow[0x10];
    printf("Give me overflow: ");
    read(0, overflow, 0x30);

    return 0;
}
