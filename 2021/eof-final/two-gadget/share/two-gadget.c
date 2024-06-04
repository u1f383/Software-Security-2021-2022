#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>

void init_proc()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
    seccomp_load(ctx);
    seccomp_release(ctx);
}

int main()
{
    char buf[0x8] = {0};

    init_proc();
    printf("Gift: %p\n", setvbuf);

    read(0, buf, 0x8);
    ((void (*)(void)) (*(unsigned long *) buf))();

    read(0, buf, 0x8);
    write(1, (*(unsigned long *) buf), 0x8);

    read(0, buf, 0x28);
    return 0;
}