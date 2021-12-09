#include <stdio.h>

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    
    char buf[8];
    unsigned long canary = *(unsigned long *)(buf + 8);
    printf("canary: 0x%016lx\n", canary);
    return 0;
}