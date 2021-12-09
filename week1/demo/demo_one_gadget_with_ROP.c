#include <stdio.h>
#include <unistd.h>

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    char s[0x10];

    printf("Your libc: %p", printf);
    read(0, s, 0x100);

    return 0;
}
