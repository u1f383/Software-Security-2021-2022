#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    char fmt[0x20];

    system("echo 'Give me fmt: '");
    read(0, fmt, 0x20);
    printf(fmt);

    system("echo 'Give me string: '");
    read(0, fmt, 0x20);
    puts(fmt);

    return 0;
}