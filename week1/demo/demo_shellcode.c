#include <stdio.h>
#include <unistd.h>

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    char shellcode[0x30];
    printf("Give me shellcode: ");

    read(0, shellcode, 0x30);
    ((void(*)(void))shellcode)();
    return 0;
}