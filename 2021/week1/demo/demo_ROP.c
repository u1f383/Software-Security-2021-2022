#include <stdio.h>
#include <unistd.h>

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    char s[0x10];

    printf("Here is your \"/bin/sh\": %p\n", "/bin/sh");
    printf("Give me your ROP: ");
    read(0, s, 0x400);

    return 0;
}
