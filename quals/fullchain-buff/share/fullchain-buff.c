#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

char global[0x20];

void myread(char *addr)
{
    size_t len;

    printf("length > ");
    scanf("%lu", &len);
    if (len >= 24) {
        puts("Too much");
        return;
    }
    read(0, addr, len);
}

void mywrite(char *addr)
{
    printf(addr);
}

void chal()
{
    char local[0x20] = {0};
    char *ptr = NULL;
    register int cnt = 3;

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

        printf("read or write > ");
        scanf("%10s", local);

        if (!strncmp("read", local, 4))
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
    puts("[*] Flag is in the /home/fullchain-buff/flag");
    chal();
}