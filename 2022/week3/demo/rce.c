#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main()
{
    FILE *fp;
    char *buf;
    unsigned long addr;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    buf = malloc(0x10);
    fp = fopen("/tmp/meow", "r");

    printf("GIFT: %p\n", system);
    printf("addr: ");
    scanf("%ld", &addr);
    printf("value: ");
    read(0, (void *)addr, 0x100);

    read(0, buf, 0x1000);
    fwrite(buf, 0x1, 1, fp);
    return 0;
}
