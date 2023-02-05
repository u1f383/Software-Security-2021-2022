#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

char flag[0x10] = "FLAG{TEST}\n";

int main()
{
    FILE *fp;
    char *buf;

    buf = malloc(0x10);
    fp = fopen("/tmp/meow", "w");
    read(0, buf, 0x1000);
    fwrite(buf, 0x10, 1, fp);
    return 0;
}
