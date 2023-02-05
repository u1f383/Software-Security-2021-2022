#include <stdio.h>
#include <fcntl.h>

int main()
{
    FILE *fp;
    char buf[0x10];

    fp = fopen("/tmp/meow", "r");
    fread(buf, 0x1, 0x10, fp);
    fclose(fp);

    return 0;
}
