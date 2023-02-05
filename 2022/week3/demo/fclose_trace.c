#include <stdio.h>
#include <fcntl.h>

int main()
{
    FILE *fp;
    fp = fopen("/tmp/meow", "r");
    fclose(fp);

    return 0;
}
