#include <stdio.h>
#include <stdlib.h>

int main()
{
    unsigned long *chk1 = malloc(0x10);
    void *chk2 = malloc(0x10);
    chk1[3] = 0x31;
    free(chk2);

    return 0;
}