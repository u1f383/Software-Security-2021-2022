#include <stdio.h>
#include <stdlib.h>

int main()
{
    void *dummy[7];
    unsigned long *A, *B;

    for (int i = 0; i < 7; i++)
        dummy[i] = malloc(0x10);

    A = malloc(0x10);
    B = malloc(0x10);

    for (int i = 0; i < 7; i++)
        free(dummy[i]);

    free(A);
    free(B);
    free(A);
    // clean tcache
    A = malloc(0x10);
    *A = 0xdeadbeef;
    malloc(0x10);
    malloc(0x10);
    malloc(0x10); // 0xdeadbeef

    return 0;
}