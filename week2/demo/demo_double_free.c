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
    // 不過因為 malloc 會 trigger tcache stashing，
    // 因此我們用 calloc() 直接從 fastbin 取出 chunk
    A = calloc(0x10, 1);
    *A = 0xdeadbeef;
    calloc(0x10, 1);
    calloc(0x10, 1);
    calloc(0x10, 1); // 0xdeadbeef

    return 0;
}