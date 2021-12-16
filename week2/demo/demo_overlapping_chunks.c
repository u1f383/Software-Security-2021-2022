#include <stdio.h>
#include <stdlib.h>

int main()
{
    unsigned long *A, *B;
    unsigned total;
	A = malloc(0x410);
	B = malloc(0x10);

    *(A-1) = 0x421 + 0x20; // 0x20 == B 的 chunk size
    free(A); // consolidate to top chunk
    
    A = malloc(0x430);
    total = (0x430 / 8);
    A[total - 2] = 0xdeadbeef;
    
    printf("%lx\n", B[0]);
    return 0;
}