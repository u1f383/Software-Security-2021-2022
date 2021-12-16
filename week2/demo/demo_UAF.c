#include <stdio.h>
#include <stdlib.h>

int main()
{
    void *AA, *BB;
    
    AA = malloc(0x10);
    BB = malloc(0x10);
    free(BB);
    free(AA);
    
    unsigned long *a = malloc(0x10);
    *a = 0xdeadbeef;
    free(a);
    *a = 0xdeadbeef;
    malloc(0x10);
    malloc(0x10);

    return 0;
}