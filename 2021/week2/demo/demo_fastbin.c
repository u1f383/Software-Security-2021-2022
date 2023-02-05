#include <stdio.h>
#include <stdlib.h>

int main()
{
    void *dummy[7];
    void *chk1, *chk2;

    for (int i = 0; i < 7; i++)
        dummy[i] = malloc(0x10);

    chk1 = malloc(0x10);
    chk2 = malloc(0x10);

    // fill tcache
    for (int i = 0; i < 7; i++)
        free(dummy[i]);

    free(chk1);
    free(chk2);

    return 0;
}