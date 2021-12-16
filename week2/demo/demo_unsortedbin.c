#include <stdio.h>
#include <stdlib.h>

int main()
{
    void *avoid_consolidation[7];
    void *chk[7];

    for (int i = 0; i < 7; i++) {
        chk[i] = malloc(0x440);
        avoid_consolidation[i] = malloc(0x10);
    }

    for (int i = 0; i < 7; i++)
        free(chk[i]);

    return 0;
}