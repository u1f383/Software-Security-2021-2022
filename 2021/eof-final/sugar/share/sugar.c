#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    int size = 0, idx = 0, val = 0;
    unsigned char *ptr = NULL;
    
    while (scanf("%d", &size) == 1) {
        free(ptr);
        ptr = malloc(size);
    }

    while (scanf("%d %d", &idx, &val) == 2)
        ptr[idx] = val;
    
    free(ptr);
    return 0;
}