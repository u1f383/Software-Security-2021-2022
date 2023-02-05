#include <stdio.h>
#include <stdlib.h>

int main()
{
    void *a, *b, *c, *d;
    void *dummy1, *dummy2;
    
    dummy1 = malloc(0x140);
    dummy2 = malloc(0x140);
    free(dummy1);
    free(dummy2);

a = malloc(0x10);
b = malloc(0x10);
c = malloc(0x10);
d = malloc(0x10);

free(a);
malloc(0x10);
free(b);
free(c);
free(d);

    return 0;
}