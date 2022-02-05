#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    size_t stack_var;

    intptr_t *a = malloc(128);
    intptr_t *b = malloc(128);

    free(a);
    free(b);

    b[0] = (intptr_t)&stack_var;
    intptr_t *c = malloc(128);

    assert((long)&stack_var == (long)c);
    return 0;
}