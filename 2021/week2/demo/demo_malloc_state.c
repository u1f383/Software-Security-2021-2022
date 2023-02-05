#include <stdlib.h>
#include <stdio.h>

int main()
{
    malloc(0x100);
    return 0;
}