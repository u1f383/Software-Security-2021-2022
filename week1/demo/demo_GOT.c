#include <stdio.h>

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    
    puts("1. lazy binding");
    puts("2. call directly");
    return 0;
}