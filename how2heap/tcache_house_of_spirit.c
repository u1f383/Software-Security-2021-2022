#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

// 只要 data 視為 size 是合法的，在 stack 的 chunk 也能被放到 tcache 當中
int main()
{
    setbuf(stdout, NULL);
    malloc(1);
    unsigned long long *a;
    unsigned long long fake_chunks[10];

    fake_chunks[1] = 0x40;
    a = &fake_chunks[2];
    // ! vuln
    free(a);

    void *b = malloc(0x30);
    assert((long)b == (long)&fake_chunks[2]);
}