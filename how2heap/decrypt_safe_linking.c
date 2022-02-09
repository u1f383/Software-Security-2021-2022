#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

long decrypt(long cipher)
{
    long key = 0;
    long plain;

    for (int i = 1; i < 6; i++)
    {
        int bits = 64 - 12 * i;
        if (bits < 0)
            bits = 0;
        // 52, 40, 28, 16, 4, 0
        plain = ((cipher ^ key) >> bits) << bits;
        key = plain >> 12;
        printf("round %d:\n", i);
        printf("key:    %#016lx\n", key);
        printf("plain:  %#016lx\n", plain);
        printf("cipher: %#016lx\n\n", cipher);
    }
    return plain;
}

int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    // step 1: allocate chunks
    long *a = malloc(0x20);
    long *b = malloc(0x20);
    malloc(0x10);

    // tcache: b --> a
    free(a);
    free(b);

    // decrypt the encrypted pointer
    long plaintext = decrypt(b[0]);

    printf("value: %p\n", a);
    printf("recovered value: %#lx\n", plaintext);
    assert(plaintext == (long)a);
}