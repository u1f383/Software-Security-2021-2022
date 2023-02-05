#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    srand(time(NULL));

    void *tcache_chk[7]                = {0};
    unsigned char tcachebin[3][7]      = {0}; // 0x20, 0x30, 0x40
    unsigned int tcachebin_counts[4]   = {0};
    unsigned long tcache_size[7]       = {0};
    unsigned long tcache_free_order[7] = {0};

    puts("----------- ** tcache chall ** -----------");
    unsigned long tmp = 0;
    for (int i = 0; i < 7; i++) {
        tmp = (rand() % 0x21) + 0x10; // 0x10 ~ 0x30
        tcache_size[i] = tmp;
    }

    for (int i = 0; i < 7; i++) {
    repeat:
        tmp = rand() % 7;
        for (int j = 0; j < i; j++)
            if (tmp == tcache_free_order[j]) goto repeat;
        tcache_free_order[i] = tmp;
    }

    for (int i = 0; i < 7; i++) {
        tcache_chk[i] = malloc( tcache_size[i] );
        printf("char *%c = (char *) malloc(0x%lx);\n", 'A' + i, tcache_size[i]);
    }

    for (int i = 0; i < 7; i++) {
        int idx = tcache_free_order[i];
        free(tcache_chk[ idx ]);
        printf("free(%c);\n", 'A' + (unsigned char) idx);

        tmp = tcache_size[ idx ] - 0x8;
        if (tmp % 0x10)
            tmp = (tmp & ~0xf) + 0x20;
        else
            tmp += 0x10;

        unsigned int binidx = ((tmp - 0x20) / 0x10);
        unsigned int bincnt = tcachebin_counts[ binidx ];
        tcachebin[ binidx ][ bincnt ] = 'A' + (unsigned char) idx;
        tcachebin_counts[ binidx ]++;
    }

    char tmpbuf[0x100]   = {0};
    char ansbuf[3][0x100] = {0};
    for (int i = 0; i < 3; i++) {
        for (int j = 6; j >= 0; j--)
            if (tcachebin[i][j]) {
                sprintf(tmpbuf, "%c --> ", tcachebin[i][j]);
                strcat(ansbuf[i], tmpbuf);
            }
        strcat(ansbuf[i], "NULL");
    }
    puts("");
    for (int i = 0; i < 3; i++) {
        printf("[chunk size] 0x%x: ", (i+2) * 0x10);
        if (i == 0) {
            printf("%s\t(just send \"%s\")\n", ansbuf[i], ansbuf[i]);
        } else {
            printf("?\n> ");
            fgets(tmpbuf, 0x100, stdin);
            if (!strncmp(tmpbuf, ansbuf[i], strlen(ansbuf[i]))) {
                puts("Correct !");
            } else {
                puts("Wrong !");
                printf("Ans: \"%s\"\n", ansbuf[i]);
                exit(0);
            }
        }
    }

    puts("\n----------- ** address chall ** -----------");
    int cmp1 = 0;
    int cmp2 = 0;
    unsigned long ans_addr = 0;

    cmp1 = rand() % 7;
    while ((cmp2 = rand() % 7) == cmp1);
    if (cmp1 > cmp2) {
        tmp = cmp1;
        cmp1 = cmp2;
        cmp2 = tmp;
    }

    printf("assert( %c == %p );\n", 'A' + cmp1, tcache_chk[ cmp1 ]);
    printf("%c == ?\t(send as hex format, e.g. \"%p\")\n> ",
                'A' + cmp2, tcache_chk[ cmp1 ]);
    scanf("%s", tmpbuf);
    ans_addr = strtoul(tmpbuf, NULL, 16);

    if (ans_addr == (unsigned long) tcache_chk[ cmp2 ]) {
        puts("Correct !");
    } else {
        puts("Wrong !");
        printf("Ans: %p\n", tcache_chk[ cmp2 ]);
        exit(0);
    }

    puts("\n----------- ** index chall ** -----------");
    unsigned long *fastbin[2] = {0};
    unsigned long fastbin_size = 0;
    unsigned long secret_idx = 0, result_idx = 0, res = 0;

    fastbin_size = (rand() % 0x31) + 0x40; // 0x40 ~ 0x70
    fastbin_size &= ~0xf;
    fastbin[0] = (unsigned long *) malloc( fastbin_size );
    fastbin[1] = (unsigned long *) malloc( fastbin_size );
    
    printf("unsigned long *%c = (unsigned long *) malloc(0x%lx);\n", 'X', fastbin_size);
    printf("unsigned long *%c = (unsigned long *) malloc(0x%lx);\n", 'Y', fastbin_size);

    secret_idx = rand() % (fastbin_size / 8);
    fastbin[1][ secret_idx ] = 0xdeadbeef;
    result_idx = ((unsigned long)(&fastbin[1][ secret_idx ]) - (unsigned long)(&fastbin[0][0])) / 8;
    
    printf("Y[%lu] = 0xdeadbeef;\n", secret_idx);
    printf("X[?] == 0xdeadbeef\t(just send an integer, e.g. \"8\")\n> ");
    scanf("%lu", &res);

    if (fastbin[0][res] == 0xdeadbeef) {
        puts("Correct !");
    } else {
        puts("Wrong !");
        printf("Ans: %lu\n", result_idx);
        exit(0);
    }

    puts("\n----------- ** tcache fd chall ** -----------");
    free(fastbin[0]);
    free(fastbin[1]);
    printf("free(X);\nfree(Y);\nassert( Y == %p );\n", fastbin[1]);
    printf("fd of Y == ?\t(send as hex format, e.g. \"%p\")\n> ", fastbin[1]);
    scanf("%s", tmpbuf);
    ans_addr = strtoul(tmpbuf, NULL, 16);

    if (ans_addr == *fastbin[1]) {
        puts("Correct !");
    } else {
        puts("Wrong !");
        printf("Ans: 0x%lx\n", *fastbin[1]);
        exit(0);
    }

    puts("\n----------- ** fastbin fd chall (final) ** -----------");
    puts("[*] Restore the chunk to X and Y");
    printf("%c = (unsigned long *) malloc(0x%lx);\n", 'Y', fastbin_size);
    printf("%c = (unsigned long *) malloc(0x%lx);\n", 'X', fastbin_size);
    fastbin[1] = malloc(fastbin_size);
    fastbin[0] = malloc(fastbin_size);
    printf("[*] Do something to fill up 0x%lx tcache\n...\n[*] finish\n", fastbin_size + 0x10);
    void *tmpchk[7];
    for (int i = 0; i < 7; i++)
        tmpchk[i] = malloc(fastbin_size);
    for (int i = 0; i < 7; i++)
        free(tmpchk[i]);
    printf("free(X);\nfree(Y);\nassert( Y == %p );\n", fastbin[1]);
    free(fastbin[0]);
    free(fastbin[1]);
    printf("fd of Y == ?\t(send as hex format, e.g. \"%p\")\n> ", fastbin[1]);
    scanf("%s", tmpbuf);
    ans_addr = strtoul(tmpbuf, NULL, 16);

    if (ans_addr == *fastbin[1]) {
        puts("Correct !");
        memset(tmpbuf, 0, 0x31);
        
        int fd = open("/home/heapmath/flag", O_RDONLY);
        read(fd, tmpbuf, 0x30);
        close(fd);
        printf("Here is your flag: %s\n", tmpbuf);
    } else {
        puts("Wrong !");
        printf("Ans: 0x%lx\n", *fastbin[1]);
        exit(0);
    }
}