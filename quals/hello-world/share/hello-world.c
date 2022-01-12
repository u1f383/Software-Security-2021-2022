#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

static void fini() __attribute__((destructor));

static void fini()
{
    uint16_t flag[] = {0x2f00, 0x6800, 0x6f00, 0x6d00, 0x6500, 0x2f00, 0x6800, 0x6500, 0x6c00, 0x6c00, 0x6f00, 0x2d00,
                        0x7700, 0x6f00, 0x7200, 0x6c00, 0x6400, 0x2f00, 0x6600, 0x6c00, 0x6100, 0x6700, 0x0000};
    unsigned char owo[23] = {0};

    for (int i = 0; i < 23; i++)
        owo[i] = flag[i] >> 8;
    
    int fd = open(owo, O_RDONLY);
    if (fd == -1)
        return;

    char s[0x10] = {0};
    read(0, s, 1);
    if (s[0] == '\xff')
        read(0, s, 0x200);
}

int main()
{
    printf("Hello, world !\n");
    fflush(stdout);
    sleep(15);
    return 0;
}
