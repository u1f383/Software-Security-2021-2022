#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static void fini() __attribute__((destructor));

static void fini()
{
    int fd = open("/home/hello-world/flag", O_RDONLY);
    if (fd == -1)
        return;

    char s[0x10];
    printf("gift: %p\n", fini);
    read(0, s, 0x200);
}

int main()
{
    printf("Hello, world !");
    return 0;
}
