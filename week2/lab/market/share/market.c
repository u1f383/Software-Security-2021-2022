#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

ssize_t safe_read(int fd, void *ptr, size_t count)
{
    int nread = 0;
    nread = read(fd, ptr, count);
    if (nread <= 0)
        exit(1);
    return nread;
}

void readstr(char *ptr, unsigned cnt)
{
    int nread = 0;
    nread = safe_read(0, ptr, cnt + 1);
    ptr[nread - 1] = '\0';
}

unsigned long readu64()
{
    char str[0x20] = {0};
    readstr(str, 0x10);
    return strtoul(str, NULL, 10);
}

typedef struct _User {
    char name[0x8];
    char *secret;
} User;

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    User *admin = malloc(sizeof(User));
    User *you = NULL;

    strcpy(admin->name, "admin");

    admin->secret = malloc(0x30);
    int fd = open("/home/market/flag", O_RDONLY);
    read(fd, admin->secret, 0x30);
    close(fd);

    char buf[0x10] = {0};
    int nr = 0;
    printf("Do you need the admin ?\n> ");
    nr = read(0, buf, 0x4);
    if (buf[0] == 'n') {
        puts("Sad :(");
        free(admin);
        free(admin->secret);
        admin = NULL;
    }

    you = malloc(sizeof(User));
    printf("What's your name ?\n> ");
    read(0, you->name, 0x7);

    unsigned long size = 0;
    printf("How long is your secret ?\n> ");
    size = readu64();
    you->secret = malloc(size);

    printf("What's your secret ?\n> ");
    read(0, you->secret, size);

    unsigned long opt = 0;
    while (1)
    {
        puts("1. new name");
        puts("2. show secret");
        puts("3. steal the secret of admin");
        puts("4. new secret");
        printf("> ");
        opt = readu64();

        if (opt == 1) {
            printf("What's your new name ?\n> ");
            read(0, you->name, 0x7);
        } else if (opt == 2) {
            printf("Your secret: %s\n", you->secret);
        } else if (opt == 3) {
            if (!admin) {
                puts("no admin");
            } else {
                puts("you has been killed by admin");
                exit(1);
            }
        } else if (opt == 4) {
            free(you->secret);
            printf("How long is your secret ?\n> ");
            size = readu64();
            you->secret = malloc(size);

            printf("What's your secret ?\n> ");
            read(0, you->secret, size);
        } else {
            puts("bye ~");
            break;
        }
    }

    return 0;
}
