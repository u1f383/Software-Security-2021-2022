#ifndef _BEEFTALK_H_
#define _BEEFTALK_H_

const char *banner = ""
"  ____             __ _        _ _    \n"
" | __ )  ___  ___ / _| |_ __ _| | | __\n"
" |  _ \\ / _ \\/ _ \\ |_| __/ _` | | |/ /\n"
" | |_) |  __/  __/  _| || (_| | |   < \n"
" |____/ \\___|\\___|_|  \\__\\__,_|_|_|\\_\\\n"
"\n"
"The greatest chat software in the world !\n"
"Welcome ! If you use our service first time, make sure you have an account :)";

void readstr();
void show_chat_menu();
void show_begin_menu();
unsigned char readc();
unsigned long readu64();
unsigned long readlx64();
long int readi64();
ssize_t safe_read(int, void*, size_t);

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

unsigned long readlx64()
{
    char str[0x20] = {0};
    readstr(str, 0x10);
    return strtoul(str, NULL, 16);
}

long int readi64()
{
    char str[0x20] = {0};
    readstr(str, 0x10);
    return strtol(str, NULL, 10);
}

unsigned char readc()
{
    char c = getc(stdin);
    getc(stdin);
    return c;
}

void show_chat_menu()
{
    puts("1. update information");
    puts("2. chat with other");
    puts("3. delete account");
    puts("4. logout");
    printf("> ");
}

void show_begin_menu()
{
    puts("1. login");
    puts("2. signup");
    puts("3. leave");
    printf("> ");
}

#endif