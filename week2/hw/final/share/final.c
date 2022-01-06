#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

// ***************** we don't care *****************
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
// *************************************************

typedef struct _Animal {
    char type[0x10];
    unsigned long len;
    char *name;
    void (*bark)(char *, char *);
} Animal;

Animal *animals[2];

void meow(char* type, char *name) { printf("MEOW, I am a cute %s, my name is %s !!\n", type, name); }
void woof(char* type, char *name) { printf("WOOF, I am a cute %s, my name is %s !!\n", type, name); }

void buy()
{
    Animal *ani = malloc(sizeof(Animal));
    char tmp[0x10];
    unsigned long idx = 0;

    printf("cat or dog ?\n> ");
    readstr(tmp, 0x8);

    if (!strncmp(tmp, "cat", 3)) {
        strcpy(ani->type, "Persian");
        ani->bark = meow;
    } else {
        strcpy(ani->type, "Shiba");
        ani->bark = woof;
    }
    
    // 由於名字的長度是可以控的，如果我們請求 chunk size >= 0x420，則此 chunk 在後續釋放時
    // 會進入 unsorted bin，再次取得時 fd 與 bk 的位址會有 libc address
    printf("len of name:\n> ");
    ani->len = readu64();

    ani->name = malloc(ani->len);
    printf("name:\n> ");
    // 因為 read 可以不以 \x00 結尾，因此如果此時在 heap 上殘留記憶體位址，則可以 leak 出來
    read(0, ani->name, ani->len);

    printf("where to keep (0 or 1) ?\n> ");
    idx = readu64();

    if (idx == 1)
        animals[1] = ani;
    else
        animals[0] = ani;
    
    ani->bark( ani->type, ani->name );
    puts("you get an animal !");
}

void release()
{
    unsigned long idx = 0;
    printf("which one to release (0 or 1) ?\n> ");
    idx = readu64();
    if (idx != 0 && idx != 1) return;
    
    // 在釋放完後並沒有將 ptr 清成 NULL，可以做 double free
    if (animals[idx]) {
        free(animals[idx]->name);
        free(animals[idx]);
    }
}

void change()
{
    unsigned long idx = 0;
    char buf[0x10] = {0};
    printf("which one to change (0 or 1) ?\n> ");
    idx = readu64();
    if (idx != 0 && idx != 1) return;

    printf("will the len of name change (y/n) ?\n> ");
    readstr(buf, 0x8);
    if (buf[0] == 'y') {
        printf("new len of name:\n> ");
        free(animals[idx]->name);
        animals[idx]->len = readu64();
        animals[idx]->name = malloc(animals[idx]->len);
    }

    // 配合 release() 可以控制到 freed chunk，有 UAF 問題
    printf("new name:\n> ");
    read(0, animals[idx]->name, animals[idx]->len);
}

void play()
{
    unsigned long idx = 0;
    printf("which one to play (0 or 1) ?\n> ");
    idx = readu64();
    if (idx != 0 && idx != 1) return;

    // 由於使用 function pointer，因此若可以透過程式漏洞蓋寫 function pointer，
    // 則可以輕易控制程式執行流程
    animals[idx]->bark( animals[idx]->type, animals[idx]->name );
}

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    while (1)
    {
        puts("1. buy an animal");
        puts("2. release animal");
        puts("3. change animal");
        puts("4. play with animal");
        printf("> ");
        switch ( readu64() ) {
            case 1:
                buy();
                continue;
            case 2:
                release();
                continue;
            case 3:
                change();
                continue;
            case 4:
                play();
                continue;
        }
        break;
    }

    return 0;
}