#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

struct User
{
    char name[0x10];
    int size;
    FILE *data;
};

struct User *users[8];

static short int get_idx()
{
    short int idx;

    printf("index\n> ");
    scanf("%hu", &idx);

    if (idx >= 8)
        printf("no, no ..."), exit(1);
    
    return idx;
}

static short int get_size()
{
    short int size;

    printf("size\n> ");
    scanf("%hu", &size);

    if (size >= 0x200)
        printf("no, no ..."), exit(1);
    
    return size;
}

void add_user()
{
    short int idx;

    idx = get_idx();
    users[idx] = malloc(sizeof(*users[idx]));

    printf("username\n> ");
    read(0, users[idx]->name, 0x10);

    users[idx]->data = NULL;
    printf("success!\n");
}

void edit_data()
{
    short int idx;
    short int size;
    char *buf;

    idx = get_idx();
    size = get_size();

    if (users[idx]->data == NULL)
        users[idx]->data = tmpfile();
    
    buf = malloc(size);
    read(0, buf, size);
    
    fwrite(buf, size, 1, users[idx]->data);
    printf("success!\n");
}

void del_user()
{
    short int idx;

    idx = get_idx();
    if (users[idx]->data != NULL)
        fclose(users[idx]->data);
    
    free(users[idx]);
    printf("success!\n");
}

void show_users()
{
    char buf[0x200] = {};

    for (int i = 0; i < 8; i++) {
        if (users[i] == NULL || users[i]->data == NULL)
            continue;
        
        printf("[%d] %s\ndata: ", i, users[i]->name);
        fseek(users[i]->data, 0, SEEK_SET);
        fread(buf, sizeof(buf), 1, users[i]->data);
        printf("%s\n", buf);
    }
}

int main()
{
    char opt[2];
    int power = 20;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("**** [Mini] User Management System ****\n");

    while (power)
    {
        power--;
        printf("1. add_user\n"
               "2. edit_data\n"
               "3. del_user\n"
               "4. show_users\n"
               "5. bye\n"
               "> ");
        read(0, opt, 2);

        switch (opt[0]) {
        case '1': add_user(); break;
        case '2': edit_data(); break;
        case '3': del_user(); break;
        case '4': show_users(); break;
        case '5': exit(0);
        }
    }
    printf("No... no power..., b..ye...\n");
    
    return 0;
}
