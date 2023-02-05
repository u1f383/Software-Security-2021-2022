#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define FLAG1 "flag{XXXXXXXX}"

struct User
{
    char name[0x10];
    char password[0x10];
    void *data;
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

    if (size >= 0x500)
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

    printf("password\n> ");
    read(0, users[idx]->password, 0x10);

    users[idx]->data = NULL;
    printf("success!\n");
}

void edit_data()
{
    short int idx;
    short int size;

    idx = get_idx();
    size = get_size();

    if (users[idx]->data == NULL)
        users[idx]->data = malloc(size);
    
    read(0, users[idx]->data, size);
    printf("success!\n");
}

void del_user()
{
    short int idx;

    idx = get_idx();
    free(users[idx]->data);
    free(users[idx]);
    printf("success!\n");
}

void show_users()
{
    for (int i = 0; i < 8; i++) {
        if (users[i] == NULL || users[i]->data == NULL)
            continue;
        
        printf("[%d] %s\ndata: %s\n", i, users[i]->name, (char *)users[i]->data);
    }
}

void add_admin()
{
    users[0] = malloc(sizeof(*users[0]));
    strcpy(users[0]->name, "admin");
    strcpy(users[0]->password, FLAG1);
    users[0]->data = NULL;
}

int main()
{
    char opt[2];
    int power = 20;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("**** User Management System ****\n");
    add_admin();

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