#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "beeftalk.h"
#define MAX_USER 0x8

typedef struct _User {
    char *name;
    char *desc;
    char *job;
    char *pipe_name;
    char *fifo0;
    char *fifo1;
    unsigned long namelen;
    unsigned long token;
    long int assets;
} User;

User *init_user();
void update_user(User*);
void free_user(User*);
void show_user(User*);
User *find_user_by_token(unsigned long);

User *login();
void chat(User*);
void signup();

User *users[ MAX_USER ];
int uridx = 0;

User *init_user()
{
    User *u = malloc(sizeof(User));
    u->name = malloc(0x20);
    u->desc = malloc(0x40);
    u->job = malloc(0x10);
    u->fifo0 = malloc(0x20);
    u->fifo1 = malloc(0x20);
    u->token = 0;
    u->assets = 0;
    u->namelen = 0;

    return u;
}

void free_user(User *u)
{
    free(u->name);
    free(u->desc);
    free(u->job);
    free(u->fifo0);
    free(u->fifo1);
    unlink(u->fifo0);
    unlink(u->fifo1);
    free(u);
    
}

void show_user(User *u)
{
    printf("-----------\n"
            "Name:    %s\n"
            "Desc:    %s\n"
            "Job:     %s\n"
            "Assets:  %ld\n"
            "Token:   %lu\n"
            "-----------\n", u->name, u->desc, u->job, u->assets, u->token);
}

void delete_account(unsigned long token)
{
    User *u = find_user_by_token(token);

    if (u) {
        free_user(u);
        uridx--;
    }
}

User *find_user_by_token(unsigned long token)
{
    for (int i = 0; i < MAX_USER; i++)
        if (users[i] && users[i]->token == token)
            return users[i];

    return NULL;
}

User *login()
{
    unsigned long token = 0;
    User *u;
    
    printf("Give me your token: \n> ");
    token = readlx64();

    u = find_user_by_token(token);
    if (u)
        puts("[+] Login successfully !");
    else
        puts("[-] Login failed");

    return u;
}

void update_user(User *u)
{
    printf("Name: \n> ");
    readstr(u->name, u->namelen);
    
    printf("Desc: \n> ");
    readstr(u->desc, 0x40);
    
    printf("Job: \n> ");
    readstr(u->job, 0x10);
    
    printf("Money: \n> ");
    u->assets = readi64();

    puts("Update successfully !");
}

void signup()
{
    if (uridx >= MAX_USER) {
        puts("Our server can't hold more users");
        return;
    }

    User *tmpuser = init_user();
    char buf[0x100];
    int nr;
    
    printf("What's your name ?\n> ");
    nr = safe_read(0, buf, 0x100);
    if (nr > 0x20)
        tmpuser->name = realloc(tmpuser->name, nr);
    
    tmpuser->namelen = nr;
    memcpy(tmpuser->name, buf, nr);
    
    printf("What's your desc ?\n> ");
    readstr(tmpuser->desc, 0x40);
    
    printf("What's your job ?\n> ");
    readstr(tmpuser->job, 0x10);
    
    printf("How much money do you have ?\n> ");
    tmpuser->assets = readi64();

    show_user(tmpuser);
    printf("Is correct ?\n(y/n) > ");

    if (readc() == 'n') {
        free_user(tmpuser);
        puts("Sorry, plz signup again :(");
        return;
    }

    do {
        tmpuser->token = (((unsigned long) rand()) << 32) + (unsigned long) rand() + tmpuser->assets;
        sprintf(tmpuser->fifo0, "/tmp/%lx-0", tmpuser->token);
    } while (!access(tmpuser->fifo0, F_OK));

    sprintf(tmpuser->fifo1, "/tmp/%lx-1", tmpuser->token);    
    mkfifo(tmpuser->fifo0, 0666); // for send
    mkfifo(tmpuser->fifo1, 0666); // for recv
    users[uridx++] = tmpuser;

    printf("Done! This is your login token: %lx\n", tmpuser->token);
}

void chat(User *u)
{
    char buf[0x100] = {0};
    char fifo0[0x20] = {0};
    char fifo1[0x20] = {0};
    int nr, len;
    int fd0, fd1;
    int connector = 0;
    char *chat_buf = (char *) malloc(0x100);

    printf("Connect to room with token ?\n(y/n) > ");
    if (readc() == 'y')
    {
        printf("Connection token: \n> ");
        readstr(buf, 0x10);
        sprintf(fifo1, "/tmp/%16s-0", buf);
        sprintf(fifo0, "/tmp/%16s-1", buf);

        if (access(fifo1, F_OK) == -1 || access(fifo0, F_OK) == -1) {
            puts("[-] Match failed");
            free(chat_buf);
            return;
        }

        fd0 = open(fifo0, O_RDONLY);
        fd1 = open(fifo1, O_WRONLY);
        puts("Match successfully !");

        connector = 1;
    }
    else
    {
        strcpy(fifo0, u->fifo0);
        strcpy(fifo1, u->fifo1);

        puts("Waiting for matching ...");
        fd1 = open(fifo1, O_WRONLY);
        fd0 = open(fifo0, O_RDONLY);
        puts("Match successfully !");
    }

    if (fd0 == -1 || fd1 == -1) {
        puts("[-] Match failed");
        free(chat_buf);
        return;
    }

    puts("\n*--------** Room **--------*");
    if (connector)
    {
        while (1)
        {
            // send
            printf("> ");
            nr = safe_read(0, buf, 0x80);
            sprintf(chat_buf, "%s: ", u->name); // name prefix
            len = strlen(chat_buf);
            memcpy(chat_buf + len, buf , nr); // copy content
            write(fd1, chat_buf, nr + len);

            // maybe you want to exit
            if (strstr(buf, "I need to go :("))
                break;

            // recv
            nr = safe_read(fd0, chat_buf, 0x100);
            write(1, chat_buf, nr);

            // maybe he/she want to exit
            if (strstr(chat_buf, "I need to go :("))
                break;
        }
    }
    else
    {
        while (1)
        {
            // recv
            nr = safe_read(fd0, chat_buf, 0x80);
            write(1, chat_buf, nr);

            // maybe he/she want to exit
            if (strstr(chat_buf, "I need to go :("))
                break;
            
            // send
            printf("> ");
            nr = safe_read(0, buf, 0x80);
            sprintf(chat_buf, "%s: ", u->name); // name prefix
            len = strlen(chat_buf);
            memcpy(chat_buf + len, buf , nr); // copy content
            write(fd1, chat_buf, nr + len);

            // maybe you want to exit
            if (strstr(buf, "I need to go :("))
                break;
        }
    }
    
    puts("\n*--------** Chat end **--------*");
    sleep(1);
    close(fd0);
    close(fd1);
    free(chat_buf);

    return;
}

int main()
{
    srand(time(NULL));
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    puts(banner);

    User *user;
    while (1)
    {
        while (1)
        {
            show_begin_menu();
            switch (readu64()) {
                case 1:
                    if (user = login())
                        break;
                    continue;
                case 2:
                    signup();
                    continue;
                case 3:
                    puts("Goodbye !");
                    goto leave;
                default:
                    puts("Invalid option");
                    continue;
            }
            break;
        }
        printf("Hello %s, have a nice day !\n", user->name);

        while (1)
        {
            show_chat_menu();
            switch (readu64()) {
                case 1:
                    update_user(user);
                    continue;
                case 2:
                    chat(user);
                    continue;
                case 3:
                    printf("Are you sure ?\n(y/n) > ");
                    if (readc() == 'y') {
                        delete_account(user->token);
                        puts("Delete successfully !");
                        break;
                    }
                    continue;
                case 4:
                    puts("Login again");
                    break;
                default:
                    puts("Invalid option");
                    continue;
            }
            break;
        }        
    }
leave:
    return 0;
}