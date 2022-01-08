#include "user.h"
#include "fs.h"
#include "gc.h"
#include "list.h"
#include <stdio.h>

GC *gc;

static void banner()
{
#define ENDL "\n"
    printf(
        " _|      _|            _|_|_|_|    _|_|_|  " ENDL
        " _|_|  _|_|  _|    _|  _|        _|        " ENDL
        " _|  _|  _|  _|    _|  _|_|_|      _|_|    " ENDL
        " _|      _|  _|    _|  _|              _|  " ENDL
        " _|      _|    _|_|_|  _|        _|_|_|    " ENDL
        "                   _|                      " ENDL
        "               _|_|                        " ENDL
        "                                  beta ver." ENDL
    );
}

void pexit(const char *msg)
{
    perror(msg);
    exit(1);
}

int mock()
{
    MyUser *admin = new_mu("admin");
    if (create_mf(admin, "dir", "test1") != 0)
        return -1;
}

void init_proc()
{
    gc = new_gc();
    gc->gc_list_add = mf_gc_list_add;
}

int main()
{
    init_proc();
    banner();
    if (mock())
        pexit("[-] server error");

#define DELIM " "
#define CMD_LEN 0x80
    
    char cmd[CMD_LEN];
    char *argv0 = NULL, *argv1 = NULL, *argv2 = NULL;
    MyUser *mu = new_mu("test");
    MyFile *mf = NULL;

    while (1)
    {
        for (int i = 0; i < mu->dir_deep; i++)
            printf("/%s ", mu->dir_stack[i]->fn);
        printf("> ");

        if (fgets(cmd, CMD_LEN, stdin) == NULL)
            pexit("[-] read command error");
        if (cmd[strlen(cmd) - 1] == '\n')
            cmd[strlen(cmd) - 1] = '\0';
        
        argv0 = strtok(cmd, DELIM);
        argv1 = (argv0 != NULL) ? strtok(NULL, DELIM) : NULL;
        argv2 = (argv1 != NULL) ? strtok(NULL, DELIM) : NULL;
        printf("[*] %s %s %s\n", argv0, argv1, argv2);

        if (!strcmp(argv0, "list")) {
            list_dir(mu);
        } else if (!strcmp(argv0, "create")) {
            if (!argv1 || !argv2 || create_mf(mu, argv1, argv2) == -1)
                puts("[-] create file error");
        } else {
            if (!strcmp(argv1, "..")) {
                if (mu->dir_deep == 1) {
                    puts("[-] at root directory");
                    continue;
                }
                mf = mu->dir_stack[mu->dir_deep - 2];
            } else if (!argv1 || !is_existed(&mf, mu, argv1)) {
                puts("[-] file not found");
                continue;
            }

            if (!strcmp(argv0, "delete")) {
                if (delete_mf(gc, mu, mf) == -1)
                    puts("[-] delete file error");
            } else if (!strcmp(argv0, "enter")) {
                if (enter_dir(mu, mf) == -1)
                    puts("[-] enter directory error");
            } else if (!strcmp(argv0, "read")) {
                if (read_mf(mu, mf) == -1)
                    puts("[-] read file error");
            } else if (!strcmp(argv0, "write")) {
                if (write_mf(mu, mf) == -1)
                    puts("[-] write file error");
            } else if (!strcmp(argv0, "enc")) {
                if (!argv2 || enc_mf(mu, mf, argv2) == -1)
                    puts("[-] encrypt file error");
            } else if (!strcmp(argv0, "dec")) {
                if (!argv2 || dec_mf(mu, mf, argv2) == -1)
                    puts("[-] deccrypt file error");
            } else if (!strcmp(argv0, "set")) {
                if (!argv2 || set_mf_prot(mu, mf, argv2) == -1)
                    puts("[-] set permission error");
            } else if (!strcmp(argv0, "unset")) {
                if (!argv2 || unset_mf_prot(mu, mf, argv2) == -1)
                    puts("[-] unset permission error");
            } else if (!strcmp(argv0, "softlink_setsrc")) {
                softlink_setsrc(mu, mf);
            } else if (!strcmp(argv0, "softlink_setdst")) {
                if (mf || softlink_setdst(mu, argv1) == -1)
                    puts("[-] softlink error");
            } else if (!strcmp(argv0, "hardlink_setsrc")) {
                hardlink_setsrc(mu, mf);
            } else if (!strcmp(argv0, "hardlink_setdst")) {
                if (mf || hardlink_setdst(mu, argv1) == -1)
                    puts("[-] hardlink error");
            }  else {
                puts("[-] unknown command");
            }
        }
            
    }    
}