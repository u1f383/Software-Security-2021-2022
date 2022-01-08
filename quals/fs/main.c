#include "fs.h"
#include "user.h"
#include "gc.h"
#include "list.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

GC *gc;
extern list_head rootfs;

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
    MyFile *tmp_mf = NULL, *tmp_dir = NULL;
    MyFile *rootfs_mf = container_of(rootfs.next, MyFile, next_file);
    MyUser *root = new_mu("root", rootfs_mf);
    int pipefd[2];
    int old_stdin, old_stdout;

    old_stdin = dup(STDIN_FILENO);
    old_stdout = dup(STDOUT_FILENO);
    pipe(pipefd);
    dup2(pipefd[0], STDIN_FILENO);
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[0]);
    close(pipefd[1]);

    // set rootfs as readable and writable
    set_mf_prot(root, rootfs_mf, "read,write");

    // Test 1. create directory and normal file
    if (create_mf(root, "dir", "test_dir") == -1)
        return -1;
    if (create_mf(root, "normfile", "test_file") == -1)
        return -1;
    
    // Test 2. update file and directory permission
    tmp_mf = get_mf_by_fname(root, "test_file");
    if (set_mf_prot(root, tmp_mf, "read") == -1)
        return -1;
    tmp_dir = get_mf_by_fname(root, "test_dir");
    if (set_mf_prot(root, tmp_dir, "read,write") == -1)
        return -1;

    // Test 3. change directory and create some files
    if (enter_dir(root, tmp_dir) == -1)
        return -1;
    if (create_mf(root, "dir", "test_dir") == -1)
        return -1;
    if (create_mf(root, "normfile", "test_file") == -1)
        return -1;
    if (create_mf(root, "normfile", "test_file2") == -1)
        return -1;
    
    // Test 4. read and write file
    char buf[0x10] = {0};
    tmp_mf = get_mf_by_fname(root, "test_file2");
    write(STDOUT_FILENO, "for test", 9);
    if (read_mf(root, tmp_mf) == -1)
        return -1;
    if (write_mf(root, tmp_mf) == -1)
        return -1;
    read(STDIN_FILENO, buf, 0x10);
    if (strcmp(buf, "for test"))
        return -1;
    
    // Test 5. encrypt and decrypt file
    if (enc_mf(root, tmp_mf, "AAAAAAAABBBBBBBB") == -1)
        return -1;
    if (dec_mf(root, tmp_mf, "AAAAAAAABBBBBBBB") == -1)
        return -1;
    if (write_mf(root, tmp_mf) == -1)
        return -1;
    read(STDIN_FILENO, buf, 0x10);
    if (strcmp(buf, "for test"))
        return -1;

    // Test 6. test softlink
    softlink_setsrc(root, tmp_mf);

    tmp_dir = get_mf_by_fname(root, "test_dir");
    if (enter_dir(root, tmp_dir) == -1)
        return -1;
    if (softlink_setdst(root, "will_fail") != -1)
        return -1;

    goto_rootfs(root);
    if (softlink_setdst(root, "will_ok") == -1)
        return -1;

    // restore environment
    dup2(old_stdin, STDIN_FILENO);
    dup2(old_stdout, STDOUT_FILENO);
    close(old_stdin);
    close(old_stdout);

    return 0;
}

void init_proc()
{
    // init garbage collector
    gc = new_gc();
    gc->gc_list_add = mf_gc_list_add;

    // init filesystem
    MyFile *_rootfs_mf = _new_dir(0, "");
    rootfs.next = &_rootfs_mf->next_file;
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
    MyFile *_rootfs_mf = container_of(rootfs.next, MyFile, next_file);
    MyFile *mf = NULL;
    MyUser *mu = new_mu("test", _rootfs_mf);

    while (1)
    {
        for (int i = 0; i < mu->dir_deep; i++)
            printf("%s/", mu->dir_stack[i]->fn);
        printf("> ");

        if (fgets(cmd, CMD_LEN, stdin) == NULL)
            pexit("[-] read command error");
        if (cmd[strlen(cmd) - 1] == '\n')
            cmd[strlen(cmd) - 1] = '\0';
        
        mf = NULL;
        argv0 = strtok(cmd, DELIM);
        argv1 = (argv0 != NULL) ? strtok(NULL, DELIM) : NULL;
        argv2 = (argv1 != NULL) ? strtok(NULL, DELIM) : NULL;

        if (!argv0)
            continue;

        if (!strcmp(argv0, "ls")) {
            list_dir(mu);
        } else if (!strcmp(argv0, "create")) {
            if (!argv1 || !argv2 || create_mf(mu, argv1, argv2) == -1)
                puts("[-] create file error");
        } else {
            if (argv1 && !strcmp(argv1, "..")) {
                if (mu->dir_deep == 1) {
                    puts("[-] at root directory");
                    continue;
                }
                mf = mu->dir_stack[mu->dir_deep - 2];
            }

            if (!mf && argv1)
                is_existed(&mf, mu->curr_dir, argv1);

            if (mf && !strcmp(argv0, "rm")) {
                if (delete_mf(gc, mu, mf) == -1)
                    puts("[-] delete file error");
            } else if ((mf || (argv1 && !strcmp(argv1, ".."))) &&
                        !strcmp(argv0, "cd")) {
                if (enter_dir(mu, mf) == -1)
                    puts("[-] enter directory error");
            } else if (mf && !strcmp(argv0, "read")) {
                if (read_mf(mu, mf) == -1)
                    puts("[-] read file error");
            } else if (mf && !strcmp(argv0, "write")) {
                if (write_mf(mu, mf) == -1)
                    puts("[-] write file error");
            } else if (mf && !strcmp(argv0, "info")) {
                show_fileinfo(mu, mf, 1);
            } else if (mf && !strcmp(argv0, "enc")) {
                if (!argv2 || enc_mf(mu, mf, argv2) == -1)
                    puts("[-] encrypt file error");
            } else if (mf && !strcmp(argv0, "dec")) {
                if (!argv2 || dec_mf(mu, mf, argv2) == -1)
                    puts("[-] deccrypt file error");
            } else if (mf && !strcmp(argv0, "set")) {
                if (!argv2 || set_mf_prot(mu, mf, argv2) == -1)
                    puts("[-] set permission error");
            } else if (mf && !strcmp(argv0, "unset")) {
                if (!argv2 || unset_mf_prot(mu, mf, argv2) == -1)
                    puts("[-] unset permission error");
            } else if (mf && !strcmp(argv0, "slss")) {
                softlink_setsrc(mu, mf);
            } else if (!strcmp(argv0, "slsd")) {
                if (mf || softlink_setdst(mu, argv1) == -1)
                    puts("[-] softlink error");
            } else if (mf && !strcmp(argv0, "hlss")) {
                hardlink_setsrc(mu, mf);
            } else if (!strcmp(argv0, "hlsd")) {
                if (mf || hardlink_setdst(mu, argv1) == -1)
                    puts("[-] hardlink error");
            }  else {
                if (argv1 && !mf)
                    puts("[-] file not found");
                else
                    puts("[-] unknown command");
            }
        }
            
    }    
}