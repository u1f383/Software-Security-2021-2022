#include "fs.h"
#include "user.h"
#include "gc.h"
#include "list.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

GC *gc;
extern list_head rootfs;

#define ENDL "\n"
static void banner()
{
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

static void usage()
{
    printf(
        "[add new user]" ENDL
        "   useradd <username> <password>" ENDL
        "[delete new user]" ENDL
        "   userdel <username> <password>" ENDL
        "[login]" ENDL
        "   login <username> <password>" ENDL
        "[create]" ENDL
        "   create dir <file_name>" ENDL
        "   create normfile <file_name>" ENDL
        "[delete]" ENDL
        "   rm <file_name>" ENDL
        "[enter dir]" ENDL
        "   cd <file_name>" ENDL
        "[read]" ENDL
        "   read <file_name>" ENDL
        "[write]" ENDL
        "   write <file_name>" ENDL
        "[encrypt]" ENDL
        "   enc <file_name>" ENDL
        "[decrypt]" ENDL
        "   dec <file_name>" ENDL
        "[set permission]" ENDL
        "   set <file_name> <prot>" ENDL
        "[unset permission]" ENDL
        "   unset <file_name> <prot>" ENDL
        "[list files]" ENDL
        "   ls" ENDL
        "[show info of file]" ENDL
        "   info <file_name>" ENDL
        "[set softlink source]" ENDL
        "   slss <file_name>" ENDL
        "[set softlink destination]" ENDL
        "   slsd <file_name>" ENDL
        "[set hardlink source]" ENDL
        "   hlss <file_name>" ENDL
        "[set hardlink destination]" ENDL
        "   hlsd <file_name>" ENDL
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
    MyUser *root = new_mu("root", "root", rootfs_mf);
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
    if (create_mf(root, "dir", "test_dir_L1") == -1)
        return -1;
    if (create_mf(root, "normfile", "test_file_L1") == -1)
        return -1;
    
    // Test 2. update file and directory permission
    tmp_mf = get_mf_by_fname(root, "test_file_L1");
    if (set_mf_prot(root, tmp_mf, "read") == -1)
        return -1;
    tmp_dir = get_mf_by_fname(root, "test_dir_L1");
    if (set_mf_prot(root, tmp_dir, "read,write") == -1)
        return -1;

    // Test 3. change directory and create some files
    if (enter_dir(root, tmp_dir) == -1)
        return -1;
    if (create_mf(root, "dir", "test_dir_L2") == -1)
        return -1;
    if (create_mf(root, "normfile", "test_file_L2") == -1)
        return -1;
    if (create_mf(root, "normfile", "test_file2_L2") == -1)
        return -1;
    
    // Test 4. read and write file
    char buf[0x20] = {0};
    char buf2[0x20] = {0};
    int flag1_fd = open("/home/myfs/flag1.txt", O_RDONLY);
    int flag_len;
    
    if (flag1_fd == -1)
        return -1;
    read(flag1_fd, buf, 0x10);
    close(flag1_fd);


    if ((flag_len = strlen(buf)) >= 0x10)
        return -1;
    
    tmp_mf = get_mf_by_fname(root, "test_file2_L2");
    write(STDOUT_FILENO, buf, flag_len);
    if (read_mf(root, tmp_mf) == -1)
        return -1;
    if (write_mf(root, tmp_mf) == -1)
        return -1;
    read(STDIN_FILENO, buf2, flag_len);
    if (strcmp(buf, buf2))
        return -1;
    unlink("/home/myfs/flag1.txt");
    
    // Test 5. encrypt and decrypt file
    if (enc_mf(root, tmp_mf) == -1)
        return -1;
    if (dec_mf(root, tmp_mf) == -1)
        return -1;
    if (write_mf(root, tmp_mf) == -1)
        return -1;
    read(STDIN_FILENO, buf2, flag_len);
    if (strcmp(buf, buf2))
        return -1;

    // Test 6. test softlink
    softlink_setsrc(root, tmp_mf);

    tmp_dir = get_mf_by_fname(root, "test_dir_L2");
    if (enter_dir(root, tmp_dir) == -1)
        return -1;
    if (softlink_setdst(root, "sl_will_fail") != -1)
        return -1;

    goto_rootfs(root);
    if (softlink_setdst(root, "sl_will_ok") == -1)
        return -1;
    tmp_mf = get_mf_by_fname(root, "sl_will_ok");
    if (delete_mf(gc, root, tmp_mf) == -1)
        return -1;
    
    // Test 7. test hardlink
    tmp_dir = get_mf_by_fname(root, "test_dir_L1");
    if (enter_dir(root, tmp_dir) == -1)
        return -1;

    tmp_mf = get_mf_by_fname(root, "test_file2_L2");
    hardlink_setsrc(root, tmp_mf);

    tmp_dir = get_mf_by_fname(root, "test_dir_L2");

    if (enter_dir(root, tmp_dir) == -1)
        return -1;
    if (hardlink_setdst(root, "hl_will_fail") != -1)
        return -1;

    goto_rootfs(root);
    if (hardlink_setdst(root, "hl_will_ok") == -1)
        return -1;
    tmp_mf = get_mf_by_fname(root, "hl_will_ok");
    if (delete_mf(gc, root, tmp_mf) == -1)
        return -1;

    // Test 8. create and delete user
    MyUser *_new_mu = new_mu("test", "test", rootfs_mf);
    if (delete_mu("root", "root", root) != -1)
        return -1;
    if (delete_mu("root", "root", _new_mu) == -1)
        return -1;

    memset(buf, 0, 0x10);
    int flag2_fd = open("/home/myfs/flag2.txt", O_RDONLY);
    if (flag2_fd == -1)
        return -1;
    read(flag2_fd, buf, 0x10);
    close(flag2_fd);

    if ((flag_len = strlen(buf)) >= 0x10)
        return -1;

    tmp_mf = get_mf_by_fname(root, "test_file_L1");
    write(STDOUT_FILENO, buf, flag_len);
    if (read_mf(root, tmp_mf) == -1)
        return -1;
    if (enc_mf(root, tmp_mf) == -1)
        return -1;
    unlink("/home/myfs/flag2.txt");

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
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

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
    MyUser *mu = new_mu("user1", "1234", _rootfs_mf);


    if (mu == NULL)
        pexit("[-] create user error");

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
            if (!argv1 || !argv2 || 
                is_existed(&mf, mu->curr_dir, argv2) ||
                create_mf(mu, argv1, argv2) == -1)
                puts("[-] create file error");
        } else if (argv1 && argv2 && !strcmp(argv0, "useradd")) {
            if (new_mu(argv1, argv2, _rootfs_mf) == NULL)
                puts("[-] change user error");
        } else if (argv1 && argv2 && !strcmp(argv0, "userdel")) {
            if (delete_mu(argv1, argv2, mu) == -1)
                puts("[-] change user error");
        } else if (argv1 && argv2 && !strcmp(argv0, "login")) {
            MyUser *tmp_mu = login_mu(argv1, argv2);
            if (tmp_mu == NULL)
                puts("[-] change user error");
            else
                mu = tmp_mu;
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
                if (enc_mf(mu, mf) == -1)
                    puts("[-] encrypt file error");
            } else if (mf && !strcmp(argv0, "dec")) {
                if (dec_mf(mu, mf) == -1)
                    puts("[-] decrypt file error");
            } else if (mf && !strcmp(argv0, "set")) {
                if (!argv2 || set_mf_prot(mu, mf, argv2) == -1)
                    puts("[-] set permission error");
            } else if (mf && !strcmp(argv0, "unset")) {
                if (!argv2 || unset_mf_prot(mu, mf, argv2) == -1)
                    puts("[-] unset permission error");
            } else if (mf && !strcmp(argv0, "slss")) {
                softlink_setsrc(mu, mf);
            } else if (!strcmp(argv0, "slsd")) {
                if (mf || !argv1 || softlink_setdst(mu, argv1) == -1)
                    puts("[-] softlink error");
            } else if (mf && !strcmp(argv0, "hlss")) {
                hardlink_setsrc(mu, mf);
            } else if (!strcmp(argv0, "hlsd")) {
                if (mf || !argv1 || hardlink_setdst(mu, argv1) == -1)
                    puts("[-] hardlink error");
            } else if (!strcmp(argv0, "help") || !strcmp(argv0, "?")) {
                usage();
            } else {
                if (argv1 && !mf)
                    puts("[-] file not found");
                else
                    puts("[-] unknown command");
            }
        }
            
    }    
}