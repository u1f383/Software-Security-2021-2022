#include "fs.h"
#include "list.h"
#include "gc.h"
#include "mycrypto.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

list_head rootfs = { .next = NULL };
extern unsigned char key[17];

MyFile *__new_mf()
{
    MyFile *mf = (MyFile *) malloc(sizeof(MyFile));
    mf->fid = mf_cnt++;
    mf->uid = 0;
    mf->refcnt = 1;
    mf->size = 0;
    mf->metadata = 0;
    mf->data.ino = NULL;
    mf->dir_hd.next = NULL;
    mf->next_file.next = NULL;
    return mf;
}

MyFile *_new_normfile(uint8_t uid, char *fn)
{
    MyFile *mf = __new_mf();
    mf->uid = uid;
    mf->fn = strdup(fn);
    mf->data.ino = (iNode *) malloc(sizeof(iNode));
    mf->data.ino->refcnt = 1;
    return mf;
}

MyFile *_new_dir(uint8_t uid, char *fn)
{
    MyFile *mf = _new_normfile(uid, fn);
    mf->metadata |= MF_META_TYPE_IS_DIR;
    return mf;
}

MyFile *_new_slink(uint8_t uid, MyFile *link, char *fn)
{
    MyFile *mf = __new_mf();
    mf->uid = uid;
    mf->data.link = link;
    mf->metadata |= MF_META_TYPE_IS_SLINK;
    mf->fn = strdup(fn);

    link->refcnt++;
    return mf;
}

MyFile *_new_hlink(uint8_t uid, MyFile *link, char *fn)
{
    MyFile *mf = __new_mf();
    mf->uid = uid;
    mf->data.ino = link->data.ino;
    mf->size = link->size;
    mf->metadata |= (MF_META_TYPE_IS_HLINK | link->metadata);
    mf->fn = strdup(fn);

    link->data.ino->refcnt++;
    return mf;
}

MyFile* _get_mf_by_fname(MyFile *dir, char *fn)
{
    MyFile *curr_mf = NULL;
    list_head *curr = dir->dir_hd.next;
    
    while (curr) {
        curr_mf = container_of(curr, MyFile, next_file);
        if (!strcmp(curr_mf->fn, fn))
            return curr_mf;
        curr = curr->next;
    }
    return NULL;
}

MyFile* get_mf_by_fname(MyUser *mu, char *fn)
{
    return _get_mf_by_fname(mu->curr_dir, fn);
}

int create_mf(MyUser *mu, char *type, char *fn)
{
    MyFile *mf = NULL;

    if (mu->curr_dir->uid != mu->uid &&
        !mf_is_writable(mu->curr_dir))
        return -1;

    if (!strcmp(type, "dir"))
        mf = _new_dir(mu->uid, fn);
    else if (!strcmp(type, "normfile"))
        mf = _new_normfile(mu->uid, fn);
    else
        return -1;
    
    list_add(&mu->curr_dir->dir_hd, &mf->next_file);
    mu->curr_dir->size++;
    return 0;
}

void show_fileinfo(MyUser *mu, MyFile *mf, uint8_t all_name)
{
    const char *prot = NULL;
    const char *uname = NULL;
    const char *type = NULL;

    if (mf_is_slink(mf))
        type = "s";
    else if (mf_is_normfile(mf))
        type = "-";
    else if (mf_is_dir(mf))
        type = "d";
    else
        return;

    if (mf_is_readable(mf) && mf_is_writable(mf))
        prot = "rw";
    else if (mf_is_readable(mf))
        prot = "r-";
    else if (mf_is_writable(mf))
        prot = "-w";
    else
        prot = "--";

    uname = get_uname_by_uid(mf->uid);
    if (uname == NULL)
        return;

    if (all_name) {
        printf("%srw----%s- %-32s%8u %s\n", type, prot, uname, mf->size, mf->fn);
    } else {
        char buf[0x20] = {0};
        memset(buf, '.', 0x1f);
        if (strlen(mf->fn) >= 0x1f)
            memcpy(buf, mf->fn, 0x1c);
        else
            strcpy(buf, mf->fn);
        
        printf("%srw----%s- %-32s%8u %-32s\n", type, prot, uname, mf->size, buf);
    }
}

int delete_mf(GC *gc, MyUser *mu, MyFile *mf)
{
    /**
     * if there are some files in the directory,
     * we cannot delete the directory
     */
    if (mf_is_dir(mf) && mf->size > 0)
        return -1;
    
    /**
     * even though file is removed from current directory,
     * it is maybe softlinked by other file
     */
    list_delete(&mu->curr_dir->dir_hd, &mf->next_file);
    mu->curr_dir->size--;
    
    mf->fid = -1;
    mf->refcnt--;
    
    // we use gc as we can
    if (gc)
        return gc->gc_list_add(gc, &mf->next_file);
    return _release_mf(mf);
}

int enter_dir(MyUser *mu, MyFile *mf)
{
    while (mf && mf_is_slink(mf))
        mf = mf->data.link;

    if (!mf || mf_is_deleted(mf) || !mf_is_dir(mf))
        return -1;

    if (mf->uid != mu->uid && !mf_is_readable(mf))
        return -1;

    if (mf == mu->dir_stack[mu->dir_deep - 2]) {
        // cd ..
        mu->dir_stack[mu->dir_deep - 1] = NULL;
        mu->dir_deep--;
    } else {
        if (mu->dir_deep == MU_DIR_MAX_DEEP)
            return -1;
        mu->dir_deep++;
        mu->dir_stack[mu->dir_deep - 1] = mf;
    }
    mu->curr_dir = mf;
    return 0;
}

int goto_rootfs(MyUser *mu)
{
    for (; mu->dir_deep != 1; mu->dir_deep--)
        mu->dir_stack[mu->dir_deep - 1] = NULL;

    mu->curr_dir = mu->dir_stack[0];
    return 0;
}

int enc_mf(MyUser *mu, MyFile *mf)
{
    while (mf && mf_is_slink(mf))
        mf = mf->data.link;

    if (!mf || mf_is_deleted(mf) || !mf_is_normfile(mf) ||
        mf_is_enc(mf) || mf->data.ino->content == NULL)
        return -1;

    if (mf->uid != mu->uid && !mf_is_readable(mf))
        return -1;

    if (my_encrypt(mf->data.ino->content, &mf->size) == -1)
        return -1;
    mf->metadata |= MF_META_ENCED;

    return 0;
}

int dec_mf(MyUser *mu, MyFile *mf)
{
    while (mf && mf_is_slink(mf))
        mf = mf->data.link;

    if (!mf || mf_is_deleted(mf) || !mf_is_normfile(mf) ||
        !mf_is_enc(mf) || mf->data.ino->content == NULL)
        return -1;

    if (mf->uid != mu->uid && !mf_is_readable(mf))
        return -1;

    if (my_decrypt(mf->data.ino->content, &mf->size) == -1)
        return -1;
    mf->metadata &= ~MF_META_ENCED;

    return 0;
}

int read_mf(MyUser *mu, MyFile *mf)
{
    while (mf && mf_is_slink(mf))
        mf = mf->data.link;

    if (!mf || mf_is_deleted(mf) || !mf_is_normfile(mf))
        return -1;

    if (mf->uid != mu->uid && !mf_is_readable(mf))
        return -1;
    
    char buf[MF_SIZE_MAX];
    int nr;

    if (mf_is_enc(mf))
        return read(STDIN_FILENO, mf->data.ino->content, mf->size);

    nr = read(STDIN_FILENO, buf, MF_SIZE_MAX);
    if (nr == -1)
        return -1;

    uint16_t tmp = mf->size % 0x10;
    int16_t chk_min = tmp >= 0x9 ? (mf->size - tmp + 0x9) : (mf->size - tmp - 0x7);
    int16_t chk_max = chk_min + 0xf;
    
    if (!mf->size || chk_min < 0 || chk_max < 0 || chk_min > nr || chk_max < nr)
        mf->data.ino->content = realloc(mf->data.ino->content, nr + 0x10);
        
    mf->size = nr;
    memcpy(mf->data.ino->content, buf, mf->size);
    return nr;
}

ssize_t write_mf(MyUser *ms, MyFile *mf)
{
    while (mf && mf_is_slink(mf))
        mf = mf->data.link;

    if (!mf || mf_is_deleted(mf) || !mf_is_normfile(mf))
        return -1;

    if (mf_is_enc(mf))
        return hexdump(mf->data.ino->content, AES_BLOCK_SIZE);
    
    if (mf->uid != ms->uid && !mf_is_writable(mf))
        return -1;

    return write(STDOUT_FILENO, mf->data.ino->content, mf->size);
}

int set_mf_prot(MyUser *ms, MyFile *mf, char *prot)
{
    while (mf && mf_is_slink(mf))
        mf = mf->data.link;

    if (!mf || mf_is_deleted(mf))
        return -1;
        
    if (mf->uid != ms->uid && !mf_is_writable(mf))
        return -1;

    if (!strcmp(prot, "read"))
        mf->metadata |= MF_META_PROT_READ;
    else if (!strcmp(prot, "write"))
        mf->metadata |= MF_META_PROT_WRITE;
    else if (!strcmp(prot, "read,write"))
        mf->metadata |= (MF_META_PROT_WRITE | MF_META_PROT_READ);
    
    return 0;
}

int unset_mf_prot(MyUser *ms, MyFile *mf, char *prot)
{
    while (mf && mf_is_slink(mf))
        mf = mf->data.link;

    if (!mf || mf_is_deleted(mf))
        return -1;

    if (mf->uid != ms->uid && !mf_is_writable(mf))
        return -1;

    if (!strcmp(prot, "read"))
        mf->metadata &= ~MF_META_PROT_READ;
    else if (!strcmp(prot, "write"))
        mf->metadata &= ~MF_META_PROT_WRITE;
    else if (!strcmp(prot, "read,write"))
        mf->metadata &= ~(MF_META_PROT_WRITE | MF_META_PROT_READ);

    return 0;
}

void list_dir(MyUser *mu)
{
    MyFile *curr_mf = NULL;
    list_head *curr = mu->curr_dir->dir_hd.next;

    printf("total %u\n", mu->curr_dir->size);
    while (curr) {
        curr_mf = container_of(curr, MyFile, next_file);
        show_fileinfo(mu, curr_mf, 0);
        curr = curr->next;
    }
}

void softlink_setsrc(MyUser *mu, MyFile *mf)
{
    mu->softlink = mf;
}

int softlink_setdst(MyUser *mu, char *fn)
{
    if (!mu->softlink)
        return -1;

    // we hope a file not to link file of higher layer
    if (!is_desc(mu->curr_dir, mu->softlink))
        return -1;
    
    MyFile *mf = _new_slink(mu->uid, mu->softlink, fn);
    list_add(&mu->curr_dir->dir_hd, &mf->next_file);
    mu->curr_dir->size++;
    mu->softlink = NULL;
    return 0;
}

void hardlink_setsrc(MyUser *mu, MyFile *mf)
{
    mu->hardlink = mf;
}

int hardlink_setdst(MyUser *mu, char *fn)
{
    if (!mu->hardlink)
        return -1;

    // we hope a file not to link file of higher layer
    if (!is_desc(mu->curr_dir, mu->hardlink))
        return -1;

    // sorry we don't support other types currently
    if (!mf_is_normfile(mu->hardlink))
        return -1;
    
    MyFile *mf = _new_hlink(mu->uid, mu->hardlink, fn);
    list_add(&mu->curr_dir->dir_hd, &mf->next_file);
    mu->curr_dir->size++;
    mu->hardlink = NULL;
    return 0;
}

int mf_gc_list_add(GC *gc, list_head *hd)
{
    list_add(&gc->next_g, hd);

    if (++gc->delcnt % 0x10)
        return 0;

    // if there are 16 deleted files, sweep them
    MyFile *curr_mf = NULL;
    list_head *curr = gc->next_g.next, *next = NULL;

    while (curr) {
        next = curr->next;
        curr_mf = container_of(curr, MyFile, next_file);
        if (_release_mf(curr_mf) == -1)
            return -1;
        curr = next;
    }
    return 0;
}

int _release_mf(MyFile *mf)
{
    /**
     * if there is a softlink linked to file being deleted at least,
     * we just do nothing, waiting for softlink checking to release it
     */
    MyFile *root = container_of(rootfs.next, MyFile, next_file);
    if (mf->refcnt)
        return 0;

    if (mf_is_hlink(mf))
        if (--mf->data.ino->refcnt != 0)
            goto ret;
    
    if (mf_is_normfile(mf)) {
        free(mf->data.ino->content);
        free(mf->data.ino);
    } else if (mf_is_dir(mf)) {
        free(mf->data.ino);
    } else if (mf_is_slink(mf)) {
        // try to release softlink target
        _release_mf(mf->data.link);
    } else {
        return -1;
    }

ret:
    free(mf->fn);
    free(mf);
    return 0;
}

int is_desc(MyFile *curr_mf, MyFile *target)
{
    list_head *curr = curr_mf->dir_hd.next;
    while (curr) {
        curr_mf = container_of(curr, MyFile, next_file);
        
        if (target == curr_mf)
            return 1;
        
        if (mf_is_dir(curr_mf) && is_desc(curr_mf, target))
            return 1;

        curr = curr->next;
    }

    return 0;
}

int is_ref_by_other(MyFile *dir, MyFile *target)
{
    MyFile *curr_mf = NULL;
    list_head *curr = dir->dir_hd.next;

    while (curr) {
        curr_mf = container_of(curr, MyFile, next_file);
        if (mf_is_slink(curr_mf) && target == curr_mf->data.link) {
            return 1;
        } else if (mf_is_dir(curr_mf) && is_ref_by_other(curr_mf, target)) {
            return 1;
        }
        curr = curr->next;
    }

    return 0;
}

int is_existed(MyFile **mf, MyFile *curr_dir, char *fn)
{
    if ((*mf = _get_mf_by_fname(curr_dir, fn)) != NULL)
        return 1;
    return 0;
}