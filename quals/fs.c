#include "fs.h"
#include "list.h"
#include "gc.h"
#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

list_head fs_root = { .next = NULL };

MyFile *__new_mf()
{
    MyFile *mf = (MyFile *) malloc(sizeof(MyFile));
    mf->fid = mf_cnt++;
    mf->uid = -1;
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
    MyFile *curr = container_of(dir->dir_hd.next, MyFile, next_file);
    while (curr) {
        if (!strcmp(curr->fn, fn))
            return curr;
        curr = container_of(curr->next_file.next, MyFile, next_file);
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
    if (is_existed(&mf, mu->curr_dir, fn))
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

void show_fileinfo(MyUser *mu, MyFile *mf)
{
    const char *prot = NULL;

    if (mf_is_readable(mf) && mf_is_writable(mf))
        prot = "RW";
    else if (mf_is_readable(mf))
        prot = "R-";
    else if (mf_is_writable(mf))
        prot = "-W";
    else
        prot = "--";

    printf("%s\t%d  %d  %u  %s\n", mf->fn, mf->fid, mf->uid, mf->size, prot);
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
    if (mu->dir_deep == DIR_MAX_DEEP)
        return -1;

    while (mf_is_slink(mf))
        mf = mf->data.link;

    if (!mf_is_dir(mf))
        return -1;

    if (mf == mu->dir_stack[mu->dir_deep - 2]) {
        // enter ..
        mu->dir_stack[mu->dir_deep - 1] = NULL;
        mu->dir_deep--;
    } else {
        mu->dir_deep++;
        mu->dir_stack[mu->dir_deep - 1] = mu->curr_dir;
    }
    mu->curr_dir = mf;
    return 0;
}

int enc_mf(MyUser *mu, MyFile *mf, char *key)
{
    while (mf_is_slink(mf))
        mf = mf->data.link;

    if (!mf_is_normfile(mf))
        return -1;

    if (mf->uid != mu->uid && mf_is_readable(mf) && mf_is_writable(mf))
        return -1;

    if (my_encrypt(mf->data.ino->content, key, mf->size) == -1)
        return -1;
    mf->metadata |= MF_META_ENCED;

    return 0;
}

int dec_mf(MyUser *mu, MyFile *mf, char *key)
{
    while (mf_is_slink(mf))
        mf = mf->data.link;

    if (!mf_is_normfile(mf))
        return -1;

    if (mf->uid != mu->uid && mf_is_readable(mf) && mf_is_writable(mf))
        return -1;

    if (my_decrypt(mf->data.ino->content, key, mf->size) == -1)
        return -1;
    mf->metadata &= ~MF_META_ENCED;

    return 0;
}

int read_mf(MyUser *mu, MyFile *mf)
{
    while (mf_is_slink(mf))
        mf = mf->data.link;

    if (mf_is_deleted(mf) || !mf_is_normfile(mf))
        return -1;

    if (mf->uid != mu->uid && mf_is_readable(mf))
        return -1;
    
    char buf[MF_SIZE_MAX];
    int nr;
    nr = read(STDIN_FILENO, buf, MF_SIZE_MAX);
    if (nr != -1) {
        mf->size = nr;
        mf->data.ino->content = realloc(mf->data.ino->content, mf->size);
        memcpy(mf->data.ino->content, buf, mf->size);
    }
    return nr;
}

ssize_t write_mf(MyUser *ms, MyFile *mf)
{
    while (mf_is_slink(mf))
        mf = mf->data.link;
        
    if (mf_is_deleted(mf) || !mf_is_normfile(mf))
        return -1;

    if (mf->uid != ms->uid && mf_is_writable(mf))
        return -1;
    
    ssize_t wn;
    wn = write(STDOUT_FILENO, mf->data.ino->content, mf->size);
    return wn;
}

int set_mf_prot(MyUser *ms, MyFile *mf, char *prot)
{
    while (mf_is_slink(mf))
        mf = mf->data.link;
        
    if (mf_is_deleted(mf) || !mf_is_normfile(mf))
        return -1;

    if (mf->uid != ms->uid && mf_is_writable(mf))
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
    while (mf_is_slink(mf))
        mf = mf->data.link;
        
    if (mf_is_deleted(mf) || !mf_is_normfile(mf))
        return -1;

    if (mf->uid != ms->uid && mf_is_writable(mf))
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
    MyFile *curr = container_of(mu->curr_dir->dir_hd.next, MyFile, next_file);
    while (curr) {
        show_fileinfo(curr);
        curr = container_of(curr->next_file.next, MyFile, next_file);
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
    if (is_desc(mu->curr_dir, mu->softlink))
        return -1;
    
    MyFile *mf = _new_slink(mu->uid, mu->softlink, fn);
    list_add(&mu->curr_dir->dir_hd, &mf->next_file);
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
    if (is_desc(mu->curr_dir, mu->hardlink))
        return -1;

    // sorry we don't support other types currently
    if (!mf_is_normfile(mu->hardlink))
        return -1;
    
    MyFile *mf = _new_hlink(mu->uid, mu->hardlink, fn);
    list_add(&mu->curr_dir->dir_hd, &mf->next_file);
    mu->hardlink = NULL;
    return 0;
}

int mf_gc_list_add(GC *gc, list_head *hd)
{
    MyFile *mf = container_of(hd, MyFile, next_file);
    list_add(&gc->next_g, hd);

    if (gc->delcnt++ % 0x10)
        return 0;

    // if there are 16 deleted files, sweep them
    MyFile *curr, *next;
    curr = container_of(gc->next_g.next, MyFile, next_file);

    while (curr) {
        next = container_of(curr->next_file.next, MyFile, next_file);
        if (_release_mf(curr) == -1)
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
    MyFile *root = container_of(fs_root.next, MyFile, next_file);
    if (is_ref_by_other(root, mf))
        return 0;

    free(mf->fn);

    if (mf_is_hlink(mf))
        if (mf->data.ino->refcnt-- != 0)
            return 0;
            
    if (mf_is_normfile(mf)) {
        free(mf->data.ino->content);
        free(mf->data.ino);
    } else if (mf_is_dir(mf)) {
        free(mf->data.ino);
    } else if (mf_is_slink(mf)) {
        // try to release softlink target
        mf->data.link = NULL;
        _release_mf(mf->data.link);
    } else {
        return -1;
    }

    free(mf);
    return 0;
}

int is_desc(MyFile *curr, MyFile *target)
{
    while (curr) {
        if (target == curr)
            return 1;
        
        if (mf_is_dir(curr)) {
            MyFile *next_dir = container_of(curr->dir_hd.next,
                                        MyFile, next_file);
            if (is_desc(next_dir, target))
                return 1;
        }
        curr = container_of(curr->next_file.next, MyFile, next_file);
    }

    return 0;
}

int is_ref_by_other(MyFile *root, MyFile *target)
{
    while (root) {
        if (mf_is_slink(root) && target == root->data.link) {
            return 1;
        } else if (mf_is_dir(root)) {
            MyFile *next_dir = container_of(root->dir_hd.next,
                                        MyFile, next_file);
            if (is_ref_by_other(next_dir, target))
                return 1;
        }
        root = container_of(root->next_file.next, MyFile, next_file);
    }

    return 0;
}

int is_existed(MyFile **mf, MyFile *curr_dir, char *fn)
{
    if ((*mf = _get_mf_by_fname(curr_dir, fn)) != NULL)
        return 1;
    return 0;
}