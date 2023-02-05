#ifndef _FS_H_
#define _FS_H_

#include "list.h"
#include "gc.h"
#include <stdint.h>
#include <sys/types.h>

#define MF_SIZE_INIT 0x100
#define MF_SIZE_MAX  0x1000
#define MF_META_PROT_READ     0b00000001
#define MF_META_PROT_WRITE    0b00000010
#define MF_META_ENCED         0b00000100
#define MF_META_TYPE_IS_DIR   0b00001000
#define MF_META_TYPE_IS_SLINK 0b00010000
#define MF_META_TYPE_IS_HLINK 0b00100000

static int8_t mf_cnt = 0;

typedef struct iNode
{
    char *content;
    uint8_t refcnt;
} iNode;

typedef struct _MyFile
{
    int8_t fid;
    uint8_t uid;
    uint8_t refcnt;
    uint8_t metadata;
    uint16_t size;
    
    char *fn;
    union
    {
        iNode *ino;
        struct _MyFile *link;
    } data;
    
    list_head dir_hd;
    list_head next_file;
} MyFile;

static inline int mf_is_readable(MyFile *mf)
{
    return (mf->metadata & MF_META_PROT_READ) != 0;
}

static inline int mf_is_writable(MyFile *mf)
{
    return (mf->metadata & MF_META_PROT_WRITE) != 0;
}

static inline int mf_is_deleted(MyFile *mf)
{
    return mf->fid == -1;
}

static inline int mf_is_enc(MyFile *mf)
{
    return (mf->metadata & MF_META_ENCED) != 0;
}

static inline int mf_is_dir(MyFile *mf)
{
    return (mf->metadata & MF_META_TYPE_IS_DIR) != 0;
}

static inline int mf_is_slink(MyFile *mf)
{
    return (mf->metadata & MF_META_TYPE_IS_SLINK) != 0;
}

static inline int mf_is_hlink(MyFile *mf)
{
    return (mf->metadata & MF_META_TYPE_IS_HLINK) != 0;
}

static inline int mf_is_normfile(MyFile *mf)
{
    return ((mf->metadata & MF_META_TYPE_IS_SLINK) |
            (mf->metadata & MF_META_TYPE_IS_HLINK) |
            (mf->metadata & MF_META_TYPE_IS_DIR)) == 0;
}

MyFile *__new_mf();

MyFile *_new_normfile(uint8_t uid, char *fn);
MyFile *_new_dir(uint8_t uid, char *fn);
MyFile *_new_slink(uint8_t uid, MyFile *link, char *fn);
MyFile *_new_hlink(uint8_t uid, MyFile *link, char *fn);
MyFile *_get_mf_by_fname(MyFile *hd, char *fn);

int _release_mf();

int is_desc(MyFile *curr_mf, MyFile *target);
int is_existed(MyFile **mf, MyFile *curr_dir, char *fn);
int is_ref_by_other(MyFile *_root, MyFile *target);

int mf_gc_list_add(GC *gc, list_head *hd);


#include "user.h"
MyFile *get_mf_by_fname(MyUser *mu, char *fn);
/**
 * create_mf(): create file 
 * > create dir <file_name>
 * > create normfile <file_name>
 */
int create_mf(MyUser *mu, char *type, char *fn);

/**
 * delete_mf(): delete file
 * > rm <file_name>
 */
int delete_mf(GC *gc, MyUser *mu, MyFile *mf);

/**
 * enter_dir(): enter a directory
 * > cd <file_name>
 */
int enter_dir(MyUser *mu, MyFile *mf);
int goto_rootfs(MyUser *mu);

/**
 * read_mf(): read data from stdin and write to file
 * > read <file_name>
 */
int read_mf(MyUser *mu, MyFile *mf);

/**
 * write_mf(): write file content to stdout
 * > write <file_name>
 */
ssize_t write_mf(MyUser *mu, MyFile *mf);

/**
 * enc_mf(): encrypt file
 * > enc <file_name>
 */
int enc_mf(MyUser *mu, MyFile *mf);

/**
 * dec_mf(): decrypt file
 * > dec <file_name>
 */
int dec_mf(MyUser *mu, MyFile *mf);

/**
 * set_mf_prot(): set the prot of file
 * > set <file_name> <prot>
 */
int set_mf_prot(MyUser *ms, MyFile *mf, char *prot);

/**
 * unset_mf_prot(): unset the prot of file
 * > unset <file_name> <prot>
 */
int unset_mf_prot(MyUser *ms, MyFile *mf, char *prot);

/**
 * show_fileinfo(): show the information of file
 * > info <file_name>
 */
void show_fileinfo(MyUser *mu, MyFile *mf, uint8_t all_name);

/**
 * list_file(): list files in the current directory
 * > ls
 */
void list_dir(MyUser *mu);

/**
 * softlink_setsrc(): set the source file of softlink
 * > slss <file_name>
 */
void softlink_setsrc(MyUser *mu, MyFile *mf);

/**
 * softlink_setdst(): set the destination file of softlink
 * > slsd <file_name>
 */
int softlink_setdst(MyUser *mu, char *fn);

/**
 * hardlink_setsrc(): set the source file of hardlink
 * > hlss <file_name>
 */
void hardlink_setsrc(MyUser *mu, MyFile *mf);

/**
 * hardlink_setdst(): set the destination file of hardlink
 * > hlsd <file_name>
 */
int hardlink_setdst(MyUser *mu, char *fn);

#endif