#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#define MAX_BOOK_NUM 0x10

typedef struct _Book {
    char *name;
    unsigned long index;
    unsigned long price;
    unsigned long namelen;
} Book;

Book* books[ MAX_BOOK_NUM ];

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

void show_book(Book *book)
{
    printf("Index:\t%lu\n", book->index);
    printf("Name:\t%s\n", book->name);
    printf("Price:\t%lu\n", book->price);
}

void add_book()
{
    unsigned long idx = 0;
    unsigned long namelen = 0;

    printf("Index: ");
    idx = readu64();
    if (idx >= MAX_BOOK_NUM || books[idx]) {
        puts("Invalid");
        return;
    }
    printf("Length of name: ");
    namelen = readu64();

    if (namelen >= 0x440) {
        puts("Too long");
        return;
    }

    books[idx] = (Book *) malloc(sizeof(Book));
    books[idx]->name = malloc(namelen);
    books[idx]->price = 0;
    books[idx]->index = idx;
    books[idx]->index = namelen;

    printf("Name: ");
    readstr(books[idx]->name, namelen);

    printf("Price: ");
    books[idx]->price = readu64();

    puts("Create book successfully !");
    show_book(books[idx]);
}

void delete_book()
{
    unsigned long idx = 0;
    
    printf("Which book do you want to delete: ");
    idx = readu64();
    if (!books[idx]) {
        puts("Invalid");
        return;
    }

    free(books[idx]->name);
    free(books[idx]);
}

void edit_book()
{
    unsigned long idx = 0;
    
    printf("Which book do you want to edit: ");
    idx = readu64();
    if (!books[idx]) {
        puts("Invalid");
        return;
    }

    printf("Name: ");
    readstr(books[idx]->name, 0x20);

    printf("Price: ");
    books[idx]->price = readu64();

    puts("Edit book successfully !");
    show_book(books[idx]);
}

void list_book()
{
    for (int i = 0; i < MAX_BOOK_NUM; i++) {
        if (books[i]) {
            puts("--------------------");
            show_book(books[i]);
        }
    }
}

void get_name_from_idx()
{
    unsigned long idx = 0;

    printf("Index: ");
    idx = readu64();
    if (books[idx])
        printf("Name: %s\n", books[idx]->name);
    else
        puts("Not found");
}

int main()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    unsigned long opt = 0;
    while (1)
    {
        printf("--- happy bookstore ---\n"
                "1. add book\n"
                "2. delete book\n"
                "3. edit book\n"
                "4. list books\n"
                "5. find book\n"
                "6. leave\n"
                "> ");
        
        opt = readu64();
        switch (opt) {
            case 1:
                add_book();
                break;
            case 2:
                delete_book();
                break;
            case 3:
                edit_book();
                break;
            case 4:
                list_book();
                break;
            case 5:
                get_name_from_idx();
                break;
            case 6:
                puts("Goodbye~");
                goto leave;
            default:
                puts("Invalid");
                break;
        }
    }

leave:
    return 0;
}