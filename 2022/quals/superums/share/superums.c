#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct Note
{
    unsigned short size;
    char *data;
};

struct Note *notes[0x10];

static unsigned short get_idx()
{
    unsigned short idx;

    printf("index\n> ");
    scanf("%hu", &idx);

    if (idx >= 0x10)
        printf("no, no ...\n"), exit(1);
    
    return idx;
}

static unsigned short get_size()
{
    unsigned short size;

    printf("size\n> ");
    scanf("%hu", &size);
    
    if (size > 0x78)
        printf("no, no ...\n"), exit(1);
    
    return size;
}

void add_note()
{
    unsigned short idx;

    idx = get_idx();
    if (notes[idx])
        printf("no, no ...\n"), exit(1);

    notes[idx] = malloc(sizeof(*notes[idx]));
    printf("success!\n");
}

void edit_data()
{
    unsigned short idx;
    unsigned short size;

    idx = get_idx();
    if (!notes[idx])
        printf("no, no ...\n"), exit(1);
    
    size = get_size();
    if (!notes[idx]->data) {
        notes[idx]->data = malloc(size);
        notes[idx]->size = size;
    }
        
    if (size > notes[idx]->size)
        printf("no, no ...\n"), exit(1);
    
    read(0, notes[idx]->data, size);
    printf("success!\n");
}

void del_note()
{
    short int idx;

    idx = get_idx();
    free(notes[idx]->data);
    free(notes[idx]);

    notes[idx] = NULL;
    printf("success!\n");
}

void show_notes()
{
    for (int i = 0; i < 0x10; i++) {
        if (notes[i] == NULL || notes[i]->data == NULL)
            continue;
        
        printf("[%d] %s\n", i, notes[i]->data);
    }
}

int main()
{
    char opt[2];

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    while (1)
    {
        printf("1. add_note\n"
               "2. edit_data\n"
               "3. del_note\n"
               "4. show_notes\n"
               "5. bye\n"
               "> ");
        read(0, opt, 2);

        switch (opt[0]) {
        case '1': add_note(); break;
        case '2': edit_data(); break;
        case '3': del_note(); break;
        case '4': show_notes(); break;
        case '5': exit(0);
        }
    }
    
    return 0;
}