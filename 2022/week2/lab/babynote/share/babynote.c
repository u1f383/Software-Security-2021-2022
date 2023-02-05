#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct Note
{
    char name[0x10];
    void *data;
};

struct Note *notes[0x10];

static short int get_idx()
{
    short int idx;

    printf("index\n> ");
    scanf("%hu", &idx);

    if (idx >= 0x10)
        printf("no, no ...\n"), exit(1);
    
    return idx;
}

static short int get_size()
{
    short int size;

    printf("size\n> ");
    scanf("%hu", &size);
    
    return size;
}

void add_note()
{
    short int idx;

    idx = get_idx();
    notes[idx] = malloc(sizeof(*notes[idx]));

    printf("note name\n> ");
    read(0, notes[idx]->name, 0x10);

    notes[idx]->data = NULL;
    printf("success!\n");
}

void edit_data()
{
    short int idx;
    short int size;

    idx = get_idx();
    size = get_size();

    if (notes[idx]->data == NULL)
        notes[idx]->data = malloc(size);
    
    read(0, notes[idx]->data, size);
    printf("success!\n");
}

void del_note()
{
    short int idx;

    idx = get_idx();
    free(notes[idx]->data);
    free(notes[idx]);
    printf("success!\n");
}

void show_notes()
{
    for (int i = 0; i < 0x10; i++) {
        if (notes[i] == NULL || notes[i]->data == NULL)
            continue;
        
        printf("[%d] %s\ndata: %s\n", i, notes[i]->name, (char *)notes[i]->data);
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