#include <unistd.h>

int main()
{
    char buf[0x10];

    read(0, buf, 0x30);
    write(1, buf, 0x30);
    
    return 0;
}