#include <stdio.h>
#include <fcntl.h>

char leak[] = "MEOW!!!";

void aar(FILE *fp, void *addr, int size)
{
    char buf[0x10] = "1234";
    fp->_flags = 0xfbad0800;
    fp->_IO_read_end = fp->_IO_write_base = addr;
    fp->_IO_write_ptr = (char *)addr + size;
    fp->_IO_write_end = 0;
    fp->_fileno = 1;
    fwrite(buf, 0x10, 1, fp);
}

int main()
{
    FILE *fp;

    fp = fopen("/tmp/meow", "w");
    aar(fp, leak, sizeof(leak));
    fclose(fp); */

    return 0;
}
