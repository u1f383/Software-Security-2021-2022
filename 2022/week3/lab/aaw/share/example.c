#include <stdio.h>
#include <fcntl.h>

char leak[] = "MEOW!!!";

void aaw(FILE *fp, void *addr, int size)
{
    char buf[0x10] = "1234";
    fp->_flags = 0xfbad0000;
    fp->_IO_buf_base = fp->_IO_write_base = addr;
    fp->_IO_buf_end = (char *)addr + size;
    fp->_IO_read_ptr = fp->_IO_read_end = 0;
    fp->_fileno = 0;
    fread(buf, 0x1, 1, fp);
    puts(leak);
}

int main()
{
    FILE *fp;

    fp = fopen("/tmp/meow", "r");
    aaw(fp, leak, sizeof(leak));
    fclose(fp);

    return 0;
}
